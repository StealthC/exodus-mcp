package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

// Artifact discovery and capture resolution (roadmap issues #2 and #10): one
// call must enumerate what a context holds, and a capture id must resolve to its
// manifest and components without the original response.

// discoveryBridge serves every read a capture producer needs on a paused target:
// memory, registers, VDP status, VDP buffers, and the rendered frame. The target
// is already paused, so no capture needs a run-state mutation.
func discoveryBridge() *fakeBridgeClient {
	inner := newCaptureWindowBridge(true)
	client := inner.client
	base := client.executeFunc
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method == "regs_get" {
			return json.RawMessage(m68kRegsPayload(map[string]uint64{"d0": 1, "a7": 0x00FFF000})), nil
		}
		return base(ctx, method, params)
	}
	return client
}

func descriptorField(t *testing.T, view map[string]any, field string) any {
	t.Helper()
	value, present := view[field]
	if !present {
		t.Fatalf("descriptor missing %s: %v", field, view)
	}
	return value
}

func artifactIDOf(t *testing.T, view map[string]any) string {
	t.Helper()
	id, _ := descriptorField(t, view, "id").(string)
	if id == "" {
		t.Fatalf("descriptor without id: %v", view)
	}
	return id
}

// TestArtifactListDiscoversContextArtifacts: every artifact a context produced is
// listable in one call, with the retention facts a caller needs before it tries
// to download.
func TestArtifactListDiscoversContextArtifacts(t *testing.T) {
	client := ramBlobClient(make([]byte, 32))
	server := newTestServer(t, client)

	dump := structured(postToolCall(t, server, "memory_dump", `{"space":"mem-ram","address":"0xFF0000","length":4}`))
	dumpID := artifactIDOf(t, dump["artifact"].(map[string]any))

	listed := structured(postToolCall(t, server, "artifact_list", `{}`))
	if listed["code"] != nil {
		t.Fatalf("artifact_list failed: %v", listed)
	}
	if listed["total"] != float64(1) || listed["returned"] != float64(1) || listed["has_more"] != false {
		t.Fatalf("listing counters wrong: %v", listed)
	}
	if next, present := listed["next_cursor"]; !present || next != nil {
		t.Fatalf("last page must report a null next_cursor: %v", listed["next_cursor"])
	}
	artifacts := listed["artifacts"].([]any)
	descriptor := artifacts[0].(map[string]any)
	if descriptor["artifact_id"] != dumpID {
		t.Fatalf("listing did not find the dump artifact: %v", descriptor)
	}
	for _, field := range []string{"artifact_id", "kind", "mime_type", "size_bytes", "created_at", "expires_at", "url", "sha256", "provenance_state"} {
		descriptorField(t, descriptor, field)
	}
	if descriptor["expires_at"] != nil {
		t.Fatalf("unlimited retention must report a null expires_at: %v", descriptor["expires_at"])
	}
	if descriptor["kind"] != "memory-dump" {
		t.Fatalf("kind = %v", descriptor["kind"])
	}
}

// TestArtifactListFiltersAndPages covers the kind filter, the capture filter, and
// cursor paging over one context.
func TestArtifactListFiltersAndPages(t *testing.T) {
	server := newTestServer(t, discoveryBridge())

	for index := 0; index < 3; index++ {
		postToolCall(t, server, "memory_dump", fmt.Sprintf(`{"space":"m68k-bus","address":%d,"length":4}`, 0xFF0000+index*4))
	}
	capture := structured(postToolCall(t, server, "memory_snapshot_capture",
		`{"space":"m68k-bus","ranges":[{"name":"ram0","address":"0xFF0000","length":4}]}`))
	captureID, _ := capture["summary"].(map[string]any)["capture_id"].(string)
	if captureID == "" {
		t.Fatalf("capture produced no id: %v", capture)
	}

	dumps := structured(postToolCall(t, server, "artifact_list", `{"kind":"memory-dump"}`))
	if dumps["total"] != float64(3) {
		t.Fatalf("kind filter wrong: %v", dumps)
	}
	for _, entry := range dumps["artifacts"].([]any) {
		if entry.(map[string]any)["kind"] != "memory-dump" {
			t.Fatalf("kind filter returned another kind: %v", entry)
		}
	}

	ofCapture := structured(postToolCall(t, server, "artifact_list", fmt.Sprintf(`{"capture_id":%q}`, captureID)))
	if ofCapture["total"] != float64(2) {
		t.Fatalf("capture filter must find the manifest and one range: %v", ofCapture)
	}
	kinds := map[any]bool{}
	for _, entry := range ofCapture["artifacts"].([]any) {
		descriptor := entry.(map[string]any)
		if descriptor["capture_id"] != captureID {
			t.Fatalf("capture filter returned a foreign artifact: %v", descriptor)
		}
		kinds[descriptor["kind"]] = true
	}
	if !kinds["capture-manifest"] || !kinds["memory-snapshot"] {
		t.Fatalf("capture filter missed a component kind: %v", kinds)
	}

	first := structured(postToolCall(t, server, "artifact_list", `{"limit":2}`))
	if first["returned"] != float64(2) || first["has_more"] != true {
		t.Fatalf("first page wrong: %v", first)
	}
	cursor, _ := first["next_cursor"].(string)
	if cursor == "" {
		t.Fatalf("first page has no next_cursor: %v", first)
	}
	second := structured(postToolCall(t, server, "artifact_list", fmt.Sprintf(`{"limit":2,"cursor":%q}`, cursor)))
	if second["returned"] != float64(2) || second["has_more"] != true {
		t.Fatalf("second page wrong: %v", second)
	}
	seen := map[any]bool{}
	for _, page := range [][]any{first["artifacts"].([]any), second["artifacts"].([]any)} {
		for _, entry := range page {
			id := entry.(map[string]any)["artifact_id"]
			if seen[id] {
				t.Fatalf("artifact %v appeared on two pages", id)
			}
			seen[id] = true
		}
	}
	last := structured(postToolCall(t, server, "artifact_list", fmt.Sprintf(`{"limit":2,"cursor":%q}`, second["next_cursor"])))
	if last["has_more"] != false || last["next_cursor"] != nil {
		t.Fatalf("last page wrong: %v", last)
	}
}

// TestArtifactListRejectsInvalidFilters keeps discovery from silently answering
// an empty page for a caller mistake.
func TestArtifactListRejectsInvalidFilters(t *testing.T) {
	server := newTestServer(t, ramBlobClient(make([]byte, 4)))
	for _, args := range []string{`{"cursor":"made-up"}`, `{"capture_id":"nope"}`} {
		content := structured(postToolCall(t, server, "artifact_list", args))
		if content["code"] != "invalid_params" {
			t.Fatalf("args %s: expected invalid_params: %v", args, content)
		}
	}
}

// TestArtifactGetMergesMetadataAndProvenance: artifact_get is the merged
// successor of artifact_get + artifact_describe, always reporting retention.
func TestArtifactGetMergesMetadataAndProvenance(t *testing.T) {
	server := newTestServer(t, ramBlobClient(make([]byte, 4)))
	dump := structured(postToolCall(t, server, "memory_dump", `{"space":"mem-ram","address":"0xFF0000","length":4}`))
	artifactID := artifactIDOf(t, dump["artifact"].(map[string]any))

	merged := structured(postToolCall(t, server, "artifact_get", fmt.Sprintf(`{"artifact_id":%q}`, artifactID)))
	if merged["code"] != nil {
		t.Fatalf("artifact_get failed: %v", merged)
	}
	for _, field := range []string{"artifact_id", "kind", "mime_type", "size_bytes", "sha256", "created_at", "expires_at", "metadata", "provenance", "artifact", "retrieval"} {
		descriptorField(t, merged, field)
	}
	metadata := merged["metadata"].(map[string]any)
	if metadata["context_id"] == "" || metadata["artifact_id"] != artifactID {
		t.Fatalf("metadata block wrong: %v", metadata)
	}
	provenance := merged["provenance"].(map[string]any)
	if provenance["artifact_schema"] != "artifact-provenance/2" {
		t.Fatalf("provenance envelope missing: %v", provenance)
	}

	onlyProvenance := structured(postToolCall(t, server, "artifact_get", fmt.Sprintf(`{"artifact_id":%q,"include":["provenance"]}`, artifactID)))
	if _, present := onlyProvenance["metadata"]; present {
		t.Fatalf("include [provenance] must not return metadata: %v", onlyProvenance)
	}
	if _, present := onlyProvenance["provenance"]; !present {
		t.Fatalf("include [provenance] must return the envelope: %v", onlyProvenance)
	}
	// Retention facts are part of every response, not only of the metadata block.
	descriptorField(t, onlyProvenance, "created_at")
	descriptorField(t, onlyProvenance, "expires_at")

	onlyMetadata := structured(postToolCall(t, server, "artifact_get", fmt.Sprintf(`{"artifact_id":%q,"include":["metadata"]}`, artifactID)))
	if _, present := onlyMetadata["provenance"]; present {
		t.Fatalf("include [metadata] must not return provenance: %v", onlyMetadata)
	}

	badInclude := structured(postToolCall(t, server, "artifact_get", fmt.Sprintf(`{"artifact_id":%q,"include":["everything"]}`, artifactID)))
	if badInclude["code"] != "invalid_params" {
		t.Fatalf("unknown include token must be rejected: %v", badInclude)
	}
}

// TestArtifactDescribeIsDeprecatedAlias: the alias keeps working for one release
// with the same payload plus an explicit deprecation note.
func TestArtifactDescribeIsDeprecatedAlias(t *testing.T) {
	server := newTestServer(t, ramBlobClient(make([]byte, 4)))
	dump := structured(postToolCall(t, server, "memory_dump", `{"space":"mem-ram","address":"0xFF0000","length":4}`))
	artifactID := artifactIDOf(t, dump["artifact"].(map[string]any))

	described := structured(postToolCall(t, server, "artifact_describe", fmt.Sprintf(`{"artifact_id":%q}`, artifactID)))
	deprecated := described["deprecated"].(map[string]any)
	if deprecated["code"] != "artifact_describe_deprecated" || deprecated["replacement_tool"] != "artifact_get" {
		t.Fatalf("deprecation note wrong: %v", deprecated)
	}
	fetched := structured(postToolCall(t, server, "artifact_get", fmt.Sprintf(`{"artifact_id":%q}`, artifactID)))
	for _, field := range []string{"artifact_id", "kind", "mime_type", "size_bytes", "sha256", "created_at", "expires_at", "metadata", "provenance"} {
		if !reflect.DeepEqual(described[field], fetched[field]) {
			t.Fatalf("alias payload differs for %s: %v vs %v", field, described[field], fetched[field])
		}
	}
}

// TestCaptureGetResolvesEveryProducer: each capture producer registers its
// manifest and components, and the id alone reaches the bytes.
func TestCaptureGetResolvesEveryProducer(t *testing.T) {
	server := newTestServer(t, discoveryBridge())
	contextID := defaultContextID(t, server)

	memoryCapture := structured(postToolCall(t, server, "memory_snapshot_capture",
		`{"space":"m68k-bus","ranges":[{"name":"ram0","address":"0xFF0000","length":8}]}`))
	systemCapture := structured(postToolCall(t, server, "system_snapshot_capture",
		`{"memory_ranges":[{"name":"ram0","space":"m68k-bus","address":"0xFF0000","length":8}],"include_frame":false}`))
	vdpCapture := structured(postToolCall(t, server, "vdp_capture",
		`{"include_frame":false,"include_cram":true,"include_vsram":true,"include_vram":true,"vram_length":64}`))

	cases := []struct {
		name          string
		response      map[string]any
		producer      string
		schemaVersion string
		component     string
	}{
		{"memory_snapshot_capture", memoryCapture, "memory_snapshot_capture", "", "memory:ram0"},
		{"system_snapshot_capture", systemCapture, "system_snapshot_capture", systemSnapshotSchema, "memory:ram0"},
		{"vdp_capture", vdpCapture, "vdp_capture", "", "vram"},
	}
	for _, tc := range cases {
		captureID, _ := tc.response["summary"].(map[string]any)["capture_id"].(string)
		if captureID == "" {
			t.Fatalf("%s produced no capture id: %v", tc.name, tc.response)
		}
		resolved := structured(postToolCall(t, server, "capture_get", fmt.Sprintf(`{"capture_id":%q}`, captureID)))
		if resolved["code"] != nil {
			t.Fatalf("%s: capture_get failed: %v", tc.name, resolved)
		}
		if resolved["capture_id"] != captureID || resolved["producer_tool"] != tc.producer {
			t.Fatalf("%s: capture identity wrong: %v", tc.name, resolved)
		}
		if tc.schemaVersion != "" && resolved["schema_version"] != tc.schemaVersion {
			t.Fatalf("%s: schema_version = %v, want %s", tc.name, resolved["schema_version"], tc.schemaVersion)
		}
		manifest := resolved["manifest"].(map[string]any)
		if manifest["available"] != true || manifest["artifact_id"] == nil {
			t.Fatalf("%s: manifest not resolvable: %v", tc.name, manifest)
		}
		document, ok := resolved["manifest_document"].(map[string]any)
		if !ok || document["capture_id"] != captureID {
			t.Fatalf("%s: manifest document missing or foreign: %v", tc.name, resolved["manifest_document"])
		}
		components := resolved["components"].([]any)
		found := false
		for _, entry := range components {
			component := entry.(map[string]any)
			if component["name"] != tc.component {
				continue
			}
			found = true
			artifactID, _ := component["artifact_id"].(string)
			if artifactID == "" || component["available"] != true {
				t.Fatalf("%s: component %s is not fetchable: %v", tc.name, tc.component, component)
			}
			if _, _, err := server.store.Bytes(artifactID, contextID); err != nil {
				t.Fatalf("%s: component %s bytes do not resolve: %v", tc.name, tc.component, err)
			}
			descriptorField(t, component, "expires_at")
			if component["kind"] == "" || component["sha256"] == "" {
				t.Fatalf("%s: component metadata incomplete: %v", tc.name, component)
			}
		}
		if !found {
			t.Fatalf("%s: component %s missing from capture_get: %v", tc.name, tc.component, components)
		}
	}
}

// TestCaptureGetUnknownIDFails: an unresolvable id is an explicit error, never an
// empty or fabricated capture.
func TestCaptureGetUnknownIDFails(t *testing.T) {
	server := newTestServer(t, discoveryBridge())
	content := structured(postToolCall(t, server, "capture_get", `{"capture_id":"cap_doesnotexist00"}`))
	if content["code"] != "capture_not_found" {
		t.Fatalf("unknown capture must fail with capture_not_found: %v", content)
	}
	if content["capture_id"] != "cap_doesnotexist00" {
		t.Fatalf("failure must echo the id: %v", content)
	}
}
