package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/StealthC/exodus-mcp/internal/analysis"
)

// defaultContextID resolves the implicit default context through context_list.
func defaultContextID(t *testing.T, server *Server) string {
	t.Helper()
	result := postToolCall(t, server, "context_list", "{}")
	id, _ := structured(result)["default_context"].(string)
	if id == "" {
		t.Fatalf("default context missing: %v", result)
	}
	return id
}

func TestAnnotationCreateGetUpdateDelete(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	create := postToolCall(t, server, "annotation_create", `{
		"title":"life counter","text":"0xFF1234 tracks lives","tags":["hud"],
		"category":"hypothesis","author":"analyst-a","confidence":"medium","kind":"hypothesis",
		"address_space":"m68k-bus","address":"0xFF1234","end_address":"$FF1237",
		"links":{"artifacts":["art_diff1"],"watchpoints":[3],"symbols":["lives"]}
	}`)
	if create["isError"] == true {
		t.Fatalf("create failed: %v", structured(create))
	}
	view := structured(create)["annotation"].(map[string]any)
	annotationID := view["id"].(string)
	if !strings.HasPrefix(annotationID, "annotation_") {
		t.Fatalf("annotation id malformed: %s", annotationID)
	}
	// Flexible address parsing: 0x hex and $ hex forms must both work.
	if view["address"] != float64(0xFF1234) || view["address_hex"] != "0xFF1234" {
		t.Fatalf("address parse wrong: %v", view)
	}
	if view["end_address"] != float64(0xFF1237) || view["length"] != float64(4) {
		t.Fatalf("range wrong: %v", view)
	}
	if view["stale"] != false || view["stale_reason"] != "" {
		t.Fatalf("fresh annotation must not be stale: %v", view)
	}
	links := view["links"].(map[string]any)
	if len(links["artifacts"].([]any)) != 1 || len(links["watchpoints"].([]any)) != 1 {
		t.Fatalf("links wrong: %v", links)
	}

	// Get echoes the same view.
	get := postToolCall(t, server, "annotation_get", fmt.Sprintf(`{"annotation_id":%q}`, annotationID))
	if structured(get)["annotation"].(map[string]any)["title"] != "life counter" {
		t.Fatalf("get wrong: %v", structured(get))
	}

	// A target mutation advances the generation and flags the annotation stale.
	server.target.Advance()
	get = postToolCall(t, server, "annotation_get", fmt.Sprintf(`{"annotation_id":%q}`, annotationID))
	view = structured(get)["annotation"].(map[string]any)
	if view["stale"] != true || view["stale_reason"] != "target_generation_mismatch" {
		t.Fatalf("generation advance must flag stale: %v", view)
	}

	// Update: point annotation, address change without end; length recomputed.
	update := postToolCall(t, server, "annotation_update", fmt.Sprintf(`{"annotation_id":%q,"address":"0xFF1235"}`, annotationID))
	updated := structured(update)["annotation"].(map[string]any)
	if updated["address"] != float64(0xFF1235) || updated["end_address"] != float64(0xFF1237) || updated["length"] != float64(3) {
		t.Fatalf("update range recompute wrong: %v", updated)
	}
	// Clear the whole address domain with null.
	update = postToolCall(t, server, "annotation_update", fmt.Sprintf(`{"annotation_id":%q,"address":null}`, annotationID))
	updated = structured(update)["annotation"].(map[string]any)
	if _, present := updated["address"]; present {
		t.Fatalf("null address must clear the domain: %v", updated)
	}

	// Wrong ids map to unknown_annotation.
	for _, tool := range []string{"annotation_get", "annotation_update", "annotation_delete"} {
		result := postToolCall(t, server, tool, `{"annotation_id":"annotation_nope"}`)
		if structured(result)["code"] != "unknown_annotation" {
			t.Fatalf("%s expected unknown_annotation: %v", tool, result)
		}
	}

	// Delete removes it.
	del := postToolCall(t, server, "annotation_delete", fmt.Sprintf(`{"annotation_id":%q}`, annotationID))
	if del["isError"] == true {
		t.Fatalf("delete failed: %v", del)
	}
	result := postToolCall(t, server, "annotation_get", fmt.Sprintf(`{"annotation_id":%q}`, annotationID))
	if structured(result)["code"] != "unknown_annotation" {
		t.Fatalf("deleted annotation must be unknown: %v", result)
	}
}

func TestAnnotationCreateValidationErrors(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	cases := []struct {
		args string
		code string
	}{
		{`{}`, "invalid_params"},                          // title required
		{`{"title":"x","kind":"fact"}`, "invalid_params"}, // bad kind
		{`{"title":"x","category":"banana"}`, "invalid_params"},
		{`{"title":"x","confidence":"certain"}`, "invalid_params"},
		{`{"title":"x","address":"0xFF","end_address":1}`, "invalid_params"}, // end < address
		{`{"title":"x","end_address":1}`, "invalid_params"},                  // end without address
		{`{"title":"x","length":4}`, "invalid_params"},                       // length without address
		{`{"title":"x","unknown_field":1}`, "invalid_params"},                // strict args
	}
	for _, tc := range cases {
		result := postToolCall(t, server, "annotation_create", tc.args)
		if structured(result)["code"] != tc.code {
			t.Fatalf("args %s expected %s, got %v", tc.args, tc.code, structured(result))
		}
	}
	// Default kind must be observation.
	ok := postToolCall(t, server, "annotation_create", `{"title":"plain observation"}`)
	if ok["isError"] == true || structured(ok)["annotation"].(map[string]any)["kind"] != "observation" {
		t.Fatalf("default kind must be observation: %v", ok)
	}
}

func TestAnnotationListFiltersAndStaleness(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	for index := 0; index < 3; index++ {
		result := postToolCall(t, server, "annotation_create", fmt.Sprintf(`{"title":"fresh %d","tags":["hud"],"kind":"observation","address_space":"m68k-bus"}`, index))
		if result["isError"] == true {
			t.Fatalf("create failed: %v", result)
		}
	}
	// No ROM is loaded and the generation is 1, so these annotations are
	// fresh. Cache the default context id before any target mutation.
	context := server.contexts.Default()
	current := analysis.AnnotationTarget{Generation: server.target.Generation()}
	if served := context.Annotations.List(context.ID, analysis.AnnotationFilter{IncludeStale: true, Limit: 10}, current); len(served.Annotations) != 3 {
		t.Fatalf("seed count wrong: %d", len(served.Annotations))
	}
	// Now the target advances: every annotation becomes stale.
	server.target.Advance()
	list := postToolCall(t, server, "annotation_list", `{"include_stale":true}`)
	sc := structured(list)
	annotations := sc["annotations"].([]any)
	if len(annotations) != 3 {
		t.Fatalf("include_stale list wrong: %d", len(annotations))
	}
	for _, raw := range annotations {
		view := raw.(map[string]any)
		if view["stale"] != true || view["stale_reason"] != "target_generation_mismatch" {
			t.Fatalf("stale flags wrong: %v", view)
		}
	}
	// Default policy excludes stale but counts them.
	list = postToolCall(t, server, "annotation_list", `{}`)
	sc = structured(list)
	if len(sc["annotations"].([]any)) != 0 || sc["total"] != float64(0) || sc["stale_excluded"] != float64(3) {
		t.Fatalf("default stale exclusion wrong: %v", sc)
	}
	// stale_only.
	list = postToolCall(t, server, "annotation_list", `{"stale_only":true,"limit":2}`)
	sc = structured(list)
	if len(sc["annotations"].([]any)) != 2 || sc["truncated"] != true {
		t.Fatalf("stale_only pagination wrong: %v", sc)
	}
	// Query and tag filters.
	list = postToolCall(t, server, "annotation_list", `{"filter":"FRESH","include_stale":true}`)
	if len(structured(list)["annotations"].([]any)) != 3 {
		t.Fatalf("query filter wrong: %v", structured(list))
	}
	list = postToolCall(t, server, "annotation_list", `{"include_stale":true,"tags":["hud"]}`)
	if len(structured(list)["annotations"].([]any)) != 3 {
		t.Fatalf("tag filter wrong: %v", structured(list))
	}
	list = postToolCall(t, server, "annotation_list", `{"include_stale":true,"tags":["missing"]}`)
	if len(structured(list)["annotations"].([]any)) != 0 {
		t.Fatalf("missing tag filter wrong: %v", structured(list))
	}
	// Limit cap.
	bad := postToolCall(t, server, "annotation_list", `{"limit":101}`)
	if structured(bad)["code"] != "invalid_params" {
		t.Fatalf("limit cap must be rejected: %v", structured(bad))
	}
}

func TestAnnotationROMChangeFlagsStale(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	created := postToolCall(t, server, "annotation_create", `{"title":"before rom"}`)
	annotationID := structured(created)["annotation"].(map[string]any)["id"].(string)
	// A ROM becomes loaded: the file-derived SHA-256 differs from the empty
	// stamp recorded at creation, so the annotation turns stale.
	romPath := filepath.Join(t.TempDir(), "rom.bin")
	if err := os.WriteFile(romPath, []byte("MEGA DRIVE TEST ROM"), 0o600); err != nil {
		t.Fatal(err)
	}
	server.setROMPath(romPath)
	get := postToolCall(t, server, "annotation_get", fmt.Sprintf(`{"annotation_id":%q}`, annotationID))
	view := structured(get)["annotation"].(map[string]any)
	if view["stale"] != true || view["stale_reason"] != "rom_sha256_mismatch" {
		t.Fatalf("rom change must flag stale: %v", view)
	}
	// New annotations are stamped with the loaded ROM identity and are fresh.
	created = postToolCall(t, server, "annotation_create", `{"title":"after rom"}`)
	view = structured(created)["annotation"].(map[string]any)
	if view["stale"] != false {
		t.Fatalf("stamped annotation must be fresh: %v", view)
	}
	if view["rom_path"] != romPath || view["rom_sha256"] == "" {
		t.Fatalf("rom identity must be stamped on create: %v", view)
	}
}

func TestAnnotationExportImportRoundtrip(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	created := postToolCall(t, server, "annotation_create", `{"title":"shared finding","kind":"hypothesis","address":"0x1000","end_address":"0x1003"}`)
	if created["isError"] == true {
		t.Fatalf("create failed: %v", created)
	}
	export := postToolCall(t, server, "annotation_export", `{}`)
	if export["isError"] == true {
		t.Fatalf("export failed: %v", structured(export))
	}
	sc := structured(export)
	if sc["schema_version"] != "annotation-export/1" || sc["annotation_count"] != float64(1) {
		t.Fatalf("export summary wrong: %v", sc)
	}
	artifactDesc := sc["artifact"].(map[string]any)
	if artifactDesc["kind"] != "annotation-export" || artifactDesc["mime_type"] != "application/json" {
		t.Fatalf("artifact kind wrong: %v", artifactDesc)
	}
	if artifactDesc["provenance"].(map[string]any)["kind"] != "annotation-export" {
		t.Fatalf("provenance wrong: %v", artifactDesc)
	}
	// Verify the stored document is the versioned schema.
	raw, _, err := server.store.Bytes(artifactDesc["id"].(string), defaultContextID(t, server))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if document["schema_version"] != "annotation-export/1" || len(document["annotations"].([]any)) != 1 {
		t.Fatalf("stored document malformed: %s", raw)
	}

	// Import into a second context must use inline data: artifacts are
	// context-scoped, so artifact_id only resolves within the owning context.
	createdCtx := postToolCall(t, server, "context_create", `{"name":"analyst-b"}`)
	targetContextID := structured(createdCtx)["context"].(map[string]any)["id"].(string)
	inline := postToolCall(t, server, "annotation_import", fmt.Sprintf(`{"data":%s,"context":%q}`, string(raw), targetContextID))
	sc = structured(inline)
	if sc["imported"] != float64(1) || len(sc["conflicts"].([]any)) != 0 {
		t.Fatalf("cross-context inline import wrong: %v", sc)
	}
	// Re-import without overwrite reports the conflict.
	inline = postToolCall(t, server, "annotation_import", fmt.Sprintf(`{"data":%s,"context":%q}`, string(raw), targetContextID))
	sc = structured(inline)
	if sc["imported"] != float64(0) || len(sc["conflicts"].([]any)) != 1 {
		t.Fatalf("conflict import wrong: %v", sc)
	}
	// Re-import with overwrite replaces.
	inline = postToolCall(t, server, "annotation_import", fmt.Sprintf(`{"data":%s,"context":%q,"overwrite":true}`, string(raw), targetContextID))
	sc = structured(inline)
	if sc["imported"] != float64(1) || len(sc["conflicts"].([]any)) != 0 {
		t.Fatalf("overwrite import wrong: %v", sc)
	}

	// artifact_id resolves within the artifact's owning context: re-importing
	// the export into the default context conflicts and then overwrites.
	conflicted := postToolCall(t, server, "annotation_import", fmt.Sprintf(`{"artifact_id":%q}`, artifactDesc["id"].(string)))
	sc = structured(conflicted)
	if sc["imported"] != float64(0) || len(sc["conflicts"].([]any)) != 1 {
		t.Fatalf("artifact_id conflict import wrong: %v", sc)
	}
	overwritten := postToolCall(t, server, "annotation_import", fmt.Sprintf(`{"artifact_id":%q,"overwrite":true}`, artifactDesc["id"].(string)))
	sc = structured(overwritten)
	if sc["imported"] != float64(1) || len(sc["conflicts"].([]any)) != 0 {
		t.Fatalf("artifact_id overwrite import wrong: %v", sc)
	}

	// Neither artifact_id nor data is invalid.
	bad := postToolCall(t, server, "annotation_import", `{}`)
	if structured(bad)["code"] != "invalid_params" {
		t.Fatalf("missing both sources must be invalid: %v", structured(bad))
	}
	// Unknown artifact id.
	bad = postToolCall(t, server, "annotation_import", `{"artifact_id":"art_nope"}`)
	if structured(bad)["code"] != "unknown_artifact" {
		t.Fatalf("unknown artifact must fail: %v", structured(bad))
	}
	// Wrong artifact kind.
	dump := postToolCall(t, server, "memory_dump", `{"space":"m68k-ram","address":0,"length":16}`)
	dumpID := structured(dump)["artifact"].(map[string]any)["id"].(string)
	bad = postToolCall(t, server, "annotation_import", fmt.Sprintf(`{"artifact_id":%q}`, dumpID))
	if structured(bad)["code"] != "invalid_params" || !strings.Contains(structured(bad)["message"].(string), "annotation-export") {
		t.Fatalf("wrong kind must be rejected: %v", structured(bad))
	}
	// Malformed inline data.
	bad = postToolCall(t, server, "annotation_import", `{"data":"{not json"}`)
	if structured(bad)["code"] != "invalid_params" {
		t.Fatalf("malformed data must fail: %v", structured(bad))
	}
}

func TestAnnotationLimitExceeded(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	context := server.contexts.Default()
	for index := 0; index < analysis.MaxAnnotationsPerContext; index++ {
		ann := analysis.Annotation{Title: "seed", Kind: "observation"}
		if _, err := context.Annotations.Create(context.ID, ann); err != nil {
			t.Fatalf("seed %d failed: %v", index, err)
		}
	}
	result := postToolCall(t, server, "annotation_create", `{"title":"overflow"}`)
	if structured(result)["code"] != "annotation_limit_exceeded" {
		t.Fatalf("expected annotation_limit_exceeded: %v", structured(result))
	}
	// A different context still has budget.
	createdCtx := postToolCall(t, server, "context_create", `{"name":"fresh-space"}`)
	ctxID := structured(createdCtx)["context"].(map[string]any)["id"].(string)
	result = postToolCall(t, server, "annotation_create", fmt.Sprintf(`{"title":"ok","context":%q}`, ctxID))
	if result["isError"] == true {
		t.Fatalf("fresh context create must succeed: %v", result)
	}
}
