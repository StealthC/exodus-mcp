package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"testing"
)

// system_snapshot_capture contract (roadmap issue #3): the published schema and
// the strict decoder must describe the same arguments, and every emitted memory
// range must carry the real address domain of its space instead of its range
// name.

// systemSnapshotBridge answers the reads a system snapshot needs on a paused
// target, honoring the requested memory range so provenance can be compared
// against the same range captured by memory_snapshot_capture.
func systemSnapshotBridge() *fakeBridgeClient {
	inner := newCaptureWindowBridge(true)
	client := inner.client
	base := client.executeFunc
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "regs_get":
			return json.RawMessage(m68kRegsPayload(map[string]uint64{"d0": 1, "a7": 0x00FFF000})), nil
		case "mem_read":
			address, _ := strconv.ParseUint(params["address"], 10, 64)
			length, _ := strconv.ParseUint(params["length"], 10, 64)
			payload := fmt.Sprintf(`{"space_id":%q,"kind":"memory","address":%d,"effective_address":%d,"length":%d,"byte_order":"big-endian","encoding":"base64","consistency":"live","system_paused_during_read":false,"data":%q}`,
				params["space"], address, address, length, base64.StdEncoding.EncodeToString(make([]byte, length)))
			return json.RawMessage(payload), nil
		}
		return base(ctx, method, params)
	}
	return client
}

// storedProvenance reads the stored provenance envelope of one artifact id.
func storedProvenance(t *testing.T, server *Server, artifactID string) map[string]any {
	t.Helper()
	described := structured(postToolCall(t, server, "artifact_get",
		fmt.Sprintf(`{"artifact_id":%q,"include":["provenance"]}`, artifactID)))
	if described["code"] != nil {
		t.Fatalf("artifact_get failed: %v", described)
	}
	return described["provenance"].(map[string]any)
}

func artifactIDFromDescriptor(t *testing.T, value any, label string) string {
	t.Helper()
	descriptor := mustMap(t, value, label)
	id, _ := descriptor["id"].(string)
	if id == "" {
		t.Fatalf("%s has no artifact id: %v", label, descriptor)
	}
	return id
}

// TestSystemSnapshotMemoryProvenanceMatchesMemorySnapshot is the regression of the
// live defect: the same range captured by both producers must describe the same
// address domain, device, and start addresses.
func TestSystemSnapshotMemoryProvenanceMatchesMemorySnapshot(t *testing.T) {
	server := newTestServer(t, systemSnapshotBridge())
	server.runState.observe(server, false, nil)

	memory := structured(postToolCall(t, server, "memory_snapshot_capture",
		`{"space":"mem-ram","address_space":"m68k-bus","ranges":[{"name":"ram0","address":"0xFF0000","length":8}]}`))
	if memory["code"] != nil {
		t.Fatalf("memory_snapshot_capture failed: %v", memory)
	}
	memoryRange := mustMap(t, memory["ranges"].([]any)[0], "memory range")
	memoryProvenance := storedProvenance(t, server, artifactIDFromDescriptor(t, memoryRange["artifact"], "memory range artifact"))

	system := structured(postToolCall(t, server, "system_snapshot_capture",
		`{"memory_ranges":[{"name":"ram0","space":"mem-ram","address":"0xFF0000","address_space":"m68k-bus","length":8}],"include_frame":false}`))
	if system["code"] != nil {
		t.Fatalf("system_snapshot_capture failed: %v", system)
	}
	systemComponents := mustMap(t, system["components"], "components")
	systemProvenance := storedProvenance(t, server, artifactIDFromDescriptor(t, systemComponents["memory:ram0"], "memory component"))

	// The component is keyed by the range label, and the envelope carries the
	// real domain, not the label.
	if systemProvenance["address_space"] != "mem-ram" {
		t.Fatalf("address_space = %v, want mem-ram (the range name is not an address space): %v", systemProvenance["address_space"], systemProvenance)
	}
	if systemProvenance["device"] != "68000 work RAM" || systemProvenance["space_kind"] != "memory" {
		t.Fatalf("domain facts wrong: %v", systemProvenance)
	}
	if systemProvenance["start_address"] != float64(0) || systemProvenance["start_space_address"] != float64(0) {
		t.Fatalf("start address must be space-relative: %v", systemProvenance)
	}
	if systemProvenance["start_bus_address"] != float64(0xFF0000) {
		t.Fatalf("bus address must be reported: %v", systemProvenance["start_bus_address"])
	}
	for _, field := range []string{"address_space", "device", "space_kind", "start_address", "start_space_address", "start_bus_address", "byte_length", "byte_order", "raw_byte_ordering"} {
		if !reflect.DeepEqual(systemProvenance[field], memoryProvenance[field]) {
			t.Fatalf("provenance %s differs between producers: system %v, memory %v", field, systemProvenance[field], memoryProvenance[field])
		}
	}
	// The capture index repeats the same facts so a consumer can decide coverage
	// without reading the artifact.
	captureID, _ := system["summary"].(map[string]any)["capture_id"].(string)
	resolved := structured(postToolCall(t, server, "capture_get", fmt.Sprintf(`{"capture_id":%q}`, captureID)))
	var component map[string]any
	for _, entry := range resolved["components"].([]any) {
		candidate := entry.(map[string]any)
		if candidate["name"] == "memory:ram0" {
			component = candidate
		}
	}
	if component == nil {
		t.Fatalf("capture_get lost the memory component: %v", resolved["components"])
	}
	if component["address_space"] != "mem-ram" || component["start_address"] != float64(0) {
		t.Fatalf("capture index component describes a wrong domain: %v", component)
	}
}

// TestSystemSnapshotAcceptsPublishedAddressSpace is the decoder half of the
// defect: the schema publishes address_space, so the strict decoder must accept
// it.
func TestSystemSnapshotAcceptsPublishedAddressSpace(t *testing.T) {
	server := newTestServer(t, systemSnapshotBridge())
	server.runState.observe(server, false, nil)

	content := structured(postToolCall(t, server, "system_snapshot_capture",
		`{"space":"mem-ram","address_space":"mem-ram","memory_ranges":[{"name":"ram0","address":"0xFF0000","length":4}],"include_frame":false,"include_m68k_registers":false,"include_z80_registers":false,"include_vdp_status":false,"include_cram":false,"include_vsram":false}`))
	if content["code"] != nil {
		t.Fatalf("a published argument must be accepted: %v", content)
	}
	components := mustMap(t, content["components"], "components")
	provenance := storedProvenance(t, server, artifactIDFromDescriptor(t, components["memory:ram0"], "memory component"))
	if provenance["address_space"] != "mem-ram" {
		t.Fatalf("address_space argument must not change the range domain: %v", provenance)
	}
}

// TestSystemSnapshotRangeSpaceBeatsAddressSpace: a range that declares both a
// space and an address domain keeps its space; the domain only parses the
// address.
func TestSystemSnapshotRangeSpaceBeatsAddressSpace(t *testing.T) {
	server := newTestServer(t, systemSnapshotBridge())
	server.runState.observe(server, false, nil)

	content := structured(postToolCall(t, server, "system_snapshot_capture",
		`{"memory_ranges":[{"name":"ram0","space":"mem-ram","address":"0xFF0000","address_space":"m68k-bus","length":4}],"include_frame":false}`))
	if content["code"] != nil {
		t.Fatalf("range with space and address_space failed: %v", content)
	}
	components := mustMap(t, content["components"], "components")
	provenance := storedProvenance(t, server, artifactIDFromDescriptor(t, components["memory:ram0"], "memory component"))
	if provenance["address_space"] != "mem-ram" || provenance["start_address"] != float64(0) {
		t.Fatalf("the declared range space must win over address_space: %v", provenance)
	}
}

// TestPublishedSchemaMatchesArgumentStructs is the property-level contract: every
// published argument must be decodable, and every decodable field must be
// published. A schema/decoder mismatch is invisible until a client follows the
// schema and the strict decoder rejects the call.
func TestPublishedSchemaMatchesArgumentStructs(t *testing.T) {
	cases := []struct {
		tool string
		args any
	}{
		{"system_snapshot_capture", systemSnapshotArgs{}},
		{"memory_snapshot_capture", memorySnapshotCaptureArgs{}},
		{"capture_get", captureGetArgs{}},
		{"artifact_get", artifactRefArgs{}},
		{"artifact_list", artifactListArgs{}},
		{"vdp_capture", vdpCaptureArgs{}},
		{"vdp_memory_export", vdpMemoryExportArgs{}},
		{"vdp_sprite_table", vdpSpriteTableArgs{}},
		{"vdp_tile_export", vdpTileExportArgs{}},
		{"vdp_plane_export", vdpPlaneExportArgs{}},
		{"vdp_pixel_info", vdpPixelInfoArgs{}},
	}
	for _, tc := range cases {
		spec := lookupTool(tc.tool)
		if spec == nil {
			t.Fatalf("%s is not registered", tc.tool)
		}
		properties, _ := spec.schema["properties"].(map[string]any)
		if properties == nil {
			t.Fatalf("%s publishes no properties", tc.tool)
		}
		fields := structFieldMap(reflect.TypeOf(tc.args))
		for published := range properties {
			if _, decodable := fields[published]; decodable {
				continue
			}
			if isContractGuardField(published) {
				t.Fatalf("%s publishes the mediation field %q but its argument struct does not decode it; publish it only when the handler applies it", tc.tool, published)
			}
			t.Fatalf("%s publishes %q but the strict decoder rejects it (decoded fields: %v)", tc.tool, published, sortedFieldNames(fields))
		}
		for field := range fields {
			if _, published := properties[field]; published {
				continue
			}
			t.Fatalf("%s decodes %q but does not publish it", tc.tool, field)
		}
	}
}

// TestSystemSnapshotRangeItemSchemaMatchesDecoder covers the nested range object:
// the published range properties must all decode.
func TestSystemSnapshotRangeItemSchemaMatchesDecoder(t *testing.T) {
	spec := lookupTool("system_snapshot_capture")
	properties := spec.schema["properties"].(map[string]any)
	ranges := properties["memory_ranges"].(map[string]any)
	items := ranges["items"].(map[string]any)
	itemProperties := items["properties"].(map[string]any)
	fields := structFieldMap(reflect.TypeOf(captureRangeArgs{}))
	for published := range itemProperties {
		if _, decodable := fields[published]; !decodable {
			t.Fatalf("memory_ranges items publish %q but captureRangeArgs rejects it (fields: %v)", published, sortedFieldNames(fields))
		}
	}
}

func sortedFieldNames(fields map[string]reflect.Type) []string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	return names
}
