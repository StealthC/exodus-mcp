package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/StealthC/exodus-mcp/internal/bridge"
)

// ----------------------------------------------------------------------------------------------------------------------
// Bus mapping in memory_spaces_list (roadmap P1 "Schema and response contract
// hardening").
// ----------------------------------------------------------------------------------------------------------------------

func TestMemorySpacesListIncludesBusMapping(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		return json.RawMessage(memSpacesPayload()), nil
	}
	result := callTool(t, client, "memory_spaces_list", `{}`)
	content := structured(result)
	if content["bus_address_formula"] != "bus_address = bus_base + bus_offset + space_relative_address" {
		t.Fatalf("bus_address_formula missing: %v", content)
	}
	byID := map[string]map[string]any{}
	for _, entry := range content["spaces"].([]any) {
		space := entry.(map[string]any)
		byID[space["id"].(string)] = space
	}

	memRAM, present := byID["mem-ram"]
	if !present {
		t.Fatal("mem-ram missing from catalog")
	}
	if memRAM["bus"] != "m68k" || memRAM["bus_base"] != float64(0xFF0000) || memRAM["bus_offset"] != float64(0) {
		t.Fatalf("mem-ram bus mapping wrong: %v", memRAM)
	}

	z80RAM, present := byID["mem-z80-ram"]
	if !present {
		t.Fatal("mem-z80-ram missing from catalog")
	}
	if z80RAM["bus"] != "m68k" || z80RAM["bus_base"] != float64(0xA00000) {
		t.Fatalf("mem-z80-ram bus mapping wrong: %v", z80RAM)
	}

	bus, present := byID["m68k-bus"]
	if !present {
		t.Fatal("m68k-bus missing from catalog")
	}
	if bus["bus"] != "m68k" || bus["bus_base"] != float64(0) {
		t.Fatalf("m68k-bus bus mapping wrong: %v", bus)
	}

	// VDP buffers are not linearly mapped; they explain instead of guessing.
	vram, present := byID["mem-vdp-vram"]
	if !present {
		t.Fatal("mem-vdp-vram missing from catalog")
	}
	if _, hasBase := vram["bus_base"]; hasBase {
		t.Fatalf("mem-vdp-vram must not claim a bus_base: %v", vram)
	}
	if !strings.Contains(vram["bus_mapping_note"].(string), "not linearly mapped") {
		t.Fatalf("mem-vdp-vram bus_mapping_note wrong: %v", vram)
	}

	// Unknown space ids get an explicit note, never a guessed mapping.
	unknownSpace, present := byID["mem-unknown-thing"]
	if !present {
		t.Fatal("mem-unknown-thing missing from catalog")
	}
	if _, hasBase := unknownSpace["bus_base"]; hasBase {
		t.Fatalf("unknown space must not claim a bus_base: %v", unknownSpace)
	}
	if !strings.Contains(unknownSpace["bus_mapping_note"].(string), "No documented bus mapping") {
		t.Fatalf("unknown space note wrong: %v", unknownSpace)
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// out_of_range carries the valid canonical hex range.
// ----------------------------------------------------------------------------------------------------------------------

func TestMemoryReadOutOfRangeIncludesValidRange(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		if method == "mem_spaces" {
			return json.RawMessage(memSpacesPayload()), nil
		}
		return nil, &bridge.CommandError{Code: "out_of_range", Message: "Requested range exceeds space mem-ram size of 65536 bytes"}
	}
	result := callTool(t, client, "memory_read", `{"space":"mem-ram","address":"0xFF0000","length":4}`)
	content := structured(result)
	if result["isError"] != true || content["code"] != "out_of_range" {
		t.Fatalf("expected out_of_range: %v", result)
	}
	message := content["message"].(string)
	if !strings.Contains(message, "0x000000-0x00FFFF") || !strings.Contains(message, "mem-ram") {
		t.Fatalf("out_of_range must include the valid canonical hex range: %v", message)
	}
}

func TestMemoryDumpOutOfRangeIncludesValidRange(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		if method == "mem_spaces" {
			return json.RawMessage(memSpacesPayload()), nil
		}
		return nil, &bridge.CommandError{Code: "out_of_range", Message: "Requested range exceeds space size of 65536 bytes"}
	}
	result := callTool(t, client, "memory_dump", `{"space":"mem-ram","address":"0xFF0000","length":4}`)
	content := structured(result)
	if result["isError"] != true || content["code"] != "out_of_range" {
		t.Fatalf("expected out_of_range: %v", result)
	}
	if !strings.Contains(content["message"].(string), "0x000000-0x00FFFF") {
		t.Fatalf("out_of_range must include the valid canonical hex range: %v", content["message"])
	}
}

func TestMemoryDumpReportsEffectiveAddress(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		return json.RawMessage(memReadPayloadPaused([]byte{1, 2, 3, 4, 5}, "big-endian", 0xFF0000, false)), nil
	}
	result := callTool(t, client, "memory_dump", `{"space":"mem-ram","address":0,"length":5}`)
	if result["isError"] == true {
		t.Fatalf("unexpected error: %v", result)
	}
	summary := structured(result)["summary"].(map[string]any)
	if summary["effective_address"] != float64(0xFF0000) {
		t.Fatalf("effective_address = %v, want 0xFF0000", summary["effective_address"])
	}
}

func TestResolveAddressDualForm(t *testing.T) {
	got, failure := resolveAddress("0xFF0000", "m68k-bus", "mem-ram")
	if failure != nil || got != 0 {
		t.Fatalf("bus address did not translate to RAM offset: got %X, failure %v", got, failure)
	}
	got, failure = resolveAddress(0, "mem-ram", "m68k-bus")
	if failure != nil || got != 0xFF0000 {
		t.Fatalf("RAM offset did not translate to bus address: got %X, failure %v", got, failure)
	}
	if _, failure = resolveAddress(0, "z80-bus", "mem-ram"); failure == nil || failure.Code != "invalid_params" {
		t.Fatalf("incompatible address domains must fail: %v", failure)
	}
}

func TestAddressDualFormSchemaAndMemoryResponse(t *testing.T) {
	var memoryReadSchema map[string]any
	for _, schema := range toolSchemas() {
		if schema["name"] != "memory_read" {
			continue
		}
		memoryReadSchema = schema["inputSchema"].(map[string]any)
	}
	if _, ok := memoryReadSchema["properties"].(map[string]any)["address_space"]; !ok {
		t.Fatal("memory_read schema must expose address_space")
	}
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "mem_read" {
			t.Fatalf("unexpected bridge method %s", method)
		}
		if params["address"] != "0" {
			t.Fatalf("translated address = %s, want 0", params["address"])
		}
		return json.RawMessage(memReadPayloadPaused([]byte{1, 2}, "big-endian", 0, false)), nil
	}
	result := callTool(t, client, "memory_read", `{"space":"mem-ram","address":"0xFF0000","address_space":"m68k-bus","length":2}`)
	if result["isError"] == true {
		t.Fatalf("unexpected dual-form read error: %v", result)
	}
	content := structured(result)
	if content["space_address"] != float64(0) || content["bus_address"] != float64(0xFF0000) {
		t.Fatalf("dual-form response coordinates missing: %v", content)
	}
}

func memSpacesPayload() string {
	return `{"spaces":[
		{"id":"m68k-bus","kind":"bus","device_instance":"Main 68000","device_display":"Main 68000","size_bytes":16777216,"entry_size_bytes":1,"byte_order":"big-endian"},
		{"id":"mem-ram","kind":"memory","device_instance":"RAM","device_display":"RAM","size_bytes":65536,"entry_size_bytes":2,"byte_order":"big-endian"},
		{"id":"mem-z80-ram","kind":"memory","device_instance":"Z80 RAM","device_display":"Z80 RAM","size_bytes":8192,"entry_size_bytes":1,"byte_order":"not-applicable"},
		{"id":"z80-bus","kind":"bus","device_instance":"Z80","device_display":"Z80","size_bytes":65536,"entry_size_bytes":1,"byte_order":"little-endian"},
		{"id":"mem-vdp-vram","kind":"memory","device_instance":"VDP - VRAM","device_display":"VDP - VRAM","size_bytes":65536,"entry_size_bytes":1,"byte_order":"not-applicable"},
		{"id":"mem-vdp-cram","kind":"memory","device_instance":"VDP - CRAM","device_display":"VDP - CRAM","size_bytes":128,"entry_size_bytes":1,"byte_order":"not-applicable"},
		{"id":"mem-unknown-thing","kind":"memory","device_instance":"Mystery","device_display":"Mystery","size_bytes":1024,"entry_size_bytes":1,"byte_order":"not-applicable"}
	]}`
}
