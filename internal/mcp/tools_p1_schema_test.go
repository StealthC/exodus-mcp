package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// ----------------------------------------------------------------------------------------------------------------------
// P1 Schema and response contract hardening — acceptance fixtures
// ----------------------------------------------------------------------------------------------------------------------

func TestAddressSchemaOneOfAndNested(t *testing.T) {
	for _, spec := range toolRegistry {
		props, ok := spec.schema["properties"].(map[string]any)
		if !ok {
			continue
		}
		for fieldName, rawProp := range props {
			prop, ok := rawProp.(map[string]any)
			if !ok {
				continue
			}
			// Top-level address fields use addressProperty() which is oneOf.
			// Check all fields that should be address-typed.
			isAddressField := fieldName == "address" || fieldName == "range_end" || fieldName == "region_start" || fieldName == "region_end" || fieldName == "start_address"
			if !isAddressField {
				continue
			}
			if _, hasOneOf := prop["oneOf"]; !hasOneOf {
				t.Fatalf("tool %q field %q must use oneOf address schema, got %v", spec.name, fieldName, prop)
			}
			oneOf, _ := prop["oneOf"].([]map[string]any)
			if len(oneOf) != 2 {
				t.Fatalf("tool %q field %q oneOf must have 2 branches, got %v", spec.name, fieldName, prop)
			}
			hasInteger, hasString := false, false
			for _, branch := range oneOf {
				if branch["type"] == "integer" {
					hasInteger = true
					if branch["minimum"] != 0 {
						t.Fatalf("tool %q integer branch must have minimum 0", spec.name)
					}
				}
				if branch["type"] == "string" {
					hasString = true
					if _, hasPattern := branch["pattern"]; !hasPattern {
						t.Fatalf("tool %q string branch must have pattern", spec.name)
					}
				}
			}
			if !hasInteger || !hasString {
				t.Fatalf("tool %q field %q oneOf missing integer/string branch", spec.name, fieldName)
			}
		}
	}
	// Check nested address in symbols_set and memory_snapshot_capture.
	for _, spec := range toolRegistry {
		if spec.name == "symbols_set" {
			symbolsProp := spec.schema["properties"].(map[string]any)["symbols"].(map[string]any)
			items := symbolsProp["items"].(map[string]any)
			if items["additionalProperties"] != false {
				t.Fatalf("symbols_set items must have additionalProperties:false")
			}
			addrProp := items["properties"].(map[string]any)["address"].(map[string]any)
			if _, ok := addrProp["oneOf"]; !ok {
				t.Fatalf("symbols_set nested address must use oneOf")
			}
		}
		if spec.name == "memory_snapshot_capture" {
			rangesProp := spec.schema["properties"].(map[string]any)["ranges"].(map[string]any)
			items := rangesProp["items"].(map[string]any)
			if items["additionalProperties"] != false {
				t.Fatalf("memory_snapshot_capture ranges items must have additionalProperties:false")
			}
			addrProp := items["properties"].(map[string]any)["address"].(map[string]any)
			if _, ok := addrProp["oneOf"]; !ok {
				t.Fatalf("memory_snapshot_capture nested address must use oneOf")
			}
		}
	}
	// Top-level schemas must have additionalProperties:false
	for _, spec := range toolRegistry {
		if ap, ok := spec.schema["additionalProperties"]; !ok || ap != false {
			t.Fatalf("tool %q schema must have additionalProperties:false, got %v", spec.name, spec.schema)
		}
	}
}

func TestStrictDecodingRejectsTypoWithPath(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		return json.RawMessage(`{"data":"AQIDBA==","byte_order":"big-endian","effective_address":0,"consistency":"live","system_paused_during_read":false}`), nil
	}
	server := newTestServer(t, client)

	cases := []struct {
		tool      string
		args      string
		wantField string
		wantPath  string
	}{
		{"memory_read", `{"space":"m68k-ram","adress":0,"length":4}`, "adress", "$.adress"},
		{"memory_read", `{"space":"m68k-ram","address":0,"length":4,"unknown_field":123}`, "unknown_field", "$.unknown_field"},
		{"memory_read", `{"space":"m68k-ram","address":0,"length":4,"decode":{"type":"u16","typo":"big-endian"}}`, "typo", "$.decode.typo"},
		{"symbols_set", `{"symbols":[{"nane":"x","address":0}]}`, "nane", "$.symbols[0].nane"},
		{"memory_snapshot_capture", `{"space":"m68k-bus","ranges":[{"name":"a","adress":0,"length":4}]}`, "adress", "$.ranges[0].adress"},
	}
	for _, tc := range cases {
		result := postToolCall(t, server, tc.tool, tc.args)
		if result["isError"] != true {
			t.Fatalf("tool %q args %s must be rejected", tc.tool, tc.args)
		}
		sc := structured(result)
		if sc["code"] != "invalid_params" {
			t.Fatalf("tool %q expected invalid_params, got %v", tc.tool, sc)
		}
		msg, _ := sc["message"].(string)
		if !strings.Contains(msg, tc.wantField) || !strings.Contains(msg, tc.wantPath) {
			t.Fatalf("tool %q message must contain field %q and path %q, got %q", tc.tool, tc.wantField, tc.wantPath, msg)
		}
		if path, _ := sc["path"].(string); path != tc.wantPath {
			t.Fatalf("tool %q expected path %q, got %q", tc.tool, tc.wantPath, path)
		}
	}
	// Valid address forms must be accepted (decoding succeeds, bridge may be called).
	validForms := []string{
		`{"space":"m68k-ram","address":4096,"length":4}`,
		`{"space":"m68k-ram","address":"0x1000","length":4}`,
		`{"space":"m68k-ram","address":"$2000","length":4}`,
		`{"space":"m68k-ram","address":"C000h","length":4}`,
		`{"space":"m68k-ram","address":"4660","length":4}`,
	}
	for _, args := range validForms {
		result := postToolCall(t, server, "memory_read", args)
		if result["isError"] == true {
			t.Fatalf("valid address form %s rejected: %v", args, structured(result))
		}
	}
	// Globally allowed fields must not be rejected.
	result := postToolCall(t, server, "memory_read", `{"space":"m68k-ram","address":0,"length":4,"control_id":"abc","expected_target_generation":1}`)
	if result["isError"] == true {
		t.Fatalf("globally allowed control_id must not be rejected: %v", structured(result))
	}
}

func TestCanonicalAddressAndArtifactShapes(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "mem_read":
			return json.RawMessage(memReadPayload([]byte{1, 2, 3, 4}, "big-endian", 0x100)), nil
		case "disasm":
			return json.RawMessage(`{"cpu":"m68k","start_address":256,"requested_count":1,"lines":[{"address":256,"length":2,"bytes":"4E71","mnemonic":"nop","operands":""}]}`), nil
		default:
			return json.RawMessage(`{}`), nil
		}
	}
	server := newTestServer(t, client)

	// memory_read canonical
	result := postToolCall(t, server, "memory_read", `{"space":"m68k-ram","address":256,"length":4}`)
	sc := structured(result)
	if sc["address"] != float64(256) || sc["address_hex"] != "0x000100" || sc["address_space"] != "m68k-ram" || sc["effective_address_hex"] != "0x000100" {
		t.Fatalf("memory_read canonical fields wrong: %v", sc)
	}
	if sc["address_width_bits"] != float64(24) || sc["address_mask_hex"] != "0xFFFFFF" {
		t.Fatalf("memory_read bus width/mask wrong: %v", sc)
	}
	if sc["result_type"] != "memory_read" || sc["schema_version"] != "1" {
		t.Fatalf("memory_read result_type/schema_version missing: %v", sc)
	}
	if _, ok := sc["structuredContent"]; ok {
		t.Fatalf("structuredContent should not be nested")
	}

	// symbols_list canonical
	postToolCall(t, server, "symbols_set", `{"symbols":[{"name":"test","space_id":"m68k-bus","address":"0x100"}]}`)
	listResult := postToolCall(t, server, "symbols_list", `{}`)
	symbols := structured(listResult)["symbols"].([]any)
	first := symbols[0].(map[string]any)
	if first["address_hex"] != "0x000100" || first["address_space"] != "m68k-bus" {
		t.Fatalf("symbols_list canonical wrong: %v", first)
	}

	// disassembly canonical
	disResult := postToolCall(t, server, "m68k_disassemble", `{"address":256,"count":1}`)
	disSc := structured(disResult)
	if disSc["start_address_hex"] != "0x000100" || disSc["address_space"] != "m68k-bus" || disSc["address_width_bits"] != float64(24) {
		t.Fatalf("disasm canonical wrong: %v", disSc)
	}
	lines := disSc["lines"].([]any)
	line := lines[0].(map[string]any)
	if line["address_hex"] != "0x000100" || line["address_space"] != "m68k-bus" {
		t.Fatalf("disasm line canonical wrong: %v", line)
	}

	// memory_dump artifact shape
	dumpResult := postToolCall(t, server, "memory_dump", `{"space":"m68k-ram","address":256,"length":4}`)
	dumpSc := structured(dumpResult)
	if dumpSc["result_type"] != "memory_dump" || dumpSc["schema_version"] != "1" {
		t.Fatalf("memory_dump result_type missing: %v", dumpSc)
	}
	summary := dumpSc["summary"].(map[string]any)
	if summary["start_address_hex"] != "0x000100" || summary["address_space"] != "m68k-ram" {
		t.Fatalf("memory_dump summary canonical wrong: %v", summary)
	}
	artifactDesc := dumpSc["artifact"].(map[string]any)
	for _, key := range []string{"id", "kind", "mime_type", "size_bytes", "sha256", "url", "resource_uri", "provenance", "provenance_state"} {
		if _, ok := artifactDesc[key]; !ok {
			t.Fatalf("artifact descriptor missing %s: %v", key, artifactDesc)
		}
	}

	// vdp tile export artifacts array
	vram := make([]byte, 65536)
	cram := make([]byte, 128)
	tileClient := newFakeVDPMemoryClient(vram, cram)
	tileServer := newTestServer(t, tileClient)
	tileResult := postToolCall(t, tileServer, "vdp_tile_export", `{"tile":0,"count":1}`)
	tileSc := structured(tileResult)
	if tileSc["result_type"] != "vdp_tile_export" {
		t.Fatalf("tile export result_type missing")
	}
	tileSummary := tileSc["summary"].(map[string]any)
	if tileSummary["vram_address_start_hex"] != "0x000000" || tileSummary["address_space"] != "315-5313 VRAM" {
		t.Fatalf("tile export canonical wrong: %v", tileSummary)
	}
	artifacts, ok := tileSc["artifacts"].([]any)
	if !ok || len(artifacts) != 2 {
		t.Fatalf("tile export artifacts wrong: %v", tileSc)
	}
	for _, a := range artifacts {
		desc := a.(map[string]any)
		for _, key := range []string{"id", "mime_type", "size_bytes", "sha256", "url", "resource_uri", "provenance"} {
			if _, ok := desc[key]; !ok {
				t.Fatalf("tile artifact missing %s: %v", key, desc)
			}
		}
	}

	// memory_snapshot_capture artifacts normalization
	capClient := &fakeBridgeClient{status: newFakeStatus()}
	capClient.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method == "cpu_control" {
			return json.RawMessage(`{"system_running":false}`), nil
		}
		return json.RawMessage(memReadPayload([]byte{1, 2, 3, 4}, "big-endian", 0)), nil
	}
	capServer := newTestServer(t, capClient)
	capResult := postToolCall(t, capServer, "memory_snapshot_capture", `{"space":"m68k-bus","ranges":[{"name":"a","address":0,"length":4}]}`)
	capSc := structured(capResult)
	if _, ok := capSc["artifacts"].([]any); !ok {
		t.Fatalf("memory_snapshot_capture must have artifacts array: %v", capSc)
	}
	if len(capSc["artifacts"].([]any)) != 2 {
		t.Fatalf("memory_snapshot_capture artifacts count wrong: %v", capSc["artifacts"])
	}
}

func TestSpaceCapabilitiesDistinguishTypes(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		return json.RawMessage(memSpacesPayload()), nil
	}
	result := callTool(t, client, "memory_spaces_list", `{}`)
	content := structured(result)
	spaces := content["spaces"].([]any)
	byID := map[string]map[string]any{}
	for _, entry := range spaces {
		space := entry.(map[string]any)
		byID[space["id"].(string)] = space
	}
	// RAM must be read+write
	ram := byID["mem-ram"]
	if perms, _ := ram["permissions"].([]any); len(perms) != 2 || perms[0] != "read" || perms[1] != "write" {
		t.Fatalf("mem-ram permissions wrong: %v", ram["permissions"])
	}
	// ROM read-only
	if _, ok := byID["mem-rom"]; ok {
		// mem-rom not in our fixture, but we test the logic via synthetic payload
	}
	// Create synthetic payload with mem-rom
	syntheticPayload := `{"spaces":[
		{"id":"mem-rom","kind":"memory","device_instance":"ROM","device_display":"ROM","size_bytes":4194304,"entry_size_bytes":2,"byte_order":"big-endian"},
		{"id":"mem-vdp-vram","kind":"memory","device_instance":"VDP - VRAM","device_display":"VDP - VRAM","size_bytes":65536,"entry_size_bytes":1,"byte_order":"not-applicable"},
		{"id":"m68k-bus","kind":"bus","device_instance":"Main 68000","device_display":"Main 68000","size_bytes":16777216,"entry_size_bytes":1,"byte_order":"big-endian"}
	]}`
	synClient := &fakeBridgeClient{status: newFakeStatus()}
	synClient.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		return json.RawMessage(syntheticPayload), nil
	}
	synResult := callTool(t, synClient, "memory_spaces_list", `{}`)
	synContent := structured(synResult)
	synSpaces := synContent["spaces"].([]any)
	synByID := map[string]map[string]any{}
	for _, entry := range synSpaces {
		space := entry.(map[string]any)
		synByID[space["id"].(string)] = space
	}
	romPerms := synByID["mem-rom"]["permissions"].([]any)
	if len(romPerms) != 1 || romPerms[0] != "read" {
		t.Fatalf("mem-rom must be read-only, got %v", romPerms)
	}
	vramPerms := synByID["mem-vdp-vram"]["permissions"].([]any)
	if len(vramPerms) != 1 || vramPerms[0] != "read" {
		t.Fatalf("mem-vdp-vram must be read-only, got %v", vramPerms)
	}
	busPerms := synByID["m68k-bus"]["permissions"].([]any)
	if len(busPerms) != 2 {
		t.Fatalf("m68k-bus must be read+write, got %v", busPerms)
	}
	// Check bus mapping still present
	if synByID["mem-vdp-vram"]["bus_mapping_note"] == nil || !strings.Contains(synByID["mem-vdp-vram"]["bus_mapping_note"].(string), "not linearly mapped") {
		t.Fatalf("VDP bus_mapping_note wrong")
	}
}
