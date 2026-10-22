package mcp

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"testing"
)

// ----------------------------------------------------------------------------------------------------------------------
// memory_write space permissions (issue #7): the permissions memory_spaces_list
// reports are authoritative for the write path.
// ----------------------------------------------------------------------------------------------------------------------

// memWritePolicySpacesPayload is a Mega Drive catalog covering every space
// class the write policy distinguishes: bus spaces, read+write memory devices,
// the loaded cartridge images, the timed-buffer VDP shells, and an unknown
// read+write device that must inherit the default.
func memWritePolicySpacesPayload() string {
	return `{"spaces":[
		{"id":"m68k-bus","kind":"bus","device_instance":"Main 68000","device_display":"Main 68000","size_bytes":16777216,"entry_size_bytes":1,"byte_order":"big-endian"},
		{"id":"z80-bus","kind":"bus","device_instance":"Z80","device_display":"Z80","size_bytes":65536,"entry_size_bytes":1,"byte_order":"little-endian"},
		{"id":"mem-ram","kind":"memory","device_instance":"RAM","device_display":"RAM","size_bytes":65536,"entry_size_bytes":2,"byte_order":"big-endian"},
		{"id":"mem-z80-ram","kind":"memory","device_instance":"Z80 RAM","device_display":"Z80 RAM","size_bytes":8192,"entry_size_bytes":1,"byte_order":"not-applicable"},
		{"id":"mem-sram-cart","kind":"memory","device_instance":"Cartridge SRAM","device_display":"Cartridge SRAM","size_bytes":32768,"entry_size_bytes":1,"byte_order":"not-applicable"},
		{"id":"mem-rom","kind":"memory","device_instance":"ROM","device_display":"ROM","size_bytes":4194304,"entry_size_bytes":2,"byte_order":"big-endian"},
		{"id":"mem-boot-rom","kind":"memory","device_instance":"Boot ROM","device_display":"Boot ROM","size_bytes":2048,"entry_size_bytes":1,"byte_order":"not-applicable"},
		{"id":"mem-vdp-vram","kind":"memory","device_instance":"VDP - VRAM","device_display":"VDP - VRAM","size_bytes":65536,"entry_size_bytes":1,"byte_order":"not-applicable"},
		{"id":"mem-vdp-cram","kind":"memory","device_instance":"VDP - CRAM","device_display":"VDP - CRAM","size_bytes":128,"entry_size_bytes":1,"byte_order":"not-applicable"}
	]}`
}

// memWritePolicyClient serves the space catalog and echoes mem_write, so a test
// can assert both what memory_spaces_list reports and whether a write ever
// reached the bridge.
func memWritePolicyClient(t *testing.T, spaces string) *fakeBridgeClient {
	t.Helper()
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "mem_spaces":
			return json.RawMessage(spaces), nil
		case "mem_write":
			address := params["address"]
			payload := fmt.Sprintf(`{"space_id":%q,"kind":"memory","address":%s,"effective_address":%s,"length":1,"byte_order":"big-endian","encoding":"base64","consistency":"live","written":"AA==","system_paused_during_write":false}`,
				params["space"], address, address)
			return json.RawMessage(payload), nil
		default:
			return nil, fmt.Errorf("unexpected method %s", method)
		}
	}
	return client
}

// TestMemoryWriteRejectsReadOnlySpaceByID proves a write addressed directly at a
// read-only space id is refused before any native write, without a state change.
func TestMemoryWriteRejectsReadOnlySpaceByID(t *testing.T) {
	for _, test := range []struct {
		space  string
		reason string
	}{
		{space: "mem-rom", reason: "read_only_image"},
		{space: "mem-boot-rom", reason: "read_only_image"},
		{space: "mem-vdp-vram", reason: "timed_buffer_device"},
	} {
		client := memWritePolicyClient(t, memWritePolicySpacesPayload())
		server := newTestServer(t, client)

		result := postToolCall(t, server, "memory_write", `{"space":"`+test.space+`","address":0,"data":"AA=="}`)
		content := structured(result)
		if result["isError"] != true || content["code"] != "write_not_supported" {
			t.Fatalf("%s: expected write_not_supported, got %v", test.space, content)
		}
		if content["space"] != test.space || content["reason"] != test.reason {
			t.Fatalf("%s: refusal must name the space and reason: %v", test.space, content)
		}
		permissions, _ := content["permissions"].([]any)
		if len(permissions) != 1 || permissions[0] != "read" {
			t.Fatalf("%s: refusal must echo the reported permissions: %v", test.space, content)
		}
		if content["note"] == nil {
			t.Fatalf("%s: refusal must explain the bus alternative: %v", test.space, content)
		}
		if calls := countCalls(client, "mem_write"); calls != 0 {
			t.Fatalf("%s: a refused write must never reach the bridge, got %d calls", test.space, calls)
		}

		// No state change: the next successful mutation still starts at the
		// generation the refusal observed.
		writable := postToolCall(t, server, "memory_write", `{"space":"m68k-bus","address":0,"data":"AA=="}`)
		writableContent := structured(writable)
		if writable["isError"] == true {
			t.Fatalf("%s: the follow-up writable write failed: %v", test.space, writableContent)
		}
		if writableContent["target_generation_before"] != float64(1) {
			t.Fatalf("%s: the refused write advanced the target generation: %v", test.space, writableContent)
		}

		// The attempt is still audited, so a caller can prove it was rejected
		// rather than silently dropped.
		log := structured(postToolCall(t, server, "target_audit_log", `{}`))
		refusals := 0
		for _, raw := range log["entries"].([]any) {
			entry := raw.(map[string]any)
			failure, _ := entry["failure"].(map[string]any)
			if entry["tool"] == "memory_write" && entry["outcome"] == "failed" && failure["code"] == "write_not_supported" {
				refusals++
			}
		}
		if refusals != 1 {
			t.Fatalf("%s: the refused write must be audited once, got %v", test.space, log["entries"])
		}
	}
}

// TestMemoryWriteThroughBusKeepsHardwareDiscard proves the documented bus
// behavior is unchanged: a write addressed through m68k-bus at a cartridge
// address succeeds, the cartridge ignores it, and the reported ROM identity
// stays consistent.
func TestMemoryWriteThroughBusKeepsHardwareDiscard(t *testing.T) {
	body := make([]byte, 0x600)
	for index := range body {
		body[index] = byte(index * 5)
	}
	fixture := buildMDROMFixture(body)
	binary.BigEndian.PutUint16(fixture.Header[0x8E:0x90], computeSegaChecksum(body))
	client, _ := writeFixtureROM(t, fixture, 0)

	var busWrites []map[string]string
	served := client.executeFunc
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method == "mem_write" {
			busWrites = append(busWrites, params)
			// The cartridge ignores the write: the bus reports the write
			// completed and the image behind it is untouched.
			return json.RawMessage(`{"space_id":"m68k-bus","kind":"bus","address":0,"effective_address":0,"length":2,"byte_order":"big-endian","encoding":"base64","consistency":"live","written":"TnE=","system_paused_during_write":true}`), nil
		}
		return served(ctx, method, params)
	}
	server := newTestServer(t, client)

	before := structured(postToolCall(t, server, "rom_info", `{}`))["rom_identity"].(map[string]any)
	observedGeneration := before["target_generation"].(float64)

	write := postToolCall(t, server, "memory_write", `{"space":"m68k-bus","address":0,"data_hex":"4E 71"}`)
	writeContent := structured(write)
	if write["isError"] == true {
		t.Fatalf("a bus-addressed cartridge write must not fail: %v", writeContent)
	}
	if writeContent["target_generation_before"] != observedGeneration || writeContent["target_generation_after"] != observedGeneration+1 {
		t.Fatalf("the bus write must execute as a mutation: %v", writeContent)
	}
	if len(busWrites) != 1 || busWrites[0]["space"] != "m68k-bus" || busWrites[0]["address"] != "0" {
		t.Fatalf("the write must be addressed at the bus space, got %v", busWrites)
	}

	after := structured(postToolCall(t, server, "rom_info", `{}`))["rom_identity"].(map[string]any)
	for _, key := range []string{"rom_sha256", "rom_sha256_available", "size_bytes", "title", "serial", "header_identified", "mapped_image_base"} {
		if before[key] != after[key] {
			t.Fatalf("bus write changed the reported ROM identity field %s: before %v, after %v", key, before[key], after[key])
		}
	}
	beforeChecksum := before["checksum"].(map[string]any)
	afterChecksum := after["checksum"].(map[string]any)
	for _, key := range []string{"stored", "computed", "matches", "complete"} {
		if beforeChecksum[key] != afterChecksum[key] {
			t.Fatalf("bus write changed the reported ROM checksum field %s: before %v, after %v", key, beforeChecksum[key], afterChecksum[key])
		}
	}
}

// TestSpacePermissionsGovernMemoryWrite fails if the permissions
// memory_spaces_list reports and the enforcement memory_write applies ever
// disagree for any space in the catalog.
func TestSpacePermissionsGovernMemoryWrite(t *testing.T) {
	client := memWritePolicyClient(t, memWritePolicySpacesPayload())
	server := newTestServer(t, client)

	list := structured(postToolCall(t, server, "memory_spaces_list", `{}`))
	spaces := list["spaces"].([]any)
	if len(spaces) == 0 {
		t.Fatal("empty space catalog")
	}
	checked := 0
	for _, entry := range spaces {
		space := entry.(map[string]any)
		id := space["id"].(string)
		permissions, _ := space["permissions"].([]any)
		readable, writable := false, false
		for _, permission := range permissions {
			switch permission {
			case "read":
				readable = true
			case "write":
				writable = true
			}
		}
		if !readable {
			t.Fatalf("%s: every space must report read permission, got %v", id, permissions)
		}

		before := countCalls(client, "mem_write")
		result := postToolCall(t, server, "memory_write", `{"space":"`+id+`","address":0,"data":"AA=="}`)
		after := countCalls(client, "mem_write")
		content := structured(result)

		if writable {
			if result["isError"] == true {
				t.Fatalf("%s: permissions say writable but memory_write refused it: %v", id, content)
			}
			if after != before+1 {
				t.Fatalf("%s: permissions say writable but the write never reached the bridge", id)
			}
		} else {
			if result["isError"] != true || content["code"] != "write_not_supported" {
				t.Fatalf("%s: permissions say read-only but memory_write allowed it: %v", id, content)
			}
			if after != before {
				t.Fatalf("%s: a read-only space must never reach the bridge", id)
			}
			if content["reason"] == nil || content["reason"] == "" {
				t.Fatalf("%s: a refusal must carry the stable reason: %v", id, content)
			}
			refusalPermissions, _ := content["permissions"].([]any)
			if len(refusalPermissions) != len(permissions) {
				t.Fatalf("%s: refusal permissions %v disagree with the catalog %v", id, refusalPermissions, permissions)
			}
		}
		checked++
	}
	for _, expected := range []string{"mem-rom", "mem-boot-rom", "mem-vdp-vram", "m68k-bus", "mem-sram-cart"} {
		found := false
		for _, entry := range spaces {
			if entry.(map[string]any)["id"] == expected {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("catalog fixture lost %s; the consistency check would silently narrow", expected)
		}
	}
	if checked != len(spaces) {
		t.Fatalf("checked %d of %d spaces", checked, len(spaces))
	}
}

// TestMemoryWritePermissionCheckKeepsGuardSemantics proves the shared
// precondition order is unchanged: a foreign control lock and a stale expected
// generation still report first, and only the holder's own call reaches the
// permission refusal.
func TestMemoryWritePermissionCheckKeepsGuardSemantics(t *testing.T) {
	client := memWritePolicyClient(t, memWritePolicySpacesPayload())
	server := newTestServer(t, client)
	lock := structured(postToolCall(t, server, "target_control_acquire", `{"purpose":"boss fight"}`))
	controlID, _ := lock["control_id"].(string)
	if controlID == "" {
		t.Fatalf("acquire returned no control id: %v", lock)
	}

	foreign := postToolCall(t, server, "memory_write", `{"space":"mem-rom","address":0,"data":"AA=="}`)
	if content := structured(foreign); foreign["isError"] != true || content["code"] != "target_control_held" {
		t.Fatalf("a foreign caller must still see the control lock first: %v", foreign)
	}

	held := postToolCall(t, server, "memory_write", `{"space":"mem-rom","address":0,"data":"AA==","control_id":"`+controlID+`"}`)
	if content := structured(held); held["isError"] != true || content["code"] != "write_not_supported" {
		t.Fatalf("the holder's read-only write must report the permission refusal: %v", held)
	}

	stale := postToolCall(t, server, "memory_write", `{"space":"mem-rom","address":0,"data":"AA==","control_id":"`+controlID+`","expected_target_generation":99}`)
	if content := structured(stale); stale["isError"] != true || content["code"] != "target_generation_conflict" {
		t.Fatalf("a stale generation must still report the conflict first: %v", stale)
	}

	if calls := countCalls(client, "mem_write"); calls != 0 {
		t.Fatalf("no guarded read-only write may reach the bridge, got %d", calls)
	}
}
