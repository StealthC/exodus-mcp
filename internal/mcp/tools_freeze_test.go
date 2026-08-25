package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/StealthC/exodus-mcp/internal/bridge"
)

// freezeWriteClient records mem_write params for freeze lifecycle tests.
func freezeWriteClient() *fakeBridgeClient {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "mem_write":
			return json.RawMessage(`{"space_id":"m68k-bus","address":16776222,"length":6}`), nil
		case "rom_load":
			return json.RawMessage(`{"loaded":true,"system_running":false}`), nil
		default:
			return nil, fmt.Errorf("unexpected method %s", method)
		}
	}
	return client
}

func freezeData(d byte) string {
	return base64.StdEncoding.EncodeToString([]byte{0x00, d, 0x00, d, 0x00, d})
}

func TestMemoryFreezeLifecycle(t *testing.T) {
	client := freezeWriteClient()
	server := newTestServer(t, client)
	lease := structured(postToolCall(t, server, "context_lease_acquire", `{"purpose":"freeze test"}`))
	leaseID := lease["lease_id"].(string)

	set := structured(postToolCall(t, server, "memory_freeze", fmt.Sprintf(`{"lease_id":%q,"space":"m68k-bus","address":"0xFFFC1E","data":%q}`, leaseID, freezeData(0x05))))
	if set["code"] != nil {
		t.Fatalf("freeze failed: %v", set)
	}
	freezeID := set["freeze_id"].(string)
	if freezeID == "" || set["replaced"] != false || set["byte_length"] != float64(6) {
		t.Fatalf("freeze entry wrong: %v", set)
	}

	// Creating the entry applies the bytes once immediately.
	if got := countCalls(client, "mem_write"); got != 1 {
		t.Fatalf("creation should write once, got %d mem_write calls", got)
	}

	// The sweeper re-applies the range at tick cadence.
	server.applyFreezes()
	server.applyFreezes()
	listed := structured(postToolCall(t, server, "memory_freeze_list", `{}`))
	freezes := listed["freezes"].([]any)
	if len(freezes) != 1 {
		t.Fatalf("freeze_list = %v", freezes)
	}
	entry := freezes[0].(map[string]any)
	if entry["freeze_id"] != freezeID || entry["write_count"] != float64(2) || entry["byte_length"] != float64(6) {
		t.Fatalf("entry view wrong: %v", entry)
	}
	if got := countCalls(client, "mem_write"); got != 3 {
		t.Fatalf("two sweeps should add two writes, got %d total", got)
	}

	// Replacing at the same space+address updates the pinned bytes.
	set2 := structured(postToolCall(t, server, "memory_freeze", fmt.Sprintf(`{"lease_id":%q,"space":"m68k-bus","address":16776222,"data":%q}`, leaseID, freezeData(0x07))))
	if set2["replaced"] != true || set2["freeze_id"] != freezeID {
		t.Fatalf("replace must keep the entry id: %v", set2)
	}
	listed = structured(postToolCall(t, server, "memory_freeze_list", `{}`))
	if len(listed["freezes"].([]any)) != 1 {
		t.Fatalf("replace must not grow the set: %v", listed)
	}

	// Removal stops the re-writes.
	removed := structured(postToolCall(t, server, "memory_freeze_remove", fmt.Sprintf(`{"lease_id":%q,"freeze_id":%q}`, leaseID, freezeID)))
	if removed["removed"] != true {
		t.Fatalf("remove failed: %v", removed)
	}
	before := countCalls(client, "mem_write")
	server.applyFreezes()
	if after := countCalls(client, "mem_write"); after != before {
		t.Fatalf("removed freeze must not write again (%d -> %d)", before, after)
	}
	listed = structured(postToolCall(t, server, "memory_freeze_list", `{}`))
	if listed["freezes_total"] != float64(0) {
		t.Fatalf("list must be empty after removal: %v", listed)
	}

	// The mutation log recorded both actions.
	log := structured(postToolCall(t, server, "context_mutation_log", `{}`))
	entries := log["entries"].([]any)
	tools := map[string]bool{}
	for _, e := range entries {
		tools[e.(map[string]any)["tool"].(string)] = true
	}
	if !tools["memory_freeze"] || !tools["memory_freeze_remove"] {
		t.Fatalf("mutation log missing freeze entries: %v", entries)
	}
}

func TestMemoryFreezeValidation(t *testing.T) {
	client := freezeWriteClient()
	server := newTestServer(t, client)
	lease := structured(postToolCall(t, server, "context_lease_acquire", `{"purpose":"freeze validation"}`))
	leaseID := lease["lease_id"].(string)

	good := fmt.Sprintf(`{"lease_id":%q,"space":"m68k-bus","address":0,"data":%q}`, leaseID, freezeData(0x05))
	for _, tc := range []struct {
		name      string
		arguments string
		code      string
	}{
		{"missing lease", `{"space":"m68k-bus","address":0,"data":"AAU="}`, "lease_required"},
		{"empty space", fmt.Sprintf(`{"lease_id":%q,"address":0,"data":"AAU="}`, leaseID), "invalid_params"},
		{"bad data", fmt.Sprintf(`{"lease_id":%q,"space":"m68k-bus","address":0,"data":"not base64!!"}`, leaseID), "invalid_params"},
		{"empty data", fmt.Sprintf(`{"lease_id":%q,"space":"m68k-bus","address":0,"data":""}`, leaseID), "invalid_params"},
		{"bad address", fmt.Sprintf(`{"lease_id":%q,"space":"m68k-bus","address":"zzz","data":"AAU="}`, leaseID), "invalid_params"},
	} {
		result := structured(postToolCall(t, server, "memory_freeze", tc.arguments))
		if result["code"] != tc.code {
			t.Fatalf("%s: code = %v (%v)", tc.name, result["code"], result)
		}
	}

	// Creating the freeze applies the pinned bytes immediately.
	if result := structured(postToolCall(t, server, "memory_freeze", good)); result["code"] != nil {
		t.Fatalf("valid freeze rejected: %v", result)
	}

	// Remove with a missing or wrong lease is rejected.
	removeNoLease := structured(postToolCall(t, server, "memory_freeze_remove", `{"freeze_id":"frz_x"}`))
	if removeNoLease["code"] != "lease_required" {
		t.Fatalf("remove without lease must fail: %v", removeNoLease)
	}
	removeUnknown := structured(postToolCall(t, server, "memory_freeze_remove", fmt.Sprintf(`{"lease_id":%q,"freeze_id":"frz_missing"}`, leaseID)))
	if removeUnknown["code"] != "unknown_freeze" {
		t.Fatalf("remove of unknown entry must fail: %v", removeUnknown)
	}
}

func TestMemoryFreezeSurfacesWriteErrors(t *testing.T) {
	client := freezeWriteClient()
	server := newTestServer(t, client)
	lease := structured(postToolCall(t, server, "context_lease_acquire", `{"purpose":"freeze errors"}`))
	leaseID := lease["lease_id"].(string)

	// Freeze registers fine; afterwards the periodic re-write starts failing.
	set := structured(postToolCall(t, server, "memory_freeze", fmt.Sprintf(`{"lease_id":%q,"space":"m68k-bus","address":0,"data":%q}`, leaseID, freezeData(0x05))))
	if set["code"] != nil {
		t.Fatalf("freeze failed: %v", set)
	}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		return nil, &bridge.CommandError{Code: "unknown_space", Message: "space gone"}
	}
	server.applyFreezes()
	listed := structured(postToolCall(t, server, "memory_freeze_list", `{}`))
	entry := listed["freezes"].([]any)[0].(map[string]any)
	if entry["write_count"] != float64(0) || entry["last_error"] != "unknown_space: space gone" {
		t.Fatalf("write error not surfaced: %v", entry)
	}
}

func TestMemoryFreezePurgedOnROMLoad(t *testing.T) {
	client := freezeWriteClient()
	server := newTestServer(t, client)
	lease := structured(postToolCall(t, server, "context_lease_acquire", `{"purpose":"freeze purge"}`))
	leaseID := lease["lease_id"].(string)

	set := structured(postToolCall(t, server, "memory_freeze", fmt.Sprintf(`{"lease_id":%q,"space":"m68k-bus","address":0,"data":%q}`, leaseID, freezeData(0x05))))
	if set["code"] != nil {
		t.Fatalf("freeze failed: %v", set)
	}
	loaded := structured(postToolCall(t, server, "rom_load", `{"path":"F:\\roms\\other.bin","run":false}`))
	if loaded["freezes_purged"] != float64(1) {
		t.Fatalf("rom_load must report the purge: %v", loaded)
	}
	listed := structured(postToolCall(t, server, "memory_freeze_list", `{}`))
	if listed["freezes_total"] != float64(0) {
		t.Fatalf("freezes must be purged on rom_load: %v", listed)
	}
	before := countCalls(client, "mem_write")
	server.applyFreezes()
	if after := countCalls(client, "mem_write"); after != before {
		t.Fatalf("purged freeze must not write again (%d -> %d)", before, after)
	}
}

func TestMemoryFreezeLimit(t *testing.T) {
	client := freezeWriteClient()
	server := newTestServer(t, client)
	lease := structured(postToolCall(t, server, "context_lease_acquire", `{"purpose":"freeze limit"}`))
	leaseID := lease["lease_id"].(string)

	for index := 0; index < freezeMaxEntries; index++ {
		result := structured(postToolCall(t, server, "memory_freeze", fmt.Sprintf(`{"lease_id":%q,"space":"m68k-bus","address":%d,"data":%q}`, leaseID, index*2, freezeData(0x05))))
		if result["code"] != nil {
			t.Fatalf("entry %d failed: %v", index, result)
		}
	}
	over := structured(postToolCall(t, server, "memory_freeze", fmt.Sprintf(`{"lease_id":%q,"space":"m68k-bus","address":4096,"data":%q}`, leaseID, freezeData(0x05))))
	if over["code"] != "freeze_limit" {
		t.Fatalf("expected freeze_limit, got %v", over)
	}
}

func TestMemoryFreezeClear(t *testing.T) {
	client := freezeWriteClient()
	server := newTestServer(t, client)
	lease := structured(postToolCall(t, server, "context_lease_acquire", `{"purpose":"freeze clear"}`))
	leaseID := lease["lease_id"].(string)

	// Clear without a lease is rejected.
	noLease := structured(postToolCall(t, server, "memory_freeze_clear", `{}`))
	if noLease["code"] != "lease_required" {
		t.Fatalf("clear without lease must fail: %v", noLease)
	}

	for index := 0; index < 3; index++ {
		result := structured(postToolCall(t, server, "memory_freeze", fmt.Sprintf(`{"lease_id":%q,"space":"m68k-bus","address":%d,"data":%q}`, leaseID, index*2, freezeData(0x05))))
		if result["code"] != nil {
			t.Fatalf("entry %d failed: %v", index, result)
		}
	}
	listed := structured(postToolCall(t, server, "memory_freeze_list", `{}`))
	if listed["freezes_total"] != float64(3) {
		t.Fatalf("expected 3 entries before clear: %v", listed)
	}

	cleared := structured(postToolCall(t, server, "memory_freeze_clear", fmt.Sprintf(`{"lease_id":%q}`, leaseID)))
	if cleared["removed"] != float64(3) || cleared["freezes_total"] != float64(0) {
		t.Fatalf("clear result wrong: %v", cleared)
	}
	listed = structured(postToolCall(t, server, "memory_freeze_list", `{}`))
	if listed["freezes_total"] != float64(0) {
		t.Fatalf("list must be empty after clear: %v", listed)
	}
	before := countCalls(client, "mem_write")
	server.applyFreezes()
	if after := countCalls(client, "mem_write"); after != before {
		t.Fatalf("cleared freezes must not write again (%d -> %d)", before, after)
	}

	// Clearing an already-empty set is a harmless no-op reporting zero.
	clearedAgain := structured(postToolCall(t, server, "memory_freeze_clear", fmt.Sprintf(`{"lease_id":%q}`, leaseID)))
	if clearedAgain["removed"] != float64(0) {
		t.Fatalf("second clear must report zero: %v", clearedAgain)
	}

	log := structured(postToolCall(t, server, "context_mutation_log", `{}`))
	entries := log["entries"].([]any)
	tools := map[string]bool{}
	for _, e := range entries {
		tools[e.(map[string]any)["tool"].(string)] = true
	}
	if !tools["memory_freeze_clear"] {
		t.Fatalf("mutation log missing memory_freeze_clear: %v", entries)
	}
}
