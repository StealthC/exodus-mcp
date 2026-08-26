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

	set := structured(postToolCall(t, server, "memory_freeze", fmt.Sprintf(`{"space":"m68k-bus","address":"0xFFFC1E","data":%q}`, freezeData(0x05))))
	if set["code"] != nil {
		t.Fatalf("freeze failed: %v", set)
	}
	freezeID := set["freeze_id"].(string)
	if freezeID == "" || set["replaced"] != false || set["byte_length"] != float64(6) {
		t.Fatalf("freeze entry wrong: %v", set)
	}
	// A freeze is a mutation: generations advance.
	if set["target_generation_before"] != float64(1) || set["target_generation_after"] != float64(2) {
		t.Fatalf("freeze generations wrong: %v", set)
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
	// Provenance is recorded on the entry.
	if entry["context_id"] == "" || entry["target_generation"] != float64(2) {
		t.Fatalf("entry provenance missing: %v", entry)
	}
	if got := countCalls(client, "mem_write"); got != 3 {
		t.Fatalf("two sweeps should add two writes, got %d total", got)
	}

	// Replacing at the same space+address updates the pinned bytes.
	set2 := structured(postToolCall(t, server, "memory_freeze", fmt.Sprintf(`{"space":"m68k-bus","address":16776222,"data":%q}`, freezeData(0x07))))
	if set2["replaced"] != true || set2["freeze_id"] != freezeID {
		t.Fatalf("replace must keep the entry id: %v", set2)
	}
	listed = structured(postToolCall(t, server, "memory_freeze_list", `{}`))
	if len(listed["freezes"].([]any)) != 1 {
		t.Fatalf("replace must not grow the set: %v", listed)
	}

	// Removal stops the re-writes.
	removed := structured(postToolCall(t, server, "memory_freeze_remove", fmt.Sprintf(`{"freeze_id":%q}`, freezeID)))
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

	good := fmt.Sprintf(`{"space":"m68k-bus","address":0,"data":%q}`, freezeData(0x05))
	for _, tc := range []struct {
		name      string
		arguments string
		code      string
	}{
		{"empty space", `{"address":0,"data":"AAU="}`, "invalid_params"},
		{"bad data", `{"space":"m68k-bus","address":0,"data":"not base64!!"}`, "invalid_params"},
		{"empty data", `{"space":"m68k-bus","address":0,"data":""}`, "invalid_params"},
		{"bad address", `{"space":"m68k-bus","address":"zzz","data":"AAU="}`, "invalid_params"},
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

	// A stale expected generation is rejected before any native write.
	stale := structured(postToolCall(t, server, "memory_freeze", fmt.Sprintf(`{"space":"m68k-bus","address":8,"data":%q,"expected_target_generation":1}`, freezeData(0x05))))
	if stale["code"] != "target_generation_conflict" {
		t.Fatalf("stale freeze must conflict: %v", stale)
	}
	if got := countCalls(client, "mem_write"); got != 1 {
		t.Fatalf("conflicted freeze must not write: %v calls", got)
	}

	// Remove of an unknown entry fails.
	removeUnknown := structured(postToolCall(t, server, "memory_freeze_remove", `{"freeze_id":"frz_missing"}`))
	if removeUnknown["code"] != "unknown_freeze" {
		t.Fatalf("remove of unknown entry must fail: %v", removeUnknown)
	}
}

func TestMemoryFreezeSurfacesWriteErrors(t *testing.T) {
	client := freezeWriteClient()
	server := newTestServer(t, client)

	// Freeze registers fine; afterwards the periodic re-write starts failing.
	set := structured(postToolCall(t, server, "memory_freeze", fmt.Sprintf(`{"space":"m68k-bus","address":0,"data":%q}`, freezeData(0x05))))
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

	set := structured(postToolCall(t, server, "memory_freeze", fmt.Sprintf(`{"space":"m68k-bus","address":0,"data":%q}`, freezeData(0x05))))
	if set["code"] != nil {
		t.Fatalf("freeze failed: %v", set)
	}
	freezeID := set["freeze_id"].(string)
	loaded := structured(postToolCall(t, server, "rom_load", `{"path":"F:\\roms\\other.bin","run":false}`))
	invalidated, _ := loaded["resources_invalidated"].([]any)
	if len(invalidated) != 1 || invalidated[0] != freezeID {
		t.Fatalf("rom_load must report the audited purge: %v", loaded)
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

	// The invalidation batch is recorded in the audit stream.
	audit := structured(postToolCall(t, server, "target_audit_log", `{"tool":"rom_load"}`))
	entries := audit["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("expected one rom_load audit entry: %v", audit)
	}
	entry := entries[0].(map[string]any)
	if entry["rom_after"] != `F:\roms\other.bin` {
		t.Fatalf("rom identity missing: %v", entry)
	}
	resources, _ := entry["resource_ids"].([]any)
	if len(resources) != 1 || resources[0] != freezeID {
		t.Fatalf("invalidation batch missing: %v", entry)
	}
}

func TestMemoryFreezeLimit(t *testing.T) {
	client := freezeWriteClient()
	server := newTestServer(t, client)

	for index := 0; index < freezeMaxEntries; index++ {
		result := structured(postToolCall(t, server, "memory_freeze", fmt.Sprintf(`{"space":"m68k-bus","address":%d,"data":%q}`, index*2, freezeData(0x05))))
		if result["code"] != nil {
			t.Fatalf("entry %d failed: %v", index, result)
		}
	}
	over := structured(postToolCall(t, server, "memory_freeze", fmt.Sprintf(`{"space":"m68k-bus","address":4096,"data":%q}`, freezeData(0x05))))
	if over["code"] != "freeze_limit" {
		t.Fatalf("expected freeze_limit, got %v", over)
	}
	// The rejected entry must not have written or advanced the generation.
	if got := countCalls(client, "mem_write"); got != freezeMaxEntries {
		t.Fatalf("rejected freeze must not write; got %d calls", got)
	}
}

func TestMemoryFreezeClear(t *testing.T) {
	client := freezeWriteClient()
	server := newTestServer(t, client)

	for index := 0; index < 3; index++ {
		result := structured(postToolCall(t, server, "memory_freeze", fmt.Sprintf(`{"space":"m68k-bus","address":%d,"data":%q}`, index*2, freezeData(0x05))))
		if result["code"] != nil {
			t.Fatalf("entry %d failed: %v", index, result)
		}
	}
	listed := structured(postToolCall(t, server, "memory_freeze_list", `{}`))
	if listed["freezes_total"] != float64(3) {
		t.Fatalf("expected 3 entries before clear: %v", listed)
	}

	cleared := structured(postToolCall(t, server, "memory_freeze_clear", `{}`))
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
	clearedAgain := structured(postToolCall(t, server, "memory_freeze_clear", `{}`))
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

func TestFreezeRegistryGeneratesUniqueIDs(t *testing.T) {
	registry := newFreezeRegistry()
	seen := make(map[string]bool)
	for index := 0; index < freezeMaxEntries; index++ {
		entry, _, err := registry.set("m68k-bus", uint64(index), []byte{byte(index)}, freezeProvenance{})
		if err != nil {
			t.Fatalf("entry %d failed: %v", index, err)
		}
		if seen[entry.ID] {
			t.Fatalf("duplicate freeze id %q", entry.ID)
		}
		seen[entry.ID] = true
	}

	registry.purge()
	entry, _, err := registry.set("m68k-bus", 100, []byte{1}, freezeProvenance{})
	if err != nil {
		t.Fatal(err)
	}
	if seen[entry.ID] {
		t.Fatalf("freeze id reused after purge: %q", entry.ID)
	}
}
