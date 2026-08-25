package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

// ----------------------------------------------------------------------------------------------------------------------
// system_paused_during_read propagation (roadmap P0 "Honest capture
// consistency"): memory_read, memory_dump, memory_search, and frame_capture.
// ----------------------------------------------------------------------------------------------------------------------

func TestMemoryReadPropagatesPausedDuringRead(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		if method != "mem_read" {
			t.Fatalf("method = %s, want mem_read", method)
		}
		return json.RawMessage(memReadPayloadPaused([]byte{1, 2}, "big-endian", 0, true)), nil
	}
	result := callTool(t, client, "memory_read", `{"space":"m68k-ram","address":0,"length":2}`)
	content := structured(result)
	if content["system_paused_during_read"] != true {
		t.Fatalf("system_paused_during_read = %v, want true", content["system_paused_during_read"])
	}
}

func TestMemoryReadPropagatesNotPaused(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		return json.RawMessage(memReadPayloadPaused([]byte{1, 2}, "big-endian", 0, false)), nil
	}
	result := callTool(t, client, "memory_read", `{"space":"m68k-ram","address":0,"length":2}`)
	content := structured(result)
	if content["system_paused_during_read"] != false {
		t.Fatalf("system_paused_during_read = %v, want false", content["system_paused_during_read"])
	}
}

func TestMemoryDumpReportsPausedFlag(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		return json.RawMessage(memReadPayloadPaused([]byte{1, 2, 3, 4, 5}, "big-endian", 0xFF0000, true)), nil
	}
	result := callTool(t, client, "memory_dump", `{"space":"mem-ram","address":0,"length":5}`)
	if result["isError"] == true {
		t.Fatalf("unexpected error: %v", result)
	}
	summary := structured(result)["summary"].(map[string]any)
	if summary["system_paused_during_read"] != true {
		t.Fatalf("system_paused_during_read = %v, want true", summary["system_paused_during_read"])
	}
}

func TestMemorySearchPropagatesPausedFlag(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		return json.RawMessage(memReadPayloadPaused([]byte("hello"), "big-endian", 0, true)), nil
	}
	result := callTool(t, client, "memory_search", `{"space":"m68k-bus","pattern":"68 65 6C 6C 6F","start_address":0,"length":5}`)
	if result["isError"] == true {
		t.Fatalf("unexpected error: %v", result)
	}
	summary := structured(result)["summary"].(map[string]any)
	if summary["system_paused_during_read"] != true {
		t.Fatalf("system_paused_during_read = %v, want true", summary["system_paused_during_read"])
	}
	if summary["snapshot_read_note"] == nil {
		t.Fatalf("snapshot_read_note must document the flag source: %v", summary)
	}
}

func memReadPayloadPaused(data []byte, byteOrder string, effective uint64, paused bool) string {
	return fmt.Sprintf(`{"space_id":"m68k-ram","kind":"memory","address":0,"effective_address":%d,"length":%d,"byte_order":"%s","encoding":"base64","consistency":"live","system_paused_during_read":%t,"data":"%s"}`,
		effective, len(data), byteOrder, paused, base64.StdEncoding.EncodeToString(data))
}
