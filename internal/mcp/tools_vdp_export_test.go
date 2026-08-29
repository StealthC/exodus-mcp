package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"
)

// vdpExportPayload renders a fake vdp_mem_read bridge response for one target.
func vdpExportPayload(target string, data []byte) string {
	return `{"data":"` + base64.StdEncoding.EncodeToString(data) + `","byte_order":"big-endian","address_space":"mem-vdp-` + target + `","entry_size":2,"buffer_size":` + strconv.Itoa(len(data)) + `,"system_paused_during_read":false,"consistency":"live"}`
}

// TestVDPMemoryExportStoresArtifact: the export stores the raw bytes as an
// artifact with the provenance envelope and echoes the address domain.
func TestVDPMemoryExportStoresArtifact(t *testing.T) {
	raw := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "vdp_mem_read" {
			t.Fatalf("method = %s", method)
		}
		if params["target"] != "vram" || params["address"] != "256" || params["length"] != "8" {
			t.Fatalf("params = %v", params)
		}
		return json.RawMessage(vdpExportPayload("vram", raw)), nil
	}
	server := newTestServer(t, client)

	result := postToolCall(t, server, "vdp_memory_export", `{"target":"vram","address":256,"length":8}`)
	content := structured(result)
	if result["isError"] == true {
		t.Fatalf("export failed: %v", content)
	}
	if content["address"] != float64(256) || content["address_hex"] != "0x000100" {
		t.Fatalf("address echo wrong: %v", content)
	}
	if content["length"] != float64(8) || content["byte_order"] != "big-endian" {
		t.Fatalf("length/byte order wrong: %v", content)
	}
	artifact := content["artifact"].(map[string]any)
	artifactID := artifact["id"].(string)
	if artifact["kind"] != "vdp-memory-export" || artifact["mime_type"] != "application/octet-stream" {
		t.Fatalf("artifact descriptor wrong: %v", artifact)
	}
	// The artifact bytes must be the raw payload bytes.
	contextID := defaultContextID(t, server)
	stored, _, err := server.store.Bytes(artifactID, contextID)
	if err != nil {
		t.Fatalf("fetch artifact: %v", err)
	}
	if len(stored) != len(raw) {
		t.Fatalf("artifact bytes length = %d, want %d", len(stored), len(raw))
	}
	for i := range raw {
		if stored[i] != raw[i] {
			t.Fatalf("artifact byte %d = %02X, want %02X", i, stored[i], raw[i])
		}
	}
	digest := sha256.Sum256(raw)
	if artifact["sha256"] != hex.EncodeToString(digest[:]) {
		t.Fatalf("artifact sha256 mismatch: %v", artifact["sha256"])
	}
	// Provenance envelope carries the address domain.
	provenance := artifact["provenance"].(map[string]any)
	if provenance["start_address"] != float64(256) || provenance["address_space"] != "mem-vdp-vram" || provenance["device"] != "VDP VRAM" {
		t.Fatalf("provenance wrong: %v", provenance)
	}
	if content["capture_consistency"] == nil {
		t.Fatalf("capture_consistency missing: %v", content)
	}
}

// TestVDPMemoryExportDefaultsToFullBuffer: a zero length exports the whole
// buffer (cram = 128 bytes).
func TestVDPMemoryExportDefaultsToFullBuffer(t *testing.T) {
	raw := make([]byte, 128)
	for i := range raw {
		raw[i] = byte(i)
	}
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if params["target"] != "cram" || params["length"] != "128" {
			t.Fatalf("params = %v", params)
		}
		return json.RawMessage(vdpExportPayload("cram", raw)), nil
	}
	server := newTestServer(t, client)

	result := postToolCall(t, server, "vdp_memory_export", `{"target":"cram","address":0}`)
	content := structured(result)
	if result["isError"] == true {
		t.Fatalf("export failed: %v", content)
	}
	if content["length"] != float64(128) {
		t.Fatalf("length = %v, want 128", content["length"])
	}
}

// TestVDPMemoryExportValidation: bad target, out-of-range address, and
// length past the buffer end are rejected before any native action.
func TestVDPMemoryExportValidation(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	server := newTestServer(t, client)

	cases := []struct {
		name string
		args string
		code string
	}{
		{"bad target", `{"target":"sram","address":0}`, "invalid_params"},
		{"address out of range", `{"target":"cram","address":128}`, "out_of_range"},
		{"length past end", `{"target":"cram","address":64,"length":65}`, "length_exceeds_buffer"},
		{"length over cap", `{"target":"vram","address":0,"length":131072}`, "length_exceeds_buffer"},
	}
	for _, tc := range cases {
		result := postToolCall(t, server, "vdp_memory_export", tc.args)
		if content := structured(result); result["isError"] != true || content["code"] != tc.code {
			t.Fatalf("%s: expected %s: %v", tc.name, tc.code, result)
		}
	}
	if len(client.recordedCalls) != 0 {
		t.Fatalf("no native action expected, got %v", client.recordedCalls)
	}
}

// TestVDPMemoryExportPausedMode: capture_mode "paused" pauses once before the
// read and restores afterwards (one cpu_control pause + one run).
func TestVDPMemoryExportPausedMode(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "cpu_control":
			return json.RawMessage(`{"system_running":` + boolString(params["action"] == "run") + `}`), nil
		case "vdp_status":
			return json.RawMessage(`{"image_buffer":{"last_rendered_frame_token":42}}`), nil
		case "vdp_mem_read":
			return json.RawMessage(vdpExportPayload("vsram", make([]byte, 8))), nil
		default:
			t.Fatalf("unexpected method %s", method)
			return nil, nil
		}
	}
	server := newTestServer(t, client)
	server.runState.observe(server, true, nil)

	result := postToolCall(t, server, "vdp_memory_export", `{"target":"vsram","address":0,"length":8,"capture_mode":"paused"}`)
	content := structured(result)
	if result["isError"] == true {
		t.Fatalf("export failed: %v", content)
	}
	consistency := content["capture_consistency"].(map[string]any)
	if consistency["state"] != "atomic" || consistency["execution_paused_by_tool"] != true || consistency["execution_resumed_after"] != true {
		t.Fatalf("paused-mode consistency wrong: %v", consistency)
	}
	pauses, runs := 0, 0
	for _, call := range client.recordedCalls {
		if call.Method == "cpu_control" {
			if call.Params["action"] == "pause" {
				pauses++
			}
			if call.Params["action"] == "run" {
				runs++
			}
		}
	}
	if pauses != 1 || runs != 1 {
		t.Fatalf("pause/resume cycle = %d/%d, want 1/1 (calls %v)", pauses, runs, client.recordedCalls)
	}
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
