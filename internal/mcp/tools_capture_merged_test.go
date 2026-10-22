package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
)

// ----------------------------------------------------------------------------------------------------------------------
// capture alias parity (group 10)
//
// capture is a facade: each producer's payload is the payload of the handler it
// absorbed, so the parity assertions compare capture.detail with the alias
// response field by field (only per-store identity and wall-clock values are
// normalized). frame_capture is the one documented mapping: it produced a PNG
// artifact with no capture index entry, so capture{components:["frame"]} stores
// the same frame inside a tracked VDP capture; the test asserts the frame bytes
// (sha256) and the resolvable capture id instead of payload equality.
// ----------------------------------------------------------------------------------------------------------------------

// captureClient answers every read the capture producers perform.
func captureClient() *fakeBridgeClient {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "emulator_status":
			return json.RawMessage(`{"system_running":false,"modules":[],"devices":[],"rom":{"loaded":false}}`), nil
		case "vdp_status":
			return json.RawMessage(`{"vdp_found":true,"registers":[{"register":12,"value":0},{"register":16,"value":0}],"decoded":{"display_enabled":true,"extended_vram":false,"name_table_base_a":8192,"name_table_base_b":12288},"image_buffer":{"last_rendered_frame_token":7}}`), nil
		case "cpu_control":
			return json.RawMessage(`{"action":"` + params["action"] + `","system_running":false}`), nil
		case "mem_read":
			length, _ := strconv.Atoi(params["length"])
			data := make([]byte, length)
			data[0] = 0x5A
			return json.RawMessage(fmt.Sprintf(`{"space_id":%q,"address":%s,"effective_address":%s,"length":%d,"byte_order":"big-endian","encoding":"base64","consistency":"paused","data":%q}`,
				params["space"], params["address"], params["address"], length, base64.StdEncoding.EncodeToString(data))), nil
		case "regs_get":
			return json.RawMessage(`{"cpu":"m68k","byte_order":"not-applicable","registers":{"pc":4096,"d0":0,"a7":16711680}}`), nil
		case "frame_capture":
			// 2x2 rgb24 frame, deterministic bytes.
			return json.RawMessage(`{"width":2,"height":2,"frame_token":7,"encoding":"base64","data":"` + base64.StdEncoding.EncodeToString([]byte{0xFF, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF}) + `"}`), nil
		case "vdp_mem_read":
			length, _ := strconv.Atoi(params["length"])
			data := make([]byte, length)
			if len(data) > 0 {
				data[0] = 0x0E
			}
			return json.RawMessage(fmt.Sprintf(`{"target":%q,"address_space":"mem-vdp-%s","address":%s,"effective_address":%s,"length":%d,"buffer_size":65536,"entry_size":1,"byte_order":"big-endian","encoding":"base64","consistency":"paused","system_paused_during_read":false,"data":%q}`,
				params["target"], params["target"], params["address"], params["address"], length, base64.StdEncoding.EncodeToString(data))), nil
		default:
			return json.RawMessage(`{}`), nil
		}
	}
	return client
}

// TestCaptureAbsorbsTheMemorySnapshot: capture{components:["memory"]} is the
// paused memory snapshot, and its capture id is resolvable with capture_get.
func TestCaptureAbsorbsTheMemorySnapshot(t *testing.T) {
	arguments := `"space":"mem-ram","ranges":[{"name":"state","address":"0xFF0000","length":8}]`
	canonical := canonicalPayload(t, captureClient(), "capture", `{"components":["memory"],`+arguments+`}`)
	legacy := canonicalPayload(t, captureClient(), "memory_snapshot_capture", `{`+arguments+`}`)

	if canonical["producer"] != captureProducerMemory || canonical["mode"] != consistencyAtomic {
		t.Fatalf("producer/mode = %v/%v", canonical["producer"], canonical["mode"])
	}
	detail, _ := canonical["detail"].(map[string]any)
	if detail == nil {
		t.Fatalf("capture has no detail: %v", canonical)
	}
	if !jsonEqual(t, normalizeVolatile(detail), normalizeVolatile(legacy)) {
		t.Fatalf("memory parity failed:\ndetail = %v\nlegacy = %v", detail, legacy)
	}
	captureID, _ := canonical["capture_id"].(string)
	if captureID == "" {
		t.Fatalf("capture has no capture_id: %v", canonical)
	}
	// The merged tool must keep the resolvable-capture contract (#2/#3/#10).
	server := newTestServer(t, captureClient())
	result := structured(postToolCall(t, server, "capture", `{"components":["memory"],`+arguments+`}`))
	resolved := structured(postToolCall(t, server, "capture_get", fmt.Sprintf(`{"capture_id":%q}`, result["capture_id"])))
	if resolved["code"] != nil {
		t.Fatalf("capture_get could not resolve the merged capture: %v", resolved)
	}
	if resolved["capture_id"] != result["capture_id"] {
		t.Fatalf("resolved capture id = %v, want %v", resolved["capture_id"], result["capture_id"])
	}
}

// TestCaptureAbsorbsTheSystemSnapshot: a memory set plus CPU/VDP/frame
// components is the system snapshot, including its per-component include flags.
func TestCaptureAbsorbsTheSystemSnapshot(t *testing.T) {
	canonical := canonicalPayload(t, captureClient(), "capture",
		`{"components":["memory","registers","vdp","frame","cram","vsram","sprites"],"space":"mem-ram","ranges":[{"name":"state","address":"0xFF0000","length":8}]}`)
	legacy := canonicalPayload(t, captureClient(), "system_snapshot_capture",
		`{"space":"mem-ram","memory_ranges":[{"name":"state","address":"0xFF0000","length":8}]}`)

	if canonical["producer"] != captureProducerSystem {
		t.Fatalf("producer = %v", canonical["producer"])
	}
	detail, _ := canonical["detail"].(map[string]any)
	if detail == nil {
		t.Fatalf("capture has no detail: %v", canonical)
	}
	if !jsonEqual(t, normalizeVolatile(detail), normalizeVolatile(legacy)) {
		t.Fatalf("system parity failed:\ndetail = %v\nlegacy = %v", detail, legacy)
	}
	if canonical["manifest"] == nil {
		t.Fatalf("capture lost the producer manifest: %v", canonical)
	}
}

// TestCaptureAbsorbsTheVDPCapture: VDP component sets are the VDP capture, with
// the requested includes mapped one for one.
func TestCaptureAbsorbsTheVDPCapture(t *testing.T) {
	canonical := canonicalPayload(t, captureClient(), "capture",
		`{"components":["vdp","frame","cram","vsram","vram","sprites"],"mode":"live"}`)
	legacy := canonicalPayload(t, captureClient(), "vdp_capture", `{}`)

	if canonical["producer"] != captureProducerVDP || canonical["mode"] != consistencyLive {
		t.Fatalf("producer/mode = %v/%v", canonical["producer"], canonical["mode"])
	}
	detail, _ := canonical["detail"].(map[string]any)
	if detail == nil {
		t.Fatalf("capture has no detail: %v", canonical)
	}
	if !jsonEqual(t, normalizeVolatile(detail), normalizeVolatile(legacy)) {
		t.Fatalf("vdp parity failed:\ndetail = %v\nlegacy = %v", detail, legacy)
	}
}

// TestCaptureFrameMappingIsDocumented covers the approved mapping: frame_capture
// returns one PNG with no capture index entry, so capture{components:["frame"]}
// stores the same frame inside a tracked VDP capture. Payload equality does not
// hold (the envelopes differ by design); the frame bytes and the resolvable
// capture id do.
func TestCaptureFrameMappingIsDocumented(t *testing.T) {
	canonical := canonicalPayload(t, captureClient(), "capture", `{"components":["frame"],"mode":"live"}`)
	legacy := canonicalPayload(t, captureClient(), "frame_capture", `{"capture_mode":"live"}`)

	if canonical["producer"] != captureProducerVDP {
		t.Fatalf("frame-only components routed to %v, want the vdp producer so capture_id is resolvable", canonical["producer"])
	}
	captureID, _ := canonical["capture_id"].(string)
	if captureID == "" {
		t.Fatalf("frame capture has no capture_id: %v", canonical)
	}
	detail, _ := canonical["detail"].(map[string]any)
	summary, _ := canonical["summary"].(map[string]any)
	if summary["kind"] != "vdp-capture" || detail["manifest"] == nil {
		t.Fatalf("frame capture is not a tracked capture: %v", canonical)
	}
	frameSHA := ""
	for _, raw := range detail["artifacts"].([]any) {
		descriptor := raw.(map[string]any)
		if descriptor["kind"] == "frame-capture" {
			frameSHA, _ = descriptor["sha256"].(string)
		}
	}
	legacySHA, _ := legacy["summary"].(map[string]any)["sha256"].(string)
	if frameSHA == "" || legacySHA == "" || frameSHA != legacySHA {
		t.Fatalf("frame bytes differ: capture %q, frame_capture %q", frameSHA, legacySHA)
	}
}

// TestCaptureRejectsUnsupportedRequests keeps the facade honest about what it
// cannot hold in one window.
func TestCaptureRejectsUnsupportedRequests(t *testing.T) {
	server := newTestServer(t, captureClient())
	cases := []struct {
		arguments string
		code      string
	}{
		{`{"components":[]}`, "invalid_params"},
		{`{"components":["memory"],"mode":"live","space":"mem-ram","ranges":[{"name":"a","address":0,"length":1}]}`, "invalid_params"},
		{`{"components":["vdp"],"ranges":[{"name":"a","address":0,"length":1}]}`, "unsupported_parameter"},
		{`{"components":["vdp"],"control_id":"ctl_x"}`, "unsupported_parameter"},
		{`{"components":["memory"]}`, "invalid_params"},
	}
	for _, tc := range cases {
		result := postToolCall(t, server, "capture", tc.arguments)
		if structured(result)["code"] != tc.code {
			t.Fatalf("%s: code = %v, want %s", tc.arguments, structured(result)["code"], tc.code)
		}
	}
}
