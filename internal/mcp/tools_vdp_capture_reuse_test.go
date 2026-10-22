package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
)

// VDP capture reuse (roadmap issue #2): the four VDP readers must consume the
// stored components of a vdp_capture when they are given its id, report where the
// data came from, and fail explicitly when the capture cannot serve it instead of
// performing a silent live read.

// vdpReuseBridge serves a deterministic VDP: VRAM holds a sprite table at 512 and
// patterned tiles, CRAM holds a palette ramp, and every device read is counted so
// a test can prove a reuse performed none.
type vdpReuseBridge struct {
	client      *fakeBridgeClient
	vram        []byte
	cram        []byte
	deviceReads int
	statusReads int
}

func newVDPReuseBridge(t *testing.T) *vdpReuseBridge {
	t.Helper()
	bridge := &vdpReuseBridge{
		vram: make([]byte, 65536),
		cram: make([]byte, 128),
	}
	for index := range bridge.vram {
		bridge.vram[index] = byte(index * 7)
	}
	for index := range bridge.cram {
		bridge.cram[index] = byte(index * 2)
	}
	// Sprite table at VRAM 512: entry 0 links to 5, entry 5 links back to 0.
	putSprite := func(index, link, tile int) {
		offset := 512 + index*8
		bridge.vram[offset+0] = 0x00
		bridge.vram[offset+1] = 0x80 // y raw 128
		bridge.vram[offset+2] = byte(link)
		bridge.vram[offset+3] = 0x00
		bridge.vram[offset+4] = byte(tile >> 8)
		bridge.vram[offset+5] = byte(tile)
		bridge.vram[offset+6] = 0x00
		bridge.vram[offset+7] = 0x90 // x raw 144
	}
	putSprite(0, 5, 1)
	putSprite(5, 0, 6)

	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "mem_read":
			return memReadFromBlob(make([]byte, 64), 0xFF0000)(context.Background(), method, params)
		case "emulator_status":
			return json.RawMessage(`{"system_running":false}`), nil
		case "cpu_control":
			return json.RawMessage(`{"system_running":false}`), nil
		case "vdp_status":
			bridge.statusReads++
			return json.RawMessage(`{"vdp_found":true,"registers":[{"register":12,"value":0},{"register":16,"value":0}],"decoded":{"display_enabled":true,"extended_vram":false,"name_table_base_sprite":512,"name_table_base_a":1024,"name_table_base_b":2048,"name_table_base_window":4096},"image_buffer":{"last_rendered_frame_token":77}}`), nil
		case "vdp_mem_read":
			bridge.deviceReads++
			address, err := strconv.ParseUint(params["address"], 10, 64)
			if err != nil {
				return nil, err
			}
			length, err := strconv.ParseUint(params["length"], 10, 64)
			if err != nil {
				return nil, err
			}
			buffer := bridge.vram
			target := "vram"
			if params["target"] != "vram" {
				buffer = bridge.cram
				target = "cram"
			}
			if address+length > uint64(len(buffer)) {
				return nil, fmt.Errorf("read past the fake %s buffer: %d+%d", target, address, length)
			}
			payload := fmt.Sprintf(`{"target":%q,"address":%d,"length":%d,"byte_order":"big-endian","encoding":"base64","consistency":"live","system_paused_during_read":false,"data":%q}`,
				target, address, length, base64.StdEncoding.EncodeToString(buffer[address:address+length]))
			return json.RawMessage(payload), nil
		case "frame_capture":
			return json.RawMessage(fmt.Sprintf(`{"width":2,"height":2,"pixel_format":"rgb24","encoding":"base64","frame_token":77,"data":%q}`,
				base64.StdEncoding.EncodeToString(make([]byte, 12)))), nil
		default:
			return nil, fmt.Errorf("unexpected method %s", method)
		}
	}
	bridge.client = client
	return bridge
}

// resetCounters clears the device-read counters so a test can assert that a reuse
// performed none.
func (bridge *vdpReuseBridge) resetCounters() {
	bridge.deviceReads = 0
	bridge.statusReads = 0
}

// captureVDP stores one vdp_capture with the given extra arguments and returns the
// capture id, resetting the device-read counters afterwards.
func captureVDP(t *testing.T, bridge *vdpReuseBridge, server *Server, extra string) string {
	t.Helper()
	content := structured(postToolCall(t, server, "vdp_capture",
		`{"include_frame":false,"include_cram":true,"include_vsram":true,"include_vram":true,"vram_length":65536`+extra+`}`))
	if content["code"] != nil {
		t.Fatalf("vdp_capture failed: %v", content)
	}
	captureID, _ := content["summary"].(map[string]any)["capture_id"].(string)
	if captureID == "" {
		t.Fatalf("vdp_capture produced no id: %v", content)
	}
	bridge.resetCounters()
	return captureID
}

func TestVDPSpriteTableReadsStoredCapture(t *testing.T) {
	bridge := newVDPReuseBridge(t)
	server := newTestServer(t, bridge.client)
	server.runState.observe(server, false, nil)
	captureID := captureVDP(t, bridge, server, "")

	content := structured(postToolCall(t, server, "vdp_sprite_table",
		fmt.Sprintf(`{"offset":0,"count":16,"vdp_capture_id":%q}`, captureID)))
	if content["code"] != nil {
		t.Fatalf("sprite table from capture failed: %v", content)
	}
	if content["data_source"] != "capture" || content["vdp_capture_reused"] != true || content["vdp_capture_id"] != captureID {
		t.Fatalf("reuse provenance wrong: %v", content)
	}
	if content["vdp_capture_frame_token"] != float64(77) {
		t.Fatalf("capture frame token not echoed: %v", content["vdp_capture_frame_token"])
	}
	if content["sprite_table_base"] != float64(512) {
		t.Fatalf("sprite table base must come from the captured status: %v", content["sprite_table_base"])
	}
	if content["chain_visible_count"] != float64(2) {
		t.Fatalf("stored table decode wrong: %v", content["chain_visible_count"])
	}
	if bridge.deviceReads != 0 || bridge.statusReads != 0 {
		t.Fatalf("a reuse must not read the device (%d buffer reads, %d status reads)", bridge.deviceReads, bridge.statusReads)
	}
	note, _ := content["note"].(string)
	if note == "" || !contains(note, "stored VRAM component") {
		t.Fatalf("reuse note must state where the data came from: %q", note)
	}
}

func TestVDPSpriteTableCaptureMissingVRAMFails(t *testing.T) {
	bridge := newVDPReuseBridge(t)
	server := newTestServer(t, bridge.client)
	server.runState.observe(server, false, nil)
	content := structured(postToolCall(t, server, "vdp_capture",
		`{"include_frame":false,"include_cram":true,"include_vsram":false,"include_vram":false}`))
	captureID, _ := content["summary"].(map[string]any)["capture_id"].(string)
	bridge.resetCounters()

	failed := structured(postToolCall(t, server, "vdp_sprite_table",
		fmt.Sprintf(`{"offset":0,"count":16,"vdp_capture_id":%q}`, captureID)))
	if failed["code"] != "capture_component_omitted" {
		t.Fatalf("expected capture_component_omitted: %v", failed)
	}
	if failed["required_component"] != "vram" || failed["capture_id"] != captureID {
		t.Fatalf("omission must name the component and the capture: %v", failed)
	}
	captured, _ := failed["components_captured"].([]any)
	if len(captured) == 0 {
		t.Fatalf("omission must list what the capture holds: %v", failed)
	}
	if bridge.deviceReads != 0 || bridge.statusReads != 0 {
		t.Fatalf("a failed reuse must not fall back to a live read (%d/%d)", bridge.deviceReads, bridge.statusReads)
	}
}

func TestVDPReadersRejectUnknownAndForeignCaptures(t *testing.T) {
	bridge := newVDPReuseBridge(t)
	server := newTestServer(t, bridge.client)
	server.runState.observe(server, false, nil)

	// A capture from a different producer holds no VDP buffers.
	foreign := structured(postToolCall(t, server, "memory_snapshot_capture",
		`{"space":"m68k-bus","ranges":[{"name":"ram0","address":"0xFF0000","length":4}]}`))
	foreignID, _ := foreign["summary"].(map[string]any)["capture_id"].(string)
	bridge.resetCounters()

	tools := map[string]string{
		"vdp_sprite_table": `{"offset":0,"count":4,"vdp_capture_id":%q}`,
		"vdp_tile_export":  `{"tile":0,"count":1,"vdp_capture_id":%q}`,
		"vdp_plane_export": `{"plane":"a","vdp_capture_id":%q}`,
		"vdp_pixel_info":   `{"x":0,"y":0,"vdp_capture_id":%q}`,
	}
	for tool, arguments := range tools {
		unknown := structured(postToolCall(t, server, tool, fmt.Sprintf(arguments, "cap_unknown000000")))
		if unknown["code"] != "capture_not_found" {
			t.Fatalf("%s: unknown id must fail with capture_not_found: %v", tool, unknown)
		}
		other := structured(postToolCall(t, server, tool, fmt.Sprintf(arguments, foreignID)))
		if other["code"] != "capture_not_found" {
			t.Fatalf("%s: foreign id must fail with capture_not_found: %v", tool, other)
		}
	}
	if bridge.deviceReads != 0 {
		t.Fatalf("an unresolvable capture id must not read the device (%d reads)", bridge.deviceReads)
	}
}

func TestVDPTileExportReusesCaptureAndReportsCaptureData(t *testing.T) {
	bridge := newVDPReuseBridge(t)
	server := newTestServer(t, bridge.client)
	server.runState.observe(server, false, nil)
	captureID := captureVDP(t, bridge, server, "")

	fromCapture := structured(postToolCall(t, server, "vdp_tile_export",
		fmt.Sprintf(`{"tile":2,"count":2,"palette":1,"vdp_capture_id":%q}`, captureID)))
	if fromCapture["code"] != nil {
		t.Fatalf("tile export from capture failed: %v", fromCapture)
	}
	summary := fromCapture["summary"].(map[string]any)
	if summary["data_source"] != "capture" || summary["vdp_capture_reused"] != true {
		t.Fatalf("tile export must report capture data: %v", summary)
	}
	if summary["source_capture_id"] != captureID || summary["capture_id"] != captureID {
		t.Fatalf("derived export must stay in the capture lineage: %v", summary)
	}
	if summary["vdp_capture_frame_token"] != float64(77) {
		t.Fatalf("capture frame token not echoed: %v", summary["vdp_capture_frame_token"])
	}
	if bridge.deviceReads != 0 || bridge.statusReads != 0 {
		t.Fatalf("a reuse must not read the device (%d/%d)", bridge.deviceReads, bridge.statusReads)
	}

	// The same export against the live device must produce the same pixels, which
	// is only true if the capture really served the bytes.
	bridge.resetCounters()
	live := structured(postToolCall(t, server, "vdp_tile_export", `{"tile":2,"count":2,"palette":1}`))
	if live["code"] != nil {
		t.Fatalf("live tile export failed: %v", live)
	}
	liveSummary := live["summary"].(map[string]any)
	if liveSummary["data_source"] != "live" || liveSummary["vdp_capture_reused"] != nil {
		t.Fatalf("a live export must not claim reuse: %v", liveSummary)
	}
	if liveSummary["png_sha256"] != summary["png_sha256"] || liveSummary["json_sha256"] != summary["json_sha256"] {
		t.Fatalf("capture export is not byte-identical to the live export: %v vs %v", summary, liveSummary)
	}
	if bridge.deviceReads == 0 {
		t.Fatal("the live export should have read the device")
	}
}

func TestVDPPlaneExportReusesCapture(t *testing.T) {
	bridge := newVDPReuseBridge(t)
	server := newTestServer(t, bridge.client)
	server.runState.observe(server, false, nil)
	captureID := captureVDP(t, bridge, server, "")

	fromCapture := structured(postToolCall(t, server, "vdp_plane_export",
		fmt.Sprintf(`{"plane":"a","vdp_capture_id":%q}`, captureID)))
	if fromCapture["code"] != nil {
		t.Fatalf("plane export from capture failed: %v", fromCapture)
	}
	summary := fromCapture["summary"].(map[string]any)
	if summary["data_source"] != "capture" || summary["vdp_capture_reused"] != true {
		t.Fatalf("plane export must report capture data: %v", summary)
	}
	if summary["name_table_base"] != float64(1024) {
		t.Fatalf("plane base must come from the captured status: %v", summary["name_table_base"])
	}
	if bridge.deviceReads != 0 || bridge.statusReads != 0 {
		t.Fatalf("a reuse must not read the device (%d/%d)", bridge.deviceReads, bridge.statusReads)
	}
}

func TestVDPPlaneExportPartialVRAMCaptureFails(t *testing.T) {
	bridge := newVDPReuseBridge(t)
	server := newTestServer(t, bridge.client)
	server.runState.observe(server, false, nil)
	// A 4 KiB VRAM component cannot serve a full-plane render.
	content := structured(postToolCall(t, server, "vdp_capture",
		`{"include_frame":false,"include_cram":true,"include_vsram":false,"include_vram":true,"vram_address":0,"vram_length":4096}`))
	captureID, _ := content["summary"].(map[string]any)["capture_id"].(string)
	bridge.resetCounters()

	failed := structured(postToolCall(t, server, "vdp_plane_export",
		fmt.Sprintf(`{"plane":"a","vdp_capture_id":%q}`, captureID)))
	if failed["code"] != "capture_component_omitted" {
		t.Fatalf("a partial VRAM component must fail explicitly: %v", failed)
	}
	if failed["required_component"] != "vram" {
		t.Fatalf("omission must name vram: %v", failed)
	}
	reason, _ := failed["reason"].(string)
	if !contains(reason, "covers") {
		t.Fatalf("omission reason must state the captured range: %q", reason)
	}
	if bridge.deviceReads != 0 {
		t.Fatalf("a failed reuse must not read the device (%d reads)", bridge.deviceReads)
	}
}

func TestVDPPixelInfoCannotReuseCapture(t *testing.T) {
	bridge := newVDPReuseBridge(t)
	server := newTestServer(t, bridge.client)
	server.runState.observe(server, false, nil)
	captureID := captureVDP(t, bridge, server, "")

	failed := structured(postToolCall(t, server, "vdp_pixel_info",
		fmt.Sprintf(`{"x":10,"y":20,"vdp_capture_id":%q}`, captureID)))
	if failed["code"] != "capture_component_omitted" {
		t.Fatalf("pixel info has no capturable component and must say so: %v", failed)
	}
	if failed["required_component"] != "pixel_attribution" {
		t.Fatalf("omission must name pixel_attribution: %v", failed)
	}
	reason, _ := failed["reason"].(string)
	if !contains(reason, "completed frame buffer") {
		t.Fatalf("omission must document why the component cannot be captured: %q", reason)
	}
	captured, _ := failed["components_captured"].([]any)
	if len(captured) == 0 {
		t.Fatalf("omission must list what the capture holds: %v", failed)
	}
	if bridge.deviceReads != 0 || bridge.statusReads != 0 {
		t.Fatalf("a failed reuse must not read the device (%d/%d)", bridge.deviceReads, bridge.statusReads)
	}
}

func TestVDPLiveReadsStillReportLiveDataSource(t *testing.T) {
	bridge := newVDPReuseBridge(t)
	server := newTestServer(t, bridge.client)
	server.runState.observe(server, false, nil)

	sprite := structured(postToolCall(t, server, "vdp_sprite_table", `{"offset":0,"count":4}`))
	if sprite["data_source"] != "live" || sprite["vdp_capture_reused"] != nil {
		t.Fatalf("a live sprite table must not claim reuse: %v", sprite)
	}
	plane := structured(postToolCall(t, server, "vdp_plane_export", `{"plane":"a"}`))
	if plane["summary"].(map[string]any)["data_source"] != "live" {
		t.Fatalf("a live plane export must report live data: %v", plane)
	}
}

// contains is a local substring helper so the assertions read as one expression.
func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for index := 0; index+len(needle) <= len(haystack); index++ {
		if haystack[index:index+len(needle)] == needle {
			return true
		}
	}
	return false
}
