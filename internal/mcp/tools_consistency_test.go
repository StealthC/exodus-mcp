package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/StealthC/exodus-mcp/internal/artifact"
)

// ----------------------------------------------------------------------------------------------------------------------
// Shared fixtures
// ----------------------------------------------------------------------------------------------------------------------

// consistencyBridge serves cpu_control (pause/run), mem_read from one blob,
// vdp_status with a frame token, and records the order of bridge calls.
type consistencyBridge struct {
	client  *fakeBridgeClient
	blob    []byte
	space   string
	token   uint64
	paused  bool
	actions []string // recorded action labels: "pause", "run", "read", "status"
}

func newConsistencyBridge(blob []byte, token uint64) *consistencyBridge {
	bridge := &consistencyBridge{blob: blob, token: token}
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "cpu_control":
			action := params["action"]
			bridge.actions = append(bridge.actions, action)
			if action == "pause" {
				bridge.paused = true
				return json.RawMessage(`{"system_running":false}`), nil
			}
			bridge.paused = false
			return json.RawMessage(`{"system_running":true}`), nil
		case "mem_read":
			bridge.actions = append(bridge.actions, "read")
			return memReadFromBlob(bridge.blob, 0xFF0000)(context.Background(), method, params)
		case "vdp_status":
			bridge.actions = append(bridge.actions, "status")
			payload := fmt.Sprintf(`{"vdp_found":true,"image_buffer":{"last_rendered_frame_token":%d}}`, bridge.token)
			return json.RawMessage(payload), nil
		default:
			return nil, fmt.Errorf("unexpected method %s", method)
		}
	}
	bridge.client = client
	return bridge
}

func consistencyOf(result map[string]any) map[string]any {
	consistency, _ := result["capture_consistency"].(map[string]any)
	return consistency
}

func TestCaptureConsistencyPausedAndLiveReads(t *testing.T) {
	bridge := newConsistencyBridge([]byte{1, 2, 3, 4}, 0)
	server := newTestServer(t, bridge.client)

	// Paused system: emulator_status says not running, then a read reports
	// the paused state.
	_ = structured(postToolCall(t, server, "cpu_pause", `{}`))
	read := structured(postToolCall(t, server, "memory_read", `{"space":"m68k-bus","address":"0xFF0000","length":4}`))
	consistency := consistencyOf(read)
	if consistency["state"] != "paused" {
		t.Fatalf("paused read must report paused, got %v", consistency)
	}
	if consistency["execution_paused_by_tool"] != false {
		t.Fatalf("no pause expected: %v", consistency)
	}
	if consistency["initial_run_state"] != "paused" || consistency["final_run_state"] != "paused" {
		t.Fatalf("run states wrong: %v", consistency)
	}

	// Running system: a plain read is live and can be internally inconsistent.
	_ = structured(postToolCall(t, server, "cpu_run", `{}`))
	read = structured(postToolCall(t, server, "memory_read", `{"space":"m68k-bus","address":"0xFF0000","length":4}`))
	consistency = consistencyOf(read)
	if consistency["state"] != "live" {
		t.Fatalf("running read must report live, got %v", consistency)
	}
	if !strings.Contains(consistency["note"].(string), "internally inconsistent") {
		t.Fatalf("live note missing: %v", consistency)
	}
}

func TestCaptureConsistencyAtomicTimedBufferRead(t *testing.T) {
	// A VDP timed-buffer read that had to pause a running system is atomic.
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method == "cpu_control" {
			return json.RawMessage(`{"system_running":true}`), nil
		}
		if method == "vdp_mem_read" {
			payload := fmt.Sprintf(`{"target":"cram","address_space":"mem-vdp-cram","address":0,"length":2,"entry_size":2,"buffer_size":128,"byte_order":"big-endian","encoding":"base64","consistency":"live","system_paused_during_read":true,"data":%q}`,
				base64.StdEncoding.EncodeToString([]byte{0x0E, 0xE0}))
			return json.RawMessage(payload), nil
		}
		return nil, fmt.Errorf("unexpected method %s", method)
	}
	server := newTestServer(t, client)
	_ = structured(postToolCall(t, server, "cpu_run", `{}`))
	result := structured(postToolCall(t, server, "vdp_memory_read", `{"target":"cram","address":0,"length":2}`))
	consistency := consistencyOf(result)
	if consistency["state"] != "atomic" {
		t.Fatalf("paused-by-tool read must be atomic, got %v", consistency)
	}
	if consistency["execution_paused_by_tool"] != true || consistency["execution_resumed_after"] != true {
		t.Fatalf("pause/resume facts wrong: %v", consistency)
	}
	if result["system_paused_during_read"] != true {
		t.Fatalf("raw flag must stay: %v", result)
	}
}

func TestCaptureGuardPausedModePausesAndRestores(t *testing.T) {
	bridge := newConsistencyBridge([]byte{0xAA, 0xBB, 0xCC, 0xDD}, 77)
	server := newTestServer(t, bridge.client)
	_ = structured(postToolCall(t, server, "cpu_run", `{}`))
	bridge.actions = nil // count only the guarded read's actions

	result := structured(postToolCall(t, server, "memory_read", `{"space":"m68k-bus","address":"0xFF0000","length":4,"capture_mode":"paused"}`))
	if result["code"] != nil {
		t.Fatalf("guarded read failed: %v", result)
	}
	consistency := consistencyOf(result)
	if consistency["state"] != "atomic" || consistency["execution_paused_by_tool"] != true || consistency["execution_resumed_after"] != true {
		t.Fatalf("guard window wrong: %v", consistency)
	}
	// Exactly one pause and one resume, with the read between them; the frame
	// tokens are observed around the window (vdp_status calls).
	pauses, runs, reads := 0, 0, 0
	for index, action := range bridge.actions {
		switch action {
		case "pause":
			pauses++
			if reads != 0 {
				t.Fatalf("pause must precede the read: %v", bridge.actions)
			}
		case "run":
			runs++
			if index < 2 {
				t.Fatalf("resume must follow the read: %v", bridge.actions)
			}
		case "read":
			reads++
		}
	}
	if pauses != 1 || runs != 1 || reads != 1 {
		t.Fatalf("guard window actions wrong: %v", bridge.actions)
	}
	// The frame token is observed before and after the window.
	if consistency["initial_frame_token"] != float64(77) || consistency["final_frame_token"] != float64(77) {
		t.Fatalf("frame tokens missing: %v", consistency)
	}
}

func TestCaptureGuardRestoresOnReadFailure(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	actions := []string{}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "cpu_control":
			actions = append(actions, params["action"])
			if params["action"] == "pause" {
				return json.RawMessage(`{"system_running":false}`), nil
			}
			return json.RawMessage(`{"system_running":true}`), nil
		case "mem_read":
			actions = append(actions, "read")
			return nil, fmt.Errorf("read exploded")
		default:
			return nil, fmt.Errorf("unexpected method %s", method)
		}
	}
	server := newTestServer(t, client)
	_ = structured(postToolCall(t, server, "cpu_run", `{}`))
	actions = nil

	result := structured(postToolCall(t, server, "memory_read", `{"space":"m68k-bus","address":"0xFF0000","length":4,"capture_mode":"paused"}`))
	if result["code"] != "bridge_error" {
		t.Fatalf("read failure must surface: %v", result)
	}
	// The failed guard must still restore the run state: one pause issued and
	// the final cpu_control action is the restore run.
	pauses, runs := 0, 0
	for _, action := range actions {
		if action == "pause" {
			pauses++
		}
		if action == "run" {
			runs++
		}
	}
	if pauses != 1 || runs != 1 || actions[len(actions)-1] != "run" {
		t.Fatalf("failed guard must not leak a paused system: %v", actions)
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// memory_snapshot_capture
// ----------------------------------------------------------------------------------------------------------------------

func TestMemorySnapshotCaptureAtomicWindow(t *testing.T) {
	blob := make([]byte, 64)
	for index := range blob {
		blob[index] = byte(index)
	}
	bridge := newConsistencyBridge(blob, 1234)
	server := newTestServer(t, bridge.client)
	_ = structured(postToolCall(t, server, "cpu_run", `{}`))
	bridge.actions = nil

	result := structured(postToolCall(t, server, "memory_snapshot_capture",
		`{"space":"m68k-bus","ranges":[{"name":"lives","address":"0xFF0000","length":16},{"name":"checksum","address":"0xFF0020","length":8}]}`))
	if result["code"] != nil {
		t.Fatalf("capture failed: %v", result)
	}
	summary := result["summary"].(map[string]any)
	if summary["pause_resume_cycle"] != float64(1) {
		t.Fatalf("exactly one pause/resume cycle expected: %v", summary)
	}
	if summary["ranges_count"] != float64(2) || summary["bytes_captured"] != float64(24) {
		t.Fatalf("ranges wrong: %v", summary)
	}
	consistency := summary["capture_consistency"].(map[string]any)
	if consistency["state"] != "atomic" || consistency["execution_paused_by_tool"] != true || consistency["execution_resumed_after"] != true {
		t.Fatalf("atomic window facts wrong: %v", consistency)
	}
	if consistency["initial_run_state"] != "running" || consistency["final_run_state"] != "running" {
		t.Fatalf("run states wrong: %v", consistency)
	}
	if consistency["initial_frame_token"] != float64(1234) || consistency["final_frame_token"] != float64(1234) {
		t.Fatalf("frame tokens wrong: %v", consistency)
	}
	// Exactly one pause and one resume around the reads (the two vdp_status
	// calls carry the frame tokens).
	pauses, runs, reads := 0, 0, 0
	for _, action := range bridge.actions {
		switch action {
		case "pause":
			pauses++
		case "run":
			runs++
		case "read":
			reads++
		}
	}
	if pauses != 1 || runs != 1 || reads != 2 {
		t.Fatalf("capture action counts wrong: %v", bridge.actions)
	}
	pauseIndex, readIndexes, runIndex := -1, []int{}, -1
	for index, action := range bridge.actions {
		switch action {
		case "pause":
			pauseIndex = index
		case "read":
			readIndexes = append(readIndexes, index)
		case "run":
			runIndex = index
		}
	}
	if pauseIndex < 0 || runIndex < 0 || readIndexes[0] < pauseIndex || readIndexes[1] > runIndex {
		t.Fatalf("reads must sit inside the pause/resume window: %v", bridge.actions)
	}

	// All range artifacts share one capture id, stamped in provenance /2.
	captureID := summary["capture_id"].(string)
	if !strings.HasPrefix(captureID, "cap_") {
		t.Fatalf("capture id shape wrong: %v", captureID)
	}
	ranges := result["ranges"].([]any)
	var firstArtifactID string
	for index, entry := range ranges {
		view := entry.(map[string]any)
		descriptor := view["artifact"].(map[string]any)
		provenance := descriptor["provenance"].(map[string]any)
		if provenance["capture_id"] != captureID {
			t.Fatalf("range %d capture id mismatch: %v", index, provenance)
		}
		if provenance["artifact_schema"] != "artifact-provenance/2" {
			t.Fatalf("envelope not v2: %v", provenance)
		}
		if index == 0 {
			firstArtifactID = descriptor["id"].(string)
		}
		if view["name"] == "lives" && view["address_hex"] != "0xFF0000" {
			t.Fatalf("range address wrong: %v", view)
		}
	}

	// The manifest artifact exists with the same capture id and generation span.
	manifest := result["manifest"].(map[string]any)
	manifestProvenance := manifest["provenance"].(map[string]any)
	if manifestProvenance["capture_id"] != captureID {
		t.Fatalf("manifest capture id mismatch: %v", manifestProvenance)
	}
	if summary["target_generation_before"] == summary["target_generation_after"] {
		t.Fatalf("generation span must advance: %v", summary)
	}
	if summary["internal_lock_acquired"] != true {
		t.Fatalf("internal lock expected: %v", summary)
	}
	// The manifest bytes embed every range and the capture id.
	manifestBytes := mustArtifactBytes(t, server, manifest["id"].(string))
	if !strings.Contains(string(manifestBytes), captureID) || !strings.Contains(string(manifestBytes), "capture-manifest") {
		t.Fatalf("manifest content wrong: %s", manifestBytes)
	}
	_ = firstArtifactID
}

func TestMemorySnapshotCaptureAlreadyPaused(t *testing.T) {
	bridge := newConsistencyBridge(make([]byte, 8), 0)
	server := newTestServer(t, bridge.client)
	_ = structured(postToolCall(t, server, "cpu_pause", `{}`))
	bridge.actions = nil

	result := structured(postToolCall(t, server, "memory_snapshot_capture",
		`{"space":"m68k-bus","ranges":[{"name":"a","address":"0xFF0000","length":4}]}`))
	summary := result["summary"].(map[string]any)
	if summary["pause_resume_cycle"] != float64(0) {
		t.Fatalf("no pause expected when already paused: %v", summary)
	}
	consistency := summary["capture_consistency"].(map[string]any)
	if consistency["state"] != "atomic" || consistency["execution_paused_by_tool"] != false {
		t.Fatalf("already-paused capture facts wrong: %v", consistency)
	}
	for _, action := range bridge.actions {
		if action == "pause" || action == "run" {
			t.Fatalf("no pause/resume mutations expected: %v", bridge.actions)
		}
	}
	if reads := countActions(bridge.actions, "read"); reads != 1 {
		t.Fatalf("expected exactly one read: %v", bridge.actions)
	}
}

func countActions(actions []string, name string) int {
	count := 0
	for _, action := range actions {
		if action == name {
			count++
		}
	}
	return count
}

func TestMemorySnapshotCaptureValidation(t *testing.T) {
	bridge := newConsistencyBridge(make([]byte, 8), 0)
	server := newTestServer(t, bridge.client)
	cases := []string{
		`{"space":"m68k-bus","ranges":[{"name":"a","address":0,"length":4},{"name":"a","address":8,"length":4}]}`,       // duplicate names
		`{"space":"m68k-bus","ranges":[{"name":"bad name","address":0,"length":4}]}`,                                    // bad characters
		`{"space":"m68k-bus","ranges":[{"name":"a","address":0,"length":9000000}]}`,                                     // over per-range cap
		`{"space":"m68k-bus","ranges":[{"name":"a","address":0,"length":4},{"name":"b","address":0,"length":9000000}]}`, // total over cap
		`{"ranges":[{"name":"a","address":0,"length":4}]}`,                                                              // no space
	}
	for _, arguments := range cases {
		result := structured(postToolCall(t, server, "memory_snapshot_capture", arguments))
		if result["code"] != "invalid_params" {
			t.Fatalf("%s: code = %v (%v)", arguments, result["code"], result)
		}
	}
	if calls := len(bridge.client.recordedCalls); calls != 0 {
		t.Fatalf("validation failures must not reach the bridge: %d calls", calls)
	}
}

func TestMemoryDiffRejectsCrossCaptureMixing(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	context, failure := resolveContext(server, "")
	if failure != nil {
		t.Fatal(failure)
	}
	stamp := func(captureID string) string {
		start := uint64(0)
		length := uint64(4)
		generation := uint64(1)
		provenance := &artifact.Provenance{
			State:               artifact.ProvenanceStateComplete,
			Kind:                "memory-snapshot",
			AddressSpace:        "m68k-bus",
			StartAddress:        &start,
			EffectiveAddress:    &start,
			StartAddressHex:     "0x000000",
			EffectiveAddressHex: "0x000000",
			ByteLength:          &length,
			ByteOrder:           "big-endian",
			RawByteOrdering:     "address-order",
			CaptureID:           captureID,
			TargetGeneration:    &generation,
			CaptureConsistency:  &artifact.CaptureConsistency{State: "atomic"},
		}
		stored, err := server.store.PutWithProvenance(context.ID, "memory-snapshot", "application/octet-stream", []byte{1, 2, 3, 4}, provenance)
		if err != nil {
			t.Fatal(err)
		}
		return stored.ID
	}
	fromCaptureA := stamp("cap_AAA")
	fromCaptureB := stamp("cap_BBB")

	// Mixing artifacts from different composite captures fails by default.
	rejected := structured(postToolCall(t, server, "memory_diff",
		fmt.Sprintf(`{"snapshot_before_id":%q,"snapshot_after_id":%q,"mode":"changed"}`, fromCaptureA, fromCaptureB)))
	if rejected["code"] != "incompatible_provenance" {
		t.Fatalf("cross-capture diff must fail: %v", rejected)
	}
	joined := fmt.Sprintf("%v", rejected["reasons"])
	if !strings.Contains(joined, "different composite captures") || !strings.Contains(joined, "cap_AAA") {
		t.Fatalf("rejection must name both captures: %v", rejected)
	}

	// The escape hatch forces it with a prominent warning.
	forced := structured(postToolCall(t, server, "memory_diff",
		fmt.Sprintf(`{"snapshot_before_id":%q,"snapshot_after_id":%q,"mode":"changed","allow_incompatible_provenance":true}`, fromCaptureA, fromCaptureB)))
	if forced["code"] != nil {
		t.Fatalf("forced cross-capture diff failed: %v", forced)
	}
	summary := forced["summary"].(map[string]any)
	if summary["before_capture_id"] != "cap_AAA" || summary["after_capture_id"] != "cap_BBB" {
		t.Fatalf("capture ids missing from summary: %v", summary)
	}
	warning, _ := summary["provenance_warning"].(string)
	if !strings.Contains(warning, "no common address origin") {
		t.Fatalf("forced diff must warn: %v", summary)
	}

	// Ranges of the SAME composite capture are comparable without the flag.
	fromCaptureA2 := stamp("cap_AAA")
	compatible := structured(postToolCall(t, server, "memory_diff",
		fmt.Sprintf(`{"snapshot_before_id":%q,"snapshot_after_id":%q,"mode":"changed"}`, fromCaptureA, fromCaptureA2)))
	if compatible["code"] != nil {
		t.Fatalf("same-capture diff must pass: %v", compatible)
	}
}

func TestStateLoadReportsStateRestoredConsistency(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "state_save":
			if err := writeFileFromParam(params["path"], "zip-bytes"); err != nil {
				return nil, err
			}
			return json.RawMessage(`{"saved":true}`), nil
		case "state_load":
			return json.RawMessage(`{"restored":true,"system_running":false}`), nil
		default:
			return nil, fmt.Errorf("unexpected method %s", method)
		}
	}
	server := newTestServer(t, client)
	saved := structured(postToolCall(t, server, "state_save", `{}`))
	stateID := saved["state_id"].(string)
	loaded := structured(postToolCall(t, server, "state_load", fmt.Sprintf(`{"state_id":%q}`, stateID)))
	consistency := loaded["capture_consistency"].(map[string]any)
	if consistency["state"] != "state_restored" {
		t.Fatalf("state_load must report state_restored: %v", consistency)
	}
}

func TestVDPTileExportCompositeConsistency(t *testing.T) {
	// Chunked reads: the first chunk finds the system running (pause needed),
	// so the composite spans moments and must report composite_non_atomic.
	client := &fakeBridgeClient{status: newFakeStatus()}
	reads := 0
	vramTile := make([]byte, 32)
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		switch method {
		case "vdp_status":
			return json.RawMessage(`{"vdp_found":true,"registers":[],"decoded":{"display_enabled":true,"extended_vram":false},"image_buffer":{"last_rendered_frame_token":5}}`), nil
		case "vdp_mem_read":
			reads++
			var data []byte
			if reads%2 == 1 {
				data = vramTile
			} else {
				data = make([]byte, 128) // CRAM
			}
			payload := fmt.Sprintf(`{"target":"vram","address_space":"mem-vdp-vram","address":0,"length":%d,"entry_size":1,"buffer_size":65536,"byte_order":"big-endian","encoding":"base64","consistency":"live","system_paused_during_read":%t,"data":%q}`,
				len(data), reads == 1, base64.StdEncoding.EncodeToString(data))
			return json.RawMessage(payload), nil
		default:
			return nil, fmt.Errorf("unexpected method %s", method)
		}
	}
	server := newTestServer(t, client)
	result := structured(postToolCall(t, server, "vdp_tile_export", `{"tile":0,"count":1,"scale":1}`))
	if result["code"] != nil {
		t.Fatalf("tile export failed: %v", result)
	}
	summary := result["summary"].(map[string]any)
	consistency := summary["capture_consistency"].(map[string]any)
	if consistency["state"] != "composite_non_atomic" {
		t.Fatalf("mixed-frame export must be composite_non_atomic: %v", consistency)
	}
	if summary["coherent_snapshot"] != false {
		t.Fatalf("coherent flag wrong: %v", summary)
	}
	captureID := summary["capture_id"].(string)
	artifacts := result["artifacts"].([]any)
	for _, entry := range artifacts {
		descriptor := entry.(map[string]any)
		provenance := descriptor["provenance"].(map[string]any)
		if provenance["capture_id"] != captureID {
			t.Fatalf("export artifacts must share the capture id: %v", provenance)
		}
		if provenance["capture_consistency"].(map[string]any)["state"] != "composite_non_atomic" {
			t.Fatalf("artifact consistency wrong: %v", provenance)
		}
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------------------------------------------------

func mustArtifactBytes(t *testing.T, server *Server, id string) []byte {
	t.Helper()
	context, failure := resolveContext(server, "")
	if failure != nil {
		t.Fatal(failure)
	}
	data, _, err := server.store.Bytes(id, context.ID)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeFileFromParam(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
