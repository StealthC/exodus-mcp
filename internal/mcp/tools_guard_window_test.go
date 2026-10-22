package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

// guardWindowBridge is a minimal target for the composite capture tools. It
// keeps a live run state so a test can assert the machine state the capture
// left behind, and it answers the lightweight emulator_status observation the
// capture window uses when the run-state tracker holds no observation yet.
type guardWindowBridge struct {
	client  *fakeBridgeClient
	blob    []byte
	running bool
}

func newGuardWindowBridge(running bool) *guardWindowBridge {
	bridge := &guardWindowBridge{running: running, blob: make([]byte, 64)}
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "cpu_control":
			switch params["action"] {
			case "pause":
				bridge.running = false
			case "run":
				bridge.running = true
			default:
				return nil, fmt.Errorf("unexpected cpu_control action %q", params["action"])
			}
			return json.RawMessage(fmt.Sprintf(`{"action":%q,"system_running":%t}`, params["action"], bridge.running)), nil
		case "emulator_status":
			return json.RawMessage(fmt.Sprintf(`{"system_running":%t}`, bridge.running)), nil
		case "mem_read":
			return memReadFromBlob(bridge.blob, 0xFF0000)(ctx, method, params)
		case "vdp_status":
			return json.RawMessage(`{"vdp_found":true,"image_buffer":{"last_rendered_frame_token":9}}`), nil
		default:
			return nil, fmt.Errorf("unexpected method %s", method)
		}
	}
	bridge.client = client
	return bridge
}

// targetGeneration runs or pauses the machine and returns the generation the
// caller must pass as expected_target_generation for the following mutation.
func targetGeneration(t *testing.T, server *Server, tool string) uint64 {
	t.Helper()
	content := structured(postToolCall(t, server, tool, `{}`))
	generation, ok := content["target_generation"].(float64)
	if !ok {
		t.Fatalf("%s did not report a target generation: %v", tool, content)
	}
	return uint64(generation)
}

func runStateRestoreOf(t *testing.T, content map[string]any) map[string]any {
	t.Helper()
	restore, ok := content["run_state_restore"].(map[string]any)
	if !ok {
		t.Fatalf("response carries no run_state_restore object: %v", content)
	}
	return restore
}

// TestMemorySnapshotCaptureRestoresWithExpectedGeneration is the regression of
// issue #1: the pause consumed the caller's expected_target_generation, so the
// resume that follows was rejected and the machine stayed paused. A guarded
// capture must return the target in the run state it found.
func TestMemorySnapshotCaptureRestoresWithExpectedGeneration(t *testing.T) {
	bridge := newGuardWindowBridge(true)
	server := newTestServer(t, bridge.client)
	generation := targetGeneration(t, server, "cpu_run")

	content := structured(postToolCall(t, server, "memory_snapshot_capture",
		fmt.Sprintf(`{"space":"m68k-bus","ranges":[{"name":"a","address":"0xFF0000","length":8}],"expected_target_generation":%d}`, generation)))
	if content["code"] != nil {
		t.Fatalf("guarded capture failed: %v", content)
	}
	if !bridge.running {
		t.Fatalf("the guarded capture left the target paused: %v", content)
	}
	if content["run_state_restore_failed"] != nil {
		t.Fatalf("a successful restore must not report run_state_restore_failed: %v", content)
	}
	restore := runStateRestoreOf(t, content)
	if restore["code"] != "restored" {
		t.Fatalf("restore code = %v, want %v (restore object %v)", restore["code"], "restored", restore)
	}
	if restore["final_run_state"] != "running" || restore["resumed"] != true || restore["verified"] != true {
		t.Fatalf("restore object wrong: %v", restore)
	}
	summary := content["summary"].(map[string]any)
	consistency := summary["capture_consistency"].(map[string]any)
	if consistency["execution_paused_by_tool"] != true || consistency["execution_resumed_after"] != true {
		t.Fatalf("window facts wrong: %v", consistency)
	}
	if consistency["final_run_state"] != "running" {
		t.Fatalf("consistency final_run_state = %v, want running", consistency["final_run_state"])
	}
	if summary["final_run_state"] != "running" || summary["resumed"] != true {
		t.Fatalf("summary run-state facts wrong: %v", summary)
	}
}

// TestMemorySnapshotCapturePausedTargetStaysPaused: a guarded capture of an
// already paused target issues no pause and no resume, and the caller's
// expected generation is still honored.
func TestMemorySnapshotCapturePausedTargetStaysPaused(t *testing.T) {
	bridge := newGuardWindowBridge(true)
	server := newTestServer(t, bridge.client)
	generation := targetGeneration(t, server, "cpu_pause")

	content := structured(postToolCall(t, server, "memory_snapshot_capture",
		fmt.Sprintf(`{"space":"m68k-bus","ranges":[{"name":"a","address":"0xFF0000","length":8}],"expected_target_generation":%d}`, generation)))
	if content["code"] != nil {
		t.Fatalf("guarded capture failed: %v", content)
	}
	if bridge.running {
		t.Fatalf("the capture started an already paused target: %v", content)
	}
	restore := runStateRestoreOf(t, content)
	if restore["code"] != "already_paused" || restore["resumed"] != false {
		t.Fatalf("restore object wrong for an already paused target: %v", restore)
	}
	if restore["final_run_state"] != "paused" {
		t.Fatalf("final_run_state = %v, want paused", restore["final_run_state"])
	}
	if summary := content["summary"].(map[string]any); summary["pause_resume_cycle"] != float64(0) {
		t.Fatalf("no pause/resume cycle expected: %v", summary)
	}
}

// TestSystemSnapshotCaptureRestoresWithExpectedGeneration covers the second
// composite capture with the same defect.
func TestSystemSnapshotCaptureRestoresWithExpectedGeneration(t *testing.T) {
	bridge := newGuardWindowBridge(true)
	server := newTestServer(t, bridge.client)
	generation := targetGeneration(t, server, "cpu_run")

	content := structured(postToolCall(t, server, "system_snapshot_capture",
		fmt.Sprintf(`{"memory_ranges":[{"name":"ram","space":"m68k-bus","address":"0xFF0000","length":8}],"include_frame":false,"include_cram":false,"include_vsram":false,"include_vram":false,"include_sprite_table":false,"include_vdp_status":false,"include_m68k_registers":false,"include_z80_registers":false,"expected_target_generation":%d}`, generation)))
	if content["code"] != nil {
		t.Fatalf("guarded system snapshot failed: %v", content)
	}
	if !bridge.running {
		t.Fatalf("the guarded system snapshot left the target paused: %v", content)
	}
	restore := runStateRestoreOf(t, content)
	if restore["code"] != "restored" || restore["verified"] != true {
		t.Fatalf("restore object wrong: %v", restore)
	}
	summary := content["summary"].(map[string]any)
	consistency := summary["capture_consistency"].(map[string]any)
	if consistency["final_run_state"] != "running" || consistency["execution_resumed_after"] != true {
		t.Fatalf("window facts wrong: %v", consistency)
	}
	// The stored manifest provenance describes the same window as the
	// response, including the completed restore.
	manifest := content["manifest"].(map[string]any)
	provenance := manifest["provenance"].(map[string]any)
	artifactConsistency := provenance["capture_consistency"].(map[string]any)
	if artifactConsistency["final_run_state"] != "running" || artifactConsistency["execution_resumed_after"] != true {
		t.Fatalf("manifest provenance disagrees with the response: %v", artifactConsistency)
	}
}

// TestSystemSnapshotCapturePausedTargetStaysPaused mirrors the memory capture
// case for the cross-domain snapshot.
func TestSystemSnapshotCapturePausedTargetStaysPaused(t *testing.T) {
	bridge := newGuardWindowBridge(true)
	server := newTestServer(t, bridge.client)
	generation := targetGeneration(t, server, "cpu_pause")

	content := structured(postToolCall(t, server, "system_snapshot_capture",
		fmt.Sprintf(`{"memory_ranges":[{"name":"ram","space":"m68k-bus","address":"0xFF0000","length":8}],"include_frame":false,"include_cram":false,"include_vsram":false,"include_vram":false,"include_sprite_table":false,"include_vdp_status":false,"include_m68k_registers":false,"include_z80_registers":false,"expected_target_generation":%d}`, generation)))
	if content["code"] != nil {
		t.Fatalf("guarded system snapshot failed: %v", content)
	}
	if bridge.running {
		t.Fatalf("the system snapshot started an already paused target: %v", content)
	}
	restore := runStateRestoreOf(t, content)
	if restore["code"] != "already_paused" || restore["final_run_state"] != "paused" {
		t.Fatalf("restore object wrong: %v", restore)
	}
}
