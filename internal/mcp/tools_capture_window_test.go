package mcp

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// captureWindowBridge is a target for the capture_mode guard tests. It keeps a
// live run state, records every cpu_control action, and can refuse the run-state
// observation so the "unknown pre-call state" path is reachable.
type captureWindowBridge struct {
	client        *fakeBridgeClient
	paused        bool
	unknownStatus bool
	actions       []string
	blob          []byte
}

func newCaptureWindowBridge(paused bool) *captureWindowBridge {
	bridge := &captureWindowBridge{paused: paused, blob: make([]byte, 64)}
	client := &fakeBridgeClient{status: newFakeStatus()}
	pixels := make([]byte, 3*2*2)
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "cpu_control":
			action := params["action"]
			bridge.actions = append(bridge.actions, action)
			switch action {
			case "pause":
				bridge.paused = true
			case "run":
				bridge.paused = false
			default:
				return nil, fmt.Errorf("unexpected cpu_control action %q", action)
			}
			return json.RawMessage(fmt.Sprintf(`{"action":%q,"system_running":%t}`, action, !bridge.paused)), nil
		case "emulator_status":
			if bridge.unknownStatus {
				return nil, fmt.Errorf("status unavailable")
			}
			return json.RawMessage(fmt.Sprintf(`{"system_running":%t}`, !bridge.paused)), nil
		case "mem_read":
			return memReadFromBlob(bridge.blob, 0xFF0000)(ctx, method, params)
		case "vdp_status":
			return json.RawMessage(`{"vdp_found":true,"image_buffer":{"last_rendered_frame_token":31}}`), nil
		case "vdp_mem_read":
			length := uint64(0)
			if _, err := fmt.Sscan(params["length"], &length); err != nil {
				return nil, err
			}
			payload := fmt.Sprintf(`{"target":%q,"address_space":"mem-vdp-vram","address":0,"length":%d,"entry_size":1,"buffer_size":65536,"byte_order":"big-endian","encoding":"base64","consistency":"live","system_paused_during_read":false,"data":%q}`,
				params["target"], length, base64.StdEncoding.EncodeToString(make([]byte, length)))
			return json.RawMessage(payload), nil
		case "frame_capture":
			return json.RawMessage(fmt.Sprintf(`{"width":2,"height":2,"pixel_format":"rgb24","encoding":"base64","frame_token":31,"data":%q}`,
				base64.StdEncoding.EncodeToString(pixels))), nil
		default:
			return nil, fmt.Errorf("unexpected method %s", method)
		}
	}
	bridge.client = client
	return bridge
}

// mustMap reads a nested object, failing the test instead of panicking when
// the response has no such field (a missing field is exactly what a broken
// contract looks like).
func mustMap(t *testing.T, value any, label string) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s is not an object: %v", label, value)
	}
	return object
}

func countCaptureActions(actions []string, name string) int {
	count := 0
	for _, action := range actions {
		if action == name {
			count++
		}
	}
	return count
}

// TestPausedCaptureLeavesPausedTargetPaused is the first regression of issue
// #8: a read with capture_mode "paused" must never start a machine that was
// already stopped.
func TestPausedCaptureLeavesPausedTargetPaused(t *testing.T) {
	bridge := newCaptureWindowBridge(true)
	server := newTestServer(t, bridge.client)
	// The tracker observed the paused machine, as any emulator_status call
	// would establish.
	server.runState.observe(server, false, nil)

	content := structured(postToolCall(t, server, "memory_read",
		`{"space":"m68k-bus","address":"0xFF0000","length":4,"capture_mode":"paused"}`))
	if content["code"] != nil {
		t.Fatalf("guarded read failed: %v", content)
	}
	if !bridge.paused {
		t.Fatalf("the guarded read resumed an already paused target: %v", content)
	}
	if len(bridge.actions) != 0 {
		t.Fatalf("an already paused target needs no run-state mutation: %v", bridge.actions)
	}
	if content["resumed"] != false || content["final_run_state"] != "paused" {
		t.Fatalf("run-state facts wrong: %v", content)
	}
	restore := mustMap(t, content["run_state_restore"], "run_state_restore")
	if restore["code"] != "already_paused" {
		t.Fatalf("restore code = %v, want already_paused", restore["code"])
	}
	consistency := mustMap(t, content["capture_consistency"], "capture_consistency")
	if consistency["state"] != "paused" || consistency["execution_paused_by_tool"] != false {
		t.Fatalf("an unperturbed paused capture must report the paused state: %v", consistency)
	}
}

// TestPausedCaptureUnknownRunStateIsNotResumed is the second regression of
// issue #8: when the pre-call run state cannot be established, the guard must
// not resume the target, because that could start a machine that was paused.
func TestPausedCaptureUnknownRunStateIsNotResumed(t *testing.T) {
	bridge := newCaptureWindowBridge(false)
	bridge.unknownStatus = true
	server := newTestServer(t, bridge.client)

	content := structured(postToolCall(t, server, "memory_read",
		`{"space":"m68k-bus","address":"0xFF0000","length":4,"capture_mode":"paused"}`))
	if content["code"] != nil {
		t.Fatalf("guarded read failed: %v", content)
	}
	if runs := countCaptureActions(bridge.actions, "run"); runs != 0 {
		t.Fatalf("an unknown pre-call state must never resume the target: %v", bridge.actions)
	}
	if resumes := countCaptureActions(bridge.actions, "pause"); resumes != 1 {
		t.Fatalf("the paused capture still pauses once: %v", bridge.actions)
	}
	if content["resumed"] != false || content["final_run_state"] != "paused" {
		t.Fatalf("run-state facts wrong: %v", content)
	}
	if content["initial_run_state"] != "unknown" {
		t.Fatalf("initial_run_state = %v, want unknown", content["initial_run_state"])
	}
	if content["resume_skipped_reason"] == nil {
		t.Fatalf("a skipped resume must state why: %v", content)
	}
	restore := mustMap(t, content["run_state_restore"], "run_state_restore")
	if restore["code"] != "resume_skipped_initial_run_state_unknown" {
		t.Fatalf("restore code = %v, want resume_skipped_initial_run_state_unknown", restore["code"])
	}
	consistency := mustMap(t, content["capture_consistency"], "capture_consistency")
	if consistency["initial_run_state"] != "unknown" || consistency["execution_resumed_after"] != false {
		t.Fatalf("consistency must stay honest about the unknown initial state: %v", consistency)
	}
}

// TestPausedCaptureArtifactProvenanceMatchesResponse is the third regression of
// issue #8: the durable artifact used to describe a different window than the
// response (live / execution_paused_by_tool false while the response said
// atomic). Every scenario compares the stored provenance with the response.
func TestPausedCaptureArtifactProvenanceMatchesResponse(t *testing.T) {
	cases := []struct {
		name          string
		setup         func(t *testing.T, server *Server, bridge *captureWindowBridge)
		wantState     string
		wantPaused    bool
		wantResumed   bool
		wantInitial   string
		wantFinal     string
		wantRestoreID string
	}{
		{
			name: "running",
			setup: func(t *testing.T, server *Server, _ *captureWindowBridge) {
				_ = structured(postToolCall(t, server, "cpu_run", `{}`))
			},
			wantState:     "atomic",
			wantPaused:    true,
			wantResumed:   true,
			wantInitial:   "running",
			wantFinal:     "running",
			wantRestoreID: "restored",
		},
		{
			name: "paused",
			setup: func(t *testing.T, server *Server, _ *captureWindowBridge) {
				_ = structured(postToolCall(t, server, "cpu_pause", `{}`))
			},
			wantState:     "paused",
			wantPaused:    false,
			wantResumed:   false,
			wantInitial:   "paused",
			wantFinal:     "paused",
			wantRestoreID: "already_paused",
		},
		{
			name:          "unknown",
			setup:         func(t *testing.T, server *Server, bridge *captureWindowBridge) { bridge.unknownStatus = true },
			wantState:     "atomic",
			wantPaused:    true,
			wantResumed:   false,
			wantInitial:   "unknown",
			wantFinal:     "paused",
			wantRestoreID: "resume_skipped_initial_run_state_unknown",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bridge := newCaptureWindowBridge(false)
			server := newTestServer(t, bridge.client)
			tc.setup(t, server, bridge)

			content := structured(postToolCall(t, server, "memory_dump",
				`{"space":"m68k-bus","address":"0xFF0000","length":8,"capture_mode":"paused"}`))
			if content["code"] != nil {
				t.Fatalf("guarded dump failed: %v", content)
			}
			response := mustMap(t, content["capture_consistency"], "capture_consistency")
			if response["state"] != tc.wantState {
				t.Fatalf("response state = %v, want %v (%v)", response["state"], tc.wantState, response)
			}
			if response["execution_paused_by_tool"] != tc.wantPaused || response["execution_resumed_after"] != tc.wantResumed {
				t.Fatalf("response window facts wrong: %v", response)
			}
			if response["initial_run_state"] != tc.wantInitial || response["final_run_state"] != tc.wantFinal {
				t.Fatalf("response run states wrong: %v", response)
			}
			if restore := mustMap(t, content["run_state_restore"], "run_state_restore"); restore["code"] != tc.wantRestoreID {
				t.Fatalf("restore code = %v, want %v", restore["code"], tc.wantRestoreID)
			}
			// The summary exposes the same object as the response.
			summary := mustMap(t, content["summary"], "summary")
			if !reflect.DeepEqual(summary["capture_consistency"], response) {
				t.Fatalf("summary consistency %v differs from response %v", summary["capture_consistency"], response)
			}
			// The stored artifact carries exactly the same window.
			artifact := mustMap(t, content["artifact"], "artifact")
			provenance := mustMap(t, artifact["provenance"], "artifact provenance")
			stored := mustMap(t, provenance["capture_consistency"], "artifact capture consistency")
			if !reflect.DeepEqual(stored, response) {
				t.Fatalf("artifact provenance %v differs from response %v", stored, response)
			}
			if provenance["consistency"] != tc.wantState {
				t.Fatalf("legacy consistency label = %v, want %v (derived from the object)", provenance["consistency"], tc.wantState)
			}
			// Issue #12: the response carries only the object, never a second
			// bare label that could disagree with it.
			if value, present := summary["consistency"]; present {
				t.Fatalf("response must not carry the deprecated consistency label, got %v", value)
			}
			// The stored metadata survives the response, so a later
			// artifact_describe sees the finalized window too.
			described := structured(postToolCall(t, server, "artifact_describe",
				fmt.Sprintf(`{"artifact_id":%q}`, artifact["id"].(string))))
			describedProvenance := mustMap(t, described["provenance"], "described provenance")
			if !reflect.DeepEqual(describedProvenance["capture_consistency"], response) {
				t.Fatalf("artifact_describe provenance %v differs from response %v", describedProvenance["capture_consistency"], response)
			}
		})
	}
}

// TestLiveCaptureProvenanceMatchesResponse covers the other half of the
// matrix: a live capture of a paused target reports the paused state in the
// object, in the response label, and in the stored provenance.
func TestLiveCaptureProvenanceMatchesResponse(t *testing.T) {
	bridge := newCaptureWindowBridge(true)
	server := newTestServer(t, bridge.client)
	server.runState.observe(server, false, nil)

	content := structured(postToolCall(t, server, "memory_dump",
		`{"space":"m68k-bus","address":"0xFF0000","length":8}`))
	if content["code"] != nil {
		t.Fatalf("live dump failed: %v", content)
	}
	if len(bridge.actions) != 0 {
		t.Fatalf("a live capture must never pause the target: %v", bridge.actions)
	}
	response := mustMap(t, content["capture_consistency"], "capture_consistency")
	if response["state"] != "paused" || response["execution_paused_by_tool"] != false {
		t.Fatalf("live capture of a paused target reports: %v", response)
	}
	summary := mustMap(t, content["summary"], "summary")
	if value, present := summary["consistency"]; present {
		t.Fatalf("response must not carry the deprecated consistency label, got %v", value)
	}
	artifact := mustMap(t, content["artifact"], "artifact")
	provenance := mustMap(t, artifact["provenance"], "artifact provenance")
	if provenance["consistency"] != "paused" {
		t.Fatalf("artifact consistency label = %v, want paused", provenance["consistency"])
	}
	if !reflect.DeepEqual(provenance["capture_consistency"], response) {
		t.Fatalf("artifact provenance %v differs from response %v", provenance["capture_consistency"], response)
	}
}

// TestPausedCaptureSingleArtifactProvenanceMatchesResponse extends the
// provenance agreement to the other capture_mode producers.
func TestPausedCaptureSingleArtifactProvenanceMatchesResponse(t *testing.T) {
	cases := []struct {
		tool      string
		arguments string
	}{
		{tool: "vdp_memory_export", arguments: `{"target":"vram","address":0,"length":8,"capture_mode":"paused"}`},
		{tool: "frame_capture", arguments: `{"capture_mode":"paused"}`},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			bridge := newCaptureWindowBridge(false)
			server := newTestServer(t, bridge.client)
			_ = structured(postToolCall(t, server, "cpu_run", `{}`))

			content := structured(postToolCall(t, server, tc.tool, tc.arguments))
			if content["code"] != nil {
				t.Fatalf("%s failed: %v", tc.tool, content)
			}
			response := mustMap(t, content["capture_consistency"], "capture_consistency")
			if response["state"] != "atomic" || response["execution_resumed_after"] != true {
				t.Fatalf("%s window facts wrong: %v", tc.tool, response)
			}
			artifact := mustMap(t, content["artifact"], "artifact")
			provenance := mustMap(t, artifact["provenance"], "artifact provenance")
			stored := mustMap(t, provenance["capture_consistency"], "artifact capture consistency")
			if !reflect.DeepEqual(stored, response) {
				t.Fatalf("%s artifact provenance %v differs from response %v", tc.tool, stored, response)
			}
			if provenance["consistency"] != "atomic" {
				t.Fatalf("%s legacy label = %v, want atomic", tc.tool, provenance["consistency"])
			}
		})
	}
}

// TestLiveCompositeCapturePublishesManifest: a live composite capture has no
// window pause, but it must still publish its manifest and report one
// consistency object for the manifest, the components, and the response.
func TestLiveCompositeCapturePublishesManifest(t *testing.T) {
	bridge := newCaptureWindowBridge(false)
	server := newTestServer(t, bridge.client)
	_ = structured(postToolCall(t, server, "cpu_run", `{}`))
	bridge.actions = nil

	content := structured(postToolCall(t, server, "vdp_capture",
		`{"include_cram":true,"include_vsram":false,"include_frame":false}`))
	if content["code"] != nil {
		t.Fatalf("live vdp_capture failed: %v", content)
	}
	if len(bridge.actions) != 0 {
		t.Fatalf("a live capture must never pause the target: %v", bridge.actions)
	}
	response := mustMap(t, content["capture_consistency"], "capture_consistency")
	if response["state"] != "live" || response["execution_paused_by_tool"] != false {
		t.Fatalf("live window facts wrong: %v", response)
	}
	manifest := mustMap(t, content["manifest"], "manifest")
	if manifest["id"] == nil {
		t.Fatalf("live composite capture produced no manifest: %v", content)
	}
	artifacts, _ := content["artifacts"].([]any)
	if len(artifacts) == 0 {
		t.Fatalf("live composite capture produced no artifacts: %v", content)
	}
	for _, entry := range artifacts {
		descriptor := mustMap(t, entry, "artifact descriptor")
		provenance := mustMap(t, descriptor["provenance"], "artifact provenance")
		stored := mustMap(t, provenance["capture_consistency"], "artifact capture consistency")
		if !reflect.DeepEqual(stored, response) {
			t.Fatalf("artifact %v provenance %v differs from response %v", descriptor["kind"], stored, response)
		}
	}
}

// TestPausedCaptureCompositeArtifactsMatchResponse checks the composite VDP
// capture, whose manifest and component artifacts are all written inside the
// window.
func TestPausedCaptureCompositeArtifactsMatchResponse(t *testing.T) {
	bridge := newCaptureWindowBridge(false)
	server := newTestServer(t, bridge.client)
	_ = structured(postToolCall(t, server, "cpu_run", `{}`))

	content := structured(postToolCall(t, server, "vdp_capture",
		`{"include_cram":true,"include_vsram":false,"include_frame":false,"capture_mode":"paused"}`))
	if content["code"] != nil {
		t.Fatalf("vdp_capture failed: %v", content)
	}
	response := mustMap(t, content["capture_consistency"], "capture_consistency")
	if response["state"] != "atomic" || response["execution_resumed_after"] != true {
		t.Fatalf("vdp_capture window facts wrong: %v", response)
	}
	artifacts, _ := content["artifacts"].([]any)
	if len(artifacts) == 0 {
		t.Fatalf("vdp_capture produced no artifacts: %v", content)
	}
	for _, entry := range artifacts {
		descriptor := mustMap(t, entry, "artifact descriptor")
		kind := descriptor["kind"]
		provenance := mustMap(t, descriptor["provenance"], "artifact provenance")
		stored := mustMap(t, provenance["capture_consistency"], "artifact capture consistency")
		if !reflect.DeepEqual(stored, response) {
			t.Fatalf("artifact %v provenance %v differs from response %v", kind, stored, response)
		}
	}
	// The manifest body links the component artifacts, so it must describe the
	// finished window too, not the provisional state it had mid-window.
	manifest := mustMap(t, content["manifest"], "manifest")
	manifestBytes := mustArtifactBytes(t, server, manifest["id"].(string))
	if !strings.Contains(string(manifestBytes), `"execution_resumed_after": true`) {
		t.Fatalf("vdp-capture manifest embeds a provisional window state: %s", manifestBytes)
	}
	if !strings.Contains(string(manifestBytes), `"final_run_state": "running"`) {
		t.Fatalf("vdp-capture manifest lacks the final run state: %s", manifestBytes)
	}
}

// TestROMInfoConsistencyLabelMatchesObject: rom_info has no capture_mode, but
// its header artifact used to stamp the literal label "live" next to a derived
// object that can say "paused".
func TestROMInfoConsistencyLabelMatchesObject(t *testing.T) {
	body := make([]byte, 0x400)
	fixture := buildMDROMFixture(body)
	expected := computeSegaChecksum(body)
	binary.BigEndian.PutUint16(fixture.Header[0x8E:0x90], expected)
	full := append(append([]byte{}, fixture.Header...), fixture.Body...)
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "emulator_status":
			return json.RawMessage(fmt.Sprintf(`{"system_running":false,"modules":[],"devices":[],"rom":{"loaded":true,"size_bytes":%d,"padded_size_bytes":%d,"path":"F:\\roms\\kid.bin"}}`, fixture.FileSize, fixture.FileSize)), nil
		case "mem_read":
			return memReadFromBlob(full, 0x100)(ctx, method, params)
		default:
			return nil, fmt.Errorf("unexpected method %s", method)
		}
	}
	server := newTestServer(t, client)

	content := structured(postToolCall(t, server, "rom_info", `{}`))
	if content["code"] != nil {
		t.Fatalf("rom_info failed: %v", content)
	}
	response := mustMap(t, content["capture_consistency"], "capture_consistency")
	if response["state"] != "paused" {
		t.Fatalf("rom_info must report the observed paused state: %v", response)
	}
	artifact := mustMap(t, content["artifact"], "artifact")
	provenance := mustMap(t, artifact["provenance"], "artifact provenance")
	if provenance["consistency"] != "paused" {
		t.Fatalf("rom_info legacy label = %v, want paused (derived from the object)", provenance["consistency"])
	}
	if !reflect.DeepEqual(provenance["capture_consistency"], response) {
		t.Fatalf("rom_info artifact provenance %v differs from response %v", provenance["capture_consistency"], response)
	}
}
