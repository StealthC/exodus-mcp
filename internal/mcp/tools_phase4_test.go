package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/StealthC/exodus-mcp/internal/bridge"
)

// ----------------------------------------------------------------------------------------------------------------------
// Target control lock
// ----------------------------------------------------------------------------------------------------------------------

func TestTargetControlLifecycleThroughTools(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})

	acquired := structured(postToolCall(t, server, "target_control_acquire", `{"purpose":"boss fight"}`))
	controlID, _ := acquired["control_id"].(string)
	if controlID == "" || !strings.HasPrefix(controlID, "ctl_") {
		t.Fatalf("acquire returned no control id: %v", acquired)
	}
	if acquired["purpose"] != "boss fight" {
		t.Fatalf("purpose not echoed: %v", acquired)
	}
	if acquired["target_generation_at_acquire"] != float64(1) {
		t.Fatalf("generation at acquire wrong: %v", acquired)
	}

	// status never leaks the capability; it reports the holder summary.
	status := structured(postToolCall(t, server, "target_control_status", `{}`))
	if status["active"] != true || status["purpose"] != "boss fight" {
		t.Fatalf("status: %v", status)
	}
	if _, leaked := status["control_id"]; leaked {
		t.Fatalf("status must not expose the control id: %v", status)
	}

	// Passing the caller's own id reports held_by_caller.
	owned := structured(postToolCall(t, server, "target_control_status", `{"control_id":"`+controlID+`"}`))
	if owned["held_by_caller"] != true {
		t.Fatalf("status must confirm ownership: %v", owned)
	}

	renewed := structured(postToolCall(t, server, "target_control_renew", `{"control_id":"`+controlID+`"}`))
	if renewed["control_id"] != controlID {
		t.Fatalf("renew lost the control id: %v", renewed)
	}

	released := structured(postToolCall(t, server, "target_control_release", `{"control_id":"`+controlID+`"}`))
	if released["released"] != true {
		t.Fatalf("release failed: %v", released)
	}
	after := structured(postToolCall(t, server, "target_control_status", `{}`))
	if after["active"] != false {
		t.Fatalf("lock should be gone: %v", after)
	}
}

func TestTargetControlAcquireIsExclusive(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	first := structured(postToolCall(t, server, "target_control_acquire", `{"purpose":"a"}`))
	second := postToolCall(t, server, "target_control_acquire", `{"purpose":"b"}`)
	content := structured(second)
	if second["isError"] != true || content["code"] != "target_control_held" {
		t.Fatalf("second acquire must be target_control_held: %v", second)
	}
	if content["control_purpose"] != "a" {
		t.Fatalf("conflict must describe the incumbent purpose: %v", content)
	}
	if _, leaked := content["control_id"]; leaked {
		t.Fatalf("conflict must not leak the control id: %v", content)
	}
	_ = first
}

func TestTargetControlReleaseRequiresOwner(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	acquired := structured(postToolCall(t, server, "target_control_acquire", `{"purpose":"a"}`))
	controlID := acquired["control_id"].(string)
	release := postToolCall(t, server, "target_control_release", `{"control_id":"ctl_wrong"}`)
	content := structured(release)
	if release["isError"] != true || content["code"] != "control_invalid" {
		t.Fatalf("foreign release must be control_invalid: %v", release)
	}
	// Releasing when no lock exists is control_not_found.
	postToolCall(t, server, "target_control_release", `{"control_id":"`+controlID+`"}`)
	again := postToolCall(t, server, "target_control_release", `{"control_id":"`+controlID+`"}`)
	if content := structured(again); again["isError"] != true || content["code"] != "control_not_found" {
		t.Fatalf("release without a lock must be control_not_found: %v", again)
	}
}

func TestTargetControlValidatePurposeAndTTL(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	empty := postToolCall(t, server, "target_control_acquire", `{"purpose":""}`)
	if empty["isError"] != true || structured(empty)["code"] != "invalid_params" {
		t.Fatalf("empty purpose must fail: %v", empty)
	}
	badTTL := postToolCall(t, server, "target_control_acquire", `{"purpose":"x","ttl_ms":-1}`)
	if badTTL["isError"] != true || structured(badTTL)["code"] != "invalid_params" {
		t.Fatalf("negative ttl must fail: %v", badTTL)
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// Optimistic concurrency: target generation
// ----------------------------------------------------------------------------------------------------------------------

// TestUnconditionalSingleAgentMutationSucceeds is the core acceptance check:
// a plain mutation works without any lease, control lock, or generation.
func TestUnconditionalSingleAgentMutationSucceeds(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		return json.RawMessage(`{"written":"AA==","length":1,"space_id":"m68k-bus"}`), nil
	}
	server := newTestServer(t, client)
	result := postToolCall(t, server, "memory_write", `{"space":"m68k-bus","address":0,"data":"AA=="}`)
	content := structured(result)
	if result["isError"] == true {
		t.Fatalf("unconditional mutation must succeed: %v", content)
	}
	if content["target_generation_before"] != float64(1) || content["target_generation_after"] != float64(2) {
		t.Fatalf("generations before/after wrong: %v", content)
	}
	// The central stamp reports the current generation (the after value).
	if content["target_generation"] != float64(2) {
		t.Fatalf("central generation stamp wrong: %v", content)
	}
	if len(client.recordedCalls) != 1 {
		t.Fatalf("expected exactly one bridge call, got %d", len(client.recordedCalls))
	}
}

func TestGenerationConflictRejectsStaleCallerWithoutNativeAction(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		return json.RawMessage(`{"written":"AA==","length":1}`), nil
	}
	server := newTestServer(t, client)

	// Two clients share an observed generation from a read.
	observed := structured(postToolCall(t, server, "emulator_status", `{}`))["target_generation"].(float64)
	expected := uint64(observed)

	first := postToolCall(t, server, "memory_write", `{"space":"m68k-bus","address":0,"data":"AA==","expected_target_generation":`+formatUint(expected)+`}`)
	if first["isError"] == true {
		t.Fatalf("first guarded mutation must succeed: %v", structured(first))
	}

	// The second client still holds the stale generation.
	second := postToolCall(t, server, "memory_write", `{"space":"m68k-bus","address":0,"data":"AA==","expected_target_generation":`+formatUint(expected)+`}`)
	content := structured(second)
	if second["isError"] != true || content["code"] != "target_generation_conflict" {
		t.Fatalf("stale caller must get target_generation_conflict: %v", second)
	}
	if content["expected_target_generation"] != float64(expected) || content["target_generation"] != float64(expected+1) {
		t.Fatalf("conflict must report expected and current: %v", content)
	}
	if content["retry_hint"] == "" {
		t.Fatalf("conflict must carry a retry hint: %v", content)
	}
	// Exactly one native mem_write action ever reached the bridge (the
	// emulator_status observation does not count as a mutation).
	if got := countCalls(client, "mem_write"); got != 1 {
		t.Fatalf("conflict must not reach the bridge; calls = %v", client.recordedCalls)
	}

	// Re-reading re-establishes the caller and the retry succeeds.
	reObserved := structured(postToolCall(t, server, "emulator_status", `{}`))["target_generation"].(float64)
	retry := postToolCall(t, server, "memory_write", `{"space":"m68k-bus","address":0,"data":"AA==","expected_target_generation":`+formatUint(uint64(reObserved))+`}`)
	if retry["isError"] == true {
		t.Fatalf("retry with fresh generation must succeed: %v", structured(retry))
	}
	if got := countCalls(client, "mem_write"); got != 2 {
		t.Fatalf("retry must reach the bridge exactly once: %v", client.recordedCalls)
	}
}

func formatUint(value uint64) string {
	return strconv.FormatUint(value, 10)
}

// ----------------------------------------------------------------------------------------------------------------------
// Control lock gating
// ----------------------------------------------------------------------------------------------------------------------

func TestControlLockGatesForeignMutationsButNotReads(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method == "mem_read" {
			return json.RawMessage(`{"data":"AA==","byte_order":"big-endian","effective_address":0}`), nil
		}
		return json.RawMessage(`{"written":"AA==","length":1}`), nil
	}
	server := newTestServer(t, client)
	lock := structured(postToolCall(t, server, "target_control_acquire", `{"purpose":"boss fight"}`))
	controlID := lock["control_id"].(string)

	// Foreign mutation without the control id is rejected before the bridge.
	foreign := postToolCall(t, server, "memory_write", `{"space":"m68k-bus","address":0,"data":"AA=="}`)
	content := structured(foreign)
	if foreign["isError"] != true || content["code"] != "target_control_held" {
		t.Fatalf("foreign mutation must be target_control_held: %v", foreign)
	}
	if content["control_purpose"] != "boss fight" {
		t.Fatalf("held failure must name the purpose: %v", content)
	}
	if _, leaked := content["control_id"]; leaked {
		t.Fatalf("held failure must not leak the control id: %v", content)
	}
	// A stale control id is also foreign.
	stale := postToolCall(t, server, "memory_write", `{"space":"m68k-bus","address":0,"data":"AA==","control_id":"ctl_wrong"}`)
	if content := structured(stale); stale["isError"] != true || content["code"] != "target_control_held" {
		t.Fatalf("stale control id must be target_control_held: %v", stale)
	}
	if len(client.recordedCalls) != 0 {
		t.Fatalf("held mutations must not reach the bridge: %v", client.recordedCalls)
	}

	// The holder's mutations pass.
	held := postToolCall(t, server, "memory_write", `{"space":"m68k-bus","address":0,"data":"AA==","control_id":"`+controlID+`"}`)
	if held["isError"] == true {
		t.Fatalf("holder mutation must pass: %v", structured(held))
	}

	// Reads remain available to everyone.
	read := postToolCall(t, server, "memory_read", `{"space":"m68k-bus","address":0,"length":1}`)
	if read["isError"] == true {
		t.Fatalf("reads must stay available under a lock: %v", structured(read))
	}
	if len(client.recordedCalls) != 2 {
		t.Fatalf("expected 2 bridge calls (write + read), got %d", len(client.recordedCalls))
	}
}

func TestControlLockExpiryUnblocksMutations(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	lock := structured(postToolCall(t, server, "target_control_acquire", `{"purpose":"short","ttl_ms":20}`))
	_ = lock
	time.Sleep(60 * time.Millisecond)

	status := structured(postToolCall(t, server, "target_control_status", `{}`))
	if status["active"] != false {
		t.Fatalf("expired lock must be inactive: %v", status)
	}
	// Expiry releases only the lock; ordinary mutations resume.
	result := postToolCall(t, server, "memory_write", `{"space":"m68k-bus","address":0,"data":"AA=="}`)
	if result["isError"] == true {
		t.Fatalf("mutation after expiry must succeed: %v", structured(result))
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// memory_write
// ----------------------------------------------------------------------------------------------------------------------

func TestMemoryWriteEchoesAndRecordsAudit(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "mem_write" {
			t.Fatalf("method = %s, want mem_write", method)
		}
		if params["space"] != "m68k-bus" || params["address"] != "16711680" || params["length"] != "3" {
			t.Fatalf("params = %v", params)
		}
		if params["data"] != base64.StdEncoding.EncodeToString([]byte{0xDE, 0xAD, 0xBE}) {
			t.Fatalf("data = %s", params["data"])
		}
		return json.RawMessage(`{"space_id":"m68k-bus","kind":"bus","address":16711680,"effective_address":16711680,"length":3,"byte_order":"big-endian","encoding":"base64","consistency":"live","written":"3q2+","system_paused_during_write":true}`), nil
	}
	server := newTestServer(t, client)
	data := base64.StdEncoding.EncodeToString([]byte{0xDE, 0xAD, 0xBE})
	result := postToolCall(t, server, "memory_write", `{"space":"m68k-bus","address":"$FF0000","data":"`+data+`"}`)
	content := structured(result)
	if result["isError"] == true {
		t.Fatalf("unexpected error: %v", content)
	}
	if content["system_paused_during_write"] != true || content["length"] != float64(3) {
		t.Fatalf("payload not echoed: %v", content)
	}
	if content["target_generation_before"] != float64(1) || content["target_generation_after"] != float64(2) {
		t.Fatalf("generations wrong: %v", content)
	}

	log := structured(postToolCall(t, server, "context_mutation_log", `{}`))
	entries := log["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("mutation log must have one entry: %v", log)
	}
	entry := entries[0].(map[string]any)
	if entry["tool"] != "memory_write" {
		t.Fatalf("unexpected audit entry: %v", entry)
	}
	if entry["target_generation_before"] != float64(1) || entry["target_generation_after"] != float64(2) {
		t.Fatalf("audit generations wrong: %v", entry)
	}
	if entry["outcome"] != "ok" {
		t.Fatalf("audit outcome wrong: %v", entry)
	}
	detail := entry["detail"].(map[string]any)
	if detail["address"] != float64(16711680) || detail["length"] != float64(3) {
		t.Fatalf("audit detail: %v", detail)
	}
}

func TestMemoryWriteValidatesInput(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	for _, test := range []struct {
		args string
		code string
	}{
		{`{"space":"m68k-bus","address":0,"data":"not-base64!"}`, "invalid_params"},
		{`{"space":"m68k-bus","address":0,"data":""}`, "invalid_params"},
		{`{"space":"m68k-bus","address":-1,"data":"AA=="}`, "invalid_params"},
		{`{"space":"","address":0,"data":"AA=="}`, "invalid_params"},
	} {
		result := postToolCall(t, server, "memory_write", test.args)
		if content := structured(result); result["isError"] != true || content["code"] != test.code {
			t.Fatalf("args %s: expected %s, got %v", test.args, test.code, content)
		}
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// state_save / state_load / state_list
// ----------------------------------------------------------------------------------------------------------------------

func TestStateSaveLoadListCycle(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "mem_read":
			return json.RawMessage(memReadPayload([]byte{0x00}, "big-endian", 0)), nil
		case "state_save":
			if params["path"] == "" {
				t.Fatal("state_save without a path")
			}
			if err := os.MkdirAll(filepath.Dir(params["path"]), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(params["path"], []byte("fake-savestate-bytes"), 0o644); err != nil {
				t.Fatal(err)
			}
			return json.RawMessage(`{"saved":true,"file_type":"zip","system_running":true}`), nil
		case "state_load":
			if params["path"] == "" {
				t.Fatal("state_load without a path")
			}
			return json.RawMessage(`{"loaded":true,"file_type":"zip","system_running":true}`), nil
		default:
			t.Fatalf("unexpected method %s", method)
			return nil, nil
		}
	}
	server := newTestServer(t, client)
	server.SetStatesDir(t.TempDir())

	// state_save does not mutate the target: it must not advance the
	// generation and needs no lock.
	before := structured(postToolCall(t, server, "memory_read", `{"space":"m68k-bus","address":0,"length":1}`))["target_generation"].(float64)
	saved := postToolCall(t, server, "state_save", `{"name":"before-boss"}`)
	content := structured(saved)
	if saved["isError"] == true {
		t.Fatalf("state_save failed: %v", content)
	}
	stateID := content["state_id"].(string)
	if !strings.HasPrefix(stateID, "state_") {
		t.Fatalf("state id %q lacks prefix", stateID)
	}
	if content["sha256"] == "" || content["size_bytes"] != float64(len("fake-savestate-bytes")) {
		t.Fatalf("snapshot metadata missing: %v", content)
	}
	if content["system_running"] != true {
		t.Fatalf("plugin payload not merged: %v", content)
	}
	if content["target_generation"] != before {
		t.Fatalf("state_save must not advance the generation: before %v, after %v", before, content["target_generation"])
	}

	listed := structured(postToolCall(t, server, "state_list", `{}`))
	snapshots := listed["snapshots"].([]any)
	if len(snapshots) != 1 || snapshots[0].(map[string]any)["state_id"] != stateID {
		t.Fatalf("unexpected snapshot list: %v", listed)
	}
	if snapshots[0].(map[string]any)["name"] != "before-boss" {
		t.Fatalf("snapshot name missing: %v", snapshots[0])
	}
	if snapshots[0].(map[string]any)["target_generation"] != before {
		t.Fatalf("snapshot provenance missing: %v", snapshots[0])
	}

	loaded := postToolCall(t, server, "state_load", `{"state_id":"`+stateID+`"}`)
	content = structured(loaded)
	if loaded["isError"] == true {
		t.Fatalf("state_load failed: %v", content)
	}
	if content["loaded"] != true || content["state_id"] != stateID {
		t.Fatalf("state_load payload: %v", content)
	}
	// state_load mutates the target: generations advance.
	if content["target_generation_before"] != before || content["target_generation_after"] != before+1 {
		t.Fatalf("state_load generations wrong: %v", content)
	}

	// State from another context must not resolve.
	createdOther := structured(postToolCall(t, server, "context_create", `{"name":"other"}`))
	otherID := createdOther["context"].(map[string]any)["id"].(string)
	missing := postToolCall(t, server, "state_load", `{"context":"`+otherID+`","state_id":"`+stateID+`"}`)
	if content := structured(missing); missing["isError"] != true || content["code"] != "state_not_found" {
		t.Fatalf("cross-context load must fail: %v", missing)
	}
}

func TestStateLoadUnknownSnapshot(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	result := postToolCall(t, server, "state_load", `{"state_id":"state_missing"}`)
	if content := structured(result); result["isError"] != true || content["code"] != "state_not_found" {
		t.Fatalf("expected state_not_found: %v", result)
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// frame_advance and input_set
// ----------------------------------------------------------------------------------------------------------------------

func TestFrameAdvance(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "frame_advance" {
			t.Fatalf("method = %s", method)
		}
		if params["frames"] != "3" {
			t.Fatalf("frames = %v", params)
		}
		return json.RawMessage(`{"frames_requested":3,"frames_completed":3,"frame_token":1042,"system_running":false}`), nil
	}
	server := newTestServer(t, client)
	result := postToolCall(t, server, "frame_advance", `{"frames":3}`)
	content := structured(result)
	if result["isError"] == true {
		t.Fatalf("frame_advance failed: %v", content)
	}
	if content["frame_token"] != float64(1042) {
		t.Fatalf("frame token not echoed: %v", content)
	}
	if content["target_generation_before"] != float64(1) || content["target_generation_after"] != float64(2) {
		t.Fatalf("frame_advance generations wrong: %v", content)
	}

	overCap := postToolCall(t, server, "frame_advance", `{"frames":61}`)
	if content := structured(overCap); overCap["isError"] != true || content["code"] != "invalid_params" {
		t.Fatalf("frames over cap must fail: %v", overCap)
	}
}

func TestInputSetNormalizesAndValidates(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "input_set" {
			t.Fatalf("method = %s", method)
		}
		if params["player"] != "2" || params["buttons"] != "a,start" || params["state"] != "down" {
			t.Fatalf("params = %v", params)
		}
		return json.RawMessage(`{"player":2,"buttons":["a","start"],"state":"down","controller_instance":"Controller","button_count":2}`), nil
	}
	server := newTestServer(t, client)
	result := postToolCall(t, server, "input_set", `{"player":2,"buttons":["A","START"],"state":"down"}`)
	content := structured(result)
	if result["isError"] == true {
		t.Fatalf("input_set failed: %v", content)
	}
	if content["button_count"] != float64(2) {
		t.Fatalf("payload not echoed: %v", content)
	}

	badButton := postToolCall(t, server, "input_set", `{"buttons":["turbo"],"state":"down"}`)
	if content := structured(badButton); badButton["isError"] != true || content["code"] != "invalid_params" {
		t.Fatalf("unknown button must fail: %v", badButton)
	}
	badState := postToolCall(t, server, "input_set", `{"buttons":["a"],"state":"tap"}`)
	if content := structured(badState); badState["isError"] != true || content["code"] != "invalid_params" {
		t.Fatalf("tap state must fail: %v", badState)
	}
}

func TestControllerMissingSurfacesPluginError(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(context.Context, string, map[string]string) (json.RawMessage, error) {
		return nil, &bridge.CommandError{Code: "controller_not_found", Message: "No controller device is connected to player port 1"}
	}
	server := newTestServer(t, client)
	result := postToolCall(t, server, "input_set", `{"buttons":["a"],"state":"down"}`)
	if content := structured(result); result["isError"] != true || content["code"] != "controller_not_found" {
		t.Fatalf("expected controller_not_found: %v", result)
	}
}

func TestPhase4ToolsRejectUnknownContext(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	result := postToolCall(t, server, "memory_write", `{"context":"ctx_bogus","space":"m68k-bus","address":0,"data":"AA=="}`)
	if content := structured(result); result["isError"] != true || content["code"] != "unknown_context" {
		t.Fatalf("expected unknown_context: %v", result)
	}
}

func TestContextCloseReleasesControlLock(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	created := structured(postToolCall(t, server, "context_create", `{"name":"temp"}`))["context"].(map[string]any)
	contextID := created["id"].(string)
	lock := structured(postToolCall(t, server, "target_control_acquire", `{"context":"`+contextID+`","purpose":"a"}`))
	controlID := lock["control_id"].(string)
	postToolCall(t, server, "context_close", `{"context_id":"`+contextID+`"}`)
	if server.controls.Valid(controlID) {
		t.Fatal("closing the context must release its control lock")
	}
	// A lock acquired under another context survives that context's close.
	other := structured(postToolCall(t, server, "context_create", `{"name":"other"}`))["context"].(map[string]any)
	lock2 := structured(postToolCall(t, server, "target_control_acquire", `{"context":"`+other["id"].(string)+`","purpose":"b"}`))
	postToolCall(t, server, "context_close", `{"context_id":"`+contextID+`"}`)
	if !server.controls.Valid(lock2["control_id"].(string)) {
		t.Fatal("closing an unrelated context must not release the lock")
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// Ambiguous failures and resynchronization
// ----------------------------------------------------------------------------------------------------------------------

func TestAmbiguousFailureMarksUnknownAndGuardedMutationsWait(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	call := 0
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		call++
		if call == 1 {
			// The mutating command times out; its outcome is unknown.
			return nil, context.DeadlineExceeded
		}
		return json.RawMessage(`{"written":"AA==","length":1}`), nil
	}
	server := newTestServer(t, client)

	result := postToolCall(t, server, "memory_write", `{"space":"m68k-bus","address":0,"data":"AA=="}`)
	content := structured(result)
	if result["isError"] != true || content["code"] != "bridge_error" {
		t.Fatalf("ambiguous failure must surface bridge_error: %v", result)
	}
	if content["target_generation_state"] != "unknown" {
		t.Fatalf("failure must report the unknown state: %v", content)
	}

	// A guarded mutation is rejected until an observation re-establishes the
	// revision.
	guarded := postToolCall(t, server, "memory_write", `{"space":"m68k-bus","address":0,"data":"AA==","expected_target_generation":1}`)
	content = structured(guarded)
	if guarded["isError"] != true || content["code"] != "target_resynchronization_required" {
		t.Fatalf("guarded mutation while unknown must be rejected: %v", guarded)
	}
	if len(client.recordedCalls) != 1 {
		t.Fatalf("rejected guarded mutation must not reach the bridge: %v", client.recordedCalls)
	}

	// A successful read re-establishes the revision and advances it.
	read := postToolCall(t, server, "memory_read", `{"space":"m68k-bus","address":0,"length":1}`)
	if read["isError"] == true {
		t.Fatalf("read must succeed: %v", structured(read))
	}
	if structured(read)["target_generation"] != float64(2) {
		t.Fatalf("resync must advance the generation: %v", structured(read))
	}

	// The guarded retry now works with the fresh generation.
	retry := postToolCall(t, server, "memory_write", `{"space":"m68k-bus","address":0,"data":"AA==","expected_target_generation":2}`)
	if retry["isError"] == true {
		t.Fatalf("guarded retry after resync must succeed: %v", structured(retry))
	}
}

func TestAuditLogRecordsConflictsAndLockLifecycle(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})

	// A conflict entry has no generations and outcome conflict.
	postToolCall(t, server, "memory_write", `{"space":"m68k-bus","address":0,"data":"AA==","expected_target_generation":99}`)
	// A successful mutation follows.
	postToolCall(t, server, "memory_write", `{"space":"m68k-bus","address":0,"data":"AA=="}`)
	// Lock lifecycle events.
	lock := structured(postToolCall(t, server, "target_control_acquire", `{"purpose":"audit test"}`))
	postToolCall(t, server, "target_control_release", `{"control_id":"`+lock["control_id"].(string)+`"}`)

	log := structured(postToolCall(t, server, "target_audit_log", `{}`))
	entries := log["entries"].([]any)
	if len(entries) != 4 {
		t.Fatalf("expected 4 audit entries, got %v", log)
	}
	byTool := map[string]int{}
	outcomes := map[string]int{}
	for _, raw := range entries {
		entry := raw.(map[string]any)
		byTool[entry["tool"].(string)]++
		outcomes[entry["outcome"].(string)]++
	}
	if byTool["memory_write"] != 2 || byTool["target_control_acquire"] != 1 {
		t.Fatalf("tool counts wrong: %v", byTool)
	}
	if outcomes["conflict"] != 1 || outcomes["lock_event"] != 2 {
		t.Fatalf("outcome counts wrong: %v", outcomes)
	}
	// The newest entry is the lock end event with the recorded reason.
	newest := entries[0].(map[string]any)
	if newest["outcome"] != "lock_event" || newest["detail"].(map[string]any)["reason"] != "caller_released" {
		t.Fatalf("lock end audit wrong: %v", newest)
	}
	// The retained window metadata is present.
	retained := log["retained"].(map[string]any)
	if retained["operation_id_min"] == float64(0) || retained["operation_id_max"] == float64(0) {
		t.Fatalf("retained window missing: %v", retained)
	}

	// Filters: context projection and generation range.
	ctxLog := structured(postToolCall(t, server, "context_mutation_log", `{}`))
	if len(ctxLog["entries"].([]any)) != 2 {
		t.Fatalf("context projection must hold the 2 mutations: %v", ctxLog)
	}
	rangeLog := structured(postToolCall(t, server, "target_audit_log", `{"generation_min":1,"generation_max":1}`))
	if len(rangeLog["entries"].([]any)) != 1 {
		t.Fatalf("generation range filter wrong: %v", rangeLog)
	}
}
