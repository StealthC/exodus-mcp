package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/StealthC/exodus-mcp/internal/analysis"
)

// stateLoadPreserveBridge serves state_save/state_load plus cpu_control. The
// load echo is configurable so a test controls the run state the native restore
// leaves behind, and the bridge records every mutation for assertions.
type stateLoadPreserveBridge struct {
	client      *fakeBridgeClient
	loadRunning bool
	controls    []string
}

func newStateLoadPreserveBridge(loadRunning bool) *stateLoadPreserveBridge {
	bridge := &stateLoadPreserveBridge{loadRunning: loadRunning}
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "state_save":
			if err := os.WriteFile(params["path"], []byte("preserve-state"), 0o600); err != nil {
				return nil, err
			}
			return json.RawMessage(`{"saved":true,"file_type":"zip","system_running":true}`), nil
		case "state_load":
			return json.RawMessage(fmt.Sprintf(`{"loaded":true,"file_type":"zip","system_running":%t}`, bridge.loadRunning)), nil
		case "cpu_control":
			bridge.controls = append(bridge.controls, params["action"])
			return json.RawMessage(fmt.Sprintf(`{"action":%q,"system_running":%t}`, params["action"], params["action"] == "run")), nil
		default:
			return nil, fmt.Errorf("unexpected method %s", method)
		}
	}
	bridge.client = client
	return bridge
}

// saveStateForLoad saves one snapshot and returns its id and the target
// generation the caller must pass as expected_target_generation.
func saveStateForLoad(t *testing.T, bridge *stateLoadPreserveBridge) (*Server, string, uint64) {
	t.Helper()
	server := newTestServer(t, bridge.client)
	server.SetStatesDir(t.TempDir())
	saved := structured(postToolCall(t, server, "state_save", `{"name":"before-load"}`))
	if saved["state_id"] == nil {
		t.Fatalf("state_save failed: %v", saved)
	}
	generation, _ := saved["target_generation"].(float64)
	return server, saved["state_id"].(string), uint64(generation)
}

// TestStateLoadPreserveKeepsPreLoadRunState covers the documented contract:
// "preserve" reports final_run_state truthfully for both a paused and a running
// machine, issues no extra run-state mutation, and marks saved_run_state as
// historical metadata that the load never applies.
func TestStateLoadPreserveKeepsPreLoadRunState(t *testing.T) {
	cases := []struct {
		name        string
		loadRunning bool
		wantFinal   string
	}{
		{name: "paused", loadRunning: false, wantFinal: "paused"},
		{name: "running", loadRunning: true, wantFinal: "running"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bridge := newStateLoadPreserveBridge(tc.loadRunning)
			server, stateID, _ := saveStateForLoad(t, bridge)

			loaded := structured(postToolCall(t, server, "state_load",
				fmt.Sprintf(`{"state_id":%q,"run_state":"preserve"}`, stateID)))
			if loaded["code"] != nil {
				t.Fatalf("state_load failed: %v", loaded)
			}
			if loaded["final_run_state"] != tc.wantFinal {
				t.Fatalf("final_run_state = %v, want %v", loaded["final_run_state"], tc.wantFinal)
			}
			if loaded["final_run_state_verified"] != true {
				t.Fatalf("final_run_state must be verified from the native echo: %v", loaded)
			}
			if loaded["run_state_override"] != "preserve" {
				t.Fatalf("run_state_override = %v, want preserve", loaded["run_state_override"])
			}
			if loaded["saved_run_state"] == nil || loaded["saved_run_state_note"] == nil {
				t.Fatalf("saved_run_state must be reported with its historical note: %v", loaded)
			}
			if loaded["deprecated_parameter_value"] != nil {
				t.Fatalf("preserve must not report a deprecation: %v", loaded)
			}
			if len(bridge.controls) != 0 {
				t.Fatalf("preserve must not issue a run-state mutation: %v", bridge.controls)
			}
			entries, _ := server.audit.Query(analysis.AuditFilter{Tool: "state_load"})
			if len(entries) != 1 {
				t.Fatalf("expected exactly one state_load mutation, got %d", len(entries))
			}
		})
	}
}

// TestStateLoadRestoreAliasIsDeprecated: the legacy alias still works like
// preserve but says so instead of being silently reinterpreted.
func TestStateLoadRestoreAliasIsDeprecated(t *testing.T) {
	bridge := newStateLoadPreserveBridge(false)
	server, stateID, _ := saveStateForLoad(t, bridge)

	loaded := structured(postToolCall(t, server, "state_load",
		fmt.Sprintf(`{"state_id":%q,"run_state":"restore"}`, stateID)))
	if loaded["code"] != nil {
		t.Fatalf("state_load with the deprecated alias failed: %v", loaded)
	}
	deprecation, ok := loaded["deprecated_parameter_value"].(map[string]any)
	if !ok {
		t.Fatalf("restore must report deprecated_parameter_value: %v", loaded)
	}
	if deprecation["parameter"] != "run_state" || deprecation["replacement"] != "preserve" {
		t.Fatalf("deprecation record wrong: %v", deprecation)
	}
	if loaded["run_state_override"] != "preserve" {
		t.Fatalf("restore must resolve to preserve, got %v", loaded["run_state_override"])
	}
	if loaded["final_run_state"] != "paused" {
		t.Fatalf("restore must behave as preserve, final_run_state = %v", loaded["final_run_state"])
	}
	if len(bridge.controls) != 0 {
		t.Fatalf("the alias must not issue a run-state mutation: %v", bridge.controls)
	}
}

// TestStateLoadPreserveAcceptsExpectedGeneration: the load is the window's
// first mutation, so a current expected_target_generation is honored instead
// of being rejected.
func TestStateLoadPreserveAcceptsExpectedGeneration(t *testing.T) {
	bridge := newStateLoadPreserveBridge(false)
	server, stateID, generation := saveStateForLoad(t, bridge)

	loaded := structured(postToolCall(t, server, "state_load",
		fmt.Sprintf(`{"state_id":%q,"run_state":"preserve","expected_target_generation":%d}`, stateID, generation)))
	if loaded["code"] != nil {
		t.Fatalf("guarded state_load failed: %v", loaded)
	}
	if loaded["final_run_state"] != "paused" {
		t.Fatalf("final_run_state = %v, want paused", loaded["final_run_state"])
	}
}

// TestStateLoadOverrideWithExpectedGeneration is the regression of issue #4:
// the override reused the load's guard, so a caller that passed a valid
// expected_target_generation got a failed override after the load was already
// applied. The override is a follow-up mutation and must carry only the
// control id.
func TestStateLoadOverrideWithExpectedGeneration(t *testing.T) {
	cases := []struct {
		runState  string
		wantFinal string
		action    string
	}{
		{runState: "running", wantFinal: "running", action: "run"},
		{runState: "paused", wantFinal: "paused", action: "pause"},
	}
	for _, tc := range cases {
		t.Run(tc.runState, func(t *testing.T) {
			// The native load lands in the opposite state, so the override has
			// to change it and the final state proves the mutation ran.
			bridge := newStateLoadPreserveBridge(tc.action != "run")
			server, stateID, generation := saveStateForLoad(t, bridge)

			loaded := structured(postToolCall(t, server, "state_load",
				fmt.Sprintf(`{"state_id":%q,"run_state":%q,"expected_target_generation":%d}`, stateID, tc.runState, generation)))
			if loaded["code"] != nil {
				t.Fatalf("guarded override %q failed: %v", tc.runState, loaded)
			}
			if loaded["run_state_override"] != tc.runState {
				t.Fatalf("run_state_override = %v, want %v", loaded["run_state_override"], tc.runState)
			}
			if loaded["final_run_state"] != tc.wantFinal {
				t.Fatalf("final_run_state = %v, want %v", loaded["final_run_state"], tc.wantFinal)
			}
			if len(bridge.controls) != 1 || bridge.controls[0] != tc.action {
				t.Fatalf("override mutations = %v, want exactly one %q", bridge.controls, tc.action)
			}
		})
	}
}
