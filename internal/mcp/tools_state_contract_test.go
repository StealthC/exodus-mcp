package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// stateContractResponder serves the state ops plus a paused observation for
// the state_load run-state contract tests.
func stateContractResponder(t *testing.T, loadRunning bool) *fakeBridgeClient {
	t.Helper()
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "state_save":
			if err := os.MkdirAll(filepath.Dir(params["path"]), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(params["path"], []byte("contract-state"), 0o644); err != nil {
				t.Fatal(err)
			}
			return json.RawMessage(`{"saved":true,"file_type":"zip","system_running":false}`), nil
		case "state_load":
			return json.RawMessage(`{"loaded":true,"file_type":"zip","system_running":` + boolString(loadRunning) + `}`), nil
		default:
			t.Fatalf("unexpected method %s", method)
			return nil, nil
		}
	}
	return client
}

// TestStateLoadReportsSavedAndFinalRunState: state_save records the last
// observed run state, state_list echoes it, and state_load reports both the
// saved and the final run state so no defensive pause is needed.
func TestStateLoadReportsSavedAndFinalRunState(t *testing.T) {
	client := stateContractResponder(t, true)
	server := newTestServer(t, client)
	server.SetStatesDir(t.TempDir())
	// The server observed a paused system before the save.
	server.runState.observe(server, false, nil)

	saved := structured(postToolCall(t, server, "state_save", `{"name":"paused-capture"}`))
	if saved["isError"] == true || saved["saved_run_state"] != "paused" {
		t.Fatalf("state_save must record saved_run_state paused: %v", saved)
	}
	stateID := saved["state_id"].(string)

	listed := structured(postToolCall(t, server, "state_list", `{}`))
	entry := listed["snapshots"].([]any)[0].(map[string]any)
	if entry["saved_run_state"] != "paused" {
		t.Fatalf("state_list must echo saved_run_state: %v", entry)
	}

	// The plugin restores a running system: final differs from saved and both
	// are reported.
	loaded := structured(postToolCall(t, server, "state_load", `{"state_id":"`+stateID+`"}`))
	if loaded["isError"] == true {
		t.Fatalf("state_load failed: %v", loaded)
	}
	if loaded["saved_run_state"] != "paused" {
		t.Fatalf("state_load saved_run_state = %v, want paused", loaded["saved_run_state"])
	}
	if loaded["final_run_state"] != "running" {
		t.Fatalf("state_load final_run_state = %v, want running", loaded["final_run_state"])
	}
	if loaded["system_running"] != true {
		t.Fatalf("payload system_running must stay merged: %v", loaded)
	}
}

// TestStateSaveUnknownRunState: without any observation the saved run state
// is reported honestly as unknown.
func TestStateSaveUnknownRunState(t *testing.T) {
	client := stateContractResponder(t, false)
	server := newTestServer(t, client)
	server.SetStatesDir(t.TempDir())

	saved := structured(postToolCall(t, server, "state_save", `{}`))
	if saved["isError"] == true {
		t.Fatalf("state_save failed: %v", saved)
	}
	if saved["saved_run_state"] != "unknown" {
		t.Fatalf("saved_run_state = %v, want unknown", saved["saved_run_state"])
	}
}
