package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/StealthC/exodus-mcp/internal/analysis"
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

// ----------------------------------------------------------------------------------------------------------------------
// state_load run_state override
// ----------------------------------------------------------------------------------------------------------------------

// stateLoadOverrideResponder serves state_save/state_load plus cpu_control so
// the override path can be exercised.
func stateLoadOverrideResponder(t *testing.T, loadRunning bool) *fakeBridgeClient {
	t.Helper()
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "state_save":
			if err := os.MkdirAll(filepath.Dir(params["path"]), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(params["path"], []byte("override-state"), 0o644); err != nil {
				t.Fatal(err)
			}
			return json.RawMessage("{\"saved\":true,\"file_type\":\"zip\",\"system_running\":true}"), nil
		case "state_load":
			return json.RawMessage("{\"loaded\":true,\"file_type\":\"zip\",\"system_running\":" + boolString(loadRunning) + "}"), nil
		case "cpu_control":
			return json.RawMessage("{\"action\":\"" + params["action"] + "\",\"system_running\":" + boolString(params["action"] == "run") + "}"), nil
		}
		return json.RawMessage("{}"), nil
	}
	return client
}

func saveStateID(t *testing.T, server *Server) string {
	t.Helper()
	saved := structured(postToolCall(t, server, "state_save", "{}"))
	if saved["isError"] == true || saved["state_id"] == nil {
		t.Fatalf("state_save failed: %v", saved)
	}
	return saved["state_id"].(string)
}

func TestStateLoadRunStateOverridePaused(t *testing.T) {
	client := stateLoadOverrideResponder(t, true)
	server := newTestServer(t, client)
	server.SetStatesDir(t.TempDir())
	stateID := saveStateID(t, server)

	pre := server.target.Generation()
	loaded := structured(postToolCall(t, server, "state_load", "{\"state_id\":\""+stateID+"\",\"run_state\":\"paused\"}"))
	if loaded["isError"] == true {
		t.Fatalf("state_load failed: %v", loaded)
	}
	if loaded["run_state_override"] != "paused" {
		t.Fatalf("run_state_override = %v, want paused", loaded["run_state_override"])
	}
	if loaded["final_run_state"] != "paused" {
		t.Fatalf("final_run_state = %v, want paused", loaded["final_run_state"])
	}
	if loaded["system_running"] != false {
		t.Fatalf("system_running = %v, want false after the pause override", loaded["system_running"])
	}
	// load + override = two mutations.
	if got := server.target.Generation(); got != pre+2 {
		t.Fatalf("generation: load + override = 2 advances, got %d (before %d)", got, pre)
	}
	// Both mutations are audited under the state_load tool.
	entries, _ := server.audit.Query(analysis.AuditFilter{Tool: "state_load"})
	if len(entries) != 2 {
		t.Fatalf("expected two state_load audit entries, got %d", len(entries))
	}
	foundOverride := false
	for _, entry := range entries {
		if entry.Detail["reason"] == "state_load run_state override" {
			foundOverride = true
		}
	}
	if !foundOverride {
		t.Fatalf("override cpu_control must be audited: %+v", entries)
	}
}

func TestStateLoadRunStateOverrideRunning(t *testing.T) {
	client := stateLoadOverrideResponder(t, false)
	server := newTestServer(t, client)
	server.SetStatesDir(t.TempDir())
	stateID := saveStateID(t, server)

	loaded := structured(postToolCall(t, server, "state_load", "{\"state_id\":\""+stateID+"\",\"run_state\":\"running\"}"))
	if loaded["isError"] == true {
		t.Fatalf("state_load failed: %v", loaded)
	}
	if loaded["run_state_override"] != "running" {
		t.Fatalf("run_state_override = %v, want running", loaded["run_state_override"])
	}
	if loaded["final_run_state"] != "running" {
		t.Fatalf("final_run_state = %v, want running", loaded["final_run_state"])
	}
}

func TestStateLoadDefaultRestoreIssuesNoOverride(t *testing.T) {
	client := stateLoadOverrideResponder(t, false)
	server := newTestServer(t, client)
	server.SetStatesDir(t.TempDir())
	stateID := saveStateID(t, server)

	loaded := structured(postToolCall(t, server, "state_load", "{\"state_id\":\""+stateID+"\"}"))
	if loaded["isError"] == true {
		t.Fatalf("state_load failed: %v", loaded)
	}
	if loaded["run_state_override"] != "restore" {
		t.Fatalf("run_state_override = %v, want restore", loaded["run_state_override"])
	}
	if loaded["final_run_state"] != "paused" {
		t.Fatalf("final_run_state = %v, want paused (plugin restored paused)", loaded["final_run_state"])
	}
	// No cpu_control mutation after the load.
	entries, _ := server.audit.Query(analysis.AuditFilter{Tool: "state_load"})
	if len(entries) != 1 {
		t.Fatalf("expected exactly one state_load entry (no override), got %d", len(entries))
	}
}

func TestStateLoadRejectsUnknownRunState(t *testing.T) {
	client := stateLoadOverrideResponder(t, false)
	server := newTestServer(t, client)
	server.SetStatesDir(t.TempDir())
	stateID := saveStateID(t, server)

	result := postToolCall(t, server, "state_load", "{\"state_id\":\""+stateID+"\",\"run_state\":\"bogus\"}")
	content := structured(result)
	if result["isError"] != true || content["code"] != "invalid_params" {
		t.Fatalf("expected invalid_params for bogus run_state: %v", result)
	}
}
