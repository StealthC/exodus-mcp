package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/StealthC/exodus-mcp/internal/analysis"
)

// emulatorStatusResponder serves the emulator_status bridge operation with a
// fixed payload while passing every other method through as an empty object.
func emulatorStatusResponder(emulatorStatusBody string) func(context.Context, string, map[string]string) (json.RawMessage, error) {
	return func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		if method == "emulator_status" {
			return json.RawMessage(emulatorStatusBody), nil
		}
		return json.RawMessage(`{}`), nil
	}
}

// TestRunStateFirstObservationAttributedExternally: with no MCP run-state
// action and no prior observation, emulator_status derives ui_or_external and
// anchors last_run_state_change at the first observation without auditing a
// (non-existent) transition.
func TestRunStateFirstObservationAttributedExternally(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = emulatorStatusResponder(`{"system_running":true,"modules":[],"devices":[],"rom":{"loaded":false}}`)
	server := newTestServer(t, client)

	pre := server.target.Generation()
	result := postToolCall(t, server, "emulator_status", `{}`)
	content := structured(result)
	if content["pause_source"] != "ui_or_external" {
		t.Fatalf("pause_source = %v, want ui_or_external", content["pause_source"])
	}
	if content["last_run_state_change"] == nil {
		t.Fatalf("last_run_state_change must be present on first observation: %v", content)
	}
	if content["run_state_note"] == nil {
		t.Fatalf("run_state_note must explain the anchored timestamp: %v", content)
	}
	if got := server.target.Generation(); got != pre {
		t.Fatalf("generation advanced on external observation: before %d after %d", pre, got)
	}
	// A first observation is not a transition: no run_state_change event.
	assertNoRunStateChangeEvents(t, server)
}

// TestRunStateMCPPauseAttribution: cpu_pause sets the state to paused, and
// the following emulator_status attributes the pause to mcp.
func TestRunStateMCPPauseAttribution(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		if method == "cpu_control" {
			return json.RawMessage(`{"action":"pause","system_running":false}`), nil
		}
		return json.RawMessage(`{}`), nil
	}
	server := newTestServer(t, client)

	_ = postToolCall(t, server, "cpu_pause", `{}`)
	client.executeFunc = emulatorStatusResponder(`{"system_running":false,"modules":[],"devices":[],"rom":{"loaded":false}}`)
	result := postToolCall(t, server, "emulator_status", `{}`)
	content := structured(result)
	if content["pause_source"] != "mcp" {
		t.Fatalf("pause_source = %v, want mcp after cpu_pause", content["pause_source"])
	}
	assertNoRunStateChangeEvents(t, server)
}

// TestRunStateExternalTransitionAudited: an observation that contradicts the
// last MCP action is an external transition and lands in the audit stream as a
// run_state_change event without advancing target_generation.
func TestRunStateExternalTransitionAudited(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		if method == "cpu_control" {
			return json.RawMessage(`{"action":"pause","system_running":false}`), nil
		}
		return json.RawMessage(`{}`), nil
	}
	server := newTestServer(t, client)

	pre := server.target.Generation()
	_ = postToolCall(t, server, "cpu_pause", `{}`)
	if got := server.target.Generation(); got != pre+1 {
		t.Fatalf("cpu_pause must advance the generation once: before %d after %d", pre, got)
	}

	// The UI resumes the system without any MCP action.
	client.executeFunc = emulatorStatusResponder(`{"system_running":true,"modules":[],"devices":[],"rom":{"loaded":false}}`)
	result := postToolCall(t, server, "emulator_status", `{}`)
	content := structured(result)
	if content["pause_source"] != "ui_or_external" {
		t.Fatalf("pause_source = %v, want ui_or_external after an external resume", content["pause_source"])
	}
	if got := server.target.Generation(); got != pre+1 {
		t.Fatalf("generation must not advance on an external transition: before %d after %d", pre+1, got)
	}

	entries, _ := server.audit.Query(analysis.AuditFilter{Tool: "run_state_change"})
	if len(entries) != 1 {
		t.Fatalf("expected exactly one run_state_change audit event, got %d", len(entries))
	}
	entry := entries[0]
	if entry.Detail["system_running"] != true || entry.Detail["previous_system_running"] != false {
		t.Fatalf("run_state_change detail wrong: %v", entry.Detail)
	}
	if entry.Detail["observed_target_generation"] != uint64(pre+1) {
		t.Fatalf("run_state_change must carry the observed generation: %v", entry.Detail)
	}
	if entry.GenerationBefore != nil || entry.GenerationAfter != nil {
		t.Fatalf("run_state_change must not claim generation before/after: %v", entry)
	}
}

// TestRunStateMCPRunAfterExternalPauseNotDuplicated: an MCP resume that ends
// an earlier external pause is a normal mutation audit entry, never a second
// run_state_change event.
func TestRunStateMCPRunAfterExternalPauseNotDuplicated(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = emulatorStatusResponder(`{"system_running":false,"modules":[],"devices":[],"rom":{"loaded":false}}`)
	server := newTestServer(t, client)

	// First observation: paused, external (no MCP action preceded it).
	_ = postToolCall(t, server, "emulator_status", `{}`)
	pre := server.target.Generation()

	// MCP resumes the system.
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		if method == "cpu_control" {
			return json.RawMessage(`{"action":"run","system_running":true}`), nil
		}
		return json.RawMessage(`{}`), nil
	}
	_ = postToolCall(t, server, "cpu_run", `{}`)
	if got := server.target.Generation(); got != pre+1 {
		t.Fatalf("cpu_run must advance the generation: before %d after %d", pre, got)
	}

	assertNoRunStateChangeEvents(t, server)
}

func assertNoRunStateChangeEvents(t *testing.T, server *Server) {
	t.Helper()
	entries, _ := server.audit.Query(analysis.AuditFilter{Tool: "run_state_change"})
	if len(entries) != 0 {
		t.Fatalf("unexpected run_state_change events: %v", entries)
	}
}

// TestRunStateStateLoadAttribution: state_load restores the saved run state
// (paused here); the restored state is MCP-caused, so emulator_status reports
// pause_source "mcp" and no external run_state_change event is audited.
func TestRunStateStateLoadAttribution(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
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
			return json.RawMessage(`{"loaded":true,"file_type":"zip","system_running":false}`), nil
		}
		return json.RawMessage(`{}`), nil
	}
	server := newTestServer(t, client)
	server.SetStatesDir(t.TempDir())

	pre := server.target.Generation()
	saved := structured(postToolCall(t, server, "state_save", `{"name":"paused-state"}`))
	if saved["state_id"] == nil {
		t.Fatalf("state_save failed: %v", saved)
	}

	client.executeFunc = emulatorStatusResponder(`{"system_running":true,"modules":[],"devices":[],"rom":{"loaded":false}}`)
	// A live observation before the load: running, external (no MCP action).
	first := structured(postToolCall(t, server, "emulator_status", `{}`))
	if first["pause_source"] != "ui_or_external" {
		t.Fatalf("pause_source = %v, want ui_or_external before the load", first["pause_source"])
	}

	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method == "state_load" {
			return json.RawMessage(`{"loaded":true,"file_type":"zip","system_running":false}`), nil
		}
		return json.RawMessage(`{}`), nil
	}
	loaded := structured(postToolCall(t, server, "state_load", `{"state_id":"`+saved["state_id"].(string)+`"}`))
	if loaded["system_running"] != false {
		t.Fatalf("state_load must echo the restored run state: %v", loaded)
	}
	if got := server.target.Generation(); got != pre+1 {
		t.Fatalf("state_load must advance the generation once: before %d after %d", pre, got)
	}

	client.executeFunc = emulatorStatusResponder(`{"system_running":false,"modules":[],"devices":[],"rom":{"loaded":false}}`)
	after := structured(postToolCall(t, server, "emulator_status", `{}`))
	if after["pause_source"] != "mcp" {
		t.Fatalf("pause_source = %v, want mcp after an MCP state_load restored paused", after["pause_source"])
	}
	assertNoRunStateChangeEvents(t, server)
}
