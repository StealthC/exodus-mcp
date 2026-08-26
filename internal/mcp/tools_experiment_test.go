package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/StealthC/exodus-mcp/internal/analysis"
	"github.com/StealthC/exodus-mcp/internal/artifact"
	"github.com/StealthC/exodus-mcp/internal/bridge"
	"github.com/StealthC/exodus-mcp/internal/experiment"
)

// newExperimentServer builds a server whose experiment runner shares the
// server artifact store and owns the given scripts directory.
func newExperimentServer(t *testing.T, client bridge.Client, scriptsDir string) (*Server, *artifact.Store) {
	t.Helper()
	store, err := artifact.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer("test", client, store, analysis.NewRegistry(), "http://127.0.0.1")
	server.SetStatesDir(t.TempDir())
	runner, err := experiment.NewRunner(experiment.Config{
		ScriptsDir:      scriptsDir,
		ArtifactBaseURL: "http://127.0.0.1:8768",
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	server.SetExperimentRunner(runner)
	return server, store
}

func writeExperimentScript(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func fixtureBridge() *fakeBridgeClient {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "mem_read":
			return json.RawMessage(memReadPayload([]byte{0x53, 0x45, 0x47, 0x41}, "big-endian", 4096)), nil
		case "frame_advance":
			return json.RawMessage(`{"frames_completed":1,"frame_token":9}`), nil
		case "state_save":
			if err := os.WriteFile(params["path"], []byte("snapshot-bytes"), 0o600); err != nil {
				return nil, err
			}
			// Marshal the path so backslashes in Windows paths are escaped
			// (a raw interpolated "C:\Users\..." breaks JSON with \U).
			encoded, err := json.Marshal(map[string]string{"path": params["path"]})
			if err != nil {
				return nil, err
			}
			return json.RawMessage(encoded), nil
		case "state_load":
			return json.RawMessage(`{"loaded":true}`), nil
		}
		return json.RawMessage(`{}`), nil
	}
	return client
}

func TestExperimentCatalogIncludesTool(t *testing.T) {
	found := false
	for _, schema := range toolSchemas() {
		if schema["name"] != "experiment_run" {
			continue
		}
		found = true
		requiredValue := schema["inputSchema"].(map[string]any)["required"]
		var names []string
		switch values := requiredValue.(type) {
		case []string:
			names = values
		case []any:
			for _, value := range values {
				names = append(names, value.(string))
			}
		}
		if len(names) != 2 || strings.Join(names, ",") != "context,script" {
			t.Fatalf("experiment_run required = %v", names)
		}
	}
	if !found {
		t.Fatal("experiment_run missing from the tool catalog")
	}
}

func TestExperimentRunDisabledWithoutRunner(t *testing.T) {
	result := callTool(t, &fakeBridgeClient{status: newFakeStatus()}, "experiment_run",
		`{"context":"","script":"x.py"}`)
	content := structured(result)
	if result["isError"] != true || content["code"] != "experiments_disabled" {
		t.Fatalf("expected experiments_disabled: %v", result)
	}
}

func TestExperimentRunScriptResolutionFailures(t *testing.T) {
	client := fixtureBridge()
	server, _ := newExperimentServer(t, client, t.TempDir())
	for _, call := range []struct{ script, code string }{
		{"missing.py", "script_not_found"},
		{"../escape.py", "script_disallowed"},
		{"notes.txt", "script_disallowed"},
	} {
		result := postToolCall(t, server, "experiment_run",
			fmt.Sprintf(`{"context":"","script":%q}`, call.script))
		content := structured(result)
		if result["isError"] != true || content["code"] != call.code {
			t.Fatalf("%s: expected %s: %v", call.script, call.code, result)
		}
	}
}

func TestExperimentRunFixtureCompletesEndToEnd(t *testing.T) {
	client := fixtureBridge()
	scriptsDir := t.TempDir()
	writeExperimentScript(t, scriptsDir, "probe.json", `{
		"version": 1,
		"steps": [
			{"tool": "memory_read", "arguments": {"space": "m68k-ram", "address": 4096, "length": 4}},
			{"tool": "frame_advance", "arguments": {"frames": 1}},
			{"tool": "state_save", "arguments": {"name": "from-experiment"}}
		]
	}`)
	server, store := newExperimentServer(t, client, scriptsDir)

	before := structured(postToolCall(t, server, "memory_read", `{"space":"m68k-bus","address":0,"length":1}`))["target_generation"].(float64)
	result := postToolCall(t, server, "experiment_run",
		`{"context":"","script":"probe.json","timeout_ms":30000}`)
	if result["isError"] == true {
		t.Fatalf("experiment failed: %v", result)
	}
	content := structured(result)
	if content["status"] != "completed" {
		t.Fatalf("status = %v", content["status"])
	}
	if steps, _ := content["completed_steps"].(float64); steps != 3 {
		t.Fatalf("completed_steps = %v", content["completed_steps"])
	}
	if content["final_state_id"] == "" || content["final_state_id"] == nil {
		t.Fatalf("final_state_id missing: %v", content)
	}
	// The run is a mutation: the frame_advance step advanced the generation.
	if content["target_generation_before"] != before || content["target_generation_after"] != before+1 {
		t.Fatalf("experiment generations wrong: before %v after %v (started at %v)",
			content["target_generation_before"], content["target_generation_after"], before)
	}
	artifacts, _ := content["artifacts"].([]any)
	if len(artifacts) < 1 {
		t.Fatalf("no artifacts: %v", content)
	}
	manifestID := ""
	for _, entry := range artifacts {
		view := entry.(map[string]any)
		if view["kind"] == "experiment-manifest" {
			manifestID = view["id"].(string)
		}
	}
	if manifestID == "" {
		t.Fatalf("manifest artifact missing: %v", artifacts)
	}
	raw, _, err := store.Bytes(manifestID, server.contexts.Default().ID)
	if err != nil {
		t.Fatalf("manifest not in store: %v", err)
	}
	var manifest struct {
		Status   string            `json:"status"`
		Steps    []json.RawMessage `json:"steps"`
		ExitCode int               `json:"exit_code"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Status != "completed" || len(manifest.Steps) != 3 {
		t.Fatalf("manifest = %+v", manifest)
	}

	logResult := postToolCall(t, server, "context_mutation_log", `{"context":""}`)
	logContent := structured(logResult)
	entries, _ := logContent["entries"].([]any)
	recorded := false
	for _, entry := range entries {
		detail := entry.(map[string]any)
		if detail["tool"] == "experiment_run" {
			recorded = true
		}
	}
	if !recorded {
		t.Fatalf("mutation log lacks experiment_run: %v", entries)
	}
	// Every step went through the real handlers: the bridge saw mem_read,
	// frame_advance, and state_save in that order.
	methods := make([]string, 0, len(client.recordedCalls))
	for _, call := range client.recordedCalls {
		methods = append(methods, call.Method)
	}
	joined := strings.Join(methods, ",")
	if !strings.Contains(joined, "mem_read") || !strings.Contains(joined, "frame_advance") || !strings.Contains(joined, "state_save") {
		t.Fatalf("bridge methods = %v", methods)
	}
	// The script-supplied arguments carried the injected context and the
	// internal control id.
	if !strings.Contains(string(raw), `"context": "`+server.contexts.Default().ID) {
		t.Fatalf("manifest steps do not echo the injected context: %s", raw)
	}
	if !strings.Contains(string(raw), `"control_id": "ctl_`) {
		t.Fatalf("manifest steps do not echo the injected control id: %s", raw)
	}
	// The internal lock was released after the run and the audit records why.
	if server.controls.Active() != nil {
		t.Fatal("the internal experiment lock must be released after the run")
	}
	audit := structured(postToolCall(t, server, "target_audit_log", `{}`))
	foundEnd := false
	for _, entry := range audit["entries"].([]any) {
		view := entry.(map[string]any)
		if view["outcome"] == "lock_event" && view["detail"].(map[string]any)["reason"] == "experiment_completed" {
			foundEnd = true
		}
	}
	if !foundEnd {
		t.Fatalf("audit stream lacks the experiment_completed lock end: %v", audit["entries"])
	}
}

func TestExperimentRunReusesCallerControlLock(t *testing.T) {
	client := fixtureBridge()
	scriptsDir := t.TempDir()
	writeExperimentScript(t, scriptsDir, "read.json", `{
		"version": 1,
		"steps": [{"tool": "memory_read", "arguments": {"space": "m68k-ram", "address": 4096, "length": 4}}]
	}`)
	server, _ := newExperimentServer(t, client, scriptsDir)
	lock := structured(postToolCall(t, server, "target_control_acquire", `{"purpose":"manual experiment"}`))
	controlID := lock["control_id"].(string)

	result := postToolCall(t, server, "experiment_run",
		`{"context":"","script":"read.json","control_id":"`+controlID+`"}`)
	if result["isError"] == true {
		t.Fatalf("experiment with a caller lock must succeed: %v", result)
	}
	// The caller keeps ownership: the lock survives the run.
	if !server.controls.Valid(controlID) {
		t.Fatal("a reused caller lock must not be released by the run")
	}
	postToolCall(t, server, "target_control_release", `{"control_id":"`+controlID+`"}`)
}

func TestExperimentRunRejectsForeignControlID(t *testing.T) {
	client := fixtureBridge()
	scriptsDir := t.TempDir()
	writeExperimentScript(t, scriptsDir, "read.json", `{
		"version": 1,
		"steps": [{"tool": "memory_read", "arguments": {"space": "m68k-ram", "address": 4096, "length": 4}}]
	}`)
	server, _ := newExperimentServer(t, client, scriptsDir)
	result := postToolCall(t, server, "experiment_run",
		`{"context":"","script":"read.json","control_id":"ctl_wrong"}`)
	content := structured(result)
	if result["isError"] != true || content["code"] != "target_control_held" {
		t.Fatalf("foreign control id must be target_control_held: %v", result)
	}
	if len(client.recordedCalls) != 0 {
		t.Fatalf("rejected run must not reach the bridge: %v", client.recordedCalls)
	}
}

func TestExperimentRunInitialStateLoadsBeforeFirstStep(t *testing.T) {
	client := fixtureBridge()
	scriptsDir := t.TempDir()
	writeExperimentScript(t, scriptsDir, "read.json", `{
		"version": 1,
		"steps": [{"tool": "memory_read", "arguments": {"space": "m68k-ram", "address": 4096, "length": 4}}]
	}`)
	server, _ := newExperimentServer(t, client, scriptsDir)
	contextID := server.contexts.Default().ID

	snapshotPath := filepath.Join(t.TempDir(), "seed.zip")
	if err := os.WriteFile(snapshotPath, []byte("seed"), 0o600); err != nil {
		t.Fatal(err)
	}
	server.contexts.States.Create(contextID, &analysis.Snapshot{
		ID:        "state_seed",
		ContextID: contextID,
		Name:      "seed",
		Path:      snapshotPath,
		SHA256:    "abc",
		SizeBytes: 4,
		CreatedAt: time.Now().UTC(),
	})

	result := postToolCall(t, server, "experiment_run",
		`{"context":"","script":"read.json","initial_state_id":"state_seed"}`)
	if result["isError"] == true {
		t.Fatalf("experiment failed: %v", result)
	}
	content := structured(result)
	if content["initial_state_id"] != "state_seed" {
		t.Fatalf("initial_state_id = %v", content["initial_state_id"])
	}
	if len(client.recordedCalls) < 2 || client.recordedCalls[0].Method != "state_load" {
		t.Fatalf("state_load must precede the first step; calls = %v", client.recordedCalls)
	}
}

func TestExperimentRunRejectsNonAllowedTool(t *testing.T) {
	client := fixtureBridge()
	scriptsDir := t.TempDir()
	writeExperimentScript(t, scriptsDir, "escape.json", `{
		"version": 1,
		"steps": [{"tool": "cpu_run", "arguments": {}}]
	}`)
	server, store := newExperimentServer(t, client, scriptsDir)

	result := postToolCall(t, server, "experiment_run",
		`{"context":"","script":"escape.json"}`)
	if result["isError"] != true {
		t.Fatalf("expected failure: %v", result)
	}
	content := structured(result)
	if content["code"] != "experiment_failed" {
		t.Fatalf("code = %v", content["code"])
	}
	errorView, _ := content["error"].(map[string]any)
	if errorView["code"] != "step_failed" {
		t.Fatalf("error = %v", errorView)
	}
	if !strings.Contains(errorView["message"].(string), "cpu_run") {
		t.Fatalf("error message = %v", errorView["message"])
	}
	manifestID, _ := content["manifest"].(map[string]any)["id"].(string)
	if manifestID == "" {
		t.Fatalf("failed run must expose its manifest: %v", content)
	}
	if _, err := store.Metadata(manifestID, server.contexts.Default().ID); err != nil {
		t.Fatalf("manifest missing: %v", err)
	}
}

func TestExperimentRunInvalidArguments(t *testing.T) {
	client := fixtureBridge()
	server, _ := newExperimentServer(t, client, t.TempDir())
	result := postToolCall(t, server, "experiment_run",
		`{"context":"","script":"x.py","timeout_ms":0}`)
	content := structured(result)
	if result["isError"] != true || content["code"] != "invalid_params" {
		t.Fatalf("expected invalid_params: %v", result)
	}
}

func TestExperimentRunToolsListHasSchema(t *testing.T) {
	request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8768/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("MCP-Protocol-Version", ModernProtocolVersion)
	request.Header.Set("Mcp-Method", "tools/list")
	recorder := newRecorder()
	server, _ := newExperimentServer(t, &fakeBridgeClient{status: newFakeStatus()}, t.TempDir())
	server.Handler().ServeHTTP(recorder, request)
	if recorder.status != http.StatusOK {
		t.Fatalf("status = %d", recorder.status)
	}
	if !strings.Contains(recorder.body.String(), `"experiment_run"`) {
		t.Fatalf("tools/list lacks experiment_run: %s", recorder.body.String())
	}
}
