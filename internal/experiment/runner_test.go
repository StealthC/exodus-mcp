package experiment

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/StealthC/exodus-mcp/internal/artifact"
)

// fakeExecutor records calls and serves canned values or errors per tool.
type fakeExecutor struct {
	mu      sync.Mutex
	calls   []fakeCall
	values  map[string]map[string]any
	errs    map[string]error
	blockCh chan struct{}
}

type fakeCall struct {
	tool string
	args map[string]any
}

func (executor *fakeExecutor) Call(ctx context.Context, tool string, arguments map[string]any) (map[string]any, error) {
	executor.mu.Lock()
	executor.calls = append(executor.calls, fakeCall{tool: tool, args: arguments})
	executor.mu.Unlock()
	if executor.blockCh != nil {
		select {
		case <-executor.blockCh:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err := executor.errs[tool]; err != nil {
		return nil, err
	}
	if value, present := executor.values[tool]; present {
		return value, nil
	}
	return map[string]any{}, nil
}

func (executor *fakeExecutor) recorded() []fakeCall {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	return append([]fakeCall(nil), executor.calls...)
}

func newRunner(t *testing.T, config Config) (*Runner, *artifact.Store) {
	t.Helper()
	store, err := artifact.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	config.ScriptsDir = t.TempDir()
	config.ArtifactBaseURL = "http://127.0.0.1:8767"
	runner, err := NewRunner(config, store)
	if err != nil {
		t.Fatal(err)
	}
	return runner, store
}

func loadScript(t *testing.T, runner *Runner, name, content string) *Script {
	t.Helper()
	if err := os.WriteFile(filepath.Join(runner.ScriptsDir(), name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	script, err := ResolveAndRead(runner.ScriptsDir(), name)
	if err != nil {
		t.Fatal(err)
	}
	return script
}

func runRequest(script *Script, executor Executor) RunRequest {
	return RunRequest{
		ExperimentID: "exp_test",
		ContextID:    "ctx_test",
		LeaseID:      "lease_test",
		Script:       script,
		Arguments:    map[string]any{"frames": 1},
		Exec:         executor,
	}
}

func TestRunFixtureCompletesAndStoresManifest(t *testing.T) {
	runner, store := newRunner(t, Config{})
	script := loadScript(t, runner, "smoke.json", `{
		"version": 1,
		"steps": [
			{"tool": "frame_advance", "arguments": {"frames": 2}},
			{"tool": "state_save", "arguments": {"name": "exp"}}
		]
	}`)
	executor := &fakeExecutor{
		values: map[string]map[string]any{
			"frame_advance": {"frames_completed": 2, "frame_token": 7},
			"state_save":    {"state_id": "state_roundtrip"},
		},
	}
	result, err := runner.Run(t.Context(), runRequest(script, executor))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Status != StatusCompleted {
		t.Fatalf("status = %q, error = %+v", result.Status, result.Error)
	}
	if result.FinalStateID != "state_roundtrip" {
		t.Fatalf("final state = %q", result.FinalStateID)
	}
	if len(result.Steps) != 2 {
		t.Fatalf("steps = %d", len(result.Steps))
	}
	if result.Steps[0].Tool != "frame_advance" || result.Steps[0].Status != "ok" {
		t.Fatalf("step 0 = %+v", result.Steps[0])
	}
	if !strings.Contains(string(result.Steps[0].Value), `"frames_completed":2`) {
		t.Fatalf("step value not echoed: %s", result.Steps[0].Value)
	}
	if result.Manifest.ID == "" {
		t.Fatal("manifest artifact missing")
	}
	if _, err := store.Metadata(result.Manifest.ID, "ctx_test"); err != nil {
		t.Fatalf("manifest lost from store: %v", err)
	}
	if _, err := store.Metadata(result.Manifest.ID, "ctx_other"); err == nil {
		t.Fatalf("manifest visible to a foreign context")
	}
	raw, _, err := store.Bytes(result.Manifest.ID, "ctx_test")
	if err != nil {
		t.Fatal(err)
	}
	var manifest manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("manifest is not JSON: %v", err)
	}
	if manifest.Status != StatusCompleted || manifest.ExperimentID != "exp_test" || manifest.Script.Name != "smoke.json" {
		t.Fatalf("manifest wrong: %+v", manifest)
	}
	if manifest.Arguments["frames"] != float64(1) {
		t.Fatalf("manifest arguments = %v", manifest.Arguments)
	}
	calls := executor.recorded()
	if len(calls) != 2 || calls[0].tool != "frame_advance" {
		t.Fatalf("executor calls = %+v", calls)
	}
}

func TestRunFixtureFailsOnStepError(t *testing.T) {
	runner, _ := newRunner(t, Config{})
	script := loadScript(t, runner, "bad.json", `{
		"version": 1,
		"steps": [{"tool": "cpu_run", "arguments": {}}]
	}`)
	executor := &fakeExecutor{
		errs: map[string]error{"cpu_run": &ToolError{Code: "tool_not_allowed", Message: `tool "cpu_run" is not on the experiment allowlist`}},
	}
	result, err := runner.Run(t.Context(), runRequest(script, executor))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Status != StatusFailed {
		t.Fatalf("status = %q", result.Status)
	}
	if result.Error == nil || result.Error.Code != "step_failed" {
		t.Fatalf("error = %+v", result.Error)
	}
	if !strings.Contains(result.Error.Message, "cpu_run") || !strings.Contains(result.Error.Message, "experiment allowlist") {
		t.Fatalf("error message = %q", result.Error.Message)
	}
	if len(result.Steps) != 1 || result.Steps[0].Error == nil || result.Steps[0].Error.Code != "tool_not_allowed" {
		t.Fatalf("step record = %+v", result.Steps)
	}
	if result.Manifest.ID == "" {
		t.Fatal("failed run must still store its manifest")
	}
}

func TestRunFixtureRejectsInvalidDeclarations(t *testing.T) {
	runner, _ := newRunner(t, Config{})
	for name, content := range map[string]string{
		"bad-version.json": `{"version": 2, "steps": []}`,
		"bad-json.json":    `{not json`,
		"no-steps.json":    `{"version": 1}`,
	} {
		script := loadScript(t, runner, name, content)
		result, err := runner.Run(t.Context(), runRequest(script, &fakeExecutor{}))
		if err != nil {
			t.Fatalf("%s: Run: %v", name, err)
		}
		if result.Status != StatusFailed || result.Error == nil || result.Error.Code != "fixture_invalid" {
			t.Fatalf("%s: status = %q error = %+v", name, result.Status, result.Error)
		}
	}
}

func TestRunFixtureTimeoutEndsBlockedStep(t *testing.T) {
	runner, _ := newRunner(t, Config{})
	script := loadScript(t, runner, "slow.json", `{
		"version": 1,
		"steps": [{"tool": "frame_advance", "arguments": {"frames": 1}}]
	}`)
	executor := &fakeExecutor{blockCh: make(chan struct{})}
	request := runRequest(script, executor)
	request.Timeout = 100 * time.Millisecond
	result, err := runner.Run(t.Context(), request)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Status != StatusFailed || result.Error == nil || result.Error.Code != "timeout" {
		t.Fatalf("status = %q error = %+v", result.Status, result.Error)
	}
}

func TestPythonHappyPathWithRealInterpreter(t *testing.T) {
	python := requirePython(t)
	runner, store := newRunner(t, Config{PythonCmd: python})
	script := loadScript(t, runner, "scan.py", `
import json, sys
init = json.loads(sys.stdin.readline())
assert init["type"] == "init", init
print(json.dumps({"type": "call", "id": "regs", "tool": "m68k_registers"}), flush=True)
regs = json.loads(sys.stdin.readline())
assert regs["type"] == "result" and regs["ok"] is True, regs
print(json.dumps({"type": "artifact", "id": "obs", "kind": "experiment-observations",
                  "mime_type": "application/json", "data_base64": "eyJvayI6MX0="}), flush=True)
obs = json.loads(sys.stdin.readline())
print(json.dumps({"type": "complete", "summary": {"pc": regs["value"]["pc"],
                                                  "obs_artifact": obs["value"]["id"]}}), flush=True)
`)
	executor := &fakeExecutor{
		values: map[string]map[string]any{"m68k_registers": {"pc": 0x1234}},
	}
	result, err := runner.Run(t.Context(), runRequest(script, executor))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Status != StatusCompleted {
		t.Fatalf("status = %q error = %+v output = %q", result.Status, result.Error, result.OutputText)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit code = %d", result.ExitCode)
	}
	if len(result.Steps) != 1 || result.Steps[0].Tool != "m68k_registers" || result.Steps[0].Status != "ok" {
		t.Fatalf("steps = %+v", result.Steps)
	}
	if pc, _ := result.Summary["pc"].(float64); pc != 0x1234 {
		t.Fatalf("summary = %+v", result.Summary)
	}
	if len(result.Artifacts) != 1 || result.Artifacts[0].Kind != "experiment-observations" {
		t.Fatalf("artifacts = %+v", result.Artifacts)
	}
	if _, err := store.Metadata(result.Artifacts[0].ID, "ctx_test"); err != nil {
		t.Fatalf("published artifact missing: %v", err)
	}
}

func TestPythonTimeoutKillsScript(t *testing.T) {
	python := requirePython(t)
	runner, _ := newRunner(t, Config{PythonCmd: python})
	script := loadScript(t, runner, "sleep.py", "import time\ntime.sleep(60)\n")
	request := runRequest(script, &fakeExecutor{})
	request.Timeout = 200 * time.Millisecond
	result, err := runner.Run(t.Context(), request)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Status != StatusFailed || result.Error == nil || result.Error.Code != "timeout" {
		t.Fatalf("status = %q error = %+v", result.Status, result.Error)
	}
	if result.DurationMS > 5000 {
		t.Fatalf("timeout did not bound the run: %d ms", result.DurationMS)
	}
}

func TestPythonProtocolViolation(t *testing.T) {
	python := requirePython(t)
	runner, _ := newRunner(t, Config{PythonCmd: python})
	script := loadScript(t, runner, "garbage.py", "import time\nprint('not json at all', flush=True)\ntime.sleep(30)\n")
	result, err := runner.Run(t.Context(), runRequest(script, &fakeExecutor{}))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Status != StatusFailed || result.Error == nil || result.Error.Code != "protocol_violation" {
		t.Fatalf("status = %q error = %+v", result.Status, result.Error)
	}
	if !strings.Contains(result.Error.Message, "not json at all") {
		t.Fatalf("error should excerpt the line: %q", result.Error.Message)
	}
}

func TestPythonDuplicateMessageIDFails(t *testing.T) {
	python := requirePython(t)
	runner, _ := newRunner(t, Config{PythonCmd: python})
	script := loadScript(t, runner, "dup.py", `
import json, sys, time
json.loads(sys.stdin.readline())
for _ in range(2):
    print(json.dumps({"type": "call", "id": "dup", "tool": "m68k_registers"}), flush=True)
    json.loads(sys.stdin.readline())
time.sleep(30)
`)
	result, err := runner.Run(t.Context(), runRequest(script, &fakeExecutor{}))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Status != StatusFailed || result.Error == nil || result.Error.Code != "duplicate_message_id" {
		t.Fatalf("status = %q error = %+v", result.Status, result.Error)
	}
}

func TestPythonArtifactTooLargeFails(t *testing.T) {
	python := requirePython(t)
	runner, _ := newRunner(t, Config{PythonCmd: python, MaxOutputBytes: 64})
	script := loadScript(t, runner, "huge-artifact.py", `
import json, sys, base64, time
json.loads(sys.stdin.readline())
print(json.dumps({"type": "artifact", "id": "a1", "kind": "obs",
                  "mime_type": "application/octet-stream",
                  "data_base64": base64.b64encode(b"x" * 100).decode()}), flush=True)
time.sleep(30)
`)
	result, err := runner.Run(t.Context(), runRequest(script, &fakeExecutor{}))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Status != StatusFailed || result.Error == nil || result.Error.Code != "artifact_too_large" {
		t.Fatalf("status = %q error = %+v", result.Status, result.Error)
	}
}

func TestPythonLineTooLongFails(t *testing.T) {
	python := requirePython(t)
	runner, _ := newRunner(t, Config{PythonCmd: python, MaxOutputBytes: 64})
	script := loadScript(t, runner, "flood.py", `
import time
print("x" * 70000, flush=True)
time.sleep(30)
`)
	result, err := runner.Run(t.Context(), runRequest(script, &fakeExecutor{}))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Status != StatusFailed || result.Error == nil || result.Error.Code != "output_line_too_long" {
		t.Fatalf("status = %q error = %+v", result.Status, result.Error)
	}
}

func requirePython(t *testing.T) string {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		python, err = exec.LookPath("python")
		if err != nil {
			t.Skip("no python interpreter available")
		}
	}
	return python
}
