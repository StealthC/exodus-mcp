package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// replayFakeConfig configures replayFake. The zero value models an honest
// bridge: state_save writes a real file (so stat/hash succeed), state_load
// leaves the VDP render counter alone because the counter is not part of a
// saved state, frame_advance reports the advancing token, regs_get reports
// pc/a7/d0 derived from the frames this run advanced, and cpu_control verifies
// the resulting run state.
type replayFakeConfig struct {
	// startToken is the render counter the machine had already reached before
	// the replay began.
	startToken uint64
	// runningAtStart models a caller that left the machine running: the state
	// load preserves that run state, so the replay has to pause it once.
	runningAtStart bool
	// resetTokenOnLoad models a counter reset across the restore. The replay
	// must not depend on it: deltas are compared either way.
	resetTokenOnLoad bool
	// frameDriftStep adds frameDriftFrames to that step's advance in run 2,
	// injecting a per-step token divergence.
	frameDriftStep   int
	frameDriftFrames uint64
	// registerDrift adds a pc offset in run 2, injecting a CPU-state
	// divergence without changing the frame count.
	registerDrift bool
	// omitFrameToken makes frame_advance report no token at all.
	omitFrameToken bool
	// unreadableRegisters makes regs_get return no register map.
	unreadableRegisters bool
	// pauseEcho, when set, replaces the run state cpu_control echoes so a
	// pause that cannot be verified can be modelled.
	pauseEcho map[string]any
}

// replayFake builds a bridge that answers the deterministic_replay flow and
// keeps the render counter across state_load, exactly like the real plugin.
func replayFake(config replayFakeConfig) *fakeBridgeClient {
	client := &fakeBridgeClient{status: newFakeStatus()}
	token := config.startToken
	loads := 0
	runFrames := uint64(0)
	advances := 0
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "state_save":
			if err := os.WriteFile(params["path"], []byte("state-bytes"), 0o644); err != nil {
				return nil, err
			}
			return json.RawMessage(`{"saved":true}`), nil
		case "state_load":
			// The VDP render counter is not part of the saved state and this
			// bridge does not reset it unless the test asks for a reset.
			if config.resetTokenOnLoad {
				token = 0
			}
			loads++
			runFrames = 0
			advances = 0
			running := config.runningAtStart && loads == 1
			return json.RawMessage(fmt.Sprintf(`{"loaded":true,"system_running":%t}`, running)), nil
		case "vdp_status":
			return json.RawMessage(fmt.Sprintf(`{"vdp_found":true,"image_buffer":{"last_rendered_frame_token":%d}}`, token)), nil
		case "cpu_control":
			if config.pauseEcho != nil {
				encoded, _ := json.Marshal(config.pauseEcho)
				return json.RawMessage(encoded), nil
			}
			return json.RawMessage(`{"action":"pause","system_running":false}`), nil
		case "input_set":
			return json.RawMessage(`{}`), nil
		case "frame_advance":
			frames, err := strconv.ParseUint(params["frames"], 10, 64)
			if err != nil {
				return nil, err
			}
			if loads == 2 && advances == config.frameDriftStep {
				frames += config.frameDriftFrames
			}
			advances++
			token += frames
			runFrames += frames
			if config.omitFrameToken {
				return json.RawMessage(fmt.Sprintf(`{"frames_requested":%d,"frames_completed":%d,"system_running":false}`, frames, frames)), nil
			}
			return json.RawMessage(fmt.Sprintf(`{"frames_requested":%d,"frames_completed":%d,"frame_token":%d,"system_running":false}`, frames, frames, token)), nil
		case "regs_get":
			if config.unreadableRegisters {
				return json.RawMessage(`{"cpu":"m68k","byte_order":"big-endian"}`), nil
			}
			pc := uint64(0x200) + runFrames*2
			if config.registerDrift && loads == 2 {
				pc += 0x100
			}
			return json.RawMessage(fmt.Sprintf(`{"cpu":"m68k","byte_order":"not-applicable","system_paused_during_read":false,"registers":{"pc":%d,"a7":16776672,"d0":%d},"flags":{},"width_bits":32}`, pc, runFrames)), nil
		default:
			return json.RawMessage(`{}`), nil
		}
	}
	return client
}

// replayContent calls the tool and returns its structured content, failing on
// an error result.
func replayContent(t *testing.T, client *fakeBridgeClient, arguments string) map[string]any {
	t.Helper()
	result := callTool(t, client, "deterministic_replay", arguments)
	if result["isError"] == true {
		t.Fatalf("unexpected error: %v", structured(result))
	}
	return structured(result)
}

// replayChecks indexes the named checks of a response.
func replayChecks(content map[string]any) map[string]map[string]any {
	checks := map[string]map[string]any{}
	entries, _ := content["checks"].([]any)
	for _, entry := range entries {
		check, _ := entry.(map[string]any)
		if name, ok := check["name"].(string); ok {
			checks[name] = check
		}
	}
	return checks
}

// replayRun returns one run view.
func replayRun(t *testing.T, content map[string]any, key string) map[string]any {
	t.Helper()
	run, ok := content[key].(map[string]any)
	if !ok {
		t.Fatalf("%s missing from response: %v", key, content)
	}
	return run
}

// uintSlice renders a JSON number array as uint64s.
func uintSlice(t *testing.T, value any, label string) []uint64 {
	t.Helper()
	raw, ok := value.([]any)
	if !ok {
		t.Fatalf("%s = %v, want an array", label, value)
	}
	out := make([]uint64, len(raw))
	for index, entry := range raw {
		number, ok := entry.(float64)
		if !ok {
			t.Fatalf("%s[%d] = %v, want a number", label, index, entry)
		}
		out[index] = uint64(number)
	}
	return out
}

// TestDeterministicReplayComparesPerStepDeltas is the regression test for the
// reported defect: the VDP render counter keeps counting across the restore
// between the runs, so absolute tokens always differ. Only the per-step delta
// from each run's own baseline is comparable.
func TestDeterministicReplayComparesPerStepDeltas(t *testing.T) {
	content := replayContent(t, replayFake(replayFakeConfig{startToken: 500, runningAtStart: true}),
		`{"steps":[{"inputs":{"1":["a","b"]},"frames":2},{"inputs":{"2":["start"]},"frames":1}]}`)

	if content["deterministic"] != true {
		t.Fatalf("deterministic = %v, want true: %v", content["deterministic"], content)
	}
	if content["frame_token_comparison"] != "per_step_delta_from_run_baseline" {
		t.Fatalf("frame_token_comparison = %v", content["frame_token_comparison"])
	}
	run1 := replayRun(t, content, "run_1")
	run2 := replayRun(t, content, "run_2")
	if run1["frame_token_baseline"] != float64(500) {
		t.Fatalf("run_1 frame_token_baseline = %v, want 500", run1["frame_token_baseline"])
	}
	if run2["frame_token_baseline"] != float64(503) {
		t.Fatalf("run_2 frame_token_baseline = %v, want 503 (the counter is not reset by state_load)", run2["frame_token_baseline"])
	}
	tokens1 := uintSlice(t, run1["frame_tokens"], "run_1 frame_tokens")
	tokens2 := uintSlice(t, run2["frame_tokens"], "run_2 frame_tokens")
	if tokens1[0] == tokens2[0] {
		t.Fatalf("absolute tokens matched across runs (%v); the fixture must exercise a counter that keeps counting", tokens1)
	}
	if len(tokens1) != 2 || len(tokens2) != 2 || tokens1[1] != 503 || tokens2[1] != 506 {
		t.Fatalf("absolute tokens = run 1 %v / run 2 %v, want [502 503] / [505 506]", tokens1, tokens2)
	}
	if deltas := uintSlice(t, run1["frame_token_deltas"], "run_1 frame_token_deltas"); len(deltas) != 2 || deltas[0] != 2 || deltas[1] != 3 {
		t.Fatalf("run_1 frame_token_deltas = %v, want [2 3]", deltas)
	}
	if deltas := uintSlice(t, run2["frame_token_deltas"], "run_2 frame_token_deltas"); len(deltas) != 2 || deltas[0] != 2 || deltas[1] != 3 {
		t.Fatalf("run_2 frame_token_deltas = %v, want [2 3]", deltas)
	}
	if unproven, _ := content["unproven"].([]any); len(unproven) != 0 {
		t.Fatalf("unproven = %v, want none", unproven)
	}
	if _, exists := content["diverged_step"]; exists {
		t.Fatalf("diverged_step reported for a matching replay: %v", content["diverged_step"])
	}
	if content["pause_resume_cycle"] != float64(1) {
		t.Fatalf("pause_resume_cycle = %v, want 1 (only the running start had to be paused; the between-runs restore was already paused)", content["pause_resume_cycle"])
	}
	for key := range map[string]bool{"run_1": true, "run_2": true} {
		run := replayRun(t, content, key)
		if run["initial_run_state"] != "paused" || run["initial_run_state_verified"] != true {
			t.Fatalf("%s initial_run_state = %v (verified %v), want paused/verified", key, run["initial_run_state"], run["initial_run_state_verified"])
		}
	}
	if content["final_run_state"] != "paused" || content["restored"] != true {
		t.Fatalf("final_run_state = %v restored = %v", content["final_run_state"], content["restored"])
	}
	artifact, _ := content["artifact"].(map[string]any)
	if artifact["kind"] != "replay-manifest" {
		t.Fatalf("artifact kind = %v", artifact["kind"])
	}
	if content["initial_state_id"] == "" {
		t.Fatalf("initial_state_id missing from result")
	}
}

// TestDeterministicReplayDoesNotDependOnTokenReset proves the verdict survives a
// bridge that resets the counter on load as well as one that does not.
func TestDeterministicReplayDoesNotDependOnTokenReset(t *testing.T) {
	content := replayContent(t, replayFake(replayFakeConfig{startToken: 500, resetTokenOnLoad: true}),
		`{"steps":[{"inputs":{"1":["a"]},"frames":2}]}`)
	if content["deterministic"] != true {
		t.Fatalf("deterministic = %v, want true: %v", content["deterministic"], content)
	}
	run2 := replayRun(t, content, "run_2")
	if run2["frame_token_baseline"] != float64(0) {
		t.Fatalf("run_2 frame_token_baseline = %v, want 0 with a resetting bridge", run2["frame_token_baseline"])
	}
	if deltas := uintSlice(t, run2["frame_token_deltas"], "run_2 frame_token_deltas"); len(deltas) != 1 || deltas[0] != 2 {
		t.Fatalf("run_2 frame_token_deltas = %v, want [2]", deltas)
	}
}

// TestDeterministicReplayReportsDivergedStep injects a per-step difference and
// asserts the response names the step and both observed values.
func TestDeterministicReplayReportsDivergedStep(t *testing.T) {
	content := replayContent(t, replayFake(replayFakeConfig{startToken: 10, frameDriftStep: 1, frameDriftFrames: 2}),
		`{"steps":[{"inputs":{"1":["a"]},"frames":2},{"inputs":{"1":["b"]},"frames":1}]}`)
	if content["deterministic"] != false {
		t.Fatalf("deterministic = %v, want false: %v", content["deterministic"], content)
	}
	diverged, ok := content["diverged_step"].(map[string]any)
	if !ok {
		t.Fatalf("diverged_step missing: %v", content)
	}
	if diverged["step"] != float64(1) || diverged["field"] != "frame_token_delta" {
		t.Fatalf("diverged_step = %v, want step 1 / frame_token_delta", diverged)
	}
	if diverged["run1"] != float64(3) || diverged["run2"] != float64(5) {
		t.Fatalf("diverged_step values = run1 %v run2 %v, want 3 and 5", diverged["run1"], diverged["run2"])
	}
	checks := replayChecks(content)
	if check := checks["frame_token_deltas_match"]; check == nil || check["passed"] != false {
		t.Fatalf("frame_token_deltas_match = %v, want a failed check", check)
	}
	if detail, _ := checks["frame_token_deltas_match"]["detail"].(string); detail == "" {
		t.Fatalf("failed check carries no detail: %v", checks["frame_token_deltas_match"])
	}
	divergences, _ := content["divergences"].([]any)
	if len(divergences) == 0 {
		t.Fatalf("divergences missing from response: %v", content)
	}
}

// TestDeterministicReplayRegistersAttributeDivergenceToStep injects a CPU-state
// difference that leaves the frame count untouched.
func TestDeterministicReplayRegistersAttributeDivergenceToStep(t *testing.T) {
	content := replayContent(t, replayFake(replayFakeConfig{registerDrift: true}),
		`{"steps":[{"inputs":{"1":["a"]},"frames":1}]}`)
	if content["deterministic"] != false {
		t.Fatalf("deterministic = %v, want false: %v", content["deterministic"], content)
	}
	diverged, ok := content["diverged_step"].(map[string]any)
	if !ok {
		t.Fatalf("diverged_step missing: %v", content)
	}
	if diverged["field"] != "step_registers.m68k_pc" || diverged["step"] != float64(0) {
		t.Fatalf("diverged_step = %v, want step 0 / step_registers.m68k_pc", diverged)
	}
	if diverged["run1"] == diverged["run2"] {
		t.Fatalf("diverged_step reports identical values: %v", diverged)
	}
	checks := replayChecks(content)
	if checks["frame_token_deltas_match"]["passed"] != true {
		t.Fatalf("frame_token_deltas_match = %v, want true (the drift leaves the token deltas intact)", checks["frame_token_deltas_match"])
	}
	if checks["final_registers_match"]["passed"] != false {
		t.Fatalf("final_registers_match = %v, want false", checks["final_registers_match"])
	}
}

// TestDeterministicReplayUnreadableTokenIsNotProven asserts an unreadable axis
// is never counted as a match.
func TestDeterministicReplayUnreadableTokenIsNotProven(t *testing.T) {
	content := replayContent(t, replayFake(replayFakeConfig{omitFrameToken: true}),
		`{"steps":[{"inputs":{"1":["a"]},"frames":1}]}`)
	if content["deterministic"] != false {
		t.Fatalf("deterministic = %v, want false when the token is unreadable", content["deterministic"])
	}
	unproven, _ := content["unproven"].([]any)
	if len(unproven) == 0 {
		t.Fatalf("unproven missing for an unreadable token: %v", content)
	}
	found := false
	for _, entry := range unproven {
		if reason, _ := entry.(string); reason == "run_1: step 0 reported no frame token" || reason == "run_2: step 0 reported no frame token" {
			found = true
		}
	}
	if !found {
		t.Fatalf("unproven reasons do not name the unreadable step token: %v", unproven)
	}
	checks := replayChecks(content)
	if checks["frame_token_deltas_match"]["passed"] != false {
		t.Fatalf("frame_token_deltas_match = %v, want false when unproven", checks["frame_token_deltas_match"])
	}
	if checks["frames_advanced_match"]["passed"] != true {
		t.Fatalf("frames_advanced_match = %v, want true", checks["frames_advanced_match"])
	}
}

// TestDeterministicReplayUnreadableRegistersAreNotProven covers the register
// axis of the same rule.
func TestDeterministicReplayUnreadableRegistersAreNotProven(t *testing.T) {
	content := replayContent(t, replayFake(replayFakeConfig{unreadableRegisters: true}),
		`{"steps":[{"inputs":{"1":["a"]},"frames":1}]}`)
	if content["deterministic"] != false {
		t.Fatalf("deterministic = %v, want false when registers are unreadable", content["deterministic"])
	}
	unproven, _ := content["unproven"].([]any)
	if len(unproven) < 2 {
		t.Fatalf("unproven = %v, want per-run register reasons", unproven)
	}
	checks := replayChecks(content)
	if checks["step_registers_match"]["passed"] != false || checks["final_registers_match"]["passed"] != false {
		t.Fatalf("register checks = %v / %v, want both failed", checks["step_registers_match"], checks["final_registers_match"])
	}
	if checks["frame_token_deltas_match"]["passed"] != true {
		t.Fatalf("frame_token_deltas_match = %v, want true (tokens stay readable)", checks["frame_token_deltas_match"])
	}
}

// TestDeterministicReplayPausesBeforeStepping asserts the machine is forced
// paused after every restore that precedes stepping.
func TestDeterministicReplayPausesBeforeStepping(t *testing.T) {
	client := replayFake(replayFakeConfig{})
	content := replayContent(t, client, `{"steps":[{"inputs":{"1":["a"]},"frames":1}]}`)
	if content["pause_resume_cycle"] != float64(0) {
		t.Fatalf("pause_resume_cycle = %v, want 0 when the machine was already paused", content["pause_resume_cycle"])
	}

	loads := []int{}
	pauses := []int{}
	advances := []int{}
	for index, call := range client.recordedCalls {
		switch call.Method {
		case "state_load":
			loads = append(loads, index)
		case "cpu_control":
			pauses = append(pauses, index)
			if call.Params["action"] != "pause" {
				t.Fatalf("cpu_control action = %q, want pause", call.Params["action"])
			}
		case "frame_advance":
			advances = append(advances, index)
		}
	}
	if len(loads) != 3 {
		t.Fatalf("state_load calls = %d, want 3 (initial, between runs, final)", len(loads))
	}
	if len(pauses) != 2 {
		t.Fatalf("pause calls = %d, want 2 (one per run)", len(pauses))
	}
	for run := 0; run < 2; run++ {
		if pauses[run] != loads[run]+1 {
			t.Fatalf("pause %d at call %d, want immediately after state_load at %d", run, pauses[run], loads[run])
		}
	}
	if advances[0] < pauses[0] || advances[1] < pauses[1] {
		t.Fatalf("frame_advance before the run's pause: advances %v pauses %v", advances, pauses)
	}
	for _, pause := range pauses {
		if pause > loads[2] {
			t.Fatalf("the final restore must not force a pause (pause %d after final load %d)", pause, loads[2])
		}
	}
}

// TestDeterministicReplayUnverifiedPausedStartIsNotProven covers a pause whose
// echo cannot confirm the run state.
func TestDeterministicReplayUnverifiedPausedStartIsNotProven(t *testing.T) {
	content := replayContent(t, replayFake(replayFakeConfig{pauseEcho: map[string]any{"action": "pause"}}),
		`{"steps":[{"inputs":{"1":["a"]},"frames":1}]}`)
	if content["deterministic"] != false {
		t.Fatalf("deterministic = %v, want false when the paused start is unverified", content["deterministic"])
	}
	if checks := replayChecks(content); checks["initial_run_state_paused"]["passed"] != false {
		t.Fatalf("initial_run_state_paused = %v, want false", checks["initial_run_state_paused"])
	}
	unproven, _ := content["unproven"].([]any)
	found := false
	for _, entry := range unproven {
		if reason, _ := entry.(string); strings.Contains(reason, "did not verify a paused start") {
			found = true
		}
	}
	if !found {
		t.Fatalf("unproven does not explain the unverified start: %v", unproven)
	}
	for key := range map[string]bool{"run_1": true, "run_2": true} {
		if run := replayRun(t, content, key); run["initial_run_state"] != "unknown" {
			t.Fatalf("%s initial_run_state = %v, want unknown", key, run["initial_run_state"])
		}
	}
}

// TestDeterministicReplayLowTokenIsNotProven covers a counter that moves
// backwards: the delta is meaningless and must not be compared.
func TestDeterministicReplayLowTokenIsNotProven(t *testing.T) {
	client := replayFake(replayFakeConfig{startToken: 1000})
	inner := client.executeFunc
	token := uint64(1000)
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method == "frame_advance" {
			// Model a counter that wrapped or was reset mid-run.
			token = 5
			return json.RawMessage(fmt.Sprintf(`{"frames_requested":1,"frames_completed":1,"frame_token":%d,"system_running":false}`, token)), nil
		}
		return inner(ctx, method, params)
	}
	content := replayContent(t, client, `{"steps":[{"inputs":{"1":["a"]},"frames":1}]}`)
	if content["deterministic"] != false {
		t.Fatalf("deterministic = %v, want false for a token below the baseline", content["deterministic"])
	}
	unproven, _ := content["unproven"].([]any)
	found := false
	for _, entry := range unproven {
		if reason, _ := entry.(string); strings.Contains(reason, "below the run baseline") {
			found = true
		}
	}
	if !found {
		t.Fatalf("unproven does not explain the wrapped counter: %v", unproven)
	}
	if checks := replayChecks(content); checks["frame_token_deltas_match"]["passed"] != false {
		t.Fatalf("frame_token_deltas_match = %v, want false", checks["frame_token_deltas_match"])
	}
}

// TestDeterministicReplayManifestRecordsBaselines asserts the durable manifest
// records the per-run baseline and the delta comparison, so a stored artifact
// explains the verdict without the response.
func TestDeterministicReplayManifestRecordsBaselines(t *testing.T) {
	server := newTestServer(t, replayFake(replayFakeConfig{startToken: 40}))
	content := structured(postToolCall(t, server, "deterministic_replay",
		`{"steps":[{"inputs":{"1":["a"]},"frames":2}]}`))
	descriptor, _ := content["artifact"].(map[string]any)
	id, _ := descriptor["id"].(string)
	if id == "" {
		t.Fatalf("artifact descriptor missing: %v", descriptor)
	}
	raw, err := os.ReadFile(filepath.Join(server.store.Dir(), id))
	if err != nil {
		t.Fatalf("read manifest artifact: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if manifest["schema_version"] != "replay-manifest/2" {
		t.Fatalf("schema_version = %v, want replay-manifest/2", manifest["schema_version"])
	}
	if manifest["frame_token_comparison"] != "per_step_delta_from_run_baseline" {
		t.Fatalf("frame_token_comparison = %v", manifest["frame_token_comparison"])
	}
	run1, _ := manifest["run_1"].(map[string]any)
	run2, _ := manifest["run_2"].(map[string]any)
	if run1["frame_token_baseline"] != float64(40) || run2["frame_token_baseline"] != float64(42) {
		t.Fatalf("baselines = %v / %v, want 40 / 42", run1["frame_token_baseline"], run2["frame_token_baseline"])
	}
	if unproven, ok := manifest["unproven"].([]any); !ok || len(unproven) != 0 {
		t.Fatalf("unproven = %v, want an empty array", manifest["unproven"])
	}
	if methodology, _ := manifest["methodology"].(string); !strings.Contains(methodology, "delta") {
		t.Fatalf("methodology does not describe the delta comparison: %q", methodology)
	}
}

func TestDeterministicReplayValidation(t *testing.T) {
	result := callTool(t, replayFake(replayFakeConfig{}), "deterministic_replay", `{"steps":[{"frames":100}]}`)
	content := structured(result)
	if content["code"] != "invalid_params" {
		t.Fatalf("code = %v, want invalid_params", content["code"])
	}
	result = callTool(t, replayFake(replayFakeConfig{}), "deterministic_replay", `{"steps":[]}`)
	content = structured(result)
	if content["code"] != "invalid_params" {
		t.Fatalf("code = %v for empty steps, want invalid_params", content["code"])
	}
	result = callTool(t, replayFake(replayFakeConfig{}), "deterministic_replay", `{"steps":[{"inputs":{"1":["turbo"]}}]}`)
	content = structured(result)
	if content["code"] != "invalid_params" {
		t.Fatalf("code = %v for unknown button, want invalid_params", content["code"])
	}
	result = callTool(t, replayFake(replayFakeConfig{}), "deterministic_replay", `{"steps":[{"inputs":{"9":["a"]}}]}`)
	content = structured(result)
	if content["code"] != "invalid_params" {
		t.Fatalf("code = %v for bad port, want invalid_params", content["code"])
	}
}

func TestDeterministicReplayUnknownInitialState(t *testing.T) {
	result := callTool(t, replayFake(replayFakeConfig{}), "deterministic_replay",
		`{"initial_state_id":"missing","steps":[{"frames":1}]}`)
	content := structured(result)
	if content["code"] != "unknown_state" {
		t.Fatalf("code = %v, want unknown_state", content["code"])
	}
}
