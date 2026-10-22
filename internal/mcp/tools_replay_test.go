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
// paused bridge: state_save writes a real file (so stat/hash succeed),
// state_load restores machine state but never the run state (the VDP render
// counter is not part of a saved state either), frame_advance reports the
// advancing token and leaves the system paused, regs_get reports pc/a7/d0
// derived from the frames the machine executed since the last restore, and
// cpu_control echoes the run state it produced.
type replayFakeConfig struct {
	// startToken is the render counter the machine had already reached before
	// the replay began.
	startToken uint64
	// runningAtStart models a caller that left the machine running: the state
	// load preserves that run state, so the replay has to pause it.
	runningAtStart bool
	// autoAdvanceFrames models a machine that keeps executing while it runs:
	// every IPC call that arrives advances that many frames before it is
	// served, so a still-running bridge does real work in the gaps between the
	// replay's own calls. This is what makes a pause issued after the restore
	// skew run 1 relative to run 2.
	autoAdvanceFrames uint64
	// resetTokenOnLoad models a counter reset across the restore. The replay
	// must not depend on it: deltas are compared either way.
	resetTokenOnLoad bool
	// frameDriftStep adds frameDriftFrames to that step's advance on the restore
	// selected by frameDriftLoad, injecting a per-step token divergence.
	frameDriftStep   int
	frameDriftFrames uint64
	// frameDriftLoad selects the restore whose frame advances drift (default 2).
	frameDriftLoad int
	// registerDrift adds a pc offset to the samples taken after the selected
	// run's first frame advance, injecting a CPU-state divergence without
	// changing the frame count or the post-restore fingerprint.
	registerDrift bool
	// registerDriftLoad selects the restore whose samples drift (default 2).
	registerDriftLoad int
	// registerDriftD0 adds to d0 on the same restore, modelling the reported
	// live skew: an identical start fingerprint with a one-count d0 difference
	// after the steps.
	registerDriftD0 uint64
	// restoreBiasLoad selects the restore whose machine state is off by biasPC
	// and biasD0 bytes and whose condition codes are xored with biasCCR; 0
	// disables it. This models a state_load that is not bit-exact: the machine
	// resumes one instruction earlier or later, so the post-restore fingerprint
	// already differs and every later sample inherits the drift.
	restoreBiasLoad int
	biasPC          uint64
	biasD0          uint64
	biasCCR         uint64
	// omitCCR drops the condition codes from regs_get, modelling a bridge whose
	// register payload does not expose flags.
	omitCCR bool
	// omitFrameToken makes frame_advance report no token at all.
	omitFrameToken bool
	// unreadableRegisters makes regs_get return no register map.
	unreadableRegisters bool
	// omitLoadRunState drops system_running from the state_load echo, modelling
	// a bridge that cannot report the run state a restore left behind.
	omitLoadRunState bool
	// omitStatusRunState drops system_running from emulator_status, modelling a
	// target whose pre-call run state the server cannot observe.
	omitStatusRunState bool
	// pauseEcho, when set, replaces the run state a pause echoes so a pause that
	// cannot be verified can be modelled.
	pauseEcho map[string]any
}

// replayFake builds a bridge that answers the deterministic_replay flow and
// keeps the render counter and the run state across state_load, exactly like the
// real plugin.
func replayFake(config replayFakeConfig) *fakeBridgeClient {
	client := &fakeBridgeClient{status: newFakeStatus()}
	token := config.startToken
	running := config.runningAtStart
	loads := 0
	advances := 0
	executed := uint64(0) // frames the machine ran since the last restore
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		// A running machine executes on its own between IPC calls until
		// something pauses it.
		if running && config.autoAdvanceFrames > 0 {
			token += config.autoAdvanceFrames
			executed += config.autoAdvanceFrames
		}
		switch method {
		case "emulator_status":
			if config.omitStatusRunState {
				return json.RawMessage(`{}`), nil
			}
			return json.RawMessage(fmt.Sprintf(`{"system_running":%t}`, running)), nil
		case "state_save":
			if err := os.WriteFile(params["path"], []byte("state-bytes"), 0o644); err != nil {
				return nil, err
			}
			return json.RawMessage(fmt.Sprintf(`{"saved":true,"system_running":%t}`, running)), nil
		case "state_load":
			// The VDP render counter is not part of the saved state and this
			// bridge does not reset it unless the test asks for a reset. The
			// load never changes the run state either.
			if config.resetTokenOnLoad {
				token = 0
			}
			loads++
			executed = 0
			advances = 0
			if config.omitLoadRunState {
				return json.RawMessage(`{"loaded":true}`), nil
			}
			return json.RawMessage(fmt.Sprintf(`{"loaded":true,"system_running":%t}`, running)), nil
		case "vdp_status":
			return json.RawMessage(fmt.Sprintf(`{"vdp_found":true,"image_buffer":{"last_rendered_frame_token":%d}}`, token)), nil
		case "cpu_control":
			action := params["action"]
			switch action {
			case "pause":
				running = false
				if config.pauseEcho != nil {
					encoded, _ := json.Marshal(config.pauseEcho)
					return json.RawMessage(encoded), nil
				}
			case "run":
				running = true
			}
			return json.RawMessage(fmt.Sprintf(`{"action":%q,"system_running":%t}`, action, running)), nil
		case "input_set":
			return json.RawMessage(`{}`), nil
		case "frame_advance":
			frames, err := strconv.ParseUint(params["frames"], 10, 64)
			if err != nil {
				return nil, err
			}
			if loads == driftLoad(config.frameDriftLoad) && advances == config.frameDriftStep {
				frames += config.frameDriftFrames
			}
			advances++
			token += frames
			executed += frames
			running = false
			if config.omitFrameToken {
				return json.RawMessage(fmt.Sprintf(`{"frames_requested":%d,"frames_completed":%d,"system_running":false}`, frames, frames)), nil
			}
			return json.RawMessage(fmt.Sprintf(`{"frames_requested":%d,"frames_completed":%d,"frame_token":%d,"system_running":false}`, frames, frames, token)), nil
		case "regs_get":
			if config.unreadableRegisters {
				return json.RawMessage(`{"cpu":"m68k","byte_order":"big-endian"}`), nil
			}
			pc := uint64(0x200) + executed*2
			d0 := executed
			ccr := uint64(0x04)
			if loads == config.restoreBiasLoad {
				// A state_load that is not bit-exact leaves the machine one
				// instruction off, so the drift is already in the fingerprint.
				pc += config.biasPC
				d0 += config.biasD0
				ccr ^= config.biasCCR
			}
			if config.registerDrift && loads == driftLoad(config.registerDriftLoad) && advances > 0 {
				pc += 0x100
			}
			if config.registerDriftD0 != 0 && loads == driftLoad(config.registerDriftLoad) && advances > 0 {
				d0 += config.registerDriftD0
			}
			conditionCodes := fmt.Sprintf(`,"ccr":%d`, ccr)
			if config.omitCCR {
				conditionCodes = ""
			}
			return json.RawMessage(fmt.Sprintf(`{"cpu":"m68k","byte_order":"not-applicable","system_paused_during_read":false,"registers":{"pc":%d,"a7":16776672,"d0":%d%s},"flags":{},"width_bits":32}`, pc, d0, conditionCodes)), nil
		default:
			return json.RawMessage(`{}`), nil
		}
	}
	return client
}

// driftLoad resolves an optional restore selector: the zero value means the
// second restore, which is the first compared run.
func driftLoad(selected int) int {
	if selected == 0 {
		return 2
	}
	return selected
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
		t.Fatalf("pause_resume_cycle = %v, want 1 (the running target had to be paused once, before the first restore)", content["pause_resume_cycle"])
	}
	if run := replayRun(t, content, "run_1"); run["initial_run_state"] != "paused" || run["paused_start_confirmed"] != true {
		t.Fatalf("run_1 initial_run_state = %v (confirmed %v), want a confirmed paused start", run["initial_run_state"], run["paused_start_confirmed"])
	} else if run["initial_run_state_verified"] != false {
		t.Fatalf("run_1 initial_run_state_verified = %v, want false: the replay paused a running target", run["initial_run_state_verified"])
	}
	if run := replayRun(t, content, "run_2"); run["initial_run_state"] != "paused" || run["initial_run_state_verified"] != true {
		t.Fatalf("run_2 initial_run_state = %v (verified %v), want paused/verified", run["initial_run_state"], run["initial_run_state_verified"])
	}
	if content["final_run_state"] != "running" || content["resumed_after_restore"] != true {
		t.Fatalf("final_run_state = %v (resumed %v), want running: the target ran before the call", content["final_run_state"], content["resumed_after_restore"])
	}
	if content["restored"] != true {
		t.Fatalf("restored = %v, want true", content["restored"])
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

// TestDeterministicReplayReportsDivergedStep injects a per-step difference in a
// compared run and asserts the response names the step and both observed values.
// run1/run2 in the divergence are the compared phases (run_1 and run_2 by
// default).
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
		t.Fatalf("diverged_step values = run_1 %v run_2 %v, want 3 and 5", diverged["run1"], diverged["run2"])
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

// TestDeterministicReplayFrameDeltaDivergenceFailsInBothModes proves the frame
// axis is what the verdict certifies: a different number of frames advanced fails
// with and without strict.
func TestDeterministicReplayFrameDeltaDivergenceFailsInBothModes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		strict bool
		scope  string
	}{
		{"default", false, "frame_only"},
		{"strict", true, "frame_and_register"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			arguments := `{"steps":[{"inputs":{"1":["a"]},"frames":2}]}`
			if tc.strict {
				arguments = `{"steps":[{"inputs":{"1":["a"]},"frames":2}],"strict":true}`
			}
			content := replayContent(t, replayFake(replayFakeConfig{frameDriftStep: 0, frameDriftFrames: 2}), arguments)
			if content["deterministic"] != false {
				t.Fatalf("deterministic = %v, want false", content["deterministic"])
			}
			if content["determinism_scope"] != tc.scope {
				t.Fatalf("determinism_scope = %v, want %v", content["determinism_scope"], tc.scope)
			}
			diverged, ok := content["diverged_step"].(map[string]any)
			if !ok || diverged["field"] != "frame_token_delta" {
				t.Fatalf("diverged_step = %v, want a frame_token_delta divergence", content["diverged_step"])
			}
			if checks := replayChecks(content); checks["frame_token_deltas_match"]["passed"] != false || checks["frame_token_deltas_match"]["gating"] != true {
				t.Fatalf("frame_token_deltas_match = %v, want a failed gating check", checks["frame_token_deltas_match"])
			}
		})
	}
}

// TestDeterministicReplayRegistersAreAdvisoryByDefault is the regression test
// for the fourth live finding: the same restored image produces frame-identical
// runs whose M68K samples differ by one count (d0 255 vs 256) even when the start
// fingerprints match. Register equality is not a property this emulator delivers,
// so the default verdict is frame-level and the register difference is reported
// as advisory evidence.
func TestDeterministicReplayRegistersAreAdvisoryByDefault(t *testing.T) {
	content := replayContent(t, replayFake(replayFakeConfig{registerDriftD0: 1}),
		`{"steps":[{"inputs":{"1":["a"]},"frames":3}]}`)

	if content["deterministic"] != true {
		t.Fatalf("deterministic = %v, want true (the frames match): %v", content["deterministic"], content)
	}
	if content["determinism_scope"] != "frame_only" {
		t.Fatalf("determinism_scope = %v, want frame_only", content["determinism_scope"])
	}
	if content["register_evidence"] != "advisory" {
		t.Fatalf("register_evidence = %v, want advisory", content["register_evidence"])
	}
	if note, _ := content["register_evidence_note"].(string); !strings.Contains(note, "not instruction-exact") {
		t.Fatalf("register_evidence_note does not explain the advisory axis: %q", note)
	}
	if content["strict"] != false || content["warmup"] != false {
		t.Fatalf("strict = %v warmup = %v, want the default modes", content["strict"], content["warmup"])
	}
	if compared, _ := content["runs_compared"].([]any); len(compared) != 2 || compared[0] != "run_1" || compared[1] != "run_2" {
		t.Fatalf("runs_compared = %v, want [run_1 run_2]", content["runs_compared"])
	}
	if _, exists := content["run_3"]; exists {
		t.Fatalf("run_3 present without warmup: %v", content["run_3"])
	}
	if _, exists := content["warmup_divergences"]; exists {
		t.Fatalf("warmup_divergences present without warmup: %v", content["warmup_divergences"])
	}
	// The difference must not be a gating divergence, but it must stay visible
	// with both values and the step.
	if divergences, exists := content["divergences"]; exists {
		t.Fatalf("divergences = %v, want none: register evidence is advisory by default", divergences)
	}
	if _, exists := content["diverged_step"]; exists {
		t.Fatalf("diverged_step reported for advisory register evidence: %v", content["diverged_step"])
	}
	advisories, _ := content["advisory_divergences"].([]any)
	if len(advisories) == 0 {
		t.Fatalf("advisory_divergences missing: %v", content)
	}
	found := false
	for _, entry := range advisories {
		divergence, _ := entry.(map[string]any)
		if divergence["field"] != "step_registers.m68k_d0" || divergence["step"] != float64(0) {
			continue
		}
		found = true
		if first, ok := divergence["run1"].(float64); !ok || first != 3 {
			t.Fatalf("advisory d0 run1 = %v, want 3", divergence["run1"])
		}
		if second, ok := divergence["run2"].(float64); !ok || second != 4 {
			t.Fatalf("advisory d0 run2 = %v, want 4", divergence["run2"])
		}
	}
	if !found {
		t.Fatalf("advisory_divergences do not name step_registers.m68k_d0 at step 0: %v", advisories)
	}
	checks := replayChecks(content)
	for _, name := range []string{"frame_token_deltas_match", "frames_advanced_match", "initial_run_state_paused"} {
		if checks[name]["passed"] != true || checks[name]["gating"] != true {
			t.Fatalf("%s = %v, want a passed gating check", name, checks[name])
		}
	}
	for _, name := range []string{"step_registers_match", "final_registers_match"} {
		if checks[name]["passed"] != false || checks[name]["gating"] != false {
			t.Fatalf("%s = %v, want a failed advisory check", name, checks[name])
		}
	}
}

// TestDeterministicReplayStrictGatesRegisters proves the opt-in: with strict the
// same d0 skew is a gating divergence, which is what a target with
// instruction-exact save states would be expected to deliver.
func TestDeterministicReplayStrictGatesRegisters(t *testing.T) {
	content := replayContent(t, replayFake(replayFakeConfig{registerDriftD0: 1}),
		`{"steps":[{"inputs":{"1":["a"]},"frames":3}],"strict":true}`)
	if content["deterministic"] != false {
		t.Fatalf("deterministic = %v, want false under strict", content["deterministic"])
	}
	if content["strict"] != true || content["register_evidence"] != "gating" {
		t.Fatalf("strict = %v register_evidence = %v, want true/gating", content["strict"], content["register_evidence"])
	}
	if content["determinism_scope"] != "frame_and_register" {
		t.Fatalf("determinism_scope = %v, want frame_and_register", content["determinism_scope"])
	}
	diverged, ok := content["diverged_step"].(map[string]any)
	if !ok {
		t.Fatalf("diverged_step missing: %v", content)
	}
	if diverged["field"] != "step_registers.m68k_d0" || diverged["step"] != float64(0) {
		t.Fatalf("diverged_step = %v, want step 0 / step_registers.m68k_d0", diverged)
	}
	if diverged["run1"] == diverged["run2"] {
		t.Fatalf("diverged_step reports identical values: %v", diverged)
	}
	checks := replayChecks(content)
	if checks["step_registers_match"]["gating"] != true || checks["step_registers_match"]["passed"] != false {
		t.Fatalf("step_registers_match = %v, want a failed gating check", checks["step_registers_match"])
	}
	if checks["frame_token_deltas_match"]["passed"] != true {
		t.Fatalf("frame_token_deltas_match = %v, want true (the frames match)", checks["frame_token_deltas_match"])
	}
	if advisories, _ := content["advisory_divergences"].([]any); len(advisories) != 0 {
		t.Fatalf("advisory_divergences = %v, want none under strict", advisories)
	}
}

// TestDeterministicReplayAdvisoryRegistersWhenRestoreIsNotExact is the
// regression test for the second reported defect: state_load is not bit-exact,
// so one run can start one instruction away from the other. The runs are then
// frame-identical and the register samples differ, which used to be reported as
// sequence nondeterminism. The difference must stay visible as advisory
// evidence instead of failing the verdict.
func TestDeterministicReplayAdvisoryRegistersWhenRestoreIsNotExact(t *testing.T) {
	content := replayContent(t, replayFake(replayFakeConfig{restoreBiasLoad: 2, biasPC: 4}),
		`{"steps":[{"inputs":{"1":["a"]},"frames":2}]}`)

	if content["deterministic"] != true {
		t.Fatalf("deterministic = %v, want true: %v", content["deterministic"], content)
	}
	if content["restore_fidelity"] != "not_exact" {
		t.Fatalf("restore_fidelity = %v, want not_exact", content["restore_fidelity"])
	}
	if content["register_evidence"] != "advisory" {
		t.Fatalf("register_evidence = %v, want advisory", content["register_evidence"])
	}
	fields, _ := content["restore_fidelity_fields"].([]any)
	if len(fields) != 1 || fields[0] != "m68k_pc" {
		t.Fatalf("restore_fidelity_fields = %v, want [m68k_pc]", fields)
	}
	if unproven, _ := content["unproven"].([]any); len(unproven) != 0 {
		t.Fatalf("unproven = %v, want none (nothing was unreadable)", unproven)
	}
	// A register difference caused by the restore must not be a gating
	// divergence, but it must stay visible with both values and the step.
	if divergences, exists := content["divergences"]; exists {
		t.Fatalf("divergences = %v, want none: register differences are advisory here", divergences)
	}
	if _, exists := content["diverged_step"]; exists {
		t.Fatalf("diverged_step reported for an advisory register difference: %v", content["diverged_step"])
	}
	advisories, _ := content["advisory_divergences"].([]any)
	if len(advisories) == 0 {
		t.Fatalf("advisory_divergences missing: %v", content)
	}
	first, _ := advisories[0].(map[string]any)
	if first["field"] != "step_registers.m68k_pc" || first["step"] != float64(0) {
		t.Fatalf("advisory_discoveries[0] = %v, want step 0 / step_registers.m68k_pc", first)
	}
	run1, run2 := first["run1"].(float64), first["run2"].(float64)
	if run2-run1 != 4 {
		t.Fatalf("advisory pc values = %v / %v, want a 4-byte drift", run1, run2)
	}
	// The fingerprints that justify the advisory comparison travel with the
	// response, both values included.
	fingerprints, _ := content["restore_fingerprints"].(map[string]any)
	firstFingerprint, _ := fingerprints["run_1"].(map[string]any)
	secondFingerprint, _ := fingerprints["run_2"].(map[string]any)
	if firstFingerprint["m68k_pc"] == secondFingerprint["m68k_pc"] {
		t.Fatalf("restore_fingerprints = %v, want differing pc values", fingerprints)
	}
	checks := replayChecks(content)
	if checks["frame_token_deltas_match"]["gating"] != true || checks["frame_token_deltas_match"]["passed"] != true {
		t.Fatalf("frame_token_deltas_match = %v, want a passed gating check", checks["frame_token_deltas_match"])
	}
	for _, name := range []string{"step_registers_match", "final_registers_match"} {
		if checks[name]["gating"] != false || checks[name]["passed"] != false {
			t.Fatalf("%s = %v, want a failed advisory check", name, checks[name])
		}
		if detail, _ := checks[name]["detail"].(string); !strings.Contains(detail, "advisory") {
			t.Fatalf("%s detail does not explain the advisory comparison: %q", name, detail)
		}
	}
}

// TestDeterministicReplayFrameDriftGatesEvenWhenRestoreIsNotExact proves the
// frame axis always counts: an inexact restore never excuses a different
// number of frames advanced.
func TestDeterministicReplayFrameDriftGatesEvenWhenRestoreIsNotExact(t *testing.T) {
	content := replayContent(t, replayFake(replayFakeConfig{restoreBiasLoad: 2, biasPC: 4, frameDriftStep: 0, frameDriftFrames: 2}),
		`{"steps":[{"inputs":{"1":["a"]},"frames":2}]}`)
	if content["deterministic"] != false {
		t.Fatalf("deterministic = %v, want false", content["deterministic"])
	}
	if content["restore_fidelity"] != "not_exact" || content["register_evidence"] != "advisory" {
		t.Fatalf("restore_fidelity = %v register_evidence = %v, want not_exact/advisory", content["restore_fidelity"], content["register_evidence"])
	}
	diverged, ok := content["diverged_step"].(map[string]any)
	if !ok || diverged["field"] != "frame_token_delta" {
		t.Fatalf("diverged_step = %v, want a gating frame_token_delta divergence", content["diverged_step"])
	}
	checks := replayChecks(content)
	if checks["frame_token_deltas_match"]["passed"] != false || checks["frame_token_deltas_match"]["gating"] != true {
		t.Fatalf("frame_token_deltas_match = %v, want a failed gating check", checks["frame_token_deltas_match"])
	}
	if advisories, _ := content["advisory_divergences"].([]any); len(advisories) == 0 {
		t.Fatalf("advisory_divergences missing for an inexact restore: %v", content)
	}
}

// TestDeterministicReplayWarmupAbsorbsFirstRunSkew is the regression test for the
// third reported defect: run 1 carried residual state from the moment the tool
// stopped a running target, which shifted one register by one count while the
// frames matched. The warm-up pass must absorb it: run_1 differences are
// observations, never failures.
func TestDeterministicReplayWarmupAbsorbsFirstRunSkew(t *testing.T) {
	content := replayContent(t, replayFake(replayFakeConfig{restoreBiasLoad: 1, biasD0: 1}),
		`{"steps":[{"inputs":{"1":["a"]},"frames":3}],"warmup":true}`)

	if content["deterministic"] != true {
		t.Fatalf("deterministic = %v, want true: %v", content["deterministic"], content)
	}
	if content["warmup"] != true {
		t.Fatalf("warmup = %v, want true", content["warmup"])
	}
	if note, _ := content["warmup_note"].(string); !strings.Contains(note, "warm-up pass") {
		t.Fatalf("warmup_note does not explain the warm-up pass: %q", note)
	}
	if _, exists := content["diverged_step"]; exists {
		t.Fatalf("diverged_step reported for a warm-up-only difference: %v", content["diverged_step"])
	}
	if divergences, exists := content["divergences"]; exists {
		t.Fatalf("divergences = %v, want none: the skew belongs to the warm-up pass", divergences)
	}
	// The discarded pass is reported in full, with both values.
	warmupDivergences, _ := content["warmup_divergences"].([]any)
	if len(warmupDivergences) == 0 {
		t.Fatalf("warmup_divergences missing: %v", content)
	}
	found := false
	for _, entry := range warmupDivergences {
		divergence, _ := entry.(map[string]any)
		if divergence["field"] != "step_registers.m68k_d0" || divergence["step"] != float64(0) {
			continue
		}
		found = true
		if first, ok := divergence["run1"].(float64); !ok || first != 4 {
			t.Fatalf("warmup divergence run1 = %v, want 4 (run_1: 3 frames plus the residual count)", divergence["run1"])
		}
		if second, ok := divergence["run2"].(float64); !ok || second != 3 {
			t.Fatalf("warmup divergence run2 = %v, want 3 (run_2)", divergence["run2"])
		}
	}
	if !found {
		t.Fatalf("warmup_divergences do not name step_registers.m68k_d0 at step 0: %v", warmupDivergences)
	}
	if content["warmup_restore_fidelity"] != "not_exact" {
		t.Fatalf("warmup_restore_fidelity = %v, want not_exact: the residual state shows in the run_1/run_2 fingerprints", content["warmup_restore_fidelity"])
	}
	if fields, _ := content["warmup_restore_fidelity_fields"].([]any); len(fields) != 1 || fields[0] != "m68k_d0" {
		t.Fatalf("warmup_restore_fidelity_fields = %v, want [m68k_d0]", fields)
	}
	// The compared pair is runs 2 and 3, and their restores are identical.
	if compared, _ := content["runs_compared"].([]any); len(compared) != 2 || compared[0] != "run_2" || compared[1] != "run_3" {
		t.Fatalf("runs_compared = %v, want [run_2 run_3]", content["runs_compared"])
	}
	if content["restore_fidelity"] != "exact" || content["register_evidence"] != "advisory" {
		t.Fatalf("restore_fidelity = %v register_evidence = %v, want exact/advisory for runs 2 and 3", content["restore_fidelity"], content["register_evidence"])
	}
	if content["determinism_scope"] != "frame_only" {
		t.Fatalf("determinism_scope = %v, want frame_only", content["determinism_scope"])
	}
	for key, want := range map[string]bool{"run_1": true, "run_2": false, "run_3": false} {
		if run := replayRun(t, content, key); run["warmup"] != want {
			t.Fatalf("%s warmup = %v, want %v", key, run["warmup"], want)
		}
	}
}

// TestDeterministicReplayGatesOnRunsTwoAndThree asserts a difference between the
// compared runs is a genuine nondeterminism verdict, named with run 2 and run 3
// values.
func TestDeterministicReplayWarmupStrictGatesOnTheComparedPasses(t *testing.T) {
	content := replayContent(t, replayFake(replayFakeConfig{registerDrift: true, registerDriftLoad: 3}),
		`{"steps":[{"inputs":{"1":["a"]},"frames":1}],"warmup":true,"strict":true}`)
	if content["deterministic"] != false {
		t.Fatalf("deterministic = %v, want false: %v", content["deterministic"], content)
	}
	if content["determinism_scope"] != "frame_and_register" || content["restore_fidelity"] != "exact" {
		t.Fatalf("determinism_scope = %v restore_fidelity = %v, want frame_and_register/exact", content["determinism_scope"], content["restore_fidelity"])
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
	// The warm-up pair agreed, so its observations are empty.
	if warmup, _ := content["warmup_divergences"].([]any); len(warmup) != 0 {
		t.Fatalf("warmup_divergences = %v, want none", warmup)
	}
	if content["warmup_restore_fidelity"] != "exact" {
		t.Fatalf("warmup_restore_fidelity = %v, want exact", content["warmup_restore_fidelity"])
	}
}

// TestDeterministicReplayFrameDriftBetweenRunsTwoAndThree proves frame-token
// drift inside the compared pair still fails, and stays out of the warm-up
// observations.
func TestDeterministicReplayFrameDriftBetweenRunsTwoAndThree(t *testing.T) {
	content := replayContent(t, replayFake(replayFakeConfig{frameDriftStep: 0, frameDriftFrames: 2, frameDriftLoad: 3}),
		`{"steps":[{"inputs":{"1":["a"]},"frames":2}],"warmup":true}`)
	if content["deterministic"] != false {
		t.Fatalf("deterministic = %v, want false", content["deterministic"])
	}
	diverged, ok := content["diverged_step"].(map[string]any)
	if !ok || diverged["field"] != "frame_token_delta" {
		t.Fatalf("diverged_step = %v, want a gating frame_token_delta divergence", content["diverged_step"])
	}
	if diverged["run1"] != float64(2) || diverged["run2"] != float64(4) {
		t.Fatalf("diverged_step values = run_2 %v run_3 %v, want 2 and 4", diverged["run1"], diverged["run2"])
	}
	if warmup, _ := content["warmup_divergences"].([]any); len(warmup) != 0 {
		t.Fatalf("warmup_divergences = %v, want none (the drift is in run 3)", warmup)
	}
}

// TestDeterministicReplayCCRDifferenceDemotesRegisters covers the flag gap the
// pc/a7/d0 fingerprint cannot see: a condition-code difference between the
// compared restores must demote the register axis to advisory.
func TestDeterministicReplayCCRDifferenceIsReportedInTheFingerprint(t *testing.T) {
	content := replayContent(t, replayFake(replayFakeConfig{restoreBiasLoad: 2, biasCCR: 0x01}),
		`{"steps":[{"inputs":{"1":["a"]},"frames":2}]}`)
	if content["deterministic"] != true {
		t.Fatalf("deterministic = %v, want true (the frames match): %v", content["deterministic"], content)
	}
	if content["restore_fidelity"] != "not_exact" {
		t.Fatalf("restore_fidelity = %v, want not_exact", content["restore_fidelity"])
	}
	if fields, _ := content["restore_fidelity_fields"].([]any); len(fields) != 1 || fields[0] != "ccr" {
		t.Fatalf("restore_fidelity_fields = %v, want [ccr]", fields)
	}
	if compared, _ := content["restore_fidelity_compare"].([]any); len(compared) != 4 || compared[3] != "ccr" {
		t.Fatalf("restore_fidelity_compare = %v, want pc/a7/d0 plus ccr", compared)
	}
	if content["register_evidence"] != "advisory" || content["determinism_scope"] != "frame_only" {
		t.Fatalf("register_evidence = %v determinism_scope = %v, want advisory/frame_only", content["register_evidence"], content["determinism_scope"])
	}
	fingerprints, _ := content["restore_fingerprints"].(map[string]any)
	first, _ := fingerprints["run_1"].(map[string]any)
	second, _ := fingerprints["run_2"].(map[string]any)
	if first["ccr"] == second["ccr"] {
		t.Fatalf("restore_fingerprints = %v, want differing ccr values", fingerprints)
	}
	if pc := first["m68k_pc"]; pc != second["m68k_pc"] {
		t.Fatalf("restore_fingerprints pc = %v / %v, want matching pc for a flag-only difference", pc, second["m68k_pc"])
	}
}

// TestDeterministicReplayReportsMissingCCR asserts the response says which fields
// the fidelity comparison covered, so a build without condition codes is visible
// instead of assumed.
func TestDeterministicReplayReportsMissingCCR(t *testing.T) {
	content := replayContent(t, replayFake(replayFakeConfig{omitCCR: true}),
		`{"steps":[{"inputs":{"1":["a"]},"frames":1}]}`)
	if content["deterministic"] != true {
		t.Fatalf("deterministic = %v, want true: %v", content["deterministic"], content)
	}
	compared, _ := content["restore_fidelity_compare"].([]any)
	if len(compared) != 3 {
		t.Fatalf("restore_fidelity_compare = %v, want only pc/a7/d0 (no ccr in the payload)", compared)
	}
	for _, entry := range compared {
		if entry == "ccr" {
			t.Fatalf("restore_fidelity_compare = %v claims ccr was compared", compared)
		}
	}
	fingerprints, _ := content["restore_fingerprints"].(map[string]any)
	if first, _ := fingerprints["run_2"].(map[string]any); first["ccr"] != nil {
		t.Fatalf("restore_fingerprints = %v, want no invented ccr", fingerprints)
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

// TestDeterministicReplayUnreadableRegistersAreAdvisoryByDefault covers the
// register axis of the unproven rule after the default became frame-level: an
// unreadable register sample never fails a frame verdict, but it is reported and
// it gates again under strict.
func TestDeterministicReplayUnreadableRegistersAreAdvisoryByDefault(t *testing.T) {
	content := replayContent(t, replayFake(replayFakeConfig{unreadableRegisters: true}),
		`{"steps":[{"inputs":{"1":["a"]},"frames":1}]}`)
	if content["deterministic"] != true {
		t.Fatalf("deterministic = %v, want true: unreadable register data is advisory by default", content["deterministic"])
	}
	if content["restore_fidelity"] != "unverified" || content["register_evidence"] != "advisory" {
		t.Fatalf("restore_fidelity = %v register_evidence = %v, want unverified/advisory", content["restore_fidelity"], content["register_evidence"])
	}
	advisoryUnproven, _ := content["advisory_unproven"].([]any)
	if len(advisoryUnproven) < 2 {
		t.Fatalf("advisory_unproven = %v, want per-run register reasons", advisoryUnproven)
	}
	if gating, _ := content["unproven"].([]any); len(gating) != 0 {
		t.Fatalf("unproven = %v, want none on the frame axis", gating)
	}
	checks := replayChecks(content)
	if checks["frame_token_deltas_match"]["passed"] != true || checks["frame_token_deltas_match"]["gating"] != true {
		t.Fatalf("frame_token_deltas_match = %v, want a passed gating check", checks["frame_token_deltas_match"])
	}
	for _, name := range []string{"step_registers_match", "final_registers_match"} {
		if checks[name]["passed"] != false || checks[name]["gating"] != false {
			t.Fatalf("%s = %v, want a failed advisory check", name, checks[name])
		}
	}

	// The same fixture under strict must fail: register data that cannot be read
	// is never counted as a match when registers gate.
	strict := replayContent(t, replayFake(replayFakeConfig{unreadableRegisters: true}),
		`{"steps":[{"inputs":{"1":["a"]},"frames":1}],"strict":true}`)
	if strict["deterministic"] != false {
		t.Fatalf("deterministic = %v, want false under strict", strict["deterministic"])
	}
	if unproven, _ := strict["unproven"].([]any); len(unproven) == 0 {
		t.Fatalf("unproven = %v, want the unreadable register reasons under strict", strict["unproven"])
	}
	if strictChecks := replayChecks(strict); strictChecks["step_registers_match"]["gating"] != true {
		t.Fatalf("step_registers_match = %v, want a gating check under strict", strictChecks["step_registers_match"])
	}
}

// TestDeterministicReplayRunningTargetStaysDeterministic is the regression test
// for the reported defect: the target is running when the call arrives and keeps
// executing on its own between IPC calls until something pauses it. The window
// must pause it BEFORE the first restore, otherwise run 1 observes frames run 2
// never gets and a deterministic target is reported as nondeterministic.
func TestDeterministicReplayRunningTargetStaysDeterministic(t *testing.T) {
	client := replayFake(replayFakeConfig{runningAtStart: true, autoAdvanceFrames: 1})
	content := replayContent(t, client,
		`{"steps":[{"inputs":{"1":["a","b"]},"frames":2},{"inputs":{"2":["start"]},"frames":1}]}`)

	if content["deterministic"] != true {
		t.Fatalf("deterministic = %v, want true: %v", content["deterministic"], content)
	}
	if unproven, _ := content["unproven"].([]any); len(unproven) != 0 {
		t.Fatalf("unproven = %v, want none", unproven)
	}
	if _, exists := content["divergences"]; exists {
		t.Fatalf("divergences reported for a matching replay: %v", content["divergences"])
	}
	checks := replayChecks(content)
	for _, name := range []string{"frame_token_deltas_match", "step_registers_match", "final_registers_match", "frames_advanced_match", "initial_run_state_paused"} {
		if check := checks[name]; check == nil || check["passed"] != true {
			t.Fatalf("%s = %v, want a passed check", name, check)
		}
	}
	if content["pause_resume_cycle"] != float64(1) {
		t.Fatalf("pause_resume_cycle = %v, want 1 (the running target was paused once, before the restore)", content["pause_resume_cycle"])
	}
	if note, _ := content["pause_resume_cycle_note"].(string); !strings.Contains(note, "BEFORE the restore") {
		t.Fatalf("pause_resume_cycle_note does not state that the pause precedes the restore: %q", note)
	}
	run1 := replayRun(t, content, "run_1")
	run2 := replayRun(t, content, "run_2")
	for key, run := range map[string]map[string]any{"run_1": run1, "run_2": run2} {
		if run["initial_run_state"] != "paused" || run["paused_start_confirmed"] != true {
			t.Fatalf("%s initial_run_state = %v (confirmed %v), want a confirmed paused start", key, run["initial_run_state"], run["paused_start_confirmed"])
		}
	}
	if run1["initial_run_state_verified"] != false {
		t.Fatalf("run_1 initial_run_state_verified = %v, want false (the replay paused the running target)", run1["initial_run_state_verified"])
	}
	if note, _ := run1["initial_run_state_note"].(string); !strings.Contains(note, "before the initial restore") {
		t.Fatalf("run_1 initial_run_state_note does not explain the pause: %q", note)
	}
	if run2["initial_run_state_verified"] != true {
		t.Fatalf("run_2 initial_run_state_verified = %v, want true (run 2 starts from the machine run 1 left paused)", run2["initial_run_state_verified"])
	}

	// The pause must precede every restore, and the resume must follow the last
	// one: a pause after a restore is what skewed the runs.
	loads := []int{}
	pauses := []int{}
	resumes := []int{}
	for index, call := range client.recordedCalls {
		switch call.Method {
		case "state_load":
			loads = append(loads, index)
		case "cpu_control":
			switch call.Params["action"] {
			case "pause":
				pauses = append(pauses, index)
			case "run":
				resumes = append(resumes, index)
			}
		}
	}
	if len(loads) != 3 {
		t.Fatalf("state_load calls = %d, want 3 (initial, between runs, final)", len(loads))
	}
	if len(pauses) != 1 || pauses[0] > loads[0] {
		t.Fatalf("pause calls = %v, want exactly one before the first state_load at call %d", pauses, loads[0])
	}
	if len(resumes) != 1 || resumes[0] < loads[2] {
		t.Fatalf("run calls = %v, want exactly one after the final state_load at call %d", resumes, loads[2])
	}
	// The target must be left in the run state it had before the call.
	if content["entry_run_state"] != "running" {
		t.Fatalf("entry_run_state = %v, want running", content["entry_run_state"])
	}
	if content["final_run_state"] != "running" || content["final_run_state_verified"] != true {
		t.Fatalf("final_run_state = %v (verified %v), want running/verified", content["final_run_state"], content["final_run_state_verified"])
	}
	if content["resumed_after_restore"] != true || content["run_state_restored"] != "restored" {
		t.Fatalf("resumed_after_restore = %v run_state_restored = %v, want true/restored", content["resumed_after_restore"], content["run_state_restored"])
	}
}

// TestDeterministicReplayPausedTargetNeedsNoPause asserts a target that is
// already paused sees no run-state transition at all, and stays paused.
func TestDeterministicReplayPausedTargetNeedsNoPause(t *testing.T) {
	client := replayFake(replayFakeConfig{})
	content := replayContent(t, client, `{"steps":[{"inputs":{"1":["a"]},"frames":1}]}`)
	if content["pause_resume_cycle"] != float64(0) {
		t.Fatalf("pause_resume_cycle = %v, want 0 when the machine was already paused", content["pause_resume_cycle"])
	}
	if content["entry_run_state"] != "paused" || content["final_run_state"] != "paused" {
		t.Fatalf("entry_run_state = %v final_run_state = %v, want paused/paused", content["entry_run_state"], content["final_run_state"])
	}
	if content["resumed_after_restore"] != false || content["run_state_restored"] != "already_paused" {
		t.Fatalf("resumed_after_restore = %v run_state_restored = %v, want false/already_paused", content["resumed_after_restore"], content["run_state_restored"])
	}
	for _, call := range client.recordedCalls {
		if call.Method == "cpu_control" {
			t.Fatalf("cpu_control %q called for an already paused target", call.Params["action"])
		}
	}
}

// TestDeterministicReplayUnknownEntryRunStateIsNotResumed covers a target whose
// pre-call run state the server cannot observe: the replay still pauses before
// the restore (so the runs stay comparable) but never resumes a machine it
// cannot attribute.
func TestDeterministicReplayUnknownEntryRunStateIsNotResumed(t *testing.T) {
	client := replayFake(replayFakeConfig{omitStatusRunState: true, autoAdvanceFrames: 1, runningAtStart: true})
	content := replayContent(t, client, `{"steps":[{"inputs":{"1":["a"]},"frames":2}]}`)
	if content["deterministic"] != true {
		t.Fatalf("deterministic = %v, want true: %v", content["deterministic"], content)
	}
	if content["entry_run_state"] != "unknown" {
		t.Fatalf("entry_run_state = %v, want unknown", content["entry_run_state"])
	}
	if content["run_state_restored"] != "resume_skipped_initial_run_state_unknown" {
		t.Fatalf("run_state_restored = %v, want resume_skipped_initial_run_state_unknown", content["run_state_restored"])
	}
	if content["resumed_after_restore"] != false || content["final_run_state"] != "paused" {
		t.Fatalf("resumed_after_restore = %v final_run_state = %v, want false/paused", content["resumed_after_restore"], content["final_run_state"])
	}
	resumes := 0
	for _, call := range client.recordedCalls {
		if call.Method == "cpu_control" && call.Params["action"] == "run" {
			resumes++
		}
	}
	if resumes != 0 {
		t.Fatalf("cpu_control run called %d times for an unobserved entry state", resumes)
	}
}

// TestDeterministicReplayUnverifiedPausedStartIsNotProven covers a bridge that
// reports no run state on either the restore or the pause: the replay still
// pauses before stepping, but the paused start stays unproven instead of being
// assumed.
func TestDeterministicReplayUnverifiedPausedStartIsNotProven(t *testing.T) {
	content := replayContent(t, replayFake(replayFakeConfig{omitLoadRunState: true, pauseEcho: map[string]any{"action": "pause"}}),
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
		if reason, _ := entry.(string); strings.Contains(reason, "could not prove a paused start") {
			found = true
		}
	}
	if !found {
		t.Fatalf("unproven does not explain the unverified start: %v", unproven)
	}
	for key := range map[string]bool{"run_1": true, "run_2": true} {
		run := replayRun(t, content, key)
		if run["initial_run_state"] != "unknown" || run["paused_start_confirmed"] != false {
			t.Fatalf("%s initial_run_state = %v (confirmed %v), want unknown/unconfirmed", key, run["initial_run_state"], run["paused_start_confirmed"])
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
	if manifest["schema_version"] != "replay-manifest/5" {
		t.Fatalf("schema_version = %v, want replay-manifest/4", manifest["schema_version"])
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
	if note, _ := manifest["pause_resume_cycle_note"].(string); !strings.Contains(note, "BEFORE the restore") {
		t.Fatalf("manifest pause_resume_cycle_note does not state that the pause precedes the restore: %q", note)
	}
	if manifest["pause_resume_cycle"] != float64(0) || manifest["entry_run_state"] != "paused" {
		t.Fatalf("manifest pause_resume_cycle = %v entry_run_state = %v, want 0/paused", manifest["pause_resume_cycle"], manifest["entry_run_state"])
	}
	if manifest["run_state_restored"] != "already_paused" || manifest["resumed_after_restore"] != false {
		t.Fatalf("manifest run_state_restored = %v resumed_after_restore = %v, want already_paused/false", manifest["run_state_restored"], manifest["resumed_after_restore"])
	}
	// The manifest must carry the mode contract and the register evidence, so a
	// stored artifact explains what the verdict certified.
	if manifest["restore_fidelity"] != "exact" || manifest["register_evidence"] != "advisory" {
		t.Fatalf("manifest restore_fidelity = %v register_evidence = %v, want exact/advisory", manifest["restore_fidelity"], manifest["register_evidence"])
	}
	if manifest["strict"] != false || manifest["warmup"] != false {
		t.Fatalf("manifest strict = %v warmup = %v, want the default modes", manifest["strict"], manifest["warmup"])
	}
	if note, _ := manifest["register_evidence_note"].(string); !strings.Contains(note, "strict") {
		t.Fatalf("manifest register_evidence_note does not point at strict: %q", note)
	}
	if advisories, ok := manifest["advisory_divergences"].([]any); !ok || len(advisories) != 0 {
		t.Fatalf("manifest advisory_discoveries = %v, want an empty array", manifest["advisory_divergences"])
	}
	fingerprints, _ := manifest["restore_fingerprints"].(map[string]any)
	if first, _ := fingerprints["run_1"].(map[string]any); first["m68k_pc"] == nil {
		t.Fatalf("manifest restore_fingerprints = %v, want both fingerprints", fingerprints)
	}
	if note, _ := manifest["restore_fidelity_note"].(string); !strings.Contains(note, "excluded") {
		t.Fatalf("manifest restore_fidelity_note does not explain the token exclusion: %q", note)
	}
	// The manifest records the two-pass default and which passes decided the
	// verdict; the warm-up fields exist only when the mode was requested.
	if compared, _ := manifest["runs_compared"].([]any); len(compared) != 2 || compared[0] != "run_1" || compared[1] != "run_2" {
		t.Fatalf("manifest runs_compared = %v, want [run_1 run_2]", manifest["runs_compared"])
	}
	if manifest["determinism_scope"] != "frame_only" {
		t.Fatalf("manifest determinism_scope = %v, want frame_only", manifest["determinism_scope"])
	}
	if fields, _ := manifest["restore_fidelity_compare"].([]any); len(fields) != 4 || fields[3] != "ccr" {
		t.Fatalf("manifest restore_fidelity_compare = %v, want pc/a7/d0 plus ccr", fields)
	}
	for _, absent := range []string{"run_3", "warmup_note", "warmup_divergences", "warmup_restore_fidelity"} {
		if value, exists := manifest[absent]; exists {
			t.Fatalf("manifest carries %s = %v without warmup", absent, value)
		}
	}
	// The artifact envelope must not claim a live sample of a paused window.
	provenance := mustMap(t, mustMap(t, descriptor["provenance"], "artifact provenance")["capture_consistency"], "capture consistency")
	if provenance["state"] != "paused" || provenance["initial_run_state"] != "paused" || provenance["final_run_state"] != "paused" {
		t.Fatalf("capture_consistency = %v, want a paused window", provenance)
	}
	if provenance["execution_paused_by_tool"] != false || provenance["execution_resumed_after"] != false {
		t.Fatalf("capture_consistency = %v, want no tool run-state change", provenance)
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
