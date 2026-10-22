package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/StealthC/exodus-mcp/internal/analysis"
)

// deterministic_replay (roadmap P8): execute one declarative input sequence
// twice from the same saved state under exclusive control, capture per-step
// frame-token deltas and M68K registers for both runs, and report whether the
// runs matched frame-for-frame. The manifest artifact (schema replay-manifest/2)
// records the normalized steps, both runs' observables, the determinism checks,
// and the methodology. This is both the input recording (run 1) and the replay
// verification (run 2) in one tool: recording and replay share the identical
// code path, so a mismatch is a real emulator nondeterminism signal rather than
// a harness artifact.
//
// The VDP render counter is not part of a saved state and is never reset by
// state_load: it keeps counting across the restore between the two runs.
// Absolute per-step tokens are therefore not comparable run-to-run, and only
// the distance each step advanced from a baseline captured at the start of its
// own run is compared. An axis whose data could not be read is reported as
// unproven and never counted as a match.

const (
	maxReplaySteps     = 64
	minReplayFrames    = 1
	maxReplayFrames    = maxFrameAdvance // 60
	replayManifestKind = "replay-manifest"
	replayManifestVer  = "replay-manifest/2"

	// replayTokenComparison names the comparison the verdict rests on, so a
	// caller can tell a delta comparison from an absolute one.
	replayTokenComparison = "per_step_delta_from_run_baseline"

	// replayStepRegisterDivergencePrefix and replayFinalRegisterDivergencePrefix
	// qualify the register fields a divergence names.
	replayStepRegisterDivergencePrefix  = "step_registers"
	replayFinalRegisterDivergencePrefix = "final_registers"
)

func replayToolSpecs() []toolSpec {
	return []toolSpec{
		{
			name:        "deterministic_replay",
			description: "Record and replay one declarative input sequence to verify frame-for-frame determinism: run the same steps twice from the same saved state under exclusive control, capture per-step frame-token deltas, per-step M68K register samples and final M68K registers for both runs, then report deterministic true/false plus a replay-manifest/2 artifact. Each step holds the listed buttons down for the given number of frames (input_set down, frame_advance x N, input_set up). The VDP render counter is not part of a saved state, so every step is compared as a delta from a baseline token captured at the start of its own run (frame_token_baseline), never as an absolute token. After each restore the machine is forced paused and initial_run_state is reported per run, so both runs step from a comparable instant. A difference is reported in diverged_step (step, field, run1, run2) when it belongs to one step and in divergences otherwise; an axis that could not be read is listed in unproven and never counts as a match. initial_state_id is optional: omitting it snapshots the current machine state first. The emulator is restored to the initial state afterwards. Accepts optional expected_target_generation and control_id; without control_id the server acquires an internal lock for the whole window.",
			schema: objectSchema(map[string]any{
				"initial_state_id": stringProperty("Optional state id saved through this analysis context; omitting it snapshots the current machine state first."),
				"steps": map[string]any{
					"type":        "array",
					"description": fmt.Sprintf("Input steps (1-%d), executed in order; each step frames must be 1-%d.", maxReplaySteps, maxReplayFrames),
					"items": map[string]any{
						"type":                 "object",
						"additionalProperties": false,
						"properties": map[string]any{
							"inputs": map[string]any{
								"type":                 "object",
								"description":          "Map of player port (\"1\"..\"4\") to the button names held during this step.",
								"additionalProperties": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
							},
							"frames": integerProperty(fmt.Sprintf("Frames to advance while the buttons are held (default 1, cap %d).", maxReplayFrames), 1),
						},
					},
					"minItems": 1,
					"maxItems": maxReplaySteps,
				},
				"context":                    contextProperty(),
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
				"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
			}, []string{"steps"}),
			run: runDeterministicReplay,
		},
	}
}

type replayStepArgs struct {
	Inputs map[string][]string `json:"inputs"`
	Frames *uint64             `json:"frames"`
}

type normalizedReplayStep struct {
	Inputs map[uint64][]string
	Frames uint64
}

type deterministicReplayArgs struct {
	InitialStateID string           `json:"initial_state_id"`
	Steps          []replayStepArgs `json:"steps"`
	Context        string           `json:"context"`
	guardArgs
}

// replayRegisters is the M68K register subset the replay compares. A nil field
// was not readable and is never compared as if it matched.
type replayRegisters struct {
	PC *uint64
	A7 *uint64
	D0 *uint64
}

// complete reports whether every compared register was readable.
func (registers replayRegisters) complete() bool {
	return registers.PC != nil && registers.A7 != nil && registers.D0 != nil
}

// missing names the registers that were not readable, for unproven reasons.
func (registers replayRegisters) missing() string {
	missing := make([]string, 0, 3)
	for _, field := range []struct {
		name  string
		value *uint64
	}{{"m68k_pc", registers.PC}, {"m68k_a7", registers.A7}, {"m68k_d0", registers.D0}} {
		if field.value == nil {
			missing = append(missing, field.name)
		}
	}
	if len(missing) == 0 {
		return "none"
	}
	return strings.Join(missing, ", ")
}

// view renders the readable registers; unreadable ones stay absent instead of
// being invented.
func (registers replayRegisters) view() map[string]any {
	view := map[string]any{}
	if registers.PC != nil {
		view["m68k_pc"] = *registers.PC
		view["m68k_pc_hex"] = canonicalHex(*registers.PC & m68kBusMask)
	}
	if registers.A7 != nil {
		view["m68k_a7"] = *registers.A7
		view["m68k_a7_hex"] = canonicalHex(*registers.A7 & m68kBusMask)
	}
	if registers.D0 != nil {
		view["m68k_d0"] = *registers.D0
	}
	return view
}

// readReplayRegisters reads the M68K register subset the replay compares and
// reports whether the read itself succeeded. A failed read yields an empty,
// incomplete set rather than zeroed registers.
func readReplayRegisters(tc toolContext) (replayRegisters, bool) {
	payload, failure := tc.server.executeCommand(tc.ctx, "regs_get", map[string]string{"cpu": "m68k"})
	if failure != nil {
		return replayRegisters{}, false
	}
	registers, ok := payload["registers"].(map[string]any)
	if !ok {
		return replayRegisters{}, false
	}
	observed := replayRegisters{}
	if pc, ok := registerValue(registers, "pc"); ok {
		observed.PC = &pc
	}
	if a7, ok := registerValue(registers, "a7", "sp", "ssp", "usp"); ok {
		observed.A7 = &a7
	}
	if d0, ok := registerValue(registers, "d0"); ok {
		observed.D0 = &d0
	}
	return observed, observed.complete()
}

// replayRunResult is every observable of one run plus the facts that decide
// whether those observables can be compared at all.
type replayRunResult struct {
	Phase string

	// FrameTokenBaseline is the absolute VDP render token observed before the
	// run's first step. Per-step deltas are measured from it, so the counter
	// starting anywhere after the restore cannot fabricate a divergence.
	FrameTokenBaseline *uint64
	FrameTokens        []*uint64
	FrameTokenDeltas   []*uint64

	StepRegisters  []replayRegisters
	FinalRegisters replayRegisters

	// FramesAdvanced is what the run actually advanced; FramesRequested is what
	// the normalized steps asked for.
	FramesAdvanced  uint64
	FramesRequested uint64
	GenerationStart uint64
	GenerationEnd   uint64
	GenerationSpan  uint64

	// InitialRunState is the run state the restore left the machine in before
	// the first step; InitialRunStateVerified reports whether the native echo
	// confirmed it was paused.
	InitialRunState         string
	InitialRunStateVerified bool

	// Unproven records every axis this run could not observe, so the verdict
	// never silently drops an axis it failed to read.
	Unproven []string
}

func runDeterministicReplay(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[deterministicReplayArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	steps, failure := normalizeReplaySteps(parsed.Steps)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	var totalFrames uint64
	for _, step := range steps {
		totalFrames += step.Frames
	}

	// Generation precondition before any lock is taken.
	if parsed.ExpectedTargetGeneration != nil {
		if failure := targetGenerationPrecondition(tc.server, *parsed.ExpectedTargetGeneration); failure != nil {
			return failureResult(failure, tc.modern)
		}
	}

	// Exclusive control for the full window: reuse an active caller lock or
	// acquire an internal one released at the end (matching the composite
	// capture pattern).
	controlID := parsed.ControlID
	if controlID == "" {
		lock, err := tc.server.controls.Acquire("deterministic_replay", context.ID, 120*time.Second, tc.server.target.Generation())
		if err != nil {
			var held *analysis.ControlHeldError
			if errors.As(err, &held) {
				return failureResult(controlHeldFailure(held.Lock, tc.server.target.Generation()), tc.modern)
			}
			return failureResult(&toolFailure{Code: "invalid_params", Message: err.Error()}, tc.modern)
		}
		controlID = lock.ID
		defer func() {
			_ = tc.server.controls.Release(controlID, "replay_completed")
		}()
	} else if !tc.server.controls.Valid(controlID) {
		return failureResult(&toolFailure{
			Code:    "target_control_held",
			Message: "the provided control_id does not own the active target control lock; acquire one with target_control_acquire or omit control_id to let the server manage the lock",
		}, tc.modern)
	}
	windowGuard := mutationGuard{ControlID: controlID}
	generationBefore := tc.server.target.Generation()

	// Determine the initial state: the caller's snapshot, or a fresh snapshot
	// of the current machine. Both runs start from this exact instant.
	initialSnapshot, failure := replayInitialState(tc, context, parsed.InitialStateID)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	// Every restore that precedes stepping forces the machine paused, so a
	// running target cannot advance frames between the replay's own steps.
	initialRestore, failure := replayRestoreState(tc, context.ID, initialSnapshot.Path, windowGuard, "initial_load", true)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	pauseResumeCycles := 0
	if initialRestore.pauseCycle() {
		pauseResumeCycles++
	}

	run1, failure := replayRunSequence(tc, context.ID, steps, windowGuard, initialRestore, "run_1")
	if failure != nil {
		_, _ = replayRestoreState(tc, context.ID, initialSnapshot.Path, windowGuard, "abort_restore", false)
		return failureResult(failure, tc.modern)
	}
	betweenRuns, failure := replayRestoreState(tc, context.ID, initialSnapshot.Path, windowGuard, "between_runs_restore", true)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if betweenRuns.pauseCycle() {
		pauseResumeCycles++
	}
	run2, failure := replayRunSequence(tc, context.ID, steps, windowGuard, betweenRuns, "run_2")
	if failure != nil {
		_, _ = replayRestoreState(tc, context.ID, initialSnapshot.Path, windowGuard, "abort_restore", false)
		return failureResult(failure, tc.modern)
	}
	// Reload the initial snapshot so the machine describes it again. The final
	// restore preserves the machine's run state instead of forcing one, and
	// because the replay's last frame_advance ended paused, the target ends
	// paused; a failed restore is surfaced, not silently swallowed.
	restored := true
	finalRunState := runStateUnknown
	finalRunStateVerified := false
	if finalRestore, failure := replayRestoreState(tc, context.ID, initialSnapshot.Path, windowGuard, "final_restore", false); failure != nil {
		restored = false
	} else {
		finalRunState = finalRestore.RunState
		finalRunStateVerified = finalRestore.Verified
	}
	generationAfter := tc.server.target.Generation()

	comparison := compareReplayRuns(run1, run2)

	stepsView := make([]map[string]any, 0, len(steps))
	for index, step := range steps {
		inputs := map[string][]string{}
		for port, buttons := range step.Inputs {
			inputs[strconv.FormatUint(port, 10)] = buttons
		}
		stepsView = append(stepsView, map[string]any{"index": index, "frames": step.Frames, "inputs": inputs})
	}
	comparisonView := comparison.view()
	manifest := map[string]any{
		"kind":                   replayManifestKind,
		"schema_version":         replayManifestVer,
		"initial_state_id":       initialSnapshot.ID,
		"initial_state_name":     initialSnapshot.Name,
		"steps":                  stepsView,
		"run_1":                  replayRunView(run1),
		"run_2":                  replayRunView(run2),
		"deterministic":          comparison.Deterministic,
		"checks":                 comparison.Checks,
		"unproven":               comparison.Unproven,
		"frame_token_comparison": replayTokenComparison,
		"pause_resume_cycle":     pauseResumeCycles,
		"final_run_state":        finalRunState,
		"restored":               restored,
		"methodology":            replayMethodology,
	}
	for key, value := range comparisonView {
		manifest[key] = value
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}
	stored, err := tc.server.store.PutWithProvenance(context.ID, replayManifestKind, "application/json", manifestBytes, genericProvenance(tc.server, replayManifestKind, time.Now().UTC()))
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}

	result := map[string]any{
		"kind":                     replayManifestKind,
		"deterministic":            comparison.Deterministic,
		"checks":                   comparison.Checks,
		"unproven":                 comparison.Unproven,
		"frame_token_comparison":   replayTokenComparison,
		"steps":                    len(steps),
		"frames_total":             totalFrames,
		"run_1":                    replayRunView(run1),
		"run_2":                    replayRunView(run2),
		"pause_resume_cycle":       pauseResumeCycles,
		"final_run_state":          finalRunState,
		"final_run_state_verified": finalRunStateVerified,
		"restored":                 restored,
		"artifact":                 artifactDescriptor(tc.server, stored, context.ID),
		"sha256":                   stored.SHA256,
		"initial_state_id":         initialSnapshot.ID,
		"run_state_note":           "The replay forces a paused start after every restore and never resumes the target inside the window: pause_resume_cycle counts the restores that had to pause a machine which was not already paused. The final restore reloads the initial snapshot and preserves the run state rather than forcing one, so the target ends paused because the replay's own frame advances end paused.",
	}
	for key, value := range comparisonView {
		result[key] = value
	}
	if !restored {
		result["restore_warning"] = "WARNING: restoring the initial state after the replay failed; the emulator still describes the end of run 2."
	}
	return okResult(stampGenerations(result, generationBefore, generationAfter), tc.modern)
}

const replayMethodology = "Two identical input sequences (input_set down, frame_advance x N, input_set up per step) executed from the same saved state under exclusive control. Every restore that precedes stepping forces the machine paused, so no frame advances outside the replay's own steps, and each run reports its initial_run_state. The VDP render counter is not part of a saved state and is never reset by state_load, so per-step tokens are compared as deltas from a frame_token_baseline captured at the start of each run, never as absolute values; a token below its run's baseline proves the counter was reset or wrapped and is reported unproven. Per-step M68K register samples (pc/a7/d0) and the final register set are compared field by field. An unreadable token or register set is reported as unproven and never counted as a match. Demonstrated determinism holds for this emulator build and this ROM only; it does not guarantee cross-build reproducibility."

// replayRunView renders one run's observables.
func replayRunView(run *replayRunResult) map[string]any {
	stepRegisters := make([]map[string]any, 0, len(run.StepRegisters))
	for _, registers := range run.StepRegisters {
		stepRegisters = append(stepRegisters, registers.view())
	}
	view := map[string]any{
		"phase":                      run.Phase,
		"frame_token_baseline":       run.FrameTokenBaseline,
		"frame_tokens":               run.FrameTokens,
		"frame_token_deltas":         run.FrameTokenDeltas,
		"step_registers":             stepRegisters,
		"frames_advanced":            run.FramesAdvanced,
		"generation_start":           run.GenerationStart,
		"generation_end":             run.GenerationEnd,
		"generation_span":            run.GenerationSpan,
		"initial_run_state":          run.InitialRunState,
		"initial_run_state_verified": run.InitialRunStateVerified,
		"final_registers":            run.FinalRegisters.view(),
	}
	if len(run.Unproven) > 0 {
		view["unproven"] = run.Unproven
	}
	return view
}

// replayComparison is the determinism verdict and all of the evidence behind
// it: the named checks, the observed differences, and the axes that could not
// be read.
type replayComparison struct {
	Deterministic bool
	Checks        []map[string]any
	Divergences   []map[string]any
	Unproven      []string
}

// view renders the comparison fields that travel with the response and the
// manifest. An empty divergence list is omitted; diverged_step is present only
// when a difference is attributable to one step.
func (comparison replayComparison) view() map[string]any {
	view := map[string]any{"unproven": comparison.Unproven}
	if len(comparison.Divergences) > 0 {
		view["divergences"] = comparison.Divergences
	}
	if diverged := firstStepDivergence(comparison.Divergences); diverged != nil {
		view["diverged_step"] = diverged
	}
	return view
}

// firstStepDivergence returns the first divergence that belongs to one step, or
// nil when every divergence is an end-of-run observation.
func firstStepDivergence(divergences []map[string]any) map[string]any {
	for _, divergence := range divergences {
		if _, ok := divergence["step"]; ok {
			return divergence
		}
	}
	return nil
}

// replayDivergence renders one observed difference with both runs' values. step
// is nil for a divergence that is not attributable to a single step.
func replayDivergence(step *int, field string, run1, run2 any) map[string]any {
	divergence := map[string]any{"field": field, "run1": run1, "run2": run2}
	if step != nil {
		divergence["step"] = *step
	}
	return divergence
}

// compareReplayRuns builds the determinism verdict. deterministic is only true
// when every compared axis was readable in both runs and matched: an axis that
// could not be observed is unproven, never a match.
func compareReplayRuns(run1, run2 *replayRunResult) replayComparison {
	comparison := replayComparison{Deterministic: true, Unproven: []string{}}
	comparison.Unproven = append(comparison.Unproven, run1.Unproven...)
	comparison.Unproven = append(comparison.Unproven, run2.Unproven...)
	addCheck := func(name string, passed bool, detail string) {
		comparison.Checks = append(comparison.Checks, map[string]any{"name": name, "passed": passed, "detail": detail})
	}

	// 1. Per-step frame-token deltas from each run's own baseline: the only
	// frame-token comparison that survives a restore.
	stepCount := len(run1.FrameTokens)
	seriesProven := len(run2.FrameTokens) == stepCount
	if !seriesProven {
		comparison.Unproven = append(comparison.Unproven, fmt.Sprintf("run_1 recorded %d step tokens but run_2 recorded %d, so the step series cannot be aligned", stepCount, len(run2.FrameTokens)))
	}
	deltaDivergences, comparableDeltas := compareReplayDeltas(run1, run2)
	comparison.Divergences = append(comparison.Divergences, deltaDivergences...)
	switch {
	case len(deltaDivergences) > 0:
		first := deltaDivergences[0]
		addCheck("frame_token_deltas_match", false, fmt.Sprintf("step %v advanced %v frames from its baseline in run 1 and %v in run 2", first["step"], first["run1"], first["run2"]))
	case !seriesProven || comparableDeltas != stepCount:
		addCheck("frame_token_deltas_match", false, fmt.Sprintf("only %d of %d steps had a readable frame-token delta in both runs; the frame-token axis is not proven", comparableDeltas, stepCount))
	default:
		addCheck("frame_token_deltas_match", true, fmt.Sprintf("all %d per-step frame-token deltas, measured from each run's own baseline, are identical", stepCount))
	}

	// 2. Per-step register samples: attributes a CPU-state difference to the
	// step that first showed it.
	stepRegisterDivergences, comparableSteps := compareReplayStepRegisters(run1, run2)
	comparison.Divergences = append(comparison.Divergences, stepRegisterDivergences...)
	switch {
	case len(stepRegisterDivergences) > 0:
		first := stepRegisterDivergences[0]
		addCheck("step_registers_match", false, fmt.Sprintf("step %v: %s is %v in run 1 and %v in run 2", first["step"], first["field"], first["run1"], first["run2"]))
	case comparableSteps != stepCount:
		addCheck("step_registers_match", false, fmt.Sprintf("only %d of %d steps had readable registers in both runs; the per-step CPU axis is not proven", comparableSteps, stepCount))
	default:
		addCheck("step_registers_match", true, fmt.Sprintf("all %d per-step M68K register samples are identical", stepCount))
	}

	// 3. The final register set, field by field, so the response names what
	// changed instead of reporting a generic mismatch.
	finalDivergences := replayRegisterDivergences(nil, replayFinalRegisterDivergencePrefix, run1.FinalRegisters, run2.FinalRegisters)
	comparison.Divergences = append(comparison.Divergences, finalDivergences...)
	switch {
	case len(finalDivergences) > 0:
		first := finalDivergences[0]
		addCheck("final_registers_match", false, fmt.Sprintf("%s is %v in run 1 and %v in run 2", first["field"], first["run1"], first["run2"]))
	case !run1.FinalRegisters.complete() || !run2.FinalRegisters.complete():
		addCheck("final_registers_match", false, fmt.Sprintf("the final M68K registers are not fully readable (run 1 missing %s, run 2 missing %s); the axis is not proven", run1.FinalRegisters.missing(), run2.FinalRegisters.missing()))
	default:
		addCheck("final_registers_match", true, "the final M68K registers (pc/a7/d0) are identical across runs")
	}

	// 4. Both runs must have advanced exactly the requested frames.
	if run1.FramesAdvanced == run2.FramesAdvanced && run1.FramesAdvanced == run1.FramesRequested {
		addCheck("frames_advanced_match", true, fmt.Sprintf("both runs advanced exactly %d frames", run1.FramesAdvanced))
	} else {
		addCheck("frames_advanced_match", false, fmt.Sprintf("run 1 advanced %d frames, run 2 advanced %d (requested %d)", run1.FramesAdvanced, run2.FramesAdvanced, run1.FramesRequested))
	}

	// 5. A replay is only meaningful when both runs started paused: a running
	// target advances frames between the steps.
	startedPaused := run1.InitialRunStateVerified && run2.InitialRunStateVerified
	addCheck("initial_run_state_paused", startedPaused, fmt.Sprintf("run 1 started %s, run 2 started %s", run1.InitialRunState, run2.InitialRunState))
	if !startedPaused {
		comparison.Unproven = append(comparison.Unproven, fmt.Sprintf("the replay did not verify a paused start (run 1: %s, run 2: %s), so the stepped frames are not comparable", run1.InitialRunState, run2.InitialRunState))
	}

	comparison.Deterministic = len(comparison.Divergences) == 0 && len(comparison.Unproven) == 0
	for _, check := range comparison.Checks {
		if check["passed"] != true {
			comparison.Deterministic = false
			break
		}
	}
	return comparison
}

// compareReplayDeltas compares the per-step frame-token deltas and reports how
// many steps were comparable. Steps whose delta is unproven on either side are
// skipped: that run already recorded why.
func compareReplayDeltas(run1, run2 *replayRunResult) (divergences []map[string]any, comparable int) {
	steps := min(len(run1.FrameTokenDeltas), len(run2.FrameTokenDeltas))
	for index := 0; index < steps; index++ {
		first, second := run1.FrameTokenDeltas[index], run2.FrameTokenDeltas[index]
		if first == nil || second == nil {
			continue
		}
		comparable++
		if *first == *second {
			continue
		}
		step := index
		divergences = append(divergences, replayDivergence(&step, "frame_token_delta", *first, *second))
	}
	return divergences, comparable
}

// compareReplayStepRegisters compares the per-step register samples and reports
// how many steps were comparable.
func compareReplayStepRegisters(run1, run2 *replayRunResult) (divergences []map[string]any, comparable int) {
	steps := min(len(run1.StepRegisters), len(run2.StepRegisters))
	for index := 0; index < steps; index++ {
		first, second := run1.StepRegisters[index], run2.StepRegisters[index]
		if !first.complete() || !second.complete() {
			continue
		}
		comparable++
		step := index
		divergences = append(divergences, replayRegisterDivergences(&step, replayStepRegisterDivergencePrefix, first, second)...)
	}
	return divergences, comparable
}

// replayRegisterDivergences compares two fully readable register observations
// field by field. prefix qualifies the field name; step is nil for an
// end-of-run observation.
func replayRegisterDivergences(step *int, prefix string, run1, run2 replayRegisters) []map[string]any {
	pairs := []struct {
		name   string
		value1 *uint64
		value2 *uint64
	}{
		{"m68k_pc", run1.PC, run2.PC},
		{"m68k_a7", run1.A7, run2.A7},
		{"m68k_d0", run1.D0, run2.D0},
	}
	divergences := make([]map[string]any, 0, 3)
	for _, pair := range pairs {
		if pair.value1 == nil || pair.value2 == nil || *pair.value1 == *pair.value2 {
			continue
		}
		divergences = append(divergences, replayDivergence(step, prefix+"."+pair.name, *pair.value1, *pair.value2))
	}
	return divergences
}

// normalizeReplaySteps validates and normalizes the step list.
func normalizeReplaySteps(steps []replayStepArgs) ([]normalizedReplayStep, *toolFailure) {
	if len(steps) < 1 {
		return nil, &toolFailure{Code: "invalid_params", Message: "steps must hold 1 or more entries"}
	}
	if len(steps) > maxReplaySteps {
		return nil, &toolFailure{Code: "invalid_params", Message: fmt.Sprintf("steps is capped at %d entries", maxReplaySteps)}
	}
	out := make([]normalizedReplayStep, 0, len(steps))
	for index, step := range steps {
		frames := uint64(1)
		if step.Frames != nil {
			if *step.Frames < minReplayFrames || *step.Frames > maxReplayFrames {
				return nil, &toolFailure{
					Code:    "invalid_params",
					Message: fmt.Sprintf("steps[%d].frames must be between %d and %d", index, minReplayFrames, maxReplayFrames),
				}
			}
			frames = *step.Frames
		}
		inputs := map[uint64][]string{}
		for portKey, buttons := range step.Inputs {
			port, err := strconv.ParseUint(portKey, 10, 64)
			if err != nil || port < 1 || port > 4 {
				return nil, &toolFailure{
					Code:    "invalid_params",
					Message: fmt.Sprintf("steps[%d].inputs key %q must be a player port between 1 and 4", index, portKey),
				}
			}
			if len(buttons) == 0 || len(buttons) > maxInputButtons {
				return nil, &toolFailure{
					Code:    "invalid_params",
					Message: fmt.Sprintf("steps[%d].inputs[%s] must name between 1 and %d buttons", index, portKey, maxInputButtons),
				}
			}
			normalized := make([]string, 0, len(buttons))
			for _, button := range buttons {
				name := strings.ToLower(button)
				if !inputButtonNames[name] {
					return nil, &toolFailure{
						Code:    "invalid_params",
						Message: fmt.Sprintf("steps[%d].inputs[%s]: unknown button %q", index, portKey, button),
					}
				}
				normalized = append(normalized, name)
			}
			inputs[port] = normalized
		}
		out = append(out, normalizedReplayStep{Inputs: inputs, Frames: frames})
	}
	return out, nil
}

func sortedReplayPorts(inputs map[uint64][]string) []uint64 {
	ports := make([]uint64, 0, len(inputs))
	for port := range inputs {
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports
}

// replayInitialState resolves the caller's snapshot or saves the current
// machine state through the native path (state_save does not mutate the
// target and does not advance the generation).
func replayInitialState(tc toolContext, context *analysis.Context, stateID string) (*analysis.Snapshot, *toolFailure) {
	if stateID != "" {
		snapshot, err := tc.server.contexts.States.Get(context.ID, stateID)
		if err != nil {
			return nil, &toolFailure{Code: "unknown_state", Message: err.Error()}
		}
		if _, err := os.Stat(snapshot.Path); err != nil {
			return nil, &toolFailure{Code: "state_file_missing", Message: "snapshot file " + snapshot.Path + " no longer exists"}
		}
		return snapshot, nil
	}
	contextDir := filepath.Join(tc.server.StatesDir(), context.ID)
	if err := os.MkdirAll(contextDir, 0o755); err != nil {
		return nil, &toolFailure{Code: "state_store_error", Message: "create snapshot directory: " + err.Error()}
	}
	snapshotID := analysis.NewSnapshotID()
	path := filepath.Join(contextDir, snapshotID+".zip")
	if _, failure := tc.server.executeCommand(tc.ctx, "state_save", map[string]string{"path": path}); failure != nil {
		return nil, failure
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, &toolFailure{Code: "state_store_error", Message: "verify snapshot file: " + err.Error()}
	}
	digest, err := fileSHA256(path)
	if err != nil {
		return nil, &toolFailure{Code: "state_store_error", Message: "hash snapshot file: " + err.Error()}
	}
	return tc.server.contexts.States.Create(context.ID, &analysis.Snapshot{
		ID:               snapshotID,
		ContextID:        context.ID,
		Path:             path,
		SHA256:           digest,
		SizeBytes:        info.Size(),
		CreatedAt:        time.Now().UTC(),
		ROMPath:          tc.server.currentROMPath(),
		ROMSHA256:        tc.server.romIdentity.romFileFacts(tc.server.currentROMPath()).SHA256,
		TargetGeneration: tc.server.target.Generation(),
	}), nil
}

// replayRestoreOutcome reports the run state one restore left the machine in and
// whether the replay had to force a pause to get there.
type replayRestoreOutcome struct {
	// RestoredRunState is the run state the load echo reported before the
	// replay forced a pause, so a caller can see whether the machine had to be
	// paused at all.
	RestoredRunState string
	// RunState is the run state after the restore, including the forced pause
	// when one was requested; Verified reports whether the native echo
	// confirmed it.
	RunState string
	Verified bool
	Paused   bool
}

// pauseCycle reports whether this restore needed a pause cycle: the replay
// paused a machine that was not already paused. A machine that was already
// paused costs no run-state transition.
func (outcome *replayRestoreOutcome) pauseCycle() bool {
	return outcome != nil && outcome.Paused && outcome.RestoredRunState != runStatePaused
}

// replayRestoreState loads a snapshot back into the emulator under the
// exclusive window guard. When pause is set, it forces the restored machine
// paused inside the same window: a replay that steps on a running target
// observes frames the sequence never requested.
func replayRestoreState(tc toolContext, contextID, path string, guard mutationGuard, phase string, pause bool) (*replayRestoreOutcome, *toolFailure) {
	payload, _, _, failure := tc.server.executeMutation(tc.ctx, mutationCall{
		tool:      "deterministic_replay",
		operation: "state_load",
		params:    map[string]string{"path": path},
		guard:     guard,
		contextID: contextID,
		detail:    map[string]any{"phase": phase},
	})
	if failure != nil {
		return nil, failure
	}
	recordStateFromPayload(tc.server, payload, false)
	outcome := &replayRestoreOutcome{}
	outcome.RestoredRunState, _ = payloadRunState(payload)
	outcome.RunState = outcome.RestoredRunState
	if !pause {
		outcome.Verified = outcome.RestoredRunState != runStateUnknown
		return outcome, nil
	}
	pausePayload, _, _, failure := tc.server.executeMutation(tc.ctx, mutationCall{
		tool:      "deterministic_replay",
		operation: "cpu_control",
		params:    map[string]string{"action": "pause"},
		guard:     windowCloseGuard(guard.ControlID),
		contextID: contextID,
		detail:    map[string]any{"phase": phase, "action": "pause", "reason": "the replay requires a paused start"},
	})
	if failure != nil {
		return nil, &toolFailure{
			Code:    failure.Code,
			Message: "the initial state was restored, but pausing the machine before the replay failed: " + failure.Message,
			Data:    map[string]any{"state_restored": true, "restore_phase": phase},
		}
	}
	outcome.Paused = true
	recordStateFromPayload(tc.server, pausePayload, false)
	outcome.RunState, outcome.Verified = payloadRunState(pausePayload)
	return outcome, nil
}

// replayFrameTokenBaseline reads the absolute VDP render token the run starts
// from. vdp_status is the only operation that exposes the counter without
// advancing a frame. Unlike currentFrameToken it keeps a zero token: zero is an
// observable baseline, not a missing observation.
func replayFrameTokenBaseline(tc toolContext) *uint64 {
	payload, failure := tc.server.executeCommand(tc.ctx, "vdp_status", nil)
	if failure != nil {
		return nil
	}
	imageBuffer, ok := payload["image_buffer"].(map[string]any)
	if !ok {
		return nil
	}
	token, ok := imageBuffer["last_rendered_frame_token"].(float64)
	if !ok || token < 0 {
		return nil
	}
	value := uint64(token)
	return &value
}

// replayFrameToken extracts the token a frame_advance reported. A missing token
// is unreadable, never zero: zero would compare as a match against a zeroed
// baseline.
func replayFrameToken(payload map[string]any) (uint64, bool) {
	if payload == nil {
		return 0, false
	}
	token, ok := payload["frame_token"].(float64)
	if !ok || token < 0 {
		return 0, false
	}
	return uint64(token), true
}

// derivePerStepDeltas computes the per-step frame-token deltas from this run's
// baseline and records every axis the run could not observe. A token below the
// baseline proves the render counter was reset or wrapped mid-run, so the delta
// is meaningless and is left unproven instead of being compared.
func (run *replayRunResult) derivePerStepDeltas() {
	run.FrameTokenDeltas = make([]*uint64, len(run.FrameTokens))
	if run.FrameTokenBaseline == nil {
		run.Unproven = append(run.Unproven, run.Phase+": the VDP frame token was unreadable before the run started, so no per-step delta can be derived (absolute tokens are not comparable across a restore)")
	} else {
		for index, token := range run.FrameTokens {
			switch {
			case token == nil:
				run.Unproven = append(run.Unproven, fmt.Sprintf("%s: step %d reported no frame token", run.Phase, index))
			case *token < *run.FrameTokenBaseline:
				run.Unproven = append(run.Unproven, fmt.Sprintf("%s: step %d frame token %d is below the run baseline %d (the render counter was reset or wrapped)", run.Phase, index, *token, *run.FrameTokenBaseline))
			default:
				delta := *token - *run.FrameTokenBaseline
				run.FrameTokenDeltas[index] = &delta
			}
		}
	}
	if !run.FinalRegisters.complete() {
		run.Unproven = append(run.Unproven, fmt.Sprintf("%s: the final M68K registers are unreadable (missing %s)", run.Phase, run.FinalRegisters.missing()))
	}
	unreadableSteps := 0
	for index, registers := range run.StepRegisters {
		if registers.complete() {
			continue
		}
		unreadableSteps++
		if unreadableSteps <= 3 {
			run.Unproven = append(run.Unproven, fmt.Sprintf("%s: step %d M68K registers are unreadable (missing %s)", run.Phase, index, registers.missing()))
		}
	}
	if unreadableSteps > 3 {
		run.Unproven = append(run.Unproven, fmt.Sprintf("%s: %d of %d steps have unreadable M68K registers", run.Phase, unreadableSteps, len(run.StepRegisters)))
	}
}

// replayRunSequence executes the normalized steps once: for every step it
// presses the step's buttons down on each port, advances the requested number of
// frames, records the resulting frame token, samples the M68K registers, and
// releases the buttons.
func replayRunSequence(tc toolContext, contextID string, steps []normalizedReplayStep, guard mutationGuard, restored *replayRestoreOutcome, phase string) (*replayRunResult, *toolFailure) {
	var requested uint64
	for _, step := range steps {
		requested += step.Frames
	}
	run := &replayRunResult{
		Phase:                   phase,
		FrameTokens:             make([]*uint64, 0, len(steps)),
		StepRegisters:           make([]replayRegisters, 0, len(steps)),
		FramesRequested:         requested,
		GenerationStart:         tc.server.target.Generation(),
		InitialRunState:         restored.RunState,
		InitialRunStateVerified: restored.Verified && restored.RunState == runStatePaused,
	}
	// The baseline is captured before the first step so every step is compared
	// as a distance from this run's own starting token.
	run.FrameTokenBaseline = replayFrameTokenBaseline(tc)
	for stepIndex, step := range steps {
		ports := sortedReplayPorts(step.Inputs)
		for _, port := range ports {
			if _, _, _, failure := tc.server.executeMutation(tc.ctx, mutationCall{
				tool:      "deterministic_replay",
				operation: "input_set",
				params: map[string]string{
					"player":  strconv.FormatUint(port, 10),
					"buttons": strings.Join(step.Inputs[port], ","),
					"state":   "down",
				},
				guard:     guard,
				contextID: contextID,
				detail:    map[string]any{"step": stepIndex, "phase": phase, "player": port, "buttons": step.Inputs[port], "state": "down"},
			}); failure != nil {
				return nil, failure
			}
		}
		payload, _, _, failure := tc.server.executeMutation(tc.ctx, mutationCall{
			tool:      "deterministic_replay",
			operation: "frame_advance",
			params:    map[string]string{"frames": strconv.FormatUint(step.Frames, 10)},
			guard:     guard,
			contextID: contextID,
			detail:    map[string]any{"step": stepIndex, "phase": phase, "frames": step.Frames},
		})
		if failure != nil {
			return nil, failure
		}
		tc.server.runState.setByMCP(false)
		run.FramesAdvanced += step.Frames
		if token, ok := replayFrameToken(payload); ok {
			run.FrameTokens = append(run.FrameTokens, &token)
		} else {
			run.FrameTokens = append(run.FrameTokens, nil)
		}
		registers, _ := readReplayRegisters(tc)
		run.StepRegisters = append(run.StepRegisters, registers)
		for _, port := range ports {
			if _, _, _, failure := tc.server.executeMutation(tc.ctx, mutationCall{
				tool:      "deterministic_replay",
				operation: "input_set",
				params: map[string]string{
					"player":  strconv.FormatUint(port, 10),
					"buttons": strings.Join(step.Inputs[port], ","),
					"state":   "up",
				},
				guard:     guard,
				contextID: contextID,
				detail:    map[string]any{"step": stepIndex, "phase": phase, "player": port, "buttons": step.Inputs[port], "state": "up"},
			}); failure != nil {
				return nil, failure
			}
		}
	}
	run.GenerationEnd = tc.server.target.Generation()
	run.GenerationSpan = run.GenerationEnd - run.GenerationStart
	run.FinalRegisters, _ = readReplayRegisters(tc)
	run.derivePerStepDeltas()
	return run, nil
}
