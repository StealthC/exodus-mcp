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
	"github.com/StealthC/exodus-mcp/internal/artifact"
)

// deterministic_replay (roadmap P8): execute one declarative input sequence
// twice from the same saved state under exclusive control, capture per-step
// frame-token deltas and M68K registers for every run, and report whether the
// runs matched frame-for-frame. The manifest artifact (schema
// replay-manifest/5) records the normalized steps, every run's observables, the
// determinism checks, and the methodology.
//
// The verdict certifies FRAME-level determinism: the per-step frame-token deltas,
// the frames advanced, and the paused start. Register evidence is reported but
// advisory by default, because this target's state_load is not instruction-exact
// — the VDP render counter is demonstrably not restored, and a mid-sequence M68K
// register skew appears even when the start fingerprints and the frame deltas are
// identical. strict:true restores register gating for a caller whose target does
// have instruction-exact save states.
//
// The VDP render counter is not part of a saved state and is never reset by
// state_load: it keeps counting across each restore. Absolute per-step tokens are
// therefore not comparable run-to-run, and only the distance each step advanced
// from a baseline captured at the start of its own run is compared. An axis whose
// data could not be read is reported as unproven (gating) or advisory_unproven
// and never counted as a match.
//
// Each run also fingerprints the machine state its restore produced (pc/a7/d0,
// the condition codes, and the render token) before any input, so a stored
// manifest records what the restores actually delivered. warmup:true adds a
// discarded first pass for targets with residual state; its hypothesis was not
// confirmed on this build, which is why it is off by default.

const (
	maxReplaySteps     = 64
	minReplayFrames    = 1
	maxReplayFrames    = maxFrameAdvance // 60
	replayManifestKind = "replay-manifest"
	replayManifestVer  = "replay-manifest/5"

	// replayTokenComparison names the comparison the verdict rests on, so a
	// caller can tell a delta comparison from an absolute one.
	replayTokenComparison = "per_step_delta_from_run_baseline"

	// replayStepRegisterDivergencePrefix and replayFinalRegisterDivergencePrefix
	// qualify the register fields a divergence names.
	replayStepRegisterDivergencePrefix  = "step_registers"
	replayFinalRegisterDivergencePrefix = "final_registers"

	// replayDefaultRuns and replayWarmupRuns are how many times the input
	// sequence is executed. Two passes are the default: run_1 and run_2 are
	// compared. warmup:true adds a first pass that is discarded, so the verdict
	// comes from run_2 vs run_3 instead.
	replayDefaultRuns = 2
	replayWarmupRuns  = 3

	// m68kConditionCodeMask selects the X/N/Z/V/C bits of the M68K status
	// register, the fallback source of the condition-code fingerprint.
	m68kConditionCodeMask = 0x1F

	// restoreFidelity* classify how faithfully the two restores reproduced the
	// machine state the runs start from. Only an exact restore lets a register
	// difference prove sequence nondeterminism; a not-exact or unverified one
	// demotes the register axis to advisory evidence.
	restoreFidelityExact      = "exact"
	restoreFidelityNotExact   = "not_exact"
	restoreFidelityUnverified = "unverified"

	// registerComparison* (now registerEvidence*) name whether register
	// differences count against the verdict: gating only under strict.
	registerEvidenceGating   = "gating"
	registerEvidenceAdvisory = "advisory"

	// determinismScope* name what a verdict covers: the frame axis always, the
	// register axis only under strict.
	determinismScopeFrameAndRegister = "frame_and_register"
	determinismScopeFrameOnly        = "frame_only"

	// replayRun2Phase and replayRun3Phase are the phases a warm-up run compares.
	replayRun2Phase = "run_2"
	replayRun3Phase = "run_3"
)

func replayToolSpecs() []toolSpec {
	return []toolSpec{
		{
			name:        "deterministic_replay",
			description: "Record and replay one declarative input sequence to verify FRAME-FOR-FRAME determinism of the input sequence: run the same steps twice from the same saved state under exclusive control, capture per-step frame-token deltas, per-step M68K register samples and final M68K registers for every run, then report deterministic true/false plus a replay-manifest/5 artifact. The verdict rests on the frame axis (frame_token_deltas_match, frames_advanced_match, initial_run_state_paused) because this emulator's state_load is not instruction-exact: the VDP render counter is demonstrably not restored, and a mid-sequence M68K register skew (d0 +/-1) appears at identical start fingerprints and identical frame deltas. Register evidence is therefore reported but advisory by default (register_evidence:advisory, determinism_scope:frame_only, differences in advisory_divergences with both values and the step). Pass strict:true only for an emulator with instruction-exact save states: it makes register differences gate again (register_evidence:gating, determinism_scope:frame_and_register, divergences/diverged_step) and is expected to report nondeterminism on this build. Each step holds the listed buttons down for the given number of frames (input_set down, frame_advance x N, input_set up). If the target is running when the call arrives the replay pauses it BEFORE the first restore, so no frame executes between the restore and the first step; pause_resume_cycle and per-run initial_run_state_verified report that pause and are informational only. warmup:true runs the sequence three times and discards the first pass (warmup, warmup_note, warmup_divergences, warmup_restore_fidelity*), deciding the verdict from run_2 vs run_3; it is an experiment for targets with residual state and doubles runtime. Every step is compared as a delta from a frame_token_baseline captured at the start of its own run, never as an absolute token. A gating difference is reported in diverged_step (step, field, run1, run2) when it belongs to one step and in divergences otherwise; an axis that could not be read is listed in unproven (gating) or advisory_unproven and never counts as a match. initial_state_id is optional: omitting it snapshots the current machine state first. The initial state is restored afterwards and the target is left in the run state it had before the call (a running target runs again, a paused target stays paused). Accepts optional expected_target_generation and control_id; without control_id the server acquires an internal lock for the whole window.",
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
				"strict":                     booleanProperty("Default false: register evidence is reported but advisory, because this emulator's state_load is not instruction-exact. True restores register gating (determinism_scope frame_and_register) and requires a target with instruction-exact save states; on the current build it is expected to report nondeterminism."),
				"warmup":                     booleanProperty("Default false: run the sequence twice. True runs it three times, discards run_1 as a warm-up (its differences go to warmup_divergences) and decides the verdict from run_2 vs run_3; an experiment for targets with residual state, at the cost of one extra pass."),
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
	// Strict makes register evidence gate again. It is opt-in because the
	// target's state_load is not instruction-exact, so register equality is not
	// a property this emulator delivers at frame granularity.
	Strict bool `json:"strict"`
	// Warmup runs one extra pass and discards it, for targets with residual
	// state left over from the stop.
	Warmup bool `json:"warmup"`
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

// readReplayRegisterPayload reads the raw M68K register map the native
// registers command returned and reports whether the read itself succeeded.
func readReplayRegisterPayload(tc toolContext) (map[string]any, bool) {
	payload, failure := tc.server.executeCommand(tc.ctx, "regs_get", map[string]string{"cpu": "m68k"})
	if failure != nil {
		return nil, false
	}
	registers, ok := payload["registers"].(map[string]any)
	if !ok {
		return nil, false
	}
	return registers, true
}

// readReplayRegisters reads the M68K register subset the replay compares and
// reports whether the read itself succeeded. A failed read yields an empty,
// incomplete set rather than zeroed registers.
func readReplayRegisters(tc toolContext) (replayRegisters, bool) {
	registers, ok := readReplayRegisterPayload(tc)
	if !ok {
		return replayRegisters{}, false
	}
	observed := replayRegistersFromPayload(registers)
	return observed, observed.complete()
}

// replayRegistersFromPayload extracts the compared register subset from a
// register map.
func replayRegistersFromPayload(registers map[string]any) replayRegisters {
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
	return observed
}

// readReplayConditionCodes reads the M68K condition codes from a register map:
// the ccr field the native registers command exposes, or the low five bits of sr
// when a build reports no ccr. A build that exposes neither leaves them
// unreadable instead of inventing flags.
func readReplayConditionCodes(registers map[string]any) *uint64 {
	if ccr, ok := registerValue(registers, "ccr"); ok {
		return &ccr
	}
	if sr, ok := registerValue(registers, "sr"); ok {
		ccr := sr & m68kConditionCodeMask
		return &ccr
	}
	return nil
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

	// InitialRunState is the run state the native echo reported when the run
	// began. InitialRunStateVerified reports that the machine was already
	// paused before this run changed anything, so the pause was not caused by
	// the tool. PausedStartConfirmed reports that the native echo proved the
	// run actually began paused; that is the fact the verdict rests on, because
	// a pause issued before the restore costs the run nothing.
	InitialRunState         string
	InitialRunStateVerified bool
	PausedStartConfirmed    bool
	InitialRunStateNote     string

	// RestoreFingerprint is the machine state this run's restore produced,
	// measured before any input. Two runs whose fingerprints differ did not
	// start from bit-identical machines, so a register difference between them
	// is not proof that the input sequence is nondeterministic.
	RestoreFingerprint replayFingerprint

	// Warmup marks the first pass, whose differences are reported as
	// observations instead of deciding the verdict.
	Warmup bool

	// Unproven records every gating axis this run could not observe, so the
	// verdict never silently drops an axis it failed to read. RegisterUnproven
	// holds the same for the register axis, which only gates under strict.
	Unproven         []string
	RegisterUnproven []string
}

// replayFingerprint is the post-restore machine state one run starts from: the
// M68K registers, the condition codes, and the absolute VDP render token. It is
// measured before the run's first input, so it describes what state_load
// actually produced. The condition codes matter because a restore that leaves
// the flags behind can shift the first executed instruction without changing
// pc/a7/d0.
type replayFingerprint struct {
	Registers  replayRegisters
	CCR        *uint64
	FrameToken *uint64
}

// view renders the fingerprint; unreadable fields stay absent instead of being
// invented.
func (fingerprint replayFingerprint) view() map[string]any {
	view := fingerprint.Registers.view()
	if fingerprint.CCR != nil {
		view["ccr"] = *fingerprint.CCR
	}
	if fingerprint.FrameToken != nil {
		view["frame_token"] = *fingerprint.FrameToken
	}
	return view
}

// readReplayFingerprint measures the state a restore produced from one register
// read plus one vdp_status read, the only operation that exposes the render
// counter without advancing a frame.
func readReplayFingerprint(tc toolContext) replayFingerprint {
	fingerprint := replayFingerprint{FrameToken: replayFrameTokenBaseline(tc)}
	raw, ok := readReplayRegisterPayload(tc)
	if !ok {
		return fingerprint
	}
	fingerprint.Registers = replayRegistersFromPayload(raw)
	fingerprint.CCR = readReplayConditionCodes(raw)
	return fingerprint
}

// replayRunStart is the run-state evidence one run begins with.
type replayRunStart struct {
	// RunState is the run state the native echo reported for the run's start.
	RunState string
	// Confirmed reports that the echo proved the machine was paused.
	Confirmed bool
	// PreexistingPause reports that the machine was already paused before the
	// replay changed anything for this run, so the tool never paused it.
	PreexistingPause bool
	// Note explains who paused the machine for this run.
	Note string
}

// newReplayRunStart resolves the run-state evidence of one restore. It never
// promotes a pause the replay performed into a preexisting one: the reported
// fact is what the machine did before the tool touched it.
func newReplayRunStart(outcome *replayRestoreOutcome, stage string, toolPausedBefore bool) replayRunStart {
	start := replayRunStart{
		RunState:  outcome.RunState,
		Confirmed: outcome.Verified && outcome.RunState == runStatePaused,
	}
	start.PreexistingPause = start.Confirmed && !outcome.PausedByTool && !toolPausedBefore
	switch {
	case outcome.PausedByTool:
		start.Note = stage + " left the machine running, so the replay paused it afterwards; frames may have executed between that restore and the pause, and the paused start is reported as not preexisting."
	case toolPausedBefore:
		start.Note = "The target was running when deterministic_replay was called, so the replay paused it before the initial restore. Because the pause precedes the restore, no frame executed between the restore and the first step; this is informational and does not weaken the verdict."
	case start.Confirmed:
		start.Note = "The machine was already paused before " + stage + ", so the replay did not change the run state to start this run."
	default:
		start.Note = "The native echo did not prove a paused start for " + stage + ", so the stepped frames are not comparable."
	}
	return start
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

	// Observe the run state the target has when the call arrives. It decides
	// both whether the replay has to pause before its first restore and the run
	// state the target is left in when the window closes.
	entryRunState, entryKnown := replayEntryRunState(tc)
	entryPaused := entryKnown && entryRunState == runStatePaused

	// Pause before the first restore, inside the same guard window. A pause
	// issued after the restore lets the machine execute between state_load and
	// the pause, so run 1 would observe frames run 2 never gets and a
	// deterministic target would be reported as nondeterministic.
	pauseResumeCycles := 0
	pausedBeforeRestore := false
	if !entryPaused {
		if _, _, failure := replaySetRunState(tc, context.ID, windowGuard, "pre_restore_pause", "pause", "pause before the initial restore so no frame executes between the restore and the run"); failure != nil {
			return failureResult(failure, tc.modern)
		}
		pauseResumeCycles++
		pausedBeforeRestore = true
	}

	// Determine the initial state: the caller's snapshot, or a fresh snapshot
	// of the current machine, taken after the pause so the snapshot is already
	// a quiescent instant.
	initialSnapshot, failure := replayInitialState(tc, context, parsed.InitialStateID)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	// Every restore that precedes stepping ends with the machine paused, so a
	// running target cannot advance frames between the replay's own steps.
	initialRestore, failure := replayRestoreState(tc, context.ID, initialSnapshot.Path, windowGuard, "initial_load", true)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if initialRestore.PausedByTool {
		pauseResumeCycles++
	}

	// The sequence runs twice by default, from the same snapshot. warmup:true
	// adds one discarded pass for targets with residual state: the first pass
	// after a stop still carries state the emulator does not restore, so its
	// samples are reported but never decide the verdict.
	passes := replayDefaultRuns
	if parsed.Warmup {
		passes = replayWarmupRuns
	}
	runs := make([]*replayRunResult, 0, passes)
	for pass := 0; pass < passes; pass++ {
		start := newReplayRunStart(initialRestore, "the initial restore", pausedBeforeRestore)
		if pass > 0 {
			restorePhase := fmt.Sprintf("between_runs_restore_%d", pass)
			between, failure := replayRestoreState(tc, context.ID, initialSnapshot.Path, windowGuard, restorePhase, true)
			if failure != nil {
				return failureResult(failure, tc.modern)
			}
			if between.PausedByTool {
				pauseResumeCycles++
			}
			start = newReplayRunStart(between, "the between-runs restore", false)
		}
		phase := fmt.Sprintf("run_%d", pass+1)
		run, failure := replayRunSequence(tc, context.ID, steps, windowGuard, start, phase)
		if failure != nil {
			_, _ = replayCloseWindow(tc, context.ID, initialSnapshot.Path, windowGuard, "abort_restore", entryRunState, entryKnown)
			return failureResult(failure, tc.modern)
		}
		run.Warmup = parsed.Warmup && pass == 0
		runs = append(runs, run)
	}
	// run1 and run2 are the compared passes: the first two by default, the last
	// two when a warm-up pass is discarded.
	run1 := runs[0]
	run2 := runs[1]
	if parsed.Warmup {
		run1 = runs[1]
		run2 = runs[2]
	}
	// Reload the initial snapshot so the machine describes it again, and leave
	// the target in the run state this call found it in: a target that was
	// running runs again, a paused target stays paused. A failed restore or a
	// failed resume is surfaced, never silently swallowed.
	closure, closureFailure := replayCloseWindow(tc, context.ID, initialSnapshot.Path, windowGuard, "final_restore", entryRunState, entryKnown)
	restored := closure.Restored
	finalRunState := closure.FinalRunState
	finalRunStateVerified := closure.FinalRunStateVerified
	generationAfter := tc.server.target.Generation()

	// Only the compared passes decide the verdict; a discarded warm-up pass is
	// reported for transparency.
	comparison := compareReplayRuns(run1, run2, parsed.Strict)
	var warmupView map[string]any
	if parsed.Warmup {
		warmupView = replayWarmupView(compareReplayRuns(runs[0], run1, parsed.Strict))
	}

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
		"kind":                    replayManifestKind,
		"initial_state_id":        initialSnapshot.ID,
		"initial_state_name":      initialSnapshot.Name,
		"steps":                   stepsView,
		"deterministic":           comparison.Deterministic,
		"checks":                  comparison.Checks,
		"unproven":                comparison.Unproven,
		"frame_token_comparison":  replayTokenComparison,
		"strict":                  parsed.Strict,
		"warmup":                  parsed.Warmup,
		"entry_run_state":         entryRunState,
		"pause_resume_cycle":      pauseResumeCycles,
		"final_run_state":         finalRunState,
		"resumed_after_restore":   closure.Resumed,
		"run_state_restored":      closure.RestoreState,
		"restored":                restored,
		"methodology":             replayMethodology,
		"pause_resume_cycle_note": replayPauseCycleNote,
	}
	for key, value := range replayRunsView(runs) {
		manifest[key] = value
	}
	for key, value := range comparisonView {
		manifest[key] = value
	}
	for key, value := range warmupView {
		manifest[key] = value
	}
	provenance := genericProvenance(tc.server, replayManifestKind, time.Now().UTC())
	provenance.CaptureConsistency = replayConsistency(entryRunState, entryKnown, pauseResumeCycles > 0, closure, comparison.Deterministic)
	stored, err := putJSONArtifact(tc.server, context.ID, replayManifestKind, manifest, provenance)
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}

	result := map[string]any{
		"kind":                     replayManifestKind,
		"deterministic":            comparison.Deterministic,
		"determinism_scope":        comparison.DeterminismScope,
		"runs_compared":            comparison.RunsCompared,
		"checks":                   comparison.Checks,
		"unproven":                 comparison.Unproven,
		"frame_token_comparison":   replayTokenComparison,
		"steps":                    len(steps),
		"frames_total":             totalFrames,
		"strict":                   parsed.Strict,
		"warmup":                   parsed.Warmup,
		"entry_run_state":          entryRunState,
		"pause_resume_cycle":       pauseResumeCycles,
		"pause_resume_cycle_note":  replayPauseCycleNote,
		"final_run_state":          finalRunState,
		"final_run_state_verified": finalRunStateVerified,
		"resumed_after_restore":    closure.Resumed,
		"run_state_restored":       closure.RestoreState,
		"restored":                 restored,
		"artifact":                 artifactDescriptor(tc.server, stored, context.ID),
		"sha256":                   stored.SHA256,
		"initial_state_id":         initialSnapshot.ID,
		"run_state_note":           "Before the first restore the replay pauses a target that is running, so no frame executes between the restore and the first step and a running start does not make a deterministic target nondeterministic; pause_resume_cycle and initial_run_state_verified report that pause but neither affects the verdict. The final restore reloads the initial snapshot and leaves the target in the run state observed before the call, so a target that was running runs again and a paused target stays paused.",
	}
	for key, value := range replayRunsView(runs) {
		result[key] = value
	}
	for key, value := range comparisonView {
		result[key] = value
	}
	for key, value := range warmupView {
		result[key] = value
	}
	switch {
	case !restored:
		result["restore_warning"] = "WARNING: restoring the initial state after the replay failed; the emulator still describes the end of the last run."
	case closureFailure != nil:
		result["restore_warning"] = "WARNING: the initial state was restored, but restoring the run state observed before the call failed (" + closureFailure.Message + "); the target stays paused."
	}
	return okResult(stampGenerations(result, generationBefore, generationAfter), tc.modern)
}

// replayWarmupNote explains why the first pass exists and what it is used for.
const replayWarmupNote = "warmup:true runs the input sequence three times from the same snapshot and only run_2 vs run_3 decide the verdict. run_1 is a warm-up pass: a target stopped to enter the window can still carry state the emulator does not restore, so a difference that only shows up in run_1 is reported in warmup_divergences as an observation and never as a failure. warmup_restore_fidelity compares the run_1 and run_2 fingerprints as a direct measure of that residual state. This is an experiment: on the current build the residual state also reaches run_2/run_3, so the warm-up does not make register evidence stable, and it costs one extra pass."

// replayPauseCycleNote states what pause_resume_cycle counts and why a call that
// had to pause a running target is still expected to be deterministic.
const replayPauseCycleNote = "pause_resume_cycle counts the pauses the replay issued to guarantee a quiescent machine: one for a target that was running when the call arrived, plus any restore that had to pause a machine the load left running. It is informational: the pause happens BEFORE the restore, so no frame executes between the restore and the first step, and a call that had to pause a running target is still expected to report deterministic true when the two runs match."

// replayPauseOrigin names who produced the paused start of one run, for the
// check detail. initial_run_state_verified is reported separately so a caller
// can tell a preexisting pause from one the replay performed.
func replayPauseOrigin(run *replayRunResult) string {
	switch {
	case !run.PausedStartConfirmed:
		return "unproven"
	case run.InitialRunStateVerified:
		return "already paused before the run"
	default:
		return "paused by the replay before the restore"
	}
}

// replayConsistency states in the artifact envelope that the manifest spans a
// paused execution window: the machine was paused before the first restore and
// left in the run state the call found.
func replayConsistency(entryRunState string, entryKnown, pausedByTool bool, closure *replayClosureResult, deterministic bool) *artifact.CaptureConsistency {
	consistency := &artifact.CaptureConsistency{
		State:                 consistencyPaused,
		ExecutionPausedByTool: pausedByTool,
		ExecutionResumedAfter: closure.Resumed,
		InitialRunState:       entryRunState,
		FinalRunState:         closure.FinalRunState,
	}
	verdict := "deterministic"
	if !deterministic {
		verdict = "not deterministic for the observed steps"
	}
	note := "The replay ran the input sequence three times on a paused machine (run 1 as a warm-up), compared run 2 against run 3, and restored the initial state; the verdict is " + verdict + "."
	if pausedByTool {
		note += " The target was running when the call arrived and was paused before the first restore, so no frame executed between the restore and the first step."
	}
	switch {
	case closure.Resumed:
		consistency.State = consistencyAtomic
		note += " The target was resumed afterwards because it was running before the call."
	case !entryKnown:
		consistency.State = consistencyAtomic
		note += " The run state before the call was never observed, so the target was left paused instead of guessing."
	case !closure.Restored:
		note += " Restoring the initial state failed; the target describes the end of run 2."
	}
	consistency.Note = note
	return consistency
}

const replayMethodology = "The input sequence (input_set down, frame_advance x N, input_set up per step) is executed twice from the same saved state under exclusive control, with warmup:true adding a discarded first pass and comparing run_2 vs run_3 instead (runs_compared). The verdict certifies frame-level determinism: the per-step frame-token deltas, the frames advanced, and the paused start of both runs gate. Register evidence (per-step and final M68K samples) is reported but advisory by default, because this target's state_load is not instruction-exact: the VDP render counter is demonstrably not restored, and a mid-sequence M68K register skew appears even when the start fingerprints and the frame deltas are identical, so register equality is not something the emulator delivers at frame granularity. strict:true makes register differences gate again (register_evidence:gating, determinism_scope:frame_and_register) and is meant for a target with instruction-exact save states. Register differences are never dropped: they are listed in advisory_divergences with both values and the step, and they become gating divergences under strict. If the target is running when the call arrives it is paused before the initial restore, so nothing executes between the restore and the first step; every restore that precedes stepping ends paused, so no frame advances outside the replay's own steps, and each run reports initial_run_state, initial_run_state_verified (was the machine already paused before this run changed anything), paused_start_confirmed (did the native echo prove the run began paused) and initial_run_state_note. A pause the replay had to perform is informational and does not weaken the verdict. Each run also fingerprints the state its restore produced, before any input: M68K pc/a7/d0, the condition codes when the register payload exposes them, and the absolute VDP render token (restore_fingerprints); restore_fidelity/restore_fidelity_compare report how closely the compared restores matched, as evidence only. The render token is excluded from that comparison because it is not part of a saved state and always moves between runs: per-step tokens are compared as deltas from a frame_token_baseline captured at the start of each run, never as absolute values, and a token below its run's baseline proves the counter was reset or wrapped and is reported unproven. An unreadable frame token is listed in unproven and never counted as a match; an unreadable register sample is listed in advisory_unproven unless strict is set. The final restore reloads the initial snapshot and leaves the target in the run state observed before the call. Demonstrated determinism holds for this emulator build and this ROM only; it does not guarantee cross-build reproducibility."

// replayRunsView renders every executed pass, keyed by phase: run_1/run_2 by
// default, run_1/run_2/run_3 when a warm-up pass was requested.
func replayRunsView(runs []*replayRunResult) map[string]any {
	view := make(map[string]any, len(runs))
	for _, run := range runs {
		view[run.Phase] = replayRunView(run)
	}
	return view
}

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
		"initial_run_state_note":     run.InitialRunStateNote,
		"paused_start_confirmed":     run.PausedStartConfirmed,
		"restore_fingerprint":        run.RestoreFingerprint.view(),
		"warmup":                     run.Warmup,
		"final_registers":            run.FinalRegisters.view(),
	}
	if len(run.Unproven) > 0 {
		view["unproven"] = run.Unproven
	}
	return view
}

// replayComparison is the determinism verdict and all of the evidence behind
// it: the named checks, the observed differences, and the axes that could not be
// read.
type replayComparison struct {
	Deterministic bool
	Checks        []map[string]any
	Divergences   []map[string]any
	// AdvisoryDivergences holds observed differences that do not count against
	// the verdict because register evidence is advisory in this mode. They are
	// reported with both values, never dropped.
	AdvisoryDivergences []map[string]any
	// Unproven lists gating axes that could not be read; AdvisoryUnproven lists
	// axes whose unreadability does not fail the verdict.
	Unproven         []string
	AdvisoryUnproven []string

	// RestoreFidelity is exact, not_exact, or unverified; RestoreFidelityFields
	// names the fingerprint fields that differed and RestoreFidelityCompare
	// names the ones the comparison actually covered.
	RestoreFidelity        string
	RestoreFidelityFields  []string
	RestoreFidelityCompare []string
	RestoreFingerprints    map[string]any
	// RegisterEvidence is gating under strict and advisory otherwise.
	RegisterEvidence string
	// DeterminismScope is frame_and_register when the register axis gates and
	// frame_only when it does not; RunsCompared names the compared phases.
	DeterminismScope string
	RunsCompared     []string
}

// view renders the comparison fields that travel with the response and the
// manifest. An empty divergence list is omitted; diverged_step is present only
// when a gating difference is attributable to one step.
func (comparison replayComparison) view() map[string]any {
	view := map[string]any{
		"unproven":                 comparison.Unproven,
		"advisory_unproven":        comparison.AdvisoryUnproven,
		"advisory_divergences":     comparison.AdvisoryDivergences,
		"restore_fidelity":         comparison.RestoreFidelity,
		"restore_fidelity_fields":  comparison.RestoreFidelityFields,
		"restore_fidelity_compare": comparison.RestoreFidelityCompare,
		"restore_fidelity_note":    replayFidelityNote,
		"restore_fingerprints":     comparison.RestoreFingerprints,
		"register_evidence":        comparison.RegisterEvidence,
		"register_evidence_note":   replayRegisterEvidenceNote,
		"determinism_scope":        comparison.DeterminismScope,
		"runs_compared":            comparison.RunsCompared,
	}
	if len(comparison.Divergences) > 0 {
		view["divergences"] = comparison.Divergences
	}
	if diverged := firstStepDivergence(comparison.Divergences); diverged != nil {
		view["diverged_step"] = diverged
	}
	return view
}

// replayRegisterEvidenceNote states why the register axis is advisory unless the
// caller opts into strict.
const replayRegisterEvidenceNote = "Register evidence is advisory by default because this target's state_load is not instruction-exact: the VDP render counter is demonstrably not restored, and a mid-sequence M68K register skew appears even when the start fingerprints and the frame deltas are identical. Pass strict:true to make register differences gate, which requires an emulator with instruction-exact save states."

// replayFidelityNote states what restore_fidelity covers and why the VDP frame
// token sits in the fingerprint but not in the comparison.
const replayFidelityNote = "restore_fidelity compares the M68K registers (pc/a7/d0) and, when the register payload exposes them, the condition codes (ccr, or sr's low five bits) that each restore produced before any input; restore_fidelity_compare lists the fields that were actually compared, so a build without ccr is visible instead of assumed. The VDP render counter is recorded in every fingerprint but excluded: it is not part of a saved state and always moves between runs, so per-step frame-token deltas are compared instead. exact means the compared fields were identical and not_exact means they were not; this is reported evidence, never a gate."

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
// when every gating axis was readable in both runs and matched: an axis that
// could not be observed is unproven, never a match. The frame axis (per-step
// frame-token deltas, frames advanced, paused start) always gates. Register
// evidence gates only under strict, because this target's state_load is not
// instruction-exact: register equality is not a property the emulator delivers at
// frame granularity, and reporting it as nondeterminism would accuse the input
// sequence of an emulator defect.
func compareReplayRuns(run1, run2 *replayRunResult, strict bool) replayComparison {
	comparison := replayComparison{
		Deterministic:       true,
		Unproven:            []string{},
		AdvisoryUnproven:    []string{},
		AdvisoryDivergences: []map[string]any{},
	}
	comparison.Unproven = append(comparison.Unproven, run1.Unproven...)
	comparison.Unproven = append(comparison.Unproven, run2.Unproven...)
	comparison.AdvisoryUnproven = append(comparison.AdvisoryUnproven, run1.RegisterUnproven...)
	comparison.AdvisoryUnproven = append(comparison.AdvisoryUnproven, run2.RegisterUnproven...)
	addCheck := func(name string, gating, passed bool, detail string) {
		comparison.Checks = append(comparison.Checks, map[string]any{"name": name, "gating": gating, "passed": passed, "detail": detail})
	}

	// 0. What did each restore produce, and is register evidence gating?
	comparison.RestoreFidelity, comparison.RestoreFidelityFields, comparison.RestoreFidelityCompare, comparison.RestoreFingerprints = compareRestoreFingerprints(run1, run2)
	registersGating := strict
	comparison.RunsCompared = []string{run1.Phase, run2.Phase}
	if registersGating {
		comparison.RegisterEvidence = registerEvidenceGating
		comparison.DeterminismScope = determinismScopeFrameAndRegister
		// Under strict every register reason is gating evidence too.
		comparison.Unproven = append(comparison.Unproven, run1.RegisterUnproven...)
		comparison.Unproven = append(comparison.Unproven, run2.RegisterUnproven...)
		comparison.AdvisoryUnproven = []string{}
	} else {
		comparison.RegisterEvidence = registerEvidenceAdvisory
		comparison.DeterminismScope = determinismScopeFrameOnly
	}
	if comparison.RestoreFidelity == restoreFidelityUnverified {
		reason := fmt.Sprintf("the post-restore fingerprint could not be read (%s missing %s, %s missing %s), so the restores themselves cannot be compared", run1.Phase, run1.RestoreFingerprint.Registers.missing(), run2.Phase, run2.RestoreFingerprint.Registers.missing())
		if registersGating {
			comparison.Unproven = append(comparison.Unproven, reason)
		} else {
			comparison.AdvisoryUnproven = append(comparison.AdvisoryUnproven, reason)
		}
	}
	if !registersGating {
		comparison.AdvisoryUnproven = append(comparison.AdvisoryUnproven, fmt.Sprintf("the register axis is advisory in this mode, so unreadable register data never fails the verdict; a gating failure here can only come from the frame axis"))
	}

	// 1. Per-step frame-token deltas from each run's own baseline: the only
	// frame-token comparison that survives a restore, and always gating.
	stepCount := len(run1.FrameTokens)
	seriesProven := len(run2.FrameTokens) == stepCount
	if !seriesProven {
		comparison.Unproven = append(comparison.Unproven, fmt.Sprintf("%s recorded %d step tokens but %s recorded %d, so the step series cannot be aligned", run1.Phase, stepCount, run2.Phase, len(run2.FrameTokens)))
	}
	deltaDivergences, comparableDeltas := compareReplayDeltas(run1, run2)
	comparison.Divergences = append(comparison.Divergences, deltaDivergences...)
	switch {
	case len(deltaDivergences) > 0:
		first := deltaDivergences[0]
		addCheck("frame_token_deltas_match", true, false, fmt.Sprintf("step %v advanced %v frames from its baseline in %s and %v in %s", first["step"], first["run1"], run1.Phase, first["run2"], run2.Phase))
	case !seriesProven || comparableDeltas != stepCount:
		addCheck("frame_token_deltas_match", true, false, fmt.Sprintf("only %d of %d steps had a readable frame-token delta in both runs; the frame-token axis is not proven", comparableDeltas, stepCount))
	default:
		addCheck("frame_token_deltas_match", true, true, fmt.Sprintf("all %d per-step frame-token deltas, measured from each run's own baseline, are identical", stepCount))
	}

	// 2. Per-step register samples: attributes a CPU-state difference to the
	// step that first showed it.
	stepRegisterDivergences, comparableSteps := compareReplayStepRegisters(run1, run2)
	comparison.addRegisterDivergences(registersGating, stepRegisterDivergences)
	switch {
	case len(stepRegisterDivergences) > 0:
		first := stepRegisterDivergences[0]
		addCheck("step_registers_match", registersGating, false, fmt.Sprintf("step %v: %s is %v in %s and %v in %s%s", first["step"], first["field"], first["run1"], run1.Phase, first["run2"], run2.Phase, comparison.registerQualifier()))
	case comparableSteps != stepCount:
		addCheck("step_registers_match", registersGating, false, fmt.Sprintf("only %d of %d steps had readable registers in both runs; the per-step CPU axis is not proven", comparableSteps, stepCount))
	default:
		addCheck("step_registers_match", registersGating, true, fmt.Sprintf("all %d per-step M68K register samples are identical", stepCount))
	}

	// 3. The final register set, field by field, so the response names what
	// changed instead of reporting a generic mismatch.
	finalDivergences := replayRegisterDivergences(nil, replayFinalRegisterDivergencePrefix, run1.FinalRegisters, run2.FinalRegisters)
	comparison.addRegisterDivergences(registersGating, finalDivergences)
	switch {
	case len(finalDivergences) > 0:
		first := finalDivergences[0]
		addCheck("final_registers_match", registersGating, false, fmt.Sprintf("%s is %v in %s and %v in %s%s", first["field"], first["run1"], run1.Phase, first["run2"], run2.Phase, comparison.registerQualifier()))
	case !run1.FinalRegisters.complete() || !run2.FinalRegisters.complete():
		addCheck("final_registers_match", registersGating, false, fmt.Sprintf("the final M68K registers are not fully readable (%s missing %s, %s missing %s); the axis is not proven", run1.Phase, run1.FinalRegisters.missing(), run2.Phase, run2.FinalRegisters.missing()))
	default:
		addCheck("final_registers_match", registersGating, true, "the final M68K registers (pc/a7/d0) are identical across runs")
	}

	// 4. Both runs must have advanced exactly the requested frames.
	if run1.FramesAdvanced == run2.FramesAdvanced && run1.FramesAdvanced == run1.FramesRequested {
		addCheck("frames_advanced_match", true, true, fmt.Sprintf("both runs advanced exactly %d frames", run1.FramesAdvanced))
	} else {
		addCheck("frames_advanced_match", true, false, fmt.Sprintf("%s advanced %d frames, %s advanced %d (requested %d)", run1.Phase, run1.FramesAdvanced, run2.Phase, run2.FramesAdvanced, run1.FramesRequested))
	}

	// 5. Both runs must have actually begun paused, proven by the native echo.
	// A pause the replay had to perform does not fail this check: it is issued
	// before the restore, so the run still started from a quiescent machine.
	pausedStarts := run1.PausedStartConfirmed && run2.PausedStartConfirmed
	addCheck("initial_run_state_paused", true, pausedStarts, fmt.Sprintf("%s began %s (%s), %s began %s (%s)", run1.Phase, run1.InitialRunState, replayPauseOrigin(run1), run2.Phase, run2.InitialRunState, replayPauseOrigin(run2)))
	if !pausedStarts {
		comparison.Unproven = append(comparison.Unproven, fmt.Sprintf("the replay could not prove a paused start (%s: %s, %s: %s), so the stepped frames are not comparable", run1.Phase, run1.InitialRunState, run2.Phase, run2.InitialRunState))
	}

	comparison.Deterministic = len(comparison.Divergences) == 0 && len(comparison.Unproven) == 0
	for _, check := range comparison.Checks {
		if check["gating"] == true && check["passed"] != true {
			comparison.Deterministic = false
			break
		}
	}
	return comparison
}

// addRegisterDivergences files observed register differences where they belong:
// gating divergences under strict, advisory ones otherwise, so a difference the
// emulator cannot avoid is never dropped and never counted against the sequence.
func (comparison *replayComparison) addRegisterDivergences(gating bool, divergences []map[string]any) {
	if len(divergences) == 0 {
		return
	}
	if gating {
		comparison.Divergences = append(comparison.Divergences, divergences...)
		return
	}
	comparison.AdvisoryDivergences = append(comparison.AdvisoryDivergences, divergences...)
}

// registerQualifier explains why a register difference does or does not count.
func (comparison *replayComparison) registerQualifier() string {
	if comparison.RegisterEvidence == registerEvidenceAdvisory {
		return "; the register axis is advisory in this mode, so this difference does not make the input sequence nondeterministic (pass strict:true to gate on it)"
	}
	return ""
}

// compareRestoreFingerprints compares the state the two compared restores
// produced and classifies how faithful they were. The register fields decide the
// classification; the VDP render counter is recorded in each fingerprint but
// excluded because it is not part of a saved state and always moves between
// runs.
func compareRestoreFingerprints(run1, run2 *replayRunResult) (string, []string, []string, map[string]any) {
	views := map[string]any{run1.Phase: run1.RestoreFingerprint.view(), run2.Phase: run2.RestoreFingerprint.view()}
	compared := make([]string, 0, 4)
	differing := make([]string, 0, 4)
	if !run1.RestoreFingerprint.Registers.complete() || !run2.RestoreFingerprint.Registers.complete() {
		return restoreFidelityUnverified, differing, compared, views
	}
	for _, pair := range []struct {
		name          string
		first, second *uint64
	}{
		{"m68k_pc", run1.RestoreFingerprint.Registers.PC, run2.RestoreFingerprint.Registers.PC},
		{"m68k_a7", run1.RestoreFingerprint.Registers.A7, run2.RestoreFingerprint.Registers.A7},
		{"m68k_d0", run1.RestoreFingerprint.Registers.D0, run2.RestoreFingerprint.Registers.D0},
	} {
		compared = append(compared, pair.name)
		if *pair.first != *pair.second {
			differing = append(differing, pair.name)
		}
	}
	// The condition codes are compared only when the payload exposes them; a
	// build without ccr/sr says so through restore_fidelity_compare instead of
	// pretending the flags were checked.
	if run1.RestoreFingerprint.CCR != nil && run2.RestoreFingerprint.CCR != nil {
		compared = append(compared, "ccr")
		if *run1.RestoreFingerprint.CCR != *run2.RestoreFingerprint.CCR {
			differing = append(differing, "ccr")
		}
	}
	if len(differing) > 0 {
		return restoreFidelityNotExact, differing, compared, views
	}
	return restoreFidelityExact, differing, compared, views
}

// replayWarmupView renders what the discarded warm-up pass observed, so a
// caller can see the residual state that motivated it without any of it
// counting against the verdict. run1/run2 in these divergences are the warm-up
// pass and the first gating pass.
func replayWarmupView(comparison replayComparison) map[string]any {
	divergences := make([]map[string]any, 0, len(comparison.Divergences)+len(comparison.AdvisoryDivergences))
	divergences = append(divergences, comparison.Divergences...)
	divergences = append(divergences, comparison.AdvisoryDivergences...)
	return map[string]any{
		"warmup_note":                    replayWarmupNote,
		"warmup_divergences":             divergences,
		"warmup_restore_fidelity":        comparison.RestoreFidelity,
		"warmup_restore_fidelity_fields": comparison.RestoreFidelityFields,
	}
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
	// RestoredRunState is the run state the load echo reported, before any
	// follow-up pause, so a caller can see whether the restore itself left the
	// machine running.
	RestoredRunState string
	// RunState is the last run state a native echo reported for this restore
	// and Verified reports whether that echo proved the machine was paused.
	RunState string
	Verified bool
	// PausedByTool reports whether this restore had to pause a machine the load
	// left running (or left unobserved).
	PausedByTool bool
}

// replayRestoreState loads a snapshot back into the emulator under the
// exclusive window guard. When pauseIfRunning is set, a load that leaves the
// machine running (or leaves its run state unobserved) is followed by a pause:
// a replay that steps on a running target observes frames the sequence never
// requested. The replay always pauses before its first restore, so this
// fallback only covers a bridge whose load resumes execution.
func replayRestoreState(tc toolContext, contextID, path string, guard mutationGuard, phase string, pauseIfRunning bool) (*replayRestoreOutcome, *toolFailure) {
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
	state, echoPresent := payloadRunState(payload)
	outcome.RestoredRunState = state
	outcome.RunState, outcome.Verified = state, echoPresent && state == runStatePaused
	if outcome.Verified || !pauseIfRunning {
		return outcome, nil
	}
	pauseState, pausePresent, failure := replaySetRunState(tc, contextID, guard, phase, "pause", "the replay requires a paused start")
	if failure != nil {
		return nil, &toolFailure{
			Code:    failure.Code,
			Message: "the initial state was restored, but pausing the machine before the replay failed: " + failure.Message,
			Data:    map[string]any{"state_restored": true, "restore_phase": phase},
		}
	}
	outcome.PausedByTool = true
	outcome.RunState = pauseState
	outcome.Verified = pausePresent && pauseState == runStatePaused
	return outcome, nil
}

// replaySetRunState issues one run-state action (pause or run) inside the
// exclusive window and returns the state the native echo reported with whether
// the echo carried it at all.
func replaySetRunState(tc toolContext, contextID string, guard mutationGuard, phase, action, reason string) (string, bool, *toolFailure) {
	payload, _, _, failure := tc.server.executeMutation(tc.ctx, mutationCall{
		tool:      "deterministic_replay",
		operation: "cpu_control",
		params:    map[string]string{"action": action},
		guard:     windowCloseGuard(guard.ControlID),
		contextID: contextID,
		detail:    map[string]any{"phase": phase, "action": action, "reason": reason},
	})
	if failure != nil {
		return runStateUnknown, false, failure
	}
	recordStateFromPayload(tc.server, payload, action == "run")
	state, present := payloadRunState(payload)
	return state, present, nil
}

// replayEntryRunState observes the run state the target has when the call
// arrives. It asks the emulator instead of trusting the run-state tracker: a
// tracker observation can predate a UI-initiated resume, and this reading
// decides whether the replay has to pause before its first restore.
func replayEntryRunState(tc toolContext) (string, bool) {
	payload, failure := tc.server.executeCommand(tc.ctx, "emulator_status", nil)
	if failure == nil {
		if running, ok := payload["system_running"].(bool); ok {
			tc.server.runState.observe(tc.server, running, nil)
			return runStateLabel(running), true
		}
	}
	return observedRunState(tc)
}

// replayClosureResult is the outcome of closing the replay window: the initial
// state is reloaded and the target is left in the run state the call found.
type replayClosureResult struct {
	Restored              bool
	FinalRunState         string
	FinalRunStateVerified bool
	Resumed               bool
	// RestoreState is one of the runStateRestore* labels, so a caller can tell
	// a resumed target from one that was already paused and from a resume the
	// server refused to guess.
	RestoreState string
}

// replayCloseWindow reloads the initial snapshot and restores the run state the
// call observed before it changed anything: a target that was running runs
// again, a paused target stays paused, and a run state the server never
// observed is not guessed (the target stays paused, like the capture windows).
// The returned outcome is non-nil even when a step failed.
func replayCloseWindow(tc toolContext, contextID, path string, guard mutationGuard, phase, entryRunState string, entryKnown bool) (*replayClosureResult, *toolFailure) {
	result := &replayClosureResult{FinalRunState: runStateUnknown, RestoreState: runStateRestoreFailed}
	outcome, failure := replayRestoreState(tc, contextID, path, guard, phase, false)
	if failure != nil {
		return result, failure
	}
	result.Restored = true
	result.FinalRunState = outcome.RunState
	result.FinalRunStateVerified = outcome.Verified
	switch {
	case !entryKnown:
		// A run state the server never observed is not guessed: the target
		// stays paused instead of being started blindly.
		result.RestoreState = runStateRestoreSkippedUnknown
		return result, nil
	case entryRunState != runStateRunning:
		result.RestoreState = runStateRestoreAlreadyPaused
		return result, nil
	}
	state, present, failure := replaySetRunState(tc, contextID, guard, phase, "run", "restore the run state observed before the call")
	if failure != nil {
		return result, failure
	}
	result.FinalRunState = state
	result.FinalRunStateVerified = present && state == runStateRunning
	result.Resumed = true
	result.RestoreState = runStateRestoreRestored
	return result, nil
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
	// Register evidence is recorded separately: it is advisory unless the caller
	// asked for strict, so unreadable register data must not fail a frame verdict.
	if !run.FinalRegisters.complete() {
		run.RegisterUnproven = append(run.RegisterUnproven, fmt.Sprintf("%s: the final M68K registers are unreadable (missing %s)", run.Phase, run.FinalRegisters.missing()))
	}
	unreadableSteps := 0
	for index, registers := range run.StepRegisters {
		if registers.complete() {
			continue
		}
		unreadableSteps++
		if unreadableSteps <= 3 {
			run.RegisterUnproven = append(run.RegisterUnproven, fmt.Sprintf("%s: step %d M68K registers are unreadable (missing %s)", run.Phase, index, registers.missing()))
		}
	}
	if unreadableSteps > 3 {
		run.RegisterUnproven = append(run.RegisterUnproven, fmt.Sprintf("%s: %d of %d steps have unreadable M68K registers", run.Phase, unreadableSteps, len(run.StepRegisters)))
	}
}

// replayRunSequence executes the normalized steps once: for every step it
// presses the step's buttons down on each port, advances the requested number of
// frames, records the resulting frame token, samples the M68K registers, and
// releases the buttons.
func replayRunSequence(tc toolContext, contextID string, steps []normalizedReplayStep, guard mutationGuard, start replayRunStart, phase string) (*replayRunResult, *toolFailure) {
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
		InitialRunState:         start.RunState,
		InitialRunStateVerified: start.PreexistingPause,
		PausedStartConfirmed:    start.Confirmed,
		InitialRunStateNote:     start.Note,
	}
	// The fingerprint of the state the restore produced is measured before any
	// input, and its render token doubles as the baseline every step of this
	// run is compared against.
	run.RestoreFingerprint = readReplayFingerprint(tc)
	run.FrameTokenBaseline = run.RestoreFingerprint.FrameToken
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
