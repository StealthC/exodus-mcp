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
// frame tokens and final M68K registers for both runs, and report whether the
// runs matched frame-for-frame. The manifest artifact (schema replay-manifest/1)
// records the normalized steps, both runs' observables, the determinism checks,
// and the methodology. This is both the input recording (run 1) and the
// replay verification (run 2) in one tool: recording and replay share the
// identical code path, so a mismatch is a real emulator nondeterminism signal
// rather than a harness artifact.

const (
	maxReplaySteps     = 64
	minReplayFrames    = 1
	maxReplayFrames    = maxFrameAdvance // 60
	replayManifestKind = "replay-manifest"
	replayManifestVer  = "replay-manifest/1"
)

func replayToolSpecs() []toolSpec {
	return []toolSpec{
		{
			name:        "deterministic_replay",
			description: "Record and replay one declarative input sequence to verify frame-for-frame determinism: run the same steps twice from the same saved state under exclusive control, capture per-step frame tokens and final M68K registers for both runs, then report deterministic true/false plus a replay-manifest/1 artifact. Each step holds the listed buttons down for the given number of frames (input_set down, frame_advance x N, input_set up). initial_state_id is optional: omitting it snapshots the current machine state first. The emulator is restored to the initial state afterwards. Accepts optional expected_target_generation and control_id; without control_id the server acquires an internal lock for the whole window.",
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

type replayRunResult struct {
	FrameTokens     []uint64
	FramesAdvanced  uint64
	GenerationStart uint64
	GenerationEnd   uint64
	GenerationSpan  uint64
	FinalRegisters  map[string]any
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
	if failure := replayRestoreState(tc, context.ID, initialSnapshot.Path, windowGuard, "initial_load"); failure != nil {
		return failureResult(failure, tc.modern)
	}

	run1, failure := replayRunSequence(tc, context.ID, steps, windowGuard, "run_1")
	if failure != nil {
		_ = replayRestoreState(tc, context.ID, initialSnapshot.Path, windowGuard, "abort_restore")
		return failureResult(failure, tc.modern)
	}
	if failure := replayRestoreState(tc, context.ID, initialSnapshot.Path, windowGuard, "between_runs_restore"); failure != nil {
		return failureResult(failure, tc.modern)
	}
	run2, failure := replayRunSequence(tc, context.ID, steps, windowGuard, "run_2")
	if failure != nil {
		_ = replayRestoreState(tc, context.ID, initialSnapshot.Path, windowGuard, "abort_restore")
		return failureResult(failure, tc.modern)
	}
	// Restore the initial state so the tool leaves the machine where it
	// found it; a failed restore is surfaced, not silently swallowed.
	restored := true
	if failure := replayRestoreState(tc, context.ID, initialSnapshot.Path, windowGuard, "final_restore"); failure != nil {
		restored = false
	}
	generationAfter := tc.server.target.Generation()

	// Determinism verdict across every observable.
	checks := []map[string]any{}
	deterministic := true
	addCheck := func(name string, passed bool, detail string) {
		checks = append(checks, map[string]any{"name": name, "passed": passed, "detail": detail})
		if !passed {
			deterministic = false
		}
	}
	tokensMatch := len(run1.FrameTokens) == len(run2.FrameTokens)
	if tokensMatch {
		for i := range run1.FrameTokens {
			if run1.FrameTokens[i] != run2.FrameTokens[i] {
				tokensMatch = false
				break
			}
		}
	}
	if tokensMatch {
		addCheck("frame_tokens_match", true, fmt.Sprintf("all %d per-step frame tokens are identical across runs", len(run1.FrameTokens)))
	} else {
		addCheck("frame_tokens_match", false, "per-step frame tokens differ between run 1 and run 2")
	}
	registersMatch := jsonText(run1.FinalRegisters) == jsonText(run2.FinalRegisters)
	if registersMatch {
		addCheck("final_registers_match", true, "final M68K registers (pc/a7/d0 where readable) are identical across runs")
	} else {
		addCheck("final_registers_match", false, "final M68K registers differ between run 1 and run 2")
	}
	if run1.FramesAdvanced == run2.FramesAdvanced && run1.FramesAdvanced == totalFrames {
		addCheck("frames_advanced_match", true, fmt.Sprintf("both runs advanced exactly %d frames", totalFrames))
	} else {
		addCheck("frames_advanced_match", false, fmt.Sprintf("run 1 advanced %d frames, run 2 advanced %d (requested %d)", run1.FramesAdvanced, run2.FramesAdvanced, totalFrames))
	}

	stepsView := make([]map[string]any, 0, len(steps))
	for index, step := range steps {
		inputs := map[string][]string{}
		for port, buttons := range step.Inputs {
			inputs[strconv.FormatUint(port, 10)] = buttons
		}
		stepsView = append(stepsView, map[string]any{"index": index, "frames": step.Frames, "inputs": inputs})
	}
	manifest := map[string]any{
		"kind":               replayManifestKind,
		"schema_version":     replayManifestVer,
		"initial_state_id":   initialSnapshot.ID,
		"initial_state_name": initialSnapshot.Name,
		"steps":              stepsView,
		"run_1":              replayRunView(run1),
		"run_2":              replayRunView(run2),
		"deterministic":      deterministic,
		"checks":             checks,
		"restored":           restored,
		"methodology":        "Two identical input sequences (input_set down, frame_advance x N, input_set up per step) executed from the same saved state under exclusive control. Determinism is judged on per-step frame tokens and final M68K registers. Frame tokens come from the VDP render counter; a target without a VDP yields vacuous zero tokens, in which case the register check carries the verdict. Demonstrated determinism holds for this emulator build and this ROM only; it does not guarantee cross-build reproducibility.",
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
		"kind":             replayManifestKind,
		"deterministic":    deterministic,
		"checks":           checks,
		"steps":            len(steps),
		"frames_total":     totalFrames,
		"run_1":            replayRunView(run1),
		"run_2":            replayRunView(run2),
		"restored":         restored,
		"artifact":         artifactDescriptor(tc.server, stored, context.ID),
		"sha256":           stored.SHA256,
		"initial_state_id": initialSnapshot.ID,
	}
	if !restored {
		result["restore_warning"] = "WARNING: restoring the initial state after the replay failed; the emulator still describes the end of run 2."
	}
	return okResult(stampGenerations(result, generationBefore, generationAfter), tc.modern)
}

func replayRunView(run *replayRunResult) map[string]any {
	return map[string]any{
		"frame_tokens":     run.FrameTokens,
		"frames_advanced":  run.FramesAdvanced,
		"generation_start": run.GenerationStart,
		"generation_end":   run.GenerationEnd,
		"generation_span":  run.GenerationSpan,
		"final_registers":  run.FinalRegisters,
	}
}

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

// replayRestoreState loads a snapshot back into the emulator under the
// exclusive window guard and attributes the resulting paused state to MCP.
func replayRestoreState(tc toolContext, contextID, path string, guard mutationGuard, phase string) *toolFailure {
	if _, _, _, failure := tc.server.executeMutation(tc.ctx, mutationCall{
		tool:      "deterministic_replay",
		operation: "state_load",
		params:    map[string]string{"path": path},
		guard:     guard,
		contextID: contextID,
		detail:    map[string]any{"phase": phase},
	}); failure != nil {
		return failure
	}
	tc.server.runState.setByMCP(false)
	return nil
}

// replayRunSequence executes the normalized steps once: for every step it
// presses the step's buttons down on each port, advances the requested number
// of frames, records the resulting frame token, and releases the buttons. The
// final M68K registers are captured best-effort for the determinism verdict.
func replayRunSequence(tc toolContext, contextID string, steps []normalizedReplayStep, guard mutationGuard, phase string) (*replayRunResult, *toolFailure) {
	run := &replayRunResult{
		FrameTokens:     make([]uint64, 0, len(steps)),
		FinalRegisters:  map[string]any{},
		GenerationStart: tc.server.target.Generation(),
	}
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
		token, _ := payload["frame_token"].(float64)
		run.FrameTokens = append(run.FrameTokens, uint64(token))
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

	if payload, failure := tc.server.executeCommand(tc.ctx, "regs_get", map[string]string{"cpu": "m68k"}); failure == nil {
		if registers, ok := payload["registers"].(map[string]any); ok {
			if pc, ok := registerValue(registers, "pc"); ok {
				run.FinalRegisters["m68k_pc"] = pc
				run.FinalRegisters["m68k_pc_hex"] = canonicalHex(pc & m68kBusMask)
			}
			if a7, ok := registerValue(registers, "a7", "sp", "ssp", "usp"); ok {
				run.FinalRegisters["m68k_a7"] = a7
				run.FinalRegisters["m68k_a7_hex"] = canonicalHex(a7 & m68kBusMask)
			}
			if d0, ok := registerValue(registers, "d0"); ok {
				run.FinalRegisters["m68k_d0"] = d0
			}
		}
	}
	return run, nil
}
