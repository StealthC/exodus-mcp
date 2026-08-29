package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/StealthC/exodus-mcp/internal/analysis"
)

const (
	maxInputSequenceSteps  = 64
	maxInputSequenceFrames = maxFrameAdvance // one step holds buttons for at most 60 frames
)

// inputSequenceToolSpecs implements atomic multi-step controller scheduling
// (roadmap Phase 9): one call presses buttons, advances a requested number of
// frames, and releases them per step, under exclusive control for the whole
// window — reproducible traversal without separate input_set/frame_advance
// choreography and without input-release timing errors.
func inputSequenceToolSpecs() []toolSpec {
	return []toolSpec{
		{
			name:        "input_sequence",
			description: fmt.Sprintf("Execute an atomic multi-step controller sequence: per step the given buttons are pressed on one player port, the system advances the requested number of frames, and the buttons are released. Ends paused with every button released; a failed step releases its buttons before returning, so no input state is left behind. Runs under exclusive control for the whole window (caller control_id reused, otherwise an internal lock is acquired and released). Accepts optional expected_target_generation and control_id; each step is audited individually. Steps: 1-%d entries, frames per step 1-%d.", maxInputSequenceSteps, maxInputSequenceFrames),
			schema: objectSchema(map[string]any{
				"context": contextProperty(),
				"player":  integerProperty("Player port (1-based) selecting the controller device (default 1).", 1),
				"steps": map[string]any{
					"type":        "array",
					"description": "Ordered steps; each step holds the listed buttons for the given number of frames.",
					"minItems":    1,
					"maxItems":    maxInputSequenceSteps,
					"items": map[string]any{
						"type":                 "object",
						"additionalProperties": false,
						"properties": map[string]any{
							"buttons": enumArrayProperty("Buttons to hold for this step.", []string{"up", "down", "left", "right", "a", "b", "c", "start", "x", "y", "z", "mode"}),
							"frames":  integerProperty(fmt.Sprintf("Number of frames to hold the buttons (default 1, cap %d).", maxInputSequenceFrames), 1),
						},
						"required": []string{"buttons"},
					},
				},
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
				"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
			}, []string{"steps"}),
			run: runInputSequence,
		},
	}
}

type inputSequenceStepArgs struct {
	Buttons []string `json:"buttons"`
	Frames  *uint64  `json:"frames"`
}

type inputSequenceArgs struct {
	Context string                  `json:"context"`
	Player  *uint64                 `json:"player"`
	Steps   []inputSequenceStepArgs `json:"steps"`
	guardArgs
}

// normalizedInputSequenceStep is one validated step with normalized button
// names (lowercase, deduplicated, order preserved) and a resolved frame count.
type normalizedInputSequenceStep struct {
	Buttons []string
	Frames  uint64
}

func runInputSequence(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[inputSequenceArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	player := uint64(1)
	if parsed.Player != nil {
		if *parsed.Player < 1 || *parsed.Player > 4 {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "player must be between 1 and 4"}, tc.modern)
		}
		player = *parsed.Player
	}
	steps, failure := normalizeInputSequenceSteps(parsed.Steps)
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
	// acquire an internal one released at the end (composite pattern shared
	// with deterministic_replay and experiment_run).
	controlID := parsed.ControlID
	if controlID == "" {
		lock, err := tc.server.controls.Acquire("input_sequence", context.ID, 120*time.Second, tc.server.target.Generation())
		if err != nil {
			var held *analysis.ControlHeldError
			if errors.As(err, &held) {
				return failureResult(controlHeldFailure(held.Lock, tc.server.target.Generation()), tc.modern)
			}
			return failureResult(&toolFailure{Code: "invalid_params", Message: err.Error()}, tc.modern)
		}
		controlID = lock.ID
		defer func() {
			_ = tc.server.controls.Release(controlID, "input_sequence_completed")
		}()
	} else if !tc.server.controls.Valid(controlID) {
		return failureResult(&toolFailure{
			Code:    "target_control_held",
			Message: "the provided control_id does not own the active target control lock; acquire one with target_control_acquire or omit control_id to let the server manage the lock",
		}, tc.modern)
	}
	windowGuard := mutationGuard{ControlID: controlID}
	generationBefore := tc.server.target.Generation()

	// Execute the steps. Every step presses, advances, releases; on any
	// failure the current step's buttons are released before returning so no
	// input state survives a partial sequence.
	completed := 0
	frameTokens := make([]uint64, 0, len(steps))
	for stepIndex, step := range steps {
		detail := map[string]any{"step": stepIndex, "player": player, "buttons": step.Buttons, "frames": step.Frames}
		if _, _, _, failure := tc.server.executeMutation(tc.ctx, mutationCall{
			tool:      "input_sequence",
			operation: "input_set",
			params: map[string]string{
				"player":  strconv.FormatUint(player, 10),
				"buttons": strings.Join(step.Buttons, ","),
				"state":   "down",
			},
			guard:     windowGuard,
			contextID: context.ID,
			detail:    mergeDetail(detail, map[string]any{"state": "down"}),
		}); failure != nil {
			return failureResult(failure, tc.modern)
		}
		payload, _, _, failure := tc.server.executeMutation(tc.ctx, mutationCall{
			tool:      "input_sequence",
			operation: "frame_advance",
			params:    map[string]string{"frames": strconv.FormatUint(step.Frames, 10)},
			guard:     windowGuard,
			contextID: context.ID,
			detail:    detail,
		})
		// The release must always be attempted: the emulator may have paused
		// mid-advance, but the buttons were pressed and must come up.
		releaseFailure := func() *toolFailure {
			_, _, _, releaseFailure := tc.server.executeMutation(tc.ctx, mutationCall{
				tool:      "input_sequence",
				operation: "input_set",
				params: map[string]string{
					"player":  strconv.FormatUint(player, 10),
					"buttons": strings.Join(step.Buttons, ","),
					"state":   "up",
				},
				guard:     windowGuard,
				contextID: context.ID,
				detail:    mergeDetail(detail, map[string]any{"state": "up"}),
			})
			return releaseFailure
		}
		if failure != nil {
			if releaseFailure := releaseFailure(); releaseFailure != nil {
				// Preserve the original failure code (e.g. controller_not_found)
				// and surface the release problem as a note.
				return failureResult(&toolFailure{
					Code:    failure.Code,
					Message: failure.Message + fmt.Sprintf("; additionally, releasing the step's buttons also failed (%s)", releaseFailure.Message),
				}, tc.modern)
			}
			return failureResult(failure, tc.modern)
		}
		if releaseFailure := releaseFailure(); releaseFailure != nil {
			return failureResult(releaseFailure, tc.modern)
		}
		completed++
		tc.server.runState.setByMCP(false)
		token, _ := payload["frame_token"].(float64)
		frameTokens = append(frameTokens, uint64(token))
	}

	generationAfter := tc.server.target.Generation()
	result := map[string]any{
		"player":          player,
		"steps":           len(steps),
		"steps_completed": completed,
		"frames_total":    totalFrames,
		"frame_tokens":    frameTokens,
		"system_running":  false,
		"note":            "The sequence ends paused with every button released; call cpu_run to resume.",
	}
	return okResult(stampGenerations(result, generationBefore, generationAfter), tc.modern)
}

// normalizeInputSequenceSteps validates and normalizes the step list: button
// names are lowercased, deduplicated (order preserved), and frame counts are
// resolved with the documented caps.
func normalizeInputSequenceSteps(steps []inputSequenceStepArgs) ([]normalizedInputSequenceStep, *toolFailure) {
	if len(steps) < 1 {
		return nil, &toolFailure{Code: "invalid_params", Message: "steps must hold 1 or more entries"}
	}
	if len(steps) > maxInputSequenceSteps {
		return nil, &toolFailure{Code: "invalid_params", Message: fmt.Sprintf("steps is capped at %d entries", maxInputSequenceSteps)}
	}
	out := make([]normalizedInputSequenceStep, 0, len(steps))
	for index, step := range steps {
		if len(step.Buttons) == 0 || len(step.Buttons) > maxInputButtons {
			return nil, &toolFailure{Code: "invalid_params", Message: fmt.Sprintf("steps[%d].buttons must name between 1 and %d buttons", index, maxInputButtons)}
		}
		seen := make(map[string]bool, len(step.Buttons))
		normalized := make([]string, 0, len(step.Buttons))
		for _, button := range step.Buttons {
			name := strings.ToLower(button)
			if !inputButtonNames[name] {
				return nil, &toolFailure{Code: "invalid_params", Message: fmt.Sprintf("steps[%d].buttons: unknown button %q", index, button)}
			}
			if !seen[name] {
				seen[name] = true
				normalized = append(normalized, name)
			}
		}
		frames := uint64(1)
		if step.Frames != nil {
			if *step.Frames < 1 || *step.Frames > maxInputSequenceFrames {
				return nil, &toolFailure{Code: "invalid_params", Message: fmt.Sprintf("steps[%d].frames must be between 1 and %d", index, maxInputSequenceFrames)}
			}
			frames = *step.Frames
		}
		out = append(out, normalizedInputSequenceStep{Buttons: normalized, Frames: frames})
	}
	return out, nil
}

// mergeDetail combines audit detail maps; both are plain key/value maps.
func mergeDetail(base, extra map[string]any) map[string]any {
	merged := make(map[string]any, len(base)+len(extra))
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range extra {
		merged[key] = value
	}
	return merged
}
