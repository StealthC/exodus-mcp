package mcp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/StealthC/exodus-mcp/internal/analysis"
	"github.com/StealthC/exodus-mcp/internal/artifact"
)

// memory_snapshot_capture (roadmap P0): one bounded paused memory snapshot
// operation. It accepts one or more named ranges in one address space, pauses
// the system once if necessary, reads every range while paused, restores the
// original run state, and links all produced raw artifacts plus a manifest to
// one capture id. Unlike the per-range live read loop, the pause happens
// exactly once, so the whole set describes one temporally atomic instant.

const (
	captureMaxRanges       = 16
	captureMaxRangeNameLen = 64
	captureKind            = "capture-manifest"
)

type captureRangeArgs struct {
	Name    string `json:"name"`
	Address any    `json:"address"`
	Length  uint64 `json:"length"`
}

type memorySnapshotCaptureArgs struct {
	Space   string             `json:"space"`
	Ranges  []captureRangeArgs `json:"ranges"`
	Context string             `json:"context"`
	guardArgs
}

func memorySnapshotCaptureSpec() toolSpec {
	return toolSpec{
		name:        "memory_snapshot_capture",
		description: "Capture one or more named ranges of one address space as a temporally atomic snapshot: pauses the system once if it is running, reads every range while paused (never the per-range live read loop), restores the prior run state, and links all raw range artifacts plus a capture manifest to one stable capture id. The response reports exactly one pause/resume cycle when the system was running (zero when it was already paused), the target generation span, initial/final run states, and frame tokens when the VDP exposes them. Runs under exclusive control for the full window (a caller-provided active control_id is reused, otherwise an internal lock is acquired and released). A paused capture can perturb real-time behavior; a live capture would be internally inconsistent across ranges. Accepts optional expected_target_generation and control_id.",
		schema: objectSchema(map[string]any{
			"space": stringProperty("Address space id from memory_spaces_list; every range shares it."),
			"ranges": map[string]any{
				"type":        "array",
				"description": fmt.Sprintf("Named ranges to capture (1-%d, total bytes capped at %d).", captureMaxRanges, dumpCapBytes),
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"name":    stringProperty(fmt.Sprintf("Unique range label (max %d characters, letters/digits/_/-).", captureMaxRangeNameLen)),
						"address": addressProperty(),
						"length":  integerProperty("Byte length between 1 and the dump cap.", 1),
					},
					"required": []string{"name", "address", "length"},
				},
				"minItems": 1,
				"maxItems": captureMaxRanges,
			},
			"context":                    contextProperty(),
			"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
			"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
		}, []string{"space", "ranges"}),
		run: runMemorySnapshotCapture,
	}
}

// validateCaptureRanges enforces the bounded range contract: unique labels,
// per-range length limits, and a total byte cap.
func validateCaptureRanges(ranges []captureRangeArgs) ([]captureRange, *toolFailure) {
	if len(ranges) < 1 || len(ranges) > captureMaxRanges {
		return nil, &toolFailure{
			Code:    "invalid_params",
			Message: fmt.Sprintf("ranges must hold between 1 and %d entries", captureMaxRanges),
		}
	}
	prepared := make([]captureRange, 0, len(ranges))
	seen := map[string]bool{}
	var total uint64
	for index, entry := range ranges {
		name := strings.TrimSpace(entry.Name)
		if name == "" || len(name) > captureMaxRangeNameLen {
			return nil, &toolFailure{
				Code:    "invalid_params",
				Message: fmt.Sprintf("ranges[%d].name must be 1-%d characters", index, captureMaxRangeNameLen),
			}
		}
		for _, ch := range name {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-') {
				return nil, &toolFailure{
					Code:    "invalid_params",
					Message: fmt.Sprintf("ranges[%d].name %q contains unsupported characters (letters, digits, _ and - only)", index, name),
				}
			}
		}
		if seen[name] {
			return nil, &toolFailure{
				Code:    "invalid_params",
				Message: fmt.Sprintf("ranges[%d].name %q is duplicated; range labels must be unique", index, name),
			}
		}
		seen[name] = true
		address, failure := parseAddress(entry.Address)
		if failure != nil {
			return nil, &toolFailure{
				Code:    "invalid_params",
				Message: fmt.Sprintf("ranges[%d].address: %s", index, failure.Message),
			}
		}
		if entry.Length < 1 || entry.Length > dumpCapBytes {
			return nil, &toolFailure{
				Code:    "invalid_params",
				Message: fmt.Sprintf("ranges[%d].length must be between 1 and %d bytes", index, dumpCapBytes),
			}
		}
		total += entry.Length
		if total > dumpCapBytes {
			return nil, &toolFailure{
				Code:    "invalid_params",
				Message: fmt.Sprintf("the combined range length exceeds the %d byte cap", dumpCapBytes),
			}
		}
		prepared = append(prepared, captureRange{Name: name, Address: address, Length: entry.Length})
	}
	return prepared, nil
}

type captureRange struct {
	Name    string
	Address uint64
	Length  uint64
}

// runMemorySnapshotCapture implements the paused composite capture. The whole
// window runs under exclusive control so no other mutation interleaves between
// the pause and the resume; every produced artifact carries the same capture
// id, and the manifest records the generation span and consistency facts.
func runMemorySnapshotCapture(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[memorySnapshotCaptureArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	space := strings.TrimSpace(parsed.Space)
	if space == "" {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "space must name a space id from memory_spaces_list"}, tc.modern)
	}
	ranges, failure := validateCaptureRanges(parsed.Ranges)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}

	// Generation precondition before any lock is taken.
	if parsed.ExpectedTargetGeneration != nil {
		if failure := targetGenerationPrecondition(tc.server, *parsed.ExpectedTargetGeneration); failure != nil {
			return failureResult(failure, tc.modern)
		}
	}

	// Exclusive control for the full window: reuse an active caller lock or
	// acquire an internal one released at the end.
	controlID := parsed.ControlID
	internalLock := false
	if controlID == "" {
		lock, err := tc.server.controls.Acquire("memory_snapshot_capture "+space, context.ID, 60*time.Second, tc.server.target.Generation())
		if err != nil {
			var held *analysis.ControlHeldError
			if errors.As(err, &held) {
				return failureResult(controlHeldFailure(held.Lock, tc.server.target.Generation()), tc.modern)
			}
			return failureResult(&toolFailure{Code: "invalid_params", Message: err.Error()}, tc.modern)
		}
		controlID = lock.ID
		internalLock = true
		defer func() {
			_ = tc.server.controls.Release(controlID, "capture_completed")
		}()
	} else if !tc.server.controls.Valid(controlID) {
		return failureResult(&toolFailure{
			Code:    "target_control_held",
			Message: "the provided control_id does not own the active target control lock; acquire one with target_control_acquire or omit control_id to let the server manage the lock",
		}, tc.modern)
	}

	// Observe the initial run state and frame token.
	initialState := initialRunStateLabel(tc.server)
	initialToken := currentFrameToken(tc)
	generationBefore := tc.server.target.Generation()

	// The pause/resume mutations carry the effective control id (acquired or
	// caller-provided) so the exclusive window never rejects its own actions.
	windowGuard := mutationGuard{ControlID: controlID}
	if parsed.ExpectedTargetGeneration != nil {
		windowGuard.ExpectedGeneration = *parsed.ExpectedTargetGeneration
		windowGuard.HasExpectedGeneration = true
	}

	// Pause exactly once when the system is running.
	running, known := tc.server.runState.currentState()
	wasRunning := !known || running
	pauseResumeCycle := 0
	if wasRunning {
		_, _, _, failure := tc.server.executeMutation(tc.ctx, mutationCall{
			tool:      "memory_snapshot_capture",
			operation: "cpu_control",
			params:    map[string]string{"action": "pause"},
			guard:     windowGuard,
			contextID: context.ID,
			detail:    map[string]any{"action": "pause", "reason": "paused composite capture"},
		})
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		tc.server.runState.setByMCP(false)
		pauseResumeCycle = 1
	}

	// Read every range while paused; all artifacts share one capture id.
	captureID := newCaptureID()
	capturedAt := time.Now().UTC()
	atomicConsistency := &artifact.CaptureConsistency{
		State:                 consistencyAtomic,
		ExecutionPausedByTool: wasRunning,
		ExecutionResumedAfter: false,
		InitialRunState:       initialState,
		InitialFrameToken:     initialToken,
	}
	readRanges := make([]map[string]any, 0, len(ranges))
	restoreFailed := false
	for _, entry := range ranges {
		params := map[string]string{
			"space":   space,
			"address": strconv.FormatUint(entry.Address, 10),
			"length":  strconv.FormatUint(entry.Length, 10),
		}
		payload, failure := tc.server.executeCommand(tc.ctx, "mem_read", params)
		if failure != nil {
			// Restore the prior run state so a partial capture never leaks a
			// paused system.
			if pauseResumeCycle == 1 {
				if _, _, _, restoreFailure := tc.server.executeMutation(tc.ctx, mutationCall{
					tool:      "memory_snapshot_capture",
					operation: "cpu_control",
					params:    map[string]string{"action": "run"},
					contextID: context.ID,
					detail:    map[string]any{"action": "run", "reason": "capture abort restore"},
				}); restoreFailure == nil {
					tc.server.runState.setByMCP(true)
				}
			}
			return failureResult(annotateSpaceRangeFailure(tc, failure, space), tc.modern)
		}
		rawDataBase64, _ := payload["data"].(string)
		raw, err := base64.StdEncoding.DecodeString(rawDataBase64)
		if err != nil {
			return failureResult(&toolFailure{Code: "bridge_error", Message: "decode base64 capture payload: " + err.Error()}, tc.modern)
		}
		provenance := captureProvenance(tc.server, "memory-snapshot", space, entry.Address, uint64(len(raw)), payload, capturedAt, captureID, atomicConsistency)
		stored, err := tc.server.store.PutWithProvenance(context.ID, "memory-snapshot", "application/octet-stream", raw, provenance)
		if err != nil {
			return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
		}
		readRanges = append(readRanges, map[string]any{
			"name":              entry.Name,
			"space":             space,
			"address":           entry.Address,
			"address_hex":       canonicalHex(entry.Address),
			"effective_address": uint64(rawEffectiveAddress(payload)),
			"byte_length":       len(raw),
			"artifact":          artifactDescriptor(tc.server, stored, context.ID),
		})
	}

	// Restore the prior run state.
	if pauseResumeCycle == 1 {
		if _, _, _, failure := tc.server.executeMutation(tc.ctx, mutationCall{
			tool:      "memory_snapshot_capture",
			operation: "cpu_control",
			params:    map[string]string{"action": "run"},
			guard:     windowGuard,
			contextID: context.ID,
			detail:    map[string]any{"action": "run", "reason": "capture restore"},
		}); failure != nil {
			restoreFailed = true
		} else {
			tc.server.runState.setByMCP(true)
		}
	}
	atomicConsistency.ExecutionResumedAfter = !restoreFailed
	atomicConsistency.FinalRunState = initialState
	atomicConsistency.FinalFrameToken = currentFrameToken(tc)
	if restoreFailed {
		atomicConsistency.Note = "WARNING: restoring the prior run state failed after the capture; the system may still be paused."
	} else if pauseResumeCycle == 0 {
		atomicConsistency.Note = "The system was already paused; the capture added exactly one pause window of zero length and no run-state change."
	} else {
		atomicConsistency.Note = fmt.Sprintf("Exactly one pause/resume cycle: the system was paused for the reads and restored to %s afterwards; all ranges describe one temporally atomic instant.", initialState)
	}
	generationAfter := tc.server.target.Generation()

	// Manifest artifact linking every range to the capture id.
	manifest := map[string]any{
		"kind":                     captureKind,
		"capture_id":               captureID,
		"capture_consistency":      atomicConsistency,
		"pause_resume_cycle":       pauseResumeCycle,
		"target_generation_before": generationBefore,
		"target_generation_after":  generationAfter,
		"rom_identity":             tc.server.romIdentityView(0),
		"space":                    space,
		"ranges":                   readRanges,
		"internal_lock_acquired":   internalLock,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}
	manifestProvenance := genericProvenance(tc.server, captureKind, capturedAt)
	manifestProvenance.CaptureID = captureID
	manifestProvenance.CaptureConsistency = atomicConsistency
	storedManifest, err := tc.server.store.PutWithProvenance(context.ID, captureKind, "application/json", manifestBytes, manifestProvenance)
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}

	result := map[string]any{
		"summary": map[string]any{
			"kind":                     captureKind,
			"capture_id":               captureID,
			"capture_consistency":      captureConsistencyToMap(atomicConsistency),
			"pause_resume_cycle":       pauseResumeCycle,
			"target_generation_before": generationBefore,
			"target_generation_after":  generationAfter,
			"space":                    space,
			"ranges_count":             len(readRanges),
			"bytes_captured":           sumCaptureBytes(readRanges),
			"internal_lock_acquired":   internalLock,
			"manifest_sha256":          storedManifest.SHA256,
		},
		"manifest": artifactDescriptor(tc.server, storedManifest, context.ID),
		"ranges":   readRanges,
	}
	if restoreFailed {
		result["run_state_restore_failed"] = true
	}
	return okResult(stampGenerations(result, generationBefore, generationAfter), tc.modern)
}

// rawEffectiveAddress extracts the effective address of a mem_read payload.
func rawEffectiveAddress(payload map[string]any) uint64 {
	effective, _ := payload["effective_address"].(float64)
	return uint64(effective)
}

// sumCaptureBytes totals the captured byte lengths of the range views.
func sumCaptureBytes(ranges []map[string]any) uint64 {
	var total uint64
	for _, entry := range ranges {
		if length, ok := entry["byte_length"].(int); ok {
			total += uint64(length)
		}
	}
	return total
}
