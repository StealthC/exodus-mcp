package mcp

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/StealthC/exodus-mcp/internal/artifact"
)

// Honest capture consistency (roadmap P0): one standardized
// capture_consistency object on every state-observing tool. It distinguishes
// live, paused, atomic, state_restored, and composite_non_atomic captures;
// states whether execution was paused by the tool and resumed afterwards; and
// reports observed run states and frame tokens. Agents choose between a
// paused capture (temporally atomic, perturbs timing) and a live capture
// (non-invasive, possibly internally inconsistent) from this metadata instead
// of inferring it from a tool name.

// Capture consistency states (see artifact.CaptureConsistency).
const (
	consistencyLive               = "live"
	consistencyPaused             = "paused"
	consistencyAtomic             = "atomic"
	consistencyStateRestored      = "state_restored"
	consistencyCompositeNonAtomic = "composite_non_atomic"
)

// captureModeLive is the explicit default of the optional capture guard:
// never pause a running system.
const captureModeLive = "live"

// captureModePaused is the opt-in capture guard: pause once before the read,
// restore the prior run state afterwards, so the sample is temporally atomic.
const captureModePaused = "paused"

// newCaptureID returns a stable id linking the artifacts of one composite
// capture.
func newCaptureID() string {
	buffer := make([]byte, 12)
	if _, err := rand.Read(buffer); err != nil {
		return "cap_" + fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return "cap_" + base64.RawURLEncoding.EncodeToString(buffer)
}

// initialRunStateLabel returns the last observed run state as a label.
func initialRunStateLabel(server *Server) string {
	if running, known := server.runState.currentState(); known {
		if running {
			return "running"
		}
		return "paused"
	}
	return "unknown"
}

// buildCaptureConsistency computes the standardized object for one read
// operation. payload mirrors the plugin read payload (system_paused_during_read,
// consistency); composite marks a multi-read composition, and allChunksPaused
// reports whether every component read found the system already paused (only
// meaningful when composite). initialToken/finalToken are optional observed
// frame tokens; when the caller provides none, they stay absent rather than
// being invented.
func buildCaptureConsistency(server *Server, payload map[string]any, composite, allChunksPaused bool, initialToken, finalToken *uint64) *artifact.CaptureConsistency {
	initial := initialRunStateLabel(server)
	pausedByTool, _ := payload["system_paused_during_read"].(bool)
	if composite {
		pausedByTool = !allChunksPaused
	}
	consistency := &artifact.CaptureConsistency{
		ExecutionPausedByTool: pausedByTool,
		ExecutionResumedAfter: pausedByTool,
		InitialRunState:       initial,
		InitialFrameToken:     initialToken,
		FinalFrameToken:       finalToken,
	}
	// Composite captures first: the composition itself decides the state. All
	// component reads paused means one stable paused instant; any read that
	// found the system running means the pieces span multiple moments.
	if composite {
		if allChunksPaused {
			consistency.State = consistencyPaused
			consistency.FinalRunState = "paused"
			consistency.Note = "Every component read found the system already paused; the composite spans one stable paused instant."
			if initial != "paused" {
				consistency.Note += " The run-state tracker's last observation said " + initial + "; the system was paused throughout the reads."
			}
		} else {
			consistency.State = consistencyCompositeNonAtomic
			consistency.FinalRunState = "running"
			consistency.Note = "Component reads spanned multiple emulated moments (at least one found the system running); the pieces must not be combined into a coherent instant. Per-component frame tokens are not captured."
		}
		return consistency
	}
	if pausedByTool {
		// The handler stopped a running system and restored it: the sample is
		// temporally atomic and the end state equals the start state.
		consistency.State = consistencyAtomic
		if initial == "unknown" {
			// The tracker never saw the state, but the pause flag proves the
			// system was running and was resumed; state it explicitly.
			consistency.InitialRunState = "running"
			consistency.FinalRunState = "running"
			consistency.Note = "The plugin paused a running system for the read and restored it; the pre-operation run state was not otherwise observed."
			return consistency
		}
		consistency.FinalRunState = initial
		consistency.Note = "The capture paused a running system once and restored it; the sample is temporally atomic."
		return consistency
	}
	if initial == "paused" {
		consistency.State = consistencyPaused
		consistency.FinalRunState = "paused"
		consistency.Note = "The system was already paused; no run-state change was caused by the capture."
		return consistency
	}
	consistency.State = consistencyLive
	consistency.FinalRunState = initial
	if initial == "unknown" {
		consistency.Note = "The read never paused the system; the pre-read run state was not observed (query emulator_status first for a full verdict)."
	} else {
		consistency.Note = "Sampled while the system was running without pausing; values are live and can be internally inconsistent across reads."
	}
	return consistency
}

// compositeCaptureConsistency builds the object for a composite capture whose
// component reads all found the system paused (coherent) or not, without a
// plugin payload.
func compositeCaptureConsistency(server *Server, coherent bool) *artifact.CaptureConsistency {
	return buildCaptureConsistency(server, map[string]any{}, true, coherent, nil, nil)
}

// captureGuard carries the optional capture_mode argument of a read tool.
// "live" (default) never pauses; "paused" pauses once before the read and
// restores the prior run state afterwards.
type captureGuard struct {
	Mode string `json:"capture_mode"`
}

// resolve validates the capture_mode argument.
func (guard *captureGuard) resolve() *toolFailure {
	if guard.Mode == "" {
		guard.Mode = captureModeLive
	}
	if guard.Mode != captureModeLive && guard.Mode != captureModePaused {
		return &toolFailure{
			Code:    "invalid_params",
			Message: fmt.Sprintf("capture_mode must be %q (default) or %q", captureModeLive, captureModePaused),
		}
	}
	return nil
}

// pauseSystemOnce pauses the system when it is running, via the serialized
// mutation path, and reports whether a pause was issued. The tracker records
// the MCP attribution.
func (server *Server) pauseSystemOnce(tc toolContext) (bool, *toolFailure) {
	running, known := server.runState.currentState()
	if known && !running {
		return false, nil
	}
	_, _, _, failure := server.executeMutation(tc.ctx, mutationCall{
		tool:      "capture_guard",
		operation: "cpu_control",
		params:    map[string]string{"action": "pause"},
		contextID: "",
		detail:    map[string]any{"action": "pause", "reason": "capture guard"},
	})
	if failure != nil {
		return false, failure
	}
	server.runState.setByMCP(false)
	return true, nil
}

// resumeSystemOnce restores a running system after a capture-guard pause.
func (server *Server) resumeSystemOnce(tc toolContext) *toolFailure {
	_, _, _, failure := server.executeMutation(tc.ctx, mutationCall{
		tool:      "capture_guard",
		operation: "cpu_control",
		params:    map[string]string{"action": "run"},
		contextID: "",
		detail:    map[string]any{"action": "run", "reason": "capture guard restore"},
	})
	if failure != nil {
		return failure
	}
	server.runState.setByMCP(true)
	return nil
}

// withCaptureGuard implements the optional capture guard for one read:
// "paused" pauses once before the read and restores the prior run state
// afterwards, so the sample is temporally atomic; "live" (default) never
// pauses. The wrapped value map is stamped with the capture_consistency
// object describing the window and returned as the MCP result envelope. A
// failed restore is surfaced prominently in the result instead of silently
// leaving the system paused.
func withCaptureGuard(tc toolContext, guard captureGuard, read func() (map[string]any, *toolFailure)) map[string]any {
	if guard.Mode == captureModeLive {
		result, failure := read()
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		return okResult(result, tc.modern)
	}
	initialState := initialRunStateLabel(tc.server)
	initialToken := currentFrameToken(tc)
	paused, failure := tc.server.pauseSystemOnce(tc)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	result, readFailure := read()
	if readFailure != nil {
		// Restore the prior run state even when the read failed, so the
		// guard never leaks a paused system.
		if paused {
			_ = tc.server.resumeSystemOnce(tc)
		}
		return failureResult(readFailure, tc.modern)
	}
	finalToken := currentFrameToken(tc)
	consistency := &artifact.CaptureConsistency{
		State:                 consistencyAtomic,
		ExecutionPausedByTool: paused,
		ExecutionResumedAfter: false,
		InitialRunState:       initialState,
		FinalRunState:         initialState,
		InitialFrameToken:     initialToken,
		FinalFrameToken:       finalToken,
	}
	if paused {
		if failure := tc.server.resumeSystemOnce(tc); failure != nil {
			consistency.ExecutionResumedAfter = false
			consistency.Note = "WARNING: restoring the prior run state failed after the capture; the system may still be paused."
			result["run_state_restore_failed"] = true
		} else {
			consistency.ExecutionResumedAfter = true
		}
	} else {
		consistency.Note = "The system was already paused; the capture guard added no run-state change."
	}
	view := captureConsistencyToMap(consistency)
	result["capture_consistency"] = view
	// Composite results expose the object in their summary; keep both in sync.
	if summary, ok := result["summary"].(map[string]any); ok {
		summary["capture_consistency"] = view
	}
	return okResult(result, tc.modern)
}

// currentFrameToken returns the last rendered frame token from vdp_status, or
// nil when the read fails or the VDP is absent. Never fails the caller.
func currentFrameToken(tc toolContext) *uint64 {
	payload, failure := tc.server.executeCommand(tc.ctx, "vdp_status", nil)
	if failure != nil {
		return nil
	}
	imageBuffer, _ := payload["image_buffer"].(map[string]any)
	token, _ := imageBuffer["last_rendered_frame_token"].(float64)
	if token == 0 {
		return nil
	}
	value := uint64(token)
	return &value
}

// captureConsistencyToMap renders the object as a plain map for responses.
func captureConsistencyToMap(consistency *artifact.CaptureConsistency) map[string]any {
	if consistency == nil {
		return nil
	}
	encoded, err := json.Marshal(consistency)
	if err != nil {
		return map[string]any{"state": consistency.State}
	}
	var view map[string]any
	if err := json.Unmarshal(encoded, &view); err != nil {
		return map[string]any{"state": consistency.State}
	}
	return view
}
