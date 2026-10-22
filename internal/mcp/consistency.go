package mcp

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
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

// Run-state labels used by every capture window. "unknown" is reserved for a
// run state no observation established: it is never silently upgraded to a
// guess, and a window with an unknown initial state never resumes the target.
const (
	runStateRunning = "running"
	runStatePaused  = "paused"
	runStateUnknown = "unknown"
)

// Stable codes of the run_state_restore object every capture window reports.
// A caller can branch on the code instead of parsing prose, and no code claims
// a restore that did not happen.
const (
	runStateRestoreRestored       = "restored"
	runStateRestoreAlreadyPaused  = "already_paused"
	runStateRestoreSkippedUnknown = "resume_skipped_initial_run_state_unknown"
	runStateRestoreFailed         = "run_state_restore_failed"
	runStateRestoreUnverified     = "run_state_restore_unverified"
)

// runStateLabel renders one observed run state as a label.
func runStateLabel(running bool) string {
	if running {
		return runStateRunning
	}
	return runStatePaused
}

// initialRunStateLabel returns the last observed run state as a label.
func initialRunStateLabel(server *Server) string {
	if running, known := server.runState.currentState(); known {
		return runStateLabel(running)
	}
	return runStateUnknown
}

// observedRunState returns the run state a capture window must trust before it
// pauses anything, and whether that state is known. The tracker answers when it
// holds an observation; otherwise one read-only emulator_status query
// establishes it, so a fresh server never pauses a target it cannot attribute.
// When neither source answers, the state stays honestly unknown and the window
// will not resume.
func observedRunState(tc toolContext) (string, bool) {
	if running, known := tc.server.runState.currentState(); known {
		return runStateLabel(running), true
	}
	payload, failure := tc.server.executeCommand(tc.ctx, "emulator_status", nil)
	if failure != nil {
		return runStateUnknown, false
	}
	running, ok := payload["system_running"].(bool)
	if !ok {
		return runStateUnknown, false
	}
	tc.server.runState.observe(tc.server, running, nil)
	return runStateLabel(running), true
}

// payloadRunState reads the run state a native run-state action echoed, and
// reports whether the payload actually carried it. It is the verification of a
// restore: the plugin answers cpu_control with the resulting system_running.
func payloadRunState(payload map[string]any) (string, bool) {
	running, ok := payload["system_running"].(bool)
	if !ok {
		return runStateUnknown, false
	}
	return runStateLabel(running), true
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
// restores the prior run state it observed afterwards. A target whose pre-call
// run state could not be observed is paused for the sample and never resumed.
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
// the MCP attribution. The native payload is returned so the caller can verify
// the resulting run state instead of assuming it.
func (server *Server) pauseSystemOnce(tc toolContext) (map[string]any, bool, *toolFailure) {
	running, known := server.runState.currentState()
	if known && !running {
		return nil, false, nil
	}
	payload, _, _, failure := server.executeMutation(tc.ctx, mutationCall{
		tool:      "capture_guard",
		operation: "cpu_control",
		params:    map[string]string{"action": "pause"},
		contextID: "",
		detail:    map[string]any{"action": "pause", "reason": "capture guard"},
	})
	if failure != nil {
		return nil, false, failure
	}
	server.runState.setByMCP(false)
	return payload, true, nil
}

// resumeSystemOnce restores a running system after a capture-guard pause and
// returns the native payload so the caller can verify the restored run state.
func (server *Server) resumeSystemOnce(tc toolContext) (map[string]any, *toolFailure) {
	payload, _, _, failure := server.executeMutation(tc.ctx, mutationCall{
		tool:      "capture_guard",
		operation: "cpu_control",
		params:    map[string]string{"action": "run"},
		contextID: "",
		detail:    map[string]any{"action": "run", "reason": "capture guard restore"},
	})
	if failure != nil {
		return nil, failure
	}
	server.runState.setByMCP(true)
	return payload, nil
}

// captureWindow is the run-state bookkeeping of one capture guard window: what
// the target was doing before the read, whether the tool paused it, whether the
// capture restored it, and the final observed state. One window yields exactly
// one capture-consistency object, and that object is what both the response and
// every artifact written inside the window must describe.
type captureWindow struct {
	Mode string

	InitialRunState string
	InitialKnown    bool
	InitialToken    *uint64
	FinalToken      *uint64

	PausedByTool  bool
	PauseVerified bool
	Resumed       bool
	// ResumeSkippedReason states why the capture did not restore a target it
	// paused; empty when a restore was attempted or no pause happened.
	ResumeSkippedReason string
	RestoreFailure      *toolFailure
	RestoreVerified     bool
	FinalRunState       string

	// Consistency is the single object describing this window. Producers
	// attach it to artifact provenance while the window is open; the window
	// completes it after the guard and re-stamps the stored envelopes.
	Consistency *artifact.CaptureConsistency

	// publish, when set by a producer, builds the final response after the
	// window closed and the consistency object is final. A producer whose
	// response embeds a durable manifest uses it so no artifact is written
	// with a provisional window state.
	publish func() (map[string]any, *toolFailure)

	artifacts []artifact.Artifact
}

// track registers one artifact written inside the window so its stored
// capture-consistency object can be completed before the response is published.
func (window *captureWindow) track(stored artifact.Artifact) {
	if window == nil {
		return
	}
	window.artifacts = append(window.artifacts, stored)
}

// ids returns the stored artifact ids written inside the window.
func (window *captureWindow) ids() []string {
	if window == nil || len(window.artifacts) == 0 {
		return nil
	}
	ids := make([]string, 0, len(window.artifacts))
	for _, stored := range window.artifacts {
		ids = append(ids, stored.ID)
	}
	return ids
}

// consistencyFor returns the capture-consistency object a producer must attach
// to its artifact provenance and response. A paused capture owns one object for
// the whole window (the guard completes it after the restore); a live capture
// derives it from the read payload and the run-state tracker.
func (window *captureWindow) consistencyFor(server *Server, payload map[string]any) *artifact.CaptureConsistency {
	if window == nil {
		return buildCaptureConsistency(server, payload, false, true, nil, nil)
	}
	if window.Consistency == nil {
		// A live window derives its object from the read payload once; every
		// later call in the same window reuses it, so one window never reports
		// two different objects.
		window.Consistency = buildCaptureConsistency(server, payload, false, true, nil, nil)
	}
	return window.Consistency
}

// legacyConsistency returns the legacy consistency label a producer must
// report next to the object. It is derived from the object, never copied from
// the plugin payload, so the two fields describing one capture cannot
// contradict each other.
func (window *captureWindow) legacyConsistency(server *Server, payload map[string]any) string {
	return window.consistencyFor(server, payload).State
}

// beginCaptureWindow starts a window: it observes the initial run state and
// pauses the system once when the caller asked for a paused capture.
func beginCaptureWindow(tc toolContext, guard captureGuard) (*captureWindow, *toolFailure) {
	window := &captureWindow{Mode: guard.Mode, InitialRunState: runStateUnknown}
	if guard.Mode == captureModeLive {
		return window, nil
	}
	window.InitialRunState, window.InitialKnown = observedRunState(tc)
	window.InitialToken = currentFrameToken(tc)
	payload, paused, failure := tc.server.pauseSystemOnce(tc)
	if failure != nil {
		return nil, failure
	}
	window.PausedByTool = paused
	if paused {
		if state, ok := payloadRunState(payload); ok {
			window.PauseVerified = state == runStatePaused
		}
	}
	// The window only claims atomicity when it really paused the target; a
	// target that was already paused is the documented "paused" state, exactly
	// as an unguarded read of the same machine reports.
	consistencyState := consistencyPaused
	if paused {
		consistencyState = consistencyAtomic
	}
	window.Consistency = &artifact.CaptureConsistency{
		State:                 consistencyState,
		ExecutionPausedByTool: paused,
		InitialRunState:       window.InitialRunState,
		InitialFrameToken:     window.InitialToken,
	}
	return window, nil
}

// closeWindow restores the prior run state and completes the consistency
// object. A target the guard paused is resumed only when its pre-call run state
// was actually observed: resuming a machine that may already have been paused
// would start it, so an unknown initial state leaves the target paused and says
// so. The restore is verified from the native run-state echo, never assumed.
// resume performs the restore inside the window (nil uses the default
// capture-guard resume), so a composite capture can keep its own control lock
// and audit attribution.
func (window *captureWindow) closeWindow(tc toolContext, resume func() (map[string]any, *toolFailure)) {
	if window == nil || window.Mode == captureModeLive {
		return
	}
	if window.PausedByTool {
		switch {
		case !window.InitialKnown:
			window.ResumeSkippedReason = "the pre-call run state was unknown, so resuming could start a machine that was already paused; the target is left paused"
		default:
			if resume == nil {
				resume = func() (map[string]any, *toolFailure) {
					return tc.server.resumeSystemOnce(tc)
				}
			}
			payload, failure := resume()
			if failure != nil {
				window.RestoreFailure = failure
			} else {
				window.Resumed = true
				if state, ok := payloadRunState(payload); ok {
					window.RestoreVerified = state == runStateRunning
				}
			}
		}
	}
	window.FinalToken = currentFrameToken(tc)
	switch {
	case !window.PausedByTool:
		// The window found the system already paused and changed nothing.
		window.FinalRunState = window.InitialRunState
	case window.Resumed && window.RestoreVerified:
		window.FinalRunState = runStateRunning
	case window.Resumed:
		window.FinalRunState = runStateUnknown
	default:
		// Paused by the tool and deliberately not resumed (or the restore
		// failed): the target is paused, and the object says so.
		window.FinalRunState = runStatePaused
	}
	consistency := window.Consistency
	if consistency == nil {
		return
	}
	consistency.ExecutionPausedByTool = window.PausedByTool
	consistency.ExecutionResumedAfter = window.Resumed
	consistency.InitialRunState = window.InitialRunState
	consistency.FinalRunState = window.FinalRunState
	consistency.InitialFrameToken = window.InitialToken
	consistency.FinalFrameToken = window.FinalToken
	consistency.Note = window.note()
}

// note explains the window in one sentence, matching the reported facts.
func (window *captureWindow) note() string {
	switch {
	case window.RestoreFailure != nil:
		return "WARNING: the capture could not restore the prior run state; the target may still be paused."
	case window.ResumeSkippedReason != "":
		return "The capture paused the target but did not resume it: " + window.ResumeSkippedReason + ". Send cpu_run when it should be running again."
	case !window.PausedByTool:
		return "The system was already paused; the capture guard caused no run-state change."
	case window.Resumed && window.RestoreVerified:
		return "The capture paused the running system once and resumed it afterwards; the sample is temporally atomic."
	case window.Resumed:
		return "The capture paused the running system and issued the resume, but the native payload did not report the resulting run state; the final state is unverified."
	default:
		return "The capture paused the running system for the sample and did not resume it."
	}
}

// restoreView renders the run-state restore outcome as a stable-code object.
func (window *captureWindow) restoreView() map[string]any {
	code := runStateRestoreRestored
	message := "The prior run state was restored and verified from the native run-state echo."
	switch {
	case window.RestoreFailure != nil:
		code = runStateRestoreFailed
		message = "Restoring the prior run state failed: " + window.RestoreFailure.Message
	case window.ResumeSkippedReason != "":
		code = runStateRestoreSkippedUnknown
		message = "The target was not resumed: " + window.ResumeSkippedReason + "."
	case !window.PausedByTool:
		code = runStateRestoreAlreadyPaused
		message = "No pause was issued, so there was no run state to restore."
	case window.Resumed && !window.RestoreVerified:
		code = runStateRestoreUnverified
		message = "The resume command succeeded, but the native payload did not report the resulting run state; the final state is unverified."
	}
	view := map[string]any{
		"code":              code,
		"message":           message,
		"initial_run_state": window.InitialRunState,
		"final_run_state":   window.FinalRunState,
		"paused_by_tool":    window.PausedByTool,
		"resumed":           window.Resumed,
		"verified":          window.RestoreVerified,
	}
	if window.ResumeSkippedReason != "" {
		view["resume_skipped_reason"] = window.ResumeSkippedReason
	}
	if window.RestoreFailure != nil {
		view["failure_code"] = window.RestoreFailure.Code
		view["failure_message"] = window.RestoreFailure.Message
	}
	return view
}

// withCaptureGuard implements the optional capture guard for one read:
// "paused" pauses once before the read and restores the prior run state
// afterwards, so the sample is temporally atomic; "live" (default) never
// pauses. The read closure receives the window so it can attach the window's
// capture-consistency object to the artifact provenance it writes; the guard
// completes that object after the restore and re-stamps the response and the
// stored envelopes, so the durable artifact never claims a different window
// than the response.
func withCaptureGuard(tc toolContext, guard captureGuard, read func(window *captureWindow) (map[string]any, *toolFailure)) map[string]any {
	window, failure := beginCaptureWindow(tc, guard)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if guard.Mode == captureModeLive {
		result, readFailure := read(window)
		if readFailure == nil && window.publish != nil {
			result, readFailure = window.publish()
		}
		if readFailure != nil {
			return failureResult(readFailure, tc.modern)
		}
		// A live window never changes the run state, but it still reports the
		// one consistency object its artifacts were written with.
		if window.Consistency != nil {
			view := captureConsistencyToMap(window.Consistency)
			result["capture_consistency"] = view
			if summary, ok := result["summary"].(map[string]any); ok {
				summary["capture_consistency"] = view
			}
		}
		return okResult(result, tc.modern)
	}
	result, readFailure := read(window)
	window.closeWindow(tc, nil)
	if readFailure == nil && window.publish != nil {
		// The producer deferred its publication until the window was final, so
		// no durable artifact states a provisional run-state outcome.
		result, readFailure = window.publish()
	}
	restore := window.restoreView()
	if readFailure != nil {
		// Restore the prior run state even when the read failed, so the guard
		// never leaks a paused system, and report the restore outcome with the
		// failure instead of dropping it.
		if readFailure.Data == nil {
			readFailure.Data = map[string]any{}
		}
		readFailure.Data["run_state_restore"] = restore
		if restore["code"] == runStateRestoreFailed {
			readFailure.Data[runStateRestoreFailed] = true
		}
		return failureResult(readFailure, tc.modern)
	}
	view := captureConsistencyToMap(window.Consistency)
	result["capture_consistency"] = view
	result["run_state_restore"] = restore
	result["initial_run_state"] = window.InitialRunState
	result["final_run_state"] = window.FinalRunState
	result["resumed"] = window.Resumed
	if window.ResumeSkippedReason != "" {
		result["resume_skipped_reason"] = window.ResumeSkippedReason
	}
	if restore["code"] == runStateRestoreFailed {
		result[runStateRestoreFailed] = true
	}
	// Composite results expose the same objects in their summary; keep both in
	// sync so neither view contradicts the other.
	if summary, ok := result["summary"].(map[string]any); ok {
		summary["capture_consistency"] = view
		summary["run_state_restore"] = restore
		summary["initial_run_state"] = window.InitialRunState
		summary["final_run_state"] = window.FinalRunState
		summary["resumed"] = window.Resumed
		if window.ResumeSkippedReason != "" {
			summary["resume_skipped_reason"] = window.ResumeSkippedReason
		}
	}
	// The artifacts were written while the window was open: complete their
	// stored provenance now, then re-stamp every provenance view in the
	// response so the durable artifact and the response agree.
	tc.server.store.FinalizeCaptureConsistency(window.ids(), window.Consistency)
	restampCaptureProvenance(result, view, window.Consistency.State)
	return okResult(result, tc.modern)
}

// restampCaptureProvenance walks a response and replaces the capture-consistency
// object of every embedded provenance envelope with the finalized one, so a
// descriptor built before the restore never reports an earlier window state.
// Responses nest descriptors in plain maps and in typed slices (such as
// []map[string]any), so slices and pointers are walked reflectively.
func restampCaptureProvenance(value any, view map[string]any, state string) {
	if value == nil {
		return
	}
	if typed, ok := value.(map[string]any); ok {
		if schema, _ := typed["artifact_schema"].(string); schema == artifact.ProvenanceSchema {
			typed["capture_consistency"] = view
			typed["consistency"] = state
		}
		for _, item := range typed {
			restampCaptureProvenance(item, view, state)
		}
		return
	}
	reflected := reflect.ValueOf(value)
	if !reflected.IsValid() {
		return
	}
	switch reflected.Kind() {
	case reflect.Slice, reflect.Array:
		for index := 0; index < reflected.Len(); index++ {
			restampCaptureProvenance(reflected.Index(index).Interface(), view, state)
		}
	case reflect.Pointer, reflect.Interface:
		if !reflected.IsNil() {
			restampCaptureProvenance(reflected.Elem().Interface(), view, state)
		}
	}
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
