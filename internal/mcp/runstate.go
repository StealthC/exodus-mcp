package mcp

import (
	"sync"
	"time"

	"github.com/StealthC/exodus-mcp/internal/analysis"
)

// runStateTracker records the emulator run state the server knows about and
// attributes changes to MCP actions or to external actors. The emulator UI,
// another bridge client, or a native breakpoint/watchpoint stop can flip
// system_running without any MCP mutation, and the target's audit stream used
// to be blind to those transitions.
//
// The tracker distinguishes:
//   - "mcp": the observed state matches the last run-state-affecting MCP
//     action (cpu_pause/cpu_run/cpu steps/frame_advance).
//   - "ui_or_external": the state differs from the last MCP action, or no MCP
//     action preceded the observation (emulator UI, another bridge client, or
//     a native debugger stop).
//   - "breakpoint_or_watchpoint": a native stop reason attributed the pause.
//     Reserved for when the plugin exposes one in emulator_status.
//   - "unknown": nothing has been observed or set yet.
//
// target_generation never advances for externally observed transitions: the
// contract is that the generation advances only for successful MCP mutations,
// so a UI-initiated pause is audited as a run_state_change event with the
// observed generation, never as a new revision.
type runStateTracker struct {
	mu sync.Mutex

	// observed is the last run state the server observed or set; nil while
	// the server has never seen the state.
	observed *bool
	// mcpSet is the last run state an MCP mutation explicitly requested; nil
	// when no such action has happened or an external transition followed it,
	// because a stale MCP expectation must not explain a later external state.
	mcpSet *bool
	// lastChange is when the run state last changed (MCP-caused or observed
	// externally); zero until the first known transition.
	lastChange time.Time
	// firstObserved is when the run state was first seen by this process.
	firstObserved time.Time
}

// setByMCP records a run state produced by a successful target-mutating MCP
// action (cpu_pause, cpu_run, CPU steps, frame_advance). A state difference
// here is the mutation's own effect and is already recorded by the mutation
// audit entry, so no separate run_state_change event is written.
func (tracker *runStateTracker) setByMCP(running bool) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	now := time.Now().UTC()
	if tracker.firstObserved.IsZero() {
		tracker.firstObserved = now
	}
	if tracker.observed != nil && *tracker.observed != running {
		// The state really changed; the mutation audit already records the
		// action, so only the transition clock moves here.
		tracker.lastChange = now
	}
	tracker.observed = &running
	tracker.mcpSet = &running
}

// observe records one passive observation of the run state. When the state
// differs from the last known state and no MCP action explains it, the
// transition is external and lands in the global audit stream as a
// run_state_change event carrying the observed target generation (never
// advancing it) and an optional frame token.
func (tracker *runStateTracker) observe(server *Server, running bool, frameToken *uint64) {
	tracker.mu.Lock()
	now := time.Now().UTC()
	first := tracker.firstObserved.IsZero()
	transition := tracker.observed != nil && *tracker.observed != running
	external := transition && (tracker.mcpSet == nil || *tracker.mcpSet != running)
	if first {
		tracker.firstObserved = now
	}
	if transition {
		tracker.lastChange = now
		// The MCP expectation no longer explains the current state; clear it
		// so a later observation cannot misattribute to MCP.
		if external {
			tracker.mcpSet = nil
		}
	}
	tracker.observed = &running
	tracker.mu.Unlock()

	if !external || server == nil {
		return
	}
	detail := map[string]any{
		"event":                      "run_state_change",
		"system_running":             running,
		"previous_system_running":    !running,
		"observed_target_generation": server.target.Generation(),
		"attribution":                "external (no MCP run-state action explains the transition)",
	}
	if frameToken != nil {
		detail["frame_token"] = *frameToken
	}
	server.recordAudit(analysis.AuditEntry{
		Tool:      "run_state_change",
		Outcome:   analysis.OutcomeObserved,
		Detail:    detail,
		ROMBefore: server.currentROMPath(),
	})
}

// view derives the pause attribution for a freshly observed run state.
// observed must be non-nil; the caller observes before asking.
func (tracker *runStateTracker) view(running bool) (source, note string) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if tracker.mcpSet != nil && *tracker.mcpSet == running {
		return "mcp", "The observed run state matches the last run-state-affecting MCP action; the change is attributed to MCP."
	}
	if tracker.observed != nil {
		return "ui_or_external", "No MCP run-state action explains the current state; it was changed by the emulator UI, another bridge client, or a native debugger stop (breakpoint_or_watchpoint is reported when the plugin exposes a stop reason)."
	}
	return "unknown", "No run state has been observed or set yet in this server process."
}

// lastKnownChange returns the last known run-state transition time and
// whether any transition has been observed or set.
func (tracker *runStateTracker) lastKnownChange() (time.Time, bool) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return tracker.lastChange, !tracker.lastChange.IsZero()
}

// firstObservedAt returns when the server first saw (or set) the run state;
// zero when nothing has been observed yet.
func (tracker *runStateTracker) firstObservedAt() time.Time {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return tracker.firstObserved
}
