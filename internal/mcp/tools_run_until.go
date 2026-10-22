package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/StealthC/exodus-mcp/internal/analysis"
)

const (
	// defaultRunUntilTimeoutMs is the default window for a run_until_* call
	// when the caller does not pass timeout_ms.
	defaultRunUntilTimeoutMs = 30000
	// maxRunUntilTimeoutMs caps the caller-requested window.
	maxRunUntilTimeoutMs = 120000
	// minRunUntilTimeoutMs prevents accidental near-zero polling windows.
	minRunUntilTimeoutMs = 100
	// runUntilPollInterval is the pause between emulator_status probes.
	runUntilPollInterval = 100 * time.Millisecond
	// runUntilInternalLockTTL bounds the internal exclusive control lock a
	// run_until window acquires when the caller did not bring its own.
	runUntilInternalLockTTL = 120 * time.Second
)

// runUntilToolSpecs implements the roadmap Phase 9 run-until primitives:
// one-shot run-to-breakpoint / run-to-watchpoint wrappers that set the
// instrument with one_shot semantics, run the system until it fires, pause on
// completion, and report the stop evidence. The instrument is removed on
// every exit path, so no armed instrumentation or polling is left behind.
func runUntilToolSpecs() []toolSpec {
	return []toolSpec{
		{
			name:        "run_until_breakpoint",
			description: "Set a one-shot execution breakpoint, run the system until it fires, and pause with the stop evidence: the stop reason, triggering PC, hit count, and registers. Stop provenance is split: `stop_source` says why execution stopped (`instrument` when this call's breakpoint fired, `external` for a foreign pause, `mcp` for an MCP pause, `none` when the window ended without a stop), while `triggering_pc_source` says where the PC came from (`register_read`; the PC is null when no read proved it) and never carries the stop reason (`pc_source` is a deprecated alias with the same value). `debug_event_id` names the structured debug event recorded for the stop (`debug_event_ids` lists every event when the stop produced more than one), so the response joins directly to cpu_debug_events_list. The instrument is removed automatically (and audited), so no armed instrumentation is left behind; the call ends paused at the stop. A foreign pause preempts the call with the instrument removed, and a timeout removes it too. Optional `condition`, `break_on_counter`, and `break_counter` match cpu_breakpoint_set; `timeout_ms` bounds the window (default 30000, cap 120000). Runs under exclusive control for the whole window (caller control_id reused, otherwise an internal lock is acquired and released). Accepts optional expected_target_generation and control_id.",
			schema: objectSchema(map[string]any{
				"cpu":                        enumProperty("Processor to break.", []string{"m68k", "z80"}),
				"address":                    addressProperty(),
				"condition":                  enumProperty("Location condition. equal breaks at exactly `address`; greater/less break above/below it; range breaks inside `address` (exclusive lower bound) and `range_end` (exclusive upper bound).", []string{"equal", "greater", "less", "range"}),
				"range_end":                  addressProperty(),
				"break_on_counter":           booleanProperty("Only fire on every Nth hit instead of every hit; N comes from break_counter."),
				"break_counter":              integerProperty("Fire every Nth hit when break_on_counter is true (default 1).", 1),
				"timeout_ms":                 integerProperty(fmt.Sprintf("Run window before the call gives up (default %d, min %d, cap %d).", defaultRunUntilTimeoutMs, minRunUntilTimeoutMs, maxRunUntilTimeoutMs), 1),
				"context":                    contextProperty(),
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
				"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
			}, []string{"cpu", "address"}),
			run: runRunUntilBreakpoint,
		},
		{
			name:        "run_until_watchpoint",
			description: "Set a one-shot read and/or write watchpoint, run the system until it fires, and pause with the stop evidence: the stop reason, triggering PC, watched address, access direction, hit count, and registers. Stop provenance is split: `stop_source` says why execution stopped (`instrument` when this call's watchpoint fired, `external` for a foreign pause, `mcp` for an MCP pause, `none` when the window ended without a stop), while `triggering_pc_source` says where the PC came from (`register_read`; the PC is null when no read proved it) and never carries the stop reason (`pc_source` is a deprecated alias with the same value). `debug_event_id` names the structured debug event recorded for the stop (`debug_event_ids` lists every event when the stop produced more than one), so the response joins directly to cpu_debug_events_list. The watched range matches access start addresses exactly like cpu_watchpoint_set. The instrument is removed automatically (and audited), so no armed instrumentation is left behind; the call ends paused at the stop. A foreign pause preempts the call with the instrument removed, and a timeout removes it too. `access` matches cpu_watchpoint_set (default any); `timeout_ms` bounds the window (default 30000, cap 120000). Runs under exclusive control for the whole window (caller control_id reused, otherwise an internal lock is acquired and released). Accepts optional expected_target_generation and control_id.",
			schema: objectSchema(map[string]any{
				"cpu":                        enumProperty("Processor to watch.", []string{"m68k", "z80"}),
				"address":                    addressProperty(),
				"length":                     integerProperty("Watched range length in bytes (default 1).", 1),
				"access":                     enumProperty("Access types that trigger the watchpoint (default any).", []string{"read", "write", "any"}),
				"timeout_ms":                 integerProperty(fmt.Sprintf("Run window before the call gives up (default %d, min %d, cap %d).", defaultRunUntilTimeoutMs, minRunUntilTimeoutMs, maxRunUntilTimeoutMs), 1),
				"context":                    contextProperty(),
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
				"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
			}, []string{"cpu", "address"}),
			run: runRunUntilWatchpoint,
		},
	}
}

type runUntilBreakpointArgs struct {
	CPU            string  `json:"cpu"`
	Address        any     `json:"address"`
	AddressSpace   string  `json:"address_space"`
	Condition      string  `json:"condition"`
	RangeEnd       any     `json:"range_end"`
	BreakOnCounter bool    `json:"break_on_counter"`
	BreakCounter   *uint64 `json:"break_counter"`
	TimeoutMs      *uint64 `json:"timeout_ms"`
	Context        string  `json:"context"`
	guardArgs
}

type runUntilWatchpointArgs struct {
	CPU          string  `json:"cpu"`
	Address      any     `json:"address"`
	AddressSpace string  `json:"address_space"`
	Length       *uint64 `json:"length"`
	Access       string  `json:"access"`
	TimeoutMs    *uint64 `json:"timeout_ms"`
	Context      string  `json:"context"`
	guardArgs
}

func runRunUntilBreakpoint(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[runUntilBreakpointArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.CPU != "m68k" && parsed.CPU != "z80" {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "cpu must be m68k or z80"}, tc.modern)
	}
	address, failure := resolveAddress(parsed.Address, addressSpaceFromArgs(args), parsed.CPU+"-bus")
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	condition := parsed.Condition
	switch condition {
	case "", "equal", "greater", "less", "range":
	default:
		return failureResult(&toolFailure{Code: "invalid_params", Message: "condition must be equal, greater, less, or range"}, tc.modern)
	}
	var rangeEnd uint64
	if parsed.RangeEnd != nil {
		if condition != "range" {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "range_end applies only to condition=range"}, tc.modern)
		}
		if rangeEnd, failure = resolveAddress(parsed.RangeEnd, addressSpaceFromArgs(args), parsed.CPU+"-bus"); failure != nil {
			return failureResult(failure, tc.modern)
		}
		if rangeEnd <= address {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "range_end must be above address (range bounds are exclusive)"}, tc.modern)
		}
	} else if condition == "range" {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "condition=range requires range_end"}, tc.modern)
	}
	breakCounter := uint64(1)
	if parsed.BreakCounter != nil {
		if !parsed.BreakOnCounter {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "break_counter applies only when break_on_counter is true"}, tc.modern)
		}
		if *parsed.BreakCounter == 0 {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "break_counter must be at least 1"}, tc.modern)
		}
		breakCounter = *parsed.BreakCounter
	}
	timeout, failure := resolveRunUntilTimeout(parsed.TimeoutMs)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	params := map[string]string{
		"cpu":     parsed.CPU,
		"address": strconv.FormatUint(address, 10),
	}
	if condition != "" {
		params["condition"] = condition
	}
	if condition == "range" {
		params["range_end"] = strconv.FormatUint(rangeEnd, 10)
	}
	if parsed.BreakOnCounter {
		params["break_on_counter"] = "true"
		params["break_counter"] = strconv.FormatUint(breakCounter, 10)
	}
	return runUntil(tc, context, runUntilPlan{
		tool:            "run_until_breakpoint",
		kind:            "breakpoint",
		cpu:             parsed.CPU,
		setOperation:    "breakpoint_set",
		removeOperation: "breakpoint_remove",
		idKey:           "breakpoint_id",
		params:          params,
		breakCounter:    breakCounter,
		timeout:         timeout,
		guard:           parsed.guard(),
		setDetail:       map[string]any{"cpu": parsed.CPU, "address": address, "condition": condition},
	})
}

func runRunUntilWatchpoint(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[runUntilWatchpointArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.CPU != "m68k" && parsed.CPU != "z80" {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "cpu must be m68k or z80"}, tc.modern)
	}
	address, failure := resolveAddress(parsed.Address, addressSpaceFromArgs(args), parsed.CPU+"-bus")
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	switch parsed.Access {
	case "", "read", "write", "any":
	default:
		return failureResult(&toolFailure{Code: "invalid_params", Message: "access must be read, write, or any"}, tc.modern)
	}
	if parsed.Length != nil && *parsed.Length == 0 {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "length must be at least 1"}, tc.modern)
	}
	timeout, failure := resolveRunUntilTimeout(parsed.TimeoutMs)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	access := parsed.Access
	if access == "" {
		access = "any"
	}
	params := map[string]string{
		"cpu":     parsed.CPU,
		"address": strconv.FormatUint(address, 10),
		"access":  access,
	}
	if parsed.Length != nil {
		params["length"] = strconv.FormatUint(*parsed.Length, 10)
	}
	length := uint64(1)
	if parsed.Length != nil {
		length = *parsed.Length
	}
	return runUntil(tc, context, runUntilPlan{
		tool:            "run_until_watchpoint",
		kind:            "watchpoint",
		cpu:             parsed.CPU,
		setOperation:    "watchpoint_set",
		removeOperation: "watchpoint_remove",
		idKey:           "watchpoint_id",
		params:          params,
		breakCounter:    1,
		timeout:         timeout,
		guard:           parsed.guard(),
		setDetail:       map[string]any{"cpu": parsed.CPU, "address": address, "access": access, "length": length},
	})
}

func resolveRunUntilTimeout(timeoutMs *uint64) (time.Duration, *toolFailure) {
	value := uint64(defaultRunUntilTimeoutMs)
	if timeoutMs != nil {
		value = *timeoutMs
	}
	if value < minRunUntilTimeoutMs || value > maxRunUntilTimeoutMs {
		return 0, &toolFailure{Code: "invalid_params", Message: fmt.Sprintf("timeout_ms must be between %d and %d", minRunUntilTimeoutMs, maxRunUntilTimeoutMs)}
	}
	return time.Duration(value) * time.Millisecond, nil
}

// runUntilPlan describes one run-until operation: the instrument to arm and
// the window to run toward it.
type runUntilPlan struct {
	tool             string // audit tool name for every step
	kind             string // "breakpoint" | "watchpoint"
	cpu              string
	setOperation     string
	removeOperation  string
	idKey            string
	params           map[string]string
	breakCounter     uint64
	timeout          time.Duration
	guard            mutationGuard
	setDetail        map[string]any
	generationBefore uint64
	// eventCursor is the highest debug-event id when the window opened; the
	// stop's events are the ones recorded after it.
	eventCursor uint64
}

// runUntil is the shared run-until choreography: arm a one-shot instrument,
// run the system toward it, poll until it proves fired, and report the stop
// evidence with the instrument removed. Every exit path removes the
// instrument, so no armed instrumentation or polling is left behind.
func runUntil(tc toolContext, ac *analysis.Context, plan runUntilPlan) map[string]any {
	server := tc.server

	// Generation precondition before any lock is taken.
	if plan.guard.HasExpectedGeneration {
		if failure := targetGenerationPrecondition(server, plan.guard.ExpectedGeneration); failure != nil {
			return failureResult(failure, tc.modern)
		}
	}

	// Exclusive control for the full window: reuse an active caller lock or
	// acquire an internal one released at the end (composite pattern shared
	// with input_sequence and deterministic_replay).
	controlID := plan.guard.ControlID
	if controlID == "" {
		lock, err := server.controls.Acquire(plan.tool, ac.ID, runUntilInternalLockTTL, server.target.Generation())
		if err != nil {
			var held *analysis.ControlHeldError
			if errors.As(err, &held) {
				return failureResult(controlHeldFailure(held.Lock, server.target.Generation()), tc.modern)
			}
			return failureResult(&toolFailure{Code: "invalid_params", Message: err.Error()}, tc.modern)
		}
		controlID = lock.ID
		defer func() {
			_ = server.controls.Release(controlID, plan.tool+"_completed")
		}()
	} else if !server.controls.Valid(controlID) {
		return failureResult(&toolFailure{
			Code:    "target_control_held",
			Message: "the provided control_id does not own the active target control lock; acquire one with target_control_acquire or omit control_id to let the server manage the lock",
		}, tc.modern)
	}
	windowGuard := mutationGuard{ControlID: controlID}
	plan.generationBefore = server.target.Generation()
	// Events recorded after this boundary belong to this window; the tool
	// reports their ids so a caller can join the response to the event rows.
	plan.eventCursor = server.lastDebugEventID()

	// 1. Arm the instrument with one-shot semantics.
	setPayload, _, _, failure := server.executeMutation(tc.ctx, mutationCall{
		tool:      plan.tool,
		operation: plan.setOperation,
		params:    plan.params,
		guard:     windowGuard,
		contextID: ac.ID,
		detail:    mergeDetail(plan.setDetail, map[string]any{"step": "set", "one_shot": true}),
	})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	idValue, ok := setPayload[plan.idKey].(float64)
	if !ok || uint64(idValue) == 0 {
		return failureResult(&toolFailure{Code: "bridge_error", Message: "instrument set succeeded without a resource id"}, tc.modern)
	}
	id := uint64(idValue)
	// The window owns the removal: the paused-state sweep must only attribute
	// the stop and record the event while this call is still running, so the
	// tool can remove the instrument itself and report the verified outcome.
	server.trackDebugResource(plan.kind, id, debugResourceMeta{
		ContextID:        ac.ID,
		ControlID:        controlID,
		TargetGeneration: server.target.Generation(),
		CreatedAt:        time.Now().UTC(),
		ROMPath:          server.currentROMPath(),
		OneShot:          true,
		DeferRemoval:     true,
		BreakCounter:     plan.breakCounter,
	})

	// removeInstrument cleans the armed instrument through the audited
	// mutation path and reports what the native side proved. When the caller's
	// request context is already cancelled (run_until_cancelled), the cleanup
	// runs on a short detached window so the residue is still removed.
	removeInstrument := func() instrumentRemoval {
		removeCtx, cancel := tc.ctx, func() {}
		if err := tc.ctx.Err(); err != nil {
			removeCtx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		}
		defer cancel()
		_, _, _, failure := server.executeMutation(removeCtx, mutationCall{
			tool:      plan.tool,
			operation: plan.removeOperation,
			params:    map[string]string{plan.idKey: strconv.FormatUint(id, 10)},
			guard:     windowGuard,
			contextID: ac.ID,
			detail: map[string]any{
				"step": "cleanup", "resource_id": id, "reason": "run_until_cleanup",
			},
			commit:    func() { server.forgetDebugResource(plan.kind, id) },
			resources: func() []string { return []string{strconv.FormatUint(id, 10)} },
		})
		removal := instrumentRemoval{Result: instrumentRemovalFailed, Failure: failure}
		switch {
		case failure == nil:
			removal.Removed, removal.Result = true, instrumentRemovalRemoved
		case failure.Code == plan.kind+"_not_found":
			// The native side no longer owns the resource (for example a ROM
			// reload purged managed instruments), so nothing is armed.
			removal.Removed, removal.Result = true, instrumentRemovalAlreadyAbsent
			server.forgetDebugResource(plan.kind, id)
		default:
			// Keep the sweep as a retry path instead of leaving the instrument
			// armed with no owner.
			server.setDebugResourceDeferRemoval(plan.kind, id, false)
		}
		return removal
	}

	// 2. Run the system toward the instrument.
	runPayload, _, _, failure := server.executeMutation(tc.ctx, mutationCall{
		tool:      plan.tool,
		operation: "cpu_control",
		params:    map[string]string{"cpu": plan.cpu, "action": "run"},
		guard:     windowGuard,
		contextID: ac.ID,
		detail:    mergeDetail(plan.setDetail, map[string]any{"step": "run"}),
	})
	if failure != nil {
		removal := removeInstrument()
		if !removal.Removed {
			return failureResult(&toolFailure{
				Code:    failure.Code,
				Message: failure.Message + "; additionally, removing the instrument also failed (" + removal.Failure.Message + "), so it is still armed",
			}, tc.modern)
		}
		return failureResult(failure, tc.modern)
	}
	recordStateFromPayload(server, runPayload, true)

	// 3. Poll until the instrument proves fired, a foreign pause preempts,
	// the caller disconnects, or the window elapses.
	deadline := time.Now().Add(plan.timeout)
	started := time.Now()
	polls := 0
	for {
		if err := tc.ctx.Err(); err != nil {
			removal := removeInstrument()
			data := map[string]any{
				"stop_source": stopSourceNone,
				"elapsed_ms":  time.Since(started).Milliseconds(),
				"poll_count":  polls,
			}
			applyInstrumentRemoval(data, removal)
			return failureResult(&toolFailure{
				Code:    "run_until_cancelled",
				Message: "the run_until call was cancelled before the instrument fired; " + removalSentence(removal),
				Data:    data,
			}, tc.modern)
		}
		// Force a fresh emulator_status probe: the 5 s status cache would
		// otherwise hide the stop from the poll.
		server.invalidateStatusCache()
		status, failure := fetchEmulatorStatus(tc)
		polls++
		if failure != nil {
			removal := removeInstrument()
			data := map[string]any{"stop_source": stopSourceUnknown}
			applyInstrumentRemoval(data, removal)
			if failure.Data == nil {
				failure.Data = map[string]any{}
			}
			for key, value := range data {
				failure.Data[key] = value
			}
			return failureResult(failure, tc.modern)
		}
		if !status.SystemRunning {
			stop := server.runState.lastBreakpointStop()
			if stop != nil && stop.Kind == plan.kind && stop.ResourceID == id {
				removal := removeInstrument()
				return runUntilSuccess(tc, plan, status, id, stop, removal, polls, started)
			}
			// A foreign pause preempted the run: leave no residue behind.
			pauseSource, pauseNote, _, _ := runStateView(server, status)
			removal := removeInstrument()
			data := map[string]any{
				"stop_source":           stopSourceForPause(pauseSource, stop),
				"observed_pause_source": pauseSource,
				"poll_count":            polls,
				"elapsed_ms":            time.Since(started).Milliseconds(),
			}
			if stop != nil {
				data["other_stop_resource_kind"] = stop.Kind
				data["other_stop_resource_id"] = stop.ResourceID
				data["other_stop_hit_count"] = stop.HitCount
			}
			if pauseNote != "" {
				data["observed_pause_note"] = pauseNote
			}
			applyInstrumentRemoval(data, removal)
			return failureResult(&toolFailure{
				Code:    "run_until_preempted",
				Message: "the system paused before the requested instrument fired; " + removalSentence(removal),
				Data:    data,
			}, tc.modern)
		}
		if time.Now().After(deadline) {
			removal := removeInstrument()
			data := map[string]any{
				"stop_source":         stopSourceNone,
				"last_system_running": status.SystemRunning,
				"poll_count":          polls,
				"elapsed_ms":          time.Since(started).Milliseconds(),
				"retry_hint":          "Raise timeout_ms, or verify the instrument's address/condition actually executes.",
			}
			applyInstrumentRemoval(data, removal)
			return failureResult(&toolFailure{
				Code:    "run_until_timeout",
				Message: fmt.Sprintf("the instrument did not fire within %d ms; %s", plan.timeout.Milliseconds(), removalSentence(removal)),
				Data:    data,
			}, tc.modern)
		}
		time.Sleep(runUntilPollInterval)
	}
}

// run_until stop_reason labels: which instrument ended the window. This is not
// stop_source (why execution stopped) and not triggering_pc_source (where the
// PC came from).
const (
	stopReasonBreakpointHit = "breakpoint_hit"
	stopReasonWatchpointHit = "watchpoint_hit"
)

// stopReasonForKind renders the stop_reason of one run_until window from its
// instrument kind, in the declared vocabulary.
func stopReasonForKind(kind string) string {
	switch kind {
	case "breakpoint":
		return stopReasonBreakpointHit
	case "watchpoint":
		return stopReasonWatchpointHit
	default:
		return consistencyUnknown
	}
}

// instrumentRemoval is the verified outcome of one native removal call.
// Removed is true only when the native side proved no instrument is armed:
// either it deleted the resource (removed) or it no longer owned it
// (already_absent).
type instrumentRemoval struct {
	Removed bool
	Result  string // removed | already_absent | failed
	Failure *toolFailure
}

const (
	instrumentRemovalRemoved       = "removed"
	instrumentRemovalAlreadyAbsent = "already_absent"
	instrumentRemovalFailed        = "failed"
)

// applyInstrumentRemoval stamps the verified removal outcome into a response.
// A failure is always named, so a caller never infers cleanup from a field
// that was merely optimistically set.
func applyInstrumentRemoval(data map[string]any, removal instrumentRemoval) {
	data["instrument_removed"] = removal.Removed
	data["instrument_removal"] = removal.Result
	if removal.Failure != nil {
		data["instrument_removal_detail"] = removal.Failure.Message
	}
	if !removal.Removed && removal.Failure != nil {
		data["instrument_removal_failure"] = removal.Failure.Message
	}
}

// removalSentence renders the cleanup outcome for a failure message.
func removalSentence(removal instrumentRemoval) string {
	if removal.Removed {
		if removal.Result == instrumentRemovalAlreadyAbsent {
			return "the instrument was already absent (nothing is armed)"
		}
		return "the instrument was removed"
	}
	message := "the instrument could NOT be removed and is still armed"
	if removal.Failure != nil {
		message += " (" + removal.Failure.Message + ")"
	}
	return message + "; the paused-state sweep will retry"
}

// stopSourceForPause classifies why the system is paused: a managed
// instrument fired, an MCP run-state action explains it, or an external actor
// paused the machine. It answers "why did execution stop" only; where the PC
// came from is reported separately as triggering_pc_source.
func stopSourceForPause(pauseSource string, stop *stopAttributionInfo) string {
	switch {
	case pauseSource == stopSourceMCP:
		return stopSourceMCP
	case stop != nil:
		return stopSourceInstrument
	default:
		return stopSourceExternal
	}
}

// runUntilSuccess renders the stop evidence after the instrument proved fired
// and its removal was attempted.
func runUntilSuccess(tc toolContext, plan runUntilPlan, status *emulatorStatusData, id uint64, stop *stopAttributionInfo, removal instrumentRemoval, polls int, started time.Time) map[string]any {
	server := tc.server
	elapsed := time.Since(started).Milliseconds()
	pauseSource, pauseNote, _, _ := runStateView(server, status)
	// The stop's events are the ones this window recorded; the newest one is
	// the stop that ended it.
	windowEvents := server.debugEventsForResourceSince(plan.kind, id, plan.eventCursor)
	var event *debugEvent
	if len(windowEvents) > 0 {
		last := windowEvents[len(windowEvents)-1]
		event = &last
	} else if fallback := server.debugEventForResource(plan.kind, id); fallback != nil {
		event = fallback
		windowEvents = []debugEvent{*fallback}
	}
	stopSource := stopSourceForPause(pauseSource, stop)
	registers := fetchCPURegisters(tc, plan.cpu)
	pc, pcSource := stopTriggeringPC(event, registers)
	result := map[string]any{
		"stop_reason":   stopReasonForKind(plan.kind),
		"stop_source":   stopSource,
		"resource_kind": plan.kind,
		"resource_id":   id,
		"hit_count":     stop.HitCount,
		"one_shot":      true,
		// triggering_pc_source answers "where did the PC come from" on every
		// surface; pc_source is its deprecated alias and carries the same
		// value.
		"triggering_pc_source": pcSource,
		"pc_source":            pcSource,
		"address_space":        plan.cpu + "-bus",
		"pause_source":         pauseSource,
		"pause_source_note":    pauseNote,
		"system_running":       false,
		"poll_count":           polls,
		"elapsed_ms":           elapsed,
		"note":                 "The system is paused at the instrument's stop; call cpu_run to resume.",
	}
	if pcSource == pcSourceUnknown {
		// 0x000000 is a plausible vector address; an unreadable PC is reported
		// as null with its source instead of a fabricated zero.
		result["triggering_pc"] = nil
		result["triggering_pc_hex"] = nil
		result["triggering_pc_note"] = "The triggering PC could not be proven for this stop; the value is null, not zero."
	} else {
		result["triggering_pc"] = pc
		result["triggering_pc_hex"] = canonicalHex(pc)
		annotateAddressRangePair(result, "triggering_pc", plan.cpu+"-bus", pc)
	}
	applyInstrumentRemoval(result, removal)
	if registers != nil {
		result["registers"] = registers
	}
	if len(windowEvents) > 0 {
		ids := make([]uint64, 0, len(windowEvents))
		for _, recorded := range windowEvents {
			ids = append(ids, recorded.ID)
		}
		// debug_event_id is the join key back to cpu_debug_events_list; the
		// array carries every event the stop produced.
		result["debug_event_id"] = ids[len(ids)-1]
		if len(ids) > 1 {
			result["debug_event_ids"] = ids
		}
		// event_id predates the debug_event_id name and keeps its value.
		result["event_id"] = ids[len(ids)-1]
	}
	if event != nil {
		result["configured_access"] = event.AccessDirection
		// access_direction is the historical name of configured_access and keeps
		// its old value for compatibility.
		result["access_direction"] = event.AccessDirection
		result["observed_direction"] = event.ObservedDirection
		if plan.kind == "watchpoint" {
			result["watched_address"] = event.WatchedAddress
			result["watched_address_hex"] = canonicalHex(event.WatchedAddress)
			result["requested_length"] = event.RequestedLength
			result["range_semantics"] = watchpointRangeSemantics(event.RequestedLength)
			annotateAddressRangePair(result, "watched", event.AddressSpace, event.WatchedAddress)
		}
	}
	stamped := stampGenerations(result, plan.generationBefore, server.target.Generation())
	if !removal.Removed {
		evidence := make(map[string]any, len(stamped)+1)
		for key, value := range stamped {
			evidence[key] = value
		}
		return failureResult(&toolFailure{
			Code:    "run_until_cleanup_failed",
			Message: "the instrument fired and the stop evidence is complete, but removing the armed instrument failed; it is still armed and the paused-state sweep will retry",
			Data:    evidence,
		}, tc.modern)
	}
	return okResult(stamped, tc.modern)
}

// fetchCPURegisters reads every register of one processor, or nil when the
// read failed. The payload itself is returned when the plugin answers without
// a nested registers object.
func fetchCPURegisters(tc toolContext, cpu string) map[string]any {
	payload, failure := tc.server.executeCommand(tc.ctx, "regs_get", map[string]string{"cpu": cpu})
	if failure != nil {
		return nil
	}
	if registers, ok := payload["registers"].(map[string]any); ok {
		return registers
	}
	return payload
}

// registerPC extracts the program counter from a register view.
func registerPC(registers map[string]any) (uint64, bool) {
	if registers == nil {
		return 0, false
	}
	for _, key := range []string{"pc", "PC"} {
		if value, ok := numberAsUint64(registers[key]); ok {
			return value, true
		}
	}
	return 0, false
}

// fetchCPUCurrentPCSourced reads a program counter and reports whether the
// read proved a value; a failed read is unknown, never zero.
func fetchCPUCurrentPCSourced(tc toolContext, cpu string) (uint64, string) {
	if value, ok := registerPC(fetchCPURegisters(tc, cpu)); ok {
		return value, pcSourceRegisterRead
	}
	return 0, pcSourceUnknown
}

// stopTriggeringPC returns the PC proven for one managed stop and where that
// value came from. The value the stop event recorded while the CPU was paused
// at the instrument wins (the PC cannot have moved since) and is still a
// register read; otherwise the registers read in the tool path are used. The
// second return value is the PC source, never the stop reason.
func stopTriggeringPC(event *debugEvent, registers map[string]any) (uint64, string) {
	if event != nil && event.TriggeringPCSource == pcSourceRegisterRead {
		return event.TriggeringPC, pcSourceRegisterRead
	}
	if value, ok := registerPC(registers); ok {
		return value, pcSourceRegisterRead
	}
	return 0, pcSourceUnknown
}

// ----------------------------------------------------------------------------------------------------------------------
// One-shot housekeeping sweep
// ----------------------------------------------------------------------------------------------------------------------

// instrumentFiredProof reports whether a native hit counter proves the break
// fired. The core increments the counter on every passing location hit and
// breaks exactly when the counter is a positive multiple of the break counter
// N (1 when the instrument always breaks), so a positive multiple is proof.
func instrumentFiredProof(hitCount, breakCounter uint64) bool {
	if breakCounter == 0 {
		breakCounter = 1
	}
	return hitCount >= 1 && hitCount%breakCounter == 0
}

// sweepDebugInstruments is the server-side housekeeping pass. It runs
// whenever the emulator is observed paused (from fetchEmulatorStatus) and:
//   - drops provenance for managed instruments the plugin no longer lists
//     (a ROM reload purges them natively);
//   - attributes every managed instrument whose hit counter proves a break
//     fired to the run-state tracker, so emulator_status reports
//     pause_source breakpoint_or_watchpoint;
//   - records one structured debug event for every proven stop, one-shot or
//     steady, so a plain cpu_run hit is queryable exactly like a one-shot hit;
//   - removes fired one-shot instruments through the audited mutation path
//     (unless a run_until window owns that removal).
//
// The pass is best-effort and never fails the caller; a failed removal is
// audited by the mutation path and retried on the next sweep.
func (server *Server) sweepDebugInstruments(tc toolContext) []map[string]any {
	removals := server.sweepDebugKind(tc, "breakpoint", "breakpoint_list", "breakpoints", "breakpoint_id")
	removals = append(removals, server.sweepDebugKind(tc, "watchpoint", "watchpoint_list", "watchpoints", "watchpoint_id")...)
	return removals
}

func (server *Server) sweepDebugKind(tc toolContext, kind, listOp, listKey, idKey string) []map[string]any {
	payload, failure := server.executeCommand(tc.ctx, listOp, nil)
	if failure != nil {
		return nil
	}
	entries, _ := payload[listKey].([]any)

	// Index the native instruments by id with their hit counters.
	native := make(map[uint64]map[string]any, len(entries))
	for _, raw := range entries {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		id, ok := entry[idKey].(float64)
		if !ok {
			continue
		}
		native[uint64(id)] = entry
	}

	metas := server.debugResourceMetas(kind)
	if len(metas) == 0 {
		return nil
	}
	ids := make([]uint64, 0, len(metas))
	for id := range metas {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	var removals []map[string]any
	for _, id := range ids {
		meta := metas[id]
		entry, present := native[id]
		if !present {
			// The plugin no longer owns the resource (ROM reload purge);
			// drop the stale provenance without a mutation.
			server.forgetDebugResource(kind, id)
			continue
		}
		breakCounter := meta.BreakCounter
		if breakCounter == 0 {
			breakCounter = 1
		}
		hitCount := hitCountFromEntry(entry)
		if !instrumentFiredProof(hitCount, breakCounter) {
			continue
		}
		// Every proven managed stop is attributed and recorded, one-shot or
		// not, so a plain breakpoint/watchpoint hit is as queryable as a
		// one-shot stop; folding keeps a repeated paused observation from
		// creating duplicates.
		server.runState.setBreakpointStop(kind, id, hitCount)
		eventID := server.pushSweepDebugEvent(tc, kind, id, entry, meta, server.target.Generation())
		if !meta.OneShot {
			continue
		}
		if meta.DeferRemoval {
			// A run_until window owns this removal: it removes the instrument
			// synchronously and reports the verified outcome. The tool clears
			// the flag when its own removal fails, so the sweep retries.
			continue
		}
		_, _, _, failure := server.executeMutation(tc.ctx, mutationCall{
			tool:      "one_shot_sweep",
			operation: kind + "_remove",
			params:    map[string]string{idKey: strconv.FormatUint(id, 10)},
			guard:     mutationGuard{ControlID: meta.ControlID},
			contextID: meta.ContextID,
			detail: map[string]any{
				"event":         "one_shot_hit",
				"resource_kind": kind,
				"resource_id":   id,
				"hit_count":     hitCount,
				"break_counter": breakCounter,
			},
			commit:    func() { server.forgetDebugResource(kind, id) },
			resources: func() []string { return []string{strconv.FormatUint(id, 10)} },
		})
		if failure != nil {
			// The failure is already audited; the next sweep retries.
			continue
		}
		removals = append(removals, map[string]any{
			"resource_kind": kind,
			"resource_id":   id,
			"hit_count":     hitCount,
			"event_id":      eventID,
		})
	}
	return removals
}

// debugResourceMetas snapshots the provenance of every managed instrument of
// one kind.
func (server *Server) debugResourceMetas(kind string) map[uint64]debugResourceMeta {
	server.debugMu.Lock()
	defer server.debugMu.Unlock()
	src := server.breakpoints
	if kind == "watchpoint" {
		src = server.watchpoints
	}
	out := make(map[uint64]debugResourceMeta, len(src))
	for id, meta := range src {
		out[id] = meta
	}
	return out
}

func hitCountFromEntry(entry map[string]any) uint64 {
	if count, ok := entry["hit_count"].(float64); ok {
		return uint64(count)
	}
	if count, ok := entry["hit_counter"].(float64); ok {
		return uint64(count)
	}
	return 0
}

// pushSweepDebugEvent records the structured stop evidence for a managed
// instrument the paused-state sweep proved fired, one-shot or not.
func (server *Server) pushSweepDebugEvent(tc toolContext, kind string, id uint64, entry map[string]any, meta debugResourceMeta, generation uint64) uint64 {
	cpu, _ := entry["cpu"].(string)
	if cpu == "" {
		return 0
	}
	pc, pcSource := fetchCPUCurrentPCSourced(tc, cpu)
	event := debugEvent{
		ResourceKind:       kind,
		ResourceID:         id,
		ContextID:          meta.ContextID,
		CPU:                cpu,
		TriggeringPC:       pc,
		TriggeringPCSource: pcSource,
		AddressSpace:       cpu + "-bus",
		AccessDirection:    "execute",
		RequestedLength:    1,
		HitCount:           hitCountFromEntry(entry),
		TargetGeneration:   generation,
		FrameToken:         currentFrameToken(tc),
		// The sweep only runs on a paused observation, so the state is known
		// here even though the tracker's own observation lands after it.
		RunState: "paused",
	}
	if address, ok := entry["address"].(float64); ok {
		event.WatchedAddress = uint64(address)
	}
	if kind == "watchpoint" {
		if length, ok := entry["length"].(float64); ok {
			event.RequestedLength = uint64(length)
		}
		// The configured access is what the watchpoint was set with; the
		// observed direction is derived in pushDebugEvent and stays unknown
		// for an "any" watchpoint because the core reports no transfer
		// direction.
		if access, ok := entry["access"].(string); ok {
			event.AccessDirection = access
		} else {
			event.AccessDirection = "any"
		}
	}
	return server.pushDebugEvent(event)
}

// debugEventForResource returns the most recent debug event for one managed
// instrument, or nil.
func (server *Server) debugEventForResource(kind string, id uint64) *debugEvent {
	server.debugEventsMu.Lock()
	defer server.debugEventsMu.Unlock()
	for i := len(server.debugEvents) - 1; i >= 0; i-- {
		event := server.debugEvents[i]
		if event.ResourceKind == kind && event.ResourceID == id {
			copy := event
			return &copy
		}
	}
	return nil
}

// lastDebugEventID returns the highest event id handed out so far, or 0. A
// caller that looks at the events recorded after this boundary observes only
// the stops produced by its own window.
func (server *Server) lastDebugEventID() uint64 {
	server.debugEventsMu.Lock()
	defer server.debugEventsMu.Unlock()
	return server.nextEventID
}

// debugEventsForResourceSince returns the retained events of one managed
// resource recorded after a boundary id, oldest first. It is the join between a
// run_until_* window and the events its stop produced.
func (server *Server) debugEventsForResourceSince(kind string, id, since uint64) []debugEvent {
	server.debugEventsMu.Lock()
	defer server.debugEventsMu.Unlock()
	var out []debugEvent
	for _, event := range server.debugEvents {
		if event.ID > since && event.ResourceKind == kind && event.ResourceID == id {
			out = append(out, event)
		}
	}
	return out
}
