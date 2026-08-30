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
			description: "Set a one-shot execution breakpoint, run the system until it fires, and pause with the stop evidence: the stop reason, triggering PC, hit count, and registers. The instrument is removed automatically (and audited), so no armed instrumentation is left behind; the call ends paused at the stop. A foreign pause preempts the call with the instrument removed, and a timeout removes it too. Optional `condition`, `break_on_counter`, and `break_counter` match cpu_breakpoint_set; `timeout_ms` bounds the window (default 30000, cap 120000). Runs under exclusive control for the whole window (caller control_id reused, otherwise an internal lock is acquired and released). Accepts optional expected_target_generation and control_id.",
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
			description: "Set a one-shot read and/or write watchpoint, run the system until it fires, and pause with the stop evidence: the stop reason, triggering PC, watched address, access direction, hit count, and registers. The instrument is removed automatically (and audited), so no armed instrumentation is left behind; the call ends paused at the stop. A foreign pause preempts the call with the instrument removed, and a timeout removes it too. `access` matches cpu_watchpoint_set (default any); `timeout_ms` bounds the window (default 30000, cap 120000). Runs under exclusive control for the whole window (caller control_id reused, otherwise an internal lock is acquired and released). Accepts optional expected_target_generation and control_id.",
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
	server.trackDebugResource(plan.kind, id, debugResourceMeta{
		ContextID:        ac.ID,
		ControlID:        controlID,
		TargetGeneration: server.target.Generation(),
		CreatedAt:        time.Now().UTC(),
		ROMPath:          server.currentROMPath(),
		OneShot:          true,
		BreakCounter:     plan.breakCounter,
	})

	// removeInstrument cleans the armed instrument through the audited
	// mutation path; used on every non-success exit. When the caller's request
	// context is already cancelled (run_until_cancelled), the cleanup runs on
	// a short detached window so the residue is still removed.
	removeInstrument := func() *toolFailure {
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
		return failure
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
		if removeFailure := removeInstrument(); removeFailure != nil {
			return failureResult(&toolFailure{
				Code:    failure.Code,
				Message: failure.Message + "; additionally, removing the instrument also failed (" + removeFailure.Message + ")",
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
			_ = removeInstrument()
			return failureResult(&toolFailure{
				Code:    "run_until_cancelled",
				Message: "the run_until call was cancelled before the instrument fired; the instrument was removed",
				Data: map[string]any{
					"instrument_removed": true,
					"elapsed_ms":         time.Since(started).Milliseconds(),
					"poll_count":         polls,
				},
			}, tc.modern)
		}
		// Force a fresh emulator_status probe: the 5 s status cache would
		// otherwise hide the stop from the poll.
		server.invalidateStatusCache()
		status, failure := fetchEmulatorStatus(tc)
		polls++
		if failure != nil {
			_ = removeInstrument()
			return failureResult(failure, tc.modern)
		}
		if !status.SystemRunning {
			stop := server.runState.lastBreakpointStop()
			if stop != nil && stop.Kind == plan.kind && stop.ResourceID == id {
				return runUntilSuccess(tc, plan, id, stop, polls, started)
			}
			// A foreign pause preempted the run: leave no residue behind.
			pauseSource, pauseNote, _, _ := runStateView(server, status)
			data := map[string]any{
				"instrument_removed":    true,
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
			removeFailure := removeInstrument()
			if removeFailure != nil {
				data["instrument_removed"] = false
				data["instrument_removal_failure"] = removeFailure.Message
			}
			return failureResult(&toolFailure{
				Code:    "run_until_preempted",
				Message: "the system paused before the requested instrument fired; the instrument was removed",
				Data:    data,
			}, tc.modern)
		}
		if time.Now().After(deadline) {
			data := map[string]any{
				"instrument_removed":  true,
				"last_system_running": status.SystemRunning,
				"poll_count":          polls,
				"elapsed_ms":          time.Since(started).Milliseconds(),
				"retry_hint":          "Raise timeout_ms, or verify the instrument's address/condition actually executes.",
			}
			if removeFailure := removeInstrument(); removeFailure != nil {
				data["instrument_removed"] = false
				data["instrument_removal_failure"] = removeFailure.Message
			}
			return failureResult(&toolFailure{
				Code:    "run_until_timeout",
				Message: fmt.Sprintf("the instrument did not fire within %d ms; the instrument was removed", plan.timeout.Milliseconds()),
				Data:    data,
			}, tc.modern)
		}
		time.Sleep(runUntilPollInterval)
	}
}

// runUntilSuccess renders the stop evidence after the instrument proved fired.
func runUntilSuccess(tc toolContext, plan runUntilPlan, id uint64, stop *stopAttributionInfo, polls int, started time.Time) map[string]any {
	server := tc.server
	elapsed := time.Since(started).Milliseconds()
	pc := fetchCPUCurrentPC(tc, plan.cpu)
	result := map[string]any{
		"stop_reason":        plan.kind + "_hit",
		"resource_kind":      plan.kind,
		"resource_id":        id,
		"hit_count":          stop.HitCount,
		"triggering_pc":      pc,
		"triggering_pc_hex":  canonicalHex(pc),
		"address_space":      plan.cpu + "-bus",
		"pause_source":       "breakpoint_or_watchpoint",
		"system_running":     false,
		"instrument_removed": true,
		"poll_count":         polls,
		"elapsed_ms":         elapsed,
		"note":               "The system is paused at the instrument's stop; call cpu_run to resume.",
	}
	annotateAddressRangePair(result, "triggering_pc", plan.cpu+"-bus", pc)
	if payload, failure := server.executeCommand(tc.ctx, "regs_get", map[string]string{"cpu": plan.cpu}); failure == nil {
		if registers, ok := payload["registers"].(map[string]any); ok {
			result["registers"] = registers
		} else {
			result["registers"] = payload
		}
	}
	if event := server.debugEventForResource(plan.kind, id); event != nil {
		result["event_id"] = event.ID
		if plan.kind == "watchpoint" {
			result["watched_address"] = event.WatchedAddress
			result["watched_address_hex"] = canonicalHex(event.WatchedAddress)
			result["access_direction"] = event.AccessDirection
			result["requested_length"] = event.RequestedLength
			annotateAddressRangePair(result, "watched", event.AddressSpace, event.WatchedAddress)
		}
	}
	return okResult(stampGenerations(result, plan.generationBefore, server.target.Generation()), tc.modern)
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

// sweepDebugInstruments is the server-side one-shot housekeeping pass. It
// runs whenever the emulator is observed paused (from fetchEmulatorStatus)
// and:
//   - drops provenance for managed instruments the plugin no longer lists
//     (a ROM reload purges them natively);
//   - attributes every managed instrument whose hit counter proves a break
//     fired to the run-state tracker, so emulator_status reports
//     pause_source breakpoint_or_watchpoint;
//   - removes fired one-shot instruments through the audited mutation path
//     and records a structured debug event per removal.
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
		// Attribution for any proven stop; removal only for one-shot.
		server.runState.setBreakpointStop(kind, id, hitCount)
		if !meta.OneShot {
			continue
		}
		_, _, after, failure := server.executeMutation(tc.ctx, mutationCall{
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
		eventID := server.pushSweepDebugEvent(tc, kind, id, entry, meta, after)
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

// pushSweepDebugEvent records the structured stop evidence for a one-shot
// instrument the sweep removed.
func (server *Server) pushSweepDebugEvent(tc toolContext, kind string, id uint64, entry map[string]any, meta debugResourceMeta, generation uint64) uint64 {
	cpu, _ := entry["cpu"].(string)
	if cpu == "" {
		return 0
	}
	event := debugEvent{
		ResourceKind:     kind,
		ResourceID:       id,
		ContextID:        meta.ContextID,
		CPU:              cpu,
		TriggeringPC:     fetchCPUCurrentPC(tc, cpu),
		AddressSpace:     cpu + "-bus",
		AccessDirection:  "execute",
		RequestedLength:  1,
		HitCount:         hitCountFromEntry(entry),
		TargetGeneration: generation,
		FrameToken:       currentFrameToken(tc),
	}
	if address, ok := entry["address"].(float64); ok {
		event.WatchedAddress = uint64(address)
	}
	if kind == "watchpoint" {
		if length, ok := entry["length"].(float64); ok {
			event.RequestedLength = uint64(length)
		}
		if access, ok := entry["access"].(string); ok {
			event.AccessDirection = access
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
