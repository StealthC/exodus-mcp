package mcp

import (
	"encoding/json"
	"fmt"
	"sort"
)

// debug_instrument is the single debug-instrument tool (roadmap issue #17). It
// absorbs cpu_breakpoint_set/list/remove, cpu_watchpoint_set/list/remove,
// run_until_breakpoint and run_until_watchpoint: the concept is "manage one
// breakpoint or watchpoint", and the resource kind, the action, and whether the
// call runs the system toward the instrument are arguments.
//
// The merged tool is a dispatcher over the absorbed handlers, not a
// reimplementation: every action, default, guard, audit record, and response
// field is produced by the handler that owned it, so no behavior can drift. Only
// canonical-only arguments are consumed here, and an argument that does not
// apply to the selected action is rejected (never silently ignored, #9).

const (
	instrumentActionList   = "list"
	instrumentActionSet    = "set"
	instrumentActionRemove = "remove"
	instrumentActionUpdate = "update"

	instrumentKindBreakpoint = "breakpoint"
	instrumentKindWatchpoint = "watchpoint"
)

// instrumentActionVocab is the closed action vocabulary. list is first so a
// schema-only probe of the action property performs the read-only action.
var instrumentActionVocab = newEnumVocab("action", instrumentActionList, instrumentActionSet, instrumentActionRemove, instrumentActionUpdate)

// instrumentKindVocab is the closed resource-kind vocabulary.
var instrumentKindVocab = newEnumVocab("kind", instrumentKindBreakpoint, instrumentKindWatchpoint)

type debugInstrumentArgs struct {
	Action     string  `json:"action"`
	Kind       string  `json:"kind"`
	CPU        string  `json:"cpu"`
	Address    any     `json:"address"`
	Condition  string  `json:"condition"`
	RangeEnd   any     `json:"range_end"`
	BreakOn    bool    `json:"break_on_counter"`
	BreakCount *uint64 `json:"break_counter"`
	OneShot    bool    `json:"one_shot"`
	Length     *uint64 `json:"length"`
	Access     string  `json:"access"`
	Breakpoint *uint64 `json:"breakpoint_id"`
	Watchpoint *uint64 `json:"watchpoint_id"`
	RunUntil   bool    `json:"run_until"`
	TimeoutMS  *uint64 `json:"timeout_ms"`
	Context    string  `json:"context"`
	guardArgs
	// AddressSpace is the shared input domain published by objectSchema for
	// every address-bearing tool; it is forwarded verbatim to the handler.
	AddressSpace string `json:"address_space"`
}

func debugInstrumentSpec() toolSpec {
	return toolSpec{
		name:        "debug_instrument",
		description: fmt.Sprintf("Manage one execution breakpoint or one memory watchpoint. action list (default is not assumed: action is required) lists the instruments of `kind` created through this MCP process, including hit counters and creation provenance; set creates one (exact-address breakpoint, or read/write watchpoint whose range matches access start addresses); remove deletes one by id; update replaces one (the native API has no in-place update, so update removes the old instrument and creates the new one, reporting both ids and advancing the target generation twice). `kind` selects breakpoint or watchpoint and defaults to breakpoint. Set `run_until: true` on action set to arm a one-shot instrument, run the system until it fires, and pause with the stop evidence (stop_reason, stop_source, triggering PC, hit count, registers, debug_event_id); that window is bounded by timeout_ms (default %d, cap %d) and the instrument is always removed afterwards. Breakpoints accept condition/range_end/break_on_counter/break_counter; watchpoints accept length/access. one_shot auto-removes a steady instrument once a hit proves it fired. Mutating actions accept optional expected_target_generation and control_id. Deprecated aliases: cpu_breakpoint_set, cpu_breakpoint_list, cpu_breakpoint_remove, cpu_watchpoint_set, cpu_watchpoint_list, cpu_watchpoint_remove, run_until_breakpoint, run_until_watchpoint.", defaultRunUntilTimeoutMs, maxRunUntilTimeoutMs),
		schema: objectSchema(map[string]any{
			"action":                     instrumentActionVocab.property("Action to perform: list, set, remove, or update."),
			"kind":                       instrumentKindVocab.property("Instrument kind: breakpoint or watchpoint (default breakpoint)."),
			"cpu":                        cpuVocab.property("Processor the instrument belongs to (set, update, and run_until)."),
			"address":                    addressProperty(),
			"condition":                  breakpointConditionVocab.property("Breakpoint location condition (set, update, run_until): equal breaks at exactly `address`; greater/less break above/below it; range breaks inside `address` (exclusive lower bound) and `range_end` (exclusive upper bound)."),
			"range_end":                  addressProperty(),
			"break_on_counter":           booleanProperty("Breakpoint: only pause on every Nth hit instead of every hit; N comes from break_counter."),
			"break_counter":              integerProperty("Breakpoint: pause every Nth hit when break_on_counter is true (default 1).", 1),
			"one_shot":                   booleanProperty("Set/update: remove this instrument automatically once a hit proves it fired. Rejected with run_until, whose instrument is one-shot by definition."),
			"length":                     integerProperty("Watchpoint: watched range length in bytes (default 1). The range matches access start addresses only.", 1),
			"access":                     watchAccessVocab.property("Watchpoint: access types that trigger the watchpoint (default any)."),
			"breakpoint_id":              integerProperty("Breakpoint id to remove or update.", 1),
			"watchpoint_id":              integerProperty("Watchpoint id to remove or update.", 1),
			"run_until":                  booleanProperty("With action set: arm the instrument, run until it fires, pause with the stop evidence, and remove it afterwards."),
			"timeout_ms":                 integerProperty(fmt.Sprintf("With run_until: the run window in milliseconds (default %d, min %d, cap %d).", defaultRunUntilTimeoutMs, minRunUntilTimeoutMs, maxRunUntilTimeoutMs), 1),
			"context":                    contextProperty(),
			"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
			"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
		}, []string{"action"}),
		run: runDebugInstrument,
	}
}

func runDebugInstrument(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[debugInstrumentArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.Action == "" {
		return failureResult(&toolFailure{
			Code:    "invalid_params",
			Message: "action is required: list, set, remove, or update",
			Data:    map[string]any{"field": "action", "allowed": instrumentActionVocab.valuesEcho()},
		}, tc.modern)
	}
	action, failure := instrumentActionVocab.resolve(parsed.Action, instrumentActionList)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	kind, failure := instrumentKindVocab.resolve(parsed.Kind, instrumentKindBreakpoint)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	raw, failure := decodeArgumentMap(args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if failure := validateInstrumentArguments(raw, action, kind, parsed.RunUntil); failure != nil {
		return failureResult(failure, tc.modern)
	}
	if failure := validateInstrumentRequiredFields(parsed, action, kind); failure != nil {
		return failureResult(failure, tc.modern)
	}

	result := map[string]any{"action": action, "kind": kind}
	switch action {
	case instrumentActionList:
		// Listing is read-only, but a supplied guard is still a promise the
		// caller made about the target: honor it instead of ignoring it.
		if failure := readOnlyGuardPrecondition(tc, parsed.guard()); failure != nil {
			return failureResult(failure, tc.modern)
		}
		handler := runBreakpointList
		if kind == instrumentKindWatchpoint {
			handler = runWatchpointList
		}
		payload, failure := composeTool(tc, handler, pickArguments(raw, "context"))
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		result["result"] = payload
		return okResult(result, tc.modern)

	case instrumentActionRemove:
		idKey, id := "breakpoint_id", parsed.Breakpoint
		handler := runBreakpointRemove
		if kind == instrumentKindWatchpoint {
			idKey, id = "watchpoint_id", parsed.Watchpoint
			handler = runWatchpointRemove
		}
		payload, failure := composeTool(tc, handler, instrumentRemoveArguments(raw, idKey))
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		result["instrument_id"] = *id
		result["result"] = payload
		return okResult(result, tc.modern)

	case instrumentActionUpdate:
		return runDebugInstrumentUpdate(tc, parsed, raw, kind, result)

	default:
		if parsed.RunUntil {
			handler := runRunUntilBreakpoint
			if kind == instrumentKindWatchpoint {
				handler = runRunUntilWatchpoint
			}
			payload, failure := composeTool(tc, handler, instrumentRunUntilArguments(raw, kind))
			if failure != nil {
				return failureResult(failure, tc.modern)
			}
			result["run_until"] = true
			result["instrument_id"] = payload["resource_id"]
			result["result"] = payload
			return okResult(result, tc.modern)
		}
		handler := runBreakpointSet
		if kind == instrumentKindWatchpoint {
			handler = runWatchpointSet
		}
		payload, failure := composeTool(tc, handler, instrumentSetArguments(raw, kind))
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		result["instrument_id"] = instrumentID(payload, kind)
		result["result"] = payload
		return okResult(result, tc.modern)
	}
}

// runDebugInstrumentUpdate replaces one instrument. The native API exposes
// create/delete only, so update is delete-then-create inside one call: both
// native mutations are audited separately, and the response reports both ids so
// a caller never has to guess which one is now armed.
func runDebugInstrumentUpdate(tc toolContext, parsed *debugInstrumentArgs, raw map[string]json.RawMessage, kind string, result map[string]any) map[string]any {
	idKey, previous := "breakpoint_id", parsed.Breakpoint
	removeHandler, setHandler := runBreakpointRemove, runBreakpointSet
	if kind == instrumentKindWatchpoint {
		idKey, previous = "watchpoint_id", parsed.Watchpoint
		removeHandler, setHandler = runWatchpointRemove, runWatchpointSet
	}
	removed, failure := composeTool(tc, removeHandler, instrumentRemoveArguments(raw, idKey))
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	created, failure := composeTool(tc, setHandler, instrumentSetArguments(raw, kind))
	if failure != nil {
		// The old instrument is already gone: say exactly that instead of
		// reporting a plain set failure the caller could misread as "nothing
		// happened".
		data := map[string]any{
			"update_partial":         true,
			"previous_instrument_id": *previous,
			"removed":                removed,
			"note":                   "the previous instrument was removed and the replacement could not be created, so no instrument of this kind is armed under the old id",
		}
		for key, value := range failure.Data {
			if _, present := data[key]; !present {
				data[key] = value
			}
		}
		failure.Data = data
		return failureResult(failure, tc.modern)
	}
	result["previous_instrument_id"] = *previous
	result["instrument_id"] = instrumentID(created, kind)
	result["result"] = map[string]any{"removed": removed, "created": created}
	return okResult(result, tc.modern)
}

// instrumentID reads the native id of one created instrument.
func instrumentID(payload map[string]any, kind string) any {
	key := "breakpoint_id"
	if kind == instrumentKindWatchpoint {
		key = "watchpoint_id"
	}
	if value, present := payload[key]; present {
		return value
	}
	return nil
}

// decodeArgumentMap decodes the raw arguments so the dispatcher can tell an
// omitted argument from one explicitly supplied as false/zero.
func decodeArgumentMap(raw json.RawMessage) (map[string]json.RawMessage, *toolFailure) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, &toolFailure{Code: "invalid_params", Message: "invalid arguments: " + err.Error()}
	}
	return fields, nil
}

// pickArguments copies the named arguments that were supplied, keeping the
// caller's JSON form (a hex address stays a string).
func pickArguments(raw map[string]json.RawMessage, names ...string) map[string]any {
	selected := make(map[string]any, len(names))
	for _, name := range names {
		value, present := raw[name]
		if !present {
			continue
		}
		var decoded any
		if json.Unmarshal(value, &decoded) != nil {
			continue
		}
		selected[name] = decoded
	}
	return selected
}

func instrumentRemoveArguments(raw map[string]json.RawMessage, idKey string) map[string]any {
	return pickArguments(raw, idKey, "control_id", "expected_target_generation")
}

func instrumentSetArguments(raw map[string]json.RawMessage, kind string) map[string]any {
	if kind == instrumentKindWatchpoint {
		return pickArguments(raw, "cpu", "address", "address_space", "length", "access", "one_shot", "context", "control_id", "expected_target_generation")
	}
	return pickArguments(raw, "cpu", "address", "address_space", "condition", "range_end", "break_on_counter", "break_counter", "one_shot", "context", "control_id", "expected_target_generation")
}

func instrumentRunUntilArguments(raw map[string]json.RawMessage, kind string) map[string]any {
	if kind == instrumentKindWatchpoint {
		return pickArguments(raw, "cpu", "address", "address_space", "length", "access", "timeout_ms", "context", "control_id", "expected_target_generation")
	}
	return pickArguments(raw, "cpu", "address", "address_space", "condition", "range_end", "break_on_counter", "break_counter", "timeout_ms", "context", "control_id", "expected_target_generation")
}

// instrumentAcceptedFields lists the arguments one action consumes. A supplied
// argument outside this set is rejected instead of dropped (#9): a caller must
// never believe a field it sent had an effect.
func instrumentAcceptedFields(action, kind string, runUntil bool) []string {
	// run_until is accepted by every action so an explicit false is not treated
	// as a field the tool does not consume; the action-specific list below still
	// rejects it where it would change nothing (the dispatcher only acts on it
	// for action set).
	common := []string{"action", "kind", "context", "run_until"}
	switch action {
	case instrumentActionList:
		return append(common, "control_id", "expected_target_generation")
	case instrumentActionRemove:
		if kind == instrumentKindWatchpoint {
			return append(common, "watchpoint_id", "control_id", "expected_target_generation")
		}
		return append(common, "breakpoint_id", "control_id", "expected_target_generation")
	case instrumentActionUpdate:
		if kind == instrumentKindWatchpoint {
			return append(common, "watchpoint_id", "cpu", "address", "address_space", "length", "access", "one_shot", "control_id", "expected_target_generation")
		}
		return append(common, "breakpoint_id", "cpu", "address", "address_space", "condition", "range_end", "break_on_counter", "break_counter", "one_shot", "control_id", "expected_target_generation")
	default:
		if runUntil {
			if kind == instrumentKindWatchpoint {
				return append(common, "cpu", "address", "address_space", "length", "access", "timeout_ms", "control_id", "expected_target_generation")
			}
			return append(common, "cpu", "address", "address_space", "condition", "range_end", "break_on_counter", "break_counter", "timeout_ms", "control_id", "expected_target_generation")
		}
		if kind == instrumentKindWatchpoint {
			return append(common, "cpu", "address", "address_space", "length", "access", "one_shot", "control_id", "expected_target_generation")
		}
		return append(common, "cpu", "address", "address_space", "condition", "range_end", "break_on_counter", "break_counter", "one_shot", "control_id", "expected_target_generation")
	}
}

// validateInstrumentArguments rejects an argument outside the selected action's
// contract, naming the field and the accepted set.
func validateInstrumentArguments(raw map[string]json.RawMessage, action, kind string, runUntil bool) *toolFailure {
	accepted := instrumentAcceptedFields(action, kind, runUntil)
	allowed := make(map[string]bool, len(accepted))
	for _, name := range accepted {
		allowed[name] = true
	}
	keys := make([]string, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if allowed[key] {
			continue
		}
		return &toolFailure{
			Code:    "unsupported_parameter",
			Message: fmt.Sprintf("%q is not consumed by debug_instrument{action:%q, kind:%q, run_until:%t}", key, action, kind, runUntil),
			Data: map[string]any{
				"field":           key,
				"path":            "$." + key,
				"accepted_fields": accepted,
				"action":          action,
				"kind":            kind,
				"run_until":       runUntil,
			},
		}
	}
	return nil
}

// validateInstrumentRequiredFields states the per-action requirements the
// dispatcher enforces before delegating, so a missing field is reported against
// the action instead of as a decoder error from an absorbed handler.
func validateInstrumentRequiredFields(parsed *debugInstrumentArgs, action, kind string) *toolFailure {
	requireAddress := func() *toolFailure {
		if parsed.CPU == "" {
			return &toolFailure{Code: "invalid_params", Message: "cpu is required for action " + action, Data: map[string]any{"field": "cpu"}}
		}
		if parsed.Address == nil {
			return &toolFailure{Code: "invalid_params", Message: "address is required for action " + action, Data: map[string]any{"field": "address"}}
		}
		return nil
	}
	switch action {
	case instrumentActionList:
		return nil
	case instrumentActionRemove:
		if kind == instrumentKindWatchpoint && (parsed.Watchpoint == nil || *parsed.Watchpoint == 0) {
			return &toolFailure{Code: "invalid_params", Message: "watchpoint_id is required for action remove", Data: map[string]any{"field": "watchpoint_id"}}
		}
		if kind == instrumentKindBreakpoint && (parsed.Breakpoint == nil || *parsed.Breakpoint == 0) {
			return &toolFailure{Code: "invalid_params", Message: "breakpoint_id is required for action remove", Data: map[string]any{"field": "breakpoint_id"}}
		}
		return nil
	case instrumentActionUpdate:
		if kind == instrumentKindWatchpoint && (parsed.Watchpoint == nil || *parsed.Watchpoint == 0) {
			return &toolFailure{Code: "invalid_params", Message: "watchpoint_id is required for action update", Data: map[string]any{"field": "watchpoint_id"}}
		}
		if kind == instrumentKindBreakpoint && (parsed.Breakpoint == nil || *parsed.Breakpoint == 0) {
			return &toolFailure{Code: "invalid_params", Message: "breakpoint_id is required for action update", Data: map[string]any{"field": "breakpoint_id"}}
		}
		return requireAddress()
	}
	return requireAddress()
}

// readOnlyGuardPrecondition applies the guard fields of a read-only action the
// same way a mutation would: an expected generation that no longer matches, or
// a control id that does not own an active lock, rejects the call instead of
// being silently dropped.
func readOnlyGuardPrecondition(tc toolContext, guard mutationGuard) *toolFailure {
	if guard.HasExpectedGeneration {
		if failure := targetGenerationPrecondition(tc.server, guard.ExpectedGeneration); failure != nil {
			return failure
		}
	}
	if lock := tc.server.controls.Active(); lock != nil && !tc.server.controls.Valid(guard.ControlID) {
		return controlHeldFailure(lock, tc.server.target.Generation())
	}
	return nil
}
