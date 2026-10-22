package mcp

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func controlToolSpecs() []toolSpec {
	return []toolSpec{
		{name: "cpu_pause", description: "Pause the emulated system. Mutates the target: advances the target generation, and emulator_status reports pause_source \"mcp\" until an external actor changes the state. Accepts optional expected_target_generation and control_id.", schema: controlGuardSchema(), run: makeRunCPUControl("cpu_pause", "", "pause")},
		{name: "cpu_run", description: "Run the emulated system. Mutates the target: advances the target generation, and emulator_status reports pause_source \"mcp\" until an external actor changes the state. UI-initiated transitions are audited as run_state_change events and never advance the generation. Use this to resume execution after a machine reset (rom_load with the same path) or after restoring a snapshot (state_load). Accepts optional expected_target_generation and control_id.", schema: controlGuardSchema(), run: makeRunCPUControl("cpu_run", "", "run")},
		{name: "m68k_step", description: "Pause and execute exactly one M68000 instruction. Mutates the target: advances the target generation, and the system ends paused (pause_source \"mcp\"). Accepts optional expected_target_generation and control_id.", schema: controlGuardSchema(), run: makeRunCPUControl("m68k_step", "m68k", "step")},
		{name: "z80_step", description: "Pause and execute exactly one Z80 instruction. Mutates the target: advances the target generation, and the system ends paused (pause_source \"mcp\"). Accepts optional expected_target_generation and control_id.", schema: controlGuardSchema(), run: makeRunCPUControl("z80_step", "z80", "step")},
		{
			name:        "cpu_step_over",
			description: "Run the selected processor until Exodus completes the current instruction without entering a call. Mutates the target: advances the target generation, and the system is typically paused again (pause_source \"mcp\"). Accepts optional expected_target_generation and control_id.",
			schema:      stepGuardSchema(),
			run:         makeRunCPUControlFromArgs("cpu_step_over", "step_over"),
		},
		{
			name:        "cpu_step_out",
			description: "Run the selected processor until Exodus returns from the current call frame. Mutates the target: advances the target generation, and the system is typically paused again (pause_source \"mcp\"). Accepts optional expected_target_generation and control_id.",
			schema:      stepGuardSchema(),
			run:         makeRunCPUControlFromArgs("cpu_step_out", "step_out"),
		},
		{
			name:        "cpu_breakpoint_set",
			description: "Create an enabled exact-address execution breakpoint owned by this MCP process, recording context provenance. For the Exodus M68K and Z80 cores, the address check runs before the opcode is fetched/executed; when it hits, the triggering instruction has not executed yet. Optional `condition` filters by the processor's program counter (greater/less boundaries, inclusive-free range), and `break_on_counter` pauses only on every Nth hit; `breakpoint_list` reports the native hit counter. `one_shot: true` auto-removes the breakpoint through the audited mutation path once a hit proves it fired (checked at the next paused observation), so one-shot instrumentation never stays armed. Mutates the target: advances the target generation. Accepts optional expected_target_generation and control_id.",
			schema: objectSchema(map[string]any{
				"cpu":                        cpuVocab.property("Processor to break."),
				"address":                    addressProperty(),
				"condition":                  breakpointConditionVocab.property("Location condition. equal breaks at exactly `address`; greater/less break above/below it; range breaks inside `address` (exclusive lower bound) and `range_end` (exclusive upper bound)."),
				"range_end":                  addressProperty(),
				"break_on_counter":           booleanProperty("Only pause on every Nth hit instead of every hit; N comes from break_counter."),
				"break_counter":              integerProperty("Break every Nth hit when break_on_counter is true (default 1).", 1),
				"one_shot":                   booleanProperty("Remove this breakpoint automatically once a hit proves it fired (default false). A one-shot breakpoint will be absent from breakpoint_list after its hit; emulator_status reports one_shot_removals."),
				"context":                    contextProperty(),
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
				"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
			}, []string{"cpu", "address"}),
			run: runBreakpointSet,
		},
		{
			name:        "cpu_breakpoint_list",
			description: "List execution breakpoints created through this MCP process, including enabled state, condition, break-on-counter settings, native hit counters, the one_shot flag, and creation provenance (context, target generation). An optional context handle restricts the listing to the breakpoints that context created; omitted or \"all\" lists every entry.",
			schema:      objectSchema(map[string]any{"context": listScopeProperty()}, nil),
			run:         runBreakpointList,
		},
		{
			name:        "cpu_breakpoint_remove",
			description: "Remove one execution breakpoint created through this MCP process. Mutates the target: advances the target generation. Accepts optional expected_target_generation and control_id.",
			schema: objectSchema(map[string]any{
				"breakpoint_id":              integerProperty("Breakpoint id returned by cpu_breakpoint_set.", 1),
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
				"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
			}, []string{"breakpoint_id"}),
			run: runBreakpointRemove,
		},
		{
			name:        "cpu_watchpoint_set",
			description: "Create an enabled read and/or write watchpoint owned by this MCP process, recording context provenance. The system pauses when the watched range is accessed. Range semantics are start-address based, exactly like the Exodus debugger: the watchpoint fires when the **start address** of an access falls inside [address, address+length-1], never when an access merely overlaps the range (the processor watchpoint API receives only the access start address, not the transfer width). `range_semantics` echoes the contract (`exact_address` for length 1, `access_start_in_range` otherwise). `access` defaults to any; for a single-direction watchpoint the stop event can prove the observed direction, while an `any` watchpoint stop reports `observed_direction: null` (the core does not expose the transfer direction). `one_shot: true` auto-removes the watchpoint through the audited mutation path once a hit proves it fired (checked at the next paused observation), so one-shot instrumentation never stays armed. Mutates the target: advances the target generation. Accepts optional expected_target_generation and control_id.",
			schema: objectSchema(map[string]any{
				"cpu":                        cpuVocab.property("Processor to watch."),
				"address":                    addressProperty(),
				"length":                     integerProperty("Watched range length in bytes (default 1). The range matches access start addresses only; it must stay inside the processor address bus.", 1),
				"access":                     watchAccessVocab.property("Access types that trigger the watchpoint (default any)."),
				"one_shot":                   booleanProperty("Remove this watchpoint automatically once a hit proves it fired (default false). A one-shot watchpoint will be absent from watchpoint_list after its hit; emulator_status reports one_shot_removals."),
				"context":                    contextProperty(),
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
				"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
			}, []string{"cpu", "address"}),
			run: runWatchpointSet,
		},
		{name: "cpu_watchpoint_list", description: "List read/write watchpoints created through this MCP process, including hit counters, the configured access, the range semantics, the one_shot flag, and creation provenance (context, target generation). An optional context handle restricts the listing to the watchpoints that context created; omitted or \"all\" lists every entry.", schema: objectSchema(map[string]any{"context": listScopeProperty()}, nil), run: runWatchpointList},
		{
			name:        "cpu_watchpoint_remove",
			description: "Remove one watchpoint created through this MCP process. Mutates the target: advances the target generation. Accepts optional expected_target_generation and control_id.",
			schema: objectSchema(map[string]any{
				"watchpoint_id":              integerProperty("Watchpoint id returned by cpu_watchpoint_set.", 1),
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
				"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
			}, []string{"watchpoint_id"}),
			run: runWatchpointRemove,
		},
		{
			name:        "cpu_debug_events_list",
			description: "List structured breakpoint/watchpoint stop events with pagination and filters. Every managed stop is recorded once - a steady breakpoint or watchpoint hit reached through cpu_run as well as a one-shot hit - at the next paused observation. Each event separates `configured_access` (what the instrument was set with) from `observed_direction` (`read`/`write`/`execute` when the stop proves the direction, null when the core cannot tell: an `any` watchpoint stop), and carries `stop_source` (why execution stopped, `instrument` for every managed stop) apart from `triggering_pc_source` (`register_read` | `unknown`, where the PC came from). `debug_event_id` in a run_until_* response names the event row for the same stop. `direction` filters the OBSERVED value: `any` matches every event including unknown directions, and a concrete direction never matches an event whose direction is unknown. `resource_kind`, `cpu`, and `direction` are validated server-side (invalid_params for unknown values). History is bounded (100 retained events): the response's history object states the capacity, how many records were recorded, how many the cap dropped, the retained id span, whether the retained history is complete, the context scope, how many retained events the scope holds (`scope_retained`), and how many the filters match (`matching`, identical to `total`). Scope the query with `context` (handle, omitted for the caller's default context) or `context: \"all\"` for every context. A repeated observation of the same paused hit (same resource, counter value, and direction) is folded into the existing event and counted in repeat_count instead of creating a duplicate - the native counter is the identity of a stop - and a resumed CPU increments the counter on the next hit and records a new event.",
			schema: objectSchema(map[string]any{
				"offset":        integerProperty("Pagination offset within the filtered set (default 0).", 0),
				"limit":         integerProperty("Pagination limit (default 20, cap 100).", 1),
				"resource_kind": debugEventResourceKindVocab.property("Filter by resource kind."),
				"resource_id":   integerProperty("Filter by managed resource id.", 1),
				"cpu":           cpuVocab.property("Filter by processor."),
				"direction":     debugEventDirectionVocab.property("Filter by the OBSERVED access direction. \"any\" matches every event, including events whose direction could not be observed; read/write/execute match only events that proved that direction."),
				"event_id_min":  integerProperty("Only events with an id at or above this value.", 1),
				"event_id_max":  integerProperty("Only events with an id at or below this value.", 1),
				"context":       stringProperty("Analysis context handle; omitted means the caller's default context, and \"all\" queries the retained history across every context."),
			}, nil),
			run: runDebugEventsList,
		},
	}
}

// controlGuardSchema is the schema of the CPU control tools without a cpu
// argument (pause/run/single steps).
func controlGuardSchema() map[string]any {
	return objectSchema(map[string]any{
		"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
		"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
	}, nil)
}

func stepGuardSchema() map[string]any {
	return objectSchema(map[string]any{
		"cpu":                        cpuVocab.property("Processor to control."),
		"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
		"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
	}, []string{"cpu"})
}

func makeRunCPUControl(tool, cpu, action string) func(toolContext, json.RawMessage) map[string]any {
	return func(tc toolContext, args json.RawMessage) map[string]any {
		parsed, failure := decodeArgs[cpuControlGuardArgs](args)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		params := map[string]string{"action": action}
		if cpu != "" {
			params["cpu"] = cpu
		}
		payload, before, after, failure := tc.server.executeMutation(tc.ctx, mutationCall{
			tool:      tool,
			operation: "cpu_control",
			params:    params,
			guard:     parsed.guard(),
			detail: map[string]any{
				"action": action,
			},
		})
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		// cpu_pause/cpu_run end in a deterministic state; steps echo the live
		// state. The tracker attributes the new state to MCP so subsequent
		// emulator_status calls can report pause_source.
		recordStateFromPayload(tc.server, payload, action == "run")
		return okResult(stampGenerations(payload, before, after), tc.modern)
	}
}

// recordStateFromPayload feeds the run-state tracker after a successful CPU
// control mutation. The plugin echoes the live system_running when the action
// can race with an async internal break (step_over/step_out), so the payload
// value wins over the action's expected end state.
func recordStateFromPayload(server *Server, payload map[string]any, fallback bool) {
	if value, ok := payload["system_running"].(bool); ok {
		server.runState.setByMCP(value)
		return
	}
	server.runState.setByMCP(fallback)
}

type cpuControlGuardArgs struct {
	guardArgs
}

type cpuControlArgs struct {
	CPU string `json:"cpu"`
	guardArgs
}

func makeRunCPUControlFromArgs(tool, action string) func(toolContext, json.RawMessage) map[string]any {
	return func(tc toolContext, args json.RawMessage) map[string]any {
		parsed, failure := decodeArgs[cpuControlArgs](args)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		payload, before, after, failure := tc.server.executeMutation(tc.ctx, mutationCall{
			tool:      tool,
			operation: "cpu_control",
			params:    map[string]string{"cpu": parsed.CPU, "action": action},
			guard:     parsed.guard(),
			detail:    map[string]any{"cpu": parsed.CPU, "action": action},
		})
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		recordStateFromPayload(tc.server, payload, false)
		return okResult(stampGenerations(payload, before, after), tc.modern)
	}
}

type breakpointSetArgs struct {
	CPU            string  `json:"cpu"`
	Address        any     `json:"address"`
	AddressSpace   string  `json:"address_space"`
	Condition      string  `json:"condition"`
	RangeEnd       any     `json:"range_end"`
	BreakOnCounter bool    `json:"break_on_counter"`
	BreakCounter   *uint64 `json:"break_counter"`
	OneShot        bool    `json:"one_shot"`
	Context        string  `json:"context"`
	guardArgs
}

func runBreakpointSet(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[breakpointSetArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if failure := cpuVocab.validate(parsed.CPU); failure != nil {
		return failureResult(failure, tc.modern)
	}
	if failure := cpuVocab.validate(parsed.CPU); failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	address, failure := resolveAddress(parsed.Address, addressSpaceFromArgs(args), parsed.CPU+"-bus")
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	condition := parsed.Condition
	if failure := breakpointConditionVocab.validate(condition); failure != nil {
		return failureResult(failure, tc.modern)
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
	payload, before, after, failure := tc.server.executeMutation(tc.ctx, mutationCall{
		tool:      "cpu_breakpoint_set",
		operation: "breakpoint_set",
		params:    params,
		guard:     parsed.guard(),
		contextID: context.ID,
		detail: map[string]any{
			"cpu":       parsed.CPU,
			"address":   address,
			"condition": condition,
		},
	})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	payload["address"] = address
	payload["address_hex"] = canonicalHex(address)
	payload["address_space"] = parsed.CPU + "-bus"
	annotateAddressPair(payload, parsed.CPU+"-bus", address)
	if condition == "range" {
		payload["range_end"] = rangeEnd
		payload["range_end_hex"] = canonicalHex(rangeEnd)
		annotateAddressRangePair(payload, "range_end", parsed.CPU+"-bus", rangeEnd)
	}
	if width, mask := addressBusWidthMask(parsed.CPU + "-bus"); width != 0 {
		payload["address_width_bits"] = width
		payload["address_mask_hex"] = canonicalHex(mask)
	}
	payload["one_shot"] = parsed.OneShot
	if id, ok := payload["breakpoint_id"].(float64); ok {
		tc.server.trackDebugResource("breakpoint", uint64(id), debugResourceMeta{
			ContextID:        context.ID,
			ControlID:        parsed.ControlID,
			TargetGeneration: after,
			CreatedAt:        time.Now().UTC(),
			ROMPath:          tc.server.currentROMPath(),
			OneShot:          parsed.OneShot,
			BreakCounter:     breakCounter,
		})
	}
	return okResult(stampGenerations(payload, before, after), tc.modern)
}

func runBreakpointList(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[listScopeArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	scope, contextID, failure := resolveListScope(tc, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	payload, failure := tc.server.executeCommand(tc.ctx, "breakpoint_list", nil)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	annotateDebugList(payload, "breakpoint", "breakpoints", "breakpoint_id", tc.server)
	return okResult(applyListScope(payload, "breakpoints", "breakpoint_id", "breakpoint", scope, contextID, tc.server), tc.modern)
}

type breakpointRemoveArgs struct {
	BreakpointID uint64 `json:"breakpoint_id"`
	guardArgs
}

func runBreakpointRemove(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[breakpointRemoveArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.BreakpointID == 0 {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "breakpoint_id must be positive"}, tc.modern)
	}
	payload, before, after, failure := tc.server.executeMutation(tc.ctx, mutationCall{
		tool:      "cpu_breakpoint_remove",
		operation: "breakpoint_remove",
		params:    map[string]string{"breakpoint_id": strconv.FormatUint(parsed.BreakpointID, 10)},
		guard:     parsed.guard(),
		detail: map[string]any{
			"breakpoint_id": parsed.BreakpointID,
		},
		commit: func() {
			tc.server.forgetDebugResource("breakpoint", parsed.BreakpointID)
		},
		resources: func() []string { return []string{strconv.FormatUint(parsed.BreakpointID, 10)} },
	})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	return okResult(stampGenerations(payload, before, after), tc.modern)
}

type watchpointSetArgs struct {
	CPU          string  `json:"cpu"`
	Address      any     `json:"address"`
	AddressSpace string  `json:"address_space"`
	Length       *uint64 `json:"length"`
	Access       string  `json:"access"`
	OneShot      bool    `json:"one_shot"`
	Context      string  `json:"context"`
	guardArgs
}

func runWatchpointSet(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[watchpointSetArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if failure := cpuVocab.validate(parsed.CPU); failure != nil {
		return failureResult(failure, tc.modern)
	}
	if failure := cpuVocab.validate(parsed.CPU); failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	address, failure := resolveAddress(parsed.Address, addressSpaceFromArgs(args), parsed.CPU+"-bus")
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	access, failure := watchAccessVocab.resolve(parsed.Access, "any")
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	length := uint64(1)
	if parsed.Length != nil {
		length = *parsed.Length
	}
	if length == 0 {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "length must be at least 1"}, tc.modern)
	}
	// The whole watched range must exist on the processor address bus: the
	// range matches access start addresses, so its last byte is the highest
	// start address that can fire.
	if _, mask := addressBusWidthMask(parsed.CPU + "-bus"); mask != 0 {
		if length-1 > mask || address > mask || address+length-1 > mask {
			maxLength := uint64(0)
			if address <= mask {
				maxLength = mask + 1 - address
			}
			return failureResult(&toolFailure{
				Code: "invalid_params",
				Message: fmt.Sprintf("watched range %s..%s is outside the %s bus (mask %s); shorten length or move address",
					canonicalHex(address), canonicalHex(address+length-1), parsed.CPU+"-bus", canonicalHex(mask)),
				Data: map[string]any{
					"address":          address,
					"length":           length,
					"range_end":        address + length - 1,
					"address_space":    parsed.CPU + "-bus",
					"address_mask_hex": canonicalHex(mask),
					"range_semantics":  watchpointRangeSemantics(length),
					"max_length":       maxLength,
				},
			}, tc.modern)
		}
	}
	params := map[string]string{
		"cpu":     parsed.CPU,
		"address": strconv.FormatUint(address, 10),
		"access":  access,
	}
	if parsed.Length != nil {
		params["length"] = strconv.FormatUint(length, 10)
	}
	payload, before, after, failure := tc.server.executeMutation(tc.ctx, mutationCall{
		tool:      "cpu_watchpoint_set",
		operation: "watchpoint_set",
		params:    params,
		guard:     parsed.guard(),
		contextID: context.ID,
		detail: map[string]any{
			"cpu":     parsed.CPU,
			"address": address,
			"access":  access,
			"length":  length,
		},
	})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	payload["address"] = address
	payload["address_hex"] = canonicalHex(address)
	payload["address_space"] = parsed.CPU + "-bus"
	payload["access"] = access
	payload["length"] = length
	payload["one_shot"] = parsed.OneShot
	payload["range_semantics"] = watchpointRangeSemantics(length)
	annotateAddressPair(payload, parsed.CPU+"-bus", address)
	if length > 1 {
		payload["range_end"] = address + length - 1
		payload["range_end_hex"] = canonicalHex(address + length - 1)
		annotateAddressRangePair(payload, "range_end", parsed.CPU+"-bus", address+length-1)
	}
	if width, mask := addressBusWidthMask(parsed.CPU + "-bus"); width != 0 {
		payload["address_width_bits"] = width
		payload["address_mask_hex"] = canonicalHex(mask)
	}
	if id, ok := payload["watchpoint_id"].(float64); ok {
		tc.server.trackDebugResource("watchpoint", uint64(id), debugResourceMeta{
			ContextID:        context.ID,
			ControlID:        parsed.ControlID,
			TargetGeneration: after,
			CreatedAt:        time.Now().UTC(),
			ROMPath:          tc.server.currentROMPath(),
			OneShot:          parsed.OneShot,
			BreakCounter:     1,
		})
	}
	return okResult(stampGenerations(payload, before, after), tc.modern)
}

func runWatchpointList(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[listScopeArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	scope, contextID, failure := resolveListScope(tc, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	payload, failure := tc.server.executeCommand(tc.ctx, "watchpoint_list", nil)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	annotateDebugList(payload, "watchpoint", "watchpoints", "watchpoint_id", tc.server)
	return okResult(applyListScope(payload, "watchpoints", "watchpoint_id", "watchpoint", scope, contextID, tc.server), tc.modern)
}

type watchpointRemoveArgs struct {
	WatchpointID uint64 `json:"watchpoint_id"`
	guardArgs
}

func runWatchpointRemove(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[watchpointRemoveArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.WatchpointID == 0 {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "watchpoint_id must be positive"}, tc.modern)
	}
	payload, before, after, failure := tc.server.executeMutation(tc.ctx, mutationCall{
		tool:      "cpu_watchpoint_remove",
		operation: "watchpoint_remove",
		params:    map[string]string{"watchpoint_id": strconv.FormatUint(parsed.WatchpointID, 10)},
		guard:     parsed.guard(),
		detail: map[string]any{
			"watchpoint_id": parsed.WatchpointID,
		},
		commit: func() {
			tc.server.forgetDebugResource("watchpoint", parsed.WatchpointID)
		},
		resources: func() []string { return []string{strconv.FormatUint(parsed.WatchpointID, 10)} },
	})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	return okResult(stampGenerations(payload, before, after), tc.modern)
}

type debugEventsListArgs struct {
	Offset       uint64 `json:"offset"`
	Limit        uint64 `json:"limit"`
	ResourceKind string `json:"resource_kind"`
	ResourceID   uint64 `json:"resource_id"`
	CPU          string `json:"cpu"`
	Direction    string `json:"direction"`
	EventIDMin   uint64 `json:"event_id_min"`
	EventIDMax   uint64 `json:"event_id_max"`
	Context      string `json:"context"`
}

// debugEventQueryAllScopes is the explicit context value that queries the
// retained history across every analysis context. Context handles are
// generated as ctx_<base64url>, so the token cannot collide with a handle.
const debugEventQueryAllScopes = "all"

func runDebugEventsList(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[debugEventsListArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if failure := debugEventResourceKindVocab.validate(parsed.ResourceKind); failure != nil {
		return failureResult(failure, tc.modern)
	}
	if failure := cpuVocab.validate(parsed.CPU); failure != nil {
		return failureResult(failure, tc.modern)
	}
	if failure := debugEventDirectionVocab.validate(parsed.Direction); failure != nil {
		return failureResult(failure, tc.modern)
	}
	// The context scope is a query decision, not an implicit default: the
	// default context keeps unrelated instrumentation out of an analysis
	// record, and "all" is the explicit cross-context query.
	scope := "context"
	if strings.EqualFold(strings.TrimSpace(parsed.Context), debugEventQueryAllScopes) {
		scope = debugEventQueryAllScopes
	} else {
		context, failure := resolveContext(tc.server, parsed.Context)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		scope = "context:" + context.ID
	}
	offset := int(parsed.Offset)
	limit := int(parsed.Limit)
	if limit == 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	filter := debugEventFilter{
		ResourceKind: parsed.ResourceKind,
		ResourceID:   parsed.ResourceID,
		CPU:          parsed.CPU,
		Direction:    parsed.Direction,
		EventIDMin:   parsed.EventIDMin,
		EventIDMax:   parsed.EventIDMax,
	}
	if scope != debugEventQueryAllScopes {
		filter.ContextID = strings.TrimPrefix(scope, "context:")
	}
	events, total, truncated := tc.server.listDebugEvents(filter, offset, limit)
	history := tc.server.debugEventHistoryFor(filter, scope)
	views := make([]map[string]any, 0, len(events))
	for _, ev := range events {
		view := map[string]any{
			"event_id":          ev.ID,
			"resource_kind":     ev.ResourceKind,
			"resource_id":       ev.ResourceID,
			"context_id":        ev.ContextID,
			"cpu":               ev.CPU,
			"address_space":     ev.AddressSpace,
			"watched_address":   ev.WatchedAddress,
			"configured_access": ev.AccessDirection,
			// access_direction is the historical name of configured_access and
			// keeps its old value for compatibility; observed_direction is what
			// the stop proves and what the direction filter matches.
			"access_direction":   ev.AccessDirection,
			"observed_direction": ev.ObservedDirection,
			"requested_length":   ev.RequestedLength,
			"hit_count":          ev.HitCount,
			"target_generation":  ev.TargetGeneration,
			"timestamp":          ev.Timestamp,
		}
		if ev.ObservedDirection != nil && ev.ResourceKind == "watchpoint" {
			view["range_semantics"] = watchpointRangeSemantics(ev.RequestedLength)
		}
		if ev.TriggeringPCSource == pcSourceUnknown {
			// A PC that could not be read is null with its source, never a
			// fabricated zero.
			view["triggering_pc"] = nil
			view["triggering_pc_hex"] = nil
		} else {
			view["triggering_pc"] = ev.TriggeringPC
			view["triggering_pc_hex"] = canonicalHex(ev.TriggeringPC)
			annotateAddressRangePair(view, "triggering_pc", ev.AddressSpace, ev.TriggeringPC)
		}
		view["triggering_pc_source"] = ev.TriggeringPCSource
		// stop_source answers "why did execution stop" (the same vocabulary a
		// run_until_* response reports); triggering_pc_source answers "where did
		// the PC come from" and never carries the stop reason.
		view["stop_source"] = ev.StopSource
		view["watched_address_hex"] = canonicalHex(ev.WatchedAddress)
		annotateAddressRangePair(view, "watched", ev.AddressSpace, ev.WatchedAddress)
		if ev.FrameToken != nil {
			view["frame_token"] = *ev.FrameToken
		}
		view["first_seen_at"] = ev.FirstSeenAt
		view["last_seen_at"] = ev.LastSeenAt
		view["repeat_count"] = ev.RepeatCount
		if ev.RunState != "" {
			view["run_state"] = ev.RunState
		}
		views = append(views, view)
	}
	return okResult(map[string]any{
		"events":    views,
		"total":     total,
		"offset":    offset,
		"limit":     limit,
		"truncated": truncated,
		"history":   history,
		"filters": map[string]any{
			"resource_kind": filter.ResourceKind,
			"resource_id":   filter.ResourceID,
			"cpu":           filter.CPU,
			"direction":     filter.Direction,
			"event_id_min":  filter.EventIDMin,
			"event_id_max":  filter.EventIDMax,
			"context_id":    filter.ContextID,
			"scope":         history.Scope,
		},
		"semantics": map[string]any{
			"stop":          "A hit that fired pauses the CPU; the event's hit_count is the native counter at that observation. Every managed stop is recorded once, one-shot or steady, at the next paused observation.",
			"resume":        "After cpu_run the CPU can reach the watched range again; the next confirmed hit increments the counter and records a new event.",
			"duplicate":     "Re-observing the same paused hit (same resource, counter value, and direction) increases repeat_count; the native counter is the identity of a stop, so a re-observation is never a second access.",
			"direction":     "configured_access is what the instrument was set with; observed_direction is what the stop proves (null when the core cannot tell, for an \"any\" watchpoint hit). The direction filter matches observed_direction only: \"any\" matches every event, and a concrete direction never matches an event whose direction is unknown.",
			"triggering_pc": "triggering_pc is null when the value could not be read; triggering_pc_source states register_read or unknown (where the PC came from), never the stop reason, so a stop is never attributed to a fabricated address 0.",
			"stop_source":   "stop_source states why execution stopped: instrument for a managed breakpoint/watchpoint stop (every recorded event), external for a UI/other-client pause, mcp for an MCP run-state action. Join a run_until_* response to its event with debug_event_id.",
			"scope":         "scope \"all\" queries every context; \"context:<id>\" restricts to one. history.matching equals total, and history.scope_retained is the ring size inside the scope.",
			"gap":           "history.dropped counts records the 100-event cap evicted; history.complete is false whenever records are gone.",
		},
		"note": "History is bounded to 100 retained events. Use history.matching/history.scope_retained/history.dropped to decide whether the retained list is a complete record of what the query can return, and page with offset/limit over the filtered set.",
	}, tc.modern)
}

// listScopeArgs is the optional context scope accepted by the resource
// listings (breakpoints, watchpoints, freezes). The scope is a query decision,
// never an implicit default: omitted or "all" lists every entry, and a handle
// restricts the listing to the resources that context created.
type listScopeArgs struct {
	Context string `json:"context"`
}

// listScopeAll is the explicit cross-context scope token. Context handles are
// generated as ctx_<base64url>, so the token cannot collide with a handle.
const listScopeAll = "all"

// listScopeProperty documents the shared listing scope argument.
func listScopeProperty() map[string]any {
	return stringProperty("Optional analysis context scope. A context handle restricts the listing to resources created under that context; omitted or \"all\" lists every entry, including resources created outside MCP.")
}

// resolveListScope turns the optional context argument into a filter id.
func resolveListScope(tc toolContext, handle string) (scope, contextID string, failure *toolFailure) {
	trimmed := strings.TrimSpace(handle)
	if trimmed == "" || strings.EqualFold(trimmed, listScopeAll) {
		return listScopeAll, "", nil
	}
	resolved, failure := resolveContext(tc.server, trimmed)
	if failure != nil {
		return "", "", failure
	}
	return resolved.ID, resolved.ID, nil
}

// filterDebugListByContext drops the listed debug resources that do not belong
// to contextID and returns how many were hidden. A resource created outside
// MCP has no provenance, so a scoped listing reports it as out of scope instead
// of attributing it to the caller's context.
func filterDebugListByContext(payload map[string]any, key, idKey, kind, contextID string, server *Server) int {
	if contextID == "" {
		return 0
	}
	entries, ok := payload[key].([]any)
	if !ok {
		return 0
	}
	kept := make([]any, 0, len(entries))
	hidden := 0
	for _, entry := range entries {
		record, ok := entry.(map[string]any)
		if !ok {
			kept = append(kept, entry)
			continue
		}
		id, ok := record[idKey].(float64)
		var meta *debugResourceMeta
		if ok {
			meta = server.debugResourceMeta(kind, uint64(id))
		}
		if meta == nil || meta.ContextID != contextID {
			hidden++
			continue
		}
		kept = append(kept, entry)
	}
	payload[key] = kept
	return hidden
}

// applyListScope echoes the effective scope and hides the resources another
// context created, so a scoped listing is never silently incomplete.
func applyListScope(payload map[string]any, key, idKey, kind, scope, contextID string, server *Server) map[string]any {
	payload["context_scope"] = scope
	if hidden := filterDebugListByContext(payload, key, idKey, kind, contextID, server); hidden > 0 {
		payload["hidden_out_of_scope"] = hidden
	}
	return payload
}

// annotateDebugList merges server-side provenance into a breakpoint_list or
// watchpoint_list payload. The control_id is never exposed here: it is a
// capability of the acquirer only.
func annotateDebugList(payload map[string]any, kind, key, idKey string, server *Server) {
	entries, _ := payload[key].([]any)
	for _, entry := range entries {
		record, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		// Normalize address-bearing fields.
		if addr, ok := numberAsUint64(record["address"]); ok {
			record["address_hex"] = canonicalHex(addr)
			if cpu, ok := record["cpu"].(string); ok && cpu != "" {
				record["address_space"] = cpu + "-bus"
			}
			if space, ok := record["address_space"].(string); ok {
				annotateAddressPair(record, space, addr)
				if width, mask := addressBusWidthMask(space); width != 0 {
					record["address_width_bits"] = width
					record["address_mask_hex"] = canonicalHex(mask)
				}
			}
		}
		if rangeEnd, ok := numberAsUint64(record["range_end"]); ok {
			record["range_end_hex"] = canonicalHex(rangeEnd)
			if space, ok := record["address_space"].(string); ok {
				annotateAddressRangePair(record, "range_end", space, rangeEnd)
			}
		}
		if kind == "watchpoint" {
			// The watchpoint range contract is start-address based: state it on
			// every list entry so the parameter never silently means something
			// else than the documentation.
			length, _ := numberAsUint64(record["length"])
			if length == 0 {
				length = 1
			}
			record["length"] = length
			record["range_semantics"] = watchpointRangeSemantics(length)
			if length > 1 {
				if addr, ok := numberAsUint64(record["address"]); ok {
					record["range_end"] = addr + length - 1
					record["range_end_hex"] = canonicalHex(addr + length - 1)
					if space, ok := record["address_space"].(string); ok {
						annotateAddressRangePair(record, "range_end", space, addr+length-1)
					}
				}
			}
		}
		id, ok := record[idKey].(float64)
		if !ok {
			continue
		}
		meta := server.debugResourceMeta(kind, uint64(id))
		if meta == nil {
			continue
		}
		record["context_id"] = meta.ContextID
		record["target_generation"] = meta.TargetGeneration
		record["created_at"] = meta.CreatedAt
		record["rom_path"] = meta.ROMPath
		record["one_shot"] = meta.OneShot
	}
}

// Watchpoint range semantics. The Exodus processor evaluates one location per
// access — the access START address — and its watchpoint API never reports the
// transfer width, so a range watchpoint cannot implement overlap matching. The
// documented contract is therefore hardware-consistent start-address matching:
// the watchpoint fires exactly when the access start address falls inside
// [address, address+length-1].
const (
	watchpointRangeExact       = "exact_address"
	watchpointRangeAccessStart = "access_start_in_range"
)

// watchpointRangeSemantics names the documented range contract for a watch
// length; the set and list responses echo it next to the range.
func watchpointRangeSemantics(length uint64) string {
	if length <= 1 {
		return watchpointRangeExact
	}
	return watchpointRangeAccessStart
}
