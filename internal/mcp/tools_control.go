package mcp

import (
	"encoding/json"
	"strconv"
	"time"
)

func controlToolSpecs() []toolSpec {
	return []toolSpec{
		{name: "cpu_pause", description: "Pause the emulated system. Mutates the target: advances the target generation. Accepts optional expected_target_generation and control_id.", schema: controlGuardSchema(), run: makeRunCPUControl("cpu_pause", "", "pause")},
		{name: "cpu_run", description: "Run the emulated system. Mutates the target: advances the target generation. Accepts optional expected_target_generation and control_id.", schema: controlGuardSchema(), run: makeRunCPUControl("cpu_run", "", "run")},
		{name: "m68k_step", description: "Pause and execute exactly one M68000 instruction. Mutates the target: advances the target generation. Accepts optional expected_target_generation and control_id.", schema: controlGuardSchema(), run: makeRunCPUControl("m68k_step", "m68k", "step")},
		{name: "z80_step", description: "Pause and execute exactly one Z80 instruction. Mutates the target: advances the target generation. Accepts optional expected_target_generation and control_id.", schema: controlGuardSchema(), run: makeRunCPUControl("z80_step", "z80", "step")},
		{
			name:        "cpu_step_over",
			description: "Run the selected processor until Exodus completes the current instruction without entering a call. Mutates the target: advances the target generation. Accepts optional expected_target_generation and control_id.",
			schema:      stepGuardSchema(),
			run:         makeRunCPUControlFromArgs("cpu_step_over", "step_over"),
		},
		{
			name:        "cpu_step_out",
			description: "Run the selected processor until Exodus returns from the current call frame. Mutates the target: advances the target generation. Accepts optional expected_target_generation and control_id.",
			schema:      stepGuardSchema(),
			run:         makeRunCPUControlFromArgs("cpu_step_out", "step_out"),
		},
		{
			name:        "cpu_breakpoint_set",
			description: "Create an enabled exact-address execution breakpoint owned by this MCP process, recording context provenance. Optional `condition` filters by the processor's program counter (greater/less boundaries, inclusive-free range), and `break_on_counter` pauses only on every Nth hit; `breakpoint_list` reports the native hit counter. Mutates the target: advances the target generation. Accepts optional expected_target_generation and control_id.",
			schema: objectSchema(map[string]any{
				"cpu":                        enumProperty("Processor to break.", []string{"m68k", "z80"}),
				"address":                    addressProperty(),
				"condition":                  enumProperty("Location condition. equal breaks at exactly `address`; greater/less break above/below it; range breaks inside `address` (exclusive lower bound) and `range_end` (exclusive upper bound).", []string{"equal", "greater", "less", "range"}),
				"range_end":                  addressProperty(),
				"break_on_counter":           booleanProperty("Only pause on every Nth hit instead of every hit; N comes from break_counter."),
				"break_counter":              integerProperty("Break every Nth hit when break_on_counter is true (default 1).", 1),
				"context":                    contextProperty(),
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
				"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
			}, []string{"cpu", "address"}),
			run: runBreakpointSet,
		},
		{name: "cpu_breakpoint_list", description: "List execution breakpoints created through this MCP process, including enabled state, condition, break-on-counter settings, native hit counters, and creation provenance (context, target generation).", schema: objectSchema(map[string]any{}, nil), run: runBreakpointList},
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
			description: "Create an enabled read and/or write watchpoint owned by this MCP process, recording context provenance. The system pauses when the watched range is accessed. Mutates the target: advances the target generation. Accepts optional expected_target_generation and control_id.",
			schema: objectSchema(map[string]any{
				"cpu":                        enumProperty("Processor to watch.", []string{"m68k", "z80"}),
				"address":                    addressProperty(),
				"length":                     integerProperty("Watched range length in bytes (default 1).", 1),
				"access":                     enumProperty("Access types that trigger the watchpoint.", []string{"read", "write", "any"}),
				"context":                    contextProperty(),
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
				"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
			}, []string{"cpu", "address"}),
			run: runWatchpointSet,
		},
		{name: "cpu_watchpoint_list", description: "List read/write watchpoints created through this MCP process, including hit counters and creation provenance (context, target generation).", schema: objectSchema(map[string]any{}, nil), run: runWatchpointList},
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
		"cpu":                        enumProperty("Processor to control.", []string{"m68k", "z80"}),
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
		return okResult(stampGenerations(payload, before, after), tc.modern)
	}
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
		return okResult(stampGenerations(payload, before, after), tc.modern)
	}
}

type breakpointSetArgs struct {
	CPU            string  `json:"cpu"`
	Address        any     `json:"address"`
	Condition      string  `json:"condition"`
	RangeEnd       any     `json:"range_end"`
	BreakOnCounter bool    `json:"break_on_counter"`
	BreakCounter   *uint64 `json:"break_counter"`
	Context        string  `json:"context"`
	guardArgs
}

func runBreakpointSet(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[breakpointSetArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	address, failure := parseAddress(parsed.Address)
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
		if rangeEnd, failure = parseAddress(parsed.RangeEnd); failure != nil {
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
	if id, ok := payload["breakpoint_id"].(float64); ok {
		tc.server.trackDebugResource("breakpoint", uint64(id), debugResourceMeta{
			ContextID:        context.ID,
			ControlID:        parsed.ControlID,
			TargetGeneration: after,
			CreatedAt:        time.Now().UTC(),
			ROMPath:          tc.server.currentROMPath(),
		})
	}
	return okResult(stampGenerations(payload, before, after), tc.modern)
}

func runBreakpointList(tc toolContext, _ json.RawMessage) map[string]any {
	payload, failure := tc.server.executeCommand(tc.ctx, "breakpoint_list", nil)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	annotateDebugList(payload, "breakpoint", "breakpoints", "breakpoint_id", tc.server)
	return okResult(payload, tc.modern)
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
	CPU     string  `json:"cpu"`
	Address any     `json:"address"`
	Length  *uint64 `json:"length"`
	Access  string  `json:"access"`
	Context string  `json:"context"`
	guardArgs
}

func runWatchpointSet(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[watchpointSetArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	address, failure := parseAddress(parsed.Address)
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
	params := map[string]string{
		"cpu":     parsed.CPU,
		"address": strconv.FormatUint(address, 10),
		"access":  parsed.Access,
	}
	if parsed.Length != nil {
		params["length"] = strconv.FormatUint(*parsed.Length, 10)
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
			"access":  parsed.Access,
		},
	})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if id, ok := payload["watchpoint_id"].(float64); ok {
		tc.server.trackDebugResource("watchpoint", uint64(id), debugResourceMeta{
			ContextID:        context.ID,
			ControlID:        parsed.ControlID,
			TargetGeneration: after,
			CreatedAt:        time.Now().UTC(),
			ROMPath:          tc.server.currentROMPath(),
		})
	}
	return okResult(stampGenerations(payload, before, after), tc.modern)
}

func runWatchpointList(tc toolContext, _ json.RawMessage) map[string]any {
	payload, failure := tc.server.executeCommand(tc.ctx, "watchpoint_list", nil)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	annotateDebugList(payload, "watchpoint", "watchpoints", "watchpoint_id", tc.server)
	return okResult(payload, tc.modern)
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
	}
}
