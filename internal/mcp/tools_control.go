package mcp

import (
	"encoding/json"
	"strconv"
)

func controlToolSpecs() []toolSpec {
	return []toolSpec{
		{name: "cpu_pause", description: "Pause the emulated system.", schema: objectSchema(map[string]any{}, nil), run: makeRunCPUControl("", "pause")},
		{name: "cpu_run", description: "Run the emulated system.", schema: objectSchema(map[string]any{}, nil), run: makeRunCPUControl("", "run")},
		{name: "m68k_step", description: "Pause and execute exactly one M68000 instruction.", schema: objectSchema(map[string]any{}, nil), run: makeRunCPUControl("m68k", "step")},
		{name: "z80_step", description: "Pause and execute exactly one Z80 instruction.", schema: objectSchema(map[string]any{}, nil), run: makeRunCPUControl("z80", "step")},
		{
			name:        "cpu_step_over",
			description: "Run the selected processor until Exodus completes the current instruction without entering a call.",
			schema:      objectSchema(map[string]any{"cpu": enumProperty("Processor to control.", []string{"m68k", "z80"})}, []string{"cpu"}),
			run:         makeRunCPUControlFromArgs("step_over"),
		},
		{
			name:        "cpu_step_out",
			description: "Run the selected processor until Exodus returns from the current call frame.",
			schema:      objectSchema(map[string]any{"cpu": enumProperty("Processor to control.", []string{"m68k", "z80"})}, []string{"cpu"}),
			run:         makeRunCPUControlFromArgs("step_out"),
		},
		{
			name:        "cpu_breakpoint_set",
			description: "Create an enabled exact-address execution breakpoint owned by this MCP process. Optional `condition` filters by the processor's program counter (greater/less boundaries, inclusive-free range), and `break_on_counter` pauses only on every Nth hit; `breakpoint_list` reports the native hit counter.",
			schema: objectSchema(map[string]any{
				"cpu":              enumProperty("Processor to break.", []string{"m68k", "z80"}),
				"address":          addressProperty(),
				"condition":        enumProperty("Location condition. equal breaks at exactly `address`; greater/less break above/below it; range breaks inside `address` (exclusive lower bound) and `range_end` (exclusive upper bound).", []string{"equal", "greater", "less", "range"}),
				"range_end":        addressProperty(),
				"break_on_counter": booleanProperty("Only pause on every Nth hit instead of every hit; N comes from break_counter."),
				"break_counter":    integerProperty("Break every Nth hit when break_on_counter is true (default 1).", 1),
			}, []string{"cpu", "address"}),
			run: runBreakpointSet,
		},
		{name: "cpu_breakpoint_list", description: "List execution breakpoints created through this MCP process, including enabled state, condition, break-on-counter settings, and native hit counters.", schema: objectSchema(map[string]any{}, nil), run: runBreakpointList},
		{
			name:        "cpu_breakpoint_remove",
			description: "Remove one execution breakpoint created through this MCP process.",
			schema:      objectSchema(map[string]any{"breakpoint_id": integerProperty("Breakpoint id returned by cpu_breakpoint_set.", 1)}, []string{"breakpoint_id"}),
			run:         runBreakpointRemove,
		},
		{
			name:        "cpu_watchpoint_set",
			description: "Create an enabled read and/or write watchpoint owned by this MCP process. The system pauses when the watched range is accessed.",
			schema: objectSchema(map[string]any{
				"cpu":     enumProperty("Processor to watch.", []string{"m68k", "z80"}),
				"address": addressProperty(),
				"length":  integerProperty("Watched range length in bytes (default 1).", 1),
				"access":  enumProperty("Access types that trigger the watchpoint.", []string{"read", "write", "any"}),
			}, []string{"cpu", "address"}),
			run: runWatchpointSet,
		},
		{name: "cpu_watchpoint_list", description: "List read/write watchpoints created through this MCP process, including hit counters.", schema: objectSchema(map[string]any{}, nil), run: runWatchpointList},
		{
			name:        "cpu_watchpoint_remove",
			description: "Remove one watchpoint created through this MCP process.",
			schema:      objectSchema(map[string]any{"watchpoint_id": integerProperty("Watchpoint id returned by cpu_watchpoint_set.", 1)}, []string{"watchpoint_id"}),
			run:         runWatchpointRemove,
		},
	}
}

func makeRunCPUControl(cpu, action string) func(toolContext, json.RawMessage) map[string]any {
	return func(tc toolContext, _ json.RawMessage) map[string]any {
		params := map[string]string{"action": action}
		if cpu != "" {
			params["cpu"] = cpu
		}
		payload, failure := tc.server.executeCommand(tc.ctx, "cpu_control", params)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		return okResult(payload, tc.modern)
	}
}

type cpuControlArgs struct {
	CPU string `json:"cpu"`
}

func makeRunCPUControlFromArgs(action string) func(toolContext, json.RawMessage) map[string]any {
	return func(tc toolContext, args json.RawMessage) map[string]any {
		parsed, failure := decodeArgs[cpuControlArgs](args)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		payload, failure := tc.server.executeCommand(tc.ctx, "cpu_control", map[string]string{"cpu": parsed.CPU, "action": action})
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		return okResult(payload, tc.modern)
	}
}

type breakpointSetArgs struct {
	CPU            string  `json:"cpu"`
	Address        any     `json:"address"`
	Condition      string  `json:"condition"`
	RangeEnd       any     `json:"range_end"`
	BreakOnCounter bool    `json:"break_on_counter"`
	BreakCounter   *uint64 `json:"break_counter"`
}

func runBreakpointSet(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[breakpointSetArgs](args)
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
	payload, failure := tc.server.executeCommand(tc.ctx, "breakpoint_set", params)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	return okResult(payload, tc.modern)
}

func runBreakpointList(tc toolContext, _ json.RawMessage) map[string]any {
	payload, failure := tc.server.executeCommand(tc.ctx, "breakpoint_list", nil)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	return okResult(payload, tc.modern)
}

type breakpointRemoveArgs struct {
	BreakpointID uint64 `json:"breakpoint_id"`
}

func runBreakpointRemove(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[breakpointRemoveArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.BreakpointID == 0 {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "breakpoint_id must be positive"}, tc.modern)
	}
	payload, failure := tc.server.executeCommand(tc.ctx, "breakpoint_remove", map[string]string{"breakpoint_id": strconv.FormatUint(parsed.BreakpointID, 10)})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	return okResult(payload, tc.modern)
}

type watchpointSetArgs struct {
	CPU     string  `json:"cpu"`
	Address any     `json:"address"`
	Length  *uint64 `json:"length"`
	Access  string  `json:"access"`
}

func runWatchpointSet(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[watchpointSetArgs](args)
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
	payload, failure := tc.server.executeCommand(tc.ctx, "watchpoint_set", params)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	return okResult(payload, tc.modern)
}

func runWatchpointList(tc toolContext, _ json.RawMessage) map[string]any {
	payload, failure := tc.server.executeCommand(tc.ctx, "watchpoint_list", nil)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	return okResult(payload, tc.modern)
}

type watchpointRemoveArgs struct {
	WatchpointID uint64 `json:"watchpoint_id"`
}

func runWatchpointRemove(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[watchpointRemoveArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.WatchpointID == 0 {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "watchpoint_id must be positive"}, tc.modern)
	}
	payload, failure := tc.server.executeCommand(tc.ctx, "watchpoint_remove", map[string]string{"watchpoint_id": strconv.FormatUint(parsed.WatchpointID, 10)})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	return okResult(payload, tc.modern)
}
