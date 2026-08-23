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
			description: "Create an enabled exact-address execution breakpoint owned by this MCP process.",
			schema: objectSchema(map[string]any{
				"cpu":     enumProperty("Processor to break.", []string{"m68k", "z80"}),
				"address": addressProperty(),
			}, []string{"cpu", "address"}),
			run: runBreakpointSet,
		},
		{name: "cpu_breakpoint_list", description: "List execution breakpoints created through this MCP process.", schema: objectSchema(map[string]any{}, nil), run: runBreakpointList},
		{
			name:        "cpu_breakpoint_remove",
			description: "Remove one execution breakpoint created through this MCP process.",
			schema:      objectSchema(map[string]any{"breakpoint_id": integerProperty("Breakpoint id returned by cpu_breakpoint_set.", 1)}, []string{"breakpoint_id"}),
			run:         runBreakpointRemove,
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
	CPU     string `json:"cpu"`
	Address any    `json:"address"`
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
	payload, failure := tc.server.executeCommand(tc.ctx, "breakpoint_set", map[string]string{"cpu": parsed.CPU, "address": strconv.FormatUint(address, 10)})
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
