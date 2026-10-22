package mcp

import (
	"encoding/json"
	"fmt"
	"sort"
)

// trace is the single trace-capture tool (roadmap issue #17). One concept:
// "record what the processor executes". Two arguments select which capture runs:
//
//   - analyze: trace records an instruction trace artifact; coverage turns the
//     same native trace into a coverage artifact with instruction-aware blocks,
//     execution counts and observed edges;
//   - until: window captures a bounded time window; watchpoint runs until a
//     managed watchpoint hits and keeps the instructions that led to the hit.
//
// Every combination maps to the handler that owned it, so the trace text/JSONL
// contract (#5), provenance, guards and stop evidence are unchanged. Arguments a
// combination does not consume are rejected. Retained trace-session events are a
// different concept: query them with trace_session_query.

const (
	traceAnalyzeTrace    = "trace"
	traceAnalyzeCoverage = "coverage"

	traceUntilWindow     = "window"
	traceUntilWatchpoint = "watchpoint"
)

// traceAnalyzeVocab and traceUntilVocab are the closed selectors of trace.
var (
	traceAnalyzeVocab = newEnumVocab("analyze", traceAnalyzeTrace, traceAnalyzeCoverage)
	traceUntilVocab   = newEnumVocab("until", traceUntilWindow, traceUntilWatchpoint)
)

type traceArgs struct {
	Analyze           string  `json:"analyze"`
	Until             string  `json:"until"`
	CPU               string  `json:"cpu"`
	WatchpointID      *uint64 `json:"watchpoint_id"`
	TimeoutMS         *uint64 `json:"timeout_ms"`
	MaxEntries        uint64  `json:"max_entries"`
	AddressRangeStart any     `json:"address_range_start"`
	AddressRangeEnd   any     `json:"address_range_end"`
	AddressSpace      string  `json:"address_space"`
	IncludeROM        *bool   `json:"include_rom"`
	IncludeRAM        *bool   `json:"include_ram"`
	RetainRepeated    *bool   `json:"retain_repeated"`
	Context           string  `json:"context"`
	guardArgs
}

func traceSpec() toolSpec {
	return toolSpec{
		name:        "trace",
		description: "Record what the processor executes. analyze \"trace\" (default) captures an instruction trace artifact plus a versioned JSONL artifact (PC, opcode bytes, mnemonic, cycle, control flow, frame token where available); analyze \"coverage\" turns the same native capture into a coverage artifact with instruction-aware blocks, execution counts and observed edges. until \"window\" (default) captures a bounded time window; until \"watchpoint\" runs until the given managed watchpoint hits and captures the instructions that led to the hit (watchpoint_id; implies until=watchpoint when cpu is omitted). Both forms run the system for the window and restore the prior run state, so the capture mutates the target and advances the target generation. Optional address_range_start/end, include_rom/include_ram and retain_repeated filter the result and are recorded in provenance. Accepts optional expected_target_generation and control_id. Retained trace-session events are queried with trace_session_query, not captured here.",
		schema: objectSchema(map[string]any{
			"analyze":                    traceAnalyzeVocab.property("What to produce: trace (instruction trace) or coverage (coverage artifact) (default trace)."),
			"until":                      traceUntilVocab.property("What ends the capture: window (a bounded time window, default) or watchpoint (run until the given watchpoint hits)."),
			"cpu":                        cpuVocab.property("Processor to trace (required for until=window; a watchpoint capture carries the processor on the watchpoint)."),
			"watchpoint_id":              integerProperty("Managed watchpoint to run toward with until=watchpoint.", 1),
			"timeout_ms":                 integerProperty("Capture window in milliseconds (default 5000 for a window capture, 500 for coverage, cap 30000; coverage caps the window at 5000).", 1),
			"max_entries":                integerProperty(fmt.Sprintf("Maximum entries retained (default %d, cap %d).", defaultTraceEntries, maxTraceEntries), 1),
			"address_range_start":        addressProperty(),
			"address_range_end":          addressProperty(),
			"include_rom":                booleanProperty("Include ROM addresses when filtering (default true)."),
			"include_ram":                booleanProperty("Include RAM addresses when filtering (default true)."),
			"retain_repeated":            booleanProperty("Retain repeated PC events (default true); with analyze=coverage, false counts only distinct addresses."),
			"context":                    contextProperty(),
			"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
			"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
		}, nil),
		run: runTrace,
	}
}

func runTrace(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[traceArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	analyze, failure := traceAnalyzeVocab.resolve(parsed.Analyze, traceAnalyzeTrace)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	until, failure := resolveTraceUntil(*parsed)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	raw, failure := decodeArgumentMap(args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if failure := validateTraceArguments(raw, analyze, until, *parsed); failure != nil {
		return failureResult(failure, tc.modern)
	}

	var payload map[string]any
	switch {
	case analyze == traceAnalyzeCoverage:
		arguments := map[string]any{
			"cpu":             parsed.CPU,
			"max_entries":     parsed.MaxEntries,
			"region_start":    parsed.AddressRangeStart,
			"region_end":      parsed.AddressRangeEnd,
			"include_rom":     parsed.IncludeROM,
			"include_ram":     parsed.IncludeRAM,
			"retain_repeated": parsed.RetainRepeated,
			"context":         parsed.Context,
		}
		if parsed.AddressSpace != "" {
			arguments["address_space"] = parsed.AddressSpace
		}
		if parsed.TimeoutMS != nil {
			arguments["duration_ms"] = *parsed.TimeoutMS
		}
		putGuardArguments(arguments, parsed.ControlID, parsed.ExpectedTargetGeneration)
		payload, failure = composeTool(tc, runCpuCoverageCapture, arguments)
	case until == traceUntilWatchpoint:
		arguments := map[string]any{
			"watchpoint_id": *parsed.WatchpointID,
			"max_entries":   parsed.MaxEntries,
			"context":       parsed.Context,
		}
		if parsed.TimeoutMS != nil {
			arguments["timeout_ms"] = *parsed.TimeoutMS
		}
		putGuardArguments(arguments, parsed.ControlID, parsed.ExpectedTargetGeneration)
		payload, failure = composeTool(tc, runCpuTraceCaptureWatchpoint, arguments)
	default:
		arguments := map[string]any{
			"cpu":                 parsed.CPU,
			"max_entries":         parsed.MaxEntries,
			"address_range_start": parsed.AddressRangeStart,
			"address_range_end":   parsed.AddressRangeEnd,
			"include_rom":         parsed.IncludeROM,
			"include_ram":         parsed.IncludeRAM,
			"retain_repeated":     parsed.RetainRepeated,
			"context":             parsed.Context,
		}
		if parsed.AddressSpace != "" {
			arguments["address_space"] = parsed.AddressSpace
		}
		if parsed.TimeoutMS != nil {
			arguments["timeout_ms"] = *parsed.TimeoutMS
		}
		putGuardArguments(arguments, parsed.ControlID, parsed.ExpectedTargetGeneration)
		payload, failure = composeTool(tc, runCpuTraceCapture, arguments)
	}
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	return okResult(map[string]any{
		"analyze": analyze,
		"until":   until,
		"result":  payload,
	}, tc.modern)
}

// resolveTraceUntil applies the documented default and the watchpoint inference.
func resolveTraceUntil(parsed traceArgs) (string, *toolFailure) {
	if parsed.Until != "" {
		return traceUntilVocab.resolve(parsed.Until, traceUntilWindow)
	}
	// A watchpoint id with no processor can only mean a watchpoint capture; that
	// keeps the argument meaningful instead of rejecting it as unused.
	if parsed.WatchpointID != nil && parsed.CPU == "" {
		return traceUntilWatchpoint, nil
	}
	return traceUntilWindow, nil
}

// traceConsumers maps each argument to the capture combinations that consume it.
func traceConsumers() map[string][]string {
	return map[string][]string{
		"analyze":                    {"trace/window", "trace/watchpoint", "coverage/window"},
		"until":                      {"trace/window", "trace/watchpoint", "coverage/window"},
		"cpu":                        {"trace/window", "coverage/window"},
		"watchpoint_id":              {"trace/watchpoint"},
		"timeout_ms":                 {"trace/window", "trace/watchpoint", "coverage/window"},
		"max_entries":                {"trace/window", "trace/watchpoint", "coverage/window"},
		"address_range_start":        {"trace/window", "coverage/window"},
		"address_range_end":          {"trace/window", "coverage/window"},
		"address_space":              {"trace/window", "coverage/window"},
		"include_rom":                {"trace/window", "coverage/window"},
		"include_ram":                {"trace/window", "coverage/window"},
		"retain_repeated":            {"trace/window", "coverage/window"},
		"context":                    {"trace/window", "trace/watchpoint", "coverage/window"},
		"expected_target_generation": {"trace/window", "trace/watchpoint", "coverage/window"},
		"control_id":                 {"trace/window", "trace/watchpoint", "coverage/window"},
	}
}

// validateTraceArguments rejects an argument the selected capture does not
// consume, and states the requirements of the selected combination.
func validateTraceArguments(raw map[string]json.RawMessage, analyze, until string, parsed traceArgs) *toolFailure {
	if analyze == traceAnalyzeCoverage && until == traceUntilWatchpoint {
		return &toolFailure{
			Code:    "invalid_params",
			Message: "until=watchpoint is not available with analyze=coverage: coverage summarizes a time window; use until=window and filter the region",
			Data:    map[string]any{"field": "until", "analyze": analyze},
		}
	}
	combination := analyze + "/" + until
	consumers := traceConsumers()
	keys := make([]string, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		appliesTo, known := consumers[key]
		if !known {
			continue
		}
		consumed := false
		for _, candidate := range appliesTo {
			if candidate == combination {
				consumed = true
				break
			}
		}
		if consumed {
			continue
		}
		accepted := []string{}
		for name, candidates := range consumers {
			for _, candidate := range candidates {
				if candidate == combination {
					accepted = append(accepted, name)
					break
				}
			}
		}
		sort.Strings(accepted)
		return &toolFailure{
			Code:    "unsupported_parameter",
			Message: fmt.Sprintf("%q is not consumed by trace{analyze:%q, until:%q}", key, analyze, until),
			Data: map[string]any{
				"field":           key,
				"path":            "$." + key,
				"analyze":         analyze,
				"until":           until,
				"accepted_fields": accepted,
			},
		}
	}
	switch {
	case until == traceUntilWatchpoint:
		if parsed.WatchpointID == nil || *parsed.WatchpointID == 0 {
			return &toolFailure{Code: "invalid_params", Message: "watchpoint_id is required with until=watchpoint", Data: map[string]any{"field": "watchpoint_id"}}
		}
	default:
		if parsed.CPU == "" {
			return &toolFailure{Code: "invalid_params", Message: "cpu is required for until=window", Data: map[string]any{"field": "cpu"}}
		}
	}
	if analyze == traceAnalyzeCoverage && parsed.TimeoutMS != nil && *parsed.TimeoutMS > 5000 {
		return &toolFailure{
			Code:    "invalid_params",
			Message: "analyze=coverage caps the capture window at 5000 ms",
			Data:    map[string]any{"field": "timeout_ms", "max": 5000},
		}
	}
	return nil
}
