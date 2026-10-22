package mcp

import (
	"encoding/json"
	"fmt"
	"sort"
)

// This file is the single declaration of the deprecated tool aliases
// (roadmap issue #17, catalog consolidation).
//
// One concept per tool: the catalog exposes one canonical implementation per
// concept (target_status, memory_map, cpu_step, debug_instrument, ...). Every
// tool name that predates the consolidation stays registered for one release as
// an alias of the canonical tool, because an agent transcript outlives a server
// version. An alias:
//
//   - keeps its published inputSchema, so existing arguments keep validating
//     exactly as before;
//   - runs the exact handler it ran before, so the payload shape is the shape
//     the caller already parses;
//   - additionally carries a `deprecated` block naming the replacement and the
//     mapping between the two payloads, so a caller can migrate from the
//     response alone.
//
// toolAliasRecords is authoritative: the registry test proves every alias is
// registered, every replacement is a canonical (non-alias) tool, and every
// alias response carries a well-formed `deprecated` block.

// aliasDeprecatedCode is the success-payload marker of an alias response. Like
// artifact_describe_deprecated it is a warning marker, not an error code: the
// call succeeded, and the marker tells the caller which tool to migrate to.
const aliasDeprecatedCode = "tool_alias_deprecated"

// aliasRemovalPolicy is published in every alias response so a client can decide
// when to migrate instead of guessing.
const aliasRemovalPolicy = "The alias stays available for one release and is removed afterwards."

// toolAliasRecord declares one deprecated tool name.
type toolAliasRecord struct {
	// Alias is the legacy tool name that stays registered.
	Alias string
	// Replacement is the canonical tool that now owns the concept.
	Replacement string
	// Mapping states, for a caller reading one response, which canonical field
	// carries the alias' payload (or how the alias payload is composed).
	Mapping string
}

// toolAliasRecords declares every deprecated alias in the catalog.
var toolAliasRecords = []toolAliasRecord{
	{
		Alias:       "bridge_status",
		Replacement: "target_status",
		Mapping:     "bridge_status returns the legacy flat bridge object; target_status.bridge carries the same fields.",
	},
	{
		Alias:       "emulator_status",
		Replacement: "target_status",
		Mapping:     "emulator_status returns the legacy flat object; target_status.run_state, devices and rom carry the same fields (modules and devices move under devices).",
	},
	{
		Alias:       "mega_drive_memory_map",
		Replacement: "memory_map",
		Mapping:     "mega_drive_memory_map returns the legacy {regions, note, live_spaces} object; memory_map.reference carries the same fields.",
	},
	{
		Alias:       "state_diff",
		Replacement: "snapshot_diff",
		Mapping:     "state_diff returns the legacy state comparison payload; snapshot_diff{sections:[\"state\"], snapshot_before_id, snapshot_after_id} returns the same payload under results.state.",
	},
	{
		Alias:       "memory_diff",
		Replacement: "snapshot_diff",
		Mapping:     "memory_diff returns the legacy memory comparison payload; snapshot_diff{sections:[\"memory\"], ...} accepts the same arguments and returns the same payload (and cursor family) under results.memory.",
	},
	{
		Alias:       "memory_snapshot_capture",
		Replacement: "capture",
		Mapping:     "memory_snapshot_capture returns the legacy paused range capture; capture{components:[\"memory\"], space, ranges} returns the same capture_id, manifest, ranges and artifacts, with the producer payload under detail.",
	},
	{
		Alias:       "system_snapshot_capture",
		Replacement: "capture",
		Mapping:     "system_snapshot_capture returns the legacy system snapshot; capture{components:[\"memory\",\"registers\",\"vdp\",\"frame\",...], ranges} captures the same components and returns the same capture_id and artifacts, with the producer payload under detail.",
	},
	{
		Alias:       "vdp_capture",
		Replacement: "capture",
		Mapping:     "vdp_capture returns the legacy VDP capture; capture{components:[\"vdp\",\"frame\",\"cram\",\"vsram\",\"vram\",\"sprites\"]} captures the same components and returns the same capture_id and artifacts, with the producer payload under detail.",
	},
	{
		Alias:       "frame_capture",
		Replacement: "capture",
		Mapping:     "frame_capture returns one PNG artifact without a capture index entry; capture{components:[\"frame\"], mode:atomic} stores the same frame inside a tracked VDP capture and returns its capture_id and manifest. Resolve the frame with capture_get or artifact_list{capture_id}.",
	},
	{
		Alias:       "vdp_tile_export",
		Replacement: "vdp_render_export",
		Mapping:     "vdp_tile_export returns the legacy {summary, artifacts} payload; vdp_render_export{mode:\"tiles\", ...} runs the same render and returns the same payload with mode and, when requested, crop.",
	},
	{
		Alias:       "vdp_plane_export",
		Replacement: "vdp_render_export",
		Mapping:     "vdp_plane_export returns the legacy {summary, artifacts} payload; vdp_render_export{mode:\"plane\", plane, ...} runs the same render and returns the same payload with mode and, when requested, crop.",
	},
	{
		Alias:       "vdp_memory_export",
		Replacement: "vdp_memory_read",
		Mapping:     "vdp_memory_export returns the legacy artifact payload; vdp_memory_read{output:\"artifact\", ...} returns the same artifact descriptor and provenance with an output echo.",
	},
	{
		Alias:       "target_audit_log",
		Replacement: "events_list",
		Mapping:     "target_audit_log returns the global audit page; events_list{kinds:[\"audit\"], ...} returns the same page under sections.audit with the same cursor family.",
	},
	{
		Alias:       "context_mutation_log",
		Replacement: "events_list",
		Mapping:     "context_mutation_log returns one context's mutation trail without control-lock lifecycle events; events_list{kinds:[\"mutation\"], context:...} returns the same page under sections.mutation.",
	},
	{
		Alias:       "cpu_debug_events_list",
		Replacement: "events_list",
		Mapping:     "cpu_debug_events_list returns the debug stop-event page; events_list{kinds:[\"debug\"], ...} accepts the same filters and offset and returns the same page under sections.debug plus an id-based next_cursor.",
	},
	{
		Alias:       "cpu_breakpoint_set",
		Replacement: "debug_instrument",
		Mapping:     "cpu_breakpoint_set returns its legacy {breakpoint_id, ...} payload; debug_instrument{action:\"set\", kind:\"breakpoint\", ...} performs the same create and returns it under result.",
	},
	{
		Alias:       "cpu_breakpoint_list",
		Replacement: "debug_instrument",
		Mapping:     "cpu_breakpoint_list returns its legacy {breakpoints, ...} payload; debug_instrument{action:\"list\", kind:\"breakpoint\"} performs the same listing and returns it under result.",
	},
	{
		Alias:       "cpu_breakpoint_remove",
		Replacement: "debug_instrument",
		Mapping:     "cpu_breakpoint_remove returns its legacy payload; debug_instrument{action:\"remove\", kind:\"breakpoint\", breakpoint_id} performs the same removal and returns it under result with instrument_id.",
	},
	{
		Alias:       "cpu_watchpoint_set",
		Replacement: "debug_instrument",
		Mapping:     "cpu_watchpoint_set returns its legacy {watchpoint_id, ...} payload; debug_instrument{action:\"set\", kind:\"watchpoint\", ...} performs the same create and returns it under result.",
	},
	{
		Alias:       "cpu_watchpoint_list",
		Replacement: "debug_instrument",
		Mapping:     "cpu_watchpoint_list returns its legacy {watchpoints, ...} payload; debug_instrument{action:\"list\", kind:\"watchpoint\"} performs the same listing and returns it under result.",
	},
	{
		Alias:       "cpu_watchpoint_remove",
		Replacement: "debug_instrument",
		Mapping:     "cpu_watchpoint_remove returns its legacy payload; debug_instrument{action:\"remove\", kind:\"watchpoint\", watchpoint_id} performs the same removal and returns it under result with instrument_id.",
	},
	{
		Alias:       "run_until_breakpoint",
		Replacement: "debug_instrument",
		Mapping:     "run_until_breakpoint returns its legacy stop-evidence payload; debug_instrument{action:\"set\", kind:\"breakpoint\", run_until:true, ...} performs the same one-shot window and returns it under result with instrument_id (the legacy resource_id).",
	},
	{
		Alias:       "run_until_watchpoint",
		Replacement: "debug_instrument",
		Mapping:     "run_until_watchpoint returns its legacy stop-evidence payload; debug_instrument{action:\"set\", kind:\"watchpoint\", run_until:true, ...} performs the same one-shot window and returns it under result with instrument_id (the legacy resource_id).",
	},
	{
		Alias:       "m68k_step",
		Replacement: "cpu_step",
		Mapping:     "m68k_step returns the legacy synchronous M68K single-step payload; cpu_step{cpu:\"m68k\", mode:\"instruction\"} runs the same native action and adds mode (and cpu, which the native echo already carries).",
	},
	{
		Alias:       "z80_step",
		Replacement: "cpu_step",
		Mapping:     "z80_step returns the legacy synchronous Z80 single-step payload; cpu_step{cpu:\"z80\", mode:\"instruction\"} runs the same native action and adds mode.",
	},
	{
		Alias:       "cpu_step_over",
		Replacement: "cpu_step",
		Mapping:     "cpu_step_over returns the legacy step_over payload; cpu_step{cpu:..., mode:\"over\"} runs the same native action and adds mode (plus step_completion only when timeout_ms is supplied).",
	},
	{
		Alias:       "cpu_step_out",
		Replacement: "cpu_step",
		Mapping:     "cpu_step_out returns the legacy step_out payload; cpu_step{cpu:..., mode:\"out\"} runs the same native action and adds mode (plus step_completion only when timeout_ms is supplied).",
	},
	{
		Alias:       "m68k_disassemble",
		Replacement: "disassemble",
		Mapping:     "m68k_disassemble returns the legacy M68K sweep payload; disassemble{cpu:\"m68k\", ...} accepts the same address/addresses/count/context arguments and returns the same payload.",
	},
	{
		Alias:       "z80_disassemble",
		Replacement: "disassemble",
		Mapping:     "z80_disassemble returns the legacy Z80 sweep payload; disassemble{cpu:\"z80\", ...} accepts the same address/addresses/count/context arguments and returns the same payload.",
	},
	{
		Alias:       "m68k_read_memory",
		Replacement: "memory_read",
		Mapping:     "m68k_read_memory returns the legacy inline read object; memory_read{cpu:\"m68k\", address, length, ...} returns the same bytes with the same byte order for space m68k-bus, plus cpu and the requested_*/effective_* echo.",
	},
	{
		Alias:       "z80_read_memory",
		Replacement: "memory_read",
		Mapping:     "z80_read_memory returns the legacy inline read object; memory_read{cpu:\"z80\", address, length, ...} returns the same bytes with the same byte order for space z80-bus, plus cpu and the requested_*/effective_* echo.",
	},
	{
		Alias:       "memory_spaces_list",
		Replacement: "memory_map",
		Mapping:     "memory_spaces_list returns the legacy {spaces, byte_order_policy, bus_address_formula} object; memory_map.live carries the same fields.",
	},
	{
		Alias:       "target_info",
		Replacement: "target_status",
		Mapping:     "target_info returns the legacy flat object; target_status.emulator, devices, platform and rom (rom.summary) carry the same fields.",
	},
}

// toolAliasByName indexes the records so the alias wrapper cannot drift from the
// declaration.
var toolAliasByName = func() map[string]toolAliasRecord {
	index := make(map[string]toolAliasRecord, len(toolAliasRecords))
	for _, record := range toolAliasRecords {
		index[record.Alias] = record
	}
	return index
}()

// aliasRun wraps the unchanged legacy handler of one deprecated tool so its
// successful and failed payloads both name the replacement.
func aliasRun(tool string, legacy func(toolContext, json.RawMessage) map[string]any) func(toolContext, json.RawMessage) map[string]any {
	return func(tc toolContext, args json.RawMessage) map[string]any {
		return attachAliasDeprecation(legacy(tc, args), tool)
	}
}

// attachAliasDeprecation adds the `deprecated` block to a completed alias
// result. Both encodings are patched: structuredContent for modern clients and
// the JSON text content for legacy clients. A failure text such as
// "invalid_params: ..." is not JSON and is left alone; the structured payload
// still carries the marker.
func attachAliasDeprecation(result map[string]any, tool string) map[string]any {
	if result == nil {
		return result
	}
	record, present := toolAliasByName[tool]
	if !present {
		// A registered alias without a record is a defect the registry test
		// catches; never publish a half-formed migration hint.
		record = toolAliasRecord{Alias: tool, Replacement: "unregistered_alias"}
	}
	block := map[string]any{
		"code":        aliasDeprecatedCode,
		"tool":        record.Alias,
		"replacement": record.Replacement,
		"removal":     aliasRemovalPolicy,
		"message":     fmt.Sprintf("%s is a deprecated alias of %s and returns its legacy payload shape. Use %s; the alias is removed after one release.", record.Alias, record.Replacement, record.Replacement),
	}
	if record.Mapping != "" {
		block["mapping"] = record.Mapping
	}
	if structured, ok := result["structuredContent"].(map[string]any); ok {
		structured["deprecated"] = block
	}
	content, ok := result["content"].([]map[string]string)
	if !ok || len(content) == 0 {
		return result
	}
	var value map[string]any
	if json.Unmarshal([]byte(content[0]["text"]), &value) != nil {
		return result
	}
	value["deprecated"] = block
	if encoded, err := json.Marshal(value); err == nil {
		content[0]["text"] = string(encoded)
	}
	return result
}

// aliasToolNames returns the sorted alias names, for diagnostics and tests.
func aliasToolNames() []string {
	names := make([]string, 0, len(toolAliasRecords))
	for _, record := range toolAliasRecords {
		names = append(names, record.Alias)
	}
	sort.Strings(names)
	return names
}

// deprecationAnnotation renders the machine-readable migration marker published
// next to an alias' inputSchema, so a client can warn before calling it.
func deprecationAnnotation(tool string) map[string]any {
	record, present := toolAliasByName[tool]
	if !present {
		return nil
	}
	return map[string]any{
		"replacement": record.Replacement,
		"removal":     aliasRemovalPolicy,
		"mapping":     record.Mapping,
	}
}
