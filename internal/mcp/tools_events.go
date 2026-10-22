package mcp

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// events_list is the single event-query tool (roadmap issue #17). One concept:
// "what happened on this target". kinds selects which event streams to read, and
// every stream keeps the behavior it had as its own tool:
//
//   - audit (default): the global target audit stream (target_audit_log);
//   - mutation: one context's mutation trail without control-lock lifecycle
//     events (context_mutation_log);
//   - debug: structured breakpoint/watchpoint stop events (cpu_debug_events_list);
//   - trace: retained trace-session events through the shared cursor/limit view
//     (trace_session_events keeps the full filter surface under
//     trace_session_query);
//   - run_state: the target audit rows recorded for externally observed run-state
//     transitions (the run_state_change entries the audit stream already holds).
//
// Paging is #11 paging: a cursor names a position in the stream's own ordering
// key (audit operation id, debug event id, trace store sequence) and carries the
// query, so a later page needs only the cursor. A cursor is unambiguous only for
// one stream, so it is accepted with exactly one kind; a multi-kind call returns
// one independent page per stream, each with its own next_cursor.

// eventKinds is the closed kind vocabulary. audit is first so a schema-only
// probe of `kinds` reads the cheapest stream.
var eventKinds = newEnumVocab("kinds", "audit", "mutation", "debug", "trace", "run_state")

// debugEventsCursorPrefix is the cursor family of the debug event stream read
// through events_list; cpu_debug_events_list itself pages by offset.
const debugEventsCursorPrefix = "dbg1."

type eventsListArgs struct {
	Kinds         []string `json:"kinds"`
	Cursor        string   `json:"cursor"`
	Limit         uint64   `json:"limit"`
	Offset        uint64   `json:"offset"`
	Tool          string   `json:"tool"`
	ControlID     string   `json:"control_id"`
	GenerationMin uint64   `json:"generation_min"`
	GenerationMax uint64   `json:"generation_max"`
	Since         string   `json:"since"`
	Until         string   `json:"until"`
	ResourceKind  string   `json:"resource_kind"`
	ResourceID    uint64   `json:"resource_id"`
	CPU           string   `json:"cpu"`
	Direction     string   `json:"direction"`
	EventIDMin    uint64   `json:"event_id_min"`
	EventIDMax    uint64   `json:"event_id_max"`
	Context       string   `json:"context"`
}

func eventsListSpec() toolSpec {
	return toolSpec{
		name:        "events_list",
		description: "Query the target's event streams. kinds selects the streams; when it is omitted the streams addressed by the supplied filters are read (audit by default, debug when only debug filters are supplied): audit is the global target audit stream (every mutation outcome, generation/control conflict, control-lock lifecycle event, and run-state transition, newest first); mutation is one context's mutation trail without control-lock lifecycle events; debug is the structured breakpoint/watchpoint stop events; trace is the retained trace-session event stream through the shared limit/cursor view (use trace_session_query for the full trace filter surface, exports, and histograms); run_state is the audit rows recorded for externally observed run-state transitions. Filters apply to the streams that publish them: tool/control_id/generation_min/generation_max/since/until for audit and run_state, resource_kind/resource_id/cpu/direction/event_id_min/event_id_max for debug, context/limit/offset/cursor for all. A filter that no requested kind consumes is rejected. Paging is cursor-based (audit operation id, debug event id, trace store sequence): a cursor carries the query and the position, so a later page needs only the cursor, and a cursor is accepted with exactly one kind. " + cursorSteppingNote + " " + pagingNote,
		schema: objectSchema(map[string]any{
			"kinds": map[string]any{
				"type":        "array",
				"description": "Event streams to read (default [\"audit\"]). Each requested kind returns one independent section.",
				"items":       map[string]any{"type": "string", "enum": eventKinds.values},
				"minItems":    1,
			},
			"limit":          integerProperty("Page size per stream (audit default 50, cap 200; debug default 20, cap 100; trace and mutation use their own default when omitted).", 1),
			"offset":         integerProperty("Skip this many matching entries in the selected streams (default 0). Mutually exclusive with cursor.", 0),
			"tool":           stringProperty("Audit filter: only entries recorded by this tool name. run_state pins its own tool filter."),
			"control_id":     stringProperty("Audit filter: only entries authorized by this control-lock id."),
			"generation_min": integerProperty("Audit filter: only entries whose before/after target generation is at least this value.", 0),
			"generation_max": integerProperty("Audit filter: only entries whose before/after target generation is at most this value.", 0),
			"since":          stringProperty("Audit filter: only entries at or after this UTC RFC3339 timestamp."),
			"until":          stringProperty("Audit filter: only entries at or before this UTC RFC3339 timestamp."),
			"resource_kind":  debugEventResourceKindVocab.property("Debug filter: resource kind of the stop event."),
			"resource_id":    integerProperty("Debug filter: managed resource id.", 1),
			"cpu":            cpuVocab.property("Debug filter: processor."),
			"direction":      debugEventDirectionVocab.property("Debug filter: the OBSERVED access direction. \"any\" matches every event, including events whose direction could not be observed."),
			"event_id_min":   integerProperty("Debug filter: only events with an id at or above this value.", 1),
			"event_id_max":   integerProperty("Debug filter: only events with an id at or below this value.", 1),
			"cursor":         stringProperty("next_cursor from a previous events_list call of ONE kind. The cursor carries the stream, its query, and the position, so a later page needs only the cursor; any filter supplied alongside it must match the cursor. Omit to start at the newest page; mutually exclusive with offset."),
			"context":        contextProperty(),
		}, nil),
		run: runEventsList,
	}
}

func runEventsList(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[eventsListArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	kinds, failure := resolveEventKinds(parsed)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if failure := validateEventFilters(*parsed, kinds); failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.Cursor != "" && len(kinds) != 1 {
		return failureResult(&toolFailure{
			Code:    "invalid_params",
			Message: "cursor requires exactly one kind: a cursor names a position in one stream's ordering",
			Data:    map[string]any{"field": "cursor", "kinds": kinds},
		}, tc.modern)
	}

	sections := map[string]any{}
	nextCursor := ""
	returned := 0
	hasMore := false
	for _, kind := range kinds {
		payload, failure := runEventSection(tc, *parsed, kind)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		sections[kind] = payload
		if cursor, ok := payload["next_cursor"].(string); ok && cursor != "" {
			hasMore = true
			if len(kinds) == 1 {
				nextCursor = cursor
			}
		}
		if value, ok := numberAsUint64(payload["returned"]); ok {
			returned += int(value)
		}
	}

	result := map[string]any{
		"kinds":    kinds,
		"sections": sections,
		"returned": returned,
		"has_more": hasMore,
		"note":     "Each section is the payload of the stream that owns the concept, including its own totals, filters and next_cursor. A multi-kind call returns one independent page per stream; pass a cursor with exactly one kind to page a stream to exhaustion.",
	}
	if len(kinds) == 1 {
		section, _ := sections[kinds[0]].(map[string]any)
		for _, key := range []string{"total", "truncated"} {
			if value, present := section[key]; present {
				result[key] = value
			}
		}
		if nextCursor != "" {
			result["next_cursor"] = nextCursor
		} else {
			result["next_cursor"] = nil
		}
	}
	return okResult(result, tc.modern)
}

// resolveEventKinds validates and de-duplicates the requested kinds, applying the
// documented default: without an explicit selection, the streams the supplied
// filters address are read (audit by default). Inferring from the filters keeps
// every published filter meaningful: a stream-specific filter is never accepted
// and then ignored.
func resolveEventKinds(parsed *eventsListArgs) ([]string, *toolFailure) {
	requested := parsed.Kinds
	if len(requested) == 0 {
		return inferEventKinds(*parsed), nil
	}
	seen := map[string]bool{}
	kinds := make([]string, 0, len(requested))
	for _, kind := range requested {
		if failure := eventKinds.validate(kind); failure != nil {
			return nil, failure
		}
		if seen[kind] {
			return nil, &toolFailure{
				Code:    "invalid_params",
				Message: fmt.Sprintf("kinds lists %q twice; request each stream once", kind),
				Data:    map[string]any{"field": "kinds", "value": kind},
			}
		}
		seen[kind] = true
		kinds = append(kinds, kind)
	}
	return kinds, nil
}

// eventFilterConsumers maps each filter argument to the streams that consume it.
func eventFilterConsumers() map[string][]string {
	return map[string][]string{
		"limit":          {"audit", "mutation", "debug", "trace", "run_state"},
		"offset":         {"audit", "mutation", "debug", "run_state"},
		"context":        {"audit", "mutation", "debug", "trace", "run_state"},
		"cursor":         {"audit", "mutation", "debug", "trace", "run_state"},
		"tool":           {"audit"},
		"control_id":     {"audit", "run_state"},
		"generation_min": {"audit", "run_state"},
		"generation_max": {"audit", "run_state"},
		"since":          {"audit", "run_state"},
		"until":          {"audit", "run_state"},
		"resource_kind":  {"debug"},
		"resource_id":    {"debug"},
		"cpu":            {"debug"},
		"direction":      {"debug"},
		"event_id_min":   {"debug"},
		"event_id_max":   {"debug"},
	}
}

// validateEventFilters rejects a filter that none of the requested streams
// consumes, and states the filters the selection does consume.
func validateEventFilters(parsed eventsListArgs, kinds []string) *toolFailure {
	consumers := eventFilterConsumers()
	supplied := make([]string, 0, len(consumers))
	if parsed.Limit != 0 {
		supplied = append(supplied, "limit")
	}
	if parsed.Offset != 0 {
		supplied = append(supplied, "offset")
	}
	if parsed.Context != "" {
		supplied = append(supplied, "context")
	}
	if parsed.Cursor != "" {
		supplied = append(supplied, "cursor")
	}
	if parsed.Tool != "" {
		supplied = append(supplied, "tool")
	}
	if parsed.ControlID != "" {
		supplied = append(supplied, "control_id")
	}
	if parsed.GenerationMin != 0 {
		supplied = append(supplied, "generation_min")
	}
	if parsed.GenerationMax != 0 {
		supplied = append(supplied, "generation_max")
	}
	if parsed.Since != "" {
		supplied = append(supplied, "since")
	}
	if parsed.Until != "" {
		supplied = append(supplied, "until")
	}
	if parsed.ResourceKind != "" {
		supplied = append(supplied, "resource_kind")
	}
	if parsed.ResourceID != 0 {
		supplied = append(supplied, "resource_id")
	}
	if parsed.CPU != "" {
		supplied = append(supplied, "cpu")
	}
	if parsed.Direction != "" {
		supplied = append(supplied, "direction")
	}
	if parsed.EventIDMin != 0 {
		supplied = append(supplied, "event_id_min")
	}
	if parsed.EventIDMax != 0 {
		supplied = append(supplied, "event_id_max")
	}
	requested := map[string]bool{}
	for _, kind := range kinds {
		requested[kind] = true
	}
	sort.Strings(supplied)
	for _, name := range supplied {
		consumed := false
		for _, kind := range consumers[name] {
			if requested[kind] {
				consumed = true
				break
			}
		}
		if consumed {
			continue
		}
		return &toolFailure{
			Code:    "unsupported_parameter",
			Message: fmt.Sprintf("%q is not consumed by any requested kind (%s); it applies to %s", name, strings.Join(kinds, ","), strings.Join(consumers[name], ",")),
			Data: map[string]any{
				"field":           name,
				"kinds":           kinds,
				"consumed_by":     consumers[name],
				"accepted_fields": eventAcceptedFields(kinds),
				"path":            "$." + name,
			},
		}
	}
	if requested["run_state"] && parsed.Tool != "" && parsed.Tool != "run_state_change" {
		return &toolFailure{
			Code:    "invalid_params",
			Message: fmt.Sprintf("kind run_state reads the run_state_change audit entries; tool %q would select a different stream", parsed.Tool),
			Data:    map[string]any{"field": "tool", "value": parsed.Tool},
		}
	}
	return nil
}

// eventAcceptedFields renders the filters the requested kinds consume, for the
// structured rejection of an inapplicable one.
func eventAcceptedFields(kinds []string) []string {
	requested := map[string]bool{}
	for _, kind := range kinds {
		requested[kind] = true
	}
	accepted := []string{"kinds"}
	for name, consumers := range eventFilterConsumers() {
		for _, kind := range consumers {
			if requested[kind] {
				accepted = append(accepted, name)
				break
			}
		}
	}
	sort.Strings(accepted)
	return accepted
}

// runEventSection renders one stream's page.
func runEventSection(tc toolContext, parsed eventsListArgs, kind string) (map[string]any, *toolFailure) {
	switch kind {
	case "mutation":
		return composeTool(tc, runMutationLog, map[string]any{
			"context": parsed.Context,
			"limit":   optionalPositive(parsed.Limit),
			"cursor":  parsed.Cursor,
			"offset":  parsed.Offset,
		})
	case "debug":
		return runDebugEventsSection(tc, parsed)
	case "trace":
		return composeTool(tc, runTraceSessionEvents, map[string]any{
			"limit":   optionalPositive(parsed.Limit),
			"cursor":  parsed.Cursor,
			"context": parsed.Context,
		})
	default:
		tool := parsed.Tool
		if kind == "run_state" {
			tool = "run_state_change"
		}
		return composeTool(tc, runTargetAuditLog, map[string]any{
			"context":        parsed.Context,
			"tool":           tool,
			"control_id":     parsed.ControlID,
			"generation_min": parsed.GenerationMin,
			"generation_max": parsed.GenerationMax,
			"since":          parsed.Since,
			"until":          parsed.Until,
			"offset":         parsed.Offset,
			"limit":          optionalPositive(parsed.Limit),
			"cursor":         parsed.Cursor,
		})
	}
}

// optionalPositive renders an optional page size as either the supplied value or
// nothing, so the stream's own default stays in force.
func optionalPositive(value uint64) any {
	if value == 0 {
		return nil
	}
	return value
}

// debugEventsCursorQuery is the filter identity a debug cursor carries.
type debugEventsCursorQuery struct {
	ResourceKind string `json:"resource_kind,omitempty"`
	ResourceID   uint64 `json:"resource_id,omitempty"`
	CPU          string `json:"cpu,omitempty"`
	Direction    string `json:"direction,omitempty"`
	Context      string `json:"context,omitempty"`
}

// runDebugEventsSection reads the debug event stream through an id-based cursor
// so a page never repeats or skips a row: events are append-only and their ids
// are monotonic, which offsets cannot promise.
func runDebugEventsSection(tc toolContext, parsed eventsListArgs) (map[string]any, *toolFailure) {
	query := debugEventsCursorQuery{
		ResourceKind: parsed.ResourceKind,
		ResourceID:   parsed.ResourceID,
		CPU:          parsed.CPU,
		Direction:    parsed.Direction,
		Context:      parsed.Context,
	}
	eventIDMin := parsed.EventIDMin
	offset := parsed.Offset
	if parsed.Cursor != "" {
		parts, failure := decodeCursor(parsed.Cursor, debugEventsCursorPrefix, 2)
		if failure != nil {
			return nil, failure
		}
		lastID, err := strconv.ParseUint(parts[0], 10, 64)
		if err != nil || lastID == 0 {
			return nil, invalidCursorFailure(fmt.Sprintf("%q is not a cursor this server issued", parsed.Cursor))
		}
		var cursorQuery debugEventsCursorQuery
		if failure := decodeCursorQuery(parts[1], &cursorQuery, parsed.Cursor); failure != nil {
			return nil, failure
		}
		if failure := reconcileDebugCursorQuery(query, cursorQuery); failure != nil {
			return nil, failure
		}
		if offset != 0 {
			return nil, invalidCursorFailure("pass either cursor or offset, not both: the cursor already names the position in the stream")
		}
		if eventIDMin > 0 && eventIDMin <= lastID {
			return nil, cursorConflictFailure("event_id_min", lastID+1, eventIDMin)
		}
		eventIDMin = lastID + 1
	}
	payload, failure := composeTool(tc, runDebugEventsList, map[string]any{
		"offset":        offset,
		"limit":         parsed.Limit,
		"resource_kind": query.ResourceKind,
		"resource_id":   query.ResourceID,
		"cpu":           query.CPU,
		"direction":     query.Direction,
		"event_id_min":  eventIDMin,
		"event_id_max":  parsed.EventIDMax,
		"context":       query.Context,
	})
	if failure != nil {
		return nil, failure
	}
	payload["next_cursor"] = nil
	if truncated, _ := payload["truncated"].(bool); truncated {
		events, _ := payload["events"].([]any)
		if len(events) > 0 {
			if last, ok := events[len(events)-1].(map[string]any); ok {
				if id, ok := numberAsUint64(last["event_id"]); ok {
					encoded, failure := encodeCursorQuery(query)
					if failure != nil {
						return nil, failure
					}
					payload["next_cursor"] = encodeCursor(debugEventsCursorPrefix, strconv.FormatUint(id, 10), encoded)
				}
			}
		}
	}
	return payload, nil
}

// reconcileDebugCursorQuery rejects a filter that contradicts the query the
// cursor carries.
func reconcileDebugCursorQuery(provided, cursor debugEventsCursorQuery) *toolFailure {
	if provided.ResourceKind != "" && provided.ResourceKind != cursor.ResourceKind {
		return cursorConflictFailure("resource_kind", cursor.ResourceKind, provided.ResourceKind)
	}
	if provided.ResourceID != 0 && provided.ResourceID != cursor.ResourceID {
		return cursorConflictFailure("resource_id", cursor.ResourceID, provided.ResourceID)
	}
	if provided.CPU != "" && provided.CPU != cursor.CPU {
		return cursorConflictFailure("cpu", cursor.CPU, provided.CPU)
	}
	if provided.Direction != "" && provided.Direction != cursor.Direction {
		return cursorConflictFailure("direction", cursor.Direction, provided.Direction)
	}
	if provided.Context != "" && provided.Context != cursor.Context {
		return cursorConflictFailure("context", cursor.Context, provided.Context)
	}
	return nil
}

// inferEventKinds derives the default selection from the stream-specific filters
// the caller supplied. Universal filters (limit, offset, context, cursor) do not
// select a stream, so audit stays the default.
func inferEventKinds(parsed eventsListArgs) []string {
	audit := parsed.Tool != "" || parsed.ControlID != "" || parsed.GenerationMin != 0 ||
		parsed.GenerationMax != 0 || parsed.Since != "" || parsed.Until != ""
	debug := parsed.ResourceKind != "" || parsed.ResourceID != 0 || parsed.CPU != "" ||
		parsed.Direction != "" || parsed.EventIDMin != 0 || parsed.EventIDMax != 0
	switch {
	case audit && debug:
		return []string{"audit", "debug"}
	case debug:
		return []string{"debug"}
	default:
		return []string{"audit"}
	}
}
