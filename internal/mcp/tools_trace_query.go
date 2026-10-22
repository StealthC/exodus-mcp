package mcp

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// trace_session_query is the single trace-session query tool (roadmap issue #17).
// One concept: "read the trace session". include selects the views:
//
//   - status: the live/retained session configuration, native counters, segment
//     table, watch deltas, store totals and loss accounting;
//   - events: the accumulated execution/access events, histogram, watch samples,
//     bounded inline page, JSONL export, and #11 cursor paging.
//
// Both views are the absorbed handlers' own payloads, so draining, loss honesty
// (#5), Cursor paging (#11) and filtering cannot drift. An argument that the
// requested views do not consume is rejected.

// traceSessionQueryViewVocab is the closed view vocabulary. status is first so a
// schema-only probe of include drains and reports without paging.
var traceSessionQueryViewVocab = newEnumVocab("include", "status", "events")

type traceSessionQueryArgs struct {
	Include []string `json:"include"`

	// status view
	SessionID          string `json:"session_id"`
	RequestWatchReport *bool  `json:"request_watch_report"`

	// shared drain controls
	Collect         *bool  `json:"collect"`
	MaxCollectBytes uint64 `json:"max_collect_bytes"`

	// events view
	Kind                 string `json:"kind"`
	AddressRangeStart    any    `json:"address_range_start"`
	AddressRangeEnd      any    `json:"address_range_end"`
	CycleMin             uint64 `json:"cycle_min"`
	CycleMax             uint64 `json:"cycle_max"`
	Stream               string `json:"stream"`
	Direction            string `json:"direction"`
	ValueEquals          *any   `json:"value_equals"`
	ValueMin             *any   `json:"value_min"`
	ValueMax             *any   `json:"value_max"`
	PreviousEquals       *any   `json:"previous_equals"`
	PCStart              any    `json:"pc_start"`
	PCEnd                any    `json:"pc_end"`
	ResolveSymbols       *bool  `json:"resolve_symbols"`
	SequenceMin          uint64 `json:"sequence_min"`
	SequenceMax          uint64 `json:"sequence_max"`
	AddressSpace         string `json:"address_space"`
	Limit                uint64 `json:"limit"`
	IncludeAddressCounts *bool  `json:"include_address_counts"`
	AddressLimit         uint64 `json:"address_limit"`
	Export               bool   `json:"export"`
	Cursor               string `json:"cursor"`
	Context              string `json:"context"`
}

func traceSessionQuerySpec() toolSpec {
	properties := map[string]any{
		"include": map[string]any{
			"type":        "array",
			"description": "Views to return (default: the views the supplied arguments address, otherwise both). status reports the session and drains sealed segments; events returns the accumulated events with filters, histogram and cursor paging.",
			"items":       map[string]any{"type": "string", "enum": traceSessionQueryViewVocab.values},
			"minItems":    1,
		},
	}
	// The two view schemas are copied from the tools that own them, so a merged
	// argument can never mean something different from the view's own contract.
	for _, spec := range traceSessionToolSpecs() {
		if spec.name != "trace_session_status" && spec.name != "trace_session_events" {
			continue
		}
		for key, value := range schemaProperties(spec.schema) {
			properties[key] = value
		}
	}
	return toolSpec{
		name:        "trace_session_query",
		description: "Query the trace session. include selects the views (default: the views the supplied arguments address, otherwise both). status reports the live or retained session and, by default, drains every sealed native segment first (draining never disarms capture); it carries the session configuration, native counters, per-segment table, watched read/write deltas, bounded store totals, and the machine-readable loss object, whose complete flag is only true for an ended, unsampled capture. events returns the accumulated execution events and histogram, watch-counter samples, and per-occurrence read/write access records with the full filter surface, an optional JSONL export, and cursor paging in capture order: a cursor carries the session and the event filter, so a later page needs only the cursor and pages advance to exhaustion instead of repeating the oldest window. Neither view pauses the system. An argument the requested views do not consume is rejected. trace_session_start/stop/recover stay separate tools: they mutate the session, not the query.",
		schema:      objectSchema(properties, nil),
		run:         runTraceSessionQuery,
	}
}

func runTraceSessionQuery(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[traceSessionQueryArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	views, failure := resolveTraceQueryViews(parsed)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	raw, failure := decodeArgumentMap(args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if failure := validateTraceQueryArguments(raw, views); failure != nil {
		return failureResult(failure, tc.modern)
	}

	sections := map[string]any{}
	returned := 0
	hasMore := false
	nextCursor := ""
	for _, view := range views {
		var payload map[string]any
		switch view {
		case "status":
			arguments := pickArguments(raw, "session_id", "collect", "max_collect_bytes", "request_watch_report", "context")
			payload, failure = composeTool(tc, runTraceSessionStatus, arguments)
		default:
			arguments := pickArguments(raw,
				"kind", "address_range_start", "address_range_end", "cycle_min", "cycle_max",
				"stream", "direction", "value_equals", "value_min", "value_max", "previous_equals",
				"pc_start", "pc_end", "resolve_symbols", "sequence_min", "sequence_max",
				"address_space", "limit", "include_address_counts", "address_limit", "export",
				"collect", "max_collect_bytes", "cursor", "context")
			payload, failure = composeTool(tc, runTraceSessionEvents, arguments)
		}
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		sections[view] = payload
		if value, ok := numberAsUint64(payload["returned"]); ok {
			returned += int(value)
		}
		if cursor, ok := payload["next_cursor"].(string); ok && cursor != "" {
			hasMore = true
			if len(views) == 1 {
				nextCursor = cursor
			}
		}
	}

	result := map[string]any{
		"include":  views,
		"sections": sections,
		"returned": returned,
		"has_more": hasMore,
		"note":     "Each section is the payload of the view that owns it, including its loss accounting, totals and next_cursor. The events cursor carries the session and the event filter, so page 2 needs only the cursor.",
	}
	if len(views) == 1 {
		section, _ := sections[views[0]].(map[string]any)
		for _, key := range []string{"total", "truncated", "loss", "drained"} {
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

// resolveTraceQueryViews validates and de-duplicates the requested views, and
// infers the pair the supplied arguments address when none was given.
func resolveTraceQueryViews(parsed *traceSessionQueryArgs) ([]string, *toolFailure) {
	if len(parsed.Include) == 0 {
		return inferTraceQueryViews(*parsed), nil
	}
	seen := map[string]bool{}
	views := make([]string, 0, len(parsed.Include))
	for _, view := range parsed.Include {
		if failure := traceSessionQueryViewVocab.validate(view); failure != nil {
			return nil, failure
		}
		if seen[view] {
			return nil, &toolFailure{
				Code:    "invalid_params",
				Message: fmt.Sprintf("include lists %q twice", view),
				Data:    map[string]any{"field": "include", "value": view},
			}
		}
		seen[view] = true
		views = append(views, view)
	}
	return views, nil
}

// inferTraceQueryViews derives the default view selection from the arguments a
// view owns, so a view-specific argument is never accepted and then ignored.
func inferTraceQueryViews(parsed traceSessionQueryArgs) []string {
	status := parsed.SessionID != "" || parsed.RequestWatchReport != nil
	events := parsed.Kind != "" || parsed.AddressRangeStart != nil || parsed.AddressRangeEnd != nil ||
		parsed.CycleMin != 0 || parsed.CycleMax != 0 || parsed.Stream != "" || parsed.Direction != "" ||
		parsed.ValueEquals != nil || parsed.ValueMin != nil || parsed.ValueMax != nil ||
		parsed.PreviousEquals != nil || parsed.PCStart != nil || parsed.PCEnd != nil ||
		parsed.ResolveSymbols != nil || parsed.SequenceMin != 0 || parsed.SequenceMax != 0 ||
		parsed.Limit != 0 || parsed.IncludeAddressCounts != nil || parsed.AddressLimit != 0 ||
		parsed.Export || parsed.Cursor != ""
	switch {
	case status && events:
		return []string{"status", "events"}
	case events:
		return []string{"events"}
	case status:
		return []string{"status"}
	default:
		return []string{"status", "events"}
	}
}

// traceQueryConsumers maps each argument to the views that consume it.
func traceQueryConsumers() map[string][]string {
	consumers := map[string][]string{
		"include":              {"status", "events"},
		"collect":              {"status", "events"},
		"max_collect_bytes":    {"status", "events"},
		"context":              {"status", "events"},
		"session_id":           {"status"},
		"request_watch_report": {"status"},
	}
	for _, name := range []string{
		"kind", "address_range_start", "address_range_end", "cycle_min", "cycle_max", "stream",
		"direction", "value_equals", "value_min", "value_max", "previous_equals", "pc_start",
		"pc_end", "resolve_symbols", "sequence_min", "sequence_max", "address_space", "limit",
		"include_address_counts", "address_limit", "export", "cursor",
	} {
		consumers[name] = []string{"events"}
	}
	return consumers
}

// validateTraceQueryArguments rejects an argument that no requested view
// consumes, naming the accepted set.
func validateTraceQueryArguments(raw map[string]json.RawMessage, views []string) *toolFailure {
	consumers := traceQueryConsumers()
	requested := map[string]bool{}
	for _, view := range views {
		requested[view] = true
	}
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
		for _, view := range appliesTo {
			if requested[view] {
				consumed = true
				break
			}
		}
		if consumed {
			continue
		}
		accepted := []string{"include"}
		for name, candidates := range consumers {
			for _, view := range candidates {
				if requested[view] {
					accepted = append(accepted, name)
					break
				}
			}
		}
		sort.Strings(accepted)
		return &toolFailure{
			Code:    "unsupported_parameter",
			Message: fmt.Sprintf("%q is not consumed by any requested view (%s); it applies to %s", key, strings.Join(views, ","), strings.Join(appliesTo, ",")),
			Data: map[string]any{
				"field":           key,
				"path":            "$." + key,
				"include":         views,
				"consumed_by":     appliesTo,
				"accepted_fields": accepted,
			},
		}
	}
	return nil
}
