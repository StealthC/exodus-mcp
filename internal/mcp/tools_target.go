package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/StealthC/exodus-mcp/internal/analysis"
)

// targetToolSpecs implements the global target concurrency surface: the
// optional exclusive control lock, the bounded target audit stream, and the
// context-filtered mutation log projection.
func targetToolSpecs() []toolSpec {
	return []toolSpec{
		{
			name:        "target_audit_log",
			description: "Query the bounded global target audit stream, newest first. Every target mutation (successful or failed), generation/control precondition conflict, control-lock lifecycle event, and externally observed run-state transition (run_state_change, UI-initiated pauses with the observed generation and frame token when available) is recorded with target generations, ROM identity, originating context, and control-lock provenance. Filter by operation, context, control id, generation range, or time range; a truncated response reports the retained window. Pages by cursor (the monotonic operation id of the last entry, so a mutation recorded between pages never duplicates or skips a row) or by offset; the cursor carries the filters, so a later page returns the same filtered stream. " + cursorSteppingNote + " next_offset and next_cursor are null on the last page instead of pointing at an empty page. " + pagingNote,
			schema: objectSchema(map[string]any{
				"context":        contextProperty(),
				"tool":           stringProperty("Filter by tool name, e.g. memory_write or rom_load."),
				"control_id":     stringProperty("Filter by the control-lock audit id that authorized the operations."),
				"generation_min": integerProperty("Only entries whose before/after target generation is at least this value.", 0),
				"generation_max": integerProperty("Only entries whose before/after target generation is at most this value.", 0),
				"since":          stringProperty("Only entries at or after this UTC RFC3339 timestamp."),
				"until":          stringProperty("Only entries at or before this UTC RFC3339 timestamp."),
				"offset":         integerProperty("Skip this many matching entries (default 0). Mutually exclusive with cursor.", 0),
				"limit":          integerProperty("Maximum entries returned (default 50, cap 200).", 0),
				"cursor":         stringProperty("next_cursor from a previous target_audit_log call. The cursor carries the filters and the position, so a later page needs only the cursor; any filter supplied alongside it must match the cursor. Omit to start at the newest page; mutually exclusive with offset."),
			}, nil),
			run: aliasRun("target_audit_log", runTargetAuditLog),
		},
		{
			name:        "target_control_acquire",
			description: "Take the optional process-wide exclusive control lock over the one Exodus instance. While the lock is active, every target mutation must present the returned control_id or fails with target_control_held; read-only tools stay available. The lock expires automatically and can be renewed. The control_id is a capability: it is returned only here and must be kept by the acquirer.",
			schema: objectSchema(map[string]any{
				"context":                    contextProperty(),
				"purpose":                    stringProperty("Human-readable reason for the exclusive window; shown in contention diagnostics."),
				"ttl_ms":                     integerProperty(fmt.Sprintf("Lock lifetime in milliseconds (default %d, cap %d).", analysis.DefaultControlTTL.Milliseconds(), analysis.MaxControlTTL.Milliseconds()), 1),
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; acquisition fails with target_generation_conflict on mismatch.", 1),
			}, []string{"purpose"}),
			run: runTargetControlAcquire,
		},
		{
			name:        "target_control_renew",
			description: "Extend the active control lock. The presenting control id must be the current owner.",
			schema: objectSchema(map[string]any{
				"control_id": stringProperty("Control id returned by target_control_acquire."),
				"ttl_ms":     integerProperty(fmt.Sprintf("New lock lifetime in milliseconds (default %d, cap %d).", analysis.DefaultControlTTL.Milliseconds(), analysis.MaxControlTTL.Milliseconds()), 1),
			}, []string{"control_id"}),
			run: runTargetControlRenew,
		},
		{
			name:        "target_control_release",
			description: "End the active control lock early. Releasing a foreign control id fails so a stale agent cannot revoke the current owner.",
			schema: objectSchema(map[string]any{
				"control_id": stringProperty("Control id returned by target_control_acquire."),
			}, []string{"control_id"}),
			run: runTargetControlRelease,
		},
		{
			name:        "target_control_status",
			description: "Show whether the exclusive control lock is active, with its purpose, expiry, and an opaque holder summary suitable for contention diagnostics. Never exposes the control_id; pass an optional control_id to check whether it currently owns the lock.",
			schema: objectSchema(map[string]any{
				"control_id": stringProperty("Optional control id of the caller; the response reports held_by_caller."),
			}, nil),
			run: runTargetControlStatus,
		},
		{
			name:        "context_mutation_log",
			description: "List the audited mutation trail of a context, newest first, as a filtered projection of the global target audit stream. Every mutating tool call records its target generations, echoed arguments, and timestamp here. Pages by cursor (the monotonic operation id of the last entry) or by offset; the cursor carries the context scope, so a later page needs only the cursor. " + cursorSteppingNote + " " + pagingNote,
			schema: objectSchema(map[string]any{
				"context": contextProperty(),
				"limit":   integerProperty("Maximum entries returned (default 50, cap 200).", 0),
				"offset":  integerProperty("Skip this many matching entries (default 0). Mutually exclusive with cursor.", 0),
				"cursor":  stringProperty("next_cursor from a previous context_mutation_log call. The cursor carries the context scope and the position, so a later page needs only the cursor."),
			}, nil),
			run: aliasRun("context_mutation_log", runMutationLog),
		},
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// target_control_acquire / renew / release / status
// ----------------------------------------------------------------------------------------------------------------------

type targetControlAcquireArgs struct {
	Context                  string  `json:"context"`
	Purpose                  string  `json:"purpose"`
	TTLMS                    *int64  `json:"ttl_ms"`
	ExpectedTargetGeneration *uint64 `json:"expected_target_generation"`
}

func runTargetControlAcquire(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[targetControlAcquireArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	// The generation precondition is validated before the lock is taken so a
	// stale caller never churns the exclusive window.
	if parsed.ExpectedTargetGeneration != nil {
		if failure := targetGenerationPrecondition(tc.server, *parsed.ExpectedTargetGeneration); failure != nil {
			return failureResult(failure, tc.modern)
		}
	}
	ttl := analysis.DefaultControlTTL
	if parsed.TTLMS != nil {
		if *parsed.TTLMS <= 0 {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "ttl_ms must be positive"}, tc.modern)
		}
		ttl = time.Duration(*parsed.TTLMS) * time.Millisecond
	}
	lock, err := tc.server.controls.Acquire(strings.TrimSpace(parsed.Purpose), context.ID, ttl, tc.server.target.Generation())
	if err != nil {
		var held *analysis.ControlHeldError
		if errors.As(err, &held) {
			return failureResult(controlHeldFailure(held.Lock, tc.server.target.Generation()), tc.modern)
		}
		return failureResult(&toolFailure{Code: "invalid_params", Message: err.Error()}, tc.modern)
	}
	tc.server.recordAudit(analysis.AuditEntry{
		Tool:      "target_control_acquire",
		ContextID: context.ID,
		ControlID: lock.ID,
		Outcome:   analysis.OutcomeLockEvent,
		Detail: map[string]any{
			"event":             "lock_acquired",
			"purpose":           lock.Purpose,
			"ttl_ms":            lock.TTL.Milliseconds(),
			"target_generation": lock.Generation,
		},
		ROMBefore: tc.server.currentROMPath(),
	})
	return okResult(controlLockView(lock, true), tc.modern)
}

type targetControlRenewArgs struct {
	ControlID string `json:"control_id"`
	TTLMS     *int64 `json:"ttl_ms"`
}

func runTargetControlRenew(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[targetControlRenewArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	ttl := analysis.DefaultControlTTL
	if parsed.TTLMS != nil {
		if *parsed.TTLMS <= 0 {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "ttl_ms must be positive"}, tc.modern)
		}
		ttl = time.Duration(*parsed.TTLMS) * time.Millisecond
	}
	lock, err := tc.server.controls.Renew(parsed.ControlID, ttl)
	if err != nil {
		return failureResult(controlFailure(err), tc.modern)
	}
	tc.server.recordAudit(analysis.AuditEntry{
		Tool:      "target_control_renew",
		ContextID: lock.ContextID,
		ControlID: lock.ID,
		Outcome:   analysis.OutcomeLockEvent,
		Detail: map[string]any{
			"event":  "lock_renewed",
			"ttl_ms": lock.TTL.Milliseconds(),
		},
	})
	return okResult(controlLockView(lock, true), tc.modern)
}

type targetControlReleaseArgs struct {
	ControlID string `json:"control_id"`
}

func runTargetControlRelease(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[targetControlReleaseArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if err := tc.server.controls.Release(parsed.ControlID, "caller_released"); err != nil {
		return failureResult(controlFailure(err), tc.modern)
	}
	// The lock_ended audit entry is written by the drop hook.
	return okResult(map[string]any{"released": true, "control_id": parsed.ControlID}, tc.modern)
}

type targetControlStatusArgs struct {
	ControlID string `json:"control_id"`
}

func runTargetControlStatus(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[targetControlStatusArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	result := map[string]any{
		"active":            false,
		"target_generation": tc.server.target.Generation(),
	}
	if lock := tc.server.controls.Active(); lock != nil {
		view := controlLockView(lock, false)
		view["active"] = true
		if parsed.ControlID != "" {
			view["held_by_caller"] = tc.server.controls.Valid(parsed.ControlID)
		}
		result = view
	}
	return okResult(result, tc.modern)
}

// controlLockView renders one lock. The control_id is included only for the
// acquirer's own acquire/renew/release responses.
func controlLockView(lock *analysis.ControlLock, includeID bool) map[string]any {
	view := map[string]any{
		"purpose":                      lock.Purpose,
		"context_id":                   lock.ContextID,
		"created_at":                   lock.CreatedAt,
		"expires_at":                   lock.ExpiresAt,
		"ttl_ms":                       lock.TTL.Milliseconds(),
		"target_generation_at_acquire": lock.Generation,
	}
	if includeID {
		view["control_id"] = lock.ID
	}
	return view
}

// controlFailure maps control registry errors to stable tool failures.
func controlFailure(err error) *toolFailure {
	message := err.Error()
	code := "control_not_found"
	if strings.Contains(message, "does not own") {
		code = "control_invalid"
	}
	return &toolFailure{Code: code, Message: message}
}

// ----------------------------------------------------------------------------------------------------------------------
// target_audit_log and context_mutation_log
// ----------------------------------------------------------------------------------------------------------------------

type targetAuditLogArgs struct {
	Context       string  `json:"context"`
	Tool          string  `json:"tool"`
	ControlID     string  `json:"control_id"`
	GenerationMin uint64  `json:"generation_min"`
	GenerationMax uint64  `json:"generation_max"`
	Since         string  `json:"since"`
	Until         string  `json:"until"`
	Offset        uint64  `json:"offset"`
	Limit         *uint64 `json:"limit"`
	Cursor        string  `json:"cursor"`
}

// auditCursorQuery is the filter identity of one target_audit_log or
// context_mutation_log enumeration. A cursor reproduces it, so a later page
// returns the same filtered stream instead of the unfiltered one.
type auditCursorQuery struct {
	ContextID     string `json:"context_id,omitempty"`
	Tool          string `json:"tool,omitempty"`
	ControlID     string `json:"control_id,omitempty"`
	GenerationMin uint64 `json:"generation_min,omitempty"`
	GenerationMax uint64 `json:"generation_max,omitempty"`
	Since         string `json:"since,omitempty"`
	Until         string `json:"until,omitempty"`
}

// auditCursor is the paging anchor of one target_audit_log or
// context_mutation_log enumeration: the monotonic operation id of the last
// entry of the previous page plus the filter that produced the page. New
// entries take higher ids and therefore sort before the anchor, so a concurrent
// mutation can never shift a page boundary the way an offset does.
type auditCursor struct {
	OperationID uint64
	Query       auditCursorQuery
}

func encodeAuditCursor(prefix string, operationID uint64, query auditCursorQuery) (string, *toolFailure) {
	encodedQuery, failure := encodeCursorQuery(query)
	if failure != nil {
		return "", failure
	}
	return encodeCursor(prefix, strconv.FormatUint(operationID, 10), encodedQuery), nil
}

func decodeAuditCursor(cursor, prefix string) (auditCursor, *toolFailure) {
	parts, failure := decodeCursor(cursor, prefix, 2)
	if failure != nil {
		return auditCursor{}, failure
	}
	operationID, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil || operationID == 0 {
		return auditCursor{}, invalidCursorFailure(fmt.Sprintf("%q is not a cursor this server issued", cursor))
	}
	decoded := auditCursor{OperationID: operationID}
	if failure := decodeCursorQuery(parts[1], &decoded.Query, cursor); failure != nil {
		return auditCursor{}, failure
	}
	return decoded, nil
}

// reconcileAuditCursorQuery applies the filter a cursor carries when the caller
// omitted it, and rejects an argument that contradicts it.
func reconcileAuditCursorQuery(parsed targetAuditLogArgs, resolvedContextID string, cursor auditCursor) (auditCursorQuery, *toolFailure) {
	query := cursor.Query
	if resolvedContextID != "" && resolvedContextID != query.ContextID {
		return query, cursorConflictFailure("context", query.ContextID, resolvedContextID)
	}
	if provided := parsed.Tool; provided != "" && provided != query.Tool {
		return query, cursorConflictFailure("tool", query.Tool, provided)
	}
	if provided := parsed.ControlID; provided != "" && provided != query.ControlID {
		return query, cursorConflictFailure("control_id", query.ControlID, provided)
	}
	if parsed.GenerationMin != 0 && parsed.GenerationMin != query.GenerationMin {
		return query, cursorConflictFailure("generation_min", query.GenerationMin, parsed.GenerationMin)
	}
	if parsed.GenerationMax != 0 && parsed.GenerationMax != query.GenerationMax {
		return query, cursorConflictFailure("generation_max", query.GenerationMax, parsed.GenerationMax)
	}
	if provided := parsed.Since; provided != "" && provided != query.Since {
		return query, cursorConflictFailure("since", query.Since, provided)
	}
	if provided := parsed.Until; provided != "" && provided != query.Until {
		return query, cursorConflictFailure("until", query.Until, provided)
	}
	return query, nil
}

func runTargetAuditLog(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[targetAuditLogArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	contextID := ""
	if parsed.Context != "" {
		context, failure := resolveContext(tc.server, parsed.Context)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		contextID = context.ID
	}
	// The cursor is decoded before the filter is applied: the token carries the
	// filter, so a page 2 call needs none of the original arguments.
	query := auditCursorQuery{
		ContextID:     contextID,
		Tool:          parsed.Tool,
		ControlID:     parsed.ControlID,
		GenerationMin: parsed.GenerationMin,
		GenerationMax: parsed.GenerationMax,
		Since:         parsed.Since,
		Until:         parsed.Until,
	}
	limit := uint64(50)
	if parsed.Limit != nil {
		if *parsed.Limit > 200 {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "limit is capped at 200 entries"}, tc.modern)
		}
		limit = *parsed.Limit
	}
	// A cursor resumes strictly after one operation id; an offset is the legacy
	// equivalent. Mixing them would name two different positions.
	cursor := auditCursor{}
	cursorPage := parsed.Cursor != ""
	if cursorPage {
		if parsed.Offset != 0 {
			return failureResult(invalidCursorFailure("pass either cursor or offset, not both: the cursor already names the position in the stream"), tc.modern)
		}
		cursor, failure = decodeAuditCursor(parsed.Cursor, auditCursorPrefix)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		query, failure = reconcileAuditCursorQuery(*parsed, contextID, cursor)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
	}
	filter := analysis.AuditFilter{
		ContextID:     query.ContextID,
		Tool:          query.Tool,
		ControlID:     query.ControlID,
		GenerationMin: query.GenerationMin,
		GenerationMax: query.GenerationMax,
	}
	if query.Since != "" {
		parsedTime, err := time.Parse(time.RFC3339, query.Since)
		if err != nil {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "since must be a UTC RFC3339 timestamp"}, tc.modern)
		}
		filter.Since = parsedTime
	}
	if query.Until != "" {
		parsedTime, err := time.Parse(time.RFC3339, query.Until)
		if err != nil {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "until must be a UTC RFC3339 timestamp"}, tc.modern)
		}
		filter.Until = parsedTime
	}

	entries, window := tc.server.audit.Query(filter)
	total := len(entries)
	if cursorPage {
		// The stream is newest first, so the page continues at the first entry
		// whose id is below the anchor. Entries evicted from the retained
		// window simply no longer appear; nothing is invented.
		start := len(entries)
		for index, entry := range entries {
			if entry.OperationID < cursor.OperationID {
				start = index
				break
			}
		}
		entries = entries[start:]
	}
	start := parsed.Offset
	if start > uint64(len(entries)) {
		start = uint64(len(entries))
	}
	entries = entries[start:]
	truncated := false
	if uint64(len(entries)) > limit {
		entries = entries[:limit]
		truncated = true
	}
	views := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		views = append(views, auditEntryView(entry))
	}
	paging := pagingPage{
		Returned:  len(views),
		Total:     total,
		Remaining: boolToRemaining(truncated),
	}
	if truncated && len(entries) > 0 {
		next, nextFailure := encodeAuditCursor(auditCursorPrefix, entries[len(entries)-1].OperationID, query)
		if nextFailure != nil {
			return failureResult(nextFailure, tc.modern)
		}
		paging.NextCursor = next
	}
	// next_offset and next_cursor are reported together and are null on the
	// last page: an offset that yields nothing is a trap, not a convenience. A
	// cursor page has no global offset to report, so only the cursor continues.
	nextOffset := any(nil)
	if paging.hasMore() && parsed.Cursor == "" {
		nextOffset = start + uint64(len(views))
	}
	result := map[string]any{
		"entries":   views,
		"count":     len(views),
		"truncated": truncated,
		"pagination": map[string]any{
			"offset":      start,
			"limit":       limit,
			"next_offset": nextOffset,
			"cursor":      nil,
			"order":       "operation_id_desc",
		},
		"retained": map[string]any{
			"operation_id_min":      window.OldestOperationID,
			"operation_id_max":      window.NewestOperationID,
			"target_generation_min": window.GenerationMin,
			"target_generation_max": window.GenerationMax,
			"oldest_timestamp":      window.OldestTimestamp,
			"newest_timestamp":      window.NewestTimestamp,
		},
	}
	if parsed.Cursor != "" {
		result["pagination"].(map[string]any)["cursor"] = parsed.Cursor
	}
	paging.apply(result)
	return okResult(result, tc.modern)
}

func auditEntryView(entry analysis.AuditEntry) map[string]any {
	view := map[string]any{
		"operation_id": entry.OperationID,
		"timestamp":    entry.Timestamp,
		"tool":         entry.Tool,
		"outcome":      entry.Outcome,
	}
	if entry.ContextID != "" {
		view["context_id"] = entry.ContextID
	}
	if entry.ControlID != "" {
		view["control_id"] = entry.ControlID
	}
	if entry.GenerationBefore != nil {
		view["target_generation_before"] = *entry.GenerationBefore
	}
	if entry.GenerationAfter != nil {
		view["target_generation_after"] = *entry.GenerationAfter
	}
	if entry.ROMBefore != "" {
		view["rom_before"] = entry.ROMBefore
	}
	if entry.ROMAfter != "" {
		view["rom_after"] = entry.ROMAfter
	}
	if len(entry.Detail) > 0 {
		view["detail"] = entry.Detail
	}
	if len(entry.Result) > 0 {
		view["result"] = entry.Result
	}
	if entry.Failure != nil {
		view["failure"] = entry.Failure
	}
	if len(entry.ResourceIDs) > 0 {
		view["resource_ids"] = entry.ResourceIDs
	}
	return view
}

func runMutationLog(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[struct {
		Context string  `json:"context"`
		Limit   *uint64 `json:"limit"`
		Cursor  string  `json:"cursor"`
		Offset  uint64  `json:"offset"`
	}](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	limit := uint64(50)
	if parsed.Limit != nil {
		if *parsed.Limit > 200 {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "limit is capped at 200 entries"}, tc.modern)
		}
		limit = *parsed.Limit
	}
	// The projection is scoped to one context, and the cursor carries that scope:
	// a cursor from another context is a conflict, not a silently different page.
	cursor := auditCursor{}
	cursorPage := parsed.Cursor != ""
	if cursorPage {
		if parsed.Offset != 0 {
			return failureResult(invalidCursorFailure("pass either cursor or offset, not both: the cursor already names the position in the stream"), tc.modern)
		}
		cursor, failure = decodeAuditCursor(parsed.Cursor, mutationCursorPrefix)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		if cursor.Query.ContextID != "" && cursor.Query.ContextID != context.ID {
			return failureResult(cursorConflictFailure("context", cursor.Query.ContextID, context.ID), tc.modern)
		}
	}
	entries, _ := tc.server.audit.Query(analysis.AuditFilter{ContextID: context.ID})
	// The projection is the context's mutation trail: control-lock lifecycle
	// events stay in the global stream, not here.
	mutations := make([]analysis.AuditEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Outcome == analysis.OutcomeLockEvent {
			continue
		}
		mutations = append(mutations, entry)
	}
	total := len(mutations)
	if cursorPage {
		start := len(mutations)
		for index, entry := range mutations {
			if entry.OperationID < cursor.OperationID {
				start = index
				break
			}
		}
		mutations = mutations[start:]
	}
	if parsed.Offset < uint64(len(mutations)) {
		mutations = mutations[parsed.Offset:]
	} else {
		mutations = nil
	}
	truncated := uint64(len(mutations)) > limit
	if truncated {
		mutations = mutations[:limit]
	}
	views := make([]map[string]any, 0, len(mutations))
	for _, entry := range mutations {
		views = append(views, auditEntryView(entry))
	}
	paging := pagingPage{
		Returned:  len(views),
		Total:     total,
		Remaining: boolToRemaining(truncated),
	}
	if truncated && len(mutations) > 0 {
		next, nextFailure := encodeAuditCursor(mutationCursorPrefix, mutations[len(mutations)-1].OperationID, auditCursorQuery{ContextID: context.ID})
		if nextFailure != nil {
			return failureResult(nextFailure, tc.modern)
		}
		paging.NextCursor = next
	}
	result := map[string]any{
		"context_id": context.ID,
		"entries":    views,
		"pagination": map[string]any{
			"offset": parsed.Offset,
			"limit":  limit,
			"order":  "operation_id_desc",
		},
	}
	paging.apply(result)
	return okResult(result, tc.modern)
}
