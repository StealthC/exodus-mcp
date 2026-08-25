package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
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
			description: "Query the bounded global target audit stream, newest first. Every target mutation (successful or failed), generation/control precondition conflict, and control-lock lifecycle event is recorded with target generations, ROM identity, originating context, and control-lock provenance. Filter by operation, context, control id, generation range, or time range; a truncated response reports the retained window.",
			schema: objectSchema(map[string]any{
				"context":        contextProperty(),
				"tool":           stringProperty("Filter by tool name, e.g. memory_write or rom_load."),
				"control_id":     stringProperty("Filter by the control-lock audit id that authorized the operations."),
				"generation_min": integerProperty("Only entries whose before/after target generation is at least this value.", 0),
				"generation_max": integerProperty("Only entries whose before/after target generation is at most this value.", 0),
				"since":          stringProperty("Only entries at or after this UTC RFC3339 timestamp."),
				"until":          stringProperty("Only entries at or before this UTC RFC3339 timestamp."),
				"offset":         integerProperty("Skip this many matching entries (default 0).", 0),
				"limit":          integerProperty("Maximum entries returned (default 50, cap 200).", 0),
			}, nil),
			run: runTargetAuditLog,
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
			description: "List the audited mutation trail of a context, newest first, as a filtered projection of the global target audit stream. Every mutating tool call records its target generations, echoed arguments, and timestamp here.",
			schema: objectSchema(map[string]any{
				"context": contextProperty(),
				"limit":   integerProperty("Maximum entries returned (default 50, cap 200).", 0),
			}, nil),
			run: runMutationLog,
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
	filter := analysis.AuditFilter{
		ContextID:     contextID,
		Tool:          parsed.Tool,
		ControlID:     parsed.ControlID,
		GenerationMin: parsed.GenerationMin,
		GenerationMax: parsed.GenerationMax,
	}
	if parsed.Since != "" {
		parsedTime, err := time.Parse(time.RFC3339, parsed.Since)
		if err != nil {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "since must be a UTC RFC3339 timestamp"}, tc.modern)
		}
		filter.Since = parsedTime
	}
	if parsed.Until != "" {
		parsedTime, err := time.Parse(time.RFC3339, parsed.Until)
		if err != nil {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "until must be a UTC RFC3339 timestamp"}, tc.modern)
		}
		filter.Until = parsedTime
	}
	limit := uint64(50)
	if parsed.Limit != nil {
		if *parsed.Limit > 200 {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "limit is capped at 200 entries"}, tc.modern)
		}
		limit = *parsed.Limit
	}

	entries, window := tc.server.audit.Query(filter)
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
	return okResult(map[string]any{
		"entries":   views,
		"count":     len(views),
		"truncated": truncated,
		"pagination": map[string]any{
			"offset":      start,
			"limit":       limit,
			"next_offset": start + uint64(len(views)),
		},
		"retained": map[string]any{
			"operation_id_min":      window.OldestOperationID,
			"operation_id_max":      window.NewestOperationID,
			"target_generation_min": window.GenerationMin,
			"target_generation_max": window.GenerationMax,
			"oldest_timestamp":      window.OldestTimestamp,
			"newest_timestamp":      window.NewestTimestamp,
		},
	}, tc.modern)
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
	entries, _ := tc.server.audit.Query(analysis.AuditFilter{ContextID: context.ID})
	views := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		// The projection is the context's mutation trail: control-lock
		// lifecycle events stay in the global stream, not here.
		if entry.Outcome == analysis.OutcomeLockEvent {
			continue
		}
		if uint64(len(views)) >= limit {
			break
		}
		views = append(views, auditEntryView(entry))
	}
	return okResult(map[string]any{
		"context_id": context.ID,
		"entries":    views,
	}, tc.modern)
}
