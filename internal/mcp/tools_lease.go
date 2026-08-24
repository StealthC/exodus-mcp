package mcp

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/StealthC/exodus-mcp/internal/analysis"
)

// leaseToolSpecs implements the explicit context-lease tools required before
// broader mutation support: mutations on one context are exclusive while a
// lease is active.
func leaseToolSpecs() []toolSpec {
	return []toolSpec{
		{
			name:        "context_lease_acquire",
			description: "Take the exclusive mutation lease of an analysis context. At most one lease can be active per context; all Phase 4 mutation tools (state_save, state_load, memory_write, frame_advance, input_set) require it. Leases expire automatically and can be renewed.",
			schema: objectSchema(map[string]any{
				"context": contextProperty(),
				"purpose": stringProperty("Human-readable reason for the lease; recorded in the mutation log."),
				"ttl_ms":  integerProperty("Lease lifetime in milliseconds (default 300000, cap 3600000).", 1),
			}, []string{"purpose"}),
			run: runLeaseAcquire,
		},
		{
			name:        "context_lease_renew",
			description: "Extend the active lease of a context. The presenting lease id must be the current owner.",
			schema: objectSchema(map[string]any{
				"context":  contextProperty(),
				"lease_id": stringProperty("Lease id returned by context_lease_acquire."),
				"ttl_ms":   integerProperty("New lease lifetime in milliseconds (default 300000, cap 3600000).", 1),
			}, []string{"lease_id"}),
			run: runLeaseRenew,
		},
		{
			name:        "context_lease_release",
			description: "End the active lease of a context early. Releasing a foreign lease id fails so a stale agent cannot revoke a newer owner.",
			schema: objectSchema(map[string]any{
				"context":  contextProperty(),
				"lease_id": stringProperty("Lease id returned by context_lease_acquire."),
			}, []string{"lease_id"}),
			run: runLeaseRelease,
		},
		{
			name:        "context_lease_list",
			description: "Show the active lease of a context, if any.",
			schema:      objectSchema(map[string]any{"context": contextProperty()}, nil),
			run:         runLeaseList,
		},
		{
			name:        "context_mutation_log",
			description: "List the audited mutation trail of a context, newest first. Every mutating Phase 4 tool call records its lease, echoed arguments, and timestamp here.",
			schema:      objectSchema(map[string]any{"context": contextProperty()}, nil),
			run:         runMutationLog,
		},
	}
}

type leaseAcquireArgs struct {
	Context string `json:"context"`
	Purpose string `json:"purpose"`
	TTLMS   *int64 `json:"ttl_ms"`
}

func runLeaseAcquire(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[leaseAcquireArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	ttl := analysis.DefaultLeaseTTL
	if parsed.TTLMS != nil {
		if *parsed.TTLMS <= 0 {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "ttl_ms must be positive"}, tc.modern)
		}
		ttl = time.Duration(*parsed.TTLMS) * time.Millisecond
	}
	lease, err := tc.server.contexts.Leases.Acquire(context.ID, parsed.Purpose, ttl)
	if err != nil {
		return failureResult(&toolFailure{Code: "lease_conflict", Message: err.Error()}, tc.modern)
	}
	return okResult(leaseView(lease), tc.modern)
}

type leaseRenewArgs struct {
	Context string `json:"context"`
	LeaseID string `json:"lease_id"`
	TTLMS   *int64 `json:"ttl_ms"`
}

func runLeaseRenew(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[leaseRenewArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	ttl := analysis.DefaultLeaseTTL
	if parsed.TTLMS != nil {
		if *parsed.TTLMS <= 0 {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "ttl_ms must be positive"}, tc.modern)
		}
		ttl = time.Duration(*parsed.TTLMS) * time.Millisecond
	}
	lease, err := tc.server.contexts.Leases.Renew(context.ID, parsed.LeaseID, ttl)
	if err != nil {
		return failureResult(leaseFailure(err), tc.modern)
	}
	return okResult(leaseView(lease), tc.modern)
}

type leaseReleaseArgs struct {
	Context string `json:"context"`
	LeaseID string `json:"lease_id"`
}

func runLeaseRelease(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[leaseReleaseArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if err := tc.server.contexts.Leases.Release(context.ID, parsed.LeaseID); err != nil {
		return failureResult(leaseFailure(err), tc.modern)
	}
	return okResult(map[string]any{"released": true, "context_id": context.ID, "lease_id": parsed.LeaseID}, tc.modern)
}

func runLeaseList(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[struct {
		Context string `json:"context"`
	}](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	leases := []map[string]any{}
	if lease := tc.server.contexts.Leases.Active(context.ID); lease != nil {
		leases = append(leases, leaseView(lease))
	}
	return okResult(map[string]any{"context_id": context.ID, "leases": leases}, tc.modern)
}

func runMutationLog(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[struct {
		Context string `json:"context"`
	}](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	return okResult(map[string]any{
		"context_id": context.ID,
		"entries":    tc.server.contexts.Ledger.List(context.ID),
	}, tc.modern)
}

func leaseView(lease *analysis.Lease) map[string]any {
	return map[string]any{
		"lease_id":   lease.ID,
		"context_id": lease.ContextID,
		"purpose":    lease.Purpose,
		"created_at": lease.CreatedAt,
		"expires_at": lease.ExpiresAt,
		"ttl_ms":     lease.TTL.Milliseconds(),
	}
}

// leaseFailure maps lease store errors to machine-readable tool failures.
func leaseFailure(err error) *toolFailure {
	message := err.Error()
	code := "lease_not_found"
	if strings.Contains(message, "does not own") {
		code = "lease_invalid"
	}
	return &toolFailure{Code: code, Message: message}
}
