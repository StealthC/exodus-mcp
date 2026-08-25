package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/StealthC/exodus-mcp/internal/analysis"
)

// guardArgs are the optional optimistic-concurrency preconditions accepted by
// every target-mutating tool: an optional exclusive control-lock id and an
// optional expected target generation. Both are optional so ordinary
// single-agent mutations need no ceremony; stateful agents and scripts that
// continue a workflow pass the last known generation.
type guardArgs struct {
	ControlID                string  `json:"control_id"`
	ExpectedTargetGeneration *uint64 `json:"expected_target_generation"`
}

func (args guardArgs) guard() mutationGuard {
	guard := mutationGuard{ControlID: args.ControlID}
	if args.ExpectedTargetGeneration != nil {
		guard.ExpectedGeneration = *args.ExpectedTargetGeneration
		guard.HasExpectedGeneration = true
	}
	return guard
}

// mutationGuard is the resolved precondition set of one mutating call.
type mutationGuard struct {
	ControlID             string
	ExpectedGeneration    uint64
	HasExpectedGeneration bool
}

// mutationCall describes one scheduled target-mutating operation.
type mutationCall struct {
	tool      string
	operation string // bridge operation; empty for server-local-only mutations
	params    map[string]string
	guard     mutationGuard
	contextID string
	detail    map[string]any // normalized, redacted arguments for the audit
	romAfter  string         // ROM identity after the operation (rom_load only)

	// resources lists resource ids created or invalidated by the operation.
	// It is evaluated after commit while the scheduler lock is still held.
	resources func() []string

	// prepare validates server-local preconditions under the scheduler lock
	// before any native action and must not mutate anything.
	prepare func() *toolFailure
	// commit performs the server-local part of the mutation after the native
	// action succeeded; its preconditions ran in prepare, so it must not
	// fail.
	commit func()
}

// executeMutation runs one target-mutating operation inside the serialized
// scheduler. Preconditions are validated immediately before the native
// action, the generation advances exactly once on success, and every outcome
// lands in the global audit stream. Returns the payload, the generation
// before and after, or a failure. A nil payload is valid for server-local
// mutations without a bridge operation.
func (server *Server) executeMutation(ctx context.Context, call mutationCall) (map[string]any, uint64, uint64, *toolFailure) {
	server.schedulerMu.Lock()
	defer server.schedulerMu.Unlock()

	target := server.target
	romBefore := server.currentROMPath()
	current := target.Generation()

	record := func(outcome string, before, after *uint64, failure *toolFailure, result map[string]any) {
		entry := analysis.AuditEntry{
			Tool:      call.tool,
			ContextID: call.contextID,
			ControlID: call.guard.ControlID,
			Outcome:   outcome,
			Detail:    call.detail,
			Result:    result,
			ROMBefore: romBefore,
			ROMAfter:  call.romAfter,
		}
		if before != nil {
			entry.GenerationBefore = before
		}
		if after != nil {
			entry.GenerationAfter = after
		}
		if failure != nil {
			entry.Failure = &analysis.AuditFailure{Code: failure.Code, Message: failure.Message}
		}
		// Resource ids are only meaningful when the mutation actually landed.
		if outcome == analysis.OutcomeOK && call.resources != nil {
			entry.ResourceIDs = call.resources()
		}
		server.recordAudit(entry)
	}

	// 1. Unknown revision: guarded preconditions cannot be honored. Only a
	// successful observation re-establishes the revision.
	if target.Unknown() && call.guard.HasExpectedGeneration {
		failure := &toolFailure{
			Code:    "target_resynchronization_required",
			Message: "the target revision is unknown after an ambiguous failure; observe the target with a read-only tool before retrying a guarded mutation",
			Data: map[string]any{
				"target_generation_state":      "unknown",
				"last_known_target_generation": current,
				"retry_hint":                   "Call a read-only tool such as emulator_status, then retry with the target_generation it reports.",
			},
		}
		record(analysis.OutcomeConflict, nil, nil, failure, nil)
		return nil, 0, 0, failure
	}

	// 2. Optimistic concurrency, validated inside the scheduler immediately
	// before the native action.
	if call.guard.HasExpectedGeneration && call.guard.ExpectedGeneration != current {
		failure := targetGenerationConflict(server, call.guard.ExpectedGeneration)
		record(analysis.OutcomeConflict, nil, nil, failure, nil)
		return nil, 0, 0, failure
	}

	// 3. Optional exclusive control lock: a held lock rejects foreign
	// mutations but never blocks reads.
	if lock := server.controls.Active(); lock != nil && !server.controls.Valid(call.guard.ControlID) {
		failure := controlHeldFailure(lock, current)
		record(analysis.OutcomeHeld, nil, nil, failure, nil)
		return nil, 0, 0, failure
	}

	// 4. Server-local preconditions.
	if call.prepare != nil {
		if failure := call.prepare(); failure != nil {
			record(analysis.OutcomeFailed, &current, &current, failure, nil)
			return nil, 0, 0, failure
		}
	}

	// 5. Native action.
	beforeGen := current
	var payload map[string]any
	if call.operation != "" {
		var commandFailure *toolFailure
		var ambiguous bool
		payload, commandFailure, ambiguous = server.runCommand(ctx, call.operation, call.params)
		if commandFailure != nil {
			if ambiguous {
				// The bridge may or may not have executed the command; the
				// target revision is no longer provable.
				target.MarkUnknown()
				commandFailure.Data = map[string]any{
					"target_generation_state":      "unknown",
					"last_known_target_generation": beforeGen,
				}
				record(analysis.OutcomeAmbiguous, &beforeGen, nil, commandFailure, nil)
			} else {
				record(analysis.OutcomeFailed, &beforeGen, &beforeGen, commandFailure, nil)
			}
			return nil, 0, 0, commandFailure
		}
	}

	// 6. Advance exactly once per successful mutation, then run the
	// server-local commit so it observes the post-mutation generation (for
	// resource provenance). Commit is infallible by design: its preconditions
	// ran in prepare.
	afterGen := target.Advance()
	if call.commit != nil {
		call.commit()
	}
	record(analysis.OutcomeOK, &beforeGen, &afterGen, nil, boundedAuditResult(payload))
	return payload, beforeGen, afterGen, nil
}

// boundedAuditResult renders a bounded summary of a mutation payload for the
// audit stream. Bulk values (trace text, sample arrays) are recursively
// truncated so the whole result stays compact even for artifact-first tools;
// the full payload is already available to the caller through the tool
// response.
func boundedAuditResult(payload map[string]any) map[string]any {
	if payload == nil {
		return nil
	}
	const maxAuditResultBytes = 2048
	bound, ok := boundAuditValue(payload, maxAuditResultBytes).(map[string]any)
	if !ok {
		return map[string]any{"summary": "<unrepresentable payload>"}
	}
	return bound
}

// boundAuditValue returns a copy of value whose JSON encoding fits within
// budget bytes. Strings and arrays are truncated, maps are bounded
// recursively; the shape of the data is preserved so analysts still see the
// keys.
func boundAuditValue(value any, budget int) any {
	if budget < 64 {
		budget = 64
	}
	if encoded, err := json.Marshal(value); err == nil && len(encoded) <= budget {
		return value
	}
	switch typed := value.(type) {
	case string:
		return fmt.Sprintf("<%d bytes truncated>", len(typed))
	case []any:
		if len(typed) == 0 {
			return typed
		}
		limit := 16
		if len(typed) < limit {
			limit = len(typed)
		}
		per := budget / limit
		out := make([]any, 0, limit)
		for _, item := range typed[:limit] {
			out = append(out, boundAuditValue(item, per))
		}
		if len(typed) > limit {
			out = append(out, fmt.Sprintf("<%d more items>", len(typed)-limit))
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[key] = boundAuditValue(item, budget/2)
		}
		return out
	default:
		return value
	}
}

// stampGenerations annotates a successful mutation result with the observed
// generations before and after.
func stampGenerations(result map[string]any, before, after uint64) map[string]any {
	result["target_generation_before"] = before
	result["target_generation_after"] = after
	return result
}

// targetGenerationConflict builds the standard conflict failure for a caller
// whose observed generation no longer matches the target.
func targetGenerationConflict(server *Server, expected uint64) *toolFailure {
	current := server.target.Generation()
	return &toolFailure{
		Code:    "target_generation_conflict",
		Message: fmt.Sprintf("target generation %d does not match expected %d; the machine changed since the caller's last observation", current, expected),
		Data: map[string]any{
			"expected_target_generation": expected,
			"target_generation":          current,
			"target_generation_state":    "known",
			"rom":                        server.currentROMPath(),
			"retry_hint":                 "Re-read the target with a read-only tool, then retry with the target_generation it reports.",
		},
	}
}

// targetGenerationPrecondition evaluates a caller's expected generation,
// returning the resynchronization failure while the target revision is
// unknown and the conflict failure on mismatch.
func targetGenerationPrecondition(server *Server, expected uint64) *toolFailure {
	if server.target.Unknown() {
		current := server.target.Generation()
		return &toolFailure{
			Code:    "target_resynchronization_required",
			Message: "the target revision is unknown after an ambiguous failure; observe the target with a read-only tool before retrying a guarded mutation",
			Data: map[string]any{
				"target_generation_state":      "unknown",
				"last_known_target_generation": current,
				"retry_hint":                   "Call a read-only tool such as emulator_status, then retry with the target_generation it reports.",
			},
		}
	}
	return targetGenerationConflict(server, expected)
}

// controlHeldFailure renders the standard failure for an active foreign lock.
// The control id itself is never exposed to the rejected caller.
func controlHeldFailure(lock *analysis.ControlLock, currentGeneration uint64) *toolFailure {
	return &toolFailure{
		Code:    "target_control_held",
		Message: fmt.Sprintf("the target is under exclusive control: %q (expires %s); present the matching control_id from target_control_acquire", lock.Purpose, lock.ExpiresAt.Format(time.RFC3339)),
		Data: map[string]any{
			"control_purpose":    lock.Purpose,
			"control_expires_at": lock.ExpiresAt,
			"control_context_id": lock.ContextID,
			"target_generation":  currentGeneration,
		},
	}
}

// injectTargetGeneration stamps every tool result with the target generation
// observed at response completion. Mutating tools already report explicit
// target_generation_before/after; the stamp is the current generation (the
// after value for a successful mutation). Read-only tools get the generation
// they observed, so a read -> guarded mutation round trip is safe.
func injectTargetGeneration(server *Server, result map[string]any) map[string]any {
	if server == nil || server.target == nil {
		return result
	}
	generation := server.target.Generation()
	if structured, ok := result["structuredContent"].(map[string]any); ok {
		if _, exists := structured["target_generation"]; !exists {
			structured["target_generation"] = generation
		}
		return result
	}
	content, ok := result["content"].([]map[string]string)
	if !ok || len(content) == 0 {
		return result
	}
	var value map[string]any
	if err := json.Unmarshal([]byte(content[0]["text"]), &value); err != nil {
		return result
	}
	if _, exists := value["target_generation"]; !exists {
		value["target_generation"] = generation
	}
	if encoded, err := json.Marshal(value); err == nil {
		content[0]["text"] = string(encoded)
	}
	return result
}
