package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/StealthC/exodus-mcp/internal/experiment"
)

// experimentAllowlist is the bounded tool surface scripts and fixtures may
// call. Every entry exists today; recursive, control-plane, and
// context/lease management tools are deliberately absent so a script cannot
// escalate its mediation windows or leave global execution in an arbitrary
// state.
var experimentAllowlist = map[string]bool{
	"input_set":            true,
	"frame_advance":        true,
	"state_save":           true,
	"state_load":           true,
	"memory_write":         true,
	"memory_read":          true,
	"memory_dump":          true,
	"memory_search":        true,
	"frame_capture":        true,
	"vdp_status":           true,
	"vdp_pixel_info":       true,
	"vdp_sprite_table":     true,
	"m68k_registers":       true,
	"z80_registers":        true,
	"cpu_coverage_capture": true,
}

const (
	defaultExperimentTimeoutMS = 30000
	maxExperimentTimeoutMS     = 300000
)

func experimentToolSpecs() []toolSpec {
	return []toolSpec{
		{
			name:        "experiment_run",
			description: "Run an operator-authored experiment script (.py) or declarative fixture (.json) from the configured scripts directory (EXODUS_MCP_SCRIPTS_DIR / --scripts; launcher default: repo scripts/experiments). The server mediates every step against an allowlist, injects this context and its lease, and records a reproducible manifest artifact plus capped script output; scripts never see the native pipe or capability. Requires an exclusive context lease.",
			schema: objectSchema(map[string]any{
				"context":          stringProperty("Analysis context handle that owns the experiment artifacts and mutations."),
				"lease_id":         stringProperty("Lease id returned by context_lease_acquire; the experiment and every mutating step run under it."),
				"script":           stringProperty("Script file name inside the configured scripts directory; must end in .py or .json and contain no path separators."),
				"arguments":        map[string]any{"type": "object", "description": "JSON values passed verbatim to the script through the init message."},
				"initial_state_id": stringProperty("Optional state id loaded with state_load before the first script step."),
				"timeout_ms":       integerProperty(fmt.Sprintf("Wall-clock budget for the whole run (default %d, cap %d).", defaultExperimentTimeoutMS, maxExperimentTimeoutMS), 1),
			}, []string{"context", "lease_id", "script"}),
			run: runExperiment,
		},
	}
}

type experimentRunArgs struct {
	Context        string         `json:"context"`
	LeaseID        string         `json:"lease_id"`
	Script         string         `json:"script"`
	Arguments      map[string]any `json:"arguments"`
	InitialStateID string         `json:"initial_state_id"`
	TimeoutMS      *int64         `json:"timeout_ms"`
}

func runExperiment(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[experimentRunArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	runner := tc.server.experiments
	if runner == nil {
		return failureResult(&toolFailure{
			Code:    "experiments_disabled",
			Message: "experiment_run is not configured: launch exodus-mcp with --scripts (EXODUS_MCP_SCRIPTS_DIR) and a writable scripts directory",
		}, tc.modern)
	}
	if failure := tc.server.requireLease(context, parsed.LeaseID, "experiment_run"); failure != nil {
		return failureResult(failure, tc.modern)
	}
	timeout := time.Duration(defaultExperimentTimeoutMS) * time.Millisecond
	if parsed.TimeoutMS != nil {
		if *parsed.TimeoutMS < 1 {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "timeout_ms must be positive"}, tc.modern)
		}
		timeout = time.Duration(*parsed.TimeoutMS) * time.Millisecond
	}
	timeout = runner.ResolveTimeout(timeout)
	script, err := experiment.ResolveAndRead(runner.ScriptsDir(), parsed.Script)
	if err != nil {
		return failureResult(experimentFailure(err), tc.modern)
	}

	executor := &experimentExecutor{server: tc.server, contextID: context.ID, leaseID: parsed.LeaseID}
	if parsed.InitialStateID != "" {
		if _, err := executor.Call(tc.ctx, "state_load", map[string]any{"state_id": parsed.InitialStateID}); err != nil {
			var toolErr *experiment.ToolError
			code := "initial_state_load_failed"
			message := err.Error()
			if errors.As(err, &toolErr) {
				code = toolErr.Code
			}
			return failureResult(&toolFailure{Code: code, Message: "load initial_state_id: " + message}, tc.modern)
		}
	}

	result, err := runner.Run(tc.ctx, experiment.RunRequest{
		ExperimentID:   experiment.NewID(),
		ContextID:      context.ID,
		LeaseID:        parsed.LeaseID,
		Script:         script,
		Arguments:      parsed.Arguments,
		InitialStateID: parsed.InitialStateID,
		Timeout:        timeout,
		Exec:           executor,
	})
	if err != nil {
		return failureResult(&toolFailure{Code: "experiment_error", Message: err.Error()}, tc.modern)
	}
	tc.server.recordMutation(context, parsed.LeaseID, "experiment_run", map[string]any{
		"experiment_id":    result.ExperimentID,
		"script":           map[string]any{"name": result.ScriptName, "kind": result.ScriptKind, "sha256": result.ScriptSHA256},
		"initial_state_id": result.InitialStateID,
		"final_state_id":   result.FinalStateID,
		"status":           result.Status,
		"duration_ms":      result.DurationMS,
		"steps":            len(result.Steps),
		"manifest_id":      result.Manifest.ID,
	})

	artifacts := []map[string]any{artifactDescriptor(tc.server, result.Manifest, context.ID)}
	for _, ref := range result.Artifacts {
		artifacts = append(artifacts, experimentArtifactView(ref, tc.server, context.ID))
	}
	if result.Status != experiment.StatusCompleted {
		data := map[string]any{
			"experiment_id": result.ExperimentID,
			"status":        result.Status,
			"error": map[string]any{
				"code":    result.Error.Code,
				"message": result.Error.Message,
			},
			"manifest":  artifactDescriptor(tc.server, result.Manifest, context.ID),
			"artifacts": artifacts,
		}
		return failureResult(&toolFailure{Code: "experiment_failed", Message: result.Error.Message, Data: data}, tc.modern)
	}
	return okResult(map[string]any{
		"experiment_id":    result.ExperimentID,
		"status":           result.Status,
		"script":           map[string]any{"name": result.ScriptName, "kind": result.ScriptKind, "sha256": result.ScriptSHA256},
		"completed_steps":  len(result.Steps),
		"duration_ms":      result.DurationMS,
		"initial_state_id": result.InitialStateID,
		"final_state_id":   result.FinalStateID,
		"artifacts":        artifacts,
	}, tc.modern)
}

// experimentFailure maps script resolution errors to stable tool codes.
func experimentFailure(err error) *toolFailure {
	switch {
	case errors.Is(err, experiment.ErrScriptNotFound):
		return &toolFailure{Code: "script_not_found", Message: err.Error()}
	case errors.Is(err, experiment.ErrScriptDisallowed):
		return &toolFailure{Code: "script_disallowed", Message: err.Error()}
	case errors.Is(err, experiment.ErrScriptTooLarge):
		return &toolFailure{Code: "script_too_large", Message: err.Error()}
	default:
		return &toolFailure{Code: "script_error", Message: err.Error()}
	}
}

// experimentArtifactView renders the artifact descriptor for script-published
// artifacts, matching the descriptor shape of artifactDescriptor without a
// full artifact.Artifact record.
func experimentArtifactView(ref experiment.ArtifactRef, server *Server, contextID string) map[string]any {
	return map[string]any{
		"id":           ref.ID,
		"kind":         ref.Kind,
		"mime_type":    ref.MimeType,
		"size_bytes":   ref.SizeBytes,
		"sha256":       ref.SHA256,
		"url":          fmt.Sprintf("%s/artifacts/%s?context=%s", server.baseURL, ref.ID, contextID),
		"resource_uri": "exodus://artifacts/" + ref.ID,
	}
}

// experimentExecutor implements experiment.Executor on top of the real tool
// registry. Every call injects the experiment's context and lease, so a
// script can never address another context or bypass the lease guard; the
// response handed to the script is the structuredContent of the tool result.
type experimentExecutor struct {
	server    *Server
	contextID string
	leaseID   string
}

func (executor *experimentExecutor) Call(ctx context.Context, tool string, arguments map[string]any) (map[string]any, error) {
	if !experimentAllowlist[tool] {
		return nil, &experiment.ToolError{
			Code:    "tool_not_allowed",
			Message: fmt.Sprintf("tool %q is not on the experiment allowlist", tool),
		}
	}
	spec := lookupTool(tool)
	if spec == nil {
		return nil, &experiment.ToolError{Code: "unknown_tool", Message: fmt.Sprintf("unknown tool %q", tool)}
	}
	if arguments == nil {
		arguments = map[string]any{}
	}
	arguments["context"] = executor.contextID
	arguments["lease_id"] = executor.leaseID
	raw, err := json.Marshal(arguments)
	if err != nil {
		return nil, &experiment.ToolError{Code: "tool_args_invalid", Message: "encode tool arguments: " + err.Error()}
	}
	result := spec.run(toolContext{server: executor.server, ctx: ctx, modern: true}, raw)
	if failed, _ := result["isError"].(bool); failed {
		content, _ := result["structuredContent"].(map[string]any)
		code, _ := content["code"].(string)
		message, _ := content["message"].(string)
		if code == "" {
			code = "tool_error"
		}
		if message == "" {
			message = tool + " failed"
		}
		return nil, &experiment.ToolError{Code: code, Message: message}
	}
	content, _ := result["structuredContent"].(map[string]any)
	if content == nil {
		content = map[string]any{}
	}
	return content, nil
}
