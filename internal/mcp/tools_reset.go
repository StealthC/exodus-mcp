package mcp

import (
	"encoding/json"
	"strconv"
)

func resetToolSpecs() []toolSpec {
	return []toolSpec{{
		name:        "target_reset",
		description: "Reset the emulated Mega Drive. kind hard reloads the current cartridge module and purges MCP-managed debug resources. kind soft requires the versioned native Mega Drive reset operation; it is rejected as unsupported when the connected fork does not provide that operation, with no register or memory-write fallback. Accepts optional expected_target_generation and control_id.",
		schema: objectSchema(map[string]any{
			"context":                    contextProperty(),
			"kind":                       enumProperty("Reset kind.", []string{"hard", "soft"}),
			"expected_target_generation": integerProperty("Optional target generation precondition.", 1),
			"control_id":                 stringProperty("Optional exclusive control id."),
		}, []string{"kind"}),
		run: runTargetReset,
	}}
}

type targetResetArgs struct {
	Context string `json:"context"`
	Kind    string `json:"kind"`
	guardArgs
}

func runTargetReset(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[targetResetArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.Kind == "hard" {
		path := tc.server.currentROMPath()
		if path == "" {
			return failureResult(&toolFailure{Code: "no_rom_loaded", Message: "no cartridge path is known"}, tc.modern)
		}
		payload, before, after, invalidated, failure := performROMLoad(tc, path, true, parsed.guard(), context.ID, map[string]any{"kind": "hard", "path": path, "run": true}, "target_reset")
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		if len(invalidated) > 0 {
			payload["resources_invalidated"] = invalidated
		}
		recordStateFromPayload(tc.server, payload, false)
		payload["reset_source"] = "hard"
		payload["reset_note"] = "Hard reset reloaded the cartridge module and purged MCP-managed debug resources."
		return okResult(stampGenerations(payload, before, after), tc.modern)
	}
	if parsed.Kind != "soft" {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "kind must be \"hard\" or \"soft\""}, tc.modern)
	}
	return runSoftReset(tc, *parsed, context.ID)
}

func runSoftReset(tc toolContext, parsed targetResetArgs, contextID string) map[string]any {
	status, err := tc.server.statusFor(tc.ctx)
	if err != nil {
		return failureResult(&toolFailure{Code: "bridge_unavailable", Message: err.Error()}, tc.modern)
	}
	if !status.SupportsOperation("soft_reset") {
		return failureResult(&toolFailure{Code: "unsupported_plugin", Message: "The connected ExodusMcpPlugin does not advertise the versioned native 'soft_reset' operation. Update the Exodus fork and extension DLL.", Data: map[string]any{"supported_operations": status.SupportedOperations}}, tc.modern)
	}
	var invalidated []string
	payload, before, after, failure := tc.server.executeMutation(tc.ctx, mutationCall{
		tool: "target_reset", operation: "soft_reset", params: nil, guard: parsed.guard(), contextID: contextID,
		detail: map[string]any{"kind": "soft"},
		prepare: func() *toolFailure {
			for _, id := range tc.server.freezes.ids() {
				invalidated = append(invalidated, id)
			}
			for _, id := range tc.server.debugResourceIDs() {
				invalidated = append(invalidated, strconv.FormatUint(id, 10))
			}
			return nil
		},
		commit:    func() { tc.server.freezes.purge(); tc.server.purgeDebugResources() },
		resources: func() []string { return invalidated },
	})
	if failure != nil {
		if failure.Code == "soft_reset_partial" {
			if failure.Data == nil {
				failure.Data = map[string]any{}
			}
			failure.Data["state_changed"] = true
			failure.Data["resources_invalidated"] = invalidated
		}
		return failureResult(failure, tc.modern)
	}
	payload["resources_invalidated"] = invalidated
	return okResult(stampGenerations(payload, before, after), tc.modern)
}
