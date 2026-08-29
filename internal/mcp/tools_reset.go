package mcp

import (
	"encoding/json"
)

// resetToolSpecs implements the discoverable reset surface (roadmap Phase 9).
// Hard reset is the documented same-path cartridge reload: the module reload
// reinitializes the system and purges all MCP-managed debug resources in one
// audited batch. Soft reset is not delivered — a debugger-driven reset-vector
// jump needs a register-write primitive and explicit semantics.
func resetToolSpecs() []toolSpec {
	return []toolSpec{
		{
			name:        "target_reset",
			description: "Reset the emulated Mega Drive. kind \"hard\" reloads the currently loaded cartridge module — the same operation rom_load performs when given the current path: the system is reinitialized and all MCP-managed debug resources (breakpoints, watchpoints, freezes) are purged in one audited invalidation batch, and the system runs afterwards. The current cartridge path is taken from emulator_status (rom.path), so a cartridge opened through the Exodus UI is reset identically to one loaded via rom_load. kind \"soft\" is not delivered (a debugger-driven reset-vector jump is under design); register or memory writes are never a documented reset workaround. Accepts optional expected_target_generation and control_id; a mismatch fails with target_generation_conflict before any native action.",
			schema: objectSchema(map[string]any{
				"context":                    contextProperty(),
				"kind":                       enumProperty("Reset kind.", []string{"hard"}),
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
				"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
			}, []string{"kind"}),
			run: runTargetReset,
		},
	}
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
	if parsed.Kind != "hard" {
		if parsed.Kind == "soft" {
			return failureResult(&toolFailure{
				Code:    "invalid_params",
				Message: `kind "soft" is not delivered: a debugger-driven reset-vector jump (SP/PC re-read from the cartridge header, RAM preserved) is under design; use kind "hard", which reloads the loaded cartridge module.`,
			}, tc.modern)
		}
		return failureResult(&toolFailure{Code: "invalid_params", Message: "kind must be \"hard\""}, tc.modern)
	}
	path := tc.server.currentROMPath()
	if path == "" {
		return failureResult(&toolFailure{
			Code:    "no_rom_loaded",
			Message: "no cartridge path is known; load one with rom_load or open one in the Exodus UI (emulator_status reports rom.path and path_source)",
		}, tc.modern)
	}

	// Hard reset is the documented same-path module reload; the shared
	// rom_load mutation path purges managed debug resources and reinitializes
	// the system, and always runs afterwards.
	payload, before, after, invalidated, failure := performROMLoad(tc, path, true, parsed.guard(), context.ID, map[string]any{
		"kind": "hard",
		"path": path,
		"run":  true,
	}, "target_reset")
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if len(invalidated) > 0 {
		payload["resources_invalidated"] = invalidated
	}
	recordStateFromPayload(tc.server, payload, false)
	result := stampGenerations(payload, before, after)
	result["reset_source"] = "hard"
	result["reset_note"] = "Hard reset reloaded the loaded cartridge module: the system was reinitialized and all MCP-managed debug resources were purged in one audited batch."
	return okResult(result, tc.modern)
}
