package mcp

import (
	"encoding/json"
)

// target_status is the single target-observation tool (roadmap issue #17). It
// answers "what is the target right now" once: bridge connectivity, the observed
// run state, the loaded modules and devices, the cartridge, and the platform
// baseline. It absorbs bridge_status, emulator_status and target_info, which
// stay registered as deprecated aliases for one release.
//
// The tool is deliberately more resilient than the tools it absorbs: a section
// the bridge cannot answer is reported as unavailable with the reason instead of
// failing the whole observation, so a caller can always see the bridge
// connectivity it does have. The deprecated aliases keep their stricter
// behavior (emulator_status and target_info still fail when the emulator status
// is unavailable), because their payloads cannot express a partial answer.

func targetStatusSpec() toolSpec {
	return toolSpec{
		name:        "target_status",
		description: "Observe the target in one call: bridge connectivity and supported operations (bridge), the observed run state with pause/stop attribution (run_state), the loaded modules, processor and memory device inventory (devices), the cartridge summary including the light Mega Drive header read (rom), the platform baseline (platform), and the emulator identity (emulator). A section the bridge cannot answer reports available=false with an unavailable block naming the reason instead of failing the whole observation; log lifecycle events use bridge.lifecycle, and the full parsed cartridge header lives in rom_info. No arguments.",
		schema:      objectSchema(map[string]any{}, nil),
		run:         runTargetStatus,
	}
}

func runTargetStatus(tc toolContext, args json.RawMessage) map[string]any {
	if _, failure := decodeArgs[noArgs](args); failure != nil {
		return failureResult(failure, tc.modern)
	}
	result := map[string]any{
		"bridge": bridgeStatusView(tc),
	}

	emulator, failure := fetchEmulatorStatus(tc)
	if failure != nil {
		// The identity is still available from the bridge; everything that
		// needs the live device inventory is not.
		result["emulator"] = emulatorIdentityView(tc, nil)
		result["run_state"] = map[string]any{
			"available":    false,
			"run_state":    runStateUnknown,
			"pause_source": pauseSourceUnknown,
			"stop_source":  stopSourceUnknown,
			"unavailable":  unavailableSectionView(failure),
		}
		result["devices"] = map[string]any{
			"available":     false,
			"count":         0,
			"processors":    []string{},
			"memory_spaces": []string{},
			"modules":       []moduleInfo{},
			"entries":       []deviceInfo{},
			"unavailable":   unavailableSectionView(failure),
		}
		result["rom"] = map[string]any{
			"available":   false,
			"loaded":      false,
			"unavailable": unavailableSectionView(failure),
		}
		result["platform"] = targetInfoPlatformView()
		return okResult(result, tc.modern)
	}

	statusView := emulatorStatusView(tc, emulator)
	runState := map[string]any{"available": true}
	for _, key := range []string{
		"system_running", "run_state", "pause_source", "stop_source",
		"last_run_state_change", "run_state_note", "pause_source_note",
		"one_shot_removals", "one_shot_note", "capture_consistency",
	} {
		if value, present := statusView[key]; present {
			runState[key] = value
		}
	}
	result["run_state"] = runState
	result["devices"] = map[string]any{
		"available":     true,
		"count":         len(emulator.Devices),
		"processors":    deviceSummaryView(emulator)["processors"],
		"memory_spaces": deviceSummaryView(emulator)["memory_spaces"],
		"modules":       emulator.Modules,
		"entries":       emulator.Devices,
	}
	result["platform"] = targetInfoPlatformView()

	rom := map[string]any{"available": true}
	for key, value := range emulator.RomView() {
		rom[key] = value
	}
	summary := targetInfoROM(tc)
	rom["summary"] = summary
	for key, value := range summary {
		if _, present := rom[key]; !present {
			rom[key] = value
		}
	}
	result["rom"] = rom

	statusPayload, statusFailure := tc.server.executeCommand(tc.ctx, "status", nil)
	if statusFailure != nil {
		statusPayload = nil
	}
	result["emulator"] = emulatorIdentityView(tc, statusPayload)
	return okResult(result, tc.modern)
}

// unavailableSectionView renders why one section of target_status is missing.
func unavailableSectionView(failure *toolFailure) map[string]any {
	return map[string]any{
		"code":    failure.Code,
		"class":   errorClassOf(failure.Code),
		"message": failure.Message,
	}
}

// RomView renders the cartridge facts of one observed status as a map, so the
// canonical tool can merge the header summary into the same object.
func (status *emulatorStatusData) RomView() map[string]any {
	return map[string]any{
		"loaded":            status.Rom.Loaded,
		"size_bytes":        status.Rom.SizeBytes,
		"padded_size_bytes": status.Rom.PaddedSizeBytes,
		"path":              status.Rom.Path,
		"path_source":       status.Rom.PathSource,
	}
}
