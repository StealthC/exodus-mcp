package mcp

import (
	"encoding/json"
	"time"
)

// vdpCommandDMAToolSpecs exposes only native VDP observations. It deliberately
// does not synthesize the command latch from bus writes or DMA registers.
func vdpCommandDMAToolSpecs() []toolSpec {
	return []toolSpec{{
		name:        "vdp_command_dma_status",
		description: "Read the VDP command/DMA state through the native IS315_5313 interface. The command latch is reported as unknown when the pinned SDK does not expose it; DMA fields are direct observations and are never reconstructed from bus writes. This read does not alter VDP state and is bounded to the register/status summary.",
		schema:      objectSchema(map[string]any{"context": contextProperty()}, nil),
		run:         runVDPCommandDMAStatus,
	}}
}

func runVDPCommandDMAStatus(tc toolContext, _ json.RawMessage) map[string]any {
	payload, failure := tc.server.executeCommand(tc.ctx, "vdp_command_dma_status", nil)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if found, ok := payload["vdp_found"].(bool); ok && !found {
		return failureResult(&toolFailure{Code: "vdp_not_found", Message: "No Mega Drive VDP (315-5313) device is present in the loaded target"}, tc.modern)
	}
	capturedAt := time.Now().UTC()
	payload["result_type"] = "vdp-command-dma"
	payload["schema_version"] = "vdp-command-dma/1"
	payload["device"] = "315-5313 VDP"
	payload["target_generation"] = tc.server.target.Generation()
	payload["rom_identity"] = tc.server.romIdentityView(0)
	payload["captured_at"] = capturedAt.Format(time.RFC3339Nano)
	payload["capture_consistency"] = map[string]any{
		"state":             "composite_non_atomic",
		"paused_by_tool":    false,
		"initial_run_state": tc.server.runStateString(),
		"final_run_state":   tc.server.runStateString(),
		"note":              "VDP registers and internal status are observed by the native plugin; atomicity with CPU state is not claimed.",
	}
	return okResult(payload, tc.modern)
}
