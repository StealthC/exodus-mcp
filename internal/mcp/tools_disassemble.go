package mcp

import (
	"encoding/json"
	"fmt"
)

// disassemble is the single disassembly tool (roadmap issue #17). It absorbs
// m68k_disassemble and z80_disassemble: the only difference between them was the
// processor, which is now an argument. Address batching (#18) and context
// symbol annotation (#13) are unchanged, because the merged tool delegates to
// the same per-processor handler.

type disassembleArgs struct {
	CPU          string `json:"cpu"`
	Address      any    `json:"address"`
	Addresses    []any  `json:"addresses"`
	AddressSpace string `json:"address_space"`
	Count        uint64 `json:"count"`
	Context      string `json:"context"`
}

func disassembleSpec() toolSpec {
	return toolSpec{
		name:        "disassemble",
		description: "Disassemble instructions of one processor from a start address (default: current PC) via linear sweep. Not execution-verified; bytes are echoed for interpretation. Context symbols are resolved into per-line `symbol` and `targets` annotations. Pass `addresses` (up to 32) to disassemble several independent locations in one call: each becomes one native sweep of one instruction and a `batches` entry carrying its own lines, so a caller annotating a coverage report makes one MCP call instead of one per address. cpu selects the processor and therefore the address bus (m68k = 24-bit big-endian bus, z80 = 16-bit little-endian bus).",
		schema: objectSchema(map[string]any{
			"cpu":       cpuVocab.property("Processor to disassemble."),
			"address":   addressProperty(),
			"addresses": disassemblyAddressesProperty(),
			"count":     integerProperty(fmt.Sprintf("Instruction count between 1 and %d (default %d).", maxDisassemblyCount, defaultDisassemblyCount), 1),
			"context":   contextProperty(),
		}, []string{"cpu"}),
		run: runDisassemble,
	}
}

func runDisassemble(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[disassembleArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.CPU == "" {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "cpu is required: m68k or z80"}, tc.modern)
	}
	if failure := cpuVocab.validate(parsed.CPU); failure != nil {
		return failureResult(failure, tc.modern)
	}
	payload, failure := composeTool(tc, makeRunDisassembly(parsed.CPU), map[string]any{
		"address":       parsed.Address,
		"addresses":     parsed.Addresses,
		"address_space": parsed.AddressSpace,
		"count":         parsed.Count,
		"context":       parsed.Context,
	})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	// The per-processor handler echoes the processor on every path (single sweep
	// and batch); fill it in defensively so the merged payload always names the
	// processor it decoded.
	if _, present := payload["cpu"]; !present {
		payload["cpu"] = parsed.CPU
	}
	return okResult(payload, tc.modern)
}
