package mcp

import (
	"encoding/json"
)

// memory_map is the single memory-layout tool (roadmap issue #17). It answers
// both halves of "what memory does this target have" in one call:
//
//   - reference is the Mega Drive bus map (region ranges, mirrors, backing
//     device, read/write capability, timing, byte order, I/O semantics) with the
//     live existence flag of every region;
//   - live is the live address-space inventory the bridge reports (id, owner
//     device, size, entry width, permissions, declared byte order, and the
//     processor bus mapping).
//
// mega_drive_memory_map and memory_spaces_list stay registered as deprecated
// aliases for one release.

func memoryMapSpec() toolSpec {
	return toolSpec{
		name:        "memory_map",
		description: "Report the memory layout of the target in one call. reference is the Mega Drive bus map: CPU-visible range, mirrors/mask, backing device, read/write capability, timing caveats, byte order, I/O semantics, and whether the region exists on the loaded target. live is the live address-space inventory from the bridge: space id, owner device, size, entry width, permissions, declared byte order, and the processor bus mapping (bus, bus_base, bus_offset), where bus_address = bus_base + bus_offset + space_relative_address. reference does not imply every region exists on every loaded system; live.spaces is the authoritative inventory and reference[].exists_live relates the two.",
		schema: objectSchema(map[string]any{
			"context": contextProperty(),
		}, nil),
		run: runMemoryMap,
	}
}

func runMemoryMap(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[struct {
		Context string `json:"context"`
	}](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	// Both halves are the existing implementations, composed in-process: the
	// reference map needs the context to exist, and the live inventory is
	// context-free by contract.
	if _, failure := resolveContext(tc.server, parsed.Context); failure != nil {
		return failureResult(failure, tc.modern)
	}
	reference, failure := composeTool(tc, runMegaDriveMemoryMap, map[string]any{"context": parsed.Context})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	live, failure := composeTool(tc, runMemorySpacesList, map[string]any{})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	return okResult(map[string]any{
		"reference": reference,
		"live":      live,
		"note":      "reference is the documented bus map with its live existence flags; live is the bridge inventory. A region absent from live.spaces is not addressable on the loaded target.",
	}, tc.modern)
}
