package mcp

import (
	"fmt"
	"strings"
)

// Space bus mapping (Mega Drive baseline).
//
// memory_spaces_list reports space-relative (0-based) address domains. Those
// domains are ambiguous on their own: the validated 2026-08-25 session showed
// memory_dump rejecting 0xFF0000 on mem-ram because the space is 0-based, and
// the correct bus window had to be guessed. This documented table maps each
// known space id to its processor bus window so callers can translate
// bus_address = bus_base + bus_offset + space_relative_address.
//
// The plugin enumerates spaces from the loaded device list and cannot read a
// memory device's bus attachment through the extension interfaces, so the
// mapping lives server-side as a documented Mega Drive baseline table. Unknown
// spaces keep the fields absent and receive an explicit note instead of a
// guessed mapping.
type spaceBusMapping struct {
	Bus       string // processor bus the window belongs to ("m68k", "z80", "")
	BusBase   uint64 // bus address of space-relative address 0
	BusOffset uint64 // constant offset added after bus_base (0 for 0-based spaces)
	Note      string
}

// canonicalHex formats an address as uppercase zero-padded 0x hex with at
// least six digits, matching the roadmap's canonical address form.
func canonicalHex(value uint64) string {
	return fmt.Sprintf("0x%06X", value)
}

// mdSpaceBusMap is the documented Mega Drive baseline mapping keyed by the
// exact space ids the plugin emits for the classic Mega Drive system.
var mdSpaceBusMap = map[string]spaceBusMapping{
	"m68k-bus": {
		Bus:       "m68k",
		BusBase:   0x000000,
		BusOffset: 0,
		Note:      "Space addresses are the 24-bit 68000 bus addresses; bus_base is the bus origin.",
	},
	"mem-ram": {
		Bus:       "m68k",
		BusBase:   0xFF0000,
		BusOffset: 0,
		Note:      "68000 work RAM occupies 0xFF0000-0xFFFFFF on the M68K bus (mirrored every 0x10000); the space is 0-based.",
	},
	"mem-rom": {
		Bus:       "m68k",
		BusBase:   0x000000,
		BusOffset: 0,
		Note:      "Cartridge ROM window starts at 0x000000; the padded image is bus-mirrored across 0x000000-0x3FFFFF.",
	},
	"mem-boot-rom": {
		Bus:       "m68k",
		BusBase:   0x000000,
		BusOffset: 0,
		Note:      "Boot ROM occupies the start of the 68000 bus window.",
	},
	"m68k-ram": {
		Bus:       "m68k",
		BusBase:   0xFF0000,
		BusOffset: 0,
		Note:      "68000 work RAM occupies 0xFF0000-0xFFFFFF on the M68K bus; this alias is space-relative.",
	},
	"mem-z80-ram": {
		Bus:       "m68k",
		BusBase:   0xA00000,
		BusOffset: 0,
		Note:      "Z80 RAM is the 68K-visible window at 0xA00000 into the Z80 address space; the space itself is 0-based.",
	},
	"z80-ram": {
		Bus:       "z80",
		BusBase:   0,
		BusOffset: 0,
		Note:      "Z80 work RAM is a 0-based space-relative view of the Z80 bus.",
	},
	"z80-bus": {
		Bus:       "z80",
		BusBase:   0x000000,
		BusOffset: 0,
		Note:      "Space addresses are the 16-bit Z80 bus addresses; the 68K bus exposes this window at 0xA00000.",
	},
}

// mdSpaceBusNotes describes mapping-relevant spaces that are not linearly
// reachable on any processor bus.
var mdSpaceBusNotes = map[string]string{
	"mem-vdp-vram":        "VDP VRAM is not linearly mapped on a CPU bus; it is accessed through the VDP ports at 0xC00000.",
	"mem-vdp-cram":        "VDP CRAM is not linearly mapped on a CPU bus; it is accessed through the VDP ports at 0xC00000.",
	"mem-vdp-vsram":       "VDP VSRAM is not linearly mapped on a CPU bus; it is accessed through the VDP ports at 0xC00000.",
	"mem-vdp-spritecache": "VDP sprite cache is an internal render-time buffer, not linearly mapped on a CPU bus.",
}

// annotateSpaceBusMapping adds the bus mapping fields to one space entry.
// Known spaces receive bus, bus_base, bus_offset, and a note; unknown spaces
// receive only a note, never a guessed mapping. bus_address follows
// bus_address = bus_base + bus_offset + space_relative_address.
func annotateSpaceBusMapping(space map[string]any) {
	id, _ := space["id"].(string)
	if mapping, known := mdSpaceBusMap[id]; known {
		space["bus_base"] = mapping.BusBase
		space["bus_offset"] = mapping.BusOffset
		space["bus"] = mapping.Bus
		space["bus_mapping_note"] = mapping.Note + " bus_address = bus_base + bus_offset + space_relative_address (" +
			canonicalHex(mapping.BusBase) + " + space address)."
		return
	}
	if note, known := mdSpaceBusNotes[id]; known {
		space["bus_mapping_note"] = note
		return
	}
	space["bus_mapping_note"] = "No documented bus mapping for this space; treat space-relative addresses as opaque."
}

// spaceRangeHex renders the canonical valid range of one space from its byte
// size, e.g. "0x000000-0x00FFFF".
func spaceRangeHex(sizeBytes uint64) string {
	if sizeBytes == 0 {
		return canonicalHex(0) + "-" + canonicalHex(0)
	}
	return canonicalHex(0) + "-" + canonicalHex(sizeBytes-1)
}

// spaceIDFromEntry extracts the space id from a mem_spaces catalog entry.
func spaceIDFromEntry(entry map[string]any) string {
	id, _ := entry["id"].(string)
	return id
}

// findSpaceSizeBytes locates one space in a mem_spaces payload and returns
// its byte size; 0 when not found or ill-formed.
func findSpaceSizeBytes(payload map[string]any, spaceID string) uint64 {
	spaces, _ := payload["spaces"].([]any)
	for _, entry := range spaces {
		space, ok := entry.(map[string]any)
		if !ok || spaceIDFromEntry(space) != spaceID {
			continue
		}
		if size, ok := space["size_bytes"].(float64); ok && size > 0 {
			return uint64(size)
		}
	}
	return 0
}

// addressBusWidthMask returns the bus width and mask for spaces that are
// directly mapped on a CPU bus. Unknown or timed-buffer spaces return 0.
func addressBusWidthMask(spaceID string) (int, uint64) {
	switch spaceID {
	case "m68k-bus", "mem-rom", "mem-ram", "mem-boot-rom", "m68k-ram":
		return 24, 0xFFFFFF
	case "z80-bus", "mem-z80-ram", "z80-ram":
		return 16, 0xFFFF
	default:
		return 0, 0
	}
}

// readOnlySpaceReasons classifies the spaces whose backing store the debugger
// path must not modify, keyed by the catalog space id, with a stable refusal
// reason. mem-rom and mem-boot-rom are the loaded cartridge image: patching it
// in place would make the executing code disagree with the ROM identity
// reported by rom_info, snapshots, and artifacts. Writes addressed through a
// processor bus space (m68k-bus/z80-bus) keep real hardware behavior instead,
// where the cartridge ignores them.
//
// This table is the single source of truth: memory_spaces_list derives the
// reported permissions from it and memory_write enforces it, so a new
// read-only space only needs one entry here to be enforced everywhere.
var readOnlySpaceReasons = map[string]string{
	"mem-rom":      "read_only_image",
	"mem-boot-rom": "read_only_image",
}

// spaceWritePolicy is the resolved write decision for one space.
type spaceWritePolicy struct {
	Writable bool
	Reason   string // stable refusal reason; empty when writable
	Message  string // human-readable refusal detail; empty when writable
}

// spaceWritePolicyFor resolves the write decision for one space id. It depends
// only on the id because the plugin reports every VDP memory shell as
// "mem-vdp-*" and never emits a separate timed-buffer kind, so the id is the
// one fact both the catalog view and the write path always share.
func spaceWritePolicyFor(spaceID string) spaceWritePolicy {
	if spaceID == "" {
		return spaceWritePolicy{Writable: true}
	}
	if strings.HasPrefix(spaceID, "mem-vdp-") {
		return spaceWritePolicy{
			Reason:  "timed_buffer_device",
			Message: "space " + spaceID + " is a timed-buffer device owned by its worker thread and cannot be written through the debugger path",
		}
	}
	if reason, readOnly := readOnlySpaceReasons[spaceID]; readOnly {
		return spaceWritePolicy{
			Reason:  reason,
			Message: "space " + spaceID + " is a read-only image space; the loaded cartridge image is not writable through the debugger path",
		}
	}
	return spaceWritePolicy{Writable: true}
}

// spaceWriteRefusal renders the standard refusal for a write to a read-only
// space. It echoes the same permission list memory_spaces_list reports so a
// caller sees the catalog and the write path agree, plus the instruction that
// bus-addressed writes keep hardware behavior.
func spaceWriteRefusal(spaceID string, policy spaceWritePolicy) *toolFailure {
	return &toolFailure{
		Code:    "write_not_supported",
		Message: policy.Message,
		Data: map[string]any{
			"space":       spaceID,
			"permissions": spacePermissions(map[string]any{"id": spaceID}),
			"reason":      policy.Reason,
			"write_path":  "debugger",
			"note":        "memory_spaces_list reports this space as read-only. Writes addressed through a processor bus space (for example m68k-bus) keep real hardware behavior, where the cartridge ignores them.",
		},
	}
}

// spacePermissions reports the readable and writable capabilities of a space
// exactly as memory_write enforces them: timed-buffer VDP shells and the
// loaded cartridge image are read-only, every other bus and memory space is
// read+write through the debugger path.
func spacePermissions(space map[string]any) []string {
	id, _ := space["id"].(string)
	if spaceWritePolicyFor(id).Writable {
		return []string{"read", "write"}
	}
	return []string{"read"}
}

// annotateSpaceRangeFailure enriches an out_of_range failure with the valid
// canonical hex range of the target space. It queries the live catalog on
// the error path (rare) and leaves the failure untouched when the plugin
// already included the "spans" clause or the catalog cannot be read.
func annotateSpaceRangeFailure(tc toolContext, failure *toolFailure, spaceID string) *toolFailure {
	if failure == nil || failure.Code != "out_of_range" || strings.TrimSpace(spaceID) == "" ||
		strings.Contains(failure.Message, "spans") {
		return failure
	}
	spacesPayload, err := tc.server.executeCommand(tc.ctx, "mem_spaces", nil)
	if err != nil {
		return failure
	}
	size := findSpaceSizeBytes(spacesPayload, spaceID)
	if size == 0 {
		return failure
	}
	failure.Message += "; valid range: " + spaceRangeHex(size) + " (space " + spaceID + ", " + fmt.Sprintf("%d bytes)", size)
	return failure
}
