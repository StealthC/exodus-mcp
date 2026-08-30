package mcp

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/StealthC/exodus-mcp/internal/analysis"
	"github.com/StealthC/exodus-mcp/internal/artifact"
)

// Phase 5 — Advanced analysis tools. Each tool is artifact-first and either
// reads a consistent snapshot (memory_search) or reuses the proven
// trace_capture bridge op (watchpoint-triggered tracing, coverage) without
// adding new bridge operations.

const (
	defaultSearchMaxMatches  = 64
	maxSearchMaxMatches      = 1024
	maxSearchArtifactMatches = 1 << 18 // addresses in one full-results artifact
	maxCoverageAddresses     = 1 << 16
	coveragePageSize         = uint64(0x100)
	coverPageTop             = 32
)

func phase5ToolSpecs() []toolSpec {
	return []toolSpec{
		memorySnapshotCaptureSpec(),
		{
			name:        "cpu_coverage_capture",
			description: "Run the system for a bounded window and record which code addresses executed into a versioned coverage artifact with instruction-aware blocks, execution counts, and observed edges (not byte-adjacent). Reuses the trace_capture path; the prior run state is restored afterwards. The system runs during the window, so the capture mutates the target and advances the target generation. Optional filters (region_start/end, include_rom/include_ram, retain_repeated) are applied and recorded in provenance. Accepts optional expected_target_generation and control_id.",
			schema: objectSchema(map[string]any{
				"cpu":                        enumProperty("Processor to trace.", []string{"m68k", "z80"}),
				"duration_ms":                integerProperty("Trace window in milliseconds (default 500, cap 5000).", 1),
				"max_entries":                integerProperty("Maximum trace entries retained (default 10000, cap 10000).", 1),
				"region_start":               addressProperty(),
				"region_end":                 addressProperty(),
				"include_rom":                booleanProperty("Include ROM addresses when filtering (default true)."),
				"include_ram":                booleanProperty("Include RAM addresses when filtering (default true)."),
				"retain_repeated":            booleanProperty("Retain repeated PC events when building coverage (default true); when false only distinct addresses are counted."),
				"context":                    stringProperty("Analysis context that will own the coverage artifact."),
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
				"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
			}, []string{"cpu"}),
			run: runCpuCoverageCapture,
		},
		{
			name:        "cpu_trace_capture_watchpoint",
			description: "Event-driven trace capture: run the system until a managed watchpoint hits and capture the executed instructions that led up to the hit. The system runs during the window even if it was parked, then the prior run state is restored, so the capture mutates the target and advances the target generation. The trace artifact is text; the summary reports which watchpoint fired. Accepts optional expected_target_generation and control_id.",
			schema: objectSchema(map[string]any{
				"watchpoint_id":              integerProperty("watchpoint id returned by cpu_watchpoint_set.", 1),
				"max_entries":                integerProperty(fmt.Sprintf("Maximum entries (default %d, cap %d).", defaultTraceEntries, maxTraceEntries), 1),
				"timeout_ms":                 integerProperty("Wait before giving up on the hit (default 5000, cap 30000).", 100),
				"context":                    stringProperty("Analysis context that will own the trace artifact."),
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
				"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
			}, []string{"watchpoint_id"}),
			run: runCpuTraceCaptureWatchpoint,
		},
		{
			name:        "memory_search",
			description: "Search a consistent snapshot for a raw byte pattern, with optional wildcard/mask. Without snapshot_id the tool dumps the range into a snapshot artifact first (never a live racy scan); with snapshot_id it searches that artifact without any new read and derives the address space, start address, byte length, and byte order from the snapshot's capture provenance. Pattern is hex bytes with optional spaces; use \"??\" or \"?\" for a single wildcard byte (any value), e.g. \"4A ?? 42\" matches 4A xx 42. Wildcard mask is explicitly documented; exact-byte mode (no wildcards) is unchanged. Optional alignment restricts matches to addresses aligned to that power-of-two. Snapshots without capture metadata (legacy) are reported as provenance_unknown. Returns bounded inline matches plus a full-results artifact that serializes the parsed pattern and mask for reproducibility.",
			schema: objectSchema(map[string]any{
				"space":         stringProperty("Address space id from memory_spaces_list; required without snapshot_id or when the snapshot lacks provenance. With a proven snapshot it must match the snapshot's captured space."),
				"pattern":       stringProperty("Byte pattern as hex with optional spaces and ??/? wildcards, e.g. \"4A 42 41\" or \"4A ?? 42\" (wildcard byte)."),
				"start_address": addressProperty(),
				"length":        integerProperty(fmt.Sprintf("Bytes to scan (default %d when no snapshot is given; must equal the snapshot size with snapshot_id).", dumpCapBytes), 1),
				"max_matches":   integerProperty(fmt.Sprintf("Maximum inline matches (default %d, cap %d).", defaultSearchMaxMatches, maxSearchMaxMatches), 1),
				"snapshot_id":   stringProperty("Optional id of a memory-dump or memory-snapshot artifact to search instead of reading again."),
				"alignment":     integerProperty("Optional alignment: matches only at addresses where (address - start_address) % alignment == 0 (must be power of two, e.g. 2 for word-aligned).", 1),
				"context":       contextProperty(),
			}, []string{"pattern"}),
			run: runMemorySearch,
		},
		{
			name:        "memory_diff",
			description: "Compare two consistent memory snapshots cell-by-cell and report cells matching a comparison mode. Without snapshot_after_id the region is read fresh into a snapshot first (never a live racy scan). The before snapshot's capture provenance supplies the address space, range, and default byte order; comparing snapshots with incompatible provenance (different space, range, or ROM identity) fails with incompatible_provenance by default — pass allow_incompatible_provenance to force it, and the response warns with both source manifests instead of fabricating a common address origin. Snapshots without capture metadata (legacy) are reported provenance_unknown. Modes: changed, unchanged, increased, decreased, changed_by (signed delta), equal_to (after value), in_range (after value bounds). Width byte/word/long with explicit byte order (default big-endian) and aligned scanning by default. Returns bounded inline matches plus a full-results artifact.",
			schema: objectSchema(map[string]any{
				"snapshot_before_id":            stringProperty("id of a memory-dump or memory-snapshot artifact representing the earlier state."),
				"snapshot_after_id":             stringProperty("optional id of a memory-dump or memory-snapshot artifact representing the later state; when omitted, the before range is read fresh into a snapshot before comparing."),
				"space":                         stringProperty("Address space id from memory_spaces_list; required when snapshot_after_id is omitted and the before snapshot lacks provenance. With a proven before snapshot it must match the captured space."),
				"mode":                          enumProperty("Comparison mode.", []string{"changed", "unchanged", "increased", "decreased", "changed_by", "equal_to", "in_range"}),
				"width":                         enumProperty("Cell width. Default byte; word/long cells honor byte_order.", []string{"byte", "word", "long"}),
				"byte_order":                    enumProperty("Byte order for word/long cells. Defaults to the before snapshot's captured byte order when it has provenance; otherwise big-endian (M68K domain); use little-endian for Z80 RAM cells.", []string{"big-endian", "little-endian"}),
				"value":                         integerProperty("Value for equal_to (unsigned, must fit the width) or the signed delta for changed_by.", 0),
				"min_value":                     integerProperty("Lower bound for in_range.", 0),
				"max_value":                     integerProperty("Upper bound for in_range.", 0),
				"start_address":                 addressProperty(),
				"max_matches":                   integerProperty(fmt.Sprintf("Maximum inline matches (default %d, cap %d).", defaultSearchMaxMatches, maxSearchMaxMatches), 1),
				"allow_misaligned":              booleanProperty("Scan every cell offset instead of aligning to the cell width in the address domain."),
				"allow_incompatible_provenance": booleanProperty("Compare snapshots whose capture provenance differs (space, range, or ROM identity) and report a prominent warning instead of failing with incompatible_provenance. Never fabricates a common address origin."),
				"context":                       contextProperty(),
			}, []string{"snapshot_before_id", "mode"}),
			run: runMemoryDiff,
		},
		{
			name:        "rom_info",
			description: "Parse the Mega Drive cartridge header at 0x100 (system type, copyright, titles, serial, checksum, I/O support, ROM/RAM/SRAM windows, region) and validate the header checksum against the computed Sega sum over the ROM body. Also reports the declared and reference memory mapping. Attaches a header-region hexdump artifact.",
			schema:      objectSchema(map[string]any{"context": contextProperty()}, nil),
			run:         runROMInfo,
		},
		megaDriveMemoryMapSpec(),
	}
}

func megaDriveMemoryMapSpec() toolSpec {
	return toolSpec{
		name:        "mega_drive_memory_map",
		description: "Structured operational Mega Drive memory map combining the reference bus map with the live target. Each region states CPU-visible range, mirrors/mask, backing device, read/write capability, timing caveats, byte order, and I/O semantics. Distinct from memory_spaces_list inventory; does not imply all reference regions exist on every loaded system.",
		schema:      objectSchema(map[string]any{"context": contextProperty()}, nil),
		run:         runMegaDriveMemoryMap,
	}
}

func runMegaDriveMemoryMap(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[struct {
		Context string `json:"context"`
	}](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if _, failure = resolveContext(tc.server, parsed.Context); failure != nil {
		return failureResult(failure, tc.modern)
	}
	// Fetch live spaces to mark which regions exist
	liveSpaces := map[string]bool{}
	if payload, err := tc.server.executeCommand(tc.ctx, "mem_spaces", nil); err == nil {
		if spaces, ok := payload["spaces"].([]any); ok {
			for _, entry := range spaces {
				if m, ok := entry.(map[string]any); ok {
					if id, ok := m["id"].(string); ok {
						liveSpaces[id] = true
					}
				}
			}
		}
	}
	type region struct {
		Range         string `json:"range"`
		CPUVisible    string `json:"cpu_visible"`
		MirrorsMask   string `json:"mirrors_mask"`
		BackingDevice string `json:"backing_device"`
		ReadWrite     string `json:"read_write"`
		TimingCaveats string `json:"timing_caveats"`
		ByteOrder     string `json:"byte_order"`
		IOSemantics   string `json:"io_semantics"`
		ExistsLive    bool   `json:"exists_live"`
	}
	regions := []region{
		{"0x000000-0x3FFFFF", "0x000000-0x3FFFFF", "mirrored every 4MB, mask 0x3FFFFF", "Cartridge ROM (mem-rom, m68k-bus)", "read (writes discarded by bus, debugger can write mem-rom)", "No timing caveats for ROM; bus reads are single-cycle", "big-endian", "Cartridge port, not I/O", liveSpaces["mem-rom"] || liveSpaces["m68k-bus"]},
		{"0x400000-0x9FFFFF", "0x400000-0x9FFFFF", "unmapped", "Unmapped / expansion", "none", "Access causes bus error on real hardware", "big-endian", "none", false},
		{"0xA00000-0xA01FFF", "0xA00000-0xA01FFF", "mirrored", "Z80 RAM (mem-z80-ram, z80-bus at 0xA00000)", "read+write", "68K-visible window into Z80 address space; Z80 has priority", "little-endian for Z80, not-applicable for 68K window", "Z80 bus window, YM2612/PSG at 0xA04000", liveSpaces["mem-z80-ram"]},
		{"0xA04000-0xA04003", "0xA04000-0xA04003", "mirrored", "YM2612 FM", "write, read status", "FM registers write-only except status", "not-applicable", "YM2612 ports", liveSpaces["m68k-bus"]},
		{"0xA10000-0xA1001F", "0xA10000-0xA1001F", "mirrored", "I/O ports (version, controller)", "read+write", "I/O area, not RAM", "not-applicable", "Controller ports, version register", liveSpaces["m68k-bus"]},
		{"0xC00000-0xC0001F", "0xC00000-0xC0001F", "mirrored every 32 bytes, 0xC00000-0xDFFFFF", "VDP ports (mem-vdp-vram/cram/vsram via 0xC00000)", "read+write via VDP ports, not via debugger mem_write", "Timing-sensitive: VDP access via ports, not direct memory; use vdp_* tools", "device-specific", "VDP control/data ports", liveSpaces["mem-vdp-vram"]},
		{"0xFF0000-0xFFFFFF", "0xFF0000-0xFFFFFF", "mirrored every 64K (0xFF0000-0xFFFFFF repeats every 0x10000)", "Work RAM (mem-ram, m68k-bus)", "read+write", "Single-cycle RAM, no wait states", "big-endian", "RAM, not I/O", liveSpaces["mem-ram"]},
	}
	return okResult(map[string]any{
		"regions":     regions,
		"note":        "Reference bus map combined with live target existence (exists_live). Not all regions exist on every loaded system; check liveSpaces via memory_spaces_list.",
		"live_spaces": liveSpaces,
	}, tc.modern)
}

// ----------------------------------------------------------------------------------------------------------------------
// Shared bridge read
// ----------------------------------------------------------------------------------------------------------------------

// readBridgeBytes executes mem_read and returns the decoded bytes, the
// space's declared byte order, the effective address, and whether the read
// temporarily paused a running system. Reads are capped at dumpCapBytes,
// matching memory_dump.
func readBridgeBytes(tc toolContext, space string, address, length uint64) ([]byte, string, uint64, bool, *toolFailure) {
	if length < 1 || length > dumpCapBytes {
		return nil, "", 0, false, &toolFailure{
			Code:    "length_out_of_range",
			Message: fmt.Sprintf("length must be between 1 and %d bytes.", dumpCapBytes),
		}
	}
	params := map[string]string{
		"space":   space,
		"address": strconv.FormatUint(address, 10),
		"length":  strconv.FormatUint(length, 10),
	}
	payload, failure := tc.server.executeCommand(tc.ctx, "mem_read", params)
	if failure != nil {
		return nil, "", 0, false, annotateSpaceRangeFailure(tc, failure, space)
	}
	rawDataBase64, _ := payload["data"].(string)
	raw, err := base64.StdEncoding.DecodeString(rawDataBase64)
	if err != nil {
		return nil, "", 0, false, &toolFailure{Code: "bridge_error", Message: "decode base64 memory payload: " + err.Error()}
	}
	byteOrder, _ := payload["byte_order"].(string)
	effective, _ := payload["effective_address"].(float64)
	pausedDuringRead, _ := payload["system_paused_during_read"].(bool)
	return raw, byteOrder, uint64(effective), pausedDuringRead, nil
}

// ----------------------------------------------------------------------------------------------------------------------
// memory_search
// ----------------------------------------------------------------------------------------------------------------------

type memorySearchArgs struct {
	Space        string `json:"space"`
	Pattern      string `json:"pattern"`
	StartAddress any    `json:"start_address"`
	AddressSpace string `json:"address_space"`
	Length       uint64 `json:"length"`
	MaxMatches   uint64 `json:"max_matches"`
	SnapshotID   string `json:"snapshot_id"`
	Alignment    uint64 `json:"alignment"`
	Context      string `json:"context"`
}

// provenanceConflict builds the structured failure for a caller parameter that
// duplicates a proven capture fact and contradicts it.
func provenanceConflict(parameter string, expected, provided any) *toolFailure {
	return &toolFailure{
		Code:    "provenance_conflict",
		Message: fmt.Sprintf("%s duplicates the snapshot's capture provenance and does not match: provenance says %v, call says %v. Omit the parameter to derive it from the snapshot.", parameter, expected, provided),
		Data: map[string]any{
			"parameter":        parameter,
			"provenance_value": expected,
			"provided_value":   provided,
		},
	}
}

// resolveSearchSource resolves the byte range memory_search scans over. With a
// snapshot_id the artifact's capture provenance supplies space, start address,
// byte length, and byte order; caller duplicates are assertions and rejected
// on mismatch. Without provenance (legacy artifacts) the caller must supply
// the addressing and the mismatch with the capture provenance is reported
// honestly. Without a snapshot the range is read fresh and stored as a
// proven snapshot artifact.
func resolveSearchSource(tc toolContext, contextID string, args memorySearchArgs, startAddress uint64, pattern []byte) (searchSource, *toolFailure) {
	source := searchSource{startAddress: startAddress, byteOrder: ""}
	if args.SnapshotID == "" {
		space := strings.TrimSpace(args.Space)
		if space == "" {
			return source, &toolFailure{Code: "invalid_params", Message: "space is required when no snapshot_id is given"}
		}
		length := args.Length
		if length == 0 {
			length = dumpCapBytes
		}
		if length < 1 || length > dumpCapBytes {
			return source, &toolFailure{
				Code:    "length_out_of_range",
				Message: fmt.Sprintf("length must be between 1 and %d bytes.", dumpCapBytes),
			}
		}
		raw, byteOrder, effective, pausedDuringRead, failure := readBridgeBytes(tc, space, startAddress, length)
		if failure != nil {
			return source, failure
		}
		payload := map[string]any{
			"effective_address":         float64(effective),
			"byte_order":                byteOrder,
			"consistency":               "live",
			"system_paused_during_read": pausedDuringRead,
		}
		provenance := captureProvenance(tc.server, "memory-snapshot", space, startAddress, uint64(len(raw)), payload, time.Now().UTC(), "", nil)
		stored, err := tc.server.store.PutWithProvenance(contextID, "memory-snapshot", "application/octet-stream", raw, provenance)
		if err != nil {
			return source, &toolFailure{Code: "artifact_error", Message: err.Error()}
		}
		source.bytes = raw
		source.descriptor = artifactDescriptor(tc.server, stored, contextID)
		source.provenance = provenance
		source.startAddress = uint64(effective)
		source.byteOrder = byteOrder
		source.pausedDuringRead = pausedDuringRead
		source.consistency = buildCaptureConsistency(tc.server, payload, false, true, nil, nil)
		source.readOrigin = "live read; system_paused_during_read reports whether the snapshot read temporarily paused a running system"
		source.provenanceNote = "complete"
		return source, nil
	}

	meta, err := tc.server.store.Metadata(args.SnapshotID, contextID)
	if err != nil {
		return source, &toolFailure{Code: "unknown_artifact", Message: err.Error()}
	}
	if meta.Kind != "memory-dump" && meta.Kind != "memory-snapshot" {
		return source, &toolFailure{
			Code:    "invalid_params",
			Message: "snapshot_id must reference a memory-dump or memory-snapshot artifact; got kind " + meta.Kind,
		}
	}
	raw, _, err := tc.server.store.Bytes(args.SnapshotID, contextID)
	if err != nil {
		return source, &toolFailure{Code: "artifact_error", Message: err.Error()}
	}
	source.bytes = raw
	source.descriptor = artifactDescriptor(tc.server, meta, contextID)
	source.pausedDuringRead = false
	source.readOrigin = "snapshot artifact reused; no new read performed, so system_paused_during_read is false"

	if meta.Provenance != nil && meta.Provenance.Known() {
		provenance := meta.Provenance
		derivedStart, _ := provenance.CapturedStart()
		derivedLength, _ := provenance.CapturedLength()
		if args.Space != "" && args.Space != provenance.AddressSpace {
			return source, provenanceConflict("space", provenance.AddressSpace, args.Space)
		}
		if args.StartAddress != nil && startAddress != derivedStart {
			return source, provenanceConflict("start_address", derivedStart, startAddress)
		}
		if args.Length != 0 && args.Length != derivedLength {
			return source, provenanceConflict("length", derivedLength, args.Length)
		}
		if args.Length == 0 && derivedLength == 0 {
			return source, &toolFailure{Code: "invalid_params", Message: "the snapshot's captured byte length is unknown; pass length explicitly"}
		}
		source.startAddress = derivedStart
		source.byteOrder = provenance.ByteOrder
		source.provenance = provenance
		source.consistency = provenance.CaptureConsistency
		source.provenanceNote = "complete"
		return source, nil
	}

	// Legacy artifact: no capture metadata. The caller's addressing anchors
	// the scan; the result is honest about the unknown origin.
	if strings.TrimSpace(args.Space) == "" {
		return source, &toolFailure{Code: "invalid_params", Message: "space is required: the snapshot has no capture provenance (legacy artifact) and its address domain cannot be derived"}
	}
	if args.Length != 0 && args.Length != uint64(len(raw)) {
		return source, &toolFailure{
			Code:    "invalid_params",
			Message: fmt.Sprintf("length %d does not match the snapshot byte length %d", args.Length, len(raw)),
		}
	}
	source.startAddress = startAddress
	source.readOrigin = "snapshot artifact reused; the artifact has no capture provenance (provenance_unknown), so matches are anchored to the caller-provided start address " + canonicalHex(startAddress)
	source.provenanceNote = "provenance_unknown"
	return source, nil
}

// searchSource is the resolved byte range and its provenance for one search.
type searchSource struct {
	bytes            []byte
	descriptor       map[string]any
	provenance       *artifact.Provenance
	startAddress     uint64
	byteOrder        string
	pausedDuringRead bool
	readOrigin       string
	provenanceNote   string
	consistency      *artifact.CaptureConsistency
}

// sourceRange renders the captured address range of the searched snapshot.
func (source *searchSource) sourceRange() map[string]any {
	rangeInfo := map[string]any{
		"start_address":     source.startAddress,
		"start_address_hex": canonicalHex(source.startAddress),
		"byte_length":       len(source.bytes),
		"end_address":       source.startAddress + uint64(len(source.bytes)) - 1,
		"end_address_hex":   canonicalHex(source.startAddress + uint64(len(source.bytes)) - 1),
	}
	if source.provenance != nil {
		if source.provenance.EffectiveAddress != nil {
			rangeInfo["effective_address"] = *source.provenance.EffectiveAddress
			rangeInfo["effective_address_hex"] = canonicalHex(*source.provenance.EffectiveAddress)
		}
		if source.provenance.AddressSpace != "" {
			rangeInfo["address_space"] = source.provenance.AddressSpace
		}
	}
	return rangeInfo
}

func runMemorySearch(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[memorySearchArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	pattern, mask, failure := parseHexPatternWithMask(parsed.Pattern)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.Alignment != 0 && (parsed.Alignment&(parsed.Alignment-1) != 0) {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "alignment must be a power of two"}, tc.modern)
	}

	maxMatches := parsed.MaxMatches
	if maxMatches == 0 {
		maxMatches = defaultSearchMaxMatches
	}
	if maxMatches > maxSearchMaxMatches {
		return failureResult(&toolFailure{
			Code:    "invalid_params",
			Message: fmt.Sprintf("max_matches is capped at %d inline matches.", maxSearchMaxMatches),
		}, tc.modern)
	}

	startAddress := uint64(0)
	if parsed.StartAddress != nil {
		startAddress, failure = resolveAddress(parsed.StartAddress, addressSpaceFromArgs(args), parsed.Space)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
	}

	source, failure := resolveSearchSource(tc, context.ID, *parsed, startAddress, pattern)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}

	spaceID := parsed.Space
	if source.provenance != nil && source.provenance.AddressSpace != "" {
		spaceID = source.provenance.AddressSpace
	}
	matches, total, inlineTruncated, artifactTruncated := findPatternMatches(source.bytes, pattern, mask, source.startAddress, maxMatches, parsed.Alignment)

	patternHex := strings.ToUpper(hex.EncodeToString(pattern))
	maskHex := strings.ToUpper(hex.EncodeToString(mask))
	results := map[string]any{
		"kind":                 "memory-search-results",
		"address_space":        spaceID,
		"pattern_hex":          patternHex,
		"pattern_mask_hex":     maskHex,
		"pattern_length_bytes": len(pattern),
		"alignment":            parsed.Alignment,
		"interpretation":       "matches are byte addresses in the address space; the pattern is raw bytes in address order with mask 00=wildcard and no endian interpretation is applied",
		"source_snapshot":      source.descriptor,
		"source_range":         source.sourceRange(),
		"range": map[string]any{
			"start_address": source.startAddress,
			"byte_length":   len(source.bytes),
		},
		"matches_total":  total,
		"truncated":      artifactTruncated,
		"addresses":      matches.Addresses,
		"parsed_pattern": map[string]any{"bytes_hex": patternHex, "mask_hex": maskHex, "alignment": parsed.Alignment},
	}
	resultsBytes, err := json.Marshal(results)
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}
	storedResults, err := tc.server.store.PutWithProvenance(context.ID, "memory-search-results", "application/json", resultsBytes, genericProvenance(tc.server, "memory-search-results", time.Now().UTC()))
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}

	summary := map[string]any{
		"kind":                       "memory-search",
		"address_space":              spaceID,
		"pattern_hex":                patternHex,
		"pattern_mask_hex":           maskHex,
		"pattern_length_bytes":       len(pattern),
		"alignment":                  parsed.Alignment,
		"interpretation":             "matches are byte addresses; raw pattern bytes preserve address order with mask 00=wildcard and are never decoded",
		"searched_start_address":     source.startAddress,
		"searched_start_address_hex": canonicalHex(source.startAddress),
		"searched_byte_length":       len(source.bytes),
		"matches_total":              total,
		"inline_matches_shown":       len(matches.Inline),
		"matches_truncated":          inlineTruncated,
		"system_paused_during_read":  source.pausedDuringRead,
		"snapshot_read_note":         source.readOrigin,
		"snapshot":                   source.descriptor,
		"source_range":               source.sourceRange(),
		"parsed_pattern":             map[string]any{"bytes_hex": patternHex, "mask_hex": maskHex, "alignment": parsed.Alignment},
	}
	if source.consistency != nil {
		summary["capture_consistency"] = captureConsistencyToMap(source.consistency)
	}
	if source.byteOrder != "" {
		summary["byte_order"] = source.byteOrder
	}
	if source.provenanceNote == "provenance_unknown" {
		summary["provenance_warning"] = "The searched snapshot has no capture provenance (provenance_unknown, legacy artifact); its address origin cannot be verified and matches are anchored to the caller-provided start address."
	}
	result := map[string]any{
		"summary":  summary,
		"matches":  matches.Inline,
		"artifact": artifactDescriptor(tc.server, storedResults, context.ID),
	}
	annotateAddressMap(result, spaceID)
	return okResult(result, tc.modern)
}

type searchMatches struct {
	Inline    []map[string]any
	Addresses []uint64
}

// findPatternMatches scans data for pattern and reports the first up to
// inlineLimit matches inline plus up to maxSearchArtifactMatches addresses for
// the full-results artifact. Adresses are anchored at startAddress.
// It supports wildcard masks (mask 0x00 = any) and optional alignment (0 = no alignment).
func findPatternMatches(data, pattern, mask []byte, startAddress uint64, inlineLimit uint64, alignment uint64) (searchMatches, uint64, bool, bool) {
	result := searchMatches{Inline: []map[string]any{}, Addresses: []uint64{}}
	var total uint64
	if len(pattern) == 0 {
		return result, 0, false, false
	}
	for index := 0; index+len(pattern) <= len(data); index++ {
		if alignment != 0 && (uint64(index)%alignment != 0) {
			continue
		}
		matched := true
		for j := 0; j < len(pattern); j++ {
			if mask[j] == 0x00 {
				continue
			}
			if data[index+j] != pattern[j] {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		total++
		address := startAddress + uint64(index)
		if uint64(len(result.Addresses)) < maxSearchArtifactMatches {
			result.Addresses = append(result.Addresses, address)
		}
		if uint64(len(result.Inline)) < inlineLimit {
			result.Inline = append(result.Inline, map[string]any{
				"address":     address,
				"address_hex": canonicalHex(address),
				"offset":      uint64(index),
			})
		}
	}
	inlineTruncated := uint64(len(result.Inline)) < total
	artifactTruncated := uint64(len(result.Addresses)) < total
	return result, total, inlineTruncated, artifactTruncated
}

func parseHexPattern(raw string) ([]byte, *toolFailure) {
	pattern, _, failure := parseHexPatternWithMask(raw)
	return pattern, failure
}

func parseHexPatternWithMask(raw string) ([]byte, []byte, *toolFailure) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil, &toolFailure{Code: "invalid_params", Message: "pattern is required and must contain hex bytes"}
	}
	// Split by whitespace to handle wildcards; if no whitespace and no wildcards, fall back to even-length cleaning
	if strings.Contains(raw, "?") {
		tokens := strings.Fields(raw)
		pattern := []byte{}
		mask := []byte{}
		for _, token := range tokens {
			if token == "?" || token == "??" {
				pattern = append(pattern, 0x00)
				mask = append(mask, 0x00)
			} else if len(token) == 2 {
				b, err := hex.DecodeString(token)
				if err != nil {
					return nil, nil, &toolFailure{Code: "invalid_params", Message: "pattern contains non-hex characters: " + err.Error()}
				}
				pattern = append(pattern, b[0])
				mask = append(mask, 0xFF)
			} else {
				return nil, nil, &toolFailure{Code: "invalid_params", Message: "wildcard pattern tokens must be '??' or two hex digits"}
			}
		}
		return pattern, mask, nil
	}
	// No wildcards: original exact mode
	cleaned := ""
	for _, r := range raw {
		switch r {
		case ' ', '\t', '\r', '\n':
		default:
			cleaned += string(r)
		}
	}
	if cleaned == "" {
		return nil, nil, &toolFailure{Code: "invalid_params", Message: "pattern is required and must contain hex bytes"}
	}
	if len(cleaned)%2 != 0 {
		return nil, nil, &toolFailure{Code: "invalid_params", Message: "pattern must contain an even number of hex digits"}
	}
	decoded, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, nil, &toolFailure{Code: "invalid_params", Message: "pattern contains non-hex characters: " + err.Error()}
	}
	mask := make([]byte, len(decoded))
	for i := range mask {
		mask[i] = 0xFF
	}
	return decoded, mask, nil
}

// ----------------------------------------------------------------------------------------------------------------------
// memory_diff — cheat-finder snapshot comparison
// ----------------------------------------------------------------------------------------------------------------------

type memoryDiffArgs struct {
	SnapshotBeforeID            string  `json:"snapshot_before_id"`
	SnapshotAfterID             string  `json:"snapshot_after_id"`
	Space                       string  `json:"space"`
	Mode                        string  `json:"mode"`
	Width                       string  `json:"width"`
	ByteOrder                   string  `json:"byte_order"`
	Value                       *int64  `json:"value"`
	MinValue                    *uint64 `json:"min_value"`
	MaxValue                    *uint64 `json:"max_value"`
	StartAddress                any     `json:"start_address"`
	AddressSpace                string  `json:"address_space"`
	MaxMatches                  uint64  `json:"max_matches"`
	AllowMisaligned             bool    `json:"allow_misaligned"`
	AllowIncompatibleProvenance bool    `json:"allow_incompatible_provenance"`
	Context                     string  `json:"context"`
}

// diffWidths maps the width argument to its byte size.
var diffWidths = map[string]int{
	"byte": 1,
	"word": 2,
	"long": 4,
}

// maxCellValue returns the largest representable unsigned value for a width.
func maxCellValue(width int) uint64 {
	switch width {
	case 2:
		return 0xFFFF
	case 4:
		return 0xFFFFFFFF
	default:
		return 0xFF
	}
}

// loadDiffSnapshot resolves one memory snapshot artifact and returns its raw
// bytes, its descriptor, its provenance (nil for legacy artifacts), and the
// space used for a fresh read when needed.
func loadDiffSnapshot(tc toolContext, contextID, id string) ([]byte, map[string]any, *artifact.Provenance, *toolFailure) {
	meta, err := tc.server.store.Metadata(id, contextID)
	if err != nil {
		return nil, nil, nil, &toolFailure{Code: "unknown_artifact", Message: err.Error()}
	}
	if meta.Kind != "memory-dump" && meta.Kind != "memory-snapshot" {
		return nil, nil, nil, &toolFailure{
			Code:    "invalid_params",
			Message: "snapshot ids must reference memory-dump or memory-snapshot artifacts; got kind " + meta.Kind,
		}
	}
	data, _, err := tc.server.store.Bytes(id, contextID)
	if err != nil {
		return nil, nil, nil, &toolFailure{Code: "artifact_error", Message: err.Error()}
	}
	return data, artifactDescriptor(tc.server, meta, contextID), meta.Provenance, nil
}

// provenanceCompatibility compares two proven snapshots and reports whether
// their address domain and ROM identity match. Provenance may be nil on either
// side (legacy artifacts); a nil side is reported as unknown rather than
// incompatible, and the caller decides how to proceed.
type provenanceCompatibility struct {
	compatible  bool
	unknownSide string   // "before", "after", or "" when both are proven
	reasons     []string // why the proven sides are incompatible
}

func compareProvenance(before, after *artifact.Provenance) provenanceCompatibility {
	if !before.Known() || !after.Known() {
		side := ""
		if !before.Known() && !after.Known() {
			side = "both snapshots"
		} else if !before.Known() {
			side = "the before snapshot"
		} else {
			side = "the after snapshot"
		}
		return provenanceCompatibility{compatible: true, unknownSide: side}
	}
	reasons := []string{}
	if before.AddressSpace != after.AddressSpace {
		reasons = append(reasons, fmt.Sprintf("address space differs: %s vs %s", before.AddressSpace, after.AddressSpace))
	}
	beforeStart, _ := before.CapturedStart()
	afterStart, _ := after.CapturedStart()
	if beforeStart != afterStart {
		reasons = append(reasons, fmt.Sprintf("captured start address differs: %s vs %s", canonicalHex(beforeStart), canonicalHex(afterStart)))
	}
	beforeLength, _ := before.CapturedLength()
	afterLength, _ := after.CapturedLength()
	if beforeLength != afterLength {
		reasons = append(reasons, fmt.Sprintf("captured byte length differs: %d vs %d", beforeLength, afterLength))
	}
	// Artifacts from different composite captures describe different atomic
	// windows; mixing them into one comparison is an explicit cross-capture
	// operation (escapable with allow_incompatible_provenance). Standalone
	// single-read artifacts carry no capture id and are unaffected.
	if before.CaptureID != "" && after.CaptureID != "" && before.CaptureID != after.CaptureID {
		reasons = append(reasons, fmt.Sprintf("artifacts belong to different composite captures: %s vs %s (each capture is one atomic window)", before.CaptureID, after.CaptureID))
	}
	if before.ROMSHA256 != "" || after.ROMSHA256 != "" {
		if before.ROMSHA256 != after.ROMSHA256 {
			reasons = append(reasons, "ROM identity differs (rom_sha256)")
		}
	} else if before.ROMPath != "" || after.ROMPath != "" {
		if before.ROMPath != after.ROMPath {
			reasons = append(reasons, "ROM identity differs (rom_path)")
		}
	}
	return provenanceCompatibility{compatible: len(reasons) == 0, reasons: reasons}
}

// incompatibleProvenanceFailure builds the structured rejection for a
// cross-domain comparison, carrying both source manifests for the agent.
func incompatibleProvenanceFailure(reasons []string, beforeDescriptor, afterDescriptor map[string]any) *toolFailure {
	message := "snapshots have incompatible capture provenance: " + strings.Join(reasons, "; ")
	if afterDescriptor == nil {
		message += ". Pass allow_incompatible_provenance: true to read the after range from the caller-supplied space anyway; the result then carries a prominent warning and never fabricates a common address origin."
	} else {
		message += ". Pass allow_incompatible_provenance: true to compare them anyway; the result then carries a prominent warning with both source manifests and never fabricates a common address origin."
	}
	data := map[string]any{
		"reasons":         reasons,
		"before_snapshot": beforeDescriptor,
	}
	if afterDescriptor != nil {
		data["after_snapshot"] = afterDescriptor
	}
	return &toolFailure{Code: "incompatible_provenance", Message: message, Data: data}
}

// provenanceWarning renders the prominent cross-domain warning used when an
// incompatible or unknown-provenance comparison is forced.
func provenanceWarning(kind string, compatibility provenanceCompatibility, beforeDescriptor, afterDescriptor map[string]any) string {
	anchor := "the before snapshot's captured range"
	if provenance, ok := beforeDescriptor["provenance"].(map[string]any); ok {
		if hexValue, present := provenance["effective_address_hex"].(string); present && hexValue != "" {
			anchor = "the before snapshot's captured range (" + hexValue + ")"
		}
	}
	switch kind {
	case "forced":
		return "WARNING: comparing snapshots with incompatible capture provenance (" + strings.Join(compatibility.reasons, "; ") + "). The result is anchored to " + anchor + "; no common address origin was fabricated. See both source manifests below."
	case "unknown":
		return "WARNING: " + compatibility.unknownSide + " has no capture provenance (provenance_unknown, legacy artifact); its address origin cannot be verified. The result is anchored to " + anchor + " when known, otherwise to the caller-provided start address."
	default:
		return ""
	}
}

func runMemoryDiff(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[memoryDiffArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.SnapshotBeforeID == "" {
		return errorResult("invalid_params", "snapshot_before_id is required", tc.modern)
	}
	if parsed.Mode == "" {
		return errorResult("invalid_params", "mode is required", tc.modern)
	}
	switch parsed.Mode {
	case "changed", "unchanged", "increased", "decreased", "changed_by", "equal_to", "in_range":
	default:
		return errorResult("invalid_params", "mode must be one of changed, unchanged, increased, decreased, changed_by, equal_to, in_range", tc.modern)
	}
	width := 1
	widthName := "byte"
	if parsed.Width != "" {
		resolved, supported := diffWidths[parsed.Width]
		if !supported {
			return errorResult("invalid_params", "width must be byte, word, or long", tc.modern)
		}
		width = resolved
		widthName = parsed.Width
	}
	byteOrder := parsed.ByteOrder
	if byteOrder == "" {
		byteOrder = "big-endian"
	}
	if byteOrder != "big-endian" && byteOrder != "little-endian" {
		return errorResult("invalid_params", "byte_order must be big-endian or little-endian", tc.modern)
	}
	cellMax := maxCellValue(width)
	switch parsed.Mode {
	case "equal_to":
		if parsed.Value == nil {
			return errorResult("invalid_params", "equal_to requires value", tc.modern)
		}
		if *parsed.Value < 0 || uint64(*parsed.Value) > cellMax {
			return errorResult("invalid_params", fmt.Sprintf("value %d is outside the representable range 0..%d for width %s", *parsed.Value, cellMax, widthName), tc.modern)
		}
	case "changed_by":
		if parsed.Value == nil {
			return errorResult("invalid_params", "changed_by requires value (the signed delta)", tc.modern)
		}
	case "in_range":
		if parsed.MinValue == nil || parsed.MaxValue == nil {
			return errorResult("invalid_params", "in_range requires min_value and max_value", tc.modern)
		}
		if *parsed.MinValue > *parsed.MaxValue {
			return errorResult("invalid_params", "min_value must not exceed max_value", tc.modern)
		}
		if *parsed.MinValue > cellMax {
			return errorResult("invalid_params", fmt.Sprintf("min_value %d is outside the representable range 0..%d for width %s", *parsed.MinValue, cellMax, widthName), tc.modern)
		}
	}

	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	requestedStart := uint64(0)
	if parsed.StartAddress != nil {
		requestedStart, failure = resolveAddress(parsed.StartAddress, addressSpaceFromArgs(args), parsed.Space)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
	}
	maxMatches := parsed.MaxMatches
	if maxMatches == 0 {
		maxMatches = defaultSearchMaxMatches
	}
	if maxMatches > maxSearchMaxMatches {
		return failureResult(&toolFailure{
			Code:    "invalid_params",
			Message: fmt.Sprintf("max_matches is capped at %d inline matches.", maxSearchMaxMatches),
		}, tc.modern)
	}

	beforeBytes, beforeSnapshot, beforeProvenance, failure := loadDiffSnapshot(tc, context.ID, parsed.SnapshotBeforeID)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if len(beforeBytes) == 0 {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "the before snapshot is empty; nothing to compare."}, tc.modern)
	}

	// The comparison's address domain derives from the before snapshot's
	// capture provenance; caller parameters that duplicate provenance are
	// assertions and are rejected on mismatch.
	startAddress := requestedStart
	beforeProven := beforeProvenance != nil && beforeProvenance.Known()
	if beforeProven {
		if derivedStart, ok := beforeProvenance.CapturedStart(); ok {
			if parsed.StartAddress != nil && requestedStart != derivedStart {
				return failureResult(provenanceConflict("start_address", derivedStart, requestedStart), tc.modern)
			}
			startAddress = derivedStart
		}
	}
	if parsed.ByteOrder == "" && beforeProven && beforeProvenance.ByteOrder != "" {
		byteOrder = beforeProvenance.ByteOrder
	}

	var afterBytes []byte
	var afterSnapshot map[string]any
	var afterProvenance *artifact.Provenance
	freshAfterRead := false
	warning := ""
	if parsed.SnapshotAfterID != "" {
		afterBytes, afterSnapshot, afterProvenance, failure = loadDiffSnapshot(tc, context.ID, parsed.SnapshotAfterID)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		if len(afterBytes) != len(beforeBytes) {
			return failureResult(&toolFailure{
				Code:    "invalid_params",
				Message: fmt.Sprintf("snapshot lengths differ: before %d bytes, after %d bytes; both snapshots must cover the same range", len(beforeBytes), len(afterBytes)),
			}, tc.modern)
		}
		compatibility := compareProvenance(beforeProvenance, afterProvenance)
		if !compatibility.compatible {
			if !parsed.AllowIncompatibleProvenance {
				return failureResult(incompatibleProvenanceFailure(compatibility.reasons, beforeSnapshot, afterSnapshot), tc.modern)
			}
			warning = provenanceWarning("forced", compatibility, beforeSnapshot, afterSnapshot)
		} else if compatibility.unknownSide != "" {
			warning = provenanceWarning("unknown", compatibility, beforeSnapshot, afterSnapshot)
		}
	} else {
		// Fresh after read: capture the same proven range again, never a live
		// racy scan. With proven provenance the space/start are derived;
		// contradicting them is an incompatible-comparison case.
		space := strings.TrimSpace(parsed.Space)
		freshStart := startAddress
		if beforeProven {
			if beforeProvenance.AddressSpace == "" {
				return failureResult(&toolFailure{Code: "invalid_params", Message: "the before snapshot's provenance names no address space; pass space explicitly"}, tc.modern)
			}
			if space != "" && space != beforeProvenance.AddressSpace {
				if !parsed.AllowIncompatibleProvenance {
					return failureResult(incompatibleProvenanceFailure(
						[]string{fmt.Sprintf("address space differs: %s (provenance) vs %s (call)", beforeProvenance.AddressSpace, space)},
						beforeSnapshot, nil), tc.modern)
				}
				warning = "WARNING: the fresh after read uses caller space " + space + " while the before snapshot was captured in " + beforeProvenance.AddressSpace + "; the result is anchored to the before snapshot's captured range and no common address origin is fabricated."
			} else {
				space = beforeProvenance.AddressSpace
			}
		}
		if space == "" {
			return errorResult("invalid_params", "space is required when snapshot_after_id is omitted and the before snapshot has no capture provenance", tc.modern)
		}
		raw, spaceOrder, effective, pausedDuringRead, failure := readBridgeBytes(tc, space, freshStart, uint64(len(beforeBytes)))
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		payload := map[string]any{
			"effective_address":         float64(effective),
			"byte_order":                spaceOrder,
			"consistency":               "live",
			"system_paused_during_read": pausedDuringRead,
		}
		provenance := captureProvenance(tc.server, "memory-snapshot", space, freshStart, uint64(len(raw)), payload, time.Now().UTC(), "", nil)
		stored, err := tc.server.store.PutWithProvenance(context.ID, "memory-snapshot", "application/octet-stream", raw, provenance)
		if err != nil {
			return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
		}
		afterBytes = raw
		afterSnapshot = artifactDescriptor(tc.server, stored, context.ID)
		afterProvenance = provenance
		freshAfterRead = true
		if warning == "" && (beforeProvenance == nil || !beforeProvenance.Known()) {
			warning = provenanceWarning("unknown", provenanceCompatibility{unknownSide: "the before snapshot"}, beforeSnapshot, afterSnapshot)
		}
	}

	// Alignment policy: by default the scan is aligned to the cell width in
	// the address domain, so a word scan of a big-endian 68K range starts at
	// an even address; misaligned cells are skipped. allow_misaligned
	// opts into scanning every cell offset.
	firstCell := uint64(0)
	alignment := "aligned-to-width"
	if parsed.AllowMisaligned {
		alignment = "misaligned-scan"
	} else if startAddress%uint64(width) != 0 {
		firstCell = uint64(width) - startAddress%uint64(width)
	}

	matches := []map[string]any{}
	records := []map[string]any{}
	var total uint64
	littleEndian := byteOrder == "little-endian"
	// Aligned scans advance one cell per step; a misaligned scan advances one
	// byte so every byte offset is visited as a cell.
	stride := uint64(width)
	if parsed.AllowMisaligned {
		stride = 1
	}
	for offset := firstCell; offset+uint64(width) <= uint64(len(beforeBytes)); offset += stride {
		beforeValue := decodeCell(beforeBytes, offset, width, littleEndian)
		afterValue := decodeCell(afterBytes, offset, width, littleEndian)
		matched := false
		switch parsed.Mode {
		case "changed":
			matched = beforeValue != afterValue
		case "unchanged":
			matched = beforeValue == afterValue
		case "increased":
			matched = afterValue > beforeValue
		case "decreased":
			matched = afterValue < beforeValue
		case "changed_by":
			matched = int64(afterValue)-int64(beforeValue) == *parsed.Value
		case "equal_to":
			matched = afterValue == uint64(*parsed.Value)
		case "in_range":
			matched = afterValue >= *parsed.MinValue && afterValue <= *parsed.MaxValue
		}
		if !matched {
			continue
		}
		total++
		address := startAddress + offset
		delta := int64(afterValue) - int64(beforeValue)
		if uint64(len(records)) < maxSearchArtifactMatches {
			records = append(records, map[string]any{
				"address": address,
				"offset":  offset,
				"before":  beforeValue,
				"after":   afterValue,
				"delta":   delta,
			})
		}
		if uint64(len(matches)) < maxMatches {
			matches = append(matches, map[string]any{
				"address":     address,
				"address_hex": canonicalHex(address),
				"offset":      offset,
				"before":      beforeValue,
				"after":       afterValue,
				"delta":       delta,
			})
		}
	}

	cellsScanned := uint64(0)
	trailingBytes := uint64(0)
	if parsed.AllowMisaligned {
		if uint64(len(beforeBytes)) >= uint64(width) {
			cellsScanned = 1 + uint64(len(beforeBytes)) - uint64(width)
		}
	} else {
		if uint64(len(beforeBytes)) > firstCell {
			cellsScanned = (uint64(len(beforeBytes)) - firstCell) / uint64(width)
		}
		trailingBytes = uint64(len(beforeBytes)) - firstCell - cellsScanned*uint64(width)
	}
	inlineTruncated := uint64(len(matches)) < total
	artifactTruncated := uint64(len(records)) < total

	rangeInfo := map[string]any{
		"start_address":          startAddress,
		"start_address_hex":      canonicalHex(startAddress),
		"end_address":            startAddress + uint64(len(beforeBytes)) - 1,
		"end_address_hex":        canonicalHex(startAddress + uint64(len(beforeBytes)) - 1),
		"byte_length":            len(beforeBytes),
		"width_bytes":            width,
		"cells_scanned":          cellsScanned,
		"first_cell_offset":      firstCell,
		"trailing_bytes_ignored": trailingBytes,
	}
	if beforeProvenance != nil && beforeProvenance.AddressSpace != "" {
		rangeInfo["address_space"] = beforeProvenance.AddressSpace
	}
	document := map[string]any{
		"kind":             "memory-diff-results",
		"mode":             parsed.Mode,
		"width":            widthName,
		"width_bytes":      width,
		"byte_order":       byteOrder,
		"alignment":        alignment,
		"interpretation":   fmt.Sprintf("cells are compared at %d-byte granularity in address order; the %s representation is applied per cell and %s is the alignment policy. The comparison is anchored to the before snapshot's captured range; no common address origin is fabricated.", width, byteOrder, alignment),
		"range":            rangeInfo,
		"before_snapshot":  beforeSnapshot,
		"after_snapshot":   afterSnapshot,
		"fresh_after_read": freshAfterRead,
		"matches_total":    total,
		"truncated":        artifactTruncated,
		"matches":          records,
	}
	if warning != "" {
		document["provenance_warning"] = warning
	}
	if beforeProvenance != nil && beforeProvenance.CaptureID != "" {
		document["before_capture_id"] = beforeProvenance.CaptureID
	}
	if afterProvenance != nil && afterProvenance.CaptureID != "" {
		document["after_capture_id"] = afterProvenance.CaptureID
	}
	if afterProvenance != nil && afterProvenance.CaptureConsistency != nil {
		document["capture_consistency"] = captureConsistencyToMap(afterProvenance.CaptureConsistency)
	}
	if parsed.Mode == "equal_to" {
		document["value"] = *parsed.Value
	}
	if parsed.Mode == "changed_by" {
		document["delta"] = *parsed.Value
	}
	if parsed.Mode == "in_range" {
		document["min_value"] = *parsed.MinValue
		document["max_value"] = *parsed.MaxValue
	}
	documentBytes, err := json.Marshal(document)
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}
	storedResults, err := tc.server.store.PutWithProvenance(context.ID, "memory-diff-results", "application/json", documentBytes, genericProvenance(tc.server, "memory-diff-results", time.Now().UTC()))
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}

	summary := map[string]any{
		"kind":                 "memory-diff",
		"mode":                 parsed.Mode,
		"width":                widthName,
		"width_bytes":          width,
		"byte_order":           byteOrder,
		"alignment":            alignment,
		"interpretation":       fmt.Sprintf("cells are compared at %d-byte granularity in address order; the %s representation is applied per cell and %s is the alignment policy. The comparison is anchored to the before snapshot's captured range; no common address origin is fabricated.", width, byteOrder, alignment),
		"range":                rangeInfo,
		"before_snapshot":      beforeSnapshot,
		"after_snapshot":       afterSnapshot,
		"fresh_after_read":     freshAfterRead,
		"matches_total":        total,
		"inline_matches_shown": len(matches),
		"matches_truncated":    inlineTruncated,
		"sha256":               storedResults.SHA256,
	}
	if warning != "" {
		summary["provenance_warning"] = warning
	}
	if beforeProvenance != nil && beforeProvenance.CaptureID != "" {
		summary["before_capture_id"] = beforeProvenance.CaptureID
	}
	if afterProvenance != nil && afterProvenance.CaptureID != "" {
		summary["after_capture_id"] = afterProvenance.CaptureID
	}
	if afterProvenance != nil && afterProvenance.CaptureConsistency != nil {
		summary["capture_consistency"] = captureConsistencyToMap(afterProvenance.CaptureConsistency)
	}
	if parsed.Mode == "equal_to" {
		summary["value"] = *parsed.Value
	}
	if parsed.Mode == "changed_by" {
		summary["delta"] = *parsed.Value
	}
	if parsed.Mode == "in_range" {
		summary["min_value"] = *parsed.MinValue
		summary["max_value"] = *parsed.MaxValue
	}
	result := map[string]any{
		"summary":  summary,
		"matches":  matches,
		"artifact": artifactDescriptor(tc.server, storedResults, context.ID),
	}
	space := parsed.Space
	if beforeProvenance != nil && beforeProvenance.AddressSpace != "" {
		space = beforeProvenance.AddressSpace
	}
	annotateAddressMap(result, space)
	return okResult(result, tc.modern)
}

// decodeCell reads one cell of the given width from data at offset using the
// declared byte order. Offsets are byte offsets within the snapshot; the
// snapshot preserves address order, so the byte order only affects how the
// cell's bytes are combined into a numeric value.
func decodeCell(data []byte, offset uint64, width int, littleEndian bool) uint64 {
	switch width {
	case 2:
		if littleEndian {
			return uint64(binary.LittleEndian.Uint16(data[offset : offset+2]))
		}
		return uint64(binary.BigEndian.Uint16(data[offset : offset+2]))
	case 4:
		if littleEndian {
			return uint64(binary.LittleEndian.Uint32(data[offset : offset+4]))
		}
		return uint64(binary.BigEndian.Uint32(data[offset : offset+4]))
	default:
		return uint64(data[offset])
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// rom_info — Mega Drive cartridge header
// ----------------------------------------------------------------------------------------------------------------------

type mdIOEntry struct {
	Code   rune   `json:"code"`
	Device string `json:"device"`
}

type mdHeader struct {
	SystemType  string
	Copyright   string
	Domestic    string
	Overseas    string
	Serial      string
	Checksum    uint16
	IOSupport   []mdIOEntry
	ROMStart    uint32
	ROMEnd      uint32
	RAMStart    uint32
	RAMEnd      uint32
	SRAMPresent bool
	SRAMType    string
	SRAMStart   uint32
	SRAMEnd     uint32
	Modem       string
	Memo        string
	Region      string
}

var mdIODevices = map[rune]string{
	'J': "Joypad (3-button)", '4': "Team Play", '6': "6-button joypad",
	'0': "Joystick (Master System)", 'K': "Keyboard", 'R': "Serial RS232C",
	'P': "Printer", 'T': "Tablet", 'B': "Control ball", 'V': "Paddle",
	'F': "Floppy disk drive", 'C': "CD-ROM", 'L': "Activator", 'M': "Mega Mouse",
}

var mdRegionCountries = map[rune]string{
	'J': "Japan",
	'U': "USA/Canada",
	'E': "Europe",
}

// decodeMDHeader parses the 256-byte Sega Mega Drive header that starts at
// cart offset 0x100. Fields follow the Sega ID table layout: all strings are
// space-padded ASCII, all multi-byte values are big-endian.
func decodeMDHeader(header []byte) (*mdHeader, *toolFailure) {
	if len(header) < 0x100 {
		return nil, &toolFailure{Code: "no_cartridge", Message: "header buffer is shorter than the 256-byte Sega header"}
	}
	systemType := trimASCII(header[0x00:0x10])
	if !strings.HasPrefix(strings.ToUpper(systemType), "SEGA") {
		return nil, &toolFailure{
			Code:    "no_cartridge",
			Message: "no Mega Drive cartridge header found at 0x100 (system type did not start with SEGA); load a ROM with rom_load first",
		}
	}

	// Backup RAM block: "RA" + backup flag byte (bit 7) + access byte.
	sramPresent := len(header) >= 0xBC && header[0xB0] == 'R' && header[0xB1] == 'A'
	var sramType string
	if sramPresent {
		switch header[0xB3] & 0x03 {
		case 0:
			sramType = "word (both even and odd addresses)"
		case 2:
			sramType = "even addresses only"
		case 3:
			sramType = "odd addresses only"
		default:
			sramType = "reserved access bits"
		}
	}

	parsed := &mdHeader{
		SystemType:  systemType,
		Copyright:   trimASCII(header[0x10:0x20]),
		Domestic:    trimASCII(header[0x20:0x50]),
		Overseas:    trimASCII(header[0x50:0x80]),
		Serial:      trimASCII(header[0x80:0x8E]),
		Checksum:    binary.BigEndian.Uint16(header[0x8E:0x90]),
		ROMStart:    binary.BigEndian.Uint32(header[0xA0:0xA4]),
		ROMEnd:      binary.BigEndian.Uint32(header[0xA4:0xA8]),
		RAMStart:    binary.BigEndian.Uint32(header[0xA8:0xAC]),
		RAMEnd:      binary.BigEndian.Uint32(header[0xAC:0xB0]),
		SRAMPresent: sramPresent,
		SRAMType:    sramType,
		Modem:       trimASCII(header[0xBC:0xC8]),
		Memo:        trimASCII(header[0xC8:0xF0]),
		Region:      trimASCII(header[0xF0:0xF3]),
	}
	if sramPresent {
		parsed.SRAMStart = binary.BigEndian.Uint32(header[0xB4:0xB8])
		parsed.SRAMEnd = binary.BigEndian.Uint32(header[0xB8:0xBC])
	}
	for _, r := range header[0x90:0xA0] {
		if r == ' ' || r == 0 {
			continue
		}
		device := mdIODevices[rune(r)]
		if device == "" {
			device = "unknown device code"
		}
		parsed.IOSupport = append(parsed.IOSupport, mdIOEntry{Code: rune(r), Device: device})
	}
	return parsed, nil
}

// computeSegaChecksum implements the cartridge checksum: sum of big-endian
// words from offset 0x200 to the end of the ROM body, keeping the low 16 bits.
// A trailing odd byte is treated as the high byte of the final word.
func computeSegaChecksum(body []byte) uint16 {
	var sum uint16
	for index := 0; index+1 < len(body); index += 2 {
		sum += binary.BigEndian.Uint16(body[index:])
	}
	if len(body)%2 == 1 {
		sum += uint16(body[len(body)-1]) << 8
	}
	return sum
}

func trimASCII(raw []byte) string {
	return strings.TrimRight(strings.TrimRight(string(raw), "\x00"), " \x00")
}

func decodeSerial(raw string) map[string]any {
	out := map[string]any{"raw": raw}
	productType := ""
	productLabel := ""
	if len(raw) >= 2 {
		productType = raw[:2]
		switch productType {
		case "GM":
			productLabel = "Game"
		case "AI":
			productLabel = "Education"
		default:
			productLabel = "other type"
		}
		out["product_type"] = productType
		out["product_type_label"] = productLabel
	}
	rest := strings.TrimSpace(strings.TrimPrefix(raw, productType))
	if hyphen := strings.Index(rest, "-"); hyphen >= 0 {
		out["catalog_number"] = strings.TrimSpace(rest[:hyphen])
		out["version"] = strings.TrimSpace(rest[hyphen+1:])
	} else {
		out["catalog_number"] = strings.TrimSpace(rest)
	}
	return out
}

func decodeRegions(raw string) ([]string, map[string]any) {
	countries := []string{}
	hardware := map[string]any{}
	letters := 0
	for _, r := range raw {
		if r >= '0' && r <= '9' {
			letters++
		}
		if name, ok := mdRegionCountries[r]; ok {
			countries = append(countries, name)
			letters++
		}
	}
	// The Genesis Technical Bulletin allows a single hardware-code byte
	// (0-F) instead of country letters.
	if len(raw) == 1 && letters == 1 {
		hardware["byte"] = raw
		hardware["note"] = "Hardware code style (Sega Genesis Technical Bulletin, ID table): 0=Japan NTSC, 1=Japan PAL, 2=Overseas NTSC, 4=Overseas NTSC (US Genesis), 6=Overseas PAL, 8=Overseas PAL (Europe), F=common/no restriction; other values map via bits 7-6."
	}
	return countries, hardware
}

var mdBusMap = []map[string]any{
	{"start": "0x000000", "end": "0x3FFFFF", "description": "Cartridge ROM/RAM window (SRAM in 0x200000+)"},
	{"start": "0x400000", "end": "0x7FFFFF", "description": "Reserved (Mega-CD / 32X)"},
	{"start": "0xA00000", "end": "0xA0FFFF", "description": "Z80 address space window"},
	{"start": "0xA10000", "end": "0xA10FFF", "description": "I/O registers (controllers, version)"},
	{"start": "0xA11000", "end": "0xA11FFF", "description": "Z80 control (bus request 0xA11100, reset 0xA11200)"},
	{"start": "0xA13000", "end": "0xA130FF", "description": "Cartridge / TIME registers (SRAM access 0xA130F1, bank registers 0xA130EC-0xA130FF)"},
	{"start": "0xA14000", "end": "0xA14003", "description": "TMSS security register"},
	{"start": "0xC00000", "end": "0xDFFFFF", "description": "VDP ports (data 0xC00000, control 0xC00004, HV counter 0xC00008)"},
	{"start": "0xFF0000", "end": "0xFFFFFF", "description": "68000 work RAM (mirrored every 0x10000)"},
}

// mdROMInfo reads the header and ROM body through the M68K bus and returns the
// full parsed cartridge summary. romSizeBytes is the loaded ROM file size from
// emulator_status (0 when unknown), used to clamp the checksum range;
// paddedSizeBytes is the padded mapping size for the rom_identity view;
// contextID scopes the header artifact.
func mdROMInfo(tc toolContext, contextID string, romSizeBytes uint64, paddedSizeBytes uint64) (map[string]any, *toolFailure) {
	header, byteOrder, effective, _, failure := readBridgeBytes(tc, "m68k-bus", 0x100, 0x100)
	if failure != nil {
		return nil, failure
	}
	parsed, failure := decodeMDHeader(header)
	if failure != nil {
		return nil, failure
	}

	// Checksum body: [0x200, min(declared ROM end + 1, loaded file size)).
	// Licensed games store the ROM end address in the header; the file size
	// keeps a broken/generic header from dragging the read past the real ROM.
	// Completeness is reported explicitly: a range cut by the dump cap or by a
	// file shorter than the declared body is never presented as full
	// header-checksum validation.
	readStart := uint64(0x200)
	declaredEnd := uint64(parsed.ROMEnd) + 1
	declaredSane := declaredEnd > readStart && uint64(parsed.ROMEnd) >= uint64(parsed.ROMStart)
	expectedEnd := declaredEnd
	if !declaredSane {
		expectedEnd = romSizeBytes
	}
	if romSizeBytes > 0 && expectedEnd > romSizeBytes {
		expectedEnd = romSizeBytes
	}
	expectedLength := uint64(0)
	if expectedEnd > readStart {
		expectedLength = expectedEnd - readStart
	}
	expectedRange := map[string]any{
		"start_address": readStart,
		"end_address":   expectedEnd - 1,
		"byte_length":   expectedLength,
	}
	bodyEnd := expectedEnd
	rangeCapped := false
	capReason := "none"
	if bodyEnd > readStart+dumpCapBytes {
		bodyEnd = readStart + dumpCapBytes
		rangeCapped = true
		capReason = "dump_cap"
	}
	if declaredSane && declaredEnd > romSizeBytes && capReason != "dump_cap" {
		rangeCapped = true
		capReason = "declared_end_beyond_file"
	}
	if !declaredSane && capReason == "none" {
		rangeCapped = true
		capReason = "degenerate_declared_range"
	}
	computed := uint16(0)
	checksumRange := map[string]any{
		"start_address": readStart,
		"end_address":   uint64(0x1FF),
		"byte_length":   uint64(0),
		"capped":        rangeCapped,
	}
	if bodyEnd > readStart {
		body, _, _, _, failure := readBridgeBytes(tc, "m68k-bus", readStart, bodyEnd-readStart)
		if failure != nil {
			return nil, failure
		}
		computed = computeSegaChecksum(body)
		checksumRange = map[string]any{
			"start_address": readStart,
			"end_address":   bodyEnd - 1,
			"byte_length":   bodyEnd - readStart,
			"capped":        rangeCapped,
		}
	}
	checksumComplete := declaredSane && bodyEnd == declaredEnd && !rangeCapped
	checksumNote := ""
	if !checksumComplete {
		checksumNote = fmt.Sprintf("The comparison covers only the range above (%d bytes, %s); it is NOT full header-checksum validation of the declared ROM body (%d bytes).", bodyEnd-readStart, capReason, expectedLength)
	}

	countries, hardwareCode := decodeRegions(parsed.Region)

	generation := tc.server.target.Generation()
	romFacts := tc.server.romIdentity.romFileFacts(tc.server.currentROMPath())
	headerProvenance := &artifact.Provenance{
		State:               artifact.ProvenanceStateComplete,
		Kind:                "rom-header",
		AddressSpace:        "m68k-bus",
		StartAddress:        uint64Ptr(0x100),
		EffectiveAddress:    uint64Ptr(effective),
		StartAddressHex:     canonicalHex(0x100),
		EffectiveAddressHex: canonicalHex(effective),
		ByteLength:          uint64Ptr(0x100),
		RawByteOrdering:     "address-order",
		ByteOrder:           byteOrder,
		SpaceKind:           "bus",
		Device:              "cartridge ROM",
		TargetGeneration:    &generation,
		ROMSHA256:           romFacts.SHA256,
		ROMPath:             tc.server.currentROMPath(),
		Consistency:         "live",
		CapturedAt:          time.Now().UTC(),
		CaptureConsistency:  buildCaptureConsistency(tc.server, map[string]any{}, false, true, nil, nil),
	}
	headerArtifact, err := tc.server.store.PutWithProvenance(contextID, "rom-header", "application/octet-stream", header, headerProvenance)
	if err != nil {
		return nil, &toolFailure{Code: "artifact_error", Message: err.Error()}
	}

	mapping := map[string]any{
		"declared": map[string]any{
			"rom": map[string]any{"start_address": parsed.ROMStart, "end_address": parsed.ROMEnd},
			"ram": map[string]any{"start_address": parsed.RAMStart, "end_address": parsed.RAMEnd},
		},
		"reference": mdBusMap,
	}
	if parsed.SRAMPresent {
		mapping["declared"].(map[string]any)["sram"] = map[string]any{
			"start_address": parsed.SRAMStart,
			"end_address":   parsed.SRAMEnd,
		}
	}

	checksumView := map[string]any{
		"stored":         parsed.Checksum,
		"computed":       computed,
		"matches":        parsed.Checksum == computed,
		"complete":       checksumComplete,
		"bytes_covered":  checksumRange["byte_length"],
		"expected_range": expectedRange,
		"cap_reason":     capReason,
		"range":          checksumRange,
	}
	if checksumNote != "" {
		checksumView["note"] = checksumNote
	}

	result := map[string]any{
		"identified":        true,
		"byte_order":        "big-endian (M68K cartridge header; the bus read reported " + byteOrder + ")",
		"effective_address": effective,
		"loaded_size_bytes": romSizeBytes,
		"rom_identity":      tc.server.romIdentityView(paddedSizeBytes),
		"header": map[string]any{
			"system_type":   parsed.SystemType,
			"copyright":     parsed.Copyright,
			"domestic_name": parsed.Domestic,
			"overseas_name": parsed.Overseas,
			"serial":        decodeSerial(parsed.Serial),
			"io_support":    parsed.IOSupport,
			"modem":         parsed.Modem,
			"memo":          parsed.Memo,
			"checksum":      checksumView,
			"backup_ram": map[string]any{
				"present":       parsed.SRAMPresent,
				"type":          parsed.SRAMType,
				"start_address": parsed.SRAMStart,
				"end_address":   parsed.SRAMEnd,
			},
			"region": map[string]any{
				"raw":       parsed.Region,
				"countries": countries,
			},
		},
		"mapping":  mapping,
		"artifact": artifactDescriptor(tc.server, headerArtifact, contextID),
	}
	if len(hardwareCode) > 0 {
		result["header"].(map[string]any)["region"].(map[string]any)["hardware_code"] = hardwareCode
	}
	return result, nil
}

// uint64Ptr is a small helper for building provenance envelopes.
func uint64Ptr(value uint64) *uint64 { return &value }

func runROMInfo(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[struct{ Context string }](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	status, failure := fetchEmulatorStatus(tc)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	info, failure := mdROMInfo(tc, context.ID, status.Rom.SizeBytes, status.Rom.PaddedSizeBytes)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	return okResult(info, tc.modern)
}

// ----------------------------------------------------------------------------------------------------------------------
// Watchpoint-triggered trace capture
// ----------------------------------------------------------------------------------------------------------------------

type traceCaptureWatchpointArgs struct {
	WatchpointID uint64 `json:"watchpoint_id"`
	MaxEntries   uint64 `json:"max_entries"`
	TimeoutMs    uint64 `json:"timeout_ms"`
	Context      string `json:"context"`
	guardArgs
}

func runCpuTraceCaptureWatchpoint(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[traceCaptureWatchpointArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.WatchpointID == 0 {
		return errorResult("invalid_params", "watchpoint_id must be the positive id returned by cpu_watchpoint_set", tc.modern)
	}
	maxEntries := parsed.MaxEntries
	if maxEntries == 0 {
		maxEntries = defaultTraceEntries
	}
	if maxEntries > maxTraceEntries {
		maxEntries = maxTraceEntries
	}
	timeoutMs := parsed.TimeoutMs
	if timeoutMs == 0 {
		timeoutMs = 5000
	}

	params := map[string]string{
		"watchpoint_id": strconv.FormatUint(parsed.WatchpointID, 10),
		"max_entries":   strconv.FormatUint(maxEntries, 10),
		"timeout_ms":    strconv.FormatUint(timeoutMs, 10),
	}
	payload, before, after, failure := tc.server.executeMutation(tc.ctx, mutationCall{
		tool:      "cpu_trace_capture_watchpoint",
		operation: "trace_capture",
		params:    params,
		guard:     parsed.guard(),
		contextID: context.ID,
		detail: map[string]any{
			"watchpoint_id": parsed.WatchpointID,
			"max_entries":   maxEntries,
			"timeout_ms":    timeoutMs,
		},
	})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}

	summary, artifactDesc, jsonlDesc, failure := traceArtifactsFromPayloadGeneric(tc, context, payload, "", 0, 0, false, true, true, true)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	summary["watchpoint_id"] = parsed.WatchpointID
	if value, ok := payload["stopped_on_watchpoint"].(bool); ok {
		summary["stopped_on_watchpoint"] = value
	}
	if value, ok := payload["stop_reason"].(string); ok {
		summary["stop_reason"] = value
	}
	if value, ok := payload["watchpoint_ids_hit"].([]any); ok {
		summary["watchpoint_ids_hit"] = value
	}
	if value, ok := payload["event_note"].(string); ok {
		summary["event_note"] = value
	}
	// Emit structured watchpoint event when the requested watchpoint fired; distinguish timeout / different resource.
	var eventDesc map[string]any
	var eventID uint64
	stoppedOnWatchpoint, _ := payload["stopped_on_watchpoint"].(bool)
	watchpointIDsHit, _ := payload["watchpoint_ids_hit"].([]any)
	hitRequested := false
	for _, idVal := range watchpointIDsHit {
		if idNum, ok := idVal.(float64); ok && uint64(idNum) == parsed.WatchpointID {
			hitRequested = true
			break
		}
	}
	if stoppedOnWatchpoint && hitRequested {
		// Fetch triggering PC via regs_get
		pc := fetchCPUCurrentPC(tc, payload["cpu"].(string))
		meta := tc.server.debugResourceMeta("watchpoint", parsed.WatchpointID)
		contextID := context.ID
		if meta != nil {
			contextID = meta.ContextID
		}
		// Fetch watchpoint details for access direction and range
		watchpointInfo := fetchWatchpointInfo(tc, parsed.WatchpointID)
		access := "write"
		watchedAddr := uint64(0)
		watchedLen := uint64(1)
		if watchpointInfo != nil {
			if a, ok := watchpointInfo["access"].(string); ok {
				access = a
			}
			if addr, ok := watchpointInfo["address"].(float64); ok {
				watchedAddr = uint64(addr)
			}
			if length, ok := watchpointInfo["length"].(float64); ok {
				watchedLen = uint64(length)
			}
		}
		event := debugEvent{
			ResourceKind:     "watchpoint",
			ResourceID:       parsed.WatchpointID,
			ContextID:        contextID,
			CPU:              payload["cpu"].(string),
			TriggeringPC:     pc,
			AddressSpace:     payload["cpu"].(string) + "-bus",
			WatchedAddress:   watchedAddr,
			AccessDirection:  access,
			RequestedLength:  watchedLen,
			HitCount:         fetchWatchpointHitCount(tc, parsed.WatchpointID),
			TargetGeneration: after,
			FrameToken:       currentFrameToken(tc),
		}
		eventID = tc.server.pushDebugEvent(event)
		eventDesc = debugEventDescriptor(tc.server, event, contextID, captureIDFromPayload(payload))
		summary["event_id"] = eventID
		summary["event"] = eventDesc
		// Link trace to event
		summary["linked_trace_capture_id"] = captureIDFromPayload(payload)
	} else if stoppedOnWatchpoint && !hitRequested && len(watchpointIDsHit) > 0 {
		summary["event_note"] = "A different managed watchpoint fired; the requested watchpoint did not."
		summary["different_watchpoint_hit"] = true
	} else if !stoppedOnWatchpoint {
		summary["event_note"] = "Timeout: no watchpoint fired within the window; no synthetic event was created."
		summary["timeout_without_hit"] = true
	}
	result := map[string]any{"summary": summary, "artifact": artifactDesc, "jsonl_artifact": jsonlDesc, "artifacts": []map[string]any{artifactDesc, jsonlDesc}}
	if eventDesc != nil {
		result["event"] = eventDesc
		result["artifacts"] = []map[string]any{artifactDesc, jsonlDesc, eventDesc}
	}
	return okResult(stampGenerations(result, before, after), tc.modern)
}

// traceArtifactFromPayload turns a trace_capture payload into stored text and JSONL artifacts.
// It is kept for watchpoint-driven traces that do not have filter args; the main trace path uses traceArtifactsFromPayload.
func traceArtifactFromPayload(tc toolContext, context *analysis.Context, payload map[string]any) (map[string]any, map[string]any, *toolFailure) {
	summary, textDesc, jsonlDesc, failure := traceArtifactsFromPayloadGeneric(tc, context, payload, "m68k", 0, 0, false, true, true, true)
	if failure != nil {
		return nil, nil, failure
	}
	// For backward compatibility, return only the text artifact; the caller for watchpoint will handle jsonl separately via the generic.
	_ = jsonlDesc
	return summary, textDesc, nil
}

// traceArtifactsFromPayloadGeneric is the shared implementation for both plain and watchpoint traces.
func traceArtifactsFromPayloadGeneric(tc toolContext, context *analysis.Context, payload map[string]any, cpuOverride string, rangeStart, rangeEnd uint64, hasRange, includeROM, includeRAM bool, retainRepeated bool) (map[string]any, map[string]any, map[string]any, *toolFailure) {
	traceText, _ := payload["trace_text"].(string)
	cpu, _ := payload["cpu"].(string)
	if cpu == "" {
		cpu = cpuOverride
	}
	if cpu == "" {
		cpu = "m68k"
	}
	captureID := newCaptureID()
	generation := tc.server.target.Generation()
	frameToken := currentFrameToken(tc)
	provenance := genericProvenance(tc.server, "cpu-trace", time.Now().UTC())
	provenance.Device = cpu
	provenance.CaptureID = captureID
	if cpu == "z80" {
		provenance.AddressSpace = "z80-bus"
		provenance.ByteOrder = "little-endian"
	} else {
		provenance.AddressSpace = "m68k-bus"
		provenance.ByteOrder = "big-endian"
	}
	if hasRange {
		provenance.StartAddress = &rangeStart
		if rangeEnd > rangeStart {
			length := rangeEnd - rangeStart
			provenance.ByteLength = &length
		}
	}
	storedText, err := tc.server.store.PutWithProvenance(context.ID, "cpu-trace", "text/plain; charset=utf-8", []byte(traceText), provenance)
	if err != nil {
		return nil, nil, nil, &toolFailure{Code: "artifact_error", Message: err.Error()}
	}
	// Build JSONL
	dummyArgs := &traceCaptureArgs{CPU: cpu, IncludeROM: &includeROM, IncludeRAM: &includeRAM, RetainRepeated: &retainRepeated}
	if hasRange {
		startCopy := rangeStart
		endCopy := rangeEnd
		// Use dummyArgs to carry range for filtering; set via closure below
		dummyArgs.AddressRangeStart = startCopy
		dummyArgs.AddressRangeEnd = endCopy
	}
	// For range filtering, we pass the range values directly
	var rs, re uint64
	if hasRange {
		rs, re = rangeStart, rangeEnd
	}
	events, truncation := buildTraceJSONLEvents(tc, cpu, traceText, rs, re, dummyArgs, captureID, generation, frameToken)
	var jsonlBytes []byte
	for _, event := range events {
		line, _ := json.Marshal(event)
		jsonlBytes = append(jsonlBytes, line...)
		jsonlBytes = append(jsonlBytes, '\n')
	}
	jsonlProvenance := genericProvenance(tc.server, "cpu-trace-jsonl", time.Now().UTC())
	jsonlProvenance.Device = cpu
	jsonlProvenance.CaptureID = captureID
	jsonlProvenance.AddressSpace = provenance.AddressSpace
	jsonlProvenance.ByteOrder = provenance.ByteOrder
	jsonlProvenance.StartAddress = provenance.StartAddress
	jsonlProvenance.ByteLength = provenance.ByteLength
	if frameToken != nil {
		jsonlProvenance.FrameToken = frameToken
	}
	storedJSONL, err := tc.server.store.PutWithProvenance(context.ID, "cpu-trace-jsonl", "application/jsonl", jsonlBytes, jsonlProvenance)
	if err != nil {
		return nil, nil, nil, &toolFailure{Code: "artifact_error", Message: err.Error()}
	}
	captured, _ := payload["captured"].(float64)
	timedOut, _ := payload["timed_out"].(bool)
	sample, _ := payload["sample"].([]any)
	captureChannel, _ := payload["capture_channel"].(string)
	summary := map[string]any{
		"kind":              "cpu-trace",
		"cpu":               cpu,
		"captured":          int(captured),
		"timed_out":         timedOut,
		"sample":            sample,
		"sha256":            storedText.SHA256,
		"jsonl_sha256":      storedJSONL.SHA256,
		"jsonl_events":      len(events),
		"capture_id":        captureID,
		"target_generation": generation,
		"truncation":        truncation,
		"schema_version":    "trace-jsonl/1",
	}
	if note, ok := payload["sampling_note"].(string); ok && note != "" {
		summary["sampling_note"] = note
	} else {
		summary["sampling_note"] = "Sampling follows live emulation only; a paused system yields few or no entries."
	}
	if captureChannel != "" {
		summary["capture_channel"] = captureChannel
	}
	filters := map[string]any{
		"include_rom":     includeROM,
		"include_ram":     includeRAM,
		"retain_repeated": retainRepeated,
	}
	if hasRange {
		filters["address_range_start"] = rs
		filters["address_range_start_hex"] = canonicalHex(rs)
		filters["address_range_end"] = re
		filters["address_range_end_hex"] = canonicalHex(re)
	}
	summary["filters"] = filters
	delete(payload, "trace_text")
	return summary, artifactDescriptor(tc.server, storedText, context.ID), artifactDescriptor(tc.server, storedJSONL, context.ID), nil
}

func fetchCPUCurrentPC(tc toolContext, cpu string) uint64 {
	payload, failure := tc.server.executeCommand(tc.ctx, "regs_get", map[string]string{"cpu": cpu})
	if failure != nil {
		return 0
	}
	// Try m68k pc, then z80 pc
	if regs, ok := payload["registers"].(map[string]any); ok {
		if pc, ok := regs["pc"].(float64); ok {
			return uint64(pc)
		}
		if pc, ok := regs["PC"].(float64); ok {
			return uint64(pc)
		}
	}
	// Fallback: try direct pc field
	if pc, ok := payload["pc"].(float64); ok {
		return uint64(pc)
	}
	return 0
}

func fetchWatchpointInfo(tc toolContext, watchpointID uint64) map[string]any {
	payload, failure := tc.server.executeCommand(tc.ctx, "watchpoint_list", nil)
	if failure != nil {
		return nil
	}
	list, _ := payload["watchpoints"].([]any)
	for _, entry := range list {
		if m, ok := entry.(map[string]any); ok {
			if id, ok := m["watchpoint_id"].(float64); ok && uint64(id) == watchpointID {
				return m
			}
		}
	}
	return nil
}

func fetchWatchpointHitCount(tc toolContext, watchpointID uint64) uint64 {
	info := fetchWatchpointInfo(tc, watchpointID)
	if info == nil {
		return 0
	}
	if cnt, ok := info["hit_count"].(float64); ok {
		return uint64(cnt)
	}
	if cnt, ok := info["hit_counter"].(float64); ok {
		return uint64(cnt)
	}
	return 0
}

func debugEventDescriptor(server *Server, event debugEvent, contextID, captureID string) map[string]any {
	provenance := genericProvenance(server, "debug-event", time.Now().UTC())
	provenance.CaptureID = captureID
	provenance.AddressSpace = event.AddressSpace
	provenance.Device = event.CPU
	provenance.StartAddress = &event.WatchedAddress
	provenance.EffectiveAddress = &event.WatchedAddress
	provenance.StartAddressHex = canonicalHex(event.WatchedAddress)
	provenance.EffectiveAddressHex = canonicalHex(event.WatchedAddress)
	length := event.RequestedLength
	provenance.ByteLength = &length
	provenance.CaptureConsistency = &artifact.CaptureConsistency{State: "live", Note: "Watchpoint event captured upon hit; system was paused by the watchpoint."}
	if event.FrameToken != nil {
		provenance.FrameToken = event.FrameToken
	}
	eventData := map[string]any{
		"kind":                "watchpoint-event",
		"event_id":            event.ID,
		"resource_kind":       event.ResourceKind,
		"resource_id":         event.ResourceID,
		"context_id":          event.ContextID,
		"cpu":                 event.CPU,
		"triggering_pc":       event.TriggeringPC,
		"triggering_pc_hex":   canonicalHex(event.TriggeringPC),
		"address_space":       event.AddressSpace,
		"watched_address":     event.WatchedAddress,
		"watched_address_hex": canonicalHex(event.WatchedAddress),
		"access_direction":    event.AccessDirection,
		"requested_length":    event.RequestedLength,
		"hit_count":           event.HitCount,
		"target_generation":   event.TargetGeneration,
		"timestamp":           event.Timestamp,
		"schema_version":      "debug-event/1",
	}
	if event.FrameToken != nil {
		eventData["frame_token"] = *event.FrameToken
	}
	// Access width/value fields are not available from the native API; mark unknown.
	eventData["access_width"] = nil
	eventData["value_before"] = nil
	eventData["value_after"] = nil
	eventData["transferred_value"] = nil
	eventData["decoded_instruction_bytes"] = nil
	eventData["note"] = "Access width/value fields are not exposed by the native API and are marked unknown."
	// Store as artifact
	// Use a temporary context for storage; the event's context is used for provenance but storage is per requesting context
	stored, _ := server.store.PutWithProvenance(contextID, "debug-event", "application/json", mustMarshal(eventData), provenance)
	return artifactDescriptor(server, stored, contextID)
}

func mustMarshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func captureIDFromPayload(payload map[string]any) string {
	if id, ok := payload["capture_id"].(string); ok && id != "" {
		return id
	}
	return newCaptureID()
}

// ----------------------------------------------------------------------------------------------------------------------
// cpu_coverage_capture
// ----------------------------------------------------------------------------------------------------------------------

type coverageCaptureArgs struct {
	CPU            string `json:"cpu"`
	DurationMs     uint64 `json:"duration_ms"`
	MaxEntries     uint64 `json:"max_entries"`
	RegionStart    any    `json:"region_start"`
	RegionEnd      any    `json:"region_end"`
	AddressSpace   string `json:"address_space"`
	IncludeROM     *bool  `json:"include_rom"`
	IncludeRAM     *bool  `json:"include_ram"`
	RetainRepeated *bool  `json:"retain_repeated"`
	Context        string `json:"context"`
	guardArgs
}

func runCpuCoverageCapture(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[coverageCaptureArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.CPU != "m68k" && parsed.CPU != "z80" {
		return errorResult("invalid_params", "cpu must be m68k or z80", tc.modern)
	}
	duration := parsed.DurationMs
	if duration == 0 {
		duration = 500
	}
	if duration > 5000 {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "duration_ms is capped at 5000 ms."}, tc.modern)
	}
	maxEntries := parsed.MaxEntries
	if maxEntries == 0 {
		maxEntries = maxTraceEntries
	}
	if maxEntries > maxTraceEntries {
		maxEntries = maxTraceEntries
	}
	regionStart := uint64(0)
	if parsed.RegionStart != nil {
		regionStart, failure = resolveAddress(parsed.RegionStart, addressSpaceFromArgs(args), parsed.CPU+"-bus")
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
	}
	regionEnd := uint64(0xFFFFFFFF)
	if parsed.RegionEnd != nil {
		regionEnd, failure = resolveAddress(parsed.RegionEnd, addressSpaceFromArgs(args), parsed.CPU+"-bus")
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
	}
	if regionEnd <= regionStart {
		return errorResult("invalid_params", "region_end must be greater than region_start", tc.modern)
	}

	params := map[string]string{
		"cpu":         parsed.CPU,
		"timeout_ms":  strconv.FormatUint(duration, 10),
		"max_entries": strconv.FormatUint(maxEntries, 10),
		// Coverage needs entries even when the system is parked: the plugin
		// resumes it for the window and restores the prior run state.
		"force_run": "true",
	}
	payload, before, after, failure := tc.server.executeMutation(tc.ctx, mutationCall{
		tool:      "cpu_coverage_capture",
		operation: "trace_capture",
		params:    params,
		guard:     parsed.guard(),
		contextID: context.ID,
		detail: map[string]any{
			"cpu":          parsed.CPU,
			"duration_ms":  duration,
			"max_entries":  maxEntries,
			"region_start": regionStart,
			"region_end":   regionEnd,
		},
	})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	traceText, _ := payload["trace_text"].(string)
	allAddresses := parseTraceAddresses(traceText)
	entriesTotal := uint64(len(allAddresses))

	// Apply filters
	includeROM := true
	if parsed.IncludeROM != nil {
		includeROM = *parsed.IncludeROM
	}
	includeRAM := true
	if parsed.IncludeRAM != nil {
		includeRAM = *parsed.IncludeRAM
	}
	retainRepeated := true
	if parsed.RetainRepeated != nil {
		retainRepeated = *parsed.RetainRepeated
	}
	filtered := []uint64{}
	for _, addr := range allAddresses {
		if addr < regionStart || addr >= regionEnd {
			continue
		}
		if !includeROM && isROMAddress(addr, parsed.CPU) {
			continue
		}
		if !includeRAM && isRAMAddress(addr, parsed.CPU) {
			continue
		}
		filtered = append(filtered, addr)
	}
	// For coverage, we need the ordered filtered sequence for edges, and the set for blocks.
	// If retainRepeated is false, we deduplicate for the purpose of distinct set but keep edges from original filtered order.
	addressesForBlocks := filtered
	if !retainRepeated {
		seen := map[uint64]bool{}
		deduped := []uint64{}
		for _, a := range filtered {
			if !seen[a] {
				seen[a] = true
				deduped = append(deduped, a)
			}
		}
		addressesForBlocks = deduped
	}

	coverage := buildCoverageV2(tc, parsed.CPU, filtered, addressesForBlocks, regionStart, regionEnd)
	// Build versioned document
	coverageDocument := map[string]any{
		"schema_version": "cpu-coverage/2",
		"kind":           "cpu-coverage",
		"cpu":            parsed.CPU,
		"address_space":  coverage.AddressSpace,
		"byte_order":     coverage.ByteOrder,
		"region":         map[string]any{"start_address": regionStart, "start_address_hex": canonicalHex(regionStart), "end_address": regionEnd, "end_address_hex": canonicalHex(regionEnd)},
		"capture": map[string]any{
			"duration_ms":     duration,
			"max_entries":     maxEntries,
			"region_start":    regionStart,
			"region_end":      regionEnd,
			"include_rom":     includeROM,
			"include_ram":     includeRAM,
			"retain_repeated": retainRepeated,
		},
		"execution": map[string]any{
			"total_events":     entriesTotal,
			"filtered_events":  len(filtered),
			"unique_addresses": coverage.Distinct,
			"addresses":        coverage.Addresses,
			"counts":           coverage.Counts,
		},
		"blocks":      coverage.Blocks,
		"edges":       coverage.Edges,
		"pages_top":   coverage.PagesTop,
		"pages_total": coverage.PagesTotal,
		"truncation":  coverage.Truncation,
		"provenance": map[string]any{
			"capture_conditions": map[string]any{
				"duration_ms":     duration,
				"max_entries":     maxEntries,
				"region_start":    regionStart,
				"region_end":      regionEnd,
				"include_rom":     includeROM,
				"include_ram":     includeRAM,
				"retain_repeated": retainRepeated,
			},
			"rom_identity": tc.server.romIdentityView(0),
		},
	}
	// Keep legacy fields for backward compatibility
	coverageDocument["duration_ms"] = duration
	coverageDocument["entries_total"] = entriesTotal
	coverageDocument["distinct_total"] = coverage.Distinct
	coverageDocument["ranges"] = coverage.Ranges
	coverageDocument["truncated"] = coverage.AddressesTruncated
	if !coverage.AddressesTruncated {
		coverageDocument["addresses"] = coverage.Addresses
	} else {
		coverageDocument["addresses"] = coverage.Addresses[:maxCoverageAddresses]
	}
	annotateAddressMap(coverageDocument, coverage.AddressSpace)
	documentBytes, err := json.Marshal(coverageDocument)
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}
	provenance := coverageProvenance(tc, parsed.CPU, regionStart, regionEnd)
	// Record filters in provenance
	if !includeROM || !includeRAM || !retainRepeated {
		provenance.CaptureConsistency = &artifact.CaptureConsistency{
			State: "live",
			Note:  fmt.Sprintf("Filters: include_rom=%v include_ram=%v retain_repeated=%v", includeROM, includeRAM, retainRepeated),
		}
	}
	stored, err := tc.server.store.PutWithProvenance(context.ID, "cpu-coverage", "application/json", documentBytes, provenance)
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}

	result := map[string]any{
		"summary": map[string]any{
			"kind":            "cpu-coverage",
			"schema_version":  "cpu-coverage/2",
			"cpu":             parsed.CPU,
			"address_space":   coverage.AddressSpace,
			"duration_ms":     duration,
			"entries_total":   entriesTotal,
			"filtered_events": len(filtered),
			"distinct_total":  coverage.Distinct,
			"blocks_count":    len(coverage.Blocks),
			"edges_count":     len(coverage.Edges),
			"ranges_count":    len(coverage.Ranges),
			"pages_total":     coverage.PagesTotal,
			"pages_top":       coverage.PagesTop,
			"truncated":       coverage.Truncation,
			"sha256":          stored.SHA256,
		},
		"artifact": artifactDescriptor(tc.server, stored, context.ID),
	}
	// Include legacy fields for existing tests
	summary := result["summary"].(map[string]any)
	summary["entries_total"] = entriesTotal
	summary["distinct_total"] = coverage.Distinct
	summary["ranges_count"] = len(coverage.Ranges)
	return okResult(stampGenerations(result, before, after), tc.modern)
}

// coverageProvenance builds the capture envelope for one coverage artifact:
// the CPU's bus address domain over the requested region plus target and ROM
// identity at capture time. The region window is recorded as the captured
// address domain; the executed-address set itself lives in the document.
func coverageProvenance(tc toolContext, cpu string, regionStart, regionEnd uint64) *artifact.Provenance {
	provenance := genericProvenance(tc.server, "cpu-coverage", time.Now().UTC())
	start := regionStart
	length := regionEnd - regionStart
	if cpu == "z80" {
		provenance.AddressSpace = "z80-bus"
		provenance.ByteOrder = "little-endian"
	} else {
		provenance.AddressSpace = "m68k-bus"
		provenance.ByteOrder = "big-endian"
	}
	provenance.Device = cpu
	provenance.StartAddress = &start
	provenance.EffectiveAddress = &start
	provenance.StartAddressHex = canonicalHex(start)
	provenance.EffectiveAddressHex = canonicalHex(start)
	provenance.ByteLength = &length
	return provenance
}

// parseTraceAddresses reads the leading hex address of every trace line
// (format: "ADDRESS CYCLE OPCODE ARGS").
func parseTraceAddresses(traceText string) []uint64 {
	addresses := []uint64{}
	for _, line := range strings.Split(traceText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		space := strings.IndexByte(line, ' ')
		token := line
		if space > 0 {
			token = line[:space]
		}
		address, err := strconv.ParseUint(token, 16, 64)
		if err != nil {
			continue
		}
		addresses = append(addresses, address)
	}
	return addresses
}

type coverageResult struct {
	Distinct           uint64
	Ranges             []map[string]any
	PagesTop           []map[string]any
	PagesTotal         uint64
	Addresses          []uint64
	AddressesTruncated bool
}

func buildCoverage(addresses []uint64, regionStart, regionEnd uint64) coverageResult {
	unique := make([]uint64, 0, len(addresses))
	seen := make(map[uint64]struct{}, len(addresses))
	for _, address := range addresses {
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		unique = append(unique, address)
	}
	sort.Slice(unique, func(i, j int) bool { return unique[i] < unique[j] })

	// Merged consecutive-address spans.
	ranges := []map[string]any{}
	if len(unique) > 0 {
		start := unique[0]
		previous := unique[0]
		count := uint64(1)
		for _, address := range unique[1:] {
			if address == previous+1 {
				previous = address
				count++
				continue
			}
			ranges = append(ranges, map[string]any{"start_address": start, "end_address": previous, "count": count})
			start = address
			previous = address
			count = 1
		}
		ranges = append(ranges, map[string]any{"start_address": start, "end_address": previous, "count": count})
	}

	// Page histogram (page size 0x100 bytes), top pages by distinct count.
	pageCounts := map[uint64]uint64{}
	for _, address := range unique {
		pageCounts[address/coveragePageSize]++
	}
	type pageEntry struct {
		Page  uint64
		Count uint64
	}
	pages := []pageEntry{}
	for page, count := range pageCounts {
		pages = append(pages, pageEntry{Page: page, Count: count})
	}
	sort.Slice(pages, func(i, j int) bool {
		if pages[i].Count != pages[j].Count {
			return pages[i].Count > pages[j].Count
		}
		return pages[i].Page < pages[j].Page
	})
	pagesTop := []map[string]any{}
	for index := 0; index < len(pages) && index < coverPageTop; index++ {
		pagesTop = append(pagesTop, map[string]any{
			"page":      pages[index].Page,
			"page_base": pages[index].Page * coveragePageSize,
			"count":     pages[index].Count,
		})
	}

	return coverageResult{
		Distinct:           uint64(len(unique)),
		Ranges:             ranges,
		PagesTop:           pagesTop,
		PagesTotal:         uint64(len(pages)),
		Addresses:          unique,
		AddressesTruncated: uint64(len(unique)) > maxCoverageAddresses,
	}
}

type coverageResultV2 struct {
	coverageResult
	AddressSpace string
	ByteOrder    string
	Counts       map[string]uint64
	Blocks       []map[string]any
	Edges        []map[string]any
	Truncation   map[string]any
}

func buildCoverageV2(tc toolContext, cpu string, ordered []uint64, uniqueForBlocks []uint64, regionStart, regionEnd uint64) coverageResultV2 {
	// Use the legacy unique set for distinct count, but build instruction-aware blocks from uniqueForBlocks.
	base := buildCoverage(uniqueForBlocks, regionStart, regionEnd)
	addressSpace := "m68k-bus"
	byteOrder := "big-endian"
	if cpu == "z80" {
		addressSpace = "z80-bus"
		byteOrder = "little-endian"
	}
	// Execution counts per address from ordered (including filtered) sequence
	counts := map[uint64]uint64{}
	for _, addr := range ordered {
		counts[addr]++
	}
	countsStrKeys := map[string]uint64{}
	for addr, cnt := range counts {
		countsStrKeys[canonicalHex(addr)] = cnt
	}
	// Build edges from ordered sequence
	edgeCounts := map[string]uint64{}
	edgeFromTo := map[string][2]uint64{}
	for i := 1; i < len(ordered); i++ {
		from := ordered[i-1]
		to := ordered[i]
		key := canonicalHex(from) + "->" + canonicalHex(to)
		edgeCounts[key]++
		if _, ok := edgeFromTo[key]; !ok {
			edgeFromTo[key] = [2]uint64{from, to}
		}
	}
	edges := []map[string]any{}
	for key, cnt := range edgeCounts {
		fromTo := edgeFromTo[key]
		edges = append(edges, map[string]any{
			"from":     fromTo[0],
			"from_hex": canonicalHex(fromTo[0]),
			"to":       fromTo[1],
			"to_hex":   canonicalHex(fromTo[1]),
			"count":    cnt,
		})
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i]["from"].(uint64) != edges[j]["from"].(uint64) {
			return edges[i]["from"].(uint64) < edges[j]["from"].(uint64)
		}
		return edges[i]["to"].(uint64) < edges[j]["to"].(uint64)
	})

	// Instruction-aware blocks: need lengths
	uniqueSorted := base.Addresses
	// Fetch lengths for each unique address (cached)
	lengths := map[uint64]int{}
	for _, addr := range uniqueSorted {
		info := fetchInstructionInfo(tc, cpu, addr)
		if info != nil {
			if l, ok := info["length"].(int); ok && l > 0 {
				lengths[addr] = l
			} else {
				lengths[addr] = 2 // default for m68k
				if cpu == "z80" {
					lengths[addr] = 1
				}
			}
		} else {
			lengths[addr] = 2
			if cpu == "z80" {
				lengths[addr] = 1
			}
		}
	}
	blocks := []map[string]any{}
	if len(uniqueSorted) > 0 {
		blockStart := uniqueSorted[0]
		blockEnd := uniqueSorted[0]
		blockAddrs := []uint64{uniqueSorted[0]}
		blockExecCount := counts[uniqueSorted[0]]
		for idx := 1; idx < len(uniqueSorted); idx++ {
			curr := uniqueSorted[idx]
			prev := uniqueSorted[idx-1]
			prevLen := lengths[prev]
			expectedNext := prev + uint64(prevLen)
			if curr == expectedNext {
				// Same block
				blockEnd = curr
				blockAddrs = append(blockAddrs, curr)
				blockExecCount += counts[curr]
			} else {
				// Close block
				blocks = append(blocks, map[string]any{
					"start_address":     blockStart,
					"start_address_hex": canonicalHex(blockStart),
					"end_address":       blockEnd,
					"end_address_hex":   canonicalHex(blockEnd),
					"instruction_count": len(blockAddrs),
					"execution_count":   blockExecCount,
					"addresses":         append([]uint64{}, blockAddrs...),
					"address_space":     addressSpace,
				})
				blockStart = curr
				blockEnd = curr
				blockAddrs = []uint64{curr}
				blockExecCount = counts[curr]
			}
		}
		blocks = append(blocks, map[string]any{
			"start_address":     blockStart,
			"start_address_hex": canonicalHex(blockStart),
			"end_address":       blockEnd,
			"end_address_hex":   canonicalHex(blockEnd),
			"instruction_count": len(blockAddrs),
			"execution_count":   blockExecCount,
			"addresses":         append([]uint64{}, blockAddrs...),
			"address_space":     addressSpace,
		})
	}
	// Truncation facts
	truncation := map[string]any{
		"source_events":    len(ordered),
		"decoded_events":   len(ordered), // we decoded all for lengths
		"unique_addresses": len(uniqueSorted),
		"blocks":           len(blocks),
		"edges":            len(edges),
		"complete":         !base.AddressesTruncated,
		"note":             "Truncation is per-category; a trace ring/timeout limit truncates source_events, which propagates to decoded/unique/blocks/edges. Complete is false when source was truncated.",
	}
	return coverageResultV2{
		coverageResult: base,
		AddressSpace:   addressSpace,
		ByteOrder:      byteOrder,
		Counts:         countsStrKeys,
		Blocks:         blocks,
		Edges:          edges,
		Truncation:     truncation,
	}
}
