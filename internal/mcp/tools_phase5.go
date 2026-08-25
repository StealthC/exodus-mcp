package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/StealthC/exodus-mcp/internal/analysis"
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
		{
			name:        "cpu_coverage_capture",
			description: "Run the system for a bounded window and record which code addresses executed into a coverage artifact (distinct addresses, merged ranges, page histogram). Reuses the trace_capture path; the prior run state is restored afterwards. The system runs during the window, so the capture mutates the target and advances the target generation. Accepts optional expected_target_generation and control_id.",
			schema: objectSchema(map[string]any{
				"cpu":                        enumProperty("Processor to trace.", []string{"m68k", "z80"}),
				"duration_ms":                integerProperty("Trace window in milliseconds (default 500, cap 5000).", 1),
				"max_entries":                integerProperty("Maximum trace entries retained (default 10000, cap 10000).", 1),
				"region_start":               addressProperty(),
				"region_end":                 addressProperty(),
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
			description: "Search a consistent snapshot for a raw byte pattern. Without snapshot_id the tool dumps the range into a snapshot artifact first (never a live racy scan); with snapshot_id it searches that artifact without any new read. Returns bounded inline matches plus a full-results artifact.",
			schema: objectSchema(map[string]any{
				"space":         stringProperty("Address space id from memory_spaces_list; defines the address domain of the matches."),
				"pattern":       stringProperty("Byte pattern as hex with optional spaces, e.g. \"4A 42 41\" or \"4a4241\"."),
				"start_address": addressProperty(),
				"length":        integerProperty(fmt.Sprintf("Bytes to scan (default %d when no snapshot is given; must equal the snapshot size with snapshot_id).", dumpCapBytes), 1),
				"max_matches":   integerProperty(fmt.Sprintf("Maximum inline matches (default %d, cap %d).", defaultSearchMaxMatches, maxSearchMaxMatches), 1),
				"snapshot_id":   stringProperty("Optional id of a memory-dump or memory-snapshot artifact to search instead of reading again."),
				"context":       contextProperty(),
			}, []string{"space", "pattern"}),
			run: runMemorySearch,
		},
		{
			name:        "memory_diff",
			description: "Compare two consistent memory snapshots cell-by-cell and report cells matching a comparison mode. Without snapshot_after_id the region is read fresh into a snapshot first (never a live racy scan). Modes: changed, unchanged, increased, decreased, changed_by (signed delta), equal_to (after value), in_range (after value bounds). Width byte/word/long with explicit byte order (default big-endian) and aligned scanning by default. Returns bounded inline matches plus a full-results artifact.",
			schema: objectSchema(map[string]any{
				"snapshot_before_id": stringProperty("id of a memory-dump or memory-snapshot artifact representing the earlier state."),
				"snapshot_after_id":  stringProperty("optional id of a memory-dump or memory-snapshot artifact representing the later state; when omitted, the before range is read fresh into a snapshot before comparing."),
				"space":              stringProperty("Address space id from memory_spaces_list; required when snapshot_after_id is omitted."),
				"mode":               enumProperty("Comparison mode.", []string{"changed", "unchanged", "increased", "decreased", "changed_by", "equal_to", "in_range"}),
				"width":              enumProperty("Cell width. Default byte; word/long cells honor byte_order.", []string{"byte", "word", "long"}),
				"byte_order":         enumProperty("Byte order for word/long cells. Default big-endian (M68K domain); use little-endian for Z80 RAM cells.", []string{"big-endian", "little-endian"}),
				"value":              integerProperty("Value for equal_to (unsigned, must fit the width) or the signed delta for changed_by.", 0),
				"min_value":          integerProperty("Lower bound for in_range.", 0),
				"max_value":          integerProperty("Upper bound for in_range.", 0),
				"start_address":      addressProperty(),
				"max_matches":        integerProperty(fmt.Sprintf("Maximum inline matches (default %d, cap %d).", defaultSearchMaxMatches, maxSearchMaxMatches), 1),
				"allow_misaligned":   booleanProperty("Scan every cell offset instead of aligning to the cell width in the address domain."),
				"context":            contextProperty(),
			}, []string{"snapshot_before_id", "mode"}),
			run: runMemoryDiff,
		},
		{
			name:        "rom_info",
			description: "Parse the Mega Drive cartridge header at 0x100 (system type, copyright, titles, serial, checksum, I/O support, ROM/RAM/SRAM windows, region) and validate the header checksum against the computed Sega sum over the ROM body. Also reports the declared and reference memory mapping. Attaches a header-region hexdump artifact.",
			schema:      objectSchema(map[string]any{"context": contextProperty()}, nil),
			run:         runROMInfo,
		},
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// Shared bridge read
// ----------------------------------------------------------------------------------------------------------------------

// readBridgeBytes executes mem_read and returns the decoded bytes, the
// space's declared byte order, and the effective address. Reads are capped at
// dumpCapBytes, matching memory_dump.
func readBridgeBytes(tc toolContext, space string, address, length uint64) ([]byte, string, uint64, *toolFailure) {
	if length < 1 || length > dumpCapBytes {
		return nil, "", 0, &toolFailure{
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
		return nil, "", 0, failure
	}
	rawDataBase64, _ := payload["data"].(string)
	raw, err := base64.StdEncoding.DecodeString(rawDataBase64)
	if err != nil {
		return nil, "", 0, &toolFailure{Code: "bridge_error", Message: "decode base64 memory payload: " + err.Error()}
	}
	byteOrder, _ := payload["byte_order"].(string)
	effective, _ := payload["effective_address"].(float64)
	return raw, byteOrder, uint64(effective), nil
}

// ----------------------------------------------------------------------------------------------------------------------
// memory_search
// ----------------------------------------------------------------------------------------------------------------------

type memorySearchArgs struct {
	Space        string `json:"space"`
	Pattern      string `json:"pattern"`
	StartAddress any    `json:"start_address"`
	Length       uint64 `json:"length"`
	MaxMatches   uint64 `json:"max_matches"`
	SnapshotID   string `json:"snapshot_id"`
	Context      string `json:"context"`
}

func runMemorySearch(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[memorySearchArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if strings.TrimSpace(parsed.Space) == "" {
		return errorResult("invalid_params", "space is required", tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	pattern, failure := parseHexPattern(parsed.Pattern)
	if failure != nil {
		return failureResult(failure, tc.modern)
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
		startAddress, failure = parseAddress(parsed.StartAddress)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
	}

	var snapshotBytes []byte
	var snapshot = make(map[string]any)
	if parsed.SnapshotID != "" {
		meta, err := tc.server.store.Metadata(parsed.SnapshotID, context.ID)
		if err != nil {
			return failureResult(&toolFailure{Code: "unknown_artifact", Message: err.Error()}, tc.modern)
		}
		if meta.Kind != "memory-dump" && meta.Kind != "memory-snapshot" {
			return failureResult(&toolFailure{
				Code:    "invalid_params",
				Message: "snapshot_id must reference a memory-dump or memory-snapshot artifact; got kind " + meta.Kind,
			}, tc.modern)
		}
		snapshotBytes, _, err = tc.server.store.Bytes(parsed.SnapshotID, context.ID)
		if err != nil {
			return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
		}
		if parsed.Length != 0 && parsed.Length != uint64(len(snapshotBytes)) {
			return failureResult(&toolFailure{
				Code:    "invalid_params",
				Message: fmt.Sprintf("length %d does not match the snapshot byte length %d", parsed.Length, len(snapshotBytes)),
			}, tc.modern)
		}
		snapshot = artifactDescriptor(tc.server, meta, context.ID)
	} else {
		length := parsed.Length
		if length == 0 {
			length = dumpCapBytes
		}
		if length < 1 || length > dumpCapBytes {
			return failureResult(&toolFailure{
				Code:    "length_out_of_range",
				Message: fmt.Sprintf("length must be between 1 and %d bytes.", dumpCapBytes),
			}, tc.modern)
		}
		raw, _, _, failure := readBridgeBytes(tc, parsed.Space, startAddress, length)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		snapshotBytes = raw
		stored, err := tc.server.store.Put(context.ID, "memory-snapshot", "application/octet-stream", raw)
		if err != nil {
			return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
		}
		snapshot = artifactDescriptor(tc.server, stored, context.ID)
	}

	matches, total, inlineTruncated, artifactTruncated := findPatternMatches(snapshotBytes, pattern, startAddress, maxMatches)

	patternHex := strings.ToUpper(hex.EncodeToString(pattern))
	results := map[string]any{
		"kind":                 "memory-search-results",
		"address_space":        parsed.Space,
		"pattern_hex":          patternHex,
		"pattern_length_bytes": len(pattern),
		"interpretation":       "matches are byte addresses in the address space; the pattern is raw bytes in address order and no endian interpretation is applied",
		"range": map[string]any{
			"start_address": startAddress,
			"byte_length":   len(snapshotBytes),
		},
		"matches_total": total,
		"truncated":     artifactTruncated,
		"addresses":     matches.Addresses,
	}
	resultsBytes, err := json.Marshal(results)
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}
	storedResults, err := tc.server.store.Put(context.ID, "memory-search-results", "application/json", resultsBytes)
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}

	return okResult(map[string]any{
		"summary": map[string]any{
			"kind":                   "memory-search",
			"address_space":          parsed.Space,
			"pattern_hex":            patternHex,
			"pattern_length_bytes":   len(pattern),
			"interpretation":         "matches are byte addresses; raw pattern bytes preserve address order and are never decoded",
			"searched_start_address": startAddress,
			"searched_byte_length":   len(snapshotBytes),
			"matches_total":          total,
			"inline_matches_shown":   len(matches.Inline),
			"matches_truncated":      inlineTruncated,
			"snapshot":               snapshot,
		},
		"matches":  matches.Inline,
		"artifact": artifactDescriptor(tc.server, storedResults, context.ID),
	}, tc.modern)
}

type searchMatches struct {
	Inline    []map[string]any
	Addresses []uint64
}

// findPatternMatches scans data for pattern and reports the first up to
// inlineLimit matches inline plus up to maxSearchArtifactMatches addresses for
// the full-results artifact. Adresses are anchored at startAddress.
func findPatternMatches(data, pattern []byte, startAddress uint64, inlineLimit uint64) (searchMatches, uint64, bool, bool) {
	result := searchMatches{Inline: []map[string]any{}, Addresses: []uint64{}}
	var total uint64
	if len(pattern) == 0 {
		return result, 0, false, false
	}
	for index := 0; index+len(pattern) <= len(data); index++ {
		if !bytes.Equal(data[index:index+len(pattern)], pattern) {
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
				"address_hex": fmt.Sprintf("0x%X", address),
				"offset":      uint64(index),
			})
		}
	}
	inlineTruncated := uint64(len(result.Inline)) < total
	artifactTruncated := uint64(len(result.Addresses)) < total
	return result, total, inlineTruncated, artifactTruncated
}

func parseHexPattern(raw string) ([]byte, *toolFailure) {
	cleaned := ""
	for _, r := range raw {
		switch r {
		case ' ', '\t', '\r', '\n':
		default:
			cleaned += string(r)
		}
	}
	if cleaned == "" {
		return nil, &toolFailure{Code: "invalid_params", Message: "pattern is required and must contain hex bytes"}
	}
	if len(cleaned)%2 != 0 {
		return nil, &toolFailure{Code: "invalid_params", Message: "pattern must contain an even number of hex digits"}
	}
	decoded, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, &toolFailure{Code: "invalid_params", Message: "pattern contains non-hex characters: " + err.Error()}
	}
	return decoded, nil
}

// ----------------------------------------------------------------------------------------------------------------------
// memory_diff — cheat-finder snapshot comparison
// ----------------------------------------------------------------------------------------------------------------------

type memoryDiffArgs struct {
	SnapshotBeforeID string  `json:"snapshot_before_id"`
	SnapshotAfterID  string  `json:"snapshot_after_id"`
	Space            string  `json:"space"`
	Mode             string  `json:"mode"`
	Width            string  `json:"width"`
	ByteOrder        string  `json:"byte_order"`
	Value            *int64  `json:"value"`
	MinValue         *uint64 `json:"min_value"`
	MaxValue         *uint64 `json:"max_value"`
	StartAddress     any     `json:"start_address"`
	MaxMatches       uint64  `json:"max_matches"`
	AllowMisaligned  bool    `json:"allow_misaligned"`
	Context          string  `json:"context"`
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
// bytes, its descriptor, and the space used for a fresh read when needed.
func loadDiffSnapshot(tc toolContext, contextID, id string) ([]byte, map[string]any, *toolFailure) {
	meta, err := tc.server.store.Metadata(id, contextID)
	if err != nil {
		return nil, nil, &toolFailure{Code: "unknown_artifact", Message: err.Error()}
	}
	if meta.Kind != "memory-dump" && meta.Kind != "memory-snapshot" {
		return nil, nil, &toolFailure{
			Code:    "invalid_params",
			Message: "snapshot ids must reference memory-dump or memory-snapshot artifacts; got kind " + meta.Kind,
		}
	}
	data, _, err := tc.server.store.Bytes(id, contextID)
	if err != nil {
		return nil, nil, &toolFailure{Code: "artifact_error", Message: err.Error()}
	}
	return data, artifactDescriptor(tc.server, meta, contextID), nil
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
	startAddress := uint64(0)
	if parsed.StartAddress != nil {
		startAddress, failure = parseAddress(parsed.StartAddress)
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

	beforeBytes, beforeSnapshot, failure := loadDiffSnapshot(tc, context.ID, parsed.SnapshotBeforeID)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if len(beforeBytes) == 0 {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "the before snapshot is empty; nothing to compare."}, tc.modern)
	}

	var afterBytes []byte
	var afterSnapshot map[string]any
	freshAfterRead := false
	if parsed.SnapshotAfterID != "" {
		afterBytes, afterSnapshot, failure = loadDiffSnapshot(tc, context.ID, parsed.SnapshotAfterID)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		if len(afterBytes) != len(beforeBytes) {
			return failureResult(&toolFailure{
				Code:    "invalid_params",
				Message: fmt.Sprintf("snapshot lengths differ: before %d bytes, after %d bytes; both snapshots must cover the same range", len(beforeBytes), len(afterBytes)),
			}, tc.modern)
		}
	} else {
		if parsed.Space == "" {
			return errorResult("invalid_params", "space is required when snapshot_after_id is omitted", tc.modern)
		}
		raw, _, _, failure := readBridgeBytes(tc, parsed.Space, startAddress, uint64(len(beforeBytes)))
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		afterBytes = raw
		stored, err := tc.server.store.Put(context.ID, "memory-snapshot", "application/octet-stream", raw)
		if err != nil {
			return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
		}
		afterSnapshot = artifactDescriptor(tc.server, stored, context.ID)
		freshAfterRead = true
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
				"address_hex": fmt.Sprintf("0x%X", address),
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
		"byte_length":            len(beforeBytes),
		"width_bytes":            width,
		"cells_scanned":          cellsScanned,
		"first_cell_offset":      firstCell,
		"trailing_bytes_ignored": trailingBytes,
	}
	document := map[string]any{
		"kind":             "memory-diff-results",
		"mode":             parsed.Mode,
		"width":            widthName,
		"width_bytes":      width,
		"byte_order":       byteOrder,
		"alignment":        alignment,
		"interpretation":   fmt.Sprintf("cells are compared at %d-byte granularity in address order; the %s representation is applied per cell and %s is the alignment policy", width, byteOrder, alignment),
		"range":            rangeInfo,
		"before_snapshot":  beforeSnapshot,
		"after_snapshot":   afterSnapshot,
		"fresh_after_read": freshAfterRead,
		"matches_total":    total,
		"truncated":        artifactTruncated,
		"matches":          records,
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
	storedResults, err := tc.server.store.Put(context.ID, "memory-diff-results", "application/json", documentBytes)
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
		"interpretation":       fmt.Sprintf("cells are compared at %d-byte granularity in address order; the %s representation is applied per cell and %s is the alignment policy", width, byteOrder, alignment),
		"range":                rangeInfo,
		"before_snapshot":      beforeSnapshot,
		"after_snapshot":       afterSnapshot,
		"fresh_after_read":     freshAfterRead,
		"matches_total":        total,
		"inline_matches_shown": len(matches),
		"matches_truncated":    inlineTruncated,
		"sha256":               storedResults.SHA256,
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
	return okResult(map[string]any{
		"summary":  summary,
		"matches":  matches,
		"artifact": artifactDescriptor(tc.server, storedResults, context.ID),
	}, tc.modern)
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
// emulator_status (0 when unknown), used to clamp the checksum range; contextID
// scopes the header artifact.
func mdROMInfo(tc toolContext, contextID string, romSizeBytes uint64) (map[string]any, *toolFailure) {
	header, byteOrder, effective, failure := readBridgeBytes(tc, "m68k-bus", 0x100, 0x100)
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
	bodyEnd := uint64(parsed.ROMEnd) + 1
	rangeCapped := false
	if romSizeBytes > 0 && bodyEnd > romSizeBytes {
		bodyEnd = romSizeBytes
		rangeCapped = true
	}
	readStart := uint64(0x200)
	if bodyEnd > readStart+dumpCapBytes {
		bodyEnd = readStart + dumpCapBytes
		rangeCapped = true
	}
	computed := uint16(0)
	checksumRange := map[string]any{"start_address": readStart, "end_address": uint64(0x1FF)}
	if bodyEnd > readStart {
		body, _, _, failure := readBridgeBytes(tc, "m68k-bus", readStart, bodyEnd-readStart)
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

	countries, hardwareCode := decodeRegions(parsed.Region)

	headerArtifact, err := tc.server.store.Put(contextID, "rom-header", "application/octet-stream", header)
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

	result := map[string]any{
		"identified":        true,
		"byte_order":        "big-endian (M68K cartridge header; the bus read reported " + byteOrder + ")",
		"effective_address": effective,
		"loaded_size_bytes": romSizeBytes,
		"header": map[string]any{
			"system_type":   parsed.SystemType,
			"copyright":     parsed.Copyright,
			"domestic_name": parsed.Domestic,
			"overseas_name": parsed.Overseas,
			"serial":        decodeSerial(parsed.Serial),
			"io_support":    parsed.IOSupport,
			"modem":         parsed.Modem,
			"memo":          parsed.Memo,
			"checksum": map[string]any{
				"stored":   parsed.Checksum,
				"computed": computed,
				"matches":  parsed.Checksum == computed,
				"range":    checksumRange,
			},
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
	info, failure := mdROMInfo(tc, context.ID, status.Rom.SizeBytes)
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

	summary, artifactDesc, failure := traceArtifactFromPayload(tc, context, payload)
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
	result := map[string]any{"summary": summary, "artifact": artifactDesc}
	return okResult(stampGenerations(result, before, after), tc.modern)
}

// traceArtifactFromPayload turns a trace_capture payload into a stored
// text artifact plus a compact inline summary.
func traceArtifactFromPayload(tc toolContext, context *analysis.Context, payload map[string]any) (map[string]any, map[string]any, *toolFailure) {
	traceText, _ := payload["trace_text"].(string)
	stored, err := tc.server.store.Put(context.ID, "cpu-trace", "text/plain; charset=utf-8", []byte(traceText))
	if err != nil {
		return nil, nil, &toolFailure{Code: "artifact_error", Message: err.Error()}
	}
	delete(payload, "trace_text")
	captured, _ := payload["captured"].(float64)
	timedOut, _ := payload["timed_out"].(bool)
	cpu, _ := payload["cpu"].(string)
	sample, _ := payload["sample"].([]any)
	captureChannel, _ := payload["capture_channel"].(string)

	summary := map[string]any{
		"kind":      "cpu-trace",
		"cpu":       cpu,
		"captured":  int(captured),
		"timed_out": timedOut,
		"sample":    sample,
		"sha256":    stored.SHA256,
	}
	if note, ok := payload["sampling_note"].(string); ok && note != "" {
		summary["sampling_note"] = note
	} else {
		summary["sampling_note"] = "Sampling follows live emulation only; a paused system yields few or no entries."
	}
	if captureChannel != "" {
		summary["capture_channel"] = captureChannel
	}
	return summary, artifactDescriptor(tc.server, stored, context.ID), nil
}

// ----------------------------------------------------------------------------------------------------------------------
// cpu_coverage_capture
// ----------------------------------------------------------------------------------------------------------------------

type coverageCaptureArgs struct {
	CPU         string `json:"cpu"`
	DurationMs  uint64 `json:"duration_ms"`
	MaxEntries  uint64 `json:"max_entries"`
	RegionStart any    `json:"region_start"`
	RegionEnd   any    `json:"region_end"`
	Context     string `json:"context"`
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
		regionStart, failure = parseAddress(parsed.RegionStart)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
	}
	regionEnd := uint64(0xFFFFFFFF)
	if parsed.RegionEnd != nil {
		regionEnd, failure = parseAddress(parsed.RegionEnd)
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
	addresses := parseTraceAddresses(traceText)

	filtered := addresses[:0]
	entriesTotal := uint64(0)
	for _, address := range addresses {
		if address >= regionStart && address < regionEnd {
			filtered = append(filtered, address)
		}
		entriesTotal++
	}
	addresses = filtered

	coverage := buildCoverage(addresses, regionStart, regionEnd)
	coverageDocument := map[string]any{
		"kind":           "cpu-coverage",
		"cpu":            parsed.CPU,
		"byte_order":     "M68K addresses are 24-bit big-endian address values; Z80 addresses are 16-bit little-endian values; addresses are reported in canonical hex",
		"region":         map[string]any{"start_address": regionStart, "end_address": regionEnd},
		"duration_ms":    duration,
		"entries_total":  entriesTotal,
		"distinct_total": coverage.Distinct,
		"ranges":         coverage.Ranges,
		"pages_top":      coverage.PagesTop,
		"pages_total":    coverage.PagesTotal,
		"truncated":      coverage.AddressesTruncated,
	}
	if !coverage.AddressesTruncated {
		coverageDocument["addresses"] = coverage.Addresses
	} else {
		coverageDocument["addresses"] = coverage.Addresses[:maxCoverageAddresses]
	}
	documentBytes, err := json.Marshal(coverageDocument)
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}
	stored, err := tc.server.store.Put(context.ID, "cpu-coverage", "application/json", documentBytes)
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}

	result := map[string]any{
		"summary": map[string]any{
			"kind":           "cpu-coverage",
			"cpu":            parsed.CPU,
			"duration_ms":    duration,
			"entries_total":  entriesTotal,
			"distinct_total": coverage.Distinct,
			"ranges_count":   len(coverage.Ranges),
			"pages_total":    coverage.PagesTotal,
			"pages_top":      coverage.PagesTop,
			"truncated":      coverage.AddressesTruncated,
			"sha256":         stored.SHA256,
		},
		"artifact": artifactDescriptor(tc.server, stored, context.ID),
	}
	return okResult(stampGenerations(result, before, after), tc.modern)
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
