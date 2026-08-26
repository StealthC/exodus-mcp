package mcp

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/StealthC/exodus-mcp/internal/analysis"
	"github.com/StealthC/exodus-mcp/internal/symbols"
)

// m68k_backtrace (roadmap P7): walk the M68K stack through A7 (the active
// stack pointer) plus an optional A6 frame-pointer chain, resolving addresses
// against context symbols. Every frame beyond the live PC is a heuristic:
// stack slots are only plausible return addresses, never execution-verified
// call sites. The scan is read-only live memory access (the plugin pauses per
// read when the system runs, as mem_read always does) and the result carries
// the standardized composite capture-consistency object.

const (
	defaultBacktraceFrames = 32
	maxBacktraceFrames     = 128
	// backtraceScanWindow bounds the linear stack scan in address space;
	// backtraceScanSlots bounds the number of bridge reads per walk so a
	// garbage stack pointer cannot turn into an unbounded IPC loop.
	backtraceScanWindow = 0x10000
	backtraceScanSlots  = 256
	// maxBacktraceSymbolOffset is the largest distance from a symbol base for
	// which a frame is labeled symbol+offset; farther addresses stay unnamed.
	maxBacktraceSymbolOffset = 0x10000
)

// m68kBusMask is the 24-bit bus mask of the Mega Drive M68K bus, matching
// disasmSymbolMask("m68k") and addressBusWidthMask.
const m68kBusMask = 0x00FFFFFF

func backtraceToolSpecs() []toolSpec {
	return []toolSpec{
		{
			name:        "m68k_backtrace",
			description: "Walk the M68K stack from A7 (active stack pointer, USP or SSP depending on the SR supervisor bit) and optionally follow the A6 frame-pointer chain, resolving candidate return addresses against symbols_set symbols. Heuristics are documented and flagged per frame: frame 0 is the live PC; every other frame is a 4-byte stack slot whose value is nonzero, even, and falls inside a documented executable region (ROM 0x000000-0x3FFFFF or RAM 0xFF0000-0xFFFFFF). Never claims execution-verified call sites; a stack may hold data, not return addresses. Reads are live (no capture guard) and the result carries the standardized capture_consistency object.",
			schema: objectSchema(map[string]any{
				"max_frames":  integerProperty(fmt.Sprintf("Maximum frames (default %d, cap %d).", defaultBacktraceFrames, maxBacktraceFrames), 1),
				"include_raw": booleanProperty("Include the raw 4-byte stack slot (stack address and word value) per frame (default false)."),
				"context":     contextProperty(),
			}, nil),
			run: runBacktrace,
		},
	}
}

type backtraceArgs struct {
	MaxFrames  uint64 `json:"max_frames"`
	IncludeRaw bool   `json:"include_raw"`
	Context    string `json:"context"`
}

// registerValue reads the first present register from a list of candidate
// names (JSON numbers arrive as float64; other encodings are tolerated).
func registerValue(registers map[string]any, names ...string) (uint64, bool) {
	for _, name := range names {
		raw, ok := registers[name]
		if !ok || raw == nil {
			continue
		}
		switch value := raw.(type) {
		case float64:
			if value >= 0 && value == float64(uint64(value)) {
				return uint64(value), true
			}
		case json.Number:
			if parsed, err := value.Int64(); err == nil && parsed >= 0 {
				return uint64(parsed), true
			}
		case int:
			if value >= 0 {
				return uint64(value), true
			}
		case int64:
			if value >= 0 {
				return uint64(value), true
			}
		case uint64:
			return value, true
		case string:
			if parsed, ok := parseFlexibleNumber(value); ok {
				return parsed, true
			}
		}
	}
	return 0, false
}

// backtraceSymbolIndex resolves addresses against the context symbols that
// belong to the M68K bus, through the 24-bit bus mask (mirroring the
// disassembly annotation rules).
type backtraceSymbolIndex struct {
	byAddress map[uint64]string
	sorted    []symbols.Symbol
}

func buildBacktraceSymbolIndex(context *analysis.Context) *backtraceSymbolIndex {
	index := &backtraceSymbolIndex{byAddress: map[uint64]string{}}
	for _, symbol := range context.Symbols.List("") {
		if symbol.SpaceID != "" && symbol.SpaceID != disasmSpaceID("m68k") {
			continue
		}
		masked := symbol.Address & m68kBusMask
		if _, exists := index.byAddress[masked]; !exists {
			index.byAddress[masked] = symbol.Name
		}
		index.sorted = append(index.sorted, symbols.Symbol{Name: symbol.Name, Address: masked})
	}
	sort.Slice(index.sorted, func(i, j int) bool { return index.sorted[i].Address < index.sorted[j].Address })
	return index
}

// resolve returns the symbol at the exact masked address (offset 0), or the
// nearest symbol at or below the address when the distance is bounded.
func (index *backtraceSymbolIndex) resolve(address uint64) (string, uint64) {
	masked := address & m68kBusMask
	if name, ok := index.byAddress[masked]; ok {
		return name, 0
	}
	lo, hi := 0, len(index.sorted)
	for lo < hi {
		mid := (lo + hi) / 2
		if index.sorted[mid].Address <= masked {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == 0 {
		return "", 0
	}
	best := index.sorted[lo-1]
	offset := masked - best.Address
	if offset > maxBacktraceSymbolOffset {
		return "", 0
	}
	return best.Name, offset
}

// plausibleReturnAddress applies the documented low-cost filter: nonzero,
// even, and inside a 24-bit executable region (ROM window 0x000000-0x3FFFFF
// or work RAM 0xFF0000-0xFFFFFF). It deliberately does not disassemble.
func plausibleReturnAddress(candidate uint64) bool {
	masked := candidate & m68kBusMask
	if masked == 0 || candidate&1 != 0 {
		return false
	}
	return masked < 0x400000 || masked >= 0xFF0000
}

// backtraceConfidence labels how much a candidate return address is trusted:
// ROM-window candidates are typical call-site text and are marked medium;
// RAM-window candidates (RAM-resident code) are rarer and marked low.
func backtraceConfidence(candidate uint64) string {
	if candidate&m68kBusMask < 0x400000 {
		return "medium"
	}
	return "low"
}

// backtraceFrame builds one result frame entry with symbol resolution and the
// optional raw stack slot view.
func backtraceFrame(address, stackAddress uint64, raw []byte, method, confidence, note string, includeRaw bool, index *backtraceSymbolIndex) map[string]any {
	masked := address & m68kBusMask
	frame := map[string]any{
		"address":        masked,
		"address_hex":    canonicalHex(masked),
		"address_space":  disasmSpaceID("m68k"),
		"method":         method,
		"confidence":     confidence,
		"heuristic_note": note,
	}
	if name, offset := index.resolve(masked); name != "" {
		frame["symbol"] = name
		frame["offset"] = offset
	}
	if includeRaw && raw != nil {
		frame["raw"] = map[string]any{
			"stack_address":     stackAddress & m68kBusMask,
			"stack_address_hex": canonicalHex(stackAddress & m68kBusMask),
			"bytes_hex":         strings.ToUpper(hex.EncodeToString(raw)),
			"word":              address, // the 32-bit value read from the slot
			"word_hex":          canonicalHex(address),
		}
	}
	return frame
}

func runBacktrace(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[backtraceArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	maxFrames := parsed.MaxFrames
	if maxFrames == 0 {
		maxFrames = defaultBacktraceFrames
	}
	if maxFrames > maxBacktraceFrames {
		return failureResult(&toolFailure{
			Code:    "invalid_params",
			Message: fmt.Sprintf("max_frames is capped at %d.", maxBacktraceFrames),
		}, tc.modern)
	}
	budget := int(maxFrames)

	payload, failure := tc.server.executeCommand(tc.ctx, "regs_get", map[string]string{"cpu": "m68k"})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	registers, ok := payload["registers"].(map[string]any)
	if !ok {
		// Tolerate a flattened payload shape from older plugin builds.
		registers = payload
	}
	sp, ok := registerValue(registers, "a7", "sp", "usp", "ssp")
	if !ok || sp == 0 {
		return failureResult(&toolFailure{
			Code:    "bridge_error",
			Message: "the m68k register payload provides no usable stack pointer (a7/sp/usp/ssp)",
		}, tc.modern)
	}
	a6, _ := registerValue(registers, "a6", "fp")
	pc, _ := registerValue(registers, "pc")
	sr, _ := registerValue(registers, "sr")
	usp, _ := registerValue(registers, "usp")
	ssp, _ := registerValue(registers, "ssp")

	symbolsIndex := buildBacktraceSymbolIndex(context)

	// readWord reads one big-endian 32-bit slot through the M68K bus and
	// reports whether the plugin had to pause a running system for the read.
	allReadsPaused := true
	readWord := func(address uint64) ([]byte, uint64, bool, *toolFailure) {
		raw, _, _, pausedDuringRead, failure := readBridgeBytes(tc, disasmSpaceID("m68k"), address, 4)
		if failure != nil {
			return nil, 0, false, failure
		}
		if pausedDuringRead {
			// The plugin paused a running system for this read, so the stack
			// slots span multiple emulated moments.
			allReadsPaused = false
		}
		value := uint64(raw[0])<<24 | uint64(raw[1])<<16 | uint64(raw[2])<<8 | uint64(raw[3])
		return raw, value, pausedDuringRead, nil
	}

	// Frame-pointer chain walk: follow the classic 68K linkage where [A6] is
	// the saved A6 of the caller and [A6+4] is the return address. The chain
	// must progress to lower addresses; a non-advancing or null pointer ends
	// the walk.
	fpWalkNote := ""
	fpFrames := []map[string]any{}
	if a6&m68kBusMask == 0 || a6&m68kBusMask == sp&m68kBusMask {
		fpWalkNote = "a6 is zero or equals a7; the frame-pointer walk was skipped."
	} else {
		fp := a6 & m68kBusMask
		for len(fpFrames) < budget {
			_, savedA6, _, failure := readWord(fp)
			if failure != nil {
				fpWalkNote = "frame-pointer walk stopped: " + failure.Code
				break
			}
			rawRA, returnAddress, _, failure := readWord(fp + 4)
			if failure != nil {
				fpWalkNote = "frame-pointer walk stopped: " + failure.Code
				break
			}
			if !plausibleReturnAddress(returnAddress) {
				fpWalkNote = "frame-pointer walk stopped: [A6+4] is not a plausible return address."
				break
			}
			fpFrames = append(fpFrames, backtraceFrame(returnAddress, fp+4, rawRA, "frame_pointer", "medium",
				"Return address recovered from the A6 frame linkage ([A6+4]); trustworthy only when the code builds standard 68K frame pointers.", parsed.IncludeRaw, symbolsIndex))
			nextFP := savedA6 & m68kBusMask
			if nextFP == 0 {
				break
			}
			if nextFP >= fp {
				fpWalkNote = "frame-pointer walk stopped: the saved A6 does not advance the chain (possible missing frame linkage)."
				break
			}
			fp = nextFP
		}
	}

	// Linear stack scan: walk 4-byte slots upward from A7, accepting every
	// slot that looks like a return address. The window and slot counts bound
	// the number of bridge reads.
	scanNote := ""
	scanFrames := []map[string]any{}
	scanStart := sp & m68kBusMask
	scanEnd := scanStart + backtraceScanWindow
	attempts := 0
	for address := scanStart; len(scanFrames) < budget && attempts < backtraceScanSlots && address < scanEnd && address <= m68kBusMask; address += 4 {
		attempts++
		raw, candidate, _, failure := readWord(address)
		if failure != nil {
			scanNote = "stack scan stopped: " + failure.Code
			break
		}
		if !plausibleReturnAddress(candidate) {
			continue
		}
		scanFrames = append(scanFrames, backtraceFrame(candidate, address, raw, "stack_scan", backtraceConfidence(candidate),
			"4-byte stack slot whose value is nonzero, even, and inside a documented executable region (ROM 0x000000-0x3FFFFF or RAM 0xFF0000-0xFFFFFF); the stack may hold data, not return addresses.", parsed.IncludeRaw, symbolsIndex))
	}

	// Merge: the live PC first, then the frame-pointer chain (most reliable),
	// then stack-scan finds not already present, de-duplicated by address and
	// bounded by max_frames.
	frames := []map[string]any{}
	seen := map[uint64]bool{}
	frames = append(frames, backtraceFrame(pc, 0, nil, "register_pc", "high",
		"Current M68K program counter from regs_get; not a stack guess.", false, symbolsIndex))
	seen[pc&m68kBusMask] = true
	addFrame := func(frame map[string]any) {
		if address, ok := frame["address"].(uint64); ok {
			if seen[address] {
				return
			}
			seen[address] = true
		}
		frames = append(frames, frame)
	}
	for _, frame := range fpFrames {
		addFrame(frame)
	}
	for _, frame := range scanFrames {
		addFrame(frame)
	}
	truncated := false
	if len(frames) > budget {
		frames = frames[:budget]
		truncated = true
	}
	if len(frames) >= budget && !truncated {
		// The walk filled the whole budget; more candidates may exist above.
		truncated = true
	}
	for index, frame := range frames {
		frame["index"] = index
	}

	registerSummary := map[string]any{
		"a7": sp,
		"pc": pc,
		"sr": sr,
	}
	if usp != 0 {
		registerSummary["usp"] = usp
	}
	if ssp != 0 {
		registerSummary["ssp"] = ssp
	}
	if a6 != 0 {
		registerSummary["a6"] = a6
	}
	for key, value := range registerSummary {
		if numeric, ok := value.(uint64); ok {
			registerSummary[key+"_hex"] = canonicalHex(numeric & m68kBusMask)
		}
	}

	result := map[string]any{
		"heuristic":           true,
		"note":                "Heuristic, not execution-verified; the stack may contain data, not return addresses. Frame 0 is the live PC; every other frame is a plausible return address recovered from memory.",
		"methodology":         "Frame 0 reads the live PC from regs_get. A linear scan walks 4-byte slots upward from A7 (the active stack pointer, USP or SSP per the SR supervisor bit), accepting nonzero, even values inside the documented executable regions (ROM 0x000000-0x3FFFFF, RAM 0xFF0000-0xFFFFFF). Separately, when A6 is nonzero and differs from A7, the classic frame linkage is followed: [A6] is the saved A6, [A6+4] the return address, walking downward until the chain terminates. Both walks merge de-duplicated by masked address; confidence is high for the live PC, medium for frame-pointer and ROM-window stack-scan frames, low for RAM-window stack-scan frames.",
		"frame_count":         len(frames),
		"truncated":           truncated,
		"frames":              frames,
		"registers":           registerSummary,
		"capture_consistency": captureConsistencyToMap(buildCaptureConsistency(tc.server, map[string]any{}, true, allReadsPaused, nil, nil)),
	}
	if scanNote != "" {
		result["scan_note"] = scanNote
	}
	if fpWalkNote != "" {
		result["frame_pointer_note"] = fpWalkNote
	}
	return okResult(result, tc.modern)
}
