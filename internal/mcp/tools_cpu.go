package mcp

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/StealthC/exodus-mcp/internal/analysis"
	"github.com/StealthC/exodus-mcp/internal/symbols"
)

const (
	defaultDisassemblyCount = 32
	maxDisassemblyCount     = 256
	defaultTraceEntries     = 1000
	maxTraceEntries         = 10000
)

func cpuToolSpecs() []toolSpec {
	return []toolSpec{
		{
			name:        "cpu_trace_capture",
			description: "Capture a bounded M68K or Z80 execution trace into a text artifact. The capture stops the system, routes the processor trace log through a temporary on-disk file (the in-memory ring accessor is unsafe across the extension boundary), and restores the prior run state. The system runs during the window, so the capture mutates the target and advances the target generation. Accepts optional expected_target_generation and control_id.",
			schema: objectSchema(map[string]any{
				"cpu":                        enumProperty("Processor to trace.", []string{"m68k", "z80"}),
				"max_entries":                integerProperty(fmt.Sprintf("Maximum entries (default %d, cap %d).", defaultTraceEntries, maxTraceEntries), 1),
				"timeout_ms":                 integerProperty("Capture window in milliseconds (default 5000, cap 30000).", 100),
				"context":                    stringProperty("Analysis context that will own the trace artifact."),
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
				"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
			}, []string{"cpu"}),
			run: runCpuTraceCapture,
		},
		{
			name:        "m68k_disassemble",
			description: "Disassemble M68K instructions from a start address (default: current PC) via linear sweep. Not execution-verified; bytes are echoed for interpretation. Context symbols are resolved into per-line `symbol` and `targets` annotations.",
			schema: objectSchema(map[string]any{
				"address": addressProperty(),
				"count":   integerProperty(fmt.Sprintf("Instruction count between 1 and %d (default %d).", maxDisassemblyCount, defaultDisassemblyCount), 1),
				"context": contextProperty(),
			}, nil),
			run: makeRunDisassembly("m68k"),
		},
		{
			name:        "m68k_read_memory",
			description: "Read memory through the 68000 bus view. Declared byte order: big-endian. Inline reads are capped at 4096 bytes. Reports the standardized capture_consistency object; optional capture_mode \"paused\" makes the read temporally atomic.",
			schema:      cpuReadMemorySchema(),
			run:         makeRunCpuMemoryRead("m68k-bus"),
		},
		{
			name:        "m68k_registers",
			description: "Return all M68000 registers and decomposed status flags as plain integers (byte order not applicable), with the standardized capture_consistency object (live while running, paused when already stopped).",
			schema:      objectSchema(map[string]any{}, nil),
			run:         makeRunRegisters("m68k"),
		},
		{
			name:        "symbols_clear",
			description: "Remove every symbol from an analysis context.",
			schema: objectSchema(map[string]any{
				"context": contextProperty(),
			}, nil),
			run: runSymbolsClear,
		},
		{
			name:        "symbols_list",
			description: "List symbols in an analysis context ordered by address. An optional case-insensitive prefix filters by name.",
			schema: objectSchema(map[string]any{
				"filter":  stringProperty("Case-insensitive name prefix filter."),
				"context": contextProperty(),
			}, nil),
			run: runSymbolsList,
		},
		{
			name:        "symbols_set",
			description: "Upsert named addresses in an analysis context. Symbols are server-side labels only; emulator state is untouched.",
			schema: objectSchema(map[string]any{
				"symbols": map[string]any{
					"type":        "array",
					"description": "Symbols to upsert.",
					"items": map[string]any{
						"type":                 "object",
						"additionalProperties": false,
						"properties": map[string]any{
							"name":     stringProperty("Symbol label."),
							"space_id": stringProperty("Address space id from memory_spaces_list."),
							"address":  addressProperty(),
						},
						"required": []string{"name", "address"},
					},
				},
				"context": contextProperty(),
			}, []string{"symbols"}),
			run: runSymbolsSet,
		},
		{
			name:        "z80_disassemble",
			description: "Disassemble Z80 instructions from a start address (default: current PC) via linear sweep. Not execution-verified; bytes are echoed for interpretation. Context symbols are resolved into per-line `symbol` and `targets` annotations.",
			schema: objectSchema(map[string]any{
				"address": addressProperty(),
				"count":   integerProperty(fmt.Sprintf("Instruction count between 1 and %d (default %d).", maxDisassemblyCount, defaultDisassemblyCount), 1),
				"context": contextProperty(),
			}, nil),
			run: makeRunDisassembly("z80"),
		},
		{
			name:        "z80_read_memory",
			description: "Read memory through the Z80 bus view. Declared byte order: little-endian. Inline reads are capped at 4096 bytes. Reports the standardized capture_consistency object; optional capture_mode \"paused\" makes the read temporally atomic.",
			schema:      cpuReadMemorySchema(),
			run:         makeRunCpuMemoryRead("z80-bus"),
		},
		{
			name:        "z80_registers",
			description: "Return Z80 register pairs, index registers, interrupt state, and decomposed flags as plain integers (byte order not applicable), with the standardized capture_consistency object (live while running, paused when already stopped).",
			schema:      objectSchema(map[string]any{}, nil),
			run:         makeRunRegisters("z80"),
		},
	}
}

func cpuReadMemorySchema() map[string]any {
	return objectSchema(map[string]any{
		"address":        addressProperty(),
		"length":         integerProperty(fmt.Sprintf("Byte length between 1 and %d.", inlineReadCapBytes), 1),
		"representation": enumProperty("Inline rendering.", []string{"raw_base64", "hexdump", "array_u8"}),
		"decode":         decodeSchemaProperty(),
		"capture_mode":   captureModeProperty(),
		"context":        contextProperty(),
	}, []string{"address", "length"})
}

// ----------------------------------------------------------------------------------------------------------------------
// Registers and disassembly
// ----------------------------------------------------------------------------------------------------------------------
func makeRunRegisters(cpu string) func(toolContext, json.RawMessage) map[string]any {
	return func(tc toolContext, _ json.RawMessage) map[string]any {
		payload, failure := tc.server.executeCommand(tc.ctx, "regs_get", map[string]string{"cpu": cpu})
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		payload["capture_consistency"] = captureConsistencyToMap(buildCaptureConsistency(tc.server, payload, false, true, nil, nil))
		return okResult(payload, tc.modern)
	}
}

type disassemblyArgs struct {
	Address any    `json:"address"`
	Count   uint64 `json:"count"`
	Context string `json:"context"`
}

func makeRunDisassembly(cpu string) func(toolContext, json.RawMessage) map[string]any {
	return func(tc toolContext, args json.RawMessage) map[string]any {
		parsed, failure := decodeArgs[disassemblyArgs](args)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		context, failure := resolveContext(tc.server, parsed.Context)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		count := parsed.Count
		if count == 0 {
			count = defaultDisassemblyCount
		}
		if count > maxDisassemblyCount {
			return failureResult(&toolFailure{
				Code:    "invalid_params",
				Message: fmt.Sprintf("count is capped at %d instructions per call.", maxDisassemblyCount),
			}, tc.modern)
		}
		params := map[string]string{"cpu": cpu, "count": strconv.FormatUint(count, 10)}
		if parsed.Address != nil {
			address, failure := parseAddress(parsed.Address)
			if failure != nil {
				return failureResult(failure, tc.modern)
			}
			params["address"] = strconv.FormatUint(address, 10)
		}
		payload, failure := tc.server.executeCommand(tc.ctx, "disasm", params)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		if annotated, ok := annotateDisassemblySymbols(context, cpu, payload); ok {
			payload = annotated
		} else {
			normalizeDisassemblyPayload(payload, cpu)
		}
		return okResult(payload, tc.modern)
	}
}

func normalizeDisassemblyPayload(payload map[string]any, cpu string) {
	spaceID := disasmSpaceID(cpu)
	mask := disasmSymbolMask(cpu)
	width := 24
	if cpu == "z80" {
		width = 16
	}
	if start, ok := payload["start_address"].(float64); ok {
		payload["start_address_hex"] = canonicalHex(uint64(start))
		payload["address_space"] = spaceID
		payload["address_width_bits"] = width
		payload["address_mask_hex"] = canonicalHex(mask)
	} else if start, ok := payload["start_address"].(int); ok {
		payload["start_address_hex"] = canonicalHex(uint64(start))
		payload["address_space"] = spaceID
		payload["address_width_bits"] = width
		payload["address_mask_hex"] = canonicalHex(mask)
	}
	if lines, ok := payload["lines"].([]any); ok {
		for _, lineEntry := range lines {
			if line, ok := lineEntry.(map[string]any); ok {
				if addr, ok := line["address"].(float64); ok {
					line["address_hex"] = canonicalHex(uint64(addr))
					line["address_space"] = spaceID
				}
			}
		}
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// Symbol-aware disassembly
// ----------------------------------------------------------------------------------------------------------------------

// disasmLine mirrors the plugin's linear-sweep line entry. comment is omitted
// by the plugin when the opcode carries none.
type disasmLine struct {
	Address  uint64 `json:"address"`
	Length   uint64 `json:"length"`
	Bytes    string `json:"bytes"`
	Mnemonic string `json:"mnemonic"`
	Operands string `json:"operands"`
	Comment  string `json:"comment,omitempty"`
}

// symbolTarget records one operand literal that resolved to a context symbol.
type symbolTarget struct {
	Name       string `json:"name"`
	Address    uint64 `json:"address"`
	AddressHex string `json:"address_hex"`
}

// disasmSymbolMask returns the bus mask applied when matching symbols to
// disassembly addresses for the Mega Drive baseline: 24-bit for the 68K bus
// and 16-bit for the Z80 bus. Matching through the mask keeps the annotation
// exact inside the real addressable bus while tolerating wider user-supplied
// addresses (for example 0x00FF0000 vs 0xFF0000).
func disasmSymbolMask(cpu string) uint64 {
	if cpu == "m68k" {
		return 0x00FFFFFF
	}
	return 0x0000FFFF
}

// disasmSpaceID is the address space whose symbols apply to a CPU's
// disassembly. Symbols declared with a differing space id belong to another
// bus and are ignored, matching the memory_spaces_list contract.
func disasmSpaceID(cpu string) string {
	if cpu == "m68k" {
		return "m68k-bus"
	}
	return "z80-bus"
}

// operandHexLiterals extracts address-like literals from a disassembly
// operand string: $-prefixed Motorola hex, 0x-prefixed hex, and Zilog
// h-suffixed hex runs (1-4 digits). Bare digit runs are not matched because
// register names and displacement placeholders such as "d16(An)" or "(HL)"
// are also composed of hex-looking characters.
func operandHexLiterals(operands string) []uint64 {
	literals := make([]uint64, 0, 2)
	for index := 0; index < len(operands); {
		ch := operands[index]
		if ch == '$' || (ch == '0' && index+1 < len(operands) && (operands[index+1] == 'x' || operands[index+1] == 'X')) {
			start := index + 1
			if ch == '0' {
				start = index + 2
			}
			end := start
			for end < len(operands) && isHexDigit(operands[end]) {
				end++
			}
			if end > start {
				if value, ok := parseHexRun(operands[start:end]); ok {
					literals = append(literals, value)
				}
				index = end
				continue
			}
			index++
			continue
		}
		if isHexDigit(ch) {
			start := index
			for index < len(operands) && isHexDigit(operands[index]) {
				index++
			}
			run := operands[start:index]
			if len(run) <= 4 && index < len(operands) && (operands[index] == 'h' || operands[index] == 'H') &&
				(start == 0 || !isHexDigit(operands[start-1])) {
				if value, ok := parseHexRun(run); ok {
					literals = append(literals, value)
				}
				index++ // consume the h suffix
				continue
			}
			continue
		}
		index++
	}
	return literals
}

func isHexDigit(ch byte) bool {
	return ('0' <= ch && ch <= '9') || ('a' <= ch && ch <= 'f') || ('A' <= ch && ch <= 'F')
}

// parseHexRun converts a bare hex digit run to an address.
func parseHexRun(run string) (uint64, bool) {
	value, err := strconv.ParseUint(run, 16, 64)
	return value, err == nil
}

// annotateDisassemblySymbols resolves context symbols against instruction
// addresses and operand literals of a disasm bridge payload. The response
// gains a per-line `symbol` (the line's own address) and `targets` (operand
// literals that resolved), plus top-level `symbols_annotated` and
// `annotation_method` fields. Annotation is best-effort: an unparseable
// payload is passed through unchanged.
func annotateDisassemblySymbols(context *analysis.Context, cpu string, payload map[string]any) (map[string]any, bool) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return payload, false
	}
	var decoded struct {
		CPU               string       `json:"cpu"`
		StartAddress      uint64       `json:"start_address"`
		RequestedCount    uint64       `json:"requested_count"`
		DisassemblyMethod string       `json:"disassembly_method"`
		Lines             []disasmLine `json:"lines"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil || decoded.Lines == nil {
		return payload, false
	}
	mask := disasmSymbolMask(cpu)
	spaceID := disasmSpaceID(cpu)
	byAddress := make(map[uint64]string)
	for _, symbol := range context.Symbols.List("") {
		if symbol.SpaceID != "" && symbol.SpaceID != spaceID {
			continue
		}
		address := symbol.Address & mask
		if _, exists := byAddress[address]; !exists {
			byAddress[address] = symbol.Name
		}
	}
	if len(byAddress) == 0 {
		return payload, false
	}

	annotated := make([]map[string]any, 0, len(decoded.Lines))
	applied := false
	for _, line := range decoded.Lines {
		entry := map[string]any{
			"address":       line.Address,
			"address_hex":   canonicalHex(line.Address),
			"address_space": spaceID,
			"length":        line.Length,
			"bytes":         line.Bytes,
			"mnemonic":      line.Mnemonic,
			"operands":      line.Operands,
		}
		if line.Comment != "" {
			entry["comment"] = line.Comment
		}
		if name, exists := byAddress[line.Address&mask]; exists {
			entry["symbol"] = name
			applied = true
		}
		var targets []symbolTarget
		for _, literal := range operandHexLiterals(line.Operands) {
			masked := literal & mask
			if name, exists := byAddress[masked]; exists {
				targets = append(targets, symbolTarget{Name: name, Address: masked, AddressHex: canonicalHex(masked)})
			}
		}
		if len(targets) > 0 {
			entry["targets"] = targets
			applied = true
		}
		annotated = append(annotated, entry)
	}

	bitWidth := 24
	if cpu == "z80" {
		bitWidth = 16
	}
	payload["cpu"] = decoded.CPU
	payload["start_address"] = decoded.StartAddress
	payload["start_address_hex"] = canonicalHex(decoded.StartAddress)
	payload["address_space"] = spaceID
	payload["address_width_bits"] = bitWidth
	payload["address_mask_hex"] = canonicalHex(mask)
	payload["requested_count"] = decoded.RequestedCount
	payload["disassembly_method"] = decoded.DisassemblyMethod
	payload["symbols_annotated"] = applied
	payload["annotation_method"] = fmt.Sprintf("context symbols resolved against instruction addresses and operand literals, %d-bit bus mask", bitWidth)
	payload["lines"] = annotated
	return payload, true
}

// ----------------------------------------------------------------------------------------------------------------------
// CPU-pinned memory reads
// ----------------------------------------------------------------------------------------------------------------------
func makeRunCpuMemoryRead(spaceID string) func(toolContext, json.RawMessage) map[string]any {
	return func(tc toolContext, args json.RawMessage) map[string]any {
		parsed, failure := decodeArgs[memoryReadArgs](args)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		if _, failure = resolveContext(tc.server, parsed.Context); failure != nil {
			return failureResult(failure, tc.modern)
		}
		guard := captureGuard{Mode: parsed.CaptureMode}
		if failure = guard.resolve(); failure != nil {
			return failureResult(failure, tc.modern)
		}
		address, failure := parseAddress(parsed.Address)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		return readMemory(tc, spaceID, address, parsed.Length, parsed.Representation, parsed.Decode, guard)
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// Trace capture
// ----------------------------------------------------------------------------------------------------------------------
type traceCaptureArgs struct {
	CPU        string `json:"cpu"`
	MaxEntries uint64 `json:"max_entries"`
	TimeoutMs  uint64 `json:"timeout_ms"`
	Context    string `json:"context"`
	guardArgs
}

func runCpuTraceCapture(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[traceCaptureArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
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
		"cpu":         parsed.CPU,
		"max_entries": strconv.FormatUint(maxEntries, 10),
		"timeout_ms":  strconv.FormatUint(timeoutMs, 10),
	}
	payload, before, after, failure := tc.server.executeMutation(tc.ctx, mutationCall{
		tool:      "cpu_trace_capture",
		operation: "trace_capture",
		params:    params,
		guard:     parsed.guard(),
		contextID: context.ID,
		detail: map[string]any{
			"cpu":         parsed.CPU,
			"max_entries": maxEntries,
			"timeout_ms":  timeoutMs,
		},
	})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}

	summary, artifactDesc, failure := traceArtifactFromPayload(tc, context, payload)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	result := map[string]any{
		"summary":  summary,
		"artifact": artifactDesc,
	}
	return okResult(stampGenerations(result, before, after), tc.modern)
}

// ----------------------------------------------------------------------------------------------------------------------
// Symbols
// ----------------------------------------------------------------------------------------------------------------------
type symbolInput struct {
	Name    string `json:"name"`
	SpaceID string `json:"space_id"`
	Address any    `json:"address"`
}

type symbolsSetArgs struct {
	Symbols []symbolInput `json:"symbols"`
	Context string        `json:"context"`
}

func runSymbolsSet(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[symbolsSetArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	prepared := make([]storedSymbolInput, 0, len(parsed.Symbols))
	for index, symbol := range parsed.Symbols {
		address, failure := parseAddress(symbol.Address)
		if failure != nil {
			return failureResult(&toolFailure{
				Code:    "invalid_params",
				Message: fmt.Sprintf("symbols[%d].address: %s", index, failure.Message),
			}, tc.modern)
		}
		prepared = append(prepared, storedSymbolInput{Name: symbol.Name, SpaceID: symbol.SpaceID, Address: address})
	}
	written, err := context.Symbols.Set(toStoreSymbols(prepared))
	if err != nil {
		return failureResult(&toolFailure{Code: "invalid_params", Message: err.Error()}, tc.modern)
	}
	return okResult(map[string]any{"upserted": written}, tc.modern)
}

type storedSymbolInput struct {
	Name    string
	SpaceID string
	Address uint64
}

func toStoreSymbols(inputs []storedSymbolInput) []symbols.Symbol {
	prepared := make([]symbols.Symbol, 0, len(inputs))
	for _, input := range inputs {
		prepared = append(prepared, symbols.Symbol{Name: input.Name, SpaceID: input.SpaceID, Address: input.Address})
	}
	return prepared
}

func runSymbolsList(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[struct {
		Filter  string `json:"filter"`
		Context string `json:"context"`
	}](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	symbols := context.Symbols.List(parsed.Filter)
	views := make([]map[string]any, 0, len(symbols))
	for _, symbol := range symbols {
		view := map[string]any{
			"name":         symbol.Name,
			"space_id":     symbol.SpaceID,
			"address":      symbol.Address,
			"address_hex":  canonicalHex(symbol.Address),
			"address_space": symbol.SpaceID,
		}
		if width, mask := addressBusWidthMask(symbol.SpaceID); width != 0 {
			view["address_width_bits"] = width
			view["address_mask_hex"] = canonicalHex(mask)
		}
		views = append(views, view)
	}
	return okResult(map[string]any{"symbols": views, "count": len(views)}, tc.modern)
}

func runSymbolsClear(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[struct {
		Context string `json:"context"`
	}](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	removed := context.Symbols.Clear()
	return okResult(map[string]any{"removed": removed}, tc.modern)
}
