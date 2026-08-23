package mcp

import (
	"encoding/json"
	"fmt"
	"strconv"

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
			description: "Capture a bounded M68K or Z80 execution trace into a text artifact. WARNING: enabling tracing against a running system currently crashes the emulator in some conditions (see docs/TRACE-CRASH-INVESTIGATION.md). Treat as experimental; entries accumulate only while the system is running.",
			schema: objectSchema(map[string]any{
				"cpu":         enumProperty("Processor to trace.", []string{"m68k", "z80"}),
				"max_entries": integerProperty(fmt.Sprintf("Maximum entries (default %d, cap %d).", defaultTraceEntries, maxTraceEntries), 1),
				"timeout_ms":  integerProperty("Capture window in milliseconds (default 5000, cap 30000).", 100),
				"context":     stringProperty("Analysis context that will own the trace artifact."),
			}, []string{"cpu"}),
			run: runCpuTraceCapture,
		},
		{
			name:        "m68k_disassemble",
			description: "Disassemble M68K instructions from a start address (default: current PC) via linear sweep. Not execution-verified; bytes are echoed for interpretation.",
			schema: objectSchema(map[string]any{
				"address": addressProperty(),
				"count":   integerProperty(fmt.Sprintf("Instruction count between 1 and %d (default %d).", maxDisassemblyCount, defaultDisassemblyCount), 1),
				"context": contextProperty(),
			}, nil),
			run: makeRunDisassembly("m68k"),
		},
		{
			name:        "m68k_read_memory",
			description: "Read memory through the 68000 bus view. Declared byte order: big-endian. Inline reads are capped at 4096 bytes.",
			schema:      cpuReadMemorySchema(),
			run:         makeRunCpuMemoryRead("m68k-bus"),
		},
		{
			name:        "m68k_registers",
			description: "Return all M68000 registers and decomposed status flags as plain integers (byte order not applicable).",
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
						"type": "object",
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
			description: "Disassemble Z80 instructions from a start address (default: current PC) via linear sweep. Not execution-verified; bytes are echoed for interpretation.",
			schema: objectSchema(map[string]any{
				"address": addressProperty(),
				"count":   integerProperty(fmt.Sprintf("Instruction count between 1 and %d (default %d).", maxDisassemblyCount, defaultDisassemblyCount), 1),
				"context": contextProperty(),
			}, nil),
			run: makeRunDisassembly("z80"),
		},
		{
			name:        "z80_read_memory",
			description: "Read memory through the Z80 bus view. Declared byte order: little-endian. Inline reads are capped at 4096 bytes.",
			schema:      cpuReadMemorySchema(),
			run:         makeRunCpuMemoryRead("z80-bus"),
		},
		{
			name:        "z80_registers",
			description: "Return Z80 register pairs, index registers, interrupt state, and decomposed flags as plain integers (byte order not applicable).",
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
		if _, failure = resolveContext(tc.server, parsed.Context); failure != nil {
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
		return okResult(payload, tc.modern)
	}
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
		address, failure := parseAddress(parsed.Address)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		return readMemory(tc, spaceID, address, parsed.Length, parsed.Representation, parsed.Decode)
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
	payload, failure := tc.server.executeCommand(tc.ctx, "trace_capture", params)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}

	traceText, _ := payload["trace_text"].(string)
	stored, err := tc.server.store.Put(context.ID, "cpu-trace", "text/plain; charset=utf-8", []byte(traceText))
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}
	delete(payload, "trace_text")
	captured, _ := payload["captured"].(float64)
	timedOut, _ := payload["timed_out"].(bool)
	cpu, _ := payload["cpu"].(string)
	sample, _ := payload["sample"].([]any)

	return okResult(map[string]any{
		"summary": map[string]any{
			"kind":          "cpu-trace",
			"cpu":           cpu,
			"captured":      int(captured),
			"timed_out":     timedOut,
			"sampling_note": "Sampling follows live emulation only; a paused system yields few or no entries.",
			"sample":        sample,
			"sha256":        stored.SHA256,
		},
		"artifact": artifactDescriptor(tc.server, stored, context.ID),
	}, tc.modern)
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
		views = append(views, map[string]any{
			"name":        symbol.Name,
			"space_id":    symbol.SpaceID,
			"address":     symbol.Address,
			"address_hex": fmt.Sprintf("0x%X", symbol.Address),
		})
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
