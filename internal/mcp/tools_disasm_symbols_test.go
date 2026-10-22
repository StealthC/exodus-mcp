package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/StealthC/exodus-mcp/internal/symbols"
)

// TestDisassemblySymbolAnnotationM68K verifies that context symbols resolve
// against instruction addresses and $-prefixed operand literals on the 68K
// side, that symbols declared for another bus never annotate, and that
// displacement placeholders and decimal immediates never match.
func TestDisassemblySymbolAnnotationM68K(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		if method != "disasm" {
			t.Fatalf("unexpected call %s", method)
		}
		payload := `{"cpu":"m68k","start_address":8292,"requested_count":4,"disassembly_method":"linear sweep from the start address; not execution-verified","lines":[` +
			`{"address":8292,"length":2,"bytes":"60 FA","mnemonic":"bra.s","operands":"$205A"},` +
			`{"address":8294,"length":10,"bytes":"4EF9 00FF 0000","mnemonic":"jmp","operands":"($FF0000).l"},` +
			`{"address":8304,"length":4,"bytes":"207C FFFF FFF0","mnemonic":"movea.l","operands":"#$FFFFFFF0,A0"},` +
			`{"address":8308,"length":4,"bytes":"0C80 0000 2064","mnemonic":"cmpi.l","operands":"#$2064,D0"}]}`
		return json.RawMessage(payload), nil
	}

	server := newTestServer(t, client)
	// other_space shares line 2's address (8304) but belongs to the Z80 bus:
	// space filtering must keep it from annotating the 68K output.
	setResult := postToolCall(t, server, "symbols_set", `{"symbols":[{"name":"main","space_id":"m68k-bus","address":"0x2064"},{"name":"lives","space_id":"m68k-bus","address":16711680},{"name":"other_space","space_id":"z80-bus","address":8304}]}`)
	if structured(setResult)["upserted"] != float64(3) {
		t.Fatalf("symbol upsert failed: %v", setResult)
	}

	result := structured(postToolCall(t, server, "m68k_disassemble", `{"count":4}`))
	if result["symbols_annotated"] != true {
		t.Fatalf("symbols_annotated must be true: %v", result)
	}
	lines := result["lines"].([]any)

	// Instruction address 0x2064 resolves to main; the $205A branch target
	// has no symbol, so no targets appear.
	first := lines[0].(map[string]any)
	if first["symbol"] != "main" {
		t.Fatalf("line 0 address symbol = %v, want main", first["symbol"])
	}
	if first["targets"] != nil {
		t.Fatalf("line 0 must not resolve targets: %v", first["targets"])
	}

	// Operand ($FF0000).l resolves to lives through the 24-bit bus mask.
	jump := lines[1].(map[string]any)
	gt := jump["targets"].([]any)
	if len(gt) != 1 || gt[0].(map[string]any)["name"] != "lives" {
		t.Fatalf("jump target = %v, want lives", gt)
	}

	// The $FFFFFFF0 immediate masks to FFFFF0 (no symbol), and the line's own
	// address belongs to the Z80-bus symbol other_space which must not apply.
	movea := lines[2].(map[string]any)
	if movea["symbol"] != nil {
		t.Fatalf("cross-bus symbol must not annotate: %v", movea["symbol"])
	}
	if movea["targets"] != nil {
		t.Fatalf("movea must not resolve targets: %v", movea["targets"])
	}

	// The $2064 immediate resolves to main.
	cmp := lines[3].(map[string]any)
	ct := cmp["targets"].([]any)
	if len(ct) != 1 || ct[0].(map[string]any)["name"] != "main" {
		t.Fatalf("cmpi operand target = %v, want main", ct)
	}
}

// TestDisassemblySymbolAnnotationZ80 covers h-suffixed Zilog hex and the
// 16-bit bus mask, and confirms missing operand literals stay unannotated.
func TestDisassemblySymbolAnnotationZ80(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		if method != "disasm" {
			t.Fatalf("unexpected call %s", method)
		}
		payload := `{"cpu":"z80","start_address":4096,"requested_count":2,"disassembly_method":"linear sweep from the start address; not execution-verified","lines":[` +
			`{"address":4096,"length":3,"bytes":"C3 34 12","mnemonic":"jp","operands":"1234h"},` +
			`{"address":4099,"length":2,"bytes":"21 45 23","mnemonic":"ld","operands":"hl,$2345"},` +
			`{"address":4101,"length":1,"bytes":"3E 01","mnemonic":"ld","operands":"a,01h"}]}`
		return json.RawMessage(payload), nil
	}

	server := newTestServer(t, client)
	setResult := postToolCall(t, server, "symbols_set", `{"symbols":[{"name":"sound","address":"0x1234"},{"name":"table","space_id":"z80-bus","address":"0x12345"}]}`)
	if structured(setResult)["upserted"] != float64(2) {
		t.Fatalf("symbol upsert failed: %v", setResult)
	}

	result := structured(postToolCall(t, server, "z80_disassemble", `{"count":3}`))
	lines := result["lines"].([]any)

	// Zilog h-suffix operand 1234h matches the exact symbol sound.
	jp := lines[0].(map[string]any)
	jpTargets := jp["targets"].([]any)
	if len(jpTargets) != 1 || jpTargets[0].(map[string]any)["name"] != "sound" {
		t.Fatalf("jp target = %v, want sound", jpTargets)
	}

	// 0x12345 falls outside the 16-bit Z80 bus; the masked address 0x2345
	// matches the $2345 operand, and the `01h` immediate matches nothing.
	ld := lines[1].(map[string]any)
	ldTargets := ld["targets"].([]any)
	if len(ldTargets) != 1 || ldTargets[0].(map[string]any)["name"] != "table" {
		t.Fatalf("ld target = %v, want table (masked)", ldTargets)
	}
	if lines[2].(map[string]any)["targets"] != nil {
		t.Fatalf("a,01h must not resolve a target: %v", lines[2])
	}
}

// TestDisassemblyWithoutSymbolsPassesThrough verifies that a context without
// symbols leaves the bridge payload untouched: no annotation fields, no
// reordering, no dropped lines.
func TestDisassemblyWithoutSymbolsPassesThrough(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		if method != "disasm" {
			t.Fatalf("unexpected call %s", method)
		}
		payload := `{"cpu":"m68k","start_address":512,"requested_count":1,"disassembly_method":"linear sweep from the start address; not execution-verified","lines":[{"address":512,"length":2,"bytes":"4E71","mnemonic":"nop","operands":""}]}`
		return json.RawMessage(payload), nil
	}
	result := structured(callTool(t, client, "m68k_disassemble", `{"count":1}`))
	if result["symbols_annotated"] != nil {
		t.Fatalf("no symbols must not add symbols_annotated: %v", result)
	}
	lines := result["lines"].([]any)
	if len(lines) != 1 || lines[0].(map[string]any)["mnemonic"] != "nop" {
		t.Fatalf("passthrough lost fields: %v", result)
	}
}

func TestDisassemblySymbolAnnotationNotAppliedWithoutContextSymbolsForSpace(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		payload := `{"cpu":"m68k","start_address":512,"requested_count":1,"disassembly_method":"linear sweep from the start address; not execution-verified","lines":[{"address":512,"length":2,"bytes":"4E71","mnemonic":"nop","operands":""}]}`
		return json.RawMessage(payload), nil
	}
	server := newTestServer(t, client)
	postToolCall(t, server, "symbols_set", `{"symbols":[{"name":"zonly","space_id":"z80-bus","address":512}]}`)
	result := structured(postToolCall(t, server, "m68k_disassemble", `{"count":1}`))
	if result["symbols_annotated"] != nil {
		t.Fatalf("z80-bus symbols must not annotate m68k disassembly: %v", result)
	}
}

func TestOperandHexLiteralExtraction(t *testing.T) {
	for input, want := range map[string][]uint64{
		"$FF0000":       {0xFF0000},
		"($FF0000).l":   {0xFF0000},
		"#$FFFFFFF0,A0": {0xFFFFFFF0},
		"1234h":         {0x1234},
		"0x1234":        {0x1234},
		"a,01h":         {0x01},
		"d16(A0),D1":    nil, // displacement placeholder, not a literal
		"(HL)":          nil,
		"(IX+d)":        nil,
		"#-2":           nil, // decimal immediate
		"":              nil,
	} {
		got := operandHexLiterals(input)
		if len(got) != len(want) {
			t.Fatalf("hexLiterals(%q) = %v, want %v", input, got, want)
		}
		for index := range want {
			if got[index] != want[index] {
				t.Fatalf("hexLiterals(%q) = %v, want %v", input, got, want)
			}
		}
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// Space-relative symbols (issue #13): a symbol stored with a space id from
// memory_spaces_list must annotate at its resolved processor-bus address, and
// symbols_set must echo both coordinates.
// ----------------------------------------------------------------------------------------------------------------------

// disasmFixture builds a linear-sweep disasm payload whose lines sit at the
// given addresses, so a test controls exactly which addresses annotation sees.
func disasmFixture(cpu string, start uint64, addresses ...uint64) string {
	lines := make([]string, 0, len(addresses))
	for _, address := range addresses {
		lines = append(lines, fmt.Sprintf(`{"address":%d,"length":2,"bytes":"4E71","mnemonic":"nop","operands":""}`, address))
	}
	return fmt.Sprintf(`{"cpu":%q,"start_address":%d,"requested_count":%d,"disassembly_method":"linear sweep from the start address; not execution-verified","lines":[%s]}`,
		cpu, start, len(addresses), strings.Join(lines, ","))
}

// ramSymbolServer builds a server whose bridge disassembles a fixed M68K window
// and which already holds one symbol, inserted through the tool or the store.
func ramSymbolServer(t *testing.T, busAddress uint64, insert func(server *Server)) *Server {
	t.Helper()
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		if method != "disasm" {
			t.Fatalf("unexpected bridge call %s", method)
		}
		return json.RawMessage(disasmFixture("m68k", busAddress, busAddress, busAddress+2)), nil
	}
	server := newTestServer(t, client)
	insert(server)
	return server
}

// TestDisassemblyRAMSymbolAnnotatesAtBusAddress is the issue #13 acceptance
// case: symbols_set with space_id mem-ram and a space-relative address must
// annotate m68k_disassemble at the bus address, and the echo must report both
// coordinates so the caller can see where the symbol actually landed.
func TestDisassemblyRAMSymbolAnnotatesAtBusAddress(t *testing.T) {
	const busAddress = 0xFF1000
	server := ramSymbolServer(t, busAddress, func(server *Server) {
		setResult := structured(postToolCall(t, server, "symbols_set", `{"symbols":[{"name":"score","space_id":"mem-ram","address":"0x1000"}]}`))
		if setResult["upserted"] != float64(1) {
			t.Fatalf("symbol upsert failed: %v", setResult)
		}
		stored, ok := setResult["symbols"].([]any)[0].(map[string]any)
		if !ok {
			t.Fatalf("symbols_set must echo the stored symbols: %v", setResult)
		}
		if stored["space_id"] != "mem-ram" || stored["address"] != float64(0x1000) || stored["space_address"] != float64(0x1000) {
			t.Fatalf("space coordinate missing from the echo: %v", stored)
		}
		if stored["bus_space_id"] != "m68k-bus" || stored["bus_address"] != float64(busAddress) || stored["bus_address_hex"] != "0xFF1000" {
			t.Fatalf("bus coordinate missing from the echo: %v", stored)
		}
	})

	// Round trip: disassembling the address the echo reported must annotate.
	setResult := structured(postToolCall(t, server, "symbols_set", `{"symbols":[{"name":"score","space_id":"mem-ram","address":"0x1000"}]}`))
	stored := setResult["symbols"].([]any)[0].(map[string]any)
	reported := uint64(stored["bus_address"].(float64))
	arguments := fmt.Sprintf(`{"address":%d,"count":2}`, reported)
	result := structured(postToolCall(t, server, "m68k_disassemble", arguments))
	if result["symbols_annotated"] != true {
		t.Fatalf("RAM symbol did not annotate: %v", result)
	}
	if result["start_address"] != float64(busAddress) {
		t.Fatalf("disassembly start = %v, want the reported bus address %#x", result["start_address"], busAddress)
	}
	lines := result["lines"].([]any)
	first := lines[0].(map[string]any)
	if first["symbol"] != "score" || first["address"] != float64(busAddress) {
		t.Fatalf("line 0 = %v, want the score symbol at the bus address", first)
	}
	if second := lines[1].(map[string]any); second["symbol"] != nil {
		t.Fatalf("line 1 must stay unannotated: %v", second)
	}
}

// TestDisassemblyBusSymbolBackwardCompatible keeps the historical contract: a
// symbol stored with space_id m68k-bus and a bus address still annotates, and
// its two coordinates coincide.
func TestDisassemblyBusSymbolBackwardCompatible(t *testing.T) {
	const busAddress = 0x2064
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		if method != "disasm" {
			t.Fatalf("unexpected bridge call %s", method)
		}
		return json.RawMessage(disasmFixture("m68k", busAddress, busAddress)), nil
	}
	server := newTestServer(t, client)
	setResult := structured(postToolCall(t, server, "symbols_set", `{"symbols":[{"name":"main","space_id":"m68k-bus","address":"0x2064"}]}`))
	stored := setResult["symbols"].([]any)[0].(map[string]any)
	if stored["space_id"] != "m68k-bus" || stored["bus_space_id"] != "m68k-bus" ||
		stored["address"] != float64(busAddress) || stored["bus_address"] != float64(busAddress) {
		t.Fatalf("bus symbol coordinates wrong: %v", stored)
	}

	// No explicit address: the bridge default PC is used, as before.
	result := structured(postToolCall(t, server, "m68k_disassemble", `{"count":1}`))
	if result["symbols_annotated"] != true {
		t.Fatalf("bus symbol did not annotate: %v", result)
	}
	if lines := result["lines"].([]any); lines[0].(map[string]any)["symbol"] != "main" {
		t.Fatalf("line 0 = %v, want main", lines[0])
	}
}

// TestLegacyStoredSpaceSymbolResolvesThroughBusMapping covers symbols written
// before the store kept a bus coordinate: they carry only space_id/address.
// Annotation must derive the bus coordinate from the documented space mapping
// instead of ignoring them.
func TestLegacyStoredSpaceSymbolResolvesThroughBusMapping(t *testing.T) {
	const busAddress = 0xFF1000
	server := ramSymbolServer(t, busAddress, func(server *Server) {
		context, err := server.contexts.Resolve("")
		if err != nil {
			t.Fatalf("resolve default context: %v", err)
		}
		if _, err := context.Symbols.Set([]symbols.Symbol{{Name: "legacy_ram", SpaceID: "mem-ram", Address: 0x1000}}); err != nil {
			t.Fatalf("seed legacy symbol: %v", err)
		}
	})
	result := structured(postToolCall(t, server, "m68k_disassemble", `{"count":1}`))
	lines := result["lines"].([]any)
	if lines[0].(map[string]any)["symbol"] != "legacy_ram" {
		t.Fatalf("legacy space symbol did not annotate at its bus address: %v", lines[0])
	}
}

// TestZ80RAMWindowSymbolAnnotatesM68KDisassembly covers a space whose bus base
// is neither zero nor the M68K RAM base: Z80 RAM is visible to the 68000 at
// 0xA00000, which is where the symbol must annotate.
func TestZ80RAMWindowSymbolAnnotatesM68KDisassembly(t *testing.T) {
	const busAddress = 0xA01000
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		return json.RawMessage(disasmFixture("m68k", busAddress, busAddress)), nil
	}
	server := newTestServer(t, client)
	setResult := structured(postToolCall(t, server, "symbols_set", `{"symbols":[{"name":"z80_marker","space_id":"mem-z80-ram","address":"0x1000"}]}`))
	stored := setResult["symbols"].([]any)[0].(map[string]any)
	if stored["bus_space_id"] != "m68k-bus" || stored["bus_address"] != float64(busAddress) {
		t.Fatalf("mem-z80-ram must resolve into the 68K window at 0xA00000: %v", stored)
	}
	result := structured(postToolCall(t, server, "m68k_disassemble", `{"count":1}`))
	if lines := result["lines"].([]any); lines[0].(map[string]any)["symbol"] != "z80_marker" {
		t.Fatalf("mem-z80-ram symbol did not annotate: %v", lines[0])
	}
}

// TestZ80BusSymbolAnnotatesZ80Disassembly covers the Z80 side. There is no Z80
// backtrace tool (m68k_backtrace walks the 68000 stack), so z80_disassemble is
// the annotation surface to prove.
func TestZ80BusSymbolAnnotatesZ80Disassembly(t *testing.T) {
	const busAddress = 0x1234
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		if method != "disasm" {
			t.Fatalf("unexpected bridge call %s", method)
		}
		return json.RawMessage(disasmFixture("z80", busAddress, busAddress)), nil
	}
	server := newTestServer(t, client)
	setResult := structured(postToolCall(t, server, "symbols_set", `{"symbols":[{"name":"sound_init","space_id":"z80-bus","address":"0x1234"}]}`))
	stored := setResult["symbols"].([]any)[0].(map[string]any)
	if stored["bus_space_id"] != "z80-bus" || stored["bus_address"] != float64(busAddress) {
		t.Fatalf("z80-bus symbol coordinate wrong: %v", stored)
	}
	if stored["address_width_bits"] != float64(16) || stored["address_mask_hex"] != "0x00FFFF" {
		t.Fatalf("z80-bus symbol must report 16-bit width: %v", stored)
	}
	result := structured(postToolCall(t, server, "z80_disassemble", `{"count":1}`))
	if result["symbols_annotated"] != true {
		t.Fatalf("z80-bus symbol did not annotate: %v", result)
	}
	if lines := result["lines"].([]any); lines[0].(map[string]any)["symbol"] != "sound_init" {
		t.Fatalf("line 0 = %v, want sound_init", lines[0])
	}
}

// TestSymbolAddressSpaceAloneTranslatesToBus covers the second half of the
// reported bug: address_space without space_id used to be resolved against
// itself and stored as an untyped symbol.
func TestSymbolAddressSpaceAloneTranslatesToBus(t *testing.T) {
	const busAddress = 0xFF1000
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		return json.RawMessage(disasmFixture("m68k", busAddress, busAddress)), nil
	}
	server := newTestServer(t, client)
	setResult := structured(postToolCall(t, server, "symbols_set", `{"symbols":[{"name":"arena","address_space":"mem-ram","address":4096}]}`))
	stored := setResult["symbols"].([]any)[0].(map[string]any)
	if stored["untyped"] != false || stored["space_id"] != "mem-ram" || stored["bus_address"] != float64(busAddress) {
		t.Fatalf("address_space alone must produce a typed, translated symbol: %v", stored)
	}
	result := structured(postToolCall(t, server, "m68k_disassemble", `{"count":1}`))
	if lines := result["lines"].([]any); lines[0].(map[string]any)["symbol"] != "arena" {
		t.Fatalf("address_space symbol did not annotate: %v", lines[0])
	}
}

// TestSymbolAddressSpaceInBusDomainKeepsSuppliedSpace covers the mixed form:
// the address is written in bus units while the symbol belongs to a space, so
// both coordinates are translated from the bus-domain input.
func TestSymbolAddressSpaceInBusDomainKeepsSuppliedSpace(t *testing.T) {
	const busAddress = 0xFF1000
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		return json.RawMessage(disasmFixture("m68k", busAddress, busAddress)), nil
	}
	server := newTestServer(t, client)
	setResult := structured(postToolCall(t, server, "symbols_set",
		`{"symbols":[{"name":"counter","space_id":"mem-ram","address_space":"m68k-bus","address":"0xFF1000"}]}`))
	stored := setResult["symbols"].([]any)[0].(map[string]any)
	if stored["space_id"] != "mem-ram" || stored["space_address"] != float64(0x1000) {
		t.Fatalf("space coordinate must be translated into mem-ram: %v", stored)
	}
	if stored["bus_space_id"] != "m68k-bus" || stored["bus_address"] != float64(busAddress) {
		t.Fatalf("bus coordinate wrong: %v", stored)
	}
	result := structured(postToolCall(t, server, "m68k_disassemble", `{"count":1}`))
	if lines := result["lines"].([]any); lines[0].(map[string]any)["symbol"] != "counter" {
		t.Fatalf("bus-domain symbol did not annotate: %v", lines[0])
	}
}

// TestSymbolsSetRejectsUnmappedSpaces requires unknown and non-bus spaces to
// fail with invalid_params instead of being stored inert.
func TestSymbolsSetRejectsUnmappedSpaces(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	for _, testCase := range []struct {
		arguments string
		want      string
	}{
		{`{"symbols":[{"name":"typo","space_id":"mem-raam","address":4096}]}`, "unknown address space"},
		{`{"symbols":[{"name":"vram","space_id":"mem-vdp-vram","address":0}]}`, "no CPU-bus coordinate"},
		{`{"symbols":[{"name":"mixed","space_id":"mem-ram","address_space":"z80-bus","address":4096}]}`, "incompatible"},
	} {
		result := postToolCall(t, server, "symbols_set", testCase.arguments)
		content := structured(result)
		if result["isError"] != true || content["code"] != "invalid_params" {
			t.Fatalf("%s must fail with invalid_params: %v", testCase.arguments, result)
		}
		message, _ := content["message"].(string)
		if !strings.Contains(message, testCase.want) {
			t.Fatalf("message %q does not explain the rejection (%q)", message, testCase.want)
		}
	}
	// Nothing was stored by the rejected calls.
	listContent := structured(postToolCall(t, server, "symbols_list", `{}`))
	if listContent["count"] != float64(0) {
		t.Fatalf("rejected symbols must not be stored: %v", listContent)
	}
}

// TestSymbolsListReportsBothCoordinates keeps list and set consistent.
func TestSymbolsListReportsBothCoordinates(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	postToolCall(t, server, "symbols_set", `{"symbols":[{"name":"score","space_id":"mem-ram","address":"0x1000"}]}`)
	content := structured(postToolCall(t, server, "symbols_list", `{}`))
	first := content["symbols"].([]any)[0].(map[string]any)
	if first["space_id"] != "mem-ram" || first["address"] != float64(0x1000) || first["space_address"] != float64(0x1000) {
		t.Fatalf("symbols_list space coordinate wrong: %v", first)
	}
	if first["bus_space_id"] != "m68k-bus" || first["bus_address"] != float64(0xFF1000) {
		t.Fatalf("symbols_list bus coordinate wrong: %v", first)
	}
}

// TestZ80RAMSymbolAnnotatesZ80Disassembly covers the Z80's own RAM space
// (z80-ram is a 0-based view of the Z80 bus) so RAM symbols are proven on both
// processors, not only through the 68K window.
func TestZ80RAMSymbolAnnotatesZ80Disassembly(t *testing.T) {
	const busAddress = 0x1A00
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		if method != "disasm" {
			t.Fatalf("unexpected bridge call %s", method)
		}
		return json.RawMessage(disasmFixture("z80", busAddress, busAddress)), nil
	}
	server := newTestServer(t, client)
	setResult := structured(postToolCall(t, server, "symbols_set", `{"symbols":[{"name":"z80_var","space_id":"z80-ram","address":"0x1A00"}]}`))
	stored := setResult["symbols"].([]any)[0].(map[string]any)
	if stored["bus_space_id"] != "z80-bus" || stored["bus_address"] != float64(busAddress) {
		t.Fatalf("z80-ram must resolve onto the Z80 bus: %v", stored)
	}
	result := structured(postToolCall(t, server, "z80_disassemble", `{"count":1}`))
	if lines := result["lines"].([]any); lines[0].(map[string]any)["symbol"] != "z80_var" {
		t.Fatalf("z80-ram symbol did not annotate: %v", lines[0])
	}
}
