package mcp

import (
	"context"
	"encoding/json"
	"testing"
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
