package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
)

// ----------------------------------------------------------------------------------------------------------------------
// Analysis workflows (roadmap issue #18): z80_backtrace, input_status, batched
// disassembly, and instruction-aware coverage decoding.
// ----------------------------------------------------------------------------------------------------------------------

func TestZ80BacktraceWalksTheStack(t *testing.T) {
	// SP points at 0xFF00; two plausible return addresses sit above it, decoded
	// little-endian from the z80-bus read.
	stack := map[uint64][]byte{
		0xFF00: {0x10, 0x02}, // 0x0210
		0xFF02: {0x00, 0x00}, // skipped: zero
		0xFF04: {0x00, 0x80}, // 0x8000 (outside Z80 work RAM)
	}
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "regs_get":
			return json.RawMessage(`{"cpu":"z80","registers":{"sp":65280,"pc":256,"af":47000,"ix":65282,"iy":0}}`), nil
		case "mem_read":
			address, _ := strconv.ParseUint(params["address"], 10, 64)
			length, _ := strconv.ParseUint(params["length"], 10, 64)
			data := make([]byte, length)
			if slot, present := stack[address]; present {
				copy(data, slot)
			}
			payload := fmt.Sprintf(`{"space_id":"z80-bus","kind":"bus","address":%d,"effective_address":%d,"length":%d,"byte_order":"little-endian","encoding":"base64","consistency":"live","system_paused_during_read":false,"data":%q}`,
				address, address, length, base64.StdEncoding.EncodeToString(data))
			return json.RawMessage(payload), nil
		}
		return nil, fmt.Errorf("unexpected method %s", method)
	}

	server := newTestServer(t, client)
	if set := structured(postToolCall(t, server, "symbols_set",
		`{"symbols":[{"name":"sound_tick","space_id":"z80-bus","address":256}]}`)); set["code"] != nil {
		t.Fatalf("symbols_set failed: %v", set)
	}
	content := structured(postToolCall(t, server, "z80_backtrace", `{"max_frames":8,"include_raw":true}`))
	if content["code"] != nil {
		t.Fatalf("z80_backtrace failed: %v", content)
	}
	frames, _ := content["frames"].([]any)
	if len(frames) != 3 {
		t.Fatalf("expected the live PC plus two stack candidates: %v", frames)
	}
	first := frames[0].(map[string]any)
	if first["address"] != float64(256) || first["symbol"] != "sound_tick" || first["method"] != "register_pc" {
		t.Fatalf("frame 0 must be the live PC with its symbol: %v", first)
	}
	second := frames[1].(map[string]any)
	if second["address"] != float64(0x0210) {
		t.Fatalf("first candidate decoded wrong (little-endian expected): %v", second)
	}
	if second["confidence"] != "medium" {
		t.Fatalf("a candidate inside Z80 work RAM must be medium confidence: %v", second)
	}
	raw := second["raw"].(map[string]any)
	if raw["byte_order"] != "little-endian" || raw["bytes_hex"] != "1002" || raw["stack_address"] != float64(0xFF00) {
		t.Fatalf("raw slot facts wrong: %v", raw)
	}
	third := frames[2].(map[string]any)
	if third["address"] != float64(0x8000) || third["confidence"] != "low" {
		t.Fatalf("a candidate outside Z80 work RAM must be low confidence: %v", third)
	}
	if content["byte_order"] != "little-endian" || content["address_mask_hex"] != "0x00FFFF" {
		t.Fatalf("Z80 decoding facts missing: %v", content)
	}
	if content["capture_consistency"] == nil {
		t.Fatal("the backtrace must report capture_consistency")
	}
}

func TestInputStatusReportsTheServerLedger(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "input_set" {
			return json.RawMessage(`{}`), nil
		}
		return json.RawMessage(fmt.Sprintf(`{"player":%s,"buttons":["right"],"state":%q,"controller_instance":"Control Pad","button_count":1}`, params["player"], params["state"])), nil
	}
	server := newTestServer(t, client)

	empty := structured(postToolCall(t, server, "input_status", `{}`))
	if empty["code"] != nil {
		t.Fatalf("input_status failed: %v", empty)
	}
	if ports, _ := empty["ports"].([]any); len(ports) != 0 {
		t.Fatalf("a port this server never commanded must be absent: %v", ports)
	}
	if empty["native_read_supported"] != false || empty["state_from"] != "server_input_ledger" {
		t.Fatalf("input_status must state the ledger contract: %v", empty)
	}

	if pressed := structured(postToolCall(t, server, "input_set", `{"player":1,"buttons":["Right"],"state":"down"}`)); pressed["code"] != nil {
		t.Fatalf("input_set failed: %v", pressed)
	}
	status := structured(postToolCall(t, server, "input_status", `{"player":1}`))
	ports := status["ports"].([]any)
	if len(ports) != 1 {
		t.Fatalf("expected one commanded port: %v", status)
	}
	port := ports[0].(map[string]any)
	if port["player"] != float64(1) || port["button_count"] != float64(1) {
		t.Fatalf("port facts wrong: %v", port)
	}
	if buttons, _ := port["buttons"].([]any); len(buttons) != 1 || buttons[0] != "right" {
		t.Fatalf("held buttons wrong: %v", port["buttons"])
	}
	if port["pad_type"] != "Control Pad" || port["pad_type_source"] != "native_input_set_echo" {
		t.Fatalf("pad type must come from the native echo: %v", port)
	}
	if port["verified_by_emulator"] != false {
		t.Fatalf("the ledger must not claim an emulator observation: %v", port)
	}

	if released := structured(postToolCall(t, server, "input_set", `{"player":1,"buttons":["right"],"state":"up"}`)); released["code"] != nil {
		t.Fatalf("release failed: %v", released)
	}
	afterRelease := structured(postToolCall(t, server, "input_status", `{}`))
	port = afterRelease["ports"].([]any)[0].(map[string]any)
	if port["button_count"] != float64(0) {
		t.Fatalf("release must clear the held buttons: %v", port)
	}
	if bad := structured(postToolCall(t, server, "input_status", `{"player":9}`)); bad["code"] != "invalid_params" {
		t.Fatalf("an out-of-range player must be rejected: %v", bad)
	}
}

func TestDisassembleBatchAddresses(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	calls := 0
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "disasm" {
			return json.RawMessage(`{}`), nil
		}
		calls++
		if params["count"] != "1" {
			t.Fatalf("a batch entry must request one instruction, params = %v", params)
		}
		address, _ := strconv.ParseUint(params["address"], 10, 64)
		return json.RawMessage(fmt.Sprintf(`{"cpu":"m68k","start_address":%d,"lines":[{"address":%d,"length":2,"bytes":"4E71","mnemonic":"nop","operands":""}]}`, address, address)), nil
	}
	server := newTestServer(t, client)
	if set := structured(postToolCall(t, server, "symbols_set",
		`{"symbols":[{"name":"second","space_id":"m68k-bus","address":512}]}`)); set["code"] != nil {
		t.Fatalf("symbols_set failed: %v", set)
	}
	content := structured(postToolCall(t, server, "m68k_disassemble", `{"addresses":["0x100","0x200"]}`))
	if content["code"] != nil {
		t.Fatalf("batched disassembly failed: %v", content)
	}
	if content["mode"] != "address_list" || content["batch_count"] != float64(2) {
		t.Fatalf("batch envelope wrong: %v", content)
	}
	batches := content["batches"].([]any)
	second := batches[1].(map[string]any)
	if second["address"] != float64(0x200) || second["address_hex"] != "0x000200" {
		t.Fatalf("second batch address wrong: %v", second)
	}
	lines := second["lines"].([]any)
	if len(lines) != 1 {
		t.Fatalf("second batch must carry its own lines: %v", second)
	}
	if line := lines[0].(map[string]any); line["symbol"] != "second" {
		t.Fatalf("batch lines must keep symbol annotation: %v", line)
	}
	if calls != 2 {
		t.Fatalf("expected one native sweep per address, got %d", calls)
	}

	if both := structured(postToolCall(t, server, "m68k_disassemble", `{"address":256,"addresses":["0x200"]}`)); both["code"] != "invalid_params" {
		t.Fatalf("address and addresses together must be refused: %v", both)
	}
	if withCount := structured(postToolCall(t, server, "m68k_disassemble", `{"addresses":["0x100"],"count":4}`)); withCount["code"] != "invalid_params" {
		t.Fatalf("count with addresses must be refused: %v", withCount)
	}
	tooMany := make([]string, 0, maxDisassemblyBatchAddresses+1)
	for index := 0; index <= maxDisassemblyBatchAddresses; index++ {
		tooMany = append(tooMany, fmt.Sprintf("%q", fmt.Sprintf("0x%X", index)))
	}
	oversized := `{"addresses":[` + joinStrings(tooMany, ",") + `]}`
	if result := structured(postToolCall(t, server, "m68k_disassemble", oversized)); result["code"] != "invalid_params" {
		t.Fatalf("an oversized batch must be refused: %v", result)
	}
}

func joinStrings(values []string, separator string) string {
	joined := ""
	for index, value := range values {
		if index > 0 {
			joined += separator
		}
		joined += value
	}
	return joined
}

func TestCoverageDecodingIsBatched(t *testing.T) {
	// Eight contiguous executed addresses, one byte each: one sweep must cover
	// the whole run instead of eight calls.
	trace := "0000100 1 nop\n0000101 1 nop\n0000102 1 nop\n0000103 1 nop\n0000104 1 nop\n0000105 1 nop\n0000106 1 nop\n0000107 1 nop"
	client := &fakeBridgeClient{status: newFakeStatus()}
	sweeps := 0
	requested := []string{}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "disasm":
			sweeps++
			start, _ := strconv.ParseUint(params["address"], 10, 64)
			count, _ := strconv.ParseUint(params["count"], 10, 64)
			requested = append(requested, fmt.Sprintf("%d+%d", start, count))
			lines := make([]string, 0, count)
			for offset := uint64(0); offset < count; offset++ {
				address := start + offset
				lines = append(lines, fmt.Sprintf(`{"address":%d,"length":1,"bytes":"00","mnemonic":"nop","operands":""}`, address))
			}
			return json.RawMessage(fmt.Sprintf(`{"cpu":"m68k","start_address":%d,"requested_count":%d,"lines":[%s]}`, start, count, joinStrings(lines, ","))), nil
		case "trace_capture":
			return json.RawMessage(fmt.Sprintf(`{"cpu":"m68k","requested_entries":10000,"captured":8,"timed_out":true,"duration_ms":500,"sample":[],"trace_text":%q}`, trace)), nil
		}
		return json.RawMessage(`{}`), nil
	}
	content := structured(callTool(t, client, "cpu_coverage_capture", `{"cpu":"m68k","duration_ms":500}`))
	if content["code"] != nil {
		t.Fatalf("cpu_coverage_capture failed: %v", content)
	}
	summary := content["summary"].(map[string]any)
	truncation := summary["truncated"].(map[string]any)
	if truncation["decode_sweeps"] != float64(1) {
		t.Fatalf("a contiguous run must decode in one sweep, got %v (sweeps %v)", truncation["decode_sweeps"], requested)
	}
	if sweeps != 1 {
		t.Fatalf("expected one native disasm call for eight contiguous addresses, got %d: %v", sweeps, requested)
	}
	if summary["distinct_total"] != float64(8) || summary["blocks_count"] != float64(1) {
		t.Fatalf("batching must not change the coverage result: %v", summary)
	}
}
