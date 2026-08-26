package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// m68kRegsPayload builds the plugin-shaped regs_get response for the M68K.
func m68kRegsPayload(registers map[string]uint64) string {
	fields := make([]string, 0, len(registers))
	names := []string{"d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "pc", "sr", "ccr", "ssp", "usp"}
	for _, name := range names {
		value, ok := registers[name]
		if !ok {
			continue
		}
		fields = append(fields, fmt.Sprintf("%q:%d", name, value))
	}
	return fmt.Sprintf(`{"cpu":"m68k","byte_order":"not-applicable","register_note":"Values are plain host integers; byte order is not applicable.","system_paused_during_read":false,"registers":{%s},"flags":{},"width_bits":32}`, strings.Join(fields, ","))
}

// stackMemFake returns an executeFunc answering mem_read from an address
// -> 32-bit big-endian value map (missing addresses read as zero) and
// regs_get with the given register set.
func stackMemFake(registers map[string]uint64, stack map[uint64]uint64) func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
	return func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "regs_get":
			return json.RawMessage(m68kRegsPayload(registers)), nil
		case "mem_read":
			address, _ := strconv.ParseUint(params["address"], 10, 64)
			length, _ := strconv.ParseUint(params["length"], 10, 64)
			buffer := make([]byte, length)
			for i := uint64(0); i+4 <= length; i += 4 {
				value, ok := stack[address+i]
				if !ok {
					continue
				}
				buffer[i] = byte(value >> 24)
				buffer[i+1] = byte(value >> 16)
				buffer[i+2] = byte(value >> 8)
				buffer[i+3] = byte(value)
			}
			return json.RawMessage(fmt.Sprintf(`{"space_id":"m68k-bus","kind":"memory","address":%d,"effective_address":%d,"length":%d,"byte_order":"big-endian","encoding":"base64","consistency":"live","system_paused_during_read":false,"data":"%s"}`,
				address, address, length, base64.StdEncoding.EncodeToString(buffer))), nil
		default:
			return json.RawMessage(`{}`), nil
		}
	}
}

func TestBacktraceHeuristicWalk(t *testing.T) {
	registers := map[string]uint64{
		"a7": 0x00FFF000,
		"a6": 0x00FFF100,
		"pc": 0x00000200,
		"sr": 0x2700,
	}
	stack := map[uint64]uint64{
		0x00FFF000: 0x00FF1234, // RAM window -> plausible, low confidence
		0x00FFF004: 0x00010000, // ROM window -> plausible, medium confidence
		0x00FFF008: 0xDEADBEEF, // masked 0xEFBEEF -> unmapped, rejected
		0x00FFF00C: 0x00000200, // equals the live PC -> de-duplicated
		0x00FFF010: 0x00030000, // ROM window -> plausible
		0x00FFF100: 0x00FFF200, // [A6] saved A6 of the outer frame
		0x00FFF104: 0x00030000, // [A6+4] return address
		0x00FFF200: 0x00000000, // chain terminator
		0x00FFF204: 0x00000000,
	}
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = stackMemFake(registers, stack)

	result := callTool(t, client, "m68k_backtrace", `{"max_frames":4,"context":""}`)
	if result["isError"] == true {
		t.Fatalf("unexpected error: %v", structured(result))
	}
	content := structured(result)
	if content["heuristic"] != true {
		t.Fatalf("heuristic = %v, want true", content["heuristic"])
	}
	note, _ := content["note"].(string)
	if !strings.Contains(note, "not execution-verified") {
		t.Fatalf("note missing heuristic disclaimer: %q", note)
	}
	frames, _ := content["frames"].([]any)
	if len(frames) != 4 {
		t.Fatalf("frame_count = %d, want 4 (got %v)", len(frames), content["frame_count"])
	}
	if content["truncated"] != true {
		t.Fatalf("truncated = %v, want true (budget filled)", content["truncated"])
	}
	first := frames[0].(map[string]any)
	if first["method"] != "register_pc" || first["confidence"] != "high" || first["address"] != float64(0x200) {
		t.Fatalf("frame 0 = %v", first)
	}
	second := frames[1].(map[string]any)
	if second["method"] != "frame_pointer" || second["confidence"] != "medium" || second["address"] != float64(0x30000) {
		t.Fatalf("frame 1 = %v", second)
	}
	third := frames[2].(map[string]any)
	if third["method"] != "stack_scan" || third["confidence"] != "low" || third["address"] != float64(0xFF1234) {
		t.Fatalf("frame 2 = %v", third)
	}
	fourth := frames[3].(map[string]any)
	if fourth["method"] != "stack_scan" || fourth["confidence"] != "medium" || fourth["address"] != float64(0x10000) {
		t.Fatalf("frame 3 = %v", fourth)
	}
	if content["capture_consistency"] == nil {
		t.Fatalf("capture_consistency missing")
	}
	registersView, _ := content["registers"].(map[string]any)
	if registersView["a7_hex"] != "0xFFF000" {
		t.Fatalf("a7_hex = %v", registersView["a7_hex"])
	}
}

func TestBacktraceResolvesSymbolsAndRaw(t *testing.T) {
	registers := map[string]uint64{"a7": 0x00FFF000, "pc": 0x00000200, "a6": 0x00000000}
	stack := map[uint64]uint64{
		0x00FFF000: 0x00010004, // ROM window, near the symbol at 0x10000
		0x00FFF004: 0x00011000, // 0x1000 above the symbol -> offset reported
	}
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = stackMemFake(registers, stack)
	server := newTestServer(t, client)
	if result := postToolCall(t, server, "symbols_set", `{"symbols":[{"name":"main_loop","space_id":"m68k-bus","address":65536}]}`); result["isError"] == true {
		t.Fatalf("symbols_set failed: %v", structured(result))
	}
	result := postToolCall(t, server, "m68k_backtrace", `{"max_frames":3,"include_raw":true}`)
	if result["isError"] == true {
		t.Fatalf("unexpected error: %v", structured(result))
	}
	content := structured(result)
	frames, _ := content["frames"].([]any)
	var scanFrame map[string]any
	for _, entry := range frames {
		frame := entry.(map[string]any)
		if frame["address"] == float64(0x10004) {
			scanFrame = frame
		}
	}
	if scanFrame == nil {
		t.Fatalf("scan frame at 0x10004 not found: %v", content["frames"])
	}
	if scanFrame["symbol"] != "main_loop" || scanFrame["offset"] != float64(4) {
		t.Fatalf("exact-offset symbol resolution = %v", scanFrame)
	}
	raw, _ := scanFrame["raw"].(map[string]any)
	if raw == nil || raw["bytes_hex"] != "00010004" || raw["stack_address_hex"] != "0xFFF000" {
		t.Fatalf("raw view = %v", scanFrame["raw"])
	}
}

func TestBacktraceMissingStackPointerFails(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		return json.RawMessage(m68kRegsPayload(map[string]uint64{"pc": 0x200})), nil
	}
	result := callTool(t, client, "m68k_backtrace", `{}`)
	content := structured(result)
	if content["code"] != "bridge_error" {
		t.Fatalf("code = %v, want bridge_error", content["code"])
	}
}

func TestBacktraceMaxFramesCap(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	result := callTool(t, client, "m68k_backtrace", `{"max_frames":1000}`)
	content := structured(result)
	if content["code"] != "invalid_params" {
		t.Fatalf("code = %v, want invalid_params", content["code"])
	}
}
