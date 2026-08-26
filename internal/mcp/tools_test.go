package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/StealthC/exodus-mcp/internal/analysis"
	"github.com/StealthC/exodus-mcp/internal/artifact"
	"github.com/StealthC/exodus-mcp/internal/bridge"
)

// newTestServer builds one Server with session-stable storage so multi-step
// tool flows (dump -> get -> preview) operate on shared state.
func newTestServer(t *testing.T, client bridge.Client) *Server {
	t.Helper()
	store, err := artifact.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return NewServer("test", client, store, analysis.NewRegistry(), "http://127.0.0.1")
}

func postToolCall(t *testing.T, server *Server, name, arguments string) map[string]any {
	t.Helper()
	params := fmt.Sprintf(`{"name":%q,"arguments":%s,"_meta":{"io.modelcontextprotocol/protocolVersion":%q}}`, name, arguments, ModernProtocolVersion)
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":%s}`, params)
	request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8768/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("MCP-Protocol-Version", ModernProtocolVersion)
	request.Header.Set("Mcp-Method", "tools/call")
	request.Header.Set("Mcp-Name", name)
	recorder := newRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.status != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.status, recorder.body.String())
	}
	var envelope struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(recorder.body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response %s: %v", recorder.body.String(), err)
	}
	return envelope.Result
}

// callTool posts one-shot calls against a throwaway server.
func callTool(t *testing.T, client bridge.Client, name, arguments string) map[string]any {
	t.Helper()
	return postToolCall(t, newTestServer(t, client), name, arguments)
}

func structured(result map[string]any) map[string]any {
	content, _ := result["structuredContent"].(map[string]any)
	return content
}

func memReadPayload(data []byte, byteOrder string, effective uint64) string {
	return fmt.Sprintf(`{"space_id":"m68k-ram","kind":"memory","address":4096,"effective_address":%d,"length":%d,"byte_order":"%s","encoding":"base64","consistency":"live","data":"%s"}`,
		effective, len(data), byteOrder, base64.StdEncoding.EncodeToString(data))
}

func TestMemoryReadEchoesMetadata(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "mem_read" {
			t.Fatalf("method = %s", method)
		}
		if params["space"] != "m68k-ram" || params["address"] != "4096" || params["length"] != "4" {
			t.Fatalf("params = %v", params)
		}
		return json.RawMessage(memReadPayload([]byte{0x12, 0x34, 0xAB, 0xCD}, "big-endian", 4096)), nil
	}
	result := callTool(t, client, "memory_read", `{"space":"m68k-ram","address":4096,"length":4}`)
	content := structured(result)
	if content["byte_order"] != "big-endian" || content["effective_address"] != float64(4096) {
		t.Fatalf("metadata not echoed: %v", content)
	}
	if content["data_base64"] != base64.StdEncoding.EncodeToString([]byte{0x12, 0x34, 0xAB, 0xCD}) {
		t.Fatalf("payload mismatch: %v", content)
	}
}

func TestMemoryReadRejectsAboveInlineCap(t *testing.T) {
	result := callTool(t, &fakeBridgeClient{status: newFakeStatus()}, "memory_read", `{"space":"m68k-ram","address":0,"length":5000}`)
	content := structured(result)
	if result["isError"] != true || content["code"] != "length_exceeds_inline_cap" {
		t.Fatalf("expected length_exceeds_inline_cap: %v", result)
	}
	if !strings.Contains(content["message"].(string), "memory_dump") {
		t.Fatalf("error must orient to memory_dump: %v", content)
	}
}

func TestMemoryReadUnknownSpaceSurfacesValidIds(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		return nil, &bridge.CommandError{Code: "unknown_space", Message: "Unknown space id: bogus. Valid ids: m68k-ram z80-ram"}
	}
	result := callTool(t, client, "memory_read", `{"space":"bogus","address":0,"length":8}`)
	content := structured(result)
	if result["isError"] != true || content["code"] != "unknown_space" {
		t.Fatalf("expected unknown_space error: %v", result)
	}
	if !strings.Contains(content["message"].(string), "z80-ram") {
		t.Fatalf("message should list valid ids: %v", content)
	}
}

func TestMemoryDecodeRejectsByteOrderMismatch(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		return json.RawMessage(memReadPayload([]byte{1, 2, 3, 4}, "big-endian", 0)), nil
	}
	result := callTool(t, client, "m68k_read_memory", `{"address":0,"length":4,"decode":{"type":"u16","byte_order":"little-endian"}}`)
	content := structured(result)
	if result["isError"] != true || content["code"] != "byte_order_mismatch" {
		t.Fatalf("expected byte_order_mismatch: %v", result)
	}
}

func TestMemoryDecodeBigEndianValues(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		return json.RawMessage(memReadPayload([]byte{0x00, 0x01, 0xFF, 0xFE}, "big-endian", 0)), nil
	}
	result := callTool(t, client, "m68k_read_memory", `{"address":0,"length":4,"decode":{"type":"u16","byte_order":"big-endian"}}`)
	content := structured(result)
	decoded := content["decoded"].(map[string]any)
	values := decoded["values"].([]any)
	if values[0] != float64(1) || values[1] != float64(65534) {
		t.Fatalf("decoded values wrong: %v", decoded)
	}
}

func TestHexdumpRepresentation(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		return json.RawMessage(memReadPayload([]byte{'A', 'B'}, "not-applicable", 0)), nil
	}
	result := callTool(t, client, "z80_read_memory", `{"address":0,"length":2,"representation":"hexdump"}`)
	content := structured(result)
	hexDumpText, _ := content["hex"].(string)
	if !strings.Contains(hexDumpText, "41 42") || !strings.Contains(hexDumpText, "|AB|") {
		t.Fatalf("hex dump malformed: %q", hexDumpText)
	}
}

func TestMemoryDumpProducesArtifact(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		return json.RawMessage(memReadPayload([]byte{1, 2, 3, 4, 5}, "big-endian", 16)), nil
	}
	result := callTool(t, client, "memory_dump", `{"space":"m68k-ram","address":16,"length":5}`)
	if result["isError"] == true {
		t.Fatalf("unexpected error: %v", result)
	}
	content := structured(result)
	artifactDesc := content["artifact"].(map[string]any)
	for _, key := range []string{"id", "mime_type", "size_bytes", "sha256", "url", "resource_uri"} {
		if _, present := artifactDesc[key]; !present {
			t.Fatalf("artifact descriptor missing %s: %v", key, artifactDesc)
		}
	}
	if !strings.HasPrefix(artifactDesc["id"].(string), "art_") {
		t.Fatalf("opaque id expected: %v", artifactDesc)
	}
}

func TestArtifactGetAndPreviewRoundtrip(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		return json.RawMessage(memReadPayload([]byte("hello m68k world"), "big-endian", 0)), nil
	}
	server := newTestServer(t, client)

	dumpResult := postToolCall(t, server, "memory_dump", `{"space":"m68k-ram","address":0,"length":16}`)
	dumpArtifact := structured(dumpResult)["artifact"].(map[string]any)
	artifactID := dumpArtifact["id"].(string)

	getResult := postToolCall(t, server, "artifact_get", fmt.Sprintf(`{"artifact_id":%q}`, artifactID))
	retrieved := structured(getResult)["artifact"].(map[string]any)
	if retrieved["sha256"] != dumpArtifact["sha256"] {
		t.Fatal("sha256 mismatch between dump and get")
	}

	previewResult := postToolCall(t, server, "artifact_preview", fmt.Sprintf(`{"artifact_id":%q,"mode":"text","length":20}`, artifactID))
	if structured(previewResult)["text"] != "hello m68k world" {
		t.Fatalf("preview text wrong: %v", previewResult)
	}

	unknown := postToolCall(t, server, "artifact_get", `{"artifact_id":"art_doesnotexist"}`)
	if structured(unknown)["code"] != "unknown_artifact" {
		t.Fatalf("expected unknown_artifact: %v", unknown)
	}
}

func TestContextLifecycle(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	listResult := postToolCall(t, server, "context_list", "{}")
	defaultContextID := structured(listResult)["default_context"].(string)
	if defaultContextID == "" {
		t.Fatal("default context missing")
	}

	createResult := postToolCall(t, server, "context_create", `{"name":"research"}`)
	contextID := structured(createResult)["context"].(map[string]any)["id"].(string)
	if !strings.HasPrefix(contextID, "ctx_") {
		t.Fatalf("context handle malformed: %s", contextID)
	}

	closeDefault := postToolCall(t, server, "context_close", fmt.Sprintf(`{"context_id":%q}`, defaultContextID))
	if structured(closeDefault)["code"] != "cannot_close_default" {
		t.Fatalf("default close must be refused: %v", closeDefault)
	}

	closeResult := postToolCall(t, server, "context_close", fmt.Sprintf(`{"context_id":%q}`, contextID))
	if closeResult["isError"] == true {
		t.Fatalf("close failed: %v", closeResult)
	}

	reopen := postToolCall(t, server, "context_close", fmt.Sprintf(`{"context_id":%q}`, contextID))
	if structured(reopen)["code"] != "unknown_context" {
		t.Fatalf("closed context must be unresolvable: %v", reopen)
	}
}

func TestCpuRegistersPassthrough(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "regs_get" || params["cpu"] != "m68k" {
			t.Fatalf("unexpected call %s %v", method, params)
		}
		payload := `{"cpu":"m68k","byte_order":"not-applicable","registers":{"d0":7,"pc":512},"flags":{"n":true},"width_bits":32}`
		return json.RawMessage(payload), nil
	}
	result := callTool(t, client, "m68k_registers", "{}")
	registers := structured(result)["registers"].(map[string]any)
	if registers["d0"] != float64(7) || registers["pc"] != float64(512) {
		t.Fatalf("registers mismatch: %v", registers)
	}
}

func TestDisassemblyPassthroughAndCap(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "disasm" || params["cpu"] != "z80" || params["count"] != "32" {
			t.Fatalf("unexpected call %s %v", method, params)
		}
		payload := `{"cpu":"z80","start_address":256,"requested_count":32,"lines":[{"address":256,"length":1,"bytes":"00","mnemonic":"nop","operands":""}]}`
		return json.RawMessage(payload), nil
	}
	result := callTool(t, client, "z80_disassemble", `{"count":32}`)
	lines := structured(result)["lines"].([]any)
	if len(lines) != 1 {
		t.Fatalf("lines lost: %v", structured(result))
	}

	capped := callTool(t, &fakeBridgeClient{status: newFakeStatus()}, "m68k_disassemble", `{"count":100000}`)
	if structured(capped)["code"] != "invalid_params" {
		t.Fatalf("oversized count must be rejected: %v", capped)
	}
}

func TestTraceCaptureWritesArtifact(t *testing.T) {
	trace := "2064 10 move.l d0,-(sp)\n2066 22 rts"
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		payload := fmt.Sprintf(`{"cpu":"m68k","requested_entries":2,"captured":2,"timed_out":false,"duration_ms":120,"sample":[{"address":2064,"cycle":10,"text":"2064 10 move.l"}],"trace_text":%q}`, trace)
		return json.RawMessage(payload), nil
	}
	result := callTool(t, client, "cpu_trace_capture", `{"cpu":"m68k","max_entries":2}`)
	content := structured(result)
	summary := content["summary"].(map[string]any)
	if summary["captured"] != float64(2) {
		t.Fatalf("captured mismatch: %v", summary)
	}
	artifactDesc := content["artifact"].(map[string]any)
	if artifactDesc["mime_type"] != "text/plain; charset=utf-8" {
		t.Fatalf("trace mime wrong: %v", artifactDesc)
	}
}

func TestROMLoadPassesWindowsPath(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "rom_load" || params["path"] != `F:\roms\kid.bin` || params["run"] != "true" {
			t.Fatalf("unexpected call %s %v", method, params)
		}
		return json.RawMessage(`{"path":"F:\\roms\\kid.bin","loaded":true}`), nil
	}
	result := callTool(t, client, "rom_load", `{"path":"F:\\roms\\kid.bin","run":true}`)
	if !structured(result)["loaded"].(bool) {
		t.Fatalf("ROM load result lost: %v", structured(result))
	}

	invalid := callTool(t, client, "rom_load", `{"path":"F:\\roms\\kid.bin\nmethod=status"}`)
	if structured(invalid)["code"] != "invalid_params" {
		t.Fatalf("newline path must be rejected: %v", invalid)
	}
}

func TestControlToolsPassExpectedCommands(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "cpu_control":
			if params["cpu"] != "m68k" || params["action"] != "step" {
				t.Fatalf("unexpected control params: %v", params)
			}
		case "breakpoint_set":
			if params["cpu"] != "z80" || params["address"] != "4660" {
				t.Fatalf("unexpected breakpoint params: %v", params)
			}
		case "watchpoint_set":
			if params["cpu"] != "m68k" || params["address"] != "8192" || params["length"] != "4" || params["access"] != "write" {
				t.Fatalf("unexpected watchpoint params: %v", params)
			}
		case "watchpoint_list":
		case "watchpoint_remove":
			if params["watchpoint_id"] != "3" {
				t.Fatalf("unexpected watchpoint remove params: %v", params)
			}
		default:
			t.Fatalf("unexpected command: %s", method)
		}
		return json.RawMessage(`{"ok":true}`), nil
	}
	if structured(callTool(t, client, "m68k_step", "{}"))["ok"] != true {
		t.Fatal("step result lost")
	}
	if structured(callTool(t, client, "cpu_breakpoint_set", `{"cpu":"z80","address":"0x1234"}`))["ok"] != true {
		t.Fatal("breakpoint result lost")
	}
	setResult := structured(callTool(t, client, "cpu_watchpoint_set", `{"cpu":"m68k","address":"$2000","length":4,"access":"write"}`))
	if setResult["ok"] != true {
		t.Fatalf("watchpoint result lost: %v", setResult)
	}
	if structured(callTool(t, client, "cpu_watchpoint_list", "{}"))["ok"] != true {
		t.Fatal("watchpoint list lost")
	}
	if structured(callTool(t, client, "cpu_watchpoint_remove", `{"watchpoint_id":3}`))["ok"] != true {
		t.Fatal("watchpoint remove lost")
	}

	badAccess := callTool(t, client, "cpu_watchpoint_set", `{"cpu":"m68k","address":"$2000","access":"execute"}`)
	if structured(badAccess)["code"] != "invalid_params" {
		t.Fatalf("invalid access must be rejected: %v", badAccess)
	}
	badLength := callTool(t, client, "cpu_watchpoint_set", `{"cpu":"m68k","address":"$2000","length":0}`)
	if structured(badLength)["code"] != "invalid_params" {
		t.Fatalf("zero length must be rejected: %v", badLength)
	}
}

func TestVdpTools(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "vdp_status":
			return json.RawMessage(`{"vdp_found":true,"registers":[{"register":0,"value":4}],"decoded":{"display_enabled":true},"image_buffer":{"line_count":224,"line_width":320}}`), nil
		case "frame_capture":
			// 2x1 frame: red pixel then green pixel.
			frame := []byte{0xFF, 0x00, 0x00, 0x00, 0xFF, 0x00}
			return json.RawMessage(`{"width":2,"height":1,"pixel_format":"rgb24","byte_order":"not-applicable","encoding":"base64","consistency":"live","frame_token":77,"data":"` + base64.StdEncoding.EncodeToString(frame) + `"}`), nil
		default:
			t.Fatalf("unexpected command: %s", method)
		}
		return nil, nil
	}

	server := newTestServer(t, client)
	status := structured(postToolCall(t, server, "vdp_status", "{}"))
	if status["vdp_found"] != true {
		t.Fatalf("vdp_status passthrough lost: %v", status)
	}

	capture := structured(postToolCall(t, server, "frame_capture", "{}"))
	if capture["code"] != nil {
		t.Fatalf("frame_capture failed: %v", capture)
	}
	summary := capture["summary"].(map[string]any)
	if summary["width"] != float64(2) || summary["height"] != float64(1) || summary["frame_token"] != float64(77) {
		t.Fatalf("capture summary wrong: %v", summary)
	}
	artifactInfo := capture["artifact"].(map[string]any)
	preview := structured(postToolCall(t, server, "artifact_preview", fmt.Sprintf(`{"artifact_id":%q,"mode":"hex","length":8}`, artifactInfo["id"])))
	if !strings.Contains(strings.ToUpper(fmt.Sprintf("%v", preview)), "89 50 4E 47 0D 0A 1A 0A") {
		t.Fatalf("stored artifact must start with the PNG magic bytes: %v", preview)
	}

	mismatchClient := &fakeBridgeClient{status: newFakeStatus()}
	mismatchClient.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		return json.RawMessage(`{"width":4,"height":4,"data":"AAAA"}`), nil
	}
	mismatch := callTool(t, mismatchClient, "frame_capture", "{}")
	if structured(mismatch)["code"] != "bridge_error" {
		t.Fatalf("dimension mismatch must be rejected: %v", mismatch)
	}
}

func TestVDPMemoryReadCramRGB333View(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "vdp_mem_read" {
			t.Fatalf("method = %s", method)
		}
		if params["target"] != "cram" || params["address"] != "0" || params["length"] != "4" {
			t.Fatalf("params = %v", params)
		}
		cram := []byte{0x01, 0x23, 0x00, 0x00}
		return json.RawMessage(`{"target":"cram","address_space":"315-5313 CRAM","address":0,"length":4,"buffer_size":128,"entry_size":2,"byte_order":"big-endian","encoding":"base64","consistency":"live","data":"` + base64.StdEncoding.EncodeToString(cram) + `"}`), nil
	}

	content := structured(callTool(t, client, "vdp_memory_read", `{"target":"cram","address":0,"length":4,"representation":"cram_rgb333"}`))
	if content["code"] != "" && content["code"] != nil {
		t.Fatalf("unexpected failure: %v", content)
	}
	if content["address_space"] != "315-5313 CRAM" || content["byte_order"] != "big-endian" || content["entry_size"] != float64(2) {
		t.Fatalf("metadata lost: %v", content)
	}
	entries, _ := content["entries"].([]any)
	if len(entries) != 2 {
		t.Fatalf("entries = %v", entries)
	}
	first := entries[0].(map[string]any)
	if first["index"] != float64(0) || first["r"] != float64(36) || first["g"] != float64(36) || first["b"] != float64(0) || first["color_hex"] != "#242400" {
		t.Fatalf("first entry decode wrong: %v", first)
	}
	second := entries[1].(map[string]any)
	if second["color_hex"] != "#000000" {
		t.Fatalf("second entry decode wrong: %v", second)
	}
}

func TestVDPMemoryReadDefaultsAndMetadata(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "vdp_mem_read" {
			t.Fatalf("method = %s", method)
		}
		if params["target"] != "vsram" || params["address"] != "4660" || params["length"] != fmt.Sprintf("%d", defaultVDPMemoryReadLen) {
			t.Fatalf("params = %v", params)
		}
		vsram := make([]byte, defaultVDPMemoryReadLen)
		for i := range vsram {
			vsram[i] = byte(i)
		}
		return json.RawMessage(`{"target":"vsram","address_space":"315-5313 VSRAM","address":4660,"length":128,"buffer_size":80,"entry_size":2,"byte_order":"big-endian","encoding":"base64","consistency":"live","data":"` + base64.StdEncoding.EncodeToString(vsram) + `"}`), nil
	}

	content := structured(callTool(t, client, "vdp_memory_read", `{"target":"vsram","address":"$1234"}`))
	if content["representation"] != "hexdump" {
		t.Fatalf("default representation must be hexdump: %v", content["representation"])
	}
	hexText := fmt.Sprintf("%v", content["hex"])
	if !strings.Contains(strings.ToUpper(hexText), "00001234") {
		t.Fatalf("hexdump must echo the start address column: %v", hexText)
	}
}

func TestVDPMemoryReadRejectsBadRequests(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		t.Fatalf("bridge must not be reached for invalid requests: %s", method)
		return nil, nil
	}

	cases := []struct {
		name      string
		arguments string
		code      string
	}{
		{"unknown target", `{"target":"oam","address":0}`, "invalid_params"},
		{"cram view on vram", `{"target":"vram","address":0,"length":4,"representation":"cram_rgb333"}`, "invalid_params"},
		{"unaligned word view", `{"target":"cram","address":1,"length":4,"representation":"array_u16"}`, "unaligned_request"},
		{"unaligned word length", `{"target":"vsram","address":0,"length":3,"representation":"array_u16"}`, "unaligned_request"},
		{"length above cap", fmt.Sprintf(`{"target":"vram","address":0,"length":%d}`, inlineReadCapBytes+1), "length_exceeds_inline_cap"},
	}
	for _, testCase := range cases {
		result := structured(callTool(t, client, "vdp_memory_read", testCase.arguments))
		if result["code"] != testCase.code {
			t.Fatalf("%s: code = %v (%v)", testCase.name, result["code"], result)
		}
	}
}

// fakeVDPMemoryClient serves vdp_status plus chunked vdp_mem_read calls from
// one in-memory VRAM/CRAM pair, mirroring the plugin payload shape.
type fakeVDPMemoryClient struct {
	fakeBridgeClient
	vram           []byte
	cram           []byte
	statusResponse string
	bridgeHits     int
}

// newFakeVDPMemoryClient wires a client whose capability advertisement covers
// every VDP op while responses serve from the given buffers.
func newFakeVDPMemoryClient(vram, cram []byte) *fakeVDPMemoryClient {
	return &fakeVDPMemoryClient{
		fakeBridgeClient: fakeBridgeClient{status: newFakeStatus()},
		vram:             vram,
		cram:             cram,
		statusResponse:   newFakeVDPStatus(),
	}
}

func (f *fakeVDPMemoryClient) Execute(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
	if f.executeFunc != nil {
		return f.executeFunc(ctx, method, params)
	}
	switch method {
	case "vdp_status":
		return json.RawMessage(f.statusResponse), nil
	case "vdp_mem_read":
		f.bridgeHits++
		address, _ := strconv.ParseUint(params["address"], 10, 64)
		length, _ := strconv.ParseUint(params["length"], 10, 64)
		var blob []byte
		if params["target"] == "vram" {
			blob = f.vram[address : address+length]
		} else {
			blob = f.cram[address : address+length]
		}
		payload := map[string]any{
			"target": params["target"], "address_space": "fake",
			"address": address, "length": length,
			"entry_size": 1, "byte_order": "big-endian", "encoding": "base64",
			"consistency": "live", "system_paused_during_read": true,
			"data": base64.StdEncoding.EncodeToString(blob),
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		return raw, nil
	}
	return nil, fmt.Errorf("unexpected command %s", method)
}

func newFakeVDPStatus() string {
	return `{"decoded":{"extended_vram":false,"name_table_base_b":8192},"registers":[{"register":12,"value":0},{"register":16,"value":0}]}`
}

// testContextID resolves the implicit default analysis context handle.
func testContextID(t *testing.T, server *Server) string {
	t.Helper()
	resolved, err := server.contexts.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	return resolved.ID
}

// pixelAt samples any decoded image as straight 8-bit RGBA.
func pixelAt(t *testing.T, img image.Image, x, y int) [4]uint8 {
	t.Helper()
	red, green, blue, alpha := img.At(x, y).RGBA()
	return [4]uint8{uint8(red >> 8), uint8(green >> 8), uint8(blue >> 8), uint8(alpha >> 8)}
}

func TestVDPPixelInfoReadyAndPending(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	readyPayload := `{"attribution_ready":true,"frame_token":42,"buffer_plane":1,"line_count":224,"line_width":320,` +
		`"source":"layer_a","hcounter":279,"vcounter":120,"palette_row":2,"palette_entry":5,` +
		`"shadow_highlight_enabled":false,"pixel_is_shadowed":false,"pixel_is_highlighted":false,` +
		`"color_rgb333":[4,2,1],"color_888":"#DB9249",` +
		`"mapping_present":true,"mapping_vram_address":4096,"mapping_data_word":8452,"tile":68,` +
		`"hflip":false,"vflip":true,"priority":false,"pattern_row":3,"pattern_column":7,` +
		`"sprite_present":false}`
	pendingPayload := `{"attribution_ready":false,"frame_token":41,"buffer_plane":0,"line_count":224,"line_width":320}`
	mode := "ready"
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "vdp_pixel_info" {
			t.Fatalf("method = %s", method)
		}
		if params["x"] != "100" || params["y"] != "60" {
			t.Fatalf("params = %v", params)
		}
		if mode == "ready" {
			return json.RawMessage(readyPayload), nil
		}
		return json.RawMessage(pendingPayload), nil
	}
	content := structured(callTool(t, client, "vdp_pixel_info", `{"x": 100, "y": 60}`))
	if content["source"] != "layer_a" || content["color_888"] != "#DB9249" || content["tile"] != float64(68) ||
		content["vflip"] != true || content["pattern_row"] != float64(3) {
		t.Fatalf("ready payload lost fields: %v", content)
	}
	if content["address_space"] != "315-5313 completed image buffer" {
		t.Fatalf("metadata missing: %v", content["address_space"])
	}

	mode = "pending"
	result := callTool(t, client, "vdp_pixel_info", `{"x": 100, "y": 60}`)
	if result["isError"] != true {
		t.Fatalf("pending must surface as tool error: %v", result)
	}
	structuredResult := structured(result)
	if structuredResult["code"] != "pixel_info_pending" {
		t.Fatalf("wrong pending code: %v", structuredResult["code"])
	}
}

func TestVDPPixelInfoRejectsBridgeErrors(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		return nil, &bridge.CommandError{Code: "out_of_range", Message: "y exceeds the completed image buffer line count"}
	}
	result := structured(callTool(t, client, "vdp_pixel_info", `{"x": 5, "y": 999}`))
	if result["code"] != "out_of_range" {
		t.Fatalf("bridge error code lost: %v", result)
	}
}

func TestVDPTileExportDecodeAndPNG(t *testing.T) {
	vram := make([]byte, 65536)
	copy(vram[5*32:], []byte{0x01, 0x23, 0x45, 0x67}) // row zero: pixels 0..7
	cram := make([]byte, 128)
	for entry := 1; entry < 16; entry++ {
		word := 0x0EEE // all channels max: white
		cram[entry*2] = byte(word >> 8)
		cram[entry*2+1] = byte(word)
	}
	client := newFakeVDPMemoryClient(vram, cram)
	server := newTestServer(t, client)

	content := structured(postToolCall(t, server, "vdp_tile_export", `{"tile": 5, "scale": 2}`))
	summary := content["summary"].(map[string]any)
	if summary["tile_count"] != float64(1) || summary["bpp"] != float64(4) {
		t.Fatalf("summary wrong: %v", summary)
	}
	// The fake reports system_paused_during_read=true (each read stopped a
	// running system), so the composite cannot claim snapshot coherence.
	if summary["coherent_snapshot"] != false {
		t.Fatalf("incoherent reads must not claim snapshot coherence: %v", summary["coherent_snapshot"])
	}
	if fmt.Sprintf("%v", summary["nonzero_pixels_per_tile"]) != "[7]" {
		t.Fatalf("nonzero pixels wrong: %v", summary["nonzero_pixels_per_tile"])
	}
	pngInfo := content["artifacts"].([]any)[0].(map[string]any)

	rawPNG, _, err := server.store.Bytes(pngInfo["id"].(string), testContextID(t, server))
	if err != nil {
		t.Fatal(err)
	}
	decodedImg, err := png.Decode(bytes.NewReader(rawPNG))
	if err != nil {
		t.Fatal(err)
	}
	if bounds := decodedImg.Bounds(); bounds.Dx() != 16 || bounds.Dy() != 16 {
		t.Fatalf("png size %dx%d, want 16x16", bounds.Dx(), bounds.Dy())
	}
	transparent := pixelAt(t, decodedImg, 0, 0) // pixel index 0
	if transparent[3] != 0 {
		t.Fatalf("pixel 0 must stay transparent: %v", transparent)
	}
	white := pixelAt(t, decodedImg, 3, 1) // pixel index 1 at scale 2
	if white != [4]uint8{255, 255, 255, 255} {
		t.Fatalf("pixel 1 must be white: %v", white)
	}
}

func TestVDPTileExportRejectsBadRequests(t *testing.T) {
	client := newFakeVDPMemoryClient(make([]byte, 65536), make([]byte, 128))
	server := newTestServer(t, client)
	for _, arguments := range []string{
		`{"palette": 4}`,
		`{"count": 65}`,
		`{"scale": 33}`,
	} {
		result := structured(postToolCall(t, server, "vdp_tile_export", arguments))
		if result["code"] != "invalid_params" {
			t.Fatalf("%s: code = %v (%v)", arguments, result["code"], result)
		}
	}
	if hits := client.bridgeHits; hits != 0 {
		t.Fatalf("static validation must not reach the bridge, got %d hits", hits)
	}
	result := structured(postToolCall(t, server, "vdp_tile_export", `{"tile": 2048}`))
	if result["code"] != "out_of_range" {
		t.Fatalf("out of range tile: %v", result)
	}
}

func TestVDPPlaneExportRender(t *testing.T) {
	vram := make([]byte, 65536)
	writeWord := func(address uint64, word int) {
		vram[address] = byte(word >> 8)
		vram[address+1] = byte(word)
	}
	// Name table at 8192; cells: plain pal1, hflip, vflip, priority+pal3.
	writeWord(8192, 0x2004)    // (0,0) tile 4 palette 1
	writeWord(8192+2, 0x2804)  // (1,0) horizontal flip
	writeWord(8192+64, 0x3004) // (0,1) vertical flip
	writeWord(8192+66, 0xE004) // (1,1) priority + palette 3
	vram[4*32] = 0x59          // pixel row 0: indices 5 then 9

	cram := make([]byte, 128)
	setColor := func(entry, word int) {
		cram[entry*2] = byte(word >> 8)
		cram[entry*2+1] = byte(word)
	}
	setColor(21, 0x0555) // palette 1 index 5: gray 73
	setColor(48, 0x0AAA) // palette 3 index 0: gray 183
	setColor(53, 0x0333) // palette 3 index 5: gray 36

	client := newFakeVDPMemoryClient(vram, cram)
	server := newTestServer(t, client)

	content := structured(postToolCall(t, server, "vdp_plane_export", `{"plane": "b", "transparent_zero": false}`))
	summary := content["summary"].(map[string]any)
	if summary["distinct_tiles"] != float64(2) || summary["priority_entries"] != float64(1) ||
		summary["invalid_entries"] != float64(0) || summary["interlace_active"] != false {
		t.Fatalf("summary wrong: %v", summary)
	}
	sizeCells := summary["size_cells"].([]any)
	if sizeCells[0] != float64(32) || sizeCells[1] != float64(32) {
		t.Fatalf("plane geometry wrong: %v", sizeCells)
	}
	pngInfo := content["artifacts"].([]any)[0].(map[string]any)

	rawPNG, _, err := server.store.Bytes(pngInfo["id"].(string), testContextID(t, server))
	if err != nil {
		t.Fatal(err)
	}
	decodedImg, err := png.Decode(bytes.NewReader(rawPNG))
	if err != nil {
		t.Fatal(err)
	}
	if bounds := decodedImg.Bounds(); bounds.Dx() != 256 || bounds.Dy() != 256 {
		t.Fatalf("png size %dx%d, want 256x256", bounds.Dx(), bounds.Dy())
	}
	expectations := map[[2]int][4]uint8{
		{0, 0}:     {73, 73, 73, 255}, // pixel index 5 through palette 1
		{8, 0}:     {0, 0, 0, 255},    // hflip moves index 0 over this corner
		{0, 8}:     {0, 0, 0, 255},    // vflip likewise
		{8, 8}:     {36, 36, 36, 255}, // palette 3 index 5
		{100, 100}: {0, 0, 0, 255},    // empty cells use palette line of entry... entry word 0 -> palette 0 -> black opaque
	}
	for point, want := range expectations {
		if got := pixelAt(t, decodedImg, point[0], point[1]); got != want {
			t.Fatalf("pixel %v = %v, want %v", point, got, want)
		}
	}
}

func TestVDPPlaneExportRejectsBadPlane(t *testing.T) {
	client := newFakeVDPMemoryClient(make([]byte, 65536), make([]byte, 128))
	server := newTestServer(t, client)
	result := structured(postToolCall(t, server, "vdp_plane_export", `{"plane": "c"}`))
	if result["code"] != "invalid_params" {
		t.Fatalf("bad plane accepted: %v", result)
	}
}

func TestVDPSpriteTableDecodeAndChain(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "vdp_status":
			return json.RawMessage(`{"decoded":{"name_table_base_sprite":53248,"extended_vram":false}}`), nil
		case "vdp_mem_read":
			if params["target"] != "vram" || params["address"] != "53248" {
				t.Fatalf("params = %v", params)
			}
			table := make([]byte, vdpSpriteTableMaxEntries*8)
			writeSprite := func(index int, w0, w1, w2, w3 int) {
				table[index*8+0] = byte(w0 >> 8)
				table[index*8+1] = byte(w0)
				table[index*8+2] = byte(w1 >> 8)
				table[index*8+3] = byte(w1)
				table[index*8+4] = byte(w2 >> 8)
				table[index*8+5] = byte(w2)
				table[index*8+6] = byte(w3 >> 8)
				table[index*8+7] = byte(w3)
			}
			// Sprite 0: y=100 (raw 228), 2x3 cells, link=5, tile 0x155,
			// hflip, palette 2, priority; x=200 (raw 328).
			writeSprite(0, 228, 0x0529, 0x8000|(2<<13)|(1<<11)|0x155, 328)
			// Sprite 5 terminates the chain with link 0.
			writeSprite(5, 300, 0x0000, 0x0001, 100)
			return json.RawMessage(`{"target":"vram","address_space":"315-5313 VRAM","address":53248,"length":640,"buffer_size":65536,"entry_size":2,"byte_order":"big-endian","encoding":"base64","consistency":"live","data":"` + base64.StdEncoding.EncodeToString(table) + `"}`), nil
		default:
			t.Fatalf("unexpected command: %s", method)
		}
		return nil, nil
	}

	content := structured(callTool(t, client, "vdp_sprite_table", `{"offset":0,"count":8}`))
	if content["sprite_table_base"] != float64(53248) {
		t.Fatalf("base lost: %v", content["sprite_table_base"])
	}
	entries := content["entries"].([]any)
	first := entries[0].(map[string]any)
	if first["screen_y"] != float64(100) || first["width_cells"] != float64(2) || first["height_cells"] != float64(3) ||
		first["link"] != float64(5) || first["tile"] != float64(0x155) || first["hflip"] != true ||
		first["palette"] != float64(2) || first["priority"] != true || first["screen_x"] != float64(200) {
		t.Fatalf("first entry decode wrong: %v", first)
	}
	if len(entries) != 8 {
		t.Fatalf("paging window wrong: %d", len(entries))
	}
	chain := content["chain"].(map[string]any)
	order := fmt.Sprintf("%v", chain["order"])
	if order != "[0 5]" || chain["terminated_by_zero"] != true || chain["cycle_detected"] != false {
		t.Fatalf("chain walk wrong: %v", chain)
	}
}

func TestVDPSpriteTableCycleDetection(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		if method == "vdp_status" {
			return json.RawMessage(`{"decoded":{"name_table_base_sprite":0,"extended_vram":false}}`), nil
		}
		table := make([]byte, vdpSpriteTableMaxEntries*8)
		setLink := func(index, link int) { table[index*8+2] = byte(link) }
		setLink(0, 1)
		setLink(1, 2)
		setLink(2, 1) // cycle back to sprite 1
		return json.RawMessage(`{"data":"` + base64.StdEncoding.EncodeToString(table) + `"}`), nil
	}
	content := structured(callTool(t, client, "vdp_sprite_table", "{}"))
	chain := content["chain"].(map[string]any)
	if fmt.Sprintf("%v", chain["order"]) != "[0 1 2]" || chain["cycle_detected"] != true {
		t.Fatalf("cycle not detected: %v", chain)
	}
}

func TestVDPSpriteTableRejectsBadPaging(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		t.Fatalf("bridge must not be reached: %s", method)
		return nil, nil
	}
	for _, arguments := range []string{
		`{"offset":80}`,
		`{"count":81}`,
		`{"offset":70,"count":11}`,
	} {
		result := structured(callTool(t, client, "vdp_sprite_table", arguments))
		if result["code"] != "invalid_params" {
			t.Fatalf("%s: code = %v (%v)", arguments, result["code"], result)
		}
	}
}

func TestVDPPaletteExportArtifacts(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		if method != "vdp_mem_read" {
			t.Fatalf("method = %s", method)
		}
		cram := make([]byte, 128)
		cram[2] = 0x02 // entry 1 word 0x0200: blue channel 8 -> clipped 9-bit max blue
		cram[3] = 0x00
		return json.RawMessage(`{"target":"cram","address_space":"315-5313 CRAM","address":0,"length":128,"buffer_size":128,"entry_size":2,"byte_order":"big-endian","encoding":"base64","consistency":"live","data":"` + base64.StdEncoding.EncodeToString(cram) + `"}`), nil
	}

	server := newTestServer(t, client)
	content := structured(postToolCall(t, server, "vdp_palette_export", "{}"))
	summary := content["summary"].(map[string]any)
	if summary["line_count"] != float64(4) || summary["colors_per_line"] != float64(16) {
		t.Fatalf("palette summary wrong: %v", summary)
	}
	artifacts := content["artifacts"].([]any)
	if len(artifacts) != 2 {
		t.Fatalf("expected png and json artifacts: %v", artifacts)
	}
	pngInfo := artifacts[0].(map[string]any)
	preview := structured(postToolCall(t, server, "artifact_preview", fmt.Sprintf(`{"artifact_id":%q,"mode":"hex","length":8}`, pngInfo["id"])))
	if !strings.Contains(strings.ToUpper(fmt.Sprintf("%v", preview)), "89 50 4E 47") {
		t.Fatalf("palette artifact must be a PNG: %v", preview)
	}
	jsonInfo := artifacts[1].(map[string]any)
	download := structured(postToolCall(t, server, "artifact_get", fmt.Sprintf(`{"artifact_id":%q}`, jsonInfo["id"])))
	if !strings.Contains(fmt.Sprintf("%v", download), "application/json") {
		t.Fatalf("json artifact mime lost: %v", download)
	}
}

func TestParseAddressFormats(t *testing.T) {
	cases := map[string]uint64{
		"4660":     0x1234,
		"0x1234":   0x1234,
		"0XFF0000": 0xFF0000,
		"$2000":    0x2000,
		"$ff0000":  0xFF0000,
		"C000h":    0xC000,
		"c000H":    0xC000,
		"0":        0,
	}
	for input, want := range cases {
		got, failure := parseAddress(input)
		if failure != nil || got != want {
			t.Fatalf("parseAddress(%q) = %d, %v; want %d", input, got, failure, want)
		}
	}
	for _, input := range []string{"", "$", "h", "12x34", "-5", "$GG"} {
		if _, failure := parseAddress(input); failure == nil {
			t.Fatalf("parseAddress(%q) accepted invalid input", input)
		}
	}
}

func TestSymbolsLifecycle(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	setArgs := `{"symbols":[{"name":"main","space_id":"m68k-bus","address":"0x2064"},{"name":"lives","address":4242}]}`
	setResult := postToolCall(t, server, "symbols_set", setArgs)
	if structured(setResult)["upserted"] != float64(2) {
		t.Fatalf("upsert count wrong: %v", setResult)
	}

	listResult := postToolCall(t, server, "symbols_list", "{}")
	symbolsList := structured(listResult)["symbols"].([]any)
	first := symbolsList[0].(map[string]any)
	if first["name"] != "lives" || first["address_hex"] != "0x001092" {
		t.Fatalf("symbol ordering/format wrong: %v", first)
	}

	clearResult := postToolCall(t, server, "symbols_clear", "{}")
	if structured(clearResult)["removed"] != float64(2) {
		t.Fatalf("clear count wrong: %v", clearResult)
	}

	badSymbol := postToolCall(t, server, "symbols_set", `{"symbols":[{"name":"x","address":"nope"}]}`)
	if structured(badSymbol)["code"] != "invalid_params" {
		t.Fatalf("invalid address accepted: %v", badSymbol)
	}
}

func TestLegacyToolsCallParity(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		return json.RawMessage(memReadPayload([]byte{9, 9}, "little-endian", 0)), nil
	}
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"z80_read_memory","arguments":{"address":0,"length":2}}}`
	request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8768/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	recorder := newRecorder()
	newTestServer(t, client).Handler().ServeHTTP(recorder, request)
	var envelope struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(recorder.body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if _, present := envelope.Result["structuredContent"]; present {
		t.Fatal("legacy responses must not carry structuredContent")
	}
	textContent := envelope.Result["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(textContent, `"byte_order":"little-endian"`) {
		t.Fatalf("legacy text must embed the full JSON payload: %s", textContent)
	}
}
