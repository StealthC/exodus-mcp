package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
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
	request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8767/mcp", strings.NewReader(body))
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
	if first["name"] != "lives" || first["address_hex"] != "0x1092" {
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
	request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8767/mcp", strings.NewReader(body))
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
