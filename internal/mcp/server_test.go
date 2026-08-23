package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/StealthC/exodus-mcp/internal/bridge"
)

type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newRecorder() *recorder            { return &recorder{header: make(http.Header)} }
func (r *recorder) Header() http.Header { return r.header }
func (r *recorder) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(data)
}
func (r *recorder) WriteHeader(status int) { r.status = status }

type recordedCall struct {
	Method string
	Params map[string]string
}

type fakeBridgeClient struct {
	status        bridge.Status
	statusErr     error
	executeFunc   func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error)
	recordedCalls []recordedCall
}

func (client *fakeBridgeClient) Status(context.Context) (bridge.Status, error) {
	if client.statusErr != nil {
		return bridge.Status{}, client.statusErr
	}
	return client.status, nil
}

func (client *fakeBridgeClient) Execute(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
	client.recordedCalls = append(client.recordedCalls, recordedCall{Method: method, Params: params})
	if client.executeFunc == nil {
		return json.RawMessage(`{}`), nil
	}
	return client.executeFunc(ctx, method, params)
}

func newFakeStatus() bridge.Status {
	return bridge.Status{
		ProtocolVersion:     2,
		PluginVersion:       "0.2.0",
		Lifecycle:           "ready",
		BridgeEnabled:       true,
		LoadedModuleCount:   3,
		SupportedOperations: []string{"status", "emulator_status", "mem_spaces", "mem_read", "regs_get", "disasm", "cpu_control", "breakpoint_set", "breakpoint_list", "breakpoint_remove", "watchpoint_set", "watchpoint_list", "watchpoint_remove", "rom_load", "trace_capture"},
	}
}

//----------------------------------------------------------------------------------------------------------------------
// Transport fixtures
//----------------------------------------------------------------------------------------------------------------------

func TestModernDiscover(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8767/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("MCP-Protocol-Version", ModernProtocolVersion)
	request.Header.Set("Mcp-Method", "server/discover")
	recorder := newRecorder()
	NewHandler("test").ServeHTTP(recorder, request)
	if recorder.status != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.status, http.StatusOK)
	}
	if !strings.Contains(recorder.body.String(), `"resultType":"complete"`) {
		t.Fatalf("response missing resultType: %s", recorder.body.String())
	}
}

func TestModernRejectsMissingHeaders(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8767/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	recorder := newRecorder()
	NewHandler("test").ServeHTTP(recorder, request)
	if recorder.status != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.status, http.StatusBadRequest)
	}
	if !strings.Contains(recorder.body.String(), `"code":-32020`) {
		t.Fatalf("response missing HeaderMismatch: %s", recorder.body.String())
	}
}

func TestModernRejectsUnsupportedProtocolVersion(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2024-11-05"}}}`
	request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8767/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("MCP-Protocol-Version", "2024-11-05")
	request.Header.Set("Mcp-Method", "tools/list")
	recorder := newRecorder()
	NewHandler("test").ServeHTTP(recorder, request)
	if recorder.status != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.status, http.StatusBadRequest)
	}
	if !strings.Contains(recorder.body.String(), `"code":-32022`) || !strings.Contains(recorder.body.String(), ModernProtocolVersion) {
		t.Fatalf("response missing UnsupportedProtocolVersionError: %s", recorder.body.String())
	}
}

func TestLegacyInitialize(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{}}}`
	request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8767/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	recorder := newRecorder()
	NewHandler("test").ServeHTTP(recorder, request)
	if recorder.status != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.status, http.StatusOK)
	}
	if !strings.Contains(recorder.body.String(), LegacyProtocolVersion) {
		t.Fatalf("response missing legacy version: %s", recorder.body.String())
	}
}

func TestRejectsForeignOrigin(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8767/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", "https://attacker.example")
	recorder := newRecorder()
	NewHandler("test").ServeHTTP(recorder, request)
	if recorder.status != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.status, http.StatusForbidden)
	}
}

func TestBridgeStatusReportsConnectedPlugin(t *testing.T) {
	result := callTool(t, &fakeBridgeClient{status: newFakeStatus()}, "bridge_status", "{}")
	if result["isError"] == true {
		t.Fatalf("unexpected error result: %v", result)
	}
	content := structured(result)
	for _, key := range []string{"connected", "plugin_version", "loaded_module_count", "supported_operations"} {
		if _, present := content[key]; !present {
			t.Fatalf("structured content missing %s: %v", key, content)
		}
	}
	if content["connected"] != true {
		t.Fatalf("connected = %v, want true", content["connected"])
	}
}

func TestBridgeStatusWithoutBridgeIsHonest(t *testing.T) {
	result := callTool(t, &fakeBridgeClient{statusErr: bridge.ErrUnavailable}, "bridge_status", "{}")
	content := structured(result)
	if content["connected"] != false {
		t.Fatalf("connected = %v, want false", content["connected"])
	}
}

func TestToolsListDeterministicAndComplete(t *testing.T) {
	first := jsonText(toolSchemas())
	second := jsonText(toolSchemas())
	if first != second {
		t.Fatal("tools/list order is not deterministic")
	}
	expected := []string{
		"artifact_get", "artifact_preview", "bridge_status", "context_close",
		"context_create", "context_list", "cpu_trace_capture",
		"m68k_disassemble", "m68k_read_memory", "m68k_registers",
		"memory_dump", "memory_read", "memory_spaces_list",
		"symbols_clear", "symbols_list", "symbols_set",
		"target_info", "z80_disassemble", "z80_read_memory", "z80_registers",
		"emulator_status",
	}
	listed := first
	for _, name := range expected {
		if !strings.Contains(listed, `"`+name+`"`) {
			t.Fatalf("tools/list missing tool %s", name)
		}
	}
	names := make([]string, 0, len(toolRegistry))
	for _, spec := range toolRegistry {
		names = append(names, spec.name)
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("registry not sorted at %q", names[i])
		}
	}
}

func TestEmulatorDataRequiresBridgeOperationSupport(t *testing.T) {
	client := &fakeBridgeClient{status: bridge.Status{ProtocolVersion: 2}}
	result := callTool(t, client, "target_info", "{}")
	content := structured(result)
	if content["code"] != "unsupported_plugin" {
		t.Fatalf("code = %v, want unsupported_plugin", content["code"])
	}
}
