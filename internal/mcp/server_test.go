package mcp

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
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
