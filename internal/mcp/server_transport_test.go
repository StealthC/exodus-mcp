package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StealthC/exodus-mcp/internal/bridge"
)

// atomicBridgeClient is a concurrency-safe bridge stand-in. The shared
// fakeBridgeClient fixture records calls without a lock, so it cannot back a
// handler driven from several goroutines at once.
type atomicBridgeClient struct {
	status bridge.Status
	calls  atomic.Int64
}

func (client *atomicBridgeClient) Status(context.Context) (bridge.Status, error) {
	return client.status, nil
}

func (client *atomicBridgeClient) Execute(context.Context, string, map[string]string) (json.RawMessage, error) {
	client.calls.Add(1)
	return json.RawMessage(`{"system_running":false,"frame_token":1}`), nil
}

// transportPayload is one byte-identical request the transport tests replay.
type transportPayload struct {
	name    string
	body    string
	headers map[string]string
}

func modernToolCall(name, arguments string) transportPayload {
	return transportPayload{
		name: name,
		body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name +
			`","arguments":` + arguments + `,"_meta":{"io.modelcontextprotocol/protocolVersion":"` + ModernProtocolVersion + `"}}}`,
		headers: map[string]string{
			"MCP-Protocol-Version": ModernProtocolVersion,
			"Mcp-Method":           "tools/call",
			"Mcp-Name":             name,
		},
	}
}

func transportPayloads() []transportPayload {
	return []transportPayload{
		modernToolCall("bridge_status", `{}`),
		modernToolCall("emulator_status", `{}`),
		{
			name: "tools/list",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"` + ModernProtocolVersion + `"}}}`,
			headers: map[string]string{
				"MCP-Protocol-Version": ModernProtocolVersion,
				"Mcp-Method":           "tools/list",
			},
		},
		{
			name: "server/discover",
			body: `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"` + ModernProtocolVersion + `"}}}`,
			headers: map[string]string{
				"MCP-Protocol-Version": ModernProtocolVersion,
				"Mcp-Method":           "server/discover",
			},
		},
		{
			name:    "legacy initialize",
			body:    `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + LegacyProtocolVersion + `","capabilities":{}}}`,
			headers: map[string]string{},
		},
		{
			name:    "legacy tools/call",
			body:    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bridge_status","arguments":{}}}`,
			headers: map[string]string{},
		},
	}
}

// encodeTransportHeaders renders one payload as an HTTP/1.1 request, used by the
// pipelining test that writes several requests into one connection.
func encodeTransportHeaders(payload transportPayload, host string, wire *bytes.Buffer) {
	fmt.Fprintf(wire, "POST /mcp HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n", host, len(payload.body))
	for key, value := range payload.headers {
		fmt.Fprintf(wire, "%s: %s\r\n", key, value)
	}
	wire.WriteString("\r\n")
	wire.WriteString(payload.body)
}

// postTransportPayload sends one payload over client, returning the HTTP status
// and response body.
func postTransportPayload(client *http.Client, url string, payload transportPayload) (int, string, error) {
	request, err := http.NewRequest(http.MethodPost, url, strings.NewReader(payload.body))
	if err != nil {
		return 0, "", err
	}
	request.Header.Set("Content-Type", "application/json")
	for key, value := range payload.headers {
		request.Header.Set(key, value)
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return response.StatusCode, "", err
	}
	return response.StatusCode, string(body), nil
}

func transportTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := newTestServer(t, &atomicBridgeClient{status: newFakeStatus()})
	tested := httptest.NewServer(server.Handler())
	t.Cleanup(tested.Close)
	return tested
}

// TestConcurrentCallsNeverProduceParseErrors replays byte-identical payloads
// from several goroutines over pooled keep-alive connections. Every request is
// well formed and never changes, so any -32700 is a transport defect.
func TestConcurrentCallsNeverProduceParseErrors(t *testing.T) {
	tested := transportTestServer(t)
	transport := &http.Transport{MaxConnsPerHost: 8, MaxIdleConnsPerHost: 8, MaxIdleConns: 8}
	client := &http.Client{Transport: transport, Timeout: 60 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)

	payloads := transportPayloads()
	const workers, perWorker = 8, 25

	var (
		mu       sync.Mutex
		failures []string
		total    int
	)
	report := func(message string) {
		mu.Lock()
		defer mu.Unlock()
		if len(failures) < 10 {
			failures = append(failures, message)
		}
	}

	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for index := 0; index < perWorker; index++ {
				payload := payloads[(worker+index)%len(payloads)]
				status, body, err := postTransportPayload(client, tested.URL+"/mcp", payload)
				mu.Lock()
				total++
				mu.Unlock()
				switch {
				case err != nil:
					report(fmt.Sprintf("%s: transport error: %v", payload.name, err))
				case status != http.StatusOK:
					report(fmt.Sprintf("%s: http status %d: %s", payload.name, status, body))
				case strings.Contains(body, `"code":-32700`):
					report(fmt.Sprintf("%s: parse error for a byte-identical valid payload: %s", payload.name, body))
				case !strings.Contains(body, `"result"`):
					report(fmt.Sprintf("%s: response carries no result: %s", payload.name, body))
				}
			}
		}(worker)
	}
	wait.Wait()

	for _, failure := range failures {
		t.Error(failure)
	}
	if total != workers*perWorker {
		t.Fatalf("sent %d requests, want %d", total, workers*perWorker)
	}
}

// TestKeepAliveConnectionServesEveryRequest pins the connection-reuse path: a
// single pooled connection must answer every request correctly, so a later
// request can never be parsed against bytes left by an earlier one.
func TestKeepAliveConnectionServesEveryRequest(t *testing.T) {
	tested := transportTestServer(t)
	var dials atomic.Int64
	transport := &http.Transport{
		MaxConnsPerHost: 1,
		MaxIdleConns:    1,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)

	payloads := transportPayloads()
	for index := 0; index < 6; index++ {
		payload := payloads[index%len(payloads)]
		status, body, err := postTransportPayload(client, tested.URL+"/mcp", payload)
		if err != nil {
			t.Fatalf("request %d (%s): %v", index, payload.name, err)
		}
		if status != http.StatusOK {
			t.Fatalf("request %d (%s): status %d: %s", index, payload.name, status, body)
		}
		if strings.Contains(body, `"code":-32700`) {
			t.Fatalf("request %d (%s): parse error on a reused connection: %s", index, payload.name, body)
		}
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dialed %d connections, want 1 (the test must reuse one keep-alive connection)", got)
	}
}

// TestPipelinedRequestsBothParse writes two complete requests into one write and
// reads both responses: neither may be answered with -32700.
func TestPipelinedRequestsBothParse(t *testing.T) {
	tested := transportTestServer(t)
	host := strings.TrimPrefix(tested.URL, "http://")
	connection, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if err := connection.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}

	payloads := transportPayloads()
	var wire bytes.Buffer
	encodeTransportHeaders(payloads[0], host, &wire)
	encodeTransportHeaders(payloads[1], host, &wire)
	if _, err := connection.Write(wire.Bytes()); err != nil {
		t.Fatal(err)
	}

	reader := bufio.NewReader(connection)
	for index := 0; index < 2; index++ {
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatalf("response %d: %v", index, err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatalf("response %d body: %v", index, err)
		}
		if response.StatusCode != http.StatusOK {
			t.Fatalf("response %d: status %d: %s", index, response.StatusCode, body)
		}
		if strings.Contains(string(body), `"code":-32700`) {
			t.Fatalf("response %d: parse error on a pipelined request: %s", index, body)
		}
	}
}

// TestParseErrorNamesTheFailingRequest pins the diagnostic contract: a request
// the server cannot decode must report why and which call it was, instead of a
// bare "parse error" a client cannot attribute.
func TestParseErrorNamesTheFailingRequest(t *testing.T) {
	server := newTestServer(t, &atomicBridgeClient{status: newFakeStatus()})
	// The body a two-argument helper sends when a tool name lands in the
	// arguments slot: an unquoted token is not JSON.
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"artifact_list","arguments":artifact_list,"_meta":{"io.modelcontextprotocol/protocolVersion":"` + ModernProtocolVersion + `"}}}`
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8768/mcp", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	var envelope struct {
		ID    json.RawMessage `json:"id"`
		Error struct {
			Code    int            `json:"code"`
			Message string         `json:"message"`
			Data    map[string]any `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("response is not JSON: %v: %s", err, response.Body.String())
	}
	if envelope.Error.Code != -32700 {
		t.Fatalf("code = %d, want -32700", envelope.Error.Code)
	}
	if string(envelope.ID) != "7" {
		t.Fatalf("id = %s, want 7 (the parse error must attribute the failing call)", envelope.ID)
	}
	if envelope.Error.Data["method"] != "tools/call" {
		t.Fatalf("data.method = %v, want tools/call: %v", envelope.Error.Data["method"], envelope.Error.Data)
	}
	if envelope.Error.Data["tool"] != "artifact_list" {
		t.Fatalf("data.tool = %v, want artifact_list: %v", envelope.Error.Data["tool"], envelope.Error.Data)
	}
	if reason, _ := envelope.Error.Data["reason"].(string); reason == "" {
		t.Fatalf("data.reason is empty: %v", envelope.Error.Data)
	}
	snippet, _ := envelope.Error.Data["snippet"].(string)
	if !strings.Contains(snippet, `"arguments":artifact_list`) {
		t.Fatalf("data.snippet does not quote the offending payload: %q", snippet)
	}
	if bytes, _ := envelope.Error.Data["body_bytes"].(float64); int(bytes) != len(body) {
		t.Fatalf("data.body_bytes = %v, want %d", envelope.Error.Data["body_bytes"], len(body))
	}
}

// TestOversizedBodyIsRejectedNotTruncated pins the size contract: a body over
// the limit is a size failure with its own code, never a truncated body that
// surfaces as a bogus parse error.
func TestOversizedBodyIsRejectedNotTruncated(t *testing.T) {
	server := newTestServer(t, &atomicBridgeClient{status: newFakeStatus()})
	const head = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bridge_status","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"` + ModernProtocolVersion + `","pad":"`
	body := head + strings.Repeat("A", maxRequestBodyBytes) + `"}}}`
	if len(body) <= maxRequestBodyBytes {
		t.Fatalf("test body is %d bytes, must exceed %d", len(body), maxRequestBodyBytes)
	}
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8768/mcp", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("MCP-Protocol-Version", ModernProtocolVersion)
	request.Header.Set("Mcp-Method", "tools/call")
	request.Header.Set("Mcp-Name", "bridge_status")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusRequestEntityTooLarge, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "-32700") {
		t.Fatalf("oversized body answered as a parse error: %s", response.Body.String())
	}
	var envelope struct {
		Error struct {
			Code    int            `json:"code"`
			Message string         `json:"message"`
			Data    map[string]any `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("response is not JSON: %v: %s", err, response.Body.String())
	}
	if envelope.Error.Code != -32600 {
		t.Fatalf("code = %d, want -32600", envelope.Error.Code)
	}
	if !strings.Contains(envelope.Error.Message, "limit") {
		t.Fatalf("message does not name the limit: %q", envelope.Error.Message)
	}
	if limit, _ := envelope.Error.Data["limit_bytes"].(float64); int(limit) != maxRequestBodyBytes {
		t.Fatalf("data.limit_bytes = %v, want %d", envelope.Error.Data["limit_bytes"], maxRequestBodyBytes)
	}
	if envelope.Error.Data["method"] != "tools/call" {
		t.Fatalf("data.method = %v, want tools/call: %v", envelope.Error.Data["method"], envelope.Error.Data)
	}
}

// TestSalvageRecoversRequestIdentityFromUndecodableBodies covers the diagnostic
// scanner directly: it must only return complete, valid JSON scalars.
func TestSalvageRecoversRequestIdentityFromUndecodableBodies(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		key        string
		wantValue  string
		wantString string
	}{
		{"unquoted token", `{"jsonrpc":"2.0","id":7,"method":"tools/call","arguments":sql}`, "id", `7`, ""},
		{"string id", `{"jsonrpc":"2.0","id":"abc","method":"tools/call"}`, "id", `"abc"`, "abc"},
		{"escaped string", `{"jsonrpc":"2.0","id":1,"method":"tools/call","note":"a\"b","x":}`, "note", `"a\"b"`, `a"b`},
		{"nested name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"artifact_list","arguments":x}}`, "name", `"artifact_list"`, "artifact_list"},
		{"unterminated string", `{"jsonrpc":"2.0","id":1,"method":"tools/ca`, "method", "", ""},
		{"absent key", `{"jsonrpc":"2.0"}`, "id", "", ""},
		{"key without value", `{"jsonrpc":"2.0","id":}`, "id", "", ""},
		{"empty body", ``, "id", "", ""},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			value := salvageValue([]byte(testCase.body), testCase.key)
			if string(value) != testCase.wantValue {
				t.Fatalf("salvageValue(%q) = %q, want %q", testCase.key, value, testCase.wantValue)
			}
			if got := salvageString([]byte(testCase.body), testCase.key); got != testCase.wantString {
				t.Fatalf("salvageString(%q) = %q, want %q", testCase.key, got, testCase.wantString)
			}
		})
	}
}

// TestParseErrorForEmptyBodyKeepsTheContract covers the degenerate case: an
// empty body is the classic "the request body never made it" failure, and it
// must still name that fact.
func TestParseErrorForEmptyBodyKeepsTheContract(t *testing.T) {
	server := newTestServer(t, &atomicBridgeClient{status: newFakeStatus()})
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8768/mcp", strings.NewReader(""))
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if !strings.Contains(response.Body.String(), `"code":-32700`) {
		t.Fatalf("empty body is no longer a parse error: %s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"body_bytes":0`) {
		t.Fatalf("empty body diagnostic does not report its size: %s", response.Body.String())
	}
}
