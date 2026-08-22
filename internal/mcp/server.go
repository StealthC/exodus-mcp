// Package mcp implements the HTTP and JSON-RPC boundary for Exodus MCP.
package mcp

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	ModernProtocolVersion = "2026-07-28"
	LegacyProtocolVersion = "2025-11-25"
	serverName            = "exodus-mcp"
)

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// NewHandler returns the local HTTP handler. The native bridge is not connected
// yet; the initial tool set exposes that state honestly.
func NewHandler(version string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validOrigin(r.Header.Get("Origin")) {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		if r.URL.Path == "/healthz" {
			health(version, w, r)
			return
		}
		if r.URL.Path != "/mcp" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		dispatch(version, w, r)
	})
}

func health(version string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "bridge_unavailable",
		"version": version,
	})
}

func dispatch(version string, w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, nil, -32700, "unable to read request", nil)
		return
	}

	var request request
	if err := json.Unmarshal(body, &request); err != nil || request.JSONRPC != "2.0" || request.Method == "" {
		writeError(w, http.StatusBadRequest, nil, -32700, "parse error", nil)
		return
	}

	modern, protocolVersion, err := modernProtocol(request.Params)
	if err != nil {
		writeError(w, http.StatusBadRequest, request.ID, -32602, err.Error(), nil)
		return
	}
	if modern {
		dispatchModern(version, w, r, request, protocolVersion)
		return
	}
	dispatchLegacy(version, w, request)
}

func dispatchModern(version string, w http.ResponseWriter, r *http.Request, request request, protocolVersion string) {
	if protocolVersion != ModernProtocolVersion {
		writeError(w, http.StatusBadRequest, request.ID, -32022, "Unsupported protocol version", map[string]any{
			"supported": []string{ModernProtocolVersion, LegacyProtocolVersion},
			"requested": protocolVersion,
		})
		return
	}
	if err := validateModernHeaders(r.Header, request); err != nil {
		writeError(w, http.StatusBadRequest, request.ID, -32020, "Header mismatch", err.Error())
		return
	}

	result, rpcErr, status := modernResult(version, request)
	if rpcErr != nil {
		writeError(w, status, request.ID, rpcErr.Code, rpcErr.Message, rpcErr.Data)
		return
	}
	writeJSON(w, status, response{JSONRPC: "2.0", ID: request.ID, Result: result})
}

func dispatchLegacy(version string, w http.ResponseWriter, request request) {
	var result any
	switch request.Method {
	case "initialize":
		result = map[string]any{
			"protocolVersion": LegacyProtocolVersion,
			"capabilities":    capabilities(),
			"serverInfo":      serverInfo(version),
		}
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
		return
	case "tools/list":
		result = map[string]any{"tools": toolSchemas()}
	case "tools/call":
		result = callTool(request.Params, false)
	default:
		writeError(w, http.StatusOK, request.ID, -32601, "Method not found", nil)
		return
	}
	writeJSON(w, http.StatusOK, response{JSONRPC: "2.0", ID: request.ID, Result: result})
}

func modernResult(version string, request request) (map[string]any, *rpcError, int) {
	var result map[string]any
	switch request.Method {
	case "server/discover":
		result = map[string]any{
			"supportedVersions": []string{ModernProtocolVersion, LegacyProtocolVersion},
			"capabilities":      capabilities(),
			"serverInfo":        serverInfo(version),
			"instructions":      "Use bridge_status before requesting emulator data. The native Exodus bridge is not connected in this build.",
			"ttlMs":             3600000,
			"cacheScope":        "public",
		}
	case "tools/list":
		result = map[string]any{
			"tools":      toolSchemas(),
			"ttlMs":      3600000,
			"cacheScope": "public",
		}
	case "tools/call":
		result = callTool(request.Params, true)
	default:
		return nil, &rpcError{Code: -32601, Message: "Method not found"}, http.StatusNotFound
	}
	result["resultType"] = "complete"
	result["_meta"] = map[string]any{"io.modelcontextprotocol/serverInfo": serverInfo(version)}
	return result, nil, http.StatusOK
}

func capabilities() map[string]any {
	return map[string]any{"tools": map[string]any{"listChanged": false}}
}

func serverInfo(version string) map[string]string {
	return map[string]string{"name": serverName, "version": version}
}

func toolSchemas() []map[string]any {
	return []map[string]any{
		{
			"name":        "bridge_status",
			"description": "Report native Exodus bridge connectivity and supported operations.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "target_info",
			"description": "Report the loaded emulator target. Requires a connected native Exodus bridge.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
	}
}

func callTool(params json.RawMessage, modern bool) map[string]any {
	var call struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &call); err != nil || call.Name == "" {
		return toolError("invalid_params", "tools/call requires a tool name", modern)
	}
	switch call.Name {
	case "bridge_status":
		return toolSuccess(map[string]any{
			"connected":            false,
			"transport":            "windows-named-pipe",
			"supported_operations": []string{},
			"message":              "The Exodus native bridge is not connected yet.",
		}, modern)
	case "target_info":
		return toolError("bridge_unavailable", "The Exodus native bridge is not connected.", modern)
	default:
		return toolError("unknown_tool", "Unknown tool: "+call.Name, modern)
	}
}

func toolSuccess(value any, modern bool) map[string]any {
	result := map[string]any{
		"content":           []map[string]string{{"type": "text", "text": "ok"}},
		"structuredContent": value,
		"isError":           false,
	}
	if !modern {
		delete(result, "structuredContent")
		result["content"] = []map[string]string{{"type": "text", "text": jsonText(value)}}
	}
	return result
}

func toolError(code, message string, modern bool) map[string]any {
	result := map[string]any{
		"content":           []map[string]string{{"type": "text", "text": message}},
		"structuredContent": map[string]string{"code": code, "message": message},
		"isError":           true,
	}
	if !modern {
		delete(result, "structuredContent")
	}
	return result
}

func jsonText(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func modernProtocol(params json.RawMessage) (bool, string, error) {
	var envelope struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if len(params) == 0 || string(params) == "null" {
		return false, "", nil
	}
	if err := json.Unmarshal(params, &envelope); err != nil {
		return false, "", err
	}
	version, present := envelope.Meta["io.modelcontextprotocol/protocolVersion"]
	if !present {
		return false, "", nil
	}
	var value string
	if err := json.Unmarshal(version, &value); err != nil || value == "" {
		return true, "", invalidParamError("invalid protocol version metadata")
	}
	return true, value, nil
}

type invalidParamError string

func (e invalidParamError) Error() string { return string(e) }

func validateModernHeaders(headers http.Header, request request) error {
	if headers.Get("MCP-Protocol-Version") != ModernProtocolVersion {
		return invalidParamError("MCP-Protocol-Version does not match request metadata")
	}
	if headers.Get("Mcp-Method") != request.Method {
		return invalidParamError("Mcp-Method does not match request method")
	}
	if request.Method != "tools/call" {
		return nil
	}
	var call struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(request.Params, &call); err != nil {
		return invalidParamError("invalid tools/call parameters")
	}
	name, err := decodeHeaderValue(headers.Get("Mcp-Name"))
	if err != nil || name != call.Name {
		return invalidParamError("Mcp-Name does not match tools/call name")
	}
	return nil
}

func decodeHeaderValue(value string) (string, error) {
	const prefix = "=?base64?"
	const suffix = "?="
	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, suffix) {
		return value, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(value, prefix), suffix))
	return string(decoded), err
}

func validOrigin(origin string) bool {
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return parsed.Scheme == "http" && (host == "127.0.0.1" || host == "localhost" || host == "::1")
}

func writeError(w http.ResponseWriter, status int, id json.RawMessage, code int, message string, data any) {
	writeJSON(w, status, response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: message, Data: data}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
