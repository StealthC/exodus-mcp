// Package mcp implements the HTTP and JSON-RPC boundary for Exodus MCP.
package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/StealthC/exodus-mcp/internal/analysis"
	"github.com/StealthC/exodus-mcp/internal/artifact"
	"github.com/StealthC/exodus-mcp/internal/bridge"
)

const (
	// ModernProtocolVersion is the normative MCP revision this server targets.
	ModernProtocolVersion = "2026-07-28"
	// LegacyProtocolVersion is the initial legacy compatibility target.
	LegacyProtocolVersion = "2025-11-25"
	serverName            = "exodus-mcp"
	statusCacheTTL        = 5 * time.Second
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

// Server wires the HTTP boundary, the native bridge client, the artifact
// store, and the analysis-context registry together.
type Server struct {
	version  string
	bridge   bridge.Client
	store    *artifact.Store
	contexts *analysis.Registry
	baseURL  string

	statusMu      sync.Mutex
	statusExpires time.Time
	statusCache   bridge.Status
}

// NewServer constructs the full server. A nil client is treated as
// unavailable; baseURL anchors artifact download links.
func NewServer(version string, client bridge.Client, store *artifact.Store, contexts *analysis.Registry, baseURL string) *Server {
	if client == nil {
		client = bridge.UnavailableClient()
	}
	if baseURL == "" {
		baseURL = "http://127.0.0.1"
	}
	return &Server{
		version:  version,
		bridge:   client,
		store:    store,
		contexts: contexts,
		baseURL:  strings.TrimRight(baseURL, "/"),
	}
}

// Handler returns the local HTTP handler covering /healthz, /mcp, and
// /artifacts/{id}.
func (server *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validOrigin(r.Header.Get("Origin")) {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		switch {
		case r.URL.Path == "/healthz":
			health(server.version, w, r)
		case strings.HasPrefix(r.URL.Path, "/artifacts/"):
			server.store.Handler().ServeHTTP(w, r)
		case r.URL.Path == "/mcp":
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", http.MethodPost)
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			dispatch(server, w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// NewHandler returns the local HTTP handler without an available bridge.
func NewHandler(version string) http.Handler {
	return NewHandlerWithBridge(version, nil)
}

// NewHandlerWithBridge returns the local HTTP handler backed by one native
// bridge client, using throwaway storage. Production callers should construct
// a Server explicitly.
func NewHandlerWithBridge(version string, client bridge.Client) http.Handler {
	store, err := artifact.NewStore(tempArtifactDir())
	if err != nil {
		panic(err)
	}
	return NewServer(version, client, store, analysis.NewRegistry(), "").Handler()
}

// tempArtifactDir returns a session-scoped directory for handler wrappers
// that do not receive an explicit store.
func tempArtifactDir() string {
	dir, err := os.MkdirTemp("", "exodus-mcp-artifacts-")
	if err != nil {
		panic(err)
	}
	return dir
}

func health(version string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": version,
	})
}

func dispatch(server *Server, w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, nil, -32700, "unable to read request", nil)
		return
	}

	var req request
	if err := json.Unmarshal(body, &req); err != nil || req.JSONRPC != "2.0" || req.Method == "" {
		writeError(w, http.StatusBadRequest, nil, -32700, "parse error", nil)
		return
	}

	modern, protocolVersion, err := modernProtocol(req.Params)
	if err != nil {
		writeError(w, http.StatusBadRequest, req.ID, -32602, err.Error(), nil)
		return
	}
	if modern {
		dispatchModern(server, w, r, req, protocolVersion)
		return
	}
	dispatchLegacy(server, w, r, req)
}

func dispatchModern(server *Server, w http.ResponseWriter, r *http.Request, req request, protocolVersion string) {
	if protocolVersion != ModernProtocolVersion {
		writeError(w, http.StatusBadRequest, req.ID, -32022, "Unsupported protocol version", map[string]any{
			"supported": []string{ModernProtocolVersion, LegacyProtocolVersion},
			"requested": protocolVersion,
		})
		return
	}
	if err := validateModernHeaders(r.Header, req); err != nil {
		writeError(w, http.StatusBadRequest, req.ID, -32020, "Header mismatch", err.Error())
		return
	}

	result, rpcErr, status := server.modernResult(r, req)
	if rpcErr != nil {
		writeError(w, status, req.ID, rpcErr.Code, rpcErr.Message, rpcErr.Data)
		return
	}
	writeJSON(w, status, response{JSONRPC: "2.0", ID: req.ID, Result: result})
}

func dispatchLegacy(server *Server, w http.ResponseWriter, r *http.Request, req request) {
	var result any
	switch req.Method {
	case "initialize":
		result = map[string]any{
			"protocolVersion": LegacyProtocolVersion,
			"capabilities":    capabilities(),
			"serverInfo":      server.serverInfo(),
		}
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
		return
	case "tools/list":
		result = map[string]any{"tools": toolSchemas()}
	case "tools/call":
		result = server.callTool(r.Context(), req.Params, false)
	default:
		writeError(w, http.StatusOK, req.ID, -32601, "Method not found", nil)
		return
	}
	writeJSON(w, http.StatusOK, response{JSONRPC: "2.0", ID: req.ID, Result: result})
}

func (server *Server) modernResult(r *http.Request, req request) (map[string]any, *rpcError, int) {
	var result map[string]any
	switch req.Method {
	case "server/discover":
		result = map[string]any{
			"supportedVersions": []string{ModernProtocolVersion, LegacyProtocolVersion},
			"capabilities":      capabilities(),
			"serverInfo":        server.serverInfo(),
			"instructions":      "Call bridge_status before requesting emulator data. Large outputs are delivered as artifacts with bounded inline summaries.",
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
		result = server.callTool(r.Context(), req.Params, true)
	default:
		return nil, &rpcError{Code: -32601, Message: "Method not found"}, http.StatusNotFound
	}
	result["resultType"] = "complete"
	result["_meta"] = map[string]any{"io.modelcontextprotocol/serverInfo": server.serverInfo()}
	return result, nil, http.StatusOK
}

func capabilities() map[string]any {
	return map[string]any{"tools": map[string]any{"listChanged": false}}
}

func (server *Server) serverInfo() map[string]string {
	return map[string]string{"name": serverName, "version": server.version}
}

// statusFor returns the cached plugin status, refreshing it at most once per
// cache interval so composite tools avoid duplicate round trips.
func (server *Server) statusFor(ctx context.Context) (bridge.Status, error) {
	server.statusMu.Lock()
	defer server.statusMu.Unlock()
	if time.Now().Before(server.statusExpires) {
		return server.statusCache, nil
	}
	statusContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	status, err := server.bridge.Status(statusContext)
	if err != nil {
		return bridge.Status{}, err
	}
	server.statusCache = status
	server.statusExpires = time.Now().Add(statusCacheTTL)
	return status, nil
}

func (server *Server) executeCommand(ctx context.Context, operation string, params map[string]string) (map[string]any, *toolFailure) {
	status, err := server.statusFor(ctx)
	if err != nil {
		return nil, &toolFailure{Code: "bridge_unavailable", Message: "The Exodus native bridge is unavailable: " + err.Error()}
	}
	if !status.SupportsOperation(operation) {
		return nil, &toolFailure{
			Code:    "unsupported_plugin",
			Message: "The connected ExodusMcpPlugin does not advertise '" + operation + "'. Update the extension DLL to protocol version 2.",
			Data:    map[string]any{"supported_operations": status.SupportedOperations},
		}
	}
	callContext, cancel := context.WithTimeout(ctx, commandTimeout(operation))
	defer cancel()
	data, err := server.bridge.Execute(callContext, operation, params)
	if err != nil {
		var commandErr *bridge.CommandError
		if errorsAs(err, &commandErr) {
			return nil, &toolFailure{Code: commandErr.Code, Message: commandErr.Message}
		}
		return nil, &toolFailure{Code: "bridge_error", Message: err.Error()}
	}
	var payload map[string]any
	if len(data) > 0 {
		if err := json.Unmarshal(data, &payload); err != nil {
			return nil, &toolFailure{Code: "bridge_error", Message: "decode bridge payload: " + err.Error()}
		}
	}
	return payload, nil
}

func commandTimeout(operation string) time.Duration {
	switch operation {
	case "trace_capture":
		return 60 * time.Second
	case "mem_read":
		return 30 * time.Second
	default:
		return 15 * time.Second
	}
}

// errorsAs avoids importing errors just for As at every call site.
func errorsAs(err error, target **bridge.CommandError) bool {
	for err != nil {
		if typed, ok := err.(*bridge.CommandError); ok {
			*target = typed
			return true
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapper.Unwrap()
	}
	return false
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

func validateModernHeaders(headers http.Header, req request) error {
	if headers.Get("MCP-Protocol-Version") != ModernProtocolVersion {
		return invalidParamError("MCP-Protocol-Version does not match request metadata")
	}
	if headers.Get("Mcp-Method") != req.Method {
		return invalidParamError("Mcp-Method does not match request method")
	}
	if req.Method != "tools/call" {
		return nil
	}
	var call struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(req.Params, &call); err != nil {
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
