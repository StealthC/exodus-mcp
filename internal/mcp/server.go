// Package mcp implements the HTTP and JSON-RPC boundary for Exodus MCP.
package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/StealthC/exodus-mcp/internal/analysis"
	"github.com/StealthC/exodus-mcp/internal/artifact"
	"github.com/StealthC/exodus-mcp/internal/bridge"
	"github.com/StealthC/exodus-mcp/internal/experiment"
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

	// target is the process-local target revision; controls owns the single
	// optional exclusive control lock; audit is the bounded global target
	// audit stream. schedulerMu serializes every target-mutating operation
	// so precondition validation, native execution, and the generation
	// advance are atomic.
	target      *analysis.Target
	controls    *analysis.ControlRegistry
	audit       *analysis.AuditLog
	schedulerMu sync.Mutex

	// romPath is the last known loaded ROM path, refreshed by emulator
	// status reads and rom_load; "" means unknown.
	romPathMu sync.Mutex
	romPath   string

	// romIdentity caches the file-derived cartridge identity (SHA-256,
	// header, checksum) per file version for artifact provenance and
	// rom_info; the provider is always non-nil after NewServer.
	romIdentity *romIdentityProvider

	// debugMu guards the server-side provenance of MCP-managed breakpoints
	// and watchpoints (the plugin owns the native resources; the server
	// records who created them and when).
	debugMu     sync.Mutex
	breakpoints map[uint64]debugResourceMeta
	watchpoints map[uint64]debugResourceMeta

	// debugEvents is the bounded history of breakpoint/watchpoint stop events.
	debugEventsMu sync.Mutex
	debugEvents   []debugEvent
	nextEventID   uint64

	// statesDir anchors context-scoped system snapshots; empty means
	// os.TempDir()/exodus-mcp/states.
	statesDir string

	// experiments runs operator-authored scripts and fixtures; nil means the
	// experiment_run tool is disabled.
	experiments *experiment.Runner

	// freezes is the process-wide set of server-maintained frozen cell ranges;
	// nil only before NewServer finishes construction.
	freezes *freezeRegistry

	// runState attributes the emulator run state to MCP actions or external
	// actors and records externally observed transitions in the audit stream.
	runState *runStateTracker

	// metrics accumulates per-tool call/error counts and per-artifact-kind
	// counts for the /metrics endpoint.
	metrics *metricsStore

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
	server := &Server{
		version:     version,
		bridge:      client,
		store:       store,
		contexts:    contexts,
		baseURL:     strings.TrimRight(baseURL, "/"),
		target:      analysis.NewTarget(),
		controls:    analysis.NewControlRegistry(),
		audit:       analysis.NewAuditLog(),
		breakpoints: make(map[uint64]debugResourceMeta),
		watchpoints: make(map[uint64]debugResourceMeta),
		freezes:     newFreezeRegistry(),
		runState:    &runStateTracker{},
		romIdentity: newROMIdentityProvider(),
		metrics:     newMetricsStore(),
	}
	// Artifact creation is observed at the store so producers (including the
	// experiment runner, which shares the store) do not need per-call plumbing.
	if store != nil {
		store.OnPut = server.metrics.recordArtifact
	}
	// Every control-lock end (release, expiry, context close, bridge loss)
	// lands in the audit stream with the reason it ended.
	server.controls.SetDropHook(func(lock *analysis.ControlLock, reason string) {
		server.recordAudit(analysis.AuditEntry{
			Tool:      "target_control",
			ContextID: lock.ContextID,
			ControlID: lock.ID,
			Outcome:   analysis.OutcomeLockEvent,
			Detail: map[string]any{
				"event":   "lock_ended",
				"reason":  reason,
				"purpose": lock.Purpose,
			},
		})
	})
	return server
}

// Handler returns the local HTTP handler covering /healthz, /mcp,
// /artifacts/{id}, and /metrics.
func (server *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validOrigin(r.Header.Get("Origin")) {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		switch {
		case r.URL.Path == "/healthz":
			health(server.version, w, r)
		case r.URL.Path == "/metrics":
			metricsHandler(server, w, r)
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

// metricsHandler serves the process metrics snapshot over plain HTTP GET,
// outside the JSON-RPC boundary.
func metricsHandler(server *Server, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, server.metrics.snapshot())
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

// runCommand executes one bridge operation and classifies its failure:
// provable failures (status, support, or native command errors) carry
// ambiguous=false; transport or decode failures that cannot prove whether the
// native action executed carry ambiguous=true.
func (server *Server) runCommand(ctx context.Context, operation string, params map[string]string) (map[string]any, *toolFailure, bool) {
	status, err := server.statusFor(ctx)
	if err != nil {
		// The bridge is unreachable; any exclusive control window ends with
		// the connection, and the reason is recorded in the audit stream.
		server.controls.DropIf(func(*analysis.ControlLock) bool { return true }, "bridge_unavailable")
		return nil, &toolFailure{Code: "bridge_unavailable", Message: "The Exodus native bridge is unavailable: " + err.Error()}, false
	}
	if !status.SupportsOperation(operation) {
		return nil, &toolFailure{
			Code:    "unsupported_plugin",
			Message: "The connected ExodusMcpPlugin does not advertise '" + operation + "'. Update the extension DLL to protocol version 2.",
			Data:    map[string]any{"supported_operations": status.SupportedOperations},
		}, false
	}
	callContext, cancel := context.WithTimeout(ctx, commandTimeout(operation))
	defer cancel()
	data, err := server.bridge.Execute(callContext, operation, params)
	if err != nil {
		var commandErr *bridge.CommandError
		if errors.As(err, &commandErr) {
			return nil, &toolFailure{Code: commandErr.Code, Message: commandErr.Message}, false
		}
		// A transport-class failure means the cached status may describe a
		// dead or restarted bridge; force the next command to re-probe.
		server.invalidateStatusCache()
		return nil, &toolFailure{Code: "bridge_error", Message: err.Error()}, true
	}
	var payload map[string]any
	if len(data) > 0 {
		if err := json.Unmarshal(data, &payload); err != nil {
			// The command executed; an undecodable response means its outcome
			// cannot be proven.
			server.invalidateStatusCache()
			return nil, &toolFailure{Code: "bridge_error", Message: "decode bridge payload: " + err.Error()}, true
		}
	}
	return payload, nil, false
}

// executeCommand runs one read-only bridge operation. A successful read
// re-establishes the target revision after an ambiguous failure window: the
// generation advances because the machine may have changed while unknown.
func (server *Server) executeCommand(ctx context.Context, operation string, params map[string]string) (map[string]any, *toolFailure) {
	payload, failure, _ := server.runCommand(ctx, operation, params)
	if failure == nil {
		server.target.ResynchronizeIfUnknown()
		return payload, nil
	}
	return nil, failure
}

func commandTimeout(operation string) time.Duration {
	switch operation {
	case "rom_load", "state_save", "state_load", "frame_advance", "trace_capture", "soft_reset":
		return 60 * time.Second
	case "mem_read":
		return 30 * time.Second
	default:
		return 15 * time.Second
	}
}

// recordAudit appends one entry to the bounded global target audit stream.
func (server *Server) recordAudit(entry analysis.AuditEntry) {
	server.audit.Record(entry)
}

// currentROMPath returns the last known loaded ROM path, or "" when unknown.
// It is best-effort identity for conflict data, provenance, and staleness.
func (server *Server) currentROMPath() string {
	server.romPathMu.Lock()
	defer server.romPathMu.Unlock()
	return server.romPath
}

// setROMPath records the currently loaded ROM path.
func (server *Server) setROMPath(path string) {
	server.romPathMu.Lock()
	defer server.romPathMu.Unlock()
	server.romPath = path
}

// debugResourceMeta is the server-side provenance of one MCP-managed
// breakpoint or watchpoint; the plugin owns the native resource. OneShot
// marks a server-managed one-shot instrument: the server removes it through
// the audited mutation path once its native hit counter proves a break fired
// (roadmap Phase 9). BreakCounter is the N of break_on_counter (1 when the
// instrument always breaks on every hit); a break fired exactly when
// hit_count is a positive multiple of it.
type debugResourceMeta struct {
	ContextID        string
	ControlID        string
	TargetGeneration uint64
	CreatedAt        time.Time
	ROMPath          string
	OneShot          bool
	BreakCounter     uint64
}

// debugEvent is one structured breakpoint/watchpoint stop event.
type debugEvent struct {
	ID               uint64
	ResourceKind     string
	ResourceID       uint64
	ContextID        string
	CPU              string
	TriggeringPC     uint64
	AddressSpace     string
	WatchedAddress   uint64
	AccessDirection  string
	RequestedLength  uint64
	HitCount         uint64
	TargetGeneration uint64
	FrameToken       *uint64
	Timestamp        time.Time
	ControlFlow      map[string]any // placeholder for future
}

func (server *Server) trackDebugResource(kind string, id uint64, meta debugResourceMeta) {
	server.debugMu.Lock()
	defer server.debugMu.Unlock()
	switch kind {
	case "breakpoint":
		server.breakpoints[id] = meta
	case "watchpoint":
		server.watchpoints[id] = meta
	}
}

func (server *Server) debugResourceMeta(kind string, id uint64) *debugResourceMeta {
	server.debugMu.Lock()
	defer server.debugMu.Unlock()
	var meta debugResourceMeta
	var present bool
	switch kind {
	case "breakpoint":
		meta, present = server.breakpoints[id]
	case "watchpoint":
		meta, present = server.watchpoints[id]
	}
	if !present {
		return nil
	}
	copy := meta
	return &copy
}

func (server *Server) forgetDebugResource(kind string, id uint64) {
	server.debugMu.Lock()
	defer server.debugMu.Unlock()
	switch kind {
	case "breakpoint":
		delete(server.breakpoints, id)
	case "watchpoint":
		delete(server.watchpoints, id)
	}
}

// debugResourceIDs returns the ids of every tracked resource of both kinds,
// for the audited invalidation batch on rom_load.
func (server *Server) debugResourceIDs() []uint64 {
	server.debugMu.Lock()
	defer server.debugMu.Unlock()
	ids := make([]uint64, 0, len(server.breakpoints)+len(server.watchpoints))
	for id := range server.breakpoints {
		ids = append(ids, id)
	}
	for id := range server.watchpoints {
		ids = append(ids, id)
	}
	return ids
}

// purgeDebugResources drops the provenance of every managed debug resource,
// mirroring the plugin-side purge that rom_load performs natively.
func (server *Server) purgeDebugResources() {
	server.debugMu.Lock()
	defer server.debugMu.Unlock()
	server.breakpoints = make(map[uint64]debugResourceMeta)
	server.watchpoints = make(map[uint64]debugResourceMeta)
}

const maxDebugEvents = 100

func (server *Server) pushDebugEvent(event debugEvent) uint64 {
	server.debugEventsMu.Lock()
	defer server.debugEventsMu.Unlock()
	server.nextEventID++
	event.ID = server.nextEventID
	event.Timestamp = time.Now().UTC()
	server.debugEvents = append(server.debugEvents, event)
	if len(server.debugEvents) > maxDebugEvents {
		// Keep the most recent
		server.debugEvents = server.debugEvents[len(server.debugEvents)-maxDebugEvents:]
	}
	return event.ID
}

func (server *Server) listDebugEvents(offset, limit int) ([]debugEvent, int, bool) {
	server.debugEventsMu.Lock()
	defer server.debugEventsMu.Unlock()
	total := len(server.debugEvents)
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}
	if limit <= 0 || limit > total-offset {
		limit = total - offset
	}
	end := offset + limit
	if end > total {
		end = total
	}
	out := make([]debugEvent, end-offset)
	copy(out, server.debugEvents[offset:end])
	truncated := end < total
	return out, total, truncated
}

func (server *Server) debugEventByID(id uint64) *debugEvent {
	server.debugEventsMu.Lock()
	defer server.debugEventsMu.Unlock()
	for i := range server.debugEvents {
		if server.debugEvents[i].ID == id {
			copy := server.debugEvents[i]
			return &copy
		}
	}
	return nil
}

// SetStatesDir overrides the directory that anchors system snapshots.
func (server *Server) SetStatesDir(dir string) {
	server.statesDir = dir
}

// SetExperimentRunner installs the experiment runner backing experiment_run;
// leaving it unset keeps the tool disabled with experiments_disabled.
func (server *Server) SetExperimentRunner(runner *experiment.Runner) {
	server.experiments = runner
}

// StatesDir returns the directory anchoring context-scoped system snapshots.
func (server *Server) StatesDir() string {
	if server.statesDir != "" {
		return server.statesDir
	}
	return filepath.Join(os.TempDir(), "exodus-mcp", "states")
}

// invalidateStatusCache drops any cached plugin status so the next command
// re-probes the bridge instead of trusting a possibly stale snapshot.
func (server *Server) invalidateStatusCache() {
	server.statusMu.Lock()
	defer server.statusMu.Unlock()
	server.statusExpires = time.Time{}
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
