// Package mcp implements the HTTP and JSON-RPC boundary for Exodus MCP.
package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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
	"github.com/StealthC/exodus-mcp/internal/tracing"
)

const (
	// ModernProtocolVersion is the normative MCP revision this server targets.
	ModernProtocolVersion = "2026-07-28"
	// LegacyProtocolVersion is the initial legacy compatibility target.
	LegacyProtocolVersion = "2025-11-25"
	serverName            = "exodus-mcp"
	statusCacheTTL        = 5 * time.Second

	// maxRequestBodyBytes bounds one JSON-RPC request envelope. A memory_write
	// or experiment_run payload is the largest legitimate request; the bound
	// keeps a client from streaming unbounded data into memory. A body over the
	// bound is rejected explicitly and never truncated: truncating it turns a
	// well-formed request into undecodable bytes, which the client then sees as
	// an unexplained "parse error".
	maxRequestBodyBytes = 1 << 20

	// parseErrorSnippetBytes is how much of an undecodable body the -32700
	// diagnostic quotes back so the failing payload is identifiable.
	parseErrorSnippetBytes = 160
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
	// debugEventsTotal counts every recorded observation for the process (not
	// counting duplicates folded into an existing event) and
	// debugEventsDropped counts records the capacity cap evicted, so a reader
	// can see a gap instead of inferring completeness from the slice length.
	debugEventsMu      sync.Mutex
	debugEvents        []debugEvent
	debugEventsTotal   uint64
	debugEventsDropped uint64
	nextEventID        uint64

	// statesDir anchors context-scoped system snapshots; empty means
	// os.TempDir()/exodus-mcp/states.
	statesDir string

	// traceSessionsDir anchors durable trace-session manifests; empty means
	// os.TempDir()/exodus-mcp/trace-sessions.
	traceSessionsDir string

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

	// traces owns the single active-or-retained continuous trace session and
	// its bounded server-side event store.
	traces *tracing.Registry

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
		traces:      tracing.NewRegistry(),
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
	// MaxBytesReader, not a bare LimitReader: an oversized body has to fail as
	// oversized. A silent truncation would answer a well-formed request with
	// -32700, the same code a genuinely malformed body earns, leaving the
	// client no way to tell a size problem from its own encoding bug.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBodyBytes))
	if err != nil {
		var oversized *http.MaxBytesError
		if errors.As(err, &oversized) {
			log.Printf("mcp: rejecting request body from %s: larger than the %d-byte limit", r.RemoteAddr, maxRequestBodyBytes)
			data := map[string]any{"limit_bytes": maxRequestBodyBytes}
			appendRequestIdentity(data, body)
			writeError(w, http.StatusRequestEntityTooLarge, salvageID(body), -32600,
				fmt.Sprintf("request body exceeds the %d-byte server limit", maxRequestBodyBytes), data)
			return
		}
		writeError(w, http.StatusBadRequest, nil, -32700, "unable to read request", map[string]any{
			"reason": err.Error(),
		})
		return
	}

	var req request
	if err := json.Unmarshal(body, &req); err != nil {
		server.writeParseError(w, r, body, "invalid JSON: "+err.Error())
		return
	}
	if req.JSONRPC != "2.0" {
		server.writeParseError(w, r, body, fmt.Sprintf("jsonrpc field is %q, want \"2.0\"", req.JSONRPC))
		return
	}
	if req.Method == "" {
		server.writeParseError(w, r, body, "method field is missing or empty")
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

// writeParseError answers an undecodable request with -32700 plus a diagnostic
// that identifies it. A bare "parse error" cannot be acted on: with several
// tools in flight over keep-alive connections, a client cannot tell which call
// failed or why, so a client-side encoding bug looks exactly like a transport
// fault. The diagnostic recovers the id and method from bytes that still carry
// them, quotes the head of the body, and mirrors the same facts into the server
// log.
func (server *Server) writeParseError(w http.ResponseWriter, r *http.Request, body []byte, reason string) {
	data := map[string]any{
		"reason":     reason,
		"body_bytes": len(body),
		"snippet":    bodySnippet(body),
	}
	appendRequestIdentity(data, body)
	method, _ := data["method"].(string)
	log.Printf("mcp: parse error from %s: %s (body %d bytes, method %q)", r.RemoteAddr, reason, len(body), method)
	writeError(w, http.StatusBadRequest, salvageID(body), -32700, "parse error", data)
}

// appendRequestIdentity adds the request identity that survives in an
// undecodable body, so the failure names the call instead of the transport.
func appendRequestIdentity(data map[string]any, body []byte) {
	if method := salvageString(body, "method"); method != "" {
		data["method"] = method
	}
	if tool := salvageString(body, "name"); tool != "" {
		data["tool"] = tool
	}
}

// bodySnippet quotes the head of an undecodable body so the response shows the
// payload the server could not decode.
func bodySnippet(body []byte) string {
	if len(body) <= parseErrorSnippetBytes {
		return string(body)
	}
	return string(body[:parseErrorSnippetBytes]) + "…"
}

// salvageID returns the id of an undecodable body, or nil when the body does
// not carry one. Echoing a recovered id attributes the parse error to the call
// that caused it.
func salvageID(body []byte) json.RawMessage {
	return salvageValue(body, "id")
}

// salvageString returns the string value of the named field in an undecodable
// body, or "" when it is absent or not a string.
func salvageString(body []byte, key string) string {
	value := salvageValue(body, key)
	if len(value) == 0 || value[0] != '"' {
		return ""
	}
	var decoded string
	if err := json.Unmarshal(value, &decoded); err != nil {
		return ""
	}
	return decoded
}

// salvageValue returns the lexically complete JSON value of the first field
// named key anywhere in body, or nil. It exists only for diagnostics: a body
// that does not decode as a whole (a client-side encoding bug such as an
// unquoted argument, or a write cut short before the last request) can still
// identify the request it was meant to carry.
func salvageValue(body []byte, key string) []byte {
	needle := []byte(`"` + key + `"`)
	for search := 0; search < len(body); {
		index := bytes.Index(body[search:], needle)
		if index < 0 {
			return nil
		}
		position := skipJSONSpace(body, search+index+len(needle))
		if position < len(body) && body[position] == ':' {
			if value := scanJSONScalar(body, skipJSONSpace(body, position+1)); value != nil && json.Valid(value) {
				return value
			}
		}
		search += index + len(needle)
	}
	return nil
}

// skipJSONSpace advances over JSON whitespace.
func skipJSONSpace(body []byte, position int) int {
	for position < len(body) {
		switch body[position] {
		case ' ', '\t', '\r', '\n':
			position++
		default:
			return position
		}
	}
	return position
}

// scanJSONScalar returns the complete scalar starting at position, or nil when
// the value is not a scalar or runs past the end of the body.
func scanJSONScalar(body []byte, position int) []byte {
	if position >= len(body) {
		return nil
	}
	if body[position] == '"' {
		for index := position + 1; index < len(body); index++ {
			switch body[index] {
			case '\\':
				index++
			case '"':
				return body[position : index+1]
			}
		}
		return nil
	}
	end := position
	for end < len(body) && strings.IndexByte(jsonScalarTerminators, body[end]) < 0 {
		end++
	}
	if end == position {
		return nil
	}
	return body[position:end]
}

// jsonScalarTerminators ends an unquoted JSON scalar.
const jsonScalarTerminators = ",}] \t\r\n"

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
	case "trace_session_start", "trace_session_drain", "trace_session_stop":
		return 30 * time.Second
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

// currentROMSHA256 returns the loaded cartridge's SHA-256, or "" when no
// readable cartridge is loaded. A caller must never treat "" as a match.
func (server *Server) currentROMSHA256() string {
	facts := server.romIdentity.romFileFacts(server.currentROMPath())
	if !facts.SHA256Available {
		return ""
	}
	return facts.SHA256
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
// hit_count is a positive multiple of it. DeferRemoval keeps the paused-state
// sweep from removing the instrument: a run_until window owns the removal so
// the tool can report the real outcome instead of trusting the background
// sweep.
type debugResourceMeta struct {
	ContextID        string
	ControlID        string
	TargetGeneration uint64
	CreatedAt        time.Time
	ROMPath          string
	OneShot          bool
	DeferRemoval     bool
	BreakCounter     uint64
}

// Provenance vocabulary for a stop's triggering PC. The value is either read
// from the processor registers while the CPU was paused at the stop
// (register_read) or unknown. "Why the CPU stopped" is a separate fact and
// lives in stop_source, never here.
const (
	pcSourceRegisterRead = "register_read"
	pcSourceUnknown      = "unknown"
)

// Provenance vocabulary for why a stop event happened. Every recorded event is
// a managed instrument stop: the server only records a stop it proved with a
// managed breakpoint/watchpoint hit counter. The same four-plus-one values are
// published for emulator_status and run_until_*, so one conditional answers
// "why did execution stop" on every surface (see stopSourceVocab).
const (
	stopSourceInstrument = "instrument"
	stopSourceExternal   = "external"
	stopSourceMCP        = "mcp"
	stopSourceNone       = "none"
	stopSourceUnknown    = "unknown"
)

// Provenance vocabulary for who produced the current run state (pause_source).
// It is a different question from stop_source: pause_source names the actor
// that left the machine in its state, stop_source names why execution stopped.
const (
	pauseSourceBreakpointOrWatchpoint = "breakpoint_or_watchpoint"
	pauseSourceMCP                    = "mcp"
	pauseSourceUIOrExternal           = "ui_or_external"
	pauseSourceUnknown                = "unknown"
)

// eventStopSource names why an event exists from its resource kind. An event is
// only recorded for a managed breakpoint/watchpoint stop, so the same value a
// run_until_* response reports for its own instrument.
func eventStopSource(kind string) string {
	switch kind {
	case "breakpoint", "watchpoint":
		return stopSourceInstrument
	default:
		return stopSourceUnknown
	}
}

// observedDirection derives the direction a stop proves from the access the
// instrument was configured with. A single-direction watchpoint can only fire
// on that direction, and an execution breakpoint always stops execution. An
// "any" watchpoint is ambiguous: the Exodus processor watchpoint API evaluates
// only the access start address and never reports the transfer direction, so
// the observed value stays unknown (nil) instead of repeating the
// configuration.
func observedDirection(configuredAccess string) *string {
	direction := ""
	switch configuredAccess {
	case "read", "write", "execute":
		direction = configuredAccess
	default:
		return nil
	}
	return &direction
}

// debugEvent is one structured breakpoint/watchpoint stop event.
//
// Stop/resume and duplicate-hit semantics: a breaking watchpoint increments its
// native hit counter once per confirmed access and then pauses the CPU. While
// the CPU stays paused no further access can occur, so repeated observations of
// the same resource, hit count, and direction are the same event, not new hits:
// they are folded into RepeatCount with LastSeenAt updated. A resumed CPU
// (cpu_run) produces a new counter value on the next confirmed hit and
// therefore a new event. Events whose counter value cannot be proven are never
// synthesized.
type debugEvent struct {
	ID             uint64
	ResourceKind   string
	ResourceID     uint64
	ContextID      string
	CPU            string
	TriggeringPC   uint64
	AddressSpace   string
	WatchedAddress uint64
	// AccessDirection is the access the instrument was CONFIGURED with
	// ("read"/"write"/"any"/"execute"), never an observation. ObservedDirection
	// is the direction the stop proves, or nil when the core cannot tell (an
	// "any" watchpoint hit). Filters use the observed value.
	AccessDirection   string
	ObservedDirection *string
	RequestedLength   uint64
	HitCount          uint64
	TargetGeneration  uint64
	FrameToken        *uint64
	// TriggeringPCSource explains TriggeringPC: register_read when the PC was
	// read while paused at the stop, unknown when no read succeeded (the
	// numeric field is then meaningless and rendered as null).
	TriggeringPCSource string
	// StopSource explains why execution stopped (instrument | external | mcp),
	// never where the PC came from. Every recorded event is a managed
	// instrument stop.
	StopSource string
	Timestamp  time.Time
	// FirstSeenAt and LastSeenAt bracket a folded duplicate observation.
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	RepeatCount uint64
	// RunState is the observed CPU run state when the event was recorded.
	RunState    string
	ControlFlow map[string]any // placeholder for future
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

// setDebugResourceDeferRemoval marks whether the paused-state housekeeping
// sweep may remove this instrument. A run_until window owns its instrument's
// removal (so it can report the real outcome); when that removal fails, the
// tool clears the flag so the sweep retries instead of leaking the instrument.
func (server *Server) setDebugResourceDeferRemoval(kind string, id uint64, deferRemoval bool) {
	server.debugMu.Lock()
	defer server.debugMu.Unlock()
	targets := server.breakpoints
	if kind == "watchpoint" {
		targets = server.watchpoints
	}
	meta, present := targets[id]
	if !present {
		return
	}
	meta.DeferRemoval = deferRemoval
	targets[id] = meta
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

// pushDebugEvent records one stop observation, folding a repeat of the same
// paused hit (same resource, hit count, and direction) into the existing event
// instead of creating a duplicate record. The native hit counter is the
// identity of a stop: it increments once per confirmed access and strictly
// increases across a resume, so an observation that repeats the counter value
// is the same paused stop even if the reported PC moved after it (for example
// when a later MCP pause reads a different PC). The observed direction and the
// triggering-PC source are always explicit: a producer that cannot prove them
// leaves them unknown rather than copying the configuration.
func (server *Server) pushDebugEvent(event debugEvent) uint64 {
	server.debugEventsMu.Lock()
	defer server.debugEventsMu.Unlock()
	if event.ObservedDirection == nil {
		event.ObservedDirection = observedDirection(event.AccessDirection)
	}
	if event.TriggeringPCSource == "" {
		event.TriggeringPCSource = pcSourceUnknown
	}
	if event.StopSource == "" {
		event.StopSource = eventStopSource(event.ResourceKind)
	}
	now := time.Now().UTC()
	for index := len(server.debugEvents) - 1; index >= 0; index-- {
		existing := &server.debugEvents[index]
		if existing.ResourceKind != event.ResourceKind || existing.ResourceID != event.ResourceID {
			continue
		}
		if existing.HitCount == event.HitCount &&
			existing.AccessDirection == event.AccessDirection && existing.WatchedAddress == event.WatchedAddress &&
			sameOptionalString(existing.ObservedDirection, event.ObservedDirection) {
			existing.RepeatCount++
			existing.LastSeenAt = now
			return existing.ID
		}
		// Only the most recent event of this resource can be a duplicate.
		break
	}
	server.nextEventID++
	event.ID = server.nextEventID
	event.Timestamp = now
	if event.RunState == "" {
		// The server's observed run state at record time; never inferred from
		// the resource kind.
		event.RunState = server.runStateString()
	}
	event.FirstSeenAt = now
	event.LastSeenAt = now
	event.RepeatCount = 0
	server.debugEventsTotal++
	server.debugEvents = append(server.debugEvents, event)
	if len(server.debugEvents) > maxDebugEvents {
		dropped := len(server.debugEvents) - maxDebugEvents
		server.debugEventsDropped += uint64(dropped)
		server.debugEvents = server.debugEvents[dropped:]
	}
	return event.ID
}

func sameOptionalString(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

// debugEventFilter selects retained stop events. Every field is optional; an
// empty filter matches everything.
type debugEventFilter struct {
	ResourceKind string
	ResourceID   uint64
	ContextID    string
	CPU          string
	// Direction filters on the observed access direction, never on the
	// instrument's configuration. "any" matches every event (including events
	// whose observed direction is unknown) and an empty value does not filter.
	// A concrete value never matches an event whose direction could not be
	// observed.
	Direction  string
	EventIDMin uint64
	EventIDMax uint64
}

func (filter debugEventFilter) matches(event debugEvent) bool {
	if filter.ResourceKind != "" && filter.ResourceKind != "any" && event.ResourceKind != filter.ResourceKind {
		return false
	}
	if filter.ResourceID != 0 && event.ResourceID != filter.ResourceID {
		return false
	}
	if filter.ContextID != "" && event.ContextID != filter.ContextID {
		return false
	}
	if filter.CPU != "" && event.CPU != filter.CPU {
		return false
	}
	if filter.Direction != "" && filter.Direction != "any" {
		if event.ObservedDirection == nil || *event.ObservedDirection != filter.Direction {
			return false
		}
	}
	if filter.EventIDMin != 0 && event.ID < filter.EventIDMin {
		return false
	}
	if filter.EventIDMax != 0 && event.ID > filter.EventIDMax {
		return false
	}
	return true
}

// debugEventHistory is the explicit completeness statement of the retained
// history: capacity, records recorded, records dropped, and the id span. The
// scope fields keep the counters consistent with what a query can return:
// retained is the whole ring, scope_retained is the ring restricted to the
// query's context scope, and matching is exactly the number of events the same
// query can page through.
type debugEventHistory struct {
	Capacity      int    `json:"capacity"`
	Scope         string `json:"scope"`
	Retained      int    `json:"retained"`
	ScopeRetained int    `json:"scope_retained"`
	Matching      int    `json:"matching"`
	Recorded      uint64 `json:"recorded"`
	Dropped       uint64 `json:"dropped"`
	FirstEvent    uint64 `json:"first_event_id,omitempty"`
	LastEvent     uint64 `json:"last_event_id,omitempty"`
	Complete      bool   `json:"complete"`
}

// debugEventHistoryFor describes the retained history from the perspective of
// one query. scope names the context scope the query used.
func (server *Server) debugEventHistoryFor(filter debugEventFilter, scope string) debugEventHistory {
	server.debugEventsMu.Lock()
	defer server.debugEventsMu.Unlock()
	history := debugEventHistory{
		Capacity: maxDebugEvents,
		Scope:    scope,
		Retained: len(server.debugEvents),
		Recorded: server.debugEventsTotal,
		Dropped:  server.debugEventsDropped,
		Complete: server.debugEventsDropped == 0,
	}
	// The context scope alone explains how many retained events are even
	// eligible; matching then applies every filter of the query.
	scopeFilter := debugEventFilter{ContextID: filter.ContextID}
	for _, event := range server.debugEvents {
		if scopeFilter.matches(event) {
			history.ScopeRetained++
		}
		if filter.matches(event) {
			history.Matching++
		}
	}
	if len(server.debugEvents) > 0 {
		history.FirstEvent = server.debugEvents[0].ID
		history.LastEvent = server.debugEvents[len(server.debugEvents)-1].ID
	}
	return history
}

// listDebugEvents returns the retained events matching the filter, in capture
// order, with pagination over the filtered set.
func (server *Server) listDebugEvents(filter debugEventFilter, offset, limit int) ([]debugEvent, int, bool) {
	server.debugEventsMu.Lock()
	defer server.debugEventsMu.Unlock()
	matched := make([]debugEvent, 0, len(server.debugEvents))
	for _, event := range server.debugEvents {
		if filter.matches(event) {
			matched = append(matched, event)
		}
	}
	total := len(matched)
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
	out := make([]debugEvent, limit)
	copy(out, matched[offset:end])
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

// retireTraceSession marks the current session stopped because the native side
// no longer captures (cartridge reload, module swap, or a native stop). The
// accumulated events stay queryable; the loss note explains why nothing more
// will arrive.
func (server *Server) retireTraceSession(reason string) *tracing.Session {
	session := server.traces.Current()
	if session == nil || session.Stopped {
		return nil
	}
	session.MarkStopped()
	session.AddLoss(0, 0, 0, []string{"The native trace session stopped because " + reason + "; events accumulated before that remain queryable."})
	return session
}

// SetStatesDir overrides the directory that anchors system snapshots.
func (server *Server) SetStatesDir(dir string) {
	server.statesDir = dir
}

// SetTraceSessionsDir overrides the directory that anchors durable trace
// session manifests.
func (server *Server) SetTraceSessionsDir(dir string) {
	server.traceSessionsDir = dir
}

// TraceSessionsDir returns the directory that anchors durable trace session
// manifests; the default sits beside the snapshot store in the server's
// temporary workspace.
func (server *Server) TraceSessionsDir() string {
	if server.traceSessionsDir != "" {
		return server.traceSessionsDir
	}
	return filepath.Join(os.TempDir(), "exodus-mcp", "trace-sessions")
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
