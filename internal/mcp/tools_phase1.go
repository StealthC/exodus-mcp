package mcp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/StealthC/exodus-mcp/internal/analysis"
	"github.com/StealthC/exodus-mcp/internal/artifact"
)

func phase1ToolSpecs() []toolSpec {
	return []toolSpec{
		{
			name:        "artifact_get",
			description: "Return one artifact's metadata, provenance envelope, and direct loopback download URL (raw bytes are never placed in this response): artifact id, kind, MIME type, size, SHA-256, created_at, expires_at (null when retention is unlimited), the payload's own schema_version when it declares one, and the capture_id when the artifact belongs to a capture. include selects the metadata and provenance sections (both by default).",
			schema: objectSchema(map[string]any{
				"artifact_id": stringProperty("Opaque artifact id returned by a producing tool or artifact_list."),
				"include": map[string]any{
					"type":        "array",
					"description": "Sections to return; omitted means both. \"metadata\" adds the metadata block, \"provenance\" adds the typed provenance envelope.",
					"items":       map[string]any{"type": "string", "enum": []string{"metadata", "provenance"}},
				},
				"context": contextProperty(),
			}, []string{"artifact_id"}),
			run: runArtifactGet,
		},
		{
			name:        "artifact_describe",
			description: "DEPRECATED: use artifact_get with include [\"metadata\",\"provenance\"], which returns the same payload. Returns the full typed provenance envelope of one artifact: address domain (space, requested and effective addresses in decimal and canonical hex, byte length, byte order, raw-byte ordering), owning device, target generation, ROM identity, frame token, CPU run state, capture consistency, and capture time. Artifacts whose producer attached no capture metadata are reported honestly with the provenance_unknown state instead of invented fields. include selects the metadata and provenance sections exactly like artifact_get.",
			schema: objectSchema(map[string]any{
				"artifact_id": stringProperty("Opaque artifact id returned by a producing tool or artifact_list."),
				"include": map[string]any{
					"type":        "array",
					"description": "Sections to return; omitted means both. \"metadata\" adds the metadata block, \"provenance\" adds the typed provenance envelope.",
					"items":       map[string]any{"type": "string", "enum": []string{"metadata", "provenance"}},
				},
				"context": contextProperty(),
			}, []string{"artifact_id"}),
			run: runArtifactDescribe,
		},
		{
			name:        "artifact_list",
			description: "Enumerate the artifacts one analysis context holds, newest discovery for a new session or a lost response. Each descriptor carries artifact_id, kind, mime_type, size_bytes, sha256, created_at, expires_at (null when retention is unlimited), schema_version when the payload declares one, capture_id when the artifact belongs to a capture, and the direct download URL. Filters by kind and capture_id; pages by cursor/limit (default 50, cap 200) and reports total, returned, has_more, and next_cursor (null on the last page).",
			schema: objectSchema(map[string]any{
				"kind":       stringProperty("Exact artifact kind to list, for example \"memory-dump\" or \"vdp-capture-manifest\"."),
				"capture_id": stringProperty("Only artifacts carrying this capture id, including a capture's manifest and its components."),
				"cursor":     stringProperty("next_cursor from a previous artifact_list call; omitted starts at the first page."),
				"limit":      integerProperty(fmt.Sprintf("Page size between 1 and %d (default %d).", artifact.MaxListLimit, artifact.DefaultListLimit), 1),
				"context":    contextProperty(),
			}, nil),
			run: runArtifactList,
		},
		{
			name:        "artifact_preview",
			description: "Render a bounded hex, text, or base64 preview of an artifact without downloading its full bytes.",
			schema: objectSchema(map[string]any{
				"artifact_id": stringProperty("Opaque artifact id."),
				"offset":      integerProperty("Byte offset to start the preview at.", 0),
				"length":      integerProperty(fmt.Sprintf("Maximum preview bytes (default %d, cap %d).", defaultPreviewLen, maxPreviewLen), 0),
				"mode":        artifactPreviewModeVocab.property("Preview rendering (default hex)."),
				"context":     contextProperty(),
			}, []string{"artifact_id"}),
			run: runArtifactPreview,
		},
		{
			name:        "bridge_status",
			description: "Report native Exodus bridge connectivity, plugin version, lifecycle, and supported bridge operations.",
			schema:      objectSchema(map[string]any{}, nil),
			run:         runBridgeStatus,
		},
		{
			name:        "context_close",
			description: "Close an analysis context. The implicit default context cannot be closed; its artifacts stay retrievable during the session. Any process-wide control lock acquired under the context is released and the reason is recorded in the audit stream.",
			schema:      objectSchema(map[string]any{"context_id": stringProperty("Context handle returned by context_create.")}, []string{"context_id"}),
			run:         runContextClose,
		},
		{
			name:        "context_create",
			description: "Create an analysis context that scopes symbols, artifacts, snapshots, and resource provenance. Contexts are application handles, not MCP sessions, and never authorize exclusive emulator control.",
			schema:      objectSchema(map[string]any{"name": stringProperty("Short human-readable context name (max 100 characters).")}, []string{"name"}),
			run:         runContextCreate,
		},
		{
			name:        "context_list",
			description: "List open analysis contexts, including the implicit default context.",
			schema:      objectSchema(map[string]any{}, nil),
			run:         runContextList,
		},
		{
			name:        "emulator_status",
			description: "Report running state plus loaded modules and devices from the connected Exodus instance, with run-state observability: `run_state` is the observed run state (running | paused | unknown), `pause_source` names who caused it (mcp | ui_or_external | breakpoint_or_watchpoint | unknown), `stop_source` answers why execution stopped in the same vocabulary as run_until_* (instrument | external | mcp | none | unknown), and `capture_consistency` is the standardized state-observing object every read tool reports. `last_run_state_change` is the UTC time of the last observed transition. Externally observed transitions (UI pauses, other bridge clients, native stops) are recorded in the audit stream as run_state_change events and never advance target_generation: the generation advances only on successful MCP mutations.",
			schema:      objectSchema(map[string]any{}, nil),
			run:         runEmulatorStatus,
		},
		{
			name:        "memory_dump",
			description: "Dump up to 8 MiB of memory into an immutable artifact carrying a versioned capture-provenance envelope (address domain, byte order, device, target generation, ROM identity, run state, consistency, capture_consistency). Optional capture_mode \"paused\" pauses once before the dump and restores the prior run state, making the artifact a temporally atomic snapshot at the cost of perturbing real-time behavior; the default \"live\" never pauses. Returns a compact summary (address space, effective address, byte length, byte order, capture consistency, and whether the read temporarily paused a running system) plus descriptor; raw bytes stay out of model context.",
			schema: objectSchema(map[string]any{
				"space":        stringProperty("Address space id from memory_spaces_list."),
				"address":      addressProperty(),
				"length":       integerProperty(fmt.Sprintf("Byte length between 1 and %d.", dumpCapBytes), 1),
				"capture_mode": captureModeProperty(),
				"context":      stringProperty("Analysis context that will own the artifact."),
			}, []string{"space", "address", "length"}),
			run: runMemoryDump,
		},
		{
			name:        "memory_read",
			description: fmt.Sprintf("Read at most %d bytes inline with explicit byte-order metadata, effective-address echo, and the standardized capture_consistency object (live when the system runs unpaused, paused when it was already stopped, atomic when the read had to pause it). Optional capture_mode %q pauses once before the read and restores the prior run state, making the sample temporally atomic at the cost of perturbing real-time behavior; the default %q never pauses. Larger ranges must use memory_dump.", inlineReadCapBytes, captureModePaused, captureModeLive),
			schema: objectSchema(map[string]any{
				"space":          stringProperty("Address space id from memory_spaces_list."),
				"address":        addressProperty(),
				"length":         integerProperty(fmt.Sprintf("Byte length between 1 and %d.", inlineReadCapBytes), 1),
				"representation": memoryRepresentationVocab.property("Inline rendering."),
				"decode":         decodeSchemaProperty(),
				"capture_mode":   captureModeProperty(),
				"context":        contextProperty(),
			}, []string{"space", "address", "length"}),
			run: runMemoryRead,
		},
		{
			name:        "memory_spaces_list",
			description: "Enumerate readable address spaces with owner device, size, entry width, permissions, declared byte order, and the processor bus mapping (bus, bus_base, bus_offset) for the loaded target. bus_address = bus_base + bus_offset + space_relative_address; spaces that are not linearly mapped on a CPU bus (VDP buffers) explain why in bus_mapping_note.",
			schema:      objectSchema(map[string]any{}, nil),
			run:         runMemorySpacesList,
		},
		{
			name:        "rom_load",
			description: "Replace the current Mega Drive cartridge with a ROM file visible to Windows, or reset the loaded machine. Reloading the SAME path is the machine-reset equivalent: the module reload reinitializes the system and purges all MCP-managed debug resources (breakpoints, watchpoints, freezes) in one audited invalidation batch. To reset a cartridge that was loaded through the Exodus UI, read its path from emulator_status (rom.path, path_source \"loaded_module\") and pass it back here. Preserves the prior run state unless run is true. Accepts optional expected_target_generation and control_id; a mismatch fails with target_generation_conflict before any native action.",
			schema: objectSchema(map[string]any{
				"path":                       stringProperty("Absolute Windows path to a .bin, .gen, or .md ROM file."),
				"run":                        map[string]any{"type": "boolean", "description": "Run the system after the ROM loads, even if it was paused before."},
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
				"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
			}, []string{"path"}),
			run: runROMLoad,
		},
		{
			name:        "target_info",
			description: "Report emulator identity (plugin version and lifecycle), loaded modules, device summary, the platform baseline, and a light cartridge summary read from the 256-byte header at 0x100 (identified flag, system type, title, serial, region, or an explicit reason when no cartridge is identified). The full parsed header, checksum validation, and memory mapping are available through rom_info.",
			schema:      objectSchema(map[string]any{}, nil),
			run:         runTargetInfo,
		},
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// ROM loading
// ----------------------------------------------------------------------------------------------------------------------
type romLoadArgs struct {
	Path string `json:"path"`
	Run  bool   `json:"run"`
	guardArgs
}

func runROMLoad(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[romLoadArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	path := strings.TrimSpace(parsed.Path)
	if path == "" || strings.ContainsAny(path, "\r\n") {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "path must be one non-empty Windows file path"}, tc.modern)
	}
	payload, before, after, invalidated, failure := performROMLoad(tc, path, parsed.Run, parsed.guard(), "", map[string]any{
		"path": path,
		"run":  parsed.Run,
	}, "rom_load")
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if len(invalidated) > 0 {
		payload["resources_invalidated"] = invalidated
	}
	// rom_load restarts the system in the requested run state; attribute the
	// echoed state to MCP so emulator_status derives the pause source.
	recordStateFromPayload(tc.server, payload, false)
	return okResult(stampGenerations(payload, before, after), tc.modern)
}

// performROMLoad runs the shared cartridge-reload mutation used by rom_load
// and target_reset (hard). The module reload reinitializes the system and
// purges all MCP-managed debug resources (freezes, breakpoints, watchpoints)
// with one audited invalidation batch. toolName is the calling tool for audit
// attribution; contextID is the originating analysis context ("" for
// rom_load, which predates context attribution on this operation).
func performROMLoad(tc toolContext, path string, run bool, guard mutationGuard, contextID string, detail map[string]any, toolName string) (map[string]any, uint64, uint64, []string, *toolFailure) {
	// Machine-bound resources (freezes, managed breakpoints, managed
	// watchpoints) describe the previous cartridge's address map; the plugin
	// purges its debug resources natively and the server purges the rest,
	// collecting one audited invalidation batch for the reload record.
	var invalidated []string
	payload, before, after, failure := tc.server.executeMutation(tc.ctx, mutationCall{
		tool:      toolName,
		operation: "rom_load",
		params:    map[string]string{"path": path, "run": strconv.FormatBool(run)},
		guard:     guard,
		contextID: contextID,
		detail:    detail,
		romAfter:  path,
		prepare: func() *toolFailure {
			invalidated = nil
			for _, id := range tc.server.freezes.ids() {
				invalidated = append(invalidated, id)
			}
			for _, id := range tc.server.debugResourceIDs() {
				invalidated = append(invalidated, fmt.Sprintf("debug_%d", id))
			}
			return nil
		},
		commit: func() {
			server := tc.server
			server.freezes.purge()
			server.purgeDebugResources()
			// The plugin stops a live trace session while the cartridge's
			// module unloads, so the server must report the same end instead of
			// presenting a dead session as live.
			server.retireTraceSession("the cartridge was reloaded, which stops native capture")
			server.setROMPath(path)
		},
		resources: func() []string { return invalidated },
	})
	if failure != nil {
		return nil, 0, 0, nil, failure
	}
	return payload, before, after, invalidated, nil
}

// ----------------------------------------------------------------------------------------------------------------------
// Status and identity
// ----------------------------------------------------------------------------------------------------------------------
func runBridgeStatus(tc toolContext, args json.RawMessage) map[string]any {
	if _, failure := decodeArgs[noArgs](args); failure != nil {
		return failureResult(failure, tc.modern)
	}
	status, err := tc.server.statusFor(tc.ctx)
	if err == nil {
		operations := status.SupportedOperations
		if len(operations) == 0 {
			operations = []string{"status"}
		}
		return okResult(map[string]any{
			"connected":            true,
			"transport":            "windows-named-pipe",
			"plugin_version":       status.PluginVersion,
			"lifecycle":            status.Lifecycle,
			"bridge_enabled":       status.BridgeEnabled,
			"loaded_module_count":  status.LoadedModuleCount,
			"supported_operations": operations,
		}, tc.modern)
	}
	return okResult(map[string]any{
		"connected":            false,
		"transport":            "windows-named-pipe",
		"supported_operations": []string{},
		"message":              "The Exodus native bridge is unavailable: " + err.Error(),
	}, tc.modern)
}

type moduleInfo struct {
	ID           uint64 `json:"id"`
	DisplayName  string `json:"display_name"`
	InstanceName string `json:"instance_name"`
}

type deviceInfo struct {
	InstanceName string `json:"instance_name"`
	DisplayName  string `json:"display_name"`
	Processor    bool   `json:"processor"`
	Memory       bool   `json:"memory"`
}

type emulatorStatusRom struct {
	Loaded          bool   `json:"loaded"`
	SizeBytes       uint64 `json:"size_bytes"`
	PaddedSizeBytes uint64 `json:"padded_size_bytes"`
	Path            string `json:"path"`
	PathSource      string `json:"path_source"`
}

type emulatorStatusData struct {
	SystemRunning bool              `json:"system_running"`
	Modules       []moduleInfo      `json:"modules"`
	Devices       []deviceInfo      `json:"devices"`
	Rom           emulatorStatusRom `json:"rom"`
	StopReason    string            `json:"stop_reason,omitempty"`
	// OneShotRemovals is set server-side (never from the bridge) when the
	// paused-state sweep removed fired one-shot instruments during this read.
	OneShotRemovals []map[string]any `json:"-"`
}

func fetchEmulatorStatus(tc toolContext) (*emulatorStatusData, *toolFailure) {
	payload, failure := tc.server.executeCommand(tc.ctx, "emulator_status", nil)
	if failure != nil {
		return nil, failure
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, &toolFailure{Code: "bridge_error", Message: err.Error()}
	}
	var status emulatorStatusData
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, &toolFailure{Code: "bridge_error", Message: "decode emulator_status payload: " + err.Error()}
	}
	if status.Rom.Loaded {
		tc.server.setROMPath(status.Rom.Path)
	} else {
		tc.server.setROMPath("")
	}
	if !status.SystemRunning {
		// One-shot housekeeping while paused: fired one-shot instruments are
		// removed through the audited mutation path and every proven native
		// stop is attributed to its managed instrument, so pause_source can
		// report breakpoint_or_watchpoint.
		status.OneShotRemovals = tc.server.sweepDebugInstruments(tc)
	}
	// Every passive read of the run state feeds the run-state observation
	// tracker: externally observed transitions land in the audit stream as
	// run_state_change events and never advance target_generation.
	tc.server.runState.observe(tc.server, status.SystemRunning, nil)
	return &status, nil
}

// runStateView renders the attribution and transition metadata of a freshly
// observed run state. A native stop reason reported by the plugin (when it
// exposes one) takes precedence over the derived source.
func runStateView(server *Server, status *emulatorStatusData) (string, string, time.Time, bool) {
	source, note := server.runState.view(status.SystemRunning)
	if !status.SystemRunning && status.StopReason != "" {
		source = pauseSourceBreakpointOrWatchpoint
		note = "The plugin reported a native stop reason: " + status.StopReason
	}
	lastChange, known := server.runState.lastKnownChange()
	return source, note, lastChange, known
}

// stopSourceForRunState answers "why did execution stop" from one observed run
// state, in the same vocabulary run_until_* and the structured debug events
// publish. A running system has no stop; a paused one is attributed to the
// managed instrument that proved the stop, to the MCP action that caused it, or
// to an external actor.
func stopSourceForRunState(pauseSource string, running bool) string {
	if running {
		return stopSourceNone
	}
	switch pauseSource {
	case pauseSourceBreakpointOrWatchpoint:
		return stopSourceInstrument
	case pauseSourceMCP:
		return stopSourceMCP
	case pauseSourceUIOrExternal:
		return stopSourceExternal
	default:
		return stopSourceUnknown
	}
}

func runEmulatorStatus(tc toolContext, args json.RawMessage) map[string]any {
	if _, failure := decodeArgs[noArgs](args); failure != nil {
		return failureResult(failure, tc.modern)
	}
	status, failure := fetchEmulatorStatus(tc)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	modules := status.Modules
	devices := status.Devices
	pauseSource, pauseNote, lastChange, changeKnown := runStateView(tc.server, status)
	result := map[string]any{
		"system_running":      status.SystemRunning,
		"run_state":           runStateLabel(status.SystemRunning),
		"pause_source":        pauseSource,
		"stop_source":         stopSourceForRunState(pauseSource, status.SystemRunning),
		"modules":             modules,
		"devices":             devices,
		"rom":                 status.Rom,
		"capture_consistency": tc.server.captureConsistencyView(buildCaptureConsistency(tc.server, nil, false, false, nil, nil)),
	}
	if !changeKnown {
		// The first observation anchors the timestamp; there is no verified
		// transition to report yet.
		result["last_run_state_change"] = tc.server.runState.firstObservedAt()
		result["run_state_note"] = "First observation; the timestamp marks this observation, not a verified transition."
	} else {
		result["last_run_state_change"] = lastChange
	}
	result["pause_source_note"] = pauseNote
	if len(status.OneShotRemovals) > 0 {
		result["one_shot_removals"] = status.OneShotRemovals
		result["one_shot_note"] = "Fired one-shot instruments were removed through the audited mutation path during this read; see cpu_debug_events_list for the stop evidence."
	}
	return okResult(result, tc.modern)
}

func runTargetInfo(tc toolContext, args json.RawMessage) map[string]any {
	if _, failure := decodeArgs[noArgs](args); failure != nil {
		return failureResult(failure, tc.modern)
	}
	statusPayload, failure := tc.server.executeCommand(tc.ctx, "status", nil)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	emulator, failure := fetchEmulatorStatus(tc)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}

	processors := []string{}
	memories := []string{}
	for _, device := range emulator.Devices {
		if device.Processor {
			processors = append(processors, device.DisplayName)
		}
		if device.Memory {
			memories = append(memories, device.DisplayName)
		}
	}
	modules := emulator.Modules
	return okResult(map[string]any{
		"emulator": map[string]any{
			"name":           "Exodus",
			"plugin_version": statusPayload["plugin_version"],
			"lifecycle":      statusPayload["lifecycle"],
		},
		"system_running": emulator.SystemRunning,
		"modules":        modules,
		"devices": map[string]any{
			"count":         len(emulator.Devices),
			"processors":    processors,
			"memory_spaces": memories,
		},
		"platform": map[string]any{
			"baseline": "sega-mega-drive",
			"assumed":  true,
			"note":     "The baseline is derived from the Mega Drive modules shipped with Exodus; explicit target detection is planned.",
		},
		"rom": targetInfoROM(tc),
	}, tc.modern)
}

// targetInfoROM fills the rom summary from a light header read. Any read or
// decode failure keeps target_info usable and honest by reporting no cartridge
// identified; the full parse lives in rom_info.
func targetInfoROM(tc toolContext) map[string]any {
	fallback := map[string]any{
		"identified": false,
		"note":       "No Mega Drive cartridge header at 0x100; load a ROM with rom_load, then use rom_info for the full parse.",
	}
	header, _, _, _, failure := readBridgeBytes(tc, "m68k-bus", 0x100, 0x100)
	if failure != nil {
		fallback["note"] = "Header read unavailable (" + failure.Message + "); use rom_info once a cartridge is loaded."
		return fallback
	}
	parsed, failure := decodeMDHeader(header)
	if failure != nil {
		fallback["note"] = failure.Message
		return fallback
	}
	title := parsed.Overseas
	if title == "" {
		title = parsed.Domestic
	}
	return map[string]any{
		"identified":  true,
		"system_type": parsed.SystemType,
		"title":       title,
		"serial":      parsed.Serial,
		"region":      parsed.Region,
		"note":        "Header summary; the full parsed header, checksum, and mapping are available through rom_info.",
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// Memory
// ----------------------------------------------------------------------------------------------------------------------
func runMemorySpacesList(tc toolContext, args json.RawMessage) map[string]any {
	if _, failure := decodeArgs[noArgs](args); failure != nil {
		return failureResult(failure, tc.modern)
	}
	payload, failure := tc.server.executeCommand(tc.ctx, "mem_spaces", nil)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	spaces, _ := payload["spaces"].([]any)
	for _, entry := range spaces {
		if space, ok := entry.(map[string]any); ok {
			space["permissions"] = spacePermissions(space)
			annotateSpaceBusMapping(space)
		}
	}
	return okResult(map[string]any{
		"spaces": spaces,
		"byte_order_policy": map[string]string{
			"m68k": "big-endian",
			"z80":  "little-endian",
			"vdp":  "device-specific; reported per space until verified",
			"raw":  "raw bytes preserve address order and are never silently decoded",
		},
		"bus_address_formula": "bus_address = bus_base + bus_offset + space_relative_address",
	}, tc.modern)
}

type decodeRequest struct {
	Type      string `json:"type"`
	ByteOrder string `json:"byte_order"`
}

// cpuMemoryReadArgs is the argument set of the bus-pinned readers
// (m68k_read_memory, z80_read_memory). The address space is the tool's own, so
// a supplied `space` is rejected by the strict decoder instead of being
// decoded and ignored.
type cpuMemoryReadArgs struct {
	Address        any            `json:"address"`
	AddressSpace   string         `json:"address_space"`
	Length         uint64         `json:"length"`
	Representation string         `json:"representation"`
	Decode         *decodeRequest `json:"decode"`
	CaptureMode    string         `json:"capture_mode"`
	Context        string         `json:"context"`
}

type memoryReadArgs struct {
	Space          string         `json:"space"`
	Address        any            `json:"address"`
	AddressSpace   string         `json:"address_space"`
	Length         uint64         `json:"length"`
	Representation string         `json:"representation"`
	Decode         *decodeRequest `json:"decode"`
	CaptureMode    string         `json:"capture_mode"`
	Context        string         `json:"context"`
}

// readRequestEcho carries the caller's requested coordinates so a read that
// translated the address into another domain, or that returned fewer bytes than
// requested, can state both the request and the effective values.
type readRequestEcho struct {
	Address      uint64
	AddressSpace string
	Length       uint64
	HasAddress   bool
	HasLength    bool
}

// apply writes the request echo onto one read or dump summary. The effective
// values already on the summary (effective_address, effective_length) stay the
// authoritative ones; the requested_* fields are what the caller sent.
func (echo readRequestEcho) apply(summary map[string]any, targetSpace string, effectiveAddress, effectiveLength uint64) {
	if echo.HasAddress {
		summary["requested_address"] = echo.Address
		summary["requested_address_hex"] = canonicalHex(echo.Address)
		if echo.AddressSpace != "" {
			summary["requested_address_space"] = echo.AddressSpace
			summary["address_translated"] = echo.AddressSpace != targetSpace
		}
	}
	if echo.HasLength {
		summary["requested_length"] = echo.Length
	}
	summary["effective_address"] = effectiveAddress
	summary["effective_address_hex"] = canonicalHex(effectiveAddress)
	summary["effective_length"] = effectiveLength
	if echo.HasLength {
		summary["length_clamped"] = effectiveLength != echo.Length
	}
}

// readMemoryValue executes mem_read and renders the bounded inline
// representation, returning the value map and any failure. The standardized
// capture_consistency object is attached from the bridge payload.
func readMemoryValue(tc toolContext, spaceID string, address uint64, length uint64, representation string, decode *decodeRequest, window *captureWindow, echo readRequestEcho) (map[string]any, *toolFailure) {
	if length < 1 || length > inlineReadCapBytes {
		return nil, &toolFailure{
			Code:    "length_exceeds_inline_cap",
			Message: fmt.Sprintf("Inline reads are capped at %d bytes; use memory_dump for larger ranges.", inlineReadCapBytes),
			Data:    map[string]any{"inline_cap_bytes": inlineReadCapBytes},
		}
	}
	if failure := memoryRepresentationVocab.validate(representation); failure != nil {
		return nil, failure
	}
	params := map[string]string{
		"space":   spaceID,
		"address": strconv.FormatUint(address, 10),
		"length":  strconv.FormatUint(length, 10),
	}
	payload, failure := tc.server.executeCommand(tc.ctx, "mem_read", params)
	if failure != nil {
		return nil, annotateSpaceRangeFailure(tc, failure, spaceID)
	}
	rawDataBase64, _ := payload["data"].(string)
	byteOrder, _ := payload["byte_order"].(string)
	effective, _ := payload["effective_address"].(float64)
	pausedDuringRead, _ := payload["system_paused_during_read"].(bool)

	raw, err := base64.StdEncoding.DecodeString(rawDataBase64)
	if err != nil {
		return nil, &toolFailure{Code: "bridge_error", Message: "decode base64 memory payload: " + err.Error()}
	}

	value := map[string]any{
		"space_id":                  spaceID,
		"address_space":             spaceID,
		"address":                   address,
		"address_hex":               canonicalHex(address),
		"effective_address":         uint64(effective),
		"effective_address_hex":     canonicalHex(uint64(effective)),
		"length":                    len(raw),
		"byte_order":                byteOrder,
		"system_paused_during_read": pausedDuringRead,
		"capture_consistency":       tc.server.captureConsistencyViewWindow(window, window.consistencyFor(tc.server, payload)),
		"representation":            representation,
	}
	echo.apply(value, spaceID, uint64(effective), uint64(len(raw)))
	annotateAddressPair(value, spaceID, address)
	if width, mask := addressBusWidthMask(spaceID); width != 0 {
		value["address_width_bits"] = width
		value["address_mask_hex"] = canonicalHex(mask)
	}
	switch representation {
	case "hexdump":
		value["hex"] = artifact.HexDump(raw, int64(address))
	case "array_u8":
		values := make([]int, 0, len(raw))
		for _, single := range raw {
			values = append(values, int(single))
		}
		value["values"] = values
	default:
		value["representation"] = "raw_base64"
		value["data_base64"] = base64.StdEncoding.EncodeToString(raw)
	}

	if decode != nil {
		decoded, failure := decodeValues(raw, byteOrder, decode)
		if failure != nil {
			return nil, failure
		}
		value["decoded"] = decoded
	}
	return value, nil
}

// readMemory renders one inline read, honoring the optional capture guard. The
// request echo is omitted: callers that need it use readMemoryWithEcho.
func readMemory(tc toolContext, spaceID string, address uint64, length uint64, representation string, decode *decodeRequest, guard captureGuard) map[string]any {
	return readMemoryWithEcho(tc, spaceID, address, length, representation, decode, guard, readRequestEcho{})
}

// readMemoryWithEcho renders one inline read together with the echo of the
// caller's request.
func readMemoryWithEcho(tc toolContext, spaceID string, address uint64, length uint64, representation string, decode *decodeRequest, guard captureGuard, echo readRequestEcho) map[string]any {
	return withCaptureGuard(tc, guard, func(window *captureWindow) (map[string]any, *toolFailure) {
		return readMemoryValue(tc, spaceID, address, length, representation, decode, window, echo)
	})
}

func runMemoryRead(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[memoryReadArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if _, failure = resolveContext(tc.server, parsed.Context); failure != nil {
		return failureResult(failure, tc.modern)
	}
	guard := captureGuard{Mode: parsed.CaptureMode}
	if failure = guard.resolve(); failure != nil {
		return failureResult(failure, tc.modern)
	}
	address, failure := resolveAddress(parsed.Address, addressSpaceFromArgs(args), parsed.Space)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	echo := readRequestEcho{HasAddress: true, HasLength: parsed.Length != 0, Length: parsed.Length, AddressSpace: addressSpaceFromArgs(args)}
	if requested, failure := parseAddress(parsed.Address); failure == nil {
		echo.Address = requested
	}
	return readMemoryWithEcho(tc, parsed.Space, address, parsed.Length, parsed.Representation, parsed.Decode, guard, echo)
}

func decodeValues(raw []byte, spaceOrder string, decode *decodeRequest) (map[string]any, *toolFailure) {
	width := 0
	signed := false
	switch decode.Type {
	case "u8":
		width = 1
	case "i16":
		width, signed = 2, true
	case "u16":
		width = 2
	case "i32":
		width, signed = 4, true
	case "u32":
		width = 4
	default:
		return nil, &toolFailure{Code: "invalid_params", Message: "decode.type must be u8, u16, u32, i16, or i32"}
	}
	order := decode.ByteOrder
	if order == "" {
		order = spaceOrder
	}
	switch spaceOrder {
	case "not-applicable", "":
		if width > 1 && decode.ByteOrder == "" {
			return nil, &toolFailure{Code: "byte_order_required", Message: "This space declares no multi-byte convention; pass decode.byte_order explicitly."}
		}
		if width > 1 {
			return nil, &toolFailure{Code: "byte_order_unknown", Message: "This space declares no multi-byte convention; only u8 decoding is supported here."}
		}
		order = "not-applicable"
	case "big-endian", "little-endian":
		if order != spaceOrder {
			return nil, &toolFailure{
				Code:    "byte_order_mismatch",
				Message: fmt.Sprintf("The space declares %s; requested %q. Use the declared order.", spaceOrder, decode.ByteOrder),
				Data:    map[string]any{"declared_byte_order": spaceOrder},
			}
		}
	default:
		if width > 1 {
			return nil, &toolFailure{
				Code:    "byte_order_unknown",
				Message: "This space has unknown multi-byte conventions; only u8 decoding is allowed until verified.",
				Data:    map[string]any{"declared_byte_order": spaceOrder},
			}
		}
		order = "not-applicable"
	}

	count := len(raw) / width
	values := make([]int64, 0, count)
	for index := 0; index < count; index++ {
		chunk := raw[index*width : (index+1)*width]
		var combined uint64
		switch order {
		case "little-endian":
			for position := width - 1; position >= 0; position-- {
				combined = combined<<8 | uint64(chunk[position])
			}
		case "big-endian":
			for position := 0; position < width; position++ {
				combined = combined<<8 | uint64(chunk[position])
			}
		default:
			combined = uint64(chunk[0])
		}
		value := int64(combined)
		if signed && combined&(uint64(1)<<uint(width*8-1)) != 0 {
			value = int64(combined) - (int64(1) << uint(width*8))
		}
		values = append(values, value)
	}
	return map[string]any{
		"type":       decode.Type,
		"byte_order": order,
		"width_bits": width * 8,
		"count":      count,
		"values":     values,
	}, nil
}

type memoryDumpArgs struct {
	Space        string `json:"space"`
	Address      any    `json:"address"`
	AddressSpace string `json:"address_space"`
	Length       uint64 `json:"length"`
	CaptureMode  string `json:"capture_mode"`
	Context      string `json:"context"`
}

// memoryDumpValue reads the range, stores the artifact with its capture
// provenance, and renders the bounded summary. The standardized
// capture_consistency object is derived from the read payload; the optional
// capture guard overrides it at the result level.
func memoryDumpValue(tc toolContext, context *analysis.Context, spaceID string, address uint64, length uint64, window *captureWindow, echo readRequestEcho) (map[string]any, *toolFailure) {
	if length < 1 || length > dumpCapBytes {
		return nil, &toolFailure{
			Code:    "length_out_of_range",
			Message: fmt.Sprintf("memory_dump length must be between 1 and %d bytes.", dumpCapBytes),
			Data:    map[string]any{"max_length_bytes": dumpCapBytes},
		}
	}
	params := map[string]string{
		"space":   spaceID,
		"address": strconv.FormatUint(address, 10),
		"length":  strconv.FormatUint(length, 10),
	}
	payload, failure := tc.server.executeCommand(tc.ctx, "mem_read", params)
	if failure != nil {
		return nil, annotateSpaceRangeFailure(tc, failure, spaceID)
	}
	rawDataBase64, _ := payload["data"].(string)
	raw, err := base64.StdEncoding.DecodeString(rawDataBase64)
	if err != nil {
		return nil, &toolFailure{Code: "bridge_error", Message: "decode base64 memory payload: " + err.Error()}
	}
	// One consistency object for this dump: the guard's window object when the
	// caller asked for a paused capture, otherwise the object derived from the
	// read payload. The response and the artifact provenance both use it, so
	// they can never describe different windows.
	consistencyObject := window.consistencyFor(tc.server, payload)
	provenance := captureProvenance(tc.server, "memory-dump", spaceID, address, uint64(len(raw)), payload, time.Now().UTC(), "", consistencyObject)
	stored, err := tc.server.store.PutWithProvenance(context.ID, "memory-dump", "application/octet-stream", raw, provenance)
	if err != nil {
		return nil, &toolFailure{Code: "artifact_error", Message: err.Error()}
	}
	window.track(stored)

	previewLength := int64(96)
	if int64(len(raw)) < previewLength {
		previewLength = int64(len(raw))
	}
	byteOrder, _ := payload["byte_order"].(string)
	effective, _ := payload["effective_address"].(float64)
	pausedDuringRead, _ := payload["system_paused_during_read"].(bool)
	summary := map[string]any{
		"kind":                      "memory-dump",
		"address_space":             spaceID,
		"start_address":             address,
		"start_address_hex":         canonicalHex(address),
		"effective_address":         uint64(effective),
		"effective_address_hex":     canonicalHex(uint64(effective)),
		"byte_length":               len(raw),
		"byte_order":                byteOrder,
		"system_paused_during_read": pausedDuringRead,
		"capture_consistency":       tc.server.captureConsistencyViewWindow(window, consistencyObject),
		"preview_hex":               artifact.HexDump(raw[:previewLength], int64(uint64(effective))),
		"sha256":                    stored.SHA256,
		"provenance_state":          stored.Provenance.State,
	}
	echo.apply(summary, spaceID, uint64(effective), uint64(len(raw)))
	annotateAddressPair(summary, spaceID, address)
	if width, mask := addressBusWidthMask(spaceID); width != 0 {
		summary["address_width_bits"] = width
		summary["address_mask_hex"] = canonicalHex(mask)
	}
	return map[string]any{
		"summary":  summary,
		"artifact": artifactDescriptor(tc.server, stored, context.ID),
	}, nil
}

func runMemoryDump(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[memoryDumpArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	address, failure := resolveAddress(parsed.Address, addressSpaceFromArgs(args), parsed.Space)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	guard := captureGuard{Mode: parsed.CaptureMode}
	if failure = guard.resolve(); failure != nil {
		return failureResult(failure, tc.modern)
	}
	echo := readRequestEcho{HasAddress: true, HasLength: parsed.Length != 0, Length: parsed.Length, AddressSpace: addressSpaceFromArgs(args)}
	if requested, failure := parseAddress(parsed.Address); failure == nil {
		echo.Address = requested
	}
	return withCaptureGuard(tc, guard, func(window *captureWindow) (map[string]any, *toolFailure) {
		return memoryDumpValue(tc, context, parsed.Space, address, parsed.Length, window, echo)
	})
}

// ----------------------------------------------------------------------------------------------------------------------
// Artifacts
// ----------------------------------------------------------------------------------------------------------------------

// artifactDetailIncludeMetadata and artifactDetailIncludeProvenance are the
// include tokens artifact_get accepts; both are on by default so a bare call
// returns the merged artifact_describe payload.
const (
	artifactDetailIncludeMetadata   = "metadata"
	artifactDetailIncludeProvenance = "provenance"
)

type artifactRefArgs struct {
	ArtifactID string   `json:"artifact_id"`
	Context    string   `json:"context"`
	Include    []string `json:"include"`
}

// artifactIncludeSelection resolves the include argument into two switches.
// An empty list means both sections; an unknown token is rejected instead of
// silently ignored.
func artifactIncludeSelection(include []string) (metadata bool, provenance bool, failure *toolFailure) {
	if len(include) == 0 {
		return true, true, nil
	}
	for _, token := range include {
		switch token {
		case artifactDetailIncludeMetadata:
			metadata = true
		case artifactDetailIncludeProvenance:
			provenance = true
		default:
			return false, false, &toolFailure{
				Code:    "invalid_params",
				Message: "include accepts \"metadata\" and \"provenance\"; omit it to receive both",
				Data:    map[string]any{"value": token, "allowed": []string{artifactDetailIncludeMetadata, artifactDetailIncludeProvenance}},
			}
		}
	}
	return metadata, provenance, nil
}

// artifactSummaryView renders one artifact as a discovery descriptor: the facts a
// client needs to decide whether to fetch it, including its retention. Listing
// and capture resolution share it so one artifact always describes itself the
// same way.
func artifactSummaryView(server *Server, stored artifact.Artifact, contextID string) map[string]any {
	view := map[string]any{
		"artifact_id":      stored.ID,
		"kind":             stored.Kind,
		"mime_type":        stored.MimeType,
		"size_bytes":       stored.SizeBytes,
		"sha256":           stored.SHA256,
		"created_at":       stored.CreatedAt,
		"expires_at":       nil,
		"url":              fmt.Sprintf("%s/artifacts/%s?context=%s", server.baseURL, stored.ID, contextID),
		"provenance_state": artifact.ProvenanceStateUnknown,
	}
	if expiry := server.store.ExpiresAt(stored.CreatedAt); expiry != nil {
		view["expires_at"] = *expiry
	}
	if stored.SchemaVersion != "" {
		view["schema_version"] = stored.SchemaVersion
	}
	if stored.Provenance != nil {
		view["provenance_state"] = stored.Provenance.State
		if stored.Provenance.CaptureID != "" {
			view["capture_id"] = stored.Provenance.CaptureID
		}
	}
	return view
}

// artifactMetadataView is the artifactSummaryView metadata block of artifact_get:
// the same facts, plus the owning context.
func artifactMetadataView(server *Server, stored artifact.Artifact, contextID string) map[string]any {
	view := artifactSummaryView(server, stored, contextID)
	view["context_id"] = stored.ContextID
	return view
}

// artifactRetrievalView is the stable download hint returned with artifact_get.
func artifactRetrievalView() map[string]string {
	return map[string]string{
		"hint":  "Fetch the URL directly with curl or a script; HTTP byte ranges are supported. Use artifact_preview for a bounded in-context view.",
		"range": "Range: bytes=<start>-<end>",
	}
}

// runArtifactGet returns one artifact's metadata, provenance envelope, and direct
// download URL. Raw bytes are never placed in this response.
func runArtifactGet(tc toolContext, args json.RawMessage) map[string]any {
	return artifactDetailResult(tc, args, false)
}

func runArtifactDescribe(tc toolContext, args json.RawMessage) map[string]any {
	return artifactDetailResult(tc, args, true)
}

// artifactDetailResult implements artifact_get and its deprecated alias. Both
// return one payload so a caller can switch tools without re-reading fields;
// the alias adds a deprecation note.
func artifactDetailResult(tc toolContext, args json.RawMessage, deprecatedAlias bool) map[string]any {
	parsed, failure := decodeArgs[artifactRefArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	wantMetadata, wantProvenance, failure := artifactIncludeSelection(parsed.Include)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	stored, err := tc.server.store.Metadata(parsed.ArtifactID, context.ID)
	if err != nil {
		return failureResult(&toolFailure{Code: "unknown_artifact", Message: err.Error()}, tc.modern)
	}
	result := map[string]any{
		"artifact_id":      stored.ID,
		"kind":             stored.Kind,
		"mime_type":        stored.MimeType,
		"size_bytes":       stored.SizeBytes,
		"sha256":           stored.SHA256,
		"created_at":       stored.CreatedAt,
		"expires_at":       nil,
		"provenance_state": artifact.ProvenanceStateUnknown,
		"artifact":         artifactDescriptor(tc.server, stored, context.ID),
		"retrieval":        artifactRetrievalView(),
	}
	if expiry := tc.server.store.ExpiresAt(stored.CreatedAt); expiry != nil {
		result["expires_at"] = *expiry
	}
	if stored.SchemaVersion != "" {
		result["schema_version"] = stored.SchemaVersion
	}
	if wantMetadata {
		result["metadata"] = artifactMetadataView(tc.server, stored, context.ID)
	}
	if wantProvenance {
		if stored.Provenance != nil {
			result["provenance"] = tc.server.provenanceEnvelopeView(*stored.Provenance)
			result["provenance_state"] = stored.Provenance.State
			if stored.Provenance.CaptureID != "" {
				result["capture_id"] = stored.Provenance.CaptureID
			}
		} else {
			result["provenance"] = provenanceUnknownView()
		}
	}
	if deprecatedAlias {
		result["deprecated"] = map[string]any{
			"code":             "artifact_describe_deprecated",
			"replacement_tool": "artifact_get",
			"replacement_args": map[string]any{"include": []string{artifactDetailIncludeMetadata, artifactDetailIncludeProvenance}},
			"message":          "artifact_describe is a deprecated alias of artifact_get{include:[\"metadata\",\"provenance\"]} and returns the same payload. It stays available for one release and is removed afterwards.",
		}
	}
	return okResult(result, tc.modern)
}

// ----------------------------------------------------------------------------------------------------------------------
// Artifact listing (roadmap issue #10)
// ----------------------------------------------------------------------------------------------------------------------
type artifactListArgs struct {
	Kind      string `json:"kind"`
	CaptureID string `json:"capture_id"`
	Cursor    string `json:"cursor"`
	Limit     uint64 `json:"limit"`
	Context   string `json:"context"`
}

// runArtifactList enumerates the artifacts of one analysis context so a new
// session can discover what already exists instead of copying ids out of earlier
// responses. Retention is part of every descriptor, so an expiry is visible
// before a download fails.
func runArtifactList(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[artifactListArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.CaptureID != "" && !artifact.ValidCaptureID(parsed.CaptureID) {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "capture_id must be a capture id issued by a capture tool (cap_...)"}, tc.modern)
	}
	limit := int(parsed.Limit)
	if limit <= 0 {
		limit = artifact.DefaultListLimit
	}
	if limit > artifact.MaxListLimit {
		limit = artifact.MaxListLimit
	}
	page, err := tc.server.store.List(artifact.ListQuery{
		ContextID: context.ID,
		Kind:      parsed.Kind,
		CaptureID: parsed.CaptureID,
		Cursor:    parsed.Cursor,
		Limit:     limit,
	})
	if err != nil {
		code := "artifact_error"
		if errors.Is(err, artifact.ErrInvalidCursor) {
			code = "invalid_params"
		}
		return failureResult(&toolFailure{Code: code, Message: err.Error()}, tc.modern)
	}
	views := make([]map[string]any, 0, len(page.Artifacts))
	for _, stored := range page.Artifacts {
		views = append(views, artifactSummaryView(tc.server, stored, context.ID))
	}
	result := map[string]any{
		"artifacts":   views,
		"returned":    len(views),
		"total":       page.Total,
		"has_more":    page.HasMore,
		"next_cursor": nil,
		"context_id":  context.ID,
		"limit":       limit,
	}
	if page.NextCursor != "" {
		result["next_cursor"] = page.NextCursor
	}
	if parsed.Kind != "" {
		result["kind"] = parsed.Kind
	}
	if parsed.CaptureID != "" {
		result["capture_id"] = parsed.CaptureID
	}
	return okResult(result, tc.modern)
}

type artifactPreviewArgs struct {
	ArtifactID string `json:"artifact_id"`
	Offset     uint64 `json:"offset"`
	Length     uint64 `json:"length"`
	Mode       string `json:"mode"`
	Context    string `json:"context"`
}

func runArtifactPreview(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[artifactPreviewArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	mode, failure := artifactPreviewModeVocab.resolve(parsed.Mode, "hex")
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	length := parsed.Length
	if length == 0 {
		length = defaultPreviewLen
	}
	preview, err := tc.server.store.Preview(parsed.ArtifactID, context.ID, int64(parsed.Offset), int64(length), mode)
	if err != nil {
		code := "artifact_error"
		if err == artifact.ErrUnknownArtifact {
			code = "unknown_artifact"
		} else if strings.Contains(err.Error(), "capped at") {
			code = "invalid_params"
		}
		return failureResult(&toolFailure{Code: code, Message: err.Error()}, tc.modern)
	}
	return okResult(preview, tc.modern)
}

// ----------------------------------------------------------------------------------------------------------------------
// Contexts
// ----------------------------------------------------------------------------------------------------------------------
type contextCreateArgs struct {
	Name string `json:"name"`
}

func runContextCreate(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[contextCreateArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, err := tc.server.contexts.Create(parsed.Name)
	if err != nil {
		return failureResult(&toolFailure{Code: "invalid_params", Message: err.Error()}, tc.modern)
	}
	return okResult(map[string]any{"context": contextView(context)}, tc.modern)
}

func runContextList(tc toolContext, args json.RawMessage) map[string]any {
	if _, failure := decodeArgs[noArgs](args); failure != nil {
		return failureResult(failure, tc.modern)
	}
	contexts := tc.server.contexts.List()
	views := make([]map[string]any, 0, len(contexts))
	defaultID := ""
	for _, context := range contexts {
		if context.Default {
			defaultID = context.ID
		}
		views = append(views, contextView(context))
	}
	return okResult(map[string]any{"contexts": views, "default_context": defaultID}, tc.modern)
}

type contextCloseArgs struct {
	ContextID string `json:"context_id"`
}

func runContextClose(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[contextCloseArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, err := tc.server.contexts.Close(parsed.ContextID)
	if err != nil {
		code := "unknown_context"
		if strings.Contains(err.Error(), "default analysis context cannot be closed") {
			code = "cannot_close_default"
		}
		return failureResult(&toolFailure{Code: code, Message: err.Error()}, tc.modern)
	}
	// A control lock acquired under this context ends with it; the drop hook
	// records why.
	tc.server.controls.DropIf(func(lock *analysis.ControlLock) bool {
		return lock.ContextID == context.ID
	}, "context_closed")
	view := contextView(context)
	view["closed"] = true
	return okResult(map[string]any{"context": view}, tc.modern)
}

func contextView(context *analysis.Context) map[string]any {
	return map[string]any{
		"id":         context.ID,
		"name":       context.Name,
		"created_at": context.CreatedAt,
		"default":    context.Default,
	}
}
