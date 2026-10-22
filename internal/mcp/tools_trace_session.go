package mcp

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/StealthC/exodus-mcp/internal/analysis"
	"github.com/StealthC/exodus-mcp/internal/tracing"
)

// Continuous trace sessions (roadmap Phase 10). A session runs while the
// emulator keeps executing: the native plugin duty-cycles the processor trace
// into short, sealed segment files (or keeps one rolling segment in
// continuous mode), this server drains sealed segments into a bounded event
// store, and later calls query or export the accumulated events.
//
// Scope boundaries, stated in every response so a reader never over-reads the
// data:
//   - Execution events are per-instruction and come from the engine's own
//     trace file: full fidelity inside a capture window, sampled across
//     windows in "sampled" mode.
//   - Read/write observation ranges can use non-breaking watchpoint counters
//     and, when access_capture is "ranges" or "all", native per-access records
//     with PC, cycle, transferred value, width, and optional registers.
//   - The execution trace has no native address filter. Access-capture ranges
//     are filtered natively, including accesses whose byte width overlaps a
//     watched byte; event-query filters are applied to retained records.

const (
	traceSessionDefaultWindowMs      = 100
	traceSessionMinWindowMs          = 10
	traceSessionMaxWindowMs          = 5000
	traceSessionDefaultIntervalMs    = 10000
	traceSessionMaxIntervalMs        = 60000
	traceSessionDefaultSegmentMs     = 250
	traceSessionMinSegmentMs         = 50
	traceSessionMaxSegmentMs         = 60000
	traceSessionMaxVdpFrames         = 1000000000
	traceSessionDefaultTotalBytes    = 128 << 20
	traceSessionMinTotalBytes        = 1 << 20
	traceSessionMaxTotalBytes        = 1 << 30
	traceSessionDefaultMaxSegments   = 128
	traceSessionMinMaxSegments       = 2
	traceSessionMaxMaxSegments       = 1024
	traceSessionDefaultMaxEvents     = 100000
	traceSessionMaxMaxEvents         = 500000
	traceSessionDefaultCollectBudget = 4 << 20
	traceSessionMaxCollectBudget     = 16 << 20
	traceSessionDrainChunkBytes      = 1 << 20
	traceSessionMaxWatches           = 16
	traceSessionInlineEvents         = 20
	traceSessionMaxInlineEvents      = 200
	traceSessionInlineAddresses      = 20
	traceSessionMaxInlineAddresses   = 256
	traceSessionDefaultAccessBytes   = 64 << 20
	traceSessionMinAccessBytes       = 1 << 20
	traceSessionMaxAccessBytes       = 1 << 30
)

func traceSessionToolSpecs() []toolSpec {
	return []toolSpec{
		{
			name:        "trace_session_start",
			description: "Start a persistent, non-pausing trace session. It remains active until trace_session_stop, processor removal, or an explicitly configured stop_after_vdp_frames threshold; there is no wall-clock expiry, so time spent paused does not consume the frame threshold. The threshold counts completed rendered VDP frames, not instruction executions, and requires a VDP. The monitor may observe the threshold several frames late; vdp_frames_elapsed reports the actual count. Reaching the threshold stops capture, not emulation. The native plugin captures execution trace lines in sampled windows (default) or continuously, and can also record each read/write access. Set access_capture to \"ranges\" to record individual accesses overlapping the configured watches, or \"all\" to record every access; the default \"off\" keeps only aggregate watch counters. Per-access records include monotonic sequence, cycle, PC, direction, width, transferred value, and (by default for ranges) a same-instant register snapshot. Access ranges are filtered natively; execution-trace address filters are post-capture. Storage remains bounded by segment/event/byte caps with explicit loss reporting; the response's loss object states the completeness contract without overpromising at start: loss.complete is true only for a session that has ended (loss.final) in continuous mode with zero loss, so a just-started session reports loss.complete false with the reason session_running, loss.estimated_eviction_risk when the estimated trace write rate exhausts a finite retention cap before the session ends (loss.estimated_eviction carries the horizons, the assumed frame rate, and the rule), and, for sampled mode, loss.capture_is_sampled plus loss.capture (window_ms, interval_ms, duty_cycle). Starting a new session retires the previous one. Accepts optional expected_target_generation and control_id.",
			schema: objectSchema(map[string]any{
				"cpu":                   enumProperty("Processor to trace.", []string{"m68k", "z80"}),
				"mode":                  enumProperty("sampled (default) captures window_ms of every interval_ms and leaves the engine untouched in between; continuous keeps the trace writer enabled and rotates only by segment_ms.", []string{"sampled", "continuous"}),
				"disassemble":           booleanProperty("Ask the engine to disassemble every traced instruction (default true). Disabling lowers overhead but records only PC, cycle, and time."),
				"window_ms":             integerProperty(fmt.Sprintf("Capture window per interval in sampled mode (default %d, range %d-%d).", traceSessionDefaultWindowMs, traceSessionMinWindowMs, traceSessionMaxWindowMs), 1),
				"interval_ms":           integerProperty(fmt.Sprintf("Interval between capture windows (default %d, range window_ms-%d).", traceSessionDefaultIntervalMs, traceSessionMaxIntervalMs), 1),
				"segment_ms":            integerProperty(fmt.Sprintf("Maximum age of one segment file in continuous mode (default %d, range %d-%d). Sampled mode already seals one segment per window.", traceSessionDefaultSegmentMs, traceSessionMinSegmentMs, traceSessionMaxSegmentMs), 1),
				"stop_after_vdp_frames": integerProperty(fmt.Sprintf("Optional completed rendered VDP frame stop threshold; 0/omitted means no automatic frame stop. This counts frames, not instructions, and requires an active VDP (maximum %d). Monitor polling can overshoot; status.vdp_frames_elapsed reports actual frames. Reaching it stops capture, not emulation. Paused emulation does not advance it.", traceSessionMaxVdpFrames), 0),
				"max_total_bytes":       integerProperty(fmt.Sprintf("Retention cap for sealed segment files on disk (default %d, range %d-%d); exceeding it evicts the oldest segments and reports the loss.", traceSessionDefaultTotalBytes, traceSessionMinTotalBytes, traceSessionMaxTotalBytes), 1),
				"max_segments":          integerProperty(fmt.Sprintf("Retention cap in segment files (default %d, range %d-%d).", traceSessionDefaultMaxSegments, traceSessionMinMaxSegments, traceSessionMaxMaxSegments), 1),
				"max_events":            integerProperty(fmt.Sprintf("Server-side event store capacity (default %d, cap %d); evicted events are counted in loss.dropped_events.", traceSessionDefaultMaxEvents, traceSessionMaxMaxEvents), 1),
				"start_guard":           enumProperty("Configuration guard. \"none\" (default) arms tracing while the system keeps running; \"quiet\" stops the system for the configuration calls and restores the prior run state (a sub-millisecond pause, reported as a pause in the response).", []string{"none", "quiet"}),
				"watches": map[string]any{
					"type":        "array",
					"description": fmt.Sprintf("Read/write address ranges (max %d). Non-breaking watchpoint counters are always sampled. With access_capture=\"ranges\", every access whose byte width overlaps a watched byte is recorded individually; execution is never paused.", traceSessionMaxWatches),
					"items": map[string]any{
						"type":                 "object",
						"additionalProperties": false,
						"properties": map[string]any{
							"address": addressProperty(),
							"length":  integerProperty("Watched byte length (default 1).", 1),
							"access":  enumProperty("Access direction to count.", []string{"read", "write", "any"}),
						},
						"required": []string{"address"},
					},
					"maxItems": traceSessionMaxWatches,
				},
				"access_capture":             enumProperty("Per-occurrence read/write capture. \"off\" (default) records only aggregate watch counters; \"ranges\" records every access whose transferred byte width overlaps a configured watch range (native filtering); \"all\" records every access of the processor and is only viable for short windows. Access records carry sequence, cycle, PC, direction, width, transferred value, and an optional same-instant register snapshot.", []string{"off", "ranges", "all"}),
				"access_include_registers":   booleanProperty("Capture a same-instant register snapshot with every access record (default true for ranges, false for all)."),
				"access_max_bytes":           integerProperty(fmt.Sprintf("Retention cap for per-access segment files (default %d, range %d-%d); exceeding it evicts the oldest sealed access segments and reports the loss.", traceSessionDefaultAccessBytes, traceSessionMinAccessBytes, traceSessionMaxAccessBytes), 1),
				"address_space":              stringProperty("Optional domain shared by the watch addresses; omitted means the traced processor bus."),
				"context":                    contextProperty(),
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
				"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
			}, []string{"cpu"}),
			run: runTraceSessionStart,
		},
		{
			name:        "trace_session_status",
			description: "Report the live trace session and, by default, drain every sealed native segment into the server-side event store first. Draining only reads sealed segments and never ends capture: a continuous session keeps tracing across the segment boundary because the plugin re-arms its trace gate after every seal/rotate. The response carries the session configuration, native capture counters, per-segment table, watched read/write counter deltas, the bounded store's totals, and a machine-readable loss object (dropped events, malformed/truncated trace lines, evicted undrained segments). loss.complete is true only when the session has ended (loss.final) and the capture covered the requested window with no gaps: while the session runs it is always false with the reason session_running, and loss.estimated_eviction_risk states whether the estimated write rate will exhaust a finite retention cap before the session ends (loss.estimated_eviction carries the horizons and the rule). A sampled session is never complete, and loss.capture_is_sampled plus loss.capture (mode, window_ms, interval_ms, duty_cycle, untraced_ms_per_interval) and loss.incomplete_reasons state what was actually captured and why it is or is not complete. Native elapsed_ms is wall-clock telemetry only; sessions have no wall-clock auto-expiry. stop_after_vdp_frames/vdp_frames_elapsed count completed VDP rendered frames, independently of instruction-event counts, and do not advance while paused. Never mutates the target and never pauses the system.",
			schema: objectSchema(map[string]any{
				"session_id":           stringProperty("Optional session id; when present it must match the live session."),
				"collect":              booleanProperty("Drain sealed native segments before reporting (default true). Draining never disarms capture: a continuous session keeps tracing across the sealed segment boundary."),
				"max_collect_bytes":    integerProperty(fmt.Sprintf("Per-call drain budget in bytes (default %d, cap %d).", traceSessionDefaultCollectBudget, traceSessionMaxCollectBudget), 1),
				"request_watch_report": booleanProperty("Request the watchpoint counter report and fold its deltas into the store (default true)."),
				"context":              contextProperty(),
			}, nil),
			run: runTraceSessionStatus,
		},
		{
			name:        "trace_session_events",
			description: "Query accumulated trace-session data: bounded execution events and histogram, aggregate watch-counter samples, and—when access_capture was set to \"ranges\" or \"all\"—individual read/write access events with PC, cycle, width, value, and optional registers. Filters and optional JSONL export operate on retained events; access ranges are filtered natively, while execution-address filters are post-capture. Drains native segments first unless collect=false; the drain never ends a continuous session. Events page in capture order by cursor: the first page starts at the oldest retained event and each next_cursor resumes strictly after the last returned event's store sequence, so pages advance to exhaustion instead of repeating the oldest window. " + pagingNote + " loss.complete means the capture covered the requested window with no gaps, which is only decidable once the session has ended (loss.final): a running session reports loss.complete false with the reason session_running, a sampled session reports loss.complete false with capture_is_sampled and its capture duty cycle, and loss.estimated_eviction_risk states whether a finite retention cap will run out first. drained.complete is only about this call's drain cursor, not capture coverage. Never pauses the system.",
			schema: objectSchema(map[string]any{
				"kind":                   enumProperty("Event kind to select.", []string{"execute", "read", "write", "any"}),
				"address_range_start":    addressProperty(),
				"address_range_end":      addressProperty(),
				"cycle_min":              integerProperty("Minimum engine cycle to select.", 0),
				"cycle_max":              integerProperty("Maximum engine cycle to select.", 0),
				"stream":                 enumProperty("Native stream to drain before querying: \"trace\" (per-instruction execution trace) or \"access\" (per-occurrence read/write records). Omitted drains both; events already retained stay queryable either way.", []string{"trace", "access"}),
				"direction":              enumProperty("Access direction to select; access events only.", []string{"read", "write"}),
				"value_equals":           traceValueProperty("Effective-value filter: select access records whose transferred value equals this value. Applied to retained raw events; nothing is dropped from the store."),
				"value_min":              traceValueProperty("Effective-value filter: minimum transferred value (inclusive)."),
				"value_max":              traceValueProperty("Effective-value filter: maximum transferred value (inclusive)."),
				"previous_equals":        traceValueProperty("Select write records whose captured pre-write value equals this value."),
				"pc_start":               addressProperty(),
				"pc_end":                 addressProperty(),
				"resolve_symbols":        booleanProperty("Resolve access-event PCs to context symbols (default true). Resolution applies only when the loaded cartridge's SHA-256 matches the session's; a mismatch suppresses it and says so instead of resolving the wrong ROM's names."),
				"sequence_min":           integerProperty("Minimum engine access sequence to select.", 0),
				"sequence_max":           integerProperty("Maximum engine access sequence to select.", 0),
				"address_space":          stringProperty("Optional domain shared by the range addresses; omitted means the session's processor bus."),
				"limit":                  integerProperty(fmt.Sprintf("Inline event sample size (default %d, cap %d).", traceSessionInlineEvents, traceSessionMaxInlineEvents), 1),
				"include_address_counts": booleanProperty("Include the per-address execution histogram (default true)."),
				"address_limit":          integerProperty(fmt.Sprintf("Inline histogram entries (default %d, cap %d).", traceSessionInlineAddresses, traceSessionMaxInlineAddresses), 1),
				"export":                 booleanProperty("Store every retained matching event as a versioned JSONL artifact (default false). The artifact descriptor reports truncated_by_store (with truncation_reasons) when events were evicted from the bounded store or a sealed segment was evicted before it was drained, so an export is never mistaken for the whole capture."),
				"collect":                booleanProperty("Drain sealed native segments before querying (default true). Draining never disarms capture: a continuous session keeps tracing across the sealed segment boundary."),
				"max_collect_bytes":      integerProperty(fmt.Sprintf("Per-call drain budget in bytes (default %d, cap %d).", traceSessionDefaultCollectBudget, traceSessionMaxCollectBudget), 1),
				"cursor":                 stringProperty("next_cursor from a previous trace_session_events call; resumes strictly after that event's store sequence in capture order. Omit to start at the oldest retained event. Pages advance, so repeated calls never return the same page."),
				"context":                contextProperty(),
			}, nil),
			run: runTraceSessionEvents,
		},
		{
			name:        "trace_session_stop",
			description: "Stop the live trace session: drain the remaining sealed segments, ask the plugin to disable the trace writer, restore the processor's prior trace flags, delete the session's non-breaking watchpoints and its segment files, and report the final totals, watch counters, and loss. The accumulated server-side events stay queryable until the next trace_session_start. Optionally stores the final events as a JSONL artifact. Accepts optional expected_target_generation and control_id.",
			schema: objectSchema(map[string]any{
				"delete_segments":            booleanProperty("Delete the native segment files after the final drain (default true)."),
				"export":                     booleanProperty("Store every retained event as a JSONL artifact (default true)."),
				"max_collect_bytes":          integerProperty(fmt.Sprintf("Final drain budget in bytes (default %d, cap %d).", traceSessionDefaultCollectBudget, traceSessionMaxCollectBudget), 1),
				"context":                    contextProperty(),
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
				"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
			}, nil),
			run: runTraceSessionStop,
		},
		{
			name:        "trace_session_recover",
			description: "List or load durable trace-session manifests left by this or a previous MCP server process. A manifest records the session configuration, the limits that were in force, the ROM identity it was bound to, its explicit loss accounting, its counters, and the artifact ids produced from it, so a restarted server can state exactly what existed and reload whatever raw artifacts still exist. Recovery never claims more than survived: without a recorded event file it restores counters and loss only.",
			schema: objectSchema(map[string]any{
				"session_id": stringProperty("Optional session id to load; when omitted every manifest is listed."),
				"install":    booleanProperty("Install the recovered session as the current queryable session (default false; nothing live is replaced while a session is active)."),
				"max_events": integerProperty("Maximum raw events to reload from the recorded event file (default 20000).", 1),
				"context":    contextProperty(),
			}, nil),
			run: runTraceSessionRecover,
		},
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// Arguments
// ----------------------------------------------------------------------------------------------------------------------
type traceSessionWatchArgs struct {
	Address any    `json:"address"`
	Length  uint64 `json:"length"`
	Access  string `json:"access"`
}

type traceSessionStartArgs struct {
	CPU                    string                  `json:"cpu"`
	Mode                   string                  `json:"mode"`
	Disassemble            *bool                   `json:"disassemble"`
	WindowMs               uint64                  `json:"window_ms"`
	IntervalMs             uint64                  `json:"interval_ms"`
	SegmentMs              uint64                  `json:"segment_ms"`
	StopAfterVdpFrames     uint64                  `json:"stop_after_vdp_frames"`
	MaxTotalBytes          uint64                  `json:"max_total_bytes"`
	MaxSegments            uint64                  `json:"max_segments"`
	MaxEvents              uint64                  `json:"max_events"`
	StartGuard             string                  `json:"start_guard"`
	Watches                []traceSessionWatchArgs `json:"watches"`
	AccessCapture          string                  `json:"access_capture"`
	AccessIncludeRegisters *bool                   `json:"access_include_registers"`
	AccessMaxBytes         uint64                  `json:"access_max_bytes"`
	AddressSpace           string                  `json:"address_space"`
	Context                string                  `json:"context"`
	guardArgs
}

type traceSessionStatusArgs struct {
	SessionID          string `json:"session_id"`
	Collect            *bool  `json:"collect"`
	MaxCollectBytes    uint64 `json:"max_collect_bytes"`
	RequestWatchReport *bool  `json:"request_watch_report"`
	Context            string `json:"context"`
}

type traceSessionEventsArgs struct {
	Kind                 string `json:"kind"`
	AddressRangeStart    any    `json:"address_range_start"`
	AddressRangeEnd      any    `json:"address_range_end"`
	CycleMin             uint64 `json:"cycle_min"`
	CycleMax             uint64 `json:"cycle_max"`
	Stream               string `json:"stream"`
	Direction            string `json:"direction"`
	ValueEquals          *any   `json:"value_equals"`
	ValueMin             *any   `json:"value_min"`
	ValueMax             *any   `json:"value_max"`
	PreviousEquals       *any   `json:"previous_equals"`
	PCStart              any    `json:"pc_start"`
	PCEnd                any    `json:"pc_end"`
	ResolveSymbols       *bool  `json:"resolve_symbols"`
	SequenceMin          uint64 `json:"sequence_min"`
	SequenceMax          uint64 `json:"sequence_max"`
	AddressSpace         string `json:"address_space"`
	Limit                uint64 `json:"limit"`
	IncludeAddressCounts *bool  `json:"include_address_counts"`
	AddressLimit         uint64 `json:"address_limit"`
	Export               bool   `json:"export"`
	Collect              *bool  `json:"collect"`
	MaxCollectBytes      uint64 `json:"max_collect_bytes"`
	Cursor               string `json:"cursor"`
	Context              string `json:"context"`
}

type traceSessionStopArgs struct {
	DeleteSegments  *bool  `json:"delete_segments"`
	Export          *bool  `json:"export"`
	MaxCollectBytes uint64 `json:"max_collect_bytes"`
	Context         string `json:"context"`
	guardArgs
}

// ----------------------------------------------------------------------------------------------------------------------
// Handlers
// ----------------------------------------------------------------------------------------------------------------------
func runTraceSessionStart(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[traceSessionStartArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.CPU != "m68k" && parsed.CPU != "z80" {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "cpu must be m68k or z80"}, tc.modern)
	}
	mode := parsed.Mode
	if mode == "" {
		mode = "sampled"
	}
	if mode != "sampled" && mode != "continuous" {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "mode must be sampled or continuous"}, tc.modern)
	}
	startGuard := parsed.StartGuard
	if startGuard == "" {
		startGuard = "none"
	}
	if startGuard != "none" && startGuard != "quiet" {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "start_guard must be none or quiet"}, tc.modern)
	}
	disassemble := true
	if parsed.Disassemble != nil {
		disassemble = *parsed.Disassemble
	}

	windowMs, failure := traceSessionBounded(parsed.WindowMs, traceSessionDefaultWindowMs, traceSessionMinWindowMs, traceSessionMaxWindowMs, "window_ms")
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	intervalMs, failure := traceSessionBounded(parsed.IntervalMs, traceSessionDefaultIntervalMs, windowMs, traceSessionMaxIntervalMs, "interval_ms")
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	segmentMs, failure := traceSessionBounded(parsed.SegmentMs, traceSessionDefaultSegmentMs, traceSessionMinSegmentMs, traceSessionMaxSegmentMs, "segment_ms")
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.StopAfterVdpFrames > traceSessionMaxVdpFrames {
		return failureResult(&toolFailure{Code: "invalid_params", Message: fmt.Sprintf("stop_after_vdp_frames must be at most %d", traceSessionMaxVdpFrames)}, tc.modern)
	}
	maxTotalBytes, failure := traceSessionBounded(parsed.MaxTotalBytes, traceSessionDefaultTotalBytes, traceSessionMinTotalBytes, traceSessionMaxTotalBytes, "max_total_bytes")
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	maxSegments, failure := traceSessionBounded(parsed.MaxSegments, traceSessionDefaultMaxSegments, traceSessionMinMaxSegments, traceSessionMaxMaxSegments, "max_segments")
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	maxEvents, failure := traceSessionBounded(parsed.MaxEvents, traceSessionDefaultMaxEvents, 1, traceSessionMaxMaxEvents, "max_events")
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if len(parsed.Watches) > traceSessionMaxWatches {
		return failureResult(&toolFailure{Code: "invalid_params", Message: fmt.Sprintf("watches accepts at most %d ranges", traceSessionMaxWatches)}, tc.modern)
	}
	accessCapture := parsed.AccessCapture
	if accessCapture == "" {
		accessCapture = "off"
	}
	switch accessCapture {
	case "off", "ranges", "all":
	default:
		return failureResult(&toolFailure{Code: "invalid_params", Message: "access_capture must be off, ranges, or all"}, tc.modern)
	}
	if accessCapture == "ranges" && len(parsed.Watches) == 0 {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "access_capture \"ranges\" needs at least one watch range to filter on"}, tc.modern)
	}
	accessIncludeRegisters := accessCapture == "ranges"
	if parsed.AccessIncludeRegisters != nil {
		accessIncludeRegisters = *parsed.AccessIncludeRegisters
	}
	accessMaxBytes, failure := traceSessionBounded(parsed.AccessMaxBytes, traceSessionDefaultAccessBytes, traceSessionMinAccessBytes, traceSessionMaxAccessBytes, "access_max_bytes")
	if failure != nil {
		return failureResult(failure, tc.modern)
	}

	targetSpace := parsed.CPU + "-bus"
	watches := make([]tracing.Watch, 0, len(parsed.Watches))
	watchParams := map[string]string{}
	for index, watch := range parsed.Watches {
		address, addressFailure := resolveAddress(watch.Address, parsed.AddressSpace, targetSpace)
		if addressFailure != nil {
			return failureResult(&toolFailure{Code: "invalid_params", Message: fmt.Sprintf("watches[%d].address: %s", index, addressFailure.Message)}, tc.modern)
		}
		length := watch.Length
		if length == 0 {
			length = 1
		}
		access := watch.Access
		if access == "" {
			access = "any"
		}
		if access != "read" && access != "write" && access != "any" {
			return failureResult(&toolFailure{Code: "invalid_params", Message: fmt.Sprintf("watches[%d].access must be read, write, or any", index)}, tc.modern)
		}
		if _, mask := addressBusWidthMask(targetSpace); mask != 0 && (address > mask || length-1 > mask-address) {
			return failureResult(&toolFailure{
				Code:    "invalid_params",
				Message: fmt.Sprintf("watches[%d] is outside the %s address bus (%s)", index, targetSpace, canonicalHex(mask)),
			}, tc.modern)
		}
		watches = append(watches, tracing.Watch{Address: address, Length: length, Access: access})
		prefix := fmt.Sprintf("watch%d_", index)
		watchParams[prefix+"address"] = strconv.FormatUint(address, 10)
		watchParams[prefix+"length"] = strconv.FormatUint(length, 10)
		watchParams[prefix+"access"] = access
	}
	watchParams["watch_count"] = strconv.Itoa(len(watches))

	sessionID := newTraceSessionID()
	params := map[string]string{
		"cpu":                   parsed.CPU,
		"mode":                  mode,
		"disassemble":           strconv.FormatBool(disassemble),
		"window_ms":             strconv.FormatUint(windowMs, 10),
		"interval_ms":           strconv.FormatUint(intervalMs, 10),
		"segment_ms":            strconv.FormatUint(segmentMs, 10),
		"stop_after_vdp_frames": strconv.FormatUint(parsed.StopAfterVdpFrames, 10),
		"max_total_bytes":       strconv.FormatUint(maxTotalBytes, 10),
		"max_segments":          strconv.FormatUint(maxSegments, 10),
		"start_guard":           startGuard,
		"session_id":            sessionID,

		"access_capture":           accessCapture,
		"access_include_registers": strconv.FormatBool(accessIncludeRegisters),
		"access_max_bytes":         strconv.FormatUint(accessMaxBytes, 10),
	}
	for key, value := range watchParams {
		params[key] = value
	}

	config := tracing.Config{
		CPU:                parsed.CPU,
		Mode:               mode,
		Disassemble:        disassemble,
		WindowMs:           windowMs,
		IntervalMs:         intervalMs,
		SegmentMs:          segmentMs,
		StopAfterVdpFrames: parsed.StopAfterVdpFrames,
		MaxTotalBytes:      maxTotalBytes,
		MaxSegments:        maxSegments,
		MaxEvents:          maxEvents,
		Watches:            watches,

		AccessCapture:          accessCapture,
		AccessIncludeRegisters: accessIncludeRegisters,
		AccessMaxBytes:         accessMaxBytes,
	}
	var created *tracing.Session
	var retired *tracing.Session
	payload, before, after, failure := tc.server.executeMutation(tc.ctx, mutationCall{
		tool:      "trace_session_start",
		operation: "trace_session_start",
		params:    params,
		guard:     parsed.guard(),
		contextID: context.ID,
		detail: map[string]any{
			"cpu":                   parsed.CPU,
			"mode":                  mode,
			"disassemble":           disassemble,
			"window_ms":             windowMs,
			"interval_ms":           intervalMs,
			"segment_ms":            segmentMs,
			"stop_after_vdp_frames": parsed.StopAfterVdpFrames,
			"max_total_bytes":       maxTotalBytes,
			"max_segments":          maxSegments,
			"max_events":            maxEvents,
			"start_guard":           startGuard,
			"watches":               watches,
			"session_id":            sessionID,
			"access_capture":        accessCapture,
			"access_max_bytes":      accessMaxBytes,
		},
		commit: func() {
			// executeMutation advances the target revision before running
			// commit, so the observed generation here is the post-start value.
			created = tracing.NewSession(sessionID, context.ID, parsed.CPU, parsed.CPU+"-bus", config)
			created.MarkStarted(tc.server.target.Generation(), tc.server.currentROMPath())
			created.MarkROMIdentity(tc.server.currentROMSHA256())
			retired = tc.server.traces.Replace(created)
		},
	})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}

	// Surface retention bounds before capture; session lifetime is manual unless
	// the caller opts into a frame limit.
	result := map[string]any{
		"session":     traceSessionSummary(tc, created, payload),
		"native":      payload,
		"limitations": traceSessionLimitations(),
		"loss":        traceSessionLossView(created),
		"volume":      traceSessionVolume(created),
		"recovery":    traceSessionManifestPersist(tc, created, payload),
	}
	if accessCapture != "off" {
		if _, supported := payload["access"].(map[string]any); !supported {
			result["access_warning"] = "The plugin did not report a per-access stream, so access_capture had no effect; redeploy the plugin built from this repository (trace_session_status exposes the access object when the native side supports it)."
		}
	}
	if retired != nil {
		result["retired_session"] = map[string]any{
			"id":              retired.ID,
			"retained_events": retired.Retained(),
			"totals":          retired.Totals(),
			"note":            "Starting a session retires the previous one; its retained events were dropped from memory and are no longer queryable.",
		}
	}
	return okResult(stampGenerations(result, before, after), tc.modern)
}

func runTraceSessionStatus(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[traceSessionStatusArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	session, failure := currentTraceSession(tc, parsed.SessionID)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	collect := true
	if parsed.Collect != nil {
		collect = *parsed.Collect
	}
	budget, failure := traceSessionCollectBudget(parsed.MaxCollectBytes)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	drained, failure := collectTraceSession(tc, session, budget, collect, "")
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	status, failure := traceSessionNativeStatus(tc)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	requestWatch := true
	if parsed.RequestWatchReport != nil {
		requestWatch = *parsed.RequestWatchReport
	}
	if requestWatch {
		recordTraceSessionWatches(session, status)
	}
	return okResult(map[string]any{
		"session":     traceSessionSummary(tc, session, status),
		"native":      status,
		"drained":     drained,
		"loss":        traceSessionLossView(session),
		"volume":      traceSessionVolume(session),
		"recovery":    traceSessionManifestPersist(tc, session, status),
		"limitations": traceSessionLimitations(),
	}, tc.modern)
}

func runTraceSessionEvents(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[traceSessionEventsArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	session, failure := currentTraceSession(tc, "")
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if context.ID != session.ContextID {
		return failureResult(&toolFailure{
			Code:    "context_mismatch",
			Message: fmt.Sprintf("the live trace session belongs to context %q, not %q", session.ContextID, context.ID),
			Data:    map[string]any{"session_context": session.ContextID},
		}, tc.modern)
	}
	filter, failure := traceSessionFilter(*parsed, session)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	collect := true
	if parsed.Collect != nil {
		collect = *parsed.Collect
	}
	budget, failure := traceSessionCollectBudget(parsed.MaxCollectBytes)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	drained, failure := collectTraceSession(tc, session, budget, collect, parsed.Stream)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	status, failure := traceSessionNativeStatus(tc)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	recordTraceSessionWatches(session, status)

	limit := int(parsed.Limit)
	if limit <= 0 {
		limit = traceSessionInlineEvents
	}
	if limit > traceSessionMaxInlineEvents {
		limit = traceSessionMaxInlineEvents
	}
	// A cursor resumes strictly after one store sequence. The store sequence is
	// this server's monotonic event number, so a drain between pages inserts
	// new events after the cursor instead of shifting the page boundary the way
	// a row offset in a bounded ring would.
	afterSequence := uint64(0)
	if parsed.Cursor != "" {
		cursorSession, cursorSequence, failure := parseTraceEventsCursor(parsed.Cursor)
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		if cursorSession != session.ID {
			return failureResult(invalidCursorFailure(fmt.Sprintf("this cursor pages session %q, not %q", cursorSession, session.ID)), tc.modern)
		}
		afterSequence = cursorSequence
	}
	sampleFilter := filter
	sampleFilter.Limit = limit
	if afterSequence != 0 {
		sampleFilter.HasAfterSequence = true
		sampleFilter.AfterSequence = afterSequence
	}
	page := session.SelectPage(sampleFilter)
	sample := page.Events
	inline := make([]map[string]any, 0, len(sample))
	for _, event := range sample {
		inline = append(inline, traceEventView(event))
	}
	nextCursor := ""
	if page.Remaining > len(inline) && len(sample) > 0 {
		nextCursor = encodeCursor(traceEventsCursorPrefix,
			session.ID, strconv.FormatUint(sample[len(sample)-1].StoreSequence, 10))
	}
	paging := pagingPage{
		Returned:   len(inline),
		Total:      page.Total,
		Remaining:  page.Remaining - len(inline),
		NextCursor: nextCursor,
	}
	resolveSymbols := true
	if parsed.ResolveSymbols != nil {
		resolveSymbols = *parsed.ResolveSymbols
	}
	symbolView := traceSessionSymbolView(tc, session, context, sample, inline, resolveSymbols)

	result := map[string]any{
		"session":     traceSessionSummary(tc, session, status),
		"native":      status,
		"drained":     drained,
		"events":      inline,
		"event_count": len(inline),
		"loss":        traceSessionLossView(session),
		"filters":     traceFilterView(filter, session.AddressSpace),
		"symbols":     symbolView,
		"recovery":    traceSessionManifestPersist(tc, session, status),
		"limitations": traceSessionLimitations(),
		"paging": map[string]any{
			"returned":                 paging.Returned,
			"total":                    paging.Total,
			"truncated":                paging.hasMore(),
			"has_more":                 paging.hasMore(),
			"next_cursor":              nil,
			"order":                    "store_sequence_asc",
			"oldest_retained_sequence": page.OldestSequence,
			"newest_retained_sequence": page.NewestSequence,
			"cursor":                   nil,
		},
	}
	if paging.hasMore() {
		result["paging"].(map[string]any)["next_cursor"] = paging.NextCursor
	}
	if parsed.Cursor != "" {
		result["paging"].(map[string]any)["cursor"] = parsed.Cursor
		// A cursor whose events were evicted from the bounded store resumes at
		// the oldest retained event; say how many rows that skipped instead of
		// presenting a silent hole.
		if page.OldestSequence > afterSequence+1 {
			result["paging"].(map[string]any)["skipped_evicted"] = page.OldestSequence - afterSequence - 1
		}
	}
	includeCounts := true
	if parsed.IncludeAddressCounts != nil {
		includeCounts = *parsed.IncludeAddressCounts
	}
	if includeCounts {
		addressLimit := int(parsed.AddressLimit)
		if addressLimit <= 0 {
			addressLimit = traceSessionInlineAddresses
		}
		if addressLimit > traceSessionMaxInlineAddresses {
			addressLimit = traceSessionMaxInlineAddresses
		}
		counts, distinct := session.AddressHistogram(addressLimit)
		views := make([]map[string]any, 0, len(counts))
		for _, count := range counts {
			view := map[string]any{
				"address":       count.Address,
				"address_hex":   count.AddressHex,
				"address_space": count.AddressSpace,
				"count":         count.Count,
			}
			annotateAddressPair(view, count.AddressSpace, count.Address)
			views = append(views, view)
		}
		result["address_counts"] = views
		result["address_summary"] = map[string]any{
			"distinct_addresses": distinct,
			"returned":           len(views),
			"bounded_by":         "max_events",
		}
	}
	if parsed.Export {
		artifactDesc, failure := exportTraceSessionEvents(tc, context, session, filter, "trace-session-jsonl")
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		result["artifact"] = artifactDesc
	}
	paging.apply(result)
	return okResult(result, tc.modern)
}

// parseTraceEventsCursor decodes the (session id, store sequence) cursor of one
// trace_session_events enumeration.
func parseTraceEventsCursor(raw string) (string, uint64, *toolFailure) {
	parts, failure := decodeCursor(raw, traceEventsCursorPrefix, 2)
	if failure != nil {
		return "", 0, failure
	}
	sequence, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || parts[0] == "" {
		return "", 0, invalidCursorFailure(fmt.Sprintf("%q is not a cursor this server issued", raw))
	}
	return parts[0], sequence, nil
}

func runTraceSessionStop(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[traceSessionStopArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	session, failure := currentTraceSession(tc, "")
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if context.ID != session.ContextID {
		return failureResult(&toolFailure{
			Code:    "context_mismatch",
			Message: fmt.Sprintf("the live trace session belongs to context %q, not %q", session.ContextID, context.ID),
			Data:    map[string]any{"session_context": session.ContextID},
		}, tc.modern)
	}
	budget, failure := traceSessionCollectBudget(parsed.MaxCollectBytes)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	// Drain before stopping so the final window is not lost, and take one
	// last watch reading while the native session still exists.
	if _, failure := collectTraceSession(tc, session, budget, true, ""); failure != nil {
		return failureResult(failure, tc.modern)
	}
	if status, statusFailure := traceSessionNativeStatus(tc); statusFailure == nil {
		recordTraceSessionWatches(session, status)
	}
	deleteSegments := true
	if parsed.DeleteSegments != nil {
		deleteSegments = *parsed.DeleteSegments
	}
	payload, before, after, failure := tc.server.executeMutation(tc.ctx, mutationCall{
		tool:      "trace_session_stop",
		operation: "trace_session_stop",
		params: map[string]string{
			"delete_segments": strconv.FormatBool(deleteSegments),
		},
		guard:     parsed.guard(),
		contextID: context.ID,
		detail: map[string]any{
			"session_id":      session.ID,
			"delete_segments": deleteSegments,
		},
		commit: func() {
			session.MarkStopped()
		},
	})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	recordTraceSessionWatches(session, payload)

	result := map[string]any{
		"session":     traceSessionSummary(tc, session, payload),
		"native":      payload,
		"loss":        traceSessionLossView(session),
		"volume":      traceSessionVolume(session),
		"limitations": traceSessionLimitations(),
	}
	export := true
	if parsed.Export != nil {
		export = *parsed.Export
	}
	if export {
		artifactDesc, failure := exportTraceSessionEvents(tc, context, session, tracing.Filter{Kind: "any"}, "trace-session-jsonl")
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		result["artifact"] = artifactDesc
	}
	return okResult(stampGenerations(result, before, after), tc.modern)
}

// ----------------------------------------------------------------------------------------------------------------------
// Session helpers
// ----------------------------------------------------------------------------------------------------------------------
func newTraceSessionID() string {
	buffer := make([]byte, 9)
	if _, err := rand.Read(buffer); err != nil {
		return "trs_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return "trs_" + base64.RawURLEncoding.EncodeToString(buffer)
}

// traceSessionBounded applies a documented default and range to one numeric
// session parameter, rejecting values outside the supported contract instead
// of silently clamping a caller's intent.
func traceSessionBounded(value, fallback, minimum, maximum uint64, name string) (uint64, *toolFailure) {
	if value == 0 {
		return fallback, nil
	}
	if value < minimum || value > maximum {
		return 0, &toolFailure{
			Code:    "invalid_params",
			Message: fmt.Sprintf("%s must be between %d and %d", name, minimum, maximum),
			Data:    map[string]any{"field": name, "minimum": minimum, "maximum": maximum},
		}
	}
	return value, nil
}

func traceSessionCollectBudget(value uint64) (uint64, *toolFailure) {
	return traceSessionBounded(value, traceSessionDefaultCollectBudget, 4096, traceSessionMaxCollectBudget, "max_collect_bytes")
}

func currentTraceSession(tc toolContext, expectedID string) (*tracing.Session, *toolFailure) {
	session := tc.server.traces.Current()
	if session == nil {
		return nil, &toolFailure{
			Code:    "no_trace_session",
			Message: "no trace session exists in this server process; start one with trace_session_start",
		}
	}
	if expectedID != "" && expectedID != session.ID {
		return nil, &toolFailure{
			Code:    "session_mismatch",
			Message: fmt.Sprintf("live trace session is %q, not %q", session.ID, expectedID),
			Data:    map[string]any{"session_id": session.ID},
		}
	}
	return session, nil
}

// traceSessionNativeStatus reads the plugin's session status; a missing
// native session (after a restart or an auto-stop) is reported, not guessed.
func traceSessionNativeStatus(tc toolContext) (map[string]any, *toolFailure) {
	payload, failure := tc.server.executeCommand(tc.ctx, "trace_session_status", nil)
	if failure != nil {
		return nil, failure
	}
	return payload, nil
}

// collectTraceSession drains sealed native segments into the session store
// within one per-call byte budget.
func collectTraceSession(tc toolContext, session *tracing.Session, budget uint64, collect bool, stream string) (map[string]any, *toolFailure) {
	summary := map[string]any{
		"requested":           collect,
		"stream":              streamOrDefault(stream),
		"bytes_read":          uint64(0),
		"bytes_parsed":        uint64(0),
		"segments":            uint64(0),
		"events":              uint64(0),
		"malformed":           uint64(0),
		"truncated":           uint64(0),
		"budget_bytes":        budget,
		"complete":            !collect,
		"complete_definition": "drained.complete reports only that this call's drain cursor consumed every sealed segment; it says nothing about capture coverage, which is loss.complete.",
		"calls":               0,
	}
	if !collect {
		summary["note"] = "collect=false: sealed native segments were left on disk for a later drain."
		return summary, nil
	}
	drainTrace := stream == "" || stream == "trace"
	drainAccess := (stream == "" || stream == "access") && accessCaptureActive(session)
	if stream == "access" && !drainAccess {
		summary["note"] = "stream=access was requested but this session did not enable access_capture, so there is no per-access stream to drain."
	}
	var readBytes uint64
	var parsedBytes uint64
	var totalEvents uint64
	var totalMalformed uint64
	var totalTruncated uint64
	segments := uint64(0)
	calls := 0
	seal := true
	// A drain chunk can end mid-line, and a drain budget can end between two
	// calls. The incomplete tail lives in the session so it is completed by
	// the next chunk instead of being parsed (or counted malformed) twice.
	carrySegment, carry := session.Carry()
	complete := !drainTrace
	for calls < 64 && drainTrace && readBytes < budget {
		calls++
		chunk := traceSessionDrainChunkBytes
		if remaining := budget - readBytes; remaining < uint64(chunk) {
			chunk = int(remaining)
		}
		if chunk < 4096 {
			chunk = 4096
		}
		payload, failure := tc.server.executeCommand(tc.ctx, "trace_session_drain", map[string]string{
			"seal":      strconv.FormatBool(seal),
			"max_bytes": strconv.Itoa(chunk),
		})
		seal = false
		if failure != nil {
			return nil, failure
		}
		summary["calls"] = calls
		encoded, _ := payload["data"].(string)
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, &toolFailure{Code: "bridge_error", Message: "decode trace segment payload: " + err.Error()}
		}
		segmentIndex, ok := numberAsUint64(payload["segment_index"])
		if !ok {
			segmentIndex = 0
		}
		index := uint32(segmentIndex)
		if len(raw) > 0 {
			offset := uint64Of(payload["offset"])
			segmentBytes := uint64Of(payload["segment_bytes"])
			readBytes += uint64(len(raw))
			segmentComplete := segmentBytes != 0 && offset+uint64(len(raw)) >= segmentBytes
			if index != carrySegment {
				carry = nil
				carrySegment = index
			}
			if len(carry) > 0 {
				raw = append(carry, raw...)
				carry = nil
			}
			if !segmentComplete {
				if boundary := bytes.LastIndexByte(raw, '\n'); boundary >= 0 {
					carry = append([]byte{}, raw[boundary+1:]...)
					raw = raw[:boundary+1]
				} else {
					// The whole chunk is one partial line; hold it.
					carry = append([]byte{}, raw...)
					raw = nil
				}
			}
			if len(raw) > 0 {
				events, stats := tracing.ParseSegment(raw, session.CPU, session.ID, index)
				session.AddEvents(events)
				session.AddParseStats(stats)
				totalEvents += uint64(len(events))
				totalMalformed += stats.Malformed
				totalTruncated += stats.Truncated
				parsedBytes += uint64(len(raw))
			}
		}
		if sealed, _ := payload["sealed_now"].(bool); sealed {
			segments++
		}
		if evicted, ok := payload["evicted_segments"].(float64); ok && evicted >= 0 {
			notes := traceSessionNotes(payload)
			session.AddLoss(uint64(evicted), uint64Of(payload["evicted_bytes"]), uint64Of(payload["evicted_unread_segments"]), notes)
		}
		done, _ := payload["done"].(bool)
		if done {
			complete = true
			break
		}
	}
	summary["complete"] = complete
	summary["bytes_read"] = readBytes
	summary["bytes_parsed"] = parsedBytes
	summary["segments"] = segments
	summary["events"] = totalEvents
	summary["malformed"] = totalMalformed
	summary["truncated"] = totalTruncated
	session.SetCarry(carrySegment, carry)
	if len(carry) > 0 {
		summary["carried_partial_line_bytes"] = len(carry)
	}
	// The per-access stream is drained on its own native cursor: it is a
	// different file family with a different record contract, so it keeps its
	// own carry, counters, and completion flag.
	if drainAccess {
		accessSummary, accessFailure := collectTraceSessionAccess(tc, session, budget)
		if accessFailure != nil {
			return nil, accessFailure
		}
		summary["access"] = accessSummary
	}
	if !complete {
		summary["note"] = "the drain budget was reached; call again to continue (the native cursor and any partial line are preserved)."
	}
	return summary, nil
}

// streamOrDefault normalizes the drain stream selector for the response.
func streamOrDefault(stream string) string {
	if stream == "" {
		return "both"
	}
	return stream
}

// accessCaptureActive reports whether the session asked for per-access records.
func accessCaptureActive(session *tracing.Session) bool {
	return session.Config.AccessCapture != "" && session.Config.AccessCapture != "off"
}

// collectTraceSessionAccess drains the per-occurrence access stream within one
// per-call byte budget. It mirrors collectTraceSession because both streams are
// line-delimited but their record contracts, carries, and counters differ.
func collectTraceSessionAccess(tc toolContext, session *tracing.Session, budget uint64) (map[string]any, *toolFailure) {
	summary := map[string]any{
		"stream":              "access",
		"bytes_read":          uint64(0),
		"bytes_parsed":        uint64(0),
		"events":              uint64(0),
		"malformed":           uint64(0),
		"budget_bytes":        budget,
		"complete":            false,
		"complete_definition": "drained.access.complete reports only that this call's drain cursor consumed every sealed access segment; it says nothing about capture coverage.",
		"calls":               0,
	}
	var readBytes, parsedBytes, events, malformed uint64
	calls := 0
	seal := true
	carrySegment, carry := session.AccessCarry()
	complete := false
	for calls < 64 && readBytes < budget {
		calls++
		chunk := traceSessionDrainChunkBytes
		if remaining := budget - readBytes; remaining < uint64(chunk) {
			chunk = int(remaining)
		}
		if chunk < 4096 {
			chunk = 4096
		}
		payload, failure := tc.server.executeCommand(tc.ctx, "trace_session_drain", map[string]string{
			"stream":    "access",
			"seal":      strconv.FormatBool(seal),
			"max_bytes": strconv.Itoa(chunk),
		})
		seal = false
		if failure != nil {
			return nil, failure
		}
		summary["calls"] = calls
		encoded, _ := payload["data"].(string)
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, &toolFailure{Code: "bridge_error", Message: "decode access segment payload: " + err.Error()}
		}
		segmentIndex := uint32(uint64Of(payload["segment_index"]))
		if len(raw) > 0 {
			offset := uint64Of(payload["offset"])
			segmentBytes := uint64Of(payload["segment_bytes"])
			readBytes += uint64(len(raw))
			segmentComplete := segmentBytes != 0 && offset+uint64(len(raw)) >= segmentBytes
			if segmentIndex != carrySegment {
				carry = nil
				carrySegment = segmentIndex
			}
			if len(carry) > 0 {
				raw = append(carry, raw...)
				carry = nil
			}
			if !segmentComplete {
				if boundary := bytes.LastIndexByte(raw, '\n'); boundary >= 0 {
					carry = append([]byte{}, raw[boundary+1:]...)
					raw = raw[:boundary+1]
				} else {
					carry = append([]byte{}, raw...)
					raw = nil
				}
			}
			if len(raw) > 0 {
				accessEvents, stats, pending := tracing.ParseAccessSegment(raw, session.CPU, session.ID, segmentIndex)
				session.AddAccessEvents(accessEvents)
				session.AddAccessParseStats(stats)
				events += uint64(len(accessEvents))
				malformed += stats.Malformed
				parsedBytes += uint64(len(raw))
				if len(pending) > 0 {
					carry = pending
				}
			}
		}
		session.AddAccessLoss(uint64Of(payload["evicted_segments"]), uint64Of(payload["evicted_bytes"]), uint64Of(payload["evicted_unread_segments"]))
		if done, _ := payload["done"].(bool); done {
			complete = true
			break
		}
	}
	summary["complete"] = complete
	summary["bytes_read"] = readBytes
	summary["bytes_parsed"] = parsedBytes
	summary["events"] = events
	summary["malformed"] = malformed
	summary["last_sequence"] = session.LastAccessSequence()
	session.SetAccessCarry(carrySegment, carry)
	if len(carry) > 0 {
		summary["carried_partial_record_bytes"] = len(carry)
	}
	if !complete {
		summary["note"] = "the access drain budget was reached; call again to continue (the native access cursor and any partial record are preserved)."
	}
	return summary, nil
}

func uint64Of(value any) uint64 {
	parsed, _ := numberAsUint64(value)
	return parsed
}

func traceSessionNotes(payload map[string]any) []string {
	raw, ok := payload["notes"].([]any)
	if !ok {
		return nil
	}
	notes := make([]string, 0, len(raw))
	for _, item := range raw {
		if text, ok := item.(string); ok {
			notes = append(notes, text)
		}
	}
	return notes
}

// recordTraceSessionWatches folds aggregate watch counters reported by the
// plugin into the session store.
func recordTraceSessionWatches(session *tracing.Session, payload map[string]any) {
	if payload == nil {
		return
	}
	raw, ok := payload["watches"].([]any)
	if !ok {
		return
	}
	now := time.Now().UTC()
	for _, item := range raw {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		sample := tracing.WatchSample{
			SampledAt:    now,
			WatchpointID: uint64Of(entry["watchpoint_id"]),
			Address:      uint64Of(entry["address"]),
			Length:       uint64Of(entry["length"]),
			Access:       stringOf(entry["access"]),
			Hits:         uint64Of(entry["hits"]),
			Delta:        uint64Of(entry["delta"]),
			Lost:         boolOf(entry["lost"]),
		}
		session.AddWatchSample(sample)
	}
	session.AddLoss(uint64Of(payload["evicted_segments"]), uint64Of(payload["evicted_bytes"]), uint64Of(payload["evicted_unread_segments"]), traceSessionNotes(payload))
}

func stringOf(value any) string {
	text, _ := value.(string)
	return text
}

func boolOf(value any) bool {
	flag, _ := value.(bool)
	return flag
}

// traceSessionFilter validates and resolves the event query filters.
func traceSessionFilter(parsed traceSessionEventsArgs, session *tracing.Session) (tracing.Filter, *toolFailure) {
	filter := tracing.Filter{Kind: parsed.Kind}
	if filter.Kind == "" {
		filter.Kind = "any"
	}
	space := parsed.AddressSpace
	if space == "" {
		space = session.AddressSpace
	}
	if parsed.AddressRangeStart != nil || parsed.AddressRangeEnd != nil {
		if parsed.AddressRangeStart == nil {
			start, failure := resolveAddress(parsed.AddressRangeEnd, space, session.AddressSpace)
			if failure != nil {
				return filter, &toolFailure{Code: "invalid_params", Message: "address_range_end: " + failure.Message}
			}
			filter.HasRange = true
			filter.Start = 0
			filter.End = start + 1
		} else {
			start, failure := resolveAddress(parsed.AddressRangeStart, space, session.AddressSpace)
			if failure != nil {
				return filter, &toolFailure{Code: "invalid_params", Message: "address_range_start: " + failure.Message}
			}
			filter.Start = start
			filter.HasRange = true
			if parsed.AddressRangeEnd != nil {
				end, endFailure := resolveAddress(parsed.AddressRangeEnd, space, session.AddressSpace)
				if endFailure != nil {
					return filter, &toolFailure{Code: "invalid_params", Message: "address_range_end: " + endFailure.Message}
				}
				if end <= start {
					return filter, &toolFailure{Code: "invalid_params", Message: "address_range_end must be greater than address_range_start"}
				}
				filter.End = end
			} else {
				filter.End = start + 1
			}
		}
	}
	if parsed.CycleMin != 0 || parsed.CycleMax != 0 {
		if parsed.CycleMax != 0 && parsed.CycleMin > parsed.CycleMax {
			return filter, &toolFailure{Code: "invalid_params", Message: "cycle_min must not be greater than cycle_max"}
		}
		filter.HasCycle = true
		filter.CycleMin = parsed.CycleMin
		filter.CycleMax = parsed.CycleMax
		if filter.CycleMax == 0 {
			filter.CycleMax = ^uint64(0)
		}
	}
	if parsed.Direction != "" {
		if parsed.Direction != tracing.DirectionRead && parsed.Direction != tracing.DirectionWrite {
			return filter, &toolFailure{Code: "invalid_params", Message: "direction must be read or write"}
		}
		filter.Direction = parsed.Direction
	}
	if parsed.ValueEquals != nil {
		value, valueFailure := parseAddress(*parsed.ValueEquals)
		if valueFailure != nil {
			return filter, &toolFailure{Code: "invalid_params", Message: "value_equals: " + valueFailure.Message}
		}
		filter.HasValueEquals = true
		filter.ValueEquals = value
	}
	if parsed.ValueMin != nil || parsed.ValueMax != nil {
		filter.HasValueRange = true
		filter.ValueMin = 0
		filter.ValueMax = ^uint64(0)
		if parsed.ValueMin != nil {
			value, valueFailure := parseAddress(*parsed.ValueMin)
			if valueFailure != nil {
				return filter, &toolFailure{Code: "invalid_params", Message: "value_min: " + valueFailure.Message}
			}
			filter.ValueMin = value
		}
		if parsed.ValueMax != nil {
			value, valueFailure := parseAddress(*parsed.ValueMax)
			if valueFailure != nil {
				return filter, &toolFailure{Code: "invalid_params", Message: "value_max: " + valueFailure.Message}
			}
			filter.ValueMax = value
		}
		if filter.ValueMin > filter.ValueMax {
			return filter, &toolFailure{Code: "invalid_params", Message: "value_min must not be greater than value_max"}
		}
	}
	if parsed.PreviousEquals != nil {
		value, valueFailure := parseAddress(*parsed.PreviousEquals)
		if valueFailure != nil {
			return filter, &toolFailure{Code: "invalid_params", Message: "previous_equals: " + valueFailure.Message}
		}
		filter.HasPrevious = true
		filter.PreviousEquals = value
	}
	if parsed.PCStart != nil || parsed.PCEnd != nil {
		space := session.AddressSpace
		filter.PCStart = 0
		filter.PCEnd = ^uint64(0)
		filter.HasPC = true
		if parsed.PCStart != nil {
			start, pcFailure := resolveAddress(parsed.PCStart, parsed.AddressSpace, space)
			if pcFailure != nil {
				return filter, &toolFailure{Code: "invalid_params", Message: "pc_start: " + pcFailure.Message}
			}
			filter.PCStart = start
		}
		if parsed.PCEnd != nil {
			end, pcFailure := resolveAddress(parsed.PCEnd, parsed.AddressSpace, space)
			if pcFailure != nil {
				return filter, &toolFailure{Code: "invalid_params", Message: "pc_end: " + pcFailure.Message}
			}
			filter.PCEnd = end
		}
		if filter.PCStart >= filter.PCEnd {
			return filter, &toolFailure{Code: "invalid_params", Message: "pc_end must be greater than pc_start (the end is exclusive)"}
		}
	}
	if parsed.SequenceMin != 0 || parsed.SequenceMax != 0 {
		filter.HasSequence = true
		filter.SequenceMin = parsed.SequenceMin
		filter.SequenceMax = ^uint64(0)
		if parsed.SequenceMax != 0 {
			filter.SequenceMax = parsed.SequenceMax
		}
		if filter.SequenceMin > filter.SequenceMax {
			return filter, &toolFailure{Code: "invalid_params", Message: "sequence_min must not be greater than sequence_max"}
		}
	}
	return filter, nil
}

func traceFilterView(filter tracing.Filter, space string) map[string]any {
	view := map[string]any{
		"kind":          filter.Kind,
		"address_space": space,
	}
	if filter.HasRange {
		view["address_range_start"] = filter.Start
		view["address_range_end"] = filter.End
		annotateAddressRangePair(view, "address_range_start", space, filter.Start)
		annotateAddressRangePair(view, "address_range_end", space, filter.End)
	}
	if filter.HasCycle {
		view["cycle_min"] = filter.CycleMin
		view["cycle_max"] = filter.CycleMax
	}
	if filter.Direction != "" {
		view["direction"] = filter.Direction
	}
	if filter.HasValueEquals {
		view["value_equals"] = filter.ValueEquals
		view["value_equals_hex"] = canonicalHex(filter.ValueEquals)
	}
	if filter.HasValueRange {
		view["value_min"] = filter.ValueMin
		view["value_max"] = filter.ValueMax
		view["value_min_hex"] = canonicalHex(filter.ValueMin)
		view["value_max_hex"] = canonicalHex(filter.ValueMax)
	}
	if filter.HasPrevious {
		view["previous_equals"] = filter.PreviousEquals
		view["previous_equals_hex"] = canonicalHex(filter.PreviousEquals)
	}
	if filter.HasPC {
		view["pc_start"] = filter.PCStart
		view["pc_end"] = filter.PCEnd
		annotateAddressRangePair(view, "pc_start", space, filter.PCStart)
		annotateAddressRangePair(view, "pc_end", space, filter.PCEnd)
	}
	if filter.HasSequence {
		view["sequence_min"] = filter.SequenceMin
		view["sequence_max"] = filter.SequenceMax
	}
	view["applied_after_capture"] = true
	view["effective_value_filters_keep_raw_events"] = true
	view["note"] = "Every filter is applied to retained events after capture. Value filters are effective-value filters: they select which retained records are returned or exported, and never cause a raw record to be dropped from the store. Execution trace filtering happens after the engine wrote the trace, so out-of-range instructions still consumed drain bandwidth; per-access records are filtered natively inside the watched ranges and cost nothing outside them."
	return view
}

// exportTraceSessionEvents stores every retained matching event as JSONL.
func exportTraceSessionEvents(tc toolContext, context *analysis.Context, session *tracing.Session, filter tracing.Filter, kind string) (map[string]any, *toolFailure) {
	events := session.Select(filter)
	payload, err := tracing.MarshalJSONL(events)
	if err != nil {
		return nil, &toolFailure{Code: "artifact_error", Message: err.Error()}
	}
	generation := tc.server.target.Generation()
	captureID := newCaptureID()
	provenance := genericProvenance(tc.server, kind, time.Now().UTC())
	provenance.Device = session.CPU
	provenance.AddressSpace = session.AddressSpace
	if session.CPU == "z80" {
		provenance.ByteOrder = "little-endian"
	} else {
		provenance.ByteOrder = "big-endian"
	}
	provenance.CaptureID = captureID
	provenance.TargetGeneration = &generation
	if filter.HasRange {
		start := filter.Start
		length := filter.End - filter.Start
		end := filter.End - 1
		provenance.StartAddress = &start
		provenance.ByteLength = &length
		provenance.EffectiveAddress = &end
	}
	stored, err := tc.server.store.PutWithProvenance(context.ID, kind, "application/jsonl", payload, provenance)
	if err != nil {
		return nil, &toolFailure{Code: "artifact_error", Message: err.Error()}
	}
	session.AddArtifact(stored.ID)
	descriptor := artifactDescriptor(tc.server, stored, context.ID)
	descriptor["events"] = len(events)
	descriptor["session_id"] = session.ID
	// Truncation accounting: the export can only contain events the bounded
	// store still retains, so an evicted or never-drained segment is as much a
	// truncation as an inline cap. Reasons are listed so a consumer can tell
	// why the artifact is not the whole capture.
	loss := session.LossView()
	reasons := []string{}
	if loss.DroppedEvents > 0 {
		reasons = append(reasons, fmt.Sprintf("%d event(s) were evicted from the bounded event store", loss.DroppedEvents))
	}
	if loss.EvictedUnreadSegments > 0 {
		reasons = append(reasons, fmt.Sprintf("%d sealed segment(s) were evicted before this server drained them", loss.EvictedUnreadSegments))
	}
	descriptor["truncated_by_store"] = len(reasons) > 0
	if len(reasons) > 0 {
		descriptor["truncation_reasons"] = reasons
	}
	return descriptor, nil
}

// ----------------------------------------------------------------------------------------------------------------------
// Recovery
// ----------------------------------------------------------------------------------------------------------------------
type traceSessionRecoverArgs struct {
	SessionID string `json:"session_id"`
	Install   bool   `json:"install"`
	MaxEvents uint64 `json:"max_events"`
	Context   string `json:"context"`
}

// runTraceSessionRecover lists durable manifests or restores one of them. A
// recovered session is a read-only view over the manifest and whatever raw
// event file it recorded: it is never presented as a live capture.
func runTraceSessionRecover(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[traceSessionRecoverArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	root := tc.server.TraceSessionsDir()
	entries, err := tracing.ListManifests(root)
	if err != nil {
		return failureResult(&toolFailure{Code: "recovery_error", Message: "list trace-session manifests: " + err.Error()}, tc.modern)
	}
	result := map[string]any{
		"manifest_root": root,
		"manifests":     entries,
		"count":         len(entries),
		"note":          "Manifests survive an MCP server restart. Raw events survive only inside exported JSONL artifacts; a manifest without one recovers counters and loss only.",
	}
	if parsed.SessionID == "" {
		return okResult(result, tc.modern)
	}
	var manifest *tracing.Manifest
	var manifestPath string
	for _, entry := range entries {
		if entry.SessionID != parsed.SessionID {
			continue
		}
		loaded, loadErr := tracing.LoadManifest(entry.Path)
		if loadErr != nil {
			return failureResult(&toolFailure{Code: "recovery_error", Message: loadErr.Error()}, tc.modern)
		}
		manifest = loaded
		manifestPath = entry.Path
		break
	}
	if manifest == nil {
		return failureResult(&toolFailure{
			Code:    "session_not_found",
			Message: fmt.Sprintf("no manifest for session %q under %s", parsed.SessionID, root),
		}, tc.modern)
	}
	limit := parsed.MaxEvents
	if limit == 0 {
		limit = 20000
	}
	var events []tracing.Event
	if manifest.EventsFile != "" {
		loaded, readErr := tracing.ReadEventsFile(manifest.EventsFile, int(limit))
		if readErr != nil {
			result["events_error"] = readErr.Error()
		}
		events = loaded
	}
	restored := tracing.RestoreSession(manifest, events)
	romSHA := ""
	if facts := tc.server.romIdentity.romFileFacts(tc.server.currentROMPath()); facts.SHA256Available {
		romSHA = facts.SHA256
	}
	romBound := manifest.ROMSHA256 != "" && manifest.ROMSHA256 == romSHA
	result["manifest"] = manifest
	result["manifest_path"] = manifestPath
	result["restored"] = map[string]any{
		"session_id":         restored.ID,
		"retained_events":    restored.Retained(),
		"events_loaded":      len(events),
		"totals":             restored.Totals(),
		"loss":               traceSessionLossView(restored),
		"rom_bound":          romBound,
		"rom_sha256":         manifest.ROMSHA256,
		"current_rom_sha256": romSHA,
		"symbols_available":  romBound,
		"note":               "A recovered session reports the manifest's loss verbatim; without an event file only counters and loss survive. Symbols resolve only when the loaded ROM hash matches the manifest's.",
	}
	if !romBound {
		result["rom_warning"] = "The loaded ROM identity does not match the manifest's ROM SHA-256, so symbol resolution and address interpretation are suppressed for this recovered view."
	}
	if parsed.Install {
		if live := tc.server.traces.Current(); live != nil && !live.Stopped {
			result["install"] = map[string]any{
				"installed": false,
				"note":      "a live session is active; stop it before installing a recovered view",
			}
			return okResult(result, tc.modern)
		}
		restored.ContextID = context.ID
		tc.server.traces.Replace(restored)
		result["install"] = map[string]any{"installed": true, "session_id": restored.ID}
	}
	return okResult(result, tc.modern)
}

// traceSessionSymbolView annotates access-event PCs with context symbols, but
// only when the loaded cartridge is the one the session captured. Addresses are
// ROM-relative: resolving the same address against a different cartridge would
// label unrelated code.
func traceSessionSymbolView(tc toolContext, session *tracing.Session, context *analysis.Context, events []tracing.Event, views []map[string]any, resolve bool) map[string]any {
	sessionSHA := session.ROMSHA256()
	currentSHA := tc.server.currentROMSHA256()
	view := map[string]any{
		"requested":               resolve,
		"session_rom_sha256":      sessionSHA,
		"current_rom_sha256":      currentSHA,
		"raw_pc_is_authoritative": true,
	}
	if !resolve {
		view["applied"] = false
		view["reason"] = "resolve_symbols=false"
		return view
	}
	if sessionSHA == "" {
		view["applied"] = false
		view["reason"] = "session_unbound_no_rom_hash"
		view["note"] = "The session was started without a readable cartridge hash, so symbol resolution is suppressed."
		return view
	}
	if sessionSHA != currentSHA {
		view["applied"] = false
		view["reason"] = "rom_hash_mismatch"
		view["note"] = "The loaded cartridge differs from the one the session captured; symbol resolution is suppressed so no foreign ROM's names are applied."
		return view
	}
	spaceID := session.AddressSpace
	_, mask := addressBusWidthMask(spaceID)
	if mask == 0 {
		mask = ^uint64(0)
	}
	byAddress := make(map[uint64]string)
	for _, symbol := range context.Symbols.ListForROM("", sessionSHA) {
		if symbol.SpaceID != "" && symbol.SpaceID != spaceID {
			continue
		}
		address := symbol.Address & mask
		if _, exists := byAddress[address]; !exists {
			byAddress[address] = symbol.Name
		}
	}
	resolved := 0
	for index, event := range events {
		if index >= len(views) {
			break
		}
		name, ok := byAddress[event.PC&mask]
		if !ok {
			continue
		}
		views[index]["pc_symbol"] = name
		resolved++
	}
	view["applied"] = true
	view["rom_sha256"] = sessionSHA
	view["symbols_considered"] = len(byAddress)
	view["pcs_resolved"] = resolved
	view["note"] = "Symbols come from the context symbol table bound to this cartridge's SHA-256; the raw pc remains authoritative."
	return view
}

// traceSessionVolume reports retention bounds and measured throughput. The
// estimate is derived from the measured native
// behavior of the engine: a disassembled M68K instruction trace writes roughly
// 1.3 MB per 100 ms of traced time (~13 MB/s), and one access record is a
// single short line (about 120 bytes with the register snapshot).
func traceSessionVolume(session *tracing.Session) map[string]any {
	config := session.Config
	duty := 1.0
	if config.Mode == "sampled" && config.IntervalMs > 0 {
		duty = float64(config.WindowMs) / float64(config.IntervalMs)
	}
	traceBytesPerSecond := traceSessionTraceBytesPerSecond(config)
	limits := map[string]any{
		"stop_after_vdp_frames": config.StopAfterVdpFrames,
		"max_total_bytes":       config.MaxTotalBytes,
		"max_segments":          config.MaxSegments,
		"max_events":            config.MaxEvents,
		"access_max_bytes":      config.AccessMaxBytes,
		"access_capture":        config.AccessCapture,
		"store_is_bounded":      true,
		"retention_is_lossy":    true,
	}
	view := map[string]any{
		"limits": limits,
		"estimate": map[string]any{
			"trace_bytes_per_second":   uint64(traceBytesPerSecond),
			"duty_cycle":               duty,
			"access_record_bytes":      120,
			"untraced_time_in_sampled": config.Mode == "sampled",
			"basis":                    "Trace session lifetime is unbounded unless stop_after_vdp_frames is set; disk and event retention caps bound storage and evict oldest data. The throughput estimate is provided, but a total-byte estimate is not meaningful without a lifetime limit.",
		},
		"note": "Retention caps evict the oldest sealed segments and the bounded store evicts the oldest events; every eviction is counted in loss, so a cap is never silent. Serialize large results into artifacts instead of inline responses. Whether this estimated write rate exhausts a finite cap before the session ends is stated in loss.estimated_eviction_risk.",
	}
	if config.AccessCapture == "" || config.AccessCapture == "off" {
		view["access_estimate"] = map[string]any{
			"enabled": false,
			"note":    "no per-access capture; read/write observation is aggregate watch counting only",
		}
	} else {
		view["access_estimate"] = map[string]any{
			"enabled":    true,
			"mode":       config.AccessCapture,
			"registers":  config.AccessIncludeRegisters,
			"per_access": "one record with a monotonic sequence, cycle, PC, direction, width, value, optional previous value, and optional same-instant registers",
			"note":       "native range filtering means out-of-range accesses are never written, so the volume is bounded by the watched traffic, not the CPU speed",
		}
	}
	return view
}

// traceSessionTraceBytesPerSecond is the one write-rate estimate shared by the
// volume report and the retention-risk projection: the engine writes roughly
// 1.3 MB per 100 ms of traced time (~13 MiB/s) in continuous mode, scaled by the
// fraction of wall-clock time sampled mode actually traces.
func traceSessionTraceBytesPerSecond(config tracing.Config) float64 {
	duty := 1.0
	if config.Mode == "sampled" && config.IntervalMs > 0 {
		duty = float64(config.WindowMs) / float64(config.IntervalMs)
	}
	return 13.0 * 1024 * 1024 * duty
}

// traceSessionManifestPersist writes the durable manifest for a live session so
// a restarted MCP server can discover what existed. Persistence is best-effort:
// a failure is reported, never fatal, because the session itself is valid.
func traceSessionManifestPersist(tc toolContext, session *tracing.Session, native map[string]any) map[string]any {
	romPath := tc.server.currentROMPath()
	romSHA := ""
	if facts := tc.server.romIdentity.romFileFacts(romPath); facts.SHA256Available {
		romSHA = facts.SHA256
	}
	manifest := tracing.NewManifest(session, romPath, romSHA, native)
	for index := len(manifest.Artifacts) - 1; index >= 0; index-- {
		candidate := filepath.Join(tc.server.store.Dir(), manifest.Artifacts[index])
		if _, statErr := os.Stat(candidate); statErr == nil {
			manifest.EventsFile = candidate
			break
		}
	}
	consistency := "session-scoped: the CPU was never paused for the capture; the store is bounded and loss is reported"
	view := map[string]any{
		"schema":      tracing.ManifestSchema,
		"rom_sha256":  romSHA,
		"rom_bound":   romSHA != "",
		"consistency": consistency,
		"written":     false,
	}
	path, err := manifest.Save(tc.server.TraceSessionsDir())
	if err != nil {
		view["error"] = err.Error()
		view["note"] = "the manifest could not be written; recovery after an MCP server restart is unavailable for this session"
		return view
	}
	view["written"] = true
	view["manifest_path"] = path
	view["note"] = "the manifest survives an MCP server restart; raw access events survive only in exported JSONL artifacts and in the bounded in-memory store of this process"
	return view
}

// traceSessionSummary renders the shared session view used by every tool.
func traceSessionSummary(tc toolContext, session *tracing.Session, native map[string]any) map[string]any {
	if session == nil {
		return map[string]any{"state": "absent"}
	}
	generation := tc.server.target.Generation()
	summary := map[string]any{
		"id":                         session.ID,
		"context":                    session.ContextID,
		"cpu":                        session.CPU,
		"address_space":              session.AddressSpace,
		"config":                     session.Config,
		"started_at":                 session.StartedAt,
		"stopped":                    session.Stopped,
		"target_generation_at_start": session.GenerationAtStart(),
		"target_generation":          generation,
		"retained_events":            session.Retained(),
		"totals":                     session.Totals(),
		"parse":                      session.Stats(),
		"loss":                       traceSessionLossView(session),
		"capture_consistency":        traceSessionConsistency(tc, session, native),
	}
	if !session.StoppedAt.IsZero() {
		summary["stopped_at"] = session.StoppedAt
	}
	if native != nil {
		summary["native"] = map[string]any{
			"active":               native["active"],
			"capturing":            native["capturing"],
			"elapsed_ms":           native["elapsed_ms"],
			"windows_started":      native["windows_started"],
			"windows_completed":    native["windows_completed"],
			"bytes_written":        native["bytes_written"],
			"open_segment":         native["open_segment"],
			"segments":             native["segments"],
			"stop_reason":          native["stop_reason"],
			"auto_stopped":         native["auto_stopped"],
			"drain":                native["drain"],
			"watches":              native["watches"],
			"access":               native["access"],
			"trace_flags_restored": native["trace_flags_restored"],
			"setup_pause":          native["setup_pause"],
		}
		if session.Stopped {
			summary["state"] = "stopped"
		} else if active, _ := native["active"].(bool); active {
			summary["state"] = "live"
		} else {
			summary["state"] = "live_untracked"
		}
	} else if session.Stopped {
		summary["state"] = "stopped"
	} else {
		summary["state"] = "live"
	}
	return summary
}

// traceSessionConsistency describes how the session's events relate to the
// emulated timeline: a bounded window capture that never paused the CPU for
// the capture itself, plus the observed run state and — when the caller asked
// for the conservative start guard — the configuration pause it caused.
func traceSessionConsistency(tc toolContext, session *tracing.Session, native map[string]any) map[string]any {
	observed := initialRunStateLabel(tc.server)
	view := map[string]any{
		"state":                    "live_windowed",
		"execution_paused_by_tool": false,
		"execution_resumed_after":  false,
		"initial_run_state":        observed,
		"final_run_state":          observed,
		"session_started_at":       session.StartedAt,
		"note":                     "Execution events are the engine's own per-instruction trace lines written while the system ran; the capture never paused the CPU. Sampled mode leaves gaps between windows, and read/write counters are aggregate samples, so events from different windows must not be treated as one continuous instant.",
	}
	if native != nil {
		if setup, ok := native["setup_pause"].(map[string]any); ok {
			guarded, _ := setup["guarded"].(bool)
			wasRunning, _ := setup["system_was_running"].(bool)
			if guarded && wasRunning {
				view["execution_paused_by_tool"] = true
				view["execution_resumed_after"] = true
				view["initial_run_state"] = "running"
				view["final_run_state"] = "running"
				view["note"] = view["note"].(string) + " start_guard \"quiet\" paused the CPU once for the trace configuration calls and resumed it immediately; the capture windows themselves never pause execution."
			}
		}
	}
	if !session.StoppedAt.IsZero() {
		view["session_stopped_at"] = session.StoppedAt
	}
	return view
}

// traceSessionLossView renders the explicit loss contract, including whether
// the retained data is complete.
//
// `complete` has exactly one meaning here: the capture covered the requested
// window with no gaps and the session has ended. Two independent reasons keep
// it false while a session runs:
//
//   - A running session has not finished its loss accounting: retention can
//     still evict and dropped counters can still move, so a start or status
//     response cannot promise a completeness verdict the remaining lifetime may
//     contradict. Such a session reports the `session_running` reason and
//     `final: false`.
//   - A sampled session leaves the processor untraced between its capture
//     windows by construction, so it can never be complete; its coverage is
//     stated in `capture` and `capture_is_sampled` so a consumer can decide
//     what to do with a sample instead of mistaking it for a record.
//
// A continuous session that has ended with every loss counter at zero is the
// only combination that reports `complete: true` with `final: true`.
func traceSessionLossView(session *tracing.Session) map[string]any {
	if session == nil {
		return map[string]any{
			"complete":                false,
			"final":                   true,
			"capture_is_sampled":      false,
			"incomplete_reasons":      []string{"no_session"},
			"estimated_eviction_risk": false,
			"note":                    "no session exists, so there is no capture to describe and no completeness to claim.",
		}
	}
	loss := session.LossView()
	capture := traceSessionCaptureFacts(session)
	sampled, _ := capture["sampled"].(bool)
	final := session.Stopped
	reasons := make([]string, 0, 6)
	if !final {
		// The session's own end is the primary reason: no verdict about a
		// capture is final before the capture stops.
		reasons = append(reasons, "session_running")
	}
	if sampled {
		reasons = append(reasons, "sampled_mode")
	}
	if loss.DroppedEvents != 0 {
		reasons = append(reasons, "dropped_events")
	}
	if loss.MalformedLines != 0 {
		reasons = append(reasons, "malformed_lines")
	}
	if loss.TruncatedLines != 0 {
		reasons = append(reasons, "truncated_lines")
	}
	if loss.EvictedUnreadSegments != 0 {
		reasons = append(reasons, "evicted_unread_segments")
	}
	if loss.DroppedAddressCounts != 0 {
		reasons = append(reasons, "dropped_address_counts")
	}
	if loss.AccessMalformedLines != 0 {
		reasons = append(reasons, "access_malformed_lines")
	}
	if loss.EvictedUnreadAccessSegments != 0 {
		reasons = append(reasons, "evicted_unread_access_segments")
	}
	if loss.AccessSequenceGaps != 0 {
		reasons = append(reasons, "access_sequence_gaps")
	}
	complete := final && len(reasons) == 0
	risk, riskBasis := traceSessionEvictionEstimate(session, final)
	view := map[string]any{
		"complete":                       complete,
		"final":                          final,
		"complete_definition":            "complete is true only when the session has ended (final is true) and the capture covered the requested window with no gaps: continuous mode, every loss counter zero, and therefore no incomplete_reasons. A running session always reports complete false with the reason session_running, because retention and loss accounting are not final yet. Sampled mode leaves the processor untraced between windows, so a sampled session is never complete and reports its coverage in capture.",
		"incomplete_reasons":             reasons,
		"capture":                        capture,
		"capture_is_sampled":             sampled,
		"estimated_eviction_risk":        risk,
		"estimated_eviction":             riskBasis,
		"dropped_events":                 loss.DroppedEvents,
		"dropped_address_counts":         loss.DroppedAddressCounts,
		"dropped_watch_samples":          loss.DroppedWatchSamples,
		"malformed_lines":                loss.MalformedLines,
		"truncated_lines":                loss.TruncatedLines,
		"evicted_segments":               loss.EvictedSegments,
		"evicted_bytes":                  loss.EvictedBytes,
		"evicted_unread_segments":        loss.EvictedUnreadSegments,
		"access_malformed_lines":         loss.AccessMalformedLines,
		"access_truncated_lines":         loss.AccessTruncatedLines,
		"evicted_access_segments":        loss.EvictedAccessSegments,
		"evicted_access_bytes":           loss.EvictedAccessBytes,
		"evicted_unread_access_segments": loss.EvictedUnreadAccessSegments,
		"access_sequence_gaps":           loss.AccessSequenceGaps,
		"access_sequence_gap_samples":    loss.AccessSequenceGapSamples,
		"notes":                          loss.Notes,
		"sampled_mode_gaps":              sampled,
	}
	if !complete {
		switch {
		case !final && len(reasons) == 1:
			view["note"] = "The session is still running, so completeness is not final: retention can still evict and every loss counter can still move. Query again after trace_session_stop for a final verdict, and read estimated_eviction_risk for whether the estimated write rate exhausts a finite retention cap before the session ends."
		case !final:
			view["note"] = "The session is still running (session_running) and has already reported gaps or loss; see incomplete_reasons. Neither the sample nor the loss total is final until the session stops."
		case sampled && len(reasons) == 1:
			view["note"] = "Sampled mode leaves the processor untraced between capture windows, so the retained events are a sample of execution, not a complete record; capture.duty_cycle states the fraction of the session that was traced."
		case sampled:
			view["note"] = "The session is sampled and lost data in at least one further dimension; the retained events are neither a sample of known coverage nor a complete record. See incomplete_reasons."
		default:
			view["note"] = "The session ended with loss in at least one dimension; do not present the retained events as a complete record of execution. See incomplete_reasons."
		}
	}
	return view
}

// traceSessionBaselineFrameRateHz projects a stop_after_vdp_frames budget onto
// wall-clock seconds. The plugin reports frames elapsed, never a frame rate, so
// the projection states the Mega Drive NTSC baseline it assumes instead of
// implying a measurement.
const traceSessionBaselineFrameRateHz = 60.0

// traceSessionEvictionEstimate projects whether the configured retention caps
// will be exhausted before the session ends, and states the numbers behind the
// verdict.
//
// The rule: retention is finite when max_total_bytes or max_segments can evict
// (the defaults always can). The write rate is the same 13 MiB per traced
// second used by traceSessionVolume, scaled by the sampled duty cycle; the byte
// cap's horizon is max_total_bytes/rate and the segment cap's horizon is
// max_segments * segment_ms. The session window is bounded only by
// stop_after_vdp_frames, projected at the baseline frame rate. Risk is true when
// a finite retention horizon is reached inside the session window; with no
// frame limit the window is unbounded, so any finite cap is eventually reached
// and the risk is reported as true rather than as unknown.
//
// A session that has already ended reports false: its outcome is stated by the
// loss counters, not by a projection.
func traceSessionEvictionEstimate(session *tracing.Session, final bool) (bool, map[string]any) {
	config := session.Config
	rate := traceSessionTraceBytesPerSecond(config)
	retentionBounded := false
	byteCapSeconds := 0.0
	if rate > 0 && config.MaxTotalBytes > 0 {
		byteCapSeconds = float64(config.MaxTotalBytes) / rate
		retentionBounded = true
	}
	segmentCapSeconds := 0.0
	if config.MaxSegments > 0 && config.SegmentMs > 0 {
		segmentCapSeconds = float64(config.MaxSegments) * float64(config.SegmentMs) / 1000.0
		retentionBounded = true
	}
	retentionSeconds := 0.0
	switch {
	case byteCapSeconds > 0 && segmentCapSeconds > 0:
		retentionSeconds = math.Min(byteCapSeconds, segmentCapSeconds)
	case byteCapSeconds > 0:
		retentionSeconds = byteCapSeconds
	default:
		retentionSeconds = segmentCapSeconds
	}

	windowBounded := config.StopAfterVdpFrames > 0
	windowSeconds := 0.0
	if windowBounded {
		windowSeconds = float64(config.StopAfterVdpFrames) / traceSessionBaselineFrameRateHz
	}

	appliesTo := "running_session"
	verdict := "no_write_rate"
	risk := false
	switch {
	case final:
		appliesTo = "ended_session"
		verdict = "session_ended"
	case !retentionBounded || rate <= 0:
		verdict = "no_write_rate"
	case !windowBounded:
		risk = true
		verdict = "retention_exhausted_within_unbounded_session"
	case retentionSeconds < windowSeconds:
		risk = true
		verdict = "retention_exhausted_before_session_window_end"
	default:
		verdict = "retention_survives_session_window"
	}

	basis := map[string]any{
		"applies_to":             appliesTo,
		"retention_bounded":      retentionBounded,
		"trace_bytes_per_second": uint64(rate),
		"byte_cap_seconds":       traceSessionSeconds(byteCapSeconds),
		"segment_cap_seconds":    traceSessionSeconds(segmentCapSeconds),
		"retention_cap_seconds":  traceSessionSeconds(retentionSeconds),
		"session_window_bounded": windowBounded,
		"session_window_seconds": traceSessionSeconds(windowSeconds),
		"verdict":                verdict,
		"rule":                   "estimated_eviction_risk is true when retention is finite and the estimated trace write rate (13 MiB per traced second, scaled by the sampled duty cycle) exhausts max_total_bytes or max_segments * segment_ms before the session window ends. The window is the stop_after_vdp_frames budget projected at 60 fps; a session with no frame limit has an unbounded window, so any finite cap is eventually reached. The numbers are estimates, not measurements, and an ended session reports false because its loss counters state what actually happened.",
	}
	if windowBounded {
		basis["assumed_frame_rate_hz"] = traceSessionBaselineFrameRateHz
	}
	return risk, basis
}

// traceSessionSeconds rounds a projection to milliseconds of a second so the
// rendered estimate stays readable; 0 means "unbounded" together with the
// companion boolean flag, never a zero-length horizon.
func traceSessionSeconds(value float64) float64 {
	return math.Round(value*1000) / 1000
}

// traceSessionCaptureFacts renders what slice of the emulated timeline the
// session actually traced, independently of how much was lost. An unknown mode
// is treated as sampled: claiming continuous coverage is the unsafe direction.
func traceSessionCaptureFacts(session *tracing.Session) map[string]any {
	mode := session.Config.Mode
	if mode != "continuous" {
		mode = "sampled"
	}
	sampled := mode == "sampled"
	windowMs := session.Config.WindowMs
	intervalMs := session.Config.IntervalMs
	dutyCycle := 1.0
	untracedMs := uint64(0)
	if sampled {
		switch {
		case intervalMs == 0 || windowMs == 0:
			// A session without a usable window/interval pair cannot claim any
			// traced fraction.
			dutyCycle = 0
			untracedMs = intervalMs
		case windowMs >= intervalMs:
			dutyCycle = 1
		default:
			dutyCycle = float64(windowMs) / float64(intervalMs)
			untracedMs = intervalMs - windowMs
		}
	}
	return map[string]any{
		"mode":                     mode,
		"sampled":                  sampled,
		"window_ms":                windowMs,
		"interval_ms":              intervalMs,
		"duty_cycle":               dutyCycle,
		"untraced_ms_per_interval": untracedMs,
		"note":                     "duty_cycle is the fraction of wall-clock time the processor write was traced (1 in continuous mode); untraced_ms_per_interval is how long each sampled interval runs untraced. Both describe the capture mode, not the data that survived retention.",
	}
}

// traceSessionLimitations states the honest capability boundary of the
// native emulator interfaces behind this feature.
func traceSessionLimitations() map[string]any {
	return map[string]any{
		"execute_events":    "Per executed instruction inside each capture window: PC, opcode text, cycle, and emulated time come from the engine's own trace file.",
		"read_write_events": "With access_capture \"off\" read/write observation is aggregate watchpoint hit counting only. With \"ranges\" or \"all\" each access is a separate record carrying the engine's monotonic sequence, cycle, PC, direction, width, transferred value, and (by default for ranges) a same-instant register snapshot.",
		"previous_value":    "A write record carries the value written. The pre-write value is reported only when the engine captured it (previous_known); this fork does not perform a pre-write transparent read, so previous_known is false and the missing value is reported instead of being faked.",
		"frame":             "Access records carry the processor cycle and the engine's emulated time, not a per-access frame token. The frame token is a session/drain-level observation.",
		"native_filtering":  "Per-access records are filtered natively by the watched ranges, so out-of-range accesses cost one comparison and are never written. Execution trace output cannot be filtered natively; address and cycle filters apply to retained events after capture.",
		"sampling":          "In sampled mode the CPU is untraced between windows (window_ms per interval_ms); continuous mode traces every instruction but grows the segment files at full CPU speed. Access records follow the same window boundaries.",
		"retention":         "Every stream is bounded: the native segment caps, the server event store capacity, and the per-stream byte caps all evict and count. A manifest records what existed, but raw records that were evicted are gone.",
	}
}

// traceEventView renders one event for an inline response sample.
func traceEventView(event tracing.Event) map[string]any {
	view := map[string]any{
		"kind":           event.Kind,
		"address":        event.Address,
		"address_hex":    event.AddressHex,
		"address_space":  event.AddressSpace,
		"cycle":          event.Cycle,
		"segment_index":  event.SegmentIndex,
		"store_sequence": event.StoreSequence,
	}
	if event.EmulatedNanoseconds != 0 {
		view["emulated_nanoseconds"] = event.EmulatedNanoseconds
		view["emulated_seconds"] = event.EmulatedSeconds
	}
	if event.Mnemonic != "" {
		view["mnemonic"] = event.Mnemonic
	}
	if event.Operands != "" {
		view["operands"] = event.Operands
	}
	if event.Comment != "" {
		view["comment"] = event.Comment
	}
	if event.Bucket != "" {
		view["aggregation"] = event.Bucket
		view["hits"] = event.Hits
	}
	if event.ByteOrder != "" {
		view["byte_order"] = event.ByteOrder
	}
	if event.Sequence != 0 {
		view["sequence"] = event.Sequence
	}
	if event.Direction != "" {
		view["direction"] = event.Direction
	}
	if event.WidthBits != 0 {
		view["width_bits"] = event.WidthBits
		view["width_bytes"] = event.WidthBits / 8
	}
	if event.ValueKnown {
		view["value"] = event.Value
		view["value_hex"] = canonicalHex(event.Value)
		view["value_state"] = event.ValueState
	}
	view["previous_known"] = event.PreviousKnown
	if event.PreviousKnown {
		view["previous"] = event.Previous
		view["previous_hex"] = canonicalHex(event.Previous)
	}
	if event.PC != 0 || event.Kind == tracing.KindRead || event.Kind == tracing.KindWrite {
		view["pc"] = event.PC
		view["pc_hex"] = event.PCHex
		annotateAddressRangePair(view, "pc", event.AddressSpace, event.PC)
	}
	if len(event.Registers) > 0 {
		registers := make(map[string]any, len(event.Registers))
		for _, register := range event.Registers {
			registers[register.Name] = register.Value
			registers[register.Name+"_hex"] = register.Hex
		}
		view["registers"] = registers
		view["register_snapshot"] = "same instant as the access"
	}
	annotateAddressPair(view, event.AddressSpace, event.Address)
	return view
}

// traceValueProperty is the schema of a numeric value written as an integer or
// in any of the supported hexadecimal forms. It is used for effective-value
// filters, which are values rather than addresses and therefore take no
// address-space argument.
func traceValueProperty(description string) map[string]any {
	return map[string]any{
		"description": description + " Accepts an integer, 0x hex, $ Motorola hex, or h-suffixed Zilog hex.",
		"oneOf": []map[string]any{
			{"type": "integer", "minimum": 0},
			{"type": "string", "pattern": "^(\\$[0-9a-fA-F]+|[0-9a-fA-F]+[hH]|0[xX][0-9a-fA-F]+|[0-9]+)$"},
		},
	}
}
