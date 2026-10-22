package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/StealthC/exodus-mcp/internal/tracing"
)

// traceSessionFake simulates the plugin's trace session commands: a start
// handshake, ordered segment drain chunks, status with moving watch counters,
// and a stop that reports the final table.
type traceSessionFake struct {
	mu       sync.Mutex
	segments []string
	segment  int
	offset   int
	// accessSegments is the per-access stream, drained independently through
	// the same command with stream=access.
	accessSegments []string
	accessSegment  int
	accessOffset   int
	started        bool
	stopped        bool
	drains         int
	watchHit       uint64
	watch          *tracing.Watch
	started0       map[string]string
}

func newTraceSessionFake(segments ...string) *traceSessionFake {
	return &traceSessionFake{segments: segments}
}

func (fake *traceSessionFake) client() *fakeBridgeClient {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.status.SupportedOperations = append(client.status.SupportedOperations,
		"trace_session_start", "trace_session_status", "trace_session_drain", "trace_session_stop")
	client.executeFunc = fake.execute
	return client
}

func (fake *traceSessionFake) execute(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	switch method {
	case "trace_session_start":
		fake.started = true
		fake.stopped = false
		fake.started0 = map[string]string{}
		for key, value := range params {
			fake.started0[key] = value
		}
		fake.watch = nil
		if params["watch_count"] == "1" {
			address, _ := strconv.ParseUint(params["watch0_address"], 10, 64)
			length, _ := strconv.ParseUint(params["watch0_length"], 10, 64)
			fake.watch = &tracing.Watch{Address: address, Length: length, Access: params["watch0_access"]}
		}
		return json.RawMessage(fmt.Sprintf(`{"active":true,"capturing":true,"session_id":%q,"cpu":%q,"mode":%q,"window_ms":100,"interval_ms":1000,"elapsed_ms":42,"windows_started":1,"windows_completed":0,"bytes_written":0,"open_segment":1,"segments":[],"drain":{"next_segment":1,"next_offset":0},"watches":[],"stop_reason":"","auto_stopped":false,"setup_pause":{"guarded":false,"system_was_running":false},"trace_flags_restored":false}`,
			params["session_id"], params["cpu"], params["mode"])), nil
	case "trace_session_drain":
		fake.drains++
		if params["stream"] == "access" {
			maxBytes := 1 << 20
			if parsed, err := strconv.Atoi(params["max_bytes"]); err == nil && parsed > 0 {
				maxBytes = parsed
			}
			if fake.accessSegment >= len(fake.accessSegments) {
				return json.RawMessage(`{"stream":"access","segment_index":0,"offset":0,"bytes":0,"segment_bytes":0,"done":true,"sealed_now":false,"read_failed":false,"evicted_segments":0,"evicted_bytes":0,"evicted_unread_segments":0,"notes":[],"data":""}`), nil
			}
			raw := fake.accessSegments[fake.accessSegment]
			remaining := raw[fake.accessOffset:]
			chunk := remaining
			if len(chunk) > maxBytes {
				chunk = chunk[:maxBytes]
			}
			index := fake.accessSegment + 1
			startOffset := fake.accessOffset
			fake.accessOffset += len(chunk)
			done := false
			if fake.accessOffset >= len(raw) {
				fake.accessSegment++
				fake.accessOffset = 0
				done = fake.accessSegment >= len(fake.accessSegments)
			}
			return json.RawMessage(fmt.Sprintf(`{"stream":"access","segment_index":%d,"offset":%d,"bytes":%d,"segment_bytes":%d,"done":%t,"sealed_now":%t,"read_failed":false,"evicted_segments":0,"evicted_bytes":0,"evicted_unread_segments":0,"notes":[],"data":%q}`,
				index, startOffset, len(chunk), len(raw), done, params["seal"] == "true", base64.StdEncoding.EncodeToString([]byte(chunk)))), nil
		}
		maxBytes := 1 << 20
		if parsed, err := strconv.Atoi(params["max_bytes"]); err == nil && parsed > 0 {
			maxBytes = parsed
		}
		if fake.segment >= len(fake.segments) {
			return json.RawMessage(`{"segment_index":0,"offset":0,"bytes":0,"segment_bytes":0,"done":true,"sealed_now":false,"read_failed":false,"evicted_segments":0,"evicted_bytes":0,"evicted_unread_segments":0,"notes":[],"data":""}`), nil
		}
		raw := fake.segments[fake.segment]
		remaining := raw[fake.offset:]
		chunk := remaining
		if len(chunk) > maxBytes {
			chunk = chunk[:maxBytes]
		}
		index := fake.segment + 1
		startOffset := fake.offset
		fake.offset += len(chunk)
		done := false
		if fake.offset >= len(raw) {
			fake.segment++
			fake.offset = 0
			done = fake.segment >= len(fake.segments)
		}
		return json.RawMessage(fmt.Sprintf(`{"segment_index":%d,"offset":%d,"bytes":%d,"segment_bytes":%d,"done":%t,"sealed_now":%t,"read_failed":false,"evicted_segments":0,"evicted_bytes":0,"evicted_unread_segments":0,"notes":[],"data":%q}`,
			index, startOffset, len(chunk), len(raw), done, params["seal"] == "true", base64.StdEncoding.EncodeToString([]byte(chunk)))), nil
	case "trace_session_status":
		watchJSON := "[]"
		if fake.watch != nil {
			fake.watchHit++
			watchJSON = fmt.Sprintf(`[{"watchpoint_id":4,"address":%d,"length":%d,"access":%q,"hits":%d,"delta":1,"hits_since_start":%d,"lost":false}]`,
				fake.watch.Address, fake.watch.Length, fake.watch.Access, fake.watchHit, fake.watchHit)
		}
		return json.RawMessage(fmt.Sprintf(`{"active":%t,"capturing":false,"session_id":"trs_live","cpu":"m68k","mode":"sampled","window_ms":100,"interval_ms":1000,"elapsed_ms":1500,"windows_started":2,"windows_completed":1,"bytes_written":128,"open_segment":2,"segments":[{"index":1,"bytes":128,"sealed":true,"drained":false}],"drain":{"next_segment":1,"next_offset":0},"watches":%s,"stop_reason":"","auto_stopped":false,"setup_pause":{"guarded":false,"system_was_running":false},"trace_flags_restored":false,"notes":[],"evicted_segments":0,"evicted_bytes":0,"evicted_unread_segments":0}`,
			!fake.stopped, watchJSON)), nil
	case "trace_session_stop":
		fake.stopped = true
		return json.RawMessage(`{"active":false,"capturing":false,"session_id":"trs_live","cpu":"m68k","mode":"sampled","elapsed_ms":2000,"windows_started":2,"windows_completed":2,"bytes_written":256,"open_segment":0,"segments":[{"index":1,"bytes":128,"sealed":true,"drained":true},{"index":2,"bytes":128,"sealed":true,"drained":true}],"drain":{"next_segment":3,"next_offset":0},"watches":[],"stop_reason":"stopped","auto_stopped":false,"setup_pause":{"guarded":false,"system_was_running":false},"trace_flags_restored":true,"notes":[],"evicted_segments":0,"evicted_bytes":0,"evicted_unread_segments":0,"deleted_segments":true,"stopped_now":true}`), nil
	default:
		return nil, fmt.Errorf("unexpected method %s", method)
	}
}

// fakeTraceSegment builds one engine-format trace segment.
func fakeTraceSegment(entries ...[3]string) string {
	var builder strings.Builder
	for index, entry := range entries {
		builder.WriteString(entry[0])
		builder.WriteString("\t")
		builder.WriteString(entry[1])
		builder.WriteString("\t")
		builder.WriteString(entry[2])
		builder.WriteString("\t\t")
		builder.WriteString(strconv.Itoa(100 + index*4))
		builder.WriteString("\t0.")
		builder.WriteString(strconv.Itoa(index + 1))
		builder.WriteString("\n")
	}
	return builder.String()
}

func TestTraceSessionLifecycle(t *testing.T) {
	segmentOne := fakeTraceSegment(
		[3]string{"00FF0000", "MOVE.W", "#$0,D0"},
		[3]string{"00FF0004", "BSR", "$FF0100"},
		[3]string{"00001000", "NOP", ""},
	)
	segmentTwo := fakeTraceSegment([3]string{"00FF0008", "RTS", ""})
	fake := newTraceSessionFake(segmentOne, segmentTwo)
	server := newTestServer(t, fake.client())

	start := structured(postToolCall(t, server, "trace_session_start",
		`{"cpu":"m68k","stop_after_vdp_frames":3,"watches":[{"address":"0xFF0000","length":4,"access":"write"}]}`))
	if start["code"] != nil {
		t.Fatalf("start failed: %v", start)
	}
	session, _ := start["session"].(map[string]any)
	if session == nil || session["state"] != "live" {
		t.Fatalf("session view wrong: %v", start["session"])
	}
	if start["target_generation_before"] != float64(1) || start["target_generation_after"] != float64(2) {
		t.Fatalf("start generations wrong: %v", start)
	}
	if fake.started0["watch_count"] != "1" || fake.started0["watch0_address"] != strconv.Itoa(0xFF0000) ||
		fake.started0["watch0_length"] != "4" || fake.started0["watch0_access"] != "write" {
		t.Fatalf("watch encoding wrong: %v", fake.started0)
	}
	if fake.started0["stop_after_vdp_frames"] != "3" {
		t.Fatalf("VDP frame stop threshold not forwarded: %v", fake.started0)
	}
	if _, ok := start["limitations"].(map[string]any); !ok {
		t.Fatalf("limitations missing: %v", start)
	}

	events := structured(postToolCall(t, server, "trace_session_events", `{"kind":"execute"}`))
	if events["code"] != nil {
		t.Fatalf("events failed: %v", events)
	}
	drained, _ := events["drained"].(map[string]any)
	if drained["complete"] != true || drained["events"] != float64(4) {
		t.Fatalf("drain summary wrong: %v", drained)
	}
	if events["event_count"] != float64(4) {
		t.Fatalf("event count = %v, want 4", events["event_count"])
	}
	counts, _ := events["address_counts"].([]any)
	if len(counts) != 4 {
		t.Fatalf("address counts = %d, want 4", len(counts))
	}

	filtered := structured(postToolCall(t, server, "trace_session_events",
		`{"kind":"execute","address_range_start":"0xFF0000","address_range_end":"0xFF0008"}`))
	if filtered["event_count"] != float64(2) {
		t.Fatalf("filtered event count = %v, want 2", filtered["event_count"])
	}
	filters, _ := filtered["filters"].(map[string]any)
	if filters["applied_after_capture"] != true {
		t.Fatalf("filter provenance missing: %v", filters)
	}

	stop := structured(postToolCall(t, server, "trace_session_stop", `{}`))
	if stop["code"] != nil {
		t.Fatalf("stop failed: %v", stop)
	}
	stopSession, _ := stop["session"].(map[string]any)
	if stopSession["state"] != "stopped" {
		t.Fatalf("stop state = %v", stopSession["state"])
	}
	if artifact, ok := stop["artifact"].(map[string]any); ok {
		if artifact["kind"] != "trace-session-jsonl" {
			t.Fatalf("artifact kind = %v", artifact["kind"])
		}
	} else {
		t.Fatalf("stop must export by default: %v", stop)
	}
}

func TestTraceSessionStartHasNoDefaultFrameExpiry(t *testing.T) {
	fake := newTraceSessionFake()
	server := newTestServer(t, fake.client())
	result := structured(postToolCall(t, server, "trace_session_start", `{"cpu":"m68k"}`))
	if result["code"] != nil {
		t.Fatalf("start failed: %v", result)
	}
	if got := fake.started0["stop_after_vdp_frames"]; got != "0" {
		t.Fatalf("omitted stop_after_vdp_frames forwarded as %q, want 0 (unbounded)", got)
	}
	if _, exists := fake.started0["max_duration_ms"]; exists {
		t.Fatalf("wall-clock expiry must not be configured by default: %v", fake.started0)
	}
}

func TestTraceSessionStartRejectsExcessiveFrameLimit(t *testing.T) {
	fake := newTraceSessionFake()
	server := newTestServer(t, fake.client())
	result := structured(postToolCall(t, server, "trace_session_start", `{"cpu":"m68k","stop_after_vdp_frames":1000000001}`))
	if result["code"] != "invalid_params" {
		t.Fatalf("expected invalid_params, got %v", result)
	}
	if fake.started {
		t.Fatal("invalid frame limit reached native bridge")
	}
}

func TestTraceSessionDrainHonorsByteBudget(t *testing.T) {
	segment := fakeTraceSegment(
		[3]string{"00FF0000", "MOVE.W", "#$0,D0"},
		[3]string{"00FF0004", "NOP", ""},
	)
	fake := newTraceSessionFake(segment)
	server := newTestServer(t, fake.client())
	if result := structured(postToolCall(t, server, "trace_session_start", `{"cpu":"m68k"}`)); result["code"] != nil {
		t.Fatalf("start failed: %v", result)
	}
	// A tiny budget must stop mid-segment and report that the drain is not
	// complete, leaving the native cursor for the next call.
	partial := structured(postToolCall(t, server, "trace_session_status", `{"max_collect_bytes":4096}`))
	if partial["code"] != nil {
		t.Fatalf("status failed: %v", partial)
	}
	drained, _ := partial["drained"].(map[string]any)
	if drained["complete"] != true {
		t.Fatalf("small segment should drain fully: %v", drained)
	}
	if fake.drains == 0 {
		t.Fatal("status did not drain the native segment")
	}
}

func TestTraceSessionDrainReassemblesSplitLines(t *testing.T) {
	entries := make([][3]string, 0, 300)
	for index := 0; index < 300; index++ {
		entries = append(entries, [3]string{
			fmt.Sprintf("%06X", 0xFF0000+index*2),
			"MOVE.W",
			"#$0,D0",
		})
	}
	segment := fakeTraceSegment(entries...)
	if len(segment) <= 4096 {
		t.Fatalf("fixture too small to split: %d bytes", len(segment))
	}
	fake := newTraceSessionFake(segment)
	server := newTestServer(t, fake.client())
	if result := structured(postToolCall(t, server, "trace_session_start", `{"cpu":"m68k"}`)); result["code"] != nil {
		t.Fatalf("start failed: %v", result)
	}
	// A chunk smaller than the segment forces a mid-line split; no line may be
	// lost or double counted across the boundary.
	first := structured(postToolCall(t, server, "trace_session_events",
		`{"collect":true,"max_collect_bytes":4096,"limit":1}`))
	drained, _ := first["drained"].(map[string]any)
	if drained["complete"] != false {
		t.Fatalf("first drain should stop at the budget: %v", drained)
	}
	second := structured(postToolCall(t, server, "trace_session_events", `{"limit":1}`))
	finalDrain, _ := second["drained"].(map[string]any)
	session, _ := second["session"].(map[string]any)
	parse, _ := session["parse"].(map[string]any)
	if parse["malformed_lines"] != float64(0) || parse["truncated_lines"] != float64(0) {
		t.Fatalf("split chunks must not corrupt lines: parse=%v drain=%v", parse, finalDrain)
	}
	if parse["events"] != float64(300) {
		t.Fatalf("events = %v, want 300", parse["events"])
	}
	if fake.drains < 2 {
		t.Fatalf("expected multiple drain calls, got %d", fake.drains)
	}
}

func TestTraceSessionEventsExportArtifact(t *testing.T) {
	segment := fakeTraceSegment(
		[3]string{"00FF0000", "MOVE.W", "#$0,D0"},
		[3]string{"00FF0004", "NOP", ""},
	)
	fake := newTraceSessionFake(segment)
	server := newTestServer(t, fake.client())
	if result := structured(postToolCall(t, server, "trace_session_start", `{"cpu":"m68k"}`)); result["code"] != nil {
		t.Fatalf("start failed: %v", result)
	}
	exported := structured(postToolCall(t, server, "trace_session_events", `{"export":true}`))
	descriptor, ok := exported["artifact"].(map[string]any)
	if !ok {
		t.Fatalf("artifact missing: %v", exported)
	}
	id, _ := descriptor["id"].(string)
	stored, artifactMeta, err := server.store.Bytes(id, testContextID(t, server))
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	if artifactMeta.Kind != "trace-session-jsonl" {
		t.Fatalf("artifact kind = %s", artifactMeta.Kind)
	}
	lines := strings.Split(strings.TrimSpace(string(stored)), "\n")
	if len(lines) != 2 {
		t.Fatalf("exported lines = %d, want 2", len(lines))
	}
	var event map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &event); err != nil {
		t.Fatalf("decode exported event: %v", err)
	}
	if event["kind"] != "execute" || event["address_space"] != "m68k-bus" {
		t.Fatalf("exported event wrong: %v", event)
	}
	provenance, _ := descriptor["provenance"].(map[string]any)
	if provenance["address_space"] != "m68k-bus" || provenance["byte_order"] != "big-endian" {
		t.Fatalf("provenance wrong: %v", provenance)
	}
}

func TestTraceSessionWatchCountersBecomeSamples(t *testing.T) {
	segment := fakeTraceSegment([3]string{"00FF0000", "NOP", ""})
	fake := newTraceSessionFake(segment)
	server := newTestServer(t, fake.client())
	if result := structured(postToolCall(t, server, "trace_session_start",
		`{"cpu":"m68k","watches":[{"address":"0xFF0000","length":4,"access":"write"}]}`)); result["code"] != nil {
		t.Fatalf("start failed: %v", result)
	}
	for i := 0; i < 3; i++ {
		if result := structured(postToolCall(t, server, "trace_session_status", `{}`)); result["code"] != nil {
			t.Fatalf("status failed: %v", result)
		}
	}
	events := structured(postToolCall(t, server, "trace_session_events", `{"kind":"write"}`))
	// Three status calls plus the status the query itself performs sample the
	// counter once each; every sample becomes one aggregate event.
	if events["event_count"] != float64(4) {
		t.Fatalf("write samples = %v, want 4", events["event_count"])
	}
	sample, _ := events["events"].([]any)
	if len(sample) == 0 {
		t.Fatal("aggregate sample missing")
	}
	first, _ := sample[0].(map[string]any)
	if first["aggregation"] != "range-sample" || first["kind"] != "write" {
		t.Fatalf("aggregate view wrong: %v", first)
	}
}

func TestTraceSessionRequiresLiveSession(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.status.SupportedOperations = append(client.status.SupportedOperations, "trace_session_status")
	result := callTool(t, client, "trace_session_status", `{}`)
	content := structured(result)
	if result["isError"] != true || content["code"] != "no_trace_session" {
		t.Fatalf("expected no_trace_session: %v", result)
	}
}

func TestTraceSessionStartValidatesBounds(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.status.SupportedOperations = append(client.status.SupportedOperations, "trace_session_start")
	result := callTool(t, client, "trace_session_start", `{"cpu":"m68k","window_ms":1}`)
	content := structured(result)
	if result["isError"] != true || content["code"] != "invalid_params" {
		t.Fatalf("expected invalid_params: %v", result)
	}
	badCPU := callTool(t, client, "trace_session_start", `{"cpu":"6502"}`)
	if badCPU["isError"] != true {
		t.Fatalf("expected cpu validation failure: %v", badCPU)
	}
}

func TestTraceSessionStartRejectsWatchOutsideBus(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.status.SupportedOperations = append(client.status.SupportedOperations, "trace_session_start")
	result := callTool(t, client, "trace_session_start",
		`{"cpu":"m68k","watches":[{"address":"0x1000000","length":2}]}`)
	content := structured(result)
	if result["isError"] != true || content["code"] != "invalid_params" {
		t.Fatalf("expected watch range validation failure: %v", result)
	}
	if !strings.Contains(content["message"].(string), "watches[0]") {
		t.Fatalf("message should name the watch index: %v", content["message"])
	}
}

// fakeAccessSegment builds a per-access stream segment in the fork's contract
// format: sequence, cycle, direction, location, value, previous, width, pc,
// registers.
func fakeAccessSegment(lines ...string) string {
	return strings.Join(lines, "\n") + "\n"
}

// TestTraceSessionAccessCapture covers per-occurrence read/write records: the
// native request, the parsed event shape, direction and effective-value
// filtering, and the explicit sequence-gap loss.
func TestTraceSessionAccessCapture(t *testing.T) {
	access := fakeAccessSegment(
		"1\t100\tW\tff0000\t42\t-\t8\tff0100\t1,2,3",
		"2\t104\tR\tff0002\t7\t-\t16\tff0102\t-",
		"4\t108\tW\tff0000\t43\t-\t8\tff0100\t-",
	)
	fake := newTraceSessionFake()
	fake.accessSegments = []string{access}
	server := newTestServer(t, fake.client())

	start := structured(postToolCall(t, server, "trace_session_start",
		`{"cpu":"m68k","access_capture":"ranges","watches":[{"address":"0xFF0000","length":4,"access":"write"}]}`))
	if start["code"] != nil {
		t.Fatalf("start failed: %v", start)
	}
	if fake.started0["access_capture"] != "ranges" || fake.started0["access_include_registers"] != "true" {
		t.Fatalf("access parameters not forwarded: %v", fake.started0)
	}
	if fake.started0["access_max_bytes"] != strconv.Itoa(traceSessionDefaultAccessBytes) {
		t.Fatalf("access byte cap not forwarded: %v", fake.started0)
	}
	volume, _ := start["volume"].(map[string]any)
	if volume == nil {
		t.Fatalf("volume object missing: %v", start)
	}
	limits, _ := volume["limits"].(map[string]any)
	if limits["access_capture"] != "ranges" {
		t.Fatalf("volume limits wrong: %v", limits)
	}
	if _, ok := volume["access_estimate"].(map[string]any); !ok {
		t.Fatalf("access estimate missing: %v", volume)
	}

	events := structured(postToolCall(t, server, "trace_session_events", `{"direction":"write","limit":10}`))
	if events["code"] != nil {
		t.Fatalf("events failed: %v", events)
	}
	list, _ := events["events"].([]any)
	if len(list) != 2 {
		t.Fatalf("expected two write records, got %d: %v", len(list), list)
	}
	first, _ := list[0].(map[string]any)
	if first["direction"] != "write" || first["value"] != float64(0x42) || first["value_state"] != "written" {
		t.Fatalf("write record shape wrong: %v", first)
	}
	if first["width_bits"] != float64(8) || first["sequence"] != float64(1) || first["pc_hex"] == nil {
		t.Fatalf("record metadata wrong: %v", first)
	}
	if first["previous_known"] != false {
		t.Fatalf("previous value must not be claimed: %v", first)
	}
	if _, ok := first["registers"].(map[string]any); !ok {
		t.Fatalf("register snapshot missing: %v", first)
	}
	sessionView, _ := events["session"].(map[string]any)
	// Three raw access records plus one aggregate watch sample coexist in the
	// store; the direction filter selected only the writes.
	retainedBefore := sessionView["retained_events"]
	if retainedBefore == nil || retainedBefore.(float64) < 3 {
		t.Fatalf("raw access records missing from the store: %v", retainedBefore)
	}
	loss, _ := events["loss"].(map[string]any)
	if loss["access_sequence_gaps"] != float64(1) {
		t.Fatalf("sequence gap loss missing: %v", loss)
	}
	if loss["complete"] != false {
		t.Fatalf("a sequence gap must mark the loss incomplete: %v", loss)
	}
	symbolView, _ := events["symbols"].(map[string]any)
	if symbolView["applied"] != false || symbolView["reason"] != "session_unbound_no_rom_hash" {
		t.Fatalf("unbound session must suppress symbol resolution: %v", symbolView)
	}
	filters, _ := events["filters"].(map[string]any)
	if filters["direction"] != "write" || filters["effective_value_filters_keep_raw_events"] != true {
		t.Fatalf("filter provenance wrong: %v", filters)
	}

	// Effective-value selection: value 0x43 only, and the raw store is intact.
	byValue := structured(postToolCall(t, server, "trace_session_events", `{"value_equals":"0x43","limit":10}`))
	if byValue["code"] != nil {
		t.Fatalf("value filter failed: %v", byValue)
	}
	valueList, _ := byValue["events"].([]any)
	if len(valueList) != 1 {
		t.Fatalf("expected exactly one 0x43 record: %v", valueList)
	}
	selected, _ := valueList[0].(map[string]any)
	if selected["sequence"] != float64(4) {
		t.Fatalf("value filter selected the wrong record: %v", selected)
	}
	retainedAfter, _ := byValue["session"].(map[string]any)["retained_events"]
	if after, ok := retainedAfter.(float64); !ok || after < retainedBefore.(float64) {
		t.Fatalf("value filter shrank the raw store: %v (was %v)", retainedAfter, retainedBefore)
	}
	// The filtered-out raw record is still queryable by sequence.
	bySequence := structured(postToolCall(t, server, "trace_session_events", `{"sequence_min":4,"sequence_max":4,"limit":10,"collect":false}`))
	sequenceList, _ := bySequence["events"].([]any)
	if len(sequenceList) != 1 {
		t.Fatalf("raw record dropped by value filtering: %v", sequenceList)
	}
}

// TestTraceSessionRecoverListsAndRestoresManifests covers the restart-recovery
// path: a manifest written by a previous server process is discoverable, and an
// installed recovery view reports the manifest's loss instead of pretending to
// be a live capture.
func TestTraceSessionRecoverListsAndRestoresManifests(t *testing.T) {
	directory := t.TempDir()
	session := tracing.NewSession("trs_recover", "ctx", "m68k", "m68k-bus", tracing.Config{
		CPU: "m68k", Mode: "sampled", MaxEvents: 128, AccessCapture: "ranges",
	})
	session.MarkROMIdentity("deadbeef")
	session.AddAccessEvents([]tracing.Event{{
		Kind: tracing.KindWrite, Direction: tracing.DirectionWrite, Sequence: 1,
		Address: 0xff0000, AddressHex: "0xFF0000", Value: 1, ValueKnown: true, WidthBits: 8, PC: 0xff0100,
	}})
	manifest := tracing.NewManifest(session, "", "deadbeef", nil)
	if _, err := manifest.Save(directory); err != nil {
		t.Fatalf("save manifest: %v", err)
	}

	server := newTestServer(t, newTraceSessionFake().client())
	server.SetTraceSessionsDir(directory)

	list := structured(postToolCall(t, server, "trace_session_recover", `{}`))
	if list["code"] != nil {
		t.Fatalf("recover list failed: %v", list)
	}
	entries, _ := list["manifests"].([]any)
	if len(entries) != 1 {
		t.Fatalf("expected one manifest: %v", list["manifests"])
	}

	restored := structured(postToolCall(t, server, "trace_session_recover", `{"session_id":"trs_recover","install":true}`))
	if restored["code"] != nil {
		t.Fatalf("recover failed: %v", restored)
	}
	view, _ := restored["restored"].(map[string]any)
	if view == nil || view["session_id"] != "trs_recover" {
		t.Fatalf("restored view wrong: %v", restored["restored"])
	}
	if view["rom_bound"] != false {
		t.Fatalf("recovery must report the ROM binding mismatch: %v", view)
	}
	install, _ := restored["install"].(map[string]any)
	if install == nil || install["installed"] != true {
		t.Fatalf("install result wrong: %v", restored["install"])
	}
	live := server.traces.Current()
	if live == nil || live.ID != "trs_recover" || !live.Stopped {
		t.Fatalf("recovered session not installed as a stopped view: %+v", live)
	}
}

// TestTraceSessionRetiredOnROMLoad covers the cartridge-reload edge: the plugin
// stops the native session while the module unloads, so the server must report
// the same end (and keep the drained events queryable) instead of presenting a
// dead session as live.
func TestTraceSessionRetiredOnROMLoad(t *testing.T) {
	fake := newTraceSessionFake(fakeTraceSegment([3]string{"00FF0000", "NOP", ""}))
	client := fake.client()
	romLoad := client.executeFunc
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method == "rom_load" {
			return json.RawMessage(`{"path":"F:\\roms\\other.bin","loaded":true,"system_running":false}`), nil
		}
		return romLoad(ctx, method, params)
	}
	server := newTestServer(t, client)

	start := structured(postToolCall(t, server, "trace_session_start", `{"cpu":"m68k"}`))
	if start["code"] != nil {
		t.Fatalf("start failed: %v", start)
	}
	// Drain while the native session is still alive so the store has events to
	// preserve across the reload.
	drained := structured(postToolCall(t, server, "trace_session_events", `{"limit":5}`))
	if drained["code"] != nil {
		t.Fatalf("initial drain failed: %v", drained)
	}
	loaded := structured(postToolCall(t, server, "rom_load", `{"path":"F:\\roms\\other.bin"}`))
	if loaded["code"] != nil {
		t.Fatalf("rom_load failed: %v", loaded)
	}
	status := structured(postToolCall(t, server, "trace_session_status", `{"collect":false}`))
	session, _ := status["session"].(map[string]any)
	if session["state"] != "stopped" || session["stopped"] != true {
		t.Fatalf("a cartridge reload must retire the session: %v", session)
	}
	loss, _ := status["loss"].(map[string]any)
	notes, _ := loss["notes"].([]any)
	found := false
	for _, note := range notes {
		if text, ok := note.(string); ok && strings.Contains(text, "reloaded") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the loss notes must explain why capture stopped: %v", notes)
	}
	// Drained events remain queryable after the retirement.
	events := structured(postToolCall(t, server, "trace_session_events", `{"collect":false,"limit":5}`))
	if events["code"] != nil {
		t.Fatalf("events after retirement failed: %v", events)
	}
	if events["event_count"] == float64(0) {
		t.Fatalf("retained events must stay queryable: %v", events["event_count"])
	}
}

// traceSessionLossFixture builds one session for the completeness contract
// tests. It never touches the native bridge: loss.complete is computed from the
// session configuration and loss counters alone.
func traceSessionLossFixture(mode string, windowMs, intervalMs uint64) *tracing.Session {
	return tracing.NewSession("trs_loss", "ctx", "m68k", "m68k-bus", tracing.Config{
		CPU: "m68k", Mode: mode, WindowMs: windowMs, IntervalMs: intervalMs, MaxEvents: 64,
	})
}

// TestTraceSessionLossCompletenessByMode pins the definition of loss.complete:
// the capture covered the requested window with no gaps. A sampled session is
// never complete; a continuous session is complete only while nothing was lost.
func TestTraceSessionLossCompletenessByMode(t *testing.T) {
	cases := []struct {
		name         string
		mode         string
		windowMs     uint64
		intervalMs   uint64
		loseData     bool
		wantComplete bool
		wantSampled  bool
		wantDuty     float64
		wantUntraced uint64
		wantReason   string
	}{
		{
			name: "sampled default is never complete", mode: "sampled",
			windowMs: 100, intervalMs: 10000,
			wantComplete: false, wantSampled: true, wantDuty: 0.01, wantUntraced: 9900,
			wantReason: "sampled_mode",
		},
		{
			name: "sampled with loss keeps the sampled reason first", mode: "sampled",
			windowMs: 100, intervalMs: 1000, loseData: true,
			wantComplete: false, wantSampled: true, wantDuty: 0.1, wantUntraced: 900,
			wantReason: "malformed_lines",
		},
		{
			name: "continuous without loss is complete", mode: "continuous",
			windowMs: 100, intervalMs: 10000,
			wantComplete: true, wantSampled: false, wantDuty: 1, wantUntraced: 0,
		},
		{
			name: "continuous with loss is incomplete", mode: "continuous",
			windowMs: 100, intervalMs: 10000, loseData: true,
			wantComplete: false, wantSampled: false, wantDuty: 1, wantUntraced: 0,
			wantReason: "malformed_lines",
		},
		{
			name: "unknown mode is treated as sampled",
			mode: "", windowMs: 0, intervalMs: 0,
			wantComplete: false, wantSampled: true, wantDuty: 0, wantUntraced: 0,
			wantReason: "sampled_mode",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			session := traceSessionLossFixture(testCase.mode, testCase.windowMs, testCase.intervalMs)
			if testCase.loseData {
				session.AddParseStats(tracing.ParseStats{Malformed: 1})
			}
			view := traceSessionLossView(session)
			if view["complete"] != testCase.wantComplete {
				t.Fatalf("complete = %v, want %v (%v)", view["complete"], testCase.wantComplete, view)
			}
			if view["capture_is_sampled"] != testCase.wantSampled {
				t.Fatalf("capture_is_sampled = %v, want %v", view["capture_is_sampled"], testCase.wantSampled)
			}
			if view["sampled_mode_gaps"] != testCase.wantSampled {
				t.Fatalf("sampled_mode_gaps = %v, want %v", view["sampled_mode_gaps"], testCase.wantSampled)
			}
			definition, _ := view["complete_definition"].(string)
			if !strings.Contains(definition, "covered the requested window with no gaps") {
				t.Fatalf("complete_definition must state the coverage definition: %q", definition)
			}
			capture, _ := view["capture"].(map[string]any)
			if capture == nil {
				t.Fatalf("capture coverage facts missing: %v", view)
			}
			wantMode := "continuous"
			if testCase.wantSampled {
				wantMode = "sampled"
			}
			if capture["mode"] != wantMode {
				t.Fatalf("capture.mode = %v, want %v", capture["mode"], wantMode)
			}
			duty, _ := capture["duty_cycle"].(float64)
			if duty != testCase.wantDuty {
				t.Fatalf("capture.duty_cycle = %v, want %v", duty, testCase.wantDuty)
			}
			if capture["untraced_ms_per_interval"] != testCase.wantUntraced {
				t.Fatalf("capture.untraced_ms_per_interval = %v, want %v", capture["untraced_ms_per_interval"], testCase.wantUntraced)
			}
			reasons, _ := view["incomplete_reasons"].([]string)
			if testCase.wantComplete {
				if len(reasons) != 0 {
					t.Fatalf("a complete capture must list no reasons: %v", reasons)
				}
				if _, exists := view["note"]; exists {
					t.Fatalf("a complete capture must not carry a loss note: %v", view["note"])
				}
				return
			}
			if len(reasons) == 0 {
				t.Fatalf("an incomplete capture must list its reasons: %v", view)
			}
			if testCase.wantReason != "" {
				found := false
				for _, reason := range reasons {
					if reason == testCase.wantReason {
						found = true
					}
				}
				if !found {
					t.Fatalf("incomplete_reasons = %v, want %q", reasons, testCase.wantReason)
				}
			}
			if _, exists := view["note"]; !exists {
				t.Fatalf("an incomplete capture must explain itself: %v", view)
			}
		})
	}
}

// TestTraceSessionStatusReportsCaptureCoverage checks the same contract through
// the tools: the default sampled session can never report a complete capture,
// while a continuous session reports completeness and its full duty cycle, and
// the default collect=true call leaves the session queryable as live.
func TestTraceSessionStatusReportsCaptureCoverage(t *testing.T) {
	sampledFake := newTraceSessionFake(fakeTraceSegment([3]string{"00FF0000", "NOP", ""}))
	sampledServer := newTestServer(t, sampledFake.client())
	if result := structured(postToolCall(t, sampledServer, "trace_session_start", `{"cpu":"m68k"}`)); result["code"] != nil {
		t.Fatalf("sampled start failed: %v", result)
	}
	sampled := structured(postToolCall(t, sampledServer, "trace_session_status", `{}`))
	if sampled["code"] != nil {
		t.Fatalf("sampled status failed: %v", sampled)
	}
	sampledLoss, _ := sampled["loss"].(map[string]any)
	if sampledLoss == nil {
		t.Fatalf("sampled loss missing: %v", sampled)
	}
	if sampledLoss["complete"] != false {
		t.Fatalf("a sampled session must never report a complete capture: %v", sampledLoss)
	}
	if sampledLoss["capture_is_sampled"] != true || sampledLoss["sampled_mode_gaps"] != true {
		t.Fatalf("sampled capture flags wrong: %v", sampledLoss)
	}
	sampledCapture, _ := sampledLoss["capture"].(map[string]any)
	if sampledCapture == nil || sampledCapture["mode"] != "sampled" {
		t.Fatalf("sampled capture facts wrong: %v", sampledLoss)
	}
	// Defaults: window_ms 100 of every interval_ms 10000 → a 1 % duty cycle.
	if sampledCapture["duty_cycle"] != 0.01 || sampledCapture["untraced_ms_per_interval"] != float64(9900) {
		t.Fatalf("sampled coverage must state the 1%% duty cycle: %v", sampledCapture)
	}
	sampledReasons, _ := sampledLoss["incomplete_reasons"].([]any)
	if len(sampledReasons) != 1 || sampledReasons[0] != "sampled_mode" {
		t.Fatalf("sampled incomplete_reasons = %v", sampledReasons)
	}
	drained, _ := sampled["drained"].(map[string]any)
	if drained["complete"] != true {
		t.Fatalf("the drain itself must still be complete: %v", drained)
	}
	if definition, _ := drained["complete_definition"].(string); !strings.Contains(definition, "drain cursor") {
		t.Fatalf("drained.complete must state its own scope: %q", definition)
	}

	continuousFake := newTraceSessionFake(fakeTraceSegment([3]string{"00FF0000", "NOP", ""}))
	continuousServer := newTestServer(t, continuousFake.client())
	started := structured(postToolCall(t, continuousServer, "trace_session_start",
		`{"cpu":"m68k","mode":"continuous","segment_ms":250}`))
	if started["code"] != nil {
		t.Fatalf("continuous start failed: %v", started)
	}
	startLoss, _ := started["loss"].(map[string]any)
	if startLoss["complete"] != true || startLoss["capture_is_sampled"] != false {
		t.Fatalf("a fresh continuous session is complete: %v", startLoss)
	}
	// Two default status calls, each draining, must leave the session live and
	// its capture complete: collect must never be reported as ending capture.
	for attempt := 0; attempt < 2; attempt++ {
		status := structured(postToolCall(t, continuousServer, "trace_session_status", `{}`))
		if status["code"] != nil {
			t.Fatalf("continuous status %d failed: %v", attempt, status)
		}
		loss, _ := status["loss"].(map[string]any)
		if loss["complete"] != true || loss["capture_is_sampled"] != false {
			t.Fatalf("continuous status %d must stay complete: %v", attempt, loss)
		}
		if reasons, _ := loss["incomplete_reasons"].([]any); len(reasons) != 0 {
			t.Fatalf("continuous status %d reported reasons: %v", attempt, reasons)
		}
		capture, _ := loss["capture"].(map[string]any)
		if capture["duty_cycle"] != float64(1) {
			t.Fatalf("continuous capture duty_cycle = %v, want 1", capture["duty_cycle"])
		}
		session, _ := status["session"].(map[string]any)
		if session["state"] != "live" || session["stopped"] != false {
			t.Fatalf("collect must not end a continuous session: %v", session["state"])
		}
		if events, _ := status["drained"].(map[string]any); events["complete"] != true {
			t.Fatalf("continuous drain %d incomplete: %v", attempt, events)
		}
	}
}
