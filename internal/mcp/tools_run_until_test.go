package mcp

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/StealthC/exodus-mcp/internal/analysis"
)

// runUntilFake simulates the native side of the run_until / one-shot flows:
// a stateful emulator with managed breakpoints and watchpoints that report
// hit counters, plus scriptable hooks so tests can model a native stop or a
// foreign pause.
type runUntilFake struct {
	t *testing.T

	running bool
	// fireOnStatusCall transitions running -> paused and bumps the first
	// zeroed instrument hit counter to fireHitValue once that many
	// emulator_status calls happened; 0 disables the hook.
	fireOnStatusCall int
	fireHitValue     uint64
	// pauseOnStatusCall transitions running -> paused without touching hit
	// counters (a foreign pause) after that many emulator_status calls.
	pauseOnStatusCall int
	statusCalls       int

	bpHits    map[uint64]uint64
	removedBP map[uint64]bool
	nextBPID  uint64
	wpHits    map[uint64]uint64
	removedWP map[uint64]bool
	nextWPID  uint64

	calls []string
}

func newRunUntilFake(t *testing.T) *runUntilFake {
	return &runUntilFake{
		t:         t,
		running:   false,
		bpHits:    map[uint64]uint64{},
		removedBP: map[uint64]bool{},
		wpHits:    map[uint64]uint64{},
		removedWP: map[uint64]bool{},
	}
}

func (fake *runUntilFake) record(method string) {
	fake.calls = append(fake.calls, method)
}

func (fake *runUntilFake) execute() func(context.Context, string, map[string]string) (json.RawMessage, error) {
	return func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		fake.record(method)
		switch method {
		case "emulator_status":
			fake.statusCalls++
			if fake.pauseOnStatusCall > 0 && fake.statusCalls >= fake.pauseOnStatusCall && fake.running {
				fake.running = false
			}
			if fake.fireOnStatusCall > 0 && fake.statusCalls >= fake.fireOnStatusCall && fake.running {
				fake.running = false
				hit := fake.fireHitValue
				if hit == 0 {
					hit = 1
				}
				for id := range fake.bpHits {
					if fake.bpHits[id] == 0 {
						fake.bpHits[id] = hit
					}
				}
				for id := range fake.wpHits {
					if fake.wpHits[id] == 0 {
						fake.wpHits[id] = hit
					}
				}
			}
			return json.RawMessage("{\"system_running\":" + boolString(fake.running) + ",\"modules\":[],\"devices\":[],\"rom\":{\"loaded\":false}}"), nil
		case "cpu_control":
			switch params["action"] {
			case "run":
				fake.running = true
			case "pause":
				fake.running = false
			}
			return json.RawMessage("{\"action\":\"" + params["action"] + "\",\"system_running\":" + boolString(fake.running) + "}"), nil
		case "breakpoint_set":
			fake.nextBPID++
			fake.bpHits[fake.nextBPID] = 0
			return json.RawMessage("{\"breakpoint_id\":" + strconv.FormatUint(fake.nextBPID, 10) + ",\"cpu\":\"m68k\"}"), nil
		case "breakpoint_remove":
			id := mustParseID(fake.t, params["breakpoint_id"])
			fake.removedBP[id] = true
			return json.RawMessage("{\"removed\":true,\"breakpoint_id\":" + params["breakpoint_id"] + "}"), nil
		case "breakpoint_list":
			return json.RawMessage("{\"breakpoints\":" + fake.bpListJSON() + "}"), nil
		case "watchpoint_set":
			fake.nextWPID++
			fake.wpHits[fake.nextWPID] = 0
			return json.RawMessage("{\"watchpoint_id\":" + strconv.FormatUint(fake.nextWPID, 10) + ",\"cpu\":\"m68k\",\"address\":4096,\"length\":1,\"access\":\"any\",\"break_on_hit\":true}"), nil
		case "watchpoint_remove":
			id := mustParseID(fake.t, params["watchpoint_id"])
			fake.removedWP[id] = true
			return json.RawMessage("{\"removed\":true,\"watchpoint_id\":" + params["watchpoint_id"] + "}"), nil
		case "watchpoint_list":
			return json.RawMessage("{\"watchpoints\":" + fake.wpListJSON() + "}"), nil
		case "regs_get":
			return json.RawMessage("{\"cpu\":\"m68k\",\"byte_order\":\"not-applicable\",\"registers\":{\"pc\":4096,\"d0\":0,\"a7\":16711680}}"), nil
		case "vdp_status":
			return json.RawMessage("{\"image_buffer\":{\"last_rendered_frame_token\":0}}"), nil
		}
		return json.RawMessage("{}"), nil
	}
}

func (fake *runUntilFake) bpListJSON() string {
	entries := make([]string, 0)
	for id, hits := range fake.bpHits {
		if fake.removedBP[id] {
			continue
		}
		entries = append(entries, "{\"breakpoint_id\":"+strconv.FormatUint(id, 10)+",\"cpu\":\"m68k\",\"address\":4096,\"hit_count\":"+strconv.FormatUint(hits, 10)+",\"enabled\":true}")
	}
	return "[" + strings.Join(entries, ",") + "]"
}

func (fake *runUntilFake) wpListJSON() string {
	entries := make([]string, 0)
	for id, hits := range fake.wpHits {
		if fake.removedWP[id] {
			continue
		}
		entries = append(entries, "{\"watchpoint_id\":"+strconv.FormatUint(id, 10)+",\"cpu\":\"m68k\",\"address\":4096,\"length\":1,\"access\":\"any\",\"hit_count\":"+strconv.FormatUint(hits, 10)+",\"enabled\":true}")
	}
	return "[" + strings.Join(entries, ",") + "]"
}

func (fake *runUntilFake) server(t *testing.T) *Server {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = fake.execute()
	return newTestServer(t, client)
}

func mustParseID(t *testing.T, value string) uint64 {
	t.Helper()
	id, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		t.Fatalf("parse id %q: %v", value, err)
	}
	return id
}

// ----------------------------------------------------------------------------------------------------------------------
// instrumentFiredProof
// ----------------------------------------------------------------------------------------------------------------------

func TestInstrumentFiredProof(t *testing.T) {
	cases := []struct {
		hit, n uint64
		fired  bool
	}{
		{0, 1, false},
		{1, 1, true},
		{3, 1, true},
		{0, 5, false},
		{1, 5, false},
		{3, 5, false},
		{4, 5, false},
		{5, 5, true},
		{10, 5, true},
		{7, 0, true}, // breakCounter 0 normalizes to 1
	}
	for _, c := range cases {
		if got := instrumentFiredProof(c.hit, c.n); got != c.fired {
			t.Fatalf("instrumentFiredProof(%d, %d) = %v, want %v", c.hit, c.n, got, c.fired)
		}
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// run_until_breakpoint
// ----------------------------------------------------------------------------------------------------------------------

// TestRunUntilBreakpointFiresAndLeavesNoResidue: the wrapper arms a one-shot
// breakpoint, runs toward it, detects the native stop, and reports the
// evidence with the instrument removed and a structured debug event.
func TestRunUntilBreakpointFiresAndLeavesNoResidue(t *testing.T) {
	fake := newRunUntilFake(t)
	fake.fireOnStatusCall = 2 // first poll sees running, second sees the stop
	server := fake.server(t)

	result := postToolCall(t, server, "run_until_breakpoint", "{\"cpu\":\"m68k\",\"address\":\"0x1000\",\"timeout_ms\":2000}")
	content := structured(result)
	if result["isError"] == true {
		t.Fatalf("run_until_breakpoint failed: %v", content)
	}
	if content["stop_reason"] != "breakpoint_hit" {
		t.Fatalf("stop_reason = %v, want breakpoint_hit", content["stop_reason"])
	}
	if content["resource_kind"] != "breakpoint" || content["resource_id"] != float64(1) {
		t.Fatalf("resource = %v/%v, want breakpoint/1", content["resource_kind"], content["resource_id"])
	}
	if content["hit_count"] != float64(1) {
		t.Fatalf("hit_count = %v, want 1", content["hit_count"])
	}
	if content["triggering_pc"] != float64(4096) {
		t.Fatalf("triggering_pc = %v, want 4096", content["triggering_pc"])
	}
	if content["system_running"] != false || content["instrument_removed"] != true {
		t.Fatalf("must end paused with the instrument removed: %v", content)
	}
	if content["pause_source"] != "breakpoint_or_watchpoint" {
		t.Fatalf("pause_source = %v, want breakpoint_or_watchpoint", content["pause_source"])
	}
	if content["event_id"] == nil {
		t.Fatalf("a debug event must record the stop: %v", content)
	}
	registers, _ := content["registers"].(map[string]any)
	if registers["pc"] != float64(4096) {
		t.Fatalf("registers missing: %v", content["registers"])
	}
	before, _ := content["target_generation_before"].(float64)
	after, _ := content["target_generation_after"].(float64)
	if uint64(after) <= uint64(before) {
		t.Fatalf("generation must advance across the window: %v -> %v", before, after)
	}

	// No residue: the native list is empty and the server metadata is gone.
	list := structured(postToolCall(t, server, "cpu_breakpoint_list", "{}"))
	if entries, _ := list["breakpoints"].([]any); len(entries) != 0 {
		t.Fatalf("breakpoint must be removed: %v", list)
	}
	if len(server.debugResourceMetas("breakpoint")) != 0 {
		t.Fatalf("server-side breakpoint metadata must be gone")
	}
	// The sweep's removal is audited with the resource id.
	entries, _ := server.audit.Query(analysis.AuditFilter{Tool: "one_shot_sweep"})
	if len(entries) != 1 {
		t.Fatalf("expected one one_shot_sweep audit entry, got %d", len(entries))
	}
	if entries[0].Detail["resource_id"] != uint64(1) || entries[0].Detail["event"] != "one_shot_hit" {
		t.Fatalf("one_shot_sweep detail wrong: %v", entries[0].Detail)
	}
}

// TestRunUntilBreakpointTimeoutRemovesInstrument: when the instrument never
// fires, the call times out and removes the armed instrument.
func TestRunUntilBreakpointTimeoutRemovesInstrument(t *testing.T) {
	fake := newRunUntilFake(t) // never pauses, never fires
	server := fake.server(t)

	result := postToolCall(t, server, "run_until_breakpoint", "{\"cpu\":\"m68k\",\"address\":4096,\"timeout_ms\":100}")
	content := structured(result)
	if result["isError"] != true || content["code"] != "run_until_timeout" {
		t.Fatalf("expected run_until_timeout: %v", result)
	}
	if content["instrument_removed"] != true {
		t.Fatalf("timeout must remove the instrument: %v", content)
	}
	list := structured(postToolCall(t, server, "cpu_breakpoint_list", "{}"))
	if entries, _ := list["breakpoints"].([]any); len(entries) != 0 {
		t.Fatalf("instrument must not survive a timeout: %v", list)
	}
}

// TestRunUntilBreakpointPreemptedByForeignPause: a pause that no managed
// instrument explains ends the call with the instrument removed.
func TestRunUntilBreakpointPreemptedByForeignPause(t *testing.T) {
	fake := newRunUntilFake(t)
	fake.pauseOnStatusCall = 1 // the system pauses without any instrument firing
	server := fake.server(t)

	result := postToolCall(t, server, "run_until_breakpoint", "{\"cpu\":\"m68k\",\"address\":4096,\"timeout_ms\":1000}")
	content := structured(result)
	if result["isError"] != true || content["code"] != "run_until_preempted" {
		t.Fatalf("expected run_until_preempted: %v", result)
	}
	if content["instrument_removed"] != true {
		t.Fatalf("preemption must remove the instrument: %v", content)
	}
	if content["observed_pause_source"] != "ui_or_external" {
		t.Fatalf("observed_pause_source = %v, want ui_or_external", content["observed_pause_source"])
	}
}

// TestRunUntilBreakpointCounterFiresOnNthHit: break_on_counter=5 fires when
// the native counter reaches 5.
func TestRunUntilBreakpointCounterFiresOnNthHit(t *testing.T) {
	fake := newRunUntilFake(t)
	fake.fireOnStatusCall = 2
	fake.fireHitValue = 5
	server := fake.server(t)

	result := postToolCall(t, server, "run_until_breakpoint", "{\"cpu\":\"m68k\",\"address\":4096,\"break_on_counter\":true,\"break_counter\":5,\"timeout_ms\":2000}")
	content := structured(result)
	if result["isError"] == true {
		t.Fatalf("counter run_until failed: %v", content)
	}
	if content["hit_count"] != float64(5) {
		t.Fatalf("hit_count = %v, want 5", content["hit_count"])
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// run_until_watchpoint
// ----------------------------------------------------------------------------------------------------------------------

func TestRunUntilWatchpointFiresAndReportsEvidence(t *testing.T) {
	fake := newRunUntilFake(t)
	fake.fireOnStatusCall = 2
	server := fake.server(t)

	result := postToolCall(t, server, "run_until_watchpoint", "{\"cpu\":\"m68k\",\"address\":4096,\"access\":\"write\",\"timeout_ms\":2000}")
	content := structured(result)
	if result["isError"] == true {
		t.Fatalf("run_until_watchpoint failed: %v", content)
	}
	if content["stop_reason"] != "watchpoint_hit" {
		t.Fatalf("stop_reason = %v, want watchpoint_hit", content["stop_reason"])
	}
	if content["resource_kind"] != "watchpoint" || content["resource_id"] != float64(1) {
		t.Fatalf("resource = %v/%v, want watchpoint/1", content["resource_kind"], content["resource_id"])
	}
	if content["watched_address"] != float64(4096) {
		t.Fatalf("watched_address = %v, want 4096", content["watched_address"])
	}
	if content["access_direction"] != "any" {
		t.Fatalf("access_direction = %v, want any", content["access_direction"])
	}
	if content["instrument_removed"] != true {
		t.Fatalf("instrument must be removed: %v", content)
	}
	if len(server.debugResourceMetas("watchpoint")) != 0 {
		t.Fatalf("watchpoint metadata must be gone")
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// one_shot on cpu_breakpoint_set / cpu_watchpoint_set
// ----------------------------------------------------------------------------------------------------------------------

// TestOneShotBreakpointSetAndSweepEndToEnd: the full loop — set with
// one_shot, run, native stop, sweep removes and audits, debug event pushed,
// subsequent list is empty and a later emulator_status does not re-remove.
func TestOneShotBreakpointSetAndSweepEndToEnd(t *testing.T) {
	fake := newRunUntilFake(t)
	fake.fireOnStatusCall = 1
	server := fake.server(t)

	pre := server.target.Generation()
	set := structured(postToolCall(t, server, "cpu_breakpoint_set", "{\"cpu\":\"m68k\",\"address\":4096,\"one_shot\":true}"))
	if set["isError"] == true {
		t.Fatalf("set failed: %v", set)
	}
	if set["breakpoint_id"] != float64(1) {
		t.Fatalf("breakpoint_id = %v, want 1", set["breakpoint_id"])
	}

	_ = postToolCall(t, server, "cpu_run", "{}")

	// The stop observation triggers the sweep.
	status := structured(postToolCall(t, server, "emulator_status", "{}"))
	if status["isError"] == true {
		t.Fatalf("emulator_status failed: %v", status)
	}
	if status["one_shot_removals"] == nil {
		t.Fatalf("one-shot removal must be reported: %v", status)
	}
	if status["pause_source"] != "breakpoint_or_watchpoint" {
		t.Fatalf("pause_source = %v, want breakpoint_or_watchpoint", status["pause_source"])
	}

	// The instrument is gone from the native list and the server metadata.
	list := structured(postToolCall(t, server, "cpu_breakpoint_list", "{}"))
	if entries, _ := list["breakpoints"].([]any); len(entries) != 0 {
		t.Fatalf("one-shot breakpoint must be removed: %v", list)
	}
	if len(server.debugResourceMetas("breakpoint")) != 0 {
		t.Fatalf("server metadata must be gone")
	}
	if got := server.target.Generation(); got != pre+3 {
		t.Fatalf("generation: set+run+remove = 3 advances, got %d (before %d)", got, pre)
	}

	// The sweep's removal is audited; a debug event exists.
	sweeps, _ := server.audit.Query(analysis.AuditFilter{Tool: "one_shot_sweep"})
	if len(sweeps) != 1 {
		t.Fatalf("expected one one_shot_sweep entry, got %d", len(sweeps))
	}
	events, _, _ := server.listDebugEvents(0, 100)
	if len(events) != 1 || events[0].ResourceKind != "breakpoint" || events[0].ResourceID != 1 {
		t.Fatalf("expected one breakpoint debug event: %+v", events)
	}
	if events[0].HitCount != 1 || events[0].TriggeringPC != 4096 {
		t.Fatalf("debug event evidence wrong: %+v", events[0])
	}

	// A later paused observation does not re-remove anything.
	status2 := structured(postToolCall(t, server, "emulator_status", "{}"))
	if status2["one_shot_removals"] != nil {
		t.Fatalf("no second removal must be reported: %v", status2)
	}
}

// TestOneShotNotRemovedUntilProof: an armed one-shot instrument whose hit
// counter has not reached the break threshold stays armed; once the counter
// proves the break, the sweep removes it.
func TestOneShotNotRemovedUntilProof(t *testing.T) {
	fake := newRunUntilFake(t)
	fake.execute()
	server := fake.server(t)

	set := structured(postToolCall(t, server, "cpu_breakpoint_set", "{\"cpu\":\"m68k\",\"address\":4096,\"one_shot\":true,\"break_on_counter\":true,\"break_counter\":5}"))
	if set["breakpoint_id"] != float64(1) {
		t.Fatalf("breakpoint_id = %v", set["breakpoint_id"])
	}
	// Paused observation with hit count 3 (below N=5): no proof, no removal.
	fake.bpHits[1] = 3
	fake.running = false
	status := structured(postToolCall(t, server, "emulator_status", "{}"))
	if status["one_shot_removals"] != nil {
		t.Fatalf("counter 3 of N=5 must not fire: %v", status)
	}
	if len(server.debugResourceMetas("breakpoint")) != 1 {
		t.Fatalf("instrument must stay armed below the threshold")
	}
	// Now the counter reaches 5: proof, removal, event.
	fake.bpHits[1] = 5
	status = structured(postToolCall(t, server, "emulator_status", "{}"))
	if status["one_shot_removals"] == nil {
		t.Fatalf("counter 5 of N=5 must fire: %v", status)
	}
	if len(server.debugResourceMetas("breakpoint")) != 0 {
		t.Fatalf("fired one-shot must be removed")
	}
}

// TestNonOneShotBreakpointAttributedButNotRemoved: a plain (non-one-shot)
// fired breakpoint updates the pause attribution but stays armed.
func TestNonOneShotBreakpointAttributedButNotRemoved(t *testing.T) {
	fake := newRunUntilFake(t)
	fake.fireOnStatusCall = 1
	server := fake.server(t)

	set := structured(postToolCall(t, server, "cpu_breakpoint_set", "{\"cpu\":\"m68k\",\"address\":4096}"))
	if set["breakpoint_id"] != float64(1) {
		t.Fatalf("breakpoint_id = %v", set["breakpoint_id"])
	}
	_ = postToolCall(t, server, "cpu_run", "{}")

	status := structured(postToolCall(t, server, "emulator_status", "{}"))
	if status["pause_source"] != "breakpoint_or_watchpoint" {
		t.Fatalf("pause_source = %v, want breakpoint_or_watchpoint", status["pause_source"])
	}
	if status["one_shot_removals"] != nil {
		t.Fatalf("non-one-shot instrument must not be removed: %v", status)
	}
	if len(server.debugResourceMetas("breakpoint")) != 1 {
		t.Fatalf("non-one-shot instrument must stay armed")
	}
	// No removal mutation was issued.
	for _, call := range fake.calls {
		if call == "breakpoint_remove" {
			t.Fatalf("non-one-shot instrument must never be removed: %v", fake.calls)
		}
	}
	// The run_state_change audit entry carries the stop attribution.
	entries, _ := server.audit.Query(analysis.AuditFilter{Tool: "run_state_change"})
	if len(entries) != 1 {
		t.Fatalf("expected one run_state_change entry, got %d", len(entries))
	}
	attribution, _ := entries[0].Detail["attribution"].(string)
	if !strings.Contains(attribution, "breakpoint_or_watchpoint") || !strings.Contains(attribution, "breakpoint 1") {
		t.Fatalf("attribution = %q, want breakpoint_or_watchpoint naming resource 1", attribution)
	}
}

// TestRunUntilWatchpointOneShotViaSweep: a one-shot watchpoint set through
// cpu_watchpoint_set is removed by the sweep on its stop.
func TestRunUntilWatchpointOneShotViaSweep(t *testing.T) {
	fake := newRunUntilFake(t)
	fake.fireOnStatusCall = 1
	server := fake.server(t)

	set := structured(postToolCall(t, server, "cpu_watchpoint_set", "{\"cpu\":\"m68k\",\"address\":4096,\"one_shot\":true}"))
	if set["watchpoint_id"] != float64(1) {
		t.Fatalf("watchpoint_id = %v", set["watchpoint_id"])
	}
	_ = postToolCall(t, server, "cpu_run", "{}")
	status := structured(postToolCall(t, server, "emulator_status", "{}"))
	if status["one_shot_removals"] == nil {
		t.Fatalf("one-shot watchpoint must be removed: %v", status)
	}
	if len(server.debugResourceMetas("watchpoint")) != 0 {
		t.Fatalf("watchpoint metadata must be gone")
	}
}
