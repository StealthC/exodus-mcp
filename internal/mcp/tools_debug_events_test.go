package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/StealthC/exodus-mcp/internal/analysis"
)

// TestDebugEventHistoryFoldsPausedDuplicatesAndGaps covers the stop/resume
// contract of the bounded debug event history: a repeated observation of the
// same paused hit is one event, distinct hits are separate events, and records
// the capacity cap removes are counted instead of silently disappearing.
func TestDebugEventHistoryFoldsPausedDuplicatesAndGaps(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		return json.RawMessage(`{}`), nil
	}
	server := newTestServer(t, client)

	base := debugEvent{
		ResourceKind:    "watchpoint",
		ResourceID:      7,
		ContextID:       analysis.NewRegistry().Default().ID,
		CPU:             "m68k",
		TriggeringPC:    0xff0100,
		AddressSpace:    "m68k-bus",
		WatchedAddress:  0xff0000,
		AccessDirection: "write",
		HitCount:        3,
		RunState:        "paused",
	}
	first := server.pushDebugEvent(base)
	// The CPU is still paused: the same counter value, PC, and direction is a
	// repeated observation, not a second access.
	again := server.pushDebugEvent(base)
	if first != again {
		t.Fatalf("a repeated paused hit must fold into the existing event (%d vs %d)", first, again)
	}
	// The native counter is the identity of a stop: a later observation of the
	// same counter value with a different PC is the same stop, so it folds and
	// keeps the PC recorded while the CPU was paused at it.
	movedPC := base
	movedPC.TriggeringPC = 0xff0400
	if moved := server.pushDebugEvent(movedPC); moved != first {
		t.Fatalf("a changed PC at the same counter value must fold into the same stop")
	}
	// After resume the native counter advances, so a new hit is a new event.
	resumed := base
	resumed.HitCount = 4
	second := server.pushDebugEvent(resumed)
	if second == first {
		t.Fatalf("an advanced hit counter must create a new event")
	}
	events, total, _ := server.listDebugEvents(debugEventFilter{}, 0, 10)
	if total != 2 || len(events) != 2 {
		t.Fatalf("expected two events, got %d/%d: %+v", total, len(events), events)
	}
	if events[0].RepeatCount != 2 {
		t.Fatalf("duplicate repeat count wrong: %+v", events[0])
	}
	if events[0].TriggeringPC != 0xff0100 {
		t.Fatalf("the stop PC must stay the one recorded at the stop: %+v", events[0])
	}
	if !events[0].LastSeenAt.After(events[0].FirstSeenAt) && !events[0].LastSeenAt.Equal(events[0].FirstSeenAt) {
		t.Fatalf("last seen timestamp wrong: %+v", events[0])
	}
	history := server.debugEventHistoryFor(debugEventFilter{}, "all")
	if history.Recorded != 2 || history.Dropped != 0 || !history.Complete {
		t.Fatalf("history should be complete: %+v", history)
	}
	if history.Matching != 2 || history.ScopeRetained != 2 || history.Scope != "all" {
		t.Fatalf("history must describe what the query can return: %+v", history)
	}

	// Fill past the capacity: the oldest records are evicted and counted.
	for index := 0; index < maxDebugEvents+20; index++ {
		event := debugEvent{
			ResourceKind:    "breakpoint",
			ResourceID:      uint64(100 + index),
			CPU:             "m68k",
			TriggeringPC:    0xff0200,
			AccessDirection: "execute",
			HitCount:        1,
		}
		server.pushDebugEvent(event)
	}
	history = server.debugEventHistoryFor(debugEventFilter{}, "all")
	if history.Capacity != maxDebugEvents || history.Retained != maxDebugEvents {
		t.Fatalf("history capacity/retained wrong: %+v", history)
	}
	if history.Dropped == 0 || history.Complete {
		t.Fatalf("evicted records must be counted and mark the history incomplete: %+v", history)
	}
	filtered, total, truncated := server.listDebugEvents(debugEventFilter{ResourceKind: "watchpoint"}, 0, 5)
	if total != 0 || len(filtered) != 0 || truncated {
		t.Fatalf("the watchpoint event should have been evicted: total=%d events=%d", total, len(filtered))
	}
	filtered, total, truncated = server.listDebugEvents(debugEventFilter{ResourceKind: "breakpoint"}, 0, 5)
	if total != maxDebugEvents || len(filtered) != 5 || !truncated {
		t.Fatalf("breakpoint filter/pagination wrong: total=%d events=%d truncated=%t", total, len(filtered), truncated)
	}
	if filtered[0].ResourceKind != "breakpoint" {
		t.Fatalf("filter returned a foreign kind: %+v", filtered[0])
	}
	// The filtered history counters must agree with the same query's total.
	filteredHistory := server.debugEventHistoryFor(debugEventFilter{ResourceKind: "breakpoint"}, "all")
	if filteredHistory.Matching != total {
		t.Fatalf("history.matching = %d, want the filtered total %d", filteredHistory.Matching, total)
	}
	if filteredHistory.ScopeRetained != maxDebugEvents {
		t.Fatalf("history.scope_retained = %d, want the retained ring %d", filteredHistory.ScopeRetained, maxDebugEvents)
	}
}

// TestDebugEventDirectionFilterUsesObservedDirection is #14's core contract:
// the filter matches what the stop proves, not what the instrument was
// configured with, and "any" matches every observed value.
func TestDebugEventDirectionFilterUsesObservedDirection(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})

	writeEvent := debugEvent{
		ResourceKind:    "watchpoint",
		ResourceID:      1,
		CPU:             "m68k",
		AccessDirection: "write",
		WatchedAddress:  0xff0000,
		HitCount:        1,
	}
	anyEvent := debugEvent{
		ResourceKind:    "watchpoint",
		ResourceID:      2,
		CPU:             "m68k",
		AccessDirection: "any",
		WatchedAddress:  0xff0004,
		HitCount:        1,
	}
	breakpointEvent := debugEvent{
		ResourceKind:    "breakpoint",
		ResourceID:      3,
		CPU:             "m68k",
		AccessDirection: "execute",
		HitCount:        1,
	}
	for _, event := range []debugEvent{writeEvent, anyEvent, breakpointEvent} {
		server.pushDebugEvent(event)
	}

	// The observed direction is derived and the ambiguous configuration stays
	// unknown instead of echoing "any" as if it were a direction.
	events, _, _ := server.listDebugEvents(debugEventFilter{ResourceID: 1}, 0, 10)
	if len(events) != 1 || events[0].ObservedDirection == nil || *events[0].ObservedDirection != "write" {
		t.Fatalf("a write-configured watchpoint must observe write: %+v", events)
	}
	events, _, _ = server.listDebugEvents(debugEventFilter{ResourceID: 2}, 0, 10)
	if len(events) != 1 || events[0].ObservedDirection != nil {
		t.Fatalf("an any-configured watchpoint must not claim an observed direction: %+v", events)
	}
	if events[0].AccessDirection != "any" {
		t.Fatalf("the configured access must stay queryable: %+v", events[0])
	}

	cases := map[string][]uint64{
		"write":   {1},
		"execute": {3},
		"read":    {},
		"any":     {1, 2, 3},
	}
	for direction, want := range cases {
		matched, total, _ := server.listDebugEvents(debugEventFilter{Direction: direction}, 0, 100)
		if total != len(want) {
			t.Fatalf("direction %q matched %d events, want %d: %+v", direction, total, len(want), matched)
		}
		for index, event := range matched {
			if event.ResourceID != want[index] {
				t.Fatalf("direction %q matched resource %d at %d, want %d", direction, event.ResourceID, index, want[index])
			}
		}
	}
}

// TestDebugEventsListValidatesFilterEnums: an unknown enum value is an
// argument error, never an authoritative empty list.
func TestDebugEventsListValidatesFilterEnums(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	for name, arguments := range map[string]string{
		"unknown direction":     `{"direction":"wrote"}`,
		"unknown resource kind": `{"resource_kind":"events"}`,
		"unknown cpu":           `{"cpu":"6502"}`,
	} {
		result := postToolCall(t, server, "cpu_debug_events_list", arguments)
		content := structured(result)
		if result["isError"] != true || content["code"] != "invalid_params" {
			t.Fatalf("%s: expected invalid_params, got %v", name, content)
		}
	}
	// The documented vocabulary is accepted.
	for _, arguments := range []string{`{"direction":"any"}`, `{"direction":"write"}`, `{"resource_kind":"any"}`, `{"cpu":"z80"}`} {
		result := postToolCall(t, server, "cpu_debug_events_list", arguments)
		if result["isError"] == true {
			t.Fatalf("%s must be accepted: %v", arguments, structured(result))
		}
	}
}

// TestDebugEventsListScopeAllAndHistoryConsistency: the caller's context scopes
// the query by default, "all" queries every context, and the history counters
// agree with what the query can actually return.
func TestDebugEventsListScopeAllAndHistoryConsistency(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	defaultContext := server.contexts.Default()
	other, err := server.contexts.Create("other")
	if err != nil {
		t.Fatal(err)
	}
	server.pushDebugEvent(debugEvent{
		ResourceKind: "breakpoint", ResourceID: 1, ContextID: defaultContext.ID,
		CPU: "m68k", AccessDirection: "execute", HitCount: 1,
	})
	server.pushDebugEvent(debugEvent{
		ResourceKind: "watchpoint", ResourceID: 2, ContextID: other.ID,
		CPU: "m68k", AccessDirection: "write", WatchedAddress: 0xff0000, HitCount: 1,
	})

	scoped := structured(postToolCall(t, server, "cpu_debug_events_list", `{}`))
	if scoped["total"] != float64(1) {
		t.Fatalf("the default scope must see only its own context: %v", scoped["total"])
	}
	history, _ := scoped["history"].(map[string]any)
	if history["scope"] != "context:"+defaultContext.ID {
		t.Fatalf("history.scope = %v, want the context scope", history["scope"])
	}
	if history["scope_retained"] != float64(1) || history["matching"] != float64(1) || history["retained"] != float64(2) {
		t.Fatalf("history counters must agree with the scope: %v", history)
	}

	all := structured(postToolCall(t, server, "cpu_debug_events_list", `{"context":"all"}`))
	if all["total"] != float64(2) {
		t.Fatalf("context=all must query every context: %v", all["total"])
	}
	history, _ = all["history"].(map[string]any)
	if history["scope"] != "all" || history["scope_retained"] != float64(2) || history["matching"] != float64(2) {
		t.Fatalf("history counters must describe the cross-context query: %v", history)
	}
	filters, _ := all["filters"].(map[string]any)
	if filters["context_id"] != "" || filters["scope"] != "all" {
		t.Fatalf("the filters echo must state the scope: %v", filters)
	}
	// A filtered query on the cross-context scope still reports matching
	// equal to its own total.
	filtered := structured(postToolCall(t, server, "cpu_debug_events_list", `{"context":"all","direction":"write"}`))
	history, _ = filtered["history"].(map[string]any)
	if filtered["total"] != float64(1) || history["matching"] != float64(1) || history["scope_retained"] != float64(2) {
		t.Fatalf("filtered cross-context counters wrong: total=%v history=%v", filtered["total"], history)
	}
}
