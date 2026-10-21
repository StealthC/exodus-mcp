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
	if events[0].RepeatCount != 1 {
		t.Fatalf("duplicate repeat count wrong: %+v", events[0])
	}
	if !events[0].LastSeenAt.After(events[0].FirstSeenAt) && !events[0].LastSeenAt.Equal(events[0].FirstSeenAt) {
		t.Fatalf("last seen timestamp wrong: %+v", events[0])
	}
	history := server.debugEventHistory()
	if history.Recorded != 2 || history.Dropped != 0 || !history.Complete {
		t.Fatalf("history should be complete: %+v", history)
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
	history = server.debugEventHistory()
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
}
