package tracing

import "testing"

// storePageSequence collects the store sequences of one page.
func storePageSequence(events []Event) []uint64 {
	out := make([]uint64, 0, len(events))
	for _, event := range events {
		out = append(out, event.StoreSequence)
	}
	return out
}

// TestSelectPageAssignsMonotonicStoreSequence: every event gets a store
// sequence, including execution events, and the numbers are never reused even
// when the bounded ring evicts the oldest entries.
func TestSelectPageAssignsMonotonicStoreSequence(t *testing.T) {
	session := NewSession("trs_page", "ctx", "m68k", "m68k-bus", Config{CPU: "m68k", MaxEvents: 3})
	session.AddEvents([]Event{{Kind: KindExecute, Address: 0x1000}})
	session.AddEvents([]Event{{Kind: KindExecute, Address: 0x1002}, {Kind: KindExecute, Address: 0x1004}})
	page := session.SelectPage(Filter{Kind: KindExecute, Limit: 10})
	if got := storePageSequence(page.Events); len(got) != 3 || got[0] != 1 || got[2] != 3 {
		t.Fatalf("store sequences = %v, want [1 2 3]", got)
	}
	if page.Total != 3 || page.Remaining != 3 {
		t.Fatalf("page counts = %+v", page)
	}

	// Evicting the oldest entries keeps the assigned numbers: the next event is
	// number 4, not a recycled 1.
	session.AddEvents([]Event{{Kind: KindExecute, Address: 0x1006}, {Kind: KindExecute, Address: 0x1008}})
	page = session.SelectPage(Filter{Kind: KindExecute, Limit: 10})
	if got := storePageSequence(page.Events); len(got) != 3 || got[0] != 3 || got[2] != 5 {
		t.Fatalf("retained store sequences = %v, want [3 4 5]", got)
	}
	if page.OldestSequence != 3 || page.NewestSequence != 5 {
		t.Fatalf("retained window = %+v", page)
	}
}

// TestSelectPageCursorSurvivesConcurrentAppends: a cursor page keeps its
// boundary while more events arrive, so paging to exhaustion never repeats or
// skips an event.
func TestSelectPageCursorSurvivesConcurrentAppends(t *testing.T) {
	session := NewSession("trs_page", "ctx", "m68k", "m68k-bus", Config{CPU: "m68k", MaxEvents: 64})
	session.AddEvents([]Event{
		{Kind: KindExecute, Address: 0x1000},
		{Kind: KindExecute, Address: 0x1002},
		{Kind: KindExecute, Address: 0x1004},
		{Kind: KindExecute, Address: 0x1006},
	})
	first := session.SelectPage(Filter{Kind: KindExecute, Limit: 2})
	if got := storePageSequence(first.Events); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("first page = %v", got)
	}
	if first.Remaining != 4 || first.Total != 4 {
		t.Fatalf("first page counts = %+v", first)
	}

	// Two more events arrive between the pages.
	session.AddEvents([]Event{
		{Kind: KindExecute, Address: 0x1008},
		{Kind: KindExecute, Address: 0x100A},
	})
	second := session.SelectPage(Filter{Kind: KindExecute, Limit: 2, HasAfterSequence: true, AfterSequence: 2})
	if got := storePageSequence(second.Events); len(got) != 2 || got[0] != 3 || got[1] != 4 {
		t.Fatalf("second page = %v, want [3 4]", got)
	}
	if second.Remaining != 4 {
		t.Fatalf("remaining after cursor = %d, want 4", second.Remaining)
	}
	third := session.SelectPage(Filter{Kind: KindExecute, Limit: 2, HasAfterSequence: true, AfterSequence: 4})
	if got := storePageSequence(third.Events); len(got) != 2 || got[0] != 5 || got[1] != 6 {
		t.Fatalf("third page = %v, want [5 6]", got)
	}
}

// TestSelectFiltersDoNotApplyTheCursor: the JSONL export uses Select, which must
// ignore the paging cursor so an export is always the whole retained set.
func TestSelectFiltersDoNotApplyTheCursor(t *testing.T) {
	session := NewSession("trs_page", "ctx", "m68k", "m68k-bus", Config{CPU: "m68k", MaxEvents: 64})
	session.AddEvents([]Event{
		{Kind: KindExecute, Address: 0x1000},
		{Kind: KindExecute, Address: 0x1002},
		{Kind: KindRead, Address: 0x2000, ValueKnown: true, Value: 7},
	})
	all := session.Select(Filter{Kind: "any", HasAfterSequence: true, AfterSequence: 2})
	if got := storePageSequence(all); len(got) != 3 {
		t.Fatalf("Select must ignore the cursor: %v", got)
	}
}
