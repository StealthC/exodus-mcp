package mcp

import (
	"fmt"
	"testing"

	"github.com/StealthC/exodus-mcp/internal/analysis"
)

// Roadmap issue #11 follow-up: a cursor carries the query that produced it, so
// page 2 and later are cursor-only requests. These tests call each paged tool
// with nothing but {"cursor": ...} after the first page — the shape a client
// follows from the published contract — and assert the full result set is
// reached exactly once.
//
// Re-sending the original arguments with a cursor stays allowed, but only when
// they match the cursor: a differing value is invalid_params naming the field.

// cursorOnlyPage calls one tool with a cursor and no other arguments besides the
// optional page-size knob.
func cursorOnlyPage(t *testing.T, server *Server, tool, cursor string, extra string) map[string]any {
	t.Helper()
	arguments := fmt.Sprintf(`{"cursor":%q%s}`, cursor, extra)
	content := structured(postToolCall(t, server, tool, arguments))
	if content["code"] != nil {
		t.Fatalf("%s cursor-only page failed: %v (arguments %s)", tool, content, arguments)
	}
	return content
}

// TestMemorySearchCursorOnlyPagesToExhaustion pages a wildcard search with
// cursor-only requests: the token must carry the pattern, its wildcard mask, and
// the window, or page 2 would select a different set of matches.
func TestMemorySearchCursorOnlyPagesToExhaustion(t *testing.T) {
	// "41 ?? 42" with the middle byte varying: five matches at 0,3,6,9,12.
	blob := []byte{
		0x41, 0x00, 0x42,
		0x41, 0xFF, 0x42,
		0x41, 0x00, 0x42,
		0x41, 0xFF, 0x42,
		0x41, 0x00, 0x42,
	}
	server := newTestServer(t, ramBlobClient(blob))
	first := structured(postToolCall(t, server, "memory_search",
		`{"space":"mem-ram","pattern":"41 ?? 42","start_address":"0xFF0000","length":15,"max_matches":2}`))
	hasMore, cursor := requirePagingEnvelope(t, first, 2, 5)
	if !hasMore {
		t.Fatalf("first page must be partial: %v", first)
	}
	seen := matchAddresses(t, first)
	pages := 0
	for cursor != nil {
		page := cursorOnlyPage(t, server, "memory_search", cursor.(string), "")
		pages++
		returned := int(page["returned"].(float64))
		if _, next := requirePagingEnvelope(t, page, returned, 5); next != nil {
			cursor = next
		} else {
			cursor = nil
		}
		seen = append(seen, matchAddresses(t, page)...)
	}
	if len(seen) != 5 || pages == 0 {
		t.Fatalf("cursor-only paging returned %v in %d cursor-only pages, want 5 matches", seen, pages)
	}
	for index := 1; index < len(seen); index++ {
		if seen[index] <= seen[index-1] {
			t.Fatalf("cursor-only pages must advance without repeats: %v", seen)
		}
	}
	// The mask travelled with the cursor: every middle byte matched.
	want := []uint64{0xFF0000, 0xFF0003, 0xFF0006, 0xFF0009, 0xFF000C}
	for index := range want {
		if seen[index] != want[index] {
			t.Fatalf("matches = %v, want %v", seen, want)
		}
	}
	// An argument supplied next to a cursor must match it.
	conflict := structured(postToolCall(t, server, "memory_search",
		fmt.Sprintf(`{"cursor":%q,"pattern":"41 00 42"}`, first["next_cursor"])))
	if conflict["code"] != "invalid_params" || conflict["field"] != "pattern" {
		t.Fatalf("a contradicting pattern must be rejected naming the field: %v", conflict)
	}
}

// TestMemoryDiffCursorOnlyPagesToExhaustion pages a comparison with cursor-only
// requests: the token carries both snapshots and the cell semantics.
func TestMemoryDiffCursorOnlyPagesToExhaustion(t *testing.T) {
	blob := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	client := ramBlobClient(blob)
	server := newTestServer(t, client)
	before := structured(postToolCall(t, server, "memory_dump", `{"space":"mem-ram","address":"0xFF0000","length":8}`))
	beforeID := before["artifact"].(map[string]any)["id"].(string)
	for index := range blob {
		blob[index] += 0x10
	}
	first := structured(postToolCall(t, server, "memory_diff",
		fmt.Sprintf(`{"snapshot_before_id":%q,"mode":"changed","max_matches":3}`, beforeID)))
	hasMore, cursor := requirePagingEnvelope(t, first, 3, 8)
	if !hasMore {
		t.Fatalf("first page must be partial: %v", first)
	}
	seen := matchAddresses(t, first)
	for cursor != nil {
		page := cursorOnlyPage(t, server, "memory_diff", cursor.(string), "")
		returned := int(page["returned"].(float64))
		if _, next := requirePagingEnvelope(t, page, returned, 8); next != nil {
			cursor = next
		} else {
			cursor = nil
		}
		if page["summary"].(map[string]any)["fresh_after_read"] != false {
			t.Fatalf("a cursor page must reuse the after snapshot: %v", page["summary"])
		}
		seen = append(seen, matchAddresses(t, page)...)
	}
	if len(seen) != 8 {
		t.Fatalf("cursor-only paging returned %v, want 8 cells", seen)
	}
	conflict := structured(postToolCall(t, server, "memory_diff",
		fmt.Sprintf(`{"cursor":%q,"mode":"unchanged"}`, first["next_cursor"])))
	if conflict["code"] != "invalid_params" || conflict["field"] != "mode" {
		t.Fatalf("a contradicting mode must be rejected naming the field: %v", conflict)
	}
}

// TestAnnotationListCursorOnlyPagesToExhaustion pages a filtered annotation list
// with cursor-only requests: the token carries the filters.
func TestAnnotationListCursorOnlyPagesToExhaustion(t *testing.T) {
	server := newTestServer(t, ramBlobClient([]byte{0}))
	for index := 0; index < 5; index++ {
		postToolCall(t, server, "annotation_create", fmt.Sprintf(`{"title":"hud %d","tags":["hud"]}`, index))
	}
	for index := 0; index < 3; index++ {
		postToolCall(t, server, "annotation_create", fmt.Sprintf(`{"title":"other %d","tags":["other"]}`, index))
	}
	first := structured(postToolCall(t, server, "annotation_list", `{"tags":["hud"],"include_stale":true,"limit":2}`))
	hasMore, cursor := requirePagingEnvelope(t, first, 2, 5)
	if !hasMore {
		t.Fatalf("first page must be partial: %v", first)
	}
	seen := map[string]bool{}
	collect := func(page map[string]any) {
		for _, raw := range page["annotations"].([]any) {
			view := raw.(map[string]any)
			id := view["id"].(string)
			if seen[id] {
				t.Fatalf("annotation %s repeated across cursor-only pages", id)
			}
			seen[id] = true
			title, _ := view["title"].(string)
			if len(title) < 4 || title[:4] != "hud " {
				t.Fatalf("cursor-only page lost the tag filter: %v", view)
			}
		}
	}
	collect(first)
	for cursor != nil {
		page := cursorOnlyPage(t, server, "annotation_list", cursor.(string), "")
		returned := int(page["returned"].(float64))
		if _, next := requirePagingEnvelope(t, page, returned, 5); next != nil {
			cursor = next
		} else {
			cursor = nil
		}
		collect(page)
	}
	if len(seen) != 5 {
		t.Fatalf("cursor-only paging returned %d annotations, want the 5 tagged ones", len(seen))
	}
	conflict := structured(postToolCall(t, server, "annotation_list",
		fmt.Sprintf(`{"cursor":%q,"tags":["other"]}`, first["next_cursor"])))
	if conflict["code"] != "invalid_params" || conflict["field"] != "tags" {
		t.Fatalf("a contradicting tag filter must be rejected naming the field: %v", conflict)
	}
}

// TestTargetAuditLogCursorOnlyPagesToExhaustion pages a filtered audit stream
// with cursor-only requests: the token carries the filter, so the continuation
// never falls back to the unfiltered stream.
func TestTargetAuditLogCursorOnlyPagesToExhaustion(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	for index := 0; index < 5; index++ {
		server.audit.Record(analysis.AuditEntry{Tool: "memory_write", Outcome: analysis.OutcomeOK, Detail: map[string]any{"index": index}})
		server.audit.Record(analysis.AuditEntry{Tool: "rom_load", Outcome: analysis.OutcomeOK})
	}
	first := structured(postToolCall(t, server, "target_audit_log", `{"tool":"memory_write","limit":2}`))
	hasMore, cursor := requirePagingEnvelope(t, first, 2, 5)
	if !hasMore {
		t.Fatalf("first page must be partial: %v", first)
	}
	seen := map[float64]bool{}
	collect := func(page map[string]any) {
		for _, raw := range page["entries"].([]any) {
			entry := raw.(map[string]any)
			if entry["tool"] != "memory_write" {
				t.Fatalf("cursor-only page lost the tool filter: %v", entry)
			}
			id := entry["operation_id"].(float64)
			if seen[id] {
				t.Fatalf("entry %v repeated across cursor-only pages", id)
			}
			seen[id] = true
		}
	}
	collect(first)
	for cursor != nil {
		page := cursorOnlyPage(t, server, "target_audit_log", cursor.(string), "")
		returned := int(page["returned"].(float64))
		if _, next := requirePagingEnvelope(t, page, returned, 5); next != nil {
			cursor = next
		} else {
			cursor = nil
		}
		collect(page)
	}
	if len(seen) != 5 {
		t.Fatalf("cursor-only paging returned %d entries, want the 5 memory_write ones", len(seen))
	}
	conflict := structured(postToolCall(t, server, "target_audit_log",
		fmt.Sprintf(`{"cursor":%q,"tool":"rom_load"}`, first["next_cursor"])))
	if conflict["code"] != "invalid_params" || conflict["field"] != "tool" {
		t.Fatalf("a contradicting tool filter must be rejected naming the field: %v", conflict)
	}
}

// TestContextMutationLogCursorOnlyPagesToExhaustion pages the per-context
// projection with cursor-only requests.
func TestContextMutationLogCursorOnlyPagesToExhaustion(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	contextID := defaultContextID(t, server)
	for index := 0; index < 5; index++ {
		server.audit.Record(analysis.AuditEntry{Tool: "memory_write", Outcome: analysis.OutcomeOK, ContextID: contextID})
	}
	first := structured(postToolCall(t, server, "context_mutation_log", `{"limit":2}`))
	hasMore, cursor := requirePagingEnvelope(t, first, 2, 5)
	if !hasMore {
		t.Fatalf("first page must be partial: %v", first)
	}
	seen := map[float64]bool{}
	collect := func(page map[string]any) {
		for _, raw := range page["entries"].([]any) {
			id := raw.(map[string]any)["operation_id"].(float64)
			if seen[id] {
				t.Fatalf("entry %v repeated across cursor-only pages", id)
			}
			seen[id] = true
		}
	}
	collect(first)
	for cursor != nil {
		page := cursorOnlyPage(t, server, "context_mutation_log", cursor.(string), "")
		returned := int(page["returned"].(float64))
		if _, next := requirePagingEnvelope(t, page, returned, 5); next != nil {
			cursor = next
		} else {
			cursor = nil
		}
		collect(page)
	}
	if len(seen) != 5 {
		t.Fatalf("cursor-only paging returned %d entries, want 5", len(seen))
	}
}

// TestTraceSessionEventsCursorOnlyPagesToExhaustion pages a filtered event
// query with cursor-only requests: the token carries the filter, so the
// continuation cannot fall back to the unfiltered stream.
func TestTraceSessionEventsCursorOnlyPagesToExhaustion(t *testing.T) {
	fake := newTraceSessionFake(fakeTraceSegment(
		[3]string{"00FF0000", "NOP", ""},
		[3]string{"00FF0002", "NOP", ""},
		[3]string{"00FF0004", "NOP", ""},
		[3]string{"00FF0006", "NOP", ""},
		[3]string{"00FF0008", "NOP", ""},
	))
	server := newTestServer(t, fake.client())
	if start := structured(postToolCall(t, server, "trace_session_start", `{"cpu":"m68k"}`)); start["code"] != nil {
		t.Fatalf("trace_session_start failed: %v", start)
	}
	first := structured(postToolCall(t, server, "trace_session_events", `{"kind":"execute","limit":2}`))
	hasMore, cursor := requirePagingEnvelope(t, first, 2, 5)
	if !hasMore {
		t.Fatalf("first page must be partial: %v", first)
	}
	seen := map[float64]bool{}
	collect := func(page map[string]any) {
		for _, raw := range page["events"].([]any) {
			event := raw.(map[string]any)
			if event["kind"] != "execute" {
				t.Fatalf("cursor-only page lost the kind filter: %v", event)
			}
			sequence := event["store_sequence"].(float64)
			if seen[sequence] {
				t.Fatalf("event %v repeated across cursor-only pages", sequence)
			}
			seen[sequence] = true
		}
	}
	collect(first)
	pages := 0
	for cursor != nil {
		page := cursorOnlyPage(t, server, "trace_session_events", cursor.(string), `,"collect":false`)
		pages++
		returned := int(page["returned"].(float64))
		if _, next := requirePagingEnvelope(t, page, returned, 5); next != nil {
			cursor = next
		} else {
			cursor = nil
		}
		collect(page)
	}
	if len(seen) != 5 || pages == 0 {
		t.Fatalf("cursor-only paging returned %d events in %d cursor-only pages, want 5", len(seen), pages)
	}
	conflict := structured(postToolCall(t, server, "trace_session_events",
		fmt.Sprintf(`{"cursor":%q,"kind":"read"}`, first["next_cursor"])))
	if conflict["code"] != "invalid_params" || conflict["field"] != "kind" {
		t.Fatalf("a contradicting kind filter must be rejected naming the field: %v", conflict)
	}
}
