package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/StealthC/exodus-mcp/internal/analysis"
	"github.com/StealthC/exodus-mcp/internal/tracing"
)

// Roadmap issue #11: list/search/diff responses carry one paging envelope, a
// cursor that stays stable while the target changes, an echo of the requested
// values next to the effective ones, and truncation that reaches the verdict a
// consumer actually reads.
//
// These tests are written against the public tool responses only, so every
// assertion fails on a tree that lacks the envelope, the cursor, the echo, or
// the corrected verdicts.

// requirePagingEnvelope asserts the shared envelope on one response and returns
// the returned/total/has_more facts.
func requirePagingEnvelope(t *testing.T, content map[string]any, wantReturned, wantTotal int) (hasMore bool, next any) {
	t.Helper()
	for _, key := range []string{"returned", "total", "truncated", "has_more", "next_cursor"} {
		if _, present := content[key]; !present {
			t.Fatalf("paging envelope is missing %q: %v", key, content)
		}
	}
	if content["returned"] != float64(wantReturned) {
		t.Fatalf("returned = %v, want %d", content["returned"], wantReturned)
	}
	if content["total"] != float64(wantTotal) {
		t.Fatalf("total = %v, want %d", content["total"], wantTotal)
	}
	hasMore, _ = content["has_more"].(bool)
	if content["truncated"] != hasMore {
		t.Fatalf("truncated (%v) must agree with has_more (%v)", content["truncated"], hasMore)
	}
	next = content["next_cursor"]
	if hasMore != (next != nil) {
		t.Fatalf("next_cursor %v must be non-null exactly when has_more is true (%v)", next, hasMore)
	}
	return hasMore, next
}

// matchAddresses pulls the sorted address list out of one inline match page.
func matchAddresses(t *testing.T, content map[string]any) []uint64 {
	t.Helper()
	raw, _ := content["matches"].([]any)
	addresses := make([]uint64, 0, len(raw))
	for _, item := range raw {
		view, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("match is not an object: %v", item)
		}
		addresses = append(addresses, uint64(view["address"].(float64)))
	}
	return addresses
}

// TestPagingEnvelopeOnEveryListSearchAndDiffTool pins the one envelope shape on
// each result-set tool.
func TestPagingEnvelopeOnEveryListSearchAndDiffTool(t *testing.T) {
	server := newTestServer(t, ramBlobClient([]byte{0x41, 0x42, 0x41, 0x42}))
	// annotations
	for index := 0; index < 3; index++ {
		postToolCall(t, server, "annotation_create", fmt.Sprintf(`{"title":"note %d"}`, index))
	}
	annotations := structured(postToolCall(t, server, "annotation_list", `{"limit":2,"include_stale":true}`))
	hasMore, next := requirePagingEnvelope(t, annotations, 2, 3)
	if !hasMore || next == nil {
		t.Fatalf("annotation_list must expose a next page: %v", annotations)
	}
	continueAnnotations := structured(postToolCall(t, server, "annotation_list", fmt.Sprintf(`{"limit":2,"include_stale":true,"cursor":%q}`, next)))
	if hasMore, _ := requirePagingEnvelope(t, continueAnnotations, 1, 3); hasMore {
		t.Fatalf("annotation_list last page must report has_more false: %v", continueAnnotations)
	}

	// memory_search over a snapshot
	search := structured(postToolCall(t, server, "memory_search", `{"space":"mem-ram","pattern":"4142","start_address":"0xFF0000","length":4,"max_matches":1}`))
	requirePagingEnvelope(t, search, 1, 2)

	// memory_diff between two snapshots
	before := structured(postToolCall(t, server, "memory_dump", `{"space":"mem-ram","address":"0xFF0000","length":4}`))
	after := structured(postToolCall(t, server, "memory_dump", `{"space":"mem-ram","address":"0xFF0000","length":4}`))
	diff := structured(postToolCall(t, server, "memory_diff", fmt.Sprintf(
		`{"snapshot_before_id":%q,"snapshot_after_id":%q,"mode":"unchanged","max_matches":2}`,
		before["artifact"].(map[string]any)["id"], after["artifact"].(map[string]any)["id"])))
	requirePagingEnvelope(t, diff, 2, 4)

	// audit log and its per-context projection
	for index := 0; index < 2; index++ {
		server.audit.Record(analysis.AuditEntry{Tool: "memory_write", Outcome: analysis.OutcomeOK, ContextID: defaultContextID(t, server)})
	}
	audit := structured(postToolCall(t, server, "target_audit_log", `{}`))
	requirePagingEnvelope(t, audit, 2, 2)
	mutations := structured(postToolCall(t, server, "context_mutation_log", `{}`))
	requirePagingEnvelope(t, mutations, 2, 2)

	// trace session events
	fake := newTraceSessionFake(fakeTraceSegment(
		[3]string{"00FF0000", "NOP", ""},
		[3]string{"00FF0002", "NOP", ""},
		[3]string{"00FF0004", "NOP", ""},
	))
	traceServer := newTestServer(t, fake.client())
	if start := structured(postToolCall(t, traceServer, "trace_session_start", `{"cpu":"m68k"}`)); start["code"] != nil {
		t.Fatalf("trace_session_start failed: %v", start)
	}
	events := structured(postToolCall(t, traceServer, "trace_session_events", `{"limit":2}`))
	requirePagingEnvelope(t, events, 2, 3)
}

// TestMemorySearchPagesToExhaustion walks a search result set with cursors and
// verifies there are no repeats and no gaps, and that only the first page reads
// the target.
func TestMemorySearchPagesToExhaustion(t *testing.T) {
	// Five "AB" matches at offsets 0, 2, 4, 6, 8 of a 10-byte mem-ram window.
	blob := []byte{0x41, 0x42, 0x41, 0x42, 0x41, 0x42, 0x41, 0x42, 0x41, 0x42}
	client := ramBlobClient(blob)
	server := newTestServer(t, client)

	first := structured(postToolCall(t, server, "memory_search", `{"space":"mem-ram","pattern":"4142","start_address":"0xFF0000","length":10,"max_matches":2}`))
	hasMore, cursor := requirePagingEnvelope(t, first, 2, 5)
	if !hasMore || cursor == nil {
		t.Fatalf("first page must be a partial page with a cursor: %v", first)
	}
	seen := matchAddresses(t, first)

	second := structured(postToolCall(t, server, "memory_search", fmt.Sprintf(`{"pattern":"4142","cursor":%q,"max_matches":2}`, cursor)))
	hasMore, cursor = requirePagingEnvelope(t, second, 2, 5)
	if !hasMore || cursor == nil {
		t.Fatalf("second page must still have a successor: %v", second)
	}
	seen = append(seen, matchAddresses(t, second)...)

	third := structured(postToolCall(t, server, "memory_search", fmt.Sprintf(`{"pattern":"4142","cursor":%q,"max_matches":2}`, cursor)))
	if hasMore, _ := requirePagingEnvelope(t, third, 1, 5); hasMore {
		t.Fatalf("last page must report has_more false: %v", third)
	}
	seen = append(seen, matchAddresses(t, third)...)

	want := []uint64{0xFF0000, 0xFF0002, 0xFF0004, 0xFF0006, 0xFF0008}
	if len(seen) != len(want) {
		t.Fatalf("paged matches = %v, want %v", seen, want)
	}
	sort.Slice(seen, func(i, j int) bool { return seen[i] < seen[j] })
	for index := range want {
		if seen[index] != want[index] {
			t.Fatalf("paged matches = %v, want %v", seen, want)
		}
	}
	if reads := countCalls(client, "mem_read"); reads != 1 {
		t.Fatalf("only the first page may read the target: mem_read = %d", reads)
	}
}

// TestMemorySearchCursorStableUnderConcurrentWrites proves a new operation
// between pages cannot repeat or skip a row: the cursor names the snapshot, the
// window, and the pattern, not an array position.
func TestMemorySearchCursorStableUnderConcurrentWrites(t *testing.T) {
	blob := []byte{0x41, 0x42, 0x41, 0x42, 0x41, 0x42, 0x41, 0x42}
	server := newTestServer(t, ramBlobClient(blob))

	first := structured(postToolCall(t, server, "memory_search", `{"space":"mem-ram","pattern":"4142","start_address":"0xFF0000","length":8,"max_matches":2}`))
	_, cursor := requirePagingEnvelope(t, first, 2, 4)
	firstAddresses := matchAddresses(t, first)

	// A concurrent write lands between the pages: new artifacts and a new
	// mutation change the context and the audit stream, not the snapshot.
	postToolCall(t, server, "memory_dump", `{"space":"mem-ram","address":"0xFF0000","length":8}`)
	server.audit.Record(analysis.AuditEntry{Tool: "memory_write", Outcome: analysis.OutcomeOK})
	postToolCall(t, server, "annotation_create", `{"title":"between pages"}`)

	second := structured(postToolCall(t, server, "memory_search", fmt.Sprintf(`{"pattern":"4142","cursor":%q,"max_matches":2}`, cursor)))
	requirePagingEnvelope(t, second, 2, 4)
	secondAddresses := matchAddresses(t, second)
	if firstAddresses[len(firstAddresses)-1] >= secondAddresses[0] {
		t.Fatalf("page 2 must continue after page 1: %v then %v", firstAddresses, secondAddresses)
	}
	if secondAddresses[0] != 0xFF0004 || secondAddresses[1] != 0xFF0006 {
		t.Fatalf("page 2 addresses = %v, want [0xFF0004 0xFF0006]", secondAddresses)
	}

	// The cursor belongs to one query: a different pattern is rejected instead
	// of silently restarting against other bytes.
	mismatch := structured(postToolCall(t, server, "memory_search", fmt.Sprintf(`{"pattern":"4141","cursor":%q}`, cursor)))
	if mismatch["code"] != "invalid_params" {
		t.Fatalf("a cursor used with another pattern must be rejected: %v", mismatch)
	}
	foreign := structured(postToolCall(t, server, "memory_search", `{"pattern":"4142","cursor":"an1.bm90aGlz"}`))
	if foreign["code"] != "invalid_params" {
		t.Fatalf("a cursor from another family must be rejected: %v", foreign)
	}
}

// TestAnnotationListKeysetCursorSurvivesWrites pages annotations while a new
// annotation is created and an older one is edited.
func TestAnnotationListKeysetCursorSurvivesWrites(t *testing.T) {
	server := newTestServer(t, ramBlobClient([]byte{0}))
	ids := make([]string, 0, 5)
	for index := 0; index < 5; index++ {
		created := structured(postToolCall(t, server, "annotation_create", fmt.Sprintf(`{"title":"note %d"}`, index)))
		ids = append(ids, created["annotation"].(map[string]any)["id"].(string))
	}
	first := structured(postToolCall(t, server, "annotation_list", `{"limit":2,"include_stale":true}`))
	if hasMore, _ := requirePagingEnvelope(t, first, 2, 5); !hasMore {
		t.Fatalf("first page must be partial: %v", first)
	}
	cursor := first["next_cursor"]

	// A concurrent create and a concurrent edit between pages.
	postToolCall(t, server, "annotation_create", `{"title":"newest"}`)
	postToolCall(t, server, "annotation_update", fmt.Sprintf(`{"annotation_id":%q,"title":"edited"}`, ids[0]))

	second := structured(postToolCall(t, server, "annotation_list", fmt.Sprintf(`{"limit":2,"include_stale":true,"cursor":%q}`, cursor)))
	requirePagingEnvelope(t, second, 2, 6)
	seen := map[string]bool{}
	for _, list := range []map[string]any{first, second} {
		for _, raw := range list["annotations"].([]any) {
			id := raw.(map[string]any)["id"].(string)
			if seen[id] {
				t.Fatalf("annotation %s was returned twice across pages", id)
			}
			seen[id] = true
		}
	}
	// Page 2 is exactly the continuation of the documented order: the rows that
	// sort strictly after page 1's last row in (created_at desc, id desc). It must
	// not be expressed as "the two oldest creations" — several annotations can
	// share one created_at when the host clock ticks coarsely (Windows resolves
	// ~0.5-15.6 ms), and the id then decides their order.
	want := expectedAnnotationContinuation(t, server, first, 2)
	got := make([]string, 0, len(second["annotations"].([]any)))
	for _, raw := range second["annotations"].([]any) {
		got = append(got, raw.(map[string]any)["id"].(string))
	}
	if len(got) != len(want) {
		t.Fatalf("page 2 returned %v, want the continuation %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("page 2 = %v, want the continuation %v of the documented order", got, want)
		}
	}
	// offset and cursor name two different positions.
	both := structured(postToolCall(t, server, "annotation_list", fmt.Sprintf(`{"cursor":%q,"offset":1}`, cursor)))
	if both["code"] != "invalid_params" {
		t.Fatalf("cursor with offset must be rejected: %v", both)
	}
}

// expectedAnnotationContinuation derives the page that must follow one page,
// from a single full listing and the documented (created_at desc, id desc)
// order. It is tie-safe: rows sharing a timestamp are ordered by id, exactly as
// the contract states, instead of assuming creation order.
func expectedAnnotationContinuation(t *testing.T, server *Server, page map[string]any, limit int) []string {
	t.Helper()
	rows := page["annotations"].([]any)
	if len(rows) == 0 {
		t.Fatalf("cannot derive a continuation from an empty page")
	}
	last := rows[len(rows)-1].(map[string]any)
	anchorTime := parseAnnotationCreatedAt(t, last["created_at"])
	anchorID := last["id"].(string)

	full := structured(postToolCall(t, server, "annotation_list", `{"limit":100,"include_stale":true}`))
	expected := make([]string, 0, limit)
	for _, raw := range full["annotations"].([]any) {
		view := raw.(map[string]any)
		id := view["id"].(string)
		created := parseAnnotationCreatedAt(t, view["created_at"])
		if created.After(anchorTime) {
			continue
		}
		if created.Equal(anchorTime) && id > anchorID {
			continue
		}
		if created.Equal(anchorTime) && id == anchorID {
			continue
		}
		expected = append(expected, id)
		if len(expected) == limit {
			break
		}
	}
	return expected
}

// parseAnnotationCreatedAt reads one response created_at string as an instant.
func parseAnnotationCreatedAt(t *testing.T, raw any) time.Time {
	t.Helper()
	text, ok := raw.(string)
	if !ok {
		t.Fatalf("created_at is not a string: %v", raw)
	}
	parsed, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		t.Fatalf("parse created_at %q: %v", text, err)
	}
	return parsed
}

// TestTargetAuditLogPaginationFactsAreConsistent: has_more, next_cursor and
// next_offset agree, and a new entry between pages cannot repeat a row.
func TestTargetAuditLogPaginationFactsAreConsistent(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	for index := 0; index < 3; index++ {
		server.audit.Record(analysis.AuditEntry{Tool: "memory_write", Outcome: analysis.OutcomeOK, Detail: map[string]any{"index": index}})
	}
	first := structured(postToolCall(t, server, "target_audit_log", `{"limit":2}`))
	hasMore, cursor := requirePagingEnvelope(t, first, 2, 3)
	if !hasMore || cursor == nil {
		t.Fatalf("first page must be partial: %v", first)
	}
	pagination := first["pagination"].(map[string]any)
	if pagination["next_offset"] != float64(2) {
		t.Fatalf("next_offset must point at the next page, got %v", pagination["next_offset"])
	}
	firstIDs := map[float64]bool{}
	for _, raw := range first["entries"].([]any) {
		firstIDs[raw.(map[string]any)["operation_id"].(float64)] = true
	}

	// A mutation recorded between pages takes the highest operation id and
	// therefore sorts before the cursor; the continuation is unchanged.
	server.audit.Record(analysis.AuditEntry{Tool: "memory_write", Outcome: analysis.OutcomeOK})
	second := structured(postToolCall(t, server, "target_audit_log", fmt.Sprintf(`{"limit":2,"cursor":%q}`, cursor)))
	if hasMore, _ := requirePagingEnvelope(t, second, 1, 4); hasMore {
		t.Fatalf("last page must report has_more false: %v", second)
	}
	if second["pagination"].(map[string]any)["next_offset"] != nil {
		t.Fatalf("next_offset must be null on the last page: %v", second["pagination"])
	}
	for _, raw := range second["entries"].([]any) {
		operationID := raw.(map[string]any)["operation_id"].(float64)
		if firstIDs[operationID] {
			t.Fatalf("entry %v repeated across pages: %v", operationID, second["entries"])
		}
	}
}

// TestContextMutationLogPagesByCursor pages the per-context projection and keeps
// lock lifecycle events out of it.
func TestContextMutationLogPagesByCursor(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	contextID := defaultContextID(t, server)
	for index := 0; index < 3; index++ {
		server.audit.Record(analysis.AuditEntry{Tool: "memory_write", Outcome: analysis.OutcomeOK, ContextID: contextID})
	}
	server.audit.Record(analysis.AuditEntry{Tool: "target_control_acquire", Outcome: analysis.OutcomeLockEvent, ContextID: contextID})

	first := structured(postToolCall(t, server, "context_mutation_log", `{"limit":2}`))
	hasMore, cursor := requirePagingEnvelope(t, first, 2, 3)
	if !hasMore || cursor == nil {
		t.Fatalf("first page must be partial: %v", first)
	}
	second := structured(postToolCall(t, server, "context_mutation_log", fmt.Sprintf(`{"limit":2,"cursor":%q}`, cursor)))
	if hasMore, _ := requirePagingEnvelope(t, second, 1, 3); hasMore {
		t.Fatalf("last page must report has_more false: %v", second)
	}
	for _, raw := range second["entries"].([]any) {
		if raw.(map[string]any)["tool"] == "target_control_acquire" {
			t.Fatalf("lock lifecycle events stay out of the mutation projection: %v", second["entries"])
		}
	}
}

// TestTraceSessionEventsPagesToExhaustion proves the event query no longer
// repeats the oldest page: every page advances and the pages together cover the
// retained events exactly once.
func TestTraceSessionEventsPagesToExhaustion(t *testing.T) {
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
	first := structured(postToolCall(t, server, "trace_session_events", `{"limit":2}`))
	hasMore, cursor := requirePagingEnvelope(t, first, 2, 5)
	if !hasMore || cursor == nil {
		t.Fatalf("first page must be partial: %v", first)
	}
	firstCursor := cursor
	seen := map[float64]bool{}
	sequences := []float64{}
	for _, raw := range first["events"].([]any) {
		sequence := raw.(map[string]any)["store_sequence"].(float64)
		sequences = append(sequences, sequence)
		seen[sequence] = true
	}

	// A repeated call without a cursor returns the same first page: that is the
	// documented default, not a silent repeat of a cursor page.
	repeated := structured(postToolCall(t, server, "trace_session_events", `{"limit":2,"collect":false}`))
	requirePagingEnvelope(t, repeated, 2, 5)

	for page := 0; page < 2; page++ {
		next := structured(postToolCall(t, server, "trace_session_events", fmt.Sprintf(`{"limit":2,"collect":false,"cursor":%q}`, cursor)))
		returned := int(next["returned"].(float64))
		if _, nextCursor := requirePagingEnvelope(t, next, returned, 5); nextCursor != nil {
			cursor = nextCursor
		} else {
			cursor = nil
		}
		for _, raw := range next["events"].([]any) {
			sequence := raw.(map[string]any)["store_sequence"].(float64)
			if seen[sequence] {
				t.Fatalf("event %v repeated across pages", sequence)
			}
			seen[sequence] = true
			sequences = append(sequences, sequence)
		}
		if cursor == nil && page == 0 {
			t.Fatalf("three pages were expected for five events")
		}
	}
	if len(seen) != 5 {
		t.Fatalf("paged events = %d, want 5 (sequences %v)", len(seen), sequences)
	}
	sort.Float64s(sequences)
	for index, sequence := range sequences {
		if sequence != float64(index+1) {
			t.Fatalf("page sequence numbers must be 1..5 with no gaps: %v", sequences)
		}
	}
	// A cursor is bound to one session.
	if stop := structured(postToolCall(t, server, "trace_session_stop", `{"export":false}`)); stop["code"] != nil {
		t.Fatalf("trace_session_stop failed: %v", stop)
	}
	if start := structured(postToolCall(t, server, "trace_session_start", `{"cpu":"m68k"}`)); start["code"] != nil {
		t.Fatalf("second trace_session_start failed: %v", start)
	}
	stale := structured(postToolCall(t, server, "trace_session_events", fmt.Sprintf(`{"limit":2,"collect":false,"cursor":%q}`, firstCursor)))
	if stale["code"] != "invalid_params" {
		t.Fatalf("a cursor from another session must be rejected: %v", stale)
	}
	malformed := structured(postToolCall(t, server, "trace_session_events", `{"limit":2,"collect":false,"cursor":"not-a-cursor"}`))
	if malformed["code"] != "invalid_params" {
		t.Fatalf("a malformed cursor must be rejected: %v", malformed)
	}
}

// TestMemoryDiffPagesWithOneAfterRead proves a later page compares the snapshot
// the first page read, instead of taking a second live reading.
func TestMemoryDiffPagesWithOneAfterRead(t *testing.T) {
	blob := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		return memReadFromBlob(blob, 0xFF0000)(context.Background(), method, params)
	}
	server := newTestServer(t, client)
	before := structured(postToolCall(t, server, "memory_dump", `{"space":"mem-ram","address":"0xFF0000","length":8}`))
	beforeID := before["artifact"].(map[string]any)["id"].(string)

	// Every cell changes, so "changed" matches all eight.
	blob = []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}
	first := structured(postToolCall(t, server, "memory_diff", fmt.Sprintf(`{"snapshot_before_id":%q,"mode":"changed","max_matches":3}`, beforeID)))
	hasMore, cursor := requirePagingEnvelope(t, first, 3, 8)
	if !hasMore || cursor == nil {
		t.Fatalf("first page must be partial: %v", first)
	}
	summary := first["summary"].(map[string]any)
	if summary["fresh_after_read"] != true {
		t.Fatalf("the first page must have read the after range: %v", summary)
	}
	afterID := summary["after_snapshot"].(map[string]any)["id"].(string)
	firstAddresses := matchAddresses(t, first)
	readsAfterFirstPage := countCalls(client, "mem_read")

	// The target changes again between the pages; the continuation must stay
	// anchored to the first page's after snapshot.
	blob = []byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28}
	second := structured(postToolCall(t, server, "memory_diff", fmt.Sprintf(`{"cursor":%q,"max_matches":3}`, cursor)))
	requirePagingEnvelope(t, second, 3, 8)
	secondSummary := second["summary"].(map[string]any)
	if secondSummary["fresh_after_read"] != false {
		t.Fatalf("a cursor page must reuse the after snapshot: %v", secondSummary)
	}
	if secondSummary["after_snapshot"].(map[string]any)["id"] != afterID {
		t.Fatalf("a cursor page must compare the same after snapshot: %v", secondSummary["after_snapshot"])
	}
	if reads := countCalls(client, "mem_read"); reads != readsAfterFirstPage {
		t.Fatalf("a cursor page must not read the target again: mem_read %d -> %d", readsAfterFirstPage, reads)
	}
	secondAddresses := matchAddresses(t, second)
	if firstAddresses[len(firstAddresses)-1] >= secondAddresses[0] {
		t.Fatalf("page 2 must continue after page 1: %v then %v", firstAddresses, secondAddresses)
	}
}

// TestMemorySearchNarrowsProvenSnapshot: with a proven snapshot the searched
// range may be narrowed without a provenance conflict, and both the requested
// and the searched range are reported.
func TestMemorySearchNarrowsProvenSnapshot(t *testing.T) {
	blob := []byte{0x00, 0x41, 0x42, 0x00, 0x41, 0x42, 0x00, 0x00}
	server := newTestServer(t, ramBlobClient(blob))
	dump := structured(postToolCall(t, server, "memory_dump", `{"space":"mem-ram","address":"0xFF0000","length":8}`))
	snapshotID := dump["artifact"].(map[string]any)["id"].(string)

	narrowed := structured(postToolCall(t, server, "memory_search", fmt.Sprintf(
		`{"pattern":"4142","snapshot_id":%q,"start_address":"0xFF0004","length":2}`, snapshotID)))
	if narrowed["code"] != nil {
		t.Fatalf("a subset of the captured range must narrow: %v", narrowed)
	}
	summary := narrowed["summary"].(map[string]any)
	searched := summary["searched_range"].(map[string]any)
	if searched["start_address"] != float64(0xFF0004) || searched["byte_length"] != float64(2) || searched["narrowed"] != true {
		t.Fatalf("searched_range must state the narrowed window: %v", searched)
	}
	if searched["offset_within_snapshot"] != float64(4) {
		t.Fatalf("searched_range must state its offset inside the snapshot: %v", searched)
	}
	// The captured range is not rewritten by narrowing.
	source := summary["source_range"].(map[string]any)
	if source["start_address"] != float64(0xFF0000) || source["byte_length"] != float64(8) {
		t.Fatalf("source_range must stay the whole capture: %v", source)
	}
	if summary["matches_total"] != float64(1) {
		t.Fatalf("only the narrowed window may match: %v", summary["matches_total"])
	}
	matches := narrowed["matches"].([]any)
	if matches[0].(map[string]any)["address"] != float64(0xFF0004) {
		t.Fatalf("match outside the requested window: %v", matches)
	}
	requested := summary["requested_range"].(map[string]any)
	if requested["start_address"] != float64(0xFF0004) || requested["byte_length"] != float64(2) {
		t.Fatalf("requested_range must echo the request: %v", requested)
	}
}

// TestReadToolsEchoRequestedAndEffective pins the request echo of the tools that
// translate or clamp a caller's address and length.
func TestReadToolsEchoRequestedAndEffective(t *testing.T) {
	blob := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	client := ramBlobClient(blob)
	server := newTestServer(t, client)

	// memory_read addressed through the processor bus domain: RAM offset 0
	// becomes the 0x00FF0000 bus address the target actually reads.
	read := structured(postToolCall(t, server, "memory_read", `{"space":"m68k-bus","address":0,"address_space":"mem-ram","length":2}`))
	if read["requested_address"] != float64(0) || read["requested_address_space"] != "mem-ram" || read["address_translated"] != true {
		t.Fatalf("memory_read must echo the requested coordinates: %v", read)
	}
	if read["address"] != float64(0xFF0000) || read["requested_length"] != float64(2) || read["effective_length"] != float64(2) {
		t.Fatalf("memory_read must echo the effective coordinates: %v", read)
	}
	if read["effective_address"] != float64(0xFF0000) {
		t.Fatalf("memory_read effective_address = %v", read["effective_address"])
	}

	// memory_dump: requested length next to the effective byte count.
	dump := structured(postToolCall(t, server, "memory_dump", `{"space":"mem-ram","address":"0xFF0000","length":4}`))
	summary := dump["summary"].(map[string]any)
	if summary["requested_length"] != float64(4) || summary["effective_length"] != float64(4) || summary["length_clamped"] != false {
		t.Fatalf("memory_dump must echo requested_length: %v", summary)
	}
	if summary["requested_address"] != float64(0xFF0000) {
		t.Fatalf("memory_dump must echo requested_address: %v", summary)
	}

	// vdp_memory_export: the buffer address and byte count actually exported.
	vdpClient := &fakeBridgeClient{status: newFakeStatus()}
	vdpClient.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "vdp_mem_read" {
			t.Fatalf("unexpected method %s", method)
		}
		return json.RawMessage(vdpExportPayload("vram", make([]byte, 8))), nil
	}
	vdpServer := newTestServer(t, vdpClient)
	export := structured(postToolCall(t, vdpServer, "vdp_memory_export", `{"target":"vram","address":256,"length":8}`))
	if export["requested_address"] != float64(256) || export["requested_length"] != float64(8) {
		t.Fatalf("vdp_memory_export must echo the request: %v", export)
	}
	if export["effective_address"] != float64(256) || export["effective_length"] != float64(8) {
		t.Fatalf("vdp_memory_export must echo the effective values: %v", export)
	}

	// memory_diff: the comparison semantics and the range actually compared.
	before := structured(postToolCall(t, server, "memory_dump", `{"space":"mem-ram","address":"0xFF0000","length":4}`))
	after := structured(postToolCall(t, server, "memory_dump", `{"space":"mem-ram","address":"0xFF0000","length":4}`))
	diff := structured(postToolCall(t, server, "memory_diff", fmt.Sprintf(
		`{"snapshot_before_id":%q,"snapshot_after_id":%q,"mode":"changed","width":"word"}`,
		before["artifact"].(map[string]any)["id"], after["artifact"].(map[string]any)["id"])))
	diffSummary := diff["summary"].(map[string]any)
	requested, _ := diffSummary["requested_comparison"].(map[string]any)
	if requested["mode"] != "changed" || requested["width"] != "word" {
		t.Fatalf("memory_diff must echo the requested comparison: %v", diffSummary)
	}
	compared, _ := diffSummary["compared_range"].(map[string]any)
	if compared["start_address"] != float64(0xFF0000) || compared["byte_length"] != float64(4) {
		t.Fatalf("memory_diff must report the compared range: %v", diffSummary)
	}
}

// TestStateDiffTruncatedNeverIdentical: a comparison that only read a prefix
// cannot report identical, even when the metadata and the prefix agree.
func TestStateDiffTruncatedNeverIdentical(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	context, err := server.contexts.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	// Two snapshots of the same declared size and hash whose bytes only differ
	// beyond the 8 MiB comparison cap: metadata and prefix agree, so only the
	// completeness rule can keep identical false.
	prefix := make([]byte, stateDiffFileCapBytes)
	for index := range prefix {
		prefix[index] = byte(index % 251)
	}
	dir := t.TempDir()
	beforePath := filepath.Join(dir, "before.zip")
	afterPath := filepath.Join(dir, "after.zip")
	beforeBytes := append(append([]byte{}, prefix...), []byte("AAAA")...)
	afterBytes := append(append([]byte{}, prefix...), []byte("BBBB")...)
	if err := os.WriteFile(beforePath, beforeBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(afterPath, afterBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	declared := "same-declared-sha"
	server.contexts.States.Create(context.ID, &analysis.Snapshot{
		ID: "big-before", ContextID: context.ID, Path: beforePath, SHA256: declared,
		SizeBytes: int64(len(beforeBytes)), CreatedAt: now, TargetGeneration: 3,
	})
	server.contexts.States.Create(context.ID, &analysis.Snapshot{
		ID: "big-after", ContextID: context.ID, Path: afterPath, SHA256: declared,
		SizeBytes: int64(len(afterBytes)), CreatedAt: now, TargetGeneration: 3,
	})
	result := structured(postToolCall(t, server, "state_diff", `{"snapshot_before_id":"big-before","snapshot_after_id":"big-after"}`))
	if result["identical"] != false {
		t.Fatalf("a truncated comparison must never be identical: %v", result["identical"])
	}
	comparison, _ := result["comparison"].(map[string]any)
	if comparison == nil {
		t.Fatalf("state_diff must report comparison completeness: %v", result)
	}
	if comparison["complete"] != false || comparison["verdict_scope"] != "prefix" || comparison["truncated"] != true {
		t.Fatalf("comparison completeness wrong: %v", comparison)
	}
	if reasons, _ := comparison["truncated_reasons"].([]any); len(reasons) == 0 {
		t.Fatalf("truncation must state why the verdict is withheld: %v", comparison)
	}
	if result["file_diff"].(map[string]any)["complete"] != false {
		t.Fatalf("file_diff must not claim a complete comparison: %v", result["file_diff"])
	}

	// A fully compared pair still reports the verdict.
	smallPath := filepath.Join(dir, "small.zip")
	if err := os.WriteFile(smallPath, []byte("SAME"), 0o644); err != nil {
		t.Fatal(err)
	}
	server.contexts.States.Create(context.ID, &analysis.Snapshot{ID: "small-a", ContextID: context.ID, Path: smallPath, SizeBytes: 4, CreatedAt: now})
	server.contexts.States.Create(context.ID, &analysis.Snapshot{ID: "small-b", ContextID: context.ID, Path: smallPath, SizeBytes: 4, CreatedAt: now})
	full := structured(postToolCall(t, server, "state_diff", `{"snapshot_before_id":"small-a","snapshot_after_id":"small-b"}`))
	if full["identical"] != true {
		t.Fatalf("a fully compared identical pair must stay identical: %v", full["identical"])
	}
	if full["comparison"].(map[string]any)["complete"] != true {
		t.Fatalf("a fully compared pair must report complete: %v", full["comparison"])
	}
}

// TestROMInfoWithholdsChecksumVerdictWhenIncomplete: matches is not emitted for
// an incomplete comparison, in either the bus or the file identity view.
func TestROMInfoWithholdsChecksumVerdictWhenIncomplete(t *testing.T) {
	body := make([]byte, 0x200)
	for index := range body {
		body[index] = byte(index)
	}
	fixture := buildMDROMFixture(body)
	// The header claims a body the file does not contain: the comparison is a
	// prefix, so no verdict may be reported.
	binaryPutUint32BigEndian(fixture.Header[0xA4:0xA8], uint32(0x1000-1))
	client, _ := writeFixtureROM(t, fixture, 0)
	server := newTestServer(t, client)

	content := structured(postToolCall(t, server, "rom_info", `{}`))
	checksum := content["header"].(map[string]any)["checksum"].(map[string]any)
	if checksum["complete"] != false {
		t.Fatalf("fixture must produce an incomplete comparison: %v", checksum)
	}
	if _, present := checksum["matches"]; present {
		t.Fatalf("an incomplete comparison must not emit matches: %v", checksum)
	}
	if checksum["verified"] != false || checksum["verdict"] != "unverified" || checksum["unverified_reason"] == "" {
		t.Fatalf("an incomplete comparison must state that it is unverified: %v", checksum)
	}
	identity := content["rom_identity"].(map[string]any)["checksum"].(map[string]any)
	if _, present := identity["matches"]; present {
		t.Fatalf("the file identity must not emit matches either: %v", identity)
	}
	if identity["verified"] != false || identity["verdict"] != "unverified" {
		t.Fatalf("the file identity must state that it is unverified: %v", identity)
	}

	// A complete comparison still carries the verdict.
	completeFixture := buildMDROMFixture(body)
	completeClient, _ := writeFixtureROM(t, completeFixture, 0)
	completeServer := newTestServer(t, completeClient)
	complete := structured(postToolCall(t, completeServer, "rom_info", `{}`))
	completeChecksum := complete["header"].(map[string]any)["checksum"].(map[string]any)
	if completeChecksum["complete"] != true || completeChecksum["verified"] != true {
		t.Fatalf("a complete comparison must be verified: %v", completeChecksum)
	}
	if completeChecksum["verdict"] != "match" && completeChecksum["verdict"] != "mismatch" {
		t.Fatalf("a complete comparison must state a verdict: %v", completeChecksum)
	}
	if _, present := completeChecksum["matches"]; !present {
		t.Fatalf("a complete comparison must emit matches: %v", completeChecksum)
	}
}

// binaryPutUint32BigEndian keeps the fixture edit readable at the call site.
func binaryPutUint32BigEndian(target []byte, value uint32) {
	target[0] = byte(value >> 24)
	target[1] = byte(value >> 16)
	target[2] = byte(value >> 8)
	target[3] = byte(value)
}

// TestTraceSessionExportTruncationAccountsForEvictedSegments: an export that
// lost whole segments is truncated by the store, not only by inline caps.
func TestTraceSessionExportTruncationAccountsForEvictedSegments(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	context, failure := resolveContext(server, "")
	if failure != nil {
		t.Fatalf("resolve context: %v", failure.Message)
	}
	session := tracing.NewSession("trs_export", context.ID, "m68k", "m68k-bus", tracing.Config{CPU: "m68k", MaxEvents: 64})
	session.AddEvents([]tracing.Event{{Kind: tracing.KindExecute, Address: 0x100}})

	clean, failure := exportTraceSessionEvents(toolContext{server: server, ctx: context2Background(), modern: true}, context, session, tracing.Filter{Kind: "any"}, "trace-session-jsonl")
	if failure != nil {
		t.Fatalf("export failed: %v", failure.Message)
	}
	if clean["truncated_by_store"] != false {
		t.Fatalf("a lossless export must not claim store truncation: %v", clean)
	}

	// A segment evicted before it was drained drops every event it held.
	session.AddLoss(1, 4096, 1, nil)
	lossy, failure := exportTraceSessionEvents(toolContext{server: server, ctx: context2Background(), modern: true}, context, session, tracing.Filter{Kind: "any"}, "trace-session-jsonl")
	if failure != nil {
		t.Fatalf("export failed: %v", failure.Message)
	}
	if lossy["truncated_by_store"] != true {
		t.Fatalf("an evicted segment must mark the export truncated: %v", lossy)
	}
	if reasons := lossy["truncation_reasons"]; reasons == nil {
		t.Fatalf("store truncation must state its reasons: %v", lossy)
	}
}

// context2Background returns a background context without importing context
// twice in the test body.
func context2Background() context.Context { return context.Background() }
