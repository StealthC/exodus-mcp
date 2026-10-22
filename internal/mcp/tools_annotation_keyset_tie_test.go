package mcp

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/StealthC/exodus-mcp/internal/analysis"
)

// Windows resolves the wall clock to ~0.5-15.6 ms, so annotations created in a
// row can share one created_at and the listing then falls back to the id
// tie-break. These tests force that tie deterministically on any host: they
// import an annotation set whose created_at values are identical, then page it
// through the public cursor. They catch a broken tie-break (repeats or skips at
// a page boundary) that a nanosecond clock hides.
func importAnnotationsAtOneInstant(t *testing.T, server *Server, count int) []string {
	t.Helper()
	stamp := time.Date(2026, 10, 22, 15, 51, 16, 134068000, time.UTC)
	document := map[string]any{"schema_version": "annotation-export/1", "annotations": []any{}}
	ids := make([]string, 0, count)
	for index := 0; index < count; index++ {
		id := analysis.NewAnnotationID()
		ids = append(ids, id)
		document["annotations"] = append(document["annotations"].([]any), map[string]any{
			"id":         id,
			"context_id": "ctx",
			"title":      fmt.Sprintf("tie %d", index),
			"kind":       "observation",
			"created_at": stamp.Format(time.RFC3339Nano),
			"updated_at": stamp.Format(time.RFC3339Nano),
			"tags":       []string{},
			"links":      map[string]any{},
		})
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	imported := structured(postToolCall(t, server, "annotation_import", fmt.Sprintf(`{"data":%s}`, raw)))
	if imported["imported"] != float64(count) || imported["code"] != nil {
		t.Fatalf("import failed: %v", imported)
	}
	return ids
}

// TestAnnotationListCursorPagesTimestampTies pages a fully tied annotation set
// with the cursor to exhaustion and requires the pages to be the exact slices of
// one listing: no repeat and no skip at a tie boundary.
func TestAnnotationListCursorPagesTimestampTies(t *testing.T) {
	server := newTestServer(t, ramBlobClient([]byte{0}))
	ids := importAnnotationsAtOneInstant(t, server, 6)

	full := structured(postToolCall(t, server, "annotation_list", `{"limit":100,"include_stale":true}`))
	want := make([]string, 0, len(ids))
	for _, raw := range full["annotations"].([]any) {
		want = append(want, raw.(map[string]any)["id"].(string))
	}
	if len(want) != len(ids) {
		t.Fatalf("full listing = %d rows, want %d", len(want), len(ids))
	}

	got := make([]string, 0, len(want))
	cursor := ""
	for page := 0; page < len(ids)+2; page++ {
		arguments := `{"limit":2,"include_stale":true}`
		if cursor != "" {
			arguments = fmt.Sprintf(`{"limit":2,"include_stale":true,"cursor":%q}`, cursor)
		}
		content := structured(postToolCall(t, server, "annotation_list", arguments))
		if content["code"] != nil {
			t.Fatalf("page %d failed: %v", page+1, content)
		}
		for _, raw := range content["annotations"].([]any) {
			got = append(got, raw.(map[string]any)["id"].(string))
		}
		if content["next_cursor"] == nil {
			if content["has_more"] != false {
				t.Fatalf("last page must report has_more false: %v", content)
			}
			break
		}
		cursor = content["next_cursor"].(string)
	}
	if len(got) != len(want) {
		t.Fatalf("paged %d rows, listing has %d (%v vs %v)", len(got), len(want), got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("paged order differs from the listing at %d: %v vs %v", index, got, want)
		}
	}
}

// TestAnnotationListCursorWithinTieSurvivesWrites is the CI failure shape with
// the tie forced: a create and an edit land between the pages while every row
// shares one created_at. Page 2 must be the continuation of the documented
// (created_at desc, id desc) order, and no page-1 row may reappear.
func TestAnnotationListCursorWithinTieSurvivesWrites(t *testing.T) {
	server := newTestServer(t, ramBlobClient([]byte{0}))
	ids := importAnnotationsAtOneInstant(t, server, 5)

	first := structured(postToolCall(t, server, "annotation_list", `{"limit":2,"include_stale":true}`))
	if hasMore, _ := requirePagingEnvelope(t, first, 2, 5); !hasMore {
		t.Fatalf("first page must be partial: %v", first)
	}
	cursor := first["next_cursor"]

	// The concurrent writes the CI test performs: one new row (it sorts before the
	// cursor under any clock) and one edit (it never moves the created_at anchor).
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
	expected := expectedAnnotationContinuation(t, server, first, 2)
	got := make([]string, 0, len(second["annotations"].([]any)))
	for _, raw := range second["annotations"].([]any) {
		got = append(got, raw.(map[string]any)["id"].(string))
	}
	if len(got) != len(expected) {
		t.Fatalf("page 2 returned %v, want the continuation %v of the documented order", got, expected)
	}
	for index := range expected {
		if got[index] != expected[index] {
			t.Fatalf("page 2 = %v, want the continuation %v of the documented order", got, expected)
		}
	}
}
