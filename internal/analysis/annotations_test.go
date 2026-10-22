package analysis

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testAnnotation() Annotation {
	address := uint64(0xFF1234)
	end := uint64(0xFF1237)
	length := end - address + 1
	return Annotation{
		ID:               "annotation_fixtureAAA",
		Title:            "life counter",
		Text:             "claims 0xFF1234 is the life counter",
		Tags:             []string{"hud", "mario"},
		Category:         "hypothesis",
		Author:           "analyst-a",
		Source:           "diff artifact",
		Confidence:       "medium",
		Kind:             "hypothesis",
		AddressSpace:     "m68k-bus",
		Address:          &address,
		EndAddress:       &end,
		Length:           &length,
		ROMPath:          "F:\\roms\\kid.bin",
		ROMSHA256:        "aaaabbbbccccdddd",
		TargetGeneration: 7,
		Links: AnnotationLinks{
			Artifacts:   []string{"art_diff1"},
			Watchpoints: []uint64{3},
			Symbols:     []string{"lives"},
		},
	}
}

func TestAnnotationStoreLifecycle(t *testing.T) {
	store := NewAnnotationStore()
	created, err := store.Create("ctx_a", testAnnotation())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.ID, "annotation_") || len(created.ID) != len("annotation_")+12 {
		t.Fatalf("annotation id malformed: %q", created.ID)
	}
	if created.ContextID != "ctx_a" || created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Fatalf("creation stamps missing: %+v", created)
	}
	got, err := store.Get("ctx_a", created.ID)
	if err != nil || got.Title != "life counter" {
		t.Fatalf("get failed: %v %+v", err, got)
	}
	if _, err := store.Get("ctx_b", created.ID); !errors.Is(err, ErrAnnotationNotFound) {
		t.Fatalf("cross-context get must be unknown: %v", err)
	}

	title := "updated title"
	text := ""
	category := "observation"
	kind := "observation"
	tags := []string{"hud"}
	updated, err := store.Update("ctx_a", created.ID, AnnotationUpdate{
		Title: &title, Text: &text, Category: &category, Kind: &kind, Tags: &tags,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Title != "updated title" || updated.Category != "observation" || updated.Kind != "observation" {
		t.Fatalf("update not applied: %+v", updated)
	}
	if !updated.UpdatedAt.After(created.UpdatedAt) {
		t.Fatalf("updated_at must advance")
	}

	if err := store.Delete("ctx_a", created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("ctx_a", created.ID); !errors.Is(err, ErrAnnotationNotFound) {
		t.Fatalf("delete must remove: %v", err)
	}
	if err := store.Delete("ctx_a", created.ID); !errors.Is(err, ErrAnnotationNotFound) {
		t.Fatalf("double delete must fail: %v", err)
	}
}

func TestAnnotationCreateValidation(t *testing.T) {
	store := NewAnnotationStore()
	ann := testAnnotation()
	ann.Title = ""
	if _, err := store.Create("ctx", ann); err == nil || !strings.Contains(err.Error(), "title") {
		t.Fatalf("empty title must be rejected: %v", err)
	}
	ann = testAnnotation()
	ann.Title = strings.Repeat("a", 201)
	if _, err := store.Create("ctx", ann); err == nil {
		t.Fatal("overlong title must be rejected")
	}
	ann = testAnnotation()
	ann.Text = strings.Repeat("a", 4097)
	if _, err := store.Create("ctx", ann); err == nil {
		t.Fatal("overlong text must be rejected")
	}
	ann = testAnnotation()
	ann.Kind = "fact"
	if _, err := store.Create("ctx", ann); err == nil || !strings.Contains(err.Error(), "kind") {
		t.Fatalf("invalid kind must be rejected: %v", err)
	}
	ann = testAnnotation()
	ann.Category = "banana"
	if _, err := store.Create("ctx", ann); err == nil {
		t.Fatal("invalid category must be rejected")
	}
	ann = testAnnotation()
	ann.Confidence = "certain"
	if _, err := store.Create("ctx", ann); err == nil {
		t.Fatal("invalid confidence must be rejected")
	}
	ann = testAnnotation()
	badEnd := uint64(0xFF1233) // below address
	ann.EndAddress = &badEnd
	if _, err := store.Create("ctx", ann); err == nil {
		t.Fatal("end below address must be rejected")
	}
	ann = testAnnotation()
	ann.Address = nil
	if _, err := store.Create("ctx", ann); err == nil || !strings.Contains(err.Error(), "end_address") {
		t.Fatalf("end without address must be rejected: %v", err)
	}
	ann = testAnnotation()
	ann.Address = nil
	ann.EndAddress = nil
	length := uint64(4)
	ann.Length = &length
	if _, err := store.Create("ctx", ann); err == nil {
		t.Fatal("length without address must be rejected")
	}
}

func TestAnnotationStalenessFlags(t *testing.T) {
	store := NewAnnotationStore()
	created, err := store.Create("ctx_a", testAnnotation())
	if err != nil {
		t.Fatal(err)
	}
	current := AnnotationTarget{ROMPath: "F:\\roms\\kid.bin", ROMSHA256: "aaaabbbbccccdddd", Generation: 7}
	if AnnotationIsStale(created, current) {
		t.Fatal("annotation must be fresh when stamps match")
	}
	advanced := current
	advanced.Generation = 8
	if !AnnotationIsStale(created, advanced) || AnnotationStaleReason(created, advanced) != "target_generation_mismatch" {
		t.Fatalf("generation mismatch must flag stale: %q", AnnotationStaleReason(created, advanced))
	}
	otherROM := current
	otherROM.ROMSHA256 = "ffffffffffffffff"
	if !AnnotationIsStale(created, otherROM) || AnnotationStaleReason(created, otherROM) != "rom_sha256_mismatch" {
		t.Fatalf("rom mismatch must flag stale: %q", AnnotationStaleReason(created, otherROM))
	}
	both := AnnotationTarget{ROMSHA256: "ffffffffffffffff", Generation: 9}
	if reason := AnnotationStaleReason(created, both); reason != "rom_sha256_mismatch,target_generation_mismatch" {
		t.Fatalf("both axes must be reported: %q", reason)
	}
}

func TestAnnotationListFilterPaginationAndStalenessPolicy(t *testing.T) {
	store := NewAnnotationStore()
	current := AnnotationTarget{ROMSHA256: "aaaabbbbccccdddd", Generation: 7}
	for index := 0; index < 5; index++ {
		ann := testAnnotation()
		ann.Title = "fresh " + strings.Repeat("x", index)
		if _, err := store.Create("ctx_a", ann); err != nil {
			t.Fatal(err)
		}
	}
	for index := 0; index < 3; index++ {
		ann := testAnnotation()
		ann.Title = "ancient hypothesis"
		ann.ROMSHA256 = "0000000000000000"
		ann.TargetGeneration = 2
		if _, err := store.Create("ctx_a", ann); err != nil {
			t.Fatal(err)
		}
	}
	// Default policy: stale excluded but counted, never silently dropped.
	result := store.List("ctx_a", AnnotationFilter{Limit: 10}, current)
	if len(result.Annotations) != 5 || result.Total != 5 || result.StaleExcluded != 3 || result.Truncated {
		t.Fatalf("default list wrong: %d ann, total %d, excluded %d, truncated %v",
			len(result.Annotations), result.Total, result.StaleExcluded, result.Truncated)
	}
	// IncludeStale keeps them flagged; newest first ordering.
	result = store.List("ctx_a", AnnotationFilter{Limit: 10, IncludeStale: true}, current)
	if len(result.Annotations) != 8 || result.StaleExcluded != 0 {
		t.Fatalf("include_stale list wrong: %d ann, excluded %d", len(result.Annotations), result.StaleExcluded)
	}
	// StaleOnly.
	result = store.List("ctx_a", AnnotationFilter{Limit: 10, StaleOnly: true}, current)
	if len(result.Annotations) != 3 {
		t.Fatalf("stale_only list wrong: %d", len(result.Annotations))
	}
	for _, ann := range result.Annotations {
		if !AnnotationIsStale(ann, current) {
			t.Fatalf("stale_only returned fresh annotation %s", ann.ID)
		}
	}
	// Query filter over title, case-insensitive.
	result = store.List("ctx_a", AnnotationFilter{Limit: 10, IncludeStale: true, Query: "ANCIENT"}, current)
	if len(result.Annotations) != 3 {
		t.Fatalf("query filter wrong: %d", len(result.Annotations))
	}
	// Tag filter.
	result = store.List("ctx_a", AnnotationFilter{Limit: 10, IncludeStale: true, Tags: []string{"hud"}}, current)
	if len(result.Annotations) != 8 {
		t.Fatalf("tag filter wrong: %d", len(result.Annotations))
	}
	result = store.List("ctx_a", AnnotationFilter{Limit: 10, IncludeStale: true, Tags: []string{"missing"}}, current)
	if len(result.Annotations) != 0 {
		t.Fatalf("missing tag filter wrong: %d", len(result.Annotations))
	}
	// Tag filter is AND: every listed tag must be present.
	result = store.List("ctx_a", AnnotationFilter{Limit: 10, IncludeStale: true, Tags: []string{"hud", "mario"}}, current)
	if len(result.Annotations) != 8 {
		t.Fatalf("AND tag filter wrong: %d", len(result.Annotations))
	}
	result = store.List("ctx_a", AnnotationFilter{Limit: 10, IncludeStale: true, Tags: []string{"hud", "missing"}}, current)
	if len(result.Annotations) != 0 {
		t.Fatalf("AND tag filter with missing tag wrong: %d", len(result.Annotations))
	}
	// Pagination: offset and limit with truncated flag.
	result = store.List("ctx_a", AnnotationFilter{Limit: 3, IncludeStale: true}, current)
	if len(result.Annotations) != 3 || !result.Truncated || result.Total != 8 {
		t.Fatalf("pagination wrong: %d ann, truncated %v, total %d", len(result.Annotations), result.Truncated, result.Total)
	}
	result = store.List("ctx_a", AnnotationFilter{Limit: 3, Offset: 6, IncludeStale: true}, current)
	if len(result.Annotations) != 2 || result.Truncated {
		t.Fatalf("last page wrong: %d ann, truncated %v", len(result.Annotations), result.Truncated)
	}
}

func TestAnnotationLimit(t *testing.T) {
	store := NewAnnotationStore()
	for index := 0; index < MaxAnnotationsPerContext; index++ {
		ann := testAnnotation()
		ann.Title = "t"
		if _, err := store.Create("ctx_a", ann); err != nil {
			t.Fatalf("create %d failed: %v", index, err)
		}
	}
	ann := testAnnotation()
	ann.Title = "overflow"
	if _, err := store.Create("ctx_a", ann); !errors.Is(err, ErrAnnotationLimit) {
		t.Fatalf("over-cap create must fail with ErrAnnotationLimit: %v", err)
	}
	// A different context has its own budget.
	if _, err := store.Create("ctx_b", ann); err != nil {
		t.Fatalf("ctx_b create must succeed: %v", err)
	}
}

func TestAnnotationExportImportRoundtrip(t *testing.T) {
	source := NewAnnotationStore()
	created, err := source.Create("ctx_source", testAnnotation())
	if err != nil {
		t.Fatal(err)
	}
	document := AnnotationExportDocument{
		SchemaVersion:    AnnotationExportSchema,
		ExportedAt:       time.Now().UTC(),
		TargetGeneration: 7,
		Annotations:      source.Export("ctx_source"),
	}
	data, err := document.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	// The document must carry the versioned schema.
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["schema_version"] != AnnotationExportSchema || len(raw["annotations"].([]any)) != 1 {
		t.Fatalf("export document malformed: %s", data)
	}

	target := NewAnnotationStore()
	imported, conflicts, err := target.Import("ctx_target", data, false)
	if err != nil {
		t.Fatal(err)
	}
	if imported != 1 || len(conflicts) != 0 {
		t.Fatalf("import wrong: %d imported, %v conflicts", imported, conflicts)
	}
	// A non-overwrite re-import is all conflicts carrying the existing id.
	_, conflicts, err = target.Import("ctx_target", data, false)
	if err != nil || len(conflicts) != 1 || conflicts[0] != created.ID {
		t.Fatalf("conflict ids wrong: %v, %v", conflicts, err)
	}
	// Overwrite replaces and counts as imported.
	reimported, conflicts, err := target.Import("ctx_target", data, true)
	if err != nil || reimported != 1 || len(conflicts) != 0 {
		t.Fatalf("overwrite import wrong: %d, %v, %v", reimported, conflicts, err)
	}
	// Another context imports the same export independently.
	other := NewAnnotationStore()
	imported, _, err = other.Import("ctx_other", data, false)
	if err != nil || imported != 1 {
		t.Fatalf("second context import failed: %v", err)
	}
}

func TestAnnotationImportRejectsBadDocuments(t *testing.T) {
	store := NewAnnotationStore()
	if _, _, err := store.Import("ctx", []byte(`{"schema_version":"annotation-export/9","annotations":[]}`), false); err == nil {
		t.Fatal("unsupported schema must be rejected")
	}
	now := time.Now().UTC()
	bad := AnnotationExportDocument{
		SchemaVersion: AnnotationExportSchema,
		Annotations: []Annotation{{
			ID:        "not-an-annotation-id",
			Title:     "x",
			Kind:      "observation",
			CreatedAt: now,
			UpdatedAt: now,
		}},
	}
	data, err := bad.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Import("ctx", data, false); err == nil || !strings.Contains(err.Error(), "invalid id") {
		t.Fatalf("invalid annotation id must be rejected: %v", err)
	}
	invalid := AnnotationExportDocument{
		SchemaVersion: AnnotationExportSchema,
		Annotations: []Annotation{{
			ID:        "annotation_bad",
			Title:     "x",
			Kind:      "fact", // invalid kind
			CreatedAt: now,
			UpdatedAt: now,
		}},
	}
	data, err = invalid.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Import("ctx", data, false); err == nil || !strings.Contains(err.Error(), "kind") {
		t.Fatalf("invalid annotation kind must reject the whole import: %v", err)
	}
	// A valid exported document imports cleanly.
	exported := AnnotationExportDocument{
		SchemaVersion: AnnotationExportSchema,
		Annotations:   []Annotation{testAnnotation()},
	}
	data, err = exported.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Import("ctx", data, false); err != nil {
		t.Fatalf("valid document must import: %v", err)
	}
}

func TestAnnotationUpdateAddressDomain(t *testing.T) {
	store := NewAnnotationStore()
	created, err := store.Create("ctx_a", testAnnotation())
	if err != nil {
		t.Fatal(err)
	}
	// Length must be recomputed from the new address against the kept end.
	newAddress := uint64(0xFF1235)
	expectedLength := uint64(0xFF1237-0xFF1235) + 1
	updated, err := store.Update("ctx_a", created.ID, AnnotationUpdate{Address: &newAddress})
	if updated.Address == nil || *updated.Address != newAddress || updated.Length == nil || *updated.Length != expectedLength {
		t.Fatalf("address update did not recompute length: %+v", updated)
	}
	clear, err := store.Update("ctx_a", created.ID, AnnotationUpdate{ClearAddress: true})
	if err != nil {
		t.Fatal(err)
	}
	if clear.Address != nil || clear.EndAddress != nil || clear.Length != nil {
		t.Fatalf("clear address must drop the whole domain: %+v", clear)
	}
}

// importAnnotationsWithTimestamps loads one annotation set whose created_at
// values come from the caller, which is the only way to build the timestamp
// ties a coarse host clock produces (Windows resolves ~0.5-15.6 ms, so several
// annotations created in a row can share one instant).
func importAnnotationsWithTimestamps(t *testing.T, store *AnnotationStore, ctxID string, stamps []time.Time) []string {
	t.Helper()
	document := map[string]any{"schema_version": "annotation-export/1", "annotations": []any{}}
	ids := make([]string, 0, len(stamps))
	for _, stamp := range stamps {
		id := NewAnnotationID()
		ids = append(ids, id)
		document["annotations"] = append(document["annotations"].([]any), map[string]any{
			"id":         id,
			"context_id": ctxID,
			"title":      "tie " + id,
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
	imported, conflicts, err := store.Import(ctxID, raw, false)
	if err != nil || imported != len(stamps) || len(conflicts) != 0 {
		t.Fatalf("import: imported=%d conflicts=%v err=%v", imported, conflicts, err)
	}
	return ids
}

// TestAnnotationListKeysetPagingWithinOneTimestamp pins the keyset order when
// several annotations share one created_at: the (created_at, id) tuple is total,
// so paging with a cursor must return exactly the slices of the full listing —
// no repeat and no skip at a tie boundary, regardless of clock resolution.
func TestAnnotationListKeysetPagingWithinOneTimestamp(t *testing.T) {
	base := time.Date(2026, 10, 22, 15, 51, 16, 134068000, time.UTC)
	cases := []struct {
		name   string
		stamps []time.Time
	}{
		{"all-tied", []time.Time{base, base, base, base, base}},
		{"tie-groups", []time.Time{base.Add(-time.Nanosecond), base, base, base, base.Add(time.Nanosecond)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := NewAnnotationStore()
			importAnnotationsWithTimestamps(t, store, "ctx_tie", tc.stamps)
			current := AnnotationTarget{Generation: 1}

			full := store.List("ctx_tie", AnnotationFilter{Limit: 100, IncludeStale: true}, current)
			if len(full.Annotations) != len(tc.stamps) {
				t.Fatalf("full listing = %d rows, want %d", len(full.Annotations), len(tc.stamps))
			}
			want := make([]string, 0, len(full.Annotations))
			for _, ann := range full.Annotations {
				want = append(want, ann.ID)
			}

			got := make([]string, 0, len(want))
			filter := AnnotationFilter{Limit: 2, IncludeStale: true}
			for page := 0; page < len(tc.stamps)+2; page++ {
				result := store.List("ctx_tie", filter, current)
				for _, ann := range result.Annotations {
					got = append(got, ann.ID)
				}
				if !result.Truncated || len(result.Annotations) == 0 {
					break
				}
				last := result.Annotations[len(result.Annotations)-1]
				filter.AfterCreatedAt = last.CreatedAt
				filter.AfterID = last.ID
			}
			if len(got) != len(want) {
				t.Fatalf("paged %d rows, full listing has %d (%v vs %v)", len(got), len(want), got, want)
			}
			for index := range want {
				if got[index] != want[index] {
					t.Fatalf("paged order differs from the full listing at %d: %v vs %v", index, got, want)
				}
			}
			// The anchor row itself is never returned again: a resume is strict.
			anchor := full.Annotations[0]
			resumed := store.List("ctx_tie", AnnotationFilter{Limit: 100, IncludeStale: true, AfterCreatedAt: anchor.CreatedAt, AfterID: anchor.ID}, current)
			for _, ann := range resumed.Annotations {
				if ann.ID == anchor.ID {
					t.Fatalf("the anchor %s was returned again", ann.ID)
				}
			}
			if len(resumed.Annotations) != len(full.Annotations)-1 {
				t.Fatalf("resume after the first row returned %d rows, want %d", len(resumed.Annotations), len(full.Annotations)-1)
			}
		})
	}
}
