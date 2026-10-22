package artifact

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// putSequence writes n artifacts of one context in a deterministic creation
// order, backdating each so the listing order is unambiguous.
func putSequence(t *testing.T, store *Store, contextID, kind string, count int, start time.Time) []Artifact {
	t.Helper()
	stored := make([]Artifact, 0, count)
	for index := 0; index < count; index++ {
		artifact, err := store.PutWithProvenance(contextID, kind, "application/octet-stream", []byte{byte(index)}, &Provenance{Kind: kind})
		if err != nil {
			t.Fatal(err)
		}
		artifact.CreatedAt = start.Add(time.Duration(index) * time.Second)
		store.mu.Lock()
		store.artifacts[artifact.ID] = artifact
		store.mu.Unlock()
		stored = append(stored, artifact)
	}
	return stored
}

func TestListFiltersByContextAndKind(t *testing.T) {
	store := newTestStore(t)
	base := time.Now().UTC().Add(-time.Hour)
	dumps := putSequence(t, store, "ctx_a", "memory-dump", 3, base)
	traces := putSequence(t, store, "ctx_a", "cpu-trace", 2, base.Add(time.Minute))
	putSequence(t, store, "ctx_b", "memory-dump", 1, base)

	page, err := store.List(ListQuery{ContextID: "ctx_a"})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 5 || len(page.Artifacts) != 5 || page.HasMore {
		t.Fatalf("context listing wrong: total=%d returned=%d has_more=%v", page.Total, len(page.Artifacts), page.HasMore)
	}
	// Creation order, oldest first: the three dumps, then the two traces.
	expected := []string{dumps[0].ID, dumps[1].ID, dumps[2].ID, traces[0].ID, traces[1].ID}
	for index, stored := range page.Artifacts {
		if stored.ID != expected[index] {
			t.Fatalf("unexpected order at %d: %s (want %s)", index, stored.ID, expected[index])
		}
	}

	onlyDumps, err := store.List(ListQuery{ContextID: "ctx_a", Kind: "memory-dump"})
	if err != nil {
		t.Fatal(err)
	}
	if onlyDumps.Total != 3 || onlyDumps.Artifacts[0].Kind != "memory-dump" {
		t.Fatalf("kind filter wrong: %+v", onlyDumps)
	}
	// Another context never sees these artifacts.
	other, err := store.List(ListQuery{ContextID: "ctx_c"})
	if err != nil {
		t.Fatal(err)
	}
	if other.Total != 0 || len(other.Artifacts) != 0 {
		t.Fatalf("cross-context listing leaked: %+v", other)
	}
}

func TestListPagesWithStableCursor(t *testing.T) {
	store := newTestStore(t)
	putSequence(t, store, "ctx_a", "memory-dump", 5, time.Now().UTC().Add(-time.Hour))

	first, err := store.List(ListQuery{ContextID: "ctx_a", Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Artifacts) != 2 || first.Total != 5 || !first.HasMore || first.NextCursor == "" {
		t.Fatalf("first page wrong: %+v", first)
	}
	second, err := store.List(ListQuery{ContextID: "ctx_a", Limit: 2, Cursor: first.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Artifacts) != 2 || !second.HasMore {
		t.Fatalf("second page wrong: %+v", second)
	}
	third, err := store.List(ListQuery{ContextID: "ctx_a", Limit: 2, Cursor: second.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(third.Artifacts) != 1 || third.HasMore || third.NextCursor != "" {
		t.Fatalf("last page wrong: %+v", third)
	}
	// Pages never repeat an artifact.
	seen := map[string]bool{}
	for _, page := range []ListPage{first, second, third} {
		for _, stored := range page.Artifacts {
			if seen[stored.ID] {
				t.Fatalf("artifact %s appeared on two pages", stored.ID)
			}
			seen[stored.ID] = true
		}
	}
	if _, err := store.List(ListQuery{ContextID: "ctx_a", Cursor: "not-a-cursor"}); err == nil {
		t.Fatal("a malformed cursor must be rejected")
	}
}

func TestListFiltersByCaptureID(t *testing.T) {
	store := newTestStore(t)
	captured, err := store.PutWithProvenance("ctx_a", "memory-snapshot", "application/octet-stream", []byte{1}, &Provenance{Kind: "memory-snapshot", CaptureID: "cap_AAAAAAAAAAAA"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutWithProvenance("ctx_a", "memory-snapshot", "application/octet-stream", []byte{2}, &Provenance{Kind: "memory-snapshot", CaptureID: "cap_BBBBBBBBBBBB"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("ctx_a", "memory-dump", "application/octet-stream", []byte{3}); err != nil {
		t.Fatal(err)
	}
	page, err := store.List(ListQuery{ContextID: "ctx_a", CaptureID: "cap_AAAAAAAAAAAA"})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || page.Artifacts[0].ID != captured.ID {
		t.Fatalf("capture filter wrong: %+v", page)
	}
}

func TestStoreReopensPersistedArtifacts(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := store.PutWithProvenance("ctx_a", "vdp-capture-manifest", "application/json", []byte(`{"schema_version":"vdp-capture-manifest/1"}`), &Provenance{Kind: "vdp-capture-manifest", CaptureID: "cap_PERSISTED000"})
	if err != nil {
		t.Fatal(err)
	}
	if captured.SchemaVersion != "vdp-capture-manifest/1" {
		t.Fatalf("schema version not recorded at write time: %q", captured.SchemaVersion)
	}
	if err := store.PutCapture(Capture{
		CaptureID:        "cap_PERSISTED000",
		ContextID:        "ctx_a",
		ProducerTool:     "vdp_capture",
		ManifestArtifact: captured.ID,
		Components:       []CaptureComponent{{Name: "vram", ArtifactID: captured.ID, Kind: "vdp-vram"}},
	}); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := reopened.Bytes(captured.ID, "ctx_a"); err != nil {
		t.Fatalf("artifact did not survive the restart: %v", err)
	}
	page, err := reopened.List(ListQuery{ContextID: "ctx_a"})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || page.Artifacts[0].SchemaVersion != "vdp-capture-manifest/1" {
		t.Fatalf("indexed listing did not survive the restart: %+v", page)
	}
	resolved, err := reopened.Capture("cap_PERSISTED000", "ctx_a")
	if err != nil {
		t.Fatalf("capture did not survive the restart: %v", err)
	}
	if resolved.ManifestArtifact != captured.ID || len(resolved.Components) != 1 {
		t.Fatalf("capture index wrong after restart: %+v", resolved)
	}
	// The persisted file and the index live side by side.
	if _, err := os.Stat(filepath.Join(dir, indexFileName)); err != nil {
		t.Fatalf("index document missing: %v", err)
	}
}

func TestReopenDropsIndexEntriesWithoutBytes(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := store.Put("ctx_a", "memory-dump", "application/octet-stream", []byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, captured.ID)); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	page, err := reopened.List(ListQuery{ContextID: "ctx_a"})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 0 {
		t.Fatalf("an artifact without bytes must not be listed: %+v", page)
	}
}

func TestExpiryIsObservableAndDropsCaptures(t *testing.T) {
	store := newTestStore(t)
	stale, err := store.PutWithProvenance("ctx_a", "memory-snapshot", "application/octet-stream", []byte{1}, &Provenance{Kind: "memory-snapshot", CaptureID: "cap_EXPIRING00000"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutCapture(Capture{
		CaptureID:        "cap_EXPIRING00000",
		ContextID:        "ctx_a",
		ProducerTool:     "memory_snapshot_capture",
		ManifestArtifact: stale.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if expiry := store.ExpiresAt(stale.CreatedAt); expiry != nil {
		t.Fatalf("unlimited retention must report no expiry, got %v", *expiry)
	}
	if err := store.SetRetention(2 * time.Hour); err != nil {
		t.Fatal(err)
	}
	expiry := store.ExpiresAt(stale.CreatedAt)
	if expiry == nil || !expiry.Equal(stale.CreatedAt.Add(2*time.Hour)) {
		t.Fatalf("expiry not derived from retention: %v", expiry)
	}

	store.mu.Lock()
	backdated := store.artifacts[stale.ID]
	backdated.CreatedAt = time.Now().UTC().Add(-3 * time.Hour)
	store.artifacts[stale.ID] = backdated
	capture := store.captures["cap_EXPIRING00000"]
	capture.CreatedAt = backdated.CreatedAt
	store.captures[capture.CaptureID] = capture
	store.mu.Unlock()

	removed, err := store.ExpireOlderThan(time.Hour)
	if err != nil || removed != 1 {
		t.Fatalf("expiry sweep removed %d (err %v), want 1", removed, err)
	}
	if _, err := store.Capture("cap_EXPIRING00000", "ctx_a"); err == nil {
		t.Fatal("a capture whose artifacts expired must not resolve")
	}
}

func TestCaptureResolutionIsContextScoped(t *testing.T) {
	store := newTestStore(t)
	if err := store.PutCapture(Capture{CaptureID: "cap_SCOPED0000000", ContextID: "ctx_a", ProducerTool: "vdp_capture"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Capture("cap_SCOPED0000000", "ctx_a"); err != nil {
		t.Fatalf("owning context must resolve: %v", err)
	}
	if _, err := store.Capture("cap_SCOPED0000000", "ctx_b"); err == nil {
		t.Fatal("another context must not resolve the capture")
	}
	if _, err := store.Capture("bogus", "ctx_a"); err == nil {
		t.Fatal("a malformed capture id must not resolve")
	}
	if err := store.PutCapture(Capture{CaptureID: "cap_SCOPED0000000"}); err == nil {
		t.Fatal("capture registration requires a context")
	}
}
