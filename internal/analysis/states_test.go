package analysis

import (
	"strings"
	"testing"
	"time"
)

func TestStateStoreLifecycle(t *testing.T) {
	store := newStateStore()
	snapshot := &Snapshot{
		ID:        NewSnapshotID(),
		ContextID: "ctx_a",
		Name:      "before-boss",
		Path:      `C:\states\ctx_a\state_1.zip`,
		SHA256:    strings.Repeat("ab", 32),
		SizeBytes: 4096,
		CreatedAt: time.Now().UTC(),
	}
	store.Create("ctx_a", snapshot)

	found, err := store.Get("ctx_a", snapshot.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if found.Path != snapshot.Path || found.Name != "before-boss" {
		t.Fatalf("unexpected snapshot: %+v", found)
	}
	if _, err := store.Get("ctx_a", "state_missing"); err == nil {
		t.Fatal("missing snapshot must fail")
	}
	if _, err := store.Get("ctx_b", snapshot.ID); err == nil {
		t.Fatal("snapshot of another context must not resolve")
	}

	list := store.List("ctx_a")
	if len(list) != 1 || list[0].ID != snapshot.ID {
		t.Fatalf("unexpected list: %+v", list)
	}
	if len(store.List("ctx_b")) != 0 {
		t.Fatal("empty context must list nothing")
	}
}

func TestStateStoreEvictsOldest(t *testing.T) {
	store := newStateStore()
	for i := 0; i < maxSnapshotsPerContext+5; i++ {
		store.Create("ctx_a", &Snapshot{
			ID:        NewSnapshotID(),
			ContextID: "ctx_a",
			Path:      "state-" + string(rune('a'+i%26)) + ".zip",
			CreatedAt: time.Now().UTC().Add(time.Duration(i) * time.Millisecond),
		})
	}
	list := store.List("ctx_a")
	if len(list) != maxSnapshotsPerContext {
		t.Fatalf("expected %d snapshots after eviction, got %d", maxSnapshotsPerContext, len(list))
	}
	// Newest first.
	if !list[0].CreatedAt.After(list[len(list)-1].CreatedAt) {
		t.Fatal("list must be newest first")
	}
}

func TestLedgerBoundedAndNewestFirst(t *testing.T) {
	ledger := newLedger()
	for i := 0; i < maxLedgerEntriesPerContext+10; i++ {
		ledger.Record(LedgerEntry{
			Timestamp: time.Now().UTC().Add(time.Duration(i) * time.Millisecond),
			Tool:      "memory_write",
			ContextID: "ctx_a",
			LeaseID:   "lease_1",
			Detail:    map[string]any{"index": i},
		})
	}
	list := ledger.List("ctx_a")
	if len(list) != maxLedgerEntriesPerContext {
		t.Fatalf("expected %d entries, got %d", maxLedgerEntriesPerContext, len(list))
	}
	if list[0].Detail["index"] != maxLedgerEntriesPerContext+9 {
		t.Fatalf("newest entry must come first, got %v", list[0].Detail)
	}
	if len(ledger.List("ctx_b")) != 0 {
		t.Fatal("unknown context must list nothing")
	}
}
