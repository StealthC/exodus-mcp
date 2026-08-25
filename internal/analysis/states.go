package analysis

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Snapshot is one context-scoped system state saved through the emulator.
// The emulator owns the actual state file; the store keeps the metadata the
// server needs to list, verify, and reload snapshots. The provenance fields
// (context, control lock, target generation, ROM) describe who and when —
// they are not an authorization boundary.
type Snapshot struct {
	ID               string    `json:"id"`
	ContextID        string    `json:"context_id"`
	Name             string    `json:"name,omitempty"`
	Path             string    `json:"path"`
	SHA256           string    `json:"sha256"`
	SizeBytes        int64     `json:"size_bytes"`
	CreatedAt        time.Time `json:"created_at"`
	ROMPath          string    `json:"rom_path,omitempty"`
	ControlID        string    `json:"control_id,omitempty"`
	TargetGeneration uint64    `json:"target_generation"`
}

const maxSnapshotsPerContext = 32

// StateStore tracks snapshots per analysis context. The emulator system is
// single and shared, so snapshots describe machine state, not context state;
// contexts only organize ownership of the saved files.
type StateStore struct {
	mu        sync.Mutex
	snapshots map[string][]*Snapshot
}

func newStateStore() *StateStore {
	return &StateStore{snapshots: make(map[string][]*Snapshot)}
}

// Create registers a new snapshot for a context, evicting the oldest entries
// beyond the per-context cap.
func (store *StateStore) Create(contextID string, snapshot *Snapshot) *Snapshot {
	store.mu.Lock()
	defer store.mu.Unlock()
	list := store.snapshots[contextID]
	list = append(list, snapshot)
	for len(list) > maxSnapshotsPerContext {
		list = list[1:]
	}
	store.snapshots[contextID] = list
	return snapshot
}

// Get returns one snapshot of a context.
func (store *StateStore) Get(contextID, id string) (*Snapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, snapshot := range store.snapshots[contextID] {
		if snapshot.ID == id {
			return snapshot, nil
		}
	}
	return nil, fmt.Errorf("unknown state %q in context %q", id, contextID)
}

// List returns the snapshots of a context, newest first.
func (store *StateStore) List(contextID string) []*Snapshot {
	store.mu.Lock()
	defer store.mu.Unlock()
	list := make([]*Snapshot, 0, len(store.snapshots[contextID]))
	list = append(list, store.snapshots[contextID]...)
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.After(list[j].CreatedAt) })
	return list
}

// NewSnapshotID returns a fresh context-scoped snapshot identifier.
func NewSnapshotID() string {
	buffer := make([]byte, 9)
	if _, err := rand.Read(buffer); err != nil {
		panic(fmt.Sprintf("generate snapshot id: %v", err))
	}
	return "state_" + base64.RawURLEncoding.EncodeToString(buffer)
}
