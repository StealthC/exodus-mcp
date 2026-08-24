package analysis

import (
	"sync"
	"time"
)

// LedgerEntry records one mutating tool call with enough metadata to
// reproduce the action: who (lease), what (tool and echoed arguments), and
// when.
type LedgerEntry struct {
	Timestamp time.Time      `json:"timestamp"`
	Tool      string         `json:"tool"`
	ContextID string         `json:"context_id"`
	LeaseID   string         `json:"lease_id"`
	Detail    map[string]any `json:"detail,omitempty"`
}

const maxLedgerEntriesPerContext = 200

// Ledger is an append-only per-context audit trail of mutations. Entries
// beyond the cap are dropped oldest-first so the log stays bounded.
type Ledger struct {
	mu      sync.Mutex
	entries map[string][]LedgerEntry
}

func newLedger() *Ledger {
	return &Ledger{entries: make(map[string][]LedgerEntry)}
}

// Record appends one mutation entry to a context's trail.
func (ledger *Ledger) Record(entry LedgerEntry) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	list := ledger.entries[entry.ContextID]
	list = append(list, entry)
	if len(list) > maxLedgerEntriesPerContext {
		list = list[len(list)-maxLedgerEntriesPerContext:]
	}
	ledger.entries[entry.ContextID] = list
}

// List returns the mutation trail of a context, newest first.
func (ledger *Ledger) List(contextID string) []LedgerEntry {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	source := ledger.entries[contextID]
	list := make([]LedgerEntry, 0, len(source))
	for i := len(source) - 1; i >= 0; i-- {
		list = append(list, source[i])
	}
	return list
}
