package analysis

import (
	"sync"
	"time"
)

// Audit outcomes for target operations.
const (
	OutcomeOK        = "ok"
	OutcomeFailed    = "failed"       // provable native or local failure, no mutation
	OutcomePartial   = "partial"      // native operation changed target but proof failed
	OutcomeConflict  = "conflict"     // generation precondition mismatch, no native action
	OutcomeHeld      = "control_held" // control-lock precondition mismatch, no native action
	OutcomeAmbiguous = "ambiguous"    // transport failure; mutation outcome unknown
	OutcomeLockEvent = "lock_event"   // control lock lifecycle, not a target operation
	OutcomeObserved  = "observed"     // passive observation (run_state_change), no target action
)

// AuditFailure captures structured failure data for one attempted operation.
type AuditFailure struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// AuditEntry is one record of the bounded global target audit stream. It
// covers every target mutation attempt (successful or not), precondition
// conflicts, and control-lock lifecycle events.
type AuditEntry struct {
	OperationID      uint64         `json:"operation_id"`
	Timestamp        time.Time      `json:"timestamp"`
	Tool             string         `json:"tool"`
	ContextID        string         `json:"context_id,omitempty"`
	ControlID        string         `json:"control_id,omitempty"`
	GenerationBefore *uint64        `json:"target_generation_before,omitempty"`
	GenerationAfter  *uint64        `json:"target_generation_after,omitempty"`
	Outcome          string         `json:"outcome"`
	Detail           map[string]any `json:"detail,omitempty"` // normalized arguments, secrets redacted
	Result           map[string]any `json:"result,omitempty"` // bounded result summary
	Failure          *AuditFailure  `json:"failure,omitempty"`
	ROMBefore        string         `json:"rom_before,omitempty"`
	ROMAfter         string         `json:"rom_after,omitempty"`
	ResourceIDs      []string       `json:"resource_ids,omitempty"`
}

// AuditWindow describes the retained portion of the stream so a truncated
// response is never mistaken for complete reproducibility.
type AuditWindow struct {
	OldestOperationID uint64
	NewestOperationID uint64
	OldestTimestamp   time.Time
	NewestTimestamp   time.Time
	GenerationMin     uint64
	GenerationMax     uint64
}

// maxAuditEntries bounds the retained stream; older entries drop oldest-first.
const maxAuditEntries = 2000

// AuditLog is the bounded, append-only global target audit stream. Entries
// beyond the cap drop oldest-first. Querying is linear over the retained
// window, which stays cheap at the cap.
type AuditLog struct {
	mu      sync.Mutex
	entries []AuditEntry
	nextID  uint64
}

// NewAuditLog creates an empty audit stream.
func NewAuditLog() *AuditLog {
	return &AuditLog{nextID: 1}
}

// Record appends one entry, stamps its monotonic operation id and UTC
// timestamp, and returns the operation id.
func (log *AuditLog) Record(entry AuditEntry) uint64 {
	log.mu.Lock()
	defer log.mu.Unlock()
	entry.OperationID = log.nextID
	log.nextID++
	entry.Timestamp = time.Now().UTC()
	log.entries = append(log.entries, entry)
	if len(log.entries) > maxAuditEntries {
		drop := len(log.entries) - maxAuditEntries
		kept := make([]AuditEntry, 0, maxAuditEntries)
		log.entries = append(kept, log.entries[drop:]...)
	}
	return entry.OperationID
}

// AuditFilter narrows an AuditLog query. Zero-value filters are open.
type AuditFilter struct {
	ContextID     string
	Tool          string
	ControlID     string
	GenerationMin uint64
	GenerationMax uint64
	Since         time.Time
	Until         time.Time
}

// Query returns the matching entries, newest first, plus the retained window
// of the whole stream. The returned slice is a snapshot; entries are bounded
// by maxAuditEntries.
func (log *AuditLog) Query(filter AuditFilter) ([]AuditEntry, AuditWindow) {
	log.mu.Lock()
	defer log.mu.Unlock()
	window := log.windowLocked()
	out := make([]AuditEntry, 0)
	for index := len(log.entries) - 1; index >= 0; index-- {
		entry := log.entries[index]
		if !entry.matches(filter) {
			continue
		}
		out = append(out, entry)
	}
	return out, window
}

// windowLocked computes the retained window; callers must hold the log lock.
func (log *AuditLog) windowLocked() AuditWindow {
	var window AuditWindow
	if len(log.entries) == 0 {
		return window
	}
	window.OldestOperationID = log.entries[0].OperationID
	window.NewestOperationID = log.entries[len(log.entries)-1].OperationID
	window.OldestTimestamp = log.entries[0].Timestamp
	window.NewestTimestamp = log.entries[len(log.entries)-1].Timestamp
	for _, entry := range log.entries {
		if entry.GenerationBefore != nil {
			window.GenerationMin = minWindow(window.GenerationMin, *entry.GenerationBefore)
			window.GenerationMax = maxWindow(window.GenerationMax, *entry.GenerationBefore)
		}
		if entry.GenerationAfter != nil {
			window.GenerationMin = minWindow(window.GenerationMin, *entry.GenerationAfter)
			window.GenerationMax = maxWindow(window.GenerationMax, *entry.GenerationAfter)
		}
	}
	return window
}

func minWindow(current, candidate uint64) uint64 {
	if current == 0 || candidate < current {
		return candidate
	}
	return current
}

func maxWindow(current, candidate uint64) uint64 {
	if candidate > current {
		return candidate
	}
	return current
}

func (entry AuditEntry) matches(filter AuditFilter) bool {
	if filter.ContextID != "" && entry.ContextID != filter.ContextID {
		return false
	}
	if filter.Tool != "" && entry.Tool != filter.Tool {
		return false
	}
	if filter.ControlID != "" && entry.ControlID != filter.ControlID {
		return false
	}
	if !filter.Since.IsZero() && entry.Timestamp.Before(filter.Since) {
		return false
	}
	if !filter.Until.IsZero() && entry.Timestamp.After(filter.Until) {
		return false
	}
	if filter.GenerationMin == 0 && filter.GenerationMax == 0 {
		return true
	}
	if entry.GenerationBefore != nil && generationInRange(*entry.GenerationBefore, filter.GenerationMin, filter.GenerationMax) {
		return true
	}
	if entry.GenerationAfter != nil && generationInRange(*entry.GenerationAfter, filter.GenerationMin, filter.GenerationMax) {
		return true
	}
	return false
}

func generationInRange(value, min, max uint64) bool {
	if min != 0 && value < min {
		return false
	}
	if max != 0 && value > max {
		return false
	}
	return true
}
