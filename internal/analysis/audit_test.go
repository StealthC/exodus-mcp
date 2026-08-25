package analysis

import (
	"testing"
	"time"
)

func gen(value uint64) *uint64 { return &value }

func TestAuditLogBoundedAndNewestFirst(t *testing.T) {
	log := NewAuditLog()
	for index := 0; index < maxAuditEntries+10; index++ {
		log.Record(AuditEntry{
			Tool:      "memory_write",
			ContextID: "ctx_a",
			Outcome:   OutcomeOK,
			Detail:    map[string]any{"index": index},
		})
	}
	entries, _ := log.Query(AuditFilter{})
	if len(entries) != maxAuditEntries {
		t.Fatalf("expected %d retained entries, got %d", maxAuditEntries, len(entries))
	}
	if entries[0].Detail["index"] != maxAuditEntries+9 {
		t.Fatalf("newest entry must come first, got %v", entries[0].Detail)
	}
	if entries[0].OperationID != maxAuditEntries+10 {
		t.Fatalf("operation ids must be monotonic across eviction, got %d", entries[0].OperationID)
	}
}

func TestAuditLogQueryFilters(t *testing.T) {
	log := NewAuditLog()
	log.Record(AuditEntry{Tool: "frame_advance", ContextID: "ctx_a", Outcome: OutcomeOK, GenerationBefore: gen(1), GenerationAfter: gen(2)})
	log.Record(AuditEntry{Tool: "memory_write", ContextID: "ctx_b", ControlID: "ctl_1", Outcome: OutcomeOK, GenerationBefore: gen(2), GenerationAfter: gen(3)})
	log.Record(AuditEntry{Tool: "memory_write", ContextID: "ctx_a", Outcome: OutcomeConflict})
	log.Record(AuditEntry{Tool: "rom_load", ContextID: "ctx_a", Outcome: OutcomeOK, GenerationBefore: gen(3), GenerationAfter: gen(4)})

	if entries, _ := log.Query(AuditFilter{ContextID: "ctx_b"}); len(entries) != 1 || entries[0].Tool != "memory_write" {
		t.Fatalf("context filter: %v", entries)
	}
	if entries, _ := log.Query(AuditFilter{Tool: "memory_write"}); len(entries) != 2 {
		t.Fatalf("tool filter: %v", entries)
	}
	if entries, _ := log.Query(AuditFilter{ControlID: "ctl_1"}); len(entries) != 1 {
		t.Fatalf("control filter: %v", entries)
	}
	if entries, _ := log.Query(AuditFilter{GenerationMin: 2, GenerationMax: 2}); len(entries) != 2 {
		t.Fatalf("generation range filter: %v", entries)
	}
	// Conflict entries carry no generations and must not match a range.
	if entries, _ := log.Query(AuditFilter{GenerationMin: 1}); len(entries) != 3 {
		t.Fatalf("generation min filter: %v", entries)
	}
	until := time.Now().UTC().Add(-time.Minute)
	if entries, _ := log.Query(AuditFilter{Until: until}); len(entries) != 0 {
		t.Fatalf("until filter: %v", entries)
	}
}

func TestAuditLogWindowMetadata(t *testing.T) {
	log := NewAuditLog()
	_, window := log.Query(AuditFilter{})
	if window.OldestOperationID != 0 || window.NewestOperationID != 0 {
		t.Fatalf("empty log window must be zero: %+v", window)
	}
	log.Record(AuditEntry{Tool: "a", Outcome: OutcomeOK, GenerationBefore: gen(1), GenerationAfter: gen(2)})
	log.Record(AuditEntry{Tool: "b", Outcome: OutcomeOK, GenerationBefore: gen(4), GenerationAfter: gen(5)})
	_, window = log.Query(AuditFilter{})
	if window.OldestOperationID != 1 || window.NewestOperationID != 2 {
		t.Fatalf("operation id window wrong: %+v", window)
	}
	if window.GenerationMin != 1 || window.GenerationMax != 5 {
		t.Fatalf("generation window wrong: %+v", window)
	}
	if window.OldestTimestamp.IsZero() || window.NewestTimestamp.IsZero() {
		t.Fatal("timestamp window must be populated")
	}
	if !window.NewestTimestamp.After(window.OldestTimestamp) && !window.NewestTimestamp.Equal(window.OldestTimestamp) {
		t.Fatal("newest timestamp must not precede oldest")
	}
}
