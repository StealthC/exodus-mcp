package tracing

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// accessLine builds one contract line in the fork's memory access log format.
func accessLine(sequence, cycle uint64, direction, location, value, previous, width, pc, registers string) string {
	fields := []string{
		itoa(sequence), itoa(cycle), direction, location, value, previous, width, pc, registers,
	}
	return strings.Join(fields, "\t") + "\n"
}

func itoa(value uint64) string {
	if value == 0 {
		return "0"
	}
	digits := ""
	for value > 0 {
		digits = string(rune('0'+value%10)) + digits
		value /= 10
	}
	return digits
}

func TestParseAccessSegmentDirectionsAndWidths(t *testing.T) {
	segment := accessLine(1, 100, "R", "ff0000", "12", "-", "8", "ff0100", "-") +
		accessLine(2, 104, "W", "ff0002", "beef", "-", "16", "ff0102", "-") +
		accessLine(3, 108, "W", "ff0004", "deadbeef", "-", "32", "ff0104", "-")

	events, stats, carry := ParseAccessSegment([]byte(segment), "m68k", "trs_test", 1)
	if len(carry) != 0 {
		t.Fatalf("unexpected carry: %q", carry)
	}
	if stats.Malformed != 0 || stats.Events != 3 {
		t.Fatalf("stats wrong: %+v", stats)
	}
	if events[0].Kind != KindRead || events[0].Direction != DirectionRead {
		t.Fatalf("read event wrong: %+v", events[0])
	}
	if events[0].Value != 0x12 || events[0].ValueState != "read" {
		t.Fatalf("read value wrong: %+v", events[0])
	}
	if events[1].Kind != KindWrite || events[1].WidthBits != 16 || events[1].Value != 0xbeef {
		t.Fatalf("word write wrong: %+v", events[1])
	}
	if events[1].ValueState != "written" {
		t.Fatalf("write value semantics wrong: %+v", events[1])
	}
	if events[2].WidthBits != 32 || events[2].Value != 0xdeadbeef {
		t.Fatalf("long write wrong: %+v", events[2])
	}
	if events[0].PreviousKnown || events[1].PreviousKnown {
		t.Fatalf("previous must not be claimed when the engine did not capture it")
	}
	if events[0].AddressSpace != "m68k-bus" || events[0].ByteOrder != "big-endian" {
		t.Fatalf("address metadata wrong: %+v", events[0])
	}
	if events[0].Sequence != 1 || events[2].Sequence != 3 || events[2].PC != 0xff0104 {
		t.Fatalf("sequence/pc wrong: %+v", events[2])
	}
}

func TestParseAccessSegmentRegistersAndPrevious(t *testing.T) {
	registers := strings.Join([]string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f", "10", "2700", "ff0100"}, ",")
	segment := accessLine(9, 512, "W", "ff0010", "42", "0", "8", "ff0100", registers)
	events, stats, _ := ParseAccessSegment([]byte(segment), "m68k", "trs_test", 2)
	if stats.Events != 1 {
		t.Fatalf("expected one event: %+v", stats)
	}
	event := events[0]
	if !event.PreviousKnown || event.Previous != 0 {
		t.Fatalf("previous value should be captured: %+v", event)
	}
	if len(event.Registers) != 18 {
		t.Fatalf("expected 18 registers, got %d", len(event.Registers))
	}
	if event.Registers[0].Name != "d0" || event.Registers[0].Value != 1 {
		t.Fatalf("register naming wrong: %+v", event.Registers[0])
	}
	if event.Registers[15].Name != "a7" || event.Registers[16].Name != "sr" || event.Registers[17].Name != "pc" {
		t.Fatalf("register tail wrong: %+v", event.Registers[15:])
	}
	if event.Registers[17].Value != 0xff0100 {
		t.Fatalf("pc register wrong: %+v", event.Registers[17])
	}
}

func TestParseAccessSegmentZ80Naming(t *testing.T) {
	registers := "1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,10,11,12,13,14"
	segment := accessLine(1, 7, "R", "c000", "ff", "-", "8", "0100", registers)
	events, _, _ := ParseAccessSegment([]byte(segment), "z80", "trs_test", 1)
	if len(events) != 1 {
		t.Fatalf("expected one event")
	}
	if events[0].AddressSpace != "z80-bus" || events[0].ByteOrder != "little-endian" {
		t.Fatalf("z80 metadata wrong: %+v", events[0])
	}
	if events[0].Registers[0].Name != "a" || events[0].Registers[8].Name != "a_" || events[0].Registers[19].Name != "pc" {
		t.Fatalf("z80 register naming wrong: %+v", events[0].Registers)
	}
}

func TestParseAccessSegmentBoundariesAndMalformed(t *testing.T) {
	// A partial final line must be returned as carry, never parsed.
	segment := accessLine(1, 1, "R", "1000", "1", "-", "8", "1000", "-") + "2\t2\tW\t1002"
	events, stats, carry := ParseAccessSegment([]byte(segment), "m68k", "trs_test", 1)
	if len(events) != 1 || string(carry) != "2\t2\tW\t1002" {
		t.Fatalf("carry handling wrong: events=%d carry=%q", len(events), carry)
	}
	if stats.Malformed != 0 {
		t.Fatalf("a partial line is not malformed: %+v", stats)
	}

	// Invalid direction, width, and field count are malformed, not crashes.
	bad := []string{
		"1\t1\tX\t1000\t1\t-\t8\t1000\t-\n",
		"1\t1\tR\t1000\t1\t-\t24\t1000\t-\n",
		"1\t1\tR\t1000\t1\t-\t8\t1000\n",
		"1\t1\tR\tzz\t1\t-\t8\t1000\t-\n",
		"notanumber\t1\tR\t1000\t1\t-\t8\t1000\t-\n",
	}
	for _, line := range bad {
		events, stats, _ := ParseAccessSegment([]byte(line), "m68k", "trs_test", 1)
		if len(events) != 0 || stats.Malformed != 1 {
			t.Fatalf("line %q should be malformed: events=%d stats=%+v", line, len(events), stats)
		}
	}

	// A byte access at the bus boundary parses like any other.
	events, _, _ = ParseAccessSegment([]byte(accessLine(5, 9, "W", "ffffff", "0", "-", "8", "ffffff", "-")), "m68k", "trs", 1)
	if len(events) != 1 || events[0].Address != 0xffffff {
		t.Fatalf("boundary address wrong: %+v", events)
	}
}

func TestSessionAccessSequenceGapsAndRawRetention(t *testing.T) {
	session := NewSession("trs_gap", "ctx", "m68k", "m68k-bus", Config{CPU: "m68k"})
	session.AddAccessEvents([]Event{
		{Kind: KindWrite, Direction: DirectionWrite, Sequence: 10, Address: 0x1000, Value: 1, ValueKnown: true, WidthBits: 8},
		{Kind: KindWrite, Direction: DirectionWrite, Sequence: 13, Address: 0x1000, Value: 2, ValueKnown: true, WidthBits: 8},
		{Kind: KindRead, Direction: DirectionRead, Sequence: 14, Address: 0x1002, Value: 9, ValueKnown: true, WidthBits: 16},
	})
	loss := session.LossView()
	if loss.AccessSequenceGaps != 2 {
		t.Fatalf("expected two missing sequence numbers, got %d", loss.AccessSequenceGaps)
	}
	if len(loss.AccessSequenceGapSamples) != 1 || loss.AccessSequenceGapSamples[0] != "11..12" {
		t.Fatalf("gap sample wrong: %+v", loss.AccessSequenceGapSamples)
	}
	if session.Retained() != 3 {
		t.Fatalf("raw events must all be retained, got %d", session.Retained())
	}
	if session.LastAccessSequence() != 14 {
		t.Fatalf("last sequence wrong: %d", session.LastAccessSequence())
	}

	// An effective-value filter selects a subset but never drops raw events.
	filtered := session.Select(Filter{Kind: "any", HasValueEquals: true, ValueEquals: 2})
	if len(filtered) != 1 || filtered[0].Sequence != 13 {
		t.Fatalf("value filter wrong: %+v", filtered)
	}
	if session.Retained() != 3 {
		t.Fatalf("value filtering must not evict raw events, retained=%d", session.Retained())
	}
	if direction := session.Select(Filter{Kind: "any", Direction: DirectionRead}); len(direction) != 1 || direction[0].Sequence != 14 {
		t.Fatalf("direction filter wrong: %+v", direction)
	}
	rangeFiltered := session.Select(Filter{Kind: "any", HasValueRange: true, ValueMin: 2, ValueMax: 9})
	if len(rangeFiltered) != 2 {
		t.Fatalf("value range filter wrong: %+v", rangeFiltered)
	}
	sequenceFiltered := session.Select(Filter{Kind: "any", HasSequence: true, SequenceMin: 13, SequenceMax: 14})
	if len(sequenceFiltered) != 2 {
		t.Fatalf("sequence filter wrong: %+v", sequenceFiltered)
	}
	pcFiltered := session.Select(Filter{Kind: "any", HasPC: true, PCStart: 0x1000, PCEnd: 0x1001})
	if len(pcFiltered) != 0 {
		t.Fatalf("pc filter should not match events without a PC: %+v", pcFiltered)
	}
}

func TestManifestRoundTripAndRecovery(t *testing.T) {
	directory := t.TempDir()
	session := NewSession("trs_manifest", "ctx_default", "m68k", "m68k-bus", Config{
		CPU: "m68k", Mode: "sampled", WindowMs: 100, IntervalMs: 1000, MaxEvents: 1000,
		AccessCapture: "ranges", AccessIncludeRegisters: true, AccessMaxBytes: 1 << 20,
	})
	session.MarkStarted(7, `C:\roms\kid.bin`)
	session.MarkROMIdentity("abc123")
	session.AddAccessEvents([]Event{
		{Kind: KindWrite, Direction: DirectionWrite, Sequence: 1, Address: 0xff0000, Value: 0x42, ValueKnown: true, WidthBits: 8, PC: 0xff0100},
		{Kind: KindWrite, Direction: DirectionWrite, Sequence: 3, Address: 0xff0000, Value: 0x43, ValueKnown: true, WidthBits: 8, PC: 0xff0100},
	})
	manifest := NewManifest(session, `C:\roms\kid.bin`, "abc123", map[string]any{"active": true})
	path, err := manifest.Save(directory)
	if err != nil {
		t.Fatalf("save manifest: %v", err)
	}
	if !strings.HasSuffix(path, filepath.Join("trs_manifest", "manifest.json")) {
		t.Fatalf("manifest path wrong: %s", path)
	}
	loaded, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	if loaded.SessionID != "trs_manifest" || loaded.ROMSHA256 != "abc123" || loaded.Config.AccessCapture != "ranges" {
		t.Fatalf("manifest fields wrong: %+v", loaded)
	}
	if loaded.Loss.AccessSequenceGaps != 1 || loaded.Retained != 2 {
		t.Fatalf("manifest loss/retained wrong: %+v", loaded)
	}
	if loaded.Limits.MaxEvents != 1000 {
		t.Fatalf("limits must record the capacity in force: %+v", loaded.Limits)
	}

	// Events file recovery: JSONL written from the retained events reloads.
	events := session.Select(Filter{Kind: "any"})
	encoded, err := MarshalJSONL(events)
	if err != nil {
		t.Fatalf("marshal JSONL: %v", err)
	}
	eventsPath := filepath.Join(directory, "events.jsonl")
	if err := os.WriteFile(eventsPath, encoded, 0o644); err != nil {
		t.Fatalf("write events: %v", err)
	}
	// The manifest is re-saved after an export so the recorded event file is
	// discoverable by a restarted server.
	loaded.EventsFile = eventsPath
	if _, err := loaded.Save(directory); err != nil {
		t.Fatalf("re-save manifest: %v", err)
	}
	loadedEvents, err := ReadEventsFile(eventsPath, 0)
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	if len(loadedEvents) != 2 {
		t.Fatalf("expected two recovered events, got %d", len(loadedEvents))
	}
	restored := RestoreSession(loaded, loadedEvents)
	if restored.ID != "trs_manifest" || !restored.Stopped {
		t.Fatalf("restored session wrong: %+v", restored.ID)
	}
	if restored.Retained() != 2 {
		t.Fatalf("restored events wrong: %d", restored.Retained())
	}
	if restored.LossView().AccessSequenceGaps != 1 {
		t.Fatalf("restored loss must survive: %+v", restored.LossView())
	}
	if restored.ROMSHA256() != "abc123" {
		t.Fatalf("restored ROM binding wrong: %q", restored.ROMSHA256())
	}

	entries, err := ListManifests(directory)
	if err != nil || len(entries) != 1 || entries[0].SessionID != "trs_manifest" {
		t.Fatalf("manifest listing wrong: %+v err=%v", entries, err)
	}
	if !entries[0].Recoverable {
		t.Fatalf("manifest with an events file should report recoverable: %+v", entries[0])
	}
}
