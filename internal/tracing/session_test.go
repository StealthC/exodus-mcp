package tracing

import (
	"encoding/json"
	"strings"
	"testing"
)

// nativeTraceLine renders one engine trace line exactly as
// Processor::RecordTraceInternal writes it: PC hex, opcode, arguments,
// optional ";comment", cycle, and emulated time, tab separated.
func nativeTraceLine(address, opcode, args, comment string, cycle uint64, seconds string) string {
	return strings.Join([]string{address, opcode, args, comment, formatUint(cycle), seconds}, "\t")
}

func formatUint(value uint64) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func TestParseSegmentDecodesNativeTraceFormat(t *testing.T) {
	segment := strings.Join([]string{
		nativeTraceLine("00FF0000", "MOVE.W", "#$0,D0", "", 100, "0.0001"),
		nativeTraceLine("00FF0004", "BSR", "$FF0010", ";subroutine", 116, "0.0002"),
		"",
	}, "\n") + "\n"
	events, stats := ParseSegment([]byte(segment), "m68k", "trs_test", 7)
	if stats.Segments != 1 || stats.Events != 2 || stats.Malformed != 0 || stats.Truncated != 0 {
		t.Fatalf("unexpected parse stats: %+v", stats)
	}
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	first := events[0]
	if first.Address != 0x00FF0000 || first.AddressHex != "0xFF0000" || first.AddressSpace != "m68k-bus" {
		t.Fatalf("address decoding wrong: %+v", first)
	}
	if first.Mnemonic != "MOVE.W" || first.Operands != "#$0,D0" || first.Cycle != 100 {
		t.Fatalf("instruction decoding wrong: %+v", first)
	}
	if first.EmulatedNanoseconds != 0.0001 || first.EmulatedSeconds != 0.0001/1e9 {
		t.Fatalf("emulated time not parsed: %v/%v", first.EmulatedNanoseconds, first.EmulatedSeconds)
	}
	if first.SegmentIndex != 7 || first.SessionID != "trs_test" || first.Schema != EventSchema {
		t.Fatalf("provenance fields missing: %+v", first)
	}
	if events[1].Comment != "subroutine" {
		t.Fatalf("comment not decoded: %q", events[1].Comment)
	}
}

func TestParseSegmentUsesZ80Space(t *testing.T) {
	segment := nativeTraceLine("0000F123", "LD", "A,$5", "", 12, "0.1") + "\n"
	events, _ := ParseSegment([]byte(segment), "z80", "trs_z80", 1)
	if len(events) != 1 || events[0].AddressSpace != "z80-bus" {
		t.Fatalf("z80 space not applied: %+v", events)
	}
}

func TestParseSegmentCountsMalformedAndTruncated(t *testing.T) {
	segment := "00FF0000\tMOVE.W\t#0,D0\t\t100\t0.1\n" +
		"this-line-is-not-a-trace-entry\n" +
		"00FF0008\tNOP\r\n" +
		"00FF000C\tRTS"
	_, stats := ParseSegment([]byte(segment), "m68k", "trs", 0)
	if stats.Malformed != 2 {
		t.Fatalf("malformed = %d, want 2", stats.Malformed)
	}
	if stats.Truncated != 1 {
		t.Fatalf("truncated = %d, want 1", stats.Truncated)
	}
}

func TestSessionDropsOldestEventsAndAccountsLoss(t *testing.T) {
	session := NewSession("trs", "ctx", "m68k", "m68k-bus", Config{MaxEvents: 3})
	session.AddEvents([]Event{{Address: 1}, {Address: 2}, {Address: 3}})
	session.AddEvents([]Event{{Address: 4}})
	if session.Retained() != 3 {
		t.Fatalf("retained = %d, want 3", session.Retained())
	}
	if session.LossView().DroppedEvents != 1 {
		t.Fatalf("dropped = %d, want 1", session.LossView().DroppedEvents)
	}
	events := session.Select(Filter{Kind: KindExecute})
	if len(events) != 3 || events[0].Address != 2 || events[2].Address != 4 {
		t.Fatalf("ring order wrong: %+v", events)
	}
	if events[0].Kind != KindExecute || events[0].AddressHex != "0x000002" {
		t.Fatalf("defaults not applied: %+v", events[0])
	}
}

func TestSessionHistogramIsDeterministicAndBounded(t *testing.T) {
	session := NewSession("trs", "ctx", "m68k", "m68k-bus", Config{MaxEvents: 100})
	session.AddEvents([]Event{{Address: 0x100}, {Address: 0x200}, {Address: 0x100}})
	counts, distinct := session.AddressHistogram(10)
	if distinct != 2 || len(counts) != 2 {
		t.Fatalf("distinct = %d, counts = %d", distinct, len(counts))
	}
	if counts[0].Address != 0x100 || counts[0].Count != 2 {
		t.Fatalf("histogram order/count wrong: %+v", counts)
	}
	limited, _ := session.AddressHistogram(1)
	if len(limited) != 1 {
		t.Fatalf("limit not applied: %+v", limited)
	}
}

func TestSessionFilterByKindAddressAndCycle(t *testing.T) {
	session := NewSession("trs", "ctx", "m68k", "m68k-bus", Config{MaxEvents: 10})
	session.AddEvents([]Event{
		{Address: 0x100, Cycle: 10},
		{Address: 0x200, Cycle: 20},
		{Address: 0x200, Kind: KindWrite, Cycle: 30},
	})
	inRange := session.Select(Filter{Kind: "any", HasRange: true, Start: 0x100, End: 0x200})
	if len(inRange) != 1 || inRange[0].Address != 0x100 {
		t.Fatalf("range filter wrong: %+v", inRange)
	}
	writes := session.Select(Filter{Kind: KindWrite})
	if len(writes) != 1 || writes[0].Address != 0x200 {
		t.Fatalf("kind filter wrong: %+v", writes)
	}
	cycles := session.Select(Filter{Kind: "any", HasCycle: true, CycleMin: 15, CycleMax: 25})
	if len(cycles) != 1 || cycles[0].Cycle != 20 {
		t.Fatalf("cycle filter wrong: %+v", cycles)
	}
	limited := session.Select(Filter{Kind: "any", Limit: 1})
	if len(limited) != 1 {
		t.Fatalf("limit not applied: %+v", limited)
	}
}

func TestSessionWatchSamplesBecomeAggregateEvents(t *testing.T) {
	session := NewSession("trs", "ctx", "m68k", "m68k-bus", Config{MaxEvents: 10})
	session.AddWatchSample(WatchSample{Address: 0xFF0000, Length: 4, Access: "write", Hits: 9, Delta: 4})
	session.AddWatchSample(WatchSample{Address: 0xFF0008, Length: 2, Access: "read", Hits: 3, Delta: 0})
	events := session.Select(Filter{Kind: KindWrite})
	if len(events) != 1 {
		t.Fatalf("write aggregate events = %d, want 1", len(events))
	}
	if events[0].Bucket != "range-sample" || events[0].Hits != 4 {
		t.Fatalf("aggregate event wrong: %+v", events[0])
	}
	if totals := session.Totals(); totals[KindWrite] != 1 || totals[KindRead] != 0 {
		t.Fatalf("totals = %v", totals)
	}
	if samples := session.WatchSamples(); len(samples) != 2 {
		t.Fatalf("watch samples = %d, want 2", len(samples))
	}
}

func TestWriteJSONLLineCount(t *testing.T) {
	events := []Event{{Address: 1}, {Address: 2}}
	encoded, err := MarshalJSONL(events)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(encoded)), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(lines))
	}
	var decoded Event
	if err := json.Unmarshal([]byte(lines[0]), &decoded); err != nil {
		t.Fatalf("decode line: %v", err)
	}
	if decoded.AddressHex != "0x000001" || decoded.Schema != EventSchema {
		t.Fatalf("defaults missing: %+v", decoded)
	}
}

func TestSessionCarriesPartialLine(t *testing.T) {
	session := NewSession("trs", "ctx", "m68k", "m68k-bus", Config{MaxEvents: 10})
	segment, carry := session.Carry()
	if segment != 0 || len(carry) != 0 {
		t.Fatalf("fresh session carry = %d/%q", segment, carry)
	}
	session.SetCarry(3, []byte("00FF00"))
	segment, carry = session.Carry()
	if segment != 3 || string(carry) != "00FF00" {
		t.Fatalf("carry = %d/%q", segment, carry)
	}
}

func TestRegistryReplacesCurrentSession(t *testing.T) {
	registry := NewRegistry()
	first := NewSession("trs_1", "ctx", "m68k", "m68k-bus", Config{})
	if previous := registry.Replace(first); previous != nil {
		t.Fatalf("first replace returned %v", previous)
	}
	second := NewSession("trs_2", "ctx", "m68k", "m68k-bus", Config{})
	if previous := registry.Replace(second); previous != first {
		t.Fatalf("second replace returned %v", previous)
	}
	if registry.Current() != second {
		t.Fatal("current session not installed")
	}
	registry.Clear()
	if registry.Current() != nil {
		t.Fatal("clear did not forget the session")
	}
}
