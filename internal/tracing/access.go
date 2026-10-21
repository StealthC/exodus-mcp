package tracing

import (
	"fmt"
	"strconv"
	"strings"
)

// AccessSchema is the versioned schema of one per-occurrence access event in
// the JSONL export. Execution events keep EventSchema; access events are
// distinguished by kind (read/write) and carry the record fields below.
const AccessSchema = "trace-session-access/1"

// Access directions. An access event's direction is proven by the engine's
// access path, never inferred from the watch configuration.
const (
	DirectionRead  = "read"
	DirectionWrite = "write"
)

// Register is one entry of the same-instant register snapshot captured with an
// access. Names follow the processor's documented order; see registerNames.
type Register struct {
	Name  string `json:"name"`
	Value uint64 `json:"value"`
	Hex   string `json:"hex"`
}

// m68kRegisterNames is the order produced by M68000::BuildMemoryAccessRegisters:
// D0-D7, A0-A7, SR, PC.
var m68kRegisterNames = []string{
	"d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7",
	"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
	"sr", "pc",
}

// z80RegisterNames is the order produced by Z80::BuildMemoryAccessRegisters:
// A, F, B, C, D, E, H, L, then the alternate register pair bytes A', F', B',
// C', D', E', H', L', then IX, IY, SP, PC. The alternate pairs are split into
// bytes because the access hook writes a fixed-width integer array.
var z80RegisterNames = []string{
	"a", "f", "b", "c", "d", "e", "h", "l",
	"a_", "f_", "b_", "c_", "d_", "e_", "h_", "l_",
	"ix", "iy", "sp", "pc",
}

// registerNames returns the register order for one CPU, or nil when the CPU is
// unknown (the snapshot is then reported by index only).
func registerNames(cpu string) []string {
	switch cpu {
	case "m68k":
		return m68kRegisterNames
	case "z80":
		return z80RegisterNames
	default:
		return nil
	}
}

// pendingAccessCount reports the number of fields of one access line and is
// used to reject records from a future format instead of misreading them.
const accessFieldCount = 9

// ParseAccessSegment parses one drained chunk of the engine's per-access log.
//
// The line contract is documented in the fork's MemoryAccessLog.h:
//
//	sequence \t cycle \t R|W \t location \t value \t previous \t width_bits \t pc \t registers
//
// Every value except sequence, cycle and width_bits is hexadecimal without a
// prefix; "previous" and "registers" use "-" when unavailable. Returned events
// are ordered as written. Lines that do not match the contract are counted in
// ParseStats.Malformed and never silently dropped. A trailing partial line is
// returned as carry so the caller can complete it with the next chunk.
func ParseAccessSegment(data []byte, cpu, sessionID string, segmentIndex uint32) ([]Event, ParseStats, []byte) {
	stats := ParseStats{Segments: 1, Bytes: uint64(len(data))}
	events := make([]Event, 0, 256)
	addressSpace := "m68k-bus"
	byteOrder := "big-endian"
	if cpu == "z80" {
		addressSpace = "z80-bus"
		byteOrder = "little-endian"
	}
	names := registerNames(cpu)
	text := string(data)
	lines := strings.Split(text, "\n")
	var carry []byte
	for index, raw := range lines {
		line := strings.TrimSuffix(raw, "\r")
		if index == len(lines)-1 && !strings.HasSuffix(text, "\n") {
			// The chunk ended mid-line: hand the tail back instead of parsing
			// (or counting) a partial record.
			carry = append([]byte{}, []byte(line)...)
			break
		}
		if line == "" {
			if index != len(lines)-1 {
				stats.EmptyLines++
			}
			continue
		}
		stats.Lines++
		event, ok := parseAccessLine(line, cpu, names)
		if !ok {
			stats.Malformed++
			continue
		}
		event.Schema = AccessSchema
		event.SessionID = sessionID
		event.CPU = cpu
		event.AddressSpace = addressSpace
		event.ByteOrder = byteOrder
		event.AddressHex = CanonicalAddressHex(event.Address)
		event.PCHex = CanonicalAddressHex(event.PC)
		event.SegmentIndex = segmentIndex
		events = append(events, event)
		stats.Events++
	}
	return events, stats, carry
}

// parseAccessLine decodes one tab-separated access record.
func parseAccessLine(line, cpu string, names []string) (Event, bool) {
	fields := strings.Split(line, "\t")
	if len(fields) != accessFieldCount {
		return Event{}, false
	}
	sequence, err := strconv.ParseUint(strings.TrimSpace(fields[0]), 10, 64)
	if err != nil {
		return Event{}, false
	}
	cycle, err := strconv.ParseUint(strings.TrimSpace(fields[1]), 10, 64)
	if err != nil {
		return Event{}, false
	}
	direction := strings.TrimSpace(fields[2])
	if direction != "R" && direction != "W" {
		return Event{}, false
	}
	location, ok := parseHexUint(fields[3])
	if !ok {
		return Event{}, false
	}
	value, ok := parseHexUint(fields[4])
	if !ok {
		return Event{}, false
	}
	previousText := strings.TrimSpace(fields[5])
	previous, previousKnown := uint64(0), false
	if previousText != "" && previousText != "-" {
		previous, ok = parseHexUint(previousText)
		if !ok {
			return Event{}, false
		}
		previousKnown = true
	}
	widthBits, err := strconv.ParseUint(strings.TrimSpace(fields[6]), 10, 32)
	if err != nil {
		return Event{}, false
	}
	switch widthBits {
	case 8, 16, 32:
	default:
		return Event{}, false
	}
	pc, ok := parseHexUint(fields[7])
	if !ok {
		return Event{}, false
	}
	registers := parseRegisterSnapshot(strings.TrimSpace(fields[8]), names)
	kind := KindRead
	if direction == "W" {
		kind = KindWrite
	}
	event := Event{
		Kind:          kind,
		Sequence:      sequence,
		Direction:     kind,
		Address:       location,
		Value:         value,
		ValueKnown:    true,
		Previous:      previous,
		PreviousKnown: previousKnown,
		WidthBits:     uint32(widthBits),
		PC:            pc,
		Cycle:         cycle,
		Registers:     registers,
		// The semantics of the value field depend on the direction and are
		// stated explicitly so no reader mistakes a written value for a
		// previous one.
		ValueState: "read",
	}
	if kind == KindWrite {
		event.ValueState = "written"
	}
	return event, true
}

// parseRegisterSnapshot decodes the comma-separated register field.
func parseRegisterSnapshot(field string, names []string) []Register {
	if field == "" || field == "-" {
		return nil
	}
	parts := strings.Split(field, ",")
	registers := make([]Register, 0, len(parts))
	for index, part := range parts {
		value, ok := parseHexUint(part)
		if !ok {
			return nil
		}
		name := fmt.Sprintf("r%d", index)
		if names != nil && index < len(names) {
			name = names[index]
		}
		registers = append(registers, Register{Name: name, Value: value, Hex: canonicalHexValue(value)})
	}
	return registers
}

// parseHexUint parses a bare hexadecimal value.
func parseHexUint(text string) (uint64, bool) {
	text = strings.TrimSpace(text)
	text = strings.TrimPrefix(strings.TrimPrefix(text, "0x"), "0X")
	if text == "" {
		return 0, false
	}
	value, err := strconv.ParseUint(text, 16, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

// canonicalHexValue renders a register or value in canonical hexadecimal form.
func canonicalHexValue(value uint64) string {
	return fmt.Sprintf("0x%X", value)
}
