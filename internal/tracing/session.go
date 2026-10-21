// Package tracing implements the server-side event store of continuous trace
// sessions. The native plugin streams segmented trace files from the emulated
// processor; this package parses those segments into bounded per-execution
// events, aggregates per-address counts, tracks explicit loss, and renders
// the JSONL export consumed by artifact-first responses.
//
// The store is deliberately bounded in every dimension (events, distinct
// addresses, watch samples) and reports what it dropped instead of growing
// without limit or silently discarding data.
package tracing

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// EventSchema is the versioned per-event schema of the JSONL export.
const EventSchema = "trace-session-event/1"

// Event kinds. Execution events arrive per executed instruction from the
// native trace file. Read/write events are aggregate counter samples: the
// emulator exposes watchpoint hit counters only, never per-access records
// (see docs/TRACE-SESSIONS.md for the native limitation).
const (
	KindExecute = "execute"
	KindRead    = "read"
	KindWrite   = "write"
	// KindReadWrite labels an aggregate sample whose watched range counts
	// reads and writes together (`access: "any"`): the counter cannot separate
	// the two directions, so neither direction is claimed.
	KindReadWrite = "read_write"
)

// Event is one recorded session event.
type Event struct {
	Schema       string `json:"schema_version"`
	Kind         string `json:"kind"`
	SessionID    string `json:"session_id"`
	CPU          string `json:"cpu"`
	AddressSpace string `json:"address_space"`
	ByteOrder    string `json:"byte_order,omitempty"`
	Address      uint64 `json:"address"`
	AddressHex   string `json:"address_hex"`
	Cycle        uint64 `json:"cycle"`
	// EmulatedNanoseconds is the engine's own per-instruction timestamp:
	// Processor::CalculateExecutionTime accumulates cycles * 1e9 / clock, so
	// the trace file unit is nanoseconds. EmulatedSeconds is the derived
	// seconds value; the nanosecond field stays authoritative.
	EmulatedNanoseconds float64 `json:"emulated_nanoseconds,omitempty"`
	EmulatedSeconds     float64 `json:"emulated_seconds,omitempty"`
	Mnemonic            string  `json:"mnemonic,omitempty"`
	Operands            string  `json:"operands,omitempty"`
	Comment             string  `json:"comment,omitempty"`
	SegmentIndex        uint32  `json:"segment_index"`

	// Bucket reports the aggregate resolution of non-execute events: the
	// event counts hits inside one watched range between two samples, it is
	// not a single observed access.
	Bucket string `json:"aggregation,omitempty"`
	Hits   uint64 `json:"hits,omitempty"`

	// Per-occurrence access fields. Sequence is the engine's process-monotonic
	// record number: it is the only field a caller should use to order or
	// de-duplicate access events, and holes in it mean records were lost.
	Sequence uint64 `json:"sequence,omitempty"`
	// Direction is the proven access direction ("read" or "write"), equal to
	// Kind for access events.
	Direction string `json:"direction,omitempty"`
	WidthBits uint32 `json:"width_bits,omitempty"`
	// Value is the transferred value; ValueState states what it means
	// ("read" for a value returned by the bus, "written" for a value stored).
	Value      uint64 `json:"value,omitempty"`
	ValueKnown bool   `json:"value_known,omitempty"`
	ValueState string `json:"value_state,omitempty"`
	// Previous is the value the location held before a write when the engine
	// captured it; PreviousKnown false means it was not captured, never zero.
	Previous      uint64 `json:"previous,omitempty"`
	PreviousKnown bool   `json:"previous_known,omitempty"`
	// PC is the instruction that issued the access.
	PC    uint64 `json:"pc,omitempty"`
	PCHex string `json:"pc_hex,omitempty"`
	// Registers is the same-instant register snapshot, in the order documented
	// by the processor (see registerNames).
	Registers []Register `json:"registers,omitempty"`
}

// Watch is one configured read/write observation range. The native session
// arms a non-breaking watchpoint for it, so the range never pauses the CPU.
type Watch struct {
	Address uint64 `json:"address"`
	Length  uint64 `json:"length"`
	Access  string `json:"access"`
}

// Config is the immutable configuration of one trace session.
type Config struct {
	CPU           string  `json:"cpu"`
	Mode          string  `json:"mode"`
	Disassemble   bool    `json:"disassemble"`
	WindowMs      uint64  `json:"window_ms"`
	IntervalMs    uint64  `json:"interval_ms"`
	SegmentMs     uint64  `json:"segment_ms"`
	MaxDurationMs uint64  `json:"max_duration_ms"`
	MaxTotalBytes uint64  `json:"max_total_bytes"`
	MaxSegments   uint64  `json:"max_segments"`
	MaxEvents     uint64  `json:"max_events"`
	Watches       []Watch `json:"watches,omitempty"`

	// Per-occurrence read/write capture. AccessCapture is "off" (aggregate
	// counters only), "ranges" (native-filtered per-access records inside the
	// watch ranges), or "all" (every access).
	AccessCapture          string `json:"access_capture,omitempty"`
	AccessIncludeRegisters bool   `json:"access_include_registers,omitempty"`
	AccessMaxBytes         uint64 `json:"access_max_bytes,omitempty"`
}

// WatchSample is one aggregate reading of a configured watch range.
type WatchSample struct {
	SampledAt    time.Time `json:"sampled_at"`
	WatchpointID uint64    `json:"watchpoint_id,omitempty"`
	Address      uint64    `json:"address"`
	Length       uint64    `json:"length"`
	Access       string    `json:"access"`
	Hits         uint64    `json:"hits"`
	Delta        uint64    `json:"delta"`
	Lost         bool      `json:"lost,omitempty"`
}

// ParseStats accounts for every byte-level outcome of segment parsing.
type ParseStats struct {
	Segments   uint64 `json:"segments"`
	Bytes      uint64 `json:"bytes"`
	Lines      uint64 `json:"lines"`
	Events     uint64 `json:"events"`
	Malformed  uint64 `json:"malformed_lines"`
	Truncated  uint64 `json:"truncated_lines"`
	EmptyLines uint64 `json:"empty_lines"`
}

// Loss is the explicit, machine-readable record of everything this session
// could not keep.
type Loss struct {
	// DroppedEvents counts events evicted from the bounded event store.
	DroppedEvents uint64 `json:"dropped_events"`
	// DroppedAddressCounts counts executions whose address could not be
	// added to the bounded per-address histogram.
	DroppedAddressCounts uint64 `json:"dropped_address_counts"`
	// DroppedWatchSamples counts watch samples evicted from the bounded
	// sample history.
	DroppedWatchSamples uint64 `json:"dropped_watch_samples"`
	// MalformedLines and TruncatedLines count unparsable or partial trace
	// lines that never became events.
	MalformedLines  uint64 `json:"malformed_lines"`
	TruncatedLines  uint64 `json:"truncated_lines"`
	EvictedSegments uint64 `json:"evicted_segments"`
	EvictedBytes    uint64 `json:"evicted_bytes"`
	// EvictedUnreadSegments counts segments the retention cap removed before
	// this server drained them: those events are unrecoverable.
	EvictedUnreadSegments uint64 `json:"evicted_unread_segments"`
	// Per-access stream accounting. It is kept separate from the execution
	// trace accounting so a caller can tell which stream lost data.
	AccessMalformedLines        uint64 `json:"access_malformed_lines"`
	AccessTruncatedLines        uint64 `json:"access_truncated_lines"`
	EvictedAccessSegments       uint64 `json:"evicted_access_segments"`
	EvictedAccessBytes          uint64 `json:"evicted_access_bytes"`
	EvictedUnreadAccessSegments uint64 `json:"evicted_unread_access_segments"`
	// AccessSequenceGaps counts holes in the engine's monotonic per-access
	// sequence: every hole is a proven missing access record.
	AccessSequenceGaps uint64 `json:"access_sequence_gaps"`
	// AccessSequenceGapSamples lists a bounded sample of the holes as
	// "expected..observed" pairs, so a reader can see where records are gone.
	AccessSequenceGapSamples []string `json:"access_sequence_gap_samples,omitempty"`
	// Notes lists free-form loss conditions reported by the native side.
	Notes []string `json:"notes,omitempty"`
}

// Filter selects retained events for one query or export.
type Filter struct {
	Kind     string
	HasRange bool
	Start    uint64
	End      uint64
	HasCycle bool
	CycleMin uint64
	CycleMax uint64
	// Direction restricts access events to "read" or "write".
	Direction string
	// Value constraints are effective-value filters: they are applied to
	// retained raw events at query time and never cause a raw event to be
	// dropped from the store.
	HasValueEquals bool
	ValueEquals    uint64
	HasValueRange  bool
	ValueMin       uint64
	ValueMax       uint64
	HasPrevious    bool
	PreviousEquals uint64
	// HasPC restricts to accesses issued by an instruction inside [PCStart,PCEnd).
	HasPC       bool
	PCStart     uint64
	PCEnd       uint64
	HasSequence bool
	SequenceMin uint64
	SequenceMax uint64
	Limit       int
}

// AddressCount is one entry of the per-address execution histogram.
type AddressCount struct {
	Address      uint64 `json:"address"`
	AddressHex   string `json:"address_hex"`
	AddressSpace string `json:"address_space"`
	Count        uint64 `json:"count"`
}

// Session is one continuous trace session: its configuration, retained
// events, aggregates, and loss accounting. All methods are safe for
// concurrent use.
type Session struct {
	mu sync.Mutex

	ID           string    `json:"id"`
	ContextID    string    `json:"context_id"`
	CPU          string    `json:"cpu"`
	AddressSpace string    `json:"address_space"`
	Config       Config    `json:"config"`
	StartedAt    time.Time `json:"started_at"`
	StoppedAt    time.Time `json:"stopped_at,omitempty"`
	Stopped      bool      `json:"stopped"`

	// ring is the bounded event store; head points at the oldest retained
	// event and count is the number of retained events.
	ring   []Event
	head   int
	count  int
	capMax int

	totals    map[string]uint64
	addresses map[uint64]uint64
	addrCap   int
	samples   []WatchSample
	sampleCap int

	stats ParseStats
	loss  Loss

	// accessStats and the sequence bookkeeping cover the per-access stream,
	// which is parsed independently of the execution trace.
	accessStats ParseStats
	// lastAccessSequence is the highest engine sequence observed; a new record
	// that skips ahead proves the records in between were lost.
	lastAccessSequence uint64
	// artifacts records every artifact produced from this session so a saved
	// manifest can point at them after a server restart.
	artifacts []string

	// carry holds the unterminated tail of the last drained trace chunk so a
	// line split across two drain calls is completed instead of being lost or
	// counted as malformed. It resets when the segment index changes.
	carry        []byte
	carrySegment uint32
	// accessCarry is the same idea for the access stream, whose records are
	// also line delimited but drained on their own cursor.
	accessCarry        []byte
	accessCarrySegment uint32

	// generationAtStart records the target revision observed when the
	// session started; the export reports both ends of the span.
	generationAtStart uint64
	roAtStart         string
	// romSHA256AtStart binds the session to the cartridge it captured. Symbol
	// resolution is suppressed when the loaded cartridge no longer matches.
	romSHA256AtStart string
}

// NewSession creates an empty session with bounded storage.
func NewSession(id, contextID, cpu, addressSpace string, config Config) *Session {
	maxEvents := int(config.MaxEvents)
	if maxEvents <= 0 {
		maxEvents = 100000
	}
	return &Session{
		ID:           id,
		ContextID:    contextID,
		CPU:          cpu,
		AddressSpace: addressSpace,
		Config:       config,
		StartedAt:    time.Now().UTC(),
		ring:         make([]Event, maxEvents),
		capMax:       maxEvents,
		totals:       map[string]uint64{},
		addresses:    map[uint64]uint64{},
		addrCap:      maxAddresses,
		sampleCap:    maxWatchSamples,
	}
}

const (
	maxAddresses    = 131072
	maxWatchSamples = 8192
)

// Carry returns the segment index and the partial trace line that spans the
// previous drain chunk boundary.
func (session *Session) Carry() (uint32, []byte) {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.carrySegment, append([]byte{}, session.carry...)
}

// SetCarry stores the partial trace line that spans a drain chunk boundary.
func (session *Session) SetCarry(segment uint32, data []byte) {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.carrySegment = segment
	session.carry = append([]byte{}, data...)
}

// MarkStarted records the target identity observed when the session started.
func (session *Session) MarkStarted(generation uint64, romPath string) {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.generationAtStart = generation
	session.roAtStart = romPath
}

// MarkROMIdentity binds the session to the cartridge hash observed at start.
func (session *Session) MarkROMIdentity(romSHA256 string) {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.romSHA256AtStart = romSHA256
}

// ROMSHA256 returns the cartridge hash the session was bound to, or "".
func (session *Session) ROMSHA256() string {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.romSHA256AtStart
}

// GenerationAtStart returns the target revision observed at session start.
func (session *Session) GenerationAtStart() uint64 {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.generationAtStart
}

// ROMPathAtStart returns the cartridge path observed at session start.
func (session *Session) ROMPathAtStart() string {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.roAtStart
}

// AddEvents appends parsed events to the bounded store. Events beyond the
// capacity evict the oldest retained events, which are counted in Loss.
func (session *Session) AddEvents(events []Event) {
	if len(events) == 0 {
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	session.addEventsLocked(events)
}

// addEventsLocked appends events; the caller holds session.mu.
func (session *Session) addEventsLocked(events []Event) {
	for _, event := range events {
		event = session.normalizeEvent(event)
		if session.count == session.capMax {
			session.ring[session.head] = event
			session.head = (session.head + 1) % session.capMax
			session.loss.DroppedEvents++
		} else {
			session.ring[(session.head+session.count)%session.capMax] = event
			session.count++
		}
		session.totals[event.Kind]++
		if event.Kind == KindExecute {
			session.recordAddressLocked(event.Address)
		}
	}
}

// AddAccessEvents appends parsed per-access records, tracking the engine's
// monotonic sequence so a hole in it is reported as an explicit loss instead of
// being invisible.
func (session *Session) AddAccessEvents(events []Event) {
	if len(events) == 0 {
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	for _, event := range events {
		if event.Sequence != 0 && session.lastAccessSequence != 0 && event.Sequence > session.lastAccessSequence+1 {
			gap := event.Sequence - session.lastAccessSequence - 1
			session.loss.AccessSequenceGaps += gap
			if len(session.loss.AccessSequenceGapSamples) < maxSequenceGapSamples {
				session.loss.AccessSequenceGapSamples = append(session.loss.AccessSequenceGapSamples,
					fmt.Sprintf("%d..%d", session.lastAccessSequence+1, event.Sequence-1))
			}
		}
		if event.Sequence > session.lastAccessSequence {
			session.lastAccessSequence = event.Sequence
		}
		// Raw access records are always retained (subject only to the store's
		// capacity); no effective-value filter ever drops them here.
		session.addEventsLocked([]Event{event})
	}
}

const maxSequenceGapSamples = 32

// normalizeEvent applies the session defaults to one event.
func (session *Session) normalizeEvent(event Event) Event {
	if event.Kind == "" {
		event.Kind = KindExecute
	}
	if event.Schema == "" {
		event.Schema = EventSchema
	}
	if event.SessionID == "" {
		event.SessionID = session.ID
	}
	if event.CPU == "" {
		event.CPU = session.CPU
	}
	if event.AddressSpace == "" {
		event.AddressSpace = session.AddressSpace
	}
	if event.AddressHex == "" {
		event.AddressHex = CanonicalAddressHex(event.Address)
	}
	if event.ByteOrder == "" {
		event.ByteOrder = byteOrderForCPU(session.CPU)
	}
	return event
}

// byteOrderForCPU states the address-space byte order of one processor.
func byteOrderForCPU(cpu string) string {
	if cpu == "z80" {
		return "little-endian"
	}
	return "big-endian"
}

func (session *Session) recordAddressLocked(address uint64) {
	if _, exists := session.addresses[address]; exists {
		session.addresses[address]++
		return
	}
	if len(session.addresses) >= session.addrCap {
		session.loss.DroppedAddressCounts++
		return
	}
	session.addresses[address] = 1
}

// AddParseStats accumulates segment parsing counters.
func (session *Session) AddParseStats(stats ParseStats) {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.stats.Segments += stats.Segments
	session.stats.Bytes += stats.Bytes
	session.stats.Lines += stats.Lines
	session.stats.Events += stats.Events
	session.stats.Malformed += stats.Malformed
	session.stats.Truncated += stats.Truncated
	session.stats.EmptyLines += stats.EmptyLines
	session.loss.MalformedLines += stats.Malformed
	session.loss.TruncatedLines += stats.Truncated
}

// AddWatchSample records one aggregate watch reading and appends it to the
// bounded sample history.
func (session *Session) AddWatchSample(sample WatchSample) {
	session.mu.Lock()
	defer session.mu.Unlock()
	if len(session.samples) == session.sampleCap {
		copy(session.samples, session.samples[1:])
		session.samples[len(session.samples)-1] = sample
		session.loss.DroppedWatchSamples++
	} else {
		session.samples = append(session.samples, sample)
	}
	kind := KindRead
	switch sample.Access {
	case "write":
		kind = KindWrite
	case "any":
		kind = KindReadWrite
	}
	event := Event{
		Schema:       EventSchema,
		Kind:         kind,
		SessionID:    session.ID,
		CPU:          session.CPU,
		AddressSpace: session.AddressSpace,
		Address:      sample.Address,
		AddressHex:   CanonicalAddressHex(sample.Address),
		Bucket:       "range-sample",
		Hits:         sample.Delta,
	}
	event.Bucket = "range-sample"
	if sample.Delta > 0 {
		session.AddEventsLocked([]Event{event})
	}
}

// AddEventsLocked is AddEvents without re-taking the lock; callers must hold
// session.mu.
func (session *Session) AddEventsLocked(events []Event) {
	session.addEventsLocked(events)
}

// AddAccessParseStats accumulates parse counters of the per-access stream.
func (session *Session) AddAccessParseStats(stats ParseStats) {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.accessStats.Segments += stats.Segments
	session.accessStats.Bytes += stats.Bytes
	session.accessStats.Lines += stats.Lines
	session.accessStats.Events += stats.Events
	session.accessStats.Malformed += stats.Malformed
	session.accessStats.Truncated += stats.Truncated
	session.accessStats.EmptyLines += stats.EmptyLines
	session.loss.AccessMalformedLines += stats.Malformed
	session.loss.AccessTruncatedLines += stats.Truncated
}

// AccessStats returns the accumulated per-access parse counters.
func (session *Session) AccessStats() ParseStats {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.accessStats
}

// AddAccessLoss merges native per-access stream loss counters.
func (session *Session) AddAccessLoss(evictedSegments, evictedBytes, evictedUnread uint64) {
	session.mu.Lock()
	defer session.mu.Unlock()
	if evictedSegments > session.loss.EvictedAccessSegments {
		session.loss.EvictedAccessSegments = evictedSegments
	}
	if evictedBytes > session.loss.EvictedAccessBytes {
		session.loss.EvictedAccessBytes = evictedBytes
	}
	if evictedUnread > session.loss.EvictedUnreadAccessSegments {
		session.loss.EvictedUnreadAccessSegments = evictedUnread
	}
}

// AccessCarry returns the partial access record that spans a drain chunk
// boundary.
func (session *Session) AccessCarry() (uint32, []byte) {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.accessCarrySegment, append([]byte{}, session.accessCarry...)
}

// SetAccessCarry stores the partial access record that spans a drain chunk
// boundary.
func (session *Session) SetAccessCarry(segment uint32, data []byte) {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.accessCarrySegment = segment
	session.accessCarry = append([]byte{}, data...)
}

// LastAccessSequence returns the highest engine access sequence observed.
func (session *Session) LastAccessSequence() uint64 {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.lastAccessSequence
}

// AddArtifact records an artifact produced from this session.
func (session *Session) AddArtifact(id string) {
	if id == "" {
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	for _, existing := range session.artifacts {
		if existing == id {
			return
		}
	}
	if len(session.artifacts) >= maxSessionArtifacts {
		session.artifacts = session.artifacts[len(session.artifacts)-maxSessionArtifacts+1:]
	}
	session.artifacts = append(session.artifacts, id)
}

// Artifacts returns the artifact ids produced from this session.
func (session *Session) Artifacts() []string {
	session.mu.Lock()
	defer session.mu.Unlock()
	return append([]string{}, session.artifacts...)
}

const maxSessionArtifacts = 64

// AddLoss merges native-side loss counters reported by the plugin.
func (session *Session) AddLoss(evictedSegments, evictedBytes, evictedUnread uint64, notes []string) {
	session.mu.Lock()
	defer session.mu.Unlock()
	if evictedSegments > session.loss.EvictedSegments {
		session.loss.EvictedSegments = evictedSegments
	}
	if evictedBytes > session.loss.EvictedBytes {
		session.loss.EvictedBytes = evictedBytes
	}
	if evictedUnread > session.loss.EvictedUnreadSegments {
		session.loss.EvictedUnreadSegments = evictedUnread
	}
	for _, note := range notes {
		if note == "" {
			continue
		}
		duplicate := false
		for _, existing := range session.loss.Notes {
			if existing == note {
				duplicate = true
				break
			}
		}
		if !duplicate {
			session.loss.Notes = append(session.loss.Notes, note)
		}
	}
}

// MarkStopped records the session end.
func (session *Session) MarkStopped() {
	session.mu.Lock()
	defer session.mu.Unlock()
	if !session.Stopped {
		session.Stopped = true
		session.StoppedAt = time.Now().UTC()
	}
}

// Retained returns the number of retained events.
func (session *Session) Retained() int {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.count
}

// Totals returns a copy of the per-kind event counters.
func (session *Session) Totals() map[string]uint64 {
	session.mu.Lock()
	defer session.mu.Unlock()
	out := make(map[string]uint64, len(session.totals))
	for key, value := range session.totals {
		out[key] = value
	}
	return out
}

// Stats returns the accumulated parse counters.
func (session *Session) Stats() ParseStats {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.stats
}

// LossView returns a copy of the loss accounting.
func (session *Session) LossView() Loss {
	session.mu.Lock()
	defer session.mu.Unlock()
	copied := session.loss
	copied.Notes = append([]string{}, session.loss.Notes...)
	return copied
}

// WatchSamples returns a copy of the retained watch sample history.
func (session *Session) WatchSamples() []WatchSample {
	session.mu.Lock()
	defer session.mu.Unlock()
	return append([]WatchSample{}, session.samples...)
}

// Select returns the retained events matching the filter, in capture order.
func (session *Session) Select(filter Filter) []Event {
	session.mu.Lock()
	defer session.mu.Unlock()
	out := make([]Event, 0, minInt(session.count, 64))
	for index := 0; index < session.count; index++ {
		event := session.ring[(session.head+index)%session.capMax]
		if !matchesFilter(event, filter) {
			continue
		}
		out = append(out, event)
		if filter.Limit > 0 && len(out) >= filter.Limit {
			break
		}
	}
	return out
}

func matchesFilter(event Event, filter Filter) bool {
	if filter.Kind != "" && filter.Kind != "any" && event.Kind != filter.Kind {
		return false
	}
	if filter.Direction != "" && event.Direction != filter.Direction {
		return false
	}
	if filter.HasRange {
		if event.Address < filter.Start {
			return false
		}
		if event.Address >= filter.End {
			return false
		}
	}
	if filter.HasCycle {
		if event.Cycle < filter.CycleMin || event.Cycle > filter.CycleMax {
			return false
		}
	}
	if filter.HasSequence {
		if event.Sequence < filter.SequenceMin || event.Sequence > filter.SequenceMax {
			return false
		}
	}
	if filter.HasPC {
		if event.PC < filter.PCStart || event.PC >= filter.PCEnd {
			return false
		}
	}
	// Effective-value filters never remove a retained raw event from the store;
	// they only decide whether it is selected for this query.
	if filter.HasValueEquals {
		if !event.ValueKnown || event.Value != filter.ValueEquals {
			return false
		}
	}
	if filter.HasValueRange {
		if !event.ValueKnown || event.Value < filter.ValueMin || event.Value > filter.ValueMax {
			return false
		}
	}
	if filter.HasPrevious {
		if !event.PreviousKnown || event.Previous != filter.PreviousEquals {
			return false
		}
	}
	return true
}

// AddressHistogram returns the top `limit` executed addresses by count.
func (session *Session) AddressHistogram(limit int) ([]AddressCount, uint64) {
	session.mu.Lock()
	defer session.mu.Unlock()
	counts := make([]AddressCount, 0, len(session.addresses))
	for address, count := range session.addresses {
		counts = append(counts, AddressCount{
			Address:      address,
			AddressHex:   CanonicalAddressHex(address),
			AddressSpace: session.AddressSpace,
			Count:        count,
		})
	}
	sort.Slice(counts, func(i, j int) bool {
		if counts[i].Count != counts[j].Count {
			return counts[i].Count > counts[j].Count
		}
		return counts[i].Address < counts[j].Address
	})
	total := uint64(len(counts))
	if limit > 0 && len(counts) > limit {
		counts = counts[:limit]
	}
	return counts, total
}

// DistinctAddresses returns how many distinct addresses the histogram holds.
func (session *Session) DistinctAddresses() int {
	session.mu.Lock()
	defer session.mu.Unlock()
	return len(session.addresses)
}

// WriteJSONL renders events as one JSON object per line, applying the
// schema defaults so an exported line is self-describing.
func WriteJSONL(writer io.Writer, events []Event) (int, error) {
	written := 0
	for _, event := range events {
		if event.Schema == "" {
			event.Schema = EventSchema
		}
		if event.Kind == "" {
			event.Kind = KindExecute
		}
		if event.AddressHex == "" {
			event.AddressHex = CanonicalAddressHex(event.Address)
		}
		encoded, err := json.Marshal(event)
		if err != nil {
			return written, err
		}
		if _, err := writer.Write(append(encoded, '\n')); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

// MarshalJSONL renders events as JSONL bytes.
func MarshalJSONL(events []Event) ([]byte, error) {
	var builder strings.Builder
	if _, err := WriteJSONL(&builder, events); err != nil {
		return nil, err
	}
	return []byte(builder.String()), nil
}

// CanonicalAddressHex renders an address in the canonical response form.
func CanonicalAddressHex(address uint64) string {
	return fmt.Sprintf("0x%06X", address)
}

// ParseSegment parses one native trace segment. The engine writes one ASCII
// line per executed instruction as
//
//	0xADDR \t opcode \t args \t ;comment \t cycle \t time
//
// with an empty comment field when the instruction has no comment. Lines that
// do not match the contract are counted, never silently dropped.
func ParseSegment(data []byte, cpu, sessionID string, segmentIndex uint32) ([]Event, ParseStats) {
	stats := ParseStats{Segments: 1, Bytes: uint64(len(data))}
	events := make([]Event, 0, 256)
	addressSpace := "m68k-bus"
	if cpu == "z80" {
		addressSpace = "z80-bus"
	}
	text := string(data)
	lines := strings.Split(text, "\n")
	for index, raw := range lines {
		line := strings.TrimSuffix(raw, "\r")
		if line == "" {
			if index != len(lines)-1 {
				stats.EmptyLines++
			}
			continue
		}
		if index == len(lines)-1 && !strings.HasSuffix(text, "\n") {
			// A segment is only read after it was sealed, so an unterminated
			// final line means the writer was interrupted mid-entry.
			stats.Truncated++
			continue
		}
		stats.Lines++
		event, ok := parseTraceLine(line)
		if !ok {
			stats.Malformed++
			continue
		}
		event.Schema = EventSchema
		event.Kind = KindExecute
		event.SessionID = sessionID
		event.CPU = cpu
		event.AddressSpace = addressSpace
		event.ByteOrder = byteOrderForCPU(cpu)
		event.AddressHex = CanonicalAddressHex(event.Address)
		event.SegmentIndex = segmentIndex
		events = append(events, event)
		stats.Events++
	}
	return events, stats
}

// parseTraceLine decodes one tab-separated native trace line.
func parseTraceLine(line string) (Event, bool) {
	fields := strings.Split(line, "\t")
	if len(fields) < 6 {
		return Event{}, false
	}
	addressText := strings.TrimSpace(fields[0])
	addressText = strings.TrimPrefix(strings.TrimPrefix(addressText, "0x"), "0X")
	address, err := strconv.ParseUint(addressText, 16, 64)
	if err != nil {
		return Event{}, false
	}
	cycleText := strings.TrimSpace(fields[4])
	cycle, err := strconv.ParseUint(cycleText, 10, 64)
	if err != nil {
		return Event{}, false
	}
	event := Event{
		Address:      address,
		Cycle:        cycle,
		Mnemonic:     strings.TrimSpace(fields[1]),
		Operands:     strings.TrimSpace(fields[2]),
		Comment:      strings.TrimPrefix(strings.TrimSpace(fields[3]), ";"),
		SegmentIndex: 0,
	}
	if timeText := strings.TrimSpace(fields[5]); timeText != "" {
		if nanoseconds, err := strconv.ParseFloat(timeText, 64); err == nil && nanoseconds >= 0 {
			event.EmulatedNanoseconds = nanoseconds
			event.EmulatedSeconds = nanoseconds / 1e9
		}
	}
	return event, true
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
