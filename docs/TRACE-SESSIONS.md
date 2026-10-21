# Continuous trace sessions

Status: **delivered — execution trace, per-occurrence read/write capture with
native range filtering, bounded event store with explicit loss, durable session
manifests with restart recovery, and ROM-hash-bound symbol resolution**. This
document records what a session can and cannot observe, how each stream is
bounded, and which native limitations remain.

## Purpose

`cpu_trace_capture` answers "what ran during this one window". A trace
**session** answers "what has the machine been doing while I was away": it keeps
capturing across a long run, accumulates events in the server process, and lets
the caller query or export them later without pausing the emulator.

A session carries two independent streams:

| Stream | Record | Produced by | Filtering |
| --- | --- | --- | --- |
| execution trace | one line per executed instruction (PC, opcode text, args, comment, cycle, emulated time) | `Processor::RecordTrace` → segmented engine trace files | none natively: the engine cannot filter trace output |
| per-access log | one line per observed read or write (sequence, cycle, direction, address, value, previous value when captured, width, PC, optional same-instant registers) | `Processor::CheckMemoryAccessRecord` → segmented access files | **native**: up to 16 inclusive ranges are evaluated in the access path, so out-of-range accesses cost one comparison and are never written |

## What the emulator actually exposes

| Capability | Where it comes from | Non-pausing? | Granularity |
| --- | --- | --- | --- |
| Executed instruction | `Processor::RecordTrace` → on-disk trace file | yes, per-opcode write on the CPU worker | one line per instruction |
| Read/write observation | `Processor::CheckMemoryAccessPre` | yes | watchpoint evaluation, plus an optional per-access record |
| Per-access record | `Processor::CheckMemoryAccessRecord` behind `std::atomic<bool>` | yes | one record per observed access, written on the engine's commit boundary |
| Same-instant registers | the CPU core (`M68000`/`Z80` `BuildMemoryAccessRegisters`) | yes | 18 (M68K) or 20 (Z80) values captured in the access hook |
| Watchpoint hit counter | `IWatchpoint::GetHitCounter` with `SetBreakEvent(false)` | yes | aggregate count per range, sampled at status/drain |
| In-memory trace ring | `IProcessor::GetTraceLog` | — | **unusable**: unpacking the marshaled `std::vector<TraceLogEntry>` crashes this plugin (see [TRACE-CRASH-INVESTIGATION.md](TRACE-CRASH-INVESTIGATION.md)) |

Consequences that shape the API:

1. Execution events are full-fidelity *inside a capture window*, but the engine
   cannot filter them, so every executed instruction inside the window is
   written. Untraced windows are unavoidable at realistic CPU speeds.
2. Access records are per occurrence: a value, PC, width, direction, and cycle
   belong to that access and are never inferred. A range matches any byte
   touched by an access, not only its starting address. For example, a word
   access at `0xFFFB48` overlaps the monitored GotFlag byte at `0xFFFB49`.
   With `access_capture: "ranges"`, volume is bounded by watched traffic rather
   than by CPU speed.
3. The **previous value of a write** is reported only when the engine captured
   it. This fork does not perform a pre-write transparent read, so
   `previous_known` is `false` and the field is absent rather than guessed.
   Every response states this in `limitations`.

## Capture modes

- `mode: "sampled"` (default) — both writers are armed for `window_ms` (default
  100 ms) at the start of every `interval_ms` (default 10 000 ms) and disabled
  in between; the two streams share the same window boundaries. Measured on Kid
  Chameleon, a 100 ms M68K window with disassembly enabled writes about 1.3 MB
  (~13 MB/s of traced time), so the default 1 % duty cycle costs roughly
  8 MB per minute; size `max_total_bytes` (default 128 MiB) and
  `max_duration_ms` (default 10 min) from that ratio.
- `mode: "continuous"` — the writer stays armed and only the segment file
  rotates every `segment_ms` (default 250 ms). Every instruction is recorded, at
  the cost of the engine's per-opcode disassembly and a sustained write stream.
  Use it for short, focused sessions; at ~7.6 MHz a 68K emits millions of lines
  per second.

Segments are plain engine trace files (execution) and per-access log files
(`access-NNNNNN.log`, contract in
[`MemoryAccessLog.h`](../vendor/exodus/ExodusSDK/Processor/MemoryAccessLog.h)).

## Volume and bounds are surfaced before capture

`trace_session_start` returns a `volume` object carrying every limit in force
(`max_duration_ms`, `max_total_bytes`, `max_segments`, `max_events`,
`access_max_bytes`), the estimated bytes for the configured duration and duty
cycle, the measured bytes/second the estimate is derived from, and whether
access capture is on. A ten-minute, 128 MiB audit is a deliberate choice, never a
surprise at stop time. `trace_session_status` repeats the object with the live
configuration.

## Native session lifecycle

`trace_session_start` → the plugin creates
`%TEMP%\exodus-mcp\trace-sessions\<pid>-<tick>\segment-NNNNNN.log` (execution)
and `access-NNNNNN.log` (per-access), arms the trace writer, configures the
native access ranges, and starts a monitor thread that owns the arm/seal state
machine:

- seals a segment by disabling the writer, waiting one commit interval (`8 ms`)
  so the engine flushes its pending entries, and closing the file;
- rotates by pointing the engine at the next segment path (the engine's own
  debug mutex serializes the close/open against trace commits);
- seals and rotates the access stream on the same boundaries, so both streams
  share one time window;
- enforces `max_segments` (default 128, applied per stream), `max_total_bytes`
  (default 128 MiB) for the execution stream, and `access_max_bytes` (default
  64 MiB) for access records, deleting the oldest sealed segment and counting
  the eviction;
- auto-stops at `max_duration_ms` (default 10 minutes) or when the traced
  processor disappears, so a session can never outlive the configured bounds,
  even if the MCP server stops polling.

`trace_session_drain` returns the oldest not-yet-drained sealed segment of the
selected `stream` (`trace` default, `access`) in chunks (default 1 MiB, max
8 MiB) with a persistent per-stream cursor. `trace_session_stop` disables both
writers, restores the processor's prior trace flags, deletes the session's
watchpoints and (by default) its segment files.

## Server-side event store

`internal/tracing` owns a single session per server process:

- **Bounded event ring.** `max_events` (default 100 000, cap 500 000) events of
  both kinds; the oldest is evicted and counted in `loss.dropped_events`.
- **Bounded address histogram.** At most 131 072 distinct addresses; beyond that
  executions are counted in `loss.dropped_address_counts`.
- **Bounded watch samples.** At most 8 192 samples;
  `loss.dropped_watch_samples`.
- **Monotonic access sequence.** The engine numbers every access record for the
  lifetime of its process. A hole in that sequence is a proven missing record:
  it is counted in `loss.access_sequence_gaps` with a bounded sample of
  `expected..observed` ranges, and it makes `loss.complete` false.
- **Per-stream loss.** `loss.access_malformed_lines`,
  `evicted_access_segments`, `evicted_access_bytes`, and
  `evicted_unread_access_segments` are reported separately from the execution
  trace counters, so a caller can tell which stream lost data.
- **Explicit loss object.** Every response carries `loss` with `complete: false`
  plus the reason list when anything was lost, and the native notes that explain
  it.
- **Retention across sessions.** Starting a new session retires the previous one
  and reports what it discarded (`retired_session`).

Filters apply **after** capture. The response's `filters` object always states
`applied_after_capture: true`, so an out-of-range instruction is never mistaken
for an instruction that was not executed, and it explains the volume
implication: execution filtering still paid the engine's write and drain cost,
while access filtering happened natively and cost nothing outside the ranges.

### Effective-value filtering

`value_equals`, `value_min`, `value_max`, `previous_equals`, `direction`,
`pc_start`/`pc_end`, and `sequence_min`/`sequence_max` select which retained
records are returned or exported. They are **effective-value filters**: they
never drop a raw record from the store, and the response reports the retained
raw count unchanged (`filters.effective_value_filters_keep_raw_events: true`).

## Durable manifests and restart recovery

Each session writes `manifest.json` under
`<temp>/exodus-mcp/trace-sessions/<session-id>/`, atomically (write + rename),
on start, status, events, and stop. A manifest records the configuration, the
limits that were in force, the cartridge SHA-256 the session was bound to, the
target generation at start, per-stream parse counters, the complete loss object,
total counts, the last access sequence, and every artifact produced from the
session (plus the event file that can be reloaded).

`trace_session_recover` lists those manifests and can load one:

- with a recorded event file, the raw events are reloaded (bounded by
  `max_events`) into a **stopped**, read-only session view;
- without one, the manifest restores counters, limits, and loss only, and says
  so;
- `install: true` makes the recovered view the queryable session, but only when
  no live session is active; a live session is never replaced by a recovered
  one;
- the recovered view reports `rom_bound: false` when the loaded cartridge hash
  differs from the manifest's, and symbol resolution stays suppressed.

What recovery cannot do is equally explicit: records evicted from the native
segments or the server ring are gone, and the manifest reports them as loss
instead of implying completeness.

## Symbol resolution is ROM-hash-bound

`symbols_set` stamps every symbol with the SHA-256 of the cartridge that was
loaded when it was written. Resolution (disassembly annotation, backtraces, and
access-event PCs) only applies symbols whose binding matches the loaded
cartridge; a mismatch suppresses resolution and reports
`symbols.reason: "rom_hash_mismatch"` instead of labelling unrelated code.
Symbols recorded with no readable cartridge are explicitly unbound and reported
as such. Access events always expose the raw `pc` as authoritative.

## Lifecycle edges

- **Server restart.** Manifests survive; the in-memory store does not. The
  native session keeps writing until its own bounds stop it.
- **ROM load or any module swap** stops a live session first.
- **Second start.** The emulator has one trace channel per processor, so
  `trace_session_start` replaces an active session and reports
  `native.replaced_session_id`.
- **Context scoping.** A session belongs to the analysis context that started
  it; `trace_session_events` and `trace_session_stop` reject a different context
  with `context_mismatch`.

## Tools

| Tool | Kind | Purpose |
| --- | --- | --- |
| `trace_session_start` | mutation | Arm a session with `cpu`, `mode`, window/interval/segment/duration/disk caps, `max_events`, optional read/write counters, `access_capture` (`off`/`ranges`/`all`), `access_include_registers`, `access_max_bytes`, and `start_guard`; returns the volume contract. |
| `trace_session_status` | read | Drain both streams into the store (unless `collect: false`) and report configuration, limits, native counters, segment tables, access stream counters, watch deltas, totals, and loss. |
| `trace_session_events` | read | Drain, then filter by kind, direction, address/PC/cycle/sequence range, and effective value; bounded inline events, per-address histogram, optional JSONL artifact, and ROM-bound symbol resolution. |
| `trace_session_stop` | mutation | Final drain, disable both writers, restore trace flags, delete watchpoints and segment files, report final totals and loss; exports JSONL by default. |
| `trace_session_recover` | read | List or load durable manifests from this or a previous server process and install a stopped view. |

`start_guard: "quiet"` stops the system for the configuration calls only and
restores it immediately (`setup_pause` reports it). The default `"none"` arms
capture on the running CPU, which the fork's atomic flags and the mutex-guarded
file paths make safe.

## Response contract

- Execution events: `kind: "execute"`, `address`/`address_hex`,
  `address_space`, `byte_order`, `cycle`, engine timestamp, `mnemonic`,
  `operands`, `comment`, `segment_index`.
- Access events: `kind: "read" | "write"`, `sequence`, `direction`,
  `address`/`address_hex`, `width_bits`, `value`/`value_hex` with
  `value_state` (`read` or `written`), `previous_known` (and `previous` when
  known), `pc`/`pc_hex`, `cycle`, `byte_order`, and an optional `registers`
  map labelled in the processor's documented order.
- Aggregate watch samples: `kind: "read" | "write" | "read_write"`,
  `aggregation: "range-sample"`, `hits`, `delta`, and the sample time.
- JSONL export: `trace-session-event/1` for execution events,
  `trace-session-access/1` for access events, produced with artifact provenance
  (`artifact-provenance/2`, kind `trace-session-jsonl`, address space, byte
  order, target generation, ROM identity, capture id, and the
  `capture_consistency` object).
- `session.capture_consistency.state` is `live_windowed`: capture never paused
  the CPU for the capture itself.

## Validation

- `internal/tracing` unit tests cover the native trace format (including
  malformed and truncated lines, CRLF, comments, Z80 address space), the
  per-access contract (direction, width, boundary addresses, previous-value
  availability, register naming and order, malformed and partial records), the
  bounded ring with loss accounting, access sequence gaps, effective-value
  filters, JSONL rendering, manifest round trip and recovery, and registry
  replacement.
- `native-plugin/tests/memory_access_log_test.cpp` compiles the producer header
  with the host compiler and validates the encoding rules the server parses
  (`scripts/native-test.sh`, wired into `scripts/test.sh`). It proves the
  contract, not the CPU cores.
- `internal/mcp` tool tests cover the full start → status → events → stop
  lifecycle, access capture and drain, effective filters, symbol suppression,
  manifest recovery, drain budgeting, watch encoding, artifact export and
  provenance, and the debug event history's duplicate/gap semantics.
- Live validation exercises the native streams: `live-smoke.sh --full` starts a
  session with `access_capture: "ranges"`, asserts the native access stream is
  reported, checks that per-access writes accumulate with no sequence gaps, and
  confirms trace-flag restoration on stop.

## Remaining native gaps

1. **Pre-write (old) values.** The write hook runs before the bus write and the
   processor exposes no side-effect-free pre-read at that point, so
   `previous_known` is `false`. A follow-up can capture it in the M68000/Z80
   write paths behind an opt-in flag using the cores' existing
   `TransparentReadMemory` helpers, with the width and address-error cases
   handled explicitly.
2. **Native trace filtering.** Execution trace output still cannot be filtered;
   only access records are range-filtered natively.
3. **Per-access frame token.** Access records carry cycle and emulated time; the
   VDP frame token is a session/drain-level observation, not a per-record field.
