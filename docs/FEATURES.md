# Features

This catalog lists the tools the `exodus-mcp` analysis server exposes,
grouped by capability, and records how far each behavior is verified. Only
open work is tracked in [ROADMAP.md](ROADMAP.md); the
[CHANGELOG.md](../CHANGELOG.md) records the delivery history.

The MCP server currently exposes **94 tools** spanning roadmap phases 0-10:
bridge and context foundations, memory and artifact access, both processors,
VDP graphics, deterministic controlled experimentation, advanced analysis,
evidence annotations, advanced debugging, deterministic replay, workflow
ergonomics, per-occurrence trace sessions with restart recovery, and trace
sessions.

A tool exists in the catalog whether or not anyone has verified it, so every
entry that claims a verified behavior carries one of these markers:

| Marker | Meaning |
| --- | --- |
| **proven** | an automated test in this repository covers it; the test is named here and in [Validation](#validation) |
| **live check** | a check in `scripts/live-smoke.sh` covers it against a running pair; the repository stores no recorded run, so it is only proven for a run of that script at this revision |
| **unvalidated** | implemented, but no test and no smoke check exercises it — treat the behavior as unverified |
| **planned** | not implemented; tracked in ROADMAP.md |

Unavailable native capabilities are stated as unavailable instead of being
described as working. When an entry says something is validated without a
marker, the marker is defined in [Validation](#validation), which maps each
claim to the exact test function or smoke-script check that proves it.

## Cross-cutting behavior

- **Artifact-first output.** Every response is a bounded summary; high-volume
  output (ROM bytes, dumps, traces, screenshots, analysis results) lands in an
  immutable artifact with SHA-256 digest, MIME type, size, direct local URL,
  and MCP resource URI. Artifacts support ETag and HTTP byte-range downloads,
  bounded previews, per-analysis-context scoping, and optional TTL retention.
- **Versioned capture provenance.** Every artifact produced from capture data
  carries an immutable `artifact-provenance/2` envelope (address domain with
  requested/effective addresses in decimal and canonical hex, byte length,
  byte order and raw-byte ordering, owning device, target generation, ROM
  SHA-256 and path, frame token, CPU run state, capture consistency, capture
  time, plus the standardized `capture_consistency` object and — for
  composite captures — a stable `capture_id`). `artifact_get` returns the full
  typed envelope (`include: ["provenance"]`, the default), `artifact_list`
  enumerates every artifact of a context with its `capture_id`, and
  `capture_get` resolves a `capture_id` to its manifest and components;
  artifacts whose producer attached no metadata are reported honestly as
  `provenance_unknown` instead of inventing fields.
  Memory search and diff derive their address domain from the envelope, so a
  dump captured at `0xFF0000` is searched and diffed at `0xFF0000` without
  caller restatement.
- **Byte order and address space metadata.** Every multi-byte value reports
  its byte order and address space. The Mega Drive baseline is M68K
  big-endian, Z80 little-endian, and device-specific for VDP semantics; raw
  bytes preserve address order.
- **Flexible address formats.** Address arguments accept `$`-prefixed
  Motorola hex, `0x` hex, Zilog `h`-suffixed hex, and decimal integers; every
  response echoes the canonical parsed address. Address-bearing tools also
  accept an optional `address_space` selecting either a documented
  space-relative domain or processor bus domain, translating to the target
  native space and rejecting incompatible domains. Responses preserve legacy
  address fields and add `space_address`/`bus_address` (and canonical hex
  forms) wherever a mapping exists, including nested ranges, matches, lines,
  and debug events. Schemas declare addresses as a shared `oneOf` (JSON
  integer or supported string notation), and tool arguments are strictly
  decoded: unknown properties are rejected with `invalid_params` naming the
  full JSON path (`additionalProperties: false` on every object schema).
- **Stable response contract.** Every successful `structuredContent` (and
  legacy `content`) carries `result_type` (the tool name) and
  `schema_version: "1"`. Address-bearing outputs normalize to numeric
  `address` plus canonical uppercase `address_hex`, `address_space`,
  `effective_address`/`effective_address_hex` where translation occurred, and
  `address_width_bits`/`address_mask_hex` where the space is bus-mapped.
- **Optimistic concurrency.** Every response carries the process-local
  `target_generation` observed at response completion; every target mutation
  reports `target_generation_before`/`after` and accepts an optional
  `expected_target_generation` precondition, validated inside the serialized
  scheduler immediately before the native action. A mismatch fails with
  `target_generation_conflict` and no native action, with the current
  generation, ROM identity, and a retry hint.
- **Optional exclusive control lock.** `target_control_acquire`/`renew`/
  `release`/`status` provide a short-lived process-wide exclusive window
  (TTL-capped, capability-gated `control_id`) for workflows that need a
  multi-call atomic span. A held lock rejects foreign mutations with
  `target_control_held` but never blocks reads; expiry releases only the lock.
- **Bounded global audit stream.** Every target mutation, precondition
  conflict, and control-lock lifecycle event lands in `target_audit_log`
  (monotonic operation ids, target generations, ROM identity, context and
  control provenance, structured failures); `context_mutation_log` is a
  per-context projection.
- **Consistent reads only.** Searches and diffs run over snapshot artifacts
  (never a live racy scan); timed-buffer VDP reads briefly pause a running
  system, restore it afterwards, and report that in the response.
- **Honest capture consistency.** Every state-observing tool reports the
  standardized `capture_consistency` object: `live` (sampled while running
  without pausing; possibly internally inconsistent), `paused` (system was
  already stopped), `atomic` (the capture itself paused once and restored),
  `state_restored` (describes a restored snapshot), or
  `composite_non_atomic` (component reads spanned multiple moments). The
  object states whether execution was paused by the tool and resumed
  afterwards, observed initial/final run states, and frame tokens when the
  VDP exposes them. One window yields exactly one object: the response (top
  level and `summary`) and the stored artifact provenance are completed from
  the same object after the guard, the legacy `consistency` label is derived
  from it instead of copied from the plugin payload, and the object is
  stamped in both modes, so an artifact can never describe a different window
  than the response it was returned with
  (`TestPausedCaptureArtifactProvenanceMatchesResponse`,
  `TestPausedCaptureCompositeArtifactsMatchResponse`). Each capture window
  also reports `run_state_restore` with a stable code — `restored`,
  `already_paused`, `resume_skipped_initial_run_state_unknown`,
  `run_state_restore_failed`, or `run_state_restore_unverified` — plus
  `initial_run_state`, `final_run_state`, and `resumed`; a restore is
  verified from the native run-state echo, and a pre-call run state that no
  observation established is never resumed, so a paused target can never be
  started by a capture it did not ask for
  (`TestPausedCaptureUnknownRunStateIsNotResumed`,
  `TestPausedCaptureLeavesPausedTargetPaused`). `memory_snapshot_capture`
  captures one or more named ranges in one pause window (exactly one
  pause/resume cycle, one capture id, one manifest);
  `system_snapshot_capture` provides the cross-domain atomic form: memory
  ranges, CPU registers, VDP status/buffers, and an optional frame share one
  pause window and one `capture_id` in a `system-snapshot/1` manifest, and
  omitted or unavailable components are explicit. Each memory component is
  indexed under its range label (`memory:<name>`) while its provenance carries
  the range's real space id, device, space-relative start, and bus start. `memory_read`,
  `memory_dump`, `m68k_read_memory`, `z80_read_memory`, `vdp_memory_read`,
  `vdp_memory_export`, `frame_capture`, and `vdp_capture` accept an optional
  `capture_mode: "paused"` guard that makes a single sample temporally atomic
  — the default `"live"` never pauses, so timing-sensitive software is never
  silently perturbed. Mixing artifacts from different composite captures is
  rejected by `memory_diff` unless explicitly allowed.
- **Run-state observability.** `emulator_status` reports `pause_source`
  (`mcp` | `ui_or_external` | `breakpoint_or_watchpoint` | `unknown`) and
  `last_run_state_change` (UTC). Externally observed transitions (UI pauses,
  other bridge clients, native stops) land in the audit stream as
  `run_state_change` events with the observed target generation and never
  advance it — the generation advances only on successful MCP mutations.
- **System-specific prefixes.** Tools use clear `m68k_`, `z80_`, and `vdp_`
  prefixes rather than pretending behavior is generic.

## Bridge and platform foundation (Phases 0-1)

- `bridge_status`: plugin version, bridge connectivity, lifecycle, and
  initialization module count over the authenticated named pipe.
- `emulator_status`: loaded modules, running/paused state, device identity,
  and the current cartridge (path, file size, padded mapping size) plus
  run-state observability: `pause_source` (`mcp` after an MCP
  pause/run/step/frame-advance/state-load/rom-load; `ui_or_external` when no
  MCP run-state action explains the state; `breakpoint_or_watchpoint` when the
  plugin reports a native stop reason; `unknown` before any observation) and
  `last_run_state_change` (UTC, or a note that the first observation anchors
  the timestamp). UI/external transitions are audited as `run_state_change`
  events without advancing `target_generation`. The cartridge is reported even
  when it was loaded through the Exodus UI instead of MCP: `rom.path_source`
  distinguishes `mcp_load` (tracked from the bridge `rom_load`) from
  `loaded_module` (recovered from the loaded program module); a UI-loaded
  cartridge reports the file-derived `size_bytes` with `padded_size_bytes: 0`
  (unknown, because only the MCP `rom_load` module creation computes it).
- `target_info`: emulator identity, device summary, and a `target_info.rom`
  summary of the loaded cartridge.
- Analysis contexts: `context_create`, `context_list`, `context_close` with
  an implicit default context and protected close semantics.
- Authenticated local named-pipe bridge with capability-gated plugin access,
  a serialized command queue (single pipe thread, stop-event responsive),
  deadline-based cancellation, clean shutdown, and transient full-buffer
  retry on a 512 KiB outbound pipe buffer.
- `/healthz` endpoint; launcher reserves the HTTP listener before starting
  Exodus and terminates the child if the server exits unexpectedly.

## Memory and artifacts (Phase 1 and Phase 5)

- `memory_spaces_list`: named address spaces with owner device, size, entry
  width, real read/write capabilities, declared byte order, and the processor
  bus mapping — `bus`, `bus_base`, `bus_offset` with `bus_address = bus_base +
  bus_offset + space_relative_address` (RAM `mem-ram` → `0xFF0000`, Z80 RAM
  `mem-z80-ram` → `0xA00000`, ROM → `0x000000`; VDP buffers explain why they
  are not linearly mapped instead of guessing). Capabilities reflect actual
  writability and are authoritative: VDP timed buffers and
  `mem-rom`/`mem-boot-rom` report read-only and `memory_write` enforces exactly
  that, refusing them with `write_not_supported`. Out-of-range
  failures include the valid canonical hex range.
- `memory_read`: bounded inline reads with explicit representation,
  effective-address echo, `system_paused_during_read`, the standardized
  `capture_consistency` object, and decode validation against the declared
  byte order. Optional `capture_mode: "paused"` makes the sample temporally
  atomic (pauses once, restores); the default `"live"` never pauses. The
  response echoes the request next to the effective values:
  `requested_address`/`requested_address_hex`, `requested_address_space` and
  `address_translated` when the caller addressed through another domain, plus
  `requested_length`, `effective_length`, and `length_clamped`.
- `memory_dump`: artifact-first range output with hash and direct URL
  (8 MiB per-call cap); the summary reports `effective_address`, the request
  echo (`requested_address`, `requested_address_space`,
  `requested_length`, `effective_length`, `length_clamped`),
  `system_paused_during_read`, the `capture_consistency` object, and the full
  capture-provenance envelope on the artifact. Optional `capture_mode:
  "paused"` makes the dump a temporally atomic snapshot.
- `memory_write`: debugger-path writes to CPU bus spaces
  (`SetMemorySpaceByte`) and entry-based memory devices (read-modify-write
  honoring byte order). The permissions `memory_spaces_list` reports are
  enforced: timed-buffer VDP shells and `mem-rom`/`mem-boot-rom` are refused
  with `write_not_supported` before any native write, so the loaded cartridge
  image is never patched in place and the ROM identity keeps describing the
  executing code. The refusal carries the space, its `permissions`, and a
  stable `reason` (`timed_buffer_device`, `read_only_image`). Writes addressed
  through a CPU bus space keep real hardware behavior, where the bus silently
  discards writes to cartridge addresses. Every call, including a refusal, is
  audited. Bytes arrive as exactly one of `data`
  (base64) or `data_hex` (hex bytes with optional spaces); the response echoes
  bounded uppercase hex of the exact bytes written, the effective address, and
  optional read-back verification (`verify_readback` reports whether the space
  returned the exact written bytes or masks/transforms/discards them).
- `memory_search`: byte-pattern search over a consistent `memory-snapshot`
  artifact (or an existing dump/snapshot by id) — bounded inline matches plus
  a full-results artifact. With `snapshot_id` the space, start address, byte
  length, and byte order **derive from the snapshot's capture provenance**;
  the snapshot is the provenance source, so a caller-supplied
  `start_address`/`length` inside the captured range **narrows** the search
  (a subset is a smaller question about the same bytes) and the response
  echoes `requested_range` next to the `searched_range` it actually scanned,
  while a window that leaves the captured range stays `provenance_conflict`.
  Snapshots without provenance
  (legacy) warn as `provenance_unknown` and fall back to caller addressing.
  Patterns support explicit wildcards (`??`/`?` nibble/byte masks) and
  optional power-of-two `alignment`; the result artifact serializes the parsed
  pattern and masks (`parsed_pattern`, `pattern_mask_hex`) so a search is
  reproducible, and the exact-byte mode is unchanged. Reports
  `system_paused_during_read` when the snapshot's live read paused the
  system, with a note explaining the flag source when a snapshot is reused.
  Matches page by cursor: the cursor carries the snapshot id, the searched
  window, the pattern, and the resume byte offset, so every page after the
  first reuses the same immutable snapshot (no second read, no resend) and the
  envelope `{returned, total, truncated, has_more, next_cursor}` walks the
  result set to exhaustion without repeats or gaps.
- `memory_diff`: cheat-finder comparison between two consistent snapshots.
  Cell widths byte/word/long with explicit byte order (default big-endian,
  derived from the before snapshot's captured byte order when it has
  provenance) and aligned scanning by default; modes `changed`, `unchanged`,
  `increased`, `decreased`, `changed_by` (signed delta), `equal_to`, and
  `in_range`. Snapshots with incompatible provenance (different space, range,
  ROM identity, or artifacts from different composite captures) fail with
  `incompatible_provenance` by default; passing
  `allow_incompatible_provenance` forces the comparison with a prominent
  warning naming both source manifests — a common address origin is never
  fabricated. Reports both capture ids when the snapshots belong to composite
  captures. Bounded inline matches plus a `memory-diff-results` artifact, and
  the same paging envelope as `memory_search`: a cursor names **both snapshot
  artifacts** plus the cell semantics and the resume byte offset, so a page
  after the first compares exactly the bytes the first page compared — a fresh
  after read is stored once and reused (`fresh_after_read` is false on cursor
  pages) instead of taking another live reading. `requested_comparison` echoes
  the requested mode/width/byte order next to the `compared_range`.
- `system_snapshot_capture`: bounded atomic cross-domain snapshot with a
  `system-snapshot/1` artifact manifest, shared capture provenance, explicit
  omitted/unavailable components, and one pause/resume window. **proven** for
  the pause window, the verified run-state restore, and the manifest
  provenance, including a guard that carries the caller's
  `expected_target_generation`
  (`TestSystemSnapshotCaptureRestoresWithExpectedGeneration`,
  `TestSystemSnapshotCapturePausedTargetStaysPaused`); **unvalidated** for
  component selection beyond a memory range (register, VDP buffer, and frame
  components have no behavioral test). Every memory component records the real
  address domain of its range — the published `space` of the range or the
  top-level `space`, never the range label — plus the owning device, the
  space-relative start, and the bus start, through the same
  `artifact-provenance/2` builder `memory_snapshot_capture` uses, so both
  producers describe the same range identically
  (`TestSystemSnapshotMemoryProvenanceMatchesMemorySnapshot`). The published
  schema and the strict decoder are held to one property list by
  `TestPublishedSchemaMatchesArgumentStructs`; `address_space` is the optional
  domain of `vram_address`, and it never replaces a range's `space`.
- `memory_snapshot_capture`: bounded paused composite capture — one or more
  named ranges of one address space are read inside a single pause window
  (the system is paused exactly once when running and restored afterwards;
  zero pause/resume cycles when already paused), so every range describes one
  temporally atomic instant. All raw range artifacts and the JSON manifest
  share one stable `capture_id` and the `artifact-provenance/2` envelope; the
  summary reports the pause/resume cycle count, the target generation span,
  initial/final run states, frame tokens, the atomic capture-consistency
  object, and the `run_state_restore` outcome. A caller-supplied
  `expected_target_generation` gates the pause only — the resume that closes
  the window carries the control id alone
  (`TestMemorySnapshotCaptureRestoresWithExpectedGeneration`,
  `TestMemorySnapshotCapturePausedTargetStaysPaused`). Runs under exclusive
  control for the full window (caller `control_id` reused or internal lock).
  A paused capture can perturb real-time behavior; the cost is documented in
  the tool description.
- `memory_freeze`, `memory_freeze_list`, `memory_freeze_remove`,
  `memory_freeze_clear`: server-managed value freezing with optional
  generation/control preconditions. A registered range is written once and
  re-applied at 20 Hz through the serialized bridge queue; the list tool
  surfaces write counts, last write time, provenance (context, target
  generation, ROM), and the last periodic-write error; the set is purged on
  `rom_load` with an audited invalidation batch. `memory_freeze` accepts the
  same mutually exclusive `data`/`data_hex` inputs as `memory_write` and
  echoes bounded hex.
- `artifact_get` (merged successor of `artifact_get` + `artifact_describe`):
  metadata, direct retrieval, `created_at`, `expires_at` (null when retention is
  unlimited), the payload's own `schema_version`, the `capture_id` when the
  artifact belongs to a capture, and the full typed provenance envelope (address
  domain, device, target generation, ROM identity, frame token, run state,
  consistency, capture time — or the honest `provenance_unknown` state).
  `include` selects the `metadata` and `provenance` sections (both by default).
  `artifact_describe` is a deprecated alias for one release: same payload plus a
  `deprecated` note naming the replacement.
- `artifact_list`: enumerates the artifacts of one context in creation order with
  `kind` and `capture_id` filters and cursor paging (`total`, `returned`,
  `has_more`, `next_cursor`), so a new session discovers what already exists
  instead of copying ids out of earlier responses. Descriptors carry
  `artifact_id`, kind, MIME type, size, SHA-256, `created_at`, `expires_at`,
  `schema_version` when the payload declares one, `capture_id` when applicable,
  and the download URL.
- `capture_get`: resolves a `capture_id` from `memory_snapshot_capture`,
  `system_snapshot_capture`, or `vdp_capture` to its producer, frame token,
  target generation, manifest artifact (with its parsed document when bounded),
  and one descriptor per component, including omitted/unavailable components and
  their reasons. Unknown, expired, or foreign ids fail with `capture_not_found`.
- The artifact and capture indexes are persisted in
  `<artifact-dir>/artifact-index.json` and reloaded at startup, so a restarted
  server reopens the artifacts and captures it wrote; because context handles are
  process-local, they are only reachable through a handle that exists again.

## Audio observability (Phase 6, partial)

- `sound_status` reads typed YM2612 and SN76489/PSG state without reconstructing
  registers from bus writes. It reports raw register snapshots, FM channel and
  operator envelope/pan/DAC fields, PSG tone/volume/mute fields, device
  availability, and explicit null/unobservable notes. The result is
  `sound-status/1` and is a live, non-atomic sample relative to CPU/VDP.
  **unvalidated**: no Go test and no `scripts/live-smoke.sh` check calls this
  tool; the typed reads are only exercised by running it against a live pair.
- `audio_capture` — **planned, not delivered.** The server-side argument
  contract exists (duration 1-10000 ms, sample rate 22050/44100/48000,
  channels 1-2, 8 MiB WAV cap, malformed-WAV rejection) and is returned before
  the bridge is called, but the pinned plugin answers every `audio_capture`
  request with `audio_unavailable`
  (`native-plugin/ExodusMcpPlugin.cpp`, `audio_capture` branch), so the shipped
  pair can never produce an `audio-capture` artifact. No test covers the
  server's success branch. Completion is tracked in [ROADMAP.md](ROADMAP.md)
  Phase 6, which requires a safe bounded PCM buffer from the native SDK.

## Processors, symbols, and execution (Phase 2 and Phase 4 control)

- M68K: `m68k_registers`, `m68k_read_memory`, `m68k_disassemble`,
  `m68k_step` (single-instruction step).
- Z80: `z80_registers`, `z80_read_memory`, `z80_disassemble`, `z80_step`.
- Symbol-aware disassembly: `m68k_disassemble` and `z80_disassemble`
  annotate every line whose instruction address or operand literal resolves
  against the analysis context's symbols — per-line `symbol` (own address)
  plus `targets` (operand literals that matched), with a documented
  `annotation_method` (24-bit 68K / 16-bit Z80 bus mask). Annotation matches
  the processor-bus coordinate, so a symbol stored space-relative
  (`mem-ram`, `mem-rom`, `z80-bus`, ...) annotates at its resolved bus address;
  `symbols_set` rejects a space id that has no documented CPU-bus mapping
  instead of storing an inert symbol.
- Deterministic processor control: `cpu_pause`, `cpu_run`, `cpu_step_over`,
  `cpu_step_out` — with live running-state reporting.
- Execution breakpoints: `cpu_breakpoint_set`, `cpu_breakpoint_list`,
  `cpu_breakpoint_remove` — MCP-managed breakpoints that pause the selected
  processor. `cpu_breakpoint_set` accepts optional conditions: `condition`
  `greater`/`less`/`range` filters by the program counter (range bounds are
  exclusive), and `break_on_counter` pauses only on every Nth native hit
  (ignored hits never stop the system). `cpu_breakpoint_list` reports
  `enabled`, the condition fields, and the native `hit_count`. In both Exodus
  CPU cores the breakpoint check occurs before opcode fetch/execution; at a hit,
  the reported triggering PC is the instruction that has not run yet.
- Watchpoints: `cpu_watchpoint_set`, `cpu_watchpoint_list`,
  `cpu_watchpoint_remove` — byte ranges with read/write/any access filtering,
  live hit counters, and deterministic hit-and-pause through the Exodus
  debugger path. **Range semantics are start-address based**, exactly like the
  Exodus debugger: the processor evaluates one location per access — the access
  **start** address — and its watchpoint API never reports the transfer width,
  so a watchpoint on `[address, address+length-1]` fires when the access starts
  inside that range and never when a wider access merely overlaps it (a
  `MOVE.L` starting at `0xFF0000` does not trip a watchpoint at `0xFF0002`).
  The set and list responses echo the contract as `range_semantics`
  (`exact_address` for `length: 1`, `access_start_in_range` otherwise) next to
  `range_end`, so the parameter never silently means something else. The
  watched range must stay inside the processor address bus (`address: 0` with
  `length > 1` is valid and now actually fires; a range that would end past the
  bus mask is `invalid_params`). For overlap semantics the access path offers
  no width, so a caller who needs them must use a trace session with
  `access_capture: "ranges"` instead. Breakpoints and watchpoints are purged
  safely on `rom_load` with one audited invalidation batch; set and list views
  echo `one_shot` and carry creation provenance (context, target generation,
  ROM) without exposing control ids.
- `cpu_trace_capture`: artifact-first processor trace window. The trace log
  is routed through a temporary on-disk file, tracing is configured with the
  system stopped, and the prior run state is restored (the reproducible
  access-violation crash is resolved; see
  [TRACE-CRASH-INVESTIGATION.md](TRACE-CRASH-INVESTIGATION.md)). Returns the
  human-readable `cpu-trace` text plus a versioned `cpu-trace-jsonl` artifact
  with one JSON event per executed instruction — CPU, address space, PC in
  numeric and hex form, opcode bytes, instruction length,
  mnemonic/operands, cycle position, target generation, capture id, and
  frame token where available — plus typed `control_flow` facts
  (fallthrough address, resolved branch/call target, branch-taken state,
  call/return classification, exception/interrupt marker, confidence) that
  are `unknown`/nil when the native trace does not provide them, never
  inferred from disassembly text. Optional filters
  (`address_range_start`/`address_range_end`, `include_rom`/`include_ram`,
  `retain_repeated`) are stored in provenance and summary. The artifact
  carries capture provenance naming the CPU, its bus address domain, target
  generation, and ROM identity.
- `cpu_trace_capture_watchpoint`: event-driven trace capture — the system
  runs toward a managed watchpoint (even from a paused state) and the window
  ends when it fires, reporting the fired watchpoint ids and stop reason. The
  result distinguishes the requested watchpoint firing (with an
  `event`/`event_id` and `linked_trace_capture_id` pointing at the exact stop
  event), a different managed resource firing, and timeout. The trace
  artifacts include the structured `debug-event` for the stop.
- `cpu_debug_events_list`: bounded forensic event history (100 retained
  records) with `offset`/`limit` pagination over the filtered set, filters
  (`resource_kind`, `resource_id`, `cpu`, `direction`, `event_id_min/max`, and
  the context scope), and an explicit `history` object — capacity, retained,
  recorded, dropped, retained id span, `complete`, the query `scope`, how many
  retained events the scope holds (`scope_retained`), and how many the filters
  match (`matching`, identical to `total`) — so a gap is never inferred from a
  short list and the counters never describe a broader set than `events` can
  return. `resource_kind`, `cpu`, and `direction` are validated server-side
  (`invalid_params` for an unknown value instead of an authoritative empty
  list). The query is scoped to the caller's context by default and
  `context: "all"` queries every context. Whenever a managed breakpoint or
  watchpoint stops execution — a steady hit reached through `cpu_run` as well
  as a one-shot hit — a structured `debug-event` (`debug-event/1`, additive
  fields only) records the managed resource id, owner context, CPU, triggering
  PC, address space, watched effective address, requested range, hit count,
  target generation, frame token, timestamps, and provenance. The access
  evidence separates `configured_access` (what the instrument was set with)
  from `observed_direction` (`read`/`write`/`execute` when the stop proves the
  direction, `null` when the core cannot tell — an `any` watchpoint stop), and
  `access_direction` remains as the historical alias of `configured_access`.
  The `direction` filter matches the **observed** value: `any` matches every
  event including unknown directions, and `read`/`write`/`execute` never match
  an event whose direction is unknown. `triggering_pc` is `null` together with
  `triggering_pc_source: "unknown"` when the value could not be read, so a stop
  is never attributed to the plausible address 0. The two provenance fields are
  never conflated: `triggering_pc_source` (`register_read` | `unknown`) answers
  *where the PC came from*, and `stop_source` (`instrument` | `external` |
  `mcp`) answers *why execution stopped* — an event row always reports
  `stop_source: "instrument"`, the same value a `run_until_*` response reports
  for its own instrument, and a `run_until_*` stop is joined to its row through
  `debug_event_id`. Stop/resume semantics are
  explicit: a breaking hit pauses the CPU and increments the native counter
  once; the native counter is the identity of a stop, so while the CPU stays
  paused a repeated observation of the same resource, counter value, and
  direction is folded into the same event (`repeat_count`, `last_seen_at`) even
  if a later pause reads a different PC, and a resumed CPU produces a new
  counter value and therefore a new event. Access width, value before/after, and
  transferred value for *paused watchpoint stops* remain `null` with a "not
  exposed by native API" note rather than presenting zero as data —
  per-occurrence values come from a trace session with `access_capture`, not
  from the pause path.
- `cpu_coverage_capture`: execution coverage artifact (`cpu-coverage/2`)
  from a bounded trace window — the executed address set with execution
  counts, instruction-aware basic `blocks` (start/end address, instruction
  and execution counts, member addresses), and observed `edges`
  (from/to/count), replacing byte-adjacent span merging: a gap between
  `0x100` and `0x104` no longer implies separate code merely because
  instruction starts are not byte-adjacent. The artifact carries capture
  conditions, ROM identity, address-space requirements, optional filters
  (`include_rom`/`include_ram`/`retain_repeated` plus
  `region_start`/`region_end`/`max_entries`), legacy `ranges` for
  compatibility, and per-section `truncation` facts (`source_events`,
  `decoded_events`, `unique_addresses`, `blocks`, `edges`) — a trace
  ring/timeout limit is never reported as complete coverage. The counts,
  filters, and artifact shape are **proven** by
  `internal/mcp/tools_phase5_test.go` (`TestCpuCoverageCaptureBuildsCoverage`,
  `TestCpuCoverageCaptureRegionFilter`); the instruction-aware `blocks` and
  `edges` structure is **unvalidated** — no test asserts either section.
- Symbols: `symbols_set`, `symbols_list`, `symbols_clear`, scoped to an
  analysis context. Every symbol keeps both coordinates — the supplied
  `space_id` plus address, and the resolved processor-bus `bus_space_id` plus
  address — and both are echoed by `symbols_set` and `symbols_list`.

## VDP and graphics (Phase 3)

- `vdp_command_dma_status`: bounded read-only native view of all 24 VDP
  registers, directly exposed DMA enable/status, length/source/mode fields,
  and explicit null/observability metadata for the command latch and DMA
  destination/remaining fields not exposed by the pinned SDK. It never
  reconstructs state from bus writes and does not claim CPU/VDP atomicity.
- `vdp_status`: all 24 registers plus typed decode of display enable,
  extended VRAM, name-table, pattern, and h-scroll-base fields, with
  completed-plane geometry.
- `frame_capture`: the live rendered frame as a PNG artifact with frame/timing
  metadata. Paused determinism (identical digests for consecutive captures) is
  a **live check** (`scripts/live-smoke.sh`, "paused frame captures are
  deterministic" plus the consecutive-capture stress check); frame liveness
  (the frame token advancing while the system runs) is **unvalidated** and is
  visible only in the timestamped token of a manual run. The frame buffer is
  read without pausing, so `system_paused_during_read` is always false and
  `capture_consistency.state` is `live` (the frame token identifies the
  rendered frame; **proven** by `internal/mcp/tools_frame_capture_test.go`
  `TestFrameCaptureReportsNoPause`). Optional `capture_mode: "paused"` makes the
  frame match a temporally atomic instant. The artifact's capture provenance
  records the frame token, target generation, and ROM identity.
- `vdp_memory_read`: VRAM, CRAM, and VSRAM through the timed-buffer path.
  Raw views (`hexdump`, `array_u8`, `raw_base64`), big-endian
  `array_u16` words, and a decoded CRAM view expanding 9-bit RGB entries into
  8-bit RGB (`-RRR-GGG-BBB-` channel layout). Reports
  `system_paused_during_read` when execution had to be stopped and the
  standardized `capture_consistency` object (atomic for a paused timed-buffer
  read); optional `capture_mode: "paused"` makes the sample temporally
  atomic. Views and metadata are **proven** by
  `internal/mcp/tools_test.go` (`TestVDPMemoryReadCramRGB333View`,
  `TestVDPMemoryReadDefaultsAndMetadata`, `TestVDPMemoryReadRejectsBadRequests`);
  byte equality with `memory_read` is a **live check**.
- `vdp_memory_export`: artifact-first binary export of arbitrary
  VRAM/CRAM/VSRAM ranges — the raw bytes land in an immutable
  `vdp-memory-export` artifact (application/octet-stream) with SHA-256,
  size, URL, and the versioned provenance envelope (address domain, byte
  order, device, target generation, honest `capture_consistency`), so large
  regions never travel as Base64 through tool responses. Target caps are
  validated server-side (vram 65536, cram 128, vsram 80; length defaults to
  the full buffer); optional `capture_mode: "paused"` makes the sample
  temporally atomic (one explicit pause/resume cycle). The response echoes the
  request next to the effective values: `requested_address`,
  `requested_length`, `effective_address`, `effective_length`.
- `vdp_tile_export`: consecutive 8x8 4bpp patterns as a scaled PNG plus a JSON
  pixel-index artifact, colored through a chosen CRAM palette line with
  optional transparent color 0 (high-nibble-left pixel order). Reports
  `coherent_snapshot`, `system_paused_during_read`, and the standardized
  `capture_consistency` object — when any chunked read found the system
  running, the composition is `composite_non_atomic` and the VRAM/CRAM pieces
  must not be combined into a coherent instant. Both artifacts share one
  `capture_id`.
- `vdp_plane_export`: full unscrolled scroll-plane texture view (A, B, or
  window) rendered from the name table with flip, palette, and priority
  decoding; reports distinct tiles, priority counts, `coherent_snapshot`,
  `system_paused_during_read`, the `capture_consistency` object, and a shared
  `capture_id` across both artifacts.
- `vdp_palette_export`: CRAM as four 16-color lines into a PNG swatch
  artifact plus a JSON decode artifact, with nonzero counts per line, the
  backdrop color inline, `system_paused_during_read`, and a shared
  `capture_id` plus `capture_consistency` object on both artifacts.
- `vdp_sprite_table`: decoded sprite attribute table with positions, cell
  sizes, tile mapping, palette, priority, and a globally accurate link-chain
  walk (termination, cycle, dangling-link, and truncation flags), paged over
  at most 80 entries. Reports `chain_visible_count` (hardware-rendered
  link-chain length), `table_entry_count` (populated entries), and a `warning`
  when the chain renders fewer sprites than the table holds (mid-update or
  stale links), plus `system_paused_during_read`.
- `vdp_pixel_info`: per-pixel rendering attribution from the VDP full image
  buffer — source layer, name-entry mapping with tile/flip/priority, palette
  row and entry, shadow/highlight state with the resolved 8-bit color, h/v
  counters, and sprite cell data. Full image buffer info is enabled lazily and
  reported as pending until a frame has rendered with it active. Read under
  the VDP's own lock, never pausing the system (`system_paused_during_read`
  is always false).
- `vdp_capture`: one bounded VDP capture guarded by `capture_mode`. The default
  `"live"` guard performs no pause; `"paused"` pauses once and restores the
  prior run state through the shared capture guard, and every artifact of the
  capture is re-stamped with the finalized window object so provenance and
  response agree. It reads status/registers, the frame buffer, CRAM, VSRAM, and
  a VRAM range (default the whole 64 KiB buffer, 131072-byte `vram_length` cap,
  `include_vram: false` opts out), then writes a `vdp-capture-manifest` linking
  the produced artifacts to one `capture_id` and registers the capture in the
  durable capture index; omitted and unavailable components carry a reason in
  the manifest and in `capture_get`. The sprite-table component records that the
  table lives in the captured VRAM component instead of claiming a separate
  read; with `include_vram: false` it is reported unavailable. One placeholder
  remains: the `vdp-render-manifest` artifact is a structural stub whose
  `display_geometry`, `palette_state`, `sprite_state`, and `scroll_state`
  entries are notes referring to other artifacts, not decoded plane/window
  configuration, scroll offsets, sprite display order, or priority data.
  **unvalidated live**: no `scripts/live-smoke.sh` check calls `vdp_capture`.
- `vdp_capture_id` reuse is implemented for the VRAM-backed readers.
  `vdp_sprite_table`, `vdp_tile_export`, and `vdp_plane_export` resolve the id
  through the capture index and decode the stored components (status, VRAM, and
  CRAM) instead of the device; they report `data_source: "capture"`,
  `vdp_capture_reused: true`, `vdp_capture_id`, the capture's
  `vdp_capture_frame_token`, and the capture's own `capture_consistency`, and
  their derived artifacts stay in that capture's `capture_id` lineage (plus
  `source_capture_id` in the response). A capture whose components cannot serve
  the request fails with `capture_component_omitted` naming the missing
  component, the reason, and what the capture holds; an unknown, expired, or
  foreign id fails with `capture_not_found`. Neither error falls back to a live
  read. `vdp_pixel_info` cannot reuse a capture: per-pixel attribution exists
  only for the frame the VDP just completed and the bridge answers it one
  coordinate at a time, so a supplied id fails with
  `capture_component_omitted` naming `pixel_attribution`.
  A live read of any of the four tools reports `data_source: "live"` and makes
  no reuse claim.
- VDP-specific semantics are preserved in the fields that are actually decoded:
  big-endian VRAM words (`vdp_memory_read` word view), CRAM 9-bit packing
  (`vdp_memory_read` `cram_rgb333`, `vdp_palette_export`), high-nibble-left
  tile pixel order (`vdp_tile_export`), and name-entry bits
  (`vdp_sprite_table`, `vdp_pixel_info`).

## Controlled experimentation (Phase 4)

- `rom_load`: controlled local cartridge replacement that preserves the
  previous running state; MCP-managed breakpoints, watchpoints, and frozen
  cell ranges are purged before the module unloads, with one audited
  invalidation batch naming every affected resource. Reloading the same path
  is the machine-reset equivalent — the module reload reinitializes the
  system and purges all managed debug resources; to reset a cartridge loaded
  through the Exodus UI, read its path from `emulator_status.rom.path`
  (`path_source: "loaded_module"`) and pass it back here.
- `target_reset`: the discoverable reset tool — `kind: "hard"` performs the
  documented same-path cartridge reload described under `rom_load`. `kind:
  "soft"` calls the versioned native `soft_reset` bridge operation and is
  rejected with `unsupported_plugin` when the connected plugin does not
  advertise it (no register or memory-write fallback, ever). The plugin
  advertises `soft_reset` only when the loaded fork exposes a compatible
  `ISystemResetInterface`; that fork-side capability cannot be checked from
  this repository (the `vendor/exodus` submodule is not initialized in every
  checkout). The soft path itself is described in
  [Phase 9](#phase-9-workflow-ergonomics-delivered-atomic-snapshots-reset-input-exports-instrumentation-and-state-override).
- Target revision: a process-local `target_generation` starts at 1, advances
  exactly once per successful mutation, and is attached to every response,
  resource, snapshot, and audit record. Ambiguous native failures move the
  target to an `unknown`/resynchronization-required state; revision-guarded
  mutations wait until a successful observation re-establishes the revision
  (and advances it, because the machine may have changed while unknown).
- Optional exclusive control lock: `target_control_acquire`,
  `target_control_renew`, `target_control_release`, `target_control_status` —
  one process-wide lock with TTL-based expiry (5 min default, 1 h cap),
  `control_id` capability returned only to the acquirer, purpose/expiry holder
  diagnostics without leaking the id, release on context close or bridge
  loss, and audit records stating why each lock ended.
- `target_audit_log`: the bounded global target audit stream — monotonic
  operation ids, UTC timestamps, normalized redacted arguments, target
  generations before/after (or unknown), ROM identity, originating context,
  control-lock provenance, outcome, structured failures, and created or
  invalidated resource ids, with generation/time/tool/context/control filters,
  pagination, and retained-window metadata on truncated responses. Pages by
  cursor (the monotonic operation id of the last entry, so an entry recorded
  between pages never duplicates or skips a row) or by offset;
  `has_more`, `next_cursor`, and `next_offset` agree, and both are null on the
  last page instead of pointing at an empty page. Reported through the shared
  `{returned, total, truncated, has_more, next_cursor}` envelope. Externally
  observed run-state transitions are recorded here as `run_state_change`
  events with the observed generation (never advancing it).
- `context_mutation_log`: the per-context projection of the audit stream
  (target mutations only; lock lifecycle stays global). Same cursor, envelope,
  and offset rules as `target_audit_log`.
- `state_save`, `state_load`, `state_list`: context-scoped system snapshots
  through the emulator's native save-state path (ZIP format), each verified
  with SHA-256 and size and carrying provenance (context, target generation,
  ROM path and SHA-256, optional control id, and `saved_run_state` — the last
  observed run state at save time, honest `"unknown"` without an
  observation). `state_save` does not mutate the target. `saved_run_state` is
  historical metadata: the native load never applies it (the core records the
  pre-load run state, restores the snapshot, and runs again only when the
  pre-load state was running), so `state_load` reports it with
  `saved_run_state_note`. `state_load` mutates the target and reports the
  before/after generations, `capture_consistency.state: "state_restored"`,
  `run_state_override` (`preserve` by default, or the forced `paused`/
  `running`), `final_run_state`, and `final_run_state_verified` (read from the
  native run-state echo, never asserted); observations describe the restored
  instant until the system runs again. Lists flag entries stale for the
  loaded ROM and generation-mismatched while preserving them for historical
  analysis.
- `frame_advance`: pause, execute exactly N rendered VDP frames, pause —
  reports the final frame token, before/after target generations, and times
  out with a diagnostic when the display is not rendering.
- `input_set`: press/release of up, down, left, right, a, b, c, start, x, y,
  z, and mode on a controller by player port, through the controller device
  input path.
- `input_sequence`: atomic multi-step controller scheduling — one call holds
  the listed buttons on one player port for N frames per step (1-64 steps,
  1-60 frames each; always down → advance → up so no input state is left
  behind). Runs under exclusive control for the whole window (caller
  `control_id` reused, otherwise an internal lock), audits every step, ends
  paused with every button released (a failed step releases its buttons
  before returning), and reports per-step frame tokens plus the generation
  span. Lighter than `deterministic_replay`'s state-save/restore ceremony for
  reproducible title/menu/gameplay traversal.

## Advanced analysis (Phase 5)

- `rom_info`: the 256-byte Sega cartridge header parse (system type,
  copyright, domestic/overseas titles, serial/product/version, I/O support,
  ROM/RAM/backup-RAM windows, region) with header-checksum validation against
  the computed Sega sum, a reference 68K memory map, and a header-region
  artifact. Checksum validation is honest about coverage: `complete`,
  `bytes_covered`, `expected_range`, and `cap_reason` (`none` |
  `dump_cap` | `declared_end_beyond_file` | `degenerate_declared_range`) state
  exactly what was compared, and the verdict travels with that completeness —
  `matches` (with `verified: true` and `verdict: "match"`/`"mismatch"`) is only
  emitted for a complete comparison, while an incomplete one reports
  `verified: false`, `verdict: "unverified"`, and `unverified_reason` instead of
  a boolean a consumer could read as "checksum ok". The same rule applies to the
  file-derived `rom_identity.checksum`. The response also reports the
  standardized `capture_consistency` object for the header reads, and the
  header artifact's legacy `consistency` label is derived from that object
  instead of being stamped as a literal `live`
  (`TestROMInfoConsistencyLabelMatchesObject`). It also carries the shared
  `rom_identity` object (file SHA-256 when the ROM file is readable from the
  server host, file and padded mapping sizes, header title/serial, Sega
  checksum status computed over the file, mapped image base, target
  generation); an unreadable file is reported as such instead of inventing
  file-derived facts. Reference tables in
  [SEGA-HEADER.md](SEGA-HEADER.md).
- `mega_drive_memory_map`: structured operational Mega Drive memory map that
  combines the reference bus map with the live target — 7 reference regions
  (ROM, unmapped, Z80 RAM, YM2612, I/O, VDP ports, Work RAM), each with
  CPU-visible range, mirrors/mask, backing device, read/write capability,
  timing caveats, byte order, and I/O semantics, plus live existence
  cross-checked against `memory_spaces_list`. It is distinct from the generic
  inventory and never implies every reference region exists on the loaded
  system.
- `experiment_run`: operator-authored Python 3 scripts (`.py`) or declarative
  fixtures (`.json`) from the configured scripts directory. Scripts talk to
  the Go server over a bounded JSON-lines duplex and may call only an
  allowlisted subset of tools (`input_set`, `frame_advance`, `state_save`,
  `state_load`, `memory_write`, `memory_read`, `memory_dump`, `memory_search`,
  `frame_capture`, `vdp_status`, `vdp_pixel_info`, `vdp_sprite_table`,
  `m68k_registers`, `z80_registers`, `cpu_coverage_capture`). The server
  injects the experiment's context and control id, runs the whole experiment
  under exclusive control (reusing a caller-provided active `control_id` or
  acquiring an internal lock released after manifest finalization), records a
  reproducible `experiment-manifest` artifact (with capture provenance naming
  the target generation, ROM identity, and capture time) plus capped
  diagnostic output, and mirrors every step in the audit stream. Scripts never
  see the native pipe or capability; trust-in-operator-code applies (no OS
  sandboxing).

## Evidence annotations (P2)

- `annotation_create`, `annotation_get`, `annotation_update`, `annotation_delete`: context-scoped evidence store for addresses and ranges. Each annotation carries title, text, tags, category, author/source, confidence, `kind` (`observation` vs `hypothesis`), creation/update timestamps, address space/range (flexible `$`/`0x`/`h` parsing), ROM identity (`rom_sha256`+path) and `target_generation` stamping at creation, and evidence links to artifacts, states, captures, trace events, symbols, and managed debug resources. Hypotheses never promote to symbols automatically.
- `annotation_list`: bounded, paginated view (default 20, cap 100, `truncated`+`next_offset`) with filters for query substring, tags, category, kind, address space, and staleness (`stale`/`stale_reason` `rom_sha256_mismatch`/`target_generation_mismatch`, `stale_only`/`include_stale` with `stale_excluded` honesty). Preserves history across ROM loads. Pages by cursor (a keyset anchor on the immutable `created_at`+`id` pair of the last returned annotation, so a concurrent create, edit, or delete never repeats or skips a row) or by offset (mutually exclusive with `cursor`), and reports the shared `{returned, total, truncated, has_more, next_cursor}` envelope; `next_offset` is null on the last page.
- `annotation_export` / `annotation_import`: versioned `annotation-export/1` artifact (`application/json`, provenance via `genericProvenance`) and import with conflict detection (`overwrite` flag, per-id `conflicts` list, 500-per-context cap). Import honors the same staleness and provenance rules.

## Advanced debugging (Phase 7)

- `cpu_register_condition_evaluate`: server-side register-condition primitive for `cpu_breakpoint_set` hits. Evaluates conditions such as `D0 == $1234` or `A7 >= $FF0000` against live `regs_get` values (m68k `D0-D7/A0-A7/PC/SR` and z80 `AF/BC/DE/HL/IX/IY/SP/PC` plus 8-bit derivatives) with `==`/`!=`/`>`/`<`/`>=`/`<=` and `&&`/`||`, flexible hex parsing, and unsigned comparison. Returns `matched` with parsed register/expected values plus a note documenting the post-hit pause/resume race and that `cpu_run` must be called when the condition is false — the native `IBreakpoint` has no register filter, so this loop is heuristic, not atomic.
- `m68k_backtrace`: heuristic M68K stack walk from A7 (the active stack
  pointer, USP or SSP per the SR supervisor bit) with an optional A6
  frame-pointer chain, resolving candidate return addresses against
  `symbols_set` symbols. Frame 0 is the live PC (confidence high); every
  other frame is flagged with its recovery method (`register_pc`,
  `frame_pointer`, `stack_scan`), confidence, and a heuristic note — the
  frame-linkage walk reads [A6]=saved A6 and [A6+4]=return address, and the
  linear scan accepts nonzero, even stack-slot values inside the documented
  executable regions (ROM 0x000000-0x3FFFFF, RAM 0xFF0000-0xFFFFFF;
  confidence medium for ROM-window candidates, low for RAM-window code). The
  tool never claims execution-verified call sites: the response states the
  stack may contain data, not return addresses, and reports the composite
  `capture_consistency` object for its live reads.
- `state_diff`: read-only comparison of two `state_save` snapshots into a
  `state-diff-results` artifact. It diffs snapshot metadata (name, size,
  SHA-256, target generation, ROM identity, timestamps, control id) and the
  raw snapshot files byte-by-byte (per-byte counts, contiguous diff regions,
  bounded inline before/after hex, first-1KB previews, 8 MiB comparison cap),
  and reports identical true/false plus an artifact-first full report. The
  verdict includes completeness: `identical` is true only when both snapshot
  files were compared in full, and a comparison cut by the 8 MiB cap reports
  `comparison.complete: false`, `verdict_scope: "prefix"`, the truncation
  reasons, and `file_diff.complete: false` instead of a positive verdict over
  a prefix. The
  register/memory/VDP semantic sections are reported as explicitly requested
  but not performed: decoding them would require loading each snapshot into
  the emulator (`state_load`, a target mutation), which is out of scope for
  this read-only tool.

## Deterministic replay (Phase 8)

- `deterministic_replay`: record and replay one declarative input sequence
  from the same saved state under exclusive control to verify frame-for-frame
  determinism. Each step holds the listed buttons down on a player port for N
  frames (`input_set` down, `frame_advance`×N, `input_set` up; frames 1-60,
  up to 64 steps). The tool runs the sequence twice from the same state —
  capturing per-step VDP frame tokens, per-step M68K register samples and the
  final registers (pc/a7/d0) for both runs — restores the initial state
  afterwards (caller-provided `initial_state_id`, or a fresh snapshot of the
  current machine), and reports `deterministic` true/false with named checks
  plus a `replay-manifest/2` artifact recording both runs, the checks, and the
  methodology. Recording (run 1) and replay verification (run 2) share one
  code path, so a mismatch is a real emulator nondeterminism signal rather
  than a harness artifact. The VDP render counter is not part of a saved state
  and is never reset by `state_load`, so absolute tokens are not comparable
  across the restore: every step is compared as a delta from a
  `frame_token_baseline` captured at the start of its own run. Every restore
  that precedes stepping forces the machine paused, and each run reports
  `initial_run_state`; a pause the native echo cannot verify is reported, not
  assumed. A difference is reported in `diverged_step` (`step`, `field`,
  `run1`, `run2`) when it belongs to one step and in `divergences` otherwise,
  and an axis that could not be read (a missing token, an unreadable register
  set, a counter that wrapped) is listed in `unproven` and never counted as a
  match.

## Continuous trace sessions (Phase 10)

A session keeps capturing while the emulator keeps running: no pause, no
per-call round trip, and a bounded, queryable event record afterwards. The
full native capability investigation, capture modes, and deferred fork work are
documented in [TRACE-SESSIONS.md](TRACE-SESSIONS.md).

- `trace_session_start`: arms a persistent trace session for one processor.
  `mode: "sampled"` traces `window_ms` (default 100) of every `interval_ms`
  (default 10 000) and leaves the CPU untouched in between; `mode:
  "continuous"` traces every instruction and only rotates the segment file
  every `segment_ms`. **unvalidated**: every test and the live check use the
  default `sampled` window mode, so continuous capture and
  `stop_after_vdp_frames` have never been exercised by an automated check.
  Optional `watches` arm non-breaking read/write
  watchpoints whose hit counters are sampled. `access_capture: "ranges"`
  additionally records **per-occurrence read/write events** inside those ranges
  — native filtering means out-of-range accesses are never written — with a
  monotonic engine sequence, cycle, PC, direction, width, transferred value, an
  optional pre-write value when captured, and a same-instant register snapshot
  (`access_include_registers`, default true for ranges). Sessions remain active
  until explicitly stopped or the processor disappears; they do not expire by
  wall-clock time, so pausing the emulator does not consume a session lifetime.
  Optional `stop_after_vdp_frames` is a completed-rendered-VDP-frame stop
  threshold, not an instruction count, and requires a VDP; monitor polling may
  overshoot, and `vdp_frames_elapsed` reports the actual count. Reaching it
  stops capture, not emulation. `max_total_bytes`,
  `max_segments`, and `access_max_bytes`
  bound native retention (oldest data is evicted and loss is reported, never
  silent), while `max_events` bounds the server-side store. Every start response
  carries a `volume` object with retention limits and measured trace throughput;
  no total-volume estimate is claimed for an unbounded session. Because those
  caps are finite by default, the same response never claims completeness: the
  session reports itself as running (`loss.complete: false`, `loss.final: false`,
  `loss.incomplete_reasons: ["session_running"]`), and
  `loss.estimated_eviction_risk` projects whether the estimated write rate
  exhausts `max_total_bytes`/`max_segments` before the session window ends, with
  `loss.estimated_eviction` carrying the horizons and the rule. `start_guard: "quiet"`
  stops the system for the configuration calls only and restores it; the default
  `"none"` arms capture on the running CPU.
- `trace_session_status`: drains both native streams into the bounded event
  store and reports the configuration, limits, native counters, segment tables,
  access-stream counters, watch counter deltas, per-kind totals, and the explicit
  loss object. Draining never disarms capture: in `continuous` mode the native
  plugin re-arms the engine's trace gate after each seal/rotate, so the default
  `collect: true` of `trace_session_status`/`trace_session_events` cannot end a
  live session.
- `trace_session_events`: bounded inline events plus a per-address execution
  histogram, filtered by `kind`, `direction`, address/PC/cycle/sequence range,
  and effective value (`value_equals`, `value_min`/`value_max`,
  `previous_equals`); effective-value filters select records without ever
  dropping a raw event from the store. Events page in capture order by
  `cursor`: the first page starts at the oldest retained event and each
  `next_cursor` resumes strictly after the last returned event's monotonic
  `store_sequence`, so pages advance to exhaustion instead of returning the
  same oldest window, and the shared `{returned, total, truncated, has_more,
  next_cursor}` envelope plus `paging.skipped_evicted` state what was skipped
  when the bounded store evicted events between pages. Optional
  `trace-session-event/1` / `trace-session-access/1` JSONL artifact with full
  `artifact-provenance/2` metadata, plus ROM-hash-bound symbol resolution of
  access PCs. The artifact descriptor's `truncated_by_store` covers evicted
  segments (`truncation_reasons` names them), not only inline caps.
- `trace_session_stop`: final drain of both streams, disable the writers,
  restore the processor's prior trace flags, delete the session's watchpoints
  and segment files, and report the final totals, watch counters, and loss;
  exports JSONL by default.
- `trace_session_recover`: lists or loads durable `manifest.json` records from
  this or a previous MCP server process. A manifest carries the configuration,
  the limits in force, the cartridge SHA-256, per-stream parse counters, the loss
  object, and the artifact ids; recovery reloads a recorded event file into a
  stopped read-only view and installs it only when no live session is active.

Honest boundaries stated in every response: execution events are the engine's
own per-instruction trace lines (full fidelity inside a capture window,
unfiltered because the engine cannot filter natively); access events are
per-occurrence records whose value semantics are stated (`value_state: "read" |
"written"`), and a write's pre-write value is reported only when the engine
captured it (`previous_known`); access records carry cycle and emulated time but
no per-record VDP frame token; every filter applies after capture. `loss.complete`
has one definition — the capture covered the requested window with no gaps and
the session has ended — so it is false for every running session
(`loss.final: false`, reason `session_running`; the same loss object states
`estimated_eviction_risk` when a finite retention cap will run out first) and true
only for a `continuous` session that stopped with zero loss. A sampled session
always reports `loss.complete: false` plus machine-readable coverage
(`loss.capture_is_sampled`, `loss.sampled_mode_gaps`, `loss.capture.duty_cycle`/
`window_ms`/`interval_ms`/`untraced_ms_per_interval`, and
`loss.incomplete_reasons`), so a 1 % sample can never be presented as an
execution record; any loss (dropped events, malformed or truncated lines, evicted
undrained segments, holes in the access sequence) also makes `loss.complete`
false with the reason listed. Symbols are bound to the cartridge SHA-256 they
were recorded against and resolution is suppressed when a different ROM is
loaded.

## Phase 9 workflow ergonomics (delivered: atomic snapshots, reset, input, exports, instrumentation, and state override)

- `target_reset(kind: "soft")`: native hardware-like reset available only on
  the compatible fork/plugin pair. It pulses the native M68000/Z80 reset
  lines without reloading the ROM, fetches SSP/PC through the M68000 reset
  exception path with big-endian 24-bit bus metadata, preserves the previous
  running/paused state, and proves Work RAM, Z80 RAM, VDP registers, and
  exposed VDP buffers before returning success. The result includes
  `external_reset_pulse`, `vector_fetch`, preservation details, generation
  before/after, and initial/final run states. Older plugins fail closed with
  `unsupported_plugin`; native proof failures are exposed as
  `soft_reset_partial` and never converted to success. The older-plugin
  fallback is **proven** by `internal/mcp/tools_reset_test.go`
  `TestTargetResetSoftNotDelivered`; the success path is a **live check**
  (`scripts/live-smoke.sh` requires the soft reset to succeed on the built
  pair).
- `one_shot: true` on `cpu_breakpoint_set` / `cpu_watchpoint_set` (echoed by
  the set and list responses): the server marks the instrument as one-shot in
  its resource provenance. Whenever the emulator is observed paused, a
  housekeeping sweep reads the native breakpoint/watchpoint lists and proves a
  fired break by the native hit counter (a positive multiple of the break
  counter N — the core increments on every passing location hit and breaks on
  multiples of N). Every proven stop is attributed and recorded as one
  structured debug event — steady and one-shot instruments alike — so a plain
  `cpu_run` hit is as queryable as a one-shot hit and a repeated paused
  observation folds instead of duplicating. A fired one-shot instrument is
  removed through the audited mutation path (`one_shot_sweep` audit entries
  with `one_shot_hit` detail), and `emulator_status` reports the removals
  (`one_shot_removals`) plus the attribution. A one-shot instrument that never
  fires stays armed until it does or until a ROM reload purges managed
  resources; non-one-shot fired instruments get the attribution and the event
  but are never removed.
- `run_until_breakpoint` / `run_until_watchpoint`: one-shot run-to-instrument
  wrappers. One call arms the instrument (same conditions/access semantics as
  the set tools), runs the system under exclusive control for the whole
  window (caller `control_id` reused, otherwise an internal lock), polls
  `emulator_status` every 100 ms (cache bypassed) until the instrument proves
  fired, and reports the stop evidence: `stop_reason`, `stop_source`,
  resource id, `hit_count`, `one_shot`, `triggering_pc` (+ hex),
  `triggering_pc_source`, registers, `pause_source`,
  `configured_access`/`observed_direction` and the watched range for
  watchpoints, `debug_event_id`, and the generation span. The stop evidence
  never fabricates facts: `triggering_pc` is `null` with
  `triggering_pc_source: "unknown"` when no read proved it, otherwise the value
  is a `register_read` whether it was captured at the stop or re-read by the
  tool. Provenance is split into two fields everywhere: `triggering_pc_source`
  (`register_read` | `unknown`, where the PC came from) and `stop_source`
  (`instrument` | `external` | `mcp` | `none` — why execution stopped, never a
  PC source). `pc_source` remains as a deprecated alias of
  `triggering_pc_source` carrying the same value. `debug_event_id` names the
  structured event recorded for the stop (`debug_event_ids` lists every event
  when the stop produced more than one), so a caller joins the tool response to
  `cpu_debug_events_list` without matching timestamps; `event_id` remains as
  the historical name of the same id. The **tool itself** removes
  the instrument inside the call, ahead of the paused-state sweep, and reports
  the verified outcome: `instrument_removed` plus `instrument_removal`
  (`removed` | `already_absent` | `failed`). A removal failure is surfaced as
  `run_until_cleanup_failed` carrying the complete stop evidence, with
  `instrument_removed: false` and `instrument_removal_failure`, and the
  instrument is handed back to the sweep for a retry. The instrument is
  removed on every exit path — success, foreign-pause preemption
  (`run_until_preempted` with the observed pause source), timeout
  (`run_until_timeout`, window default 30000 ms, min 100, cap 120000), or
  caller cancellation — so no armed instrumentation or polling is left
  behind.
- Run-state stop attribution: the tracker now remembers the most recently
  proven native debugger stop per managed instrument, so `emulator_status`
  reports `pause_source: breakpoint_or_watchpoint` with a note naming the
  instrument after any MCP breakpoint/watchpoint stop — without plugin
  changes (the plugin does not expose a stop reason). The attribution is
  cleared by any MCP run-state action or by observing the system running
  again, and the `run_state_change` audit entry carries the attribution.
- `state_load` `run_state`: `preserve` (default) keeps the machine in the run
  state it had before the load, which is exactly what the native restore does;
  `paused` and `running` force the restored state through a post-load
  `cpu_control` inside the same control window, audited under the `state_load`
  tool with `reason: "state_load run_state override"`. The response reports the
  resolved `run_state_override`, `final_run_state` (verified from the native
  run-state echo), and `saved_run_state` with `saved_run_state_note` stating
  that the recorded value is historical and never applied. `restore` is kept as
  a deprecated alias for `preserve`: it behaves identically and reports
  `deprecated_parameter_value` instead of being silently reinterpreted. An
  override failure is observable, never silent: the load already applied, and
  the error carries `state_loaded: true`, the requested state, and the
  un-overridden `final_run_state`. The override is a follow-up mutation in the
  window and carries the control id alone, so a caller's
  `expected_target_generation` applies to the load and never rejects the
  override it was meant to protect.

## Operations

- `GET /metrics`: loopback operator endpoint (outside JSON-RPC) with per-tool `calls`/`errors`/`error_rate`, per-artifact-kind `by_kind`+`total`, and `totals`; backed by `Store.OnPut` and `callTool` accounting.
- Configuration with one precedence rule (flag > environment > `.env` >
  default), published to Windows children via `WSLENV`.
- Artifact retention: `--artifact-ttl` / `EXODUS_MCP_ARTIFACT_TTL` (e.g.
  `24h`) expires old artifacts on a background sweep; startup logging reports
  the policy.
- `scripts/live-smoke.sh`: validates a running pair through the MCP endpoint —
  read-only default checks, `--full` adds the mutating surface (target
  generation read → guarded mutation, `target_generation_conflict` without
  native action, control-lock lifecycle with TTL expiry, memory write with
  read-back, frame advance, input, save/list/load, breakpoint/watchpoint
  lifecycles, consecutive paused captures, running-state restoration,
  experiment internal-lock release, audit stream queries).
- `scripts/test.sh`: local quality gates (format, vet, race-enabled tests,
  `GOOS=windows` build/vet) plus `--windows-live` named-pipe integration
  against a real pipe.
- Bridge wire protocol v2 with flat key/value requests, one streamed JSON
  envelope response, machine-readable error codes, and base64 helpers.

## Validation

The claims above are backed by two kinds of evidence — automated tests and
live smoke checks — and this section names the exact one for every claim. The
repository stores no recorded live run, so a **live check** is only proven for
the run of `scripts/live-smoke.sh --full` that produced it.

### Proven by automated tests

The catalog contains 94 unique tool names (`grep -h 'name: *"' internal/mcp/tools*.go`
excluding tests, deduplicated); determinism of `tools/list` and presence of a
named subset are asserted by `internal/mcp/server_test.go`
`TestToolsListDeterministicAndComplete`.

| Area | Test |
| --- | --- |
| Memory read caps, decoding, hexdump, dump artifact, artifact get/preview, contexts, register passthrough, disassembly cap, trace artifact, ROM load path, control passthrough, VDP reads, tile/plane/palette exports, sprite table, address parsing, symbols | `internal/mcp/tools_test.go` |
| Strict decoding, `oneOf` address schemas, canonical address/artifact shapes, space capabilities | `internal/mcp/tools_p1_schema_test.go` |
| Address-space bus mapping and out-of-range diagnostics | `internal/mcp/tools_spacemap_test.go` |
| Paused-read flag propagation for `memory_read`, `memory_dump`, `memory_search` | `internal/mcp/tools_paused_read_test.go` |
| Artifact store: roundtrip, context scoping, preview caps, HTTP full/range/ETag, TTL and startup sweep, `provenance_unknown` vs stamped envelope | `internal/artifact/artifact_test.go` |
| Capture consistency states, paused guard pause/restore (also on read failure), `memory_snapshot_capture` window and validation, cross-capture diff rejection, `state_load` `state_restored`, composite VDP export consistency | `internal/mcp/tools_consistency_test.go` |
| Guarded capture with `expected_target_generation` (running and paused target) for `memory_snapshot_capture` and `system_snapshot_capture`, verified `run_state_restore` | `internal/mcp/tools_guard_window_test.go` |
| `capture_mode: "paused"` never resumes a paused or unknown-state target, artifact/summary/response consistency agreement (single, composite, and `rom_info`) | `internal/mcp/tools_capture_window_test.go` |
| Provenance-driven search/diff addressing, typed provenance envelope, ROM identity, checksum completeness, write read-back | `internal/mcp/tools_provenance_test.go` |
| Breakpoint conditions and the `break_counter` default | `internal/mcp/tools_breakpoint_conditions_test.go` |
| Freeze lifecycle, limits, surfaced write errors, purge on ROM load | `internal/mcp/tools_freeze_test.go` |
| Memory-write echo and audit record, `data_hex`/base64 normalization, read-back verification (the memory-write contract itself is described in its own section above) | `internal/mcp/tools_phase4_test.go` `TestMemoryWriteEchoesAndRecordsAudit`, `internal/mcp/tools_provenance_test.go` `TestMemoryWriteHexInputAndEcho`, `TestMemoryWriteReadbackVerification` |
| Debug-event history folding (counter identity, changed-PC re-observation), gaps, pagination, observed-vs-configured direction filters, filter-enum validation, cross-context scope and scope-consistent history counters | `internal/mcp/tools_debug_events_test.go` |
| Run-until wrappers and one-shot sweep: verified instrument removal (including the native-failure path), shared `triggering_pc_source`/`stop_source` vocabulary across the tool response and the event row, `debug_event_id`/`debug_event_ids` join keys, null `triggering_pc`, steady-stop event recording, watchpoint range semantics and `one_shot` echoes | `internal/mcp/tools_run_until_test.go` |
| Target generation/control lock store, conflict and resynchronization | `internal/analysis/target_test.go` |
| Control lock, generation conflicts, audit stream, state save/load/list, frame advance, input set, context close | `internal/mcp/tools_phase4_test.go` |
| Search/diff modes, ROM header parse and checksum, `target_info` ROM summary, coverage counts and region filter, watchpoint trace arguments | `internal/mcp/tools_phase5_test.go` |
| State run-state contract and `state_load` `run_state` override | `internal/mcp/tools_state_contract_test.go` |
| `state_load` `run_state` `preserve`/alias contract, verified `final_run_state`, guarded override | `internal/mcp/tools_state_load_preserve_test.go` |
| State diff metadata, file bytes, identical detection | `internal/mcp/tools_state_diff_test.go` |
| Deterministic replay true/false/validation | `internal/mcp/tools_replay_test.go` |
| Annotation lifecycle, filters, staleness, export/import round trip | `internal/mcp/tools_annotations_test.go`, `internal/analysis/annotations_test.go` |
| Backtrace heuristics, symbol resolution, frame cap | `internal/mcp/tools_backtrace_test.go` |
| Register-condition parser and evaluator | `internal/mcp/tools_register_condition_test.go` |
| Sprite-table chain divergence, cycle detection, paused flag, paging | `internal/mcp/tools_sprite_table_test.go`, `internal/mcp/tools_test.go` |
| Paging envelope on every list/search/diff tool, cursor paging to exhaustion without repeats or gaps, cursor stability while new operations land between pages, snapshot-range narrowing, request echoes, truncated-diff and incomplete-checksum verdicts, evicted-segment truncation accounting | `internal/mcp/tools_paging_verdict_test.go`, `internal/tracing/paging_test.go` |
| VDP memory export artifact, defaults, validation, paused mode | `internal/mcp/tools_vdp_export_test.go` |
| VDP DMA status native observation and unsupported-plugin path; soft-reset interface gating | `internal/mcp/tools_vdp_command_dma_test.go` |
| Reset tools: hard reload path, older-plugin soft fallback, preconditions | `internal/mcp/tools_reset_test.go` |
| Input sequence ordering, lock reuse, validation, release on failure | `internal/mcp/tools_input_sequence_test.go` |
| Experiment fixtures, allowlist, control reuse, script limits | `internal/mcp/tools_experiment_test.go`, `internal/experiment/runner_test.go`, `internal/experiment/script_test.go` |
| Trace session store, segment parsing, filters, loss accounting, recovery | `internal/tracing/session_test.go`, `internal/tracing/access_test.go` |
| Trace session tools and ROM-load retirement | `internal/mcp/tools_trace_session_test.go` |
| Run-state attribution and externally observed transitions | `internal/mcp/runstate_test.go` |
| Audit log bounds, filters, window metadata | `internal/analysis/audit_test.go` |
| Context isolation and lifecycle | `internal/analysis/context_test.go` |
| Saved-state store provenance | `internal/analysis/states_test.go` |
| Metrics endpoint | `internal/mcp/metrics_test.go` |
| Symbol-aware disassembly for both CPUs, operand literal extraction, cross-space isolation | `internal/mcp/tools_disasm_symbols_test.go` |
| Bridge wire protocol, launch configuration, Windows named-pipe round trip | `internal/bridge/protocol_test.go`, `internal/bridge/launch_test.go`, `internal/bridge/client_windows_test.go` (Windows build tag; run by `scripts/test.sh --windows-live`) |
| Child shutdown when the HTTP server fails (the listener-before-child ordering itself is code reading, `cmd/exodus-mcp/main.go`) | `cmd/exodus-mcp/main_test.go` `TestRunUntilExodusExitsShutsDownServer`, `TestRunUntilExodusExitsStopsChildWhenServerFails` |
| Native trace/access record encoding | `native-plugin/tests/memory_access_log_test.cpp`, run by `scripts/native-test.sh` (invoked from `scripts/test.sh`) |

### Proven only by live checks

Each label below is a `check` string in `scripts/live-smoke.sh`; run
`bash ./scripts/live-smoke.sh --full` against a running pair to reproduce it.

- Pause/run, M68K step, breakpoint lifecycle and conditional breakpoint echo:
  "cpu_pause succeeds", "m68k_step succeeds while paused", "plain breakpoint
  defaults break_counter to 1", "conditional breakpoint echoes condition",
  "conditional breakpoint listed with condition", "watchpoint set returns an
  id".
- Paused frame determinism: "paused frame captures are deterministic",
  "consecutive paused captures stay responsive".
- VDP reads and exports: "vdp_memory_read matches generic memory bytes", "cram
  decode yields 64 palette entries", "sprite table decodes paged entries",
  "sprite link chain walks", "palette export yields four lines", "tile export
  attaches png and json artifacts", "plane export attaches png and json
  artifacts", "pixel info attributes a source layer".
- ROM header parsing and checksum: "rom_info identifies the cartridge",
  "rom_info validates the header checksum", "rom_info checksum matches an
  independent computation" (skipped when the ROM path is not readable from
  WSL).
- Memory search/diff over a snapshot: "memory_search finds the header magic",
  "memory_diff scans the snapshot range", "memory_diff equal_to finds the
  header byte".
- Coverage and watchpoint trace: "coverage records executed entries",
  "watchpoint trace captures entries", "watchpoint trace stops on the hit".
- Concurrency, lock, freeze, audit and experiment plumbing: "stale generation
  yields target_generation_conflict", "lock expires by its TTL", "reads stay
  available under the lock", "memory_freeze sweeper re-applied the cell",
  "target audit stream is queryable", "experiment releases its internal lock".
- Hard and soft reset: "target_reset reports reset_source hard", "target_reset
  soft succeeds while paused", "soft reset advances generation once",
  "target_reset soft preserves running state".
- `run_until_*`, one-shot removal and pause attribution: "run_until_breakpoint
  fires at the target PC", "run_until_watchpoint fires on a RAM write",
  "emulator_status attributes the managed stop", "one-shot breakpoint
  auto-removes on hit". **Pending live check** (the native watchpoint
  condition is not covered by a Go test): set a watchpoint at address 0 with
  `length: 2`, let the running system access addresses 0-1 (for example the
  vector table fetch), and confirm the stop; also set an `any` watchpoint,
  confirm its event reports `observed_direction: null`, and confirm
  `cpu_debug_events_list` with `direction: "write"` excludes it while
  `direction: "any"` includes it.
- Sampled trace session: "trace session starts", "native access stream is
  reported", "per-access write records are captured", "per-access sequence has
  no gaps in a short run", "trace session never pauses the CPU", "trace session
  restores trace flags", "trace session deletes its segments".

### Unvalidated

Implemented but covered by neither a test nor a live-smoke check, so the
behavior is unverified as of this revision:

- `sound_status`: no test, no smoke check.
- `audio_capture`: unreachable success path — the pinned plugin answers
  `audio_unavailable` for every call.
- `vdp_capture` and its `vdp-capture-manifest` / `vdp-render-manifest`
  artifacts: no live-smoke check, and the render-manifest component is still a
  structural stub (see the VDP section). The paused-window provenance agreement
  is covered by `internal/mcp/tools_capture_window_test.go`, the capture index by
  `internal/mcp/tools_artifact_index_test.go`, and capture reuse by
  `internal/mcp/tools_vdp_capture_reuse_test.go`.
- `vdp_capture_id` reuse against a **real** plugin build: the reuse contract
  (stored component reads, `capture_component_omitted`, `capture_not_found`, and
  byte-identical derived exports) is proven against the fake bridge only; the
  live check still does not call `vdp_capture` or pass a `vdp_capture_id`.
- `system_snapshot_capture` component selection beyond a memory range: the
  register, VDP buffer, and frame components have no behavioral test (the
  pause window, restore verification, and manifest provenance are proven by
  `internal/mcp/tools_guard_window_test.go`; the memory-range provenance,
  capture index, and schema/decoder agreement are proven by
  `internal/mcp/tools_system_snapshot_test.go`).
- Trace session `mode: "continuous"` and `stop_after_vdp_frames`: both tests
  and the live check use the default `sampled` window mode.
- `cpu_coverage_capture` `blocks`/`edges`: the tests assert entry, distinct and
  range counts and the artifact kind, not the instruction-aware block/edge
  structure.
- Frame liveness (frame token advancing while running): no automated
  assertion; only paused determinism is checked.
- Decoding claims that were verified by looking at a title screen: tile and
  plane exports reproducing title-screen art, palette decode against the live
  frame, the attract-mode sprite chain `[0, 4, 15]`, and the per-layer
  `vdp_pixel_info` attribution list. The smoke check only asserts that a source
  layer is reported.
- Watchpoint "pauses at the offending instruction with rollback confirmed":
  the lifecycle is live-checked, the rollback assertion is not automated.
- Soft-reset preservation proofs in the fork: the server and plugin contract is
  testable (older-plugin fallback) and live-checked on a compatible pair, but
  the fork-side `ISystemResetInterface` implementation is outside this
  repository and cannot be verified here.

## Adopted external input

A review of the independent in-process `sadnescity/exodus-mcp-extension`
project (August 2026) produced these delivered adoptions: the decoded
sprite-table view, `vdp_pixel_info` rendering attribution, MCP-managed
watchpoints, snapshot-based `memory_search`, and flexible address argument
formats. Deliberately rejected alternatives are recorded as policy in
[ROADMAP.md](ROADMAP.md#design-constraints-recorded).

## Tool design rules

The delivered catalog honors these rules, and any future tool must keep them:

- Every value with a width greater than eight bits must carry an explicit byte
  order, or state why byte order is not applicable.
- Every raw range must state address space, start address, byte length, and the
  interpretation used for any decoded values.
- Address arguments accept `$`-prefixed Motorola hex, `0x` hex, Zilog `h`
  suffix, and decimal integers; every response echoes the canonical parsed
  address.
- Default responses are summaries; large output is an artifact. Inline raw
  output requires an explicit small limit.
- Mutating tools accept optional `expected_target_generation` (read →
  guarded-mutate pattern) and optional `control_id` (required while the
  exclusive control lock is active), and return enough metadata to reproduce
  the action in the global audit stream.
- System-specific tools use clear prefixes (`m68k_`, `z80_`, `vdp_`) rather
  than pretending that behavior is generic.
