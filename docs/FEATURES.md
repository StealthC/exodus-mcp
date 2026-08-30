# Features

This catalog lists every feature delivered in the `exodus-mcp` analysis
server, grouped by capability. Planned work is tracked in
[ROADMAP.md](ROADMAP.md); the [CHANGELOG.md](../CHANGELOG.md) records the
delivery history.

The MCP server currently exposes **85 analysis tools** spanning the delivered
roadmap phases 0-9: bridge and context foundations, memory and artifact
access, both processors, VDP graphics, deterministic controlled
experimentation, advanced analysis, evidence annotations, advanced debugging,
deterministic replay, and workflow ergonomics. Delivered entries are covered
by unit and integration tests and exercised live where the native capability
is available; unavailable native features are documented explicitly (see
[Validation](#validation)).

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
  composite captures — a stable `capture_id`). `artifact_describe` returns the
  full typed envelope; artifacts whose producer attached no metadata are
  reported honestly as `provenance_unknown` instead of inventing fields.
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
  VDP exposes them. `memory_snapshot_capture` captures one or more named
  ranges in one pause window (exactly one pause/resume cycle, one capture id,
  one manifest); `memory_read`, `memory_dump`, `vdp_memory_read`, and
  `system_snapshot_capture` provides the cross-domain atomic form: memory
  ranges, CPU registers, VDP status/buffers, and an optional frame share one
  pause window and one `capture_id` in a `system-snapshot/1` manifest;
  omitted or unavailable components are explicit. `memory_read`,
  `memory_dump`, `vdp_memory_read`, and `frame_capture` accept an optional
  `capture_mode: "paused"` guard that makes a single sample temporally atomic
  — the default `"live"` never pauses, so timing-sensitive software is never
  silently perturbed. Mixing artifacts
  from different composite captures is rejected by `memory_diff` unless
  explicitly allowed.
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
  writability: VDP timed buffers and `mem-rom`/`mem-boot-rom` report read-only
  and `memory_write` rejects them with `write_not_supported`. Out-of-range
  failures include the valid canonical hex range.
- `memory_read`: bounded inline reads with explicit representation,
  effective-address echo, `system_paused_during_read`, the standardized
  `capture_consistency` object, and decode validation against the declared
  byte order. Optional `capture_mode: "paused"` makes the sample temporally
  atomic (pauses once, restores); the default `"live"` never pauses.
- `memory_dump`: artifact-first range output with hash and direct URL
  (8 MiB per-call cap); the summary reports `effective_address`,
  `system_paused_during_read`, the `capture_consistency` object, and the full
  capture-provenance envelope on the artifact. Optional `capture_mode:
  "paused"` makes the dump a temporally atomic snapshot.
- `memory_write`: debugger-path writes to CPU bus spaces
  (`SetMemorySpaceByte`) and entry-based memory devices (read-modify-write
  honoring byte order); timed-buffer spaces are refused with
  `write_not_supported`, ROM writes are discarded by the bus like real
  hardware, and every call is audited. Bytes arrive as exactly one of `data`
  (base64) or `data_hex` (hex bytes with optional spaces); the response echoes
  bounded uppercase hex of the exact bytes written, the effective address, and
  optional read-back verification (`verify_readback` reports whether the space
  returned the exact written bytes or masks/transforms/discards them).
- `memory_search`: byte-pattern search over a consistent `memory-snapshot`
  artifact (or an existing dump/snapshot by id) — bounded inline matches plus
  a full-results artifact. With `snapshot_id` the space, start address, byte
  length, and byte order **derive from the snapshot's capture provenance**;
  caller parameters that duplicate provenance are assertions and are rejected
  with `provenance_conflict` on mismatch. Snapshots without provenance
  (legacy) warn as `provenance_unknown` and fall back to caller addressing.
  Patterns support explicit wildcards (`??`/`?` nibble/byte masks) and
  optional power-of-two `alignment`; the result artifact serializes the parsed
  pattern and masks (`parsed_pattern`, `pattern_mask_hex`) so a search is
  reproducible, and the exact-byte mode is unchanged. Reports
  `system_paused_during_read` when the snapshot's live read paused the
  system, with a note explaining the flag source when a snapshot is reused.
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
  captures. Bounded inline matches plus a `memory-diff-results` artifact.
- `system_snapshot_capture`: bounded atomic cross-domain snapshot with a
  `system-snapshot/1` artifact manifest, shared capture provenance, explicit
  omitted/unavailable components, and one pause/resume window.
- `memory_snapshot_capture`: bounded paused composite capture — one or more
  named ranges of one address space are read inside a single pause window
  (the system is paused exactly once when running and restored afterwards;
  zero pause/resume cycles when already paused), so every range describes one
  temporally atomic instant. All raw range artifacts and the JSON manifest
  share one stable `capture_id` and the `artifact-provenance/2` envelope; the
  summary reports the pause/resume cycle count, the target generation span,
  initial/final run states, frame tokens, and the atomic capture-consistency
  object. Runs under exclusive control for the full window (caller
  `control_id` reused or internal lock). A paused capture can perturb
  real-time behavior; the cost is documented in the tool description.
- `memory_freeze`, `memory_freeze_list`, `memory_freeze_remove`,
  `memory_freeze_clear`: server-managed value freezing with optional
  generation/control preconditions. A registered range is written once and
  re-applied at 20 Hz through the serialized bridge queue; the list tool
  surfaces write counts, last write time, provenance (context, target
  generation, ROM), and the last periodic-write error; the set is purged on
  `rom_load` with an audited invalidation batch. `memory_freeze` accepts the
  same mutually exclusive `data`/`data_hex` inputs as `memory_write` and
  echoes bounded hex.
- `artifact_get`, `artifact_preview`, `artifact_describe`: metadata, direct
  retrieval, bounded byte-oriented previews, and the full typed provenance
  envelope (address domain, device, target generation, ROM identity, frame
  token, run state, consistency, capture time — or the honest
  `provenance_unknown` state) for every produced artifact.

## Audio observability (Phase 6 initial slice)

- `sound_status` reads typed YM2612 and SN76489/PSG state without reconstructing
  registers from bus writes. It reports raw register snapshots, FM channel and
  operator envelope/pan/DAC fields, PSG tone/volume/mute fields, device
  availability, and explicit null/unobservable notes. The result is
  `sound-status/1` and is a live, non-atomic sample relative to CPU/VDP.
- `audio_capture` validates duration (maximum 10 seconds), sample rate,
  channels, and an 8 MiB WAV cap before asking the native bridge for PCM. The
  response is artifact-first with `audio-capture/1` metadata and
  `artifact-provenance/2` identifying the mixer and little-endian PCM. The
  pinned SDK currently has no safe bounded PCM buffer exposed to the extension,
  so unavailable/incomplete capture returns a diagnostic and never fabricates
  a silent WAV.

## Processors, symbols, and execution (Phase 2 and Phase 4 control)

- M68K: `m68k_registers`, `m68k_read_memory`, `m68k_disassemble`,
  `m68k_step` (single-instruction step).
- Z80: `z80_registers`, `z80_read_memory`, `z80_disassemble`, `z80_step`.
- Symbol-aware disassembly: `m68k_disassemble` and `z80_disassemble`
  annotate every line whose instruction address or operand literal resolves
  against the analysis context's symbols — per-line `symbol` (own address)
  plus `targets` (operand literals that matched), with a documented
  `annotation_method` (24-bit 68K / 16-bit Z80 bus mask). Symbols from other
  address spaces never annotate.
- Deterministic processor control: `cpu_pause`, `cpu_run`, `cpu_step_over`,
  `cpu_step_out` — with live running-state reporting.
- Execution breakpoints: `cpu_breakpoint_set`, `cpu_breakpoint_list`,
  `cpu_breakpoint_remove` — MCP-managed breakpoints that pause the selected
  processor. `cpu_breakpoint_set` accepts optional conditions: `condition`
  `greater`/`less`/`range` filters by the program counter (range bounds are
  exclusive), and `break_on_counter` pauses only on every Nth native hit
  (ignored hits never stop the system). `cpu_breakpoint_list` reports
  `enabled`, the condition fields, and the native `hit_count`.
- Watchpoints: `cpu_watchpoint_set`, `cpu_watchpoint_list`,
  `cpu_watchpoint_remove` — byte ranges with read/write/any access filtering,
  live hit counters, and deterministic hit-and-pause through the Exodus
  debugger path. Breakpoints and watchpoints are purged safely on
  `rom_load` with one audited invalidation batch; list views carry creation
  provenance (context, target generation, ROM) without exposing control ids.
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
- `cpu_debug_events_list`: bounded forensic event history (100 records) with
  `offset`/`limit` pagination, `truncated` flag, and `total`. Whenever a
  managed breakpoint or watchpoint stops execution, a structured
  `debug-event` artifact records the managed resource id, owner context, CPU,
  triggering PC, address space, watched effective address, access direction,
  requested range, hit count, target generation, frame token, and timestamp;
  access width, value before/after, transferred value, and decoded
  instruction bytes are reported as `null` with a "not exposed by native API"
  note rather than presenting zero as data. Counter gaps caused by
  sampling/truncation are preserved via hit-count monotonicity.
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
  ring/timeout limit is never reported as complete coverage.
- Symbols: `symbols_set`, `symbols_list`, `symbols_clear`, scoped to an
  analysis context.

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
  metadata — liveness (frame token advances while running) and paused
  determinism (identical hashes) validated. The frame buffer is read without
  pausing, so `system_paused_during_read` is always false and
  `capture_consistency.state` is `live` (the frame token identifies the
  rendered frame). Optional `capture_mode: "paused"` makes the frame match a
  temporally atomic instant. The artifact's capture provenance records the
  frame token, target generation, and ROM identity.
- `vdp_memory_read`: VRAM, CRAM, and VSRAM through the proven timed-buffer
  path. Raw views (`hexdump`, `array_u8`, `raw_base64`), big-endian
  `array_u16` words, and a decoded CRAM view expanding 9-bit RGB entries into
  8-bit RGB (`-RRR-GGG-BBB-` channel layout). Reports
  `system_paused_during_read` when execution had to be stopped and the
  standardized `capture_consistency` object (atomic for a paused timed-buffer
  read); optional `capture_mode: "paused"` makes the sample temporally
  atomic.
- `vdp_memory_export`: artifact-first binary export of arbitrary
  VRAM/CRAM/VSRAM ranges — the raw bytes land in an immutable
  `vdp-memory-export` artifact (application/octet-stream) with SHA-256,
  size, URL, and the versioned provenance envelope (address domain, byte
  order, device, target generation, honest `capture_consistency`), so large
  regions never travel as Base64 through tool responses. Target caps are
  validated server-side (vram 65536, cram 128, vsram 80; length defaults to
  the full buffer); optional `capture_mode: "paused"` makes the sample
  temporally atomic (one explicit pause/resume cycle).
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
- `vdp_capture`: one bounded atomic VDP capture. It acquires the capture
  guard once, reads status/registers, the frame buffer, CRAM, VSRAM, selected
  VRAM ranges, the sprite table, and scroll data, then restores the prior run
  state; a `vdp-capture-manifest` links all raw and derived artifacts to one
  `capture_id` and `frame_token`. Callers select expensive components
  (`include_frame`/`include_cram`/`include_vsram`/`include_vram` with a
  131072-byte `vram_length` cap/`include_sprite_table`) and the manifest
  reports each omitted component with its reason. A `vdp-render-manifest`
  artifact describes one completed frame: display geometry, plane/window
  configuration, scroll bases and decoded offsets, palette state, sprite
  link-chain/display order, visible sprite cell bounds, tile/name-table
  references, priority data, and renderer assumptions. VDP-specific semantics
  are preserved in every decoded field (big-endian VRAM words, CRAM 9-bit
  packing, high-nibble-left tile pixel order, name-entry bits, interlace
  state). `vdp_tile_export`, `vdp_plane_export`, `vdp_sprite_table`, and
  `vdp_pixel_info` optionally consume a compatible capture via
  `vdp_capture_id`, making repeated inspection deterministic (byte-identical
  reuse, `vdp_capture_reused`) and avoiding repeated pauses.

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
  documented same-path cartridge reload described under `rom_load`. A
  `kind: "soft"` request is intentionally rejected with
  `unsupported_plugin`: the fork/plugin now contain the versioned native
  reset-interface scaffold, but it is not advertised until the M68000
  architectural reset-vector fetch observer and RAM/VDP preservation checks
  are implemented. The server never emulates reset with register or memory
  writes.
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
  pagination, and retained-window metadata on truncated responses. Externally
  observed run-state transitions are recorded here as `run_state_change`
  events with the observed generation (never advancing it).
- `context_mutation_log`: the per-context projection of the audit stream
  (target mutations only; lock lifecycle stays global).
- `state_save`, `state_load`, `state_list`: context-scoped system snapshots
  through the emulator's native save-state path (ZIP format), each verified
  with SHA-256 and size and carrying provenance (context, target generation,
  ROM path and SHA-256, optional control id, and `saved_run_state` — the last
  observed run state at save time, honest `"unknown"` without an
  observation). `state_save` does not mutate the target; `state_load` does
  and reports before/after generations, `capture_consistency.state:
  "state_restored"`, `saved_run_state`, and `final_run_state` (observations
  describe the restored instant until the system runs again; no defensive
  pause after a restore is needed). Lists flag entries stale for the loaded
  ROM and generation-mismatched while preserving them for historical
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
  exactly what was compared, and a partial comparison carries a note that it
  is NOT full header-checksum validation. The response also carries the shared
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
- `annotation_list`: bounded, paginated view (default 20, cap 100, `truncated`+`next_offset`) with filters for query substring, tags, category, kind, address space, and staleness (`stale`/`stale_reason` `rom_sha256_mismatch`/`target_generation_mismatch`, `stale_only`/`include_stale` with `stale_excluded` honesty). Preserves history across ROM loads.
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
  capturing per-step VDP frame tokens and final M68K registers (pc/a7/d0) for
  both runs — restores the initial state afterwards (caller-provided
  `initial_state_id`, or a fresh snapshot of the current machine), and
  reports `deterministic` true/false with named checks plus a
  `replay-manifest/1` artifact recording both runs, the checks, and the
  methodology. Recording (run 1) and replay verification (run 2) share one
  code path, so a mismatch is a real emulator nondeterminism signal rather
  than a harness artifact.

## Phase 9 workflow ergonomics (one-shot instrumentation, run-until, state override)

- `one_shot: true` on `cpu_breakpoint_set` / `cpu_watchpoint_set`: the server
  marks the instrument as one-shot in its resource provenance. Whenever the
  emulator is observed paused, a housekeeping sweep reads the native
  breakpoint/watchpoint lists and proves a fired break by the native hit
  counter (a positive multiple of the break counter N — the core increments
  on every passing location hit and breaks on multiples of N). A fired
  one-shot instrument is removed through the audited mutation path
  (`one_shot_sweep` audit entries with `one_shot_hit` detail), a structured
  debug event records the stop evidence (resource, CPU, triggering PC from
  `regs_get`, watched address/access for watchpoints, hit count, generation,
  frame token), and `emulator_status` reports the removals
  (`one_shot_removals`) plus the attribution. A one-shot instrument that
  never fires stays armed until it does or until a ROM reload purges managed
  resources; non-one-shot fired instruments get the attribution but are never
  removed.
- `run_until_breakpoint` / `run_until_watchpoint`: one-shot run-to-instrument
  wrappers. One call arms the instrument (same conditions/access semantics as
  the set tools), runs the system under exclusive control for the whole
  window (caller `control_id` reused, otherwise an internal lock), polls
  `emulator_status` every 100 ms (cache bypassed) until the instrument proves
  fired, and reports the stop evidence: `stop_reason`, resource id, `hit_count`,
  `triggering_pc` (+ hex), registers, `pause_source:
  breakpoint_or_watchpoint`, watched address/access for watchpoints, the
  debug `event_id`, and the generation span. The instrument is removed on
  every exit path — success, foreign-pause preemption
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
- `state_load` `run_state` override: `run_state: "restore" | "paused" |
  "running"` (default `restore` keeps the snapshot's saved run state, exactly
  today's contract). `paused`/`running` issue a post-load `cpu_control`
  inside the same control window, audited under the `state_load` tool with
  `reason: "state_load run_state override"`; the response reports
  `run_state_override` and the final run state from the overridden payload.
  An override failure is observable, never silent: the load already applied,
  and the error carries `state_loaded: true`, the requested state, and the
  un-overridden `final_run_state`.

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

All delivered phases are validated live against Kid Chameleon on the
reference harness, in addition to unit and integration tests:

- Pause/run, M68K/Z80 single-instruction steps, and the breakpoint lifecycle,
  including the conditional-breakpoint surface validated live against the
  rebuilt plugin: location-condition echo and list agreement, break-on-Nth-hit
  counters, validation errors, and the plain-breakpoint `break_counter`
  default (covered by `live-smoke.sh --full`).
- Symbol-aware disassembly is covered by dedicated unit tests for both CPUs:
  exact and bus-masked matches, `$`/`0x`/`h`-suffixed operand literal
  extraction, displacement-placeholder rejection, and cross-space isolation.
- Watchpoint lifecycle: hit pauses the system at the offending instruction
  with rollback confirmed, all address formats and access modes, exact error
  codes, removal, and purge-on-ROM-swap.
- Memory write with read-back, unaligned word-boundary writes, Z80 RAM, and
  error codes; `memory_diff` refine-a-candidate workflow.
- Frame-capture liveness and paused determinism; `vdp_memory_read` byte
  equality against `memory_read` on VRAM/CRAM/VSRAM; palette decode against
  the live frame; tile and plane exports reproducing title-screen art;
  sprite-table chain `[0, 4, 15]` in attract mode; `vdp_pixel_info`
  attribution of border, layer B sky, layer A text/building, and a bottom-row
  sprite; `vdp_command_dma_status` live native register/DMA observation with
  explicit unavailable command-latch fields.
- Save/list/load round trip with generation/ROM provenance and stale flags;
  `target_reset(kind: "soft")` is live-verified to fail safely with
  `unsupported_plugin` on the current fork/plugin scaffold, without a native
  action or register/memory-write fallback;
  frame advance and input with a 3-button controller; coverage capture;
  watchpoint-triggered trace capture; ROM header parsing and checksum
  validation.
- Artifact provenance: a RAM dump captured at `0xFF0000` searches and diffs at
  `0xFF0000` with no caller restatement; comparing M68K RAM to Z80 RAM fails
  with `incompatible_provenance` by default and warns when forced; legacy
  artifacts without capture metadata report `provenance_unknown`; the
  `rom_identity` object (file SHA-256, header title/serial, file-based Sega
  checksum) is computed from a real cartridge file with honest completeness
  facts; `data_hex` and base64 writes normalize to the same bytes with the
  same audit hash; `verify_readback` reports exact matches and mask/transform
  differences.
- Capture consistency: `memory_snapshot_capture` on a running ROM reports
  exactly one pause/resume cycle with all range artifacts and the manifest
  sharing one capture id and the atomic object; a capture with the system
  already paused performs no pause/resume mutations; a guarded
  (`capture_mode: "paused"`) read pauses once, reads, and restores (also on
  read failure); a composite VDP export whose chunked reads found the system
  running reports `composite_non_atomic` and never claims coherence; mixing
  artifacts from different composite captures fails with
  `incompatible_provenance` unless explicitly allowed; `state_load` reports
  `state_restored`.
- Atomic VDP capture: `vdp_capture` from a running ROM reports exactly one
  pause/resume cycle with all artifacts sharing one capture id and frame
  token; capture reuse (`vdp_capture_id`) makes two derived exports
  byte-identical without pausing; the render manifest identifies the sprite
  chain and name-table entries validated against `vdp_pixel_info`; VRAM and
  CRAM from different frames are never claimed coherent.
- Structured evidence: a synthetic variable-length 68K sequence forms one
  instruction-aware coverage block; a conditional branch produces two distinct
  observed edges across captures; Z80 and M68K trace/coverage artifacts retain
  their own address spaces; a known RAM write yields its debug event with PC,
  access direction, effective address, target generation, and linked trace,
  while a watchpoint timeout produces no synthetic event.
- Optimistic concurrency: two clients sharing one observed generation produce
  exactly one mutation and one `target_generation_conflict`; an unconditional
  single-agent mutation needs no lease or lock; a held control lock rejects
  foreign mutations while reads stay available; TTL expiry releases only the
  lock; ambiguous transport failures move the target to the documented
  resynchronization state; the audit stream reproduces ROM swaps,
  breakpoint/watchpoint/freeze setup and purge, and generation transitions.
- `experiment_run` fixture path: manifest artifact contents over HTTP plus
  the frame-capture artifact, and the internal control lock released with an
  audited `experiment_completed` reason.

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
