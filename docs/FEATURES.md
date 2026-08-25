# Features

This catalog lists every feature delivered in the `exodus-mcp` analysis
server, grouped by capability. Planned work is tracked in
[ROADMAP.md](ROADMAP.md); the [CHANGELOG.md](../CHANGELOG.md) records the
delivery history.

The MCP server currently exposes **64 analysis tools** spanning the delivered
roadmap phases 0-5: bridge and context foundations, memory and artifact
access, both processors, VDP graphics, deterministic controlled
experimentation, and advanced analysis. Everything below is covered by unit
and integration tests and exercised live against a running Exodus instance
(see [Validation](#validation)).

## Cross-cutting behavior

- **Artifact-first output.** Every response is a bounded summary; high-volume
  output (ROM bytes, dumps, traces, screenshots, analysis results) lands in an
  immutable artifact with SHA-256 digest, MIME type, size, direct local URL,
  and MCP resource URI. Artifacts support ETag and HTTP byte-range downloads,
  bounded previews, per-analysis-context scoping, and optional TTL retention.
- **Byte order and address space metadata.** Every multi-byte value reports
  its byte order and address space. The Mega Drive baseline is M68K
  big-endian, Z80 little-endian, and device-specific for VDP semantics; raw
  bytes preserve address order.
- **Flexible address formats.** Address arguments accept `$`-prefixed
  Motorola hex, `0x` hex, Zilog `h`-suffixed hex, and decimal integers; every
  response echoes the canonical parsed address.
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
- **System-specific prefixes.** Tools use clear `m68k_`, `z80_`, and `vdp_`
  prefixes rather than pretending behavior is generic.

## Bridge and platform foundation (Phases 0-1)

- `bridge_status`: plugin version, bridge connectivity, lifecycle, and
  initialization module count over the authenticated named pipe.
- `emulator_status`: loaded modules, running/paused state, device identity,
  and the current cartridge (path, file size, padded mapping size).
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
  width, permissions, and declared byte order.
- `memory_read`: bounded inline reads with explicit representation,
  effective-address echo, and decode validation against the declared byte
  order.
- `memory_dump`: artifact-first range output with hash and direct URL
  (8 MiB per-call cap).
- `memory_write`: debugger-path writes to CPU bus spaces
  (`SetMemorySpaceByte`) and entry-based memory devices (read-modify-write
  honoring byte order); timed-buffer spaces are refused with
  `write_not_supported`, ROM writes are discarded by the bus like real
  hardware, and every call is audited.
- `memory_search`: byte-pattern search over a consistent `memory-snapshot`
  artifact (or an existing dump/snapshot by id) — bounded inline matches plus
  a full-results artifact.
- `memory_diff`: cheat-finder comparison between two consistent snapshots.
  Cell widths byte/word/long with explicit byte order (big-endian default)
  and aligned scanning by default; modes `changed`, `unchanged`, `increased`,
  `decreased`, `changed_by` (signed delta), `equal_to`, and `in_range`;
  bounded inline matches plus a `memory-diff-results` artifact.
- `memory_freeze`, `memory_freeze_list`, `memory_freeze_remove`,
  `memory_freeze_clear`: server-managed value freezing with optional
  generation/control preconditions. A registered range is written once and
  re-applied at 20 Hz through the serialized bridge queue; the list tool
  surfaces write counts, last write time, provenance (context, target
  generation, ROM), and the last periodic-write error; the set is purged on
  `rom_load` with an audited invalidation batch.
- `artifact_get`, `artifact_preview`: metadata, bounded previews, and range
  retrieval guidance for every produced artifact.

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
  [TRACE-CRASH-INVESTIGATION.md](TRACE-CRASH-INVESTIGATION.md)).
- `cpu_trace_capture_watchpoint`: event-driven trace capture — the system
  runs toward a managed watchpoint (even from a paused state) and the window
  ends when it fires, reporting the fired watchpoint ids and stop reason.
- `cpu_coverage_capture`: execution coverage artifact from a bounded trace
  window — distinct executed addresses, merged consecutive-address spans, and
  a page histogram.
- Symbols: `symbols_set`, `symbols_list`, `symbols_clear`, scoped to an
  analysis context.

## VDP and graphics (Phase 3)

- `vdp_status`: all 24 registers plus typed decode of display enable,
  extended VRAM, name-table, pattern, and h-scroll-base fields, with
  completed-plane geometry.
- `frame_capture`: the live rendered frame as a PNG artifact with frame/timing
  metadata — liveness (frame token advances while running) and paused
  determinism (identical hashes) validated.
- `vdp_memory_read`: VRAM, CRAM, and VSRAM through the proven timed-buffer
  path. Raw views (`hexdump`, `array_u8`, `raw_base64`), big-endian
  `array_u16` words, and a decoded CRAM view expanding 9-bit RGB entries into
  8-bit RGB (`-RRR-GGG-BBB-` channel layout). Reports
  `system_paused_during_read` when execution had to be stopped.
- `vdp_tile_export`: consecutive 8x8 4bpp patterns as a scaled PNG plus a JSON
  pixel-index artifact, colored through a chosen CRAM palette line with
  optional transparent color 0 (high-nibble-left pixel order).
- `vdp_plane_export`: full unscrolled scroll-plane texture view (A, B, or
  window) rendered from the name table with flip, palette, and priority
  decoding; reports distinct tiles, priority counts, and a
  `coherent_snapshot` flag.
- `vdp_palette_export`: CRAM as four 16-color lines into a PNG swatch
  artifact plus a JSON decode artifact, with nonzero counts per line and the
  backdrop color inline.
- `vdp_sprite_table`: decoded sprite attribute table with positions, cell
  sizes, tile mapping, palette, priority, and a globally accurate link-chain
  walk (termination, cycle, dangling-link, and truncation flags), paged over
  at most 80 entries.
- `vdp_pixel_info`: per-pixel rendering attribution from the VDP full image
  buffer — source layer, name-entry mapping with tile/flip/priority, palette
  row and entry, shadow/highlight state with the resolved 8-bit color, h/v
  counters, and sprite cell data. Full image buffer info is enabled lazily and
  reported as pending until a frame has rendered with it active.

## Controlled experimentation (Phase 4)

- `rom_load`: controlled local cartridge replacement that preserves the
  previous running state; MCP-managed breakpoints, watchpoints, and frozen
  cell ranges are purged before the module unloads, with one audited
  invalidation batch naming every affected resource.
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
  pagination, and retained-window metadata on truncated responses.
- `context_mutation_log`: the per-context projection of the audit stream
  (target mutations only; lock lifecycle stays global).
- `state_save`, `state_load`, `state_list`: context-scoped system snapshots
  through the emulator's native save-state path (ZIP format), each verified
  with SHA-256 and size and carrying provenance (context, target generation,
  ROM, optional control id). `state_save` does not mutate the target;
  `state_load` does and reports before/after generations. Lists flag entries
  stale for the loaded ROM and generation-mismatched while preserving them
  for historical analysis.
- `frame_advance`: pause, execute exactly N rendered VDP frames, pause —
  reports the final frame token, before/after target generations, and times
  out with a diagnostic when the display is not rendering.
- `input_set`: press/release of up, down, left, right, a, b, c, start, x, y,
  z, and mode on a controller by player port, through the controller device
  input path.

## Advanced analysis (Phase 5)

- `rom_info`: the 256-byte Sega cartridge header parse (system type,
  copyright, domestic/overseas titles, serial/product/version, I/O support,
  ROM/RAM/backup-RAM windows, region) with header-checksum validation against
  the computed Sega sum, a reference 68K memory map, and a header-region
  artifact. Reference tables in
  [SEGA-HEADER.md](SEGA-HEADER.md).
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
  reproducible `experiment-manifest` artifact plus capped diagnostic output,
  and mirrors every step in the audit stream. Scripts never see the native
  pipe or capability; trust-in-operator-code applies (no OS sandboxing).

## Operations

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
  sprite.
- Save/list/load round trip with generation/ROM provenance and stale flags;
  frame advance and input with a 3-button controller; coverage capture;
  watchpoint-triggered trace capture; ROM header parsing and checksum
  validation.
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