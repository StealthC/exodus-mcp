# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project will use [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Native hardware-like `target_reset(kind: "soft")` for the compatible
  Exodus fork/plugin pair. The operation pulses M68000/Z80 reset lines,
  performs architectural SSP/PC vector fetches, preserves the prior run state,
  verifies Work RAM, Z80 RAM, VDP registers and exposed VDP buffers, and
  reports generation, preservation, and diagnostic details. Legacy plugins
  remain unavailable without any register/memory-write fallback.
- `sound_status`: bounded typed observation of YM2612 and SN76489/PSG state,
  including FM channels/operators, PSG tones/volumes, DAC and explicit device
  availability notes.
- `system_snapshot_capture`: bounded atomic cross-domain capture of named
  memory ranges, CPU registers, VDP state/buffers, and an optional frame in a
  single pause window, with a versioned manifest and shared provenance.
- `vdp_command_dma_status`: bounded read-only VDP command/DMA inspection.
  The native plugin returns the 24 raw VDP registers plus directly exposed DMA
  enable/status, length, source, and mode fields. Command-latch and other
  fields absent from the pinned SDK remain `null` with explicit observability
  notes; no state is reconstructed from bus writes and no CPU/VDP atomicity is
  claimed.
- The native soft-reset scaffold is now implemented: the fork exposes the
  version-1 reset interface and executes the native coordinator transaction;
  the plugin advertises it only when ready and reports full reset metadata.
  `kind: "hard"` remains unchanged.
- Dual-form address ergonomics across address-bearing tools: optional
  `address_space` accepts documented space-relative or processor-bus addresses
  and translates them to the native target domain; responses preserve legacy
  fields while adding `space_address`/`bus_address` coordinate pairs,
  including nested ranges, matches, disassembly lines, and debug events.
- Standardized `capture_consistency` object on every state-observing tool
  (`live` | `paused` | `atomic` | `state_restored` | `composite_non_atomic`)
  with execution paused/resumed facts, observed initial/final run states, and
  frame tokens where the VDP exposes them. Applied to memory reads/dumps/
  search, CPU registers and CPU reads, `vdp_memory_read`,
  `vdp_sprite_table`, the VDP exports, `vdp_pixel_info`, `frame_capture`, and
  `state_load` (`state_restored`).
- `memory_snapshot_capture`: bounded paused composite capture of one or more
  named ranges in one address space — pauses exactly once when running (zero
  cycles when already paused), reads every range while paused, restores the
  prior run state, and links all raw range artifacts plus a JSON manifest to
  one stable `capture_id`. Runs under exclusive control for the full window;
  the summary reports the pause/resume cycle, generation span, run states,
  frame tokens, and the atomic capture-consistency object.
- Optional capture guard: `capture_mode: "paused"` on `memory_read`,
  `memory_dump`, `vdp_memory_read`, `frame_capture`, and the CPU read tools
  makes one sample temporally atomic (pause once, read, restore — also on
  read failure); the default `"live"` never pauses timing-sensitive software.
- Envelope v2: provenance is now `artifact-provenance/2` and carries the
  `capture_consistency` object and, for composite captures, a stable
  `capture_id`. VDP exports share one capture id across their artifacts;
  `memory_diff` reports both capture ids and rejects snapshots from different
  composite captures with `incompatible_provenance` unless
  `allow_incompatible_provenance` is passed (prominent warning, no fabricated
  common address origin).
- Versioned artifact capture provenance (`artifact-provenance/1`): every
  artifact produced from capture data carries an immutable envelope with the
  address domain (requested/effective addresses in decimal and canonical hex,
  byte length, raw-byte ordering, declared byte order), owning device, target
  generation, ROM SHA-256 and path, frame token where available, CPU run
  state, capture consistency, and capture time. Artifacts without capture
  metadata report the honest `provenance_unknown` state. Applied to memory
  dumps and snapshots, search/diff results, ROM headers, traces, coverage,
  frames, VDP exports, save states, and experiment manifests.
- `artifact_describe`: returns the full typed provenance envelope of one
  artifact (or `provenance_unknown` for legacy artifacts); `artifact_get`
  descriptors carry the provenance reference. `artifact_preview` stays bounded
  and byte-oriented.
- `memory_search` derives address space, start address, byte length, and byte
  order from the snapshot's capture provenance when `snapshot_id` is given;
  parameters that duplicate provenance are assertions and are rejected with
  `provenance_conflict` on mismatch. Search results include the source
  snapshot descriptor and its captured address range.
- `memory_diff` requires compatible provenance by default (same space, range,
  byte length, ROM identity); cross-domain comparisons fail with
  `incompatible_provenance` unless `allow_incompatible_provenance: true` is
  passed, which returns a prominent warning with both source manifests. A
  common address origin is never fabricated; the comparison is anchored to the
  before snapshot's captured range and the default cell byte order derives
  from its captured byte order.
- Shared `rom_identity` object: SHA-256 of the loaded ROM file (when readable
  from the server host), file and padded mapping sizes, header title/serial,
  Sega checksum status computed over the file, mapped image base, and target
  generation — attached to `rom_info`, artifact provenance, and states
  (`rom_sha256`). An unreadable file is reported honestly.
- Honest checksum completeness in `rom_info`: `complete`, `bytes_covered`,
  `expected_range`, and `cap_reason` (`none` | `dump_cap` |
  `declared_end_beyond_file` | `degenerate_declared_range`) state exactly what
  was compared; a partial comparison carries a note that it is NOT full
  header-checksum validation.
- Hex write input: `memory_write` and `memory_freeze` accept `data_hex` (hex
  bytes with optional spaces) as a mutually exclusive alternative to base64
  `data`, normalize both to raw address-order bytes, echo bounded uppercase
  hex (`data_hex_echo`), and `memory_write` adds optional `verify_readback`
  reporting whether the space returned the exact written bytes.

- Target revision (optimistic concurrency): a process-local
  `target_generation` starts at 1, advances exactly once per successful
  target mutation, and is stamped on every tool response. Every mutating
  tool (`rom_load`, CPU control and steps, breakpoint/watchpoint
  create/remove, `memory_write`, `memory_freeze` family, `state_load`,
  `frame_advance`, `input_set`, trace/coverage captures, `experiment_run`)
  accepts optional `expected_target_generation` (validated inside the
  serialized scheduler immediately before the native action) and reports
  `target_generation_before`/`after`; a mismatch fails with
  `target_generation_conflict` and no native action. Ambiguous transport
  failures move the target to an `unknown`/resynchronization-required
  state; guarded mutations wait until a successful observation
  re-establishes the revision (and advances it).
- Optional exclusive control lock: `target_control_acquire`,
  `target_control_renew`, `target_control_release`, `target_control_status`
  — one process-wide lock (5 min default TTL, 1 h cap) whose `control_id`
  is a capability returned only to the acquirer. A held lock rejects
  foreign mutations with `target_control_held` but never blocks reads;
  expiry, context close, and bridge loss release the lock and record why.
- `target_audit_log`: the bounded global target audit stream with
  monotonic operation ids, UTC timestamps, normalized redacted arguments,
  target generations before/after or unknown, ROM identity, context and
  control-lock provenance, outcomes, structured failures, and created or
  invalidated resource ids — filterable by tool, context, control id,
  generation range, and time range, with pagination and retained-window
  metadata on truncated responses. `context_mutation_log` is now a
  per-context projection of this stream.
- Resource provenance: breakpoints, watchpoints, freezes, and states record
  originating context, control-lock audit id, creation time, ROM identity,
  and target generation. `rom_load` purges machine-bound resources with one
  audited invalidation batch (`resources_invalidated`); `state_list` flags
  entries stale for the loaded ROM and generation-mismatched while keeping
  them retrievable.
- `experiment_run` executes under exclusive control for its full duration:
  a caller-provided active `control_id` is reused, otherwise the server
  acquires an internal lock (audited `experiment_completed` on release)
  before loading `initial_state_id` and releases it after manifest
  finalization. Every step's tool call carries the injected context and
  control id.
- Symbol-aware disassembly: `m68k_disassemble` and `z80_disassemble` now
  resolve the analysis context's symbols into per-line annotations —
  `symbol` when the instruction address itself has a label, and `targets`
  when an operand literal (`$`-Motorola, `0x`, or Zilog `h`-suffixed hex)
  matches one, using the 24-bit 68K / 16-bit Z80 bus mask. Symbols declared
  for another address space never annotate; a payload without matching
  symbols passes through unchanged (`symbols_annotated` and
  `annotation_method` are added when any annotation applies).
- `GET /metrics`: operator endpoint with per-tool call/error counts and
  per-artifact-kind totals (loopback-only, `Store.OnPut` hook).
- Evidence annotations (P2): `annotation_create`, `annotation_list`,
  `annotation_get`, `annotation_update`, `annotation_delete`,
  `annotation_export` (`annotation-export/1`), `annotation_import` — context-
  scoped, `observation`/`hypothesis` kinds, ROM identity and target generation
  stamping, evidence links to artifacts/states/captures/trace events/symbols/
  debug resources, staleness flagging (`rom_sha256_mismatch` /
  `target_generation_mismatch`), bounded pagination, conflict handling, 500-
  per-context cap.
- `m68k_backtrace`: heuristic M68K stack walk (A7 plus optional A6 frame
  chain, executable-region filtering, symbol resolution, `capture_consistency`
  reporting).
- `state_diff`: read-only comparison of two `state_save` snapshots
  (metadata plus raw file byte diff into `state-diff-results` artifact, 8 MiB
  cap, bounded inline diffs).
- `deterministic_replay`: record and replay a declarative `frame_advance`-
  stepped `input_set` sequence twice from one state under exclusive control,
  verifying determinism via per-step frame tokens and final registers into a
  `replay-manifest/1` artifact.
- `cpu_register_condition_evaluate`: server-side register-condition primitive
  (`D0 == $1234`, `A7 >= $FF0000`, `&&`/`||`) for `cpu_breakpoint_set` hits;
  reads `regs_get`, documents pause/resume race, returns `matched`.
- Conditional execution breakpoints: `cpu_breakpoint_set` accepts optional
  `condition` (`greater`, `less`, `range` with exclusive `range_end` bound),
  `break_on_counter`, and `break_counter` (break on every Nth hit; ignored
  hits never pause the system, evaluated natively by the emulator core).
  `cpu_breakpoint_list` now reports `condition`, `range_end`,
  `break_on_counter`, `break_counter`, and the native `hit_count`.
  Validation is enforced identically server-side and in the plugin; plain
  calls keep their exact historical wire shape.
- `memory_diff`: cheat-finder comparison between two consistent memory
  snapshots per cell (byte/word/long with explicit byte order, big-endian
  default, and aligned scanning by default). Modes: `changed`, `unchanged`,
  `increased`, `decreased`, `changed_by` (signed delta), `equal_to`, and
  `in_range`. `snapshot_before_id` is required; `snapshot_after_id` is
  optional — without it the before range is read fresh into a snapshot
  (never a live racy scan). Returns bounded inline matches (address, before,
  after, delta) plus a full-results artifact (kind `memory-diff-results`).

- Artifact retention: `--artifact-ttl` / `EXODUS_MCP_ARTIFACT_TTL` (a Go
  duration such as `24h`) expires artifacts older than the TTL on a background
  sweep; the default keeps artifacts for the whole server session. Startup
  logging reports the retention policy.
- `memory_freeze`, `memory_freeze_list`, `memory_freeze_remove`,
  `memory_freeze_clear`: server-managed value freezing with optional
  generation/control preconditions.
  `memory_freeze` writes the pinned bytes once (like `memory_write`) and then
  re-applies them at ~20 Hz through the serialized bridge queue, undoing the
  program's own updates to the range; re-registering the same space+address
  updates the pinned bytes, `rom_load` purges the whole set with an audited
  invalidation batch, and both mutating calls are recorded in the target
  audit stream. The list tool reports byte
  length, write count, last write time, and the last periodic-write error;
  `memory_freeze_clear` drops every entry at once. Validated by unit tests and
  the live smoke (pinning across a running window, write-count growth,
  per-entry removal, bulk clear).
- Honest capture consistency everywhere: `system_paused_during_read` now
  propagates to `memory_read`, `memory_dump`, `memory_search`,
  `vdp_sprite_table`, `vdp_tile_export`, `vdp_plane_export`,
  `vdp_palette_export`, `vdp_pixel_info`, and `frame_capture` (today it
  existed only on `vdp_memory_read`). The flag reports whether the handler
  paused a running system to sample and restored it afterwards; no tool's
  run-state behavior changed.
- Run-state observability: `emulator_status` reports `pause_source` (`mcp`,
  `ui_or_external`, `breakpoint_or_watchpoint`, `unknown`) and
  `last_run_state_change` (UTC). The server attributes the state to the last
  run-state-affecting MCP action (cpu controls, steps, `frame_advance`,
  `state_load`, `rom_load`); transitions observed without any MCP action
  (UI pauses, other bridge clients, native stops) land in the audit stream
  as `run_state_change` events with the observed target generation and never
  advance it.
- Address-domain hardening: `memory_spaces_list` reports each space's bus
  mapping (`bus`, `bus_base`, `bus_offset` with the documented Mega Drive
  baseline: RAM → `0xFF0000`, Z80 RAM → `0xA00000`, ROM → `0x000000`, VDP
  buffers explain why they are not linearly mapped); `out_of_range` failures
  from `memory_read`/`memory_dump` include the valid canonical hex range; and
  `memory_dump` now returns an `effective_address` like `memory_read` does.
- `vdp_sprite_table` chain-vs-table divergence: `chain_visible_count`
  (hardware-rendered link-chain length) next to `table_entry_count`
  (populated entries), with a `warning` when the chain renders fewer sprites
  than the table holds (mid-update or stale links).
- `mega_drive_memory_map`: structured operational Mega Drive memory map
  combining the reference bus map with the live target — 7 reference regions
  (ROM, unmapped, Z80 RAM, YM2612, I/O, VDP ports, Work RAM) with CPU-visible
  range, mirrors/mask, backing device, read/write capability, timing caveats,
  byte order, and I/O semantics, plus live existence cross-checked against
  `memory_spaces_list`.
- `memory_search` wildcard patterns and alignment: `??`/`?` nibble/byte
  wildcards and optional power-of-two `alignment`, with `parsed_pattern` and
  `pattern_mask_hex` serialized into the result artifact for reproducibility;
  the exact-byte mode is unchanged.
- Schema contract hardening: address arguments share one `oneOf` schema
  (JSON integer or `$`/`0x`/`h`/decimal strings); tool arguments are strictly
  decoded — unknown properties are rejected with `invalid_params` naming the
  full JSON path; every successful response injects `result_type` (tool name)
  and `schema_version: "1"`; address-bearing outputs normalize to numeric
  `address`, canonical uppercase `address_hex`, `address_space`,
  `effective_address`/`effective_address_hex`, and
  `address_width_bits`/`address_mask_hex` where bus-mapped.
- `cpu_trace_capture` now also returns a versioned `cpu-trace-jsonl` artifact
  (application/jsonl) with one JSON event per executed instruction (CPU,
  address space, PC numeric/hex, opcode bytes, instruction length,
  mnemonic/operands, cycle position, target generation, capture id, frame
  token) plus typed `control_flow` facts that are `unknown`/nil when the
  native trace does not provide them — never inferred from disassembly text.
  Optional filters (`address_range_start`/`address_range_end`,
  `include_rom`/`include_ram`, `retain_repeated`) are stored in provenance
  and summary.
- `cpu_coverage_capture` now emits `cpu-coverage/2`: instruction-aware basic
  `blocks` (start/end address, instruction and execution counts, member
  addresses) and observed `edges` (from/to/count) instead of byte-adjacent
  span merging, plus capture conditions, ROM identity, address-space
  requirements, filters, legacy `ranges`, and per-section `truncation` facts —
  a trace ring/timeout limit is never reported as complete coverage.
- Forensic debug events: whenever a managed breakpoint or watchpoint stops
  execution, a structured `debug-event` artifact records the managed resource
  id, owner context, CPU, triggering PC, address space, watched effective
  address, access direction, requested range, hit count, target generation,
  frame token, and timestamp; native-unavailable fields (access width, values
  before/after, transferred value, decoded instruction bytes) are `null` with
  a documented note, never zero. `cpu_trace_capture_watchpoint` links its
  trace artifact to the exact stop event and distinguishes timeout, a
  different resource firing, and the requested watchpoint firing.
- `cpu_debug_events_list`: bounded forensic event history (100 records) with
  `offset`/`limit` pagination, `truncated` flag, `total`, and counter-gap
  preservation via hit-count monotonicity.
- `vdp_capture`: one bounded atomic VDP capture under the capture guard —
  status/registers, frame buffer, CRAM, VSRAM, selected VRAM ranges, sprite
  table, and scroll data — with component selection (`include_frame`,
  `include_cram`, `include_vsram`, `include_vram` with a 131072-byte
  `vram_length` cap, `include_sprite_table`) and a `vdp-capture-manifest`
  linking all artifacts to one `capture_id` and `frame_token`; a
  `vdp-render-manifest` artifact carries display geometry, plane/window and
  scroll configuration, palette state, sprite link-chain/display order,
  tile/name-table references, and renderer assumptions. VDP semantics are
  preserved (big-endian VRAM words, CRAM 9-bit packing, high-nibble-left tile
  pixel order, name-entry bits, interlace state). `vdp_tile_export`,
  `vdp_plane_export`, `vdp_sprite_table`, and `vdp_pixel_info` accept
  `vdp_capture_id` for deterministic, pause-free byte-identical reuse.
- `vdp_memory_export`: artifact-first binary export of arbitrary
  VRAM/CRAM/VSRAM ranges (roadmap Phase 9) — the raw bytes land in an
  immutable `vdp-memory-export` artifact (application/octet-stream) with
  SHA-256, size, URL, and the versioned provenance envelope (address domain,
  byte order, device, target generation, honest `capture_consistency`).
  Target caps are validated server-side (vram 65536, cram 128, vsram 80;
  length defaults to the full buffer); optional `capture_mode: "paused"`
  makes the sample temporally atomic.
- `input_sequence`: atomic multi-step controller scheduling (roadmap Phase
  9) — one call holds the listed buttons on one player port for N frames per
  step (1-64 steps, 1-60 frames; always down → advance → up), under
  exclusive control for the whole window (caller `control_id` reused or an
  internal lock), with per-step frame tokens, per-step audit entries, and
  release of the failed step's buttons before returning — no input state
  left behind.
- `target_reset`: discoverable reset tool (roadmap Phase 9) — `kind: "hard"`
  performs the documented same-path cartridge reload (module reload
  reinitializes the system and purges all managed debug resources in one
  audited batch) using the current cartridge path from `emulator_status`,
  reporting `reset_source: "hard"`, the run state, and the generation span;
  with no known cartridge it fails read-only with `no_rom_loaded`. `kind:
  "soft"` is rejected as not delivered (design pending).
- State run-state contract: snapshots record `saved_run_state` (the last
  observed run state, honest `"unknown"` without an observation); `state_save`
  and `state_list` echo it, and `state_load` reports `saved_run_state` plus
  `final_run_state` so no defensive pause after a restore is needed (roadmap
  Phase 9).
- `state_load` run-state override (roadmap Phase 9): `run_state: "restore" |
  "paused" | "running"` forces the restored state through a post-load
  `cpu_control` inside the same control window, audited under the
  `state_load` tool; the response reports `run_state_override` and the final
  run state, and an override failure surfaces with the load already applied
  (`state_loaded: true`), never silently.
- One-shot instrumentation (roadmap Phase 9): `one_shot: true` on
  `cpu_breakpoint_set` / `cpu_watchpoint_set` auto-removes the instrument
  through the audited mutation path once its native hit counter proves a
  break fired (a positive multiple of the break counter N), checked by a
  housekeeping sweep at the next paused observation; the removal lands in the
  audit stream (`one_shot_sweep`), a structured debug event records the stop
  evidence, and `emulator_status` reports `one_shot_removals` plus
  `pause_source: breakpoint_or_watchpoint`.
- `run_until_breakpoint` / `run_until_watchpoint` (roadmap Phase 9): one-shot
  run-to-instrument wrappers under exclusive control for the whole window —
  arm, run, poll (100 ms, cache bypassed) until the instrument proves fired,
  then report the stop reason, triggering PC, hit count, registers, watched
  address/access, and debug event id; the instrument is removed on every exit
  path (success, foreign-pause preemption `run_until_preempted`, timeout
  `run_until_timeout` with a 30000 ms default window, cancellation), so no
  armed instrumentation or polling is left behind.
- Run-state stop attribution: `emulator_status` now reports
  `pause_source: breakpoint_or_watchpoint` after any MCP-managed
  breakpoint/watchpoint stop (the tracker remembers the most recently proven
  native stop; cleared by any MCP run-state action or running observation),
  and the `run_state_change` audit entry carries the attribution — no plugin
  changes required.
- `build-windows.bat` also installs `exodus-mcp.exe` into the Exodus install
  root (`EXODUS_MCP_EXODUS_DIR`) next to the emulator, so the server can be
  started manually from that folder.
- Bare-launch auto-detection: when `exodus-mcp.exe` starts with no bridge
  configuration (`--exodus`, `--pipe-name`, `--pipe-capability` all absent),
  it checks for `Exodus.exe` beside its own executable and adopts it as the
  target, launching Exodus from the install root. A plain double-click or an
  MCP client pointing at the installed exe starts the whole pair.

### Changed

- Roadmap cleanup: `docs/ROADMAP.md` now lists only open work. Completed
  phases and workflow features remain in `docs/FEATURES.md`, while rejected
  and deferred ideas were removed from the active roadmap. The remaining
  backlog is multi-instance orchestration, the unfinished audio capture and
  audio analysis items, safe native soft reset, and release automation.
- **Breaking:** context leases are removed outright — `context_lease_*`,
  `lease_id`, and `requireLease` no longer exist; ordinary mutations need no
  lease, lock, or generation precondition. There is no legacy compatibility
  release: the server is used only in-house.
- `memory_freeze` family is no longer lease-gated; the freeze entries carry
  provenance and accept the optional concurrency preconditions.
- `state_save` no longer requires a lease (it does not mutate the target);
  snapshots carry generation/ROM/control provenance.
- `context_close` releases any control lock acquired under the context and
  records the reason; it no longer has lease semantics.
- `cpu_pause`, `cpu_run`, `m68k_step`, `z80_step`, `cpu_step_over`,
  `cpu_step_out`, and the trace/coverage captures advance the target
  generation and accept the optional preconditions.
- `scripts/live-smoke.sh --full` validates the new contract: read ->
  guarded mutation, `target_generation_conflict` without native action,
  control-lock lifecycle with TTL expiry, holder-vs-foreign mutations,
  reads under lock, experiment internal-lock release, and audit queries.
- README rewritten: the old copy still described the project as a foundation
  shell that could not read from a running Exodus; it now summarizes the
  63-tool catalog by roadmap phase, the delivered status, configuration, and
  the MIT license.
- License: `exodus-mcp` is now MIT-licensed (`LICENSE`); the Exodus MIT notice
  remains applicable to the submodule and any redistributed Exodus-derived
  material.
- `docs/ROADMAP.md` tracks only remaining work: the open Phase 5 item
  (multi-instance orchestration), planned Phases 6-8 (audio, advanced
  debugging, deterministic replay), the deferred fork-side improvements, the
  operations backlog, and recorded design constraints. Phase 7 records what
  shipped this cycle (symbol-aware disassembly; conditional execution
  breakpoints with native hit counters, location conditions, and
  break-on-Nth-hit) and what remains (register-based conditions, M68K
  backtrace, state diff). A new `docs/FEATURES.md` catalogs the delivered
  63-tool feature set by capability with cross-cutting behavior, design
  rules, and live-validation status; README, AGENTS, and DEVELOPMENT point
  at the delivered/planned split.
- `AGENTS.md` documents the verified WSL self-service build/run/validate
  loop (`stop-windows.sh` → `build-windows.sh` → `run-windows.sh` →
  healthz version stamp → `live-smoke.sh --full` → `test.sh --windows-live`)
  and the `_meta` requirement for the modern dispatcher on raw HTTP, so
  pair lifecycle and plugin-side validation no longer require the user.
- `scripts/live-smoke.sh --full` covers the conditional-breakpoint lifecycle
  (range-condition echo/list/remove) and asserts the plain-breakpoint
  `break_counter` default.
- `m68k_backtrace`: heuristic M68K stack walk (roadmap Phase 7) from A7 (the
  active stack pointer, USP or SSP per the SR supervisor bit) with an optional
  A6 frame-pointer chain and context-symbol resolution. Frame 0 is the live
  PC; every other frame is flagged per method (`register_pc`,
  `frame_pointer`, `stack_scan`), confidence (high/medium/low), and a
  heuristic note, with the composite `capture_consistency` object for its
  live reads. Never claims execution-verified call sites.
- `state_diff`: read-only comparison of two `state_save` snapshots (roadmap
  Phase 7) into a `state-diff-results` artifact — snapshot metadata diff plus
  a raw snapshot-file byte diff (per-byte counts, contiguous diff regions,
  bounded inline before/after hex, first-1KB previews, 8 MiB comparison cap).
  The register/memory/VDP semantic sections are reported as requested but not
  performed because decoding them requires a mutating `state_load`.
- `deterministic_replay`: record-and-replay determinism verification (roadmap
  Phase 8) — runs one declarative input sequence (`input_set` +
  `frame_advance` steps) twice from the same saved state under exclusive
  control, compares per-step VDP frame tokens and final M68K registers, and
  stores a `replay-manifest/1` artifact reporting `deterministic` plus named
  checks and the methodology. Restores the initial state afterwards
  (caller-provided `initial_state_id` or a fresh snapshot of the current
  machine).
- Documentation sync: `docs/ROADMAP.md` now tracks only remaining work — the
  delivered P0–P2 interoperability backlog, Phase 7 (advanced debugging), and
  Phase 8 (deterministic replay) sections were removed and replaced by a
  delivered-status summary pointing at the feature catalog; the delivered
  `/metrics` item was dropped from Operations; the former backlog
  cross-cutting delivery rules now stand as "Delivery rules for remaining
  phases". `docs/FEATURES.md` gained the missing delivered catalog entries
  (`mega_drive_memory_map`, `vdp_capture`, `cpu_debug_events_list`, JSONL
  trace, `cpu-coverage/2` blocks/edges, schema contract hardening, wildcard
  search) and README now reports the full 80-tool catalog with Phases 7-8
  delivered.
- `docs/ROADMAP.md` gains Phase 9 (workflow ergonomics, planned) from the
  2026-08-29 Chakan reverse-engineering session report: `target_reset`,
  combined atomic system snapshot, one-shot/run-until instrumentation,
  `input_sequence`, `vdp_memory_export`, dual-form addresses, the
  `state_load` run-state contract, and a VDP command/DMA decoder, with the
  report points already covered elsewhere recorded as not re-adopted.
- Plugin `emulator_status` now reports the cartridge even when it was loaded
  through the Exodus UI: the plugin recovers the loaded program module's file
  path (`rom.path_source: "loaded_module"`), stats `size_bytes` from the file,
  and keeps `padded_size_bytes` unknown (0) because only the MCP `rom_load`
  module creation computes it (`mcp_load` tracks bridge-loaded cartridges;
  `none` when nothing is loaded). Plugin version 0.7.1. `rom_load` and
  `cpu_run` tool descriptions now document the reset recipe: read
  `emulator_status.rom.path`, reload the same path with `rom_load` (the
  module reload reinitializes the system and purges all managed debug
  resources in one audited batch), then `cpu_run` to resume.

### Removed

- `context_lease_acquire`, `context_lease_renew`, `context_lease_release`,
  `context_lease_list` tools and the `lease_id` argument everywhere; the
  per-context `LeaseRegistry` and per-context mutation ledger were replaced
  by the global target state and audit stream.

### Fixed

- Plugin `_romPath`/`_romSizeBytes`/`_romPaddedSizeBytes` were never
  initialized in the constructor: `emulator_status` could report garbage
  sizes before the first MCP `rom_load`. The members now default to
  empty/zero; a discovered (UI-loaded) cartridge reports `size_bytes` from a
  file stat and `padded_size_bytes: 0` (unknown) instead of uninitialized
  memory. Surfaced by the new `loaded_module` discovery path.
- `cpu_breakpoint_set` echoed `break_counter: 0` instead of the documented
  default `1` when `break_on_counter` was false: the plugin's `ParseUnsigned`
  zeroes its output on an absent parameter, and the default restore only ran
  on the break-on-counter path. The default is now restored in every path,
  `cpu_breakpoint_list` reports the effective default (`1`) when the feature
  is off so set/list echoes agree, and a malformed `break_counter` is
  rejected instead of silently treated as absent. Caught by the direct
  post-rebuild HTTP validation; the live smoke now asserts the default.

### Security

- Nothing yet.

## [0.1.0] - 2026-08-25

### Added

- `experiment_run`: runs operator-authored experiment scripts (`*.py`) or
  declarative fixtures (`*.json`) from the configured scripts directory
  (`EXODUS_MCP_SCRIPTS_DIR` / `--scripts`; the launcher defaults it to
  `<repo>\scripts\experiments`). The Go server mediates every step against
  an allowlist (`input_set`, `frame_advance`, `state_save`, `state_load`,
  `memory_write`, `memory_read`, `memory_dump`, `memory_search`,
  `frame_capture`, `vdp_status`, `vdp_pixel_info`, `vdp_sprite_table`,
  `m68k_registers`, `z80_registers`, `cpu_coverage_capture`), injects the
  experiment's context and lease, and records a reproducible
  `experiment-manifest` artifact plus capped diagnostic output.
  Python scripts use a bounded JSON-lines duplex (stdin/stdout) documented in
  `docs/DEVELOPMENT.md`; fixtures are plain versioned step lists. Optional
  `initial_state_id` loads a snapshot before the first step. Scripts never
  see the native pipe or capability; recursion, `rom_load`, global CPU
  control, and context/lease tools are not allowlisted. New flags:
  `--scripts`, `--python`, `--experiment-timeout`, `--experiment-max-steps`,
  `--experiment-max-output-bytes` (defaults 200 steps, 1 MiB output).
- `scripts/experiments/smoke-input.json` (lease-gated input/frame/capture
  fixture) and `scripts/experiments/title-scan.py` (documented Python
  example). `scripts/live-smoke.sh --full` now validates the fixture path:
  manifest artifact contents over HTTP and the frame-capture artifact, and
  purges leftover session leases before acquiring its own (mirroring the
  existing breakpoint/watchpoint purge).
- New artifact kinds `experiment-manifest` and `experiment-output`, plus
  script-published artifacts (e.g. `experiment-observations`) with validated
  MIME types and per-artifact byte caps.

### Changed

- `tools/list` and `tools/call` dispatch through a shared registry lookup;
  `experiment_run` steps execute the exact same handlers as MCP clients.

### Added

- Context lease tools: `context_lease_acquire`, `context_lease_renew`,
  `context_lease_release`, and `context_lease_list`. One exclusive lease per
  analysis context with TTL-based expiry and release-on-close; every Phase 4
  mutation tool requires it. Pre-existing control tools (`rom_load`,
  pause/run, steps, breakpoints, watchpoints) keep their established
  behavior.
- `context_mutation_log`: bounded per-context audit trail of every Phase 4
  mutation with lease id, echoed arguments, and timestamp.
- `state_save`, `state_load`, `state_list`: context-scoped system snapshots
  through the emulator's native save-state path (ZIP format via the
  `ISystemGUIInterface` cross-cast in the plugin), verified with SHA-256 and
  size. Snapshots anchor under `EXODUS_MCP_STATES_DIR` (new `--states`
  flag; default `%TEMP%\exodus-mcp\states`).
- `memory_write`: debugger-path writes to CPU bus spaces
  (`SetMemorySpaceByte`) and entry-based memory devices (read-modify-write
  honoring the declared byte order); timed-buffer spaces are refused with
  `write_not_supported`; every call records audit metadata and a mutation
  log entry.
- `frame_advance`: pause, execute exactly N rendered VDP frames, pause;
  reports the final frame token and times out with a diagnostic when the
  display is not rendering.
- `input_set`: press/release buttons (up/down/left/right/a/b/c/start/x/y/
  z/mode) on a controller by player port through the controller device
  input path.
- Plugin bridge operations `mem_write`, `state_save`, `state_load`,
  `frame_advance`, and `input_set` (plugin version 0.7.0), plus a strict
  RFC 4648 `Base64Decode` wire helper with unit vectors.
- `scripts/live-smoke.sh --full` now exercises the Phase 4 surface: lease
  lifecycle, memory write with read-back, frame advance, input press and
  release, save/list/load round trip, and the mutation log.
- `memory_search`: raw byte-pattern search over a consistent snapshot. It
  either dumps a `memory-snapshot` artifact for the range (never a live racy
  scan) or searches an existing `memory-dump`/`memory-snapshot` artifact by
  id without any new read. Returns bounded inline matches plus a
  full-results artifact (kind `memory-search-results`).
- `rom_info`: parses the Sega Mega Drive cartridge header at 0x100 (system
  type, copyright, domestic/overseas titles, serial/product/version,
  I/O-support codes, ROM/RAM/backup-RAM windows, region), validates the
  stored header checksum against the computed Sega sum, and reports the
  declared plus reference 68K memory mapping. Attaches a header-region
  artifact. `target_info.rom` now summarizes the loaded cartridge.
- `cpu_trace_capture_watchpoint`: event-driven trace capture. The
  `trace_capture` bridge op accepts an optional `watchpoint_id`; the system
  runs toward the managed watchpoint (even from a paused state), the window
  ends when it fires, and the response reports the fired watchpoint ids plus
  the stop reason. New tool wires it up.
- `cpu_coverage_capture`: execution coverage artifact built from a bounded
  trace window — distinct executed addresses, merged consecutive-address
  spans, and a page histogram (kind `cpu-coverage`).
- Plugin: `emulator_status` now reports the ROM loaded through `rom_load`
  (path, file size, padded mapping size) so server-side tools can bound
  header and checksum reads; `rom_load` echoes the same sizes.
- `docs/SEGA-HEADER.md`: Mega Drive cartridge header reference with data
  tables, the checksum algorithm, region/product decoding, and the source
  documents used to derive the parser.

### Changed

- The `trace_capture` bridge op gains an optional `watchpoint_id` parameter
  (event-driven mode). Plain captures keep their shape; watchpoint mode
  forces the run during the window and restores the prior run state,
  matching the established trace-capture contract.
- `cpu_trace_capture` now surfaces the plugin's mode-specific sampling note
  verbatim instead of hardcoding one server-side string.

### Changed

- The mutating Phase 4 tools (`state_save`, `state_load`, `memory_write`,
  `frame_advance`, `input_set`) require the exclusive lease of their
  analysis context; calls without one fail with `lease_required` and calls
  with a foreign lease id fail with `lease_invalid`.
- `docs/ROADMAP.md` marks Phase 4 complete and records the trace crash as
  resolved (see `TRACE-CRASH-INVESTIGATION.md`).

### Changed

- Build wrappers now default to `Release | x64` for the Exodus fork and the
  MCP plugin. Debug-CRT-only code in the plugin is guarded with `#ifdef
  _DEBUG`, and both wrappers install the complete binary set (exe,
  `System.dll`, `Assemblies/*.dll`, plugin) as one unit so stale or
  config-mixed DLLs never end up in the test install.

### Fixed

- `cpu_trace_capture` no longer crashes the emulator. The capture now routes
  the processor trace log through a temporary on-disk file (parsed by the
  server-side plugin itself) instead of unpacking the marshaled in-memory
  ring, configures tracing with the system stopped, and restores the prior
  run state. Requires the companion fork changes: a POD
  `SetTraceFileLoggingPathAscii` setter on `IProcessor`, an atomic
  `_traceLogEnabled`, and full device-DLL installation in
  `build-fork-windows.bat`.

### Added

- `vdp_pixel_info`: per-pixel rendering attribution from the VDP completed
  image buffer (source layer, name-entry mapping, palette entry,
  shadow/highlight with resolved color, sprite cell data). Enables full
  image buffer info lazily and fails with `pixel_info_pending` until one
  frame has rendered with attribution active.
- `vdp_tile_export`: exports consecutive 8x8 4bpp VRAM patterns as a scaled
  PNG artifact plus a JSON pixel-index decode, colored through a chosen CRAM
  palette line.
- `vdp_plane_export`: renders a full scroll plane (A, B, or window) as an
  unscrolled texture view into PNG and JSON artifacts, with plane geometry
  decoded from VDP register 16 and a snapshot-coherence flag derived from the
  plugin's per-read pause telemetry.
- `vdp_memory_read` responses now include `system_paused_during_read`,
  reporting whether the read had to stop a running system.
- `vdp_sprite_table`: decoded Mega Drive sprite attribute table with
  positions, cell sizes, tile mapping, palette, priority, and link-chain
  display order including termination/cycle/dangling detection; paged over
  at most 80 entries while always walking the full chain.
- `vdp_palette_export`: exports CRAM as four 16-color palette lines into a
  PNG swatch artifact and a JSON decode artifact, returning nonzero counts
  per line and the backdrop color inline.
- `vdp_memory_read`: inline VRAM, CRAM, and VSRAM reads through the plugin's
  timed-buffer path with explicit byte-order metadata. Representations cover
  raw views (`hexdump`, `array_u8`, `raw_base64`), big-endian `array_u16`
  words, and a CRAM-specific decode expanding 9-bit RGB palette entries into
  8-bit RGB with hex colors. CRAM words pack the channels as
  `-RRR-GGG-BBB-` (bits 1-3, 5-7, 9-11, with zero padding at bits 0, 4, 8). While the system runs, the plugin briefly stops
  execution around timed-buffer reads and restores the prior state; the
  response reports whether that happened.

### Fixed

- Generic `memory_read` (and therefore `memory_dump`) crashed the emulator
  with an access violation on every memory-kind space such as RAM blocks and
  the VDP buffers: bus metadata was derived from the space's processor
  pointer, which is null outside processor bus spaces. Bus metadata is now
  computed only for bus spaces.
- Foreign device memory reads in the plugin are wrapped in structured
  exception guards, so a fault inside emulator-owned objects now returns a
  diagnostic bridge error naming the faulting module and offset instead of
  terminating the emulator.

### Fixed

- The native plugin no longer truncates large bridge responses. On the
  message-mode `PIPE_NOWAIT` pipe, a full outbound buffer surfaces as
  `ERROR_NO_DATA` (or a zero-byte successful write); `WriteAll` treated
  both as fatal and abandoned the response mid-frame, which stranded the
  client until its deadline and made back-to-back paused `frame_capture`
  calls fail intermittently. Transient full-buffer conditions are now
  retried while the client drains, and the pipe outbound buffer grew from
  256 KiB to 512 KiB.
- `scripts/live-smoke.sh`: fixed breakpoint/watchpoint cleanup (wrong
  argument names sent numeric ids as JSON strings, so removals always
  failed with `invalid_params` and left armed debug state that froze later
  `cpu_run` calls), verified removals instead of asserting success,
  purged leftovers from earlier sessions, read capture digests through the
  artifact-first response (`summary.sha256`; the old path compared empty
  strings), added a consecutive paused-capture stress check, and verified
  that running state is actually restored at the end.

### Added

- `scripts/build-fork.sh`: builds the vendored Exodus emulator
  (`vendor/exodus/Exodus.sln`, Debug or Release x64) and installs the
  generated exe into the configured test install
  (`EXODUS_MCP_EXODUS_DIR`), under that install's emulator file name
  (`EXODUS_MCP_EXODUS_EXE`). This is the supported path for testing fork-side
  modifications; close the running emulator first because Windows locks the
  exe image.
- `scripts/live-smoke.sh`: a curl/python3 driver that validates a running
  pair through the MCP endpoint. Default checks are read-only (health,
  discovery, tool catalog, bridge and emulator status); `--full` adds
  pause/run, M68K step, breakpoint and watchpoint lifecycle, and paused
  frame-capture determinism, restoring running state afterwards.
- Consolidated build/run/launch tooling under `scripts/`. The WSL wrappers
  keep their names (`scripts/build-windows.sh`, `scripts/run-windows.sh`);
  the Windows batch entry points moved to `scripts/internal/` and the root
  `build.bat` / `run.bat` were removed.
- Standardized configuration through the environment with `.env` fallback
  (documented in `.env.example`): `EXODUS_MCP_EXODUS_DIR`,
  `EXODUS_MCP_EXODUS_EXE`, `EXODUS_MCP_PLUGINS_DIR`, `EXODUS_MCP_LISTEN`,
  and `EXODUS_MCP_ARTIFACTS`. One precedence rule everywhere: explicit flag
  beats environment variable beats `.env` beats built-in default. WSL
  wrappers publish the variables to Windows processes via `WSLENV`.
- `scripts/test.sh`: local quality gates mirroring CI (format check, vet,
  race-enabled tests, `GOOS=windows` build/vet) plus an optional
  `--windows-live` mode that runs the named-pipe integration suite against a
  real Windows pipe through WSL interop.
- `build-windows.bat` now validates the configured Exodus directory before
  building, accepts `--config Debug|Release` (Release requires prior Release
  builds of the fork's third-party libraries), accepts `--plugins <dir>`,
  and stamps the Go binary version from `git describe`.
- Live named-pipe client integration tests backed by an in-process fake
  plugin speaking wire protocol v2 over a real byte-mode pipe: round trips,
  structured command errors, capability rejection, multi-megabyte framing,
  context cancellation, oversized-frame rejection, and split-header assembly.

### Changed

- `--base-url` is now resolved after flag parsing from the final `--listen`
  address, so artifact links no longer advertise the default port when a
  custom listen address is used. Explicit `--base-url` still wins.

### Fixed

- Cached bridge status is invalidated after transport-class command failures
  so a dead or restarted plugin is re-probed instead of serving a stale
  healthy snapshot for up to five seconds.
- The named-pipe client sleeps instead of hot-spinning while the plugin pipe
  does not exist yet, logging once on the first wait.

- Initial `exodus-mcp` repository structure.
- Pinned `StealthC/Exodus` as the `vendor/exodus` submodule.
- Reproducible Exodus build and CI documentation.
- Go command scaffold with a local development health endpoint and test.
- Architecture and MCP protocol compatibility plans.
- Artifact-first output policy for large emulator and analysis data.
- Phased tool roadmap and mandatory byte-order/address-space metadata policy.
- Initial `/mcp` HTTP transport shell with modern discovery, tool dispatch,
  header validation, Origin checks, and bounded legacy initialization support.
- Initial native `ExodusMcpPlugin` bridge: a persistent Exodus extension with
  an authenticated local named-pipe status endpoint and a read-only module
  snapshot.
- Windows named-pipe client for the Go server. `bridge_status` now returns the
  live native plugin status when matching pipe configuration is supplied.
- Optional Exodus launcher that generates one pipe name and capability per
  child process without logging the capability.
- Windows launcher now starts Exodus in its executable directory, preserving
  its relative settings and workspace paths.
- Bridge wire protocol v2: flat key/value requests, one streamed JSON envelope
  response with machine-readable error codes, and deadline-based cancellation
  on the Windows named pipe.
- Native command scheduler increment: all commands execute serially on the
  plugin pipe thread with stop-event responsiveness and clean shutdown.
  Read-only emulator access uses the same debugger paths as the built-in
  Exodus debug windows; responses declare `consistency: live`.
- Phase 1 tools: `emulator_status`, `target_info`, `context_create`,
  `context_list`, `context_close`, `memory_spaces_list`, `memory_read`
  (bounded inline reads with byte-order echo and decode validation),
  `memory_dump`, `artifact_get`, and `artifact_preview`.
- Phase 2 tools: `m68k_registers`, `m68k_disassemble`, `m68k_read_memory`,
  `z80_registers`, `z80_disassemble`, `z80_read_memory`,
  `cpu_trace_capture` (artifact-first), and context-scoped `symbols_set`,
  `symbols_list`, `symbols_clear`.
- Immutable artifact store with SHA-256 descriptors, ETag plus HTTP byte-range
  downloads on `/artifacts/{id}`, bounded previews, startup sweeps, and
  per-analysis-context scoping.
- Analysis-context registry (`ctx_...` handles) with an implicit default
  context and protected close semantics.
- Investigation report `docs/TRACE-CRASH-INVESTIGATION.md` documenting a
  reproducible emulator crash triggered by `cpu_trace_capture`, including the
  trace machinery audit, eliminated causes, ranked hypotheses, and the
  recommended file-based capture route.
- `rom_load` for replacing the Mega Drive cartridge with a Windows-visible ROM
  path during local test automation.
- WSL wrappers for driving the Windows build and launcher.
- Controlled execution tools: pause/run, M68K/Z80 single-instruction step,
  step-over/out, plus MCP-managed exact-address execution breakpoints.
- MCP-managed read/write watchpoints: `cpu_watchpoint_set` (byte range with
  `read`, `write`, or `any` access), `cpu_watchpoint_list` (hit counters
  included), and `cpu_watchpoint_remove`. A hit pauses the system through the
  Exodus debugger path, enabling deterministic "stop on access" experiments.
- Address arguments now accept `$`-prefixed Motorola hex and Zilog
  `h`-suffixed hex in addition to decimal and `0x` hex, matching the roadmap
  address-format rule.
- Live validation of pause, M68K/Z80 single-instruction steps, and the
  MCP-managed breakpoint lifecycle against Kid Chameleon.
- Live validation of the watchpoint lifecycle against Kid Chameleon: hit
  pauses the system at the offending instruction (rollback confirmed via
  frozen PC/registers), all address formats and access modes, exact error
  codes, removal, and purge-on-ROM-swap without dangling-pointer crashes.
- Phase 3 tools: `vdp_status` (raw registers plus typed decode of display,
  EVRAM, name-table, pattern, and h-scroll-base fields with image buffer
  geometry) and `frame_capture` (plugin streams live RGB24 from the VDP
  render buffer; the server encodes a PNG artifact and returns a compact
  summary plus descriptor).
- Live validation of both Phase 3 tools against Kid Chameleon: end-to-end PNG
  delivery over HTTP, frame-token monotonicity while running, identical
  capture hashes while paused, and the `unknown_context` error contract.
- Control tools now report live state; validated against Kid Chameleon
  alongside the watchpoint lifecycle.
- Roadmap expansion informed by a review of the independent
  `sadnescity/exodus-mcp-extension` project: decoded `vdp_sprite_table` and
  nametable views, `vdp_pixel_info` per-pixel rendering attribution,
  MCP-managed watchpoints moved up to Phase 4, snapshot-based
  `memory_search`, and flexible address argument formats, with deliberately
  rejected alternatives recorded in the roadmap for traceability.

### Changed

- Tool responses now use MCP `structuredContent` plus a compact JSON text
  fallback; domain failures return `isError: true` results instead of
  JSON-RPC protocol errors.
- `tools/list` is generated from a deterministic alphabetical tool registry
  shared by modern and legacy dispatchers.
- `cpu_trace_capture` is marked experimental in its schema pending the trace
  crash investigation.

### Changed

- Split CI ownership: `exodus-mcp` now tests the Go server only, while the
  Exodus fork owns its Windows build and binary artifacts.

### Fixed

- The launcher now reserves its HTTP listener before starting Exodus and
  terminates its child when the MCP server exits unexpectedly.

- `rom_load` now purges MCP-managed breakpoints and watchpoints before
  unloading the previous program module; the processor devices that own them
  are destroyed with the module, so keeping the entries would leave dangling
  pointers behind a cartridge swap.
- Control tools (`cpu_pause`, `cpu_run`, `m68k_step`, `z80_step`,
  `cpu_step_over`, `cpu_step_out`) now report `system_running` from a live
  read instead of a hardcoded literal. Previously `cpu_step_over` and
  `cpu_step_out` always claimed the system was running even when their
  internal break had already paused execution before the response was built.

- Removed the non-reproducible Exodus build job from the MCP CI. Its clean
  checkout did not contain the upstream-ignored third-party source trees.
- Pinned an Exodus fork revision that explicitly includes `<algorithm>` for
  `std::set_difference` under current MSVC toolchains.

### Security

- Nothing yet.

[Unreleased]: https://github.com/StealthC/exodus-mcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/StealthC/exodus-mcp/releases/tag/v0.1.0
