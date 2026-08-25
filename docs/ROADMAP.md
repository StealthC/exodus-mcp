# Tool Roadmap

This roadmap prioritizes a trustworthy, useful analysis server over a large but
ambiguous tool catalog. Each phase must have unit tests, MCP transport fixtures,
and at least one integration check against a running Exodus build before the
next phase begins.

## Phase 0 — Native bridge spike

**Outcome:** the external Go process can safely ask a loaded Exodus extension
for a small amount of read-only state.
- `server/discover` and a conformant `tools/list` / `tools/call` shell.
- [x] Native persistent extension with a capability-gated named-pipe `status`
  response and an initialization-time module snapshot.
- [x] `bridge_status`: plugin version, bridge connectivity, and initialization
  module count over the authenticated named pipe. Queue state follows with the
  scheduler.
- [x] `emulator_status`: loaded modules, running/paused state, and device
  identity summary.
- [x] Named-pipe authentication, serialized command queue (single pipe thread
  with stop-event responsiveness), deadline-based cancellation, and clean
  shutdown.

## Phase 1 — First useful analysis server

**Outcome:** an agent can identify the running Mega Drive system and inspect
bounded memory without loading large bytes into its context.

- [x] `context_create`, `context_list`, `context_close`.
- [x] `target_info`: emulator, system, module, and device summary. ROM header
  parsing stays deferred to Phase 5.
- [x] `memory_spaces_list`: named spaces, processor/device owner, size,
  entry width, read permissions, and byte-order metadata.
- [x] `memory_read`: bounded inline reads with explicit representation,
  effective-address echo, and decode validation against declared byte order.
- [x] `memory_dump`: artifact-first memory range output with hash and direct
  URL (8 MiB per-call cap).
- [x] `artifact_get` and `artifact_preview`: metadata, bounded previews, and
  range retrieval guidance.

## Phase 2 — CPU-aware inspection

**Outcome:** an agent can reason about both Mega Drive processors without
silently mixing their conventions.

- [x] `m68k_registers`, `m68k_disassemble`, `m68k_read_memory`.
- [x] `z80_registers`, `z80_disassemble`, `z80_read_memory`.
- [x] `cpu_trace_capture`: the reproducible access violation documented in
  `TRACE-CRASH-INVESTIGATION.md` is **resolved (2026-08-23)**. Capture routes
  the processor trace log through a temporary on-disk file, configures
  tracing with the system stopped, and restores the prior run state;
  validated live by the smoke suite.
- [x] `symbols_set`, `symbols_list`, `symbols_clear`, scoped to an analysis
  context.

## Phase 3 — VDP and graphics analysis

**Outcome:** an agent can inspect graphics state through structured outputs,
not manually decode opaque dumps in its prompt.

- [x] `vdp_status`: registers and explicit register/value representation.
  All 24 registers plus typed decode of display enable, extended VRAM,
  name-table, pattern, and h-scroll-base fields, with completed-plane
  geometry. Validated live against Kid Chameleon.
- [x] `frame_capture`: screenshot artifact with frame/timing metadata. The
  plugin streams the live rendered frame as RGB24 through a minimal IImage
  sink; the server encodes PNG into an artifact. Validated live against Kid
  Chameleon: PNG integrity end-to-end via HTTP download, liveness (frame
  token advances while running), and paused determinism (identical hashes).
  **Fixed (2026-08-23):** back-to-back paused captures used to intermittently
  block until the client deadline. Root cause was not the screenshot path:
  the plugin pipe is message-mode `PIPE_NOWAIT`, and once the outbound
  buffer filled mid-response, `WriteFile` reported the documented
  full-buffer condition (`ERROR_NO_DATA`, or a zero-byte success) which the
  writer treated as fatal, truncating large inline responses such as frame
  captures. The writer now retries transient full-buffer conditions while
  the client drains, and the outbound buffer grew to 512 KiB so typical SD
  frames fit without retrying. The same investigation repaired the live
  smoke itself: its capture digest extraction still expected the
  pre-artifact-first response shape, so the determinism check compared
  empty strings, and it sent wrong remove argument names/types for
  breakpoints and watchpoints, silently leaking armed debug state that
  froze later `cpu_run` calls on watchpoint hits. The smoke now purges
  leftover state, verifies removals, reads `summary.sha256`, stresses
  consecutive paused captures, and verifies the restored running state.
  Reproduce with `scripts/live-smoke.sh --full` plus a loaded ROM.
- [x] `vdp_memory_read`: VRAM, CRAM, and VSRAM through the proven
  timed-buffer path (`ITimedBufferInt::ReadLatest`), with inline raw views
  (hexdump, array_u8, base64), big-endian word views, and a decoded CRAM
  view expanding 9-bit RGB entries into 8-bit RGB using the hardware
  channel layout (`-RRR-GGG-BBB-`, padding at bits 0, 4, 8). When the system is
  running, the plugin briefly stops execution around timed-buffer reads and
  restores it afterwards; responses report `system_paused_during_read`.
  The same work fixed a latent crash in generic `memory_read`: bus metadata
  was derived from a null processor pointer for every memory-kind space, so
  any read of RAM-block or VDP spaces took down the emulator. Foreign
  device reads are now wrapped in SEH guards that surface a diagnostic
  error instead of crashing if another fault class appears.
  Validated live against Kid Chameleon: byte equality between
  `vdp_memory_read` and `memory_read` on all three buffers, palette decode
  against the live frame, name-table reads at the register-reported bases,
  range/alignment/target error codes, and smoke coverage of the
  cross-check.
- [x] `vdp_tile_export`: consecutive 8x8 4bpp patterns as a scaled PNG plus a
  JSON pixel-index artifact, colored through a chosen CRAM palette line with
  optional transparent color 0. Pixel order is high-nibble-left; validated
  live against Kid Chameleon title graphics.
- [x] `vdp_plane_export`: full unscrolled scroll-plane texture view (A, B, or
  window) rendered from the name table with flip, palette, and priority
  decoding. Plane geometry comes from VDP register 16 in the `vdp_status`
  dump; the summary reports distinct tiles, priority counts, and a
  `coherent_snapshot` flag derived from per-read pause telemetry. Validated
  live: plane A reproduces the title screen art and plane B the sky bands.
- [x] `vdp_palette_export`: CRAM as four 16-color lines into a PNG swatch
  artifact plus a JSON decode artifact, with nonzero counts per line and the
  backdrop color inline. Validated live against Kid Chameleon.
- [x] `vdp_sprite_table`: decoded sprite attribute table with bounded
  paging over at most 80 entries and a globally accurate link-chain walk
  (termination, cycle, dangling-link, and truncation flags). Implemented
  entirely server-side on top of `vdp_status` plus the timed-buffer
  `vdp_mem_read` path; validated live against Kid Chameleon attract mode
  including a terminating chain `[0, 4, 15]`.
- [x] `vdp_pixel_info`: per-pixel rendering attribution from the VDP full
  image buffer through the new `vdp_pixel_info` bridge op, which reads the
  same `ImageBufferInfo` records as the Exodus debug UI: source layer
  (sprite, layer A/B, window, background, border, blanking, CRAM write),
  name-entry mapping with tile/flip/priority, palette row and entry,
  shadow/highlight state with the resolved 8-bit color, h/v counters, and
  sprite cell data. The plugin enables `VideoEnableFullImageBufferInfo`
  lazily and reports `attribution_ready=false` until a frame has rendered
  with it active; the tool surfaces that as a `pixel_info_pending` error
  carrying a retry hint. The flag stays enabled once turned on. Validated
  live against Kid Chameleon: border, layer B sky, layer A text/building,
  and a bottom-row sprite all attribute correctly.
- Native access paths already proven to work against Exodus for this phase:
  typed `IS315_5313` register, palette, and sprite accessors;
  `ITimedBufferInt::ReadLatest` for VRAM, CRAM, and VSRAM; and
  `IDevice::GetScreenshot` plus PNG encoding for frame capture. See
  [Adopted external input](#adopted-external-input).

## Phase 4 — Controlled experimentation

**Outcome:** authorized agents can perform reproducible experiments.

- [x] `rom_load`: controlled local cartridge replacement that preserves the
  previous running state. Context leases remain required before broader
  mutation support.
- [x] Deterministic processor control: `cpu_pause`, `cpu_run`, M68K/Z80
  single-instruction step, step-over, step-out, and MCP-managed exact-address
  execution breakpoints. Pause, M68K/Z80 step, and the breakpoint lifecycle
  are validated live against Kid Chameleon. These are more useful for ROM
  analysis than the unsafe trace path.
- [x] MCP-managed read/write watchpoints with range conditions, owned and
  listed like the existing execution breakpoints.
  `cpu_watchpoint_set`/`cpu_watchpoint_list`/`cpu_watchpoint_remove` support
  byte ranges, read/write/any access filtering, and live hit counters. The
  full lifecycle, deterministic hit-and-pause with rollback, error codes, and
  the purge-on-ROM-swap regression are validated live against Kid Chameleon.
- [x] Explicit context lease tools for mutation: `context_lease_acquire`,
  `context_lease_renew`, `context_lease_release`, `context_lease_list`. One
  exclusive lease per context with TTL-based expiry and release-on-close.
  Every new Phase 4 mutation tool requires the lease; the pre-existing
  control tools (`rom_load`, pause/run, steps, breakpoints, watchpoints)
  keep their established behavior. All mutations are recorded in
  `context_mutation_log` with lease, echoed arguments, and timestamp.
- [x] `state_save`, `state_load`, `state_list` using context-scoped
  snapshots: the plugin drives the emulator's native save-state path
  (`ISystemGUIInterface::SaveState`/`LoadState` through the cross-cast, ZIP
  format), and the server verifies each snapshot with SHA-256 and size.
  Validated live against Kid Chameleon including a save/list/load round
  trip.
- [x] `frame_advance` (pause, execute N rendered VDP frames, pause) and
  `input_set` (press/release up, down, left, right, a, b, c, start, x, y,
  z, mode on a controller by player port). Frame advance times out with a
  diagnostic when the display is not rendering. Both validated live against
  Kid Chameleon with a 3-button controller. Bounded scripted fixtures
  (scripted down/advance/up sequences) belong to the Phase 5 scripting
  item.
- [x] `memory_write` through the emulator debugger path: CPU bus spaces
  (`SetMemorySpaceByte`) and entry-based memory devices (read-modify-write
  with declared byte order). Timed-buffer spaces are refused with
  `write_not_supported`, ROM writes are discarded by the bus like real
  hardware, and every call carries audit metadata plus a `context_mutation_log`
  entry. Value-freeze facilities remain deferred as optional. Validated live
  against Kid Chameleon: bus write with read-back, unaligned word-boundary
  writes, Z80 RAM, and error codes.
- [x] `memory_freeze`, `memory_freeze_list`, `memory_freeze_remove`,
  `memory_freeze_clear`:
  lease-gated server-managed value freezing. A registered cell range is
  written once immediately and then re-applied at 20 Hz by the Go server
  through the serialized bridge queue, continuously undoing the program's own
  updates (replacing the entry at the same space+address updates the pinned
  bytes; the set is purged on `rom_load` so stale ranges never reach a new
  cartridge's address map). `memory_freeze_list` surfaces write counts, last
  write time, and the last periodic-write error; `memory_freeze_remove` stops
  one entry and `memory_freeze_clear` drops the whole set; the mutating calls
  are recorded in the mutation ledger. Validated live against Kid Chameleon:
  lifecycle with running-window pinning, write-count growth, per-entry
  removal, bulk clear, and smoke coverage.

## Phase 5 — Advanced analysis

- [x] Code/data logging and coverage artifacts. `cpu_coverage_capture`
  turns a bounded execution window into a coverage artifact: distinct
  executed addresses, merged consecutive-address spans, and a page
  histogram with the top pages inline. Server-side on the proven
  trace-capture path; a byte-order note states the address domain.
  Data-logging watchpoint modes remain deferred.
- [x] `memory_search`: byte-pattern search over a consistent dump-artifact or
  internal `memory-snapshot` instead of a live racy scan; bounded inline
  matches plus a full-results artifact.
- [x] `memory_diff`: cheat-finder comparison between two consistent memory
  snapshots. Cell widths byte/word/long with explicit byte order (big-endian
  default) and aligned scanning by default; modes `changed`, `unchanged`,
  `increased`, `decreased`, `changed_by` (signed delta), `equal_to`, and
  `in_range` support the classic refine-a-candidate workflow (dump before an
  action, compare after, filter by value/delta until one address remains).
  Without an `snapshot_after_id` the tool reads the range fresh into a
  snapshot, mirroring the `memory_search` consistency contract. Bounded
  inline matches plus a `memory-diff-results` artifact.
- [x] Event-driven trace capture triggered by watchpoints (the trace crash is
  resolved, so the capture path is available again). The `trace_capture`
  bridge op accepts an optional `watchpoint_id`: the system runs toward the
  managed watchpoint (even from a paused state), the window ends when the
  watchpoint fires, and the response reports the fired watchpoint ids and
  stop reason. New tool `cpu_trace_capture_watchpoint`.
- [x] ROM/header parsing, checksums, mapping, and cartridge metadata.
  `rom_info` parses the 256-byte Sega header (system type, copyright, both
  titles, serial/product/version, I/O support, ROM/RAM/backup-RAM windows,
  region) and validates the header checksum against the computed Sega sum
  (documented in `docs/SEGA-HEADER.md`), with a header-region artifact and a
  reference memory map. `target_info.rom` now summarizes the loaded
  cartridge instead of reporting that parsing is pending.
- [x] External scripting with strict allowlists and artifact-first output.
  `experiment_run` executes operator-authored Python 3 scripts (`.py`) or
  declarative fixtures (`.json`) from the configured scripts directory
  (`EXODUS_MCP_SCRIPTS_DIR` / `--scripts`; the launcher defaults it to the
  repo's `scripts/experiments`). Scripts talk to the Go server over a bounded
  JSON-lines duplex (stdin/stdout) and may call only an allowlisted subset of
  existing tools; the server injects the experiment's context and lease,
  records a reproducible `experiment-manifest` artifact plus capped
  diagnostic output, and mirrors every mutation in the context ledger.
  Scripts never see the native pipe or capability. The requirement is
  trust-in-operator-code, not OS sandboxing: interpreters run with a minimal
  environment, but arbitrary Python (including subprocesses) is not
  contained.
- Multi-instance orchestration for real parallel experiments.

## Phase 6 — Audio analysis (planned)

**Outcome:** an agent can inspect the Mega Drive sound hardware through
structured outputs, mirroring the Phase 3 VDP surface.

- [ ] `sound_status`: decoded YM2612 and PSG register state (channels,
  frequency/pitch, envelopes, volumes, panning, DAC), honoring the existing
  byte-order and device-specific interpretation rules.
- [ ] `audio_capture`: sample a bounded window of the mixed stereo output into
  a WAV artifact (artifact-first, like `frame_capture`).
- [ ] Active-note decode: from the recorded or live FM/PSG state, report the
  notes playing per channel (analogy to `vdp_sprite_table`).

## Phase 7 — Advanced debugging (planned)

**Outcome:** agents reason about execution flow, not just single instructions.

- [ ] Conditional execution breakpoints with register-based conditions and
  hit counters (execution breakpoints currently lack the counters that
  watchpoints have).
- [ ] M68K backtrace: walk the stack (A7 + frame linkage) with symbol support
  from `symbols_set`; heuristics documented and flagged as such.
- [ ] Symbol-aware disassembly: resolve symbol names in `m68k_disassemble` /
  `z80_disassemble` output.
- [ ] State diff: compare two `state_save` snapshots (registers, memory, VDP)
  into a structured differences report.

## Phase 8 — Deterministic replay (planned)

**Outcome:** reproducible frame-by-frame input sequences for testing and
demonstration.

- [ ] Input recording: capture a `frame_advance`-stepped sequence of
  `input_set` events into an artifact.
- [ ] Replay: re-execute a recorded sequence from a saved state and verify
  frame-for-frame determinism against the original run.

## Operations (planned)

- [x] Configurable artifact retention: `--artifact-ttl` /
  `EXODUS_MCP_ARTIFACT_TTL` (a Go duration such as `24h`) expires artifacts
  older than the TTL on a background sweep; unset keeps artifacts for the
  server session.
- [ ] `/metrics` endpoint with per-tool call counts, error rates, and artifact
  counts for operators.
- [ ] Release automation matching the v0.1.0 changelog cut.

## Adopted external input

A review of the independent in-process `sadnescity/exodus-mcp-extension`
project (August 2026) produced the following adoptions, now recorded as
first-class roadmap items above: the decoded sprite-table view,
`vdp_pixel_info` rendering attribution, MCP-managed watchpoints pulled
forward from Phase 5 into Phase 4, snapshot-based `memory_search`,
and flexible address argument formats. Deliberately rejected: an HTTP
listener inside the emulator process, unauthenticated transport, floating
upstream CI references, and lease-free mutation tools such as free-form
memory writes. Its source also validates the native access paths noted in
Phase 3.

## Tool design rules

- Every value with a width greater than eight bits must carry an explicit byte
  order, or state why byte order is not applicable.
- Every raw range must state address space, start address, byte length, and the
  interpretation used for any decoded values.
- Address arguments accept `$`-prefixed Motorola hex, `0x` hex, Zilog `h`
  suffix, and decimal integers; every response echoes the canonical parsed
  address.
- Default responses are summaries; large output is an artifact. Inline raw
  output requires an explicit small limit.
- Mutating tools require an exclusive analysis-context lease and return enough
  metadata to reproduce the action.
- System-specific tools use clear prefixes (`m68k_`, `z80_`, `vdp_`) rather
  than pretending that behavior is generic.
