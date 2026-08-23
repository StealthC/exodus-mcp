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
- [x] `cpu_trace_capture`: bounded capture summarized inline and stored as an
  artifact. Sampling follows live emulation only; a paused system yields few
  or no entries.
- [x] `symbols_set`, `symbols_list`, `symbols_clear`, scoped to an analysis
  context.

## Phase 3 — VDP and graphics analysis

**Outcome:** an agent can inspect graphics state through structured outputs,
not manually decode opaque dumps in its prompt.

- `vdp_status`: registers and explicit register/value representation.
- `vdp_memory_read`: VRAM, CRAM, and VSRAM with raw and decoded modes.
- `vdp_plane_export`, `vdp_tile_export`, `vdp_palette_export`: image/JSON
  artifacts plus concise structural summaries.
- `frame_capture`: screenshot artifact with frame/timing metadata.

## Phase 4 — Controlled experimentation

**Outcome:** authorized agents can perform reproducible experiments.

- Explicit context lease tools for mutation.
- `state_save`, `state_load`, `state_list` using context-scoped snapshots.
- `frame_advance`, `input_set`, and bounded scripted fixtures.
- `memory_write` and optional freeze/watch facilities, all with audit metadata.

## Phase 5 — Advanced analysis

- Code/data logging and coverage artifacts.
- Breakpoints, watchpoints, and event-driven trace capture.
- ROM/header parsing, checksums, mapping, and cartridge metadata.
- Optional external scripting with strict allowlists and artifact-first output.
- Multi-instance orchestration for real parallel experiments.

## Tool design rules

- Every value with a width greater than eight bits must carry an explicit byte
  order, or state why byte order is not applicable.
- Every raw range must state address space, start address, byte length, and the
  interpretation used for any decoded values.
- Default responses are summaries; large output is an artifact. Inline raw
  output requires an explicit small limit.
- Mutating tools require an exclusive analysis-context lease and return enough
  metadata to reproduce the action.
- System-specific tools use clear prefixes (`m68k_`, `z80_`, `vdp_`) rather
  than pretending that behavior is generic.
