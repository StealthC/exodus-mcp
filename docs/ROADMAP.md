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
- [!] `cpu_trace_capture` is quarantined pending the reproducible M68K and
  Z80 access violation documented in `TRACE-CRASH-INVESTIGATION.md`. Repair
  the upstream trace-enable synchronization and disassembly path before this
  tool is used for normal analysis.
- [x] `symbols_set`, `symbols_list`, `symbols_clear`, scoped to an analysis
  context.

## Phase 3 — VDP and graphics analysis

**Outcome:** an agent can inspect graphics state through structured outputs,
not manually decode opaque dumps in its prompt.

- `vdp_status`: registers and explicit register/value representation.
- `vdp_memory_read`: VRAM, CRAM, and VSRAM with raw and decoded modes.
- `vdp_plane_export`, `vdp_tile_export`, `vdp_palette_export`: image/JSON
  artifacts plus concise structural summaries.
- `vdp_sprite_table`: link-chain-aware decoded sprite attribute table with
  bounded paging.
- `frame_capture`: screenshot artifact with frame/timing metadata.
- `vdp_pixel_info`: per-pixel rendering attribution (source layer, tile
  mapping, palette entry, shadow/highlight result) from the VDP full image
  buffer, with lazy enable and an explicit retry-after-one-frame contract.
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
- MCP-managed read/write watchpoints with range conditions, owned and listed
  like the existing execution breakpoints.
- Explicit context lease tools for mutation.
- `state_save`, `state_load`, `state_list` using context-scoped snapshots.
- `frame_advance`, `input_set`, and bounded scripted fixtures.
- `memory_write` and optional value-freeze facilities, all with audit metadata.
  Watchpoint capture belongs to the dedicated watchpoint item above.

## Phase 5 — Advanced analysis

- Code/data logging and coverage artifacts.
- `memory_search`: byte-pattern search over a consistent dump-artifact
  snapshot instead of a live racy scan; bounded inline matches plus a
  full-results artifact.
- Event-driven trace capture triggered by watchpoints after the trace crash
  is fixed.
- ROM/header parsing, checksums, mapping, and cartridge metadata.
- Optional external scripting with strict allowlists and artifact-first output.
- Multi-instance orchestration for real parallel experiments.

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
