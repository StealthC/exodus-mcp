# Roadmap

Planned work for `exodus-mcp`. Everything delivered so far is catalogued in
[FEATURES.md](FEATURES.md); the delivery history lives in
[CHANGELOG.md](../CHANGELOG.md). This document tracks only what remains, and
each phase must have unit tests, MCP transport fixtures, and at least one
integration check against a running Exodus build before it is considered
complete.

## Phase 5 — Advanced analysis (open item)

- [ ] Multi-instance orchestration for real parallel experiments.

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

## Phase 7 — Advanced debugging (partially delivered)

**Outcome:** agents reason about execution flow, not just single instructions.

Delivered (see [FEATURES.md](FEATURES.md)): symbol-aware disassembly
(`m68k_disassemble` / `z80_disassemble` resolve context symbols into per-line
`symbol` and `targets` annotations), and conditional execution breakpoints
through the emulator's native surface — location conditions (`greater`,
`less`, `range` with exclusive bounds) plus hit counters and break-on-Nth-hit
(`break_on_counter` / `break_counter`; ignored hits never pause the system;
`cpu_breakpoint_list` reports the native `hit_count`).

Remaining:

- [ ] Register-based breakpoint conditions: evaluate conditions such as
  "D0 == $1234" or "A7 >= $FF0000" on a breakpoint hit. `IBreakpoint` has no
  register condition, so this needs either a fork-side extension of the
  breakpoint interface or a server-side post-hit evaluation loop (read
  registers after the pause, resume when the condition is false) with the
  race and pause/resume cost that implies.
- [ ] M68K backtrace: walk the stack (A7 + frame linkage) with symbol support
  from `symbols_set`; heuristics documented and flagged as such.
- [ ] State diff: compare two `state_save` snapshots (registers, memory, VDP)
  into a structured differences report.

## Phase 8 — Deterministic replay (planned)

**Outcome:** reproducible frame-by-frame input sequences for testing and
demonstration.

- [ ] Input recording: capture a `frame_advance`-stepped sequence of
  `input_set` events into an artifact.
- [ ] Replay: re-execute a recorded sequence from a saved state and verify
  frame-for-frame determinism against the original run.

## Fork-side improvements (deferred)

Work that requires changing emulator core code in the `vendor/exodus` fork
(the project prefers external extensions; these items are tracked here so
their scope and rationale stay visible).

- [ ] **Native write interceptor for reactive value freezing**: hook the
  emulator core's memory write path so cells registered by the server are
  restored directly at write time, eliminating the ~20 Hz polling re-write of
  `memory_freeze` (active, fire-and-forget by design today) and keeping the
  freeze working even when the MCP process is not running. This is the
  emulator-side equivalent of an internal cheat engine; it requires a fork
  commit plus a fork rebuild and stays deferred while the server-side polling
  freeze meets analysis needs.
- [ ] **Persist input bindings on clean shutdown**: call the system config
  save in the same shutdown path that writes `settings.xml`, so key bindings
  survive pair restarts without the manual **File → Save System** action
  (today Exodus writes `Device.MapInput` only on that explicit menu action).

## Operations (planned)

- [ ] `/metrics` endpoint with per-tool call counts, error rates, and artifact
  counts for operators.
- [ ] Release automation for the changelog-cut → annotated tag → release-notes
  workflow (the v0.1.0 cut was performed manually).

## Design constraints (recorded)

- New tools must follow the [tool design rules](FEATURES.md#tool-design-rules).
- Deliberately rejected architecture alternatives, kept as policy: an HTTP
  listener inside the emulator process, unauthenticated transport, floating
  upstream CI references, and lease-free mutation tools such as free-form
  memory writes (from the August 2026 review of the independent
  `sadnescity/exodus-mcp-extension` project; adoptions from that review are
  delivered and listed in [FEATURES.md](FEATURES.md#adopted-external-input)).