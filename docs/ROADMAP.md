# Roadmap

Planned work for `exodus-mcp`. Everything delivered so far is catalogued in
[FEATURES.md](FEATURES.md); the delivery history lives in
[CHANGELOG.md](../CHANGELOG.md). This document tracks only what remains, and
each phase must have unit tests, MCP transport fixtures, and at least one
integration check against a running Exodus build before it is considered
complete.

## Delivered

Phases 0–8 and the P0–P2 reverse-engineering interoperability backlog are
delivered and catalogued in [FEATURES.md](FEATURES.md):

- Phases 0–4: bridge/context foundations, memory and artifacts, processors and
  symbols, VDP/graphics, and controlled experimentation (target revision,
  optional control lock, global audit stream, states, frame advance, input).
- Phase 5 core: `rom_info`, `mega_drive_memory_map`, `memory_search`/`diff`,
  `memory_snapshot_capture`, `experiment_run`.
- Phase 7: advanced debugging — symbol-aware disassembly, conditional
  execution breakpoints, register-condition evaluation, `m68k_backtrace`,
  `state_diff`.
- Phase 8: deterministic replay (`deterministic_replay`).
- Phase 9 (partial, 2026-08-29): `target_reset` (hard), `input_sequence`,
  `vdp_memory_export`, and the `state_load` run-state contract.
- Interoperability backlog P0–P2: artifact provenance
  (`artifact-provenance/2`), honest capture consistency, run-state
  observability, schema contract hardening, structured trace/coverage/
  control-flow evidence, forensic breakpoint/watchpoint events, atomic VDP
  capture and frame render manifest, ROM identity, and evidence annotations.
- Operations: `/metrics` endpoint.

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

## Phase 9 — Workflow ergonomics (planned)

**Outcome:** multi-step reverse-engineering workflows (snapshot →
instrument → run → capture → restore) become safe, reproducible, and
context-efficient.

Source: review of the 2026-08-29 Chakan reverse-engineering session report.
Points already covered elsewhere were not re-adopted and are recorded at the
end of this section.

- [x] `target_reset` hard: delivered 2026-08-29 — `target_reset(kind: "hard")`
  performs the documented same-path cartridge reload (module reload
  reinitializes the system and purges all MCP-managed debug resources in one
  audited batch) using the current `emulator_status.rom.path`, and reports
  `reset_source: "hard"`, the run state, and the generation span. The
  discoverable name ends agent guessing (`emulator_reset`/`cpu_reset`).
- [ ] `target_reset` soft (`kind: "soft"`): a debugger-driven reset-vector
  jump (re-read the initial SP/PC from the cartridge header and restart
  execution, RAM preserved like real hardware) whose exact semantics must be
  designed before delivery. Register or memory writes are never a documented
  reset workaround.
- [x] Combined atomic system snapshot: delivered 2026-08-30 as
  `system_snapshot_capture`. It captures named memory ranges, CPU registers,
  VDP status and selected VDP buffers/frame in one pause window, with a
  `system-snapshot/1` manifest and shared artifact provenance. Sprite-table
  capture is explicitly unavailable when the native bridge does not expose a
  raw operation; callers can use `vdp_sprite_table` against the paused state.
- [x] One-shot instrumentation and run-until primitives: delivered 2026-08-29 —
  `one_shot: true` (auto-remove on hit) on `cpu_breakpoint_set` and
  `cpu_watchpoint_set`, plus `run_until_breakpoint` / `run_until_watchpoint`
  wrappers that pause on completion and return the stop reason, triggering
  PC/address, hit count, and registers — no persistent armed instrumentation
  or polling left behind (`frame_advance` already provides the `run_frames`
  equivalent). The server proves a fired break by its native hit counter
  (a positive multiple of the break counter N), removes one-shot instruments
  through the audited mutation path at the next paused observation, and
  attributes native stops to their managed instrument so `emulator_status`
  reports `pause_source: breakpoint_or_watchpoint` without plugin changes.
- [x] `input_sequence`: delivered 2026-08-29 — atomic multi-step controller
  scheduling: one call holds and releases buttons across N frames per step
  (1-64 steps, 1-60 frames), under exclusive control for the whole window
  (caller `control_id` reused or internal lock), with per-step frame tokens,
  per-step audit entries, and release of the failed step's buttons on error —
  reproducible title/menu/gameplay traversal without input-release timing
  errors and lighter than `deterministic_replay`'s state-save/restore
  ceremony.
- [x] `vdp_memory_export`: delivered 2026-08-29 — artifact-first binary
  export of arbitrary VRAM/CRAM/VSRAM ranges (target caps 65536/128/80
  validated server-side; byte order, hash, provenance envelope, and honest
  capture consistency) so large regions never travel as Base64 through tool
  responses, lighter than the full `vdp_capture` ceremony.
- [x] Address dual-form ergonomics: every address-bearing response echoes the
  space-relative and bus addresses when a bus mapping exists
  (`space_address` / `bus_address`), and address inputs accept either form
  with an explicit `address_space` where the space is not implied by the
  tool. Delivered 2026-08-29 with shared translation, schema exposure,
  nested range/event annotations, and incompatible-domain validation.
- [x] `state_load` run-state contract (report): delivered 2026-08-29 —
  snapshots record the last observed run state at save time
  (`saved_run_state`, honest `"unknown"` without an observation), `state_save`
  and `state_list` echo it, and `state_load` reports `saved_run_state` plus
  `final_run_state` — no defensive pause after a restore.
- [x] `state_load` run-state override: delivered 2026-08-29 — an explicit
  `run_state: "restore" | "paused" | "running"` to force the restored state
  (a composite mutation — post-load cpu_control inside the same control
  window; an override failure surfaces with the load already applied, never
  silently; the default "restore" keeps the snapshot's saved run state).
- [ ] VDP command/DMA state decoder: expose the VDP command latch and DMA
  configuration (destination, transfer type, address, mode) as a decoded
  read-only view. Feasibility depends on plugin-side access to the VDP
  device's internal command state; confirm before scheduling.

### Phase 9 report review outcomes (not re-adopted)

Recorded for traceability, following the design-constraints precedent:

- **Authoritative capability index** — MCP `tools/list` is the authoritative
  callable catalog with argument schemas; a `tool_capabilities` tool would
  duplicate it. The naming confusion behind this request (bridge operation
  `cpu_control` vs tool `cpu_run`; guessed `emulator_reset`/`execution_control`)
  is mitigated by tool descriptions that state the exact operation and its
  side effects; `cpu_run`/`rom_load` descriptions now document the reset
  recipe.
- **Mega Drive semantic decoders** — SAT, CRAM palette, tile atlas, and plane
  decoders are delivered (`vdp_sprite_table`, `vdp_memory_read` CRAM decode,
  `vdp_tile_export`, `vdp_plane_export`, `vdp_palette_export`); only the VDP
  command/DMA decoder above is adopted.
- **Unified ROM identity** — delivered 2026-08-29: `emulator_status` now
  reports the loaded cartridge even when opened through the Exodus UI
  (`rom.path` + `path_source`), and the shared `rom_identity` object
  (SHA-256, sizes, header serial, mapping base, generation) already unifies
  `rom_info`, artifact provenance, states, and annotations. `emulator_status`
  deliberately stays cheap (path, no per-call file hash); full identity is
  one `rom_info` call away.
- **Typed structured results** — the modern dispatcher returns typed
  `structuredContent`; results serialized as JSON-in-string are the bounded
  human-readable `content` fallback (and the legacy dispatcher reached when
  `_meta` protocol versioning is absent). No roadmap item; the report's
  session likely called without the modern `_meta` marker.

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

## Operations

- [ ] Release automation for the changelog-cut → annotated tag → release-notes
  workflow (the v0.1.0 cut was performed manually).

## Delivery rules for remaining phases

These rules applied to the delivered interoperability backlog and continue to
govern every remaining item above. They are policy, not scheduled tasks.

- Every new artifact schema needs a documented version, JSON fixtures,
  provenance validation, bounded previews, and backwards behavior for legacy
  artifacts that lack metadata.
- Every target-mutating operation needs unit coverage for generation
  preconditions, control-lock ownership and expiry, audit logging, ROM-change
  invalidation, and failure without partial mutation.
- Every capture feature needs a live Windows integration test that proves
  run-state restoration, capture consistency metadata, target-generation
  propagation, and bounded artifact behavior using a real Exodus instance.
- Every structured artifact needs fixture-based schema and round-trip tests
  that verify address spaces, ROM identity, provenance, and truncation facts.
- Tool descriptions must identify when an output is direct observation,
  derived decoding, heuristic inference, incomplete due to a cap, or an
  analyst-provided hypothesis.

## Design constraints (recorded)

- New tools must follow the [tool design rules](FEATURES.md#tool-design-rules).
- Deliberately rejected architecture alternatives, kept as policy: an HTTP
  listener inside the emulator process, unauthenticated transport, floating
  upstream CI references, and unconditional mutation interfaces that provide
  neither a target-generation precondition nor an optional exclusive control
  mechanism (from the August 2026 review of the independent
  `sadnescity/exodus-mcp-extension`; adoptions from that review are delivered
  and listed in [FEATURES.md](FEATURES.md#adopted-external-input)).
