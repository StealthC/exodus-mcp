# Roadmap

Planned work for `exodus-mcp`. Delivered work is catalogued in
[FEATURES.md](FEATURES.md), and its delivery history is recorded in
[CHANGELOG.md](../CHANGELOG.md). This document intentionally contains only
open work; completed, rejected, and deferred ideas are not tracked here.

## Phase 5 — Advanced analysis

- [ ] Multi-instance orchestration for real parallel experiments.
- [ ] Native batch disassembly: one request that carries a list of addresses.
  `cpu_coverage_capture` already decodes one sweep per contiguous run and the
  disassemble tools accept a bounded `addresses` batch, but an arbitrary
  address set still costs one native sweep per run because the plugin's
  `disasm` operation takes a single start address and a count.

## Analysis workspace

Delivered: persisted contexts and annotations with `context_prune` and
`state_delete` reclamation. Open work:

- [ ] Retention policy for the workspace itself: `context_prune` is explicit,
  so a long-lived install with many finished contexts keeps their annotation
  documents until someone prunes them. A TTL sweep (the artifact sweep's
  shape) needs a policy for a closed context that still owns unexpired
  artifacts.
- [ ] Persist symbols, or a versioned symbol import/export artifact: symbols
  are re-declared with `symbols_set` after every restart today.

## Phase 6 — Audio analysis

**Outcome:** inspect the Mega Drive sound hardware through structured outputs,
mirroring the VDP surface.

- [ ] `audio_capture`: capture a bounded window of mixed stereo output into a
  WAV artifact. The contract and honest unavailable diagnostics are already
  delivered; completion requires a safe bounded PCM buffer exposed by the
  native SDK.
- [ ] Active-note decoding from live or recorded FM/PSG state, reporting notes
  per channel.
- [ ] VGM or equivalent bounded, timestamped YM2612/PSG register-write
  capture, preserving chip clocks, wait commands, frame/target provenance,
  ROM identity, truncation state, and device availability.

## Phase 10 — Continuous trace sessions

Delivered: per-occurrence read/write records with native range filtering,
same-instant register snapshots, monotonic access sequence with explicit gap
loss, effective-value filters that keep raw events, durable manifests with
restart recovery, and ROM-hash-bound symbol resolution. See
[TRACE-SESSIONS.md](TRACE-SESSIONS.md).

- [ ] Pre-write (old) values for write records: the write hook runs before the
  bus write, so `previous_known` is false today. The follow-up captures the
  pre-write value in the M68000/Z80 write paths behind an opt-in flag using the
  cores' existing `TransparentReadMemory` helpers, with width and address-error
  cases handled explicitly.
- [ ] Native trace address filtering so a session does not pay disassembly and
  disk cost for out-of-range instructions.
- [ ] Per-access frame tokens: access records carry cycle and emulated time; a
  per-record VDP frame token would need a frame counter readable from the
  processor access hook.

## Phase 9 — Workflow ergonomics

- [ ] Native controller-state read. `input_status` reports the server's command
  ledger because the pinned plugin only implements `input_set` (a write); a pad
  read operation would let it report an observation, including presses made in
  the UI or by a saved state.

## Operations

- [ ] Release automation for the changelog-cut → annotated tag → release-notes
  workflow.
- [ ] Headless Exodus host with terminal logging: a windowless host executable
  that boots `System.dll`, loads the MCP plugin unchanged, maps module
  connectors deterministically, streams the emulator log to stdout, and shuts
  down without a window. See [HEADLESS.md](HEADLESS.md) for the assessment,
  phases, estimates, and open decisions.

## Delivery rules for remaining work

These rules apply to every item above:

- Every new artifact schema needs a documented version, JSON fixtures,
  provenance validation, bounded previews, and backwards behavior for legacy
  artifacts that lack metadata.
- Every target-mutating operation needs coverage for generation preconditions,
  control-lock ownership and expiry, audit logging, ROM-change invalidation,
  and failure without partial mutation.
- Every capture feature needs a live Windows integration test proving run-state
  restoration, capture consistency metadata, target-generation propagation,
  and bounded artifact behavior against a real Exodus instance.
- Every structured artifact needs fixture-based schema and round-trip tests
  covering address spaces, ROM identity, provenance, and truncation facts.
- Tool descriptions must distinguish direct observation, derived decoding,
  heuristic inference, capped output, and analyst-provided hypotheses.

## Design constraints

- New tools must follow the [tool design rules](FEATURES.md#tool-design-rules).
- Use the external Go HTTP/IPC server and the in-process C++ Exodus
  extension; do not move the HTTP listener into the emulator.
- Do not claim MCP conformance or expose `/mcp` as conformant until the
  required transport validation suite exists.
- Keep high-volume output artifact-first and preserve explicit byte-order,
  address-space, capture-consistency, and ROM-identity metadata.
- Mutations must support target-generation preconditions and the optional
  exclusive control mechanism; reads must remain available while a control
  lock is held.
- The MCP `tools/list` catalog is authoritative; do not add duplicate
  capability-index tools or emulate removed HTTP sessions with
  `Mcp-Session-Id`.
