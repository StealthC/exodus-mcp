# Roadmap

Planned work for `exodus-mcp`. Delivered work is catalogued in
[FEATURES.md](FEATURES.md), and its delivery history is recorded in
[CHANGELOG.md](../CHANGELOG.md). This document intentionally contains only
open work; completed, rejected, and deferred ideas are not tracked here.

## Phase 5 — Advanced analysis

- [ ] Multi-instance orchestration for real parallel experiments.

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

## Phase 9 — Workflow ergonomics

## Operations

- [ ] Release automation for the changelog-cut → annotated tag → release-notes
  workflow.

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
