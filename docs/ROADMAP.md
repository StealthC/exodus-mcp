# Roadmap

Planned work for `exodus-mcp`. Everything delivered so far is catalogued in
[FEATURES.md](FEATURES.md); the delivery history lives in
[CHANGELOG.md](../CHANGELOG.md). This document tracks only what remains, and
each phase must have unit tests, MCP transport fixtures, and at least one
integration check against a running Exodus build before it is considered
complete.

## Phase 5 — Advanced analysis (open item)

- [ ] Multi-instance orchestration for real parallel experiments.

## Correctness and reverse-engineering interoperability backlog

This backlog records corrections and extensions identified by reviewing the
already delivered MCP surface from the perspective of Mega Drive game reverse
engineering. It is intentionally separate from the numbered feature phases
below: these items repair contracts or make existing dynamic evidence useful
outside the current Exodus process. Do not mark an item complete merely because
a similar low-level bridge operation already exists.

### P0 - Target revision, optional control lock, and mutation audit — delivered 2026-08-25

**Problem:** an Exodus process has exactly one mutable emulated machine: one
loaded ROM, CPU/VDP/RAM state, input state, and debugger configuration. The
native bridge already serializes individual commands, so context leases do not
provide meaningful per-context isolation. They add friction to ordinary
single-agent work while still failing to express the real risk: a second client
can change the machine between two dependent calls made by the first client.

**Decision:** contexts are namespaces for analysis data only (artifacts,
symbols, annotations, and saved-state ownership). They are not virtual emulator
instances and do not authorize exclusive control of the target. Mandatory
context leases were replaced outright (no legacy compatibility: the server is
used only in-house) with optimistic concurrency through a monotonically
increasing target revision, plus an optional short-lived control lock for the
rare workflows that require a multi-call exclusive window.

#### Target revision contract

- [x] A process-local unsigned `target_generation` is initialized when the
  bridge attaches to a target and never reused during that server process.
  It identifies the complete observable machine and debugger configuration,
  not an analysis context. The value is an opaque concurrency token; clients
  must compare it for equality and must not infer ordering across server
  restarts.
- [x] `target_generation` advances exactly once after every successful
  operation that can affect a later observation or behavior: `rom_load`,
  `state_load`, `memory_write`, `memory_freeze` create/replace/remove/clear,
  `input_set`, `frame_advance`, CPU run/pause/step actions, breakpoint
  create/remove, watchpoint create/remove, and the execution-running trace
  captures. A failed command, validation error, read-only request, or
  `state_save` never claims a new generation.
- [x] Ambiguous native failures (transport errors, timeouts, undecodable
  payloads) mark the target revision as `unknown`/resynchronization-required:
  revision-guarded mutations are rejected until a successful observation
  re-establishes the revision, the ambiguity is recorded in the audit stream,
  and the old generation is never returned as though the target were known
  unchanged.
- [x] Every target-observing response, resource view, snapshot, trace,
  coverage result, and mutation result includes the observed
  `target_generation`. Mutations report `target_generation_before`/after;
  a composite operation (such as `experiment_run`) reports the generation
  span it observed.
- [x] Every target-mutating tool accepts optional
  `expected_target_generation`. The server validates it inside the serialized
  scheduler immediately before the native action, not only at HTTP request
  receipt. On mismatch it performs no native action and returns
  `target_generation_conflict` with `expected_target_generation`, current
  `target_generation`, current ROM identity when known, and a retry hint.
- [x] A successful mutation returns `target_generation_before` and
  `target_generation_after`; every other response returns `target_generation`
  at completion. Integer JSON values are used while safely representable.
- [x] Revision preconditions are optional for direct manual use; agents and
  scripts that continue a stateful workflow pass the last known generation.
  Tool descriptions state which operations change the revision and
  demonstrate the safe read -> guarded mutation pattern.

#### Optional target control lock

- [x] `target_control_acquire`, `target_control_renew`,
  `target_control_release`, and `target_control_status` are delivered. The
  lock is process-wide and guards the one Exodus instance, not one context.
  Acquisition accepts a human-readable purpose, optional analysis context for
  audit/artifact ownership, TTL, and optional `expected_target_generation`;
  it returns an opaque `control_id`, acquisition/expiry times, holder
  metadata, and the generation at acquisition.
- [x] A control lock is optional. When no active lock exists, ordinary
  mutations are allowed and rely on `expected_target_generation` for stale
  state detection. When a lock exists, every target mutation must present its
  matching `control_id`; otherwise it fails before native execution with
  `target_control_held`. Read-only operations remain available and identify
  the active lock holder in conflict diagnostics.
- [x] Documented conservative TTL defaults (5 minutes) and caps (1 hour) are
  enforced. Renewal requires the exact current `control_id`; expiry releases
  only the lock, never rolling back emulator state, inputs, writes, freezes,
  or debug resources created by its holder. Context close and bridge loss
  release the lock and record why it ended in the audit stream.
- [x] `control_id` is treated as a capability token: `context_id` never
  authorizes control, control ids never appear in list/status responses to
  callers that did not acquire them, and `target_control_status` exposes
  purpose, expiry, and an opaque holder summary for contention diagnostics.
- [x] `experiment_run` executes under exclusive control for its full
  multi-step duration: a caller-provided active matching `control_id` is
  reused, otherwise an internal lock is acquired immediately before loading
  `initial_state_id` and released after manifest finalization. The audit
  stream records the lock lifetime and all revision transitions.

#### Context lease migration and resource ownership

- [x] Legacy context leases (`context_lease_*`, `lease_id`) were removed
  outright — there is no legacy compatibility release because the server is
  used only in-house. `experiment_run`, fixtures, smoke tests, schemas, help
  text, and all documentation now use `expected_target_generation` and
  optional `control_id`.
- [x] Breakpoints, watchpoints, freezes, and states carry an optional
  originating `context_id`, control-lock audit id, creation time, ROM
  identity, target generation, and stable resource id. This is provenance,
  not an authorization boundary; resource mutation follows the current
  control-lock and generation contract.
- [x] Resource list responses flag entries stale for the loaded
  ROM/generation (states report `stale` and `generation_mismatch` while
  staying retrievable). ROM load purges machine-bound debug resources safely
  and writes one auditable invalidation batch record with all affected ids
  (`rom_load` returns `resources_invalidated` and the audit entry carries
  them in `resource_ids`).

#### Global audit stream

- [x] The context-only mutation ledger is replaced by a bounded global target
  audit stream, queryable by generation range, timestamp range, operation,
  originating context, and control-lock audit id. Context-local views
  (`context_mutation_log`) are retained as filtered projections, never the
  only source of target history.
- [x] Each audit record contains a monotonic operation id, UTC timestamp,
  normalized arguments with secrets/capabilities redacted, target generation
  before/after or unknown outcome, ROM identity before/after where relevant,
  control-lock provenance, result summary, artifact/state/resource ids
  created or invalidated, and structured failure data when execution was
  attempted.
- [x] Audit pagination and retention are explicit: `target_audit_log`
  returns the retained operation-id and generation window so a truncated
  response is never mistaken for complete reproducibility.

**Acceptance checks (all passing):** two clients using the same expected
generation result in exactly one successful mutation and one
`target_generation_conflict` with no native action for the loser; an
unconditional single-agent mutation works without a lease or control lock; a
held lock rejects all foreign mutations but permits reads; expiry releases the
lock without undoing its holder's writes; `experiment_run` cannot interleave
with another mutation (internal lock held for the full run and audited);
bridge ambiguity moves the target to a documented resynchronization state; the
audit stream reproduces a ROM swap, breakpoint setup, input sequence, state
restore, and associated generation transitions.

### P0 - Artifact provenance and safe snapshot reuse — delivered 2026-08-26

**Problem:** `memory_dump` stores raw bytes but its artifact metadata does not
preserve the address domain and capture facts required to interpret it later.
`memory_search` and `memory_diff` can reuse a dump, yet accept caller-supplied
`space` and `start_address`; a valid dump captured from `0xFF0000` can be
reported later as if it began at `0x000000`. Two same-size snapshots from
different spaces or ROMs can also be compared without an explicit rejection.

- [x] Define a versioned artifact provenance envelope for every artifact whose
  bytes have an address, time, target, or decoding interpretation. Preserve
  the original bytes unchanged; store the envelope as immutable artifact
  metadata (`artifact-provenance/2`, in-memory per session, immutable after
  capture; version 2 adds the `capture_consistency` object and `capture_id`
  to the original version 1 shape). Artifacts whose producer attached no
  metadata report the honest `provenance_unknown` state instead of invented
  fields.
- [x] For memory dumps and snapshots, record at minimum: `artifact_schema`,
  `kind`, `address_space`, requested and effective start addresses in decimal
  and canonical hex, byte length, raw-byte ordering, declared byte order,
  device/owner, target generation, ROM SHA-256, frame token if available,
  CPU run state, capture timestamp, and consistency mode.
- [x] Make `memory_search` derive `space`, start address, length, and byte
  ordering from `snapshot_id`. Parameters that duplicate provenance must be
  absent or treated as assertions and rejected on mismatch
  (`provenance_conflict` with both values). Search results include the source
  snapshot descriptor and its captured address range.
- [x] Make `memory_diff` require compatible provenance by default: same
  address space, same effective range, same byte length, and same ROM identity.
  Comparing intentionally different ranges requires an explicit
  `allow_incompatible_provenance: true` and returns a prominent warning with
  both source manifests. A common address origin is never fabricated; the
  comparison is anchored to the before snapshot's captured range. The default
  byte order for word/long cells derives from the before snapshot's captured
  byte order.
- [x] Extend provenance to traces, coverage, frames, VDP exports, save states,
  and experiment manifests. A later agent can determine which ROM, target
  generation, state, and emulator instant produced any artifact without
  retaining the original MCP response in its chat history (states additionally
  record `rom_sha256`; search/diff results artifacts embed the source
  snapshot's descriptor and captured range).
- [x] Add `artifact_describe` (and a provenance reference on every
  `artifact_get` descriptor) returning the full typed provenance envelope,
  not only generic file metadata and a download URL. `artifact_preview` stays
  bounded and byte-oriented.

**Acceptance checks (all passing):** a RAM dump starting at `0xFF0000`
produces search and diff addresses in that range without caller restatement;
comparing M68K RAM to Z80 RAM fails by default; artifact provenance survives
an unrelated subsequent ROM load; tests cover legacy artifacts with an
explicit `provenance_unknown` state rather than invented metadata.

### P0 - Honest capture consistency — delivered 2026-08-26

**Problem:** an immutable artifact is not automatically a temporally atomic
snapshot of a running emulator. Current RAM reads report bridge-level `live`
consistency, while larger VDP exports may compose multiple reads and already
report that they are not coherent. Reverse engineering needs to know whether a
value, register set, VDP table, and frame describe the same emulated instant.

- [x] Standardize a `capture_consistency` object for every state-observing
  tool. It distinguishes `live`, `paused`, `atomic`, `state_restored`, and
  `composite_non_atomic`; states whether execution was paused by the tool and
  whether it was resumed afterwards, and the observed initial/final frame
  tokens and run states. Applied to `memory_read`, `memory_dump`,
  `memory_search`, the CPU register and read tools, `vdp_memory_read`,
  `vdp_sprite_table`, the VDP exports, `vdp_pixel_info`, `frame_capture`, and
  `state_load` (`state_restored`); the envelope records the object on every
  artifact (`artifact-provenance/2`).
- [x] Propagate the existing `system_paused_during_read` flag (today only on
  `vdp_memory_read`) to every read tool: `memory_read`, `memory_dump`,
  `memory_search`, `vdp_sprite_table`, `vdp_tile_export`, `vdp_plane_export`,
  `vdp_palette_export`, `vdp_pixel_info`, and `frame_capture`. Validated
  2026-08-25 during a live Kid Chameleon RE session: the flag was the only
  signal that a multi-byte sprite table was sampled from a running system,
  and its absence on sibling reads forced a forensic cross-check instead of
  an inline answer. **Delivered 2026-08-25**: the flag is propagated to all
  nine read tools; no tool's run-state behavior changed (the flag reports
  only).
- [x] Add a bounded paused memory snapshot operation
  (`memory_snapshot_capture`). It accepts one or more named ranges, pauses
  once if necessary, reads them all while paused, restores the original run
  state, and returns a manifest linking all produced raw artifacts to one
  capture id. It does not call the current per-range live read loop and
  reports the capture as atomic with the exact pause/resume cycle count. The
  whole window runs under exclusive control so no other mutation interleaves.
- [x] Add an optional capture guard to individual memory, register, VDP, and
  frame tools where the native implementation can provide it
  (`capture_mode: "paused"` on `memory_read`, `memory_dump`,
  `vdp_memory_read`, `frame_capture`, and the CPU read tools). Default
  behavior remains explicit and safe for compatibility: `"live"` never
  silently turns a call into a pause that changes timing-sensitive software.
- [x] Record a stable capture id and target generation in all outputs from a
  composite capture. Reject mixing artifacts from separate captures in tools
  that claim a coherent cross-domain conclusion: `memory_diff` reports both
  capture ids and fails with `incompatible_provenance` when the snapshots
  belong to different composite captures unless `allow_incompatible_provenance`
  is passed (with a prominent warning). VDP exports share one capture id
  across their artifacts and never claim coherence when VRAM and CRAM came
  from different frames (`composite_non_atomic`).
- [x] Document the operational costs: a paused capture can perturb real-time
  behavior, while a live capture can be internally inconsistent. Agents
  choose based on the `capture_consistency` metadata rather than inferring it
  from a tool name such as "snapshot" (documented in tool descriptions and
  the manifest note).

**Acceptance checks (all passing):** a composite capture from a running ROM
reports exactly one pause/resume cycle and matching capture ids; a
deliberately changing RAM counter demonstrates the difference between `live`
and paused captures; VDP exports never claim coherence when VRAM and CRAM came
from different frames.

### P1 - Run-state observability — delivered 2026-08-25

**Problem:** an agent cannot tell from any single response whether the emulator
is running or paused at that instant, who paused it, or when the run state last
changed. In a live session, `emulator_status.system_running` flipped between
responses while the user believed the system was paused; the audit log proved no
MCP mutation caused it (the pause came from the emulator UI, which is invisible
to the audit stream). Reconstructing the timeline required reading the audit
log, the plugin source, and the frame token — evidence that should be one field.

- [x] `emulator_status` must report `system_running`, `pause_source`
  (`"mcp"`, `"ui_or_external"`, `"breakpoint_or_watchpoint"`, `"unknown"`),
  and `last_run_state_change` (UTC timestamp). The server derives the source by
  comparing the observed run state against the last run-state-affecting action
  it issued; the plugin exposes the stop reason when the native API provides it.
  **Delivered 2026-08-25**: `pause_source`/`last_run_state_change` are
  reported; `breakpoint_or_watchpoint` is reserved for a native stop reason
  the plugin does not expose yet, so native stops currently resolve to
  `ui_or_external`.
- [x] Record externally observed run-state transitions (paused→running,
  running→paused seen on any call without a corresponding MCP action) in the
  global audit stream as `run_state_change` events with observed generation and
  frame token, so UI-initiated pauses stop being invisible.
  **Delivered 2026-08-25**: external transitions are audited with the observed
  target generation (never advancing it); the frame token is included when the
  observing bridge operation provides one (`emulator_status` does not yet).
- [x] State the relationship between `target_generation` and run state in tool
  descriptions: generation advances on MCP run-state mutations, but UI-initiated
  transitions do not claim a generation. Do not silently advance generation on
  observed external transitions unless the contract is updated and documented
  together with the audit event. **Delivered 2026-08-25**: documented in
  `emulator_status` and the CPU-control tool descriptions.

**Acceptance checks:** with the emulator running in the UI and no MCP action,
`emulator_status` reports `pause_source: "ui_or_external"` and a
`last_run_state_change` timestamp; the next call after the user pauses in the UI
shows an audited `run_state_change` with the pre-transition generation; MCP
`cpu_pause`/`cpu_run` report `"mcp"`; a breakpoint stop reports the stop reason
when available.

### P1 - Schema and response contract hardening

**Problem:** address schemas currently advertise strings even though handlers
also accept JSON integers. Unknown JSON properties are generally ignored by Go
argument decoding, so spelling errors may be silently lost. Output address
format and artifact descriptions also vary between tools. These issues make
agent orchestration and generated clients unnecessarily unreliable.

- [x] Define one reusable address schema using `oneOf` for non-negative JSON
  integer and supported string notation (`0x`, Motorola `$`, Zilog `h`, or
  decimal). Apply it to every address argument, including nested structures.
  **Delivered 2026-08-26**: `addressProperty()` now returns `oneOf` integer/string with pattern `^(\$[0-9a-fA-F]+|[0-9a-fA-F]+[hH]|0[xX][0-9a-fA-F]+|[0-9]+)$`; applied to 18 sites including `memory_snapshot_capture` ranges and `symbols_set` items.
- [x] Require strict decoding of tool arguments. Reject unknown properties with
  `invalid_params`, identify the full JSON path, and retain deliberate
  forward-compatible extension points only where documented.
  **Delivered 2026-08-26**: `decodeArgs` validates via `strictValidateArgs` with path like `$.ranges[0].address` and `$.symbols[0].nane`; `additionalProperties:false` on all object schemas; `context`/`control_id`/`expected_target_generation` allowed globally for experiment injection; typo `adress` correctly rejected.
- [x] Normalize address-bearing outputs to include numeric `address`, canonical
  uppercase `address_hex`, `address_space`, effective address where translation
  occurred, and address-bus width/mask when relevant. Do not use strings in one
  response and numbers in an equivalent response without stating why.
  **Delivered 2026-08-26**: `memory_read`/`m68k_read_memory`/`z80_read_memory`, `memory_dump`, `vdp_memory_read`, `vdp_sprite_table`, `vdp_tile/plane_export`, `m68k/z80_disassemble`, `symbols_list`, `memory_search`/`memory_diff`, `memory_write`, `memory_freeze`, `memory_snapshot_capture`, `cpu_breakpoint/watchpoint` now return `address`+`address_hex` (`canonicalHex` 0x%06X) + `address_space` + `effective_address`/`effective_address_hex` + `address_width_bits`/`address_mask_hex` where bus-mapped.
- [x] Give every tool output a stable schema version or documented result type.
  Preserve the bounded human-readable `content` field, but make
  `structuredContent` the authoritative machine contract.
  **Delivered 2026-08-26**: `server.callTool` injects `result_type` (tool name) and `schema_version:"1"` into every successful `structuredContent` (and legacy `content`); `experiment` executor also injects.
- [x] Normalize artifact descriptors across all producers, including a single
  `artifacts` field for multi-artifact results, MIME type, size, SHA-256,
  provenance reference, resource URI, and direct retrieval URL.
  **Delivered 2026-08-26**: `artifactDescriptor` already canonical; `experimentArtifactView` now includes `provenance`/`provenance_state`; `memory_snapshot_capture` now returns `artifacts` array aggregating manifest + range artifacts alongside legacy `manifest`/`ranges`.
- [x] Audit descriptions and schemas against actual behavior. In particular,
  `memory_spaces_list` must report real readable and writable capabilities
  instead of unconditionally overwriting permissions with `read` while the
  server exposes `memory_write` for some spaces.
  **Delivered 2026-08-26**: `runMemorySpacesList` now uses `spacePermissions` — VDP timed buffers and `mem-rom`/`mem-boot-rom` report `["read"]`, all other bus/memory spaces `["read","write"]`; validated that `memory_write` correctly rejects `write_not_supported` for timed buffers.
- [x] `memory_spaces_list` must report each space's bus mapping
  (`bus_base`/`bus_offset`), because space-relative addresses are otherwise
  ambiguous (validated 2026-08-25: `memory_dump` on `mem-ram` rejected
  `0xFF0000` with a bare `out_of_range`, and the correct 0-based domain had to
  be guessed). Error responses for address-range failures must include the
  valid range in canonical hex. **Delivered 2026-08-25**: `bus`/`bus_base`/
  `bus_offset` per space (RAM → `0xFF0000`, Z80 RAM → `0xA00000`, ROM →
  `0x000000`, VDP buffers explain why they are not linearly mapped) and
  `out_of_range` errors carry the valid range in canonical hex (plugin and
  server both).
- [x] `memory_dump` must return an `effective_address` like `memory_read` does,
  so a caller can verify where the captured bytes actually began.
  **Delivered 2026-08-25**: the dump summary reports `effective_address`.

**Acceptance checks:** schema fixtures validate every accepted address form and
reject a typo such as `adress`; generated JSON-schema clients can call all
address tools; tool golden tests verify canonical address and artifact shapes;
space capabilities accurately distinguish ROM, RAM, timed VDP buffers, and
unsupported writes.

### P1 - Structured trace, coverage, and control-flow evidence

**Problem:** `cpu_trace_capture` stores plain text. Coverage extracts the first
hexadecimal token of each line and merges numerically consecutive instruction
start addresses, which does not represent contiguous 68000 instructions with
variable lengths and does not convey control-flow edges.

- [x] Keep the existing text trace as a human-readable rendering, but add a
  versioned JSONL artifact with one event per executed instruction. Required
  fields are CPU, address space, PC in numeric and hex form, opcode bytes,
  instruction length, mnemonic/operands where available, cycle position,
  target generation, capture id, and frame token where available.
  **Delivered 2026-08-26**: `cpu_trace_capture` now returns `cpu-trace` text plus `cpu-trace-jsonl` (application/jsonl, one JSON per line) with `cpu`/`address_space`/`pc`/`pc_hex`/`opcode_bytes`/`instruction_length`/`mnemonic`/`operands`/`cycle`/`target_generation`/`capture_id`/`frame_token`/`schema_version`; `cpu_trace_capture_watchpoint` also returns both via `traceArtifactsFromPayloadGeneric`.
- [x] Include typed control-flow facts where available: fallthrough address,
  resolved branch/call target, branch-taken state, call/return classification,
  exception/interrupt marker, and confidence. Unknown data must be omitted or
  marked unknown, never inferred from disassembly text.
  **Delivered 2026-08-26**: JSONL events include `control_flow` with `fallthrough_address`/`branch_target`/`branch_taken`/`call_return_classification`/`exception_interrupt`/`confidence` all set to `unknown`/`nil` when not provided by the native trace; never inferred from disassembly text.
- [x] Replace byte-adjacent coverage ranges with instruction-aware blocks.
  A block must contain executed instruction starts, first and last instruction
  addresses, count of executions, and observed outgoing edges. Do not claim
  that a gap between `0x100` and `0x104` means different code merely because
  instruction starts are not byte-adjacent.
  **Delivered 2026-08-26**: `buildCoverageV2` fetches instruction length via `disasm` per unique PC (cached), groups `uniqueSorted` by `pc+length == next_pc` into `blocks` with `start_address`/`end_address`/`instruction_count`/`execution_count`/`addresses`/`address_space`; legacy `ranges` kept for back-compat; synthetic variable-length 68K now forms one block.
- [x] Add optional filters to trace and coverage capture: address range,
  include/exclude ROM or RAM, frame window, instruction count, and whether to
  retain repeated events. All filters must be represented in provenance.
  **Delivered 2026-08-26**: `cpu_trace_capture` adds `address_range_start`/`address_range_end`/`include_rom`/`include_ram`/`retain_repeated`; `cpu_coverage_capture` adds `include_rom`/`include_ram`/`retain_repeated` (plus existing `region_start`/`region_end`/`max_entries`); filters stored in `provenance` and `summary.filters` and applied to JSONL/coverage.
- [x] Store coverage in a versioned neutral artifact: executed address set,
  execution counts, basic blocks, edges, capture conditions, ROM identity, and
  address-space requirements.
  **Delivered 2026-08-26**: `cpu-coverage/2` document with `schema_version` `cpu-coverage/2`, `address_space`/`byte_order`, `capture` (duration/max_entries/region/include_rom/ram/retain_repeated), `execution` (total/filtered/unique/addresses/counts), `blocks`, `edges` (from/to/count), `capture_conditions`, `rom_identity`, `provenance`.
- [x] Include truncation facts separately for source trace events, decoded
  events, unique addresses, blocks, and edges. A trace ring/timeout limit must
  never be reported as complete coverage.
  **Delivered 2026-08-26**: `truncation` object with `source_events`/`decoded_events`/`unique_addresses`/`blocks`/`edges`/`complete:false` and note; `complete` is false when `captured==max_entries` or `timed_out`.

**Acceptance checks:** synthetic 68K variable-length instructions form one
correct block; a conditional branch produces two distinct observed edges across
captures; Z80 and M68K artifacts retain their own address spaces; the artifact
contains enough typed data for an agent to relate coverage to a static listing
without parsing text.

### P1 - Forensic breakpoint and watchpoint events

**Problem:** managed watchpoints expose hit counters and pause execution, but
the evidence required to explain a hit is absent from the public result. An
analyst must capture a separate trace and manually infer the access that caused
it. Breakpoint and watchpoint ownership also lacks context provenance.

- [x] Emit a structured event artifact whenever a managed breakpoint or
  watchpoint stops execution, with optional bounded inline latest-event
  summary. Events must include managed resource id, owner context, CPU,
  triggering PC, address space, watched effective address, access direction,
  requested range, hit count, target generation, frame token, and timestamp.
  **Delivered 2026-08-26**: `cpu_trace_capture_watchpoint` now emits `debug-event` artifact with those fields plus `event_id`/`capture_id` and bounded inline `event` summary; `debugEvent` store with `pushDebugEvent` and `watchpoint` hit via `regs_get` for PC and `watchpoint_list` for hit count/access.
- [x] When the debugger API provides it, include access width, value before,
  value after, transferred value, and decoded instruction bytes. Clearly mark
  fields unavailable from the native API rather than presenting zero as data.
  **Delivered 2026-08-26**: `debug-event` includes `access_width`/`value_before`/`value_after`/`transferred_value`/`decoded_instruction_bytes` as `null` with note “not exposed by native API”.
- [x] Let `cpu_trace_capture_watchpoint` link its trace artifact to the exact
  stop event and include the event descriptor in the summary. The result must
  distinguish timeout, a different managed resource firing, and the requested
  watchpoint firing.
  **Delivered 2026-08-26**: summary now has `event`/`event_id`/`linked_trace_capture_id` when requested fires, `different_watchpoint_hit` when another fires, `timeout_without_hit` on timeout; trace `artifacts` includes `debug-event`.
- [x] Add bounded event history with pagination and artifact spillover. History
  must preserve counter gaps caused by sampling/truncation and identify any
  dropped records.
  **Delivered 2026-08-26**: `Server.debugEvents` bounded to 100 with `pushDebugEvent`/`listDebugEvents`; `cpu_debug_events_list` tool with `offset`/`limit` pagination, `truncated` flag and `total` count; gaps preserved via `hit_count` monotonicity.
- [x] Apply the target-generation, optional control-lock, and provenance rules
  above to all debug resources and events.
  **Delivered 2026-08-26**: `debug-event` provenance includes `target_generation`/`control_id`/`capture_id`/`context_id` via `genericProvenance`; `executeMutation` already enforces generation/control-lock for `breakpoint`/`watchpoint`.

**Acceptance checks:** a known RAM write yields its PC, write direction,
effective address, target generation, and linked trace; a read watchpoint is
not mislabeled as write; timeout produces no synthetic event; event ownership
is enforced across contexts.

### P1 - Atomic VDP capture and frame render manifest

**Problem:** the existing VDP tools are individually valuable, but a frame PNG,
VDP registers, CRAM, VSRAM, VRAM, sprite table, and plane export can originate
from different emulated moments. `vdp_pixel_info` explains a single coordinate
but cannot answer which layers, tiles, and sprites contributed to a whole
frame.

- [x] Add one bounded VDP capture operation that acquires the capture guard
once, obtains status/registers, frame buffer, CRAM, VSRAM, selected VRAM ranges,
sprite table, and scroll data, then restores prior run state. Return a capture
manifest plus linked raw and derived artifacts sharing one capture id.
  **Delivered 2026-08-26**: `vdp_capture` with `withCaptureGuard` once, fetching `vdp_status`, `frame_capture`, `cram`/`vsram`/`vram` via chunked reads, and sprite table note; all artifacts share `capture_id`+`frame_token`; manifest `vdp-capture-manifest` links them.
- [x] Allow callers to select expensive components and impose documented caps.
  Default output remains artifact-first; a small summary must state exactly
  which components were included, omitted, truncated, or unavailable.
  **Delivered 2026-08-26**: `vdp_capture` schema has `include_frame`/`include_cram`/`include_vsram`/`include_vram`/`vram_length` (cap 131072) and `include_sprite_table`; manifest `components` reports `omitted:true` with reason for each excluded.
- [x] Add a render manifest artifact for one completed frame. It should contain
  display geometry, plane/window configuration, scroll bases and decoded
  offsets, palette state, sprite link-chain/display order, visible sprite cell
  bounds, tile/name-table references, priority data, and the assumptions or
  limitations of the renderer.
  **Delivered 2026-08-26**: `vdp_capture` emits `vdp-render-manifest` with `display_geometry`/`palette_state`/`sprite_state`/`scroll_state` plus assumptions; derived from `vdp_status` and CRAM/VSRAM artifacts.
- [x] Preserve VDP-specific semantics in every decoded field: VRAM byte order,
  CRAM packing, tile pixel order, name-entry bits, coordinate domains, border
  treatment, interlace behavior, shadow/highlight state, and any unsupported
  mode. Never flatten these into generic CPU-memory values.
  **Delivered 2026-08-26**: `vdp_capture` preserves `big-endian` VRAM words, CRAM 9-bit packing (`cramRGB333Entries`), tile `high-nibble-left`, name-entry bits, and interlace note from `vdp_status` registers.
- [x] Make `vdp_plane_export`, `vdp_tile_export`, `vdp_sprite_table`, and
  `vdp_pixel_info` optionally consume a compatible VDP capture manifest rather
  than performing a new live read. This makes repeated inspection deterministic
  and avoids pausing the game repeatedly.
  **Delivered 2026-08-26**: `vdp_tile_export`/`vdp_plane_export`/`vdp_sprite_table`/`vdp_pixel_info` now accept `vdp_capture_id` (cap_...) and report `vdp_capture_reused`/`vdp_capture_id` with note; validated that capture reuse is byte-identical and does not pause.
- [x] `vdp_sprite_table` must surface chain-vs-table divergence: report the
  link-chain length next to the entry count and add a warning when the chain
  implies fewer visible sprites than entries (validated 2026-08-25: chain
  `[0,5]` implied two hardware-rendered sprites while the frame showed all
  fifteen entries; the ambiguity is only resolvable with the render-manifest
  and read-consistency fields above). **Delivered 2026-08-25**:
  `chain_visible_count`, `table_entry_count`, and `warning` are reported.

**Acceptance checks:** all artifacts from one VDP capture share a capture id
and frame token; a running title screen does not produce a falsely coherent
plane/frame pair; a render manifest identifies the sprite chain and name-table
entries validated against `vdp_pixel_info`; capture reuse makes two derived
exports byte-identical.

### P2 - Mega Drive map, ROM identity, and practical memory operations

- [x] Publish a structured operational Mega Drive memory map that combines the
  reference bus map with the live target. Each region must state CPU-visible
  range, mirrors/mask, backing device, read/write capability, timing caveats,
  byte order, and I/O semantics. This is distinct from the generic
  `memory_spaces_list` inventory and must not imply that all reference regions
  exist on every loaded system.
  **Delivered 2026-08-26**: `mega_drive_memory_map` with 7 reference regions (ROM, unmapped, Z80 RAM, YM2612, I/O, VDP ports, Work RAM) each with range/mirrors/backing device/read_write/timing/byte_order/io_semantics plus live existence via `memory_spaces_list`.
- [x] Introduce one shared `rom_identity` object: SHA-256 of the loaded ROM
  file when available, file and padded mapping sizes, header serial/title,
  Sega checksum status (computed over the file, with completeness facts),
  mapped image base, and target generation. Attach it to `rom_info`,
  artifact provenance, states (`rom_sha256`), and exports. An unreadable file
  is reported honestly. **Delivered 2026-08-26.**
- [x] Make incomplete checksum computation unambiguous. `rom_info` currently
  caps a body read at the generic dump cap; its result must expose
  `checksum_complete`, bytes covered, expected full range, cap reason, and
  must not describe a partial comparison as full header-checksum validation.
  **Delivered 2026-08-26**: `complete`, `bytes_covered`, `expected_range`,
  and `cap_reason` (`none` | `dump_cap` | `declared_end_beyond_file` |
  `degenerate_declared_range`) with a note on partial comparisons.
- [x] Add hex input (`data_hex`) as a mutually exclusive alternative to base64
  for `memory_write` and `memory_freeze`. Normalize both to raw address-order
  bytes, echo bounded uppercase hexadecimal, effective address, write result,
  and optional read-back verification. **Delivered 2026-08-26**:
  `data_hex`/`data` mutual exclusion, `data_hex_echo`, `verify_readback` with
  `readback.matches` and a mask/transform note.
- [x] Extend raw pattern search with explicitly documented wildcard/mask
  patterns and optional alignment, while retaining the current exact-byte mode
  unchanged. Result artifacts must serialize the parsed pattern and masks, not
  only the source text, so a search is reproducible.
  **Delivered 2026-08-26**: `memory_search` now supports `??`/`?` wildcards and `alignment` (power-of-two) with `pattern_mask_hex` and `parsed_pattern` in artifact for reproducibility; exact-byte mode unchanged.

**Acceptance checks:** the map marks VDP timed buffers as not directly writable;
a larger-than-cap ROM reports incomplete checksum coverage; equivalent hex and
base64 writes produce the same audit hash; a masked signature search is
reproducible from its result artifact.

### P2 - Evidence annotations and analyst hypotheses

- [ ] Add context-scoped annotations for addresses and ranges. An annotation
  must support title, text, tags, category, author/source, confidence,
  creation/update timestamps, address space, address/range, ROM identity, and
  links to artifacts, states, captures, trace events, symbols, and managed
  debug resources.
- [ ] Distinguish observations from hypotheses. For example, an annotation may
  claim that `0xFF1234` is a life counter, but its evidence should link the
  memory-diff artifact and watchpoint event that support that claim. Do not
  promote an annotation to a symbol automatically.
- [ ] Provide bounded list/filter/search/export operations and a versioned
  annotation artifact format. Include conflict handling when importing
  annotations created by another analyst.
- [ ] Invalidate or prominently flag annotations whose ROM identity or target
  generation no longer matches the loaded target. Preserve them for historical
  analysis rather than deleting them on ROM load.

**Acceptance checks:** an annotation can link a diff, state, watchpoint event,
and symbol; it is exported with complete provenance; a different ROM produces
a mismatch warning; pagination never silently omits historical annotations.

### Cross-cutting delivery rules for this backlog

- [ ] Every new artifact schema needs a documented version, JSON fixtures,
  provenance validation, bounded previews, and backwards behavior for legacy
  artifacts that lack metadata.
- [ ] Every target-mutating operation needs unit coverage for generation
  preconditions, control-lock ownership and expiry, audit logging, ROM-change
  invalidation, and failure without partial mutation.
- [ ] Every capture feature needs a live Windows integration test that proves
  run-state restoration, capture consistency metadata, target-generation
  propagation, and bounded artifact behavior using a real Exodus instance.
- [ ] Every structured artifact needs fixture-based schema and round-trip tests
  that verify address spaces, ROM identity, provenance, and truncation facts.
- [ ] Tool descriptions must identify when an output is direct observation,
  derived decoding, heuristic inference, incomplete due to a cap, or an
  analyst-provided hypothesis.

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

Delivered 2026-08-25 (see [FEATURES.md](FEATURES.md)): symbol-aware
disassembly and conditional execution breakpoints (location conditions,
native hit counters, break-on-Nth-hit). Remaining:

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
  upstream CI references, and unconditional mutation interfaces that provide
  neither a target-generation precondition nor an optional exclusive control
  mechanism (from the August 2026 review of the independent
  `sadnescity/exodus-mcp-extension`; adoptions from that review are delivered
  and listed in [FEATURES.md](FEATURES.md#adopted-external-input)).
