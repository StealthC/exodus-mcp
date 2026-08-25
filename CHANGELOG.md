# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project will use [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
- `memory_freeze`, `memory_freeze_list`, `memory_freeze_remove`: lease-gated
  server-managed value freezing. `memory_freeze` writes the pinned bytes once
  (like `memory_write`) and then re-applies them at ~20 Hz through the
  serialized bridge queue, undoing the program's own updates to the range;
  re-registering the same space+address updates the pinned bytes, `rom_load`
  purges the whole set, and both mutating calls are recorded in the mutation
  ledger. The list tool reports byte length, write count, last write time, and
  the last periodic-write error. Validated by unit tests and the live smoke
  (pinning across a running window, write-count growth, removal).

### Changed

- README rewritten: the old copy still described the project as a foundation
  shell that could not read from a running Exodus; it now summarizes the
  62-tool catalog by roadmap phase, the delivered status, configuration, and
  the MIT license.
- License: `exodus-mcp` is now MIT-licensed (`LICENSE`); the Exodus MIT notice
  remains applicable to the submodule and any redistributed Exodus-derived
  material.
- `docs/ROADMAP.md` marks `memory_diff` complete in Phase 5 and records the
  planned Phase 6 (audio), Phase 7 (advanced debugging), and Phase 8
  (deterministic replay) scope; multi-instance orchestration remains the open
  Phase 5 item.

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
