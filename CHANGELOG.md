# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project will use [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

- Removed the non-reproducible Exodus build job from the MCP CI. Its clean
  checkout did not contain the upstream-ignored third-party source trees.
- Pinned an Exodus fork revision that explicitly includes `<algorithm>` for
  `std::set_difference` under current MSVC toolchains.

### Security

- Nothing yet.

[Unreleased]: https://github.com/StealthC/exodus-mcp/compare/v0.0.0...HEAD
