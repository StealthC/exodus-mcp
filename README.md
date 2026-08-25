# Exodus MCP

Exodus MCP is a local, native bridge that exposes the [Exodus Emulation
Platform](https://github.com/StealthC/Exodus) to MCP clients for Sega
Mega Drive / Genesis ROM analysis.

The Go server speaks Streamable HTTP at `/mcp` (normative target MCP
`2026-07-28`, with a bounded legacy initialization-era layer), and drives a
single Exodus instance through an authenticated local named pipe into a native
C++ plugin. Currently **64 analysis tools** cover the phased roadmap from
bridge/context foundations through VDP graphics, deterministic controlled
experimentation, and Phase 5 advanced analysis (ROM header parsing, snapshot
memory search, watchpoint-triggered tracing, coverage, and scripted
experiments), with optimistic concurrency (target generations, optional
exclusive control lock) and a global target audit stream. See the
[feature catalog](docs/FEATURES.md) for the delivered
scope and the [roadmap](docs/ROADMAP.md) for planned work.

## Goals

- Provide a safe, local Streamable HTTP MCP endpoint for analysis agents.
- Access Exodus through a native C++ extension, not by modifying the emulator
  core whenever possible.
- Preserve upstream maintainability with Exodus pinned as a Git submodule.
- Support independent agent analysis contexts using explicit handles, while
  serializing access to the single emulator instance.
- Keep large binaries, traces, screenshots, and structured analysis results
  outside the model context by making artifacts directly retrievable.
- Offer an optional scripting layer outside the emulator process
  (`experiment_run` with strict allowlists).

## Architecture

```text
MCP client (OpenCode, other hosts)
        │ Streamable HTTP / JSON-RPC 2.0
        ▼
exodus-mcp server (Go)
        │ authenticated local IPC (named pipe + capability)
        ▼
ExodusMcpPlugin.dll (C++)
        │ serialized emulator operations
        ▼
Exodus process and Mega Drive modules
```

Details are in [Architecture](docs/ARCHITECTURE.md) and
[MCP compatibility](docs/MCP-COMPATIBILITY.md).

## Tool catalog

The catalog is a deterministic, alphabetically ordered registry shared by the
modern and legacy dispatchers. An overview by roadmap phase:

- **Phase 0-1 (bridge & memory):** `bridge_status`, `emulator_status`,
  `target_info`, analysis contexts (`context_create`/`list`/`close`),
  `memory_spaces_list`, `memory_read`, `memory_dump`, `artifact_get`,
  `artifact_preview`.
- **Phase 2 (processors):** `m68k_registers`/`z80_registers`, per-CPU
  disassembly and memory reads, `symbols_set`/`list`/`clear`,
  `cpu_trace_capture`, `cpu_coverage_capture`.
- **Phase 3 (VDP & graphics):** `vdp_status`, `vdp_memory_read` (VRAM/CRAM/
  VSRAM), `vdp_tile_export`, `vdp_plane_export`, `vdp_palette_export`,
  `vdp_sprite_table`, `vdp_pixel_info`, `frame_capture`.
- **Phase 4 (controlled experimentation):** `rom_load`, CPU pause/run/step/
  step-over/step-out, MCP-managed breakpoints and watchpoints, optimistic
  concurrency (`target_generation` on every response, optional
  `expected_target_generation` on mutations), the optional exclusive
  `target_control_*` lock, `memory_write`, the `memory_freeze` family (20 Hz
  server-side value freezing; set/list/remove/clear), `frame_advance`,
  `input_set`, `state_save`/`state_load`/`state_list`,
  `context_mutation_log`, `target_audit_log`.
- **Phase 5 (advanced analysis):** `rom_info` (Sega header + checksum),
  `memory_search`, `memory_diff` (cheat-finder snapshot comparison),
  `cpu_trace_capture_watchpoint`, `experiment_run`.

Every tool response is a bounded summary; high-volume output lands in an
immutable artifact. See [FEATURES.md](docs/FEATURES.md) for the delivered
catalog and design rules (byte order, address formats, target generations,
control locks), and [ROADMAP.md](docs/ROADMAP.md) for planned work.

## Artifact-first output

ROMs, memory dumps, disassemblies, traces, and screenshots can be much larger
than an agent's useful context window. Tools therefore return a compact,
sanitized summary by default and place the full output in an immutable
artifact. The result includes the artifact's size, hash, MIME type, direct
local URL, and MCP resource URI. Scripts can download and process the raw data
directly; an agent can request a small preview, a range, or a parsed/sanitized
derivative when it actually needs content in context.

See [Artifact delivery](docs/ARTIFACTS.md) for the contract. Artifacts are
normally kept for the server session; a retention TTL (`--artifact-ttl` /
`EXODUS_MCP_ARTIFACT_TTL`, e.g. `24h`) enables background expiry.

## Data interpretation

Every multi-byte value reported by a tool identifies its byte order and
address space. The Mega Drive baseline is M68K `big-endian` and Z80
`little-endian`; raw byte ranges retain address order and are not implicitly
decoded. VDP data is reported with device-specific interpretation metadata.

## Repository layout

```text
cmd/exodus-mcp/       Go server entry point
internal/             Go packages (mcp dispatcher, bridge client, analysis,
                      artifact store, experiment runner, symbols)
native-plugin/        C++ Exodus extension (ExodusMcpPlugin.dll)
docs/                 architecture, build, protocol, and CI documents
scripts/              WSL build/run wrappers, live smoke, experiment fixtures
vendor/exodus/        pinned StealthC/Exodus Git submodule
```

## Development quick start

```bash
go test ./...                # unit and integration tests
./scripts/test.sh            # local quality gates (fmt, vet, race, Windows build)
curl http://127.0.0.1:8767/healthz
```

Under WSL, build the pair with `./scripts/build-windows.sh` and launch it with
`./scripts/run-windows.sh` (background it; the launcher does not return until
the pair closes). Configuration lives in `.env` (copy from `.env.example`;
required: `EXODUS_MCP_EXODUS_DIR`). Validate a running pair with
`./scripts/live-smoke.sh --full`.

See [Development](docs/DEVELOPMENT.md) for the local workflow and
[Building Exodus](docs/BUILD.md) for the emulator build procedure. Client setup
for OpenCode, Codex CLI, and Claude Code is in
[MCP clients](docs/CLIENTS.md). The native extension source and its named-pipe
contract are in [native-plugin](native-plugin/README.md).

## Status

- [x] Exodus fork pinned as a submodule; reproducible build and CI baseline.
- [x] Modern `2026-07-28` MCP transport (Streamable HTTP) plus bounded legacy
      initialization compatibility; validated by transport tests.
- [x] Authenticated named-pipe bridge with capability-gated plugin access and
      serialized command scheduler.
- [x] Phases 0-4 complete and live-validated against Kid Chameleon (bridge,
      memory, CPUs, symbols, VDP/graphics, optimistic concurrency with target
      generations and the optional control lock, audit stream, mutations,
      states, breakpoints/watchpoints, frames, input).
- [x] Phase 5 core: `rom_info`, `memory_search`, `memory_diff`,
      watchpoint-triggered traces, coverage, `experiment_run`.
- [ ] Multi-instance orchestration (parallel experiments) — remaining Phase 5
      item; audio analysis (Phase 6), advanced debugging (Phase 7), and
      deterministic replay (Phase 8) are planned.

See the [feature catalog](docs/FEATURES.md), the [roadmap](docs/ROADMAP.md),
and the [changelog](CHANGELOG.md) for the delivery history.

## License

`exodus-mcp` is MIT-licensed (see [LICENSE](LICENSE)). Exodus itself is
MIT-licensed; its notice remains applicable to the submodule and any
redistributed Exodus-derived material (see `vendor/exodus/License.txt`).