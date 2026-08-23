# AGENTS.md

Guidance for contributors and coding agents working in this workspace.

## Repository boundaries

- This repository is `exodus-mcp`; its origin is `https://github.com/StealthC/exodus-mcp`.
- `vendor/exodus/` is the pinned `https://github.com/StealthC/Exodus` submodule.
  It retains `RogerSanders/Exodus` as its `upstream` remote.
- `src/` is a legacy working copy of Exodus. Do not edit it or add it to this
  repository; migrate or remove it only after explicit approval.
- Exodus is MIT-licensed (`vendor/exodus/License.txt`, copyright Roger
  Sanders). Keep its notice with redistributed Exodus-derived source or binaries.

## Documentation

- [Build guide](docs/BUILD.md): prerequisites, third-party libraries, local
  builds, outputs, and troubleshooting.
- [CI](docs/CI.md): ownership split and GitHub Actions policy.
- [Exodus fork CI](docs/EXODUS-FORK-CI.md): third-party package contract and
  ready-to-copy fork build workflow.
- [Architecture](docs/ARCHITECTURE.md): the process boundary, concurrency, and
  native-extension spike.
- [MCP compatibility](docs/MCP-COMPATIBILITY.md): normative modern transport
  target and bounded legacy policy.
- [Artifact delivery](docs/ARTIFACTS.md): large-output policy and direct
  retrieval contract.
- [Tool roadmap](docs/ROADMAP.md): phased functional scope and tool rules.
- Write all new documentation, code comments, identifiers, commit messages,
  and user-facing errors in English unless explicitly requested otherwise.

## Verified build baseline

- Upstream Exodus base: `08f388f77040af28d16d44fdfbddb73252953161` (`master`).
- Pinned fork revision: `3cd0e6895196437250bbd00dc271f101ba8faaca`.
- Validated host: Visual Studio 18 Community, MSVC 14.37 (`v143`), Windows SDK
  10.0.26100.
- Build `ThirdPartyLibraries.sln` before `Exodus.sln`, with the same
  configuration and platform. `Debug | x64` was fully built successfully.
- Do not select a `* - LLVM` profile. It requires the legacy `LLVM-vs2014`
  toolset, outside the supported baseline.

## Product baseline

- Use Go for the external HTTP/IPC server and C++ for the in-process Exodus
  extension. The boundary is local authenticated IPC, initially a Windows named
  pipe.
- MCP `2026-07-28` is the normative target. Do not emulate its removed HTTP
  sessions through `Mcp-Session-Id`; use explicit application context handles.
- Compatibility with initialization-based clients must be isolated from the
  modern dispatcher and added only with regression coverage.
- Do not claim MCP conformance or expose `/mcp` until the required transport
  validation suite exists.
- Design tools artifact-first. Raw ROM bytes, dumps, traces, screenshots, and
  other high-volume outputs must default to a compact summary plus a direct
  artifact reference, never an unbounded response placed in model context.
- Every decoded multi-byte value needs explicit byte-order and address-space
  metadata. The Mega Drive baseline is M68K `big-endian`, Z80 `little-endian`,
  and device-specific VDP semantics; raw bytes preserve address order.

## WSL environment

- When running under WSL, do not start the MCP server manually from the agent
  shell. The server runs on the Windows side and is managed outside WSL; check
  connectivity through the bridge status instead of launching processes.
- Only one `exodus-mcp` instance can bind `127.0.0.1:8767`, and each Exodus
  child is paired with one generated capability. Never launch a second
  instance or restart the pair silently: when a code or plugin change requires
  a restart, tell the user first, provide the exact PowerShell steps, and wait
  for confirmation before testing against the bridge.

## Git and upstream discipline

- Run Exodus Git commands inside `vendor/exodus/`. Check `git status` before
  fetching, merging, resetting, or advancing the submodule pin.
- Keep the upstream dependency clean. Product code, MCP code, CI, and docs
  belong in this repository. Make unavoidable Exodus changes as small,
  separately reviewable commits in the fork.
- The MCP CI must not compile a clean Exodus submodule. Build and publish
  Exodus in its fork after its vendored third-party source check has completed.
- Never use `git reset --hard` without explicit authorization. Build output is
  ignored; `git -C vendor/exodus status --short --branch` should be clean after
  a build.
