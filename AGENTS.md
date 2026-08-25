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
- Pinned fork revision: `de9c69e7aa50b8d0c99cad0a2841c01f6e774d08`.
- Build default: **`Release | x64`** for both wrappers (`build-fork.sh` and
  `build-windows.sh`); the fork installs the full binary set (exe,
  `System.dll`, `Assemblies/*.dll`) so interface slots never trail a stale
  device DLL.
- Validated host: Visual Studio 18 Community, MSVC 14.37 (`v143`), Windows SDK
  10.0.26100.
- Build `ThirdPartyLibraries.sln` before `Exodus.sln`, with the same
  configuration and platform. **`Release | x64` is the default** for both the
  fork and the plugin wrappers: the CPU cores only run at realistic speed when
  optimized, and the whole binary set (exe, `System.dll`, `Assemblies/*.dll`,
  plugin) must move as one configuration. Pass `--config Debug` to either
  wrapper only when a specific defect needs Debug-CRT checks; both
  configurations were built successfully.
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

- Under WSL, use `./scripts/build-windows.sh` to build the pair (native
  plugin + Go server) and `./scripts/run-windows.sh` to launch it. Do not run
  `exodus-mcp.exe` or Exodus directly from the Linux shell. For fork-side
  experiments, `./scripts/build-fork.sh` rebuilds the submodule's emulator
  and installs the exe into the configured test install; close the running
  emulator first (Windows locks the exe image).
- Configuration lives in `.env` (copy from `.env.example`; required:
  `EXODUS_MCP_EXODUS_DIR`). Precedence is flag > environment > `.env` >
  default everywhere. The wrappers publish `EXODUS_MCP_*` variables to
  Windows processes via `WSLENV`; without that plumbing Windows children
  silently never see WSL-side overrides.
- Starting, stopping, and restarting the pair is routine agent work and does
  not need per-restart user approval. The supported lifecycle is:
  - Check first whether a pair is already running (`tasklist.exe` for
    `Exodus.nightly.exe` and `exodus-mcp.exe`, plus port `127.0.0.1:8767`).
    Never start a second instance: only one process can bind the port, and
    each Exodus child pairs with one generated capability.
  - Stop a running pair before installing a new build with
    `scripts/stop-windows.sh`, which first asks Exodus to close gracefully
    (WM_CLOSE) so it can persist `settings.xml`, then force-kills after a
    grace period (fallback: `taskkill /F /IM Exodus.nightly.exe /IM
    exodus-mcp.exe`). Windows locks loaded images, so the plugin DLL cannot be
    copied while Exodus runs, and a stale pair keeps serving old code.
  - Exodus configuration persistence follows the emulator's own design: the
    `settings.xml` prefs are written only on a clean shutdown, and the key
    bindings (`Device.MapInput` in the default system module XML) are written
    only by the manual **File → Save System** action. A forced kill loses any
    in-session changes; prefer the graceful stop above instead of raw
    `taskkill /F` whenever a clean exit matters.
  - Launch `run-windows.sh` **in the background** — the launcher does not
    return until the pair is closed, so a foreground invocation blocks the
    shell (redirect its output to `tmp/run-windows.log`). Then check health
    from a separate foreground command: poll
    `curl -s http://127.0.0.1:8767/healthz` until it answers, and inspect
    `tmp/run-windows.log` for startup errors. Only proceed with tool calls
    once the health endpoint responds. The launcher reserves the port before
    starting Exodus and terminates its child when the MCP server exits; its
    log reports child exit codes such as `0xc0000005`.
  - Load test ROMs through `rom_load` instead of asking for manual UI steps.
- Download artifacts and write scratch files into the workspace `tmp/`
  directory (`<repo>/tmp`), not the system temp path; the user inspects that
  directory visually. It is gitignored, so leftovers never reach commits.
- Validation does not require the harness MCP connection: `live-smoke.sh`
  and raw HTTP calls against `http://127.0.0.1:8767/mcp` exercise every tool
  without the cached catalog. Prefer this path for build/test loops so a
  stale harness catalog never blocks verification.
- The harness caches the MCP tool catalog per session. Newly added or changed
  tools stay invisible or stale inside the running harness session even after
  a successful rebuild, reinstall, and pair restart. Whenever the work needs
  fresh harness MCP context — new tools, changed schemas, or first use — ask
  the user to reload the connection (`/mcp`, then disable and re-enable the
  `exodus` server) and wait for their confirmation before calling those tools
  through the harness or subagents; keep validating over raw HTTP meanwhile.
- `./scripts/test.sh --windows-live` runs the named-pipe integration suite
  against a real Windows pipe through interop; it does not start Exodus.

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
