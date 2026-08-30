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
- [Features](docs/FEATURES.md): delivered tool catalog, design rules, and validation status.
- [Tool roadmap](docs/ROADMAP.md): remaining planned phases and deferred work.
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

You can and should build, run, and validate the full Windows pair from WSL
yourself — the wrappers call Windows through interop. The complete loop below
was executed and verified against a real Windows install on 2026-08-25
(plugin C++ changes included); use it instead of asking the user to run
things. Do not run `exodus-mcp.exe` or Exodus directly from the Linux shell;
always go through the wrappers.

- Configuration lives in `.env` (copy from `.env.example`; required:
  `EXODUS_MCP_EXODUS_DIR`). Precedence is flag > environment > `.env` >
  default everywhere. The wrappers publish `EXODUS_MCP_*` variables to
  Windows processes via `WSLENV`; without that plumbing Windows children
  silently never see WSL-side overrides.

### Self-service build/run/validate loop

1. **Check what is running** before anything: `tasklist.exe | grep -iE
   "exodus"` plus `curl -s http://127.0.0.1:8768/healthz`.
   The repository shell wrappers are tracked without executable bits in some
   WSL checkouts; use `bash ./scripts/<name>.sh` (or restore execute bits
   locally) rather than assuming `./scripts/<name>.sh` is runnable.
   - The health response includes the build version (e.g.
     `v0.1.0-6-gcadc8a1`, stamped from `git describe`), so you can confirm
     which build is live before and after a rebuild.
   - Never start a second pair: only one process can bind the port, and each
     Exodus child pairs with one generated capability.
2. **Stop a running pair before building**: `bash ./scripts/stop-windows.sh`.
   - It asks Exodus to close gracefully (WM_CLOSE) so it can persist
     `settings.xml`, then force-kills after a grace period (`--grace-seconds`
     tunes it; `taskkill /F /IM ...` is the manual fallback). Windows locks
     loaded images, so the plugin DLL can only be replaced while Exodus is
     stopped.
   - `settings.xml` is written only on clean shutdown; key bindings
     (`Device.MapInput`) only via **File → Save System**. Prefer the graceful
     stop instead of raw `taskkill /F` whenever a clean exit matters.
3. **Build**: `bash ./scripts/build-windows.sh` (default `Release | x64`; pass
   `--config Debug` for Debug-CRT work). One command compiles the native
   plugin (`native-plugin/ExodusMcpPlugin.cpp` → `ExodusMcpPlugin.dll`),
   installs it into the test install (`EXODUS_MCP_EXODUS_DIR`), builds
   `bin/exodus-mcp.exe`, and copies it next to the emulator in that install
   root (a bare `exodus-mcp.exe` launch there auto-adopts `Exodus.exe`).
   Run it in the **foreground** when the build result is
   needed to continue — do not background it and poll with `sleep`.
   The final line prints the installed version, e.g. `bin\exodus-mcp.exe
   (version v0.1.0-6-gcadc8a1)`. For fork-side emulator changes use
   `bash ./scripts/build-fork.sh` instead (same stop-first rule).
4. **Run**: `bash ./scripts/run-windows.sh` **in the background** — the launcher
   does not return until the pair is closed, so a foreground invocation
   blocks the shell. Redirect its output to `tmp/run-windows.log`. Then poll
   `curl -s http://127.0.0.1:8768/healthz` from a separate foreground command
   until it answers `"ok"` (a plain `for` loop with a bounded retry count is
   fine; the pipe can lag the HTTP gate by tens of seconds on Debug builds),
   and inspect `tmp/run-windows.log` for startup errors before driving tools.
   The log also reports child exit codes such as `0xc0000005`.
5. **Validate**: `bash ./scripts/live-smoke.sh --full` against the running pair.
   - `--full` loads a test ROM itself through `rom_load` (default
     `F:\projects\kid\rom\kid.bin`; override with `EXODUS_MCP_SMOKE_ROM`),
     so no manual UI steps are needed, and covers pause/run, steps,
     breakpoint/watchpoint lifecycles, conditional breakpoints, paused frame
     determinism, VDP reads/exports, trace/coverage, rom_info, memory
     search/diff, leases, memory write/freeze, frame advance, input,
     save/load states, and the experiment fixture.
   - Read-only default checks (health, discovery, catalog, bridge, emulator
     status) run without a ROM.
   - Integration suites: `bash ./scripts/test.sh` (Linux gates) and
     `bash ./scripts/test.sh --windows-live` (named-pipe integration suite against
     a real Windows pipe through interop; it does not start Exodus).
   - The full smoke suite does not automatically exercise every newly added
     address-domain feature. After an address-translation change, run focused
     live checks against the freshly reported health version, for example:
     `bash tmp/mcp_call.sh memory_read '{"space":"mem-ram","address":"0xFF0000","address_space":"m68k-bus","length":4}'`
     and verify `space_address=0` plus `bus_address=16711680`; also verify an
     incompatible domain returns `invalid_params`. Save responses under
     `tmp/`, and use the modern `_meta` marker as `tmp/mcp_call.sh` does.
   - Expect the full loop to take a few minutes; the MSVC build alone is
     roughly two. This loop is the standard gate for plugin-side changes —
     it is what caught, for example, a `break_counter` echo regression in the
     conditional-breakpoint work (2026-08-25).

### Direct HTTP validation (bypassing the harness)

- Raw HTTP against `http://127.0.0.1:8768/mcp` exercises every tool without
  the cached MCP catalog; prefer it for build/test loops so a stale harness
  catalog never blocks verification.
- For the **modern** dispatcher (the one that returns `structuredContent`),
  the call params must carry
  `"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}`
  (plus headers `MCP-Protocol-Version: 2026-07-28`, `Mcp-Method:
  tools/call`, `Mcp-Name: <tool>`). Without `_meta` the request silently
  falls back to the legacy dispatcher, which returns only the text `content`
  field.
- The harness caches the MCP tool catalog per session. Newly added or changed
  tools stay invisible or stale inside the running harness session even after
  a successful rebuild, reinstall, and pair restart. Whenever the work needs
  fresh harness MCP context — new tools, changed schemas, or first use — ask
  the user to reload the connection (`/mcp`, then disable and re-enable the
  `exodus` server) and wait for their confirmation before calling those tools
  through the harness or subagents; keep validating over raw HTTP meanwhile.
- Download artifacts and write scratch files into the workspace `tmp/`
  directory (`<repo>/tmp`), not the system temp path; the user inspects that
  directory visually. It is gitignored, so leftovers never reach commits.

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
