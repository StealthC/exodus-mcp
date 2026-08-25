# Development

## Toolchains

- Go 1.26 or newer for the HTTP server and its tests. The bridge client relies
  on Go 1.26 `os.NewFile` overlapped-handle detection so pipe deadlines arm
  correctly; older toolchains fail every bridge command with "file type does
  not support deadline".
- Visual Studio with MSVC v143 and a Windows SDK for Exodus and the future
  native extension. See [Building Exodus](BUILD.md).

## Commands

```bash
gofmt -w cmd internal
go test -race ./...
go run ./cmd/exodus-mcp
./scripts/test.sh                  # all local gates: format, vet, tests,
                                   # GOOS=windows build/vet
./scripts/test.sh --windows-live   # also runs the named-pipe integration
                                   # suite against a real Windows pipe via
                                   # WSL interop
./scripts/build-fork.sh            # builds vendored Exodus and installs the
                                   # generated exe into the configured test
                                   # install (close the emulator first)
```

After launching the pair (`./scripts/run-windows.sh`), validate it without
touching emulator state:

```bash
./scripts/live-smoke.sh            # read-only protocol/tool checks
./scripts/live-smoke.sh --full     # adds pause/step/breakpoint/watchpoint/
                                   # frame-determinism checks and restores
                                   # running state afterwards
```

The current binary exposes `GET /healthz` and `POST /mcp`. The MCP endpoint
implements discovery and the initial status tools. `bridge_status` contacts the
native extension when its named-pipe configuration is supplied.

On Windows, point the server at a running `ExodusMcpPlugin` with the same pipe
configuration the Exodus process received:

```powershell
go run ./cmd/exodus-mcp --pipe-name '\\.\pipe\exodus-mcp-dev' --pipe-capability 'replace-with-the-generated-capability'
```

`bridge_status` makes a bounded status request through that pipe. To let the
server own the credentials and start Exodus as its child, use:

```powershell
go run ./cmd/exodus-mcp --exodus 'C:\path\to\Exodus.exe'
```

Repeat `--exodus-arg` for any Exodus command-line arguments. This mode creates
a new pipe name and capability for that one child process and never logs the
capability. When that child Exodus process exits, `exodus-mcp` shuts down its
local HTTP server and exits too.

The launcher reserves the HTTP port before it starts Exodus. A busy port fails
without opening Exodus; if the server stops after the child starts, it
terminates that child rather than leaving an orphaned emulator process.

## Windows server used from WSL

Keep the MCP server bound to `127.0.0.1`. In the default WSL2 NAT mode, WSL
cannot reach a Windows loopback server. On Windows 11, enable WSL mirrored
networking in `%USERPROFILE%\.wslconfig`, then restart the WSL VM; WSL and
Windows can subsequently reach each other's loopback services through
`127.0.0.1`.

Run the Windows build and launcher from WSL with the repository wrappers:

```bash
./scripts/build-windows.sh
./scripts/run-windows.sh
```

Both wrappers read configuration from the environment and `.env` (copy
`.env.example`), with one precedence chain everywhere: explicit flag >
environment variable > `.env` > built-in default. The required value is
`EXODUS_MCP_EXODUS_DIR`, a Windows path to the Exodus install; set
`EXODUS_MCP_EXODUS_EXE` when the emulator binary is not `Exodus.exe`. Extra
launcher arguments are forwarded, for example
`./scripts/run-windows.sh --listen 127.0.0.1:9000`.

## ROM Loading

`rom_load` replaces the active Mega Drive cartridge with an existing `.bin`,
`.gen`, or `.md` file. The `path` parameter is an absolute Windows path. The
plugin creates a minimal temporary module definition, unloads the previous
program module, and restores the prior running state after loading. Pass
`run: true` to start the loaded ROM when the system was previously paused. It
is a mutating operation intended for controlled local test automation.

## Processor Control

`cpu_pause` and `cpu_run` control global execution. `m68k_step` and
`z80_step` execute one instruction while keeping the system paused. The
generic `cpu_step_over` and `cpu_step_out` use Exodus debugger semantics.
`cpu_breakpoint_set`, `cpu_breakpoint_list`, and `cpu_breakpoint_remove`
manage exact-address execution breakpoints owned by the current MCP process.
Breakpoint IDs are invalid after an emulator restart.

`cpu_watchpoint_set`, `cpu_watchpoint_list`, and `cpu_watchpoint_remove`
manage read/write watchpoints owned by the current MCP process. A watchpoint
watches a byte range (`length`, default 1) for reads, writes, or both
(`access`). When the running system hits a watchpoint, Exodus pauses
execution with rollback, so the standard pause/run flow turns "who writes
this RAM address" into a deterministic stop. Watchpoints and breakpoints are
purged automatically when `rom_load` swaps cartridges, because the processor
devices that own them are destroyed with the loaded module.

## Experiments (`experiment_run`)

`experiment_run` executes operator-authored automation against the emulator:
Python 3 scripts (`.py`) for conditional/long-running automation, or
declarative JSON fixtures (`.json`) for short deterministic sequences. Both
live in the configured scripts directory and are mediated by the Go server —
scripts never talk to the native pipe or hold the bridge capability.

Configuration (flag > environment > `.env` > default):

- `--scripts` / `EXODUS_MCP_SCRIPTS_DIR`: allowed scripts root. The launcher
  defaults it to `<repo>\scripts\experiments` (where `smoke-input.json` and
  the `title-scan.py` example live); standalone runs default to
  `%TEMP%\exodus-mcp\scripts`.
- `--python` / `EXODUS_MCP_PYTHON`: interpreter for `.py` scripts
  (default `python` on Windows, `python3` elsewhere; resolved through PATH).
- `--experiment-timeout`: hard per-run cap (default 5 minutes); the tool's
  `timeout_ms` (default 30000, cap 300000) is clamped to it.
- `--experiment-max-steps` (default 200) and
  `--experiment-max-output-bytes` (default 1 MiB) bound step counts, each
  published artifact, and captured stderr.

Security model: scripts are trusted operator code; the server mediates only
*emulator access*, not the script itself. Interpreter isolation is limited to
a minimal environment (`-I`, `PYTHONNOUSERSITE`, `PYTHONDONTWRITEBYTECODE`,
explicit PATH) — do not place untrusted files in the scripts directory.

Requirements: `experiment_run` needs the exclusive lease of its analysis
context, like every other mutation entry point. It accepts `context`,
`lease_id`, `script` (plain `.py`/`.json` file name, no separators),
`arguments` (opaque JSON passed to the script), `initial_state_id` (loaded
through `state_load` before the first step), and `timeout_ms`.

Allowlist: `input_set`, `frame_advance`, `state_save`, `state_load`,
`memory_write`, `memory_read`, `memory_dump`, `memory_search`,
`frame_capture`, `vdp_status`, `vdp_pixel_info`, `vdp_sprite_table`,
`m68k_registers`, `z80_registers`, `cpu_coverage_capture`. Anything else —
including `cpu_run`, stepping, breakpoints/watchpoints, context/lease tools,
`rom_load`, and recursive `experiment_run` — fails with `tool_not_allowed`.
The server injects the experiment's `context` and `lease_id` into every call;
scripts cannot address another context.

Python protocol (bounded JSON lines over stdin/stdout):

1. Server writes `{"type":"init","experiment_id":…,"script":…,
   "arguments":…,"limits":{…}}` to stdin.
2. Script writes `{"type":"call","id":…,"tool":…,"arguments":{…}}` (or
   `{"type":"artifact","id":…,"kind":…,"mime_type":…,"data_base64":…}`, or
   `{"type":"complete","summary":{…}}`) to stdout — protocol JSON only;
   diagnostics belong on stderr.
3. Server replies per message with `{"type":"result","id":…,"ok":true|false,
   "value":…}` on stdin; tool failures are `ok:false` with a `{code,message}`
   payload and do not end the run.

The run always produces an `experiment-manifest` artifact (script digest,
arguments, per-step results, artifacts, status/error) and, when stderr was
captured, an `experiment-output` artifact; script-published artifacts are
stored under the context and their descriptors are replied inline. A
`context_mutation_log` entry records the whole run alongside the per-step
mutation entries the individual handlers already log.

Run `./scripts/live-smoke.sh --full` to validate the fixture path against a
loaded ROM.

## Quality gates

Before every commit:

1. Run `./scripts/test.sh` (format check, vet, race-enabled tests, and
   `GOOS=windows` build/vet gates mirroring CI). Use `gofmt -w` on changed
   Go files it reports.
2. For changes to `internal/bridge`, also run
   `./scripts/test.sh --windows-live` so the named-pipe integration suite
   executes against a real pipe.
3. Update `CHANGELOG.md` under `Unreleased` when behavior, compatibility,
   security, or user-visible functionality changes.
4. Update the relevant document when changing build, protocol, architecture,
   or deployment assumptions.
5. Update [Tool roadmap](ROADMAP.md) when a tool is added, deferred, or moves
   between phases. Add byte-order, address-space, and artifact tests for every
   tool that reads emulator data.

When releasing a version, move the `Unreleased` entries to a dated
`[x.y.z]` heading, add its comparison link, create an annotated `vX.Y.Z` tag,
and update the release notes from that exact changelog section.
