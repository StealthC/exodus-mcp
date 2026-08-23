# Development

## Toolchains

- Go 1.24 or newer for the HTTP server and its tests.
- Visual Studio with MSVC v143 and a Windows SDK for Exodus and the future
  native extension. See [Building Exodus](BUILD.md).

## Commands

```bash
gofmt -w cmd
go test ./...
go run ./cmd/exodus-mcp
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
EXODUS_MCP_EXODUS_DIR='F:\projects\kid\emulators\Exodus_2.1' ./scripts/run-windows.sh
```

`EXODUS_MCP_EXODUS_DIR` must be a Windows path because `build.bat` and
`run.bat` run through `cmd.exe`. Extra launcher arguments can be forwarded,
for example `./scripts/run-windows.sh --listen 127.0.0.1:9000`.

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

## Quality gates

Before every commit:

1. Run `gofmt -w` on changed Go files.
2. Run `go test ./...`.
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
