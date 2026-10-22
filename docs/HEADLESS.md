# Headless Exodus host

Status: **planned — not implemented.** This document records the assessment,
the recommended design, the work phases, and the acceptance criteria for
running Exodus without a visible window and with logs on the terminal.

Baseline for the assessment: fork pin `de9c69e` plus the current `exodus-mcp`
native plugin (`ExodusMcpPlugin` 0.8.0). `Exodus.exe` is a Win32 GUI
application today and parses no command-line arguments at all: `WinMain` at
`vendor/exodus/Exodus/main.cpp:30` receives `lpCmdLine` and never reads it (the
only occurrence of a command-line API in the whole tree). There is no
`--headless`, no `--rom`, and no hidden-window path.

## Purpose

Make the emulator runnable by automation without depending on an interactive
desktop:

1. **Windowless process.** No main window, docking layout, dashboards, OpenGL
   view, workspace, joystick polling, or message box.
2. **Logs in the terminal.** The emulator's structured log entries (level,
   source, time, text) stream to stdout (and optionally a file) instead of being
   visible only in the Event Log view.
3. **Predictable lifecycle.** Deterministic startup from arguments, deterministic
   connector mapping, clean shutdown that still persists `settings.xml`, and
   exit codes that automation can trust.
4. **CI-friendly.** Removing focus, DPI, docking-layout, screensaver, and
   accessibility from the execution path.

### Non-goals

- Parallel emulation inside one process. Concurrency stays at "one Exodus
  process per bridge" (`docs/ARCHITECTURE.md`).
- Replacing the GUI. The windowed host keeps working exactly as today.
- New MCP capabilities. The tool catalog and bridge protocol do not change;
  headless only changes *how the emulator process is hosted*.
- Session 0 / Windows service support in the first version (see
  [Risks](#risks-and-mitigations)).

## What the code already allows

The heavy machinery is already window-free. Verified against the pinned fork:

| Property | Evidence |
| --- | --- |
| The system core never creates a window and never holds an `HWND` | `vendor/exodus/System/System.cpp` (no `HWND`/`CreateWindow` in `System/`); its constructor only stores `IGUIExtensionInterface&` (`System.cpp:20`) |
| The system core reads exactly one GUI preference | `GetGlobalPreferenceShowDebugConsole()` in the throttle path, `System.cpp:2491` |
| Device DLLs create no windows and no views | no `CreateWindow`/`CreateView`/`GetViewManager` anywhere under `vendor/exodus/Devices/` |
| Frames do not come from the screen | the plugin renders `frame_capture` from the VDP image buffer (`native-plugin/ExodusMcpPlugin.cpp:1557`, using `GetImageBufferLineCount`/`LockImageBufferData`), so it keeps working with no window; the visible screen is only an OpenGL view (`Extensions/315-5313Menus/ImageView.cpp:549`) |
| The MCP plugin is already headless | plain thread plus named pipe (`ExodusMcpPlugin.cpp:524`), configured by `EXODUS_MCP_PIPE_NAME`/`EXODUS_MCP_CAPABILITY` (`:503-504`), and **zero** `MessageBox`/`DialogBox` calls |
| Logs are already structured and pollable | `ISystemGUIInterface::GetEventLog`/`GetEventLogLastModifiedToken` (`ExodusSDK/SystemInterface/ISystemGUIInterface.h:51-55`), entries expose level/source/time/text (`ExodusSDK/ExtensionInterface/ILogEntry.h`) |
| Console plumbing already exists | `BindCrtHandlesToStdHandles()` in `Support Libraries/WindowsSupport/WindowFunctions.cpp:195` |
| Audio failure is not fatal | `waveOutOpen` failure is logged and ignored (`Support Libraries/AudioStream/AudioStream.cpp:488-492`) |
| The launcher already forwards emulator arguments | `--exodus-arg` (`cmd/exodus-mcp/main.go:56`), pipe capability via environment (`internal/bridge/launch.go:61-62`) |
| Module loading over the interface needs no window | the plugin loads ROMs with `gui.LoadModuleFromFile(...)` (`ExodusMcpPlugin.cpp:2806`) |

## Where the GUI coupling actually lives

Everything below is inside the host executable (`vendor/exodus/Exodus/`) and
inside a few error paths of the module extension, not inside the emulation core.

| Coupling | Location | Headless consequence |
| --- | --- | --- |
| `IGUIExtensionInterface` must be implemented (30 pure virtuals) | `ExodusSDK/ExtensionInterface/IGUIExtensionInterface.h` | new host class; dialogs return `false`, paths/prefs/logging are real |
| `IViewManager` must be implemented (10 pure virtuals) | `ExodusSDK/ExtensionInterface/IViewManager.h` | no-op implementation; no view is ever opened |
| Main window creation and `ShowWindow` | `Exodus/ExodusInterface.cpp:130`, `:373` | not called at all in headless |
| Assembly scan behind a modal progress dialog | `ExodusInterface.cpp:1659` → `IDD_LOADPLUGIN` at `:1671`; the synchronous variant exists at `:1687` | call the synchronous variant directly |
| Module load behind `IDD_LOADMODULE`, view pause/resume, connector-selection dialog `IDD_MAPCONNECTOR` | `ExodusInterface.cpp:1005-1145` (pause `:1010`, mapping `:1080`, progress `:1108`) | re-implement the connector mapping deterministically and poll `LoadModuleSynchronousComplete()` (`ISystemGUIInterface.h:121-126`) instead of showing progress |
| Module unload behind `IDD_UNLOADMODULE` | `ExodusInterface.cpp:1167`/`:1176`, `:1190`/`:1201` | synchronous unload; this is the path the plugin's `rom_load` already takes (`ExodusMcpPlugin.cpp:2801`) |
| Errors are message boxes | 12 sites in `ExodusInterface.cpp`, 5 in `Extensions/MDExtensions/MegaDriveROMLoader.cpp:129,247,366,376,386` (17 total), plus `SafeMessageBox` itself at `Support Libraries/WindowsSupport/WindowFunctions.cpp:1005` | would block forever with no desktop; must become log entries (see phase H3) |
| Physical input is handled by view key handlers | `Extensions/315-5313Menus/ImageView.cpp` keyboard handlers | headless has no physical input; `input_set` over the bridge is the only input path |
| Configuration is persisted on clean shutdown | `ExodusInterface.cpp:1308` | headless host must save prefs on exit |
| Graceful stop relies on `WM_CLOSE` | `scripts/stop-windows.sh` | headless needs its own shutdown signal |

## Target architecture

```text
MCP client
   | Streamable HTTP
   v
exodus-mcp (Go)                      unchanged
   | authenticated named pipe + capability (environment)
   v
ExodusMcpPlugin.dll (C++)            unchanged
   | in-process interface calls
   v
ExodusHeadless.exe (new host)        this repository
   | ISystemGUIInterface (dynamic load of System.dll)
   v
System.dll + Assemblies/*.dll        unchanged
```

### Decisions

**D1 — A second host executable in this repository, not a flag in the GUI exe.**
`native-host/` builds `ExodusHeadless.exe` as a console-subsystem application
that links the same support libraries the plugin already links, using the same
vcxproj pattern (`native-plugin/ExodusMcpPlugin.vcxproj` imports the fork's
property sheets and project references). Benefits: no Win32 window code in the
headless path, a real stdout, and no growing divergence from upstream. The
windowed `Exodus.exe` remains untouched.

**D2 — The MCP plugin is reused unchanged.** It self-configures from environment
variables, so the host needs no knowledge of the bridge, capability, or
protocol. Host and plugin evolve independently.

**D3 — Logs come from the emulator's own log ring buffer.** A relay thread polls
`GetEventLogLastModifiedToken()`/`GetEventLog()` and prints new entries as
`<time> <level> <source> <text>`; `--log-format json` emits one JSON object per
line for CI. No new logging API is needed.

**D4 — No views.** `IViewManager` is a no-op: `OpenView` returns `false` and
logs a debug line. Module definition view requests, workspace layouts, and
dashboard state are ignored. This is the intended semantic: headless has no
display, and observing graphics goes through `frame_capture` and the VDP tools.

**D5 — Errors become log entries, not dialogs.** Add a host-side error reporting
virtual to `IGUIExtensionInterface` (bumped interface version) and route the 17
`SafeMessageBox` sites through it. The windowed host implements it as the
current message box, so GUI behavior is preserved; the headless host writes an
`Error` log entry and returns the failure to its caller. The alternative
(intercepting `MessageBoxW` process-wide) is rejected: `WindowsSupport` is
statically linked into each module DLL, so a handler installed by the host does
not reach the modules.

**D6 — Explicit lifecycle.** Command line: `--rom <path>`, `--system <module>`,
`--run`/`--no-run`, `--no-throttle`, `--log-file <path>`, `--log-format`,
`--ready-file <path>`, `--shutdown-on-stdin-eof`, `--exit-after <seconds>`.
Shutdown: a bridge `shutdown` operation or a named event, plus `CTRL_BREAK`
handling; `WM_CLOSE` is not available. `settings.xml` is written on exit.

**D7 — Audio is optional.** Default is the current device output so a desktop
session behaves normally; `--audio=null` (or `EXODUS_MCP_AUDIO=null`) selects a
silent sink so no `waveOut` device is required and logs stay clean.

## Phases

Estimates assume one engineer already familiar with this codebase, and include
reading and validation time. They are working days, not calendar days.

| Phase | Scope | Estimate | Done when |
| --- | --- | --- | --- |
| **H0** *(optional)* | Terminal log relay for the current windowed exe: poll the event log, print to stdout, add the console handles via `BindCrtHandlesToStdHandles` | 0.5 d | `run-windows.sh` log shows emulator log lines while the window is still visible |
| **H1** | `native-host/` skeleton: console subsystem, argument parsing, prefs load/save (reusing the `InitializePrefs`/`ReadPrefs` logic), `System.dll` boot (the ~40 lines of `main.cpp:60-83`), synchronous assembly scan, log relay thread, exit codes, `--ready-file` | 2–3 d | the host starts, registers devices/extensions, logs a startup summary, and exits 0 on request with `settings.xml` written |
| **H2** | `HeadlessGUIInterface` (30 virtuals) + `NoOpViewManager` (10 virtuals): paths, prefs, file streams, `LoadAssembly`, deterministic connector mapping, `LoadModuleFromFile` without dialogs or view pause, synchronous `UnloadModule`/`UnloadAllModules`, `GetMainWindowHandle() == nullptr`, file selection returns `false` | 2–3 d | `--rom` loads a cartridge and `--run` starts it; `frame_capture` and `cpu_control` work end to end without a window |
| **H3** | Fork change: host error reporting virtual + interface version bump, 17 `SafeMessageBox` sites routed through it, windowed host implements the message box | 1–2 d | a fault injection (missing ROM, ambiguous connector, failing plugin) produces an `Error` log line and a non-zero exit, and no dialog can appear |
| **H4** | Lifecycle and operations: shutdown operation/event, `CTRL_BREAK`, `--exit-after`, `--shutdown-on-stdin-eof`, `stop-windows.sh` headless path, `run-windows.sh`/`.env` support, `build-windows.sh` builds and installs the host | 1.5 d | scripts can build, start, and stop the headless pair without any GUI interaction |
| **H5** | Desktop-dependency audit and audio: null sink, verify no `GetDC(NULL)`/`joyGetNumDevs`/`waveOut` dependency in the headless path, confirm no window handles are created | 1.5 d | `Get-Process` reports `MainWindowHandle 0` for the host, and the pair runs with no audio device |
| **H6** | Validation, CI, documentation: `live-smoke.sh --full` against the headless pair, focused checks, Windows CI job, docs updates | 2 d | the acceptance list below is green and documented |

**Total: 10–14 working days** (about 2–3 calendar weeks), with a usable MVP at
the end of H2 (~6–8 days).

### Rejected for now: hidden-window stopgap

Creating the existing main window with `SW_HIDE`, skipping workspace restore,
and adding a log relay is roughly one day of work. It is rejected as the target
design because it still requires an interactive desktop, still runs the docking
window and message loop, and can still block on a modal dialog — it buys no
robustness for CI. It remains a valid emergency stopgap if the schedule
requires something this week.

## Definition of done

1. `bash ./scripts/build-windows.sh` produces `native-host\bin\ExodusHeadless.exe`
   (Release x64) and installs it into the test install root.
2. `EXODUS_MCP_EXODUS_EXE=ExodusHeadless.exe` selects the host; the Go server
   pairs over the existing pipe; `/healthz` reports the same build version.
3. `bash ./scripts/live-smoke.sh --full` passes against the headless pair
   (ROM load, pause/run/step, breakpoints, watchpoints, VDP reads and exports,
   trace/coverage, memory search/diff, leases, writes/freeze, frame advance,
   input, savestates, experiment fixture).
4. `Get-Process ExodusHeadless | Where-Object MainWindowHandle -ne 0` returns
   nothing, and the process owns no visible window.
5. Log lines appear on stdout with time, level, source, and text; no entry is
   lost between polls; `--log-format json` produces one object per line.
6. `bash ./scripts/stop-windows.sh` stops the headless pair gracefully and
   `settings.xml` is updated, with the same or shorter grace period than today.
7. Every failure path tested in H3 terminates or reports without any dialog.
8. `docs/HEADLESS.md`, `docs/BUILD.md`, `docs/DEVELOPMENT.md`, and
   `docs/ROADMAP.md` describe the delivered behavior.

## Validation plan

```bash
# build the host together with the plugin and the server
bash ./scripts/build-windows.sh

# start the pair against the headless host (background), then poll health.
# The launcher already resolves EXODUS_MCP_EXODUS_EXE inside the install root
# and passes it as --exodus, so no Go change is required for this step.
EXODUS_MCP_EXODUS_EXE=ExodusHeadless.exe \
  bash ./scripts/run-windows.sh > tmp/run-windows.log 2>&1 &
curl -s http://127.0.0.1:8768/healthz

# full behavioral gate
bash ./scripts/live-smoke.sh --full

# focused evidence: no window, log lines, deterministic mapping
powershell.exe -NoProfile -Command \
  "Get-Process ExodusHeadless | Select-Object Id,MainWindowHandle,StartTime"
grep -E '^[0-9-]+ [0-9:.]+ (Info|Warning|Error)' tmp/run-windows.log | head

# graceful stop
bash ./scripts/stop-windows.sh
```

Determinism must be re-checked after H2: paused-frame determinism, `frame_advance`
counts, and throttling-on versus `--no-throttle` behavior, because the headless
host removes the GUI-driven timing that the windowed pair had
(`DeviceContext` uses `Sleep(0)` plus `timeGetTime`, `System.cpp:2491`).

## Risks and mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| A message box blocks a headless run forever | run hangs, no diagnostics | H3 routes all 17 sites; acceptance requires fault injection with no dialog |
| Ambiguous connector mapping changed behavior | ROM load fails or maps the wrong slot | explicit deterministic policy (first free connector of the matching class in loaded order), logged with the chosen connector; single-cartridge modules are the common case |
| Hidden dependency on a screen or session | `GetDC(NULL)`, `waveOut`, `joyGetNumDevs` misbehave in session 0 | H5 audit; run as an ordinary process in an interactive session; session-0 support out of scope |
| Timing differences vs. the GUI host | frame determinism tests drift | H6 re-runs the determinism checks with throttle on and off |
| Fork divergence grows | upstream merges get harder | host code lives in this repository; the fork patch is limited to the error-reporting virtual plus 17 call sites, in small reviewable commits |
| Plugin assumptions break | bridge failures at startup | plugin needs only environment variables and the interface; validated in H4/H6 |
| Two instances share physical input | confusing test results | headless has no physical input at all by design; `input_set` is the only path, and this is documented |

## Open decisions

1. **Install naming.** Ship `ExodusHeadless.exe` beside `Exodus.exe` (proposed),
   or fold the behavior into `Exodus.exe --headless` later? Both can coexist;
   the recommended order is headless host first, optional flag second.
2. **Launcher default.** Should `exodus-mcp` prefer the headless host when both
   are present (`cmd/exodus-mcp/main.go:184`, `findExodusBeside`), or keep
   `Exodus.exe` as the default and require `--exodus`/`EXODUS_MCP_EXODUS_EXE`?
   Recommendation: keep the GUI as default, document the headless switch, and
   add an opt-in environment flag `EXODUS_MCP_PREFER_HEADLESS=1`.
3. **`--rom` argument.** Recommended yes (CI smoke without MCP), even though
   `rom_load` already exists over the bridge.
4. **Audio default.** Real device when available with `--audio=null` opt-out
   (proposed), or always silent in headless?
5. **Session 0 / service.** Out of scope for v1 (proposed); revisit only if CI
   or deployment requires it.

## Planned file changes

| Path | Change |
| --- | --- |
| `native-host/ExodusHeadless.vcxproj`, `native-host/*.cpp/.h` | new host project: arguments, prefs, system boot, interfaces, log relay, lifecycle |
| `scripts/internal/build-windows.bat` | build and install the host next to the plugin and server |
| `scripts/stop-windows.sh` (graceful headless stop), `.env.example` (`EXODUS_MCP_EXODUS_EXE=ExodusHeadless.exe`) | headless selection and shutdown path; `run-windows.sh` needs no change because it already forwards `--exodus` |
| `cmd/exodus-mcp/main.go`, `internal/bridge/launch.go` | optional headless preference; no protocol change |
| `vendor/exodus/ExodusSDK/ExtensionInterface/IGUIExtensionInterface.h` | host error reporting virtual + interface version bump |
| `vendor/exodus/Exodus/ExodusInterface.cpp` (12 sites), `vendor/exodus/Extensions/MDExtensions/MegaDriveROMLoader.cpp` (5 sites) | route errors through the new virtual, preserving GUI behavior |
| `docs/HEADLESS.md`, `docs/BUILD.md`, `docs/DEVELOPMENT.md`, `docs/ROADMAP.md`, `AGENTS.md` | document the host, its switches, and the validation gate |
