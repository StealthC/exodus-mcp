# Trace Capture Crash Investigation

Status: **resolved (2026-08-23)** — see section 0 for the resolution. The
remaining sections preserve the investigation history exactly as handed off.

## 0. Resolution

Three independent defects were confirmed, and all are fixed:

1. **The crash itself was plugin-side, not upstream.** A minidump of the
   original 2026-08-22 crash placed the faulting instruction inside
   `ExodusMcpPlugin.dll`, and a guarded (SEH) reproduction on 2026-08-23
   caught the access violation inside
   `Marshal::Ret<std::vector<TraceLogEntry>>::operator vector` while
   unpacking `GetTraceLog()`'s marshaled return value — reproducing even
   with the system paused, which rules out every enable-race hypothesis in
   section 5. The marshal machinery is simply not safe to drive through this
   plugin's template instantiations: `Ret<vector<TraceLogEntry>>` faults,
   `In<std::wstring>` silently delivers an empty string host-side, and
   complex-type probes hang nondeterministically, while plain POD virtual
   calls and `Ret<std::wstring>` (verified with `GetDeviceInstanceName`)
   work fine.
2. **The test install mixed 2018 upstream binaries with fork builds.** The
   launcher's install directory still shipped the original release-era
   `M68000.dll`, `Z80.dll`, and `System.dll`, so interface extensions
   appended in the fork (and any marshal behavior depending on them)
   diverged from the vtables the plugin saw. `build-fork-windows.bat` now
   installs `System.dll` and every rebuilt `Assemblies/*.dll` together with
   the exe; binaries move as one unit.
3. **The trace-enable flag raced.** `Processor::_traceLogEnabled` was a
   `volatile bool` toggled across threads (section 4.2); it is now
   `std::atomic<bool>`.

The tool no longer calls `GetTraceLog()` at all. `cpu_trace_capture` now:
stops the system, configures the processor trace with the new fork POD
setter `IProcessor::SetTraceFileLoggingPathAscii(const char*)` (the
`Marshal::In<std::wstring>` path setter silently failed per defect 1), lets
the worker write the existing trace-file format to a temporary file during
the capture window, stops the system again, parses the file itself, and
restores the prior run state and trace flags. Verified live against Kid
Chameleon: 10 alternating M68K/Z80 captures under stress with zero crashes,
correct disassembly in both processors, and the emulator responsive
throughout.

## 1. Context

- `exodus-mcp` (Go HTTP/MCP server) talks over an authenticated Windows named
  pipe to `ExodusMcpPlugin` (C++ extension loaded inside `Exodus.nightly.exe`,
  Debug x64 build of the pinned fork).
- Target: Sega Mega Drive module, Kid Chameleon ROM loaded, system running.
- Plugin command `trace_capture` asks `IProcessor` (M68000) for an execution
  trace snapshot and returns it as a text artifact.

Everything else works. Validated live against this exact session:

| Tool | Status |
| --- | --- |
| bridge_status, emulator_status, target_info | PASS |
| memory_spaces_list (10 spaces) | PASS |
| memory_read (raw/hexdump/array_u8, u16 BE decode, caps, unknown-space, byte-order-mismatch errors) | PASS |
| m68k/z80_read_memory (bus and device paths agree byte-for-byte, "SEGA MEGA DRIVE" header at 0x100) | PASS |
| memory_dump → artifact_get → artifact_preview roundtrip | PASS |
| m68k/z80_registers | PASS |
| m68k_disassemble (live PC default via typed interface, explicit address, count cap) | PASS |
| symbols_set/list/clear, context_create/close (+default protection) | PASS |
| **cpu_trace_capture** | **CRASHES THE EMULATOR** |

## 2. Reproduction recipe

1. Start pair: `.\build.bat` then `.\run.bat`; load Kid Chameleon; let it run.
2. Call `cpu_trace_capture {cpu:"m68k", max_entries:200, timeout_ms:3000}`.
3. Response dies mid-flight (`bridge_error: read bridge response: EOF`);
   `tasklist` shows neither `Exodus.nightly.exe` nor `exodus-mcp.exe`
   (the server shuts down because its child died).

The original M68K reproduction was 3/3. On 2026-08-22, a fresh automated
test loaded `F:\projects\kid\rom\kid.bin`, confirmed `system_running:true`,
then ran both `m68k` and `z80` captures with `max_entries:50` and
`timeout_ms:500`. Both calls returned `bridge_error: read bridge response:
EOF`; the Exodus child exited with `0xc0000005` (access violation). The Go
launcher then exited as designed, so the Z80 failure confirms that the defect
is shared by the base `Processor` trace path rather than specific to M68000.

## 3. Attempt history (what changed between crashes)

| Attempt | Trace ops performed by plugin | Result |
| --- | --- | --- |
| 1 | `ClearTraceLog()` + `SetTraceLength(200)` + enable + poll `GetTraceLog()` every ~10 ms + restore + clear | Crash |
| 2 | Enable + poll `GetTraceLog()` every ~10 ms + restore (no resize/clear) | Crash |
| 3 | Enable flags + silent wait window + disable + Sleep(150 ms) + **one** `GetTraceLog()` snapshot | Crash |

Common denominator of all attempts: **enabling tracing (`SetTraceEnabled(true)`
+ `SetTraceDisassemble(true)`) against a running system, at all**. Each attempt
removed a previously suspected layer (resize race, clear race, concurrent
reader race) and the crash persisted, which shifts suspicion toward the
enable/disassemble path itself executing on the live CPU thread.

## 4. Source-level findings (verified, with citations)

All paths relative to `vendor/exodus/`.

### 4.1 Who runs where

- Trace writer runs on the **CPU worker thread**, once per opcode, from
  `M68000::ExecuteStep` region: `Devices/M68000/M68000.cpp:934`
  `RecordTrace(GetPC().GetData(), _currentCycle, _currentTime);`.
- Gate is an **unlocked** bool read: `ExodusSDK/Processor/Processor.inl:286-297`
  (`if (_traceLogEnabled) return RecordTraceInternal(...)`).
- `RecordTraceInternal` — `ExodusSDK/Processor/Processor.cpp:1081` — takes
  `std::unique_lock<std::mutex> lock(_debugMutex);` and then, when
  `_traceLogDisassemble` is true, calls **`GetOpcodeInfo(pc, opcodeInfo)`
  while still holding `_debugMutex`**, appends to the ring
  (`_traceLog[_traceLogNextWritePos % _traceLogLength] = std::move(entry)`)
  and optionally stages a text line into `_pendingTraceLogFileEntries`.

### 4.2 The mutex discipline

- `Processor::_debugMutex` guards: trace get/set (length/get-log/clear/
  disassemble/file-path/file-enable), breakpoints, watchpoints, call stack,
  active-disassembly structures, and `ExecuteCommit`/`ExecuteRollback`
  (`Processor.cpp:208/163`) which run **every timeslice** and copy
  `_traceLog ↔ _btraceLog` under the lock.
- `std::mutex` (non-recursive). Any second acquisition on the same thread is
  undefined behavior (deadlock or abort).
- **`Processor::SetTraceEnabled` (`Processor.cpp:916`) is the only trace
  mutator that does NOT take `_debugMutex`** — it writes `_traceLogEnabled`
  while the CPU thread reads it unlocked (`Processor.inl:294`). The member is
  declared `volatile bool` (`Processor.h:421`), not `std::atomic<bool>`.
  This is a C++ data race whenever MCP toggles tracing on a running system;
  `volatile` does not provide inter-thread synchronization, so the behavior is
  undefined. This is a confirmed concurrency defect, although it does not by
  itself identify the observed crash instruction or exception.

### 4.3 What GetOpcodeInfo does under that lock

`Devices/M68000/M68000.cpp:1262`:

```cpp
_externalReferenceLock.ObtainReadLock();     // RW lock #1
...
ReadMemoryTransparent(...)                   // transparent bus read
targetOpcodeType->Clone(); ... M68000Decode(...); M68000Disassemble(...)
GetResultantPCLocations(...); GetLabelTargetLocations(...)
...
_externalReferenceLock.ReleaseReadLock();
```

i.e. **for every traced opcode**, the CPU thread performs a full instruction
clone + decode + disassembly + PC-target analysis while holding
`_debugMutex`, and additionally acquires a second lock
(`_externalReferenceLock`, `M68000.h:302`; write sites only in
`AddReference`/`RemoveReference` at `M68000.cpp:356/369`).

### 4.4 Nested-lock candidates evaluated

| Candidate path (same thread) | Gate | Verdict for our session |
| --- | --- | --- |
| `GetMemorySpaceByte`/read path → watchpoint check → `CheckMemoryReadInternal` [locks `_debugMutex`, `Processor.cpp:703`] | `CheckMemoryRead` wrapper only locks when `_watchpointExists` (`Processor.inl:254-264`) | NOT armed (`_watchpointExists=false`, constructor `Processor.cpp:19`); no watchpoints were created |
| `M68000::GetOpcodeInfo` → base-class locked helpers (active-disassembly, labels) | none found in call graph audit | no second `_debugMutex` site identified inside the decode path |
| `_externalReferenceLock` recursion | write locks only at bind time | not held during execution |

Conclusion: **no smoking-gun double-acquisition was proven.** The remaining
structural facts that make this path suspicious are: (a) heavy work
(decode+disassemble+set allocations) executed per-opcode while holding
`_debugMutex` on a hot thread, with `ExecuteCommit`/`ExecuteRollback` and any
debug-window activity contending on the same mutex each timeslice; and
(b) `GetOpcodeInfo`'s decode allocating/cloning objects per opcode, which
turns a previously near-zero-cost flag flip into sustained allocation pressure
inside the emulation loop.

### 4.5 Ruled out

- Plugin-side container races around the capture (resize/clear/poll) — removed
  in attempt 3, crash persisted.
- Plugin JSON assembly buffer overruns — prefix buffer widened and width
  clamped (`sprintf_s` `%0*X` ≤ 12 into `char[64]`); values audited.
- Protocol/framing artifacts — the other 19 tools, including 8 MiB framed
  transfers, work flawlessly over the same pipe in the same session.
- Stale DLL/binary mismatch — hashes compared across `Assemblies/` and the
  target `Plugins/` folder before the final reproduction.

## 5. Ranked hypotheses

1. **H-A (primary): upstream trace-enable concurrency defect plus a hazard in
   `RecordTraceInternal`.** Toggling `_traceLogEnabled` has a confirmed data
   race, and the newly enabled CPU path runs `GetOpcodeInfo` under
   `_debugMutex`. Either this undefined behavior, a re-entrancy path not yet
   found, or sustained lock/alloc behavior under contention with
   `ExecuteCommit`/`ExecuteRollback` and debug views can cause the failure.
   Instrumented debugging inside Exodus (SEH/vectored handler or logging
   around `RecordTraceInternal`) is still needed to identify the crash site.
2. **H-B: starvation/livelock escalation.** Holding `_debugMutex` per opcode
   for a full decode starves `ExecuteCommit`/`Rollback` and any debug UI;
   if any component reacts to that by destroying/rebuilding state, the process
   can die. Speculative; would also explain "freeze then die" reports.
3. **H-C (low): residual plugin-side fault after snapshot** — post-snapshot
   processing is plain string building over copied data; audited but not
   formally excluded (could be excluded by crashing-vs-not experiments with
   the response body stubbed).

## 6. Key experiment (isolates upstream vs our usage)

With **no MCP involvement**: run Exodus normally, open the built-in processor
Trace debug window, enable trace + disassemble while the system is running.

- If stock Exodus crashes the same way → pure upstream bug in the trace
  path; fix belongs in the fork (see §8c), independent of MCP.
- If stock Exodus survives → the trigger is specific to how/when the plugin
  toggles state (timing/thread), and the file-based route below sidesteps it.

This experiment has not been run yet and is the cheapest decisive next step.

## 7. Recommended implementation paths (ranked)

### a. File-based capture (safe by construction, recommended first)

The writer already formats exactly what we need
(`Processor.cpp:1097-1118`): `address \t opcode \t args \t ;comment \t cycle
\t time`, staged in `_pendingTraceLogFileEntries` and flushed to disk inside
`ExecuteCommit` under `_debugMutex`.

Plugin flow: `SetTraceLoggingFilePath(<temp>)` →
`SetTraceFileLoggingEnabled(true)` → `SetTraceEnabled(true)` (+disassemble) →
wait window → disable both → read the **file from disk** (bounded tail),
delete temp file. `GetTraceLog()` is never called, so the shared vector is
only touched by Exodus itself. Residual risk: enabling tracing still flips
the hot path on, so if H-A is really "enable alone is unsafe," this also
triggers it — which is why §6 must run first.

### b. Capture only while paused

Wrap capture in explicit pause/resume (`ISystemExtensionInterface::
StopSystem`/`RunSystem`). Correctness-first but mutates global run state;
belongs behind the target-generation/control-lock contract (an internal
control lock for the bounded capture window), not the removed context leases.

### c. Upstream patch (fork commit)

First replace `_traceLogEnabled` with `std::atomic<bool>` and use explicit
acquire/release loads and stores in `RecordTrace`/`SetTraceEnabled`. Then move
the disassembly branch out from under `_debugMutex` in `RecordTraceInternal`
(pre-format outside the lock, or cache decoded text), or make
`GetTraceLog`/ring use a seqlock-style snapshot. Small, reviewable fork commit
per `AGENTS.md` upstream discipline.

## 8. Operational notes for whoever continues

- Build/test ritual: `.\build.bat` (MSBuild plugin → copies DLL to
  `F:\projects\kid\emulators\Exodus_2.1\Plugins` → builds
  `bin\exodus-mcp.exe`), `.\run.bat` (launches Exodus child with generated
  capability). Only ONE server may bind `127.0.0.1:8767`; announce restarts.
- Wire protocol v2 (both sides in this repo): flat key/value request lines;
  response = 8-hex-digit length prefix + UTF-8 JSON envelope
  `{protocol_version:2,id,status,data|error}`; plugin holds the connection
  until the client closes after reading (drain handshake). Do not reintroduce
  EOF-dependent reads — that deadlocked against the drain.
- Pipe transport pitfalls already solved (do not regress): client handle needs
  `FILE_FLAG_OVERLAPPED` for deadlines; server must not `DisconnectNamedPipe`
  before the client closes; `ConnectNamedPipe` polling proved unreliable —
  the server waits for requests by polling `ReadFile` instead (treat errno
  536=no client, 232=no data yet, 234=more data).
- Live PC comes from typed interfaces (`IM68000::GetPC()` /
  `IZ80::GetPC()`); `IProcessor::GetCurrentPC()` returns 0 unless a debugger
  break latched the CPU. `GetPCMask()` may return 0 pre-attachment — derive
  from `GetPCWidth()`. Both handled in `native-plugin/ExodusMcpPlugin.cpp`.
- Address-space ids emitted natively (stable for Mega Drive):
  `m68k-bus`(BE), `z80-bus`(LE), `mem-ram`(64 KiB BE), `mem-z80-ram`(8 KiB),
  `mem-boot-rom`(16 KiB BE), `mem-vdp-vram`(64 KiB), `mem-vdp-cram`(128 B),
  `mem-vdp-vsram`(80 B), `mem-vdp-spritecache`(320 B), `mem-rom`(cart, BE).
- Transport probe used for isolated protocol testing:
  `C:\Users\<user>\AppData\Local\Temp\pipeprobe\main.go` (run via
  `go run main.go` through Windows cmd). Round trip validated at ~1.6 ms.
- Relevant repo files: `native-plugin/ExodusMcpPlugin.cpp` (all bridge
  commands; see `BuildTraceCaptureData`), `internal/bridge/client_windows.go`
  (framed client), `internal/mcp/tools_cpu.go` (tool schemas),
  `docs/ARCHITECTURE.md`, `native-plugin/README.md`.
