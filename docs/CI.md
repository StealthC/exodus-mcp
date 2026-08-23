# CI

CI is deliberately split by ownership:

- `StealthC/exodus-mcp` validates the Go HTTP server, its protocol tests, and
  later the native-plugin project against a pinned Exodus release.
- `StealthC/Exodus` validates and publishes the forked emulator. It owns the
  Visual Studio build and its third-party source bootstrap.

The MCP repository must not compile Exodus directly. The upstream repository
intentionally ignores the contents of `Third/`; a clean submodule checkout has
the Visual Studio project files but not the source code that those projects
compile. The former job consequently could never be reproducible.

## Dependency update policy

Keep `origin` in the submodule as `StealthC/Exodus` and retain
`RogerSanders/Exodus` as `upstream`. Merge upstream into the fork, validate and
publish the fork there, then advance the MCP submodule pin in a separate pull
request. Do not copy Exodus into this repository or use a Git subtree.

## Runner policy

Use `windows-2022` as the required baseline because it targets Visual Studio
2022 and v143, the Exodus-declared toolset. Do not make `windows-latest` the
only target: it moved to newer Visual Studio 2026 images. Add it later as an
allowed-to-fail scheduled compatibility check. See the current
[runner image inventory](https://github.com/actions/runner-images) for changes.

## Fork build workflow

The ready-to-copy workflow and the third-party package contract are in
[Exodus fork CI](EXODUS-FORK-CI.md). Use that workflow in `StealthC/Exodus`,
not in this repository.

## Plugin CI evolution

The native plugin is an independent `native-plugin/` project consuming the
Exodus SDK through the submodule's property sheets and project references.
The Windows CI job compiles it with `Debug | x64` against the pinned
submodule and uploads the DLL as an artifact. A `Release | x64` plugin build
additionally requires Release third-party libraries from the fork
(`ThirdPartyLibraries.sln`), so it stays a local, documented step for now.

Current jobs:

- `go-linux`: formatting, vet, race-enabled tests, and `GOOS=windows`
  cross-compilation gates on Ubuntu.
- `windows`: native Go test run with the race detector plus the native
  plugin compile on `windows-2022` (v143 toolset baseline).

Required checks over time: Exodus Debug/Release x64 builds in the fork
pipeline, HTTP/IPC unit tests without an emulator (done), live named-pipe
client integration tests on the Windows runner (in place via the fake
plugin suite), and a legal-ROM or open-fixture smoke test.
