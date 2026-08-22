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
implements discovery and the initial status tools, but reports the native bridge
as unavailable until the C++ extension and IPC transport are complete.

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
