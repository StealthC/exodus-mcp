# Exodus MCP

Exodus MCP is a local, native bridge that will expose the [Exodus Emulation
Platform](https://github.com/StealthC/Exodus) to MCP clients for Sega
Mega Drive / Genesis ROM analysis.

The project is in its foundation phase. The checked-in Go command currently
offers only a development health endpoint; it does **not** expose `/mcp` or
claim MCP conformance yet.

## Goals

- Provide a safe, local Streamable HTTP MCP endpoint for analysis agents.
- Access Exodus through a native C++ extension, not by modifying the emulator
  core whenever possible.
- Preserve upstream maintainability with Exodus pinned as a Git submodule.
- Support independent agent analysis contexts using explicit handles, while
  serializing access to the single emulator instance.
- Keep large binaries, traces, screenshots, and structured analysis results
  outside the model context by making artifacts directly retrievable.
- Offer an optional scripting layer later, outside the emulator process.

## Architecture

```text
MCP client (OpenCode, other hosts)
        │ Streamable HTTP / JSON-RPC 2.0
        ▼
exodus-mcp server (Go)
        │ authenticated local IPC
        ▼
ExodusMcpPlugin.dll (C++)
        │ serialized emulator operations
        ▼
Exodus process and Mega Drive modules
```

The server will follow MCP `2026-07-28` as its normative protocol target. It
will implement a deliberately bounded dual-era compatibility layer for clients
that still use an initialization-based revision. Details are in
[MCP compatibility](docs/MCP-COMPATIBILITY.md).

## Artifact-first output

ROMs, memory dumps, disassemblies, traces, and screenshots can be much larger
than an agent's useful context window. Tools will therefore return a compact,
sanitized summary by default and place the full output in an immutable artifact.
The result will include the artifact's size, hash, MIME type, direct local URL,
and MCP resource URI. Scripts can download and process the raw data directly;
an agent can request a small preview, a range, or a parsed/sanitized derivative
when it actually needs content in context.

See [Artifact delivery](docs/ARTIFACTS.md) for the contract.

## Data interpretation

Every multi-byte value reported by a tool will identify its byte order and
address space. The initial Mega Drive baseline is M68K `big-endian` and Z80
`little-endian`; raw byte ranges retain address order and are not implicitly
decoded. VDP data is reported with device-specific interpretation metadata.

## Repository layout

```text
cmd/exodus-mcp/       Go server entry point
native-plugin/        future C++ Exodus extension
docs/                 architecture, build, protocol, and CI documents
vendor/exodus/        pinned StealthC/Exodus Git submodule
```

## Development quick start

```bash
go test ./...
go run ./cmd/exodus-mcp
curl http://127.0.0.1:8767/healthz
```

See [Development](docs/DEVELOPMENT.md) for the local workflow and
[Building Exodus](docs/BUILD.md) for the emulator build procedure.

## Status

- [x] Exodus fork pinned as a submodule.
- [x] Reproducible Exodus build documentation and CI baseline.
- [x] Go module, formatting rules, basic test, and development health endpoint.
- [ ] Native extension discovery and lifecycle spike.
- [ ] Local IPC contract and serialized command scheduler.
- [ ] MCP `2026-07-28` conformance suite and `/mcp` endpoint.
- [ ] Legacy-client compatibility tests with OpenCode.

See the phased [tool roadmap](docs/ROADMAP.md).

## License

The license for `exodus-mcp` has not been selected yet. Exodus itself is
MIT-licensed; its license notice remains applicable to the submodule and any
redistributed Exodus-derived material.
