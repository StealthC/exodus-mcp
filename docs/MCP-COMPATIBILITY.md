# MCP Protocol and Compatibility Policy

## Normative target

The server will implement the [MCP specification revision
2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28) as its
normative protocol target. The specification's TypeScript schema is the source
of truth; SDK behavior is never a substitute for the specification.

The modern endpoint will be `/mcp` and will implement Streamable HTTP:

- one UTF-8 JSON-RPC 2.0 request or notification per HTTP `POST`;
- `application/json` or request-scoped `text/event-stream` responses;
- per-request `_meta` protocol version, client identity, and capabilities;
- required `MCP-Protocol-Version`, `Mcp-Method`, and applicable `Mcp-Name`
  header validation;
- `server/discover` and `UnsupportedProtocolVersionError` (`-32022`);
- required `resultType`, cache hints, and deterministic list order;
- POST-based `subscriptions/listen` if and when change notifications are added.

The server will bind to `127.0.0.1` by default, validate `Origin`, and reject
header/body mismatches with the specification's `HeaderMismatch` error
(`-32020`).

## Explicitly not inherited from older revisions

Modern HTTP behavior will not mint `Mcp-Session-Id` values, accept HTTP `GET`
or `DELETE` at `/mcp`, or implement resumable SSE. Those mechanisms were
removed in 2026-07-28.

## Legacy compatibility

The compatibility adapter will be dual-era, with `2025-11-25` as the initial
legacy target. It will be isolated from the modern dispatcher and tested as a
separate behavior.

Compatibility priority:

1. Correct modern `2026-07-28` behavior.
2. Legacy `initialize` handshake and POST request/response flow.
3. Legacy HTTP sessions and SSE only when an observed client requires them.
4. Deprecated 2024-11-05 HTTP+SSE only behind an explicit compatibility flag.

No legacy behavior may weaken modern Origin checks, authentication, request
validation, or context isolation.

## Large data and resources

MCP resources are useful for discovery and small text artifacts, but a raw
`resources/read` response can require large Base64 payloads and consume an
agent's context. High-volume data is therefore delivered through the
artifact-first contract: an MCP result describes the artifact and an
authenticated loopback URL streams its raw bytes, optionally by HTTP range.
The corresponding MCP resource remains available for metadata and bounded
previews, not as the default bulk transfer mechanism.

## Test policy

- Maintain fixture-based conformance tests for modern request headers, `_meta`,
  error codes, notifications, JSON-RPC IDs, and response content types.
- Add a regression fixture for every interoperability difference found in
  OpenCode or another MCP client.
- Test the Go HTTP layer without Exodus; test the native bridge separately;
  use a small end-to-end suite only for the combined path.
