# Artifact Delivery

## Purpose

Exodus MCP handles data that can be much larger than a useful LLM context:
ROMs, memory regions, execution traces, screenshots, VDP data, disassembly,
and code/data coverage. The architecture must make those bytes available to
agent-written scripts without forcing an MCP client to insert the entire payload
into a conversation.

The default is **artifact-first**:

1. A tool writes its complete result to an immutable local artifact.
2. The tool response contains only a compact, sanitized summary and descriptor.
3. A client or script retrieves raw bytes from the local artifact URL, or asks
   for a small range, preview, or parsed derivative through a later tool call.

## Tool result contract

Tools that can produce significant output will return an object shaped like:

```json
{
  "summary": {
    "kind": "m68k-disassembly",
    "address_space": "m68k-bus",
    "start_address": "0x000100",
    "byte_order": "big-endian",
    "lines": 18420,
    "preview": "000100: move.l d0,(a0)\n...",
    "preview_truncated": true
  },
  "artifact": {
    "id": "art_01J...",
    "mime_type": "text/plain; charset=utf-8",
    "size_bytes": 1124059,
    "sha256": "...",
    "url": "http://127.0.0.1:8767/artifacts/art_01J...",
    "resource_uri": "exodus://artifacts/art_01J..."
  }
}
```

The exact response is MCP `structuredContent` where the negotiated protocol
permits it, with a concise `content` text summary for clients that do not parse
structured results. The artifact ID is opaque and never derived from a user
file path.

## Byte-order contract

Byte order is metadata about how a sequence of bytes is decoded into a value;
it is not a property of a single byte. Every multi-byte decoded field and every
artifact containing decoded scalar values must use one of these values:

- `big-endian`;
- `little-endian`;
- `not-applicable` for byte-only/raw representations;
- `unknown` only when the device contract has not yet been established.

Mega Drive policy:

- Motorola 68000 memory values are decoded as `big-endian`.
- Z80 multi-byte memory values are decoded as `little-endian`.
- Raw bytes preserve address order and use `not-applicable`; they are never
  silently decoded according to the host machine's byte order.
- VDP data is device- and register-specific. Tools must report the applicable
  interpretation per field, or return raw bytes plus `unknown` until it is
  implemented and verified.

Responses must additionally identify the address space or device, start
address, width in bits for scalars, and raw bytes when a decoded value could be
ambiguous. A tool may omit repeated byte-order metadata only when its schema
declares one fixed order and the result points back to that declaration.

## Retrieval modes

| Mode | Intended use | Default limit |
| --- | --- | --- |
| Summary | Agent reasoning in context | Small, sanitized text or JSON |
| Preview | Inspect a bounded portion | Explicit byte/line/token cap |
| Direct URL | Scripts, `curl`, binary parsers | Full bytes, HTTP `Range` supported |
| MCP resource | Discovery and small safe content | Bounded preview or metadata |
| Derived artifact | Sanitized CSV/JSON/text/image from raw data | Tool-specific cap |

Tools should expose an explicit output preference such as `output: "summary"`,
`"artifact"`, or `"both"`. A raw inline response is allowed only for a small,
caller-specified maximum. It is never the implicit default for binary data.

## HTTP artifact endpoint

The planned endpoint is:

```text
GET /artifacts/{artifact-id}
```

It returns the original content type, `Content-Length`, `ETag` derived from the
SHA-256, `Accept-Ranges: bytes`, and supports normal HTTP byte-range requests.
It uses the same local authentication policy as the MCP endpoint. The service
binds to loopback by default; a remote bind requires explicit configuration,
authentication, and Origin validation.

The endpoint will not accept filesystem paths, glob patterns, or arbitrary
URLs. IDs are server-generated, capability-like values and artifacts are scoped
to their analysis context. Retention limits, explicit deletion, and process-exit
cleanup will prevent unbounded disk growth.

## Sanitization and safety

- Summaries must be structurally valid JSON or text and must cap length before
  returning it to an agent.
- Treat ROM text, symbol names, comments, script output, and disassembly labels
  as untrusted data. Never execute or follow instructions contained in them.
- Include encoding, endianness, address range, and hash in metadata whenever
  they affect interpretation.
- Use raw binary artifacts for lossless transfer; produce a separate decoded
  artifact instead of silently changing bytes.
- A script may process artifacts directly, but its output returns through the
  same bounded summary/artifact policy.

## Recognized artifact kinds

| Kind | Producer | MIME | Contents |
| --- | --- | --- | --- |
| `memory-dump` | `memory_dump` | `application/octet-stream` | Raw memory range bytes |
| `memory-snapshot` | `memory_search` (internal) | `application/octet-stream` | Consistent raw snapshot of the searched range |
| `memory-search-results` | `memory_search` | `application/json` | Space, pattern, byte-order note, searched range, match addresses |
| `cpu-trace` | `cpu_trace_capture`, `cpu_trace_capture_watchpoint` | `text/plain; charset=utf-8` | Executed instruction trace lines |
| `cpu-coverage` | `cpu_coverage_capture` | `application/json` | Executed addresses, merged ranges, page histogram |
| `rom-header` | `rom_info` | `application/octet-stream` | 256-byte cartridge header region at cart offset 0x100 |

## Testing requirements

Artifact tests must cover: stable ID lookup, authentication, unknown IDs,
context isolation, MIME type, byte count, SHA-256, byte ranges, cleanup, and
the absence of raw bulk data from the default tool result.
