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

Tools that can produce significant output return a descriptor built by
`artifactDescriptor` (`internal/mcp/tools.go`):

```json
{
  "summary": {
    "kind": "memory-dump",
    "address_space": "m68k-bus",
    "effective_address": 16711680,
    "byte_length": 4096,
    "byte_order": "big-endian",
    "sha256": "..."
  },
  "artifact": {
    "id": "art_01J...",
    "kind": "memory-dump",
    "mime_type": "application/octet-stream",
    "size_bytes": 1124059,
    "sha256": "...",
    "url": "http://127.0.0.1:8768/artifacts/art_01J...?context=default",
    "provenance_state": "complete",
    "provenance": { "artifact_schema": "artifact-provenance/2", "...": "..." }
  }
}
```

Descriptors carry no `resource_uri`. Earlier revisions advertised
`exodus://artifacts/<id>`, but the server never implemented an MCP `resources`
endpoint, so the URI promised a retrieval path that did not exist. Dropping the
field is the honest option (roadmap issue #10); the loopback `url` is the only
served path, and `artifact_list` is the discovery path.
```

The exact response is MCP `structuredContent` where the negotiated protocol
permits it, with a concise `content` text summary for clients that do not parse
structured results. Every successful result additionally carries
`result_type` and `schema_version: "1"` (the *tool response* schema), which is
independent of the artifact kind schemas below. The artifact ID is opaque and
never derived from a user file path.

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
| Listing (`artifact_list`) | Discovery of what a context already holds | Page of 50, cap 200 |
| Derived artifact | Sanitized CSV/JSON/text/image from raw data | Tool-specific cap |

Tools should expose an explicit output preference such as `output: "summary"`,
`"artifact"`, or `"both"`. A raw inline response is allowed only for a small,
caller-specified maximum. It is never the implicit default for binary data.

## HTTP artifact endpoint

The endpoint is implemented by `internal/artifact` (`Store.Handler`):

```text
GET|HEAD /artifacts/{artifact-id}?context={context-id}
```

Behavior as implemented:

- `Content-Type` is the stored MIME type; `ETag` is `"sha256-<digest>"`, and
  `If-None-Match` with that value answers `304 Not Modified`.
- `Accept-Ranges: bytes` with single-range `Range` support (`206 Partial
  Content`, `416` plus `Content-Range: bytes */N` on an unsatisfiable range).
  Multiple ranges in one request are rejected.
- `Cache-Control: private, max-age=3600`.
- The context comes from the `?context=` query parameter, or the
  `X-Exodus-Context` header; an artifact of another context, an unknown id, or
  a structurally invalid id answers `404`. Every request is subject to the
  server-wide loopback bind and `Origin` validation
  (`internal/mcp/server.go`, `Handler`); there is no per-artifact token.
- `HEAD` returns the same headers without a body.

The endpoint never accepts filesystem paths, glob patterns, or arbitrary URLs.
IDs are server-generated, capability-like values and artifacts are scoped to
their analysis context.

## Discovery and capture resolution

Two tools make the store addressable without the original responses (roadmap
issues #2 and #10):

- `artifact_list{context, kind, capture_id, cursor, limit}` returns the artifacts
  of one context in creation order, filtered by exact `kind` or by the
  `capture_id` an artifact's provenance carries. Every descriptor reports
  `artifact_id`, `kind`, `mime_type`, `size_bytes`, `sha256`, `created_at`,
  `expires_at` (`null` when retention is unlimited), `schema_version` when the
  payload declares one inside itself, `capture_id` when applicable, the download
  `url`, and `provenance_state`. The response reports `total`, `returned`,
  `has_more`, and `next_cursor` (`null` on the last page). A cursor is a position
  in the filtered, creation-ordered listing: artifacts written between pages
  append (they cannot shift an earlier page), while an expiry between pages can
  move a later entry.
- `capture_get{capture_id}` resolves a capture issued by
  `memory_snapshot_capture`, `system_snapshot_capture`, or `vdp_capture` to the
  tool that produced it, the target generation and frame token observed at
  capture time, the manifest artifact (descriptor plus its parsed document when
  it is bounded JSON), and one entry per component: artifact id, kind, MIME type,
  size, hash, address domain, captured range, download URL, and whether the
  component was omitted or unavailable and why. Components whose bytes retention
  already removed report `available: false` instead of a dead URL.

Both indexes are persisted. The artifact index lives in
`<artifact-dir>/artifact-index.json` (`artifact-index/1`), is rewritten
atomically on every write, and is loaded by `artifact.NewStore`, so a restarted
server reopens the artifacts it wrote. Files no index entry claims are still
removed at startup, so a partial write never becomes an artifact; an index
document that cannot be parsed fails startup instead of silently discarding the
artifacts it describes. The capture
index is stored in the same document and follows the same rules; a capture whose
artifacts expired stops resolving.

**What survives a restart.** Artifacts and captures are keyed by the analysis
context that produced them, so the context handle has to survive too. The
analysis workspace is persisted next to the artifact index:

```text
<artifact-dir>/artifact-index.json                 artifact index (artifact-index/1)
<artifact-dir>/analysis/contexts.json              contexts (analysis-contexts/1)
<artifact-dir>/analysis/annotations/<context>.json  one context's annotations (annotations/1)
```

`analysis.OpenRegistry` loads the context registry and every annotation document
at startup, so `context_list` reports the contexts of the previous session, the
default context keeps its id, and `artifact_list`/`annotation_list` find
yesterday's work through the same handles. The workspace lives in a
subdirectory because the artifact store reclaims unknown *files* at startup but
never descends into unknown directories. An undecodable document fails startup
instead of silently starting empty; symbols are not persisted and are
re-declared with `symbols_set`. `context_prune` is the reclamation path for a
closed context: it removes the registry entry, the annotation document, the
context's artifacts and capture entries (bytes included), and its saved state
files, and reports what it removed. `state_delete` does the same for one saved
snapshot, and `state_load` accepts a snapshot `name` when exactly one snapshot
of the context carries it.

Retention today: `--artifact-ttl` / `EXODUS_MCP_ARTIFACT_TTL` expires artifacts
on a background sweep (`Store.ExpireOlderThan`, first tick after at most one
minute). Two mechanisms named in earlier revisions are **not implemented**:
explicit artifact deletion (no tool or HTTP method deletes an artifact) and
cleanup at process exit (nothing runs on exit), so with unlimited retention the
artifact directory grows until it is removed by hand.

The store knows its retention from the last sweep (`SetRetention` is the
explicit setter), so `artifact_get`, `artifact_list`, and `capture_get` report
`expires_at` per artifact (`null` while retention is unlimited). A client can
therefore see an expiry before a download fails. Because the retention is only
learned when the sweeper first runs, `expires_at` is `null` for the first minute
of a process that was started with a TTL and no persisted value.

## Artifact kinds

Every kind below is produced by the listed tool. `schema_version` refers to a
version field *inside the artifact payload*, not to the tool response schema;
`none` marks a kind with no document-level header of our own (raw bytes, PNG,
text, WAV); every JSON document kind declares its version — see
[Schema versions](#schema-versions).

### Raw byte artifacts (`application/octet-stream`)

| Kind | Producer | Payload | `schema_version` |
| --- | --- | --- | --- |
| `memory-dump` | `memory_dump` | Requested address range, address order | none (raw bytes) |
| `memory-snapshot` | `memory_search`, `memory_diff` (internal snapshot), `memory_snapshot_capture` (per named range) | Consistent snapshot bytes | none (raw bytes) |
| `rom-header` | `rom_info` | 256 header bytes read at cart offset `0x100` | none (raw bytes) |
| `vdp-memory-export` | `vdp_memory_export` | Requested VRAM/CRAM/VSRAM range, device order | none (raw bytes) |
| `vdp-cram`, `vdp-vsram`, `vdp-vram` | `vdp_capture` | Device buffers copied during the capture | none (raw bytes) |
| `system-memory` | `system_snapshot_capture` | One named memory range | none (raw bytes) |
| `system-vdp-cram`, `system-vdp-vsram`, `system-vdp-vram` | `system_snapshot_capture` | VDP buffers copied inside the pause window | none (raw bytes) |
| `audio-capture` | `audio_capture` | RIFF/WAVE PCM (declared `little-endian PCM`, sample-interleaved) | n/a — **never produced**: the pinned plugin answers every `audio_capture` call with `audio_unavailable` |

### Image artifacts

| Kind | Producer | MIME | Payload | `schema_version` |
| --- | --- | --- | --- | --- |
| `frame-capture` | `frame_capture`, `vdp_capture` (frame component) | `image/png` | Rendered frame | none (PNG) |
| `vdp-tiles` | `vdp_tile_export` | `image/png` | Scaled tile strip, CRAM palette line | none (PNG) |
| `vdp-plane` | `vdp_plane_export` | `image/png` | Rendered scroll plane | none (PNG) |
| `vdp-palette` | `vdp_palette_export` | `image/png` | Four 16-color swatch lines | none (PNG) |
| `system-frame` | `system_snapshot_capture` | `image/png` | Frame captured inside the pause window | none (PNG) |

### Text and JSONL artifacts

| Kind | Producer | MIME | Payload | `schema_version` |
| --- | --- | --- | --- | --- |
| `cpu-trace` | `cpu_trace_capture`, `cpu_trace_capture_watchpoint` | `text/plain; charset=utf-8` | Human-readable engine trace lines | none (text) |
| `experiment-output` | `experiment_run` | `text/plain; charset=utf-8` | Capped, sanitized script stderr | none (text) |
| `cpu-trace-jsonl` | `cpu_trace_capture`, `cpu_trace_capture_watchpoint` | `application/jsonl` | One JSON object per executed instruction | `trace-event/1` per line (`cpu`, `address_space`, `pc`, `pc_hex`, `cycle`, `target_generation`, `capture_id`, optional `frame_token`, `mnemonic`, `operands`, `opcode_bytes`/`opcode_bytes_hex`, `instruction_length`, `decode_confidence`, and a `control_flow` object whose facts are `null`/`unknown` when the trace does not provide them) |
| `trace-session-jsonl` | `trace_session_events`, `trace_session_stop` | `application/jsonl` | Every retained session event | `trace-session-event/1` for execution/watches, `trace-session-access/1` for access records |

### JSON documents

| Kind | Producer | Payload | `schema_version` |
| --- | --- | --- | --- |
| `memory-search-results` | `memory_search` | `kind`, `address_space`, `pattern_hex`, `pattern_mask_hex`, `pattern_length_bytes`, `alignment`, `interpretation`, `source_snapshot`, `source_range`, `searched_range`, `range{start_address,byte_length}`, `matches_total`, `truncated`, `addresses`, `parsed_pattern` | `memory-search-results/1` |
| `memory-diff-results` | `memory_diff` | `kind`, `mode`, `width`, `width_bytes`, `byte_order`, `alignment`, `interpretation`, `range`, `before_snapshot`, `after_snapshot`, `fresh_after_read`, `matches_total`, `truncated`, `matches`, optional `provenance_warning`, `before_capture_id`, `after_capture_id`, `capture_consistency`, mode value fields | `memory-diff-results/1` |
| `cpu-coverage` | `cpu_coverage_capture` | Executed addresses with counts, instruction-aware `blocks`, observed `edges`, legacy `ranges`, filters, truncation facts | `cpu-coverage/2` |
| `debug-event` | any managed breakpoint/watchpoint stop | `kind` is `"watchpoint-event"` (the artifact kind is `debug-event`), plus `event_id`, `resource_kind`, `resource_id`, `context_id`, `cpu`, `triggering_pc`(+hex), `address_space`, `watched_address`(+hex), `access_direction`, `requested_length`, `hit_count`, `target_generation`, `timestamp`, optional `frame_token`, explicit `null` access width/values with a note | `debug-event/1` |
| `experiment-manifest` | `experiment_run` | `schema_version`, `experiment_id`, `script{name,kind,sha256}`, `context_id`, `started_at`, `duration_ms`, `status`, `exit_code`, `arguments`, `initial_state_id`, `final_state_id`, `summary`, `steps`, `artifacts`, `error` | `experiment-manifest/1` |
| `annotation-export` | `annotation_export` | Export time, target ROM identity, target generation, annotations with their creation stamps and evidence links | `annotation-export/1` |
| `replay-manifest` | `deterministic_replay` | `strict`/`warmup` modes, `determinism_scope`, `register_evidence`(+note), `runs_compared`, two runs (`run_1`/`run_2`; `run_3` plus `warmup*` fields only with `warmup:true`), restore fingerprints and `restore_fidelity*`, per-step frame tokens, per-step and final registers, gating checks, `divergences` (gating), `advisory_divergences`, `unproven`/`advisory_unproven`, methodology | `replay-manifest/5` |
| `state-diff-results` | `state_diff` | `kind`, `before_snapshot`, `after_snapshot`, `metadata_diff`, `file_diff`, `comparison` (completeness/verdict scope), `semantic` (requested but not performed), `provenance{note}` | `state-diff-results/1` |
| `capture-manifest` | `memory_snapshot_capture` | `kind`, `capture_id`, `capture_consistency`, `pause_resume_cycle`, generations, `rom_identity`, `space`, `ranges`, `internal_lock_acquired`, `run_state_restore` | `capture-manifest/1` |
| `system-snapshot-manifest` | `system_snapshot_capture` | `schema_version`, `kind`, `capture_id`, `captured_at`, `capture_consistency`, generations, `rom_identity`, `byte_order`, `components`, `artifacts` | `system-snapshot/1` |
| `system-render-manifest` | `system_snapshot_capture` | `schema_version`, `capture_id`, and references to the frame, status, palette, scroll, and sprite components | `render-manifest/1` |
| `system-m68k-registers`, `system-z80-registers`, `system-vdp-status` | `system_snapshot_capture` | The native command payload plus the declared `schema_version` | `system-m68k-registers/1`, `system-z80-registers/1`, `system-vdp-status/1` |
| `vdp-status` | `vdp_capture` | The native `vdp_status` payload (24 registers plus decoded fields) plus the declared `schema_version` | `vdp-status/1` |
| `vdp-capture-manifest` | `vdp_capture` | `kind`, `capture_id`, `captured_at`, `capture_consistency`, `components`, `artifacts`, `artifact_count`, `vdp_status` | `vdp-capture-manifest/1` |
| `vdp-render-manifest` | `vdp_capture` | `kind`, `capture_id`, and four note-only sections (`display_geometry`, `palette_state`, `sprite_state`, `scroll_state`) | `vdp-render-manifest/1` |
| `vdp-palette-json` | `vdp_palette_export` | `kind`, `color_format`, `byte_order`, `lines` (four lines of 16 `{index,word,rgb333_r_g_b,rgb888_hex}`) | `vdp-palette-json/1` |
| `vdp-tiles-json` | `vdp_tile_export` | `kind`, `pixel_order` (`high-nibble-left`), `byte_order`, `palette_line`, `tiles[]` (`index`, VRAM `address`, 8x8 row-major pixel indices) | `vdp-tiles-json/1` |
| `vdp-plane-json` | `vdp_plane_export` | `kind`, `plane`, `byte_order`, `name_entry_format`, `name_table_base`, `size_cells`, `distinct_tiles`, `priority_entries`, `invalid_entries`, `truncated` | `vdp-plane-json/1` |
| script-defined (for example `experiment-observations`) | `experiment_run` script `artifact` message | Bounded derived bytes declared by the script (kind must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`, MIME type parsed and validated) | script-declared |

## Provenance envelope

Every artifact produced from capture data carries `artifact-provenance/2`
(`ProvenanceSchema` in `internal/artifact/artifact.go`) with
`state: "complete"`. An artifact
whose producer attached no metadata is reported as `provenance_unknown` by
`artifact_get` (`include: ["provenance"]`), by its deprecated alias
`artifact_describe`, and by the descriptor (`provenance_state`), and no field is
invented. The envelope fields are:

- `kind`, `state`, `artifact_schema`;
- address domain: `start_address`, `effective_address` (decimal), the matching
  `*_hex` canonical forms, `byte_length`, `address_space`, `space_kind`
  (`bus` / `memory` / `timed-buffer`), `device`;
- decoding: `byte_order`, `raw_byte_ordering` (`address-order` or the producer's
  layout note);
- target identity: `target_generation`, `rom_sha256`/`rom_path` when the file is
  readable from the server host;
- capture identity: `capture_id`, `frame_token`, `captured_at`,
  `cpu_run_state`;
- `capture_consistency` (`state` = `live` | `atomic` | `paused` |
  `composite_non_atomic` | `state_restored` | `unknown`, pause/resume facts,
  initial/final run states and frame tokens, `target_generation`, note — the
  served view always carries the complete key set, see
  [Response vocabularies](FEATURES.md#response-vocabularies));
- `consistency`: deprecated, frozen-schema flat label of the same capture; it is
  always derived from `capture_consistency.state` at render time and can never
  disagree with it. Read `capture_consistency.state`.

## Schema versions

Every JSON artifact kind embeds a `schema_version` in its own payload, and the
value is declared once in `internal/mcp/artifact_schema.go`
(`artifactSchemaVersions`). `putJSONArtifact` is the single write path: it
stamps the declared version and refuses a kind that is not registered, so a
producer cannot publish a document whose payload claims a version the server
does not declare. A derived export (`vdp-tiles-json`, `vdp-plane-json`,
`vdp-palette-json`) goes through `storeJSONArtifactAndDescriptor`, which uses the
same wrapper.

The declared set is:

| Kind | `schema_version` |
| --- | --- |
| `memory-search-results` | `memory-search-results/1` |
| `memory-diff-results` | `memory-diff-results/1` |
| `experiment-manifest` | `experiment-manifest/1` |
| `state-diff-results` | `state-diff-results/1` |
| `capture-manifest` | `capture-manifest/1` |
| `vdp-capture-manifest` | `vdp-capture-manifest/1` |
| `vdp-render-manifest` | `vdp-render-manifest/1` |
| `vdp-status` | `vdp-status/1` |
| `vdp-palette-json` | `vdp-palette-json/1` |
| `vdp-tiles-json` | `vdp-tiles-json/1` |
| `vdp-plane-json` | `vdp-plane-json/1` |
| `system-m68k-registers` | `system-m68k-registers/1` |
| `system-z80-registers` | `system-z80-registers/1` |
| `system-vdp-status` | `system-vdp-status/1` |
| `system-snapshot-manifest` | `system-snapshot/1` (historical value, unchanged) |
| `system-render-manifest` | `render-manifest/1` (historical value, unchanged) |
| `cpu-coverage` | `cpu-coverage/2` |
| `debug-event` | `debug-event/1` |
| `replay-manifest` | `replay-manifest/5` |
| `annotation-export` | `annotation-export/1` |

Reading the version does not require downloading the payload: the store records
the declared value at write time, so `artifact_get` and `artifact_list`
descriptors report `schema_version` next to `kind`, `mime_type`,
`size_bytes`, `sha256`, and `capture_id`. An artifact whose payload declares no
version (a legacy artifact written before this declaration, or a
script-published `experiment_run` artifact, whose shape the script owns)
reports no `schema_version` field instead of a fabricated one.

Raw byte, image, and text artifacts (`memory-dump`, `memory-snapshot`,
`rom-header`, VDP buffers, PNGs, `cpu-trace`, `experiment-output`, WAV) have no
embedded header of our own and are deliberately out of scope;
`cpu-trace-jsonl` and `trace-session-jsonl` lines carry a per-line
`schema_version` (`trace-event/1`, `trace-session-event/1`,
`trace-session-access/1`) instead of a document-level one.

`TestEveryJSONArtifactKindDeclaresSchemaVersion` proves every registered kind
stamps its declared value and that an unregistered kind is refused;
`TestJSONArtifactWritesGoThroughTheSchemaDeclaration` parses this package and
fails when a JSON artifact is written around the declaration.

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

## Testing requirements

Artifact tests must cover: stable ID lookup, authentication, unknown IDs,
context isolation, MIME type, byte count, SHA-256, byte ranges, cleanup, and
the absence of raw bulk data from the default tool result. Per-artifact
authentication is not implemented (only loopback binding plus `Origin`
validation); the remaining items are covered by `internal/artifact/artifact_test.go`
(roundtrip, context scoping, preview caps and modes, text sanitization, TTL
expiry, HTTP full and range requests with `ETag`, startup sweep, and
`provenance_unknown` versus stamped provenance, index listing and paging, capture
index persistence across a store reopen) and by
`internal/mcp/server_test.go` `TestRejectsForeignOrigin` for origin handling.
Discovery and capture resolution are covered by
`internal/mcp/tools_artifact_index_test.go`.
