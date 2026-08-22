# MCP clients

The development endpoint is `http://127.0.0.1:8767/mcp`. Start it in a second
terminal before connecting a client:

```bash
go run ./cmd/exodus-mcp
```

The server currently offers `bridge_status` and `target_info`. The latter
correctly returns `bridge_unavailable` until the Go named-pipe client is added.
This guide configures the MCP transport only; it does not expose Exodus or the
endpoint to the network.

## OpenCode

Add this to the repository `opencode.json` (or your OpenCode user
configuration). Current OpenCode v2 places named servers under `mcp.servers`.

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "exodus": {
        "type": "remote",
        "url": "http://127.0.0.1:8767/mcp",
        "oauth": false,
        "codemode": false
      }
    }
  }
}
```

Verify it with `opencode mcp list`. With this server name, its tools appear as
`exodus_bridge_status` and `exodus_target_info`.

## Codex CLI

Register the Streamable HTTP endpoint directly:

```bash
codex mcp add exodus --url http://127.0.0.1:8767/mcp
codex mcp get exodus
```

This writes the equivalent entry to `~/.codex/config.toml`:

```toml
[mcp_servers.exodus]
url = "http://127.0.0.1:8767/mcp"
```

Restart Codex after adding it. Keep the URL loopback-only. The configuration is
deliberately credential-free at this stage because the public HTTP server is a
local development endpoint; the native bridge uses its separate, generated
named-pipe capability.

## Claude Code

For a personal configuration in the current project, run:

```bash
claude mcp add --transport http exodus http://127.0.0.1:8767/mcp
claude mcp list
```

To share the entry with the repository, use `--scope project`; Claude Code will
write the `.mcp.json` file. It asks each user to approve project-scoped servers
before use.

## Recommended first prompt

Use this after the client shows the server as connected:

```text
Use the Exodus MCP bridge_status tool and report the bridge state. Do not try to read emulator memory if the bridge is unavailable.
```

## Compatibility note

This MCP server targets the modern `2026-07-28` protocol and also has a bounded
legacy initialization path for clients that still require it. If a specific
client rejects the endpoint, record its request/response behavior and add a
fixture before widening the compatibility layer.
