# Use FlowSight from Claude Code and the Agent SDK

FlowSight exposes its routes as a Model Context Protocol (MCP) server, letting Claude Code and anything built on the Claude Agent SDK call FlowSight directly. Instead of asking FlowSight in the UI, you can script network queries in Claude Code or programmatically in your own agents.

## Setup: Add FlowSight as an MCP Server to Claude Code

### Via stdio (fastest for local)

```bash
claude mcp add flowsight -- flowsightd mcp
```

This runs `flowsightd mcp` as a subprocess and speaks JSON-RPC 2.0 over pipes. FlowSight reads its own config from the platform defaults or `FLOWSIGHT_CONFIG`.

### Via HTTP (for remote or managed agents)

Create an MCP config JSON with the HTTP form:

```json
{
  "mcpServers": {
    "flowsight": {
      "command": "false",
      "args": [],
      "url": "http://flowsight-host:8080/api/mcp",
      "headers": {
        "Authorization": "Bearer <api_token>"
      }
    }
  }
}
```

Then pass it to Claude Code:
```bash
claude --mcp-config <path-to-config> -p "your question"
```

Replace `flowsight-host` with your FlowSight daemon's IP/hostname, `8080` with your API port, and `<api_token>` with a valid FlowSight API token (from settings or generated at startup).

## Example: Query Your Network from Claude Code

```bash
claude -p "Which device is sending the most traffic right now, and what is it talking to?"
```

Claude will:
1. List available tools (all GET routes from FlowSight)
2. Call `visibility_hosts` to get top devices by bytes
3. Call `visibility_flows` to see what the top device is connected to
4. Synthesize an answer with citations

### Within a Python Agent SDK Script

```python
from anthropic import Anthropic
import subprocess
import json
import tempfile
import os

client = Anthropic()

# Write MCP config
mcp_config = {
    "mcpServers": {
        "flowsight": {
            "command": "flowsightd",
            "args": ["mcp"]
        }
    }
}

with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
    json.dump(mcp_config, f)
    config_path = f.name

try:
    response = client.messages.create(
        model="claude-opus-5-5",
        max_tokens=1024,
        tools=[],  # Tools loaded from MCP
        messages=[
            {
                "role": "user",
                "content": "Which device sent the most data in the last hour?"
            }
        ],
        betas=["mcp-1"]  # Requires beta
    )
    print(response.content[0].text)
finally:
    os.unlink(config_path)
```

### Within a TypeScript Agent SDK Script

```typescript
import Anthropic from "@anthropic-ai/sdk";
import * as fs from "fs";
import * as path from "path";

const client = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY,
});

const mcpConfig = {
  mcpServers: {
    flowsight: {
      command: "flowsightd",
      args: ["mcp"],
    },
  },
};

const configPath = "/tmp/flowsight-mcp.json";
fs.writeFileSync(configPath, JSON.stringify(mcpConfig));

const response = await client.messages.create({
  model: "claude-opus-5-5",
  max_tokens: 1024,
  tools: [], // Load from MCP config
  messages: [
    {
      role: "user",
      content: "What is 192.168.1.100 and what does it talk to?",
    },
  ],
});

console.log(response.content[0].type === "text" ? response.content[0].text : "");
```

## Available Tools

All GET routes in FlowSight become tools. Tool names are generated from routes (e.g., `/api/visibility/flows` → `visibility_flows`). Each tool has:

- **name:** The tool identifier (e.g., `visibility_flows`)
- **description:** What the tool does (from the route documentation)
- **inputSchema:** JSON schema of query parameters and path parameters

Get the full tool list:
```bash
curl http://flowsight-host:8080/api/assistant/tools
```

Or in Claude Code:
```bash
claude -p "List all available FlowSight tools"
```

### Common Tools

- **visibility_flows** — List flows with filters (src, dst, app, country, etc.)
- **visibility_hosts** — Top hosts by bytes, packets, or connection count
- **identity_hosts** — Get details about a host (name, MAC, zone, last seen)
- **policy_matches** — Rules that matched in a time window
- **dns_log** — Recent DNS queries with responses
- **paths_path** — Route to an IP (hops with names and geolocation)
- **categories_app** — Application usage by bandwidth
- **firewall_rules** — Active firewall rules (if enabled)

Full list with parameters: `/api/assistant/tools`

## Write Operations (if enabled)

By default, only GET routes are exposed. To allow agents to POST/PUT/DELETE, set `mcp_allow_writes: true` in the assistant settings. Then tools like `policy_matches` (read) become available alongside potential write tools (add policy, add user, etc.) if your setup supports them.

**Caution:** Write access means an agent can modify your network config. Use with care and prefer read-only unless you trust your agents.

## Examples

### Find the Device Sending Most Data

```bash
claude -p "What device sent the most data in the last 24 hours?"
```

Claude calls `visibility_hosts` with `window_hours=24`, ranks by bytes_out, names the winner.

### Check a Host's Details

```bash
claude -p "Tell me about 192.168.1.77. What zone is it in, and what did it talk to in the last 6 hours?"
```

Calls `identity_hosts` to get the device details, then `visibility_flows` filtered to that source.

### Find Suspicious Activity

```bash
claude -p "Any DNS queries in the last hour that look like typosquatting or phishing attempts?"
```

Calls `dns_log`, analyzes domain names for common attacks.

### Policy Impact Analysis

```bash
claude -p "If I block Instagram, how many devices would be affected based on recent traffic?"
```

Calls `visibility_flows` filtered to Instagram, counts unique source IPs.

## Troubleshooting

- **"No MCP servers found"**: Check your MCP config is valid JSON and the command (e.g., `flowsightd mcp`) is on PATH or has an absolute path.
- **"Tool call failed: not found"**: The tool doesn't exist on your FlowSight version. Run `curl /api/assistant/tools` to see what's available.
- **"Tool call failed: unauthorized"**: Your API token is missing or invalid. For stdio, FlowSight uses its own config; for HTTP, check the `Authorization` header.
- **"Tool call times out"**: Your query is too complex or FlowSight is slow. Try a simpler question or give the agent more time.

## Learn More

- [Ask FlowSight in Plain English](ask.md) — Use the Monitor UI instead
- [API.md](../API.md) — Full route documentation
- [SECURITY.md](../SECURITY.md) — What data leaves the gateway when MCP is on
