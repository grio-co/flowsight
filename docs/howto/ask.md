# Ask FlowSight in Plain English

The Assistant module lets you ask FlowSight questions in plain English and get answers backed by your network data. A language model—Anthropic's Claude or your own Claude Code setup—reads your question, calls FlowSight's routes as tools to look at flows, hosts, policies, and other data, and gives you an answer with citations showing which data it looked at.

## Enable the Assistant

1. Go to **Administration > Settings** and scroll to **Assistant** or search for "provider".
2. Set **AI Provider** to one of:
   - **anthropic**: Anthropic's Messages API (requires `api_key`; costs money per query)
   - **claude-code**: Claude Code CLI / Agent SDK in headless mode (free; requires `claude` binary on PATH)
   - **off**: Disabled (default)

### For Anthropic

3. Set **API Key** to your Anthropic API key (from [console.anthropic.com](https://console.anthropic.com)).
4. (Optional) Set **Model** to pick a model (default: `claude-sonnet-5`). Choices: `claude-fable-5-1` (fast, cheap), `claude-haiku-4-5-20251001`, `claude-sonnet-5` (balanced), `claude-opus-5-5` (most capable).
5. (Optional) Adjust **Max turns** (default 8; higher = more back-and-forth with tools) and **Timeout** (default 120 seconds).

### For Claude Code

3. Set **Claude Path** to the path to your `claude` binary (e.g., `/usr/local/bin/claude` or just `claude` if it's on PATH).
4. Save. The status page will say "ready" once it finds the binary.

## Ask a Question

1. Go to **Monitor > Ask**.
2. The page shows a few suggested questions. Click one or type your own (e.g., "Which devices sent the most data today?", "What is 192.168.1.50 talking to?").
3. Submit and watch the answer stream. The assistant shows:
   - Its reasoning and final answer
   - A collapsible "Tool calls" section listing which routes it called to find the data
   - Recent conversation history for context

## What Data Leaves the Gateway

**When the provider is on:**
- Your question text
- Results from routes the assistant calls (flows, hosts, policies, DNS logs, etc.)
- IP addresses, domain names, and other network identifiers visible in the results

**What stays private:**
- The API key (never sent; only used locally to sign requests)
- FlowSight's config, logs, and internal state (the assistant sees only what you query)

**For redaction:** If your network uses private ranges you want masked before the model sees them, enable **Redact addresses**. RFC1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and your configured home addresses are replaced with stable placeholders like `[private-a]`, `[private-b]`. Names and domains are not redacted.

## Example Queries

- "Which devices talked to a country other than mine today?" → assistant calls `/api/paths/path` to list routes, looks at GeoIP data
- "What is 192.168.1.115 doing?" → calls `/api/identity/host` to get the device, `/api/visibility/flows` to see its traffic
- "Which device sent the most data in the last hour, and where?" → calls `/api/visibility/hosts` with `minutes=60`, ranks by bytes
- "Any suspicious DNS queries?" → calls `/api/dns/log` to list recent queries, looks for typosquatting or known bad domains
- "What is my top application by bandwidth?" → calls `/api/categories/app`, `/api/visibility/flows` grouped by app

## Conversation History

The **Ask** page keeps a list of recent conversations in the sidebar. Click one to reopen it. Old conversations are deleted based on your **Retention days** setting (default 7).

## Privacy and Cost

- **Anthropic:** Each question costs a few cents. You control your API key and pay Anthropic directly. Never shared or logged by FlowSight.
- **Claude Code:** Free (uses your Claude Code subscription or free tier). Queries are subject to Claude Code's own privacy policy.
- **Redaction:** Use **Redact addresses** if you want to avoid sending private IP ranges to the provider.

## Troubleshooting

- **"Assistant is disabled"**: Set **AI Provider** to something other than "off".
- **"anthropic provider requires api_key"**: Add your API key in settings.
- **"claude binary not found"**: Check your **Claude Path** setting. Run `which claude` to find it.
- **Timeout while answering**: The assistant took too long. Increase **Timeout** in settings or ask a simpler question.
- **Tool calls show "error"**: The assistant asked for data that doesn't exist (e.g., a host that isn't on the network). The answer will note this; ask a different question or check the Monitor pages to see what data exists.
