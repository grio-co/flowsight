# Configuration reference

Every setting lives under **FlowSight › Settings** (module by module) and in `flowsight.json` under `modules.<name>`. The file holds only what you change; the defaults below apply otherwise. Settings marked *restart* take effect at the next service restart; everything else applies immediately.

The core keys `bind`, `port`, `api_token` (and `api_tokens`, a list of `{"name","token"}` pairs whose names the audit log records), `data_dir` and `paths` can only be changed in the file, never through the API or the UI. Where an empty value means "platform default", the settings page shows the value actually in use beneath the field. With a token set, bind the daemon to `0.0.0.0` (the OPNsense WAN rules still block it from outside) and the OPNsense page reads the token from `flowsight.json` and presents it on every proxied request, so the GUI keeps working while LAN clients must send `X-Flowsight-Token`.

Every save of `flowsight.json` first keeps the previous contents as `flowsight.json.prev`, and the daemon restores from that copy when the file comes back empty or unreadable (for example after a virtual machine backup taken mid-write). The recovery is logged as "configuration recovered".

## Core (`flowsight.json`)

| Key | Default | Meaning |
|---|---|---|
| `site_name` | hostname | Shown in the UI header and in reports. |
| `bind` / `port` | `127.0.0.1` / `8080` | Where the API and UI listen. On OPNsense the GUI proxies to it; elsewhere put a reverse proxy in front or bind to a LAN address and rely on the token. |
| `api_token` | generated on Linux, empty on OPNsense | Required for writes from anything that is not the OPNsense GUI or loopback. |
| `data_dir` | `/var/db/flowsight` (OPNsense/FreeBSD), `/var/lib/flowsight` (Linux) | The SQLite store, caches, the country database and the TLS material. |
| `log_level` | `info` | `debug`, `info`, `warn`, `error`. |
| `memory_limit_mb` | `256` | Soft limit handed to the Go runtime; the daemon trims caches and collects earlier as it nears it. |
| `retention.*` | flows 7, dns 7, alerts 30, events 30, rollups 400, tls 30 days | Capped by the license tier (Community 7 days, Pro 90, Business 365) except rollups. |
| `paths.*` | per platform | Where the backends keep their files (Unbound config, squid binary, pf, Suricata EVE log, DHCP leases). `unbound_zone_dir` is where DNS-block zone files go (OPNsense: `/var/unbound/flowsight`, inside the resolver's chroot and outside the directory it empties on every start); `unbound_persist_dir` is where includes are kept that the platform copies in when it starts the resolver (OPNsense: `/usr/local/etc/unbound.opnsense.d`). |

## Modules

### advisor

Device advisories: DNS answers that break something on a device (iCloud Private Relay, connectivity checks, network time, certificate checks, push, updates, sign-in protection), lookups that fail outright, and apps retrying one blocked name. Reads the DNS log; writes findings under module `advisor`, one per device and problem, which close once the failing answers stop. See `docs/howto/device-advisories.md`.

| Key | Default | Meaning |
|---|---|---|
| `window_minutes` | 15 | Look-back window of each scan (every minute); an advisory stays open this long after the last failing answer |
| `ignore_clients` | `[]` | Addresses never advised on |

### alerting

Notification channels (multi-protocol, 54+ destinations), alert rules (severity/module/device matching), delivery configuration, and maintenance mode.

**Storage:** Channels and rules are stored as JSON in the database (KV store `alerting.channels` and `alerting.rules`)

**Channel configuration** varies by type:

- **SMTP**: host, port, user, password, from, to (comma-separated), tls (starttls|implicit|none)
- **Webhook**: url, headers (JSON), method (POST/PUT), timeout_seconds, signature_secret (for HMAC-SHA256)
- **Slack**: webhook_url
- **Discord**: webhook_url
- **Teams**: webhook_url
- **Telegram**: bot_token, chat_id
- **Twilio**: account_sid, auth_token, from_number, to_numbers (comma-separated)
- **PagerDuty**: integration_key, service_id (optional for routing)
- **Opsgenie**: api_key, region (us|eu)
- **SendGrid**: api_key, from, to (comma-separated)
- **Splunk HEC**: hec_url, hec_token, source, sourcetype
- **Datadog**: api_key, site (us|eu), tags (optional)
- **Syslog**: server, port, facility (default 16=local0), protocol (udp|tcp)
- **AWS SNS**: access_key_id, secret_access_key, topic_arn, region
- **MQTT**: broker_url, topic, username (optional), password (optional), qos (0-2)
- **Sentry**: dsn (project key URL)

**Rule configuration:**

| Key | Type | Required | Notes |
|---|---|---|---|
| `id` | string | yes | Unique rule identifier |
| `name` | string | yes | Human-readable rule name |
| `enabled` | bool | no | Enable/disable without deleting (default: true) |
| `severity` | string | yes | Minimum severity: info, low, medium, high, critical |
| `module` | string | no | Filter by source module (dns, web, firewall, ids, etc); empty = all |
| `category` | string | no | Filter by category (anomaly, threat, finding, etc); empty = all |
| `device` | string | no | Filter by IP or MAC address; empty = all |
| `zone` | string | no | Filter by zone name; empty = all |
| `channels` | string[] | yes | Channel IDs to send to (at least one) |
| `cooldown` | int | no | Minimum seconds between identical alerts (prevent spam, default: 300) |
| `digest_minutes` | int | no | Bundle alerts into periodic summaries (0 = immediate, default: 0) |
| `escalation` | object | no | Escalate to additional channels if unacknowledged after N minutes |
| `escalation.after_minutes` | int | yes | Minutes until escalation triggers |
| `escalation.channels` | string[] | yes | Additional channels for escalation |
| `escalation.only_once` | bool | no | Only escalate once per alert (default: true) |

**Maintenance mode:**

Stored at `alerting.maintenance` in KV store. When enabled, all alerts are suppressed until the deadline or indefinitely.

```json
{
  "enabled": true,
  "until": 1696281600,  // Unix timestamp; 0 = indefinitely
  "reason": "System maintenance window"
}
```

**Delivery log & rate limiting:**

- Delivery attempts are logged per channel for 7 days (retention: /var/lib/flowsight/alerting/deliveries)
- Rate limiting per (channel_id, alert_key) pair: configurable in channel config via `rate_limit_minutes` (0 = no limit)
- Deduplication: 10-minute window by default (drop identical alerts from same rule/channel)

**Secrets & security:**

- All secret fields (passwords, API keys, tokens) are masked with `***` in API responses
- Secrets are stored encrypted in the database (at-rest encryption via SQLite pragma key)
- Delivery credentials never appear in logs or delivery logs
- HMAC-SHA256 signatures for webhooks; AWS SigV4 for AWS services

### assistant

Claude as FlowSight's analyst, and FlowSight as tools for Claude (MCP). Off by default; nothing leaves the gateway until a provider is chosen. See the how-tos [Ask FlowSight in plain English](howto/ask.md) and [Use FlowSight from Claude Code and the Agent SDK](howto/claude-code.md).

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `provider` | AI provider | choice | `off` | off: nothing leaves. anthropic: the daemon runs the agent loop against the Messages API. claude-code: Claude Code / the Agent SDK, run headless on the gateway with FlowSight attached as an MCP server. |
| `api_key` | API key | secret |  | Anthropic key for the anthropic provider. Empty means: use the map's `ai_key` (Settings › paths) if one is set. Never shown again once saved; a masked value on save means keep. |
| `workspace_id` | Anthropic workspace id | string |  | Only for an organisation-level key: the workspace requests are billed to (`anthropic-workspace-id` header). A key created inside a workspace needs nothing here. |
| `model` | Model | string | `claude-sonnet-5` | anthropic provider: claude-fable-5-1, claude-opus-5-5, claude-sonnet-5, claude-haiku-4-5-20251001. Claude Code uses its own model setting. |
| `claude_path` | Claude CLI path | string | `claude` | claude-code provider: the binary, on PATH or absolute; with `claude_ssh` set, the path on the remote machine. |
| `claude_ssh` | Run Claude Code over SSH on | string |  | `user@host` of a machine where Claude Code is installed and logged in; empty runs it on the gateway. FlowSight connects with its own key (`GET /api/assistant/ssh_key`, or `ssh_public_key` in the status). |
| `mcp_url` | MCP URL for a remote Claude | string |  | Required with `claude_ssh`: this daemon's `/api/mcp` as the remote machine sees it, e.g. `http://192.168.0.1:8080/api/mcp`. |
| `mcp_token_name` | Token for the remote Claude | string |  | Name of an `api_tokens` entry in `flowsight.json` handed to the remote Claude Code for `/api/mcp`; empty means the main token. |
| `claude_ssh_key` | SSH private key | string |  | Empty: `assistant_ssh_key` under the config directory, generated on first use (ed25519). |
| `ssh_path` | ssh binary | string | `ssh` |  |
| `max_turns` | Max turns | int | `8` | Request/answer cycles (tool rounds) per question, 1–20. |
| `max_tool_result_bytes` | Max tool result bytes | int | `65536` | A tool result larger than this is cut with a note before it goes to the model. |
| `allow_writes` | Allow write operations | bool | `false` | When on, the model may call POST/PUT/DELETE routes. Keep off unless you mean it. |
| `mcp_allow_writes` | MCP: allow write operations | bool | `false` | When on, MCP clients (Claude Code, the Agent SDK) may call write routes. |
| `timeout_seconds` | Question timeout | int | `120` | Per question; the Claude Code process is killed at the deadline. |
| `retention_days` | Conversation retention | int | `7` | Questions and answers kept in the store; 0 keeps them until the 500 newest. |
| `redact_addresses` | Redact internal addresses | bool | `false` | Replace RFC1918, ULA and MAC addresses in tool results with stable placeholders before they leave. Names and domains still leave. |

### baseline

Anomaly detection: learns each device's normal behavior (countries, ports, destinations) over a configurable learning period, then flags deviations. Every finding includes the baseline ("21 days of history had US, CA") and observation ("first time talked to IE"). Findings are dedup'd with cooldown and integrated with alerting rules.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `learning_days` | Learning period (days) | int | `7` | Days before anomaly detection begins per device; no findings raised during learning. |
| `max_destinations` | Max destinations per device | int | `50` | Prune least-frequent when exceeded; keeps memory bounded. |
| `bytes_multiplier` | Bytes threshold multiplier | float | `2.0` | Flag outbound bytes above N × device daily median. |
| `beaconing_min_sessions` | Beaconing: min sessions | int | `5` | Minimum sessions to a destination for beaconing analysis. |
| `beaconing_cv_threshold` | Beaconing: regularity threshold | float | `0.2` | Coefficient of variation of inter-arrival times; lower = more regular (stricter). |
| `dns_tunnel_min_length` | DNS: min label length | int | `20` | Flag mean DNS label length at or above this (characters). |
| `dns_tunnel_min_entropy` | DNS: min entropy | float | `5.0` | Flag DNS entropy at or above this (bits). |
| `dns_tunnel_min_rate` | DNS: NXDOMAIN rate | float | `0.3` | Flag when NXDOMAIN rate exceeds this and is far above device baseline. |
| `cooldown_minutes` | Finding cooldown (minutes) | int | `60` | Deduplication window; suppress repeat findings for same device and kind. |
| `excluded_zones` | Excluded zones | list | `[]` | Devices in these zones are never flagged; e.g., `["guest", "lab"]`. |

**Detection kinds and alert rule keys:**

- `new_country`: First connection to a country outside the learning window. Rule key: `baseline.new_country` (severity: high).
- `new_port`: First connection to a protocol/port pair. Rule key: `baseline.new_port` (severity: medium).
- `new_destination`: First connection to an IP or domain (only flagged for small, stable destination sets). Rule key: `baseline.new_destination` (severity: medium).
- `beaconing`: Regular, timed connections with constant payload size. Rule key: `baseline.beaconing` (severity: high).
- `dns_tunneling`: DNS abuse (high entropy, high NXDOMAIN rate). Rule key: `baseline.dns_tunneling` (severity: high).

### appcontrol

Application control: denied applications, identified by nDPI, are cut off at the firewall.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `kill_states` | Kill existing connections on a match | bool | `true` |  |
| `table_ttl_hours` | Forget blocked addresses after (hours) | int | `24` | Addresses of denied applications age out so a shared CDN address is not blocked forever. |

### categories

Web-content categories from open domain feeds, cached for policy and used to classify traffic.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `update_hours` | Refresh interval (h) | int | `24` |  |
| `classify` | Classify observed domains | bool | `true` | Keeps the lists in memory to tag flows and DNS with categories. Costs roughly 60 bytes per domain. |
| `classify_max` | Max domains held in memory | int | `3000000` |  |
| `disabled` | Disabled categories | list | `[]` |  |

### dns

Resolver visibility from Unbound's reply log and cache; per-group DNS blocking and safe search.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `log_path` | Resolver log | string | `""` | File that receives Unbound's log. Empty uses the platform default. |
| `manage_logging` | Enable reply logging in Unbound | bool | `true` | Writes a small include that turns on log-replies; without it there is nothing to read. |
| `cache_names_seconds` | Cache snapshot interval (s) | int | `60` |  |
| `max_zone_domains` | Max domains per policy zone | int | `1500000` | Each policy becomes one response policy zone; memory grows with its size. The compiler refuses larger ones. |

`local_domain` (default empty): the domain offered first when a device is given a DNS name from its page. Empty picks the domain your OPNsense host overrides and Pi-holes use most. Device names are kept in the store (KV `dns.local_names`) and written to `flowsight-names.conf` in the Unbound include directories (live and, on OPNsense, `/usr/local/etc/unbound.opnsense.d`) and to each chosen Pi-hole's `dns.hosts`. See `docs/howto/local-names.md`.

### egress (Business tier)

What is leaving the network right now, read from pf's live connection counters rather than from a log, so a transfer is visible while it is running.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `interval_seconds` | Sample the connection table every (seconds) | int | `5` | The difference between noticing data leaving and reading about it later. |
| `watch_groups` | Destination groups to watch | list | cloud-storage, file-transfer, code-host, webmail, messaging, ai, remote-access, tunnel, unknown | Groups not listed are still measured and shown; they just raise nothing on their own. |
| `alert_upload_mb` | Flag a single transfer above (MB sent) | int | `250` | Raised while the transfer is still running. |
| `alert_rate_mbps` | Flag a sustained upload rate above (Mbit/s) | int | `25` |  |
| `sustain_seconds` | ...held for at least (seconds) | int | `30` | Stops a brief burst raising anything. |
| `ratio_floor_mb` | Flag upload-dominant transfers above (MB sent) | int | `20` | Ordinary use pulls more than it pushes. |
| `ratio` | ...when sent exceeds received by a factor of | int | `4` |  |
| `flag_unnamed` | Flag uploads to a destination with no name | bool | `true` | No DNS answer, no server name, no reverse lookup. |
| `flag_first_use` | Flag the first time a device uses a watched group | bool | `true` |  |
| `quiet_hours` | Treat these hours as quiet | string | `""` | For example `23:00-06:00`. Anything flagged inside the window is raised one severity. |
| `min_report_kb` | Ignore connections smaller than (KB) | int | `64` |  |
| `keep_events` | Events kept in memory | int | `500` |  |

### enrich

Names and countries for bare addresses: reverse DNS and an IP geolocation database. Both off by default.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `reverse_dns` | Reverse DNS names | bool | `true` | Look up PTR records for addresses shown without a name, through the gateway's own resolver. Results are cached. |
| `geoip` | Location lookup | bool | `false` | Downloads a database (DB-IP Lite by default, refreshed monthly) into the data directory. |
| `geoip_detail` | How much detail | choice (country, city) | `"country"` | Country is a few megabytes. City is a much larger download (about 60 MB compressed) and adds the city, region and the coordinates a map needs. |
| `geoip_url` | Database URL | string | `""` | A MaxMind-format (.mmdb, optionally .gz) database. `{YYYY-MM}` is replaced by the current month. Empty: the DB-IP Lite file matching the detail level. |
| `cache_hours` | Name cache (hours) | int | `24` |  |

### enroll

Device identification and zone-based segmentation.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `enabled` | Enable device enrollment | bool | `true` |  |
| `captive_port` | Captive portal port | int | `8083` |  |
| `manage_dnsmasq_logging` | Enable dnsmasq DHCP logging | bool | `true` |  |
| `reconcile_seconds` | Reconcile interval (s) | int | `60` |  |

### firewall

FlowSight's own pf anchors: policy blocks, proxy redirects and dynamic address tables.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `log_blocks` | Log blocked packets to pflog | bool | `true` |  |
| `filter_log` | Filter log to read policy matches from | text | `/var/log/filter/latest.log` | Lines from FlowSight's policy anchor become the per-packet record behind Policies › Matches; empty turns the reader off |

### identity

Names and MAC addresses for every host, from DHCP, ARP/NDP, DNS answers and the OUI registry.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `refresh_seconds` | Refresh interval (s) | int | `30` |  |
| `local_networks` | Local networks | list | `[]` | CIDRs considered local. Empty: derived from the firewall's own interfaces. |
| `extra_lease_files` | Extra lease files | list | `[]` |  |

`dhcp_names` (default true): send device names given in FlowSight to the DHCP server. On dnsmasq, FlowSight writes `<etc>/dnsmasq-names.hosts` (`MAC,name` per line) and `<dnsmasq conf.d>/flowsight-names.conf` (`dhcp-hostsfile=` that file), validates with `dnsmasq --test`, and signals dnsmasq to re-read (a restart only when the include first appears). MACs with an OPNsense static host or a placement reservation are skipped. `GET /api/identity/dhcp-names` lists what was sent; `POST` sends now.

### ids

Suricata alerts and TLS observations from the EVE log.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `eve_path` | EVE log path | string | `""` | Empty uses the platform default. |
| `poll_seconds` | Poll interval (s) | int | `5` |  |
| `tls_records` | Record TLS sessions and certificates | bool | `true` |  |

### license

Entitlements: Community, Pro and Business tiers, activated online or with a signed license file.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `server_url` | License server | string | `"http://192.168.1.245:8770"` | Used for online activation and lease refresh. Offline license files never contact it. |
| `check_hours` | Refresh interval (hours) | int | `24` |  |

### mitm (Business tier)

Stateful Packet Inspection: the proxy hands each decrypted request and response over by ICAP on loopback, FlowSight reads it and answers "no modification". Bodies are previewed for the decoders that are switched on and never stored.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `active` | Inspect decrypted sessions | bool | `false` | Off: nothing is handed over and the proxy behaves as before. Only sessions a policy already decrypts ever arrive. |
| `all_clients` | Inspect everything that crosses the firewall | bool | `false` | On: every intercepted client is decrypted, not only those a policy names. A device that does not trust the FlowSight CA fails until the pinned-site detector relays that name untouched. Excluded hosts are never touched. |
| `port` | ICAP port (loopback) | int · restart | `1344` | Loopback only; nothing else can reach it. |
| `clients` | Limit to these clients | list | `[]` | Addresses or CIDRs. Empty: every client whose sessions are decrypted. |
| `names` | Limit to these names | list | `[]` | Server names, one per line. Empty: every decrypted name. |
| `record_headers` | Record request headers | bool | `true` | Cookies and authorization headers are recorded as their length only, never their value. |
| `decode_doh` | Decode DNS-over-HTTPS queries | bool | `true` | Reads the question out of a DoH request and files it in the DNS history. |
| `preview_bytes` | Body preview (bytes) | int | `4096` | How much of each body the proxy sends for decoding. Nothing is stored. |
| `keep_requests` | Recent requests kept in memory | int | `500` |  |

### netflow

UDP flow collectors for NetFlow v5/v9, IPFIX, and sFlow v5. Extends visibility to traffic observed by switches, routers and other devices beyond the gateway.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `collect` | Collect flows (open the listeners) | bool | `false` | The UDP listeners open and accept flows only when this is on. (`enabled` is the module switch, as for every module.) |
| `bind_address` | Bind address | string | `(LAN bind address)` | Interface to listen on; empty uses the platform default LAN address. |
| `netflow5_port` | NetFlow v5 port | int | `2055` | UDP port for NetFlow v5 (fixed-format legacy flows). |
| `netflow9_port` | NetFlow v9 port | int | `2055` | UDP port for NetFlow v9 (template-based flows). |
| `ipfix_port` | IPFIX port | int | `2055` | UDP port for IPFIX (RFC 5101, 64-bit counters, millisecond timestamps). |
| `sflow5_port` | sFlow v5 port | int | `6343` | UDP port for sFlow v5 (packet sampling with raw headers). |
| `allowed_cidrs` | Allowed exporter CIDRs | text | `(RFC1918 + link-local)` | Newline-separated CIDR ranges. Empty defaults to 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, fe80::/10. |
| `sampling_override` | Sampling multiplier | int | `0` | Multiply bytes and packets by this value (0 = use flow-provided rate). Set this if your exporter applies a fixed sampling ratio but does not export it per-flow. |
| `max_exporters` | Maximum concurrent exporters | int | `100` | Drops records from exporters beyond this limit to protect memory. Increase if you have more than 100 devices exporting. |

### pihole

Pulls Pi-hole query logs into the DNS history and, on Pi-hole v6, offers a curated set of Pi-hole settings on *Settings › dns › Pi-hole* (the tab is shown only while a v6 server is connected). See `docs/howto/pihole.md`.

| Key | Default | Meaning |
|---|---|---|
| `servers` | `[]` | One URL per line (`https://192.168.1.53`). A line starting with `#` is kept but not contacted |
| `password` | | App password (v6) or API token (v5), shared by every server |
| `verify_tls` | false | Verify the Pi-hole's certificate (off: v6 serves a self-signed one) |
| `poll_seconds` | 30 | Pull interval (minimum 10) |
| `history_hours` | 24 | History imported on first contact |
| `import_names` | true | Use Pi-hole client names for hosts FlowSight has no name for |
| `skip_local` | true | Ignore the Pi-hole's own queries |

Blocking (lists, entries, groups, clients, gravity, sync) is managed on *Settings › dns › Pi-hole blocking* and `/api/pihole/{blocking,lists,domains,groups,clients,categories,gravity,sync}`. A FlowSight category subscribed as a Pi-hole list is served at `/feeds/categories/<name>.txt?key=<feed key>`; the key (KV `core.feed_key`) is created on first use, and the feed needs `bind` reachable from the Pi-hole. Changing Pi-hole settings from FlowSight needs `webserver.api.app_sudo = true` on each Pi-hole ("Permit app password to modify config"). Changes are limited to the curated keys; listening mode, interface and port are view only. Every change is written to the change history (module `pihole`).

### paths (Pro tier)

Traces the route to destinations this network already contacts, and keeps what it finds.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `active` | Trace paths | bool | `false` | Off: nothing is traced. Nothing is ever probed that the network has not already contacted. |
| `per_run` | Destinations traced per run | int | `6` | A traceroute takes seconds; runs are five minutes apart. |
| `retrace_hours` | Trace a destination again after (hours) | int | `24` | How stale a route may get before it is measured again. |
| `max_destinations` | Destinations kept | int | `300` | Busiest first; the long tail is left alone. |
| `trace_ipv6` | Trace IPv6 destinations too | bool | `true` |  |
| `cables` | Show submarine cables | bool | `false` | Fetches TeleGeography's public cable map (about a megabyte, refreshed monthly) and draws it behind the routes. Not bundled: their data is a free public resource but is not openly licensed. |
| `cable_near_km` | A cable serves a place within (km) | int | `400` | How close a cable must pass to count as a candidate. Deliberately loose. |
| `origin_slack_km` | Your own position could be wrong by (km) | int | `100` | Every distance is measured from your origin, and unless you declared it that came from the address database. A placement is only called impossible if it misses its floor by more than this; it only ever withdraws accusations. A declared origin gets no allowance. |
| `land_detour_pct` | Fibre on land runs longer than the crow flies by (%) | int | `35` | Decides the second of the two thresholds each hop is judged against: not what light forbids, but what a built route could manage. Zero turns that category off. |
| `hop_delay_us` | Each hop adds (microseconds) | int | `200` | A router must finish receiving a packet before it starts sending it on. Small individually; over twenty hops worth counting. |
| `terrestrial` | Use published land-route maps | bool | `false` | Downloads open maps of long-haul fibre on land and measures along them where they reach. Never raises the impossible threshold: over water a cable is the only way across, on land a straight line is merely unbuilt. Refreshed monthly. |
| `terrestrial_urls` | Land-route sources | text | *(AfTerFibre)* | One GeoJSON URL per line, replacing the defaults. `#` and `//` comment a line out. |
| `ai_provider` | Ask a language model about hops nothing else can place | choice | `off` | off, anthropic, openai, google, azure, ollama, custom. Setup for each is in the field's help. |
| `ai_endpoint` | Endpoint | string | *(provider default)* | Required for azure and custom. |
| `ai_model` | Model | string | *(provider default)* | claude-haiku-4-5, gpt-4o-mini, gemini-2.0-flash, llama3.1 by default. |
| `ai_key` | API key | secret | *(empty)* | Sent only to the endpoint. |
| `ai_per_hour` | Questions per hour | int | `20` | Each hop at most once a month; this caps new questions. |
| `fcc_username` | FCC broadband map username | string | *(empty)* | National Broadband Map account username (free at broadbandmap.fcc.gov). |
| `fcc_token` | FCC API token | secret | *(empty)* | Sent as `hash_value` header to broadbandmap.fcc.gov only. With both fields set, FlowSight checks in monthly for the current release, records the file catalogue, and keeps the national fixed and mobile broadband provider summaries plus the origin state's census-place summary of who serves where and with what technology. Per-location files are skipped to stay under the gateway's memory limit. |
| `shodan_key` | Shodan API key | secret | *(empty)* | Optional; without it InternetDB (free) is used. Sent only to api.shodan.io. |
| `shodan_mode` | Look hops up on Shodan | choice | `click` | off, click (the card's button), all (every hop, twenty per five-minute run; spends credits when a key is set). |
| `abuseipdb_key` | AbuseIPDB API key | secret | *(empty)* | Enables reputation lookups for route hops: abuse confidence, reports, ISP, usage type. Twenty addresses per five-minute run, answers kept a week. Free key: abuseipdb.com › Account › API › Create Key. |
| `geofeeds` | Follow geofeeds named in the registry | bool | `true` | RFC 8805 files named in registry objects of hops on routes are fetched weekly and used like provider range lists. |
| `anycast_census` | Know which addresses are anycast | bool | `true` | LACeS census prefixes and sites, fetched weekly; anycast hops are placed at the site nearest the hop before them and labelled as regional instances. |
| `identify` | Ask anycast servers to identify themselves | bool | `true` | CHAOS TXT `id.server` / `hostname.bind` to anycast hops, twenty per five-minute run, kept a week; root-servers.org site lists fetched weekly to look the answers up. |
| `provider_feeds` | Use the clouds' published address ranges | bool | `true` | AWS, Google Cloud, Azure, Oracle, DigitalOcean, Linode regional ranges and Cloudflare/Fastly anycast ranges, one feed per half-hour run until all are under a week old, throttled to 2 MB/s; the operator's own statement outranks the database and a measurement; anycast positions are set aside. |
| `azure_service_tags_url` | Azure service tags file | string | *(discovered weekly)* | Only if the link cannot be found on Microsoft's download page. |
| `osm_telecom` | Use OpenStreetMap telecom lines (low weight) | bool | `true` | Overpass-fetched telecom/communication lines, one ten-degree tile every twenty minutes while any are outstanding (a few hundred tiles; the first pass takes about five days), kept a month, counted at half weight in the expected time only. |
| `osm_overpass_url` | Overpass API | string | *(overpass-api.de)* | Your own Overpass instance, if you run one. |
| `osm_overpass_local` | My Overpass is on this network | bool | `false` | Allows the Overpass API URL to be a private address; the only exemption from the public-host rule. | With a private server FlowSight fetches up to twelve regions per run and falls back to the public service for any region the private server has no data for.
| `learn_corrections` | Remember what the database gets wrong | bool | `true` | A router name or RIPE measurement that places a hop over 500 km from the database's position teaches the map where that announced prefix is; a registrant coordinate contradicted twice for one network is set aside. Listed at `/api/paths/corrections`; items can be forgotten. |
| `ipmap` | Ask RIPE where each router is | bool | `true` | RIPE's IPmap publishes positions worked out by measuring addresses from thousands of probes. The one source here that is measurement rather than paperwork; it outranks the address database. Asked slowly, kept a month, backs off on refusal. |
| `ipmap_per_minute` | Addresses asked about per minute | int | `20` | Deliberately small: answers last a month and the service belongs to somebody else. |
| `registry` | Look up who runs each hop | bool | `true` | Asks the public routing table which network announces a hop's address, and the regional registry who that block is allocated to. The registry's postal address is a head office, not the room the router is in, and is labelled that way wherever it is shown. Cached for a month. |
| `facilities` | List buildings the operator occupies | bool | `true` | Adds street addresses from PeeringDB, where operators publish which data centres they are in. Narrowed to a hop only when the router's own hostname gave away its city; otherwise presented as the unrelated list it is. |
| `cables_url` | Cable map URL | string | `""` | Empty: TeleGeography's published map. |
| `home` | Your location | string | `""` | Latitude and longitude, comma separated. The origin the map is drawn from, and the reference for checking a hop could really be where the database says. Empty: worked out from the gateway's public address. The Map page can fill it in from your browser. |

Needs `enrich` with `geoip_detail` set to `city`, since the country database carries no coordinates.

### policy

The declarative policy document, its compiler and continuous reconciliation onto every backend.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `enforce` | Enforce policy | bool | `true` | Off: the document is compiled and planned but never written to a backend. On: every provider is kept in step with it. |
| `reconcile_seconds` | Reconcile interval (s) | int | `60` |  |

### qos (Pro tier)

Traffic priority. Moves the bottleneck off the carrier and onto this firewall with dummynet, then shares the link by weight.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `active` | Shape traffic | bool | `false` | Off: nothing is queued and the link behaves exactly as it does now. On: every packet passes through a pipe on this firewall. |
| `download_mbit` | Download the link really carries (Mbit/s) | int | `0` | Measure it. Set above the real rate and the pipe never fills, the carrier stays the bottleneck and nothing else here has any effect. |
| `upload_mbit` | Upload the link really carries (Mbit/s) | int | `0` | The more important of the two: a saturated upload delays the acknowledgements downloads depend on. |
| `headroom_percent` | Keep back (percent) | int | `7` | How far under the measured rate the pipes are sized. |
| `lan_interface` | LAN interface | string | `""` | Where shaping is applied; addresses are untranslated here. Empty: detected from the local networks. |
| `default_class` | Class for everything not named | choice (high, normal, low) | `"normal"` |  |
| `weight_high` | Weight: high | int | `70` | Shares, not reservations. |
| `weight_normal` | Weight: normal | int | `25` |  |
| `weight_low` | Weight: low | int | `5` |  |
| `rules` | Rules | list | `[]` | One per line: `what = class`, optionally with a rate as a ceiling. See the Priority page in the user guide. |

### reports

Flexible report generation with 15+ sections, multi-format output, and scheduling.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `definitions` | Report definitions | list | Built-ins | Custom report templates; built-in definitions are read-only. |
| `keep_runs` | Keep last N runs per definition | number | `10` | Retention per definition; 0 = unlimited. |
| `max_total_mb` | Max total storage (MB) | number | `500` | Global limit for all stored runs; oldest pruned first. |

Reports are stored under `<DataDir>/reports/<definition>/<run>.<format>` with metadata indexed in KV. Scheduled delivery through alerting channels requires the alerting module.

### rulehygiene

Firewall ruleset analysis: shadowed, unused, redundant and overly permissive rules.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `analyse_minutes` | Analysis interval (minutes) | int | `15` |  |
| `min_evaluations_unused` | Min evaluations for unused detection | int | `1000` |  |
| `min_loaded_hours_unused` | Min loaded hours for unused detection | int | `24` |  |
| `wan_interfaces` | WAN interfaces (empty = auto-detect) | list | `[]` |  |
| `mgmt_ports` | Management ports (22, 80, 443) | list | `["22", "80", "443"]` |  |

### space (Pro tier)

Physical space mapping and device placement visualization.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `address` | Address | string | `""` | Your physical address for geocoding (US Census Geocoder). |
| `lat` | Latitude | float | `0.0` | Cached latitude from geocoding. |
| `lon` | Longitude | float | `0.0` | Cached longitude from geocoding. |
| `floor_height_m` | Default floor ceiling height (m) | float | `2.6` | Default height for new rooms. |
| `units` | Measurement units | string | `"metric"` | `"metric"` for metres, `"imperial"` for feet. |

### telemetry (Business tier)

Export metrics, events and alerts to an OpenTelemetry/HTTP endpoint (Grafana Mimir/Loki).

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `enabled` | Enabled | bool | `false` |  |
| `metrics_endpoint` | Metrics endpoint | string | `"http://127.0.0.1:4318/v1/metrics"` |  |
| `logs_endpoint` | Logs endpoint | string | `"http://127.0.0.1:4318/v1/logs"` |  |
| `interval_seconds` | Export interval (seconds) | int | `30` |  |
| `host_name` | Host name (default: hostname) | string | `""` |  |
| `headers` | HTTP headers (JSON map) | text | `{}` | Authentication headers, e.g. {"Authorization": "Bearer token"} |
| `events` | Also export events/alerts as log records | bool | `false` |  |

### tls

SSL transparency: the inspection CA, the certificate inventory and certificate findings.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `probe_certificates` | Complete the inventory by asking | bool | `true` | The proxy log names a certificate but carries no dates. With this on, FlowSight opens one TLS connection per recently seen server name to read its certificate: expiry, key, signature, alternative names and whether the chain verifies. A name is asked at most once a day. |
| `probe_per_run` | Names asked per run | int | `25` |  |
| `ca_name` | CA common name | string · restart | `"FlowSight Inspection CA"` |  |
| `ca_years` | CA validity (years) | int | `10` |  |
| `expiry_warn_days` | Warn on certificates expiring within (days) | int | `14` |  |

### ui

Interface preferences: colour theme.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `theme` | Theme | choice (auto, light, dark) | `"auto"` | auto follows the OPNsense theme when FlowSight is shown inside the OPNsense GUI (light, dark, or the GUI's own automatic mode), and the operating system preference otherwise. |

### updater

In-line self-update with manifest, signature and sha256 verification.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `enabled` | Enabled | bool | `true` |  |
| `channel` | Release channel | choice (stable, beta) | `"stable"` |  |
| `manifest_url` | Manifest URL | string | `"https://github.com/grioghar/flowsight/releases/latest/download/manifest.json"` |  |
| `check_hours` | Check interval (hours) | int | `6` |  |
| `auto_apply` | Apply updates automatically | bool | `false` |  |

### visibility

Flows, hosts, applications and throughput from ntopng/nDPI.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `ntopng_url` | ntopng URL | string | `""` | Empty uses the platform default. |
| `ntopng_user` | ntopng user | string | `"flowsight"` |  |
| `ntopng_password` | ntopng password | secret | `(secret)` |  |
| `ntopng_token` | ntopng API token | secret | `(secret)` | Preferred over a password when set. |
| `auto_account` | Create an ntopng account automatically | bool | `true` | When ntopng refuses the configured credentials, provision a 'flowsight' user through redis. |
| `redis_addr` | ntopng redis address | string | `"127.0.0.1:6379"` |  |
| `poll_seconds` | Poll interval (s) | int | `10` |  |
| `max_flows` | Flows per poll | int | `2000` |  |

### web

Transparent proxy: server names on every web session, inline blocking at the TLS handshake, optional inspection.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `intercept` | Intercept web traffic | bool | `true` | Redirect port 80 and 443 from the local networks through the proxy. Off: the proxy runs but sees nothing. |
| `networks` | Networks to intercept | list | `[]` | CIDRs. Empty: every local network. |
| `interfaces` | Interfaces | list | `[]` | Interface names (vtnet0, igb1 on OPNsense; eth1, lan0 on Linux). Empty: any on pf; on Linux, the interfaces holding the intercepted networks, never the WAN. |
| `http_port` | HTTP listener port | int | `3128` |  |
| `https_port` | HTTPS listener port | int | `3129` |  |
| `peek_server_cert` | Record server certificates without inspecting | bool | `false` | Peeks one step further into the handshake to log the server certificate, then splices. The device still receives the server's own certificate and judges it itself, even one the firewall cannot verify; only inspected devices get the proxy's error page for a bad certificate. A few servers dislike it. |
| `ipv6_listener` | IPv6 listener address | string | `"fd99::1"` | An IPv6 address the firewall holds on the LAN (a unique local address as a virtual IP works well). Empty: IPv6 web traffic is not intercepted. |
| `block_page_port` | Block page port | int | `8082` |  |
| `workers` | Squid workers | int | `1` |  |
| `auto_bypass_pinned` | Relay pinned sites without inspecting | bool | `true` | A client that pins its certificate refuses the inspection certificate and the site fails to load. With this on, FlowSight recognises that refusal and relays the name untouched from then on. No proxy can decrypt a pinned client. |
| `pinned_failures` | Refusals before a name counts as pinned | int | `3` |  |
| `pinned_window_minutes` | Refusal window (minutes) | int | `10` |  |
| `pinned_retest_hours` | Try inspecting a pinned name again after (hours) | int | `168` | 0 never retries. |


### scan

Active network scanning for local devices: ICMP, TCP/UDP probes, service detection, OS fingerprinting. Restricted to locally-known networks; off by default. Optional nmap enhancement when installed.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `scanning` | Allow active scanning | bool | `false` | Master switch. Off: all scans are refused. |
| `max_parallel_hosts` | Max parallel hosts | int | `2` | Job queue limit. |
| `max_parallel_ports` | Max parallel ports per host | int | `64` | TCP connect limit per target. |
| `port_set` | Port set | string | `"top100"` | `top100`, `top1000`, or `custom`. |
| `custom_ports` | Custom ports | string | `""` | Comma-separated list (e.g. `"22,80,443,3389"`). Used if `port_set` is `custom`. |
| `os_probe` | Probe for OS fingerprints | bool | `true` | TTL, mDNS, SSDP, SNMP, NetBIOS heuristics; nmap OS detection when installed. |
| `use_nmap` | Use nmap when installed | bool | `true` | Run nmap (if available) to enhance port service versions and OS accuracy. |
| `sweep_every_hours` | Sweep interval | int | `0` | 0: disabled. >0: scan all devices seen in the last 7 days every N hours. |
| `sweep_window` | Sweep time window | string | `""` | Optional UTC time window, e.g. `"02:00-05:00"`. Sweeps only run inside it. |
| `rate_limit_pps` | Rate limit (packets/sec) | int | `200` | ICMP and UDP probe rate; TCP respects connection limits. |

### inspect

Stateful and deep packet inspection via the firewall's state table and `tcpdump` capture with Wireshark-class analysis.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `max_states` | Max firewall states in memory | int | `20000` | Keep the newest N states; older discarded to cap memory. |
| `state_age_seconds` | State age threshold | int | `300` | States older than this are flagged for cleanup detection. |
| `snaplen` | Default snaplen (bytes) | int | `96` | 96: headers only (private-data safe). 65535: full payload (sensitive). |
| `max_capture_secs` | Max capture duration | int | `600` | Hard limit on capture runtime (seconds). |
| `max_capture_files` | Max rotated capture files | int | `5` | `tcpdump -W` limit: number of files in the ring buffer. |
| `max_capture_bytes` | Max total capture storage (MB) | int | `100` | Hard cap; oldest captures deleted when exceeded. |
| `payload_allowed` | Allow payload capture | bool | `false` | If true, users can select full payload (65535 bytes). Payload is sensitive. |
| `state_poll_seconds` | State poll interval | int | `30` | How often to read the firewall's connection table. |
| `syn_flood_threshold` | SYN flood alert threshold | int | `100` | Alert if SYN_SENT states from one source exceed this in the poll window. |
| `port_scan_threshold` | Port scan alert threshold | int | `50` | Alert if one source has this many non-established destinations in one poll. |

### Proxmox

The Proxmox module maps Proxmox VE cluster inventory into FlowSight: nodes, QEMU VMs, and LXC containers with their network addresses, OS information, and optional guest agent data. It enriches FlowSight's host database and optionally writes notes to guest descriptions.

**Settings**

| Key | Type | Default | Purpose |
|-----|------|---------|---------|
| `hosts` | list | empty | One or more Proxmox node URLs, e.g. `https://pve.local:8006`. Leave empty to disable. |
| `token_id` | string | empty | API token ID: `user@realm!tokenname`, e.g. `flowsight@pve!flowsight`. |
| `token_secret` | secret | empty | The API token secret. |
| `token_id_2`, `token_secret_2`, `fingerprint_2` | string, secret, string | empty | Credentials for the second URL in `hosts`, when that node is standalone and has its own token and certificate. Empty means the first node's. |
| `token_id_3`, `token_secret_3`, `fingerprint_3` | string, secret, string | empty | The same for the third URL. |
| `fingerprint` | string | empty | TLS certificate SHA-256 fingerprint pin (colon-separated hex), e.g. `4C:9E:F6:8A:...` |
| `verify_tls` | bool | false | When on, verify TLS with system CA roots. When off, use fingerprint pinning. |
| `poll_minutes` | int | 5 | Poll interval in minutes. |
| `write_notes` | bool | false | Write FlowSight notes blocks to guest descriptions (opt-in). |
| `notes_targets` | string | guests | Scope: `guests` or `guests+nodes`. |
| `exclude_vmids` | list | empty | VMID list to skip during polling. |
| `name_guests` | bool | true | Use guest names when no DHCP lease hostname. |
| `gateway_url` | string | | FlowSight URL used only to build the link back to the host page inside each guest's Notes. |
| `probe_sockets` | bool | false | For running QEMU guests with agent: query socket connections via `ss`. Requires VM.Monitor privilege. |

**Least-Privilege Token Setup**

Create a token with minimal privileges:

```bash
pveum role add FlowSight -privs "VM.Audit VM.Config.Options Sys.Audit Datastore.Audit VM.GuestAgent.Audit"
pveum user add flowsight@pve
pveum user token add flowsight@pve flowsight --privsep 0
pveum acl modify / --users flowsight@pve --roles FlowSight
```

Privileges:
- `VM.Audit`: query guests, config, status, agent info
- `VM.Config.Options`: write guest descriptions (notes only)
- `Sys.Audit`: read node status and version

**TLS Fingerprint**

Read from your Proxmox node:

```bash
pvenode cert info | grep Fingerprint
# or remotely
openssl s_client -connect pve.local:8006 -showcerts </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```

Enter with colons (case-insensitive). Verification is automatic when `verify_tls` is off.
