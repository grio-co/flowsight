# Changelog

What changed in each release, written for the person running FlowSight
rather than for the person who wrote it: what is different, what you have to
do about it, and what is now possible that was not before.

Versions are `<version>` for a release and `<version>r<YYYYMMDDHHMM>` for a
revision of it, where the suffix is the UTC minute it was built. A revision
carries fixes and small additions; the version number itself moves only when
that is decided deliberately. Every entry below is a git tag of the same
name, and every release's assets carry that string in their file names.

The newest entry is first.

## 0.9.8r202609262130

**DNS keeps working after Unbound restarts.** A DNS-block policy's zone file
was kept in `/var/unbound/etc`, which OPNsense empties every time it starts
Unbound, while the include naming the zone file came back. After a reboot,
or a restart from the GUI, Unbound refused to start ("cannot open zonefile")
and DNS was down for every client until someone intervened; FlowSight then
tried to reload the stopped resolver, failed, and reverted, so it never
recovered by itself. Zone files now live in `/var/unbound/flowsight`, which
survives restarts, and an Unbound that is enabled but stopped is started
rather than reloaded. An Unbound the operator has disabled is never started.
Old zone files are removed on the first reconcile. Nothing to do; if
Unbound is down on an older version, see OPERATIONS.md.

## 0.9.8r202609262045

**Upgrading from an older build starts again.** 0.9.8r202609262017 created
an index on the flows table's `anycast` column before the migration that
adds that column, so a gateway whose database predates the column (anything
upgrading from before 25 September) stopped at startup with "no such column:
anycast" and restarted in a loop. The index is now created after the column.
Gateways already running 0.9.8r202609262017 were not affected.

**Rule hygiene reads the ruleset through the firewall module.** Nothing
changes in its findings, which keep their fingerprints. The firewall module
must be enabled for Firewall Analysis (and for the connection-state view)
to have data; with it disabled they stay empty instead of calling pfctl
themselves. A failed read now says "reading the pf ruleset failed" instead
of "pfctl failed".

**The Map is the page.** The world now fills the whole window under the top
bar, at the same projection and scale as before; nothing is boxed or
shrunk. Everything that sat beside or under it is a panel on top of it:
**Route** (the chosen route, step by step), **Hop detail**, the **Key**
(its layer switches unchanged) and a **Data** drawer with tabs for the
overview numbers, data sources, your location, the physics tables, hops not
on the map, the destinations table, the full route trail and the notes.
Drag a panel by its title; let go near an edge or corner and it docks there
and stays put when the window changes size; double-click a title to send a
panel home; fold with the small button or Esc; close and bring back from
**Panels** in the toolbar, which also puts every panel back. The arrangement
is remembered in this browser. Panels step back while the map is being
moved, hovering a hop shows its address, place and round trip at the
pointer, and zoom and home buttons sit bottom right. Filters live in a
toolbar along the top and apply on choice, as before. On narrow screens the
panels stack under the map instead of floating.

## 0.9.8r202609262017

**Survive a restore.** Found when the gateway moved hosts from a backup taken
mid-write: `flowsight.json` came back empty, the daemon ran on defaults
(loopback bind, no token, no settings) and its first save made that
permanent. Saves are now synced to disk before the rename, the previous
contents are kept as `flowsight.json.prev`, and an empty or unreadable file
is restored from that copy and logged. Also from that boot: the pf policy
anchor was never reloaded because the rules file matched what was wanted
while the kernel held nothing; the kernel is now checked, so a reboot gets
its rules back on the first reconcile. The dark-traffic check no longer
panics on integer counts.

**IPv6 in the live egress view.** pf writes an IPv6 endpoint as
`addr[port]`, which the egress view could not read, so IPv6 transfers never
showed up there. They do now. `/api/inspect/rules` returns every rule with
its counters (`rules`), plus `backend` and `syntax`; `rule_count` now counts
rules instead of output lines, and `raw` is the rule text without the
counter lines. On a system without pf, inspect's state poller no longer
warns on every poll and `/api/inspect/rules` answers 400. Underneath,
modules that fill pf tables or read pf's connection table now go through
backend-neutral services (ARCHITECTURE.md, "Enforcement services"), the
first step towards FlowSight on nftables and pfSense. Nothing to do.

## 0.9.8r202609261940

**Proxmox poll errors are visible.** A node that could not be polled now
appears in `/api/proxmox/status` (`errors`, `hosts`) and in the inventory,
and is logged, instead of vanishing.

## 0.9.8r202609261937

**Proxmox: a token and certificate per node.** Standalone nodes share
neither, so the second and third URLs in `hosts` can carry their own
`token_id_N`, `token_secret_N` and `fingerprint_N`; empty falls back to
the first node's. Needed to watch guests on two hypervisors at once.

## 0.9.8r202609261935

**`hostmap_url` retired from zones.json.** It fed the old Python enrollment
script from a per-host sensors server and nothing in the daemon has read it
since the native rewrite; guests are matched to devices by the proxmox module
from every host in its `hosts` list. The key is ignored if present and
dropped on the next save.

## 0.9.8r202609261927

**Assistant told to page.** Its instructions now name the summary and paging
parameters so an overview of many devices is one call, not one per device.

## 0.9.8r202609261926

**Abroad fits in one answer.** `/api/visibility/abroad` takes `detail=summary`
(one small row per device, sessions per country, no destinations) and pages
with `offset`; the busiest devices are now chosen before the cut, not after.
The assistant is told to prefer summary and paging parameters over one call
per device.

## 0.9.8r202609261918

**A token of its own for the remote Claude.** `mcp_token_name` names an
`api_tokens` entry that the remote Claude Code receives for `/api/mcp`
instead of the main token, so it can be rotated on its own and its writes
show as `token:<name>` in the audit log; the status says when the name is
not in the file.

## 0.9.8r202609261909

**Two things the assistant's first answer pointed out.** The abroad view's
`ip` filter matched one address, so a device that had used a different
address (its IPv6 one, say) looked clean; it now matches every address the
device holds. And a tool result too big for the model was cut mid-row; a
JSON result is now shortened at array boundaries with a `_truncated` note
saying what was kept, and the abroad view takes a `limit` (default 50
devices) and reports `devices_total`.

## 0.9.8r202609261906

**First live question through Claude Code, and what it taught.** A 65 KB
tool result overflowed Claude Code's limit and it fell back to its own shell
and file tools, which then waited for approvals; a tool whose path also has
a write route was sent to the write route; and the run ended at the turn
cap without a sentence. Now: tool results are capped at 24 KB by default
with a note saying how to narrow the query; Claude Code is run with its
shell and file tools disallowed and a system prompt that says to use only
FlowSight's tools; a tool name always resolves to the read route when one
exists; and a run that ends without a final answer reports that plainly.

## 0.9.8r202609261903

**Claude Code on another machine.** The claude-code provider can run the
CLI over SSH on a VM or container where Claude Code is installed and logged
in with a subscription, so no API key is needed and nothing but an SSH key
is added to the gateway. FlowSight generates its own ed25519 key (shown as
`ssh_public_key` in the status, `GET /api/assistant/ssh_key`), quotes the
command for the remote shell, and attaches itself to that Claude over HTTP
MCP at `mcp_url`. Settings: `claude_ssh`, `mcp_url`, `claude_ssh_key`,
`ssh_path`. The key file is OpenSSH's own format, encoded in the daemon
without third-party code and checked against `ssh-keygen` in the tests.

## 0.9.8r202609261853

**Organisation-level Anthropic keys.** Such a key is accepted by the API
only with a workspace id; the assistant gains a `workspace_id` setting sent
as the `anthropic-workspace-id` header. A key created inside a workspace
needs nothing.

## 0.9.8r202609261845

**Assistant settings apply without a restart.** The module read its
settings once at start, so choosing a provider on the Settings page left
it reporting off until the daemon restarted. Settings are now read at every
use.

## 0.9.8r202609261844

**One key for the map's lookup and the assistant.** With no `api_key` of
its own, the assistant uses the key already set for the map's AI hop lookup
(`ai_key` under Settings › paths), so turning the assistant on needs only
the provider choice.

## 0.9.8r202609261837

**Tool names are unique.** A collection route and its item route (for
example `/api/alerting/channels` and `/api/alerting/channels/{id}`) had
produced the same tool name, which MCP clients reject; the path parameter
now stays in the name (`alerting_channels_by_id`), hyphens and dots become
underscores, and the gate asserts there are no duplicates.

## 0.9.8r202609261834

**Claude as FlowSight's analyst via Claude Code Agent SDK:** Two new features expand FlowSight's AI capabilities and integrate with Claude Code.

**Ask FlowSight in plain English:** A new "Ask" page under Monitor lets operators ask questions about their network in English. The assistant uses FlowSight's own routes as tools to answer by looking at flows, hosts, policies, and other data. Powered by Anthropic's Messages API or Claude Code's headless mode (controlled by settings `provider` and `api_key`). A system prompt ensures the assistant cites which tools it looked at, prefers FlowSight's data over guessing, and keeps answers brief. Earlier questions are kept in a searchable history. When the provider is on, a banner warns that questions and the data the model asks for leave the gateway.

**MCP server for Claude Code agents:** `flowsightd mcp` is a new subcommand that runs a Model Context Protocol (MCP) server over stdio, exposing all of FlowSight's GET routes (and write routes if allowed by setting `mcp_allow_writes`) as tools. Tools are named from their paths (e.g., `visibility_flows`, `policy_matches`) with input schemas built from their documented parameters. This lets Claude Code and other tools built on the Agent SDK call FlowSight directly. The HTTP `/api/mcp` endpoint serves the same tools over MCP's Streamable HTTP transport, guarded by the normal API auth. Claude Code setup: `claude mcp add flowsight -- flowsightd mcp` to use stdio, or add the HTTP form with the token header for remote agents.

**Paths AI now supports three providers:** The paths module's hop-location assistant now accepts `ai_provider` settings for anthropic, openai, google, azure, ollama, custom, and the new internal provider **assistant**, which delegates to the main assistant module. This means one key serves both: ask FlowSight via the Monitor page, and let the paths AI use the same model to place unroutable hops.

**New assistant module settings:** `provider` (off, anthropic, claude-code), `api_key` (Anthropic secret), `model` (default claude-sonnet-5), `claude_path` (default "claude"), `max_turns`, `max_tool_result_bytes`, `allow_writes`, `mcp_allow_writes`, `timeout_seconds`, `retention_days` (for conversation history), and `redact_addresses` (replace RFC1918 and local IPs with placeholders before sending to the provider).

**API documentation:** `/api/assistant/status` (provider state and tool count), `/api/assistant/ask` (question + streaming answer), `/api/assistant/conversations` (list and search), `/api/assistant/tools` (tool list with schemas), `/api/mcp` (MCP protocol endpoint). All routes are documented to contract with descriptions, parameters, and response schemas.

How it is built: the anthropic provider is a streaming tool-use loop over
the Messages API (text as it arrives, each tool call and its result, then
done); the claude-code provider runs `claude -p … --output-format
stream-json --append-system-prompt … --mcp-config … --allowedTools
mcp__flowsight__* --permission-mode default` in its own process group with
FlowSight attached as an MCP server, relays its transcript, and kills the
group at the deadline; `flowsightd mcp` is a stdio bridge to `POST
/api/mcp` and never opens the store; conversations live in the store; the
Ask page under Monitor streams the answer with the tool trail and says when
data leaves. Tests cover tool calls reaching the daemon, the Anthropic loop
against a fake API, the CLI against a fake transcript and a sleeping one,
the bridge, redaction and the store. Also restored: the enroll routes'
documentation (lost in an earlier merge) and the all-modules import of the
documentation gate, which had been checking seven routes instead of 230.

## 0.9.8r202609260011

One release for the branches that landed together after the visibility
release: scale, the small items, the documented API, IPv6 zones. Each was
built and tested on its own branch. Also in this release: the per-session
readability value is written when a long-lived flow is updated (it had only
been written on insert, so nearly every live session showed none), it is
never empty (encrypted without a readable handshake is *opaque*, the rest
*plain*), and the last week of sessions was filled from the stored columns.

**IPv6 zone membership:** Zones now support IPv6 subnets. The `subnet6` field 
specifies an IPv6 CIDR (e.g. `fd00::0/64`) that is returned alongside IPv4 when 
resolving `zone:<id>` members in policies. The zone resolver also returns every 
IPv6 address each device in the zone holds, so firewall and DNS rules cover both 
address families without requiring separate IPv6-specific policies. A policy 
warning alerts when zone members resolve to IPv4 only but at least one device 
uses IPv6: add the zone's IPv6 subnet or explicitly target devices by MAC or name. 
The Zones page shows the IPv6 subnet in the zone list and accepts it in the 
zones.json editor.

**Complete API documentation:** All 223 routes across categories, inspect, space, TLS, web, netflow, users, baseline, and firewall modules are now documented to the contract with descriptions, parameters, response schemas, and realistic examples. The API specification is machine-validated to ensure every route's documentation matches how it actually handles requests.

## 0.9.8rPENDING

**Encrypted traffic: visibility shows what FlowSight can and cannot see.**
Each flow now carries a `visibility` field showing why it is or is not readable:
`inspected` (squid decrypted it), `sni` (TLS with server name from ClientHello),
`http` (plain HTTP), `quic` (QUIC encrypted, name opaque by design), `opaque`
(encrypted with no visible name), `dns` (DNS transaction, always readable), or
`plain` (unencrypted). The Sessions page adds a "Readable" column with a badge
showing the visibility reason; a filter chip narrows to visibility=opaque|ech|quic|inspected.
The host summary shows traffic counts and names by visibility over the window, so
operators learn which devices use encryption that closes off policy control.

**PDF reports add charts.** The PDF writer now draws bar charts and line charts
using PDF path operators (rectangles for bars, line segments for trends) without
external dependencies. Charts appear in report sections where they help: top
traffic by device or app as horizontal bars, executive summary throughput as a
line over time, DNS allowed vs. blocked as bars.

The PDF now draws the charts: the top ten by bytes for the traffic breakdowns
and blocked against allowed for DNS, before each section's table.

**Comprehensive alerting provider tests and IPv6 zone support.** The alerting
module now has wire-format tests for 11+ channels: SMTP (fake server validates
HELO/AUTH/MAIL/DATA), SendGrid (Bearer auth, mail API), Slack/Discord/Teams/
Telegram/Ntfy (webhook POST, auth headers, payload structure), Syslog (RFC5424
UDP), SplunkHEC (/services/collector endpoint), CloudWatch (SigV4 auth), and
Wazuh API (event format). All tests verify correct HTTP methods, authentication,
content types and JSON structures.

Zones now support optional IPv6 configuration: `subnet6`, `gateway6`, and
`range6` fields alongside IPv4. Prepare for IPv6-aware device membership and
policy enforcement. Documentation expanded with non-goals (multi-gateway HA,
CARP/VRRP) and "Reviewing the host firewall" guidance on monitor mode and
rule conflicts before deploying policies.

**Scale testing, benchmarking and indices for heavy queries.** New tools
measure performance limits: `cmd/fsload` generates synthetic data at three
scales (50/500/2000 devices × 7/30/90 days); `cmd/fsbench` benchmarks read
paths and reports latency/memory; `test/e2e/run.sh` is an end-to-end
regression harness. New indices on flows table: (country,ts), (anycast,ts),
(country,anycast,ts), (src_ip,dst_ip,ts) speed heavy aggregation queries.
Retention is now configurable in flowsight.json (core.retention) with defaults:
7 days raw flows, 400 days rollups; hourly prune runs in bounded batches.
List routes (flows, top, hosts, DNS summary) support limit/offset pagination,
documented in OPERATIONS.md. macOS support: daemon runs in generic platform
mode (no firewall, DNS or proxy integration). Tested envelope shows measured
limits at three device/day scales with peak memory and query latencies.

**How-to guides for every task.** A new section `docs/howto/` with 15 task-first guides covers: first hour after install, seeing device traffic, identifying unknowns, blocking by country, reading policy matches, tracing the Map, watching DLP transfers, scheduling policies, TLS inspection, packet capture, alerting, reports, Proxmox inventory, physical space, API automation, and understanding blocked traffic. Each guide names exact pages and buttons, shows prerequisites and limits, and walks through to a working result. The existing HOWTO-IOT-ABROAD.md moved to `howto/iot-abroad.md` with a stub at the old path pointing to it.

**All 166 API routes fully documented with real data.** Complete OpenAPI 3.0
documentation across all modules with request/response schemas, parameter types,
realistic example values (IP addresses, hostnames, timestamps), and operation
descriptions. All stub responses replaced with actual return structures from
handlers. Descriptions rewritten for clarity (≥25 characters). The `apidoc` tool
generates the full searchable API.md from the live spec. Routes use documentation
helpers to keep metadata concise and aligned with actual handler implementations.
Download the spec from the API page for Swagger UI, Insomnia, or Postman.

**Country codes show their name on hover.** Everywhere the interface prints
a two-letter country (Sessions, the DLP card, Policy matches, the firewall
tables card, the policy list, the Map's filter and tables, the address
flags) the code stays short on the page and the full name is the tooltip.
The name table is the ISO 3166 list the policy editor already uses.

**FCC broadband-map data is kept and queryable.** The national provider
summaries (fixed and mobile broadband) and the origin state's census-place
summaries are now pulled and kept in compact JSON. The catalog parsing is
robust to column-name variations across releases and uses `json.Number` to
handle string record counts. `GET /api/paths/fcc/summary` shows what was
kept; `POST /api/paths/fcc/pull` runs the pull now. The parser falls back to
substring matching for numeric columns when exact names vary. The pull job
never runs concurrently with itself and skips silently when credentials are
absent.

**Submarine cables, fetched at runtime and used to rule things out.** With
*Show submarine cables* on, FlowSight downloads TeleGeography's published
cable map and draws it behind the routes. Hovering a leg long enough to have
left the continent lists the cables that could have carried it.

Could, not did. A traceroute gives router addresses and round trips and never
names a cable, so if two places are joined by eight cables then all eight fit
the observation equally. Ruling members out is the part that is not
guesswork: a cable cannot carry a round trip faster than twice its length
divided by the speed of light in fibre, and cables are long and rarely
direct, so a great many candidates are discarded outright. What survives is a
list, shortest first, never an answer.

The map is fetched by each installation rather than shipped, and refreshed
monthly. TeleGeography publish it as a free public resource but it is not
openly licensed, which is why it is not bundled.

**Also: the Map entry was in the menu and invisible.** OPNsense parses every
menu file once and caches the result for an hour, and restarting the web
interface does not clear it. The cache on this gateway predated the change by
half an hour. Deleted; it rebuilds on the next page load.

**The last phantom devices are removed, including those Windows made.** The
cleanup in 0.9.8r202609240739 recognised the client identifiers most systems
send, but Windows writes part of its identifier in the other byte order, so
its phantom stayed. Any recorded device whose address starts the way a
client identifier does and that has no IP address, name or vendor is now
removed at startup; real hardware whose address happens to start the same
way always has an IP address, so it stays, as does anything you pinned.

**Working out where you are no longer picks the gateway's own LAN address.**
It looked for an address that was globally routable and not private, and a
delegated IPv6 prefix is exactly that while still belonging to this network,
so the LAN interface won and the map had no origin at all. It now skips
anything identity recognises as ours, which is the only thing that can tell
the two apart.

**The map has its own place in the menu, and knows where you are.** It is
**Map** under FlowSight now rather than buried, and the page carries the
origin it is drawn from.

Left alone the origin is worked out from the gateway's public address, which
is usually the right town and occasionally the wrong state, because it is
where the carrier registered the block rather than where the wire ends. You
can declare it instead: type it, take the address database's answer, or let
the browser tell you, which knows precisely and asks permission first.

**And that origin earns its keep immediately.** Light in fibre covers about
200,000 km per second, so a round trip cannot beat twice the straight-line
distance divided by that, before any routing detour or equipment delay. A hop
that answers faster than that floor is not where the database says it is. The
map circles those and lists them with the numbers.

On this gateway seven of twenty-seven placements fail it. The clearest is
1.1.1.1, which the database puts in Sydney, 14,071 km away, where nothing
could answer in under 141 ms. It answers in 22. It is anycast: registered in
one place, answered from whichever site is nearest you. The map no longer
draws a line to Australia and calls it measurement.

**The device list no longer contains devices that do not exist.** DHCPv6
log lines use the same names as DHCPv4 ones (a request, for instance) but
carry a client identifier where the address would be, and the first six
octets of that identifier were being read as an address. Each IPv6 client
produced a phantom device with no name or vendor, listed as unidentified.
Those lines are now ignored, and phantom entries already recorded are
removed at startup unless you pinned one to a zone.

**Devices are recognised from DHCP acknowledgements again.** The same
parser expected the address before the IP on a DHCPv4 acknowledgement,
which is the other way round from what dnsmasq writes, so acknowledgements
were never read and a device's IP and name arrived late or not at all.

**Device zones follow the classification rules until you choose one.** A
zone used to be decided once, when a device was first seen, and then never
revisited, so a rule edit changed nothing for devices already known, and
zones handed out by the classification fault fixed in 0.9.8r202609232121
stayed wrong: on one network 112 devices were still in infrastructure. In
monitor mode every device now follows the rules on each reconcile, including
devices that have not been heard from recently.

What you have to do: check the Devices page after upgrading. Zones set by
hand before this release were not recorded as such and are replaced by what
the rules say; choose them again and they stay. Choosing a zone now pins the
device there (shown as *pinned*); choosing the empty entry unpins it. A zone
picked on the captive page pins the same way. Enforce mode is unchanged: a
device that already has a zone keeps it, and only devices without one are
placed.

Saving a device's zone no longer counts as seeing it, so *last seen* is
when the device was actually heard from.

**Which addresses belong to which device now survives a restart.** A device's
addresses are learned from the neighbour table, which is a cache of who is
reachable right now rather than a record of who has been here, and IPv6
privacy addresses rotate out of it within hours. That association was only
ever held in memory, so every restart discarded everything not currently
reachable, despite a setting promising to remember it for a day.

On this gateway that left 97 of 237 IPv6 hosts with no device behind them.
The effect showed up wherever a device means more than one address: the path
map's device filter listed the same laptop once per address, and an exclusion
written for one address family could not find the other.

The memory is now written down each cycle and pruned to the window the
setting asks for, so it cannot grow without bound.

**The path map filters by device, and a device means the whole device.** The
filter was a box for typing an address. It is now a list of devices with
their names, one entry each however many addresses they hold, and choosing
one covers all of them.

That distinction is the point rather than a nicety. On the gateway, eight of
the nine source addresses with measured routes belonged to two machines: a
laptop answers to an IPv4 lease and a handful of rotating IPv6 privacy
addresses. A picker keyed on addresses would have listed the same laptop
eight times, and filtering on whichever one was handy would have shown a
fraction of where it had actually been.

**Rules saved from the Enrollment page or the API now take effect straight
away.** Saving rules read each rule's name, zone and explanation as if they
were conditions to match. Since conditions FlowSight does not recognise now
match nothing, every saved rule matched no device, and every device was
classified as unidentified until the daemon restarted and read the file
again. Saved rules are now read exactly as the file is at startup. Nothing
to do: if you saved rules and then restarted to make them work, they were
already correct on disk.

**The map had nodes and no lines between them.** Legs refer to nodes by an
identifier that was computed and then never stored, so every leg pointed at
nothing and the filter, which quite correctly drops a leg whose ends are
missing, dropped all of them. On the live gateway that was eighty-seven hops
and zero connections.

**The FlowSight entry in the OPNsense menu now matches the sections around
it.** It carried a fixed-width icon class that no core section uses, which is
what made it sit differently from Firewall and Services, and a redundant
display name. It is now declared exactly as OPNsense declares its own
sections. The submenu entries gained icons, as the core submenus have, and
the four pages added recently are in the menu at last: Paths, Data out, Deep
inspection and Priority.

**Path tracing no longer probes things that are not destinations.** The first
live run traced a multicast group and the gateway's own global address,
twenty timed-out probes each for a row of nothing. Multicast, broadcast and
any address this network's identity module recognises as its own are now
skipped. That last part matters for IPv6: the delegated prefix is globally
routable and still ours, so no fixed list of private ranges can catch it.

**Paths: where traffic actually goes, measured.** A new page and module under
Visibility. Everything else in FlowSight watches the first hop; this traces
the rest of the route to the destinations your network already contacts, a
few at a time on a timer, and keeps what it finds. Nothing is probed that the
network has not already talked to.

A path belongs to a destination rather than a device, because everything
leaves through the same gateway. Filtering by device is a join over your own
flow history, so it costs no extra probes.

**Many routes fold into one picture.** Every route out starts the same way,
and drawn literally that is a hundred lines on top of each other. A leg used
by several destinations becomes one thicker line in a neutral colour;
coloured lines belong to a single destination. A position answering from
several addresses, which is how a carrier balances across parallel links, is
one point carrying several addresses rather than several points. Filters on
country, latency, distance in hops and device, with wheel to zoom and drag to
pan.

**Three things the map refuses to pretend.** The background is a longitude
and latitude grid, not a drawing of land, because these coordinates are
dependable for end-user addresses and rough for carrier equipment. Hops with
no coordinates are listed underneath rather than placed at zero, which would
pile a stack of routers into the Gulf of Guinea. Hops that never answered are
counted and not drawn, and they keep their place in the numbering so a path
is never quietly reported as shorter than it is.

Needs the city-level location database, since the country one carries no
coordinates.

**Location lookup can now answer with coordinates, not just a country.**
*Settings › enrich › How much detail* chooses between the country database,
which is a few megabytes, and the city database, which is a much larger
download and adds the city, the region and the latitude and longitude a map
needs. Country stays the default: the larger file is only worth fetching if
something is going to draw with it.

The two are kept in separate files on disk. Sharing one name would let a
country database already downloaded stand in for the city one that was asked
for, and the only symptom would be a map with nothing on it.

Both still come from DB-IP's free files by default, and a configured URL
still wins, so a licensed MaxMind database works as before.

**Worth knowing before trusting a map built on this.** Geolocation is
accurate for end-user addresses and unreliable for infrastructure. In
testing, 1.1.1.1 resolves to Sydney because that is where Cloudflare
registered the block, while the server actually answering is whichever one
is nearest you. Coordinates are absent for a great many addresses, and zero
is reported rather than a guess, so anything drawing a map has to handle
"unknown" as a real answer.

**Every device was being classified as the first rule in the list.** The rule
loader took the whole rule object as its condition set, so `id`, `zone`,
`confidence` and `why` sat alongside the real conditions, and the matcher
treated any key it did not recognise as a match. Between them, every rule
matched every device. On a live network that filed all 106 devices as
infrastructure, televisions and smart plugs included, which made it
impossible to write a policy that said "IoT" and have it mean anything.

The conditions are now read from the rule's `when` block, and an unrecognised
condition no longer counts as a match. A rule that fails open turns one typo
into "everything" without saying so, which is the worst way for this to be
wrong.

**An exclusion now covers the device, not just one of its addresses.**
Excluding a range exempted traffic in that address family only, so a
television excluded by its IPv4 address was still intercepted over IPv6. The
redirect rules are emitted for both families, and an exclusion written as an
IPv4 range is resolved to the devices inside it and widened to every address
those devices hold. The link between the two is the MAC, the only identifier
that spans both.

**Priority: decide who waits when the link is full.** A new module and page
under Policy, and the first thing in FlowSight that changes traffic rather
than describing it.

It works by moving the bottleneck. When an uplink fills, the queue that
decides what waits belongs to the modem or the carrier and nothing on this
firewall can reach it, so shaping starts by sending everything through a pipe
sized a little under what the link really carries. Once the queue is on this
side, weights decide who waits. That is why the two rates are settings and
why they have to be honest.

Rules are written the way you would say them: `192.168.1.178 = low`,
`redgifs.com = high`, `10.0.5.0/24 = low, 20Mbit`. An address is understood
as a device here or as something out on the internet depending on which side
of your local networks it falls. A domain matches the addresses the network
has actually been seen using for it, and the page says per rule how many that
currently is, rather than leaving a rule that matches nothing looking
identical to one that works. The generated firewall rules are shown on the
page so they can be read before they are trusted.

Measured on the test gateway, against an unshaped baseline of several
gigabits:

| | |
|---|---|
| Link held to a 46.5 Mbit/s pipe | 44.9 Mbit/s |
| Two flows, weights 70 and 5 | 93% and 7% of the link |
| A rule capped at 10 Mbit/s | 9.7 Mbit/s |

Three things had to be got right for any of that to work, and each looked
fine while wrong. A queue named on a rule that specifies a direction applies
only to that direction, so each rule needs a partner on the reply. Dummynet's
fast path is off by default, and without it the engine dropped 4.6 percent of
every packet it handled, which held a 14 Mbit/s pipe to 4.6 Mbit/s of real
throughput. And a pipe's buffer has to be sized to the rate it carries, or
TCP is throttled by loss long before it reaches the limit you set.

Shaping is off by default and has to be switched on deliberately.

**Inspecting everything no longer discards your bypass lists.** Turning on
**inspect everything that crosses the firewall** created a policy covering
every local network whose only exemptions were the exclusions and the names
found to pin. The domains you had put on a policy's bypass list, banks,
password managers, anything you had decided must never be decrypted, applied
only to the devices that policy named. So switching the setting on started
decrypting those names for every other device on the network.

That was backwards. Widening who is inspected must not narrow what is
protected: a bank is not something to start decrypting for the tablet
because it was only ever named on the laptop's policy. Every bypass list in
the document is now honoured when inspecting everything, along with the
exclusions and the pinned names, with duplicates collapsed.

On the gateway this was the difference between 35 protected names and 196.

**Sites that could be inspected were being marked as pinned and relayed.** The
detector treated any bumped CONNECT that carried no bytes as the client
refusing the certificate. The proxy writes that line the same way whether the
client accepted it or not, and then logs the requests made inside. So a
perfectly ordinary decrypted session looked identical to a refusal, and
working sites were added to the bypass list and spliced from then on, quietly
costing inspection coverage on exactly the sites where it was possible.

A bumped connection is now judged by what follows it: a request inside the
tunnel means the client accepted the certificate, and only a connection that
carries nothing for fifteen seconds counts as a refusal. The entries found
with the old test are cleared once at startup. Names that genuinely pin are
detected again within minutes; the rest stop being relayed for no reason.
Entries you added by hand are untouched.

**Turning deep inspection's settings on now takes effect at once.** The policy
compiler skips its work when nothing it depends on has changed, and the list
of things it depends on did not include the deep inspection module. So
switching on **inspect everything that crosses the firewall** appeared to do
nothing: the setting saved, the page showed it on, and the proxy carried on
with the old configuration until some unrelated change happened to force a
rebuild, which could be ten minutes later. The module is part of that list
now.

**Data out tells serving apart from reaching out.** A media server streaming
three gigabytes to someone watching from outside has really sent three
gigabytes, and it is not data leaving in the sense anyone means by it. The
firewall records who opened each connection, so those rows are now marked
**serving**, left out of the totals and never alerted on. Only connections a
device here opened count as data leaving.

**A destination is asked about before it is called nameless.** Naming used
only the server names seen in handshakes and the answers to DNS queries, so a
destination reached by address alone looked anonymous when it answers to a
perfectly ordinary name. The reverse lookup is now the last resort before
anything is reported as unnamed, which is the loudest thing this page says.

**Broadcast and multicast are not egress.** Traffic to a broadcast address, a
multicast group or a link-local address never leaves the network and is no
longer counted or listed.

**The sampler no longer reads the database.** Naming meant scanning two tables
that grow all year, on the same job as the sample, which made a five-second
sampler take twelve seconds on a real gateway. Naming is now its own job on a
minute, the sample is pure parsing, and there is an index behind the lookup
that needed one. A sample takes about fifty milliseconds.

**Data out: what is leaving the network, while it leaves.** A new page and a
new module under Security. Everything else in FlowSight reports what
happened; this reports what is happening, because a transfer you read about
tomorrow is a transfer that already finished.

It does not read logs. It samples the firewall's own connection counters
every few seconds, which means it sees what no inspection can open: sessions
whose certificate is pinned, spliced sessions, QUIC on UDP 443 that never
reaches the proxy, and encrypted tunnels. None of those can be decrypted and
all of them can be measured. Each row is one live connection with the device,
the destination and the name FlowSight can put to it, the current upload
rate, the totals and how long it has been open. **Stop** drops the connection
at the firewall while it is running.

Destinations are grouped by what would change your mind about them: cloud
storage, file transfer and paste sites, code hosting, personal mail,
messaging, AI assistants, remote access, backup, media, telemetry, content
delivery, encrypted tunnels, and **unnamed**. Unnamed means no DNS answer, no
server name in any handshake and no reverse lookup could name the place the
data is going, which makes it the row most worth reading.

Thresholds raise an event mid-transfer: a volume of data sent, a sustained
upload rate, a session that has sent several times what it received, the
first time a device reaches a kind of destination it never has before, and
anything going somewhere unnamed. A quiet-hours window raises the severity of
anything flagged inside it. Events are published to subscribers, which is the
seam a later module will use to act on them rather than only report them.

**Reading the counters the wrong way round would have reported every download
as an upload**, so the direction is pinned by test against a real capture from
the gateway, including the case that matters most here: an intercepted session
names the proxy's own loopback address as one end, and treating that as the
local device silently discarded every inspected session.

**A certificate opens where you are looking.** Inside the OPNsense panel the
FlowSight page has no scrollbar of its own and can be many screens tall, so a
dialog pinned to the top of that page opened far above whatever you had
scrolled to, and you had to scroll up to find it. Dialogs now open over the
part of the page that is on screen, and follow it if you keep scrolling.

**Deep inspection, for the Business tier.** A new module reads what a
decrypted session actually carries: the method, the full URL, the response
code, the content type, the size, the timing, and the request headers when
you ask for them. Cookies and authorization headers are recorded as a byte
count and never as a value, and no body is ever stored. It appears as
**Deep inspection** under Security.

The proxy hands each exchange over using ICAP, the protocol squid speaks to
a content adaptation service, and FlowSight answers "no modification", so
nothing is proxied through FlowSight and nothing is altered on the way. It
only ever sees sessions a policy already decrypts: a device without TLS
inspection, an excluded host and a pinned name never reach it.

**DNS-over-HTTPS queries are decoded in full.** A browser that resolves over
HTTPS puts its question in the request body, where a proxy log cannot see
it. Deep inspection reads it and files it in the DNS history like any other
lookup, so the name is visible and attributable to the device that asked.

**Inspect everything that crosses the firewall.** A checkbox in the deep
inspection settings that decrypts every intercepted client rather than only
those a policy names, appliances and televisions included. A device that
does not trust the FlowSight CA fails to connect until the pinned-site
detector notices the refusal and starts relaying that name untouched, so an
appliance you cannot install a certificate on ends up relayed rather than
broken. Excluded hosts are never touched.

**Certificate names are recorded whole.** A distinguished name contains
spaces, and the proxy was logging subject and issuer unquoted, so every name
was cut at the first space: "Let's Encrypt" became "Let's", and the rest of
the name was read as the start of the next field. The names are now logged
in quotes and parsed accordingly. The inventory rows recorded under the old
format cannot be repaired and are cleared once, at startup; the proxy
rebuilds them from the next handshakes it sees.

**The certificate inventory is filled in.** FlowSight now opens a TLS
connection to the server names it has seen and records what is served:
validity dates, key type and size, signature algorithm, serial,
alternative names, fingerprint, and whether the chain verifies against the
system roots. That is what makes the TLS page's **Key**, **Expires** and
**Flags** columns real rather than empty, including for spliced sessions
whose certificate the proxy never sees. It runs every fifteen minutes, a few
names at a time, and can be switched off.

**Certificates open.** Click any row in the TLS inventory for the whole
certificate: both distinguished names unabbreviated, the serial, the key,
the validity with the days remaining, the fingerprint and every subject
alternative name.

**The TLS page is less crowded.** Two donut charts took a third of the
screen to say that nearly everything is TLS 1.3. Protocol version and
session handling are now two proportion bars in one card, which leaves the
issuer chart the room it needed.

**The updater no longer times out on a large download.** A thirty-second
limit covered the whole transfer, so a fourteen-megabyte binary failed with
a deadline error on any ordinary connection. The limit now applies to
connecting, to the TLS handshake and to the first response header, where it
belongs.

**DNS over HTTPS is recovered where inspection can see it, and can be shut
off where it cannot.** A DoH request made with GET carries its question in
the URL; that question is decoded and filed in the DNS history. A new
built-in category, **encrypted-dns**, lists the public DoH endpoints along
with the canary name that makes Firefox turn DoH off by itself, so denying
that category sends a client back to the network resolver where every
lookup is visible again.

**Pinned sites are detected and relayed instead of failing.** A client that
pins its certificate refuses the inspection certificate, and the site simply
does not load. FlowSight now recognises that refusal from the shape of the
failed handshakes, stops decrypting that name and relays it untouched, so
the site works while everything else stays inspected. Detected names are
listed on the TLS page with how many times they refused and which clients
were affected, can be added and cleared by hand, and are retried after a
week in case an application stopped pinning.

**One scrollbar inside the OPNsense panel.** Tables had a fixed height and
their own scroller, which fought with the host page's scrollbar and produced
a scroll that went nowhere. Embedded tables now grow with the page.

**A refresh keeps your place.** Sort order, scroll position and how much of
a long table you had loaded now survive the automatic refresh, and there is
a pause button for reading something that keeps moving. Long tables are
paged with a "show more" control, or continuous scrolling if you prefer,
and the choice is remembered.

**An IPv6 address belongs to its device.** Addresses learned over IPv6 are
attributed to the same device as its IPv4 address rather than appearing as a
separate unknown host.

**Decrypted requests are visible as such.** The Web page shows the request
line for decrypted sessions and offers a decrypted-only view, reachable from
the TLS page by clicking the bump marker on a session.

**Issuer names are readable.** The issuer chart showed full distinguished
names, which do not fit; it now shows the organisation with the full name on
hover.

**Assets are versioned.** The interface is served under a version directory,
so a browser cannot keep yesterday's script after an update.

**FlowSight lives in the OPNsense panel, not beside it.** The extra panel is
gone, the name is spaced like every other entry in the menu, and the theme
follows the host's light or dark setting.

**Rollups are keyed to when traffic was observed**, not to when FlowSight
got round to aggregating it, so a graph no longer shows a spike where a
restart was. Chart labels are drawn as text in their own gutter rather than
inside the plot.

**The effective local networks list has no repeats.**

## 0.9.8 — 2026-09-21

**Pi-hole as a DNS source.** A module that pulls query logs from one or more
Pi-hole instances, parses them and associates each query with the device
that made it. Blocked queries appear on the host pages with the list that
blocked them and the resolver that answered.

**Hosts and Devices are explained** on the page and in the guide: a host is
an address FlowSight has seen, a device is a thing it has identified.

**Devices and Zones are two pages**, cross-linked, with reverse-lookup and
country lookup available for any address.

**Settings show the platform default** beneath an empty field, so you can
see what is in force without the value being silently written into your
configuration.

**Throughput separates inbound from outbound.**

**The manual.** Fourteen chapters covering installation, concepts, policy,
interception, configuration, the API, operations, security, licensing and
architecture, shipped as HTML, one PDF per chapter and a single merged PDF,
inside the packages.

## 0.9.4 — 2026-09-20

**Licensing.** Community, Pro and Business tiers, online activation against
a license server with signed offline license files as the fallback, and a
soft expiry that warns rather than switches features off.

## 0.9.3 — 2026-09-20

**Release pipeline.** Signed release manifests, an injectable signing key and
per-architecture package names, so the daemon can verify and install its own
updates.

## Earlier

Before 0.9.3 FlowSight was assembled rather than released: the Go daemon and
its module contract, the embedded store, identity and enrolment, DNS
visibility and enforcement, transparent interception with peek-and-splice,
the inspection CA, category feeds, firewall hygiene, alerting, reports and
the OPNsense plugin. The commit history is the record of that period.

## 0.9.8r202609260000
## 0.9.8r202609252359

**Target policies to people, not machines.** A new Users module tracks user
sessions from RADIUS accounting (FreeRADIUS, OPNsense captive portals,
compatible systems) and optional LDAP/AD group membership. Policies now
accept `user:<name>` and `usergroup:<group>` member types, so all of a
person's devices (laptop, phone, tablet) share one set of rules without
having to list every device. Session details are visible in a new Users panel
under Inventory, with source (RADIUS, manual, LDAP), addresses, and group
membership when LDAP is enabled. Manual API endpoint and captive portal
scripts can post logins via `POST /api/users/session`. LDAP/AD support is
built-in: minimal BER encoder/decoder for BindRequest/SearchRequest over
net.Dial with optional TLS and StartTLS; group membership from memberOf or
group search; local groups setting (name → list of users) for `usergroup:`
without a directory. RADIUS listener and LDAP client have no external
dependencies (net, crypto/md5, crypto/tls, encoding/binary).
## 0.9.8r202609252339

**Flow sources module was never loaded.** Its collector switch was named
`enabled`, which is the key the core reads to load or skip a module, so a
default of off switched the whole module off: no page, no routes. The
collector switch is now `collect` (default off; the listeners open only when
it is on) and the module loads like every other.
## 0.9.8r202609252331

**Extend visibility beyond the gateway with NetFlow, IPFIX, and sFlow.** A new
netflow module collects flows from switches, routers, and other devices via
UDP: NetFlow v5 (fixed format, legacy), NetFlow v9 (template-based), IPFIX
(RFC 5101 with 64-bit counters), and sFlow v5 (packet sampling). Flows are
enriched, stored, and searchable the same way as gateway-observed flows, so
east-west traffic (PC to NAS, server to workstation) and switch-mediated paths
become visible. The Sessions page filters by source; the new "Flow sources"
card shows connected exporters, record counts and last-seen times. Configure
ports, bind address, exporter CIDRs, sampling and max exporters in Settings.
Start with the how-to: [Add a switch or another router as a flow source](howto/flow-sources.md).

Also in this release: a session's recorded domain source is no longer
overwritten with "none" when a later poll of the same flow carries no name;
proxy sessions record `sni` or `http_host`; baseline findings name the
device (identity name with the MAC in brackets) and say "only" when the
baseline list is complete; the how-to index links the new guides; conflict
markers left in the docs index by a merge were removed.

## 0.9.8r202609252329

**Every name and domain carries where it came from.** Names now show their
source (DHCP lease, static reservation, device enrollment, reverse DNS, or
operator-assigned) and a confidence level (0–100%), replacing guesswork with
clarity. In the IP Addresses and Devices tables and elsewhere, a quiet mark
(superscript bullet) on a name reveals its source and confidence in the
tooltip. Sessions show which source gave the domain (SNI, HTTP Host, DNS
query, flow probe, or none) and when it comes from the probe cache, the domain
appears muted since that source may not be authoritative. Countries for
addresses likewise carry their source: GeoIP database or none.

The API includes `name_source` and `name_confidence` on `/api/identity/hosts`
and `/api/enroll/devices`, and flows include `domain_source` and
`country_source` on `/api/visibility/flows`. The UI helpers `FS.ipTag` and
`FS.hostLink` now accept optional provenance info to show marks inline.

Precedence is enforced at ingest: operator-assigned names override all others
(100% confidence); DHCP hostnames (88%) beat device table names (70%); resolver
answers (20%) never replace local addresses and never attach to loopback,
link-local or multicast. Durable-by-MAC names report their original source when
a device moves addresses. See CONCEPTS.md for the full precedence table and
USER-GUIDE.md for notes on the marks.
## 0.9.8r202609252328

**Anomaly detection: know when a device does something new.** A new Baseline
module learns each device's normal behavior (countries, ports, destinations,
activity patterns, DNS queries) over a configurable period (default: 7 days),
then flags first-seen countries, ports, and destinations; detects beaconing
(regular connections with constant payload size) and DNS tunneling (high
entropy queries with high NXDOMAIN rates); and reports anomalies with the
context ("first time 34:d2:70:98:9a:43 contacted IE; 21 days of history
had US, CA only"). Findings are acknowledgeable, filterable by zone, and
integrated with alerting rules. The Protect panel adds an Anomalies list and
a per-device Baseline profile showing what is known about each host.
## 0.9.8r202609252307

**No more "example.com" on every Cloudflare session.** With no SNI or Host
to go on, a session took the flow probe's own name for the far end, which
is whatever DNS answer the probe last saw point at that address. For an
address shared by many sites that is a coincidence: one check of example.com
from the gateway had every session to Cloudflare wearing that name. An
anycast far end now takes no cached name; the wrong rows already stored are
cleared once.

**Overview: one row per device in Top hosts.** A device's IPv4 lease and its
IPv6 addresses were separate rows; they fold into one, traffic summed, with
the IPv4 address shown and the count of other addresses beside it.
## 0.9.8r202609252300

**A route's trail stops where the story ends.** Once the destination itself
answered, nothing after it is shown; when it never answered, the trail ends
at the last hop that replied and one line says how far the probe went
without a reply, instead of fifteen silent rows. `GET /api/paths/path` adds
`reached`, `probed_to` and `last_answer`.

**Breadcrumbs follow the app inside OPNsense.** The app runs in a frame in
the OPNsense page, whose breadcrumb, title and address only knew the page it
was opened on. The app now reports every route change to the page around
it, which updates the breadcrumb (group and page), the tab title and the
address (`flowsight.php?page=<route>`), so a reload lands on the same page
with the same route or filter. The plugin page also names pages by their
menu titles before the app loads. The plugin page file must be updated on
the gateway for this part.

## 0.9.8r202609252254

**Report runs no longer panic on a long PDF.** The built-in PDF writer kept
room for ten objects, so a report of more than four pages crashed the run
(`index out of range`), and what it wrote for shorter ones had a broken
cross-reference table and nested text objects. Rewritten: any number of
pages, a correct xref, one text block per line, lines wrapped to the page.

## 0.9.8r202609252251

**Loopback is never named after a blocked domain.** A blocklist that answers
127.0.0.1 for a domain had the resolver-name path calling the gateway's
loopback address by that domain (it showed as "myworkdayjobs.com" in the DNS
log and the address list). Loopback, unspecified, link-local and multicast
addresses now take no resolver name; loopback reads *this gateway
(loopback)*; the stored rows were cleared.

**Alerting page loads again.** The deliveries route returned a map by
channel where the page expected a list; it now returns a flat list newest
first with the map beside it, and the page accepts either. A malformed rule
record with no id or name (left by a save that used the wrong verb) is
dropped, rule updates require a name, and the page uses PUT and DELETE for
update and delete as the API defines them.

**Report PDFs contain the report.** The PDF had been a title page. It is now
the Markdown rendering set on pages (headings, paragraphs, tables) and is
written with the other formats when a run completes.

**Audit log: who, via what, and what.** Writes made through the OPNsense
plugin now record the GUI user with the token in brackets instead of the
bare word "token". `api_tokens` in the configuration adds named tokens
(`token:<name>` in the log). Each entry carries `via` (gui, token, session,
local) and, where the body says, the module, name or id it touched; the
Audit page shows Who, Via, From and the operation with those details.
## 0.9.8r202609252242

**Withdraws 0.9.8r202609252231**, which never reached a gateway: its
country-name table broke on the apostrophe in Côte d'Ivoire and the
interface script would not have parsed. The table is now emitted as JSON,
and the release chain stops on a failed interface check instead of tagging.

## 0.9.8r202609252214

**Duplicates removed after a from-the-start read too**, not only at start:
the first read of a build with no saved position happens after the start-up
sweep and had re-inserted the copies it was meant to remove.

## 0.9.8r202609252213

**The filter-log reader keeps its place across restarts.** It re-read the
file from the start after a restart and recorded every match twice. The
position is now saved with the database, a rotated file is read from its
start, and the copies already recorded are removed once at start.

## 0.9.8r202609252212

**Logged matches always carry a country.** A destination the session table
never recorded (a lone NTP query, for instance) showed no country on the
Policy matches page; the country database now answers for it.

## 0.9.8r202609252211

**The filter-log reader found nothing.** OPNsense's filterlog names the leaf
anchor (`policy`), not the full path (`flowsight/policy`), so every line
was skipped. The reader now accepts either, and the test uses a line as the
gateway really writes it.

## 0.9.8r202609252209

**Map: clicking a hop filters to the devices behind it.** The *Device*
filter follows the click: the devices whose traffic reached any destination
routed through the hop become the filter (one selects itself; several show
as *N devices through the clicked hop*), so the map narrows to what those
devices did. `GET /api/paths/who?dsts=` answers the question and the
graph's `device` parameter now takes a comma-separated list.

**Filter-log diagnostics.** `GET /api/firewall/hits?debug=1` returns the
log's last lines, the lines mentioning FlowSight, and the anchor's rule
numbering, for when the reader finds nothing and the counters say it should.

## 0.9.8r202609252205

**Where a country rule's packets go, and from which device.** *Protect ›
Policies* gains a **Matches** button on every policy with a country rule,
opening a page with two views. *By device: where the traffic went* comes
from the session table, computed the way the rule is compiled (members
after exclusions, denied countries, anycast left out): each device, its
sessions and bytes, and the destinations behind it with domain, country,
port and application, last seen and a Map button. *Logged by the firewall
rule* is pf's own record: the firewall module now reads OPNsense's filter
log every ten seconds, keeps the lines from FlowSight's policy anchor, maps
rule numbers back to labels, and stores them for seven days
(`GET /api/firewall/hits`; `GET /api/policy/matches` returns both views).
Setting `filter_log` names the log. The rule rows in the *Firewall tables
and rules* card link to the same page.

## 0.9.8r202609252156

**Overview showed raw link tags.** The *Top applications* and *Top sites*
subtitles name the hosts behind each entry as links; the bar renderer
escaped them, so the tags appeared as text. The renderer now takes an HTML
subtitle for that purpose, and an interface check renders the Overview and
fails on escaped tags. The parse check now covers every script the UI ships.

## 0.9.8r202609252154

**Policies, Categories and Groups & Schedules were blank since 0.9.8r202609252049.**
A merge left a real line break inside a quoted string in the script that
holds those three pages, so the file failed to parse and none of them
registered. Fixed, and the interface checks now parse every script the UI
loads, so a broken file fails the build instead of the page.

## 0.9.8r202609252144

**Kernel address count, second attempt.** For a table inside an anchor,
`pfctl -vvsT` prints the anchor path as a third column, and the parser had
taken the last column as the table name. `GET /api/firewall/table` also
accepts `debug=1` to return the raw pfctl listing.

## 0.9.8r202609252138

**Country tables are remembered across a restart.** The tables live on in
pf when the daemon restarts, but the record of what filled them did not, so
the Policies card and `geo_tables` were empty for up to an hour and the next
check refilled a full table for nothing. The fill record is now kept in
`pf/geo-tables.json`; half a minute after start the tables are checked
against the kernel and the database build and refilled only when either
moved (an emptied kernel table is refilled).

## 0.9.8r202609252128

**The kernel address count read zero.** `pfctl -v -sT` prints flags and
names only; the per-table statistics need `-vv`. The *In kernel* column on
the Policies page and `kernel_addresses` in the API now show the real
figure (a membership test had already proved the table full).

## 0.9.8r202609252118

**Country tables, proven from the kernel.** The first live country policy
(monitor mode, `zone:iot`, every country except the home one) filled its
table with 1.07 million prefixes in about three minutes, 14 thousand
anycast ranges left out. To see that from the UI rather than take it on
trust, the Policies page gains a **Firewall tables and rules** card: each
table with prefixes built and what pf reports holding, the anchor's rules
with their live counters, and a box that asks the kernel whether an address
is in a table (`GET /api/firewall/table?name=&ip=`).

**`zone:<id>` now means the zone's devices too.** A zone member used to
resolve to the zone's subnet alone, so devices filed under IoT while still
holding a lease elsewhere, and every device's IPv6 addresses, fell outside
the rule (pf had inferred `inet`). It now resolves to the subnet plus every
device assigned to the zone in both address families. The home country is
no longer listed twice on an except-table.

## 0.9.8r202609252110

**A policy whose members are all excluded now says so.** The IoT subnet on
the live gateway is in the exclusions list to keep it out of web
interception, and exclusions beat everything, so a country policy on
`zone:iot` compiled to nothing without a word. The plan now carries a
warning per policy (`warning`, `excluded` beside `members`), the Policies
page shows *all members excluded*, and the Who tab gains **Apply even to
hosts in the exclusions list**: with it the firewall and DNS rules reach
excluded members; interception still never does. Documented in POLICY.md.

## 0.9.8r202609252100

**Anycast is understood everywhere a country is shown or enforced.** Every
session now carries an `anycast` flag beside its country, set at ingest from
the paths module's anycast knowledge (the University of Twente / CAIDA
census, the vendors' published lists, the public resolvers and root
servers) and back-filled over the last seven days. Sessions shows an
*anycast* pill and an `anycast=1` filter; "Outside the country" and the DLP
*Leaving the country* card never count anycast far ends as abroad and list
them in their own *Via anycast* column; country tables in the firewall leave
anycast ranges out (and MaxMind's `is_anycast` trait when the database has
it), reporting how many were skipped. The Map already placed anycast hops at
the nearest census site; nothing changed there.

**Country lists and tables no longer walk the city database.** The
countries route answered in minutes on the gateway because it decoded city
names for every network; it now answers at once from the ISO 3166 table,
with prefix counts filled in by a background pass, and firewall tables are
built from the small country-level database (fetched alongside the city one
when needed) in the background after apply. `geo_filling` in the firewall
status says when a fill is running.

**DLP: *By destination* is clickable.** Each kind (cloud storage, webmail,
tunnels, unnamed, …) opens the connections of that kind; the connections
card says which kind it is showing and offers the way back.

## 0.9.8r202609252049

**Block traffic by country.** Policies gain `deny.countries` (deny the
listed countries) and `deny.countries_except` (deny every country but the
listed ones; the gateway's own country is always allowed). The firewall
provider declares one persistent pf table per denied country, or one per
except-policy, in the `flowsight/policy` anchor and fills it in a single pass
over the local country database; both address families are covered. An
hourly check rebuilds tables after the monthly database refresh and a
restarted daemon refills them once. The policy editor has a *Countries* tab
with a searchable list from `GET /api/enrich/countries` (English names from
the database) and an *except* switch. `GET /api/firewall/status` lists the
tables under `geo_tables`. DLP's **Block…** now pre-fills the device by MAC
address, and the "outside the country" device list folds a device's v4 and
v6 addresses into one row. Documented in POLICY.md and the IoT HOWTO.

## 0.9.8r202609252040

**Sessions carry the far end's country.** The flow probe never reported
one and the proxy log cannot, so every session had an empty country and the
new abroad views were empty. Sessions are now stamped at ingest from the
local country database (both the probe's flows and the proxy's), and a quiet
background pass fills in the last seven days a few hundred rows a minute.

## 0.9.8r202609252038

**What leaves the country, per device.** Sessions now filter by the far
end's country (`country=`) or by *Outside \<home\>* (`abroad=1`), where home
is the country of the gateway's own public address; the server column shows
the country as a pill that narrows the list. The DLP page has a *Leaving the
country* card: per device, the foreign countries it reached with sessions
and bytes, the destinations behind them, and a *Block* button that opens the
policy editor pre-filled. The host page links to a device's foreign sessions.
`GET /api/visibility/abroad` serves the per-device data. A how-to,
`docs/HOWTO-IOT-ABROAD.md`, walks through seeing and blocking IoT traffic to
other countries end to end.

## 0.9.8r202609252021

**Alerting system complete: 54+ notification channels, flexible rules engine, delivery guarantees.**

New in alerting:

- **54+ notification channels** grouped by family: 11 chat (Slack, Discord, Teams, Telegram, Mattermost, etc), 5 email (SMTP, SendGrid, Mailgun, SES, Postmark), 7 SMS/voice (Twilio, Vonage, Telnyx, AWS SNS, etc), 8 incident management (PagerDuty, Opsgenie, Splunk On-Call, Squadcast, etc), 14 SIEM/logging (Splunk HEC, Elastic, Datadog, Loki, Sentinel, etc), and 3 generic (Webhook, MQTT, RSS).
- **Rules engine**: Match alerts by severity (info/low/medium/high/critical), module, category, device IP/MAC, or zone. Route to one or more channels. Cooldown to prevent alert fatigue. Digest bundling for low-severity alerts (periodic summaries). Escalation to additional channels if unacknowledged after N minutes. Quiet hours per channel.
- **Delivery engine**: Retry with exponential backoff (3 attempts, up to 2s delay). Rate limiting per (channel, alert_key). Deduplication within 10-minute window. Delivery log with status, latency, errors.
- **Maintenance mode**: Suppress all alerts during maintenance windows.
- **Channel setup wizard**: Dynamic schema forms grouped by family. Test message to verify connectivity before enabling.
- **Formatter library**: PlainText, SMS (160-char with link), JSON, Slack Block Kit, Teams Adaptive Cards, CEF, LEEF, Go templates.
- **Signature & encryption**: HMAC-SHA256 for webhooks. AWS SigV4 for AWS services. Credentials encrypted at rest.
- **New API routes**: GET/POST/PUT/DELETE for channels and rules, delivery log, maintenance, simulation, RSS feed, Apprise import.
- **Documentation**: USER-GUIDE with per-channel setup table. API reference. CONFIGURATION with schema and examples. SECURITY covering credential handling, outbound connections, no-exec guarantee.
- **Tests**: 26 tests covering formatters (PlainText, SMS, JSON, Slack, Teams, CEF, LEEF, Template), delivery engine (retry, rate limit, dedup, logging), rules engine (matching, digest, escalation, ack prevention).

Breaking change: Legacy rule format (Rule struct) is deprecated in favor of RuleConfig. Old rules still work via fallback; migrate via the UI or API.

Upgrade steps:
1. Channels created in the old system (email, webhook, discord, slack, ntfy) remain and work unchanged.
2. Rules created in the old system (map[string]Rule) remain and evaluate; new RuleConfig takes precedence if both exist.
3. Create new channels and rules via the updated Alerting page to use full feature set (digest, escalation, quiet hours).
4. RSS feed and Apprise import are not yet wired into CLI; use the UI.

## 0.9.8r202609252010

**Reporting engine with 15+ sections, multi-format output, and scheduling.**
Reports are custom, reusable definitions that select from 15 section types
(Executive Summary, Traffic by Zone/App/Category/Site, Blocked Activity,
Egress Activity & DLP, DNS Summary, TLS Posture, Scan Findings, Device
Inventory, Alerting Deliveries, System Health, Security Alerts). Each
section honors filters (IP, app, category, domain, verdict, severity) and
group_by (device, zone, app, category, site, hour, day) with top_n limiting.
Reports are output to HTML, PDF, Markdown, JSON, or CSV; multi-format reports
are stored separately. Built-in definitions (Daily Digest, Weekly Household,
Monthly Executive) are read-only but duplicable. Scheduled delivery runs
hourly, daily, weekly, or monthly at a specified time (UTC or local timezone)
through alerting channels (email, Discord, Slack, ntfy, webhooks). Retention
is configurable per definition (keep_runs, default 10) and globally (max_total_mb,
default 500 MB) with oldest runs pruned automatically. Runs are stored on disk
and indexed in KV for efficient access. Report downloads require the same
authentication as all API calls. The Reports page has a definition builder,
run history with format-specific downloads, and preview in-browser.

## 0.9.8r202609252008

**The state table is read as pf prints it.** The first live pass of Packet
Inspection showed sequence numbers where protocols should be: the parser
had been written against an invented one-line format, while `pfctl -ss -vv`
prints each state as a header line followed by indented detail lines. The
parser now reads that format (interface, protocol, addresses with NAT and
IPv6 forms, direction, state pair, age, expiry, packets, bytes, rule) and
is tested against a realistic sample.

## 0.9.8r202609252005

**Packet Inspection module.** The new **Packet Inspection** page (Protect group)
provides two packet analysis views:

- **Stateful Packet Inspection (SPI):** Real-time view of the firewall's pf
  state table: every active TCP, UDP and ICMP flow, state, age, packet/byte
  counts and rule attribution. Polled every 30 seconds (configurable). Anomaly
  detection flags SYN floods and port scans as findings. No capture overhead:
  reads state counters the kernel already keeps.

- **Deep Packet Inspection (DPI):** Managed `tcpdump` capture with post-capture
  analysis. Record traffic on any interface with optional BPF filtering
  (presets: DNS, HTTPS, HTTP, ARP, no local-to-local); hard caps on duration
  (10 min), file count (5) and total size (100 MB). Analysis extracts:
  per-conversation 5-tuples with TCP flags, retransmissions, RTT estimate;
  protocol counts; DNS queries/answers; TLS ClientHello SNI + JA3 fingerprint +
  server certificates; HTTP request lines/Host/User-Agent (plaintext); DHCP
  options; ARP pairs; ICMP types; expert notes (retransmission, zero window,
  reset, port reuse, ARP conflict, DNS no-query); top talkers; protocol
  hierarchy chart. Download pcap for Wireshark. Default 96-byte snaplen
  (headers only, privacy-safe); 65535 bytes available if payload capture is
  allowed in settings (contains sensitive data).

- **Live mode (experimental):** Stream raw packet summaries for 30 seconds, one-line
  format, no stored pcap.

Settings: state aggregation cap (20k, default), poll interval, SYN flood and port
scan thresholds, snaplen, max capture duration, file rotation, payload permission,
state age threshold. All capture files are root-only. BPF filters are validated
before capture (length, character set, compilation).

Route options: `/api/inspect/states`, `/api/inspect/states/summary`, `/api/inspect/rules`,
`/api/inspect/capture/start`, `{/stop, /captures, /{id}, /{id}/conversations,
/{id}/dns, /{id}/tls, /{id}/http, /{id}/expert, /{id}/download}`, `/api/inspect/live`.
Tab *States* on the page with state filters and half-open counter. Tab *Capture*
with form and analysis view (protocol chart, conversations, DNS, TLS, HTTP, expert
notes, top talkers). Tab *Live* with streaming pane.

## 0.9.8r202609252004

**The setup wizard is actually linked in.** The module registered itself
but was never imported into the binary, so its page and routes were absent
from the previous release. Fixed.

## 0.9.8r202609252003

**Setup wizard.** A new 12-step guided wizard under **Administration › Setup
wizard** walks new installations through essential configuration: license (optional),
site basics, traffic source (ntopng), DNS source (Pi-hole or Unbound), web
interception, identity zones, security (IDS, TLS probing), inventory (Proxmox),
alerting, updates, API access, and a review step. The wizard auto-detects platform
facts (interfaces, installed binaries, license tier), discovers services on the
subnet (Pi-hole, Proxmox), tests connectivity, and applies settings via the
existing module configuration system. Progress is kept server-side so refreshing
resumes. The Overview shows a banner until the wizard is completed or dismissed.
Never touches firewall rules, SSH or the GUI listener.

API: `/api/setup/state` (detector facts), `/api/setup/apply` (save step),
`/api/setup/test` (test connectivity), `/api/setup/reset` (start over).

## 0.9.8r202609252000

**No inline scripts anywhere.** Every inline event handler in the web pages
(the modal Close buttons, the whole Proxmox page) is gone, replaced by
data attributes and delegated listeners, and a test fails the build if one
comes back. The OPNsense page now serves the app under a Content-Security-
Policy whose script source is the app's own files plus a per-response nonce
for the boot values, with `unsafe-inline` removed for scripts; the daemon's
own page was already strict. Plugin page file and static files.

## 0.9.8r202609251958

**Security review, first fixes.** A code review of FlowSight found that
saving a module's settings echoed newly written secrets back in the reply;
the reply now masks secret fields exactly as the listing does. Login
sessions are pruned on every login and the table is capped, so a flood of
logins cannot grow memory. The updater refuses a manifest URL over plain
http unless the host is private or loopback (an operator's own relay), so a
network attacker cannot choose which signed build the daemon sees; the
signature check on every asset stands as before. Text that came from
devices is escaped before it enters a guest's Proxmox Notes, so a hostname
cannot break the table, inject HTML or forge the block markers. The
review's report and the remaining items (inline script handlers in the
web pages, to allow a stricter Content-Security-Policy) are being worked.

## 0.9.8r202609251946

**Four pages renamed.** *Data out* is now **DLP**; *Deep inspection* is now
**Stateful Packet Inspection**; *Firewall hygiene* is now **Firewall Analysis
Engine (FAE)**; *Groups & schedules* is now **Groups & Schedules**. Page
addresses and settings keys are unchanged, so bookmarks and configuration
keep working; the OPNsense menu picks up the new labels when the plugin's
menu file is updated.

## 0.9.8r202609251941

**One device, not one address.** The "who did it" lists counted a laptop's
IPv4 lease and each of its rotating IPv6 addresses as separate hosts, so
one MacBook filled all three places. Hosts fold into devices by hardware
address before ranking, and the host count is a device count.

## 0.9.8r202609251939

**Activity, not volume; and who did it.** Applications, top sites and
categories were ranked by bytes moved, which made one backup the story of
the day. They now rank by sessions, and every row says which hosts did it:
the count of hosts and the three most active, named and linked (to the host,
or straight to that host's sessions of that application), plus when it was
last seen. Bytes stay as an aside. This applies to the Overview's top
hosts, applications, categories and sites, the Applications page (with its
by-category chart) and the host page's application and site cards.
`/api/visibility/top` and `/api/visibility/apps` carry `hosts`, `last_seen`
and `top_hosts`.

## 0.9.8r202609251931

**Notes write-back, whole.** The block written into a guest's Proxmox Notes
now carries what FlowSight knows: its name, class and zone, addresses and
hardware addresses, maker, OS from the agent, what Identify found (with
open ports), traffic in the last day, first and last seen, agent state and
a link back to the host page (set *FlowSight URL* under Settings \u203a
proxmox). *Write* with no guest writes every eligible guest in the
background, and every poll rewrites only the guests whose facts changed;
the status card counts written, skipped and failed. Containers now carry
their node name, and Proxmox tags separated by semicolons are read as
separate tags, so `flowsight:off` works.

## 0.9.8r202609251924

**The Proxmox map no longer holds up the Devices page.** The map held the
module's lock for the whole of its queries, and every Devices row and host
page asks the module for its guest, so a slow map froze those pages. The
map now works on a copy of the inventory and reports per-stage timings
(`timings` in the response, and a warning in the log when a page takes
over five seconds).

## 0.9.8r202609251918

**Guest-agent answers read through the API's wrapper.** The live API wraps
every answer in a `data` object; the guest-agent parsers were written
against unwrapped captures, so every VM read as "agent not responding".
Both shapes are read now. The map computed each guest's external
dependencies with its own scan of the day's rollup, 57 scans per page load;
it now runs the one query and hands each guest its share.

## 0.9.8r202609251912

**VMs get their addresses; the Proxmox map answers.** Proxmox 9 sends a
VM's memory as a string, which a strict number field rejected, so every VM's
config was unreadable and no VM had addresses or agent facts; the config is
now read loosely. The Devices and host pages asked for the Proxmox service
under a name it was not published as; it is published under both. The
map's traffic query aggregated the whole destination rollup and timed out;
it now asks only for rows whose destination is a guest address, through
the index. The OSM telecom source counts its regions on disk from start-up
instead of showing zero until the first job run.

## 0.9.8r202609251908

**Proxmox reads what the API actually sends.** Against the live node the
first poll listed 57 guests with no addresses: container interfaces carry
addresses as `ip-addresses[].ip-address`, the guest agent reports the
family as `inet`/`inet6`, and the map's traffic queries named columns the
rollup table does not have. All three are fixed against the captured
responses, with tests. Guest-agent facts also need the `VM.GuestAgent.Audit`
privilege on Proxmox 8 and 9; the configuration guide's role now includes
it.

## 0.9.8r202609251903

**Proxmox status no longer hangs after the first poll.** The optional
socket probe was called while the inventory lock was held and took the
lock again, so the first poll deadlocked the module and its status and
inventory calls never answered. The probe now runs before the lock; a test
guards the swap.

**Identify on the zone screens.** The Zones page lists the devices without
a zone under *Unidentified* with an *Identify* button each, and the
per-zone device table has the button too, so a bare hardware address can be
probed and named where you meet it.

## 0.9.8r202609251853

**Token read from the right place.** The OPNsense page looked for the API
token under a `core` section of the daemon's config; the daemon's own keys
(`bind`, `port`, `api_token`) are top-level. Plugin file only.

## 0.9.8r202609251808

**The GUI keeps working when the API gets a token.** Setting `api_token`
in the daemon's config (to reach the API from the LAN as well as through
the OPNsense page) used to lock out the page itself, because the daemon
stops trusting the loopback proxy once a token exists. The page now reads
the token from the daemon's own config file and presents it. Plugin file
only; no daemon change.

## 0.9.8r202609251643

**Proxmox: the hypervisors join the inventory.** A new *Proxmox* page under
Inventory. With a least-privilege API token, FlowSight polls each node for
its health and every VM and container: configuration, status, hardware
addresses, and what the QEMU guest agent reports (addresses, operating
system, hostname). Guests' addresses gain their names, maker and OS in
FlowSight, and the Devices and host pages show node, type, VM ID and guest
name. With *write notes* on, each guest's Notes in Proxmox carries a
FlowSight block between markers (name, class, zone, addresses, traffic,
scan results, link back), rewritten only when it changes and never
overwriting your own text. The *Map* tab draws how guests talk to each
other: observed traffic from the gateway, declared relationships from the
configuration (startup order, storage, bridges), and, opt-in, what each VM
reports from the inside through one fixed `ss` command via the guest
agent; click a guest for its requirements, export as JSON or Markdown.
Connections to Proxmox are never unverified: the certificate fingerprint
is pinned or the system roots are used.

## 0.9.8r202609251624

**Cards go where you put them.** Every card on every page can be dragged
by its heading to a new place among its neighbours; the arrangement is kept
per page in the browser and survives refreshes. The grip on each heading
opens a menu to move a card without dragging, to save the page's current
arrangement as its default, to reset to that default, or to forget it and
return to the built-in order. A *Reset layout* button shows in the header
while a page differs from its default.

## 0.9.8r202609251615

**A session's path, one click away.** Every row on the Sessions page with
an internet destination has a *Map* button that opens the Map narrowed to
that session: the client device and the traceroute to that destination,
nothing else. Local-to-local sessions have no button.

## 0.9.8r202609251610

**The public fallback keeps the public pace.** The first fast pass against
a private Overpass fetched seven Arctic regions in ten seconds, each empty
locally, each falling through to the public service, until the public
service answered 429 and the whole job backed off for six hours, local
fetching included. The public service is now asked at most once per run
when it is only the fallback, and its refusal backs off the public service
alone; regions keep coming from the private server. The sources card says
when the public fallback is resting.

## 0.9.8r202609251547

**A private Overpass fills the map in hours and never pretends.** With your
own Overpass configured (a private address and *osm_overpass_local* on),
the telecom-line job now asks it up to twelve regions per run instead of
one every twenty minutes, since it is yours to load. A region the private
server returns nothing for is asked of the public service, because a
server holding only the extracts you loaded (North America and Europe here)
says nothing about the rest of the world. The public service keeps its
one-region-per-run pace.

## 0.9.8r202609250020

**Space: your rooms, your devices, in 3D.** A new *Space* page under
Inventory. Scan the flat with a phone app (Polycam or Scaniverse on iPhone
and Android, or a RoomPlan-based app), export GLB, OBJ, PLY or the RoomPlan
JSON, upload it, level it on three floor points, draw or import the floor
plan (the building footprint comes from OpenStreetMap for the address),
calibrate the scale, and drag devices from the palette onto the surfaces
where they really are. The viewer is hand-written WebGL2 with no third-party
code; placements are saved per device with the room they fall in and link
back to the host page. Records for the address (US Census geocode, USGS
elevation, OSM footprint, broadband at the state level) sit alongside.
Uploads are size-capped and stored under the data directory. Settings:
address, coordinates, floor height, units. Routes under `/api/space/`.

**Space: full end-to-end 3D layout and placement.** Five new features complete
the Space module's core functionality. (1) **Marker interaction in 3D:** Click
a placed device marker to see a popover with name, vendor, MAC, room, placement
date, and a 60-point visibility sparkline. An Unplace button removes it. Drag
markers to reposition them (wheel to adjust z). Highlight a device in the Palette
to fly the camera to it. (2) **Calibration tools:** Level the scan by clicking
three floor points; the tool fits a plane and stores the rotation and z offset.
Align the scan to your plan by picking two 3D points and two plan points; the
tool computes scale, rotation, and offset. (3) **Plan editor completeness:** Drag
vertices to edit room polygons in real time. Click a room to select it; Rename
and Delete buttons appear. Undo and Redo work for all operations (drawing, scaling,
importing, room edits, placement moves); an unsaved indicator shows when the layout
has pending changes. Placement dots on the plan are draggable. (4) **Mobile layout:**
At viewports ≤768px, the three panes become tabs (3D, Plan, Devices) with smooth
switching. Network errors show as auto-dismissing toasts. (5) **3D multi-floor
view:** Rooms from all floors are shown as extruded boxes; the current floor's
rooms are opaque, others faint to show context. The docs now include a walkthrough:
scan your space with LiDAR Scanner (iOS) or 3D Scanner App (Android), upload the
GLB file, level the floor, draw rooms or import from OSM, calibrate scale, and
place devices. All 42 space tests pass (15 calibration, 8 parser, 19 reducer).

**Space: scan loading and device placement now work end-to-end.** Upload a scan
(GLB, OBJ, PLY, RoomPlan JSON) via the **⬆ Scan** button; the viewer loads it,
applies any stored transform (scale, rotation, offset, Y-up/Z-up conversion),
and shows a progress bar during parsing. Drag devices from the Palette pane onto
the 3D canvas to place them; the viewer ray-casts the click to find the surface
hit point, auto-detects the room from polygon containment, and saves the placement.
The Plan pane's polygon editor now works: draw rooms (click vertices, double-click
to close), pan and zoom with mouse, set scale by two points, import OSM footprints.
Rooms are saved live. Undo/redo work for draw mode. All tests pass. See docs/USER-GUIDE.md
for what's implemented and what still needs to be done.

**Space: WebGL2 3D viewer and interactive device placement.** The 3D pane now
renders scans with full WebGL2 support, orbit/pan/zoom camera with mouse and
touch, floor grid and RGB axes. Large scans (500k+ triangles) are handled
efficiently with spatial indexing. Ray-cast from screen coordinates to place
devices on any surface; click a marker to see its room assignment (from
polygon containment), vendor, addresses, and live traffic sparkline. Level
the scan with three floor points to define z=0 and up-axis. Smooth normals
are computed for scans that lack them.

**Space module: physical space mapping and 3D device placement.** A new Space
panel in Inventory allows you to draw your living space, upload a scan from
your phone (GLB, OBJ, PLY, or RoomPlan JSON), and place each device at its
real location in 3D. The module integrates address geocoding via US Census,
building footprints from OpenStreetMap, elevation from USGS, and broadband
provider data when available. Three panes: Plan (2D room editor with OSM import),
3D viewer with scan mesh and interactive device placement, and Palette for
device search and filtering.

## 0.9.8r202609250004

**Identify names the device, not just the ports.** The first run against an
Amazon speaker found 145 filtered ports and said nothing, because the
speaker's only open ports (55442/55443, Alexa's local control) are not in
the top hundred and nothing put the answers next to what the inventory
knew. The identify profile now also scans the consumer and appliance ports
(Alexa, Cast, Roku, Sonos, AirPlay, Kasa, Tuya, Plex, Home Assistant,
Proxmox, printers, consoles), and a signature engine ranks what the device
is from the open-port shapes, the maker behind the hardware address, the
DHCP fingerprint and vendor class, the name it gave itself, mDNS model
strings, the reply TTL and the banners, each guess with its evidence. The
saved result now carries its finish time.

## 0.9.8r202609242356

**The scan switch is its own switch.** The scan module's on/off setting was
called `enabled`, which is also the name every module's load switch goes
by, so turning scanning off would have unloaded the module and its page on
the next restart, and the status card read the setting only once. The
setting is now `scanning` (*Allow active scanning*), read live, and the
status card agrees with it.

## 0.9.8r202609242353

**Scan: what a device is, from the inside.** A new *Scan* page under
Inventory, off by default, probes local addresses only: ICMP for the TTL, a
TCP connect scan of the top 100 or 1,000 ports, identity probes over UDP
(mDNS, SSDP, SNMP, NetBIOS, DNS, NTP), banners on what answers (SSH, HTTP
and its title, TLS certificate names, mail, RDP, SMB), and an operating
system guess with its evidence. When nmap is installed on the gateway it is
used as well (`-sV -O --osscan-guess`) and its service versions win; FlowSight
never installs it. Every Devices row and every host page has an *Identify*
button that runs the fast profile (under about ninety seconds) and shows the
result: OS guess, open ports and services, notable findings such as telnet or
RDP exposed. Scans are rate-limited, refuse anything outside the local
networks, are logged as events, and can trip host firewalls or the IDS.
Settings: enabled, parallelism, port set, nmap use, scheduled sweep and its
window, packet rate. Routes under `/api/scan/`.

## 0.9.8r202609242345

**Second-hand names stay second-hand.** Pi-hole's client names come from its
own reverse lookups and go stale when a lease moves; FlowSight imported
them whenever it had no name of its own, which put a laptop's name back on
an Amazon speaker every few minutes after the wrong name had been cleared.
A Pi-hole name that is some other device's own name (its lease hostname or
a chosen name) is no longer imported. The enrich module no longer does
reverse DNS for local addresses at all: identity names those, and a reverse
record is at best the same name and at worst the previous holder's. Both
the name and the address in a host link now open the host page.

**Complete CRUD API for all configuration.** Every policy, group, schedule,
zone, device, notification channel, alert rule, QoS rule, category, name override,
and pinned TLS name can now be created, read, updated, and deleted via the API.
New endpoints added for policy (groups, schedules), enrollment (zones, devices),
alerting (channels, rules), QoS (rules), categories, identity (name overrides),
and web (pinned TLS names).

**API endpoints now accept `{param}` in paths.** Routes like `/api/policy/groups/{name}`
resolve parameters from the request path; the pattern is matched against the request
and available in handlers, enabling granular resource manipulation.

**Interactive OpenAPI explorer at the API page.** Operations are grouped by the four
menu areas (Monitor, Inventory, Protect, Administration), with parameter templates,
live request/response, and copy-as-curl for easy testing.

**The menu has four areas.** Twenty-five pages in one flat list became
four groups by what you are doing: *Monitor* (Overview, Sessions,
Applications, Web, DNS, Map), *Inventory* (IP Addresses, Devices, Zones),
*Protect* (Policies, Priority, Groups & schedules, Categories, Deep
inspection, TLS, Threats, Data out, Firewall hygiene) and *Administration*
(Reports, Alerting, API, Updates, License, Status, Settings). The OPNsense
menu nests the same way, and the in-product sidebar follows. Page addresses
are unchanged, so bookmarks keep working.

**Hosts is now IP Addresses.** The page lists addresses, so it says so; the
address is the row and the device it belongs to reads under it, with a
*Device* column to sort by. The one-row-per-device checkbox still folds a
device's addresses together.

**Complete OpenAPI documentation and interactive API explorer.** Every API route
now has proper OpenAPI tags organized into four areas: Monitor (visibility, hosts,
flows, applications, web, DNS, map, data out), Inventory (devices, zones),
Protect (policy, QoS, categories, TLS, threats, firewall), and Administration
(reports, alerts, updates, license, API). The in-product API explorer at the API
page (Administration group) provides grouped operations, request/response templates,
live testing, and curl export. All 122+ routes emit proper operationIds and are
downloadable as an OpenAPI 3.0 JSON specification.

## 0.9.8r202609242333

**Traffic totals were inflated, badly.** The flow probe reports a cumulative
byte count per flow and a percentage split by direction; as the split
shifted, one direction could read lower than last time while the flow grew,
and that was taken for a counter reset, crediting the whole cumulative total
again. A long-lived WireGuard tunnel was booked at 900 GB an hour on a link
that moved 74 GB. Growth is now judged on the total and split by the current
mix, for the rollups and the per-host counters alike. Separately, every
proxied transfer was counted twice: live by the probe and again from the
proxy log when it completed; proxy lines still count as requests, with their
verdict and domain, but add no bytes. Historic rollups keep the old numbers;
they age out with retention.

**The window says where the history starts.** With six days of records, 7d
and 30d showed the same thing and looked broken. The range bar now shows
*since <date>* whenever the window reaches back past the oldest record
(`data_since` on `/api/system/info`).

**Hosts, one row per device.** A checkbox beside the count folds every
address behind the same hardware address into one row, traffic summed and
the other addresses listed under the name, so a laptop with an IPv4 lease
and five IPv6 addresses sorts as one host. Addresses with no known device
stay their own rows. The choice is remembered.

## 0.9.8r202609242323

**The echo is cleared from every address of the device.** The name a
device-table echo left on a device's IPv6 rows came back through the durable
name memory; those rows are cleared with the leased address.

## 0.9.8r202609242321

**A lease is authoritative for its address.** The device table learned its
names from the hosts table, and the hosts table took names from the device
table, so a name wrongly attached once (an Amazon speaker called after a
laptop) circulated for ever even after its source was gone. The device table
now names only addresses no lease covers, and a leased address that nothing
names any more has the echoed name cleared from its hosts row. Names come
back with the device's next lease or DHCP request.

## 0.9.8r202609242319

**Devices tells the truth about names and addresses.** Three faults fed the
Devices page wrong rows. The enrolment record kept the first address and
name it ever saw for a device, so a vacuum stayed at the address a phone
had taken over; a record now follows its newest sighting, and an address
seen behind one device is cleared from every other. Local addresses were
named from resolver answers, so a stale record in the local DNS named an
Amazon speaker after a laptop; resolver answers now name only far ends, and
rows carrying such a name with nothing live to back it are cleared once.
The address memory added in 0.9.8r202609241733 let an address that changed
hands carry the new holder's name to the old holder's hardware address; the
live tables now win, and a name attaches only to the hardware address the
live tables put behind the address.

**Devices shows what each device does and whether it is inspected.** A
*Services* column lists the applications a device used in the last day and
the ports other local hosts connected to on it, with how many came (`GET
/api/enroll/services`). A device on the policy's exclusion list is marked
*not inspected*, naming the entry that excludes it (`excluded` and
`excluded_by` on `/api/enroll/devices`), and the Devices count says how many
are excluded. The IPv6 address is shown under the IPv4 one. A device with a
private (randomised) hardware address, which has no registered maker, is
named by its DHCP fingerprint, vendor class or hostname: *Apple (private
address)* and the like.

## 0.9.8r202609242257

**The FCC release's catalogue is kept and browsable.** After a successful
check the file list is stored and `GET /api/paths/fcc/files?filter=` shows
it, so the state summaries can be chosen from what the release actually
offers rather than guessed.

## 0.9.8r202609242252

**A place for FCC broadband-map credentials.** *Settings › paths › FCC
broadband map* takes the National Broadband Map account's username and API
token (free at broadbandmap.fcc.gov; the field's help says where). With
them, FlowSight checks in monthly for the current release and its file list,
shows both on the *Data sources* card with a *Check FCC access* button, and
is ready for the state-level provider summaries once the account is
confirmed. The per-location files are tens of gigabytes and will not be
pulled onto a gateway.

## 0.9.8r202609242244

**A private Overpass on this network is allowed, explicitly.** Every URL
the daemon fetches must be a public host, so it can never be turned into a
way into the network it protects. An Overpass instance you run beside the
gateway is the one sensible exception: *My Overpass is on this network*
under *Where things are* permits a private address for the Overpass API
setting and nothing else.

## 0.9.8r202609242242

**Census anycast applies to endpoints; and eighty megabytes given back.**
The census works in /24s, and a backbone router can share one with a
service: an AT&T router three milliseconds away was being called anycast.
A census-listed range now marks a hop anycast only when the hop is where a
route ends, as the operator rule already did. And the per-prefix site lists
were sub-slices of the decoded thirty-element lists, keeping every one of
them alive -- eighty megabytes a heap profile attributed to nothing in
particular; they are copied now.

## 0.9.8r202609242239

**Three small things the live violator list showed.** The provider files
and the anycast census on disk are loaded at start, not at the first
scheduled run half an hour later, so a restart no longer forgets which
addresses are anycast. Router names carry the same dressed site codes the
server identifiers do -- `usdal2-vip-fx-103.a.aaplimg.com` is Dallas,
`usmes2` is Mesa -- and are now read the same way, undressing only tokens
that carry an instance number and a known country head, so `atlas` stays a
word. And an edge that answers a couple of milliseconds *before* the router
in front of it, which a slow router makes common, is still placed beside it.

## 0.9.8r202609242233

**The anycast census costs a fiftieth of the memory.** Sixty thousand
prefixes each carrying thirty sites were two hundred megabytes of heap on a
daemon that steers to a quarter of that. Only the six sites nearest your
origin, within five thousand kilometres, are kept per prefix -- the only
ones that could be the instance you reach -- while the card still says how
many sites there are worldwide.

## 0.9.8r202609242228

**The anycast census now loads, and the operator rule is narrower.** The
census download arrived already inflated (the server compresses on the
wire and the client undoes it), so the reader looking for a gzip header
found none and quietly kept nothing; it now sniffs the stream and reports
any failure on the *Data sources* card. And the rule that treats a known
anycast operator's address as anycast applies to endpoints only: Apple's
and Google's backbone routers on the way to their edges are ordinary
routers, and were briefly being set aside as if they were not.

## 0.9.8r202609242223

**Anycast is known, named and explained.** Of a hundred and thirty-five hops
the latency rules had flagged on a live gateway, nearly all were anycast:
Google, Cloudflare, Apple, Amazon, Vercara, NS1, Meta, measured or registered
somewhere on another continent and actually answering from a Dallas or
Kansas City instance. The map now has the lookup that says so. The LACeS
anycast census (University of Twente and CAIDA) -- forty thousand IPv4 and
eighteen thousand IPv6 prefixes detected as anycast, each with the sites it
is served from -- is fetched weekly; a hop in one of those prefixes is
placed at the census site nearest the hop before it, and its card opens
with *Anycast: announced from many datacentres at once; from here you are
reaching a local or regional instance*, with the site count and the
distance. Addresses of known anycast operators are treated the same when
nothing authoritative places them. *Know which addresses are anycast* under
*Where things are* turns it off.

**Shodan on every hop.** *Settings › paths › Shodan* takes an optional API
key (account.shodan.io; instructions in the field's help) and a mode: off,
on click, or every hop. Without a key the free InternetDB gives open ports,
names the address has been seen under, product fingerprints and known
vulnerabilities; with a key the full host record adds organisation, ISP,
operating system, Shodan's own location and last seen, at a query credit
each. Every hop's card has *Look up on Shodan*; in *every hop* mode twenty
addresses are fetched every five minutes. Records are kept a week and link
to shodan.io. `GET /api/paths/shodan?ip=` serves them.

## 0.9.8r202609242141

**Instance names are read with their dressing removed.** On the live
gateway the first round of self-identification placed ten of twenty anycast
hops; the rest answered in forms the decoder did not undress -- `qro1a`,
`usdal1`, `usmes2` -- an airport code with an instance suffix or a country
prefix. Each token is now also offered bare, so C-root answers from
Querétaro, Vercara's from Dallas and Atlanta, and Apple's resolvers from
Mesa, Arizona.

## 0.9.8r202609242137

**The status call could deadlock the Map.** In revisions 2116 to 2123 the
status endpoint gathered three new figures while holding the module's lock,
from helpers that take that same lock. The first status request after start
then waited forever, and so did every graph build behind it: the Map page
would not load and the *Data sources* card never answered. The figures are
now gathered before the lock is taken, and a test calls the endpoint under a
timeout so this cannot come back.

## 0.9.8r202609242123

**Anycast servers are asked where they are.** Root servers and large
resolvers answer a CHAOS TXT query for `id.server` with the name of the
instance that answered -- `DFW.cf.f.root-servers.org`, `c01.MCI.eroot`,
`groot-con2-1` -- and the root operators publish, per letter, their sites
with those identifiers and the town each is in. FlowSight now fetches those
site lists weekly (verified today against IANA's root hints and live DNS:
all twenty-six addresses agree) and asks each anycast hop to identify
itself, one small packet, once a week. An identifier on a published site
list is looked up; any other is read like a router name; either way the
round trip may veto it. The hop is then drawn at the instance that actually
answered -- for this network A, F and E at Dallas and Kansas City, B and I
at Ashburn, J and L at Los Angeles, M at San Jose, C at Querétaro, K at
London -- and its card shows the answer, the site and how it was read.
*Ask anycast servers to identify themselves* under *Where things are*
turns it off; the *Data sources* card counts them.

## 0.9.8r202609242119

**A language model, for the hops nothing else can place.** *Settings › paths
› AI lookup* takes a provider -- Anthropic, OpenAI, Google, Azure OpenAI, a
local Ollama, or any OpenAI-compatible endpoint -- with setup instructions
for each in the field's help, a key, a model and an hourly cap. Only hops
that answered and that no name, provider feed, geofeed, measurement or
database could place are put to it, with the hostname, network, operator and
round trip from here, and it is asked for JSON with a city and a confidence.
The answer is a hypothesis: checked against the clock like a router name,
drawn as an inference, shown on the card under *Read by a language model*
with its reasoning and confidence, overruled by any source that knows, and
remembered a month so no hop is asked about twice. Off unless configured;
the *Data sources* card shows provider, model, answered and waiting.

## 0.9.8r202609242116

**Geofeeds named in the registry are followed.** The registries' own address
for a block is the registrant's head office, but some operators publish a
geofeed -- RFC 8805, a file of prefix, country, region and city -- and name
it in the block's registry object. FlowSight already asks the registry about
every hop; it now keeps any geofeed URL the answer carries (a *Geofeed*
remark, a `geofeed` link), fetches each once a week through the public-only
client at a walking pace, and uses its rows like a provider's own range list.
The *Data sources* card counts feeds found, fetched and prefixes placed;
`GET /api/paths/geofeeds` lists them; *Follow geofeeds named in the registry*
under *Where things are* turns it off.

## 0.9.8r202609242113

**Where the "too fast" hops actually are.** Of a hundred placements the
physics had ruled out on a live gateway, eighty-odd were anycast resolvers
and root servers -- Google, Cloudflare, NS1, Vercara, Apple -- measured by
RIPE IPmap in Singapore or Johannesburg because that is where most of its
probes see them, and reached from this network via Dallas at eighteen
milliseconds. The instance reached is the one beside the upstream hop. The
map now says so: a hop past the last placed one on a route, answering within
a couple of milliseconds of it, is put beside it (*beside the last placed
hop* on its card, with the timing that says so); and the resolver and
root-server ranges no provider feed lists are carried as a curated anycast
table, so a database or measured position for them is never believed. The
AT&T hops the database had in Manhattan and Ashburn at three milliseconds
fall to the same rule.

## 0.9.8r202609242108

**AbuseIPDB reputation on every hop.** With a key under *Settings › paths ›
Reputation* (a free account at abuseipdb.com, *Account › API › Create Key*),
each address on a route is checked -- abuse confidence, reports and
reporters, ISP, usage type, domain, Tor and whitelist flags -- and the answer
shown on the hop's card under *Reputation* and kept a week. Twenty addresses
are asked about every five minutes, newest hops first, well inside the free
allowance of a thousand a day; the *Data sources* card shows how many are
known. The key is sent to api.abuseipdb.com and nowhere else.

**Provider range feeds arrive gently.** One feed per half-hour run rather
than all at once, the stalest first, read at two megabytes a second, and a
failing feed is not retried for a day. The gateway is also routing,
inspecting and counting every flow; a hundred-megabyte file pulled flat out
was a hundred megabytes taken from that.

## 0.9.8r202609242102

**The clouds' own published ranges place their addresses.** AWS, Google
Cloud, Microsoft Azure, Oracle Cloud, DigitalOcean and Linode each publish
which prefixes they use in which region, and Cloudflare and Fastly publish
their anycast ranges. FlowSight now fetches all of them weekly -- Microsoft's
hundred-megabyte file read as a stream and kept as a few hundred kilobytes;
its weekly link found on the download page -- and for an address in one of
those ranges takes the operator's own statement of where it is over the
address database and over a latency measurement. Regions become the cities
they are built in (`us-east-1` Ashburn, `westus2` Quincy, `europe-west4`
Eemshaven). An anycast address is announced everywhere at once, so a
database or measured position for one is set aside as meaningless and the
hop is placed by timing; its card says so. Such hops are drawn with a violet
ring (*position from the provider's own range list* in the key, a switch
like the others), the *Data sources* card counts each feed, and *Use the
clouds' published address ranges* under *Where things are* turns it off.

## 0.9.8r202609242053

**A placement the physics rules out is no longer drawn.** A Microsoft
backbone router in Quincy, Washington was on the map in Singapore because
the address database said so, with a red ring and a note that 58 ms cannot
reach Singapore -- a correct verdict, drawn in the wrong place. When a
database, a measurement service or a learned correction puts a hop where
its own round trip proves it cannot be, the placement is now set aside: the
hop is left for the timing to place between its neighbours, its card says
what claimed what and why it was not believed, and the *Placements the
physics rules out* table keeps the evidence with a *Said by* column and a
*Now* column. A placement from the router's own name is the exception and
stays drawn where the name says, because that is first-hand and worth
reading as an accusation.

**Microsoft's site codes.** Router names under `ntwk.msn.net` use
Microsoft's own codes -- `co` is Columbia, the Quincy, Washington campus,
which is Colorado or Colombia in anyone else's naming -- so the decoder now
carries operator-scoped code lists consulted only under that operator's
domain: co/mwh Quincy, cy Cheyenne, dm Des Moines, sn San Antonio, bn/bl
Boydton, by San Jose, ch Chicago, db Dublin, am Amsterdam, hk, sg, tk/ty.

**A learned correction is applied only where the hop's timing allows it.**
The same reachability gate that governs what is learned now governs where
it is used, so a correction for a prefix cannot move a sibling somewhere its
own round trip rules out.

## 0.9.8r202609242046

**OpenStreetMap lines are fetched by ten-degree tile.** The first region
asked for -- the eastern United States, forty degrees across -- timed out at
the public Overpass server. Regions are now cut into ten-degree tiles, a few
hundred over the populated world; one is fetched every twenty minutes
while any are outstanding, busiest first, and the job idles once all are
fresh. A timeout waits an hour and moves on; a refusal waits six. The card
counts tiles rather than regions.

## 0.9.8r202609242044

**Who was talking, and about what.** A route said where the traffic went;
it now also says whose it was and what it was doing. Under the trail, a
*Who and what* block lists every device on this network that talked to the
endpoint in the last day -- named, grouped by device rather than by address
-- and under each device its services, busiest first: the application the
flow was classified as, the name it was for, and the protocol and port
(`QUIC · one.one.one.one · udp/443`). A device links to the map narrowed to
it. The endpoint's own detail card carries a compact form of the same. The
figures come from the flow table, which gains an index by destination so
the question is answered in milliseconds; `GET /api/paths/talkers?dst=`
answers it on its own.

## 0.9.8r202609242039

**OpenStreetMap's telecom lines, as a low-weight land-route source.** Where
mappers have drawn fibre and telecom lines -- dense in a few well-mapped
countries, absent elsewhere, mostly the visible kind -- they now inform the
*expected* time between two hops at half weight: the average of following
the line and the plain detour estimate. They never touch the physics floor
and are never drawn as the route a leg took. Fetched from the Overpass API
one region per run, six hours apart, kept a month, regions taken in order of
how many of your placed hops fall in each (the populated world is sixteen
regions; the first pass takes about four days); a refusal backs off a day.
The *Data sources* card shows lines, regions and weight; *Use OpenStreetMap
telecom lines* under *Where things are* turns it off, and *Overpass API*
points it at your own instance.

## 0.9.8r202609242032

**Clicking a hop loads the route it is on.** A hop off the chosen route --
or any hop when none is chosen -- used to highlight the routes through it
and stop there. It now opens the route: the trail, the on-map table, the leg
numbers and the detail all follow, with the clicked hop selected. Where
several routes pass through a hop the busiest opens first and the chip reads
*route 1 of 4 through 4.68.72.145 · next ›*, each *next* loading the
following one. A hop already on the chosen route behaves as before: select,
zoom in, click again to zoom out.

## 0.9.8r202609242027

**The Overview's site-to-endpoint lookup is indexed and remembered.** The
join added in the previous revision read a day of flows with nothing on the
site column to seek by, and cost the Overview two seconds a load. The flow
table gains an index on site and time, and the answer is kept for two
minutes, which is well inside how fast it changes. The index is built once
on first start after the update, which on a large history takes some
seconds.

## 0.9.8r202609242025

**Every top site on the Overview links to its endpoint on the Map.** A site
is a name and a route is to an address; the flows join the two. Each row of
*Top sites* now carries a small *map* link to the route for the address that
served the site -- the one with a measured route where there is one,
otherwise the busiest, drawn dashed when the map has not traced it yet. The
API row for a site gains `dst_ip` and `traced`.

## 0.9.8r202609242021

**Arrows show which way the packets went.** Every leg carries a small arrow
on its middle segment pointing from the hop to the next; on a chosen route
they take the route's colour and the rest fade with their legs. They keep
their size on screen at any zoom. *Direction of travel* in the key switches
them off and on, remembered like the other layers.

**The whole route, on the map.** Choosing a route now puts a compact table
in the map's top-right corner, opposite the key: every step from the machine
inside the network to the endpoint, with the router's name or address, where
it is, and its round trip. Rows light up with the trail below and behave the
same way -- hover to mark the hop, click to travel to it, click the endpoint
to frame the route. It folds to its title, and remembers.

## 0.9.8r202609242015

**IPv6 addresses stay with their device.** Which addresses a device holds
*now* comes from the neighbour table and the leases, remembered for a day
because privacy addresses rotate. Which device an address *belonged to* is a
different question, and it does not expire: an IPv6 address a laptop used a
fortnight ago was that laptop's, and the traffic it sent is that laptop's.
Identity now answers the second question from every hardware address any
module ever recorded against an address, and carries the device's name to
it. The Map's device list had 79 entries that were bare IPv6 addresses --
including several that were the same MacBook -- and the trail's *inside*
address could go unnamed; both now resolve to the device, and filtering by a
device reaches the traffic it sent from addresses it no longer holds.

## 0.9.8r202609242011

**A CPU profile over the API.** `GET /api/system/profile?kind=cpu&seconds=10`
samples where the daemon's time goes and returns it in pprof format, one
sampling at a time. Twice today the gateway VM was busy while the daemon's
heap and goroutines looked innocent; the next time, the answer is a request
away rather than an inference.

**Leg labels use the chosen route's hop numbers.** A node on the map is one
router, and several routes cross it at different steps -- hop 16 of one
route is hop 18 of another -- but the label on a leg took its number from
whichever route first defined the node. On a chosen route the labels now use
that route's numbering and that route's timings.

**The slow-build log line splits reading from assembling**, since the SQL
turned out to take milliseconds while the stage that contained it took
seconds.

## 0.9.8r202609242000

**The map takes the room it has on a wide screen.** On an ultrawide the
two-column layout gave the map column its minimum width -- an SVG has no
intrinsic width to ask for -- and the tables took sixty percent of a
3,440-pixel screen. The map column is now sized from the height it may use,
doubled for the map's shape, plus the detail panel, and capped so the tables
always keep 420 pixels; on a laptop the stacked layout applies as before and
the map is no larger than it was.

**What is learned about the database is learned more carefully.** The first
hour of corrections on a live gateway included `1.1.1.0/24 in Johannesburg`
and `35.184.0.0/13 in Frankfurt`. The first is anycast: RIPE measures an
address wherever most probes see it, and a 19 ms answer from Kansas was never
Johannesburg. The second is a cloud's aggregate, spanning continents. A
correction is now learned only when the hop's own round trip could have come
back from the place (light through glass over the straight line), and a
prefix broader than a /16 (a /32 for IPv6) falls back to the /24 or /48
around the address. Anything an earlier build learned under looser rules is
dropped on load; `POST /api/paths/corrections/forget` with `all: true`
clears the lot so it can be relearned.

**Place names from RIPE IPmap are read correctly** -- *São Paulo*, not
*SÃ£o Paulo* -- on the way in and in anything already stored.

**The *Not on the map* table says why.** Each hop there now carries the
reason: nothing places it, or the database's coordinates for its block are
not believed and why.

## 0.9.8r202609241955

**The map remembers what the address database gets wrong.** The database
places a block where it was registered, which for a carrier is a head
office: every Akamai address on earth arrives at a building in Cambridge,
Massachusetts, while the router named `rio01.icn` is in Seoul. The name
already won on the map, but the win was made afresh on every rebuild and
taught the database nothing, so the next address in the same block, with no
site in its name, went straight back to Cambridge. Two things are now learned
and kept. When a router's name or a RIPE measurement places a hop more than
500 km from where the database put it, the hop's announced prefix is recorded
as being where the evidence says, and any other address of that prefix the
database alone would place follows it -- drawn as *corrected*, with the
router it was learned from and the date. And when two routers of one network
are shown to be away from one database coordinate, that coordinate is the
registrant's address and is set aside: hops the database would put there are
left for the timing to place between their neighbours, with the reason on
their card. Both lists are at `GET /api/paths/corrections`, any item can be
forgotten with `POST /api/paths/corrections/forget`, the *Data sources* card
counts them, and *Settings › paths › Remember what the database gets wrong*
turns the whole thing off.

**The IPmap line on the *Data sources* card reads "positions known"**, with
the session's share in brackets, which is what the number has meant since
1816.

## 0.9.8r202609241945

**The Map page failed to load in revisions 1805 through 1850.** The key's
*size endpoints by traffic* switch, added in 1805, rescaled the markers on
the map when the page opened, and in doing so read the current zoom from a
variable that was declared further down the page code. Browsers refuse that
(`can't access lexical declaration 'lastZ' before initialization`) and the
page stopped there. The variable is now declared ahead of everything that
reads it. The page test harness missed it because it found no markers to
rescale; it now finds one, and fails on the old code.

## 0.9.8r202609241850

**A route file cannot take the gateway down.** The daemon steers its heap
towards a soft limit (256 MB by default); a live heap far above that cannot
be steered, and the collector's answer is to run without pause. That is what
the land-route stitching did before it was fixed: a gigabyte held against a
256 MB target, every core busy collecting, and the guest agent on the VM too
starved to answer. Two guards now stand in the way. A cable or land-route
source that stitches to more than two million edges -- forty times the whole
submarine map -- is left on disk and reported on the *Data sources* card
rather than held. And a core job checks the heap every minute and logs a
warning naming the figures and the profile endpoint when the live heap is
more than twice the limit, so the condition is a log line rather than a
mystery.

**A heap profile forces a collection at most every five seconds.** Anyone
holding the token could otherwise repeat the request in a loop.

## 0.9.8r202609241847

**The Map page stops scanning the flow table.** Four things on the page read
traffic straight from the flows -- the *In / out* column of the destinations
table (twice per row, as a subquery), the traffic on each endpoint, the
device list, and the "which device talked to this" lookup behind a trail --
and the flow table has no index on the destination, so each was a scan of
every flow the store holds: on the gateway, a million rows, four hundred
times to draw one table. All four now read the five-minute rollups the core
already keeps, which hold the same totals summed, keyed by time and, from
this revision, indexed by destination. A total over hours lags the newest
flow by at most five minutes. The device list and the trail lookup consider
the last month rather than all time.

## 0.9.8r202609241844

**Interception no longer stops because an exclusion list got long.** squid
reads its configuration a line at a time, 2,048 characters to a line, and the
excluded-clients ACL was rendered as one line holding every address every
excluded device had ever held. IPv6 privacy addresses rotate daily, so that
line grew until it was cut mid-address; squid then rejected the whole
configuration (`Bad host/IP: '2600:17'`) and the *policy/reconcile* job
failed on every run, leaving the proxy on its last good configuration.
Client-address lists -- the exclusions and each policy's members -- are now
written to files, one address a line, which squid reads without limit. Each
entry is checked to be an address or a CIDR before it is written, so a
malformed one is left out rather than taking the proxy down, and a policy
whose members leave nothing valid is dropped from the configuration rather
than referenced undefined. Widening an exclusion to a device's other
addresses now takes only addresses seen in the last week.

## 0.9.8r202609241834

**The land routes cost a gigabyte of memory; they now cost nothing to
speak of.** A heap profile of the running gateway put 979 MB of its 1,045 MB
in the stitching of the land-route file, and with it the twenty garbage
collections a second that were the daemon's remaining CPU. The cause was the
shape of the data: one AfTerFibre route is 4,789 runs with a median of five
points, more than half ending exactly where the next begins, and joining every
run end to every run within 75 km made fifty million edges. Runs that end
where another starts are now chained into one line first, each line is
thinned, and each end is joined to its three nearest neighbours only. The
whole African set is 21,000 points and 58,000 edges, builds in a third of a
second and holds no measurable heap. Submarine cables come out of the same
code unchanged -- their runs were never dense enough to notice.

## 0.9.8r202609241829

**The last unremembered cable scan is remembered.** Each rebuild also asked,
for every long leg, which cables pass near both of its ends -- a walk of every
run of every cable -- and that was the three seconds left in the build after
the previous revision. The geometry half of the answer depends only on the two
places and is now kept; the timing half, which changes with every measurement,
is a cheap filter applied per leg.

**A daemon can be profiled without a debugger.** `GET /api/system/profile`
returns a heap, allocation or goroutine profile in pprof format, behind the
same access as the rest of `/api/system`. Stack traces and byte counts only;
nothing the daemon holds is in it. See *API* and *Security*.

## 0.9.8r202609241821

**The map's graph builds in a fraction of the time.** Every rebuild -- once
per twenty seconds when the page is open -- asked, for every leg, which of
842 cable and land networks offered the shortest crossing, and asked it three
times: once for the floor, once for the expectation, once to draw the shape.
Only the first was remembered. On the gateway that was a 21-second build and a
core kept busy for as long as anyone had the page open. All three now share
one memory keyed on the pair of places, emptied when the cable files reload
and bounded so a long-running daemon cannot hoard. Two tabs asking in the same
second used to each build the graph; now the first builds and the second finds
it waiting. Cable files are stitched before the module's lock is taken, so a
monthly reload never stalls a request.

**A slow build says where it was slow.** A graph that takes over three seconds
to build logs the time spent in each stage -- reading, placing, shaping,
checking, cables -- so the next slow one is a log line rather than a guess.

## 0.9.8r202609241816

**The land-route job was eating the gateway.** Turning on *Use published
land-route maps* started a job that never finished: AfTerFibre traces roads,
so its 133 routes are 222,000 points a few hundred metres apart, and the code
that stitches a cable's runs together compared every point with every other
-- twenty-five billion distances, and an adjacency list that grew to six
gigabytes while it ran. The daemon sat at nearly three cores and the *Data
sources* card said `0 loaded` with no error because the job had not yet
failed. Runs are now thinned to the points that change their shape by more
than a kilometre before stitching, and runs are joined through a grid of
one-degree cells rather than by brute force. The whole African set builds in
under two seconds and the card reports 133. Along-cable lengths change by less
than half a percent, which is far inside everything else in the estimate.

**A compressed source is bounded after inflating, not only on the wire.** The
64 MB cap on a downloaded route file applied to the bytes received; a `.gz`
source could inflate past it onto the disk. The inflated size is capped too.

**The IPmap count on the *Data sources* card is right.** It counts what is
known, but the store's prefix count was escaping its wildcard with a character
that reached SQLite as two, so it answered zero for every prefix. It answers
correctly now, with a test that pins it.

## 0.9.8r202609241805

**The land-route file was loading as nothing, and saying nothing about it.**
AfTerFibre gives its features no id and no name. Keyed on the id, all 133 of
its routes merged into a single nameless cable; the loader was written for
TeleGeography's file, which has both. A feature without an id is now its own
route, and a route without a name is named after its operator and country.
Positions with a third element -- GIS exports write elevation -- are accepted
too, which this file did not need but the next one may.

**The IPmap count survives a restart.** The *Data sources* card reported how
many positions had been measured since the daemon last started, which after
every deploy read as zero while sixty-odd hops sat placed by it. It now counts
what is actually known; the per-session figure is kept alongside.

## 0.9.8r202609241756

**Settings for the map are in sections, and the map says what feeds it.**
*Settings > paths* had grown to eighteen switches in one flat list. They now
sit under four headings -- *Tracing*, *Where things are*, *What the latency
proves*, and the rest -- and the map page carries a *Data sources* card
showing what each source has actually produced: how many positions IPmap has
measured this session and how many are queued, whether it is backing off,
how many cables and land routes are loaded, and any error a fetch returned.
Settings say what is on; this says what it has done.

**Traffic per endpoint.** Each endpoint now carries how much was received from
it and sent to it over the last day, on its card and in the destinations
table. The key gains *size endpoints by traffic*: a mode rather than a layer,
off unless asked for, that grows each endpoint's ring by the log of what went
there -- logarithmic because a megabyte and a terabyte both have to fit on one
map.

**The daemon will not fetch from inside the network it sits in.** Two settings
take URLs -- the cable map and the land-route sources -- and a daemon that
fetches whatever URL it is given is a proxy to everything the network can
see: the router's own admin page, the hypervisor's management port, the cloud
metadata address. Those fetches now go through a client that refuses any
address that is not public, and refuses at dial time after the name has
resolved, so a redirect or a name that answers differently the second time
cannot walk it somewhere private. Only http and https; no credentials in the
URL. Addresses that come off a traceroute are parsed as addresses before they
are used as a lookup key, a name to resolve or part of a URL, and an AS number
has to be digits before it goes anywhere near one.

**The graph reply is a fraction of its size.** Hops that never answered were
six of every seven nodes and nothing draws them; they are needed to build the
graph and not needed in what is sent. They are counted now and dropped, and the
reply is built once and kept for twenty seconds so the page's own refresh and
a second reader do not each walk seven thousand nodes through placement.

## 0.9.8r202609241742

**FlowSight now asks where routers actually are, and keeps asking.**

Everything else here is inference: the address database says where a block was
registered, the router's name says where its operator files it, the timing
says where it must roughly be. RIPE's IPmap is different in kind -- it is the
published result of measuring addresses from thousands of Atlas probes and
narrowing them by latency, which is the argument this module already makes
about impossibility, run at scale by people with thousands of vantage points
instead of one. It outranks the address database.

It corroborates the rest, which is the reassuring part. `4.68.39.1` is `dal2`
in Lumen's naming and Dallas to IPmap. `129.250.5.57` is `londen12` to NTT and
London to IPmap, against a database that puts it in Ashburn, Virginia. And
`62.115.139.15`, which the database places in Singapore and the speed of light
rules out at 33 ms from Kansas, IPmap puts in New York.

A background job asks about twenty addresses a minute, keeps each answer for a
month because routers do not move, remembers "they do not know either" for a
week because coverage grows, and on any refusal backs off for half an hour
rather than retrying into a wall.

**Hops that answered but could not be placed are now put between the two that
could.** A great many routers reply and have no coordinates anywhere -- 338 on
this network, against 628 that could be placed -- so the route appeared to
jump from one country to the next with nothing in between. Their position is
not unknown: the hops either side are placed, and the one in question
answered, so its round trip sits somewhere between theirs. Where it sits in
time is a fair guess at where it sits on the ground.

They are drawn hollow and dashed, marked as placed by inference, and carry the
two hops they were put between and what decided the spot. An inference is
never used to anchor another, because that drift would be invisible.

What this deliberately does not do is place the hops that never answered.
There are 6,197 of those and no measurement behind any of them; spacing them
along a line would be drawing six thousand routers out of nothing.

## 0.9.8r202609241734

**Each leg of a chosen route is labelled with the hop it arrives at as well as
what it cost** -- `#4 · 13 ms` rather than `13 ms`. The number is what ties a
label on the map to its step in the route below; the milliseconds alone left a
reader counting dots to work out which leg they were reading.

## 0.9.8r202609241731

**No more empty space around the map, and nothing on the map below the fold.**

The map is two to one and its box was whatever shape the layout gave it, so
one side or the other was always padding. The box now takes the map's shape:
the frame is two to one and its height follows from its width, which leaves
nothing above or below. Its width is capped so the whole card still fits the
screen. Measured at both a laptop and an ultrawide, the frame and the map are
now the same rectangle to the pixel.

The key is bounded to the map it sits on and scrolls its own contents, so it
is never something you have to scroll the page to reach.

**Two faults on the way, both from asking the layout for a size it could not
give.**

A flex item whose height comes from its width has no width to start from, and
the map collapsed to under half the space it had -- 482 pixels in a
1,012-pixel column. A grid column is a definite width, so the map is laid out
in a grid now and two-to-one resolves.

Then the page columns asked for the map side's max-content width. The route
trail is a single unwrapped line that scrolls sideways, so its max-content is
however long the route happens to be: the column came out at 4,087 pixels on a
2,560-pixel screen and pushed the detail panel and every table clean off the
side. It is sized by what the map can actually use instead.

## 0.9.8r202609241726

**Every entry in the key is a switch.** A key that only names the marks leaves
you to pick one kind of line out of twelve hundred by eye; one that turns them
off does the picking. Cables, shared legs, single-destination legs, sea
crossings, the bridges over unplaceable hops, endpoints, ordinary hops,
corrections, both plausibility marks and your own position each switch
independently, and the choice is remembered. Two of them -- *operator known*
and *the route you picked* -- are emphasis rather than a layer of their own,
so switching those removes the emphasis; hiding the hop would be a different
claim.

**Each leg of a selected route carries what it cost.** The panel gives one
hop's round trip, but the question is where the time went, and that is the
difference between one hop and the next. It is written along the leg, appears
only for the route you have picked, and holds its size as you zoom.

**A refresh no longer throws away your view.** The page redraws itself every
couple of minutes; zoomed in on a hop, that dropped you back at the whole
world -- the page deciding it knew better than the person using it. Where you
are, what you have narrowed to and which hop is selected all survive a
refresh. Changing route, device or filter still starts fresh, because then you
have asked for something else.

**The map uses an ultrawide screen.** Splitting the width by a ratio meant a
wider screen made the tables wider too, which they did not need: on 2560
pixels the map was using 37% of the glass while the destinations table sat in
a thousand pixels it had no use for. The side column now takes what it needs
and the map takes the rest -- 52% of the same screen, 1338 by 669 instead of
962 by 481 -- and a tall screen gives the map the height rather than capping
it at what a laptop has.

## 0.9.8r202609241716

**A placement is no longer called impossible on a margin thinner than the
origin's own error.**

Every floor is measured from your origin, and unless you declared it that
origin came from the address database -- which is where the carrier registered
the block, not where the wire ends, routinely tens of kilometres out and
sometimes hundreds. The tightest verdict on this network was a hop claiming
Montreal and missing its floor by 0.2 ms over 2,008 km. That is one per cent,
and one per cent of an origin that is itself a guess is a rounding error, not
a proof.

The hard verdict is now measured from the nearest point the origin could
honestly be -- 100 km by default, adjustable, and nothing at all for a
declared origin, where you have said where you are. It only ever withdraws
accusations. Those hops are still listed as doubtful; they have simply stopped
being called disproved.

The tables say when the allowance was made, so the arithmetic shown is the
arithmetic applied.

## 0.9.8r202609241708

**The map is shaped like the world.** Two to one, always, so at full zoom-out
pole to pole exactly fills it -- nothing cropped, nothing blank, no second
Earth in the margin. Letting it take whatever shape the window happened to be
meant one of those three every time: on a short wide window it was showing 437
degrees of latitude, a fifth of that empty sky above the pole.

It is taller too, and the frame squarer.

**A route that crosses the antimeridian keeps crossing it at every zoom.**
Past one world the copies drawn either side were being hidden, to stop the
margin filling with a second Earth. That was the easy answer and the wrong
one: those copies are what carries a leg over the seam, so a wrapping route
ran off the edge into blank space instead of coming back on the other side.
The drawing is clipped to the world instead, which empties the margin and
leaves the wrap intact.

**Two columns on a wide screen.** A two-to-one map cannot use the width of an
ultrawide display, and the tables underneath needed a scroll to reach. Past
1750 pixels the map and its route take the left and everything describing them
-- the counters, your location, the two plausibility tables, the hops with no
coordinates, the destinations -- takes the right, in a column that scrolls its
own contents so the map never moves. Below that width the page reads top to
bottom as before.

**The viewBox was not keeping up with the window.** Resizing a pane changed
the element and left the viewBox with the shape it had, which on a map drawn
three times over means showing more than one world. It listens on the window
as well as through a ResizeObserver now; one of the two always catches it.

## 0.9.8r202609241701

**Picking a hop that never answered no longer empties the panel.** Cards were
built only for hops with a position, so a silent step -- or your own location,
or a hop that replied from an address nothing can place -- selected nothing
and left a blank panel, which reads as a fault rather than as an answer.

Each now says what it is. A silent hop: nothing replied here, the traffic went
through it anyway, a router that ignores a traceroute forwards perfectly well,
and there is nothing further to know because no address came back. A hop that
answered but cannot be placed: it is listed under *Not on the map* rather than
drawn somewhere invented. And the origin gets a card of its own -- where every
route starts, the point each distance is measured from, with the public
addresses and the device that made the connection.

## 0.9.8r202609241657

**The doubtful table was showing the wrong number, and the complaint was
right.** It listed hops answering in 19.4 ms against a floor of 19.3 and
called them too fast, which is nonsense on its face. The verdict was sound --
it is made against what a *built route* needs, around 26 ms for that hop --
but the two tables shared one set of columns and the shared column was the
speed-of-light floor. So the arithmetic printed beside each verdict flatly
contradicted it.

Each table is now measured against the bound its own verdict used. The
impossible table gives what light alone needs and how far short the reply
fell; the doubtful table gives what a built route needs, how far short of
*that* it fell, and the speed-of-light floor last, where it is visibly below
the time measured and plainly not the thing that ruled.

**Interface names had started becoming cities.** `port-channel8121` is a Cisco
bundle, and read as a prefix it is Portland -- sitting four labels from the
domain while the real site code, `jan02` for Jackson, sat one label away. A
reading is now discounted for every *candidate* label it sits away from the
domain, since a router's name is written interface first and site last, and
interface words are refused outright.

Counting only candidate labels matters: an earlier version counted every
label, so `kanc-bb2-link` was penalised for being preceded by `bb2` and
`link`, neither of which was ever a contender.

## 0.9.8r202609241650

**The name proposes; the clock disposes.**

Reading a place out of a router's name matched a fixed list of codes, which
gets `dfw01` and `Dallas3` and misses `palo-bb4`, `kanc` and `sjo` -- Palo
Alto, Kansas City and San Jose, written the way anyone writes a name in a
field that is too short. Those forms are now generated from the city list
itself: a prefix of the name, or the front of each word run together.

Generating them makes the answers ambiguous, and that is the whole problem.
"san" is three cities. A decoder that picks between them confidently is worse
than one that does not pick at all, because a wrong placement is drawn with
exactly the authority of a right one.

So nothing is decided on the text. Every reading is a candidate and the
candidates are settled against the measurement: a round trip of 19 ms cannot
have reached a city 8,000 km away whatever the name says, and one of 140 ms
has no business claiming somewhere down the road. What survives carries a
score and the reason for it -- *"read as a contraction of San Jose; 50.0 ms
fits 2400 km; better than San Diego"* -- so a reader can see which of the two
did the work. A published code that the clock supports scores near one; a
reading has to be worth more than the database to replace it, and below that
line it is shown but does not move the hop.

Being *slow* counts for almost nothing either way, which took a pass over
live data to get right. A packet can be queued or sent the long way round, and
neither argues about where it ended up. Scoring slowness as evidence against
buried real readings: Arelion's `kanc-bb2-link` is Kansas City and answers in
30 ms from two hundred kilometres away, because the path goes elsewhere first.

**Endpoints look like endpoints.** The last hop of a route is the thing that
was being reached, and on a map of four hundred routes those are the points a
reader is looking for -- the rest is plumbing. They were drawn identically to
every carrier router in between. They now carry a ring of their own, say so on
hover and in their card, and clicking one opens the journey to it: the trail
from this network to that address, the map narrowed to that route, the whole
of it framed, and its detail already open.

## 0.9.8r202609241643

**Clicking a hop now shows only the routes that run through it**, and says so.
Dimming the rest was not enough: on a map carrying four hundred destinations
the faint remainder is still most of the ink, and the route you asked about is
lost in it. Everything else is taken away -- and because a map hiding most of
itself must admit to it, a chip appears above the map saying how many routes
are left and through which hop, with one click to undo it.

Concretely: clicking a hop five steps out took the drawing from 1,251 visible
legs to 21.

**The route highlights the hop you clicked on the map.** Only half of that
link existed -- a step lit its dot, but a dot left the step alone -- so on a
twenty-hop route you were reading a card with no indication which of the
twenty it belonged to. Both directions go through the same selection now, and
because the route scrolls sideways, the step is scrolled into view: marking
something the reader cannot see is not marking it.

## 0.9.8r202609241639

**The map opens pole to pole.** It had been cropping top and bottom on a wide
window, because a two-to-one world cannot fill a three-to-one box without
either cropping or repeating, and repeating is the thing this map must never
do. It now letterboxes instead: the world entire, centred, with empty margins
either side -- and past one world the copies that make panning seamless are
taken away, so the margins stay blank rather than filling with the same
continents again.

**Clicking a hop goes to it. Clicking it again comes back.** A dot on a world
map is a few pixels across, and a reader who wants to see where it is had to
zoom in and then find their own way out. The same click does both now, because
a second click on something you are already looking at can only mean you have
finished looking at it. Moving the map by hand clears that, since you are no
longer looking at what you clicked.

Two faults of mine on the way. The toggle was armed before it was known
whether anything could happen, so a click on a hop with no position -- or
before the map was ready -- still counted, and the next click came back out of
a zoom that had never happened. And the observer that keeps the viewBox in
step with the window fired mid-flight and put the view back to the whole
world, leaving an animation travelling towards a target from a position that
no longer existed and landing nowhere near the hop.

## 0.9.8r202609241631

**You are on the map.** A route's first hops are your own machine and your own
gateway, and both answer on private addresses that no database can place --
so the route appeared to begin at whichever carrier router replied first, a
couple of hundred miles away, unattached to anything. The origin was never
unknown: it is the point every other placement is judged against. It is drawn
now, and the chosen route reaches it, with the first stretch marked as the
guess it is and saying how many unplaceable hops it stands in for.

Framing a whole route includes it too, which it did not before: a route drawn
without its own beginning is not the route.

## 0.9.8r202609241629

**The map was showing the world twice.** Giving the map the window meant its
box was no longer the two-to-one shape of the world, and an SVG fitted by
height takes its extra width from outside the viewBox -- which on a map drawn
three times over to make it wrap is the copy next door. Widen the window far
enough and the same continent appeared at both ends. The viewBox now takes the
shape of the element it is drawn in, so what is on screen is exactly what was
asked for: one world, at every zoom, at any window shape.

That trade has to fall somewhere. A short, wide window cannot show a
two-to-one world whole without either repeating it sideways or letterboxing
it, so it crops -- but about the equator, not from the north pole. Anchored at
the pole it lost the entire southern hemisphere; South America and Australia
were simply not on the map.

**The key's longer lines ran out of its box.** They were held to one line each
in a panel narrower than the longest of them. They wrap now, with the swatch
aligned to the first line so a two-line entry still reads as one item.

**Apply is gone.** Choosing a filter applies it. The button existed to make
the page wait for permission it did not need, and in the meantime a filter you
had chosen sat there doing nothing while looking as though it were doing
something. Lists act on choice; the typed boxes act on Enter or when they lose
focus.

## 0.9.8r202609241626

**The map's notes fold away.** They say where the land and the cables come
from and what the map does not claim, which is worth keeping and worth reading
once -- but four dense lines sat open under every visit, and they were the
last thing pushing the map card past the bottom of the window. They are now
behind *About this map*, folded to start, and whether you leave them open is
remembered.

That was the remaining overflow: the card now ends well inside the window
rather than just past it.

## 0.9.8r202609241624

**The map fills the screen, and everything that belongs with it is on the
screen too.**

The map is what the page is for, and it was third: below a row of counters and
the location card, so reaching it meant scrolling, and reading a hop's detail
meant scrolling back. It is now the first thing on the page, sized to the
window rather than to a slice of a scroll, with the detail panel beside it and
the route beneath it. The summaries follow underneath, where a summary
belongs.

**The route moved into the map column.** It had been below the map card, which
meant clicking a step scrolled the panel it fills out of view -- the exact
problem the panel was moved beside the map to solve, reintroduced one level
down. It now runs as a single line under the map, scrolling sideways rather
than wrapping: twenty hops wrapped into five rows took the map's own height to
say something that reads perfectly well as one line.

**The key cannot be scrolled away from.** It sits in the map's bottom corner,
and now that the map is bounded to the window, so is the key -- wherever you
are on the map, and at whatever zoom, it is in front of you.

## 0.9.8r202609241617

**The key is a panel on the map, and it folds.** It had been a band across the
foot of the map: near-white on near-white ocean, the full width of the
picture, which read as a separate strip below rather than as part of it. It is
now a small opaque panel in the bottom-left corner, over empty ocean, and it
collapses to its title for anyone who would rather have the map.

It does not move when you zoom. It never did -- it is drawn beside the map
rather than inside it, so the viewBox cannot touch it -- but at ten times in
it was covering the thing being looked at, which is a fair complaint about a
key that is always open.

**Three cable names arrive from the published map with their punctuation
mangled** -- UTF-8 read as Latin-1 somewhere upstream and encoded again, which
turns Sta'O'Nuk into something that looks like a decoding error because it is
one. The damage is exactly reversible and is now undone on load. Worth doing:
a reader who sees a mangled name reasonably doubts the numbers next to it.

## 0.9.8r202609241608

**Two numbers per hop, answering two different questions.**

The floor is what light forbids: nothing answers sooner than twice the
distance divided by the speed of light in glass, measured along the cables
where a crossing has to follow one. That is a proof, and it is rigorous
precisely because it assumes a perfect path -- dead straight, nothing attached
to it.

Which is also why it is a long way below anything real. So there is now a
second number: what a route that actually exists could manage. Fibre on land
runs about a third longer than the crow flies, because it follows roads,
railways and rights of way; a sea crossing is as long as its cable, which is
measured rather than estimated; and every router holds the packet for a moment
before passing it on, which over twenty hops is worth counting.

This replaces the flat 15% margin, which was a crude stand-in for the same
idea. The band is now derived rather than guessed, and it scales with the kind
of distance and the number of hops instead of being the same everywhere.

**The middle verdict is about being too fast, not too slow.** A hop above the
floor is not disproved, but it can still answer sooner than any built route
could manage -- and the only thing that makes a reply quicker is the place
being nearer. That is evidence in the same direction as impossible, and
weaker. Being slow is never evidence of anything: congestion, queuing and
indirect routing all make a reply late and all are ordinary. The wording said
"doubtful" and left that ambiguous; it now says what it means.

**Land-route maps, fetched monthly.** With *Use published land-route maps* on,
FlowSight downloads open maps of long-haul fibre and measures along them where
they reach, instead of estimating the detour. A new job refreshes them monthly
-- long-haul routes take years to build and the datasets are revised rarely.

These never raise the impossible threshold, and the distinction is the point.
Over water a cable is the only way across, so its length is a real bound. On
land a straight line is merely something nobody built, and treating unbuilt as
impossible would convict a placement of a crime it has not committed. So a
land route sharpens the expectation and leaves the proof alone.

Coverage is thin and the setting says so. AfTerFibre covers Africa under a
Creative Commons licence and is the one substantial openly licensed set; the
comprehensive maps of North America, Europe and Asia are sold commercially,
and OpenStreetMap's telecoms tagging is dense in a few countries and absent
elsewhere. Sources are a list of URLs, so adding one later is configuration
rather than a change of design.

## 0.9.8r202609241600

**Pacific crossings resolve.** They never could, and the reason was not the
tuning it looked like.

A cable is published as a set of separate runs, because that is what a cable
is: a trunk with branching units, spurs to extra landing points, and segments
recorded apart from one another. Trans-Pacific systems come as five or seven
runs; Atlantic ones often as a single one. The search looked *inside* one run,
so it worked across the Atlantic and could not work across the Pacific at all
-- the nearest point to Kansas was on one run, the nearest to Seoul on
another, and no path existed between them. Every Pacific crossing fell back to
the straight line, or worse, to whatever unrelated cable produced a shorter
nonsense: the first honest-looking answers for Seoul and Tokyo wanted five and
a half thousand kilometres of imaginary overland at the Asian end.

Cables are now stitched back into the systems they came from -- points joined
along each run, runs joined to each other where their ends meet -- and the
distance along one is a shortest path across that network. Runs that do not
meet are still not joined, so two unrelated pieces of the same cable name are
not spliced across open water.

The cap on how far inland an end may be is raised to 3,200 km, which clears
the most landlocked places anyone actually sits. It was never the real
constraint; the share test is what stops an overland run standing in for a
crossing.

**The legend is on the map.** Stranded underneath, it made a reader look away
from the thing they were reading to find out what a colour meant, and back
again to use it.

## 0.9.8r202609241549

**Sea crossings are drawn along their cable.** A leg that crosses an ocean no
longer runs straight across the map; it follows the published route of the
cable that most likely carried it, bending where the cable bends. A straight
line there is not a simplification, it is a claim about water the cable does
not go near, and it understates the journey by however far the real route
wanders.

Hovering names the cable and gives both distances: the route and the straight
line, so the difference is visible rather than asserted.

**Picking that cable took two corrections, both found by deploying it and
looking at the answers.**

First: nothing was measured along a cable at all. The search wanted a cable
within four hundred kilometres of both ends, which is the right question for
"did this cable carry this leg" and the wrong one for "how far did the packet
travel". The gateway is in Kansas, fifteen hundred kilometres from salt water,
so every crossing it makes was discarded. The run overland is part of the
journey, not grounds for throwing the crossing away.

Then, with that relaxed, it began choosing Greenland Connect, Sunoque I and a
festoon off Colombia for crossings out of Kansas. The run ashore is measured
as a straight line and a straight line does not know about water, so a tiny
local cable with two vast imaginary approaches beat a real transatlantic
trunk. A crossing now has to be mostly the crossing -- at least 55% of the
journey on the cable itself -- and the answers became EXA North and South,
Tata TGN-Atlantic South, AEC-1 and Amitie, which are the trunks that are
actually there.

## 0.9.8r202609241539

**Distances between continents are now measured along the cables, not across
the map.**

The plausibility check asks whether a round trip could have covered the
distance, and "the distance" was the straight line over the earth's surface.
No packet travels that. Between continents it travels along a cable, and
cables do not go straight: they follow continental shelves, skirt trenches and
fishing grounds, come ashore where there is a station to land at, and are laid
with slack. The published routes are a tenth or more longer than the great
circle across the Atlantic, and a great deal more than that round Africa.

So where a crossing plausibly applies, the distance is the shortest published
cable route between the two places -- out to the cable, along it, and ashore
at the far end, with both runs ashore counted. The floor rises accordingly,
and every hop it moves was being judged against a journey nobody can make. The
tables and the hop card say which measure was used and name the cable, because
a floor you cannot check is just an assertion.

The shortest such route, not the likeliest: the check needs a bound nothing
can beat, so it takes the fastest way the packet could have gone.

Cables are consulted only where they describe this trip. Under 1,200 km the
straight line stands, because that journey is made on land and a coastal cable
that happens to pass both ends would give a long way round and accuse
perfectly good placements. A route more than twice the straight line is
rejected for the same reason: at that point it is a different journey, not a
longer version of this one. And the bound is never lowered -- a cable cannot
undercut the straight line, and the code will not let it.

This needs *Show submarine cables* on, which also downloads the map it
measures against.

## 0.9.8r202609241537

**Hop detail sits beside the map, not under it.** It used to be below, so
every answer cost a scroll away from the thing that raised the question -- and
by the time you were reading it, the hop you clicked was off screen. The panel
is now a column to the right of the map, matched to its height, scrolling its
own contents so the page never moves when you pick a different hop.

**Clicking a hop lights the routes running through it.** A dot on its own says
what a router is; the journey it belongs to says why it is there. The rest is
dimmed rather than hidden, for the same reason picking a route dims rather
than hides.

**Placed hops are no longer left floating.** A leg can only be drawn when both
its ends have a position, and most hops have none -- so a placed hop between
two unplaceable ones appeared as a dot with nothing attached to it. On this
network that was one placed dot in five, and only one of them was genuinely
unconnected: the rest were on routes whose neighbouring hops simply could not
be located. Those stretches are now bridged by a dashed leg that says how many
hops it stands in for. The traffic did go that way; what is unknown is where
it was in between, and that is a different claim from a leg between adjacent
routers, so it is drawn differently.

**Zooming out stops at one world.** Further out than that and the copies that
make the map wrap come into view, and the same place is on screen twice.

**Two bugs found by looking at the thing rather than the tests.**

The continents rendered solid black. Land and cables are drawn once and
referenced either side to make the wrap cheap, and a `<use>` renders a shadow
copy that a stylesheet rule like `.pathmap .land` does not reach -- so the
copies fell back to the SVG default, which is black fill. Their paint travels
with them now.

And where a hop was placed came down to scheduling. Reading a site out of a
name already in hand is free, but it was queued behind DNS lookups that were
going to time out, under a shared six-second budget. When the budget ran out,
hops whose names were already known were left with the address database's
answer. A router called `ae-6.a03.londen12.uk.bb.gin.ntt.net` was being shown
in Ashburn, Virginia. The free pass now runs first and in full; only the
lookups are rationed.

## 0.9.8r202609241520

**A third verdict: doubtful.** The speed of light gives a hard floor for a
round trip, and a hop that answers sooner than its placement allows is
disproved. Just above the floor was being accepted, and should not have been:
the floor assumes a dead straight fibre with nothing attached to it, and no
real route is either -- cables follow coasts and rights of way, and a packet
is queued and switched at every hop. A placement that clears the minimum by a
few per cent is claiming a journey that does not exist.

Those are now flagged as doubtful, in their own table and with their own mark
on the map: amber and dashed, against the solid red of a placement that is
ruled out. The two are kept apart deliberately. One says a reading is
disproved; the other says it is only doubted, and merging them would either
accuse the doubtful or excuse the disproved. The band is *Settings > paths*
and defaults to 15%; zero turns the category off.

**Reading router names got considerably better, which changes who gets
accused.** The decoder handled one spelling. Carriers use several: Cogent
writes dfw01, Arelion writes dls- and ash- and adm-, NTT writes dllstx14 and
londen12, and Level 3 spells the place out as Dallas3 or SanJose1. All of them
are read now, and the spelled-out names are derived from the code table so a
code and its long form cannot disagree.

That is not cosmetic either. A hop whose name is not understood keeps the
address database's answer -- which is the thing the names exist to overrule --
and can then be ruled out over a distance it never had. Arelion's
dls-b23-link is a Dallas router that the database places in St Petersburg;
answering in 17.9 ms it was being reported as physically impossible, when what
was impossible was the location, and the router's own name said so all along.

## 0.9.8r202609241515

**The map is a cylinder now, and behaves like one.** It slides east and west
without end: pan past the edge and you arrive back on the other side, with the
land, the cables and the routes all continuing rather than stopping at a seam.

This is not presentation. A leg between two points either side of the
antimeridian used to be drawn the long way -- a line clear across the map to
reach what is, on a globe, the next town over -- because the drawing measured
the distance from west to east instead of taking the shorter of the two ways
round. Legs are now laid out along the cylinder, and a route from here to
Tokyo runs west across the Pacific, which is the way the packets went.

**Clicking a step in the trail travels to it.** The map slides to that hop at
whatever zoom you are already using, in the direction the route actually goes,
rather than cutting to it -- on a map that wraps, a jump gives the reader no
way to tell which way they went. Clicking the last step frames the whole
route instead of visiting its end: by then the question has changed from
"where is this hop" to "how far did that go". Framing measures along the
cylinder too, so a short route that happens to straddle the seam is framed as
the short route it is rather than zoomed out to the whole world.

**There is a legend.** The marks on the map are not self-evident -- a thick
grey line and a thin coloured one are opposite claims, and a red ring is an
assertion about physics -- so there is now a key, drawn with the same styles
as the map itself so it cannot drift out of date.

## 0.9.8r202609241511

**A chosen route is now drawn as a trail, one step per link.** Click a
destination and the page lays the route out left to right: the machine on your
own network that made the connection, your gateway, each carrier router in
turn, and the address that was finally reached, marked as the endpoint. Each
step carries its name, where it is and what it cost in milliseconds.

**It starts inside the network.** A traceroute's own output begins at the
first router that answered, which is already one step out, and leaves the
reader to supply the beginning from memory -- when the beginning, which of
their own machines this was, is usually what they came to find out. FlowSight
joins the flow records back to the device and starts there instead. Where more
than one device used a route, the one with the most flows to that destination
is shown, or the one being filtered on.

Hovering a step lights up its dot on the map and opens its detail. Choosing a
route lifts its legs out of the rest and dims the others rather than hiding
them: a route means little without the routes it diverges from, and removing
them would make a shared leg look exclusive.

A hop that never answered keeps its place in the trail, drawn hollow, because
the traffic still went through it -- dropping it would report the path as
shorter than it is. A placement the latency rules out stays flagged as such
inside the trail, not only on the map.

## 0.9.8r202609241508

**The origin shows its public address next to its coordinates.** *Your
location* now gives the gateway's own addresses on the public internet, IPv4
and IPv6, beside the latitude and longitude the map is drawn from, and says
which of them produced those coordinates. It is shown whether or not the
coordinates came from an address at all: a reader checking where the map
thinks they are wants the address in front of them either way.

**A dual-stack gateway could previously locate itself from either family,
depending on the order its interfaces happened to enumerate in.** The walk has
no defined order, so the same gateway could take its IPv4 address one run and
its IPv6 the next, and the two geolocate to different places. That is not
cosmetic: the origin is the reference for deciding whether a hop could be
where the database claims, so an origin that moves between restarts quietly
moves the line between a placement that gets ruled out and one that stands.
IPv4 is now preferred and the list is sorted, so the answer is the same every
time it is asked. IPv4 is also the better choice on its merits, v6 blocks
being newer and more coarsely registered.

## 0.9.8r202609241505

**The map takes touch.** One finger pans, two pinch to zoom, and because the
midpoint is tracked as well as the spread, a two-finger drag pans while it
zooms -- which is the motion people actually make, rather than pinching and
dragging as separate steps. Pen works the same way. Mouse and trackpad are
unchanged.

A gesture re-bases whenever a finger lands or lifts. Without that, lifting one
finger of a pinch leaves the other anchored to a position it no longer has,
and the map jumps at the moment you were trying to settle it.

The map does not claim a touch until it is clearly a drag: a few pixels of
movement have to happen first. A captured pointer makes the browser retarget
the tap that follows to whatever holds the capture, so grabbing every touch on
the way down would have sent every tap to the map rather than to the hop under
the finger -- and on a touchscreen there is no hover to fall back on, so hop
cards would have stopped opening at all.

## 0.9.8r202609241502

**Zooming the map now shows more, rather than more ink.**

The map zooms by rewriting its viewBox, which scales everything inside it.
That is right for the coastlines and the routes -- scaling them is the whole
point -- and wrong for everything drawn on top. At four times in, a hairline
coast was four pixels wide, a three-pixel hop marker was twelve, and the
detail you had zoomed in to look at was underneath the dot pointing at it.

Strokes are now pinned to screen pixels, graticule type divides by the zoom
factor, and hop markers are redrawn from the size they started at. Zooming in
separates hops that overlapped instead of merging them into a blob.

## 0.9.8r202609240803

**The map has land, and every hop says who runs it.**

Land outlines are drawn from Natural Earth's public-domain 1:110m data. The
background had been a bare longitude and latitude grid, on the reasoning that
coastlines would imply a precision the coordinates do not have. That was the
wrong call: without land you cannot tell Kansas from Kazakhstan, and a map you
cannot read is not more honest than one you can. The caveats now live in the
text, where they belong.

Points carry what is actually known about them, in four kinds and labelled as
four kinds:

- what was **measured** -- the round trip, the position in the route;
- what **resolved** -- the router's own name;
- what its name **implies** -- carriers write the site into the hostname, so
  `po1.owr03.lax31.ntwk.msn.net` is in Los Angeles and
  `172-11-154-1.lightspeed.tpkaks.sbcglobal.net` is in Topeka;
- what the **registry** records -- which network announces the address, the
  allocation, and who holds it.

Where PeeringDB has the operator publishing street addresses of the data
centres it occupies, those are listed too.

**A hostname now overrules the address database about where a router is**, and
says so on the map. This is the substantive change rather than a presentational
one. Microsoft answers from a range the RIPE registry holds, so an address
database places its Los Angeles routers in London -- seven thousand miles out,
and the latency check cannot catch it, because London is a perfectly plausible
distance from Kansas at 134 ms. The operator's own naming can catch it. When
the two disagree the name wins, an amber dashed line runs from the discarded
position to the one now used, and the card quotes what the database had
claimed and by how much it missed. A correction you cannot audit is just an
assertion.

Two things this deliberately does not do. A registrant's postal address is
never presented as a router's location: it is a head office, and shown under
that label, or every Lumen router on earth sits in one building in Monroe,
Louisiana. And a list of buildings is only attached to a hop once the hostname
has already given away the city; otherwise the heading says it is not narrowed,
because a list of everywhere Cloudflare is tells you nothing about the hop in
front of you. Even narrowed it stays a short list. An operator publishes which
buildings it occupies, not which rack answers a traceroute.

Looking anything up over the network is optional, under *Settings > paths*.
Reading a site out of a hostname is free and always on. Results are kept for a
month.

None of it is gathered while you wait. A registry and PeeringDB are two round
trips across the internet each, and on a route table with four hundred hops in
it that took long enough that the page gave up before the answer arrived. The
map now returns immediately with whatever has been gathered, resolves names
under a short budget because a name alone is what moves a point, and fills in
the rest on a timer -- a dozen addresses a minute, so a free service run by
someone else is not emptied at in one burst.

