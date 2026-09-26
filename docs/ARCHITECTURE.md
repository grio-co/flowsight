# Architecture

## Principle

Compose, don't reimplement. Everything that touches packets is an existing,
battle-tested engine: Unbound answers DNS, squid terminates and relays TLS,
pf drops packets, nDPI (through ntopng) names applications, Suricata detects
threats. FlowSight owns the layer above them, which is the layer that never
existed: one policy model, one store, one interface, and the reconciliation
that keeps the engines in step with what the operator declared.

## The daemon

`flowsightd` is one static Go binary. It embeds the UI, opens one SQLite
file, and loads modules. It runs as root because it manages the resolver's
includes, the proxy instance and pf anchors; it listens on loopback only and
is reached through the OPNsense GUI (which authenticates) or, elsewhere,
with a token.

```
flowsightd
├── core        config · store (SQLite, WAL) · scheduler · API · module registry · policy model
├── identity    names and MACs: DHCP leases (dnsmasq/ISC/Kea), ARP/NDP, reservations, resolver answers, OUI
├── visibility  ntopng REST → flows, hosts, apps, throughput; publishes a flow bus
├── web         owns a transparent squid: SNI on every session, web.block, tls.inspect, block page
├── dns         Unbound reply log → DNS log; cache → address names; provider dns.block (RPZ + views)
├── pihole      Pi-hole query log (v6 REST API, v5 api.php) → the same DNS log, with blocks, lists, client names
├── firewall    pf anchors flowsight/*; provider net.block and the tables for app.block
├── appcontrol  subscribes to the flow bus; denied apps → pf table + state kill
├── baseline    learns per-device profiles (countries, ports, destinations); detects anomalies (new-country, beaconing, DNS tunneling); findings with context
├── tls         inspection CA (EC, generated in Go), certificate inventory, findings
├── ids         Suricata EVE → alerts, TLS sessions and certificates
├── categories  open domain feeds, cached; classification index; custom categories
├── policy      the document, validation, plan/diff, apply, reconcile every minute
├── enroll      device identification from DHCP, zones, placement, isolation, captive page
├── rulehygiene pf ruleset analysis with live counters, change tracking, risk score
├── reports     HTML reports, CSV export, schedules by email
├── alerting    rules over the store → email / webhook / Discord / Slack / ntfy
├── telemetry   optional OTLP export of metrics and events
└── updater     signed release manifest, verified download, atomic swap, roll back
```

### Module contract

A module implements `Info()` and `Setup(ctx)`. Through the context it
registers jobs (run on a shared pool; a panic is contained and reported),
API routes (every write passes one gate), policy providers, UI panels and
published services other modules consume. It declares its capabilities;
policy targets capabilities, never modules.

| Capability | Meaning | Provided by |
|---|---|---|
| `traffic.observe`, `app.observe`, `host.inventory` | flows, applications, devices | visibility, identity, enroll |
| `web.observe`, `tls.observe` | server names, sessions, certificates | web, ids, tls |
| `dns.observe` | resolver activity | dns |
| `threat.detect` | signatures | ids |
| `firewall.analyse` | ruleset hygiene | rulehygiene |
| `dns.block` | refuse a name | dns (Unbound RPZ/views) |
| `web.block` | terminate a web session by name | web (squid) |
| `app.block` | cut an application | firewall + appcontrol (pf tables from nDPI) |
| `net.block` | ports, internet | firewall (pf) |
| `tls.inspect` | decrypt selected clients | web + tls (squid bump with the CA) |
| `notify` | deliver a message | alerting |

A module that only observes must never claim a `.block` capability; the
compiler trusts the declaration, and a false one produces a policy that
silently does nothing.

### Enforcement services

Modules that fill address sets, cut connections or read the live
connection table do not talk to pf. They use two published services,
defined in `internal/core/enforce.go`:

| Service | Contract | Used by |
|---|---|---|
| `enforcer` | `core.Enforcer`: fill or replace a named address set, drop established connections | appcontrol, egress |
| `conn_states` | `core.StateReader`: live connections, described by who opened them, with both sides of any translation, the interface and direction, and bytes and packets each way | egress, inspect |
| `fw_rules` | `core.RuleReader`: the active ruleset with its counters, in the backend's own syntax (named by `Syntax()`) | inspect |

The firewall module provides all three over pf: sets are tables in the
`flowsight/policy` anchor, connections come from `pfctl -ss -v`, rules from
`pfctl -vvsr`. There is one pf state parser (`firewall.ParseStates`) and one
rule parser (`firewall.ParseRules`). The
set names are the ones the firewall's policy provider declared from the
policy document. Another backend (nftables, a firewall's API) provides the
same services and these modules work unchanged.

## Data path

FlowSight is not inline. pf redirects port 80 and 443 from the local networks
to squid on loopback; squid peeks at the ClientHello for the server name and
splices (relays untouched) unless the policy says terminate or bump.
Application blocking is reactive: nDPI names the application on the first
packets, the far end goes into a pf table, the state is killed, and every
later connection is dropped at the first packet. DNS blocking happens in the
resolver. If flowsightd dies, nothing changes for traffic already allowed;
interception rules are loaded only while the proxy answers, and withdrawn
the moment it stops, so a proxy failure cannot take the web down.

## The store

One SQLite file in WAL mode. Raw flows, DNS queries, alerts and TLS sessions
are kept for days; five-minute rollups by application, domain, destination
and DNS name are kept for a year and answer every long-window question.
Findings are idempotent on a fingerprint and closed automatically when they
stop being true. Every configuration change is recorded with its diff and
the user who made it.

## Policy compilation

`policy.json` is validated as a whole. Each provider compiles the document to
its artifact (Unbound zones and views, squid configuration and ACL files, pf
rules), shows the diff against what is in place, and applies only when
enforcement is on: write atomically, validate with the backend's own checker,
revert on rejection, reload. Reconciliation runs every minute, so schedule
windows, refreshed category feeds and hand edits converge without a button.
See [POLICY.md](POLICY.md).

## OPNsense integration

The plugin is small on purpose: an rc script, configd actions, a
`plugins.inc.d` hook that registers the service and three pf anchors
(`flowsight/*` quick at the head of the filter rules, and as rdr and nat
anchors at the tail so port forwards and reflection still win), a menu, an
ACL, and one legacy page that serves the embedded UI and proxies its API
with the session's CSRF token and a same-origin check. Everything else is
the daemon.

## Tools for models

The assistant module turns the route registry into tools: one tool per
documented route (`/api/visibility/flows` → `visibility_flows`), its input
schema built from the same parameter and body metadata the OpenAPI
generator uses, so a route documented to the contract is a usable tool
without further work. The same list serves three callers: the daemon's own
agent loop (Anthropic Messages API, tool use, streamed), `POST /api/mcp`
(Model Context Protocol over HTTP), and `flowsightd mcp`, a stdio bridge
that forwards JSON-RPC lines to the daemon and never opens the store.
Write routes are excluded unless a setting allows them.

## Testing

Three tools measure and validate the daemon:

**Load generation** (`cmd/fsload`): generates synthetic flows, DNS records,
and host updates deterministically. Use it to fill a store for testing:
`fsload -devices=50 -days=7 -flows-per-device-per-day=100 -out=/tmp/data`.
The seed flag (default 42) ensures reproducibility.

**Benchmarking** (`cmd/fsbench`): measures latency (p50/p95/p99) and peak
memory for heavy read paths on a running daemon. Start the daemon manually
with GOMEMLIMIT set, point fsbench to its data directory and port, and read
the results:
```
./fsbench -data-dir=/tmp/data -port=8888 -mem-limit-mb=256
```

**End-to-end regression** (`test/e2e/run.py`): starts the daemon, walks
every UI page in headless Chrome, and fails on rendering errors or console
messages. Also contract-tests every GET route from the OpenAPI spec. Run
with `python3 test/e2e/run.py` or make a data directory and Chrome path
explicit:
```
python3 test/e2e/run.py --data-dir=/tmp/data --chrome=/path/to/chrome
```

The measured performance envelope is in [OPERATIONS.md](OPERATIONS.md).

## Where it beats Zenarmor

No licence gates: exclusions, unlimited policies, every report. No cloud: data
never leaves the firewall, and the category feeds are open. No inline packet
engine to pin a core or drop rings. Policy, groups and schedules as a diffable
document. Firewall Analysis Engine (FAE), certificate inventory, device enrolment with zone
placement, self-hosted alerting and reports, signed in-place updates.

## Where it does not, yet

Content inspection inside decrypted sessions is not performed: inspection
today yields URLs, certificates and the ability to block by full URL path in
squid, not keyword or file-type scanning. Country blocking needs a GeoIP
source. User identity from directories (LDAP, RADIUS accounting) and per-user
policy are on the roadmap. Linux enforcement beyond DNS needs nftables
providers.
