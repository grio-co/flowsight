# Concepts

FlowSight is small in the places that matter: one daemon, one store, one
policy document, and a handful of ideas that everything else is built from.
This chapter explains those ideas so the rest of the manual reads as
consequences rather than rules to memorise.

## Compose, do not reimplement

Everything that touches a packet is an engine the gateway already runs and
that has been hardened for decades: **Unbound** answers DNS, **squid**
relays and, when asked, terminates TLS, **pf** drops packets, **nDPI**
(through ntopng) names applications, **Suricata** detects threats.
FlowSight owns the layer above them, the one that never existed as a
product: one model of who and what is on the network, one policy compiled
onto all of those engines, one place to look, and the reconciliation that
keeps the engines in step with what you declared.

The consequence is that FlowSight is **not inline**. If the daemon stops,
traffic keeps flowing exactly as it was last configured. Interception rules
are loaded only while the proxy answers and are withdrawn the moment it
stops. There is no packet engine to pin a core or to drop rings.

## The daemon and its modules

`flowsightd` is one static binary. It embeds the web interface, opens one
SQLite file, and loads **modules**. A module is a unit of function with a
name, settings, jobs that run on a shared schedule, API routes, panels in
the UI, and services other modules can consume. Each can be disabled.

| Module | What it does |
|---|---|
| identity | Names and MACs for addresses: DHCP leases (dnsmasq, ISC, Kea), ARP and NDP, reservations, resolver answers, OUI vendor lookup. Publishes the list of local networks. |
| visibility | Reads ntopng's REST API: flows, hosts, applications, throughput. Publishes a flow bus. |
| dns | Reads the Unbound reply log; snapshots its cache for names; provides `dns.block` (RPZ zones and views). |
| pihole | Pulls the query log from Pi-hole servers (v6 API or v5) into the same DNS history, with blocks, lists and client names. |
| web | Owns a transparent squid: the server name of every web session, `web.block`, `tls.inspect`, the block page. |
| firewall | Owns the pf anchors `flowsight/*`; provides `net.block` and the tables for `app.block`; maintains the local-networks table. |
| nftables | On a Linux gateway, FlowSight's own nftables table `inet flowsight`: `net.block`, `app.block` sets, country sets, interception redirects, zone isolation, the connection table through conntrack. Serves the same contracts as the firewall module. |
| tc | On a Linux gateway, the traffic shaper: the qos module's classes and ceilings as HTB queues on the LAN interface, upload through an ifb device. |
| appcontrol | Subscribes to the flow bus; a denied application's far end goes into a pf table and the state is killed. |
| tls | The inspection CA (Pro), the certificate inventory, findings about weak or expiring certificates. |
| paths | Path mapping (Pro): traces the route to destinations the network already contacts, and folds many routes into one picture by collapsing the legs they share. |
| qos | Traffic priority (Pro): moves the queue off the carrier and onto this firewall with dummynet (pf) or tc (Linux), then shares the link by weight, with ceilings per device or service. The only module that changes traffic rather than describing it. |
| egress | Live egress (Business): samples the firewall's connection counters every few seconds, so what is leaving is visible while it leaves, including pinned sessions, QUIC and tunnels that cannot be decrypted at all. Publishes an event stream other modules subscribe to. |
| mitm | Stateful Packet Inspection (Business): the proxy hands decrypted requests here, and their headers, content types and DNS-over-HTTPS questions are recorded. Bodies are decoded, never stored. |
| ids | Reads Suricata's EVE log: alerts, TLS sessions and certificates. |
| categories | Open domain feeds, cached and indexed; custom categories. |
| policy | The document, validation, plan and diff, apply, reconcile every minute. |
| enroll | Device classification from DHCP signals, zones, placement and isolation (enforce is Pro), captive page. |
| rulehygiene | pf ruleset analysis with live counters, change tracking, a risk score (Pro). |
| reports | HTML reports; schedules and CSV export (Pro). |
| alerting | Rules over the store; delivery channels (Pro). |
| telemetry | OTLP export of metrics and events (Business). |
| updater | Signed release manifest, verified download, atomic swap, roll back. |
| license | The installation's license, activation and refresh; answers every "may I?" question. |

## Capabilities and providers

Modules declare **capabilities**: what they can observe (`traffic.observe`,
`dns.observe`, `web.observe`, `tls.observe`, `threat.detect`) and what they
can enforce (`dns.block`, `web.block`, `app.block`, `net.block`,
`tls.inspect`). A module that enforces is a **provider**: it can compile
the policy document into its own artifact (Unbound zones, squid ACLs, pf
rules), show the difference against what is currently in place, and apply
it atomically with a backup and the backend's own validation.

Policies name capabilities, never modules or backends. That is what makes a
policy portable across an OPNsense box, a FreeBSD router and, as providers
arrive, a Linux gateway with nftables. A policy whose requirements no
installed provider offers is reported as *unmet* and refused, because a
policy that silently enforces nothing is worse than an error.

## Identity: who is on the network

A device is known by its MAC first and its address second, because
addresses change. The identity module folds every signal it has into one
picture: the DHCP lease gives a hostname and a MAC, ARP and NDP give the
current address, reservations give a stable name, the resolver's cache
gives names for far ends, the OUI registry gives the vendor. Devices with
private (randomised) MACs are recognised as such. The enroll module goes one
step further and classifies devices (phone, TV, camera, laptop) from DHCP
fingerprints, so a policy can be written for a kind of device before that
device exists. For the far end, the enrich module can add a reverse-DNS
name and a country to addresses nothing else named; it is off until you
turn it on.

## Where names come from

Every name and location (country) in FlowSight carries provenance: where it
was learned and how confident that answer is. Names have sources in this order
of trust:

| Priority | Source | Confidence | How it works |
|----------|--------|-----------|------------|
| 1 | Operator-assigned | 100% | A name you entered in the UI. Overrides everything. |
| 2 | DHCP lease hostname | 88% | The device itself told the DHCP server its name. |
| 3 | Static reservation | 80% | You reserved this address with a name in your firewall or `/etc/hosts`. |
| 4 | Device enrollment | 70% | FlowSight learned the device's name from DHCP fingerprints and behavior. |
| 5 | Reverse DNS | 20% | A resolver answered a `PTR` query for this address. This is the weakest signal: a resolver's cache may be stale, and its answer is often not authoritative. |

A lower-confidence name never overwrites a higher one. A resolver answer never
attaches to a local address (the identity module already named those with a
lease or reservation) nor to special addresses (loopback, link-local,
multicast).

Domains in flows come from these sources:

| Source | How it works |
|--------|-------------|
| SNI | The client announced the domain in the TLS ClientHello. |
| HTTP Host | The client sent the domain in the HTTP `Host:` header. |
| DNS query | The local device queried for the domain. |
| Probe cache | The probe (ntopng) saw a DNS answer point at this address. (Low confidence: shared servers and CDNs muddy this signal.) |
| None | No source identified the domain. |

Countries for addresses come from the GeoIP database when enabled (and always
from it for flows: any server with a country in ntopng's data used the
database). Reverse DNS enrichment does not populate countries; it only fills
names. Because enrichment is off by default and IP geography is coarse, country
information is optional for every report and is absent from the plan.

## The policy document

Everything you decide is one JSON document, `policy.json`, which the UI
edits for you and which you can also edit by hand, diff, back up and put in
version control.

- **Groups** are named sets of members: addresses, networks, `mac:`,
  `device:`, `zone:`, or `all`.
- **Schedules** are named sets of weekly windows.
- **Policies** are evaluated in order. Each matches groups, optionally on a
  schedule, and says what to **deny** (applications, application
  categories, web categories, domains, TLDs, ports, the internet) and what to
  **allow** back, plus safe search, YouTube mode, and TLS inspection with a
  bypass list. Each policy is either **monitor** (compile, report, enforce
  nothing) or **block**.
- **Exclusions** are hosts and domains that FlowSight never touches: not
  intercepted, not inspected, not policed.
- **Options** cover how a DNS denial answers and where the block page lives.

Nothing is written to any backend until **Enforce policy** is on; until
then the plan page shows exactly what would be written where. Once it is
on, a reconcile job compares desired and current state every minute and
applies the difference, so schedule windows, refreshed category feeds and
hand edits to a backend converge without a button. The full grammar is in
[The policy document](POLICY.md).

## Where each denial bites

| Denial | Engine | Moment |
|---|---|---|
| domain, category, TLD | Unbound RPZ zone per policy, tagged to the policy's clients; squid ACL as the second line | the DNS answer, then the TLS ClientHello or HTTP request for anything that slipped past DNS |
| application, application category | pf table per policy filled by app control from nDPI identifications | the first identified flow is cut; every later connection to that endpoint is dropped at the first packet |
| port, internet | pf rules in `flowsight/policy` | the first packet |
| safe search, YouTube | Unbound view with CNAME redirects | the DNS answer |
| TLS inspection | squid bumps the client with the FlowSight CA | the handshake; bypassed names are spliced |

Within a policy, allow beats deny. Exclusions beat everything. Policies are
evaluated in the order listed.

## Interception in one paragraph

pf redirects port 80 and 443 from the local networks to squid on loopback
(and, for IPv6, to an address the firewall holds on the LAN). squid peeks
at the TLS ClientHello for the server name and **splices** the connection
untouched unless a policy says **terminate** (denied) or **bump** (inspect
with the CA). Plain HTTP gets a block page for denied names. The redirect
rules sit after every port forward so NAT reflection keeps working, and
they are loaded only while the proxy answers. The details, including IPv6
and the pf ordering, are in [Interception](INTERCEPTION.md).

## The store

One SQLite file in WAL mode under the data directory. Raw flows, DNS
queries, alerts and TLS sessions are kept for days; five-minute **rollups**
by application, domain, destination and DNS name are kept for a year and
answer every long-window question. Flow rollups are credited as bytes are
observed, so a long download is spread over the minutes it actually took
rather than piled onto the minute it started; DNS rollups are rebuilt from
the raw queries, including any that arrive late. **Findings** are conditions that are
true now (a rule never evaluated, a certificate about to expire, an anchor
not referenced); they are keyed on a fingerprint, so they never duplicate,
and they close themselves when they stop being true. Every configuration
change is recorded with its diff and the user who made it.

## Tiers

Community is the whole product for a home network and never expires. Pro
adds the features a power user reaches for (TLS inspection, rule hygiene,
enrolment enforcement, scheduled reports, notification channels, no policy
limits, longer history); Business adds what running networks for others
needs (telemetry export, directory identity, multiple administrators,
commercial use). A license is a signed document, activated online or
installed as a file; expiry is soft. See [Licensing](LICENSING.md).

## What FlowSight can and cannot see

Every flow is assigned a **visibility** reason: why it is readable, or why
it is not. Policy and reports use this to understand the limits of what
can be controlled and where encryption is closing off policy enforcement.

| Traffic type | Visibility | Readable? | Policy control |
|---|---|---|---|
| DNS (port 53, DoT, DoH) | `dns` | Always; query and answer are visible | Full: names are known |
| Plain HTTP (port 80) | `http` | Yes; method, path, Host header | Full: blocking works inline |
| HTTPS/TLS with SNI | `sni` | Partial; server name known, content not | Partial: destination blocks; inspection opt-in |
| TLS without SNI | `opaque` | No; name and content unknown | None; nothing known to match |
| QUIC (port 443) | `quic` | No; encrypted at layer 4, name opaque | Very limited; port only |
| Encrypted Client Hello (ECH) | `ech` | No; the name is encrypted by design | None; address visible, nothing else |
| WireGuard/Tailscale tunnels | `opaque` | No; everything inside is encrypted | None; only tunnel endpoints visible |
| Inspected by FlowSight (bumped) | `inspected` | Yes; all content and names visible | Full: all inspection capabilities available |

The flow record shows which: the `visibility` field holds the reason. The
Sessions page filters by visibility, and the host summary shows how much of
each device's traffic falls into each visibility category. This is the place
to spot where encryption devices are using is going dark — a device whose
traffic is entirely `opaque` or `ech` is traffic your policy cannot steer.

When a policy sets `tls.inspect` on a device or application, squid bumps
(re-encrypts with the FlowSight CA) every HTTPS session the device opens,
and the flow visibility becomes `inspected`: the server name and all content
are visible to the inspection modules and to policy, and (if one is running)
the deep inspection engine sees headers and payloads.

QUIC and ECH are by design: QUIC's ciphers are negotiated inside the
encrypted Initial packet, and ECH encrypts the Client Name Indication so
the server at an anycast address is not revealed before the connection is
pinned to one of them. Neither can be fixed by FlowSight: they are not
bugs. Tunnels (WireGuard, Tailscale) can be identified only by endpoint
addresses, and only if the tunnel's source address is known on the LAN.

DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) are encrypted, but FlowSight
watches for them — they carry `dns` visibility if the client's DNS answers
arrive first and disclose the query — and can still block queries at the
proxy if deep inspection is on.

## Safety principles

- Nothing is enforced before you turn enforcement on, and every policy can
  run in monitor first.
- Every apply validates with the backend's own checker, keeps a backup and
  reverts on rejection.
- Interception cannot fail closed: redirects exist only while the proxy
  answers.
- The daemon listens on loopback; the OPNsense GUI authenticates; every
  write passes one gate and is audited.
- Private keys (the inspection CA, the release and license keys) are
  generated where they are used and never transmitted.
