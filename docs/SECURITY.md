# Security

What FlowSight exposes, who can change what, how keys are handled, and
what data it keeps. Written for the person who has to sign off on running
it on a gateway.

## Named API tokens

Beside the single `api_token`, `api_tokens` in the configuration file holds
named tokens (`[{"name": "grafana", "token": "..."}]`). Each is as powerful
as the main one; the difference is the audit log, which records
`token:<name>` for writes made with it, and `user (gui, token)` when the
OPNsense plugin acts for a logged-in GUI user. Rotate a token by replacing
its value in the file; the daemon reads the file at start.

## Who can reach FlowSight, and how

- **Addresses.** `api_allow` in `flowsight.json` lists the addresses and
  networks allowed to reach the interface and API. Everything else gets 403
  before authentication is even tried. Loopback is always allowed: that is
  the OPNsense GUI's route, so a mistake in the list never locks anyone out
  of the GUI. Pi-holes fetch category feeds from anywhere; the feed key
  protects those.
- **Encryption.** `https_port` (8443 by default) serves everything over
  HTTPS with a certificate from the inspection CA, so a device that trusts
  the CA sees no warning. With `http_local_only`, plain HTTP is served only
  to loopback and the feeds; a browser on the LAN is redirected to HTTPS.
  Session cookies are marked Secure over HTTPS.
- **Tokens.** Named tokens carry a scope: `admin` or `read`. Use `read` for
  anything that only looks (dashboards, the assistant's MCP token). With
  `api_token_local_only`, the unnamed token the OPNsense plugin reads works
  only from loopback.
- **Guessing.** Eight failed logins or bad tokens from one address within
  fifteen minutes lock that address out for a minute, doubling on each
  further failure up to an hour. Loopback is never locked out.
- **Logging out** ends the session on the server.

## Attack surface

- **The daemon listens on loopback only** (`127.0.0.1:8080`) unless `bind`
  is changed in the configuration file, which only root can do. On
  OPNsense it is reached through the GUI, which authenticates the user and
  proxies with the session's CSRF token and a same-origin check; the
  proxied request carries the GUI user's name so the audit log names
  people. Elsewhere, reach it through a reverse proxy you control or bind
  it to a LAN address and rely on the API token.
- **Writes pass one gate.** Every state-changing route requires the header
  `X-Requested-With: Flowsight` (a browser cannot add it cross-site) and,
  from anything other than the OPNsense GUI or loopback, the API token.
  Reads from loopback need nothing.
- **Some keys are locked**: `bind`, `port`, `api_token`, `data_dir`,
  `paths` and every setting that names a binary can only be changed in the
  configuration file. Whoever can change where the daemon listens or what
  it executes is root; the API is not.
- **Content Security Policy** on the UI forbids inline scripts and any
  external resource; the UI ships no third-party code and loads nothing
  from the internet.
- **The block page and captive page** listen on the LAN (ports 8082 and
  8083 by default) and serve static explanations only.
- **The proxy** listens on loopback and, for IPv6, on one LAN address you
  choose; it accepts only redirected (intercepted) connections and one
  plain forward port on loopback for its own internal URLs. It is not an
  open proxy.

## What runs as root and why

`flowsightd` runs as root because it writes the resolver's include files,
manages a squid instance, and loads pf anchors. It drops nothing it does
not need: squid itself runs as the `squid` user in the `proxy` group (the
group that may read `/dev/pf`). The license server (`flowsight-licensed`)
runs as its own unprivileged user.

## Keys and certificates

- **Inspection CA (Pro).** An EC P-256 key pair generated on the firewall
  when you create it, stored under `<etc>/tls/` readable by root and the
  proxy only. It never leaves the box; you download the certificate, not
  the key. Deleting the CA deletes the key. Only devices whose policy has
  inspection on and that trust the certificate are ever bumped; every
  other session is spliced and never decrypted. Bypass lists exempt names
  you must never inspect.
- **Release signing key.** Release binaries carry the ed25519 public key;
  the updater applies only assets whose sha256 is signed by it, and only a
  version newer than the running one. The private key lives with the
  maintainers and is not in the repository.
- **License key.** Release binaries carry a second public key; licenses
  are documents signed by the license server's private key. A build without
  the keys refuses updates and runs Community.
- **API token.** Generated at install on Linux (printed once and stored in
  `flowsight.json` with mode 600); empty on OPNsense where the GUI is the
  door. Rotate by editing the file and restarting.

## Data kept, and what leaves the box

The store (`flowsight.db`, with its `-wal` and `-shm` files) and the other
files at the top of the data directory are readable by root only; the daemon
sets that each time it opens the store.

FlowSight keeps, in one SQLite file on the gateway: hosts (addresses,
MACs, names, vendors), flows (who talked to what, how much, which
application), DNS queries and answers, web requests (client, host name,
category, bump mode; never bodies), TLS session metadata and server
certificates, IDS alerts, findings, events, and the audit log. Retention
is configurable and capped by tier; raw rows are pruned daily and rollups
keep aggregates.

Nothing leaves the gateway except:

- category feed downloads (HTTPS GET of public lists; no data sent);
- the release manifest check (HTTPS GET; no data sent);
- online license activation and refresh, when you use it: the activation
  key, the installation id, the hostname, the version and the platform,
  nothing else;
- the country database download when *Country lookup* is on (HTTPS GET
  from DB-IP or the URL you configure, monthly; no data sent), and reverse
  DNS queries through your own resolver when *Reverse DNS names* is on;
  both are off by default;
- FCC National Broadband Map checks, when credentials are configured: HTTPS
  to broadbandmap.fcc.gov with the username and API token as headers, monthly
  to retrieve the current release catalogue and the national and state-level
  provider summaries (only summaries; per-location files are skipped; total
  kept is a few hundred kilobytes);
- Pi-hole query-log pulls, when servers are configured: HTTPS to the
  Pi-holes you list with the app password you give it (read only);
- telemetry export (Business) to the collector you configure;
- notification channels (Pro) to the endpoints you configure.

There is no usage analytics, no crash reporting, no account.

## What leaves the gateway when the assistant is on

Nothing, while the assistant's provider is `off` (the default). With a
provider chosen, each question and the results of the tools the model asks
for (sessions, hosts, names, domains, countries for the window it chose)
go to that provider: Anthropic's API for the anthropic provider, or to
wherever the local Claude Code CLI is logged in for the claude-code
provider. The API token never leaves: the daemon calls its own API
itself, and Claude Code reaches FlowSight through a stdio bridge
(`flowsightd mcp`) that carries the token in its environment on the
gateway only. `redact_addresses` replaces internal addresses with stable
placeholders first; names and domains still leave. Write routes are not
offered to the model or to MCP clients unless `allow_writes` /
`mcp_allow_writes` are on. With `claude_ssh`, the token is handed to the remote Claude Code in its MCP configuration on that machine (a named token from `api_tokens` is the right one to use there), and FlowSight keeps an ed25519 key of its own under its config directory to reach that machine. The MCP endpoint `POST /api/mcp` is behind the
same authentication as the rest of the API. Conversations are kept in the
store for `retention_days` and can be forgotten from the Ask page.

## Reports: Data Privacy and Access Control

Reports generated from the store contain network traffic, DNS, application,
and security data sensitive to your organization. 

**On-Disk Storage**: Reports are stored under `<data>/reports/<definition>/`
and are **readable only by the daemon process** (file mode 0640). Run metadata
is kept in the KV store, indexed for fast lookup and retention enforcement.
Reports are not accessible from the web API unless you are authenticated.

**Scheduled Delivery**: Reports sent through notification channels (email, Slack,
Discord, ntfy, webhooks) are delivered through the alerting module and require
that you have configured the channel and specified its ID in the report's
recipients list. No report is sent if no channel is configured. Delivery logs
are kept in the notifications table.

**Downloads**: Report downloads through the web API require the same
authentication as all other API calls: loopback access (no token needed on
OPNsense), API token from any other origin, or session authentication through
the OPNsense GUI. Downloads are streamed from disk with proper content-type
headers and file names.

**Retention**: Reports are retained per definition (configurable `keep_runs`,
default 10 most recent) and globally (configurable `max_total_mb`, default 500 MB).
Oldest reports are pruned automatically when limits are exceeded, on a
per-run basis whenever the scheduler fires. Built-in definitions are read-only
but can be duplicated and customized. Reports are not included in backups by
default; include `<data>/reports/` in your backup policy if needed.

## Decryption, ethically

TLS inspection is a capability with real weight. FlowSight makes it
opt-in per policy, visible (the TLS page shows exactly which sessions were
bumped), bounded by bypass lists, and impossible without installing a
certificate on the device, which is a deliberate act on that device. Use it
on devices you own or administer with the consent their users would
reasonably expect; do not use it on guests. Inspected sessions yield URLs
and certificates for policy and inventory; bodies are not stored.

## Stateful Packet Inspection, and what it does not keep

The stateful packet inspection module (Business) listens on loopback for ICAP and is
handed each decrypted request and response by the proxy as it passes. It
records what the exchange was: method, URL, status, content type, size,
timing, and request headers when that is switched on. Cookies and
authorization headers are recorded as a length, never a value. Bodies are
read only by the decoders that are switched on, up to a byte limit, and are
discarded immediately; there is no setting that keeps a body, and none will
be added. FlowSight always answers "no modification", so no traffic is
routed through it and nothing it sees is altered. It never receives a
session a policy has not already decrypted, nor an excluded host, nor a
pinned name.

The **inspect everything that crosses the firewall** checkbox widens that
last sentence: with it on, every intercepted client is decrypted rather than
only those a policy names. Nothing else changes, exclusions and pinned names
are still never touched, but it is the widest-reaching setting in the
product and should be turned on deliberately, on a network whose users would
expect it.

The certificate probe opens outbound TLS connections from the firewall to
server names the network has already contacted, in order to read the
certificate served. It sends no request, carries no client identity and
never contacts a name the network has not. It can be switched off in
*Settings › tls*.

## Live egress monitoring

The egress module runs `pfctl -ss -v` on an interval and reads the byte
counters pf already keeps for every open connection. It reads state; it does
not add rules, change the ruleset or touch any traffic. The one action it can
take is **Stop**, which drops a single connection's state and is taken only
when an operator asks for it on the page.

Because it measures rather than decrypts, it sees connections no inspection
can open: pinned sessions, spliced sessions, QUIC on UDP 443 and encrypted
tunnels. It learns nothing about their contents and claims nothing about
them. For a tunnel it says so plainly on the finding: the volume, the far end
and the timing are the whole of what is knowable.

Addresses are named from what FlowSight already holds, the server name in a
handshake and the answer to a DNS query. No external service is consulted to
name a destination.

## Reviewing the host firewall

FlowSight's own review scope covers:

- **Daemon process and listeners**: TCP on loopback for the API; listening only on 127.0.0.1 and [::1] unless explicitly bound elsewhere
- **Anchors and pf tables**: FlowSight creates named anchors (e.g., `flowsight-dns`, `flowsight-web`) and populates tables; these are added alongside existing rules and do not replace them
- **Proxy configuration**: Squid configuration is generated and validated; every operator-typed entry is checked before being written
- **Resolver configuration**: DNS configuration is applied to dnsmasq and system resolvers

**OPNsense firewall ruleset review**: The Firewall Analysis Engine (FAE) in FlowSight provides read-only visibility into the OPNsense ruleset through the OPNsense API. To audit and review the base firewall configuration with FAE:

- Request a **read-only API key** from OPNsense (System › API › Create Token, select "Administrators in read-only mode")
- FlowSight will read `System › Firewall › Rules`, `NAT › Port Forward`, and state table information
- FAE detects shadowed rules, permissive rules, and redundancies without modifying anything
- API key should be placed in FlowSight settings (Administration › API Credentials or via CLI)

FlowSight enforces policy only on traffic the OPNsense ruleset already forwards. Because FlowSight's anchors are added alongside existing rules (not replacing them), you can:

- Remove FlowSight from the gateway without reboot and without affecting rules already in place
- Roll back to an older policy by reverting `policy.json` and restarting the daemon
- Run FlowSight in monitor mode indefinitely; it will not drop any traffic
- Review FlowSight's own configuration changes in the audit log (Events › Audit)

## Hardening checklist

- Keep the daemon on loopback; reach it through the OPNsense GUI or a
  reverse proxy with authentication.
- Back up `<etc>/tls/` if you use inspection, and treat the backup as the
  secret it is.
- Review the audit log (Events › Audit) after handing the GUI to someone
  else.
- Keep enforcement in monitor for a day when introducing a policy on a
  network you do not fully know.
- Update from the Updates page; the signature check is what makes that
  safe.

## Reporting a vulnerability

Write to <flowsight@grio.co>. Please include the version (System page),
the platform, and steps to reproduce. Fixes ship as signed releases and
the release notes name the issue once a fix is out.

## Outbound connections

Every request the daemon makes through Go's default transport, and every
alerting channel, refuses link-local (including the cloud metadata address
169.254.169.254), multicast and unspecified destinations. The check runs on
the address actually dialled, after DNS. Webhook replies are read up to 1 MB,
update manifests up to 1 MB, and release binaries up to 512 MB, and a
binary must match the size its signed manifest states.

Pi-holes serve self-signed certificates, so FlowSight pins each one on
first contact (`pin_certificates`, on by default) and refuses a different
certificate later; `POST /api/pihole/pins/clear` re-pins after a planned
replacement.

Decrypted URLs are stored without their query values, credentials or
fragments (the parameter names stay), and the proxy log keeps paths only.

## Fetching operator-supplied URLs

Two settings under *paths* take URLs: the submarine cable map and the
land-route sources. A daemon that fetches whatever URL it is given is a proxy
into the network it sits in -- the router's own administrative interface, a
hypervisor's management port, a printer, the cloud metadata address at
169.254.169.254 -- and the person entering the URL need not be the person who
owns the network.

Those fetches therefore go through a client that:

- accepts only `http` and `https`, with no credentials in the URL;
- resolves the host and **refuses to dial** any address that is loopback,
  private (RFC 1918, ULA), link-local, carrier-grade NAT (100.64/10), the IETF
  protocol range (192.0.0/24), multicast or unspecified;
- applies that check at dial time, after resolution, so a redirect or a name
  that resolves differently on the second lookup cannot lead it somewhere
  private;
- follows at most five redirects, each re-checked;
- ignores proxy environment variables, so the operator's URL is the whole of
  the request;
- reads at most 64 MB and replaces the local copy only once the whole file has
  arrived.

Addresses read from a traceroute are parsed as IP addresses before they are
used as a cache key, a name to resolve, or a path component in a request to a
public service; an AS number must be digits before it is placed in a URL.
The fixed public services asked -- RIPE IPmap, rdap.org, PeeringDB, Team Cymru
over DNS -- are asked at bounded rates and their answers cached for weeks.

## Server identification

A CHAOS-class TXT query for `id.server` is a single 30-byte UDP packet to
port 53 of an address already seen as a hop; nothing about this network is in
it, and the answer is a short string that is parsed, bounded and cached. The
root operators' site lists come from root-servers.org through the public-only
client, weekly.

## AI lookup

Off by default. When a provider is configured, the daemon sends -- only for
hops that answered and that nothing else placed -- the hostname, address,
network, operator and round trip to the chosen endpoint, with the key in that
provider's own header and nowhere else. Cloud endpoints go through the
public-only client; Ollama and custom endpoints may be local by design. The
answer is parsed as JSON, bounded, cached a month, and used only as a
hypothesis the clock can veto.

## Reputation lookups

The AbuseIPDB key is stored with the module's settings, sent only in the
`Key` header of requests to `api.abuseipdb.com`, and never written to logs or
the API. Only public addresses that appear as route hops are looked up, at
most twenty every five minutes; answers are cached a week. Without a key
nothing is sent.

## Runtime profiles

`GET /api/system/profile` returns a Go runtime profile -- heap, allocations,
goroutines, or a few seconds of CPU sampling -- for reading with `go tool pprof`. It sits behind the same access
as every other `/api/system` route. A profile is stack traces and byte counts;
it does not contain the flows, names, addresses or keys the daemon holds, and
it can be handed to support without redaction. A heap profile forces a
collection first, at most once every five seconds.

## Proxy configuration

Everything FlowSight hands to squid is generated; nothing operator-typed
reaches the configuration unchecked. Client-address lists are validated as
addresses or CIDRs and written to files one entry a line, domain lists
likewise, so neither a malformed entry nor a long list can leave the proxy
with a configuration it refuses. A rejected configuration is kept beside the
live one as `squid.conf.rejected` for inspection, and the proxy keeps running
on the last one it accepted.

## The one private-host exemption

`osm_overpass_local` lets the configured Overpass API be a private address,
for an instance the operator runs beside the gateway. It applies to that URL
only; every other fetch keeps the public-host rule.

## Operator-supplied route files

Cable and land-route sources are URLs the operator chooses. Each is fetched
through the public-only client, capped at 64 MB on the wire and 256 MB after
inflation, and stitched into networks in memory. A source that stitches to
more than two million edges is refused -- left on disk, reported on the
*Data sources* card, not held -- so a hostile or merely enormous file cannot
push the daemon's heap past what the gateway can carry.
The OpenStreetMap source is a POST to the configured Overpass endpoint through
the same client, carrying only the fixed query for one region; the answer is
capped at 64 MB and converted before it is kept.
Geofeed URLs are taken from registry answers, so they are operator-supplied
by a third party: each is checked by the same public-host rule before it is
kept, at most five hundred are remembered, each is read at one megabyte a
second and capped at 32 MB, and a feed that fails is retried weekly.
Provider range feeds (AWS, Google, Microsoft, Oracle, DigitalOcean, Linode,
Cloudflare, Fastly) are fixed URLs fetched the same way; Microsoft's weekly
link is read off its download page and must match the expected host and file
name pattern. Each file is streamed and reduced to prefix, region and
coordinates; nothing large is held in memory or on disk.

## API explorer

The in-product API explorer at the Administration › API page runs with the
viewer's session and can make requests on their behalf. Every write operation
(POST, PUT, DELETE) asks for confirmation before sending. The explorer runs
entirely in the browser and sends requests through the same authentication
gate as the UI. Every action is logged in the audit log with the user and
client address.

The OpenAPI specification endpoint (`GET /api/openapi.json`) is public and
contains no authentication secrets; it describes the routes and their
parameters but not data values. Export it freely for use with external API
clients and tools.

## Active scanning

The scan module (Scan panel, Inventory › Scan) performs active network probes
on local devices for ICMP, TCP/UDP ports, service banners, and OS fingerprinting.

**Scope**: Every target must be in a locally-known network (verified by the
identity module). Scanning across the internet is refused.

**Rate limiting**: All probes (ICMP, UDP) are rate-limited to the configured
packets-per-second (default 200, configurable). TCP respects connection
parallelism limits (default 2 hosts, 64 ports per host).

**Default state**: Off. The scan module is disabled by default and must be
explicitly turned on in Settings › scan.

**Logging**: Every scan (start, finish, cancel) is logged as an event. Open
ports, services, and findings (e.g. telnet, exposed RDP) are logged as
findings with severity.

**Origin**: Scans originate from the gateway's IP and MAC and are visible
in the target's traffic logs as connections from the gateway.

**Side effects**: Active scanning may trigger host firewalls, IDS/IPS systems,
and rate-limiting on target devices. Some network appliances rate-limit or
drop ICMP. Some hosts refuse rapid port probes or consider them suspicious.
Results may be incomplete if targets drop probes.

**Optional nmap enhancement**: When `use_nmap=true` and the nmap binary is
installed on the gateway, FlowSight uses it to enhance service version
detection and OS accuracy. nmap is never installed by FlowSight; if present,
it must be installed and updated separately (e.g. `pkg install nmap` on
OPNsense).

## Packet Inspection: Stateful and Deep Inspection

The inspect module provides two packet analysis views without packet-level capture by default.

### Stateful Packet Inspection (SPI)

Reads the firewall's own state table with `pfctl -ss -vv` on an interval (configurable, default 30 seconds):

- **No capture**: reads state counters the pf kernel already keeps, not raw packets
- **Memory capped**: keeps the newest 20,000 states; older states discarded as new flows arrive
- **Anomaly detection**: flags SYN floods and port scans (configurable thresholds) as findings
- **No side effects**: read-only, does not modify pf or touch any traffic
- **What is not kept**: full packet payloads; only state metadata (addresses, ports, state, packet/byte counts)

### Deep Packet Inspection (DPI) via Capture

`tcpdump` capture with optional analysis. Root-only; captures stored under `<data>/captures/`.

**Capture controls:**

- **Off by default**: capturing must be explicitly started from the UI
- **Hard limits**: max 10 minutes per capture, 5 rotating files at 20 MB each (cap 100 MB total)
- **Snaplen**: default 96 bytes (headers only, payload-safe). Users may select 65535 bytes (full payload)
  if settings allow; **full payloads are sensitive** and the UI warns plainly.
- **BPF validation**: filters are validated for length (max 1000 chars), character set, and compiled with
  `tcpdump -d <filter>` before any capture starts, preventing command injection.
- **Free space check**: a capture cannot start if less than 1 GB is free under the data directory.
- **File permissions**: capture files are root-only (600); non-root users cannot read them directly.

**Capture analysis** (one-pass streaming pcap parse with gopacket):

- Per-conversation 5-tuple table: packets/bytes each way, TCP flags, retransmissions, RTT estimate,
  zero-window and reset counts
- Protocol counts: Ethernet, IP, TCP, UDP, ICMP, ARP, DNS, TLS, HTTP, QUIC, mDNS, SSDP, DHCP, NTP
- Extracted artefacts: DNS queries/answers, TLS ClientHello SNI + JA3-like fingerprint + server certs,
  HTTP request lines/Host/User-Agent (plaintext only; HTTPS payloads not parsed), DHCP options,
  ARP who-has/is-at pairs, ICMP types, gratuitous ARP
- Expert notes: retransmission, duplicate ACK, zero window, reset, port reuse, ARP conflict,
  DNS response without query
- Top talkers by bytes and packets; protocol hierarchy
- Download as pcap for Wireshark

**What is NOT kept:**

- Payload data beyond what the decoders extract (DNS names, TLS certs, HTTP headers)
- HTTPS payloads: TLS inspection is not done here; only the handshake is visible
- Any plaintext HTTP/FTP/SMTP body content; only headers
- Packet timestamps inside the pcap are preserved for analysis but aggregated data is retained

**Retention:**

- Up to 10 captures, each with metadata and analysis
- Total storage capped at 100 MB; oldest captures deleted when exceeded
- Deletion is automatic on size breach and manual on the UI

**Live mode (experimental):**

- Streams raw packet summaries for 30 seconds with `tcpdump -l -n -tttt` into one-line text format
- No stored pcap, no post-capture analysis; view only
- Same BPF filter validation as capture mode

### Privilege and Root Execution

The inspect module runs these commands at root:
- `pfctl -ss -vv` (read state table)
- `pfctl -sr -vv` (read rules)
- `ifconfig -l` (list interfaces)
- `tcpdump -i <iface> -w <file> ...` with fixed, validated arguments
- `tcpdump -d <filter>` (BPF compilation validation)

Commands are built with fixed shapes from validated inputs; `tcpdump -d` is the only place a
user-supplied BPF filter is executed, and it is validated before capture to catch syntax errors early.

### Attack Surface

- **BPF injection**: impossible. Filters are validated for length and character set (no shell
  metacharacters) and compiled with `tcpdump -d` before starting a capture, rejecting syntax errors upfront.
- **Capture file abuse**: pcap files are stored in the data directory with strict permissions (root:600).
  Non-root users cannot read them. The file rotation and retention are automatic; operators cannot
  configure custom paths.
- **DoS via huge captures**: hard caps on duration (10 min), file count (5), total bytes (100 MB) and
  free space (1 GB required), preventing capture from exhausting storage.
- **State table overflow**: newest 20,000 states kept; older discarded to bound memory.

## Space module: scan uploads and physical placement

The space module stores uploaded scan files and layout blueprints.

- **Scan uploads are size-capped** at 96 MB per file and capped at 4 files
  kept simultaneously; the oldest are removed to make room for new ones.
  Files are stored under `<data>/space/` with a timestamp and the client's
  name reduced to its base name and letters, digits, dot, dash and
  underscore, so a name can never leave that folder; never executed, and
  validated by format (GLB, OBJ, PLY, RoomPlan JSON).
  Content is sniffed to detect format from magic bytes, not file extensions.
- **Outbound calls** for address records (geocoding, elevation, footprints,
  broadband data) go only to census.gov (US Census Geocoder), nationalmap.gov
  (USGS elevation), the configured Overpass instance (same public-only client
  as paths module), or broadbandmap.fcc.gov when FCC credentials are set
  (username and API token as headers, same pattern as paths module). Each
  call is rate-limited and cached 24 hours.
- **Layout and placement data** (rooms, floors, device locations) are stored
  in `<data>/space/layout.json` and saved atomically with a temporary file
  and rename, readable and writable only by the daemon.
- **Device placement is read-only integration** with the enroll module's
  device registry; placements can be associated with MAC addresses but cannot
  modify the device inventory itself.

## Proxmox Module Security

### API Token Scope

The module uses a least-privilege token with these permissions:
- `VM.Audit`: query guest list, config, status, and guest agent data
- `VM.Config.Options`: write to guest descriptions (notes write-back only)
- `Sys.Audit`: read node status and version

The token cannot start, stop, delete, or modify guests—only observe and add notes.

### TLS Certificate Pinning

Proxmox uses self-signed certificates by default. The module supports two verification modes:

**Fingerprint Pinning (default, `verify_tls` off):**
- Captures the SHA-256 fingerprint of the leaf certificate
- Pins it in settings (case-insensitive, colon-separated hex)
- Rejects any other certificate, even if signed by a trusted CA
- Read the fingerprint with `pvenode cert info | grep Fingerprint` on the Proxmox host
- Works when your infrastructure changes or you move the Proxmox node

**System CA Roots (`verify_tls` on):**
- Verifies the certificate chain against system trusted roots
- Use when Proxmox has a certificate from a real CA (Let's Encrypt, internal PKI, etc.)
- When `verify_tls` is on, fingerprint is ignored
- Supports the same pinning as fallback if set

### Notes Write-Back Security

Notes write-back is **opt-in** and disabled by default (`write_notes: false`):
- Only enabled when explicitly turned on in settings
- Uses marker-based blocks: `<!-- flowsight:begin -->` and `<!-- flowsight:end -->`
- Preserves all existing description text outside the markers
- Reads the current config (including digest) before updating to prevent clobbering concurrent edits
- Retries once if a digest mismatch occurs (concurrent edit detected)
- Never modifies the description unless notes content changed

### Guest Agent Exec (Optional)

The optional `probe_sockets` setting (default false) enables querying the guest agent for established connections:
- Runs a **fixed, read-only command only**: `ss -Htn state established` (fallback: `netstat -tn`)
- Requires `VM.Monitor` privilege on each guest (not included in the default token role)
- If you enable this, add `VM.Monitor` to the FlowSight role: `pveum role modify FlowSight -privs "...VM.Monitor"`
- Guest agent must be installed and running in the guest
- Fallback to `netstat -tn` for compatibility (e.g., OPNsense)
- No arbitrary shell commands are executed; this is safe

### Private Hosts by Design

Proxmox nodes and guests live on private networks:
- `hosts` URLs are infrastructure-local (192.168.x.x, 10.x.x.x, your own domain)
- Guests are private IP addresses on internal bridges
- FlowSight does not expose these to untrusted networks
- The API token is stored in settings (plaintext in the SQLite database), treat the FlowSight database as sensitive

### What the Module Does NOT See

- Guests on the same bridge and subnet do not route through the gateway, so FlowSight's flow probe cannot see guest-to-guest traffic on a single subnet
- Traffic analysis only covers routed inter-subnet traffic (source: "observed")
- Agent socket queries (source: "sockets") provide visibility into guest-local connections
- Declared dependencies (source: "declared") capture startup order, storage, and network config relationships

**Settings replies never carry secrets.** `POST /api/system/modules/save`
masks secret fields in its reply; a masked value sent back on a later save
means "keep what is stored".

**Update channel.** The updater accepts a manifest URL over https anywhere,
or over plain http only to a private or loopback host; every asset is still
verified by sha256 and an ed25519 signature against the key compiled into the
binary before it replaces the running daemon.

**Proxmox Notes.** Every value taken from a device (its name, hostname,
addresses, banners) is escaped before it is written into a guest's Notes: no
pipes, newlines, HTML, backticks or marker text can come from a device.

**Content-Security-Policy.** Both the daemon's page and the OPNsense page
allow scripts only from the app's own files; the OPNsense page adds a
per-response nonce for the single inline boot script. No inline event
handlers exist in the UI, and `web/uitest/csp-inline.js` fails the test run
if one is introduced.
## Alerting Module: Notification Delivery Security

### Credential Handling

- **Secrets are masked in API responses**: Passwords, API keys, tokens, and bearer credentials are replaced with `***` after initial save
- **Secrets are stored encrypted**: Channel credentials are stored in the SQLite database with at-rest encryption (pragma key)
- **No secrets in logs**: Delivery attempts are logged with status and latency, never with credentials or payloads
- **No secrets in URLs**: API calls and payload data never embed credentials in query strings

### Outbound Connections

The alerting module makes outbound connections **only** to endpoints you explicitly configure:

- **SMTP** to configured mail servers (port 25, 465, 587 depending on TLS mode)
- **HTTPS** to webhook URLs you provide
- **HTTPS** to SaaS providers (Slack, Discord, PagerDuty, Datadog, Splunk, etc.) at the endpoints you configure
- **MQTT** to brokers at the host:port you specify
- **UDP/TCP Syslog** to syslog servers
- **HTTP/HTTPS** RSS feed generation (read-only, internal)

All outbound connections respect:
- **Timeout**: 15 seconds per channel send (configurable)
- **Retry**: 3 attempts with exponential backoff (100ms, 200ms, 400ms)
- **Rate limiting**: Per (channel, alert_key) pair to prevent alert storms
- **Deduplication**: 10-minute window to drop identical alerts from same rule

### Signing & Authentication

- **HMAC-SHA256**: Webhook channels support optional HMAC-SHA256 signatures over the request body; secret is derived from the webhook config and never logged
- **AWS SigV4**: SNS, SES, CloudWatch channels use AWS Signature Version 4; credentials are stored encrypted
- **API tokens**: External APIs (PagerDuty, Opsgenie, Datadog, etc.) store tokens encrypted; never transmitted in URL parameters

### No Arbitrary Execution

- The alerting module does **not** execute shell commands, scripts, or plugins
- Webhooks accept only **HTTP/HTTPS POST/PUT** to endpoints you configure
- Templates use **Go's `text/template`** (read-only, no exec functions)
- Alert content is formatted (JSON, CEF, LEEF, plain text) but never evaluated

### Data Sent in Alerts

Alerts include:
- **Title, severity, timestamp, source module, category**
- **Device context** (IP, MAC, hostname) if present in the alert
- **Alert body** (description, evidence, findings)
- **Link** (relative to FlowSight base URL for click-through)

Alerts do **not** include:
- Authentication credentials
- Raw packet payloads or session keys
- Private hostnames or internal IP ranges (unless part of your alert rules)
- Configuration details, API tokens, or system secrets

### RSS Feed (Optional)

The RSS feed (`/api/alerting/feed.xml`) is **token-protected**:
- Requires a token query parameter to access
- Token is the `api_token` from settings or a per-feed secret (if configured)
- Feed contains recent 100 alerts with same content as alert notifications
- Feed is returned as XML with Content-Type: application/rss+xml
- No authentication beyond the token in the query string

### Maintenance Mode

When enabled, all outbound alerts are suppressed until the deadline:
- Stored in the KV store with a Unix timestamp (0 = indefinitely)
- Useful during maintenance windows or incident response
- Does **not** delete or suppress alerts internally—they still generate log entries
- After maintenance ends, alerts resume normal delivery

### Secrets Not in Maintenance or Quiet Hours

- Configuration of maintenance mode, quiet hours, and escalation rules does **not** require credentials
- These features are rule-based and operate on already-configured channels
- Changing quiet hours or escalation does **not** re-validate channel credentials
