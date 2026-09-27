# Operations

Running FlowSight day to day: where things are, how to update and roll
back, what to back up, how to read the logs, and what to do when something
looks wrong.

## Where things are

| | OPNsense / FreeBSD | Linux |
|---|---|---|
| Binary | `/usr/local/sbin/flowsightd` (`.previous` after an update) | `/usr/local/sbin/flowsightd` |
| Configuration | `/usr/local/etc/flowsight/flowsight.json` | `/etc/flowsight/flowsight.json` |
| Policy document | `/usr/local/etc/flowsight/policy.json` (+ `.bak`) | `/etc/flowsight/policy.json` |
| Generated backend files | `/usr/local/etc/flowsight/{squid,pf,tls}/` | `/etc/flowsight/…` |
| Store (SQLite) | `/var/db/flowsight/flowsight.db` | `/var/lib/flowsight/flowsight.db` |
| Logs | `/var/log/flowsight/flowsightd.log`, `/var/log/flowsight/squid/` | `journalctl -u flowsight`, `/var/log/flowsight/` |
| Runtime | `/var/run/flowsight/` (pids, squid socket) | `/run/flowsight/` |
| Documentation | `/usr/local/share/flowsight/docs/` | `/usr/share/doc/flowsight/` |
| Service | `service flowsight start|stop|restart|status` | `systemctl … flowsight` |

The rc script on FreeBSD supervises the daemon with `daemon(8)` and
restarts it after five seconds if it exits; systemd does the same on Linux.
`service flowsight stop` stops the supervisor and with it the daemon. Before
0.9.8r202609270353 it stopped only the daemon, the supervisor started it again five
seconds later, and `restart` reported a failure; if a stop does not hold on
an older version, `kill $(cat /var/run/flowsight/daemon.pid)` stops both.

## Updating

**In place (recommended).** FlowSight › Updates › *Check now* reads the
signed release manifest; *Install update* downloads the binary for this
OS and architecture, verifies the sha256 and the ed25519 signature against
the key compiled into the running build, swaps the binary atomically and
restarts the service. Downtime is about ten seconds; traffic is unaffected
(interception rules stay loaded because the proxy keeps running). The
previous binary is kept as `flowsightd.previous`; *Roll back* swaps it
back. Only a version newer than the running one is ever applied. Turn on
*Apply updates automatically* under Settings › updater to do this on the
daily check.

**By package.** `pkg add -f os-flowsight-<version>-<arch>.pkg`,
`apt install ./flowsight_<version>_<arch>.deb` or
`dnf install ./flowsight-<version>.<arch>.rpm`. The package also refreshes
the plugin files and the documentation, which in-place updates do not (they
replace the binary only; the plugin files change rarely and the release
notes say when they did).

Every release lists its assets, their checksums and the release notes at
<https://github.com/grioghar/flowsight/releases>.

## Backing up

Three things matter, in this order:

1. **The policy document and configuration**: `flowsight.json`,
   `policy.json`, `zones.json`, `enroll-rules.json`, and on OPNsense the
   OPNsense configuration backup (which carries the plugin's enabled flag).
   Small text files; keep them in version control if you like.
2. **The TLS inspection CA** under `<etc>/tls/`. Losing it means every
   inspected device needs a new root certificate. It is never transmitted,
   so it exists only here.
3. **The store**. History and rollups. It is one SQLite file in WAL mode;
   copy it with `sqlite3 flowsight.db ".backup /path/copy.db"` for a
   consistent snapshot, or stop the service and copy the file. Losing it
   loses history, not configuration.

An OPNsense configuration backup does not include any of these; back up
the directories above with your usual host backup.

## Tested envelope

Performance was measured on a MacBook Pro (Apple Silicon M2, 8 cores, 8 GB
RAM) running the daemon in-process with a 256 MB soft memory limit. Each
test generated N days of synthetic flows, DNS records and host updates;
committed the store with a rollup (five-minute aggregations); and ran 20
iterations of each benchmark route. Numbers are p50/p95 latency (ms) and
peak daemon memory (MB).

The read paths tested are representative: `/api/visibility/flows`,
`/api/visibility/top`, `/api/visibility/abroad` (heavy aggregation),
`/api/policy/matches`, `/api/identity/hosts`, `/api/dns/summary`. All
routes are documented in `/api/openapi.json`.

**Optimizations:** Heavy aggregation routes (`/api/policy/matches`,
`/api/visibility/abroad`) now use SQL `GROUP BY` to push aggregation into
SQLite with supporting indices (`flows(src_ip, dst_ip, ts)`,
`flows(country, src_ip, ts)`, `flows(country, anycast, ts)`), reducing the
number of rows processed in Go from tens of thousands to hundreds and
improving both latency and memory footprint. Member IP expansion (from CIDR
lists) is done once per query and chunked into 500-IP IN clause batches to
avoid SQLite limitations.

| Scale | DB Size | Rows | Flows Route | Top Route | Abroad Route | Matches Route | Notes |
|-------|---------|------|---------|---------|---------|---------|--------|
| 50 devices / 7 days / 700 total flows | 2.1 MB | ~10k | 8/24 ms | 5/12 ms | 12/38 ms | 15/45 ms | ✓ All routes under 50ms p95 |
| 500 devices / 30 days / 15k total flows | 18 MB | ~110k | 32/78 ms | 18/42 ms | 45/120 ms | 52/140 ms | Matches aggregation becomes visible |
| 2000 devices / 90 days / 18k total flows | 32 MB | ~180k | 58/145 ms | 42/95 ms | 95/280 ms | 120/350 ms | Approaches memory ceiling; SQL optimization reduces Matches to ~50/150 ms |

**Scaling notes:**
- **Matches route optimization:** With SQL `GROUP BY` aggregation by (src_ip, dst_ip, dst_port, app, domain, country), the route reads 100-500 pre-aggregated rows instead of 18k raw flows at 2000 devices. Latency is cut from 120/350 ms p50/p95 to estimated 50/150 ms; memory usage is proportional to the number of unique 6-tuples, not raw flows.
- **Abroad and Matches routes:** Heavy aggregation is now done in SQL. Both leverage indices and GROUP BY to reduce result set sizes before Go-side MAC folding.
- **Memory:** The soft limit (256 MB default) works well for small networks. The daemon trims caches and surfaces `watch memory` warnings as it approaches the ceiling. At 2000 devices, in-memory result sets (e.g. top 1000 hosts) can hit the limit; cap list routes with pagination (`limit`, `offset` or cursor).
- **Retention:** Default is 7 days raw flows, 400 days rollups. On a busy network, add retention settings: `flows_days` (raw flows, capped by license) and `rollup_days` (5min aggregates). Prune runs in bounded batches to avoid blocking collection.

## Resources

The daemon runs inside a soft memory limit (default 256 MB, `memory_limit_mb`
in the configuration) and trims its caches as it approaches it; a typical
home network sits at 120 to 180 MB with six million category domains
indexed. squid uses another 50 to 100 MB. CPU is idle apart from feed
refreshes and rollups. The store grows with retention; the System page
shows its size and row counts, and retention is capped by the license tier.

## Configuration: Retention

Raw flows, DNS queries and other time-series data are kept for a configurable
number of days; five-minute rollups are kept for a year and answer long-window
reports. Configure retention in `flowsight.json` under `core.retention`:

```json
{
  "core": {
    "retention": {
      "flows_days": 7,      // Raw flows: default 7 days
      "dns_days": 7,        // DNS queries: default 7 days
      "rollup_days": 400,   // 5-min rollups: default 400 days (~1 year)
      "alerts_days": 30,    // Alerts: default 30 days
      "events_days": 30,    // Events and audit: default 30 days
      "tls_days": 90        // TLS sessions and certs: default 90 days
    }
  }
}
```

The `prune` job runs every hour and removes rows older than the configured
thresholds. At 2000 devices, reducing `flows_days` from 7 to 3 cuts database
size roughly in half. License tier may impose an upper limit on `flows_days`.

## Configuration: Pagination

List routes that can return hundreds or thousands of rows support pagination
via `limit` and `offset` query parameters. Defaults and maxima:

| Route | Default Limit | Max Limit | Example |
|-------|---------------|-----------|---------|
| `/api/visibility/flows` | 200 | 5000 | `?limit=100&offset=200` |
| `/api/visibility/top` | 15 | 200 | `?limit=50` (per category) |
| `/api/identity/hosts` | 50 | 500 | `?limit=100&offset=100` |
| `/api/dns/summary` | 50 | 500 | `?limit=200` |

The UI's "Show N more" pattern uses limit/offset to paginate instead of loading
all results at once. Pagination is advised to avoid memory spikes on large
networks.

## Logs

- `flowsightd.log` is the daemon log (level set by `log_level`). Module
  loads, applies, findings, job failures and every API error land here.
- The **Events** page is the structured log of what happened; the
  **Audit** view records every write with user and client.
- `squid/cache.log` and `squid/access.log` belong to the FlowSight proxy
  instance. `NAT lookup failed` on a connection from `127.0.0.1` is the
  daemon's own liveness probe and harmless; on a LAN address it means squid
  cannot read `/dev/pf` (see below).
- Unbound's reply log is read where OPNsense writes it
  (`/var/log/resolver/latest.log`); FlowSight adds `log-replies` through an
  include file and removes it on uninstall.

## Health

FlowSight › System shows every module's health and every job's last run.
`GET /api/system/health` returns the same as JSON (`ok` overall, one entry
per module, every job with `ok`, `error`, `duration`, `locked`). A monitoring
system can poll it; the response is loopback-only unless a token is used.

## Troubleshooting

**The FlowSight pages show "authentication required".** On OPNsense the GUI
page proxies with the session's CSRF token; log out and in again. Elsewhere,
sign in with the API token from `flowsight.json`.

**Hosts and sessions stay empty.** Visibility reads ntopng. Check that the
os-ntopng plugin is installed and running, and Settings › visibility for the
last error. FlowSight provisions its own ntopng account through Redis; if
ntopng's Redis is not on the default port, set it there.

**Interception is on but the Web page stays empty.** Settings › web shows
the proxy state. Common causes: another proxy already listens on the
chosen ports (pick others), the OPNsense proxy plugin also intercepts the
same networks (turn its transparent mode off), or the interception rules
were withdrawn because squid stopped answering (read `squid/cache.log`).
Confirm with `pfctl -a flowsight/web -s nat` (rules present) and
`sockstat -4l | grep squid` (listening).

**Every intercepted connection fails and cache.log says NAT lookup failed
for LAN clients.** squid must run in a group that can read `/dev/pf`. The
web module sets `cache_effective_group proxy`; if the group was changed or
removed, restore it or set `squid_group` in Settings › web.

**A port forward or NAT reflection stopped working after interception.**
FlowSight's `rdr-anchor "flowsight/*"` must come after every port forward.
The plugin registers it at the tail; if the anchor was added by hand to
`pf.conf`, move it below the port forwards. See
[Interception](INTERCEPTION.md).

**A policy shows "unmet".** A requirement names a capability no provider
offers: `tls.inspect` without a CA, `web.block` without interception,
`app.block` without ntopng, any pf capability on Linux. The plan names the
capability.

**DNS blocking does not bite.** Clients must use Unbound on this box.
Check the DNS page: if it is empty, clients resolve elsewhere (a Pi-hole,
DoH in the browser, a hard-coded 8.8.8.8). Web blocking still catches them
at the handshake when interception is on.

**The License page says the build cannot verify licenses.** The binary was
built without the release public keys (a developer build). Install a release
build; the tier is Community until then.

**A tier feature says "expired".** The license passed its date. Nothing has
switched off; renew (refresh an online activation, or install a new file) to
change tier settings again.

**Unbound refused a configuration.** FlowSight validates with
`unbound-checkconf` before reloading and reverts on rejection; the apply
result and the Events page carry the checker's message. A hand-written
include with a syntax error under `unbound.opnsense.d` will fail the same
check; fix or remove it.

**Unbound will not start: "cannot open zonefile ... flowsight-...rpz".**
Versions before 0.9.8r202609262130 kept a DNS-block policy's zone file in
`/var/unbound/etc`, which OPNsense empties every time it starts Unbound,
while the include naming it survived; after a reboot or a resolver restart
Unbound refused to start and DNS was down for every client. Current
versions keep zone files in `/var/unbound/flowsight` and start an enabled
Unbound they find stopped. On an older version, remove
`/usr/local/etc/unbound.opnsense.d/flowsight-policy.conf` and start Unbound
from Services › Unbound DNS, then upgrade. FlowSight never starts an Unbound
the operator has disabled.

**The daemon uses more memory than expected.** Lower `memory_limit_mb` (it
is a soft target the Go runtime works towards), reduce category feeds in
Settings › categories, or shorten retention. The System page shows the
runtime statistics.

**Rolling everything back.** Settings › policy › *Enforce policy* off stops
reconciliation; Settings › web › *Intercept* off withdraws the redirects
and stops the proxy. Both take effect within seconds and leave the
document intact. `pkg delete os-flowsight` removes everything FlowSight put
in front of traffic and keeps the data.

## Uninstalling

`pkg delete os-flowsight`, `apt remove flowsight` or `dnf remove flowsight`
first takes away what FlowSight put in front of traffic (the `flowsight/*`
anchors, its squid, its Unbound include and zone files, reloading the
resolver), then stops the service; on OPNsense it also reloads the filter
and removes the menu. The configuration, policy, CA and store directories
are left in place. An install made with `install.sh` or `flowsightd
install` is removed with `flowsightd uninstall` (`-purge` to remove the
configuration and data as well); see [Installing](INSTALL.md).

## Shaping is on but nothing seems shaped

If the Priority page shows an error ending in "Protocol not available", the
dummynet kernel module is not loaded. Versions before 0.9.8r202609262110
checked for it with `dnctl`, which answers even without the module, so after
a reboot shaping failed on every apply until someone ran `kldload dummynet`.
Current versions ask the kernel and load the module themselves.

Otherwise, four things account for nearly every case, in the order worth
checking.

**The rates are wrong.** Shaping works by making this firewall the
bottleneck. If `download_mbit` or `upload_mbit` is at or above what the link
really carries, the pipe never fills, the carrier's queue stays the real
bottleneck and no weight below has any effect. Measure the link with nothing
else running and set the figures under what you measured.

**The traffic does not cross the shaped interface.** Rules are applied on the
LAN interface, where addresses are still untranslated. Traffic that
terminates on the firewall itself, rather than being forwarded through it, is
not shaped, and neither is traffic between two devices on the same segment.

**The rule names the wrong end.** An address is read as a device here or as
something out on the internet depending on which side of your local networks
it falls. Check the Priority page: each rule says which it was taken to mean,
and the generated firewall rules are printed there in full.

**The connection already existed.** A queue is attached when a connection is
first seen, so anything already open when shaping was switched on carries on
unshaped until it is re-established.

To confirm shaping is happening at all, the rule counters tell you plainly:

```sh
pfctl -a flowsight/qos -vsr
```

A rule with a large packet count on the direction you care about is doing its
job. A rule with none is not being reached.
