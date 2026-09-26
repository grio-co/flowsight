# FlowSight

Open, self-hosted layer-7 visibility, policy and enforcement for OPNsense and
other gateways. One static binary, no cloud, no licence gates.

FlowSight does what Zenarmor does and stays out of the packet path while
doing it: application and web visibility per device, per-group policy for
applications, web categories, domains and TLDs, safe search, schedules,
inline blocking at the DNS answer and the TLS handshake, an inspection CA for
the devices you choose, a certificate inventory, firewall rule hygiene,
reports and alerting. Everything is compiled onto engines the firewall already
runs: Unbound, squid, pf, nDPI (through ntopng) and Suricata.

## How it works

```
                 ┌────────────────────────────────────────────┐
   LAN ──────────┤ pf ─ rdr 80/443 ─► squid (FlowSight-owned) ├──────── WAN
                 │        │              peek SNI, splice/bump │
                 │        │              terminate denied names│
                 │   Unbound (RPZ per policy, safe search)     │
                 │   ntopng/nDPI (flows, apps)   Suricata (IDS)│
                 └───────────────┬────────────────────────────┘
                                 │ logs, REST, pfctl
                        ┌────────▼────────┐
                        │   flowsightd    │  SQLite store · policy compiler
                        │  (one binary)   │  API · embedded UI · modules
                        └─────────────────┘
```

* **Nothing inline that can fail closed.** DNS and TLS-handshake blocking are
  done by the resolver and proxy themselves; application blocking is a pf
  table filled from nDPI identifications. If flowsightd stops, the network
  keeps working. Interception rules are only loaded once the proxy answers,
  and withdrawn the moment it stops.
* **One policy, many backends.** A policy names capabilities (`dns.block`,
  `web.block`, `app.block`, `tls.inspect`, `net.block`), never a backend. The
  compiler renders it onto whatever providers are installed, shows the diff,
  and reconciles every minute once enforcement is on. Nothing is written
  before that.
* **Everything is a module** against a thin core: store, scheduler, API,
  module registry. Modules ship visibility, enforcement, reporting, alerting
  and the update mechanism; each can be disabled.

## Install on OPNsense

```sh
fetch https://github.com/grioghar/flowsight/releases/latest/download/os-flowsight-amd64.pkg
pkg add os-flowsight-amd64.pkg
```

Open **Services › FlowSight**. Visibility works immediately from ntopng (the
`os-ntopng` plugin) and Unbound. Turn on web interception under
*Settings › web* to see server names on every web session and to allow web
blocking; create the inspection CA under *TLS* if you want to decrypt for
selected devices. Policies do nothing until *Settings › policy › Enforce* is on.

Requirements: OPNsense 25.7 or later, `os-ntopng` for application identity
(optional but recommended), squid (pulled in as a dependency). The OPNsense
proxy plugin (`os-squid`) must not intercept the same networks.

## Install elsewhere (Debian, Ubuntu, FreeBSD)

```sh
curl -fsSL https://github.com/grioghar/flowsight/releases/latest/download/install.sh | sh
```

**Verified install.** To check the installer against the release checksums
before running it, fetch `install.sh` and `SHA256SUMS` from the same release
and let `sha256sum` compare them (`--ignore-missing` skips the other assets
listed in `SHA256SUMS` that you did not download):

```sh
BASE=https://github.com/grioghar/flowsight/releases/latest/download
curl -fsSLO "$BASE/install.sh" && curl -fsSLO "$BASE/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS   # must print "install.sh: OK"
sh install.sh
```

For a specific version replace `latest/download` with `download/v<version>`.
`SHA256SUMS` is written by `packaging/release/release.sh manifest` and also
lists the raw `flowsightd-<os>-<arch>` binaries, the packages and the manual,
so the same check works for any of them.

The installer places `flowsightd` in `/usr/local/sbin`, installs a systemd
unit or rc script, and prints the API token for the web UI on
`http://127.0.0.1:8080`. On Linux enforcement providers other than DNS
require nftables support that is still in progress; visibility, DNS policy,
reports and alerting work today.


## Tiers

Community is free and complete for a home network. Pro adds TLS inspection, rule hygiene, enrolment enforcement, scheduled reports, notification channels and removes the policy limits; Business adds telemetry export, directory identity, multiple administrators and commercial use. Licenses are signed documents, activated online or installed as a file for air-gapped firewalls, and expiry is soft. See [docs/LICENSING.md](docs/LICENSING.md).

## What you get

| Area | Capability |
|---|---|
| Visibility | live sessions with nDPI application and category, per-host reports, top hosts/apps/sites/destinations, throughput history, web log with server names, DNS log with block attribution, TLS sessions and certificate inventory, device inventory with vendor |
| Policy | groups by address, network, MAC, device name or zone; schedules with overnight windows; deny applications, application categories, web categories (27 open feeds plus custom), domains, TLDs, ports, all internet; allow exceptions; safe search and YouTube restricted; monitor or block; exclusions |
| Enforcement | Unbound response policy zones per policy (RPZ, logged per policy); squid terminates denied names at the ClientHello and serves a block page for HTTP; pf tables fed from nDPI cut denied applications; pf rules for ports and internet denial; optional TLS inspection with a FlowSight CA and a bypass list |
| Security | Suricata alerts, TLS findings (expired, self-signed), firewall rule hygiene with live counters, ruleset change tracking, risk score, open findings across modules |
| Operations | reports on demand and scheduled by email, CSV export, alerting to email/webhook/Discord/Slack/ntfy, audit log of every write with the GUI user, signed in-line updates with roll back, OTLP export for Grafana |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/POLICY.md](docs/POLICY.md)
and [docs/INSTALL.md](docs/INSTALL.md). The API is self-describing at
`/api/openapi.json`.

## Building

```sh
go build ./cmd/flowsightd                                   # for this machine
CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build ./cmd/flowsightd
packaging/freebsd/build-pkg.sh 1.0.0 amd64 ./flowsightd plugin/os-flowsight/src ./dist
```

Pure Go, no cgo; the UI is embedded static files with no build step.

## Licence

Apache-2.0.

## Documentation

The manual lives in [docs/](docs/README.md) and ships inside every package
(Markdown, HTML and PDF): [Getting started](docs/GETTING-STARTED.md),
[Concepts](docs/CONCEPTS.md), [User guide](docs/USER-GUIDE.md),
[Policy](docs/POLICY.md), [Interception](docs/INTERCEPTION.md),
[Configuration](docs/CONFIGURATION.md), [API](docs/API.md),
[Operations](docs/OPERATIONS.md), [Security](docs/SECURITY.md),
[Licensing](docs/LICENSING.md), [Architecture](docs/ARCHITECTURE.md).
Packages: OPNsense (`.pkg`), Debian/Ubuntu (`.deb`), RHEL-family (`.rpm`).
