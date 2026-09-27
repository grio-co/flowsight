# Installing FlowSight

Every release ships the same daemon for four platforms and three package
formats. Pick yours; the [Getting started](GETTING-STARTED.md) chapter
continues from the first login.

| Platform | Package | Service | Config | Data | Docs |
|---|---|---|---|---|---|
| OPNsense (amd64, aarch64) | `os-flowsight-<ver>-<arch>.pkg` | `service flowsight` | `/usr/local/etc/flowsight` | `/var/db/flowsight` | `/usr/local/share/flowsight/docs` |
| FreeBSD | `install.sh` or the raw binary | rc script | `/usr/local/etc/flowsight` | `/var/db/flowsight` | (manual on the release page) |
| Debian, Ubuntu (amd64, arm64) | `flowsight_<ver>_<arch>.deb` | `systemctl … flowsight` | `/etc/flowsight` | `/var/lib/flowsight` | `/usr/share/doc/flowsight` |
| RHEL, Rocky, Alma, Fedora (x86_64, aarch64) | `flowsight-<ver>-1.<arch>.rpm` | `systemctl … flowsight` | `/etc/flowsight` | `/var/lib/flowsight` | `/usr/share/doc/flowsight` |

Releases: <https://github.com/grioghar/flowsight/releases>. Every asset is
listed in `SHA256SUMS`; the binaries are additionally signed and verified by
the in-place updater.

## Checking a machine first

`flowsightd install -dry-run` looks at the machine it runs on and says what
installing FlowSight there would do, without changing anything. It reads
local facts only (it opens no network connection):

- what the machine is (OPNsense, FreeBSD, a Linux distribution; a container
  or a Kubernetes pod; a virtual machine or a cloud instance, from the
  machine's own firmware tables),
- which firewall it has, whether it routes and translates addresses for
  other machines, or only forwards for virtual machines and containers it
  runs,
- which of the tools FlowSight works with are already there (Unbound,
  dnsmasq, Pi-hole, AdGuard Home, squid, Suricata, ntopng, Zeek),
- whether FlowSight is already installed.

From that it proposes a position (*in-path* on the firewall itself,
*adjacent* beside it), the tool it would use for each job (whatever is
already installed; it installs nothing on your behalf), the steps it would
take, and the questions it could not answer. `-json` prints the same plan
as JSON and `-plan-out <file>` saves it. Enforcement is never switched on by
the installer.

Without `-dry-run`, `flowsightd install` shows the plan, asks before it
changes anything (`-yes` skips the question for unattended installs), and
then applies it:

- on FreeBSD and Linux it installs the running binary as
  `/usr/local/sbin/flowsightd`, the rc script or systemd unit (enabled),
  and a configuration with a new API token readable by root only;
- on OPNsense the os-flowsight package installs the binary and the GUI
  page, so the installer only keeps the configuration and restarts the
  service; install the package first;
- in an application container (Docker, a Kubernetes pod) it writes the
  configuration, and flowsightd runs as the container's own process. An LXC
  system container with systemd is installed like a host.

Every file it replaces is kept beside the new one (the binary as
`flowsightd.previous`, anything else as `<file>.flowsight-backup-<time>`),
an existing configuration is never overwritten, running it again changes
nothing, and each run is recorded in `install.json` in the data directory.
On FreeBSD it checks that `/etc/pf.conf` references FlowSight's anchors and
says what to add if not; it never edits `pf.conf`. After starting the
service it asks the daemon for its health over loopback and lists every
module that is not well, with the reason.

**Repeating an install.** `-plan-out site.json` saves the plan, and
`flowsightd install -plan site.json -yes` applies one without questions on
the next machine. A plan file carries decisions (the answers to the plan's
questions), never facts: the machine it runs on is always detected afresh,
and a plan made for another kind of machine (a different platform, service
or position) is refused. A hand-written file needs only what it decides,
for example `{"format": 1, "questions": [{"id": "firewall", "answer":
"opnsense 192.168.1.1"}]}`.

**Uninstalling.** `flowsightd uninstall` reverses what `flowsightd install`
recorded. It first takes away everything FlowSight put in front of traffic
(its pf anchors, its own squid, its resolver files), then stops and
disables the service, removes what the installer created and restores
what it replaced. The configuration, data and logs are kept; `-purge`
removes them too, which leaves the machine as it was before the first
install. `-dry-run` shows the steps. An install made by a package is left
to the package manager.

## Docker

```sh
docker run -d --name flowsight -p 8080:8080 -v flowsight:/var/lib/flowsight flowsight:<version>
docker logs flowsight | grep "shown once"      # the API token, printed on first start only
```

The image holds the static binary, CA certificates and nothing else (no
shell); it runs as an unprivileged user. Everything that must persist (the
configuration and token, the CA, the store) is on the one volume at
`/var/lib/flowsight`; `/etc/flowsight` links into it. To supply the token,
set `FLOWSIGHT_API_TOKEN`: it is written into the configuration at every
start and never printed. `docker exec flowsight flowsightd health` is the
image's health check. In a container FlowSight runs *adjacent*: it reads
what your firewall exports and serves the UI, API, DNS and web policy to
clients that use it, but it cannot change the network. The image is built
with `packaging/container/build-image.sh` (see [Releasing](RELEASING.md)).

## Kubernetes

```sh
helm install flowsight packaging/helm/flowsight --set image.repository=<registry>/flowsight
kubectl port-forward svc/flowsight 8080:8080
```

One replica with a persistent volume (`persistence.*`), non-root, a
read-only root filesystem and no capabilities. The token comes from
`apiToken.existingSecret` (key `apiToken.key`), from `apiToken.value` (the
chart makes the Secret), or, with neither, is generated on first start and
printed once in the pod's log. Rotating the Secret and restarting the pod
changes the token. The probes run `flowsightd health`.

**Suricata in its own pod.** A backend outside FlowSight's pod sends to it
over the provider protocol with a named token; `providers.tokens` gives the
chart each one from a Secret (in a container, any
`FLOWSIGHT_NAMED_TOKEN_<NAME>` variable becomes the token named `<name>`).
`packaging/helm/examples/suricata-provider.yaml` runs Suricata with
`flowsightd provider suricata` beside it: the provider tails Suricata's
EVE log and sends alerts and TLS records, which FlowSight shows as coming
from `suricata@<name>`. Outside Kubernetes the same command runs next to any
Suricata: `flowsightd provider suricata -core http://<flowsight>:8080 -eve
/var/log/suricata/eve.json`, with the token in `FLOWSIGHT_PROVIDER_TOKEN`
or `-token-file`.

## OPNsense

1. Install `os-ntopng` from System › Firmware › Plugins (recommended; it
   provides application identification). Leave the OPNsense proxy plugin
   (`os-squid`) without transparent interception on the networks FlowSight
   will intercept, or uninstall it: FlowSight runs its own squid instance.
2. Install the package:

   ```sh
   fetch https://github.com/grioghar/flowsight/releases/latest/download/os-flowsight-amd64.pkg
   pkg add os-flowsight-amd64.pkg
   ```

   (`os-flowsight-aarch64.pkg` on ARM.) The post-install script enables the
   service, registers the pf anchors and reloads the filter. **FlowSight**
   appears as its own section in the left-hand menu.
3. First run: the Overview shows hosts and flows within a minute. Under
   *Settings › visibility* the daemon has created its own ntopng account; no
   ntopng login is needed. Category feeds download in the background (a few
   minutes; roughly six million domains).
4. Web interception: *Settings › web › Intercept web traffic*. From then on
   every web session carries its server name and web policies can block.
5. Policies: create groups and policies, look at the plan, then turn on
   *Settings › policy › Enforce policy*. Until then nothing is written to any
   backend.
6. TLS inspection (Pro): *TLS › Create inspection CA*, download the
   certificate, install it as a trusted root on the devices you intend to
   inspect, and turn inspection on in their policy with a bypass list for
   banking and pinned applications.

Upgrading: FlowSight › Updates installs new releases in place; `pkg add -f`
with a newer package does the same and also refreshes the plugin files and
the documentation.

Uninstalling (`pkg delete os-flowsight`) stops the service, withdraws the
interception and policy rules, removes the resolver includes and reloads the
resolver and filter. The store under `/var/db/flowsight` and the policy under
`/usr/local/etc/flowsight` are kept.

## pfSense

pfSense CE 2.7 and later is supported; Plus is best effort (the package is
installed outside Netgate's repository, which a Plus upgrade may not keep).

1. Install the package from a shell (*Diagnostics › Command Prompt*, or SSH):

   ```sh
   fetch https://github.com/grioghar/flowsight/releases/latest/download/pfSense-pkg-flowsight-amd64.pkg
   pkg add pfSense-pkg-flowsight-amd64.pkg
   ```

   pkg installs squid from pfSense's own repository as a dependency (not
   the deprecated squid GUI package; leave that without transparent
   interception on the networks FlowSight will intercept). pfSense records
   the package, adds **Services › FlowSight** to the menu and the daemon to
   *Status › Services*, adds FlowSight's anchors to its ruleset through the
   package filter hook, adds three marked lines to the DNS Resolver's
   *Custom options* that include `/var/unbound/flowsight/*.conf`, and adds
   the alias `flowsight_local` (*Firewall › Aliases*): the local ranges
   FlowSight's rules mean by "not local". pfSense deletes, on every filter
   reload, any table that is not an alias, so FlowSight keeps its table as
   one; leave it in place. The
   installer then starts the daemon and checks every module.
2. Everything else is as on OPNsense (above): the Overview fills within a
   minute; web interception is *Settings › web › Intercept web traffic*;
   nothing is enforced until *Settings › policy › Enforce policy*.
3. Application identification needs ntopng, which pfSense does not
   package; point *Settings › visibility* at an ntopng elsewhere. For
   Suricata, FlowSight reads every log matching
   `/var/log/suricata/*/eve.json`, where pfSense's Suricata package keeps
   one per interface; if yours are elsewhere, set *Settings › ids › EVE log
   path* (a pattern is allowed).

Uninstalling (`pkg delete pfSense-pkg-flowsight`) stops the service,
withdraws every rule FlowSight loaded, removes its lines from the resolver's
custom options and its include directory, and reloads the resolver and the
filter. The store under `/var/db/flowsight` and the policy under
`/usr/local/etc/flowsight` are kept.

## Debian and Ubuntu

```sh
curl -fsSL https://github.com/grioghar/flowsight/releases/latest/download/install.sh | sh
```

or `apt install ./flowsight_<version>_<arch>.deb`. `install.sh` only
downloads the binary for this machine and runs `flowsightd install` (see
*Checking a machine first* above): it shows the plan, asks when there is a
terminal (`--yes` to skip the question, `--dry-run` to only see the plan),
installs the binary and the unit, and writes `/etc/flowsight/flowsight.json`
with a generated API token (printed once). The package installs its own
binary and unit and then runs `flowsightd install -packaged`, which writes
the configuration and token the same way, enables and starts the unit, and
checks the daemon's health, without touching the package's files. Upgrading
the package keeps the configuration. The UI is on `http://127.0.0.1:8080`; sign
in with the token. To expose it on a LAN set `"bind"` in the config file
(the token protects it) or put it behind a reverse proxy.

## RHEL, Rocky, Alma, Fedora

```sh
dnf install ./flowsight-<version>-1.x86_64.rpm     # or .aarch64.rpm
```

Same layout and behaviour as the Debian package, including the
`flowsightd install -packaged` step after installing. The RPM is built with
`packaging/rpm/build-rpm.sh` and depends on `unbound`; squid, ntopng and
Suricata are recommended, not required.

Backends on Linux are found where the distribution keeps them (Unbound in
`/etc/unbound`, squid in `/etc/squid`, Suricata's EVE log in
`/var/log/suricata`). Paths can be overridden under `"paths"` in the config.
On a Linux gateway with nftables, FlowSight enforces through a table of
its own, `inet flowsight`: port, internet, application and country blocks,
zone isolation, transparent web interception, and cutting connections (with
`conntrack` installed; byte counts need `net.netfilter.nf_conntrack_acct=1`).
It never touches the distribution's or your tables, and its rules only ever
reject, count or redirect: they cannot let through anything your own
firewall blocks. Only a connection's first packet is judged. Web
interception needs squid (`squid-openssl` on Debian and Ubuntu, for
inspection), and, if your firewall drops incoming connections by default,
ports 3128 and 3129 allowed from the LAN (see [Interception](INTERCEPTION.md)).
Traffic shaping uses tc (iproute2) and needs the `ifb` kernel module for
the upload direction (`modprobe ifb numifbs=0`; stock Debian, Ubuntu and
Red Hat kernels ship it). DNS policy, visibility, reports and
alerting work as elsewhere.

## FreeBSD (not OPNsense)

The same installer works; on FreeBSD it checks `pf.conf` and prints the
lines below if they are missing, but never edits the file. Add to
`pf.conf`:

```
nat-anchor "flowsight/*"
rdr-anchor "flowsight/*"
anchor "flowsight/*" quick
```

and reload pf. The firewall module reports a finding until the anchor is
referenced.

## Configuration file

`flowsight.json` holds only what you change; every key has a default. The
complete list is in the [Configuration reference](CONFIGURATION.md).

```json
{
  "site_name": "Home",
  "bind": "127.0.0.1",
  "port": 8080,
  "api_token": "",
  "retention": { "flows_days": 7, "dns_days": 7, "alerts_days": 30, "rollup_days": 400 },
  "modules": {
    "web": { "intercept": true, "networks": ["10.0.0.0/24"] },
    "policy": { "enforce": true },
    "enrich": { "reverse_dns": true, "geoip": true },
    "ui": { "theme": "auto" }
  }
}
```

`bind`, `port`, `api_token`, `data_dir` and `paths` can only be changed in
this file, never through the API: whoever can change where the daemon listens
is root, and the API is not.

## Building from source

```sh
git clone https://github.com/grioghar/flowsight && cd flowsight
CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.Version=1.0.0" -o flowsightd ./cmd/flowsightd
packaging/freebsd/build-pkg.sh 1.0.0 amd64 ./flowsightd plugin/os-flowsight/src ./dist          # on FreeBSD (needs pkg)
packaging/debian/build-deb.sh 1.0.0 amd64 ./flowsightd-linux ./dist                            # needs dpkg-deb
packaging/rpm/build-rpm.sh 1.0.0 x86_64 ./flowsightd-linux ./dist                              # needs rpmbuild
packaging/docs/build-docs.sh 1.0.0 ./dist/docs                                                # needs pandoc + weasyprint
```

Go 1.24 or newer, no cgo, no other toolchain. A build from source carries
no release keys: it cannot verify updates or licenses and runs Community
(see [Security](SECURITY.md)).
