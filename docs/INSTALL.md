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
On Linux the pf providers are unavailable: DNS policy, visibility, reports
and alerting work; web and application enforcement wait for nftables
providers.

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
