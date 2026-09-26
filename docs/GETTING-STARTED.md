# Getting started

Thirty minutes from a plain gateway to per-device visibility, a first policy, and, if you want it, TLS inspection for the devices you choose. Nothing in this chapter changes how traffic flows until you say so: every enforcement step is opt-in and reversible.

## 1. What you need

- **OPNsense 25.7 or later** on amd64 or aarch64, or a Debian, Ubuntu, RHEL-family or FreeBSD gateway. This guide follows OPNsense; differences are in [Installing elsewhere](#installing-elsewhere).
- The **os-ntopng** plugin, recommended. It provides nDPI application identification. Without it FlowSight still sees DNS and web activity, but applications are named only from server names.
- The OPNsense **proxy plugin (os-squid)** must not intercept the same networks FlowSight will intercept. Its forward proxy may keep running.
- Root on the gateway for the installation, and a device on the LAN with a browser.

## 2. Install

```sh
fetch https://github.com/grioghar/flowsight/releases/latest/download/os-flowsight-amd64.pkg
pkg add os-flowsight-amd64.pkg
```

(`os-flowsight-aarch64.pkg` on ARM.) The package pulls in squid, registers the service, adds the pf anchors and reloads the filter. Open the OPNsense GUI: **FlowSight** is a new section in the left-hand menu with one link per page.

## 3. Setup wizard

The **Setup wizard** under Administration walks you through essential configuration in 12 steps. Open it now: **Administration › Setup wizard**.

The wizard:
- **Detects your platform**: CPU, network interfaces, installed backends (ntopng, squid, suricata).
- **Auto-discovers services**: Pi-hole on the subnet, Proxmox on the gateway's /24.
- **Tests connectivity**: Before saving, you can verify ntopng, Pi-hole and Proxmox respond with the credentials you entered.
- **Keeps progress**: Each step is saved; refreshing the browser resumes where you were.
- **Is optional**: You can skip steps or re-run the wizard to change settings later.

Steps:
1. **Welcome & license** — Optionally activate a Pro or Business license key.
2. **Site basics** — Installation name, data retention (default 7 days), memory limit.
3. **Traffic source** — Where FlowSight reads traffic. ntopng URL and credentials if needed.
4. **DNS source** — Pi-hole address and API token (optional; empty means local Unbound).
5. **Interception** — Whether to redirect web traffic for server names and blocking. Off by default.
6. **Identity & zones** — Review auto-detected local networks. Delegated to Settings › Zones.
7. **Security** — Enable IDS (Suricata), TLS probing (record server certificates).
8. **Inventory** — Proxmox host, token, and fingerprint for VM/LXC inventory.
9. **Alerting** — Add a notification channel. Delegated to Settings › Alerts.
10. **Updates** — Manifest URL (leave empty for official). Auto-apply (optional).
11. **API access** — Review API bind address and token. These are file-only; edit the config to change them.
12. **Review & finish** — Mark the wizard completed.

Once complete, you can dismiss the banner on the Overview and proceed to policies.

## 4. The first look (Overview, Hosts, Sessions)

Within a minute the **Overview** shows throughput, the busiest hosts and applications, web categories and DNS activity for the last 24 hours. Use the range buttons at the top (1h to 30d) on any page.

- **Hosts** lists every device seen: name, MAC and vendor, address, first and last seen, traffic. Names come from DHCP leases, reservations, ARP and resolver answers; you do not configure anything. Click a host for its own page: applications, sites, DNS, sessions, alerts, and what policies apply to it.
- **Sessions** is the flow table from ntopng with the application, the server name, bytes each way and, once interception is on, the TLS server name and version.
- **Applications**, **Web** and **DNS** are the same data grouped the other way round.

Everything here is observation. FlowSight has written nothing to the resolver, the proxy or the firewall yet.

## 5. Turn on web interception (optional)

Interception lets FlowSight see the server name of every web session (including the ones DNS never saw) and lets web policies block at the TLS handshake with a proper block page for plain HTTP.

The **Setup wizard step 5** offers to configure this. To do it manually:

1. **Settings › web**: set *Intercept web traffic* on. Leave the ports at their defaults unless another proxy uses them (the module refuses ports that are in use). Leave *Interfaces* empty for every interface, or name the LAN interface (`vtnet0`, `igb1`).
2. For IPv6, set *IPv6 listener address* to an address the firewall holds on the LAN, typically a unique local address such as `fd00:…::1`. Without it IPv6 web traffic is simply not intercepted.
3. Save. The proxy starts, and only once it answers are the redirect rules loaded. The **Web** page starts filling with server names.

What changes for users: nothing visible. Sessions are peeked at for the server name and relayed untouched. If the proxy ever stops answering the redirects are withdrawn within seconds, so a proxy failure cannot take the web down. Details and pf ordering are in [Interception](INTERCEPTION.md).

## 6. Your first policy

Policies are written against **groups** of devices and evaluated in order.

1. **Groups & Schedules**: create a group, for example *kids*, and add members. A member can be an address, a network, `mac:…` for a device whatever address it holds, `device:<name>` or `zone:<id>`. Add a schedule if the policy should only apply at certain hours.
2. **Policies › New**: give it a name, match the group, choose the schedule, and fill in what to deny: applications (from the nDPI catalogue), application categories, web categories, domains, TLDs, ports. Turn on safe search and YouTube restricted mode if wanted.
3. Leave *action* on **monitor** first. Save.
4. **Policies › Plan** shows what would be written to each backend: Unbound zones, squid ACLs, pf rules, with a diff. Nothing is applied yet.
5. When it looks right: **Settings › policy › Enforce policy** on, then **Apply**. From now on FlowSight reconciles every minute, so schedule windows and refreshed category feeds converge on their own.
6. Switch the policy from monitor to **block** when you are happy with what monitor reports.

Blocked requests appear on the host page, on the Web and DNS pages, and as events. Community allows three policies and two schedules; Pro removes the limits.

## 7. Optional: TLS inspection (Pro)

Inspection decrypts selected devices' HTTPS so policy can see full URLs and certificates, and so the certificate inventory is complete. It is opt-in per policy and needs the FlowSight CA trusted on those devices.

1. **TLS › Create inspection CA**. An EC P-256 key pair is generated on the firewall; the private key never leaves it.
2. Download the certificate and install it as a trusted root on the devices you intend to inspect.
3. On the policy that matches those devices, turn on *Inspect TLS* and add a bypass list for banking, health, and applications with pinned certificates (they break under any inspection).
4. Apply. Sessions from those devices show as *bumped* on the TLS page; everything else stays *spliced*.

## 8. Where to go next

- **Devices & zones** classifies new devices and, in enforce mode (Pro), places them into zones with DHCP reservations and isolation.
- **Firewall Analysis Engine (FAE)** (Pro) analyses the pf ruleset continuously: rules never evaluated, unused for weeks, shadowed, or changed since the last look.
- **Reports** renders on-screen reports for any window; Pro schedules them by e-mail and exports CSV.
- **Alerting** evaluates rules over the store every minute; Pro delivers them by e-mail, webhook, Discord, Slack or ntfy.
- **Updates** checks the signed release manifest and installs updates in place, with roll back.
- **License** shows the tier and activates a key or installs a license file.

## Installing elsewhere

**Debian and Ubuntu**

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

or install the `.deb` from the release page. The installer writes `/etc/flowsight/flowsight.json` with a generated API token (printed once) and starts the `flowsight` unit. The UI is at `http://127.0.0.1:8080`; sign in with the token.

**RHEL, Rocky, Alma, Fedora**

```sh
dnf install ./flowsight-<version>.x86_64.rpm     # or .aarch64.rpm
```

Same layout as the Debian package: unit `flowsight`, config in `/etc/flowsight`, data in `/var/lib/flowsight`, docs in `/usr/share/doc/flowsight`.

**FreeBSD (not OPNsense)**

Use `install.sh`, then add to `pf.conf` and reload:

```
nat-anchor "flowsight/*"
rdr-anchor "flowsight/*"
anchor "flowsight/*" quick
```

On Linux the pf providers do not exist: DNS policy, visibility, reports and alerting work; web and application enforcement wait for nftables providers (see the [Roadmap](ROADMAP.md)).

## Uninstalling

`pkg delete os-flowsight` (or `apt remove flowsight`, `dnf remove flowsight`) stops the service, withdraws interception and policy rules, removes the resolver includes and reloads the resolver and the filter. The store and the policy document are kept; delete `/var/db/flowsight` and `/usr/local/etc/flowsight` (Linux: `/var/lib/flowsight`, `/etc/flowsight`) to remove them.
