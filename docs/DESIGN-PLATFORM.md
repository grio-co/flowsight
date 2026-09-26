# Design: FlowSight everywhere, and FlowSight-NG

Status: **proposal**, for the product owner's decision. Nothing here is built.
Written 2026-09-26.

This document is not a chapter of the manual (it is not in `CHAPTERS` in
`packaging/docs/build-docs.sh`) and does not ship to customers. When a part
of it is built, that part moves into the manual chapters the way every other
change does.

## The vision does not change

FlowSight composes tried and true open-source tools. pf drops packets,
Unbound answers DNS, squid relays web traffic, Suricata detects threats,
nDPI names applications. FlowSight owns the layer above them: one policy
model, one store, one interface, and the reconciliation that keeps the
engines in step with what the operator declared (see ARCHITECTURE.md).

FlowSight bolts into deployments that already exist. It uses what is there,
changes as little as it can, and leaves everything the way it found it when
removed.

**FlowSight will always work with existing, robust open-source
implementations.** Nothing in this document changes that, and no later
work may.

## Two tracks

| | Track 1: FlowSight everywhere | Track 2: FlowSight-NG |
|---|---|---|
| **Priority** | Primary. Starts now. | Secondary. Starts once Track 1 has the seams it needs. |
| **What** | FlowSight on every possible installation: every common firewall, resolver, IDS and proxy; bare metal, Docker, Kubernetes, cloud, many sites. | FlowSight's own packet filter, IDS engine and proxy, as optional value-adds. |
| **How it composes** | Only with existing open-source tools and the operator's existing devices. | NG engines are *additional* providers beside the open-source ones, never instead of them. |
| **Delivery** | The FlowSight binary, packages, a container image, a Helm chart. | Separate engine images (containers) and signed packages, unlocked by licence. Upgraded independently of FlowSight. |
| **Needed to use FlowSight?** | Yes, it *is* FlowSight. | Never. |

FlowSight-NG is the name of the engine line. The product the customer runs
is still FlowSight; NG engines appear in it as providers they can choose.

## Rules

The CLAUDE.md engineering rules hold everywhere in both tracks:

- Nothing enforces before the operator turns enforcement on. The installer
  never turns it on.
- Every apply validates with the backend's own checker, keeps a backup and
  reverts on rejection. That includes the installer's changes to other
  systems.
- Interception never fails closed.
- Native, compiled, no scripts in the data path; new function arrives as a
  module behind the module contract.
- Tier gating through `core.Needs`, `ModuleInfo.Tier` and friends.
- No cloud dependency.

This design adds rules of its own:

1. **Open-source providers are first-class, forever.** Each one is tested on
   every release, gets new features at the same time as any NG engine can
   use them, and is never deprecated in favour of an NG engine.
2. **FlowSight never needs NG.** Every feature of FlowSight works with the
   open-source providers alone. An NG engine may do something *better*
   (faster, lighter, more accurate), and may do something *extra* that is
   sold as such, but it may not be the only way to get a FlowSight feature.
3. **Nothing switches by itself.** An upgrade, a licence change or a new
   engine never replaces a working backend. The operator chooses, and
   switching back is one action.
4. **Better or it does not ship.** An NG engine ships only when it beats the
   open-source provider it sits beside on a published, repeatable measure
   (resource use, accuracy, latency, ease of deployment) on the test bed.
5. **Bolt in, don't take over.** FlowSight changes only objects it created
   and named (anchors, includes, address lists called `flowsight-*`). It
   never edits the operator's own rules or configuration, and it installs
   nothing on the operator's firewall they did not ask for.

## Where we are

Facts from the code today:

- **Platform detection.** `core.DetectPlatform` (`internal/core/platform.go`)
  picks `opnsense`, `freebsd`, `linux` or `darwin` from what is on disk.
  Every backend path lives in the `Platform` struct and can be overridden
  under `paths`.
- **Providers.** `core.Provider` (`Compile / Current / Apply`,
  `internal/core/module.go`) is how policy reaches a backend. Unbound, squid
  and pf are providers already.
- **Enforcement without an inline engine.** `appcontrol` takes nDPI's
  verdict from ntopng and puts the far end into a pf table. This is the
  compose-don't-reimplement principle working.
- **First-run detection.** The `setup` module detects interfaces, backend
  binaries, the default gateway, Pi-hole and Proxmox, and tests those
  connections.
- **Installers.** `install.sh` (FreeBSD, Linux), the OPNsense plugin
  package, `.deb` and `.rpm`. No container image, no Helm chart.
- **External integrations.** Proxmox, Pi-hole, ntopng, NetFlow/IPFIX
  ingestion. No firewall or switch vendor APIs.
- **What limits reach today.** pf is called directly from seven modules
  (so Linux gateways get no web or application enforcement), and a few
  places assume OPNsense's configd and `config.xml`.

# Track 1: FlowSight everywhere

## Roles and providers

Today each module talks to its backend directly. Track 1 gives each job a
contract, so that any tool which can do the job can be a provider for it.
This is what lets FlowSight bolt into whatever a site already runs, and it
is also the seam Track 2 will use later.

| Role | Job | Providers today | Open-source providers to add |
|---|---|---|---|
| **Source** | Get traffic metadata in | pflog, tcpdump, ntopng REST, NetFlow/IPFIX, Suricata EVE, Unbound and Pi-hole logs | sFlow, Zeek logs, conntrack, nflog, AdGuard Home and dnsmasq logs, cloud flow logs |
| **Classifier** | Name the device, user and application of a flow | nDPI through ntopng | Zeek (protocol and SNI), Suricata app-layer fields |
| **Enforcer** | Hold L3/L4 verdicts (address and port sets) | pf tables and anchors | nftables sets (on the roadmap already); firewall APIs (see Integrations) |
| **Interceptor** | Terminate or peek web and TLS sessions | squid + ICAP | Explicit-proxy mode for squid (containers and cloud) |
| **Detector** | Turn traffic into findings | Suricata, FlowSight's own `baseline` | Snort 3, CrowdSec decisions |
| **Resolver** | DNS policy | Unbound, dnsmasq, Pi-hole | AdGuard Home, Technitium |

The candidates in the right-hand column are there to show direction.
Each one earns its place by how many real deployments it unlocks.

The policy document does not change. It compiles to whatever providers the
site has. Each provider declares `Capabilities()`, and the UI and API show,
per policy, what this site can enforce and what it can only observe. A
policy that asks for something no provider here can do is flagged when it
is saved.

A sketch of the new contracts, in the style of `core.Provider`:

```go
// Enforcer holds verdicts in address sets the firewall's policy provider
// declared. Implemented in internal/core/enforce.go.
type Enforcer interface {
	Name() string                                // "pf", "nftables", ...
	Capabilities() []string                      // "set.v4", "set.v6", "kill.states", ...
	Available() bool
	ReplaceSet(set string, addrs []string) error
	AddToSet(set string, addrs []string) error
	KillStates(src, dst string) error
	// Still to come, with the redirect work:
	// Declare(spec EnforceSpec) (string, error) // validate, back up, apply, revert on rejection
	// Detach() error                            // fail open: remove every redirect and drop rule we own
}

// StateReader reads live connections, described by who opened them.
// Implemented in internal/core/enforce.go.
type StateReader interface {
	Name() string
	Available() bool
	States() ([]ConnState, error)
}

// RuleReader reads the active ruleset with its counters, in the backend's
// own syntax. Implemented in internal/core/enforce.go.
type RuleReader interface {
	Name() string
	Syntax() string // "pf", "nft", ...
	Available() bool
	Rules() ([]Rule, error)
	CountersSince() time.Time // when the counters started; zero if unknown
}

// Classifier names flows. It never decides; policy does. Not built yet.
type Classifier interface {
	Name() string
	Subscribe(func([]ClassifiedFlow))
}
```

The pf code in `firewall`, `egress`, `inspect`, `qos` and `rulehygiene`
moves behind `Enforcer` and a small `StateReader` with no change in
behaviour. That refactor comes first, and it makes every later port cheap.

#### Phase 1 progress

| Step | State |
|---|---|
| `core.Enforcer` and `core.StateReader` (`internal/core/enforce.go`), provided over pf by the firewall module | Done |
| appcontrol fills sets and cuts connections through `core.Enforcer` | Done |
| egress reads connections through `core.StateReader`; pf's format is parsed in `firewall.ParseStates`, and the existing capture test still pins the direction of every counter | Done |
| inspect's state and rule views through `StateReader` and a new `core.RuleReader`; its pf parser merged into `firewall.ParseStates`, and its existing tests pass unchanged through the new path | Done |
| rulehygiene's ruleset reading through `RuleReader` (its own copy of the rule parser removed, the ruleset load time behind `CountersSince`); rule descriptions and change tracking follow the platform's `ConfigXML` path instead of checking for OPNsense | Done. The analysis itself still reads pf syntax; an nftables analyser is a later provider |
| Redirects as a backend-neutral spec, so web's interception rules stop being pf text (the `Declare` and `Detach` methods sketched above) | Next; touches interception, so it gets its own fail-open test first |
| qos's shaping (dummynet) behind a `Shaper` contract | Later |
| Classifier contract over ntopng | Later |

### Providers out of process

Some providers will not be in the same process, or the same machine:
Suricata in its own container, squid on another host, and later every NG
engine. The **provider protocol** is a small versioned API over a Unix
socket, or mutual TLS across hosts, that carries the role contracts above.
An out-of-process provider looks to FlowSight exactly like an in-process
one. The protocol is built in Track 1 because Track 1 needs it for
containerised open-source backends. Track 2 then uses it as it is.

## Positions

Where FlowSight sits decides what it can do. The installer works this out;
the operator only confirms it.

| Position | What it is | Can observe | Can enforce |
|---|---|---|---|
| **In-path** | FlowSight runs on the device that routes the traffic | Everything | Everything its providers allow |
| **Adjacent** | Its own box or container, integrated with the firewall | What the firewall exports (flows, logs, DNS) and what is steered through FlowSight (DNS, proxy) | Through the firewall's API, plus the DNS and proxy policy FlowSight serves itself |
| **Off-path** | A mirror or SPAN port, or flow exports only | Everything mirrored or exported | Nothing inline; DNS and proxy policy only for clients that use them |
| **Hub** | A tunnel concentrator (WireGuard) that sites or clients route through | Everything in the tunnel | Everything in the tunnel |

The same binary runs in every position. Position is a setting the installer
proposes, not a separate build. Adjacent and off-path are what "bolt in"
means for sites where the operator will not or cannot touch the firewall.

## Deployment shapes

| Shape | Typical position | Notes |
|---|---|---|
| **On the firewall** (OPNsense, pfSense, Linux gateway) | In-path | Today's product. pfSense is planned separately; Linux needs the nftables provider. |
| **Bare metal or VM** | Adjacent or off-path | Pairs with an integration. A second NIC on a mirror port gives full visibility. |
| **Docker, one container** | Adjacent; in-path on a Linux host with host networking | Without `--network host` and `NET_ADMIN` it runs adjacent: DNS, proxy, flow ingest, integrations. The installer says which it got and what that means. |
| **Kubernetes** | Adjacent (Deployment) or cluster egress gateway | Helm chart. Never touches the CNI's own rules. |
| **Cloud** | Hub, or egress gateway for a VPC or VNet | WireGuard hub for sites behind ISP routers; cloud security groups as an enforcer through their API. |
| **Fleet** | Any of the above, per site | Many instances under one controller. See "Fleet". |

## Integrations with firewalls and switches

An integration is a module that reads from the device that is in-path, and,
once enforcement is on, pushes verdicts to it. This is how FlowSight bolts
into a firewall it does not run on.

```go
type Integration interface {
	Name() string                                // "mikrotik", "unifi", "fortigate", "snmp", ...
	Probe(addr string) (Fingerprint, bool)       // identify without credentials where possible
	Capabilities() []string                      // "read.leases", "read.arp", "read.flows", "enforce.addrlist", ...
	Read(ctx context.Context) (Inventory, error) // devices, leases, ARP/MAC tables, rules, interfaces
	Enforcer() Enforcer                          // nil when read-only
}
```

The first adapters, by how many home and SMB networks they cover:

| Adapter | Reads | Enforces |
|---|---|---|
| OPNsense, pfSense API (FlowSight adjacent) | Leases, ARP, aliases, rules | Aliases |
| Linux over SSH | Leases, neighbours, conntrack | nft sets in a FlowSight-owned table |
| MikroTik RouterOS API | Leases, ARP, bridge hosts, connections | Address lists |
| UniFi controller API | Clients, devices, DPI summaries | Firewall groups, where the controller allows |
| SNMP and LLDP (any managed switch) | MAC and ARP tables, port per MAC, neighbours | Nothing. Identity only: which port a device is on |
| NetFlow, IPFIX, sFlow (any router) | Flows | Nothing |
| FortiGate, Palo Alto, Sophos, Meraki | Logs, flows | An external dynamic list FlowSight serves for the firewall to pull, or address groups |

An external dynamic list needs no write access to the firewall at all, which
makes it the safest route on any vendor that supports it. Where it exists,
it is preferred.

Every enforcing adapter follows the apply rule and rule 5 above: it changes
only objects FlowSight created and named, validates, keeps the previous
state and reverts on rejection.

## The installer

### One entry point, thin wrappers

The installer is the binary: `flowsightd install`. Every channel is a thin
wrapper that fetches the right binary and calls it.

| Channel | Wrapper |
|---|---|
| Shell | `install.sh`, as today |
| OPNsense, pfSense | The package's post-install hook |
| Debian, RPM, Alpine, OpenWrt | The package's post-install hook |
| Docker | The image's entrypoint runs detection on first start |
| Kubernetes | Helm chart; detection runs in an init step, with chart values as answers |
| Cloud | A cloud-init snippet and a Terraform module that pass a plan file |

Detection exists once, in Go, is tested like the rest of the daemon, and
behaves the same everywhere.

### Detect, discover, plan, confirm, apply, verify

1. **Detect the host.** Local facts only; nothing leaves the box.
   - OS and distribution: `opnsense-version`, `/etc/platform` (pfSense),
     `/etc/openwrt_release`, `/etc/os-release`, VyOS markers.
   - Container or not: `/.dockerenv`, `/run/.containerenv`, cgroup,
     `KUBERNETES_SERVICE_HOST` and a service-account token.
   - Hypervisor and cloud: DMI (`/sys/class/dmi/id`) first; the cloud
     metadata endpoint only when DMI says a cloud, never a blind probe.
   - Capabilities: `/dev/pf`, nft, kernel version, `NET_ADMIN`, free disk
     and memory, architecture.
   - Backends present: Unbound, dnsmasq, Pi-hole, AdGuard Home, squid,
     Suricata, ntopng, Zeek. **Whatever is already there is what FlowSight
     uses.** The installer proposes adding a backend only when a feature the
     operator asked for has no provider on the site.
   - Network position: does this host route? Is any interface receiving
     other hosts' traffic (a mirror port)?
2. **Discover neighbours.** Only the default gateway, the resolvers in use
   and hosts the operator names. There is no network sweep unless the
   operator asks for one (the existing `scan` module, opt-in). Each
   integration's `Probe` fingerprints without credentials (TLS certificate,
   HTTP title, SSH banner, LLDP, mDNS) and proposes an adapter.
3. **Plan.** Write the plan: position, providers per role, integrations,
   what each kind of policy can do here, and the questions still open. The
   plan is a file (JSON, like `flowsight.json`) and the single source of
   what the installer will do.
4. **Confirm.** Show the plan in plain words. Ask only what detection could
   not answer. Usually that is credentials for an integration, requested
   with the narrowest API role that adapter needs.
5. **Apply.** Install the service, write the config, set up integrations
   read-only. Every change to another system follows the backup and revert
   rule. Enforcement stays off.
6. **Verify.** Run each provider's own health check (the anchor check in
   `firewall` is today's example). Print what works, what is degraded and
   why, and the address of the UI.

Unattended installs pass a finished plan (`flowsightd install -plan
site.json`). The Helm chart, Terraform and fleet enrolment all use that
option, and it takes the same file an interactive install writes, so a
site installed by hand once can be copied.

`flowsightd install -dry-run` prints the plan and changes nothing.
`flowsightd uninstall` restores every backup the install took and removes
every object FlowSight created on other systems.

## Fleet

For many sites, many clouds, many countries.

- **Controller and agents are the same binary.** A controller is a
  `flowsightd` with the `fleet` module in controller role.
- **Agents dial out** to the controller over mutual TLS, enrolled with a
  one-time token carried in the plan file. No inbound port opens at a site.
- **Policy flows down**, versioned, with per-site and per-region overrides.
  Each agent compiles against *its own* providers (one site on pf and
  Suricata, another on MikroTik and Zeek, another with an NG engine), applies
  with the validate, backup and revert rule, and reports what applied and
  what could not.
- **Data stays at the site** by default. The controller receives summaries
  and findings and fetches detail on demand. A company can run one
  controller per region so that data about people in one jurisdiction stays
  in it.
- **The customer runs the controller.** There is no FlowSight-hosted
  service, so the "no cloud dependency" rule holds.
- **Gateway failover stays out of scope**, per ROADMAP.md. An agent keeps
  enforcing its last good policy while the controller is unreachable.

## Packaging and architectures

| Artefact | Architectures |
|---|---|
| Static binary | amd64, arm64 (today), armv7, riscv64 |
| OPNsense, pfSense packages | amd64, arm64 |
| `.deb`, `.rpm` | amd64, arm64 |
| `.apk` (Alpine), `.ipk` (OpenWrt) | amd64, arm64, armv7 |
| OCI image (multi-arch, distroless) | amd64, arm64, armv7 |
| Helm chart, Terraform module, cloud-init snippet | n/a |

Go build tags make the UI and each integration optional, so small targets
get small builds. Today's binary is 22 MB; an OpenWrt build with DNS and one
integration has to be a fraction of that. CI enforces a size budget per
build.

# Track 2: FlowSight-NG

## What NG is

FlowSight-NG engines are FlowSight's own implementations of three roles:

| NG engine | Role | Sits beside (never replaces) |
|---|---|---|
| **NG Filter** | Enforcer | pf, nftables |
| **NG Inspect** (IDS and application classification) | Detector and Classifier | Suricata, Snort, nDPI, Zeek |
| **NG Proxy** | Interceptor | squid |

Each is a separate program speaking the provider protocol from Track 1. To
FlowSight it is one more provider with its own `Capabilities()`. Every
FlowSight feature works without NG (rule 2). NG exists to be better where
it can be, and to offer paid extras beyond that baseline.

## Delivery: containers and licence

- **Engine images.** Each engine ships as a signed OCI image, versioned and
  upgraded on its own schedule, independent of FlowSight's releases.
  Upgrading an engine is pulling a new image; rolling back is running the
  previous one.
- **Where there is no container runtime** (OPNsense and pfSense today), the
  same engine ships as a signed package, or runs on an adjacent container
  host and reaches FlowSight over the provider protocol with mutual TLS.
- **Signing.** Images and packages are signed. FlowSight verifies the
  signature before it will register an engine, with the same release key
  it already uses (`packaging/release/signing.pub`).
- **Licence.** NG engines are entitlements in the licence (for example
  `ng.filter`, `ng.inspect`, `ng.proxy`), in the `internal/licensing/tiers.go`
  catalogue like every other gated feature. A licence upgrade makes an
  engine available in the UI; it does not install or enable anything by
  itself (rule 3). The engine checks the entitlement too, against the
  licence key already baked into release builds.
- **Lapse.** When an NG entitlement lapses, FlowSight switches that role
  back to the open-source provider the site had before and says so. It does
  not leave a role with no provider.

## Adoption: shadow, compare, switch

The operator can see that an engine is better before trusting it:

1. **Shadow.** The NG engine runs beside the existing provider and observes
   only. NG Inspect sees the same traffic as Suricata or nDPI; NG Filter
   computes its verdicts without enforcing them.
2. **Compare.** FlowSight shows the two side by side: alerts each raised,
   applications each named, verdicts that would differ, CPU and memory each
   used.
3. **Switch.** The operator makes the NG engine the provider for that role,
   for the whole site or for one policy group first. Switching back is one
   action, and FlowSight keeps the previous provider's configuration so it
   comes back as it was.

NG Proxy cannot run in shadow, because two interceptors on one box is ruled
out (`internal/modules/mitm/icap.go` records why). It is tried on a canary
group of clients instead, with the existing proxy serving everyone else.

## Engine designs, in the order they would be built

### NG Proxy

- Explicit mode (PAC, WPAD) and transparent mode. SNI peek and splice by
  default; TLS inspection with the existing CA, only for policies that ask
  for it and only with the `tls.inspect` licence.
- Inspection runs in-process, with no ICAP hop.
- Where it should be better: runs where squid is hard to run (containers,
  Kubernetes, cloud, pfSense), lighter on small hardware, and one
  certificate path instead of squid's plus FlowSight's.
- **Fails open** as interception does today: redirects exist only while the
  proxy answers, and the enforcer removes them when the health check fails.

### NG Inspect

- Classification from TLS SNI, QUIC Initial SNI, JA4 fingerprints, HTTP
  Host and resolver answers, with a signature catalogue for common
  applications; detection from threat-intel feeds, JA4 reputation,
  beaconing and DNS tunnelling.
- Pure Go, so it builds for every architecture.
- Passive: it reads from a Source and publishes to the flow bus. It is never
  in the forwarding path, so a crash loses naming and detection, not
  traffic.
- It does not reimplement Suricata's signature language. Sites that want
  signatures keep Suricata or Snort; NG Inspect is sold on what it adds
  (lighter hardware, behaviour detection, JA4), not as a replacement.
- The application catalogue is data, versioned and shipped like the
  category lists. It is this engine's long-term cost.

### NG Filter

- Linux: address and port sets as eBPF maps, checked by a small XDP or TC
  program the engine loads and owns. Where it should be better: works the
  same on every distribution, and does not collide with vendor-managed
  rulesets (VyOS, UniFi, Firewalla) or a Kubernetes CNI.
- **Fails open**: the program passes all traffic when the engine stops
  updating a heartbeat in a map, and stopping the engine detaches it.
- FreeBSD, OPNsense and pfSense keep pf. There is nothing better to offer
  there.
- An inline engine that blocks the first packet of a denied application
  (netmap, AF_XDP, NFQUEUE) is not proposed. It would need its own bypass
  design and is only worth considering if customers ask for it.

## ROADMAP.md

ROADMAP.md lists "reimplementing DPI" and "a packet engine of our own in the
forwarding path" as non-goals. Both stay true for FlowSight itself: FlowSight
never needs either. If this design is approved, ROADMAP.md says so
explicitly and names FlowSight-NG as a separate, optional engine line with
its own section. ARCHITECTURE.md's "compose, don't reimplement" principle
stands unchanged, with a paragraph on how NG engines plug in as providers.

# Both tracks

## Security

Changes that would need `docs/SECURITY.md` updated when built:

- **Integration credentials** are stored encrypted at rest, scoped to the
  narrowest API role, never logged, and shown only as "set" in the UI.
- **The installer probes the network**, but only the gateway, the resolvers
  and hosts the operator names, and it says so first.
- **The provider protocol** is a Unix socket locally, mutual TLS between
  hosts, and a signature check before any engine registers.
- **NG parsers sit on untrusted traffic.** Go's memory safety helps, and the
  NG Proxy and NG Inspect parsers are fuzzed in CI from the first commit.
- **Fleet trust**: mutual TLS, one-use enrolment tokens, certificate
  rotation, revocation from the controller.
- **Containers** run with only the capabilities the chosen position needs,
  and the installer states which it was given.

## Licensing

A proposal. `docs/LICENSING.md` and `internal/licensing/tiers.go` change
together when it is decided.

| Capability | Proposed tier |
|---|---|
| Installer, detection, every open-source provider | Community |
| Read-only integrations (flows, leases, SNMP identity) | Community |
| Enforcing integrations | Pro |
| NG engines (each its own entitlement) | Pro |
| Fleet controller, regional controllers | Business |

## Phases

Each phase ships on its own, is tested on the PVE2 test bed before anything
live, and moves its part of this document into the manual.

**Track 1** (primary):

| Phase | Delivers | Done when |
|---|---|---|
| **1. Seams** | `Enforcer`, `StateReader`, `Classifier` contracts; pf and ntopng moved behind them. No behaviour change. | The full e2e suite passes unchanged on OPNsense and FreeBSD. |
| **2. Installer** | `flowsightd install` (detect, plan, confirm, apply, verify, `-dry-run`, `-plan`, `uninstall`) for the platforms supported today; `install.sh` and the packages call it. | A fresh OPNsense, FreeBSD and Debian box each install with no questions beyond confirmation. |
| **3. Containers** | OCI image, Helm chart, adjacent position; the provider protocol, with Suricata in its own container as the first out-of-process provider. | Docker and a small k3s cluster on the test bed run it; the installer reports the position correctly. |
| **4. Linux and pfSense** | nftables provider; the pfSense port (planned separately). | In-path enforcement on a plain Linux gateway and on pfSense. |
| **5. Integrations** | MikroTik, UniFi, SNMP and LLDP, external dynamic lists, OPNsense/pfSense API adapters. | Adjacent installs next to each device on the test bed read, and, with enforcement on, enforce. |
| **6. More open-source providers** | Chosen from the candidates above by demand (Zeek, AdGuard Home, Snort 3, CrowdSec, ...). | Each passes the provider contract tests. |
| **7. Fleet** | Controller, agents, enrolment, regional data. | Three sites on the test bed under one controller, one in another "region". |
| **8. Cloud** | WireGuard hub, egress gateway, cloud flow-log sources, Terraform. | A hub in one cloud serving a test site. |

**Track 2** (secondary; can start after Track 1 phase 3, when the provider
protocol exists):

| Phase | Delivers | Done when |
|---|---|---|
| **NG-1. Proxy** | NG Proxy image, canary adoption. | Beats squid on the agreed measures on the test bed; the fail-open test passes. |
| **NG-2. Inspect** | NG Inspect image, shadow and compare. | Agrees with nDPI on naming above an agreed threshold on a recorded corpus, and adds detections Suricata does not raise. |
| **NG-3. Filter** | NG Filter image (Linux), shadow and compare. | Verdicts match the nftables provider on the test bed; the heartbeat fail-open test passes. |

## Testing

The test bed grows with the phases: a pfSense VM, a Debian gateway VM, a
Docker host, a k3s cluster, a MikroTik CHR VM, a managed switch or SNMP
simulator, and a second "region". Every provider, open-source or NG, runs
the same contract tests (declare, apply, reject and revert, detach and fail
open). Every release runs the whole suite against the open-source providers,
so rule 1 is checked by CI, not left to memory.

## Risks

- **The support matrix grows fast.** Supported configurations are listed
  explicitly; everything else is "best effort" until it is on the test bed.
- **Other vendors' APIs change.** External dynamic lists are the most stable
  enforcement route and are preferred where they exist.
- **NG could drain effort from Track 1.** The phase gate (NG starts after
  Track 1 phase 3) and rule 4 (better or it does not ship) are there to
  stop that.
- **The NG Inspect catalogue is a product in itself.** Keeping nDPI and
  Suricata as first-class providers means FlowSight is never worse than
  today while it catches up.
- **Encrypted Client Hello and QUIC** keep eroding what any classifier can
  see, open-source or NG.

## Decisions needed from the product owner

1. Approve the two-track shape and the five rules above.
2. The tier for each capability, and whether NG engines are one entitlement
   or three.
3. Whether Track 1 phases 1 to 3 go ahead as the first step.
4. Which integrations and which extra open-source providers come first,
   from what customers actually run.
5. The ROADMAP.md and ARCHITECTURE.md wording for FlowSight-NG, once
   approved.
6. The version at which the installer and container shapes ship (per
   CLAUDE.md, a version increment needs your approval).
