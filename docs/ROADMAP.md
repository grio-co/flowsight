# Roadmap

## Done

- Native daemon: one static Go binary, embedded SQLite store, embedded UI,
  module registry, scheduler, self-describing API.
- Visibility: ntopng flows and applications, hosts with names and vendors,
  web sessions with server names, DNS log, TLS sessions and certificates,
  Suricata alerts, per-host reports, rollups for a year of history.
- Policy: document model with groups, schedules, exclusions; compiler with
  plan, diff, apply and continuous reconciliation; DNS (RPZ), web (SNI and
  HTTP), application (pf tables from nDPI), ports and internet providers;
  safe search and YouTube restriction; monitor mode.
- TLS transparency: generated inspection CA, per-policy inspection with
  bypass lists, certificate inventory and findings.
- Firewall Analysis Engine (FAE): live counters, shadowed and permissive rules, change
  tracking with the user who changed it, risk score.
- Enrolment: device identification from DHCP, zones, placement and isolation
  in monitor-first mode, captive self-identification page.
- Operations: reports and CSV export, scheduled email reports, alerting to
  email, webhooks, Discord, Slack and ntfy, audit log, signed in-place
  updates with roll back, OTLP export.
- OPNsense plugin package built with pkg alone; Debian package; installer for
  other systems.

## Next

- Content controls inside inspected sessions: URL-path rules, file-type and
  size limits, keyword lists (squid ACLs on bumped traffic).
- GeoIP: country tables from an open database for `deny.countries` and for
  destination country in reports.
- User identity: RADIUS accounting listener and LDAP/AD group lookup so
  policies can target people, not only devices.
- nftables: application, port and internet blocking and zone isolation are
  done; still to come on Linux are web interception (the proxy must listen
  on the LAN side), country blocking and traffic shaping (tc).
- Quotas: per-device or per-group bandwidth and time budgets, enforced
  through pf tables and schedules.
- Threat intelligence: IP reputation feeds into pf tables (`threat.block`),
  Suricata rule management from the UI.
- Multi-gateway: one UI over several flowsightd instances.
- Licensing and support tiers, built on the module tier field that already
  exists, after the product is stable.

## Non-goals

- Reimplementing DPI. nDPI is better than anything this project would write.
- A packet engine of our own in the forwarding path.
- A cloud dependency of any kind.
- **Multi-gateway high availability (HA)**: FlowSight is designed as a single gateway appliance. If you need redundancy, run two independent instances with separate policy documents and alert channels, or use CARP/VRRP at the appliance level (e.g., on OPNsense). FlowSight does not coordinate policy, state, or flow data across instances.
- **CARP or VRRP failover**: High-availability protocols belong in the base firewall OS (OPNsense, pfSense, Linux). FlowSight consumes the gateway's state (pf rules, DNS responses); it does not generate them and cannot drive failover decisions. For HA, configure CARP/VRRP in your firewall, then run a separate FlowSight instance on each member.

## Licensing (done 2026-09-20)

- Tiers Community / Pro / Business with a feature catalogue, limits and soft expiry (`docs/LICENSING.md`).
- Online activation with seat counting, lease refresh and revocation; offline signed license files.
- License server `flowsight-licensed` (SQLite, admin API and CLI).
- Follow-ups: Business features that are gated but not built yet (directory identity, multiple administrators) and a shop/billing hook on the admin API.

## Acting on what is seen, in time to matter

Live egress monitoring is the first stage of a larger idea: noticing
something while it is happening is only useful if something can be done
about it before it finishes.

Two seams exist for that and neither is filled in yet.

The egress module publishes every threshold event to subscribers, so a
module that decides what to do about a transfer never has to live inside the
module that measures one. Today the only action is an operator pressing
**Stop**.

Stateful Packet Inspection is the other. ICAP is a synchronous gate: the proxy sends
each decrypted request and *waits* for FlowSight's answer before forwarding
it. FlowSight answers "no modification" every time today, but the same point
in the exchange is where a request could be refused. That is what would let a
rule stop a destructive API call before it reaches the service, rather than
recording that it was made. The transport is already in place; the rule
engine and the decision to deny are not, and neither should be added without
a way to see exactly what would have been blocked before anything is.
