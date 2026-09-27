# How-tos

Task-first guides for common FlowSight operations, organized by what you want to do.

Each guide takes 5–15 minutes the first time. They name exact pages and buttons so you can follow along in your own FlowSight. Where a tier is needed (Pro, Business), the guide says so.

## Getting started

Start here after you install FlowSight. The first hour covers the setup wizard, enabling traffic capture, turning on interception, and understanding the overview.

- [Set up traffic sources and interception](getting-started.md) — run the setup wizard, add traffic sources, enable web interception, set up TLS CA
- [Find the first hour of activity](first-look.md) — read the Overview dashboard, set the time window, understand the key metrics

## Inventory and discovery

Understand what is on your network: devices, zones, and how to identify unknowns.

- [See what one device is talking to](device-traffic.md) — find a device on the Devices or IP Addresses page, open its host page, review sessions and applications
- [Fix "my phone can't browse": device advisories](device-advisories.md) — what each advisory means, where it appears, and the one-click Pi-hole fixes
- [Give a device a DNS name](local-names.md) — name a device and add it to forward and reverse DNS on the gateway and your Pi-holes, following it when its address changes
- [Use Pi-hole with FlowSight](pihole.md) — connect a Pi-hole, let FlowSight change its settings, pause blocking, edit allow and deny lists
- [Identify an unknown device](identify-device.md) — scan the network for device fingerprints, assign it to a zone, view its details and history
- [Map your Proxmox guests](proxmox-guests.md) — **Pro** — inventory Proxmox VMs and containers, view the dependency map, add notes about guests

## Monitoring and analysis

Watch traffic and understand where it goes.

- [Ask FlowSight in plain English](ask.md) — use the Monitor > Ask page to query your network in English; backed by Claude or your own Claude Code setup
- [Trace a destination on the Map](trace-map.md) — find a host or application, follow the route to its server, check hop latency and anycast status
- [See where a policy's traffic goes](policy-matches.md) — create a policy, then open the Matches page to see real sessions and firewall logs
- [See what your IoT devices send abroad, and block it](iot-abroad.md) — watch for outbound traffic to other countries, understand anycast, and write a country-blocking policy
- [Watch data transfers and prevent them](dlp-watch.md) — mark a group or application to watch, identify large transfers, stop them in flight

## Policy and enforcement

Write policies, schedule enforcement, and inspect traffic.

- [Block apps and categories on a schedule](policy-schedule.md) — write a policy with time-based rules, apply it to a group, set schedules and exceptions
- [TLS inspection for one device with a bypass list](tls-inspect-device.md) — enable TLS inspection for a single device, add domains to the inspection bypass list
- [Capture and inspect packets](packet-capture.md) — use Packet Inspection to start a capture for a device, download the pcap, or view the live session table
- [Understand blocked traffic with the Firewall Analysis Engine](firewall-analysis.md) — read the FAE report, understand why traffic was blocked, track blocked destinations

## Reporting and alerting

Proactive monitoring and proof.

- [Set up alerting](alerting.md) — create alert channels (email, webhook, syslog), write alert rules, test delivery, set quiet hours
- [Create scheduled reports](reports-schedule.md) — define report templates with sections, schedule them to run, receive PDF or JSON formats
- [Place devices in your physical space](device-location.md) — import a floor plan scan, place devices on it by hand, view the dependency map

## Automation and integration

Read data and automate through the API.

- [Use FlowSight from Claude Code and the Agent SDK](claude-code.md) — expose FlowSight as an MCP server, call routes from Claude Code agents and Python/TypeScript scripts
- [Automate through the API](api-automation.md) — use the API explorer, create tokens, examine the audit log, run curl examples
- [Add a switch or another router as a flow source](flow-sources.md)
- [Know when a device does something new](anomalies.md)
