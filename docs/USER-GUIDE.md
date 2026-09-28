# User guide

Every page of FlowSight, in the order of the menu. The range buttons at the
top (1h, 6h, 24h, 7d, 30d) set the window for every page that shows
history; the search box takes an address (opens the host), a domain (opens
its sessions) or free text.

Inside the OPNsense GUI there is one scrollbar, the page's own: tables grow
with their rows instead of scrolling inside a box. Standalone, a long table
keeps its own scroll area.

**Long tables** show the first hundred rows with the count beneath them,
*Show 100 more* and *Show all*, and an **Infinite scroll** checkbox that
loads further rows as you reach the bottom. The choice is remembered for
every table in this browser.

**Refreshing.** Pages with live data refresh themselves every 10 to 60
seconds. A refresh keeps your place: the scroll position, each table's own
scroll and the column you sorted by all survive it, and it is held back
entirely while a dialog is open, a field has focus or text is selected. The
**pause button** next to the range buttons stops it altogether for this
browser; press it again to resume and refresh at once.

Inside the OPNsense GUI the pages are reached from the **FlowSight**
section of OPNsense's own left-hand menu; the app shows no sidebar of its
own there, only the page, a top bar and a one-line footer with health,
version and attribution. Standalone (Linux, or the daemon opened directly)
the app has its own sidebar with the same entries.

**Addresses.** Wherever a host would be shown as a bare address (a
destination no DNS answer named, a client without a lease name), FlowSight
can decorate it with its reverse-DNS name and, for public addresses, a
country flag. Both are switches under *Settings › enrich*, off by default;
turn on *Reverse DNS names* and *Country lookup* to have them. Names are
looked up through the gateway's own resolver and cached; countries come
from a country database downloaded into the data directory (DB-IP Lite
unless you point it at another MaxMind-format file) and refreshed monthly.
While the DB-IP database is in use the menu footer carries its attribution.

**Theme.** *Settings › ui › Theme* is *auto* by default: inside the OPNsense
GUI the pages follow the OPNsense theme (light, dark, or the GUI's own
automatic mode), and on a standalone installation they follow the operating
system preference. Choose *light* or *dark* to pin it.

Pages marked **Pro** or **Business** need that license tier; below it they
show a card that explains what the tier adds and links to the License page.
A lock next to a menu entry means the same.

## Finding your way

The menu has four areas, by what you are doing. **Monitor** is watching
traffic: Overview, Sessions, Applications, Web, DNS and the Map. **Inventory**
is what is on the network: IP Addresses, Devices and Zones. **Protect** is
what is allowed: Policies, Priority, Groups & Schedules, Categories, Deep
inspection, TLS, Threats, DLP and Firewall Analysis Engine (FAE). **Administration**
is FlowSight itself: Reports, Alerting, API, Updates, License, Status and
Settings. The chapters below follow the same order.

**SmartSearch.** The box at the top of every page (press `/` to jump to it)
does two things as you type:

- **It filters the page you are on.** Every table keeps only its matching
  rows, counted across all its rows rather than only the ones on screen;
  every list keeps its matching items; a panel with nothing matching folds
  away; matches are highlighted. A panel whose title matches is shown whole,
  and so is a page that is itself about what you searched for (the iPhone's
  device page, when you search "iphone"). A bar under the header says what
  is filtered and how many panels are hidden. Every word must match, so
  "nintendo switch" is narrower than "nintendo".
- **It searches the whole of FlowSight.** The dropdown lists this page's
  matching panels first (click one to scroll to it), then devices, device
  names in DNS, domains looked up or visited in the last day, applications,
  open findings, policies and groups, settings and pages. Each result links
  to every page that shows the same thing: a device to its page, sessions
  and DNS lookups; a domain to its DNS lookups, sessions and web requests;
  an application to its page, sessions and control.

**On the Map** the search filters the floating panels in place (the key,
which switches what is drawn, stays), each tab of the data drawer shows how
many matches it holds, and the drawing lights the routes to destinations
that match by address, name, city or country, and the routes through hops
that match by address, router name or place; the rest fade, as when a hop is
picked. The Destinations tab keeps the destinations whose routes were lit
even when their own names do not match. A note floats over the map with the
count and *Clear search*; the map's own × clears it too. The Destinations
tab lists the busiest 400 destinations, so a lit route can lead somewhere
not in it.

The search stays on as you follow those links, so the next page opens
already narrowed to the same thing, and it survives a reload. Arrow keys move
through the dropdown and Enter opens the highlighted result; Enter on a bare
address opens that device. Esc closes the dropdown, and Esc again (or *Clear
search*) ends the search.

## Monitor

### Overview

Each row under *Top sites* carries a *map* link: the route, on the Map page,
to the endpoint that served the site (the one with a measured route where
there is one, else the busiest). A dashed link means the map has not traced
that endpoint yet; it will when it can.

The network at a glance for the window: throughput inbound and outbound
(shown separately, both in the figure and in the chart), active hosts,
sessions, applications, DNS queries, blocked requests. Charts of
throughput over time, one line each for inbound and outbound; the top hosts by traffic; the top applications; web
categories; the busiest DNS names; recent alerts and findings. Every item
links to its detail page.

**Needs attention** lists device advisories: problems a person notices on a
device ("Safari won't load", "No Internet on this Wi-Fi", "notifications
stopped") whose cause is a DNS answer rather than a threat. Each says what
the person sees, which resolver answered what for which names, and what to
do, with a button when a connected Pi-hole can apply the fix. **Devices
needing attention** lists every device with an open finding of any kind,
worst first; click one for its page. See the how-to
[Device advisories](howto/device-advisories.md).

#### Ask

A question in plain English, answered by a model that calls FlowSight's own
API as tools. The answer streams; under it a trail lists every tool call
("looked at Sessions for 192.168.1.115, last 60 minutes → 214 rows"), so
what the answer rests on is visible. Recent questions are kept in the store
with their trails and can be forgotten one by one. The page is disabled
until a provider is chosen under *Settings › assistant*; when one is on, a
banner says plainly that questions and the data the model asks for leave
the gateway for that provider. Two providers: **Anthropic** (the daemon runs
the agent loop against the Messages API) and **Claude Code** (the CLI on
the gateway, run headless with FlowSight attached as an MCP server; the
same harness the Agent SDK drives). Claude Code and the Agent SDK can also
use FlowSight directly, without this page: see the how-to.

## Sessions

Countries appear as two-letter codes throughout; hover one for the full
name.

The flow table: time, client, server, application (nDPI), server name (from
DNS or from the proxy once interception is on), protocol and port, bytes
each way, duration, verdict (observed or blocked and by which policy), TLS
version and SNI when known. Filter by host, domain, application or verdict.
Sessions come from ntopng every few seconds and from the proxy log.
The **Map** button at the end of a row opens the Map narrowed to that
session alone: the client device and the route to that destination, one
traceroute. Sessions between two local addresses have no button, since
there is no path across the internet to show.

**Domain provenance:** The server name comes from multiple sources: the client's
TLS SNI (most reliable), HTTP Host header, DNS query, or the flow probe's
reverse-DNS cache (least reliable, often wrong for shared servers like CDNs).
When the domain comes from the probe's cache, it appears muted with a tooltip
showing its source, so you can tell if it may not be authoritative.

**Where the far end is.** Each session's server shows its country; the
**Outside \<country\>** button keeps only sessions whose far end is abroad
(FlowSight learns your own country from its public address once *Country
lookup* is on under *Settings › enrich*), and a country pill narrows to that
country. The DLP page's **Leaving the country** card lists this per device.
There is a step-by-step guide in [See what your IoT devices send abroad, and block it](howto/iot-abroad.md).

**Findings say who, what, where and why.** Each open finding on the Overview, and on the Findings page, is read in columns: *Who* is the device (name, maker, address, hardware address, linking to its page); *What* is the title with the application, name, payload reading and volume behind it; *Where* is the far end with port, place, network and links to the Map and the sessions; *Why* is the rule that fired and the numbers that tripped it (days of history, what was known before, the beacon period, the threshold). Modules attach this structure when they raise a finding; a finding raised without it still shows its subject and sentence. When several devices share one finding (a pinned site, a certificate), *Who* names the latest and says how many others there were; *Why* may also list plain facts, such as how many times a site refused the inspection certificate, a certificate's issuer and dates, a firewall rule's counters, or the banner a scan read. Findings close by themselves when their condition stops: a pinned site that leaves the list, a certificate no longer seen for a week, a rule that starts matching, and a service that a later full or quick scan of the device, covering its port, finds closed.

### Applications

Applications ranked by activity: sessions first, then who did it. Each row
shows the number of sessions, how many hosts used the application and the
three that used it most (each a link to those sessions), when it was last
seen, blocked sessions, and the bytes as an aside rather than the ranking.
The Overview's top hosts, applications, categories and sites and the host
page's cards rank the same way: a backup moving a terabyte is not what the
household is doing. The catalogue used for policy (names and categories) is
the same one nDPI reports.

**One application, one page.** Click an application's name and its page answers what it is (a write-up: what it is for, the risk, common issues and what to look for, written for the common ones and taken from the category for the rest), its nDPI category and breed, who uses it, the names it talks to, where it goes (far ends with port, country, network and a way to the Map), ports and countries, how much and when, what policy says about it, and a *Block for…* action that opens a policy denying it. The category name is a link too: the category's page lists every application in it with the same detail and a *Block the category for…* action.

**The unknown, taken apart.** *Unknown* on the Applications page opens a catalogue of what nDPI could not name, grouped by signature: the name the device asked for (DNS or TLS server name), or failing that the network that announces the far end, with the port and protocol, so the row reads *TCP to apple.com on 5223 (push notifications)* rather than a bare count. Each row shows the devices, sessions, bytes and first and last seen. *Name* a signature and the pages use your name for it from then on.

**Watching and configuring are separate pages.** Monitor › Applications only watches. Protect › *Applications (L7)* is where application control is configured: which applications and nDPI categories are denied, for whom and when, the rule sets compiled from those policies with the addresses they currently hold, and recent blocks. *HOWTO: categories and applications* explains how an application is identified and how that differs from the web categories.

### Flow sources

Extend visibility beyond the gateway: switches, routers and other devices that export flows via NetFlow v5/v9, IPFIX, or sFlow v5 appear here. Each exporter shows the protocol, number of records and flows ingested, any drops (if templates timed out and data arrived without one), templates known (cached schema definitions per exporter) and when it last sent data. The help text shows the address and ports to point exporters at.

Flows from these sources are enriched the same way as gateway-observed flows and appear in the Sessions page, filterable by source. See the how-to guide: [Add a switch or another router as a flow source](howto/flow-sources.md).

### Web

Web activity from the proxy log: top sites, categories, blocked requests,
and the recent request log. Each row names the client, the site and, when
the proxy could see inside the request, the method, path and response code;
an inspected HTTPS request is marked *decrypted*, an uninspected one reads
*encrypted (not inspected)*. The **decrypted only** link above the table is
the view of everything TLS inspection has opened; combine it with a client
(`#web?decrypted=1&client=…`, or from a host page) to see one device. Empty
until interception is on. The proxy's own state (listening ports, workers,
last error) is under Settings › web.

### DNS

Resolver activity: queries over time, top names, top clients, response
codes, blocked names with the policy or list that blocked them. Records
come from the Unbound reply log and, when configured, from Pi-hole servers;
the *Via* column of the query log says which. If clients use a resolver
FlowSight does not read (a public resolver, DoH in a browser) those queries
are simply not seen.

**DNS over HTTPS.** A client that resolves through a provider over HTTPS
bypasses the network's resolver, and those lookups are invisible. Two things
help. With TLS inspection on for that device, FlowSight reads the request:
a client using the GET form puts the question in the URL, so the name is
recovered and appears here like any other lookup, marked *DoH provider* in
the *Via* column; a client using POST (Firefox and Chrome do) keeps the
question in the body, which the proxy log does not carry, so only the fact
of a DoH request to that provider is recorded. To get every name back, deny
the built-in **encrypted-dns** category in a policy: it holds the public DoH
endpoints and Firefox's canary name, which turns Firefox's own DoH off, so
clients fall back to the resolver where everything is visible.

**Pi-hole.** *Settings › pihole*: list the servers (`https://192.168.1.53`)
and give the app password (Pi-hole v6: Settings › Web interface / API ›
Configure app password; v5: the API token). FlowSight pulls the query log
every 30 seconds, going back 24 hours on first contact, deduplicates by
Pi-hole's query ids, and files each query under its client with the
verdict and list (gravity, regex, denylist, upstream blocked). Client
names Pi-hole knows are used for hosts FlowSight has no name for. Nothing is
written to the Pi-holes unless you change something under *Settings › dns ›
Pi-hole*.

**Monitor, not configure.** This page only watches. Resolver settings,
device names in DNS and Pi-hole configuration are on **Settings › dns**,
in three tabs: *Resolver*, *Device names* and, while a Pi-hole v6 server is
connected, *Pi-hole*. A link at the top of this page goes there.

**Device advisories** appear above the charts when a device keeps getting a
failing answer for a name it depends on (Private Relay, connectivity checks,
time, certificate checks, push, updates, sign-in protection), when a
device's lookups fail outright, or when an app keeps retrying one blocked
name. With a client filter only that client's are shown.
[Device advisories](howto/device-advisories.md) lists what is watched.

**Settings › dns › Device names.** Every device name FlowSight put in DNS, with what each
resolver answers for it forward and reverse right now; edit or remove them
there. See [Give a device a DNS name](howto/local-names.md).

**Settings › dns › Pi-hole.** While a Pi-hole v6 server is connected, this
tab shows the connected servers (version, blocking state,
whether FlowSight may change settings), *Pause* and *Resume* for blocking,
the allow and deny lists, and a curated set of settings in plain language,
each with what it does, FlowSight's recommendation and why, Pi-hole's own
description, and each server's value. Changing settings needs the Pi-hole's
*Permit app password to modify config* switch; the tab says so for a server
where it is off. Network binding (listening mode, interface, port) is view
only. Every change is recorded under *Status › Changes*. See
[Pi-hole with FlowSight](howto/pihole.md).

## Protect

### Threats

Suricata alerts from the EVE log: severity, signature, source and
destination, count over time, with the host page one click away. Requires
the IDS to be enabled in OPNsense; the module reports a finding when the
log is missing.

### Anomalies

Device behavior deviations detected by learning what is normal for each device
over a learning period (7 days by default, configurable). Once learning
completes, the module flags:

- **First-seen countries**: a device calling a country it has never contacted
  before (severity: high).
- **First-seen ports**: new protocol/port pairs (severity: medium).
- **First-seen destinations**: new IP addresses or domains, only for devices
  with small, stable destination sets (typical of IoT); (severity: medium).
- **Beaconing**: regular, timed connections with constant payload size,
  detected via coefficient of variation of inter-arrival times (severity: high).
  Useful for identifying C2 or vendor beacons that phone home.
- **DNS tunneling**: DNS abuse (high entropy query names, high NXDOMAIN rate)
  (severity: high). Often indicates exfiltration or DNS-based C2.

Each finding includes what the baseline was ("21 days of history had US, CA") 
and what was observed ("first time talked to IE"). Every finding is acknowledgeable
and can be used to filter the Sessions view. Device profiles show all known
countries, ports, destinations and activity patterns. Configuration options
tune the learning period, thresholds for beaconing regularity and DNS entropy,
and zone exclusions (devices in excluded zones like "guest" are never flagged).

Findings integrate with alerting rules under keys like `baseline.new_country`
and `baseline.beaconing` for automatic routing or suppression.

For details, see the [Anomalies how-to](howto/anomalies.md).

### TLS

Certificate transparency for the network.

- **Inspection CA** (Pro): create the FlowSight CA (EC P-256, generated on
  the box), download the certificate to install on devices, delete it.
  While a CA exists, policies may turn on inspection.
- **Versions and handling**: two proportion bars, one for the protocol
  version negotiated and one for what FlowSight did with the session
  (peeked, spliced, decrypted, terminated). Hover a segment for the count.
- **Certificates seen**: every server certificate observed by the proxy or
  the IDS, with subject, issuer, validity, key type, first and last seen,
  and the hosts that saw it. **Click any row for the whole certificate**:
  both distinguished names unabbreviated, the serial, the key, the validity
  with days remaining, the fingerprint and every subject alternative name.
  Findings flag expired, expiring, self-signed and weak certificates.
- **Where the details come from.** A proxy log names a certificate by its
  subject and issuer and nothing else, and a spliced session shows no
  certificate at all, so the validity, key and trust columns would be empty
  for most names. FlowSight fills them in: for server names it has seen and
  knows too little about, it opens a TLS connection from the firewall, reads
  what is served and records the whole record, including whether the chain
  verifies against the system roots. That runs every fifteen minutes, a few
  names at a time, and is *Settings › tls › Probe certificates*.
- **Sessions**: recent TLS sessions with SNI, version, bump mode.
- **Pinned sites**: names whose clients refuse the inspection certificate.
  A pinned client carries the certificate it expects and accepts no other,
  so no proxy can decrypt it; FlowSight recognises the refusal, relays the
  name untouched from then on so the site keeps working, and still records
  its server name, timing and volume. The card lists what was detected and
  what you added by hand, lets you add a name, and lets you put one back
  under inspection. The behaviour is *Settings › web › Relay pinned sites
  without inspecting*, on by default, with the number of refusals, the
  window and the retry interval beside it. Each pinned name is also an
  *info* finding naming the devices that were refused; the finding closes
  when the name leaves the list.

**Decrypting sessions, step by step.** Without a CA the proxy only peeks
at handshakes: you see server names, versions and certificates, never the
inside of a session. A device that no inspecting policy matches is never
shown the inspection certificate, with or without a CA: it receives each
server's own certificate, including one the firewall itself cannot verify,
and decides about it as it would without FlowSight. To decrypt selected
devices:

1. **TLS › Create inspection CA** (Pro). The key pair is generated on the
   firewall and never leaves it.
2. **Download the certificate** from the same card and install it as a
   trusted root on each device you intend to inspect. 
   
   - **Mac**: open the file in Keychain Access, System keychain, then set 
     the certificate's trust to *Always Trust*. Do this *before* step 4, 
     or every HTTPS connection from that device fails with a certificate warning.
   - **Linux containers and VMs** (on Proxmox): run the automated 
     installation script on your Proxmox nodes:
     ```
     ssh pve1 bash /root/install-fsca-all.sh
     ssh pve2 bash /root/install-fsca-all.sh
     ```
     This detects the OS of each running container and VM, installs the CA 
     into the appropriate system trust store (Debian/Ubuntu, RHEL/Fedora, 
     Alpine, Arch, openSUSE, FreeBSD), and verifies the installation. See 
     the script's output for per-guest results. **Limitations**: 
     Docker images inside containers are not reached (each has its own bundle); 
     stopped containers are skipped; Windows VMs and read-only appliances 
     require manual installation; VMs without a guest agent cannot be reached; 
     phones, Macs, and Echo devices outside Proxmox are not reached by this script.
   
3. **Groups & Schedules**: make a group with those devices (by `mac:` is
   the stable choice).
4. **Policies**: a policy matching the group with *Inspect TLS* on and a
   bypass list for names that must never be decrypted: banking, health,
   the device's own vendor services (Apple, Microsoft, Google account
   traffic), and applications that pin certificates, which break under any
   inspection. *Action* can stay on monitor; inspection is independent of
   blocking.
5. **Apply.** From then on the TLS page shows those sessions as *bumped*
   with the negotiated version and the real server certificate, and the
   **Web page › decrypted only** view lists every decrypted request with its
   method, path and response code; the host page's web log shows the same
   for one device. Web policies on paths inside a site become possible.

What you get is the request layer: URLs, methods, response codes, sizes,
certificates. FlowSight does not record page or file contents, and it
never will by design (see [Security](SECURITY.md)). Traffic that never
crosses the firewall, such as two devices on the same subnet talking to
each other, is not seen by any of this; only routed traffic is.

### Map (Pro)

A route's trail ends at the destination when it answered the probe. When
it did not, the trail ends at the last hop that answered and a line says how
far the probe went without a reply; the silent steps are not listed.

Inside OPNsense, the page's breadcrumb, tab title and address follow the app
as you move between its pages, so a reload lands where you were.

Clicking a hop sets the **Device** filter to the devices whose traffic ran
through it (one device selects itself; several appear as *N devices through
the clicked hop*), so the map narrows to their routes. *Every device* clears
it.

Where traffic actually goes, measured rather than assumed. Everything else in
FlowSight watches the first hop; this traces the rest of the route and keeps
what it finds.

**It only traces what you already talk to.** Destinations come from your own
flow history, a few per run on a timer. Nothing is probed that this network
has not already contacted, and addresses inside the network are skipped
because they have no route worth drawing.

**A path belongs to a destination, not to a device.** Everything leaves
through the same gateway, so the route to a given address is the same
whichever device asked for it. Filtering by device is a join: it shows the
routes used by the destinations that device has talked to, without tracing
anything extra.

**Clicking a hop lights the routes through it**, and dims the rest. A dashed
grey leg means the route continues through hops that could not be placed: the
traffic went that way, but where it was in between is unknown, so it is not
drawn as though it were one router to the next.

**Shared legs are drawn once.** Every route out of your network starts the
same way, and drawn literally that is a hundred lines on top of each other. A
leg used by several destinations becomes one thicker grey line carrying them
all; coloured lines belong to a single destination. Where one position
answers from several addresses, which is how a carrier balances across
parallel links, that is one point carrying several addresses rather than
several points.

**The map is the page.** It fills the window under the top bar at the
world's own two-to-one proportion, so zoomed out it shows pole to pole, and
nothing about the projection or scale changes with the window. Everything
else is a panel on top of it: **Route**, **Hop detail**, the **Key** and a
**Data** drawer whose tabs hold the overview numbers, the data sources, your
location, the physics tables, the hops not on the map, the destinations
table, the full route trail and the notes (*About*). Drag a panel by its
title; let go near an edge or a corner and it docks there and stays put when
the window changes size. Double-click a title to send that panel home. The
small button on each title folds it to the title (Esc does the same when the
panel has focus); the cross closes it, and **Panels** in the toolbar brings
it back or puts every panel where it started. The arrangement is kept in
this browser. While you drag or wheel the map the panels step back so the
world under them stays visible; hovering a hop shows its address, place and
round trip at the pointer; the zoom and home buttons sit bottom right.
Filters sit in the toolbar along the top and apply as soon as you choose.
On a phone-width screen the panels stack under the map instead.

**One route at a time.** Click a destination in the table and the page draws
that route in the **Route** panel, and at length in the Data drawer's *Route* tab, left to right, one step per link: the machine on your
network that made the connection, your gateway, each carrier router in turn,
and the address reached, marked as the endpoint. Hovering a step lights up its
dot on the map and opens its detail; the route's legs are lifted out of the
rest and the others dimmed rather than hidden, because a route means little
without the routes it diverges from. *Show every route* goes back.

Clicking a step travels to it: the map slides to that hop at the zoom you are
already using, so you can see which way the route went. Clicking the last step
frames the whole route instead, zoomed to fit it rather than to the world.

You are drawn on the map, and the chosen route reaches you. Your machine and
your gateway answer on private addresses nothing can place, so the first
stretch -- from you to the first hop anyone can locate -- is drawn as the
estimate it is, and says how many unplaceable hops it covers.

The trail begins inside your network rather than at the first router that
answered, which is where a traceroute's own output starts. Where more than one
device used the route, the one with the most flows to that destination is
shown, or whichever you are filtering on. A hop that never answered keeps its
place, drawn hollow: the traffic went through it even though nothing replied.

**The map wraps.** It slides east and west without end; pan past the edge and
the land, cables and routes continue rather than stopping at a seam. Distances
are measured the short way round, so a leg between two points either side of
the antimeridian is drawn as the short hop it is instead of a line across the
whole map, and a route from here to Asia runs west across the Pacific, which
is the way the packets went. A key to the marks sits under the map.

**The key is a set of switches.** Click any entry to turn that thing off and
click again to bring it back; the choice is remembered. *Operator known* and
*the route you picked* switch the emphasis rather than hiding anything. *Size
endpoints by traffic* is a mode rather than a layer: off unless you ask, it
grows each endpoint's ring by how much went there over the last day.

**What feeds the map.** The *Data sources* card lists each source and what it
has produced -- positions measured by RIPE IPmap this session and how many are
queued, cables and land routes loaded, any fetch error. The switches
themselves are under *Settings › paths*, grouped as *Tracing*, *Where
things are* and *What the latency proves*.

**A selected route shows what each leg cost** -- the difference in round trip
between one hop and the next -- written along the leg with the hop it arrives
at, as `#4 · 13 ms`, so a label on the map and a step in the route below name
the same thing.

**Your view survives the page's own refresh.** Where you are on the map, what
you have narrowed to and which hop is selected all persist; changing route,
device or filter starts fresh.

**Clicking a hop narrows the map to the routes through it.** Everything else
is taken away rather than dimmed, and a chip above the map says how many
routes remain and through which hop; its &times; puts everything back. The
matching step in the route below is highlighted and scrolled into view, and
hovering a step lights its hop on the map, so the two always agree about which
hop you are looking at.

**Click a hop to go to it, and click it again to come back.** The map opens
showing the world pole to pole; a click travels in to the hop you picked, a
second click on the same hop returns to the whole world, and moving the map by
hand clears that so the next click travels again. *Reset zoom* also returns.

**Filters** on country, latency, distance in hops and device. Choosing one
applies it; there is no Apply to press. *Clear* goes back to everything. Wheel to zoom,
drag to pan, and *Reset zoom* to go back. On a touchscreen or with a pen, one
finger pans and two pinch to zoom; a two-finger drag does both at once. A tap
still opens the hop under your finger rather than being swallowed by the map.

Zooming scales the map, not the marks on it. Coastlines and routes grow, while
line thickness, hop markers and the grid's labels hold their size on screen, so
zooming in separates hops that overlapped rather than merging them into a
larger blob.

The device filter is a list of devices, not a box for typing an address, and
it has one entry per device however many addresses that device holds.
Choosing one covers all of them: a laptop with an IPv4 lease and half a dozen
rotating IPv6 privacy addresses is one thing to filter by, and filtering on
whichever address happened to be handy would show a fraction of where it has
actually been.

**What each hop tells you.** Click any point on the map. The panel to the
right of it gives, in this order and under these headings:

- *Measured* -- the round trip, and where the hop falls in the route. This is
  observation; nothing else on the card is.
- *Resolved* -- the router's own name, from reverse DNS.
- *Endpoint* -- if the hop is one. An endpoint is an address this network was
  talking to; every other hop is a router it crossed on the way. Endpoints
  carry a ring of their own on the map, show how much was received from and
  sent to them over the last day, and clicking one opens the whole journey to
  it.
- *Position, measured* -- where RIPE's IPmap puts the address, worked out by
  measuring it from thousands of probes rather than by looking it up. This is
  the only source here that is measurement rather than paperwork, and it
  outranks the address database. FlowSight asks about twenty addresses a
  minute and keeps each answer for a month.
- *Site, read from the router name* -- carriers write the site into the
  hostname. `po1.owr03.lax31.ntwk.msn.net` says Los Angeles; `ae10.edge1.dal2.
  sp.lumen.tech` says Dallas; `172-11-154-1.lightspeed.tpkaks.sbcglobal.net`
  says Topeka, Kansas. Shortened forms are read too -- `palo-bb4` for Palo
  Alto, `kanc` for Kansas City, `sjo` for San Jose.

  Those shortenings are ambiguous, so nothing is decided on the name alone.
  Every reading is a candidate and the round trip settles them: a name cannot
  place a hop somewhere light could not have reached in the time measured. The
  card gives a confidence and says what decided it. A published code the
  measurement supports scores near 100%; a contraction the measurement merely
  fails to contradict scores lower, and below 70% it is shown but does not
  overrule the address database.
- *Who runs it* -- which network announces the address today, taken from the
  public routing table, plus the registry's record of the allocation: the
  regional registry, the date, the allocation's name, and who it is
  registered to. The registrant's postal address is shown and is marked *head
  office, not this router*, because it is. Every Lumen router in the world is
  registered to one building in Monroe, Louisiana.
- *Buildings this operator occupies in <city>* -- real street addresses, from
  PeeringDB, where operators publish which data centres they are in. This
  appears **only** once the router's name has already given away the city, so
  the list is short and about this hop. When the city is unknown the heading
  changes to say the list is not narrowed, because then it is simply
  everywhere that operator is and proves nothing about the hop in front of
  you. Even narrowed it is a short list, never one answer: an operator
  publishes which buildings it occupies, not which rack answers a traceroute.
- *Placement* -- where the point is drawn and which of the above decided it.

**Corrections are shown, not made quietly.** Where a router's name contradicts
the address database, the name wins and an amber dashed line runs from the
position the database gave to the position now used, with a small ring on the
abandoned one. The card quotes what the database claimed and how far off it
was. This matters more than it sounds: Microsoft answers from a range the
RIPE registry holds, so an address database places its Los Angeles routers in
London, seven thousand miles out, and the latency check cannot catch it
because London is a perfectly plausible distance from Kansas at 134 ms.

Looking anything up over the network is optional -- *Settings > paths > Look
up who runs each hop* and *List buildings the operator occupies*. Reading the
site out of a hostname is free and always on. Results are kept for a month,
because allocations outlive most networks and buildings do not move.

**What the map does not claim.** Land outlines are drawn from Natural Earth's
public-domain 1:110m data, so you can tell Kansas from Kazakhstan. They are
not a claim about precision: coordinates come from an address database that is
dependable for end-user addresses and rough for carrier equipment, and a
router often resolves to wherever its address block was registered rather than
where it sits. That is what the hostname reading above is for. Hops with no coordinates are listed
underneath rather than placed at zero, which would pile a stack of routers
into the Gulf of Guinea. Hops that never answered are counted and not drawn
at all, and they keep their position in the numbering so the path is not
quietly reported as shorter than it is.

**Your location.** The map is drawn from an origin, and that origin is also
the reference for the one check that can prove a placement wrong. Left alone
it is worked out from the gateway's own public address, which is usually the
right town and occasionally the wrong state, because it is where the carrier
registered the block rather than where the wire ends. The page can fill it in
from your browser, which knows precisely and asks your permission first, or
from the public address, or you can type it. It is also *Settings › paths ›
Your location*.

The card shows the gateway's own public addresses, IPv4 and IPv6, beside those
coordinates, and marks which one the coordinates were worked out from. On a
dual-stack line that is always the IPv4 address: the two families geolocate to
different places, and an origin that changed between restarts would quietly
move the line between a placement being ruled out and one standing.

**Hops put between their neighbours.** A router that answers but has no
coordinates anywhere used to be left off the map, so a route appeared to jump
from one country to the next with nothing in between. Those are now placed
between the two hops either side of them, at the point where their round trip
falls between the neighbours' -- drawn hollow and dashed, and saying on the
card what decided the spot. Hops that never answered at all are still left
off: there is no measurement behind them, and spacing them along a line would
be drawing routers out of nothing.

**Placements too fast for any built route.** Every hop is judged against two
numbers. The floor is what light forbids, and it is a proof. Above it a reply
is not disproved -- but it can still be quicker than any route anyone has
built, and the only thing that makes a reply quicker is the place being
nearer. Those are listed separately and marked with a dashed amber ring rather
than a solid red one: doubted, not disproved.

Note the direction. Being *slow* is never suspicious -- congestion, queuing
and indirect routing all make a reply late and all are ordinary. It is being
too fast for where the hop is said to be that means something.

The second number allows for fibre not going straight overland (*Settings ›
paths › Fibre on land runs longer than the crow flies by (%)*, 35% by
default), for a sea crossing being as long as its cable, and for the moment
each router spends receiving a packet before passing it on. Zero turns the
category off.

**Land-route maps.** With *Use published land-route maps* on, FlowSight
downloads open maps of long-haul fibre and measures along them where they
reach rather than estimating the detour, refreshing monthly. These never raise
the impossible threshold: over water a cable is the only way across, so its
length is a real bound, but on land a straight line is merely something nobody
built. Coverage is thin -- AfTerFibre covers Africa under a Creative Commons
licence and is the one substantial open set; the comprehensive maps of North
America, Europe and Asia are sold commercially. Sources are a list of URLs, so
adding one later is a line of configuration. OpenStreetMap's telecom lines
are a second, weaker source: fetched tile by tile from the Overpass API,
they count at half weight -- the expected time is the average of following
the line and the plain detour -- because they are mostly the visible kind of
line and rarely the buried long-haul a packet rides. Road-traced files are thinned to
the points that change a route's shape by more than a kilometre before use,
so a large one costs a second or two to load rather than a core for a day.

**Who and what.** Under a chosen route's trail, every device on this network
that talked to the endpoint in the last day is listed by name, and under each
its services -- application, the name it was for, protocol and port -- busiest
first. Click a device to narrow the map to it. The endpoint's card shows the
same in brief.

**Clicking a hop opens its route.** Any hop not on the chosen route loads the
route it belongs to, busiest first when there are several, with the hop
selected; the chip above the map then reads *route 1 of N through …* with
*next ›* to step through the others. A hop on the chosen route zooms in, and
again to zoom out.

**Direction and the route table.** Each leg carries an arrow pointing the
way the packets went; *direction of travel* in the key switches them off.
With a route chosen, a table in the map's top-right corner lists every step
from the machine inside the network to the endpoint -- name or address, place,
round trip -- and each row marks its hop on the map, travels to it on click,
and frames the whole route from the endpoint. Both the key and the table fold
to their titles.

**Anycast.** Some addresses -- the big resolvers, CDNs, root servers -- are
announced from dozens of datacentres at once, and the one you reach is local
or regional. The map knows which addresses these are (the LACeS anycast
census, weekly) and places such a hop at the census site nearest the hop
before it; its card says so in the first line, with the number of sites and
the distance. A registered or remotely measured position for an anycast
address is set aside as meaningless.

**Shodan.** Every hop's card offers *Look up on Shodan*: open ports, names the
address has been seen under, product fingerprints and known vulnerabilities,
free without a key; with a key (*Settings › paths › Shodan*) the full record
adds organisation, ISP, operating system and last seen. The mode setting can
fetch it for every hop instead.

**FCC broadband map.** The National Broadband Map publishes where every provider
reports serving broadband in the United States. With an account (*Settings ›
paths › FCC broadband map*), FlowSight checks in monthly for the current
release and keeps the national provider summaries and the census-place coverage
for the origin's state. The *Data sources* card shows the release date and what
was kept; *Pull FCC data* runs the pull now. A hop that matches a provider's
name is shown on its card with the states served and location count.

**Servers that say where they are.** Root servers and most large resolvers
answer `id.server` with the name of the instance you reached; FlowSight asks
each anycast hop once a week and, using the root operators' published site
lists (or the airport code in the answer), draws the hop at the site that
actually answered. The card shows the answer, the site and how it was read;
the round trip can still veto it.

**Anycast, and hops beside their upstream.** Resolvers and root servers are
announced from dozens of sites at once; the instance you reach is the one
beside the last router before it. A hop answering within a couple of
milliseconds of the last placed hop on its route is drawn beside that hop and
says so, and the well-known anycast ranges are never placed by a database or
by a measurement made from somewhere else.

**AI lookup.** With a provider configured under *Settings › paths › AI
lookup* (instructions for Anthropic, OpenAI, Google, Azure OpenAI and Ollama
are in the setting's help), hops that nothing else could place are put to the
model with their name, operator and round trip. Its answer is drawn as an
inference and labelled *Read by a language model* with its reasoning; the
clock still rules, and any real source overrules it.

**Reputation.** With an AbuseIPDB key (*Settings › paths › Reputation*; free
at abuseipdb.com under *Account › API*), each hop's card gains a *Reputation*
block: abuse confidence, reports and reporters, ISP, usage type and domain,
with Tor and whitelist flags. Answers are kept a week; the *Data sources* card
counts them.

**Geofeeds from the registry.** Where an operator names its own geofeed in
its registry object, FlowSight fetches it weekly and places that operator's
prefixes from it -- the operator's statement rather than the registrant's
office address.

**The clouds' own range lists.** For an address in a range AWS, Google,
Azure, Oracle, DigitalOcean or Linode publishes, the map uses the provider's
own region -- the campus the region is built in -- over the address database
and over a measurement; a violet ring marks such hops. Cloudflare and Fastly
ranges are anycast, announced everywhere at once, so no single place is
claimed for them: a database position is set aside and the hop is placed by
timing, with the reason on its card.

**Devices, not addresses.** A device is known by its hardware address; every
IP it has held is grouped under it, IPv4 and IPv6 alike. Which addresses it
holds *now* is remembered for a day (*Settings › identity › Remember a
device's addresses for*), because IPv6 privacy addresses rotate; which device
an address *belonged to* never expires, so traffic sent from an address a
device has since dropped still counts as that device's, and the device list
and route trails name it rather than showing a bare IPv6 address.

**What the database gets wrong is remembered.** The address database places
a block where it was registered, and for a carrier that is a head office. When
a router's own name or a RIPE measurement puts a hop more than 500 km from
there, the map learns two things: that the hop's announced prefix is where the
evidence says -- other addresses of the prefix follow it, drawn as *corrected*
with the router and date on their card -- and, once two routers of one network
have been shown away from the same database coordinate, that the coordinate is
the registrant's and not to be believed. Nothing is learned from a placement the
hop's own round trip could not have reached -- an anycast address is measured
wherever most probes see it -- nor recorded against an aggregate broader than
a /16. A hop the database would put there is
left for the timing to place, with the reason on its card, rather than drawn
at a head office on the wrong continent. The *Data sources* card counts both;
`/api/paths/corrections` lists them and lets any be forgotten. *Remember what
the database gets wrong*, under *Where things are*, turns it off.

**Placements the physics rules out.** This one is geometry rather than a guess
about routing: no path between two points is shorter than the straight line
over the earth's surface, and nothing in fibre beats about 200,000 km per
second. Twice that distance divided by that speed is therefore a bound no
route of any kind can undercut -- not the shortest route FlowSight could find,
but the shortest that could exist. A reply that beats it means the coordinates
are wrong, because the round trip is the one thing here that was measured
directly. When the placement came from the address
database, RIPE IPmap or a learned correction, it is set aside rather than
drawn: the hop is placed by timing instead and its card says what claimed
what. A placement from the router's own name stays drawn, because that is
first-hand; the table's *Said by* and *Now* columns tell the two apart.

The floor is taken from the nearest point your own origin could honestly be
(*Settings › paths › Your own position could be wrong by*, 100 km by default,
and nothing if you declared your location). A shortfall thinner than that
uncertainty is not counted: calling a placement impossible on a margin
narrower than the error in your own position would be claiming a precision
nobody has.

Between continents that distance is measured along the cables rather than
across the map. Cables follow continental shelves, skirt trenches and come
ashore where there is a station, so the real journey is longer than the
straight line and the floor correspondingly higher. FlowSight takes the
shortest published route joining the two places, counting the run ashore at
each end, and names it in the tables and on the hop card. Under 1,200 km the
straight line stands, because that trip is made on land; a cable route more
than twice the straight line is ignored as a different journey. The bound is
never lowered below the straight line. This needs *Show submarine cables* on.

A leg that crosses an ocean is drawn along that cable rather than straight
across the map, bending where the cable bends. Hovering it names the cable and
gives both distances, the route and the straight line. FlowSight is reading
the evidence, not reporting a fact: a traceroute never names a cable, so this
is the shortest published route that fits the two ends and the latency. A hop that
answers faster than that floor is not where the database says it is, and the
map circles it and lists it with the numbers. On a typical network several
hops fail this: anycast addresses are the usual cause, because the block is
registered in one place and answered from wherever is nearest you.

**Submarine cables.** With *Settings › paths › Show submarine cables* on,
FlowSight fetches TeleGeography's published cable map and draws it behind the
routes. Hovering a leg long enough to have left the continent lists the cables
that could have carried it.

Could, not did. A traceroute gives router addresses and round trips and never
names a cable, so if two places are joined by eight cables then all eight fit
the observation. What can be done is ruling members out, and that part is not
guesswork: light in fibre covers about 200,000 km per second, so a cable
cannot carry a round trip faster than twice its length divided by that. Cables
are long and rarely direct, so this discards a great many candidates outright.
What is left is offered as a list, shortest first, and never as an answer.

The data is fetched by your installation rather than shipped with FlowSight,
and refreshed monthly. TeleGeography publish it as a free public resource but
it is not openly licensed, which is why it is not bundled.

This needs the city-level database, since the country one carries no
coordinates. See *Settings › enrich › How much detail*.

**A destination nobody has traced yet is traced when you ask for it.** Arriving at the Map with a destination (from a policy match, a session, a host page or the DLP page) that has no measured route starts a trace at once; a chip in the toolbar says so and the route appears when the answer lands, usually within a minute. The timer would have reached it eventually; a person clicking *Map* is not on the timer.

### Devices, zones and IPv6

**A device is one thing, not one address.** A phone has an IPv4 address, one
or more IPv6 addresses, and a MAC that ties them together. Exclusions follow
the device: excluding a range in one address family also exempts the same
devices when they speak the other, because "do not inspect those things over
there" was never meant to apply only to IPv4. On a flat network this matters
more than it sounds, since every device shares one IPv6 prefix and there is
no range to write even if you wanted to.

**Classification rules match on their conditions and nothing else.** A rule's
`when` block is the whole of what it tests, and a condition FlowSight does
not recognise never counts as a match. That last part is deliberate: a rule
that fails open turns one typo into "everything", quietly, and you find out
when every device on the network has been filed under the first rule in the
list.

### Priority (Pro)

The one page that changes traffic rather than describing it. It decides who
waits when the link is full.

**It only works if the bottleneck is here.** When an uplink fills, the queue
that decides what waits belongs to the modem or the carrier, and nothing on
this firewall can reach into it. So shaping starts by sending everything
through a pipe sized a little under what the link really carries, which moves
that queue onto the firewall. That is why the two rates are settings and why
they have to be honest: set them above the real rate and the pipe never
fills, the carrier stays the bottleneck, and every weight below is
decoration. Measure the link, do not copy the figure off the bill.

**Upload matters more than it looks.** A saturated upload delays the
acknowledgements that downloads depend on, so one device pushing hard ruins
streaming in both directions. Downloads can be shaped too, but less crisply:
those packets have already crossed the carrier's bottleneck by the time the
firewall sees them, so the only lever is holding them back until the senders
slow down.

**Rules** are written the way you would say them:

```
192.168.1.178 = low
redgifs.com = high
10.0.5.0/24 = low, 20Mbit
backup.example = 5Mbit
```

The left side is an address, a CIDR or a domain. An address is understood as
a device on this network or as something out on the internet depending on
which side of your local networks it falls, and the rules are written the
right way round either way. A domain matches the addresses this network has
actually been seen using for it, so a name nobody has looked up yet matches
nothing until they do; the page says so per rule rather than leaving you to
wonder.

The three classes are shares, not reservations. A class with twice the weight
gets twice the link when both want it at the same moment, and none of it is
wasted when one does not. A rate on a rule is different: that is a ceiling,
enforced whether anything else wants the link or not.

The page shows the rules, what each one currently matches, the queues and
what they are holding, and the firewall rules the settings would produce, so
you can read them before trusting them.

**Measuring the link.** *Run a bandwidth test* on the Priority page (and on the qos panel under Settings) measures what the link really carries, from the firewall itself. For about a minute it pulls and pushes data on several streams against Cloudflare's speed endpoints while reading the WAN interface's own byte counters every second. The counters see everything the link carried, the test and everyone else's traffic, so the **Link carried** figure is the capacity as observed and **Other load during** is what was already there; a test run while two people stream is measured beside them rather than fooled by them. Cloudflare refuses a repeat download burst from one address for a while (HTTP 429 or 403); when it does, the download is taken instead from the nearest of about thirty public test-file mirrors run by Vultr, Linode, Hetzner and OVH, chosen by the time a connection to each takes, and the row says *download from* that mirror with its round trip. The upload stays on Cloudflare. Only if no mirror answers does speedtest.net's download stand in. The same run is repeated against speedtest.net's nearest server for comparison, and when the two differ by 2% or more in either direction both are run once more. Every attempt is logged, newest first, with the interface, the load before and during, the comparison server and its latency, and the difference. *Use N / M* on a row writes the link-carried numbers into the download and upload fields; headroom is still taken from them when shaping. The interface is the one the default route leaves by unless *WAN interface* names another.

### DLP (Business)

The one page written in the present tense. Everything else in FlowSight
reports what happened; this reports what is happening, because a transfer
you read about tomorrow is a transfer that finished.

It does not read logs. It reads the firewall's own connection table, which
counts every byte of every open connection and updates as they move, and it
samples that every few seconds. The consequence is that it sees everything:
a session whose certificate is pinned still has a connection, and so does a
spliced session, a QUIC session on UDP 443 that never reaches the proxy, and
a WireGuard tunnel carrying who knows what. None of those can be decrypted.
All of them can be measured.

Each row is one connection: the device, the destination with the name
FlowSight can put to it, what kind of destination it is, how fast it is
sending right now, how much it has sent and received, and how long it has
been open. **Stop** drops the connection at the firewall, which ends the
transfer immediately. The device may open another one; preventing that is a
policy decision and belongs in a policy.

Destinations are grouped coarsely, because the group is what changes what
you would do: cloud storage, file transfer and paste sites, code hosting,
personal mail, messaging, AI assistants, remote access, backup, media,
telemetry, content delivery, encrypted tunnels, and **unnamed**. That last
one is the row most worth reading. It means no DNS answer, no server name in
any handshake and no reverse lookup could put a name to the address the data
is going to.

*Settings › egress* sets which groups raise an event and at what point: a
single transfer above so many megabytes sent, a sustained upload rate held
for so many seconds, a transfer that has sent several times what it
received, the first time a device reaches a kind of destination it never has
before, and anything at all going somewhere unnamed. A quiet-hours window
raises the severity of anything flagged inside it.

What this cannot tell you is what was inside. For the sessions that can be
decrypted, stateful packet inspection reads the request itself. The two are meant to be
read together: this says a device is sending four gigabytes to a cloud
storage provider, and stateful packet inspection says which files.

**Every kind explains itself.** Each destination kind carries a description: it is the bubble on every pill, and *What the kinds mean* under **By destination** lists them with a link to the how-to. *Unnamed Destination* means nothing could name the address at all (no DNS answer seen, no TLS server name, no reverse lookup), which is why it is watched. *Other* is no longer one bucket: it is split by the application's category, the web category of the name, the network that announces the address, or failing those the port, so the bars read *Other · Software Update* or *Other · Apple Inc.* rather than *Other*. Clicking a bar narrows the connection list to that kind and scrolls to it.

**Flagged transfers say who, what and where.** Each event is enriched from what the gateway already knows: the device with its maker and hardware address; a one-line reading of the payload (*Encrypted web (TLS, name seen)*, *Inspected: images, API calls*), the application, the name, the content types of inspected sessions and how much was readable; the far end's place, whether it is anycast, and the network that announces it, with links to the Map and to the sessions; and the bytes, rate and threshold at the time. *Moving now* carries the same detail per connection.

### Stateful Packet Inspection (Business)

What a decrypted session carries, not just which server it reached. The
proxy hands each request and response to FlowSight as it passes, using ICAP,
the protocol a proxy speaks to a content adaptation service. FlowSight reads
it and answers "no modification", so nothing is proxied through FlowSight
and nothing is altered on the way.

Each exchange is recorded as the method, the full URL, the response code,
the content type, the size and the timing, plus the request headers when
that is switched on. Cookies and authorization headers are recorded as a
byte count, never as a value. Bodies are read only by the decoders that are
switched on and are never stored.

Today one decoder is shipped: **DNS over HTTPS**. A browser resolving over
HTTPS puts its question in the request body, where a proxy log cannot see
it; stateful packet inspection reads it and files it in the DNS history like any other
lookup, so the name is visible and attributable to the device that asked.

*Settings › mitm* switches it on, sets the loopback port, chooses how much
of each body the proxy sends for decoding, and limits it to particular
clients or names. It only ever sees what a policy already decrypts: a device
without TLS inspection, an excluded host or a pinned name never reaches it.

**Inspect everything that crosses the firewall.** One checkbox decrypts
every intercepted client rather than only those a policy names, appliances
and televisions included. A device that does not trust the FlowSight CA
fails to connect until the pinned-site detector notices the refusal and
starts relaying that name untouched, so an appliance you cannot install a
certificate on ends up relayed rather than broken. Excluded hosts are never
touched. Turn this on deliberately: it is the setting with the widest reach
in the product.

### Firewall Analysis Engine (FAE) (Pro)

Continuous analysis of the live pf ruleset. **Rules** lists every rule with
its evaluation and packet counters, when the ruleset was loaded, and the
labels OPNsense gives them. **Findings** are the conclusions: never
evaluated since load, unused for a long time, shadowed by an earlier rule,
overly broad, changed since the last analysis. Each carries a severity and
what to do. A **risk score** summarises. **Changes** is the history of
ruleset changes with diffs. *Run now* re-analyses immediately.

## Protect: policy

### Policies

The list in evaluation order with name, action (monitor or block), groups,
schedule, what it denies, whether it is active right now, whether every
requirement is met, and how many members it currently resolves to. Buttons
move a policy up or down, enable or disable it, edit or delete it.

**Editor**: name and description; action; groups to match (or *all*);
schedule; denied applications (search the catalogue), application
categories, web categories, domains, TLDs, ports (`tcp/25`,
`udp/6881-6889`) and *internet*; allowed domains that override the
denials; safe search; YouTube mode; TLS inspection with a bypass list.

**Plan** compiles the document onto every provider and shows, per
provider, the diff between what is in place and what would be written,
plus any unmet requirement. **Apply** writes it (needs *Enforce policy* on
in Settings › policy). **Export** and **Import** move the whole document as
JSON or YAML.

**Matches** (on a policy with a country rule) opens *Policy matches*: per
device, the far ends in denied countries from the session table (names,
domains, bytes, last seen, a Map button per destination), and beside it the
packets the firewall's own log recorded for the rule, by device and
destination. The first is computed the way the rule is compiled; the second
is pf's ground truth, read from OPNsense's filter log.

Community allows three policies; Pro removes the limit.

### Groups & Schedules

Groups: name, description and members (addresses, networks, `mac:`,
`device:`, `zone:`, `all`), with the members each resolves to right now.
Schedules: name and weekly windows (days, from, to; a window past midnight
is written as from 20:00 to 07:00). Community allows two schedules.

**Picking devices.** The group editor lists the network's devices with a search box. Ticking one adds it by hardware address, which covers every address it holds on every interface, now and after its next lease; a device with no hardware address is added by each of its addresses. *Add every device shown* takes the whole filtered list.

### Categories

The web category catalogue: each category with its source feed, the number
of domains, when it was refreshed, and a lookup box to see which categories
a domain falls into. **Custom categories** are your own lists (domains one
per line) usable in policies like any other. Feeds refresh on a schedule set
in Settings › categories; roughly six million domains are indexed in memory
in a compact form.

## Inventory

What is on the network, by address and by device.

**Reading a list, and the whitelist.** *View* on any category shows the list as cached on the gateway, searchable and paged, with its source and the time it was fetched; *Download* gives the file. The reserved custom category *whitelist* is the one list that allows rather than denies: names in it are folded into every policy's allow-list at compile time, so no policy blocks them. Web-content categories and nDPI application categories are different things; *HOWTO: categories and applications* (docs/howto/categories-and-apps.md) explains both and how each is identified.

### IP Addresses

Every device seen in the window. Columns: name (from DHCP, reservation or
resolver), address, MAC and vendor, whether the MAC is randomised, bytes in
and out, sessions, blocked requests, last seen. Sort by any column; filter
by name or address. A host that stops appearing is not deleted, it just
falls out of the window.

**One row per device.** The checkbox beside the count folds every address
behind the same hardware address into one row: traffic summed, the other
addresses listed under the name, the IPv4 address as the link. Addresses
with no known device stay their own rows. The range bar shows *since <date>*
when the window reaches back past the oldest record, so 7d and 30d reading
the same on a young installation is expected, not a fault.

**Name provenance marks:** A small bullet (•) after a device's name shows where
the name came from, with a tooltip showing the source and confidence. Names come
from DHCP hostnames (highest trust), static reservations, device enrollment,
reverse DNS, or operator assignment. The mark confirms a name is from a trusted
source (lease, reservation, enrollment) or warns it came from the network
(resolver). Operator-assigned names override all others and always have 100%
confidence.

IP Addresses and Devices overlap on purpose and answer different questions.
**IP Addresses** (once called Hosts) is what the traffic shows: one row per address seen in flows and
DNS within the window, with its traffic, and it includes far ends and
transient visitors. **Devices** (under Policy) is the enrolment inventory:
one row per physical device known by its MAC from DHCP, with a class and a
zone, listed whether or not it is talking right now. A device's address
opens its host page; a host page shows the device's class and zone.

A device is one device whatever address it is using. FlowSight ties every
address a device holds, IPv4 and IPv6 alike, to its MAC: names, vendor,
policy membership (`mac:` and `device:` members) and the device inventory
follow all of them, and an address stays associated for a day after it was
last seen so the temporary IPv6 addresses operating systems rotate through
do not shake a device loose from its policy. A host page lists the device's
other addresses and links them.

**Host page** (click a host): identity details and how each was learned;
throughput over time; applications, sites and DNS names with bytes and
counts; the session list; alerts and blocks; a **Blocked queries** card
listing the most recent DNS blocks for the host with the list that blocked
each (FlowSight policy or Pi-hole gravity, regex, denylist) and the
resolver they came through; the policies that match it and which group
brought it in; enrolment class and zone.

**Naming a device.** *rename* in the Identity card opens a dialog for the
name FlowSight shows. With *Also add it to DNS* ticked, the same dialog
gives the device a name on the network, forward and reverse
(`kitchen-ipad.grio.co` to its address and back), on the gateway resolver
and each connected Pi-hole, and can make the name follow the device when its
address changes. The Identity card's *DNS name* row shows it. See
[Give a device a DNS name](howto/local-names.md).

**Needs attention on this device** sits at the top of a host page when the
device has open findings: device advisories first, with what the person
sees, the cause and the fix, then any other finding. It covers every address
the device has used, so a phone's IPv4 and IPv6 findings appear together.
The same findings, in full, are in the *Findings* card lower down. In the
*IP Addresses* and *Devices* lists a warning mark beside a device names its
open finding (or counts them); hover for the list, click for the device.

### Devices

Every enrolled device with its class (phone, laptop, TV, camera, console,
printer, IoT), why it was classified so, its address (by name when known;
with *Settings › enrich* on, bare addresses gain a reverse-DNS name and
country), vendor, zone and last activity. The address and name follow the
device's newest sighting: when a lease moves, the row moves with it, and a
name nothing live vouches for is dropped rather than left on the wrong
device. A device with a private (randomised) hardware address has no
registered maker; FlowSight reads the maker from its DHCP fingerprint,
vendor class or name and says so (*Apple (private address)*). A maker name
is never attached to a private address: when an IP address passes from one
device to another (a lease reused), what was learned about the previous
holder (maker, name, type) stays with that device and is not inherited by
the new one.

**Services** is what the device did in the last day: the applications it
used, and the ports other local hosts connected to on it with how many came,
so a row reads "uses Netflix, HTTPS · offers ssh (3), plex (5)". Every
address the device holds counts, IPv4 and IPv6, current and remembered.

A device marked **not inspected** is on the exclusion list under *Policy ›
Exclusions and options*, and the marker names the entry. Its traffic is
never intercepted, decrypted or policed. With inspection on for everything,
that list is where anything that pins its certificates or cannot carry the
FlowSight CA belongs; the Devices count at the top says how many are
excluded. The classification rules decide
each device's zone, and in monitor mode they keep deciding it: edit a rule
and every device it covers moves on the next reconcile (every minute by
default). Choosing a zone from a device's row pins it there, marked
*pinned*, and the rules leave it alone; choosing the empty entry unpins it
and hands it back to the rules. A zone a guest picks on the captive page
pins the device the same way. In enforce mode a device that already has a
zone keeps it, since the zone is an address it holds; only devices without
one are placed. The zone name links to the Zones page, and the zone chips
at the top filter the list. **Mode** (monitor or enforce) is switched here; enforce is
Pro and writes DHCP reservations and isolation. *Re-identify* re-runs the
classification.

### Zones

The zones with their subnet (IPv4), IPv6 subnet, isolation policy, how many devices each holds
and who they are (each name links back to the device, each count opens the
Devices page filtered to that zone). Below it the two documents: **zones**
(id, name, subnet, subnet6, isolation) and **classification rules** (DHCP vendor
class, hostname pattern, OUI to a class and a zone). The IPv6 subnet (subnet6) is optional; 
set it when the zone uses IPv6 addressing so policies using `zone:<id>` members can 
match both address families. *Plan placement* shows what enforce mode would write, 
*Apply placement* writes it. A captive page on the LAN explains to an unplaced device what happens next.

Devices without a zone are listed under **Unidentified** with an *Identify*
button each (the same probe as on the Devices page), and the per-zone table
has the button too, so a bare hardware address can be probed and named
where you meet it before you choose its zone.

### Users

Active user sessions tracked from RADIUS accounting (FreeRADIUS, OPNsense
captive portals, compatible systems) or manual login APIs. Every logged-in
user appears with their current addresses (IPv4 and IPv6), the device they
logged in from (MAC and name from identity), the NAS that sent the accounting
(network access server: router, VPN, portal), when they logged in and when
they were last active.

**User targeting in policies:** Policies can match individual users
(`user:alice`, matching all of Alice's devices) or groups when LDAP/AD is
configured (`usergroup:admins`, matching every device of an admin). This
lets you apply rules by person rather than machine, so a developer's laptop,
phone and tablet all follow the same policy.

**Configuration:**
- Set up RADIUS accounting from your auth system and point it at FlowSight
  (Settings › Users › RADIUS accounting, UDP 1813 by default, shared secret
  required).
- Captive portals and scripts can manually post user logins via `POST
  /api/users/session` without RADIUS.
- LDAP/AD group lookup is supported as a framework; implement as needed for
  group-based policy targeting.

**Session details:** Click a user name to see all their sessions (current and
recent), addresses used, MAC and device, group membership (when LDAP is on),
and when they came and went. The Who tab in the policy editor lists all
known users and suggests them for targeting.

### Scan

**Identify** on a Devices row or a host page runs the fast profile and then
says what the device most likely is, ranked, each guess with its evidence:
an Amazon device with 55443 open is an Echo; 8008/8009 is a Cast device;
8060 a Roku; 1400 a Sonos; 62078 an iPhone or iPad; 9999 a Kasa plug; 6668 a
Tuya device; 32400 a Plex server, and so on, combined with the maker behind
the hardware address, the DHCP fingerprint and vendor class, the device's
own name, mDNS model strings, the reply TTL and any banners.

Active scanning for local devices: ICMP, TCP/UDP probes, service banners, and
OS fingerprinting. Restricted to locally-known networks; off by default. Each
host can be scanned on demand with the **Identify** button (on the Devices or
host page) or all known devices swept periodically. Scanning is native (no
external tools) with optional nmap enhancement when installed. The results
show open ports, inferred OS, detected services and banners, and findings
(e.g. telnet, unencrypted FTP, exposed RDP). The Scan page lists all recent
scans: click one to see full details (all ports, all OS guesses with evidence,
all banners). *Scan a host* prompts for an IP or MAC; *Sweep all local*
starts a scheduled sweep of devices seen in the last 7 days, respecting a
time window and rate limit from Settings. Scans originate from the gateway and
may be detected or rate-limited by host firewalls or IDS.
### Space

Map your physical space in 3D, place devices at their real locations, and track
their network locations. See a walkthrough below to get started.

**What works:**

**3D Scan viewer:** Upload scans from your phone or camera app in GLB (recommended),
OBJ, PLY, or RoomPlan JSON format via the **⬆ Scan** button. The viewer applies
any stored transform (scale, rotation, offset, Y-up/Z-up conversion) and displays
the geometry with spatial indexing for fast ray-casting. A progress bar shows
during parsing. Max 50 MB; decimate large scans in your app before upload. Scenes
with no scan show the floor grid and axes.

**Marker interaction:** Click a placed device marker to open a popover showing the
device name, MAC, position, floor, room, placement date, and a 60-point visibility
sparkline from the last hour. Links let you jump to the device details or Devices
page. Click **Unplace** to remove the device from the space. Drag a marker to move it
to a new position; release saves the placement. Scroll the mouse wheel while dragging
to adjust the z (height) coordinate. Highlight a device in the Palette pane to fly
the camera to it over 600 ms with a smooth animation.

**Device placement:** Drag a device from the Palette pane onto the 3D canvas. The
viewer ray-casts the click to find a hit point on the scan mesh, or falls back to
the floor plane at z=0. The placement is saved with its MAC, 3D coordinates, floor,
and room (auto-detected from polygon containment if a room contains the point).
Placed devices are shown as small red markers in the 3D view.

**3D controls:** Left-click and drag to orbit (single-finger touch also orbits).
Right-click and drag, or shift+drag, to pan. Mouse wheel or two-finger pinch to zoom.
The viewer automatically fits the camera to all loaded geometry on load. Rooms from
all floors are shown as extruded 3D boxes; the current floor's rooms are opaque,
other floors are faint to show context.

**Calibration tools:**
- **Level:** Click **📐 Level** to collect three points on the floor. The tool fits
  a plane through them and stores the up-axis rotation and z offset to transform the
  scan.
- **Align:** Click **⚙ Align** to pick two points in the 3D scan, then two corresponding
  points on the plan. The tool computes scale, rotation about the up axis, and offset
  to align the scan to the plan.

**Plan pane (2D room editor):** Click **✏ Draw** to enter draw mode, then click to
place vertices and double-click or click the first point to close a room. A dialog
prompts for the room name and ceiling height. Rooms appear as filled polygons with
vertices. Drag vertices to edit rooms in real time (grid snap is 0.1 m). Click a room
interior to select it (highlighted in blue); a **✎ Rename** button appears to edit
the name, and a **🗑 Delete** button to remove it. Pan with right-click or shift+drag;
zoom with the mouse wheel.

**Placement dragging:** Placement dots (small red circles) appear on the plan for devices
on the current floor. Drag them to reposition devices; release saves the new coordinates.

**Calibration:** **📏 Scale** lets you calibrate distances: click two points on the
plan, then enter the real distance between them (in metres) to rescale all coordinates
on the current floor.

**Import:** **🗺 Import OSM** imports the building footprint from OpenStreetMap, if
available, as a new room.

**Undo/Redo:** **↶ Undo** and **↷ Redo** buttons work for all operations: drawing,
scaling, importing, room operations (rename, delete), and placement edits. Ctrl+Z
(or Cmd+Z on Mac) also undoes; Ctrl+Y (Cmd+Y) redoes. An unsaved indicator (● Unsaved)
shows when the layout differs from the saved state.

**Floors:** The floor select dropdown shows each floor with its elevation. Each floor
is edited independently; switching floors hides non-current rooms on the plan, but
3D view shows all floors.

**Mobile:** At viewports ≤768 px wide, the three panes (3D, Plan, Devices) become tabs
with the 3D view first. Touch orbit and pinch-to-zoom work. Network errors show as
toasts at the bottom-left and auto-dismiss after 3 seconds.

**Address records:** Geocoding from the US Census Geocoder (no API key); elevation
from USGS; building footprints from OpenStreetMap when available. Placements update
device location links on the Devices page.

#### Getting started: How to scan your apartment

1. **Scan your space:** Use an app that exports 3D geometry:
   - **iOS:** LiDAR Scanner or SpatialIO (export as GLB)
   - **Android:** 3D Scanner App (export as OBJ or PLY)
   - **Any platform:** Capture a RoomPlan JSON if your device supports it
   Choose **GLB** (GLTF binary) for best results; it's the smallest and fastest to parse.

2. **Upload the scan:** Click **⬆ Scan** in the 3D pane and select your exported file.
   A progress bar shows during parsing. Max 50 MB; decimate large scans in your app.

3. **Level the floor:** Click **📐 Level** and click three points on the floor plane to
   fit a horizontal plane. The tool stores the rotation and z offset so placements sit
   at the correct height.

4. **Draw or import your floor plan:** Either:
   - Click **✏ Draw** and trace the walls by clicking vertices. Double-click or click
     the first point to close. Name the room and set ceiling height.
   - Click **🗺 Import OSM** if your building is in OpenStreetMap.

5. **Calibrate scale:** Click **📏 Scale** and click two known points (e.g., opposite
   corners of a room), then enter the real distance between them in metres. The entire
   plan rescales.

6. **Align scan to plan (optional):** Click **⚙ Align**, click two points in the 3D scan,
   switch to the Plan tab, and click the two corresponding points on the plan. The tool
   computes rotation and offset to align the scan to your drawn layout.

7. **Place devices:** Drag devices from the Palette pane onto the 3D canvas. Click and
   drag a placed marker to move it; scroll the mouse wheel to adjust height. Each
   placement is saved with its room and coordinates, linked to the device's network
   location on the Devices page.

### Proxmox

Your hypervisors, seen from the network side. With a Proxmox API token
entered under *Settings › proxmox* (hosts, token id and secret, and the
server certificate's SHA-256 fingerprint to pin, since Proxmox uses a
self-signed certificate; the configuration guide has the `pveum` commands
for a least-privilege token), FlowSight polls each node every few minutes:
node health and version, every VM and container with its configuration,
status, hardware addresses, and, where a QEMU guest agent answers, the
guest's own addresses, operating system and hostname. Containers report
their interfaces directly.

What it learns flows into the rest of FlowSight. A guest's addresses gain
its name (when no DHCP lease already names them), its maker reads
"Proxmox VE qemu on <node>" or "lxc", its operating system comes from the
agent, and the Devices page and the host page show node, type, VM ID and
guest name under the device.

**Notes.** With *write notes* on (off by default), FlowSight keeps a block
inside each guest's Notes in the Proxmox web interface, between
`<!-- flowsight:begin -->` and `<!-- flowsight:end -->`: the FlowSight
name, class and zone, addresses, maker, first and last seen, traffic in the
last day, open ports and OS guess from the latest scan, and a link back to
the host page. Everything you wrote outside the markers is preserved; the
block is rewritten only when its content changed, using the configuration
digest so a concurrent edit is never overwritten. *Preview* shows exactly
what would be written; a guest tagged `flowsight:off` or listed in
*exclude VM IDs* is left alone.

**Map.** The *Map* tab draws the guests grouped by node and the traffic
between them: solid edges are connections FlowSight observed at the
gateway, dashed edges are declared relationships from the Proxmox
configuration (startup order, shared storage, shared bridges), dotted
edges are what a VM reported from the inside. Edge width follows bytes and
the label is the port. Hover a guest to see only its edges; click it for
the requirements panel: cores and memory, the storage each disk lives on,
bridges and VLAN tags, startup order and delays, who it talks to and who
talks to it with ports, its external dependencies (top destinations outside
the house), and what the guest agent reported. *Export JSON* saves the whole
map; *Export requirements* renders the selected guest as a Markdown table.

**What the map can and cannot see.** Traffic between two guests on the same
bridge and subnet never crosses the gateway, so the flow probe cannot see
it; observed edges cover traffic routed between your subnets and to the
internet. With *Ask VMs for their connections* on (`probe_sockets`, off by
default), FlowSight runs one fixed command, `ss -Htn state established`,
inside each running VM through the guest agent and draws what the VM's own
kernel reports, which does cover same-subnet traffic for VMs. That needs
the VM.Monitor privilege on the token. Containers have no agent, so
container-to-container traffic on one subnet appears only through declared
relationships.

## Packet Inspection

The **Packet Inspection** page gives you two views of traffic:

### Stateful Packet Inspection (SPI)

The *States* tab shows the firewall's own connection state table, captured
every 30 seconds (configurable). You see each active TCP, UDP and ICMP flow,
its state (ESTABLISHED, SYN_SENT, etc.), age, packets and bytes in each
direction, and the rule number that allowed it.

**Use SPI to**:
- Troubleshoot half-open connections and SYN floods (the *half-open* KPI and
  *SYN_SENT* state filter)
- Find long-lived idle states that might be holding resources
- Understand traffic flows in real time without capture overhead

**Anomaly detection**: The module flags **SYN floods** (many half-open
connections from one source in the poll window) and **port scans** (one
source attempting connections to many different destinations in
non-established states). Findings flow through your alert channels.

States are aggregated: you see up to 20,000 of the newest states in memory,
and older ones are discarded as new flows are created. Filter by host, protocol
or state type; use the live per-second state delta to watch the conversation
rate.

### Deep Packet Inspection (DPI)

The *Capture* tab lets you record traffic with `tcpdump` and analyse it with
Wireshark-class parsing. Start a capture on any interface with optional BPF
filtering (preset filters: DNS, HTTPS, HTTP, local traffic exclusion, ARP).
Set snaplen to 96 bytes for headers only (the default, privacy-friendly) or
65535 for full payloads (if your settings allow); captures rotate into 20 MB
files with a total cap of 100 MB. Hard timeout: 10 minutes.

Once a capture finishes, the page auto-analyzes it: per-conversation table
(5-tuple, packets/bytes each way, TCP flags, retransmissions, RTT estimate,
zero-window and reset counts), protocol counts (Ethernet, IP, TCP, UDP, ICMP,
ARP, DNS, TLS, HTTP, QUIC, mDNS, SSDP, DHCP, NTP), extracted artefacts:
- **DNS**: queries and answers with response codes
- **TLS**: SNI, JA3-like fingerprint, certificate CN/SAN from handshakes
- **HTTP**: request line, Host header, User-Agent (plaintext only)
- **DHCP**: options and fingerprints
- **ARP**: who-has/is-at and gratuitous ARP
- **ICMP**: types and codes

**Expert notes** flag anomalies: retransmission, duplicate ACK, zero window,
reset, TCP port reuse, ARP conflict, DNS response without a query, etc.

**Top talkers** by bytes and packets. A protocol hierarchy bar chart. Download
the pcap file for offline analysis in Wireshark.

The *Live* tab (experimental) streams packet summaries in real time for 30
seconds, one-line format, no analysis: use it to watch traffic while it
happens.

**Capture notes**:
- Root-only: capture files are root-owned, readable only by FlowSight.
- Payload is sensitive: if snaplen is 65535, the pcap contains user data,
  headers and payloads. The default 96 bytes captures only headers.
- Free space check: a capture cannot start if less than 1 GB is free.
- Captures live under your data directory; oldest are deleted first when the
  total size cap is reached.

## Administration

### Setup wizard

A guided 12-step wizard for initial configuration after installation. Open it the first time you log in, or anytime under **Administration › Setup wizard**.

**Step 1: Welcome & license.** Optionally activate a Pro or Business license key.

**Step 2: Site basics.** Installation name (shows in the sidebar), data retention in days, and the Go memory limit (default 256 MB).

**Step 3: Traffic source.** Where to read network traffic. ntopng URL and credentials if authentication is required. The wizard detects ntopng's presence and can test the connection.

**Step 4: DNS source.** Where to read DNS queries. Pi-hole address and API token (optional; empty means use the local Unbound resolver). The wizard scans for Pi-hole on the gateway's subnet and tests connectivity.

**Step 5: Interception.** Whether to redirect web traffic through the transparent proxy for server names and blocking. Off by default. Choose which interfaces (empty means all).

**Step 6: Identity & zones.** Delegated to **Settings › identity**: review auto-detected local networks and name the zones.

**Step 7: Security.** Enable IDS (Suricata) and TLS probing (record server certificates without decrypting).

**Step 8: Inventory.** Proxmox host, API token ID, secret, and server certificate fingerprint for VM/LXC integration. The wizard can probe for Proxmox and test the connection.

**Step 9: Alerting.** Delegated to **Settings › alerting**: add a notification channel (e-mail, webhook, Discord, Slack, ntfy).

**Step 10: Updates.** Manifest URL (leave empty for the official manifest) and whether to auto-apply updates.

**Step 11: API access.** Shows the API bind address (localhost or LAN) and token status. Bind, port and token are file-only settings; edit the config file to change them.

**Step 12: Review & finish.** Marks the wizard complete so the banner on the Overview disappears.

Each step is saved immediately. You can skip steps or re-run the wizard anytime to change settings later. The wizard never touches OPNsense firewall rules, SSH, or the GUI listener.

### Reports

**Report Builder**: Create custom reports by selecting sections, setting
filters, and choosing output formats. Each report is a reusable definition
that can be run on-demand or scheduled.

**Sections** (select one or more per report):
- Executive Summary: High-level metrics (hosts, flows, bytes, alerts)
- Traffic by Device: Flows and bytes per source device
- Traffic by Zone: Aggregated activity by network zone
- Traffic by Application: Ranking by application type
- Traffic by Category: Content categories in use
- Traffic by Site: Top destination domains
- Blocked Activity: Policy violations and rejected requests
- Egress Activity & DLP: Large outbound transfers, first-seen destinations
- DNS Summary: Query counts, top domains, block rates
- TLS Posture: Protocol versions, certificate trust, interception coverage
- Scan Findings: Security findings from device identification
- Device Inventory Changes: New devices, renames, zone moves
- Alerting Deliveries: Notification delivery log
- System Health: Uptime, memory, job failures
- Security Alerts: IDS/IPS threats by severity and signature

Each section honors **Filters** (source IP, application, category, domain
pattern, verdict, severity) and supports **Group By** (device, zone,
application, category, site, hour, day) with **Top N** limiting.

**Formats** (select one or more): HTML, PDF, Markdown, JSON, CSV. Multi-format
reports are stored separately and downloaded by format.

**Scheduling**: Set cadence (hourly, daily, weekly, monthly) and time; enable
scheduled delivery through configured alerting channels (email, webhook,
Discord, Slack, ntfy). Scheduled reports run once per period; restarts do not
trigger duplicate runs. Next-run times are tracked in the database.

**Run History**: Recent runs are listed with status, size, and format-specific
download links. Built-in definitions are read-only but can be duplicated and
customized. Reports are retained per definition (keep_runs setting) and
globally (max_total_mb), with oldest pruned first.

**On-Disk Storage**: Reports are stored under `<DataDir>/reports/<definition>/`
with metadata indexed in KV for fast lookup and retention enforcement. Downloaded
reports are served with proper authentication and content types.

### Alerting

Comprehensive multi-channel alerting system with 54+ notification destinations, flexible rule routing, digest bundling, escalation, and quiet hours.

#### Channels

Connect to notification services via channel types grouped by family:

**Chat & Collaboration (11)**: Slack, Discord, Microsoft Teams, Telegram, Mattermost, Rocket.Chat, Google Chat, Matrix, Pushover, Pushbullet, Home Assistant

**Email (5)**: SMTP, SendGrid, Mailgun, Amazon SES, Postmark

**SMS & Voice (7)**: Twilio, Vonage, Telnyx, AWS SNS, Plivo, MessageBird, ClickSend

**Incident Management (8)**: PagerDuty, Opsgenie, Splunk On-Call, Squadcast, incident.io, xMatters, Zenduty, Better Stack

**SIEM & Logging (14)**: Splunk HEC, Elastic, OpenSearch, Graylog, Microsoft Sentinel, Datadog, Sumo Logic, New Relic, Grafana Loki, Sentry, AWS CloudWatch, QRadar, Wazuh, Syslog

**Generic (3)**: Webhook (HTTP POST with signatures), MQTT, RSS feed

Each channel requires configuration (API keys, URLs, recipients). *Test* sends a test message to verify connectivity. Secrets are masked in the UI and database after initial save.

#### Rules

Route alerts based on:
- **Severity**: Trigger at or above a threshold (info, low, medium, high, critical)
- **Source**: Filter by module, category, device IP/MAC, or zone
- **Channels**: One or more destinations for matched alerts
- **Cooldown**: Prevent alert fatigue; minimum seconds between identical alerts
- **Digest**: Bundle low-severity alerts into periodic summaries (N minutes)
- **Escalation**: Automatically escalate to additional channels if unacknowledged after N minutes
- **Quiet hours**: Skip or defer delivery during specified times

#### Maintenance Mode

Temporarily suppress all alerts (useful during maintenance windows). Set duration in minutes or enable indefinitely with optional reason.

#### Simulation & Testing

- **Simulate alert**: Test rule matching and channel delivery without waiting for real alerts
- **Apprise import**: Migrate channel configs from Apprise URLs (supports 90+ providers)
- **Delivery log**: View recent delivery attempts with status, latency, and error details

#### Setup: Channel-Specific Tables

| Channel | Setup | Notes |
|---------|-------|-------|
| Slack | Create Incoming Webhook at api.slack.com; paste URL | Supports message threads, blocks formatting |
| Discord | Create Webhook in channel settings; paste URL | JSON-formatted embeds with severity colors |
| Teams | Create Incoming Webhook in channel connectors; paste URL | Adaptive cards with action buttons |
| Telegram | Create bot via @BotFather; paste bot token and chat ID | Supports HTML, inline buttons |
| Twilio | API credentials from twilio.com; add phone numbers | SMS format: title [SEV]: body (160 char limit) |
| PagerDuty | Create integration key in service settings | Auto-creates incidents; escalates if acked not resolved |
| Opsgenie | API key from integrations; configure team/responders | Incident routing based on severity |
| SendGrid | API key from settings; configure from address | HTML emails with severity-based styling |
| Splunk HEC | Enable HEC, create token, paste URL and port | CEF/JSON event format with timestamp |
| Datadog | API + app key from organization settings | Posts events to Datadog event stream |
| AWS SNS | IAM credentials with SNS publish permission; topic ARN | Supports SMS via SNS subscriptions |
| Webhook | Any URL accepting JSON POST | Custom payload via Go template; HMAC-SHA256 signature |
| MQTT | Broker address, port, topic, optional credentials | Binary-safe payload; QoS 1 default |
| Syslog | Server address, port (usually 514); facility level | CEF/LEEF format; UDP or TCP |
| Grafana Loki | API endpoint, optional credentials, log labels | Streams alerts as structured logs with labels |
| Sentry | DSN from project settings | Captures alerts as events; auto-groups similar ones |

All channels support:
- **Test message** to verify connectivity before enabling
- **Severity abbreviation**: [C] critical, [H] high, [M] medium, [L] low, [I] info
- **Device context**: IP, hostname, zone (if available in alert)
- **Links**: Click-through to relevant page in FlowSight UI
- **Retry**: Automatic retry with exponential backoff (3 attempts, up to 2s delay)

### Findings

Every open finding from every module in one list: severity, who, what,
where, why (with *What to do* for device advisories), when first seen. Acknowledge to silence one until it changes.
Findings close on their own when the condition stops being true.

### Events

The event log: configuration changes, applies and their outcome, license
changes, updates, service starts, module errors. Filter by module or kind.
The **Audit** view lists every write operation with the user and client
address, and every configuration change with its diff.

### Status

What the daemon reports about itself, read-only: version, platform,
uptime, memory in use and the soft limit, store size and row counts per
table, retention, module health (each module's state and detail), the job
list with last run, duration and failures (a locked job means the license
tier does not include it), and the platform paths in use. *Run job*
triggers any job now. Useful first stop when something looks off.

Status and Settings are deliberately separate: **Status** is what
FlowSight is doing and how it is faring; **Settings** is what you tell it
to do. Nothing on the Status page changes configuration.

### Settings

One page per module: enable or disable it (restart to apply), and its
settings with help text. A setting left empty that means "use the platform
default" shows what is actually in use beneath the field (*Using: …*), such
as the detected local networks, the resolver log being followed or the
interfaces interception applies to; the field itself stays empty so the
default keeps following the platform. Saving applies immediately unless the
setting is marked restart. A module above the current tier shows its tier and cannot
be enabled. Every setting is listed in the
[Configuration reference](CONFIGURATION.md).

**dns** has these tabs: *Resolver* (the module's settings), *Device names*
(every device name FlowSight put in DNS, see [Give a device a DNS
name](howto/local-names.md)) and, while a Pi-hole v6 server is connected,
*Pi-hole* (its settings, see [Pi-hole with FlowSight](howto/pihole.md)) and
*Pi-hole blocking* (lists, entries, groups, clients, FlowSight categories as
Pi-hole lists, gravity and keeping several Pi-holes the same, on one Pi-hole
or all of them). All DNS
configuration is here; *Monitor › DNS* only watches.

**identity** › *Send device names to the DHCP server* (on by default): names
given in FlowSight also go to the DHCP server (dnsmasq), which gives each
device its name with its next lease. Names only, never addresses; a device
with its own OPNsense static host keeps it. The page lists what was sent and
what was left alone. See [Give a device a DNS name](howto/local-names.md).

**pihole** connects FlowSight to your Pi-holes (servers and app password) and
pulls their query logs; what the Pi-holes do is configured on *Settings ›
dns › Pi-hole*.

Two modules hold interface behaviour rather than network function:
**enrich** (reverse-DNS names and country lookup for bare addresses, both
off by default) and **ui** (the theme: auto, light or dark).

### Updates

Installed version, latest published version, release notes. **Check now**
fetches the signed manifest; **Install update** downloads the binary,
verifies its checksum and signature against the key compiled into the
running build, swaps it in atomically and restarts the service (about ten
seconds); **Roll back** restores the previous binary. Only a newer version
is ever applied. *Apply updates automatically* in Settings › updater does
the same on the daily check.

### License

The tier this installation runs, the licensee, expiry and seats, and how
the license got here (online activation with its lease, or a file). Two
forms: **Activate online** with an activation key, and **Install a license
file** for air-gapped installations (the installation id to quote is shown
here). The tier comparison lists every gated feature and the limits. *Remove
license* returns to Community and frees the seat. See
[Licensing](LICENSING.md).

### API

Interactive explorer for the FlowSight REST API. Operations are organized by
area: Monitor (visibility, hosts, flows, applications, web, DNS, map, data
out), Inventory (devices, zones), Protect (policy, QoS, categories, TLS,
threats, firewall), and Administration (reports, alerts, updates, license,
API itself).

Click any operation to expand it and see its parameters, request body
template, and examples. The **Send request** button calls the API through
your session; write operations (POST, PUT, DELETE) ask for confirmation.
**Copy as curl** exports the request with your token for use in scripts or
other tools.

The **Download OpenAPI JSON** link on the right fetches the machine-readable
specification for use with API clients, code generators, or documentation
tools (Swagger UI, Insomnia, Postman, etc.).

Every write is recorded in the audit log (Status › Events › Audit) with the
user and client address. Bearer token authentication and X-Flowsight-Token
headers are supported in addition to session cookies.

## Keyboard and browser notes

**Signing in and out.** Outside the OPNsense GUI, FlowSight asks for an API
token and opens a 12-hour session; *Log out* under the version in the menu
ends it on the server. Repeated wrong tokens from one address lock that
address out for a while. Where HTTPS is on (`https_port`, 8443 by default),
use `https://<gateway>:8443/`; with `http_local_only` plain HTTP redirects
there.

**Search.** `/` focuses SmartSearch from anywhere; `↑`/`↓` and Enter pick a
result; Esc closes the dropdown, and Esc again clears the search.

**Arranging cards.** Every card on every page can be moved: drag it by its
heading (the grip at the left of the heading is the handle) to a new place
among its neighbours. The arrangement is kept in this browser, per page, and
survives refreshes. Click the grip for a menu: move earlier or later, *Save
this page's layout as default*, *Reset to default*, or forget the default and
go back to the built-in order. While a page differs from its default a
*Reset layout* button shows in the header. On a touch screen use the grip
menu rather than dragging.


The interface has no build step and no external resources; it works
offline and inside the OPNsense GUI frame. It refreshes pages that show
live data every few seconds while the tab is visible, and stops when it is
hidden. Deep links use the hash (`#host/10.0.0.5`, `#flows?domain=…`), so
the browser back button and bookmarks work.
