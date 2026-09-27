# HOWTO: categories and applications, and how each is identified

FlowSight uses two things called a category. They come from different places, describe different things, and are enforced at different points. This page says which is which.

## Web-content categories (Protect › Categories)

A web-content category is a list of domain names. The built-in ones are downloaded from open feeds (ads, tracking, malware, phishing, ransomware, scam, fraud, abuse and others from the Blocklist Project) and refreshed on a timer; custom ones are typed in. *View* on the Categories page shows the list as cached on the gateway, searchable, with the source and the time it was fetched; *Download* gives the file.

**How a name is matched.** A domain belongs to a category when it, or any parent of it, is in the list: `ads.example.net` matches an entry for `example.net`. The lookup box on the page answers for one name.

**Where it is enforced.** A policy's *Categories* field denies these lists by name: the DNS provider writes them into an Unbound response-policy zone, so the name does not resolve for the policy's members, and the web provider writes them into squid, so an inspected request to the name is refused. Both enforce on the name, never on the address.

**The whitelist.** The reserved custom category *whitelist* works the other way round: names in it are never blocked by any policy. The compiler folds them into every policy's allow-list.

## Application categories (nDPI)

An application category belongs to nDPI, the deep-packet-inspection library that ntopng runs on the gateway. nDPI inspects the first packets of a flow and names the application: `TLS.Apple`, `QUIC.YouTube`, `WhatsApp`, `BitTorrent`, `SSH`, `NTP`. Every application it knows is assigned, inside nDPI's own protocol tables, one **category** (Web, Media, Cloud, SoftwareUpdate, Advertisement, Game, VoIP, Chat, SocialNetwork, VPN, RemoteAccess, Mining, Cybersecurity, Download, Streaming and more) and one **breed**, a coarse risk grade (safe, acceptable, fun, unsafe, potentially dangerous). FlowSight does not define these; it reads them from ntopng's catalogue and shows them as they are.

**How an application is identified.** By the flow itself: protocol signatures, TLS server names and certificate fields, HTTP hosts, QUIC handshakes, port and behaviour heuristics. A flow nDPI cannot place is *Unknown*; FlowSight then falls back to what else it can see (the server name, the port, the network that announces the address) to label it, which is what the DLP page's *Other* split does.

**Where it is enforced.** A policy's *Apps* and *App categories* fields deny applications by identity: application control watches the identified flows and cuts matching ones off at the firewall, addresses learned from the flow are held in a table for a while, and existing connections can be killed. This works on the identified traffic, whatever name or address it uses, which is what makes it different from a domain list.

## Side by side

| | Web-content categories | Application categories |
|---|---|---|
| Defined by | Domain-list feeds and your custom lists | nDPI, inside ntopng |
| Unit | A domain name | An identified application (and its category and breed) |
| Identified from | The name asked for or connected to | The flow's own packets |
| Enforced by | Unbound (DNS) and squid (web) | Application control at the firewall |
| Set in a policy | *Categories*, *Domains*, *TLDs*; *Allow › Domains* and the whitelist | *Apps*, *App categories*; *Allow › Apps* |
| Seen on | Web page, Categories page | Applications page, DLP page |

## Related

- *User guide › Categories*, *User guide › Applications*, *User guide › Policies*
- [Watch what leaves the network (DLP)](dlp-watch.md)
