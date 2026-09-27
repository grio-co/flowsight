package pihole

// The Pi-hole settings FlowSight offers to change, grouped the way a person
// thinks about them, each with what it does in plain words, what FlowSight
// recommends and why. Pi-hole's own description travels beside it. Settings
// that can stop the Pi-hole answering (its port, interface, listening mode)
// are shown but not writable from here: a wrong value there takes every
// client's DNS down, and the fix then needs the Pi-hole's console.
type phSetting struct {
	Key       string
	Section   string
	Label     string
	Guide     string
	Recommend any    // nil: no single right answer
	Why       string // why the recommendation
	Caution   string // shown before a change is applied
	ReadOnly  string // non-empty: not writable from FlowSight, and why
}

var phSections = []struct{ ID, Title, Intro string }{
	{"blocking", "Blocking", "How the Pi-hole answers for a name it blocks, and for how long devices remember that answer."},
	{"special", "Device-specific behaviour", "Built-in answers Pi-hole gives for names that tell Apple devices and Firefox how to behave on this network. These are not blocklist entries; each has its own switch."},
	{"upstream", "Upstream and resolution", "Where the Pi-hole sends the questions it cannot answer itself, and how strictly it checks the answers."},
	{"local", "Local names", "Names the Pi-hole answers itself, and where it asks for names on your own network."},
	{"limits", "Limits and load", "Protections that can surprise you when one address makes many queries, such as the gateway forwarding for the whole network."},
	{"visibility", "Logging and what FlowSight can see", "FlowSight's DNS history, device advisories and per-device DNS views are built from the Pi-hole's query log. These settings decide whether that log exists."},
	{"fixed", "Network binding (view only)", "Shown for reference. Changing these from a web page can stop the Pi-hole answering anyone, so FlowSight leaves them to the Pi-hole's console."},
}

var phCatalogue = []phSetting{
	{Key: "dns.blocking.active", Section: "blocking", Label: "Blocking enabled",
		Guide:     "Master switch for ad and tracker blocking. Off, the Pi-hole still resolves names but blocks nothing. To turn blocking off for a few minutes, use Pause instead: it switches itself back on.",
		Recommend: true, Why: "A forgotten 'off' leaves the network unfiltered; Pause is safer for troubleshooting."},
	{Key: "dns.blocking.mode", Section: "blocking", Label: "Blocked answer",
		Guide:     "What a device receives for a blocked name. NULL answers 0.0.0.0 / ::, so connections fail at once without a network round trip. NX says the name does not exist, which some apps retry aggressively. NODATA says the name exists but has no address. IP answers with the Pi-hole's own address, which shows a certificate error for every blocked HTTPS site.",
		Recommend: "NULL", Why: "Fastest failure, fewest retries, no certificate warnings."},
	{Key: "dns.blockTTL", Section: "blocking", Label: "Blocked answer lifetime (s)",
		Guide:     "How long a device may reuse a blocked answer before asking again. Short means an allow-list change takes effect almost at once; long means fewer repeat queries from apps that keep retrying.",
		Recommend: 2, Why: "Allowing a name should work immediately when you are fixing a device."},
	{Key: "dns.cache.upstreamBlockedTTL", Section: "blocking", Label: "Upstream-blocked cache (s)",
		Guide: "When the upstream resolver itself blocks a name (a filtering upstream such as Quad9), how long the Pi-hole remembers that. Zero turns the caching off."},
	{Key: "dns.CNAMEdeepInspect", Section: "blocking", Label: "Inspect CNAME chains",
		Guide:     "Also block a name when it is an alias (CNAME) for a blocked name. Catches trackers that hide behind a first-party name.",
		Recommend: true},
	{Key: "dns.blockESNI", Section: "blocking", Label: "Block ESNI keys",
		Guide:     "Answers NXDOMAIN for _esni names, so Firefox does not encrypt the server name in the TLS handshake. This keeps names visible to FlowSight and to Pi-hole's own blocking.",
		Recommend: true, Why: "Encrypted server names hide destinations from FlowSight's visibility and policy."},

	{Key: "dns.specialDomains.iCloudPrivateRelay", Section: "special", Label: "Block iCloud Private Relay",
		Guide:   "On, the Pi-hole answers NXDOMAIN for mask.icloud.com and mask-h2.icloud.com. Apple devices then say “Private Relay is not available”, and Safari can fail to load pages until the person turns Private Relay off for this Wi-Fi. Off, Safari traffic from devices with Private Relay goes through Apple's relay, which neither the Pi-hole nor FlowSight can see into.",
		Why:     "No single right answer: on keeps browsing visible and filtered but breaks Safari until each device is changed; off keeps Safari working but hides it. FlowSight raises a device advisory whenever a device keeps hitting this block.",
		Caution: "Turning this on can stop Safari loading pages on iPhones, iPads and Macs that use Private Relay until each is changed."},
	{Key: "dns.specialDomains.mozillaCanary", Section: "special", Label: "Keep Firefox on this resolver",
		Guide:     "On, answers NXDOMAIN for use-application-dns.net, which tells Firefox not to switch itself to DNS-over-HTTPS. Off, Firefox may send its lookups to Cloudflare or another provider, bypassing the Pi-hole and FlowSight's DNS history.",
		Recommend: true, Why: "Keeps Firefox's lookups filtered and visible."},
	{Key: "dns.specialDomains.designatedResolver", Section: "special", Label: "Refuse automatic encrypted-DNS upgrade",
		Guide:     "On, answers NODATA for _dns.resolver.arpa, so devices do not discover and move to an encrypted resolver elsewhere (Discovery of Designated Resolvers). Off, Windows 11, Android and Apple devices may upgrade to encrypted DNS and leave the Pi-hole.",
		Recommend: true, Why: "Keeps devices on the resolver you filter and log."},

	{Key: "dns.upstreams", Section: "upstream", Label: "Upstream servers",
		Guide:   "Where the Pi-hole forwards names it does not answer itself, one per line, optionally with a port after #, such as 127.0.0.1#5053 for a local DNS-over-HTTPS proxy. Two independent providers give resilience; a filtering upstream (such as Quad9) adds malware blocking.",
		Caution: "A wrong address here makes every lookup through this Pi-hole fail."},
	{Key: "dns.dnssec", Section: "upstream", Label: "Validate DNSSEC",
		Guide: "Check signatures on signed answers and refuse forged ones. Needs an upstream that passes DNSSEC records through; if the upstream strips them, signed domains start failing with SERVFAIL.",
		Why:   "Safer, but test with your upstream: a failing DNSSEC setup shows up as the 'Name lookups are failing' device advisory."},
	{Key: "dns.domainNeeded", Section: "upstream", Label: "Never forward plain names",
		Guide:     "Do not send single-label names (“printer” with no dot) to the internet. They cannot resolve there and only leak what you are looking for.",
		Recommend: true},
	{Key: "dns.bogusPriv", Section: "upstream", Label: "Never forward private reverse lookups",
		Guide:     "Do not ask the internet who owns 192.168.x.x and other private addresses. Needed off only when conditional forwarding is not set and something depends on those answers.",
		Recommend: true},
	{Key: "dns.EDNS0ECS", Section: "upstream", Label: "Honour client subnet hints",
		Guide: "Pass the EDNS Client Subnet a client supplied on to the upstream, so CDNs can pick a nearby server. Leaks part of the client's address to the upstream."},
	{Key: "dns.cache.size", Section: "upstream", Label: "Cache size (entries)",
		Guide: "How many answers the Pi-hole remembers. 10000 is ample for a home; raising it costs a little memory, lowering it means more upstream lookups."},

	{Key: "dns.revServers", Section: "local", Label: "Conditional forwarding",
		Guide: "Where to ask for names and reverse lookups on your own networks, so the Pi-hole (and FlowSight) can show “Kitchen-iPad” instead of an address. One per line: true,192.168.1.0/24,192.168.1.1,lan (enabled, network, the router or DHCP server that knows the names, local domain)."},
	{Key: "dns.domain.name", Section: "local", Label: "Local domain",
		Guide: "The domain the Pi-hole treats as local, appended to plain names in its own records."},
	{Key: "dns.hosts", Section: "local", Label: "Local DNS records",
		Guide: "Names the Pi-hole answers itself, one per line in hosts form: 192.168.1.10 nas nas.lan. Useful for giving servers stable names."},
	{Key: "dns.cnameRecords", Section: "local", Label: "Local aliases (CNAME)",
		Guide: "Aliases that point one name at another, one per line: alias.lan,target.lan. The target must be a name the Pi-hole can resolve."},

	{Key: "dns.rateLimit.count", Section: "limits", Label: "Rate limit: queries",
		Guide: "How many queries one client may make per interval before the Pi-hole refuses it (REFUSED) until the interval ends. Zero turns it off. A gateway or second resolver forwarding for the whole network counts as one client and can hit this, taking everyone's DNS down for the rest of the interval.",
		Why:   "If the gateway forwards to this Pi-hole, raise this well above normal or set 0."},
	{Key: "dns.rateLimit.interval", Section: "limits", Label: "Rate limit: interval (s)",
		Guide: "The window the rate limit counts over."},
	{Key: "dns.replyWhenBusy", Section: "limits", Label: "When the database is busy",
		Guide:     "What to do with a query that arrives while the Pi-hole is rewriting its blocklists. ALLOW answers without checking (briefly unfiltered). BLOCK blocks everything for that moment. REFUSE and DROP make clients retry.",
		Recommend: "ALLOW", Why: "A gravity update should never look like an outage."},

	{Key: "dns.queryLogging", Section: "visibility", Label: "Log queries",
		Guide:     "Record every query. Off, the Pi-hole still blocks, but FlowSight's DNS history, per-device DNS, and device advisories stop for everything this Pi-hole answers.",
		Recommend: true, Why: "FlowSight reads this log.",
		Caution: "Turning this off blinds FlowSight's DNS history and device advisories for this Pi-hole."},
	{Key: "misc.privacylevel", Section: "visibility", Label: "Privacy level",
		Guide:     "How much the Pi-hole's statistics and API reveal. 0 shows everything. 1 hides domains, 2 hides domains and clients, 3 turns statistics off. Above 0, FlowSight imports queries without names or without clients and cannot tell which device asked what.",
		Recommend: float64(0), Why: "FlowSight needs the domain and the client to attribute a query to a device."},
	{Key: "dns.analyzeOnlyAandAAAA", Section: "visibility", Label: "Only count A and AAAA",
		Guide: "Leave other record types (HTTPS, SRV, PTR) out of the statistics. They are still answered and logged."},
	{Key: "dns.ignoreLocalhost", Section: "visibility", Label: "Ignore the Pi-hole's own queries",
		Guide: "Leave queries the Pi-hole machine makes for itself out of the log and statistics."},

	{Key: "dns.listeningMode", Section: "fixed", Label: "Listening mode",
		Guide:    "Which clients the Pi-hole answers. LOCAL answers only its own subnets; ALL answers anyone, which is unsafe on a machine reachable from the internet.",
		ReadOnly: "A wrong value stops the Pi-hole answering your network. Change it on the Pi-hole (Settings › DNS › Interface settings)."},
	{Key: "dns.interface", Section: "fixed", Label: "Interface",
		ReadOnly: "The network interface the Pi-hole listens on; a wrong value stops it answering."},
	{Key: "dns.port", Section: "fixed", Label: "Port",
		ReadOnly: "Devices only ask on port 53; moving it stops them resolving."},
}

func settingFor(key string) *phSetting {
	for i := range phCatalogue {
		if phCatalogue[i].Key == key {
			return &phCatalogue[i]
		}
	}
	return nil
}
