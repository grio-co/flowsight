package advisor

import "strings"

// A rule names DNS answers that break something on the device that asked,
// says what the person holding the device sees, and says how to fix it.
// These are not threats: they are the "my phone can't browse" class of
// problem, where every packet is allowed and the network looks healthy, yet
// a resolver answer quietly turns a feature off. The catalogue is curated:
// each entry is a name a device depends on for something it cannot do
// without.
type rule struct {
	Kind     string
	Severity string
	Title    string
	// Effect is what the person sees, in their words, not the network's.
	Effect string
	// Fix is the generic remedy; fixFor adds the resolver-specific one.
	Fix     string
	Exact   []string
	Suffix  []string // matched as a label boundary: ".push.apple.com"
	Min     int      // failed answers in the window before it counts
	Devices string   // who is affected, for the page: "Apple devices"
}

var rules = []rule{
	{
		Kind: "private_relay_blocked", Severity: "high", Min: 3, Devices: "iPhone, iPad and Mac with iCloud Private Relay on",
		Title:  "iCloud Private Relay is blocked",
		Effect: "The device shows “Private Relay is not available” and Safari can stall or refuse to load pages until Private Relay is turned off for this network. Apps that do not use the relay keep working, so it looks like “only the browser is broken”.",
		Fix:    "Either allow mask.icloud.com and mask-h2.icloud.com on the resolver, or on the device turn off Limit IP Address Tracking for this Wi-Fi (Settings › Wi-Fi › ⓘ) or Private Relay itself (Settings › your name › iCloud › Private Relay).",
		Exact:  []string{"mask.icloud.com", "mask-h2.icloud.com", "mask-api.icloud.com", "mask-t.apple-dns.net", "mask.apple-dns.net"},
	},
	{
		Kind: "connectivity_check_blocked", Severity: "high", Min: 2, Devices: "phones, tablets and laptops",
		Title:  "Internet connectivity check is blocked",
		Effect: "The device decides this network has no internet: it may pop up a Wi-Fi sign-in sheet, mark the connection “No Internet” or “Limited”, or quietly move traffic to cellular.",
		Fix:    "Allow the connectivity-check name on the resolver. These names only ever serve a tiny test page.",
		Exact: []string{"captive.apple.com", "captive.g.aaplimg.com", "connectivitycheck.gstatic.com", "connectivitycheck.android.com",
			"clients3.google.com", "clients1.google.com", "www.msftconnecttest.com", "www.msftncsi.com", "dns.msftncsi.com",
			"ipv6.msftconnecttest.com", "detectportal.firefox.com", "nmcheck.gnome.org", "network-test.debian.org", "connectivity-check.ubuntu.com"},
	},
	{
		Kind: "time_sync_blocked", Severity: "medium", Min: 3, Devices: "any device",
		Title:  "Network time is blocked",
		Effect: "The clock drifts. Once it is minutes off, certificates look invalid: sign-ins fail, two-factor codes are rejected and some sites refuse to load.",
		Fix:    "Allow the time server's name on the resolver.",
		Exact: []string{"time.apple.com", "time-ios.apple.com", "time-macos.apple.com", "time.euro.apple.com", "time.asia.apple.com",
			"time.windows.com", "time.google.com", "time.android.com", "time.cloudflare.com", "time.nist.gov"},
		Suffix: []string{".pool.ntp.org"},
	},
	{
		Kind: "cert_check_blocked", Severity: "medium", Min: 3, Devices: "any device",
		Title:  "Certificate status checks are blocked",
		Effect: "Apps launch slowly while the device waits for a revocation check that never answers; some apps, installers and enterprise sign-ins refuse to continue.",
		Fix:    "Allow the OCSP/CRL name on the resolver. These answer only whether a certificate is still valid.",
		Exact: []string{"ocsp.apple.com", "ocsp2.apple.com", "valid.apple.com", "crl.apple.com", "ocsp.digicert.com", "crl3.digicert.com",
			"crl4.digicert.com", "ocsp.pki.goog", "crl.pki.goog", "ocsp.sectigo.com", "ocsp.usertrust.com", "ocsp.globalsign.com",
			"ocsp.entrust.net", "ocsp.godaddy.com", "status.rapidssl.com", "ocsp.msocsp.com", "oneocsp.microsoft.com"},
		Suffix: []string{".o.lencr.org", ".c.lencr.org"},
	},
	{
		Kind: "push_blocked", Severity: "medium", Min: 3, Devices: "phones and computers",
		Title:  "Push notifications are blocked",
		Effect: "Notifications stop arriving: messages, calls and app alerts show up late or not at all, and apps drain battery polling instead.",
		Fix:    "Allow the push service's name on the resolver.",
		Exact:  []string{"mtalk.google.com", "client.wns.windows.com", "api.push.apple.com"},
		Suffix: []string{".push.apple.com", "-mtalk.google.com", ".notify.windows.com"},
	},
	{
		Kind: "updates_blocked", Severity: "low", Min: 3, Devices: "any device",
		Title:  "Software update checks are blocked",
		Effect: "The device cannot check for or download security updates, and may nag about it.",
		Fix:    "Allow the update service's name on the resolver.",
		Exact: []string{"mesu.apple.com", "gdmf.apple.com", "updates.cdn-apple.com", "swscan.apple.com", "swdist.apple.com",
			"swcdn.apple.com", "xp.apple.com", "fe2.update.microsoft.com", "sls.update.microsoft.com", "android.clients.google.com"},
		Suffix: []string{".windowsupdate.com", ".update.microsoft.com", ".delivery.mp.microsoft.com"},
	},
	{
		Kind: "trust_check_blocked", Severity: "low", Min: 3, Devices: "any device",
		Title:  "Sign-in and checkout protection is blocked",
		Effect: "Some apps and sites will not let you sign in, pay or verify an account, because they wait for their fraud-check or challenge service before continuing.",
		Fix:    "If sign-in or checkout fails in an app, allow the named service on the resolver; if nothing is failing, the block can stay.",
		Exact:  []string{"challenges.cloudflare.com", "js.stripe.com", "m.stripe.network", "m.stripe.com"},
		Suffix: []string{".siftscience.com", ".sift.com", ".forter.com", ".riskified.com", ".hcaptcha.com", ".arkoselabs.com", ".funcaptcha.com", ".perimeterx.net", ".px-cloud.net"},
	},
}

// ruleFor returns the rule a name belongs to, or nil.
func ruleFor(domain string) *rule {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if d == "" {
		return nil
	}
	for i := range rules {
		r := &rules[i]
		for _, e := range r.Exact {
			if d == e {
				return r
			}
		}
		for _, s := range r.Suffix {
			// ".push.apple.com" matches "1-courier.push.apple.com"; a suffix
			// without a leading dot ("-mtalk.google.com") matches the name's
			// tail, which is how Google numbers its push hosts.
			if strings.HasSuffix(d, s) && len(d) > len(s) {
				return r
			}
		}
	}
	return nil
}

// Rules not tied to a name list.
const (
	kindDNSFailing  = "dns_failing"
	kindRetryStorm  = "blocked_retry_storm"
	failingPctMin   = 20  // percent of a device's queries that SERVFAIL/REFUSED
	failingQueryMin = 40  // queries in the window before the rate means anything
	retryStormMin   = 120 // blocked answers for one name in the window
)

// fixFor returns the remedy for a rule, made specific when the resolver and
// the list that answered are known. A Pi-hole "special domain" answer is a
// built-in Pi-hole behaviour with its own switch, not a blocklist entry, and
// saying which switch is the difference between a fix and a hunt.
func fixFor(r *rule, source, list string) string {
	res := resolverName(source)
	switch {
	case r != nil && r.Kind == "private_relay_blocked" && list == "pihole special domain":
		return "Pi-hole " + resolverIP(source) + " answers NXDOMAIN for Private Relay on purpose (its dns.specialDomains.iCloudPrivateRelay setting, on by default). " +
			"To let the relay work: pihole-FTL --config dns.specialDomains.iCloudPrivateRelay false on each Pi-hole. " +
			"To keep the relay off instead: on the device turn off Limit IP Address Tracking for this Wi-Fi, or turn Private Relay off."
	case r == nil:
		return ""
	case strings.HasPrefix(list, "pihole"):
		return r.Fix + " On " + res + " the answer came from its " + strings.TrimPrefix(list, "pihole ") + " list: allow the name under Domains › Allowlist."
	case list != "":
		return r.Fix + " The answer came from the “" + list + "” list on " + res + "."
	}
	return r.Fix
}

// resolverName turns the dns.source column ("pihole:192.168.1.53", "",
// "unbound") into words.
func resolverName(source string) string {
	switch {
	case strings.HasPrefix(source, "pihole:"):
		return "Pi-hole " + strings.TrimPrefix(source, "pihole:")
	case source == "", source == "unbound":
		return "the gateway resolver"
	}
	return source
}

func resolverIP(source string) string {
	if i := strings.IndexByte(source, ':'); i >= 0 {
		return source[i+1:]
	}
	return ""
}
