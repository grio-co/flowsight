package advisor

import (
	"strings"
	"testing"
)

func phone(ip string) device {
	return device{Key: "ca:51:71:75:2f:b9", IP: "192.168.1.69", Name: "iPhone", MAC: "ca:51:71:75:2f:b9"}
}

// The night this module was written: a phone pointed at a Pi-hole whose
// built-in Private Relay switch answered NXDOMAIN, over IPv4 and IPv6.
func TestPrivateRelayBlockedByPiholeSpecialDomain(t *testing.T) {
	g := []agg{
		{Client: "192.168.1.69", Domain: "mask.icloud.com", Action: "block", List: "pihole special domain", Rcode: "NXDOMAIN", Source: "pihole:192.168.1.53", Count: 60, First: 100, Last: 900},
		{Client: "2600::1", Domain: "mask-h2.icloud.com", Action: "block", List: "pihole special domain", Rcode: "NXDOMAIN", Source: "pihole:192.168.1.53", Count: 12, First: 50, Last: 800},
	}
	out := evaluate(g, nil, nil, phone, 15)
	if len(out) != 1 {
		t.Fatalf("one device, one problem: %+v", out)
	}
	a := out[0]
	why := a.Attrs["why"].(map[string]any)
	if a.Kind != "private_relay_blocked" || a.Severity != "high" || why["count"] != 72 || why["first"] != int64(50) {
		t.Fatalf("advice: %+v", a)
	}
	if !strings.Contains(why["fix"].(string), "dns.specialDomains.iCloudPrivateRelay") || why["allow"] != nil {
		t.Fatalf("a special domain has its own switch, not an allow-list entry: %v", why)
	}
	if !strings.Contains(a.Detail, "iPhone (192.168.1.69)") || !strings.Contains(a.Detail, "Pi-hole 192.168.1.53 answered NXDOMAIN") {
		t.Fatalf("detail: %s", a.Detail)
	}
}

func TestBelowThresholdAndPassedAnswersAreQuiet(t *testing.T) {
	g := []agg{
		{Client: "10.0.0.2", Domain: "captive.apple.com", Action: "block", Count: 1},
		{Client: "10.0.0.2", Domain: "example.com", Action: "pass", Rcode: "NXDOMAIN", Count: 500},
		{Client: "10.0.0.2", Domain: "ads.example.net", Action: "block", Count: 119},
	}
	solo := func(ip string) device { return device{Key: ip, IP: ip} }
	if out := evaluate(g, map[string][2]int{"10.0.0.2": {1000, 10}}, nil, solo, 15); len(out) != 0 {
		t.Fatalf("nothing should fire: %+v", out)
	}
}

func TestRetryStormAndFailingLookups(t *testing.T) {
	solo := func(ip string) device { return device{Key: ip, IP: ip} }
	g := []agg{{Client: "10.0.0.3", Domain: "api3.siftscience.com", Action: "block", List: "pihole gravity", Source: "pihole:192.168.1.53", Count: 4},
		{Client: "10.0.0.3", Domain: "telemetry.vendor.example", Action: "block", List: "pihole gravity", Source: "pihole:192.168.1.53", Count: 300}}
	out := evaluate(g, map[string][2]int{"10.0.0.3": {100, 40}}, map[string]string{"10.0.0.3": ""}, solo, 15)
	kinds := map[string]advice{}
	for _, a := range out {
		kinds[a.Kind] = a
	}
	if _, ok := kinds["trust_check_blocked"]; !ok {
		t.Fatalf("sift is a trust check: %+v", out)
	}
	if a, ok := kinds[kindRetryStorm]; !ok || !strings.HasSuffix(a.Fingerprint, ":telemetry.vendor.example") {
		t.Fatalf("storm: %+v", out)
	}
	if a, ok := kinds[kindDNSFailing]; !ok || a.Attrs["why"].(map[string]any)["percent"] != 40 {
		t.Fatalf("failing: %+v", out)
	}
	allow := kinds["trust_check_blocked"].Attrs["why"].(map[string]any)["allow"].(map[string]any)
	if allow["server"] != "192.168.1.53" {
		t.Fatalf("a gravity block on a Pi-hole can be allowed there: %v", allow)
	}
}

func TestRuleMatching(t *testing.T) {
	cases := map[string]string{
		"1-courier.push.apple.com": "push_blocked", "alt3-mtalk.google.com": "push_blocked", "push.apple.com": "",
		"r3.o.lencr.org": "cert_check_blocked", "0.pool.ntp.org": "time_sync_blocked", "CAPTIVE.APPLE.COM.": "connectivity_check_blocked",
		"example.com": "",
	}
	for d, want := range cases {
		got := ""
		if r := ruleFor(d); r != nil {
			got = r.Kind
		}
		if got != want {
			t.Errorf("%s: got %q want %q", d, got, want)
		}
	}
}
