package nftables

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func lines(tx string) []string { return strings.Split(strings.TrimSpace(tx), "\n") }

func has(t *testing.T, tx, want string) {
	t.Helper()
	for _, l := range lines(tx) {
		if l == want {
			return
		}
	}
	t.Errorf("missing line:\n  %s\nin:\n%s", want, tx)
}

func index(tx, want string) int {
	for i, l := range lines(tx) {
		if l == want {
			return i
		}
	}
	return -1
}

func TestPolicyCompilesPerFamily(t *testing.T) {
	doc := &core.PolicyDoc{Policies: []core.Policy{{
		Name: "Kids", Enabled: true, Action: "block",
		Match: core.Match{Members: []string{"10.99.0.0/24", "fd99::/64"}},
		Deny:  core.Deny{Internet: true, Ports: []string{"tcp/25", "any/6881-6889"}, Apps: []string{"BitTorrent"}},
	}}}
	tx, n, err := compilePolicy(doc, nil, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n != 8 {
		t.Fatalf("want 8 rules (4 per family), got %d:\n%s", n, tx)
	}
	has(t, tx, `add set inet flowsight fs_app_kids_v4 { type ipv4_addr; flags interval; auto-merge; }`)
	has(t, tx, `add rule inet flowsight fs_policy ip saddr { 10.99.0.0/24 } ip daddr != @local_v4 counter reject comment "flowsight:Kids:internet"`)
	has(t, tx, `add rule inet flowsight fs_policy ip6 saddr { fd99::/64 } ip6 daddr @fs_app_kids_v6 counter reject comment "flowsight:Kids:app"`)
	has(t, tx, `add rule inet flowsight fs_policy ip saddr { 10.99.0.0/24 } meta l4proto { tcp, udp } th dport 6881-6889 counter reject comment "flowsight:Kids:port"`)
	has(t, tx, `add rule inet flowsight fs_policy ip6 saddr { fd99::/64 } tcp dport 25 counter reject comment "flowsight:Kids:port"`)
	// The base chains' default policy is accept (no opinion: the packet goes
	// on to every other table); no rule of FlowSight's may accept.
	for _, l := range lines(tx) {
		if strings.HasPrefix(l, "add rule ") && strings.Contains(l, " accept") {
			t.Fatalf("a FlowSight rule accepts: %s", l)
		}
	}
	if index(tx, "flush chain inet flowsight fs_policy") > index(tx, `add rule inet flowsight fs_policy ip saddr { 10.99.0.0/24 } ip daddr != @local_v4 counter reject comment "flowsight:Kids:internet"`) {
		t.Fatal("the chain must be emptied before it is filled")
	}
}

// Monitor counts and never drops.
func TestMonitorPolicyOnlyCounts(t *testing.T) {
	doc := &core.PolicyDoc{Policies: []core.Policy{{Name: "Watch", Enabled: true, Action: "monitor",
		Match: core.Match{Members: []string{"10.0.0.5/32"}}, Deny: core.Deny{Internet: true}}}}
	tx, _, err := compilePolicy(doc, nil, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(tx, "reject") || strings.Contains(tx, "drop") {
		t.Fatalf("a monitor policy dropped:\n%s", tx)
	}
	has(t, tx, `add rule inet flowsight fs_policy ip saddr { 10.0.0.5/32 } ip daddr != @local_v4 counter comment "flowsight:Watch:internet"`)
}

func TestCountryPoliciesNeedTheDatabase(t *testing.T) {
	doc := &core.PolicyDoc{Policies: []core.Policy{{Name: "Geo", Enabled: true, Action: "block",
		Match: core.Match{Members: []string{"10.0.0.0/24"}}, Deny: core.Deny{Countries: []string{"xx"}}}}}
	if _, _, err := compilePolicy(doc, nil, false, time.Now()); err == nil || !strings.Contains(err.Error(), "country database") {
		t.Fatalf("without a country database a country policy must be refused, not silently skipped: %v", err)
	}
}

func TestCountryPoliciesCompile(t *testing.T) {
	doc := &core.PolicyDoc{Policies: []core.Policy{
		{Name: "Kids", Enabled: true, Action: "block", Match: core.Match{Members: []string{"10.0.0.0/24", "fd00::/64"}},
			Deny: core.Deny{Countries: []string{"cn", "RU", "bad;", ""}}},
		{Name: "Office", Enabled: true, Action: "block", Match: core.Match{Members: []string{"10.1.0.0/24"}},
			Deny: core.Deny{Countries: []string{"CN"}, CountriesExcept: []string{"us", "ca"}}},
	}}
	tx, _, err := compilePolicy(doc, nil, true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	has(t, tx, `add set inet flowsight fs_geo_cn_v4 { type ipv4_addr; flags interval; auto-merge; }`)
	has(t, tx, `add rule inet flowsight fs_policy ip saddr { 10.0.0.0/24 } ip daddr @fs_geo_cn_v4 counter reject comment "flowsight:Kids:country:CN"`)
	has(t, tx, `add rule inet flowsight fs_policy ip6 saddr { fd00::/64 } ip6 daddr @fs_geo_ru_v6 counter reject comment "flowsight:Kids:country:RU"`)
	has(t, tx, `add rule inet flowsight fs_policy ip saddr { 10.1.0.0/24 } ip daddr @fs_geox_office_v4 counter reject comment "flowsight:Office:country-except"`)
	if n := strings.Count(tx, "add set inet flowsight fs_geo_cn_v4 "); n != 1 {
		t.Fatalf("a country two policies deny is declared %d times", n)
	}
	if strings.Contains(tx, "bad") {
		t.Fatalf("an invalid country code reached the rules:\n%s", tx)
	}
	got := geoSets(tx)
	want := []geoSet{{Name: "fs_geo_cn", Countries: []string{"CN"}}, {Name: "fs_geo_ru", Countries: []string{"RU"}},
		{Name: "fs_geox_office", Countries: []string{"US", "CA"}, Invert: true}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("geo sets read back: %v, want %v", got, want)
	}
}

func pfx(s ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, a := range s {
		out = append(out, netip.MustParsePrefix(a))
	}
	return out
}

// A gateway: loopback, a LAN with IPv4, a ULA and a link-local address, a
// WAN, and a second LAN that is down.
var testIfs = []ifaceInfo{
	{Name: "lo", Up: true, Loopback: true, Addrs: pfx("127.0.0.1/8", "::1/128")},
	{Name: "lan0", Up: true, Addrs: pfx("10.99.0.1/24", "fd99::1/64", "fe80::1/64")},
	{Name: "wan0", Up: true, Addrs: pfx("198.51.100.2/24", "2001:db8::2/64")},
	{Name: "lan1", Up: false, Addrs: pfx("10.98.0.1/24")},
}

func TestRedirectsRender(t *testing.T) {
	tx := renderRedirects(core.RedirectSpec{
		Interfaces: []string{"lan0"},
		Excluded:   []string{"10.99.0.50", "fd99::5"},
		Rules: []core.RedirectRule{
			{Family: "inet", Sources: []string{"10.99.0.0/24"}, Port: 80, To: core.Endpoint{Addr: "127.0.0.1", Port: 3128}},
			{Family: "inet", Sources: []string{"10.99.0.0/24"}, Port: 443, To: core.Endpoint{Addr: "127.0.0.1", Port: 3129}},
			{Family: "inet6", Port: 443, To: core.Endpoint{Addr: "fd99::1", Port: 3129}},
		}}, testIfs)
	ret := index(tx, `add rule inet flowsight fs_web iifname "lan0" ip saddr { 10.99.0.50 } tcp dport { 80, 443 } return`)
	rdr := index(tx, `add rule inet flowsight fs_web iifname "lan0" ip saddr { 10.99.0.0/24 } ip daddr != @local_v4 tcp dport 80 redirect to :3128`)
	if ret < 0 || rdr < 0 || ret > rdr {
		t.Fatalf("exclusions must come before redirects:\n%s", tx)
	}
	has(t, tx, `add rule inet flowsight fs_web iifname "lan0" ip6 saddr @local_v6 ip6 daddr != @local_v6 tcp dport 443 redirect to :3129`)
	if empty := renderRedirects(core.RedirectSpec{}, testIfs); strings.Contains(empty, "redirect") {
		t.Fatal("no rules must mean no redirects")
	}
	// Only redirected connections, and loopback, may reach the proxy's ports.
	lo := index(tx, `add rule inet flowsight fs_web_in iifname "lo" return`)
	dnat := index(tx, `add rule inet flowsight fs_web_in ct status dnat return`)
	rej := index(tx, `add rule inet flowsight fs_web_in tcp dport { 3128, 3129 } counter reject with tcp reset`)
	if lo < 0 || dnat < 0 || rej < 0 || lo > rej || dnat > rej {
		t.Fatalf("the input guard must pass loopback and redirected connections before it rejects:\n%s", tx)
	}
}

func v4spec(ifaces ...string) core.RedirectSpec {
	return core.RedirectSpec{Interfaces: ifaces, Rules: []core.RedirectRule{
		{Family: "inet", Sources: []string{"10.99.0.0/24"}, Port: 80, To: core.Endpoint{Addr: "127.0.0.1", Port: 3128}},
		{Family: "inet", Sources: []string{"10.99.0.0/24"}, Port: 443, To: core.Endpoint{Addr: "127.0.0.1", Port: 3129}},
	}}
}

// With no interface named, the redirects and the proxy's listeners go where
// the intercepted networks are: the LAN, never the WAN.
func TestArrivalsFollowTheInterceptedNetworks(t *testing.T) {
	spec := v4spec()
	if got := arrivals(spec, testIfs); strings.Join(got, " ") != "10.99.0.1" {
		t.Fatalf("arrivals: %v", got)
	}
	tx := renderRedirects(spec, testIfs)
	has(t, tx, `add rule inet flowsight fs_web iifname "lan0" ip saddr { 10.99.0.0/24 } ip daddr != @local_v4 tcp dport 80 redirect to :3128`)
	if strings.Contains(tx, "wan0") || strings.Contains(tx, "lan1") {
		t.Fatalf("redirects on an interface the proxy does not listen on:\n%s", tx)
	}
	spec.Rules = append(spec.Rules, core.RedirectRule{Family: "inet6", Port: 443, To: core.Endpoint{Addr: "fd99::1", Port: 3129}})
	if got := arrivals(spec, testIfs); strings.Join(got, " ") != "10.99.0.1 fd99::1" {
		t.Fatalf("with IPv6, the LAN's non-link-local IPv6 address too: %v", got)
	}
	if got := arrivals(v4spec("lan0", "lan1", "gone0"), testIfs); strings.Join(got, " ") != "10.99.0.1" {
		t.Fatalf("named interfaces that are down or missing have no arrivals: %v", got)
	}
}

// Where no interface can be found, nothing is redirected: a redirect with no
// listener behind it is interception failing closed.
func TestNoInterfaceMeansNoRedirects(t *testing.T) {
	spec := v4spec("gone0")
	if got := arrivals(spec, testIfs); len(got) != 0 {
		t.Fatalf("arrivals: %v", got)
	}
	if tx := renderRedirects(spec, testIfs); strings.Contains(tx, "redirect to") {
		t.Fatalf("redirected with no listener:\n%s", tx)
	}
}

func TestIsolationCaptivePassesComeFirst(t *testing.T) {
	tx := renderIsolation(core.IsolationSpec{Zones: []core.IsolationZone{
		{ID: "trusted", Subnet: "10.99.10.0/24", Internet: true, Reach: []string{"iot"}},
		{ID: "iot", Subnet: "10.99.20.0/24", Internet: false},
		{ID: "guest", Subnet: "10.99.40.0/24", Gateway: "10.99.40.1", Captive: true, DNS: []string{"10.99.40.1", "1.1.1.1"}},
	}})
	gw := index(tx, `add rule inet flowsight fs_enroll ip saddr @zone_guest_v4 ip daddr 10.99.40.1 return`)
	dns := index(tx, `add rule inet flowsight fs_enroll ip saddr @zone_guest_v4 ip daddr 1.1.1.1 meta l4proto { tcp, udp } th dport 53 return`)
	rej := index(tx, `add rule inet flowsight fs_enroll ip saddr @zone_guest_v4 reject`)
	if gw < 0 || dns < 0 || rej < 0 || gw > rej || dns > rej {
		t.Fatalf("captive passes must come before the reject:\n%s", tx)
	}
	has(t, tx, `add rule inet flowsight fs_enroll ip saddr @zone_iot_v4 ip daddr != @zone_iot_v4 reject`)
	has(t, tx, `add rule inet flowsight fs_enroll ip saddr @zone_trusted_v4 ip daddr @zone_guest_v4 reject`)
	if strings.Contains(tx, "ip saddr @zone_trusted_v4 ip daddr @zone_iot_v4") {
		t.Fatal("trusted may reach iot")
	}
}

func TestParseConntrack(t *testing.T) {
	out := `ipv4     2 tcp      6 431999 ESTABLISHED src=10.10.0.2 dst=203.0.113.9 sport=40000 dport=443 packets=5 bytes=300 src=203.0.113.9 dst=198.51.100.2 sport=443 dport=40000 packets=4 bytes=500 [ASSURED] mark=0 use=1
ipv4     2 tcp      6 118 TIME_WAIT src=10.10.0.2 dst=10.20.0.9 sport=40001 dport=80 packets=6 bytes=400 src=10.10.0.1 dst=10.10.0.2 sport=3128 dport=40001 packets=5 bytes=900 [ASSURED] mark=0 use=1
ipv6     10 udp      17 29 src=fd99::2 dst=2001:db8::53 sport=5353 dport=53 src=2001:db8::53 dst=fd99::2 sport=53 dport=5353 mark=0 use=1
conntrack v1.4.8 (conntrack-tools): 3 flow entries have been shown.`
	got := ParseConntrack(out)
	if len(got) != 3 {
		t.Fatalf("want 3, got %d: %+v", len(got), got)
	}
	a := got[0]
	if a.Initiator != (core.Endpoint{Addr: "10.10.0.2", Port: 40000}) || a.InitiatorTranslated != (core.Endpoint{Addr: "198.51.100.2", Port: 40000}) ||
		a.Responder != (core.Endpoint{Addr: "203.0.113.9", Port: 443}) || a.Sent != 300 || a.Received != 500 || a.Status != "ESTABLISHED" {
		t.Errorf("outbound NAT: %+v", a)
	}
	r := got[1]
	if r.Responder != (core.Endpoint{Addr: "10.20.0.9", Port: 80}) || r.ResponderTranslated != (core.Endpoint{Addr: "10.10.0.1", Port: 3128}) {
		t.Errorf("redirected: %+v", r)
	}
	if got[2].Proto != "udp" || got[2].Status != "" || got[2].Initiator.Addr != "fd99::2" {
		t.Errorf("udp v6: %+v", got[2])
	}
}

func TestInputDropTablesAreFound(t *testing.T) {
	listing := `table inet flowsight {
	chain input {
		type filter hook input priority filter - 10; policy accept;
	}
}
table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
}
table ip nat {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
	}
}`
	if got := inputDropTables(listing); strings.Join(got, ",") != "inet filter" {
		t.Fatalf("got %v", got)
	}
}
