package dns

import (
	"net"
	"strings"
	"testing"
)

func TestLabelFromDisplayName(t *testing.T) {
	cases := map[string]string{"Kitchen iPad (2)": "kitchen-ipad-2", "  NAS  ": "nas", "Grio's MacBook Pro": "grio-s-macbook-pro",
		"---": "", "Ünïcode Box": "n-code-box"}
	for in, want := range cases {
		if got := labelFrom(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
	if l := labelFrom(strings.Repeat("a", 80)); len(l) != 63 || !labelRe.MatchString(l) {
		t.Errorf("long label: %q", l)
	}
}

func TestReverseNames(t *testing.T) {
	if got := reverseName("192.168.1.44"); got != "44.1.168.192.in-addr.arpa." {
		t.Fatal(got)
	}
	got := reverseName("2600:1700:3ab0:f43f::1")
	if !strings.HasPrefix(got, "1.0.0.0.") || !strings.HasSuffix(got, "f.3.4.f.0.b.a.3.0.0.7.1.0.0.6.2.ip6.arpa.") {
		t.Fatal(got)
	}
}

// The include answers forward and reverse, and leaves out the reverse
// where the operator's own override already answers it.
func TestRenderNames(t *testing.T) {
	text := renderNames([]localName{
		{FQDN: "nas.grio.co", Gateway: true, Addrs: []string{"192.168.1.10", "2600::10"}, NoPTR: []string{"2600::10"}},
		{FQDN: "tv.grio.co", Gateway: false, Addrs: []string{"192.168.1.20"}},
	})
	for _, want := range []string{"server:\n", `local-data: "nas.grio.co. 300 IN A 192.168.1.10"`, `local-data: "nas.grio.co. 300 IN AAAA 2600::10"`,
		`local-data-ptr: "192.168.1.10 300 nas.grio.co."`} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %s in\n%s", want, text)
		}
	}
	if strings.Contains(text, `local-data-ptr: "2600::10`) || strings.Contains(text, "tv.grio.co") {
		t.Errorf("unexpected record in\n%s", text)
	}
	if got := piholeLines(localName{FQDN: "nas.grio.co", Addrs: []string{"192.168.1.10"}}); len(got) != 1 || got[0] != "192.168.1.10 nas.grio.co" {
		t.Errorf("pihole lines: %v", got)
	}
}

func TestEUI64(t *testing.T) {
	ip := net.ParseIP("2600:1700:3ab0:f43f:be24:11ff:fe94:9732")
	if !eui64Matches(ip, "bc:24:11:94:97:32") {
		t.Fatal("the gateway's own SLAAC address is EUI-64")
	}
	if eui64Matches(net.ParseIP("2600:1700:3ab0:f43f:c01c:4a2c:3d2e:1f35"), "ca:51:71:75:2f:b9") {
		t.Fatal("a privacy address is not")
	}
}
