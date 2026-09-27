package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grioghar/flowsight/internal/core"
)

func TestDNSLabel(t *testing.T) {
	for in, want := range map[string]string{"Kitchen iPad (2)": "kitchen-ipad-2", "iPhone": "iphone", "Chromebook c7ab": "chromebook-c7ab", "---": ""} {
		if got := dnsLabel(in); got != want {
			t.Errorf("%q: %q want %q", in, got, want)
		}
	}
}

// Named devices become "MAC,label" lines; a device with an OPNsense static
// host or a placement reservation is left to it; the DNS label wins when
// there is one; two devices of one name do not share a host name.
func TestDHCPWanted(t *testing.T) {
	dir := t.TempDir()
	s, err := core.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.xml")
	_ = os.WriteFile(cfg, []byte(`<opnsense><dnsmasq><hosts uuid="1"><host>homeassistant</host><hwaddr>bc:24:11:c2:5c:a4</hwaddr><ip>192.168.1.159</ip></hosts></dnsmasq></opnsense>`), 0o644)
	confd := filepath.Join(dir, "conf.d")
	_ = os.MkdirAll(confd, 0o755)
	_ = os.WriteFile(filepath.Join(confd, "flowsight-enroll.conf"), []byte("dhcp-host=70:f0:88:2d:b0:32,192.168.3.130,switch\n"), 0o644)
	_ = s.KVSet("dns.local_names", []map[string]any{{"label": "iphone", "mac": "ca:51:71:75:2f:b9"}})
	m := &Module{ctx: &core.Context{Store: s, Platform: &core.Platform{ConfigXML: cfg, DnsmasqConfDir: confd, EtcDir: dir}},
		overr: map[string]string{"192.168.1.69": "Grio's iPhone", "2600::69": "Grio's iPhone", "192.168.1.159": "HA", "192.168.1.68": "Switch",
			"192.168.1.10": "NAS", "192.168.1.11": "NAS", "192.168.1.99": "nomac"},
		macs: map[string]string{"192.168.1.69": "CA:51:71:75:2F:B9", "2600::69": "ca:51:71:75:2f:b9", "192.168.1.159": "bc:24:11:c2:5c:a4",
			"192.168.1.68": "70:f0:88:2d:b0:32", "192.168.1.10": "aa:00:00:00:00:10", "192.168.1.11": "aa:00:00:00:00:11"},
		everMAC: map[string]string{}}
	entries, text := m.dhcpWanted()
	for _, want := range []string{"ca:51:71:75:2f:b9,iphone\n", "aa:00:00:00:00:10,nas\n", "aa:00:00:00:00:11,nas-0011\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	if strings.Contains(text, "bc:24:11:c2:5c:a4") || strings.Contains(text, "70:f0:88:2d:b0:32") || strings.Count(text, "ca:51:71:75:2f:b9") != 1 {
		t.Errorf("static hosts, reservations or duplicates written:\n%s", text)
	}
	why := map[string]string{}
	for _, e := range entries {
		why[e.IP] = e.Status + " " + e.Why
	}
	if !strings.Contains(why["192.168.1.159"], "OPNsense static host homeassistant") || !strings.Contains(why["192.168.1.68"], "placement") || !strings.Contains(why["192.168.1.99"], "no hardware address") {
		t.Errorf("reasons: %v", why)
	}
}
