package enroll

import (
	"strings"
	"testing"
)

type anchorRecorder struct{ text string }

func (r *anchorRecorder) LoadAnchor(name, rules string) error { r.text = rules; return nil }
func (r *anchorRecorder) FlushAnchor(name string) error       { return nil }

// In pf the first matching quick rule wins. A captive zone's block used to
// come before its pass to the gateway, so a captive client could reach
// nothing at all, not even the gateway serving its captive page.
func TestCaptiveZonePassesBeforeItBlocks(t *testing.T) {
	rec := &anchorRecorder{}
	m := &Module{firewall: rec, zones: &ZonesDoc{Zones: []*Zone{
		{ID: "guest", Subnet: "10.99.40.0/24", Gateway: "10.99.40.1", Captive: true, DNS: []string{"10.99.40.1", "1.1.1.1"}},
	}}}
	if err := m.applyFirewall(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(rec.text, "\n")
	idx := func(want string) int {
		for i, l := range lines {
			if l == want {
				return i
			}
		}
		t.Fatalf("missing rule %q in:\n%s", want, rec.text)
		return -1
	}
	block := idx("block return quick from <fs_guest> to any")
	gw := idx("pass quick from <fs_guest> to 10.99.40.1")
	dns := idx("pass quick proto { tcp, udp } from <fs_guest> to 1.1.1.1 port 53")
	if gw > block || dns > block {
		t.Fatalf("passes must come before the block:\n%s", rec.text)
	}
	if strings.Count(rec.text, "to 10.99.40.1") != 1 {
		t.Fatalf("a DNS server that is the gateway needs no rule of its own:\n%s", rec.text)
	}
}
