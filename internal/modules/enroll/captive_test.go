package enroll

import (
	"reflect"
	"testing"
)

// A captive zone's DNS servers reach the firewall, which lets the zone's
// clients query them (firewall/isolation_test.go pins the rule order).
func TestCaptiveZoneCarriesItsDNS(t *testing.T) {
	rec := &isolationRecorder{}
	m := &Module{isolator: rec, zones: &ZonesDoc{Zones: []*Zone{
		{ID: "guest", Subnet: "10.99.40.0/24", Gateway: "10.99.40.1", Captive: true, DNS: []string{"10.99.40.1", "1.1.1.1"}},
	}}}
	if err := m.applyFirewall(); err != nil {
		t.Fatal(err)
	}
	z := rec.spec.Zones[0]
	if !z.Captive || !reflect.DeepEqual(z.DNS, []string{"10.99.40.1", "1.1.1.1"}) {
		t.Fatalf("captive zone spec: %+v", z)
	}
}
