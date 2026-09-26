package enroll

import (
	"reflect"
	"testing"

	"github.com/grioghar/flowsight/internal/core"
)

// isolationRecorder captures the spec enroll asks the firewall for.
type isolationRecorder struct {
	spec   core.IsolationSpec
	loaded string
}

func (r *isolationRecorder) Name() string    { return "pf" }
func (r *isolationRecorder) Available() bool { return true }
func (r *isolationRecorder) RenderIsolation(spec core.IsolationSpec) string {
	r.spec = spec
	return "rendered"
}
func (r *isolationRecorder) LoadIsolation(name, text string) error {
	r.loaded = name + ":" + text
	return nil
}
func (r *isolationRecorder) ClearIsolation(name string) error { return nil }

// The spec is the zones as the operator wrote them, in order; the firewall's
// golden test (firewall/isolation_test.go) pins what pf makes of this set.
func TestApplyFirewallSpec(t *testing.T) {
	rec := &isolationRecorder{}
	m := &Module{isolator: rec, zones: &ZonesDoc{Zones: []*Zone{
		{ID: "trusted", Subnet: "10.99.10.0/24", Gateway: "10.99.10.1", Internet: true, ReachZones: []string{"iot"}},
		{ID: "iot", Subnet: "10.99.20.0/24", Gateway: "10.99.20.1", Internet: true},
		{ID: "cams", Subnet: "10.99.30.0/24", Gateway: "10.99.30.1", Internet: false},
		{ID: "guest", Subnet: "10.99.40.0/24", Gateway: "10.99.40.1", Captive: true},
	}}}
	if err := m.applyFirewall(); err != nil {
		t.Fatal(err)
	}
	want := core.IsolationSpec{Zones: []core.IsolationZone{
		{ID: "trusted", Subnet: "10.99.10.0/24", Gateway: "10.99.10.1", Internet: true, Reach: []string{"iot"}},
		{ID: "iot", Subnet: "10.99.20.0/24", Gateway: "10.99.20.1", Internet: true},
		{ID: "cams", Subnet: "10.99.30.0/24", Gateway: "10.99.30.1", Internet: false},
		{ID: "guest", Subnet: "10.99.40.0/24", Gateway: "10.99.40.1", Captive: true},
	}}
	if !reflect.DeepEqual(rec.spec, want) {
		t.Fatalf("spec changed:\n got %+v\nwant %+v", rec.spec, want)
	}
	if rec.loaded != "enroll:rendered" {
		t.Fatalf("loaded %q, want the rendered text under enroll", rec.loaded)
	}
}

// Without a firewall module, applying reports it instead of panicking.
func TestApplyFirewallWithoutFirewall(t *testing.T) {
	m := &Module{zones: &ZonesDoc{Zones: []*Zone{{ID: "a", Subnet: "10.0.0.0/24"}}}}
	if err := m.applyFirewall(); err == nil {
		t.Fatal("want an error when there is no firewall module")
	}
}
