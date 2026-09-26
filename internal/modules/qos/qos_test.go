package qos

import (
	"math"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/grioghar/flowsight/internal/core"
)

func TestParseRules(t *testing.T) {
	got := parseRules([]string{
		"192.168.1.178 = low",
		"  redgifs.com = high  ",
		"10.0.5.0/24 = low, 20Mbit",
		"backup.example = 500kbit",
		"# a comment",
		"",
		"nonsense",
		"example.com = sideways",
		"example.org =",
	})
	if len(got) != 7 {
		t.Fatalf("want 7 rules (comment and blank dropped), got %d", len(got))
	}
	by := map[string]Rule{}
	for _, r := range got {
		by[r.Match] = r
	}
	if r := by["192.168.1.178"]; !r.IsHost || r.Class != Low || r.Err != "" {
		t.Errorf("host rule wrong: %+v", r)
	}
	if r := by["redgifs.com"]; r.IsHost || r.Class != High || r.Err != "" {
		t.Errorf("domain rule wrong: %+v", r)
	}
	if r := by["10.0.5.0/24"]; !r.IsHost || r.Class != Low || r.Ceiling != 20 {
		t.Errorf("cidr with ceiling wrong: %+v", r)
	}
	if r := by["backup.example"]; r.Class != "" || r.Ceiling != 0.5 {
		t.Errorf("rate-only rule wrong: %+v", r)
	}
	if by["nonsense"].Err == "" && by[""].Err == "" {
		t.Error("a line with no = must be reported, not ignored")
	}
	if by["example.com"].Err == "" {
		t.Error("an unknown class must be reported")
	}
	if by["example.org"].Err == "" {
		t.Error("a rule that says nothing must be reported")
	}
	if len(valid(got)) != 4 {
		t.Errorf("only the four good rules should be acted on, got %d", len(valid(got)))
	}
}

// Shaping is applied on the LAN side, where addresses are not yet translated.
// Getting the direction backwards would silently prioritise the wrong half of
// every conversation, and nothing about the running system would look wrong.
func TestRateParsing(t *testing.T) {
	for in, want := range map[string]float64{
		"20": 20, "20mbit": 20, "20 Mbit/s": 20, "500kbit": 0.5, "1gbit": 1000,
	} {
		got, err := parseRate(in)
		if err != nil || got != want {
			t.Errorf("%q -> %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "fast", "-5", "0"} {
		if _, err := parseRate(bad); err == nil {
			t.Errorf("%q should not parse as a rate", bad)
		}
	}
}

type fakeIdentity struct{ core.Identity }

func (fakeIdentity) IsLocal(ip string) bool {
	return strings.HasPrefix(ip, "192.168.1.") || strings.HasPrefix(ip, "10.0.5.")
}

func newPlanModule(t *testing.T) *Module {
	t.Helper()
	cfg, err := core.LoadConfig(filepath.Join(t.TempDir(), "flowsight.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.DeclareModule("qos", map[string]any{"download_mbit": 100, "upload_mbit": 20,
		"weight_high": 70, "weight_normal": 25, "weight_low": 5, "default_class": "normal"})
	return &Module{ctx: &core.Context{Name: "qos", Config: cfg}, identity: fakeIdentity{}}
}

// The plan these rules make is the one the firewall's golden test renders
// (firewall/shaper_test.go, goldenShapePlan), so what reaches pf and
// dummynet is what this module loaded before its engine moved there.
func TestPlanMatchesFirewallGolden(t *testing.T) {
	m := newPlanModule(t)
	rules := parseRules([]string{
		"192.168.1.178 = low, 20Mbit",
		"redgifs.com = high",
		"never-looked-up.example = high",
		"203.0.113.9 = high",
		"backup.example = 5",
		"10.0.5.0/24 = low",
	})
	addrs := map[string][]string{"redgifs.com": {"203.0.113.7", "203.0.113.8"}, "backup.example": {"198.51.100.4"}}
	got := m.plan("vtnet0", rules, addrs, 0.93)
	want := core.ShapePlan{LAN: "vtnet0", DownMbit: 93, UpMbit: 18.6, WeightHigh: 70, WeightNormal: 25, WeightLow: 5,
		DefaultClass: "normal", Rules: []core.ShapeRule{
			{Key: "10.0.5.0/24", Label: "10.0.5.0/24 = low", Addrs: []string{"10.0.5.0/24"}, Local: true, Class: "low"},
			{Key: "192.168.1.178", Label: "192.168.1.178 = low, 20Mbit", Addrs: []string{"192.168.1.178"}, Local: true, Class: "low", CeilingMbit: 20},
			{Key: "203.0.113.9", Label: "203.0.113.9 = high", Addrs: []string{"203.0.113.9"}, Class: "high"},
			{Key: "backup.example", Label: "backup.example = 5", Addrs: []string{"198.51.100.4"}, CeilingMbit: 5},
			{Key: "never-looked-up.example", Label: "never-looked-up.example = high", Class: "high"},
			{Key: "redgifs.com", Label: "redgifs.com = high", Addrs: []string{"203.0.113.7", "203.0.113.8"}, Class: "high"},
		}}
	if math.Abs(got.DownMbit-want.DownMbit) > 1e-9 || math.Abs(got.UpMbit-want.UpMbit) > 1e-9 {
		t.Fatalf("rates: got %v/%v", got.DownMbit, got.UpMbit)
	}
	got.DownMbit, got.UpMbit = want.DownMbit, want.UpMbit
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("plan changed:\n got %+v\nwant %+v", got, want)
	}
}

// The same address literal can name either end of a conversation. Deciding
// wrongly shapes the opposite half of everything that matches, and nothing
// about the running system looks wrong while it does. A name is always out
// there.
func TestAddressRuleDependsOnWhichSideItIsOn(t *testing.T) {
	m := newPlanModule(t)
	p := m.plan("vtnet0", parseRules([]string{"192.168.1.178 = low", "203.0.113.9 = high", "example.com = high"}),
		map[string][]string{"example.com": {"192.168.1.9"}}, 1)
	side := map[string]bool{}
	for _, r := range p.Rules {
		side[r.Key] = r.Local
	}
	if !side["192.168.1.178"] || side["203.0.113.9"] || side["example.com"] {
		t.Errorf("local address must be this device, remote and names the far end: %v", side)
	}
}
