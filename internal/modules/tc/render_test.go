package tc

import (
	"strings"
	"testing"

	"github.com/grioghar/flowsight/internal/core"
)

func plan() core.ShapePlan {
	return core.ShapePlan{LAN: "lan0", DownMbit: 100, UpMbit: 20, WeightHigh: 70, WeightNormal: 25, WeightLow: 5,
		DefaultClass: "normal", Rules: []core.ShapeRule{
			{Key: "10.0.0.5", Addrs: []string{"10.0.0.5"}, Local: true, Class: "low"},
			{Key: "video.example", Addrs: []string{"198.51.100.7", "2001:db8::7", "junk"}, Class: "high"},
			{Key: "10.0.5.0/24", Addrs: []string{"10.0.5.0/24"}, Local: true, Class: "low", CeilingMbit: 20},
			{Key: "unresolved.example", Class: "high"},
		}}
}

func has(t *testing.T, lines []string, want string) int {
	t.Helper()
	for i, l := range lines {
		if l == want {
			return i
		}
	}
	t.Errorf("missing:\n  %s\nin:\n  %s", want, strings.Join(lines, "\n  "))
	return -1
}

func TestTreePerDirection(t *testing.T) {
	b := render(plan(), "fq_codel")
	has(t, b.Down, "qdisc add dev lan0 root handle f5: htb default 20 r2q 208")
	has(t, b.Down, "class add dev lan0 parent f5: classid f5:1 htb rate 100000kbit ceil 100000kbit")
	has(t, b.Down, "class add dev lan0 parent f5:1 classid f5:10 htb rate 70000kbit ceil 100000kbit prio 0")
	has(t, b.Down, "class add dev lan0 parent f5:1 classid f5:30 htb rate 5000kbit ceil 100000kbit prio 2")
	has(t, b.Down, "qdisc add dev lan0 parent f5:20 fq_codel")
	has(t, b.Up, "qdisc add dev lan0 handle ffff: ingress")
	has(t, b.Up, "filter add dev lan0 parent ffff: protocol all prio 1 u32 match u32 0 0 action mirred egress redirect dev fsifb0")
	has(t, b.Up, "class add dev fsifb0 parent f5: classid f5:1 htb rate 20000kbit ceil 20000kbit")
	// A ceiling gets its class's share, capped at the ceiling.
	has(t, b.Down, "class add dev lan0 parent f5:1 classid f5:100 htb rate 5000kbit ceil 20000kbit prio 2")
	has(t, b.Up, "class add dev fsifb0 parent f5:1 classid f5:100 htb rate 1000kbit ceil 20000kbit prio 2")
}

// A device here is the destination coming down and the source going up;
// something out there the reverse.
func TestFiltersMatchTheRightEnd(t *testing.T) {
	b := render(plan(), "")
	has(t, b.Down, "filter add dev lan0 parent f5: protocol ip prio 104 u32 match ip dst 10.0.0.5/32 flowid f5:30")
	has(t, b.Up, "filter add dev fsifb0 parent f5: protocol ip prio 104 u32 match ip src 10.0.0.5/32 flowid f5:30")
	has(t, b.Down, "filter add dev lan0 parent f5: protocol ip prio 102 u32 match ip src 198.51.100.7/32 flowid f5:10")
	has(t, b.Down, "filter add dev lan0 parent f5: protocol ipv6 prio 103 u32 match ip6 src 2001:db8::7/128 flowid f5:10")
	has(t, b.Up, "filter add dev fsifb0 parent f5: protocol ip prio 102 u32 match ip dst 198.51.100.7/32 flowid f5:10")
	has(t, b.Down, "filter add dev lan0 parent f5: protocol ip prio 100 u32 match ip dst 10.0.5.0/24 flowid f5:100")
	for _, l := range append(b.Down, b.Up...) {
		if strings.Contains(l, "junk") {
			t.Fatalf("an invalid address reached tc: %s", l)
		}
		if strings.Contains(l, " fq_codel") {
			t.Fatalf("no leaf qdisc was asked for: %s", l)
		}
	}
}

// Later rules override earlier ones: they are consulted first.
func TestLaterRulesComeFirst(t *testing.T) {
	p := plan()
	p.Rules = []core.ShapeRule{
		{Key: "net", Addrs: []string{"10.0.0.0/24"}, Local: true, Class: "low"},
		{Key: "one", Addrs: []string{"10.0.0.5"}, Local: true, Class: "high"},
	}
	b := render(p, "")
	one := has(t, b.Down, "filter add dev lan0 parent f5: protocol ip prio 100 u32 match ip dst 10.0.0.5/32 flowid f5:10")
	net := has(t, b.Down, "filter add dev lan0 parent f5: protocol ip prio 102 u32 match ip dst 10.0.0.0/24 flowid f5:30")
	if one < 0 || net < 0 {
		t.FailNow()
	}
}

func TestNoLANNoShaping(t *testing.T) {
	p := plan()
	p.LAN = ""
	if b := render(p, "fq_codel"); len(b.Down)+len(b.Up) != 0 {
		t.Fatalf("shaping with no LAN: %v", b)
	}
}

func TestFindsOnlyFlowSightsObjects(t *testing.T) {
	out := `qdisc noqueue 0: dev lo root refcnt 2
qdisc htb f5: dev lan0 root refcnt 2 r2q 10 default 0x20 direct_packets_stat 0 direct_qlen 1000
qdisc ingress ffff: dev lan0 parent ffff:fff1 ----------------
qdisc htb 1: dev wan0 root refcnt 2 r2q 10 default 0x10 direct_packets_stat 0 direct_qlen 1000
qdisc htb f5: dev fsifb0 root refcnt 2 r2q 10 default 0x20 direct_packets_stat 0 direct_qlen 32
qdisc ingress ffff: dev wan0 parent ffff:fff1 ----------------`
	if got := strings.Join(devsWithRoot(out), ","); got != "lan0,fsifb0" {
		t.Fatalf("roots: %s", got)
	}
	if got := strings.Join(devsWithIngress(out), ","); got != "lan0,wan0" {
		t.Fatalf("ingress (checked for the redirect before removal): %s", got)
	}
}

func TestParseStats(t *testing.T) {
	out := `class htb f5:1 root rate 100Mbit ceil 100Mbit burst 1600b cburst 1600b
 Sent 5000 bytes 50 pkt (dropped 0, overlimits 0 requeues 0)
class htb f5:10 parent f5:1 leaf 8001: prio 0 rate 70Mbit ceil 100Mbit burst 1598b cburst 1600b
 Sent 123456 bytes 321 pkt (dropped 2, overlimits 40 requeues 0)
 backlog 0b 0p requeues 0
class htb f5:100 parent f5:1 prio 2 rate 5Mbit ceil 20Mbit burst 1600b cburst 1600b
 Sent 10 bytes 1 pkt (dropped 0, overlimits 0 requeues 0)
 backlog 0b 0p requeues 0`
	got := parseStats(out, "download", 0)
	if len(got) != 2 || got[0].Name != "download high" || got[0].Queue != 0x10 ||
		!strings.Contains(got[0].Detail, "dropped 2") || got[1].Name != "download ceiling 1" {
		t.Fatalf("%+v", got)
	}
}
