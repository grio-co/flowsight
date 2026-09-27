package tc

// Turning a shaping plan into tc commands.
//
// Everything is shaped on the LAN side, as on pf, because only there are
// the devices' own addresses still visible: on the WAN, going out, source
// translation has already replaced them. Linux shapes only what leaves an
// interface, so the two directions take two paths:
//
//	download: the LAN interface's egress (towards the devices)
//	upload:   the LAN interface's ingress, redirected into an ifb device
//	          (fsifb0) and shaped on its egress
//
// Each path is an HTB tree under FlowSight's handle, f5:, that nothing else
// uses:
//
//	f5:1   the link, at the plan's rate
//	f5:10  high     rate = the link × its weight share, ceil = the link
//	f5:20  normal   (the same)
//	f5:30  low      (the same)
//	f5:1nn a rule's ceiling: its class's share, capped at the ceiling
//
// HTB lends what a class does not use to the others in proportion to their
// rates, so a rate set to a weight's share of the link is that weight. The
// leaves queue with fq_codel where the kernel has it.
//
// A rule is a u32 filter per address, per path; a later rule overrides an
// earlier one, so it gets a lower priority number and is consulted first.
// Anything no filter claims goes to the default class. Shaping only ever
// queues: nothing here can pass or drop a packet on policy grounds.

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/grioghar/flowsight/internal/core"
)

const (
	handle = "f5"
	ifb    = "fsifb0"
)

// classMinor is the leaf of a class ("" is the default's).
func classMinor(class string) int {
	switch class {
	case "high":
		return 0x10
	case "low":
		return 0x30
	default:
		return 0x20
	}
}

// kbit keeps tc's rates in whole kilobits.
func kbit(mbit float64) string {
	k := int64(mbit * 1000)
	if k < 8 {
		k = 8
	}
	return fmt.Sprintf("%dkbit", k)
}

type path struct {
	dev  string
	rate float64
	up   bool // the upload path: a device here is the source
}

// batch is what one Apply loads: the commands for tc -batch per path.
type batch struct {
	Down, Up []string
}

func (b batch) String() string {
	return "# download: LAN egress\n" + strings.Join(b.Down, "\n") + "\n# upload: LAN ingress through " + ifb + "\n" + strings.Join(b.Up, "\n") + "\n"
}

// render writes both paths. leaf is the leaf qdisc ("" for HTB's own).
func render(p core.ShapePlan, leaf string) batch {
	if p.LAN == "" {
		return batch{}
	}
	return batch{
		Down: renderPath(p, path{dev: p.LAN, rate: p.DownMbit}, leaf),
		Up: append([]string{
			fmt.Sprintf("qdisc add dev %s handle ffff: ingress", p.LAN),
			fmt.Sprintf("filter add dev %s parent ffff: protocol all prio 1 u32 match u32 0 0 action mirred egress redirect dev %s", p.LAN, ifb),
		}, renderPath(p, path{dev: ifb, rate: p.UpMbit, up: true}, leaf)...),
	}
}

func renderPath(p core.ShapePlan, pa path, leaf string) []string {
	var out []string
	w := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }
	weights := map[string]int{"high": p.WeightHigh, "normal": p.WeightNormal, "low": p.WeightLow}
	total := 0
	for _, v := range weights {
		if v > 0 {
			total += v
		}
	}
	if total == 0 {
		total, weights = 3, map[string]int{"high": 1, "normal": 1, "low": 1}
	}
	share := func(class string) float64 {
		if class == "" {
			class = p.DefaultClass
		}
		if _, ok := weights[class]; !ok {
			class = "normal"
		}
		v := weights[class]
		if v < 1 {
			v = 1
		}
		return pa.rate * float64(v) / float64(total)
	}
	def := classMinor(p.DefaultClass)
	// HTB's quantum is a class's rate over r2q; it decides how spare
	// bandwidth is lent, in proportion, so it must stay proportional to the
	// rates (never one fixed value) and within what HTB accepts. Sized so
	// the link's quantum is about 60 kB.
	r2q := int64(pa.rate*1e6/8) / 60000
	if r2q < 1 {
		r2q = 1
	}
	w("qdisc add dev %s root handle %s: htb default %x r2q %d", pa.dev, handle, def, r2q)
	w("class add dev %s parent %s: classid %s:1 htb rate %s ceil %s", pa.dev, handle, handle, kbit(pa.rate), kbit(pa.rate))
	for i, class := range []string{"high", "normal", "low"} {
		m := classMinor(class)
		w("class add dev %s parent %s:1 classid %s:%x htb rate %s ceil %s prio %d", pa.dev, handle, handle, m, kbit(share(class)), kbit(pa.rate), i)
		if leaf != "" {
			w("qdisc add dev %s parent %s:%x %s", pa.dev, handle, m, leaf)
		}
	}
	// Ceilings, then the filters, last rule first.
	flow := make([]int, len(p.Rules))
	n := 0
	for i, r := range p.Rules {
		switch {
		case r.CeilingMbit > 0:
			m := 0x100 + n
			n++
			rate := share(r.Class)
			if rate > r.CeilingMbit {
				rate = r.CeilingMbit
			}
			w("class add dev %s parent %s:1 classid %s:%x htb rate %s ceil %s prio %d", pa.dev, handle, handle, m, kbit(rate), kbit(r.CeilingMbit), prioOf(r.Class))
			if leaf != "" {
				w("qdisc add dev %s parent %s:%x %s", pa.dev, handle, m, leaf)
			}
			flow[i] = m
		case r.Class != "":
			flow[i] = classMinor(r.Class)
		}
	}
	prio := 100
	for i := len(p.Rules) - 1; i >= 0; i-- {
		r := p.Rules[i]
		if flow[i] == 0 {
			continue
		}
		// A device here is the source going up and the destination coming
		// down; something out there is the reverse.
		dir := "dst"
		if r.Local == pa.up {
			dir = "src"
		}
		var v4, v6 []string
		for _, a := range r.Addrs {
			pfx, ok := prefix(a)
			if !ok {
				continue
			}
			if pfx.Addr().Is4() {
				v4 = append(v4, pfx.String())
			} else {
				v6 = append(v6, pfx.String())
			}
		}
		for _, a := range v4 {
			w("filter add dev %s parent %s: protocol ip prio %d u32 match ip %s %s flowid %s:%x", pa.dev, handle, prio, dir, a, handle, flow[i])
		}
		for _, a := range v6 {
			w("filter add dev %s parent %s: protocol ipv6 prio %d u32 match ip6 %s %s flowid %s:%x", pa.dev, handle, prio+1, dir, a, handle, flow[i])
		}
		if len(v4)+len(v6) > 0 {
			prio += 2
		}
	}
	return out
}

func prioOf(class string) int {
	switch class {
	case "high":
		return 0
	case "low":
		return 2
	}
	return 1
}

// prefix reads an address or a prefix; nothing else may reach a filter.
func prefix(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}
