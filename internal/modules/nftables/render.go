package nftables

// Rendering FlowSight's nftables table. Everything FlowSight does on a Linux
// gateway lives in one table, `inet flowsight`; the distribution's tables
// and the operator's are never touched.
//
// Two nftables facts shape all of it. An `accept` in one table does not end
// a packet's journey: every other table's base chain on the same hook still
// sees it, and may still drop it. A `drop` or `reject` is final. So the
// chains here only ever drop, reject or redirect, never accept: FlowSight
// can take traffic away, and cannot open anything the operator's own
// firewall closes.
//
// Only a connection's first packet is judged: the forward chain lets
// established and related packets through untouched, as pf's states do.
// Without that, a reply from a zone that may not reach the opener's zone
// would be rejected. A newly blocked address is cut off by killing its
// connections (KillStates), not by filtering them mid-flight.
//
// Each consumer owns one regular chain (fs_policy, fs_web, fs_enroll) that is
// replaced whole, in one transaction, like a pf sub-anchor; the base chains
// that jump to them are the skeleton, written once.

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/grioghar/flowsight/internal/core"
)

const table = "inet flowsight"

// Chains a consumer can own.
const (
	chainPolicy = "fs_policy" // "policy" is a keyword in nftables
	chainWeb    = "fs_web"
	chainWebIn  = "fs_web_in" // turns away connections to the proxy that were not redirected
	chainEnroll = "fs_enroll"
)

// skeleton is the table, the local-network sets and the base chains. It is
// idempotent: `add` leaves what exists alone, so loading it again changes
// nothing and loses no set contents.
func skeleton() string {
	return `add table inet flowsight
add set inet flowsight local_v4 { type ipv4_addr; flags interval; auto-merge; }
add set inet flowsight local_v6 { type ipv6_addr; flags interval; auto-merge; }
add chain inet flowsight fs_policy
add chain inet flowsight fs_enroll
add chain inet flowsight fs_web
add chain inet flowsight fs_web_in
add chain inet flowsight forward { type filter hook forward priority filter - 10; policy accept; }
add chain inet flowsight prerouting { type nat hook prerouting priority dstnat - 10; policy accept; }
add chain inet flowsight input { type filter hook input priority filter - 10; policy accept; }
flush chain inet flowsight forward
flush chain inet flowsight prerouting
flush chain inet flowsight input
add rule inet flowsight forward ct state { established, related } return
add rule inet flowsight forward jump fs_enroll
add rule inet flowsight forward jump fs_policy
add rule inet flowsight prerouting jump fs_web
add rule inet flowsight input jump fs_web_in
`
}

// replaceChain is one transaction that empties a chain and fills it again.
// Sets the rules name are declared first; `add` keeps their contents.
func replaceChain(chain string, sets []string, rules []string) string {
	var b strings.Builder
	b.WriteString(skeleton())
	for _, s := range sets {
		b.WriteString(s + "\n")
	}
	fmt.Fprintf(&b, "flush chain %s %s\n", table, chain)
	for _, r := range rules {
		fmt.Fprintf(&b, "add rule %s %s %s\n", table, chain, r)
	}
	return b.String()
}

// family splits addresses and prefixes into IPv4 and IPv6; anything else is
// dropped, since nothing but an address may reach a rule.
func family(addrs []string) (v4, v6 []string) {
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		ip := net.ParseIP(a)
		if ip == nil {
			var err error
			if ip, _, err = net.ParseCIDR(a); err != nil {
				continue
			}
		}
		if ip.To4() != nil {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6
}

func elems(addrs []string) string { return "{ " + strings.Join(addrs, ", ") + " }" }

// setDecls declares the v4 and v6 halves of a named set.
func setDecls(name string) []string {
	return []string{
		fmt.Sprintf("add set %s %s_v4 { type ipv4_addr; flags interval; auto-merge; }", table, name),
		fmt.Sprintf("add set %s %s_v6 { type ipv6_addr; flags interval; auto-merge; }", table, name),
	}
}

// ---------------------------------------------------------------- redirects

// renderRedirects writes the web chain, on the interfaces interceptInterfaces
// chooses (the ones arrivals lists addresses for); with none there is
// nothing to redirect. nftables' redirect sends a connection to the incoming
// interface's own address, so the listener must accept there, not only on
// loopback. Exclusions come first as returns, in both families, as in pf.
//
// The proxy then listens on LAN addresses, so the input chain turns away
// any connection to its ports that did not come through a redirect: a
// client aiming at the proxy directly, or anyone at all when the redirects
// are withdrawn. Loopback (the fail-open probe, squid's own requests) passes.
func renderRedirects(spec core.RedirectSpec, ifs []ifaceInfo) string {
	var rules []string
	var names []string
	for _, i := range interceptInterfaces(spec, ifs) {
		names = append(names, i.Name)
	}
	if len(spec.Rules) > 0 && len(names) > 0 {
		ifaces := names
		ex4, ex6 := family(spec.Excluded)
		ports := map[int]bool{}
		var portList []string
		for _, r := range spec.Rules {
			if !ports[r.Port] {
				ports[r.Port] = true
				portList = append(portList, fmt.Sprint(r.Port))
			}
		}
		for _, ifc := range ifaces {
			on := ""
			if ifc != "" {
				on = fmt.Sprintf("iifname %q ", ifc)
			}
			if len(ex4) > 0 {
				rules = append(rules, fmt.Sprintf("%sip saddr %s tcp dport %s return", on, elems(ex4), elems(portList)))
			}
			if len(ex6) > 0 {
				rules = append(rules, fmt.Sprintf("%sip6 saddr %s tcp dport %s return", on, elems(ex6), elems(portList)))
			}
			for _, r := range spec.Rules {
				fam, set := "ip", "@local_v4"
				if r.Family == "inet6" {
					fam, set = "ip6", "@local_v6"
				}
				src := set
				if len(r.Sources) > 0 {
					s4, s6 := family(r.Sources)
					if fam == "ip" {
						src = elems(s4)
					} else {
						src = elems(s6)
					}
					if src == elems(nil) {
						continue
					}
				}
				rules = append(rules, fmt.Sprintf("%s%s saddr %s %s daddr != %s tcp dport %d redirect to :%d",
					on, fam, src, fam, set, r.Port, r.To.Port))
			}
		}
	}
	tx := replaceChain(chainWeb, nil, rules)
	var tx2 strings.Builder
	var guard []string
	seen := map[int]bool{}
	for _, r := range spec.Rules {
		if !seen[r.To.Port] {
			seen[r.To.Port] = true
			guard = append(guard, fmt.Sprint(r.To.Port))
		}
	}
	fmt.Fprintf(&tx2, "flush chain %s %s\n", table, chainWebIn)
	if len(guard) > 0 {
		fmt.Fprintf(&tx2, "add rule %s %s iifname \"lo\" return\n", table, chainWebIn)
		fmt.Fprintf(&tx2, "add rule %s %s ct status dnat return\n", table, chainWebIn)
		fmt.Fprintf(&tx2, "add rule %s %s tcp dport %s counter reject with tcp reset\n", table, chainWebIn, elems(guard))
	}
	return tx + tx2.String()
}

// ---------------------------------------------------------------- isolation

// renderIsolation writes the enroll chain: zones may not reach each other
// unless allowed, a zone without internet may not leave, and a captive zone
// reaches only its gateway and DNS. Passes are returns (to the next chain,
// never an accept), and they come before the zone's reject.
func renderIsolation(spec core.IsolationSpec) string {
	var sets, rules []string
	for _, z := range spec.Zones {
		sets = append(sets, setDecls("zone_"+z.ID)...)
		sets = append(sets, fmt.Sprintf("flush set %s zone_%s_v4", table, z.ID), fmt.Sprintf("flush set %s zone_%s_v6", table, z.ID))
		v4, v6 := family([]string{z.Subnet})
		if len(v4) > 0 {
			sets = append(sets, fmt.Sprintf("add element %s zone_%s_v4 %s", table, z.ID, elems(v4)))
		}
		if len(v6) > 0 {
			sets = append(sets, fmt.Sprintf("add element %s zone_%s_v6 %s", table, z.ID, elems(v6)))
		}
	}
	for _, z := range spec.Zones {
		for _, fam := range []string{"ip", "ip6"} {
			suf := "_v4"
			if fam == "ip6" {
				suf = "_v6"
			}
			from := fmt.Sprintf("%s saddr @zone_%s%s", fam, z.ID, suf)
			if z.Captive {
				if gw := net.ParseIP(z.Gateway); gw != nil && (gw.To4() != nil) == (fam == "ip") {
					rules = append(rules, fmt.Sprintf("%s %s daddr %s return", from, fam, z.Gateway))
				}
				for _, d := range z.DNS {
					ip := net.ParseIP(d)
					if ip == nil || d == z.Gateway || (ip.To4() != nil) != (fam == "ip") {
						continue
					}
					rules = append(rules, fmt.Sprintf("%s %s daddr %s meta l4proto { tcp, udp } th dport 53 return", from, fam, d))
				}
				rules = append(rules, fmt.Sprintf("%s reject", from))
				continue
			}
			for _, other := range spec.Zones {
				if other.ID == z.ID || contains(z.Reach, other.ID) {
					continue
				}
				rules = append(rules, fmt.Sprintf("%s %s daddr @zone_%s%s reject", from, fam, other.ID, suf))
			}
			if !z.Internet {
				rules = append(rules, fmt.Sprintf("%s %s daddr != @zone_%s%s reject", from, fam, z.ID, suf))
			}
		}
	}
	return replaceChain(chainEnroll, sets, rules)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
