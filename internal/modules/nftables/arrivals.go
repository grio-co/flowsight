package nftables

// Where redirected connections arrive. nftables' redirect rewrites the
// destination to the incoming interface's own address (IPv4: its primary
// address; IPv6: one of its addresses), not to loopback as pf's rdr can. So
// the proxy must listen on the LAN interfaces' addresses, and the web
// module's fail-open check must probe there: a proxy answering on loopback
// alone would pass the check while every redirected connection was refused.
//
// The rules and the arrivals are computed from the same interface list, so
// traffic is only ever redirected on an interface whose addresses the proxy
// was told to listen on.

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/grioghar/flowsight/internal/core"
)

type ifaceInfo struct {
	Name     string
	Up       bool
	Loopback bool
	Addrs    []netip.Prefix
}

// systemInterfaces reads this machine's interfaces; tests replace it.
var systemInterfaces = func() []ifaceInfo {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []ifaceInfo
	for _, i := range ifs {
		info := ifaceInfo{Name: i.Name, Up: i.Flags&net.FlagUp != 0, Loopback: i.Flags&net.FlagLoopback != 0}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok {
					ones, _ := n.Mask.Size()
					info.Addrs = append(info.Addrs, netip.PrefixFrom(ip.Unmap(), ones))
				}
			}
		}
		out = append(out, info)
	}
	return out
}

// interceptInterfaces is where the redirects go. Named interfaces are used
// as given (those that exist and are up). With none named, the interfaces
// holding an address inside one of the intercepted IPv4 networks: never the
// WAN, so the proxy is not made to listen on a public address.
func interceptInterfaces(spec core.RedirectSpec, ifs []ifaceInfo) []ifaceInfo {
	var out []ifaceInfo
	if len(spec.Interfaces) > 0 {
		for _, want := range spec.Interfaces {
			for _, i := range ifs {
				if i.Name == want && i.Up {
					out = append(out, i)
				}
			}
		}
		return out
	}
	var nets []netip.Prefix
	for _, r := range spec.Rules {
		for _, s := range r.Sources {
			if p, err := netip.ParsePrefix(s); err == nil && p.Addr().Is4() {
				nets = append(nets, p.Masked())
			} else if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
				nets = append(nets, netip.PrefixFrom(a, 32))
			}
		}
	}
	for _, i := range ifs {
		if !i.Up || i.Loopback {
			continue
		}
	next:
		for _, a := range i.Addrs {
			for _, n := range nets {
				if a.Addr().Is4() && n.Contains(a.Addr()) {
					out = append(out, i)
					break next
				}
			}
		}
	}
	return out
}

// arrivals lists the interfaces' addresses redirected connections can reach:
// IPv4 always, IPv6 when an IPv6 rule exists, never link-local (a listener
// there needs a zone, and the kernel does not redirect to it).
func arrivals(spec core.RedirectSpec, ifs []ifaceInfo) []string {
	if len(spec.Rules) == 0 {
		return nil
	}
	v6 := false
	for _, r := range spec.Rules {
		if r.Family == "inet6" {
			v6 = true
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, i := range interceptInterfaces(spec, ifs) {
		for _, a := range i.Addrs {
			ip := a.Addr()
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || (ip.Is6() && !v6) {
				continue
			}
			if s := ip.String(); !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out
}

// inputDropTables reads `nft list chains` and names the other tables whose
// input chain drops by default. Redirected connections go through the input
// hook, and FlowSight's table cannot accept on another table's behalf: if
// that table does not let the proxy's ports in from the LAN, interception
// fails closed, while the web module's probe (made over loopback, which such
// firewalls let in) still passes. It cannot be seen from here whether the
// operator's rules allow the ports, so this is a warning, not a refusal.
func inputDropTables(listing string) []string {
	var out []string
	tbl := ""
	for _, l := range strings.Split(listing, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "table ") {
			tbl = strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(l, "table ")), " {")
			continue
		}
		if tbl != "" && tbl != table && strings.Contains(l, "hook input") && strings.Contains(l, "policy drop") {
			if len(out) == 0 || out[len(out)-1] != tbl {
				out = append(out, tbl)
			}
		}
	}
	return out
}

func inputDropWarning(tables []string) string {
	return fmt.Sprintf("table(s) %s drop incoming connections by default: redirected web traffic arrives through "+
		"the input hook, so they must accept the proxy's ports from the LAN, or interception will cut web access "+
		"(see Interception in the manual)", strings.Join(tables, ", "))
}
