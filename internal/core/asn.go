package core

import (
	"net"
	"strings"
)

// OriginASN asks Team Cymru which network announces an address. It is a DNS
// query rather than an HTTP one, which means it is cheap, cached by the
// resolver, and works on a box with no outbound HTTP. IPv4 only: Cymru
// serves v6 under a different zone that is not wired up.
func OriginASN(ip string) (asn, prefix, rir, allocated string) {
	rev, ok := reverseV4(ip)
	if !ok {
		return "", "", "", ""
	}
	txt, err := net.LookupTXT(rev + ".origin.asn.cymru.com")
	if err != nil || len(txt) == 0 {
		return "", "", "", ""
	}
	f := splitPipe(txt[0])
	if len(f) < 5 {
		return "", "", "", ""
	}
	// The first field can list several origins for a prefix announced by more
	// than one network. One of them is the answer and nothing here can say
	// which, so the first is taken and the ambiguity is not hidden behind an
	// invented certainty.
	asn = strings.Fields(f[0])[0]
	return asn, f[1], f[3], f[4]
}

// ASName returns the registered name of an autonomous system, "" when unknown.
func ASName(asn string) string {
	if asn == "" {
		return ""
	}
	txt, err := net.LookupTXT("AS" + asn + ".asn.cymru.com")
	if err != nil || len(txt) == 0 {
		return ""
	}
	f := splitPipe(txt[0])
	return f[len(f)-1]
}

func reverseV4(ip string) (string, bool) {
	a := net.ParseIP(ip)
	if a == nil || a.To4() == nil {
		return "", false
	}
	p := strings.Split(a.To4().String(), ".")
	return p[3] + "." + p[2] + "." + p[1] + "." + p[0], true
}

func splitPipe(s string) []string {
	f := strings.Split(strings.Trim(s, `"`), "|")
	for i := range f {
		f[i] = strings.TrimSpace(f[i])
	}
	return f
}
