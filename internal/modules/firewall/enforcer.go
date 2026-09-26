package firewall

// pf behind the backend-neutral contracts in core/enforce.go: address sets
// are tables in the policy sub-anchor, and the live connection table is
// `pfctl -ss -v`.

import (
	"strconv"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// policyAnchor is the sub-anchor whose tables the policy provider declares
// and the enforcer fills.
const policyAnchor = "policy"

// pfEnforcer is published as core.ServiceEnforcer and core.ServiceConnStates.
// It is a separate type so the contract's method names do not collide with
// the pf-specific Firewall service the module also publishes.
type pfEnforcer struct{ m *Module }

var (
	_ core.Enforcer    = (*pfEnforcer)(nil)
	_ core.StateReader = (*pfEnforcer)(nil)
)

func (e *pfEnforcer) Name() string { return "pf" }

func (e *pfEnforcer) Capabilities() []string {
	return []string{core.CapSetV4, core.CapSetV6, core.CapKillStates, core.CapConnStates}
}

func (e *pfEnforcer) Available() bool { return e.m.Available() }

func (e *pfEnforcer) ReplaceSet(set string, addrs []string) error {
	return e.m.ReplaceTable(policyAnchor, set, addrs)
}

func (e *pfEnforcer) AddToSet(set string, addrs []string) error {
	return e.m.AddToTable(policyAnchor, set, addrs)
}

func (e *pfEnforcer) KillStates(src, dst string) error { return e.m.KillStates(src, dst) }

func (e *pfEnforcer) States() ([]core.ConnState, error) {
	out, err := e.m.pfctl("-ss", "-v")
	if err != nil {
		return nil, err
	}
	return ParseStates(out), nil
}

// ParseStates reads the output of `pfctl -ss -v`, three lines per state:
//
//	all tcp 127.0.0.1:3129 (140.82.114.3:443) <- 10.99.0.162:59216  ESTABLISHED:ESTABLISHED
//	   [2837096760 + 392192] wscale 7  [2817892562 + 65792] wscale 10
//	   age 00:01:09, expires in 00:00:24, 249:432 pkts, 14863:616615 bytes, anchor 4
//
// The arrow points from the end that opened the connection: "->" means the
// left address opened it, "<-" the right one. The address in parentheses is
// the other side of a translation of the left address: for "->" the source
// the opener used before outbound NAT, for "<-" the destination the opener
// asked for before a redirect or port forward. The first of each counter
// pair counts the direction the arrow points, so it is always what the
// opener sent. egress/states_test.go pins this against a real capture.
func ParseStates(text string) []core.ConnState {
	var states []core.ConnState
	var cur *core.ConnState
	flush := func() {
		if cur != nil {
			states = append(states, *cur)
		}
		cur = nil
	}
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			flush()
			cur = parseStateHeader(trimmed)
			continue
		}
		if cur != nil && strings.Contains(trimmed, "bytes") {
			parseStateCounters(trimmed, cur)
		}
	}
	flush()
	return states
}

func parseStateHeader(line string) *core.ConnState {
	f := strings.Fields(line)
	if len(f) < 4 {
		return nil
	}
	arrow := -1
	for i, x := range f {
		if x == "->" || x == "<-" {
			arrow = i
			break
		}
	}
	if arrow < 0 || arrow+1 >= len(f) {
		return nil
	}
	var left, paren string
	for i := 2; i < arrow; i++ {
		if strings.HasPrefix(f[i], "(") {
			paren = strings.Trim(f[i], "()")
		} else {
			left = f[i]
		}
	}
	if left == "" {
		return nil
	}
	l, r := endpoint(left), endpoint(f[arrow+1])
	before := l // the left end before translation
	if paren != "" {
		before = endpoint(paren)
	}
	st := &core.ConnState{Proto: f[1]}
	if f[arrow] == "->" {
		st.Initiator, st.InitiatorWire = before, l
		st.Responder, st.ResponderActual = r, r
	} else {
		st.Initiator, st.InitiatorWire = r, r
		st.Responder, st.ResponderActual = before, l
	}
	return st
}

// parseStateCounters reads "age 00:01:09, ... 249:432 pkts, 14863:616615 bytes, rule 3".
func parseStateCounters(line string, st *core.ConnState) {
	for _, part := range strings.Split(line, ",") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "age "):
			st.Age = parseAge(strings.TrimPrefix(part, "age "))
		case strings.HasSuffix(part, " bytes"):
			if a, b, ok := pair(strings.TrimSuffix(part, " bytes")); ok {
				st.Sent, st.Received = a, b
			}
		case strings.HasPrefix(part, "anchor ") || strings.HasPrefix(part, "rule "):
			st.Rule = part
		}
	}
}

func pair(s string) (int64, int64, bool) {
	a, b, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return 0, 0, false
	}
	x, err1 := strconv.ParseInt(strings.TrimSpace(a), 10, 64)
	y, err2 := strconv.ParseInt(strings.TrimSpace(b), 10, 64)
	return x, y, err1 == nil && err2 == nil
}

func parseAge(s string) time.Duration {
	f := strings.Split(strings.TrimSpace(s), ":")
	if len(f) != 3 {
		return 0
	}
	h, _ := strconv.Atoi(f[0])
	m, _ := strconv.Atoi(f[1])
	sec, _ := strconv.Atoi(f[2])
	return time.Duration(h)*time.Hour + time.Duration(m)*time.Minute + time.Duration(sec)*time.Second
}

func endpoint(s string) core.Endpoint {
	h, p := SplitHostPort(s)
	return core.Endpoint{Addr: h, Port: p}
}

// SplitHostPort handles "1.2.3.4:443" and "[fd00::1]:443".
func SplitHostPort(s string) (string, int) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i > 0 {
			p := 0
			if len(s) > i+2 && s[i+1] == ':' {
				p, _ = strconv.Atoi(s[i+2:])
			}
			return s[1:i], p
		}
	}
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return s, 0
	}
	// An IPv6 address without brackets has more than one colon.
	if strings.Count(s, ":") > 1 {
		return s, 0
	}
	p, _ := strconv.Atoi(s[i+1:])
	return s[:i], p
}
