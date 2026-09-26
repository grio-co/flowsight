package firewall

// pf behind the backend-neutral contracts in core/enforce.go: address sets
// are tables in the policy sub-anchor, and the live connection table is
// `pfctl -ss -v`.

import (
	"regexp"
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
	_ core.RuleReader  = (*pfEnforcer)(nil)
)

func (e *pfEnforcer) Name() string { return "pf" }

func (e *pfEnforcer) Capabilities() []string {
	return []string{core.CapSetV4, core.CapSetV6, core.CapKillStates, core.CapConnStates, core.CapRules}
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

// ParseStates reads the pf state table as `pfctl -ss -v` or `-ss -vv`
// prints it on FreeBSD 13 to 15. Each state is a header line at column zero
// followed by indented detail lines:
//
//	all tcp 127.0.0.1:3129 (140.82.114.3:443) <- 10.99.0.162:59216  ESTABLISHED:ESTABLISHED
//	   [2837096760 + 392192] wscale 7  [2817892562 + 65792] wscale 10
//	   age 00:01:09, expires in 00:00:24, 249:432 pkts, 14863:616615 bytes, anchor 4
//	vtnet0 tcp 2600:1700::9[52034] -> 2607:f8b0::200e[443]      ESTABLISHED:ESTABLISHED
//	   age 45s, expires in 10s, 10:10 pkts, 1000:2000 bytes, anchor 1, rule 12
//
// The arrow points from the end that opened the connection: "->" means the
// left address opened it and the state was created going out, "<-" the right
// one, coming in. Each address may be followed by the other side of its
// translation in parentheses. Going out, the address printed is the one on
// the wire and the parenthesised one the address before translation; coming
// in it is the other way round. So for "->" the left parenthesis is the
// opener's source before outbound NAT, and for "<-" the left parenthesis is
// the destination the opener asked for before a redirect or port forward.
// The first of each counter pair counts the direction the arrow points, so
// it is always what the opener sent. egress/states_test.go and
// inspect's tests pin this against real captures.
//
// Lines starting with whitespace are never headers: the -vv sequence lines
// begin with "[".
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
		if strings.TrimSpace(line) == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if cur != nil && strings.Contains(line, "bytes") {
				parseStateDetail(line, cur)
			}
			continue
		}
		flush()
		cur = parseStateHeader(line)
	}
	flush()
	return states
}

var stateHeaderRe = regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+)(?:\s+\((\S+)\))?\s+(->|<-)\s+(\S+)(?:\s+\((\S+)\))?(?:\s+(\S+))?\s*$`)

func parseStateHeader(line string) *core.ConnState {
	m := stateHeaderRe.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return nil
	}
	left, right := endpoint(m[3]), endpoint(m[6])
	leftOther, rightOther := left, right
	if m[4] != "" {
		leftOther = endpoint(m[4])
	}
	if m[7] != "" {
		rightOther = endpoint(m[7])
	}
	st := &core.ConnState{Iface: m[1], Proto: strings.ToLower(m[2]), Status: m[8]}
	if m[5] == "->" {
		// Going out: printed addresses are on the wire, parentheses are
		// before translation. The opener is on the left.
		st.Direction = "out"
		st.Initiator, st.InitiatorTranslated = leftOther, left
		st.Responder, st.ResponderTranslated = rightOther, right
	} else {
		// Coming in: printed addresses are after translation, parentheses
		// are as they were on the wire. The opener is on the right.
		st.Direction = "in"
		st.Initiator, st.InitiatorTranslated = rightOther, right
		st.Responder, st.ResponderTranslated = leftOther, left
	}
	return st
}

// parseStateDetail reads "age 00:01:09, expires in 00:00:24, 249:432 pkts,
// 14863:616615 bytes, anchor 1, rule 3".
func parseStateDetail(line string, st *core.ConnState) {
	for _, part := range strings.Split(line, ",") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "age "):
			st.Age = pfDuration(strings.TrimPrefix(part, "age "))
		case strings.HasPrefix(part, "expires in "):
			st.Expires = pfDuration(strings.TrimPrefix(part, "expires in "))
		case strings.HasSuffix(part, " pkts"):
			if a, b, ok := pair(strings.TrimSuffix(part, " pkts")); ok {
				st.PktsSent, st.PktsReceived = a, b
			}
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

// pfDuration reads "00:01:02", "45s", "3m", "2h" and "1d".
func pfDuration(s string) time.Duration {
	s = strings.TrimSpace(s)
	if strings.Contains(s, ":") {
		total := 0
		for _, p := range strings.Split(s, ":") {
			n, _ := strconv.Atoi(p)
			total = total*60 + n
		}
		return time.Duration(total) * time.Second
	}
	n, _ := strconv.Atoi(strings.TrimRight(s, "smhd"))
	switch {
	case strings.HasSuffix(s, "m"):
		n *= 60
	case strings.HasSuffix(s, "h"):
		n *= 3600
	case strings.HasSuffix(s, "d"):
		n *= 86400
	}
	return time.Duration(n) * time.Second
}

func endpoint(s string) core.Endpoint {
	h, p := SplitHostPort(s)
	return core.Endpoint{Addr: h, Port: p}
}

// SplitHostPort handles "1.2.3.4:443", "[fd00::1]:443" and pf's own IPv6
// form "fd00::1[443]". A bare address has port 0.
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
	if i := strings.LastIndex(s, "["); i > 0 && strings.HasSuffix(s, "]") {
		p, _ := strconv.Atoi(s[i+1 : len(s)-1])
		return s[:i], p
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

// ------------------------------------------------------------------ rules

func (e *pfEnforcer) Syntax() string { return "pf" }

func (e *pfEnforcer) Rules() ([]core.Rule, error) {
	out, err := e.m.pfctl("-vvsr")
	if err != nil {
		return nil, err
	}
	return ParseRules(out), nil
}

func (e *pfEnforcer) CountersSince() time.Time {
	out, err := e.m.pfctl("-si")
	if err != nil {
		return time.Time{}
	}
	return rulesLoadedAt(out, time.Now())
}

var (
	enabledForRe = regexp.MustCompile(`Enabled for (\d+) days (\d+):(\d+):(\d+)`)
	loadedAtRe   = regexp.MustCompile(`Loaded at (.+) by`)
)

// rulesLoadedAt reads when pf started counting from `pfctl -si`. FreeBSD
// prints "Status: Enabled for 0 days 01:32:10"; some builds print "Loaded
// at <date> by <user>". It is zero when pfctl does not say.
func rulesLoadedAt(info string, now time.Time) time.Time {
	if m := enabledForRe.FindStringSubmatch(info); m != nil {
		d, _ := strconv.Atoi(m[1])
		h, _ := strconv.Atoi(m[2])
		mi, _ := strconv.Atoi(m[3])
		sec, _ := strconv.Atoi(m[4])
		return now.Add(-time.Duration(d*86400+h*3600+mi*60+sec) * time.Second)
	}
	if m := loadedAtRe.FindStringSubmatch(info); m != nil {
		for _, layout := range []string{"Mon Jan 2 15:04:05 2006", "Mon Jan _2 15:04:05 2006"} {
			if t, err := time.Parse(layout, strings.TrimSpace(m[1])); err == nil {
				return t
			}
		}
	}
	return time.Time{}
}

var (
	ruleCounterRe = regexp.MustCompile(`Evaluations:\s*(\d+)\s+Packets:\s*(\d+)\s+Bytes:\s*(\d+)\s+States:\s*(\d+)`)
	ruleLabelRe   = regexp.MustCompile(`label\s+"([^"]+)"`)
)

// ParseRules reads `pfctl -vvsr`: a rule at column zero, then indented
// lines, one of which carries its counters:
//
//	pass in quick on vtnet0 inet proto tcp from any to any port = 22 flags S/SA keep state label "a1b2"
//	  [ Evaluations: 123  Packets: 456  Bytes: 789  States: 0  ]
//	  [ Inserted: uid 0 pid 123 State Creations: 4  ]
func ParseRules(text string) []core.Rule {
	var rules []core.Rule
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(trimmed, "[") {
			r := core.Rule{Text: trimmed}
			if m := ruleLabelRe.FindStringSubmatch(trimmed); m != nil {
				r.Label = m[1]
			}
			rules = append(rules, r)
			continue
		}
		if len(rules) == 0 {
			continue
		}
		if m := ruleCounterRe.FindStringSubmatch(trimmed); m != nil {
			r := &rules[len(rules)-1]
			r.Evaluations, _ = strconv.ParseInt(m[1], 10, 64)
			r.Packets, _ = strconv.ParseInt(m[2], 10, 64)
			r.Bytes, _ = strconv.ParseInt(m[3], 10, 64)
			r.States, _ = strconv.ParseInt(m[4], 10, 64)
		}
	}
	return rules
}
