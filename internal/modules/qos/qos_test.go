package qos

import (
	"errors"
	"strings"
	"testing"
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
func TestRenderDirections(t *testing.T) {
	in := anchorInput{
		LAN:          "vtnet0",
		DefaultClass: Normal,
		Rules: parseRules([]string{
			"192.168.1.178 = low",
			"redgifs.com = high",
		}),
		Addrs:    map[string][]string{"redgifs.com": {"203.0.113.7", "203.0.113.8"}},
		Ceilings: map[string]ceiling{},
	}
	text, tables := render(in)

	if len(tables) != 2 {
		t.Fatalf("want a table per rule, got %d: %v", len(tables), tables)
	}
	// One rule per match, on the direction that opens the connection, naming
	// both queues. A separate rule for the reply never fires: the reply comes
	// back through the state the first rule created.
	wantHost := []string{
		"match in on vtnet0 from <qos_r0> to any dnqueue(" + itoa(qUpLow) + ")",
		"match out on vtnet0 from any to <qos_r0> dnqueue(" + itoa(qDownLow) + ")",
	}
	wantSvc := []string{
		"match in on vtnet0 from any to <qos_r1> dnqueue(" + itoa(qUpHigh) + ")",
		"match out on vtnet0 from <qos_r1> to any dnqueue(" + itoa(qDownHigh) + ")",
	}
	for _, w := range append(wantHost, wantSvc...) {
		if !strings.Contains(text, w) {
			t.Errorf("missing rule:\n  %s\ngot:\n%s", w, text)
		}
	}
	// The default has to come first so a named rule can override it: pf takes
	// the last match when nothing is quick, and nothing here is.
	iDefault := strings.Index(text, "match in on vtnet0 all")
	iRule := strings.Index(text, "from <qos_r0> to any dnqueue")
	if iDefault < 0 || iRule < 0 || iDefault > iRule {
		t.Error("the default class must be emitted before the specific rules")
	}
	if strings.Contains(text, "quick") {
		t.Error("no rule here may be quick; shaping must not decide whether traffic passes")
	}
	if strings.Contains(text, "pass ") || strings.Contains(text, "block ") {
		t.Error("shaping must only match, never pass or block")
	}
	// Every class rule needs a partner on the reply direction; a queue named
	// on a directional rule applies only to that direction.
	if strings.Count(text, "match in on") != strings.Count(text, "match out on") {
		t.Errorf("each direction needs its own rule:\n%s", text)
	}
}

// A name nobody has resolved yet matches no addresses, so it must produce no
// table and no rule rather than an empty table that matches everything.
func TestUnresolvedDomainProducesNothing(t *testing.T) {
	text, tables := render(anchorInput{
		LAN: "vtnet0", DefaultClass: Normal,
		Rules: parseRules([]string{"never-looked-up.example = high"}),
		Addrs: map[string][]string{}, Ceilings: map[string]ceiling{},
	})
	if len(tables) != 0 {
		t.Errorf("an unresolved name must not create a table: %v", tables)
	}
	if strings.Contains(text, "qos_r0") {
		t.Errorf("an unresolved name must not create a rule:\n%s", text)
	}
	if !strings.Contains(text, "match in on vtnet0 all dnqueue(") {
		t.Error("the default class should still be applied")
	}
}

func TestCeilingUsesItsOwnPipe(t *testing.T) {
	rules := parseRules([]string{"192.168.1.178 = low, 20Mbit"})
	text, _ := render(anchorInput{
		LAN: "vtnet0", DefaultClass: Normal, Rules: rules,
		Ceilings: map[string]ceiling{"192.168.1.178": {Mbit: 20, DownPipe: ceilDownBase, UpPipe: ceilUpBase}},
	})
	if !strings.Contains(text, "dnpipe("+itoa(ceilUpBase)+")") || !strings.Contains(text, "dnpipe("+itoa(ceilDownBase)+")") {
		t.Errorf("a ceiling must have a pipe on each direction:\n%s", text)
	}
	if !strings.Contains(text, "dnqueue("+itoa(qUpLow)+")") {
		t.Error("a rule with both a class and a ceiling must still get its class")
	}
}

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

// The buffer has to match the rate. Measured on a test gateway, the default
// fifty-slot queue held a 14 Mbit/s pipe to 4.6 Mbit/s of real throughput,
// because TCP was being told to back off by loss rather than by delay.
func TestQueueBytesTracksRate(t *testing.T) {
	if got := queueBytes(100); got != int(100e6/8*0.05) {
		t.Errorf("100 Mbit should buffer about 50ms of it, got %d bytes", got)
	}
	if got := queueBytes(0.1); got < 50<<10 {
		t.Errorf("a tiny pipe still needs a floor, got %d", got)
	}
	if got := queueBytes(10000); got > 2<<20 {
		t.Errorf("a huge pipe must be capped or the queue is just delay, got %d", got)
	}
}

// The same address literal can name either end of a conversation. Deciding
// wrongly shapes the opposite half of everything that matches, and nothing
// about the running system looks wrong while it does.
func TestAddressRuleDependsOnWhichSideItIsOn(t *testing.T) {
	local := func(ip string) bool { return strings.HasPrefix(ip, "192.168.1.") }
	mk := func(rule string) string {
		text, _ := render(anchorInput{
			LAN: "vtnet0", Rules: parseRules([]string{rule}),
			Addrs: map[string][]string{}, Ceilings: map[string]ceiling{}, IsLocal: local,
		})
		return text
	}
	// A device here opens connections: it is the source on the way out.
	here := mk("192.168.1.178 = low")
	if !strings.Contains(here, "match in on vtnet0 from <qos_r0> to any") ||
		!strings.Contains(here, "match out on vtnet0 from any to <qos_r0>") {
		t.Errorf("a local address must be treated as a device here:\n%s", here)
	}
	// Something out there is the destination on the way out.
	there := mk("203.0.113.9 = high")
	if !strings.Contains(there, "match in on vtnet0 from any to <qos_r0>") ||
		!strings.Contains(there, "match out on vtnet0 from <qos_r0> to any") {
		t.Errorf("a remote address must be treated as a far end:\n%s", there)
	}
}

// After a reboot dummynet is not in the kernel, yet "dnctl pipe show" still
// succeeds; trusting it left shaping failing on every apply with "Protocol
// not available". The kernel is asked instead, and the module loaded.
func TestAvailableLoadsDummynetWhenTheKernelLacksIt(t *testing.T) {
	var sys []string
	loaded := false
	d := &dn{
		run: func(args ...string) (string, error) { return "", nil }, // dnctl answers either way
		sys: func(name string, args ...string) (string, error) {
			sys = append(sys, name+" "+strings.Join(args, " "))
			switch name {
			case "kldstat":
				if !loaded {
					return "", errors.New("exit status 1")
				}
			case "kldload":
				loaded = true
			}
			return "", nil
		},
	}
	if err := d.available(); err != nil {
		t.Fatal(err)
	}
	if !loaded {
		t.Fatalf("dummynet was not loaded; calls: %v", sys)
	}
	sys = nil
	if err := d.available(); err != nil || len(sys) != 1 || sys[0] != "kldstat -q -m dummynet" {
		t.Fatalf("with dummynet loaded, only the check should run: %v %v", err, sys)
	}
}
