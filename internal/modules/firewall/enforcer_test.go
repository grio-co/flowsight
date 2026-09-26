package firewall

import (
	"testing"

	"github.com/grioghar/flowsight/internal/core"
)

func TestSplitHostPort(t *testing.T) {
	for _, c := range []struct {
		in   string
		host string
		port int
	}{
		{"1.2.3.4:443", "1.2.3.4", 443},
		{"[2606:4700::1]:443", "2606:4700::1", 443},
		{"fd99::112a", "fd99::112a", 0},
		{"10.0.0.1", "10.0.0.1", 0},
	} {
		h, p := SplitHostPort(c.in)
		if h != c.host || p != c.port {
			t.Errorf("%q -> %q:%d, want %q:%d", c.in, h, p, c.host, c.port)
		}
	}
}

// The same capture egress/states_test.go pins, read here as backend-neutral
// connections: who opened each one, both sides of every translation, and the
// first counter always what the opener sent.
func TestParseStatesNeutral(t *testing.T) {
	const capture = `all tcp 127.0.0.1:3129 (140.82.114.3:443) <- 10.99.0.162:59216       FIN_WAIT_2:FIN_WAIT_2
   [2837096760 + 392192] wscale 7  [2817892562 + 65792] wscale 10
   age 00:01:09, expires in 00:00:24, 249:432 pkts, 14863:616615 bytes, anchor 4
all udp 162.202.41.52:17449 (192.168.1.178:56094) -> 79.127.160.158:51820       MULTIPLE:MULTIPLE
   age 08:20:20, expires in 00:01:00, 317323773:165327693 pkts, 263517066416:102413038016 bytes
all tcp 192.168.1.105:32400 (162.202.41.52:41952) <- 73.96.122.167:36068       ESTABLISHED:ESTABLISHED
   [3165868840 + 44372] wscale 10  [2555950065 + 65536] wscale 7
   age 10:34:23, expires in 15:52:01, 796:814 pkts, 42419:83330 bytes, rule 3
all icmp 192.168.1.9:11 -> 1.1.1.1:11       0:0
   age 00:00:02, expires in 00:00:08, 1:1 pkts, 84:84 bytes, rule 9
`
	got := ParseStates(capture)
	if len(got) != 4 {
		t.Fatalf("want 4 connections, got %d: %+v", len(got), got)
	}
	ep := func(a string, p int) core.Endpoint { return core.Endpoint{Addr: a, Port: p} }

	// Redirected to the proxy: the device opened it towards github.
	rd := got[0]
	if rd.Initiator != ep("10.99.0.162", 59216) || rd.InitiatorTranslated != rd.Initiator {
		t.Errorf("redirect initiator: %+v", rd)
	}
	if rd.Responder != ep("140.82.114.3", 443) || rd.ResponderTranslated != ep("127.0.0.1", 3129) {
		t.Errorf("redirect responder: %+v", rd)
	}
	if rd.Sent != 14863 || rd.Received != 616615 || rd.Rule != "anchor 4" {
		t.Errorf("redirect counters: %+v", rd)
	}

	// Outbound NAT: the device before translation, the gateway on the wire.
	nat := got[1]
	if nat.Initiator != ep("192.168.1.178", 56094) || nat.InitiatorTranslated != ep("162.202.41.52", 17449) {
		t.Errorf("nat initiator: %+v", nat)
	}
	if nat.Responder != ep("79.127.160.158", 51820) || nat.ResponderTranslated != nat.Responder {
		t.Errorf("nat responder: %+v", nat)
	}
	if nat.Sent != 263517066416 || nat.Received != 102413038016 || nat.Age.Hours() < 8 {
		t.Errorf("nat counters: %+v", nat)
	}

	// Port forward: the internet opened it towards the WAN address, and it
	// was delivered to the server.
	pf := got[2]
	if pf.Initiator != ep("73.96.122.167", 36068) || pf.Responder != ep("162.202.41.52", 41952) ||
		pf.ResponderTranslated != ep("192.168.1.105", 32400) {
		t.Errorf("port forward: %+v", pf)
	}
	if pf.Sent != 42419 || pf.Received != 83330 {
		t.Errorf("port forward counters: %+v", pf)
	}

	if got[3].Proto != "icmp" {
		t.Errorf("icmp kept as a connection: %+v", got[3])
	}
}

func TestParseRules(t *testing.T) {
	const out = `pass in quick on vtnet0 inet proto tcp from any to any port = 22 flags S/SA keep state label "a1b2"
  [ Evaluations: 123       Packets: 456       Bytes: 789         States: 2     ]
  [ Inserted: uid 0 pid 123 State Creations: 4     ]
block drop in log quick on vtnet1 all
  [ Evaluations: 10        Packets: 0         Bytes: 0           States: 0     ]
`
	got := ParseRules(out)
	if len(got) != 2 {
		t.Fatalf("want 2 rules, got %d: %+v", len(got), got)
	}
	if got[0].Label != "a1b2" || got[0].Evaluations != 123 || got[0].Packets != 456 || got[0].Bytes != 789 || got[0].States != 2 {
		t.Errorf("first rule misread: %+v", got[0])
	}
	if got[1].Text != "block drop in log quick on vtnet1 all" || got[1].Evaluations != 10 || got[1].Label != "" {
		t.Errorf("second rule misread: %+v", got[1])
	}
}

func TestSplitHostPortPFIPv6(t *testing.T) {
	if h, p := SplitHostPort("2600:1700::9[52034]"); h != "2600:1700::9" || p != 52034 {
		t.Errorf("pf ipv6 form: %q:%d", h, p)
	}
}
