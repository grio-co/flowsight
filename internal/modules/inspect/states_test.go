package inspect

import (
	"testing"
	"time"
)

const pfSample = `vtnet0 tcp 192.168.1.119:52034 -> 142.250.190.46:443       ESTABLISHED:ESTABLISHED
   [3993207633 + 62608] wscale 8  [1002905477 + 65535] wscale 7
   age 00:01:02, expires in 23:59:58, 1234:5678 pkts, 123456:654321 bytes, rule 12
   id: 0000000067ccd2e3000001 creatorid: 1a2b3c4d gateway: 0.0.0.0
vtnet0 udp 192.168.1.53:53 <- 192.168.1.5:41523              MULTIPLE:SINGLE
   age 00:00:05, expires in 00:00:55, 4:4 pkts, 344:344 bytes, anchor 1, rule 3
   id: 0000000067ccd2e3000002 creatorid: 1a2b3c4d
all icmp 192.168.1.5:1 -> 8.8.8.8:1       0:0
   age 45s, expires in 10s, 1:1 pkts, 84:84 bytes, rule 7
vtnet1 tcp 10.0.0.5:44321 (192.168.0.9:44321) -> 1.2.3.4:443  SYN_SENT:CLOSED
   [123 + 1] wscale 0  [0 + 0] wscale 0
   age 00:00:01, expires in 00:00:29, 1:0 pkts, 60:0 bytes, rule 12
vtnet0 tcp 2600:1700::9[52034] -> 2607:f8b0::200e[443]      ESTABLISHED:ESTABLISHED
   age 00:10:00, expires in 23:50:00, 10:10 pkts, 1000:2000 bytes, rule 12
`

func TestParsePFStatesRealFormat(t *testing.T) {
	st := parsePFStates(pfSample, time.Unix(0, 0))
	if len(st) != 5 {
		t.Fatalf("want 5 states, got %d", len(st))
	}
	a := st[0]
	if a.Interface != "vtnet0" || a.Proto != "tcp" || a.Src != "192.168.1.119" || a.SrcPort != 52034 || a.Dst != "142.250.190.46" || a.DstPort != 443 || a.State != "ESTABLISHED:ESTABLISHED" || a.Direction != "out" {
		t.Fatalf("header misread: %+v", a)
	}
	if a.Age != 62 || a.Expires != 86398 || a.PktsSrc != 1234 || a.PktsDst != 5678 || a.BytesSrc != 123456 || a.BytesDst != 654321 || a.RuleID != 12 {
		t.Fatalf("detail misread: %+v", a)
	}
	if st[1].Direction != "in" || st[1].Proto != "udp" || st[1].RuleID != 3 || st[1].Age != 5 {
		t.Fatalf("udp/in/anchor misread: %+v", st[1])
	}
	if st[2].Interface != "all" || st[2].Proto != "icmp" || st[2].Age != 45 || st[2].Expires != 10 {
		t.Fatalf("icmp misread: %+v", st[2])
	}
	if st[3].Src != "192.168.0.9" || st[3].State != "SYN_SENT:CLOSED" {
		t.Fatalf("nat source must be the real host: %+v", st[3])
	}
	if st[4].Src != "2600:1700::9" || st[4].SrcPort != 52034 || st[4].DstPort != 443 {
		t.Fatalf("ipv6 misread: %+v", st[4])
	}
	for _, s := range st {
		if s.Proto[0] == '[' {
			t.Fatalf("a sequence line was taken for a state: %+v", s)
		}
	}
}
