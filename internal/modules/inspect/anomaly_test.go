package inspect

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// pfLines builds a `pfctl -ss -v` capture in the format pf really prints.
func pfLines(lines ...string) string {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l + "\n   age 00:00:02, expires in 00:00:28, 1:0 pkts, 60:0 bytes, rule 3\n")
	}
	return b.String()
}

func findings(t *testing.T, capture string, syn, scan int) map[string]anomaly {
	t.Helper()
	out := map[string]anomaly{}
	for _, f := range findAnomalies(parsePFStates(capture, time.Unix(0, 0)), syn, scan) {
		out[f.Key] = f
	}
	return out
}

// pf prints a TCP state as the pair "opener:responder". Compared with a
// single word, SYN_SENT never matched and every state counted as not
// established.
func TestScanFromAClientIsFound(t *testing.T) {
	var lines []string
	for i := 1; i <= 60; i++ {
		lines = append(lines, fmt.Sprintf("all tcp 10.99.0.162:%d -> 203.0.113.%d:22       SYN_SENT:CLOSED", 40000+i, i))
	}
	got := findings(t, pfLines(lines...), 100, 50)
	scan, ok := got["port_scan_10.99.0.162"]
	if !ok || scan.Subject != "10.99.0.162" {
		t.Fatalf("scan of 60 unanswered destinations not found: %+v", got)
	}
	if _, flood := got["syn_flood_10.99.0.162"]; flood {
		t.Fatal("60 half-open states are under the flood threshold of 100")
	}
	states := parsePFStates(pfLines(lines...), time.Unix(0, 0))
	half := 0
	for _, s := range states {
		if halfOpen(s) {
			half++
		}
	}
	if half != 60 {
		t.Fatalf("half-open count: got %d, want 60", half)
	}
}

// A busy client talks to many hosts over UDP and finishes its TCP
// handshakes; none of that is a scan.
func TestBusyClientIsNotAScan(t *testing.T) {
	var lines []string
	for i := 1; i <= 120; i++ {
		lines = append(lines, fmt.Sprintf("all udp 10.99.0.162:%d -> 198.51.100.%d:443       MULTIPLE:MULTIPLE", 50000+i, i))
		lines = append(lines, fmt.Sprintf("all tcp 10.99.0.162:%d -> 192.0.2.%d:443       ESTABLISHED:ESTABLISHED", 30000+i, i))
		lines = append(lines, fmt.Sprintf("all tcp 10.99.0.162:%d -> 192.0.2.%d:443       FIN_WAIT_2:FIN_WAIT_2", 20000+i, i))
	}
	if got := findings(t, pfLines(lines...), 100, 50); len(got) != 0 {
		t.Fatalf("a busy client raised findings: %+v", got)
	}
}

// A flood arriving through a port forward is shown with the local server
// first, as pf prints it; the finding must name the sender, not the server.
func TestInboundFloodNamesTheSender(t *testing.T) {
	var lines []string
	for i := 1; i <= 150; i++ {
		lines = append(lines, fmt.Sprintf("all tcp 192.168.1.105:32400 (162.202.41.52:32400) <- 198.51.100.66:%d       SYN_SENT:CLOSED", 10000+i))
	}
	got := findings(t, pfLines(lines...), 100, 50)
	if _, ok := got["syn_flood_198.51.100.66"]; !ok {
		t.Fatalf("flood from 198.51.100.66 not found: %+v", got)
	}
	if _, wrong := got["syn_flood_192.168.1.105"]; wrong {
		t.Fatal("the flood was blamed on the server it targets")
	}
}
