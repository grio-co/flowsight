package inspect

import (
	"testing"
)

// TestPFStateOutput contains a realistic sample of pfctl -ss -vv output from FreeBSD 15
const pfctlSSOutput = `STATES       4        0

  tcp 192.168.1.100:54321 -> 10.0.0.1:443 ESTABLISHED:ESTABLISHED [OPEN, WINDOW(65535:65535)] age 245s, expires in 3355s, 1024:856 pkts, 512000:256000 bytes, rule 0
  tcp 192.168.1.101:54322 -> 10.0.0.2:80 ESTABLISHED:ESTABLISHED [OPEN, WINDOW(65535:65535)] age 187s, expires in 3413s, 512:456 pkts, 128000:96000 bytes, rule 1
  tcp 192.168.1.102:53421 -> 8.8.8.8:443 SYN_SENT:SYN_RCVD [OPEN, WINDOW(16384:0)] age 2s, expires in 3598s, 1:0 pkts, 60:0 bytes, rule 0
  udp 192.168.1.103:53422 -> 8.8.8.8:53 SINGLE:SINGLE [OPEN] age 29s, expires in 3571s, 2:2 pkts, 120:256 bytes, rule 0
`

func TestStateFiltering(t *testing.T) {
	states := []*PFState{
		{Proto: "tcp", Src: "10.0.0.1", Dst: "192.168.1.100", State: "ESTABLISHED", DstPort: 443},
		{Proto: "tcp", Src: "10.0.0.1", Dst: "192.168.1.100", State: "ESTABLISHED", DstPort: 80},
		{Proto: "tcp", Src: "10.0.0.2", Dst: "192.168.1.101", State: "ESTABLISHED", DstPort: 443},
		{Proto: "udp", Src: "8.8.8.8", Dst: "192.168.1.102", State: "SINGLE", DstPort: 53},
	}

	// Test filtering by host
	hostStates := filterStates(states, func(s *PFState) bool {
		return s.Src == "10.0.0.1" || s.Dst == "10.0.0.1"
	})
	if len(hostStates) != 2 {
		t.Errorf("host filter: got %d, want 2", len(hostStates))
	}

	// Test filtering by protocol
	tcpStates := filterStates(states, func(s *PFState) bool {
		return s.Proto == "tcp"
	})
	if len(tcpStates) != 3 {
		t.Errorf("protocol filter: got %d, want 3", len(tcpStates))
	}

	// Test filtering by state
	establishedStates := filterStates(states, func(s *PFState) bool {
		return s.State == "ESTABLISHED"
	})
	if len(establishedStates) != 3 {
		t.Errorf("state filter: got %d, want 3", len(establishedStates))
	}
}

// Helpers

func stringContains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && indexOf(s, substr) >= 0
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func filterStates(states []*PFState, predicate func(*PFState) bool) []*PFState {
	var result []*PFState
	for _, s := range states {
		if predicate(s) {
			result = append(result, s)
		}
	}
	return result
}

// Test context
type testContext struct{}

func (tc *testContext) Module(name string) map[string]any {
	return map[string]any{}
}

func (tc *testContext) Settings(name string, into any) error {
	return nil
}
