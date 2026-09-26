package egress

import (
	"strings"
	"testing"

	"github.com/grioghar/flowsight/internal/modules/firewall"
)

// parseStates runs a pf capture through the whole path: pf's parser into
// backend-neutral connections, then the orientation this package adds.
func parseStates(text string, isLocal func(string) bool) []State {
	return fromConns(firewall.ParseStates(text), isLocal)
}

// Real output from `pfctl -ss -v` on an OPNsense gateway. Reading a download
// as an upload would make every alert here meaningless, so the direction is
// pinned against traffic whose shape is known: the github session fetched
// 616615 bytes and sent 14863, and the Plex server received connections from
// outside rather than making them.
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

func local(ip string) bool {
	return strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.99.") || strings.HasPrefix(ip, "10.8.")
}

func TestParseStatesDirection(t *testing.T) {
	got := parseStates(capture, local)
	if len(got) != 3 {
		t.Fatalf("want 3 states (icmp is skipped), got %d: %+v", len(got), got)
	}
	byLocal := map[string]State{}
	for _, s := range got {
		byLocal[s.Local] = s
	}

	// A device fetching a page through the proxy: little out, a lot in.
	gh, ok := byLocal["10.99.0.162"]
	if !ok {
		t.Fatal("redirected session not attributed to the device")
	}
	if gh.Out != 14863 || gh.In != 616615 {
		t.Errorf("download read backwards: out=%d in=%d", gh.Out, gh.In)
	}
	if gh.Peer != "140.82.114.3" || gh.PeerPort != 443 {
		t.Errorf("peer wrong: %s:%d", gh.Peer, gh.PeerPort)
	}

	// A tunnel the device opened: the first counter is what it sent.
	wg, ok := byLocal["192.168.1.178"]
	if !ok {
		t.Fatal("translated outbound session not attributed to the device")
	}
	if wg.Out != 263517066416 || wg.In != 102413038016 {
		t.Errorf("tunnel read backwards: out=%d in=%d", wg.Out, wg.In)
	}
	if wg.Proto != "udp" || wg.PeerPort != 51820 {
		t.Errorf("tunnel peer wrong: %s %s:%d", wg.Proto, wg.Peer, wg.PeerPort)
	}
	if wg.Age.Hours() < 8 {
		t.Errorf("age not read: %v", wg.Age)
	}

	// A server here answering the internet: the first counter is what it
	// received, because the far side opened the connection.
	plex, ok := byLocal["192.168.1.105"]
	if !ok {
		t.Fatal("inbound session not attributed to the server")
	}
	if plex.In != 42419 || plex.Out != 83330 {
		t.Errorf("inbound session read backwards: out=%d in=%d", plex.Out, plex.In)
	}
}

// A redirected session names the proxy's loopback address as one end. The
// identity module calls 127.0.0.1 local, quite correctly, so without an
// explicit exclusion both ends look local and every intercepted session is
// silently dropped, which is precisely the traffic this is meant to watch.
func TestRedirectedSessionSurvivesLoopbackBeingLocal(t *testing.T) {
	localIncludingLoopback := func(ip string) bool { return local(ip) || strings.HasPrefix(ip, "127.") }
	got := parseStates(capture, localIncludingLoopback)
	var found bool
	for _, s := range got {
		if s.Local == "10.99.0.162" {
			found = true
			if s.Peer != "140.82.114.3" || s.Out != 14863 || s.In != 616615 {
				t.Errorf("redirected session wrong: %+v", s)
			}
		}
	}
	if !found {
		t.Fatalf("the intercepted session was dropped; got %d states: %+v", len(got), got)
	}
}

// A server on this network answering the internet has genuinely sent the
// bytes, and it is not data leaving in the sense anyone means by it. Getting
// this wrong turns every Plex stream into an exfiltration alert.
func TestInboundConnectionsAreMarkedServing(t *testing.T) {
	got := parseStates(capture, local)
	for _, s := range got {
		switch s.Local {
		case "192.168.1.105": // the far side opened this one
			if !s.Inbound {
				t.Errorf("a connection opened from outside was not marked as serving: %+v", s)
			}
		case "10.99.0.162", "192.168.1.178": // these reached out
			if s.Inbound {
				t.Errorf("a connection this network opened was marked as serving: %+v", s)
			}
		}
	}
}

// Broadcast, multicast and link-local destinations never leave the network,
// so counting them as egress is noise at best.
func TestOffNetwork(t *testing.T) {
	for _, bad := range []string{"", "255.255.255.255", "224.0.0.251", "239.255.255.250",
		"169.254.1.1", "ff02::fb", "fe80::1", "192.168.1.255"} {
		if offNetwork(bad) {
			t.Errorf("%q should not count as a destination off this network", bad)
		}
	}
	for _, good := range []string{"8.8.8.8", "140.82.114.3", "2606:4700::1111"} {
		if !offNetwork(good) {
			t.Errorf("%q should count as a destination off this network", good)
		}
	}
}
