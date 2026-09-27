package visibility

import (
	"strings"
	"testing"
)

// An unnamed flow is filed by the best thing known about it: the name, else
// the network, else the /24, always with port and protocol.
func TestUnknownSignatureUsesTheBestEvidence(t *testing.T) {
	sig, label := unknownSignature("tcp", 5223, "", "courier.push.apple.com", "17.57.144.86", "714")
	if sig != "tcp/5223 apple.com" || !strings.Contains(label, "apple.com") || !strings.Contains(label, "push notifications") {
		t.Fatalf("named: %q %q", sig, label)
	}
	sig, label = unknownSignature("udp", 40317, "", "", "23.23.189.93", "14618")
	if sig != "udp/40317 AS14618" || !strings.Contains(label, "AS14618") || !strings.Contains(label, "high port") {
		t.Fatalf("network: %q %q", sig, label)
	}
	sig, _ = unknownSignature("udp", 33434, "", "", "198.51.100.7", "")
	if sig != "udp/33434 198.51.100.0/24" {
		t.Fatalf("subnet: %q", sig)
	}
	sig, _ = unknownSignature("tcp", 443, "", "", "2001:db8:1:2:3:4:5:6", "")
	if sig != "tcp/443 2001:db8:1:2::/64" {
		t.Fatalf("v6 subnet: %q", sig)
	}
	if registrableName("a.b.example.co.uk") != "example.co.uk" || registrableName("www.example.com") != "example.com" {
		t.Fatal("registrable name")
	}
}

// Every application gets a note: its own, or its category's, with the
// breed's sentence appended.
func TestNoteForFallsBackToCategoryAndBreed(t *testing.T) {
	n := noteFor("BitTorrent", "Download", "Unsafe")
	if n.Source != "curated" || !strings.Contains(n.Risk, "unsafe") {
		t.Fatalf("curated: %+v", n)
	}
	n = noteFor("TLS.Dropbox", "Cloud", "Acceptable")
	if n.Source != "curated" || !strings.Contains(n.Purpose, "File sync") {
		t.Fatalf("dotted name should find the service: %+v", n)
	}
	n = noteFor("SomethingNew", "Game", "Fun")
	if n.Source != "category" || !strings.Contains(n.Purpose, "Games") || !strings.Contains(n.Risk, "fun") {
		t.Fatalf("category fallback: %+v", n)
	}
	n = noteFor("Nothing", "", "")
	if n.Purpose == "" || n.Risk == "" {
		t.Fatal("never empty")
	}
}
