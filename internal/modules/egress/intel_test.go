package egress

import "testing"

// "Other" is split by what is known, in the order that says most: the
// application's category, the web category, the network, the port.
func TestSubgroupSplitsOtherByWhatIsKnown(t *testing.T) {
	k, title := subgroup(&Intel{AppCategory: "SoftwareUpdate"}, 443, "tcp")
	if k != "other:app:softwareupdate" || title != "Other · Software Update" {
		t.Fatalf("app category: %q %q", k, title)
	}
	k, title = subgroup(&Intel{WebCategory: []string{"ads"}}, 443, "tcp")
	if k != "other:web:ads" || title != "Other · ads" {
		t.Fatalf("web category: %q %q", k, title)
	}
	k, title = subgroup(&Intel{ASN: "16509", ASName: "Amazon.com, Inc."}, 443, "tcp")
	if k != "other:as:16509" || title != "Other · Amazon.com, Inc." {
		t.Fatalf("network: %q %q", k, title)
	}
	k, title = subgroup(&Intel{}, 33434, "udp")
	if k != "other:port:traceroute" || title != "Other · Traceroute" {
		t.Fatalf("port: %q %q", k, title)
	}
	k, _ = subgroup(&Intel{AppCategory: "Unspecified"}, 5223, "tcp")
	if k != "other:port:push-notifications" {
		t.Fatalf("an unspecified category must not name the group: %q", k)
	}
}

// The payload line never claims more than the evidence.
func TestPayloadClassReadsTheEvidence(t *testing.T) {
	cases := []struct {
		in    Intel
		port  int
		proto string
		group string
		want  string
	}{
		{Intel{Visibility: "inspected", ContentTypes: []string{"image/jpeg", "application/json"}}, 443, "tcp", "other", "Inspected: API calls, images"},
		{Intel{App: "TLS.Apple", Visibility: "sni", SNI: "gs-loc.apple.com"}, 443, "tcp", "other", "Encrypted web (TLS, name seen)"},
		{Intel{App: "TLS", Visibility: "opaque"}, 443, "tcp", "other", "Encrypted web (TLS, opaque)"},
		{Intel{Visibility: "ech"}, 443, "tcp", "other", "Encrypted web (TLS, name hidden)"},
		{Intel{App: "QUIC.YouTube"}, 443, "udp", "media", "Media stream"},
		{Intel{App: "BitTorrent"}, 51413, "tcp", "other", "BitTorrent"},
		{Intel{}, 51820, "udp", "tunnel", "Encrypted tunnel"},
		{Intel{}, 33434, "udp", "other", "UDP to port 33434"},
		{Intel{App: "SSH"}, 22, "tcp", "remote-access", "SSH session"},
	}
	for _, c := range cases {
		if got := payloadClass(&c.in, c.port, c.proto, c.group); got != c.want {
			t.Errorf("%+v port %d: got %q want %q", c.in, c.port, got, c.want)
		}
	}
}

func TestContentKindFoldsMIMETypes(t *testing.T) {
	for ct, want := range map[string]string{
		"image/png": "images", "video/mp4": "video", "text/html; charset=utf-8": "web pages",
		"application/json": "API calls", "application/zip": "archives", "application/pdf": "documents",
		"application/octet-stream": "binary files", "multipart/form-data; boundary=x": "uploads", "text/plain": "text",
	} {
		if got := contentKind(ct); got != want {
			t.Errorf("%s: got %q want %q", ct, got, want)
		}
	}
}

func TestShortASNameDropsRegistryNoise(t *testing.T) {
	for in, want := range map[string]string{
		"AMAZON-02, US": "AMAZON-02",
		"AKAMAI-ASN1 - Akamai International B.V., NL": "Akamai International B.V.",
		"Dropbox, Inc., US":                           "Dropbox, Inc.",
	} {
		if got := shortASName(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}
