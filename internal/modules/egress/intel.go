package egress

// What a transfer is, beyond how big it is.
//
// The connection table says who is sending how much to which address. On
// its own that is a number beside an address, and the reader has to go and
// find out the rest. The rest is mostly already in the house: the flow
// record for the same connection carries the application the probe
// recognised, the name it was for, whether the session was inspected and
// what content types went through it; the enrichment module knows the far
// end's country and city; the anycast census knows whether the address is a
// nearby instance of a global service; the web-category feeds know what
// kind of site a name is; and the routing table names the network. None of
// that costs a request to the internet except the network name, which is
// asked once per address on a timer and remembered.
//
// The same facts split "Other". A destination that matched none of the
// hand-written groups still has an application, a category, a network or
// at least a port, and one of those is a better label than "Other".

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// Intel is what is known about one transfer beyond its counters. Every field
// is optional; a missing one means no source could say.
type Intel struct {
	// What: the application the flow probe recognised, its nDPI category,
	// the name the connection was for, how much of it was readable, and the
	// content types seen when it was.
	App          string   `json:"app,omitempty"`
	AppCategory  string   `json:"app_category,omitempty"`
	Domain       string   `json:"domain,omitempty"`
	SNI          string   `json:"sni,omitempty"`
	Visibility   string   `json:"visibility,omitempty"` // inspected, sni, http, quic, ech, opaque, dns, plain
	ContentTypes []string `json:"content_types,omitempty"`
	WebCategory  []string `json:"web_categories,omitempty"`
	// Payload is the one-line reading of the above: "Encrypted web (TLS, name
	// seen)", "Video stream", "Plain HTTP", "SSH session".
	Payload string `json:"payload,omitempty"`
	// Where: the far end's place and network.
	Country  string `json:"country,omitempty"`
	City     string `json:"city,omitempty"`
	Region   string `json:"region,omitempty"`
	ASN      string `json:"asn,omitempty"`
	ASName   string `json:"as_name,omitempty"`
	Anycast  bool   `json:"anycast,omitempty"`
	Provider string `json:"provider,omitempty"`
	// Who: the device behind the local address.
	MAC    string `json:"mac,omitempty"`
	Vendor string `json:"vendor,omitempty"`
}

// flowFacts is the part of Intel that comes from the flow record of one
// connection, cached per connection key for a short while.
type flowFacts struct {
	at    time.Time
	app   string
	cat   string
	dom   string
	sni   string
	vis   string
	asn   string
	cc    string
	types []string
}

type asnFact struct {
	ASN, Name string
	At        time.Time
}

// intelCache holds what has been learned, keyed by connection and by peer.
type intelCache struct {
	mu    sync.Mutex
	flows map[string]flowFacts // connection key -> facts
	asns  map[string]asnFact   // peer ip -> network
	want  map[string]bool      // peers whose network is still to be asked
}

func newIntelCache() *intelCache {
	return &intelCache{flows: map[string]flowFacts{}, asns: map[string]asnFact{}, want: map[string]bool{}}
}

const flowFactTTL = 2 * time.Minute

// intelFor fills a transfer's Intel from local sources only. It is called
// from the sampler, so nothing here may wait on the network.
func (m *Module) intelFor(t *Transfer) *Intel {
	in := &Intel{}
	if m.identity != nil {
		in.MAC = m.identity.MAC(t.Local)
		if in.MAC != "" {
			in.Vendor = m.identity.Vendor(in.MAC)
		}
	}
	ff := m.flowFactsFor(t)
	in.App, in.AppCategory, in.Domain, in.SNI, in.Visibility, in.ContentTypes = ff.app, ff.cat, ff.dom, ff.sni, ff.vis, ff.types
	if in.AppCategory == "" && in.App != "" && m.apps != nil {
		in.AppCategory = m.apps.AppCategory(in.App)
	}
	in.Country = ff.cc
	if m.rdns != nil {
		for _, info := range m.rdns.Lookup([]string{t.Peer}) {
			if info.Country != "" {
				in.Country = info.Country
			}
			in.City, in.Region = info.City, info.Region
		}
	}
	if m.anycast != nil {
		in.Anycast, in.Provider = m.anycast.Anycast(t.Peer)
	}
	name := t.PeerName
	if name == "" {
		name = ff.sni
	}
	if name == "" {
		name = ff.dom
	}
	if name != "" && m.cats != nil {
		in.WebCategory = m.cats.Classify(name)
	}
	in.ASN, in.ASName = ff.asn, ""
	m.intel.mu.Lock()
	if a, ok := m.intel.asns[t.Peer]; ok {
		if a.ASN != "" {
			in.ASN = a.ASN
		}
		in.ASName = a.Name
	} else if in.ASN == "" || in.ASName == "" {
		m.intel.want[t.Peer] = true
	}
	m.intel.mu.Unlock()
	in.Payload = payloadClass(in, t.PeerPort, t.Proto, t.Group)
	return in
}

// flowFactsFor reads the newest flow record for the same connection, or
// failing that the newest flow from the same device to the same far end.
func (m *Module) flowFactsFor(t *Transfer) flowFacts {
	m.intel.mu.Lock()
	ff, ok := m.intel.flows[t.Key]
	m.intel.mu.Unlock()
	if ok && time.Since(ff.at) < flowFactTTL {
		return ff
	}
	ff = flowFacts{at: time.Now()}
	if m.ctx == nil || m.ctx.Store == nil {
		return ff
	}
	since := time.Now().Add(-6 * time.Hour).Unix()
	q := `SELECT app, category, domain, tls_sni, visibility, asn, country, attrs FROM flows
		WHERE src_ip = ? AND dst_ip = ? AND ts >= ? %s ORDER BY ts DESC LIMIT 1`
	rows, err := m.ctx.Store.Rows(fmt.Sprintf(q, "AND dst_port = ?"), t.Local, t.Peer, since, t.PeerPort)
	if (err != nil || len(rows) == 0) && t.PeerPort > 0 {
		rows, err = m.ctx.Store.Rows(fmt.Sprintf(q, ""), t.Local, t.Peer, since)
	}
	if err == nil && len(rows) > 0 {
		r := rows[0]
		str := func(k string) string { s, _ := r[k].(string); return strings.TrimSpace(s) }
		ff.app, ff.cat, ff.dom, ff.sni, ff.vis, ff.asn, ff.cc = str("app"), str("category"), str("domain"), str("tls_sni"), str("visibility"), str("asn"), strings.ToUpper(str("country"))
		if attrs := str("attrs"); attrs != "" {
			var a map[string]any
			if json.Unmarshal([]byte(attrs), &a) == nil {
				if ct, _ := a["content_type"].(string); ct != "" {
					ff.types = append(ff.types, ct)
				}
				if cts, _ := a["content_types"].([]any); len(cts) > 0 {
					for _, c := range cts {
						if s, _ := c.(string); s != "" {
							ff.types = append(ff.types, s)
						}
					}
				}
			}
		}
	}
	// Content types across the session's recent inspected requests, when the
	// proxy decrypted it: the same device to the same name, last hour.
	if ff.vis == "inspected" && (ff.dom != "" || ff.sni != "") {
		name := ff.dom
		if name == "" {
			name = ff.sni
		}
		if rows, err := m.ctx.Store.Rows(`SELECT attrs FROM flows WHERE src_ip = ? AND (domain = ? OR tls_sni = ?)
			AND ts >= ? AND attrs LIKE '%content_type%' ORDER BY ts DESC LIMIT 40`, t.Local, name, name, time.Now().Add(-time.Hour).Unix()); err == nil {
			seen := map[string]bool{}
			for _, c := range ff.types {
				seen[c] = true
			}
			for _, r := range rows {
				var a map[string]any
				if s, _ := r["attrs"].(string); s != "" && json.Unmarshal([]byte(s), &a) == nil {
					if ct, _ := a["content_type"].(string); ct != "" && !seen[ct] {
						seen[ct] = true
						ff.types = append(ff.types, ct)
					}
				}
			}
		}
	}
	m.intel.mu.Lock()
	m.intel.flows[t.Key] = ff
	// Keep the cache to the connections still live, roughly.
	if len(m.intel.flows) > 5000 {
		for k, v := range m.intel.flows {
			if time.Since(v.at) > flowFactTTL {
				delete(m.intel.flows, k)
			}
		}
	}
	m.intel.mu.Unlock()
	return ff
}

// refreshIntel names the networks behind peers the sampler has asked about,
// a few per run so a busy network never turns this into a scan. It runs on
// the names timer, off the sampling path.
func (m *Module) refreshIntel() {
	m.intel.mu.Lock()
	var ips []string
	for ip := range m.intel.want {
		if _, ok := m.intel.asns[ip]; ok {
			delete(m.intel.want, ip)
			continue
		}
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	if len(ips) > 25 {
		ips = ips[:25]
	}
	m.intel.mu.Unlock()
	for _, ip := range ips {
		asn, _, _, _ := core.OriginASN(ip)
		name := core.ASName(asn)
		m.intel.mu.Lock()
		m.intel.asns[ip] = asnFact{ASN: asn, Name: shortASName(name), At: time.Now()}
		delete(m.intel.want, ip)
		m.intel.mu.Unlock()
	}
}

// shortASName trims a registry name like "AMAZON-02, US" or
// "AKAMAI-ASN1 - Akamai International B.V., NL" to the part a person reads.
func shortASName(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, ","); i > 0 && len(s)-i <= 4 {
		s = strings.TrimSpace(s[:i]) // ", US"
	}
	if i := strings.Index(s, " - "); i > 0 {
		s = strings.TrimSpace(s[i+3:]) // "AKAMAI-ASN1 - Akamai International B.V."
	}
	return s
}

// payloadClass is the one-line reading of what a connection carries, from
// whatever was seen of it. It never claims more than the evidence: an opaque
// TLS session is "Encrypted, unidentified", not a guess at its contents.
func payloadClass(in *Intel, port int, proto, group string) string {
	if group == "tunnel" {
		return "Encrypted tunnel"
	}
	// Inspected sessions say what went through them.
	if in.Visibility == "inspected" && len(in.ContentTypes) > 0 {
		kinds := map[string]bool{}
		for _, ct := range in.ContentTypes {
			kinds[contentKind(ct)] = true
		}
		var ks []string
		for k := range kinds {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		return "Inspected: " + strings.Join(ks, ", ")
	}
	app := strings.ToLower(in.App)
	switch {
	case strings.Contains(app, "bittorrent"):
		return "BitTorrent"
	case strings.Contains(app, "ssh"):
		return "SSH session"
	case strings.HasPrefix(app, "dns") || app == "mdns" || port == 53:
		return "DNS"
	case strings.Contains(app, "doh") || strings.Contains(app, "dns-over-https") || strings.Contains(app, "dnsoverhttps"):
		return "DNS over HTTPS"
	case strings.Contains(app, "ntp") || port == 123:
		return "Time sync"
	case strings.Contains(app, "rtp") || strings.Contains(app, "webrtc") || strings.Contains(app, "facetime") || strings.Contains(app, "zoom") || strings.Contains(app, "teams") && strings.Contains(app, "call"):
		return "Voice or video call"
	case strings.Contains(app, "youtube") || strings.Contains(app, "netflix") || strings.Contains(app, "plex") || strings.Contains(app, "twitch") || strings.Contains(app, "hls") || strings.Contains(app, "dash") || strings.Contains(app, "spotify"):
		return "Media stream"
	case strings.Contains(app, "smtp") || strings.Contains(app, "imap") || strings.Contains(app, "pop3"):
		return "Mail"
	case strings.Contains(app, "quic"):
		return "Encrypted web (QUIC)"
	case strings.HasPrefix(app, "tls") || port == 443 || port == 8443:
		switch in.Visibility {
		case "ech":
			return "Encrypted web (TLS, name hidden)"
		case "sni":
			return "Encrypted web (TLS, name seen)"
		case "inspected":
			return "Encrypted web (TLS, decrypted)"
		}
		if in.SNI != "" || in.Domain != "" {
			return "Encrypted web (TLS, name seen)"
		}
		return "Encrypted web (TLS, opaque)"
	case strings.HasPrefix(app, "http") || port == 80 || port == 8080:
		return "Plain HTTP"
	case strings.Contains(app, "wireguard") || strings.Contains(app, "openvpn") || strings.Contains(app, "ipsec"):
		return "Encrypted tunnel"
	case app != "" && app != "unknown":
		return in.App
	case strings.EqualFold(proto, "udp"):
		return fmt.Sprintf("UDP to port %d", port)
	case strings.EqualFold(proto, "tcp"):
		return fmt.Sprintf("TCP to port %d", port)
	}
	return ""
}

// contentKind folds a MIME type into a word.
func contentKind(ct string) string {
	ct = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	switch {
	case strings.HasPrefix(ct, "image/"):
		return "images"
	case strings.HasPrefix(ct, "video/"):
		return "video"
	case strings.HasPrefix(ct, "audio/"):
		return "audio"
	case strings.HasPrefix(ct, "text/html"):
		return "web pages"
	case strings.Contains(ct, "json") || strings.Contains(ct, "xml") || strings.Contains(ct, "protobuf") || strings.Contains(ct, "grpc"):
		return "API calls"
	case strings.Contains(ct, "javascript") || strings.Contains(ct, "css"):
		return "page assets"
	case strings.Contains(ct, "zip") || strings.Contains(ct, "gzip") || strings.Contains(ct, "tar") || strings.Contains(ct, "7z") || strings.Contains(ct, "rar"):
		return "archives"
	case strings.Contains(ct, "pdf") || strings.Contains(ct, "msword") || strings.Contains(ct, "officedocument") || strings.Contains(ct, "spreadsheet") || strings.Contains(ct, "presentation"):
		return "documents"
	case strings.Contains(ct, "octet-stream") || strings.Contains(ct, "binary") || strings.Contains(ct, "x-msdownload") || strings.Contains(ct, "dmg") || strings.Contains(ct, "apk"):
		return "binary files"
	case strings.HasPrefix(ct, "multipart/form-data"):
		return "uploads"
	case strings.HasPrefix(ct, "text/"):
		return "text"
	}
	return "other data"
}

// subgroup splits "Other" by what is actually known about a destination:
// the application's category, then the web-content category, then the
// network, then the port. The key is stable so the summary can filter on
// it; the title is what a person reads.
func subgroup(in *Intel, port int, proto string) (key, title string) {
	if in != nil {
		if c := strings.TrimSpace(in.AppCategory); c != "" && !strings.EqualFold(c, "unspecified") && !strings.EqualFold(c, "unknown") {
			return "other:app:" + slug(c), "Other · " + humanCategory(c)
		}
		if len(in.WebCategory) > 0 {
			return "other:web:" + slug(in.WebCategory[0]), "Other · " + humanCategory(in.WebCategory[0])
		}
		if in.ASName != "" {
			return "other:as:" + in.ASN, "Other · " + in.ASName
		}
		if in.Payload != "" && !strings.HasPrefix(in.Payload, "TCP to port") && !strings.HasPrefix(in.Payload, "UDP to port") {
			return "other:payload:" + slug(in.Payload), "Other · " + in.Payload
		}
	}
	svc := portService(port, proto)
	return "other:port:" + slug(svc), "Other · " + svc
}

func portService(port int, proto string) string {
	switch port {
	case 443:
		return "HTTPS"
	case 80:
		return "HTTP"
	case 53:
		return "DNS"
	case 123:
		return "NTP"
	case 22:
		return "SSH"
	case 25, 465, 587:
		return "SMTP"
	case 993, 143:
		return "IMAP"
	case 5223, 5228:
		return "Push notifications"
	case 3478, 19302:
		return "STUN"
	case 33434:
		return "Traceroute"
	}
	return fmt.Sprintf("%s %d", strings.ToUpper(proto), port)
}

// humanCategory spaces out an nDPI category name: "SoftwareUpdate" ->
// "Software Update", "IoT-Scada" -> "IoT/SCADA".
func humanCategory(c string) string {
	switch c {
	case "IoT-Scada":
		return "IoT/SCADA"
	case "VoIP":
		return "VoIP"
	case "RPC":
		return "RPC"
	case "VPN":
		return "VPN"
	case "ArtifIntelligence":
		return "AI Services"
	case "Crypto_Currency":
		return "Cryptocurrency"
	case "SocialNetwork":
		return "Social Network"
	case "SoftwareUpdate":
		return "Software Update"
	case "DataTransfer":
		return "Data Transfer"
	case "RemoteAccess":
		return "Remote Access"
	case "VirtAssistant":
		return "Voice Assistant"
	}
	// "SoftwareUpdate" -> "Software Update": a space before each capital,
	// the words kept capitalised to match the kinds' own titles.
	var b strings.Builder
	for i, r := range c {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte(' ')
		}
		if r == '_' || r == '-' {
			b.WriteByte(' ')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case b.Len() > 0 && b.String()[b.Len()-1] != '-':
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
