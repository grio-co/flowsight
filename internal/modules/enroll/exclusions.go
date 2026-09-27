package enroll

// What the policy keeps out of inspection, and what each device is doing.

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// policyDocSource is what the policy module publishes as policy_doc.
type policyDocSource interface{ Doc() *core.PolicyDoc }

// exclusionSet is the policy's excluded hosts, resolved to networks, each
// remembering the entry it came from, so a device can say which line of the
// exclusion list keeps it out.
type exclusionSet struct {
	nets  []*net.IPNet
	entry []string
	macs  map[string]string // mac -> entry, for mac: entries and devices without an address
}

func (m *Module) exclusions() *exclusionSet {
	es := &exclusionSet{macs: map[string]string{}}
	src, ok := m.ctx.Service("policy_doc").(policyDocSource)
	if !ok || src == nil {
		return es
	}
	doc := src.Doc()
	if doc == nil {
		return es
	}
	res, _ := m.ctx.Service("member_resolver").(core.MemberResolver)
	for _, h := range doc.Exclusions.Hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if len(h) > 4 && strings.EqualFold(h[:4], "mac:") {
			es.macs[strings.ToLower(h[4:])] = h
		}
		var members []string
		if strings.Contains(h, "/") || net.ParseIP(h) != nil {
			members = []string{h}
		} else if res != nil {
			members = res.Resolve(h)
		}
		for _, mem := range members {
			es.add(mem, h)
		}
	}
	return es
}

func (es *exclusionSet) add(cidr, entry string) {
	if !strings.Contains(cidr, "/") {
		if ip := net.ParseIP(cidr); ip != nil {
			if ip.To4() != nil {
				cidr += "/32"
			} else {
				cidr += "/128"
			}
		}
	}
	if _, n, err := net.ParseCIDR(cidr); err == nil {
		es.nets = append(es.nets, n)
		es.entry = append(es.entry, entry)
	}
}

// covers returns the exclusion entry that keeps the device out, or "".
func (es *exclusionSet) covers(d *Device) string {
	if e := es.macs[strings.ToLower(d.MAC)]; e != "" {
		return e
	}
	for _, ipStr := range []string{d.IP, d.IP6} {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		for i, n := range es.nets {
			if n.Contains(ip) {
				return es.entry[i]
			}
		}
	}
	return ""
}

// entries lists the distinct exclusion entries, for the page's key.
func (es *exclusionSet) entries() []string {
	seen := map[string]bool{}
	out := []string{}
	for _, e := range es.entry {
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	for _, e := range es.macs {
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// Services: what a device uses, and what it offers.
//
// Used: the applications the device's addresses talked, by bytes, from the
// application rollup. Offered: the ports other local hosts connected to on
// the device, with how many distinct clients came, from the destination
// rollup. Both over the last day, both by every address the device holds
// (v4 and v6, current and remembered), memoised for two minutes because the
// Devices page refreshes every thirty seconds.

type ServiceUse struct {
	Name  string `json:"name"`
	Bytes int64  `json:"bytes"`
}

type ServiceOffer struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Name    string `json:"name,omitempty"`
	Clients int    `json:"clients"`
	Flows   int64  `json:"flows"`
}

type DeviceServices struct {
	Uses   []ServiceUse   `json:"uses,omitempty"`
	Offers []ServiceOffer `json:"offers,omitempty"`
}

// wellKnown names the ports worth reading at a glance.
var wellKnown = map[string]string{
	"tcp/22": "ssh", "tcp/23": "telnet", "tcp/25": "smtp", "tcp/53": "dns", "udp/53": "dns", "tcp/80": "http",
	"tcp/88": "kerberos", "tcp/110": "pop3", "udp/123": "ntp", "tcp/135": "msrpc", "udp/137": "netbios", "udp/138": "netbios",
	"tcp/139": "netbios", "tcp/143": "imap", "udp/161": "snmp", "tcp/389": "ldap", "tcp/443": "https", "udp/443": "quic",
	"tcp/445": "smb", "tcp/465": "smtps", "tcp/515": "lpd", "tcp/548": "afp", "tcp/554": "rtsp", "tcp/587": "submission",
	"tcp/631": "ipp", "udp/1900": "ssdp", "tcp/1883": "mqtt", "tcp/2049": "nfs", "tcp/3000": "web", "tcp/3128": "proxy",
	"tcp/3306": "mysql", "tcp/3389": "rdp", "tcp/5000": "web", "tcp/5353": "mdns", "udp/5353": "mdns", "tcp/5432": "postgres",
	"tcp/5900": "vnc", "tcp/6379": "redis", "tcp/8006": "proxmox", "tcp/8080": "http-alt", "tcp/8096": "jellyfin",
	"tcp/8123": "home assistant", "tcp/8443": "https-alt", "tcp/8883": "mqtts", "tcp/9000": "web", "tcp/9090": "web",
	"tcp/9100": "printer", "tcp/32400": "plex", "udp/1194": "openvpn", "udp/51820": "wireguard", "tcp/62078": "iphone sync",
	"udp/67": "dhcp", "udp/68": "dhcp", "udp/547": "dhcpv6", "tcp/6881": "bittorrent", "udp/6881": "bittorrent",
	"udp/3478": "stun", "tcp/7000": "airplay", "tcp/7100": "airplay", "tcp/49152": "upnp",
}

func portName(proto string, port int) string {
	p := strings.ToLower(proto)
	if n := wellKnown[p+"/"+strconv.Itoa(port)]; n != "" {
		return n
	}
	return ""
}

// deviceAddresses is every address the device is known by.
func (m *Module) deviceAddresses(d *Device) []string {
	seen := map[string]bool{}
	var out []string
	add := func(ip string) {
		if ip != "" && !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	for _, ip := range []string{d.IP, d.IP6} {
		if ip == "" {
			continue
		}
		add(ip)
		if book, ok := m.identity.(core.AddressBook); ok && book != nil {
			for _, a := range book.Addresses(ip) {
				add(a)
			}
		}
	}
	return out
}

// services computes the use/offer summary for every device.
func (m *Module) services(hours int) map[string]*DeviceServices {
	m.svcMu.Lock()
	defer m.svcMu.Unlock()
	if m.svcAt.Add(2*time.Minute).After(time.Now()) && m.svcHours == hours && m.svc != nil {
		return m.svc
	}
	m.mu.RLock()
	owner := map[string]string{} // ip -> mac
	for mac, d := range m.devices {
		for _, ip := range m.deviceAddresses(d) {
			owner[ip] = mac
		}
	}
	m.mu.RUnlock()
	out := map[string]*DeviceServices{}
	get := func(mac string) *DeviceServices {
		s := out[mac]
		if s == nil {
			s = &DeviceServices{}
			out[mac] = s
		}
		return s
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()

	// Used.
	uses := map[string]map[string]int64{} // mac -> app -> bytes
	rows, _ := m.ctx.Store.Rows(`SELECT src_ip, app, SUM(bytes_in+bytes_out) AS b FROM rollup_app WHERE bucket >= ? AND app <> '' GROUP BY src_ip, app`, since)
	for _, r := range rows {
		ip, _ := r["src_ip"].(string)
		mac := owner[ip]
		if mac == "" {
			continue
		}
		app, _ := r["app"].(string)
		if app == "" || strings.EqualFold(app, "unknown") {
			continue
		}
		b := toInt64(r["b"])
		if uses[mac] == nil {
			uses[mac] = map[string]int64{}
		}
		uses[mac][app] += b
	}
	for mac, apps := range uses {
		s := get(mac)
		for app, b := range apps {
			s.Uses = append(s.Uses, ServiceUse{Name: app, Bytes: b})
		}
		sort.Slice(s.Uses, func(i, j int) bool { return s.Uses[i].Bytes > s.Uses[j].Bytes })
		if len(s.Uses) > 8 {
			s.Uses = s.Uses[:8]
		}
	}

	// Offered: connections from other local hosts to the device.
	type key struct {
		mac   string
		port  int
		proto string
	}
	clients := map[key]map[string]bool{}
	flows := map[key]int64{}
	addrs := make([]string, 0, len(owner))
	for ip := range owner {
		addrs = append(addrs, ip)
	}
	sort.Strings(addrs)
	for i := 0; i < len(addrs); i += 400 {
		j := i + 400
		if j > len(addrs) {
			j = len(addrs)
		}
		chunk := addrs[i:j]
		args := []any{since}
		ph := make([]string, 0, len(chunk))
		for _, ip := range chunk {
			args = append(args, ip)
			ph = append(ph, "?")
		}
		rows, _ := m.ctx.Store.Rows(`SELECT dst_ip, dst_port, proto, src_ip, SUM(flows) AS f FROM rollup_dst WHERE bucket >= ? AND dst_port > 0 AND dst_ip IN (`+strings.Join(ph, ",")+`) GROUP BY dst_ip, dst_port, proto, src_ip`, args...)
		for _, r := range rows {
			dst, _ := r["dst_ip"].(string)
			src, _ := r["src_ip"].(string)
			mac := owner[dst]
			if mac == "" || src == "" || owner[src] == mac {
				continue
			}
			if m.identity != nil && !m.identity.IsLocal(src) {
				continue
			}
			port := int(toInt64(r["dst_port"]))
			proto, _ := r["proto"].(string)
			proto = strings.ToLower(proto)
			// Ephemeral high ports are the reply side of something else,
			// not a service; keep them only when a name is known.
			if port >= 32768 && portName(proto, port) == "" {
				continue
			}
			k := key{mac, port, proto}
			if clients[k] == nil {
				clients[k] = map[string]bool{}
			}
			clients[k][src] = true
			flows[k] += toInt64(r["f"])
		}
	}
	for k, cs := range clients {
		s := get(k.mac)
		s.Offers = append(s.Offers, ServiceOffer{Port: k.port, Proto: k.proto, Name: portName(k.proto, k.port), Clients: len(cs), Flows: flows[k]})
	}
	for _, s := range out {
		sort.Slice(s.Offers, func(i, j int) bool {
			if s.Offers[i].Clients != s.Offers[j].Clients {
				return s.Offers[i].Clients > s.Offers[j].Clients
			}
			return s.Offers[i].Flows > s.Offers[j].Flows
		})
		if len(s.Offers) > 8 {
			s.Offers = s.Offers[:8]
		}
	}
	m.svc, m.svcAt, m.svcHours = out, time.Now(), hours
	return out
}

func toInt64(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case float64:
		return int64(x)
	}
	return 0
}

// apiServices: what each device uses and offers.
func (m *Module) apiServices(r *core.Req) (any, error) {
	hours := r.QInt("hours", 24, 1, 24*7)
	return map[string]any{"hours": hours, "services": m.services(hours)}, nil
}

// guessVendor names the maker of a device whose hardware address says
// nothing: phones and laptops that use a private (randomised) address per
// network carry no registered prefix, but their DHCP option fingerprint,
// vendor class and the name they give themselves usually say who made them.
func guessVendor(d *Device) string {
	if d.Vendor != "" || d.Randomized == 0 {
		return d.Vendor
	}
	vc := strings.ToLower(d.VendorClass)
	fp := d.Fingerprint
	name := strings.ToLower(d.Hostname)
	switch {
	case strings.Contains(vc, "android") || strings.Contains(vc, "dhcpcd") && strings.Contains(name, "android"):
		return "Android device (private address)"
	case strings.Contains(vc, "msft"):
		return "Microsoft Windows (private address)"
	case strings.Contains(name, "iphone") || strings.Contains(name, "ipad") || strings.Contains(name, "macbook") || strings.HasPrefix(name, "mac") && (len(name) < 5 || strings.Contains(name, "mac-") || strings.Contains(name, "macbook") || strings.Contains(name, "mac.") || strings.HasPrefix(name, "mac ")) || strings.Contains(name, "apple") || strings.Contains(name, "watch"):
		return "Apple (private address)"
	case strings.Contains(name, "galaxy") || strings.Contains(name, "samsung") || strings.Contains(name, "pixel") || strings.Contains(name, "-s2") && strings.Contains(name, "ultra"):
		return "Android device (private address)"
	}
	// Apple's DHCP request list starts 1,121,3,6,15,108,114,119,252 (iOS 14+
	// and macOS 11+); Android's starts 1,3,6,15,26,28,51,58,59,43 and
	// Windows' 1,3,6,15,31,33,43,44,46,47,119,121,249,252.
	switch {
	case strings.HasPrefix(fp, "1,121,3,6,15,108,114,119,252") || strings.HasPrefix(fp, "1,121,3,6,15,119,252"):
		return "Apple (private address)"
	case strings.HasPrefix(fp, "1,3,6,15,26,28,51,58,59,43") || strings.HasPrefix(fp, "1,3,6,15,26,28,51,58,59"):
		return "Android device (private address)"
	case strings.HasPrefix(fp, "1,3,6,15,31,33,43,44,46,47,119,121,249,252") || strings.HasPrefix(fp, "1,3,6,15,31,33,43,44,46,47,121,249,252"):
		return "Microsoft Windows (private address)"
	}
	return ""
}
