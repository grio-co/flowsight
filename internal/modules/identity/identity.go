// Package identity answers "who is this address": DHCP leases, the ARP and
// NDP tables, the resolver's answers, enrolment and the OUI registry are all
// folded into one name and one MAC per host. Every other module names hosts
// through the service this publishes, so the answer is the same everywhere.
package identity

import (
	"bufio"
	"encoding/csv"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

type nameSource struct {
	name       string
	source     string  // override | dhcp_hostname | reservation | device_table | mdns | reverse_dns | none
	confidence float64 // 0.0-1.0
}

type Module struct {
	ctx *core.Context

	mu      sync.RWMutex
	names   map[string]string     // ip -> best name
	sources map[string]nameSource // ip -> name source and confidence
	macs    map[string]string     // ip -> mac
	ips     map[string][]string
	seenAt  map[string]map[string]int64 // mac -> address -> last seen
	vendors map[string]string           // oui -> vendor
	leases  map[string]Lease            // mac -> lease
	everMAC map[string]string           // ip -> mac, from every source that ever recorded one; does not decay
	macName map[string]string           // mac -> a name learned on any of its addresses
	nets    []*net.IPNet
	netStrs []string
	updated time.Time
	static  map[string]string // ip -> name from reservations / hosts files
	overr   map[string]string // ip -> operator-assigned name
}

type Lease struct {
	MAC, IP, Hostname string
	Expires           int64
	Source            string
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name: "identity", Version: "1.0",
		Description:  "Names and MAC addresses for every host, from DHCP, ARP/NDP, DNS answers and the OUI registry.",
		Capabilities: []string{core.CapHostInventory, core.CapIdentity},
		Defaults: map[string]any{
			"refresh_seconds":      30,
			"extra_lease_files":    []string{},
			"local_networks":       []string{},
			"address_memory_hours": 24,
			"dhcp_names":           true,
		},
		Schema: []core.SettingField{
			{Key: "refresh_seconds", Label: "Refresh interval (s)", Type: "int"},
			{Key: "local_networks", Label: "Local networks", Type: "list",
				Help: "CIDRs considered local. Empty: derived from the firewall's own interfaces."},
			{Key: "extra_lease_files", Label: "Extra lease files", Type: "list"},
			{Key: "address_memory_hours", Label: "Remember a device's addresses for (hours)", Type: "int",
				Help: "How long an address stays associated with its device after the neighbour entry goes. Operating systems rotate temporary IPv6 addresses; remembering them keeps policy, names and history attached to the device."},
			{Key: "dhcp_names", Label: "Send device names to the DHCP server", Type: "bool",
				Help: "A name given to a device in FlowSight also goes to the DHCP server (dnsmasq), which hands it to the device with its lease and registers it in DNS. Names only, never addresses; a device with its own static host in OPNsense keeps that entry. Takes effect at each device's next lease renewal."},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.names = map[string]string{}
	m.sources = map[string]nameSource{}
	m.macs = map[string]string{}
	m.ips = map[string][]string{}
	m.leases = map[string]Lease{}
	m.vendors = map[string]string{}
	m.static = map[string]string{}
	m.overr = map[string]string{}
	m.loadOUI()
	m.loadOverrides()
	ctx.Publish("identity", m)
	ctx.Publish("member_resolver", m)
	m.loadSeen()
	every := time.Duration(core.Int(ctx.Settings(), "refresh_seconds", 30)) * time.Second
	ctx.Every("refresh", every, m.refresh)
	ctx.Every("dhcp-names", time.Minute, m.syncDHCPNames, core.Delayed())
	dhcpDoc := core.Returns("Names sent to the DHCP server", map[string]any{"ok": true, "enabled": true, "server": "dnsmasq",
		"include": "/usr/local/etc/dnsmasq.conf.d/flowsight-names.conf", "hosts_file": "/usr/local/etc/flowsight/dnsmasq-names.hosts", "last_run": 1790500000, "error": "",
		"entries": []map[string]any{{"mac": "ca:51:71:75:2f:b9", "ip": "192.168.1.69", "name": "iPhone", "label": "iphone", "status": "sent"},
			{"mac": "bc:24:11:c2:5c:a4", "ip": "192.168.1.159", "name": "homeassistant", "label": "homeassistant", "status": "skipped", "why": "already named to the DHCP server by the OPNsense static host homeassistant"}}})
	ctx.Route("GET", "/api/identity/dhcp-names", m.apiDHCPNames,
		core.Doc("Device names FlowSight sends to the DHCP server, which devices were left to an existing static host, and the last sync"), dhcpDoc)
	ctx.Route("POST", "/api/identity/dhcp-names", m.apiDHCPNames, core.Write(),
		core.Doc("Send the device names to the DHCP server now instead of at the next minute"), dhcpDoc)
	ctx.Route("GET", "/api/identity/hosts", m.apiHosts,
		core.Query("hours", "integer", "Activity window in hours to consider as active (default 24)", false, 24),
		core.Query("all", "boolean", "Include inactive hosts that are no longer seen (default false)", false, false),
		core.Doc("List all known hosts with their names, MAC addresses, vendors and last activity time"),
		core.Returns("Hosts list", map[string]any{
			"hosts": []map[string]any{
				{"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:ff", "name": "MacBook", "vendor": "Apple", "last_activity": 1790376243},
			},
		}))
	ctx.Route("GET", "/api/identity/lookup", m.apiLookup,
		core.Query("ip", "string", "IP address to look up", true, "192.168.1.10"),
		core.Doc("Lookup details for a specific IP address including MAC, vendor and display name"),
		core.Returns("Host lookup details", map[string]any{
			"ip":     "192.168.1.10",
			"mac":    "aa:bb:cc:dd:ee:ff",
			"name":   "MacBook",
			"vendor": "Apple",
		}))
	ctx.Route("GET", "/api/identity/leases", m.apiLeases,
		core.Doc("List all current DHCP leases issued by the gateway DHCP server"),
		core.Returns("Active DHCP leases", map[string]any{
			"leases": []map[string]any{
				{"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "macbook", "expires": 1790376243},
			},
		}))
	ctx.Route("POST", "/api/identity/name", m.apiSetName, core.Write(),
		core.Doc("Assign or update a custom display name for a network device by IP address"),
		core.Body(
			core.Fld("ip", "string", true, "Device IP address", "192.168.1.10"),
			core.Fld("name", "string", true, "Display name to assign", "MacBook"),
		),
		core.Returns("Name assignment result", map[string]any{"ok": true}))
	ctx.Route("DELETE", "/api/identity/name/{ip}", m.apiDeleteNameByIP, core.Write(),
		core.PathParam("ip", "string", "Device IP address", "192.168.1.10"),
		core.Doc("Remove a custom name override and revert to automatic identification for a device"),
		core.Returns("Name deletion result", map[string]any{"ok": true}))
	ctx.Panel(core.Panel{ID: "hosts", Title: "IP Addresses", Group: "Inventory", Order: 20, Icon: "hosts"})
	ctx.Panel(core.Panel{ID: "host", Title: "IP address", Group: "Inventory", Order: 21, Detail: true})
	return nil
}

// ---------------------------------------------------------------- service

// NameInfo returns the name for an address along with its source and confidence.
// Sources in precedence order: override (1.0), dhcp_hostname (0.88), reservation (0.80),
// device_table (0.70), reverse_dns (0.20), none (0.0).
// This reads from m.sources which is populated during refresh, so no DB calls.
func (m *Module) NameInfo(ip string) struct {
	Name       string
	Source     string
	Confidence float64
} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Operator override has the highest confidence
	if n := m.overr[ip]; n != "" {
		return struct {
			Name       string
			Source     string
			Confidence float64
		}{Name: n, Source: "override", Confidence: 1.0}
	}

	// Loopback addresses
	if ip == "127.0.0.1" || ip == "::1" {
		return struct {
			Name       string
			Source     string
			Confidence float64
		}{Name: "this gateway (loopback)", Source: "loopback", Confidence: 1.0}
	}

	// Check sources map (populated during refresh)
	if src, ok := m.sources[ip]; ok {
		return struct {
			Name       string
			Source     string
			Confidence float64
		}{Name: src.name, Source: src.source, Confidence: src.confidence}
	}

	// Check if device holds this address (durable-by-MAC): report original source with "via device's other address"
	if mac := m.macs[ip]; mac != "" {
		if origName := m.macName[mac]; origName != "" {
			// Find the source from any address the device holds
			for otherIP := range m.names {
				if m.macs[otherIP] == mac {
					if src, ok := m.sources[otherIP]; ok && src.name != "" {
						// Report the source from the other address
						return struct {
							Name       string
							Source     string
							Confidence float64
						}{Name: origName, Source: src.source, Confidence: src.confidence}
					}
				}
			}
		}
	}

	// Check ever-known MAC (addresses that rotated out)
	if mac := m.everMAC[ip]; mac != "" {
		if origName := m.macName[mac]; origName != "" {
			// Similar to above but for rotated addresses
			return struct {
				Name       string
				Source     string
				Confidence float64
			}{Name: origName, Source: "device_table", Confidence: 0.70}
		}
	}

	return struct {
		Name       string
		Source     string
		Confidence float64
	}{Name: "", Source: "none", Confidence: 0.0}
}

func (m *Module) Name(ip string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if n := m.overr[ip]; n != "" {
		return n
	}
	if ip == "127.0.0.1" || ip == "::1" {
		return "this gateway (loopback)"
	}
	if n := m.names[ip]; n != "" {
		return n
	}
	// A device has one name whichever address it is using; an address that
	// has fallen out of the live tables still belongs to the device it did.
	if mac := m.macs[ip]; mac != "" {
		if n := m.macName[mac]; n != "" {
			return n
		}
	}
	if mac := m.everMAC[ip]; mac != "" {
		return m.macName[mac]
	}
	return ""
}

// NameOwner is the hardware address of the device whose lease, reservation
// or chosen name is this one (first label, case-insensitive), or "". Other
// modules ask before attaching a name they learned second-hand: a resolver
// or Pi-hole name that matches a device's own name belongs to that device,
// wherever the resolver's stale record points now.
func (m *Module) NameOwner(name string) string {
	label := strings.ToLower(strings.SplitN(strings.TrimSpace(name), ".", 2)[0])
	if label == "" {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for ip, n := range m.names {
		if strings.ToLower(strings.SplitN(n, ".", 2)[0]) == label {
			if mac := m.macs[ip]; mac != "" {
				return mac
			}
		}
	}
	for _, n := range m.overr {
		if strings.ToLower(strings.SplitN(n, ".", 2)[0]) == label {
			return "operator"
		}
	}
	return ""
}

// MAC is the hardware address behind an IP. The live tables answer first;
// failing that, whatever any module ever recorded in the hosts table. That
// second answer does not age: an IPv6 privacy address that belonged to a
// laptop a fortnight ago still belonged to it then, and the traffic it sent
// is that laptop's however long ago the address rotated away.
func (m *Module) MAC(ip string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if mac := m.macs[ip]; mac != "" {
		return mac
	}
	return m.everMAC[ip]
}

func (m *Module) Vendor(mac string) string {
	mac = strings.ToLower(mac)
	if len(mac) < 8 {
		return ""
	}
	if isRandomized(mac) {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if v := m.vendors[mac[:13]]; v != "" { // /36 blocks stored as aa:bb:cc:d
		return v
	}
	return m.vendors[mac[:8]]
}

func (m *Module) IsLocal(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	if p.IsLoopback() || p.IsLinkLocalUnicast() {
		return true
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, n := range m.nets {
		if n.Contains(p) {
			return true
		}
	}
	// Before the interface scan has run there is nothing to compare against;
	// RFC1918 is the best guess then. Once local networks are known, an
	// RFC1918 address outside them (a double-NAT WAN, an upstream router) is
	// not local.
	return len(m.nets) == 0 && p.IsPrivate()
}

func (m *Module) LocalNetworks() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string(nil), m.netStrs...)
}

// EffectiveSettings reports what empty settings resolve to on this platform.
func (m *Module) EffectiveSettings() map[string]any {
	var files []string
	for _, f := range m.ctx.Platform.DHCPLeases {
		if _, err := os.Stat(f); err == nil {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		files = append([]string(nil), m.ctx.Platform.DHCPLeases...)
	}
	nets := m.LocalNetworks()
	if len(nets) == 0 {
		nets = []string{"(none detected yet)"}
	}
	return map[string]any{"local_networks": nets, "extra_lease_files": files}
}

// remember records that a device was seen at an address, so the association
// outlives the neighbour entry (operating systems rotate temporary IPv6
// addresses; a device must not lose its policy or its name when they do).
func (m *Module) remember(mac, ip string) {
	mac = strings.ToLower(strings.TrimSpace(mac))
	ip = strings.TrimSpace(ip)
	if mac == "" || ip == "" || net.ParseIP(ip) == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seenAt == nil {
		m.seenAt = map[string]map[string]int64{}
	}
	if m.seenAt[mac] == nil {
		m.seenAt[mac] = map[string]int64{}
	}
	m.seenAt[mac][ip] = time.Now().Unix()
}

// rememberedIPs returns every device's addresses, dropping those not seen
// within the memory window.
// The address memory is written down, not just held.
//
// A device's addresses are learned from the neighbour table, which is a cache
// of who is reachable now, not a record of who has been here. IPv6 privacy
// addresses rotate, so an address seen an hour ago has usually aged out of it
// entirely. Keeping the association only in memory meant every restart threw
// away everything not currently reachable, and on this network that left 97
// of 237 IPv6 hosts with no device behind them at all, despite a setting
// promising to remember them for a day.
const seenKV = "identity.seen"

func (m *Module) loadSeen() {
	var stored map[string]map[string]int64
	if !m.ctx.Store.KVGet(seenKV, &stored) || stored == nil {
		return
	}
	cut := m.memoryCutoff()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seenAt == nil {
		m.seenAt = map[string]map[string]int64{}
	}
	for mac, ips := range stored {
		for ip, at := range ips {
			if at < cut {
				continue // older than the operator asked us to remember
			}
			if m.seenAt[mac] == nil {
				m.seenAt[mac] = map[string]int64{}
			}
			if at > m.seenAt[mac][ip] {
				m.seenAt[mac][ip] = at
			}
		}
	}
}

// saveSeen writes the memory back, pruned to the configured window so the
// record cannot grow without bound.
func (m *Module) saveSeen() {
	cut := m.memoryCutoff()
	m.mu.Lock()
	out := make(map[string]map[string]int64, len(m.seenAt))
	for mac, ips := range m.seenAt {
		keep := map[string]int64{}
		for ip, at := range ips {
			if at >= cut {
				keep[ip] = at
			}
		}
		if len(keep) > 0 {
			out[mac] = keep
		}
	}
	m.mu.Unlock()
	_ = m.ctx.Store.KVSet(seenKV, out)
}

// durable is the association nothing should forget: every address the hosts
// table has a hardware address for, and the best name known for each
// hardware address from any of its addresses. The memory window above says
// which addresses a device holds now; this says which device an address
// belonged to, which is a fact about the past and does not expire. Called
// with the module lock held.
//
// The live tables win over the hosts row for any address they hold: a DHCP
// address changes hands, and the row written when the last holder had it
// says nothing about the device that has it now. Addresses whose row names
// a different device than the live tables do are returned as moved, so the
// caller can clear the name the old holder left on them.
func (m *Module) durable(names, macs map[string]string) (everMAC, macName map[string]string, moved []string) {
	everMAC, macName = map[string]string{}, map[string]string{}
	if m.ctx == nil || m.ctx.Store == nil {
		return
	}
	rows, _ := m.ctx.Store.Rows(`SELECT ip, mac, name FROM hosts WHERE mac IS NOT NULL AND mac <> ''`)
	for _, r := range rows {
		ip, _ := r["ip"].(string)
		mac, _ := r["mac"].(string)
		name, _ := r["name"].(string)
		mac = strings.ToLower(strings.TrimSpace(mac))
		if ip == "" || mac == "" {
			continue
		}
		// The name on the row was the holder's at the time, so it still
		// says what that hardware address is called; the address itself
		// is only the device's when the live tables agree or are silent.
		if name != "" && macName[mac] == "" {
			macName[mac] = name
		}
		if live := macs[ip]; live != "" && live != mac {
			moved = append(moved, ip)
			continue
		}
		everMAC[ip] = mac
	}
	for ip, mac := range macs {
		if mac != "" {
			everMAC[ip] = mac
		}
	}
	// Names learned live (leases, reservations, the device table) outrank
	// whatever the hosts row happened to record; they are attached only to
	// the hardware address the live tables put behind the address.
	for ip, mac := range macs {
		if n := names[ip]; n != "" && mac != "" {
			macName[mac] = n
		}
	}
	return
}

func (m *Module) memoryCutoff() int64 {
	hours := core.Int(m.ctx.Settings(), "address_memory_hours", 24)
	if hours < 1 {
		hours = 1
	}
	return time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
}

func (m *Module) rememberedIPs() map[string][]string {
	hours := core.Int(m.ctx.Settings(), "address_memory_hours", 24)
	if hours < 1 {
		hours = 1
	}
	cut := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	out := map[string][]string{}
	m.mu.Lock()
	defer m.mu.Unlock()
	for mac, ips := range m.seenAt {
		for ip, at := range ips {
			if at < cut {
				delete(ips, ip)
				continue
			}
			out[mac] = append(out[mac], ip)
		}
		if len(ips) == 0 {
			delete(m.seenAt, mac)
			continue
		}
		sort.Slice(out[mac], func(i, j int) bool { return ips[out[mac][i]] < ips[out[mac][j]] })
	}
	return out
}

// Addresses implements core.AddressBook: every address of the device that
// holds ip. IPv4 and IPv6 are the same thing here.
func (m *Module) Addresses(ip string) []string {
	mac := m.MAC(ip)
	if mac == "" {
		return []string{ip}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := append([]string(nil), m.ips[mac]...)
	// Every address the device has ever been recorded with, current or not:
	// filtering by a device has to reach the traffic it sent from addresses
	// it no longer holds.
	for other, om := range m.everMAC {
		if om == mac && !contains(list, other) {
			list = append(list, other)
		}
	}
	if !contains(list, ip) {
		list = append(list, ip)
	}
	sort.Strings(list)
	return list
}

// Resolve implements core.MemberResolver for mac:, device: and all.
func (m *Module) Resolve(ref string) []string {
	switch {
	case ref == "all":
		return m.LocalNetworks()
	case strings.HasPrefix(ref, "mac:"):
		mac := strings.ToLower(ref[4:])
		m.mu.RLock()
		defer m.mu.RUnlock()
		var out []string
		for _, ip := range m.ips[mac] {
			out = append(out, cidr(ip))
		}
		return out
	case strings.HasPrefix(ref, "device:"):
		want := strings.ToLower(ref[7:])
		m.mu.RLock()
		var hit []string
		for ip, n := range m.names {
			if strings.ToLower(n) == want {
				hit = append(hit, ip)
			}
		}
		for ip, n := range m.overr {
			if strings.ToLower(n) == want {
				hit = append(hit, ip)
			}
		}
		m.mu.RUnlock()
		// One name means one device: take every address it holds, v4 and v6.
		seen := map[string]bool{}
		var out []string
		for _, ip := range hit {
			for _, a := range m.Addresses(ip) {
				if c := cidr(a); !seen[c] {
					seen[c] = true
					out = append(out, c)
				}
			}
		}
		sort.Strings(out)
		return out
	}
	return nil
}

func cidr(ip string) string {
	if strings.Contains(ip, ":") {
		return ip + "/128"
	}
	return ip + "/32"
}

func isRandomized(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	var b byte
	for _, c := range mac[:2] {
		b <<= 4
		switch {
		case c >= '0' && c <= '9':
			b |= byte(c - '0')
		case c >= 'a' && c <= 'f':
			b |= byte(c-'a') + 10
		}
	}
	return b&2 != 0
}

// ---------------------------------------------------------------- refresh

func (m *Module) refresh() error {
	leases := m.readLeases()
	arp := m.readNeighbours()
	static := m.readReservations()
	nets := m.localNets()

	names := map[string]string{}
	sources := map[string]nameSource{}
	macs := map[string]string{}
	// Everything seen now is remembered against its device; see seen().
	for ip, mac := range arp {
		m.remember(mac, ip)
	}
	for _, l := range leases {
		if l.IP != "" && l.MAC != "" {
			m.remember(l.MAC, l.IP)
		}
	}
	ips := m.rememberedIPs()
	for mac, list := range ips {
		for _, ip := range list {
			macs[ip] = mac
		}
	}
	// DHCP hostnames: highest priority after override
	for _, l := range leases {
		if l.IP != "" {
			macs[l.IP] = l.MAC
			if l.Hostname != "" && l.Hostname != "*" {
				names[l.IP] = l.Hostname
				sources[l.IP] = nameSource{name: l.Hostname, source: "dhcp_hostname", confidence: 0.88}
			}
		}
	}
	// Static reservations (from /etc/hosts or dnsmasq dhcp-host)
	for ip, n := range static {
		if _, hasSource := sources[ip]; !hasSource {
			names[ip] = n
			sources[ip] = nameSource{name: n, source: "reservation", confidence: 0.80}
		}
	}
	// Enrolment / device table contributions. A lease is authoritative for
	// the address it covers: a device that sent no hostname with its lease
	// has no name from DHCP, and the device table, which learned its name
	// from the hosts table in the first place, must not hand the old one
	// back and keep it alive. The device table names only addresses no
	// lease covers.
	leased := map[string]bool{}
	for _, l := range leases {
		if l.IP != "" {
			leased[l.IP] = true
		}
	}
	devName := map[string]string{}
	drows, _ := m.ctx.Store.Rows(`SELECT mac, ip, hostname, guest_name FROM devices WHERE ip IS NOT NULL`)
	for _, r := range drows {
		ip, _ := r["ip"].(string)
		mac, _ := r["mac"].(string)
		h, _ := r["hostname"].(string)
		g, _ := r["guest_name"].(string)
		if ip == "" {
			continue
		}
		if h != "" {
			devName[ip] = h
		} else if g != "" {
			devName[ip] = g
		}
		if _, ok := names[ip]; !ok && !leased[ip] {
			if h != "" {
				names[ip] = h
				sources[ip] = nameSource{name: h, source: "device_table", confidence: 0.70}
			} else if g != "" {
				names[ip] = g
				sources[ip] = nameSource{name: g, source: "device_table", confidence: 0.70}
			}
		}
		if mac != "" {
			if _, ok := macs[ip]; !ok {
				macs[ip] = strings.ToLower(mac)
			}
		}
	}
	// Resolver answers name the far end, and only the far end: a record in
	// the local resolver that still points a laptop's name at an address the
	// laptop gave up last week must not name whatever holds that address
	// now. Local addresses are named by leases, reservations and the device
	// table, or not at all.
	isLocal := func(ip string) bool {
		p := net.ParseIP(ip)
		if p == nil {
			return false
		}
		for _, n := range nets {
			if n.Contains(p) {
				return true
			}
		}
		return false
	}
	rows, _ := m.ctx.Store.Rows(`SELECT ip, name FROM dns_names WHERE ts > ? LIMIT 50000`,
		time.Now().Add(-24*time.Hour).Unix())
	for _, r := range rows {
		ip, _ := r["ip"].(string)
		n, _ := r["name"].(string)
		// A blocklist that answers 127.0.0.1 for a domain must not name the
		// loopback address after that domain; nor do link-local, multicast
		// or the unspecified address ever carry a resolver's name.
		if _, ok := names[ip]; !ok && ip != "" && n != "" && !isLocal(ip) && !core.IsSpecialIP(ip) {
			names[ip] = n
			sources[ip] = nameSource{name: n, source: "reverse_dns", confidence: 0.20}
		}
	}

	m.mu.Lock()
	// A device has one name, whatever address it is using: carry the name
	// learned on any of its addresses (DHCP, reservation) to all of them,
	// which is what makes IPv6 rows read like IPv4 ones.
	for _, list := range ips {
		name := ""
		var src nameSource
		for _, ip := range list {
			if n := static[ip]; n != "" {
				name = n
				src = sources[ip]
				break
			}
			if n := names[ip]; n != "" && name == "" {
				name = n
				src = sources[ip]
			}
		}
		if name == "" {
			continue
		}
		for _, ip := range list {
			if names[ip] == "" {
				names[ip] = name
				sources[ip] = src
			}
		}
	}
	m.names, m.sources, m.macs, m.ips, m.leases, m.static = names, sources, macs, ips, leases, static
	var moved []string
	m.everMAC, m.macName, moved = m.durable(names, macs)
	m.nets = nets
	m.netStrs = m.netStrs[:0]
	for _, n := range nets {
		m.netStrs = append(m.netStrs, n.String())
	}
	m.updated = time.Now()
	m.mu.Unlock()

	// An address that changed hands carries the old holder's name in the
	// hosts table until something overwrites it; nothing would, when the new
	// holder has no name of its own. Clear it, so the row says "unnamed"
	// rather than naming the wrong device.
	for _, ip := range moved {
		_ = m.ctx.Store.Exec(`UPDATE hosts SET name=NULL WHERE ip=?`, ip)
	}
	// A leased address nothing names now, whose hosts row still carries the
	// device table's name for it, is wearing an echo: the device table got
	// that name from the hosts table. Clear it so the echo stops.
	for ip := range leased {
		if names[ip] == "" && devName[ip] != "" {
			_ = m.ctx.Store.Exec(`UPDATE hosts SET name=NULL WHERE ip=? AND name=?`, ip, devName[ip])
			// The echo was carried to the device's other addresses too
			// (its IPv6 rows), from where the durable name memory would
			// hand it straight back.
			if mac := macs[ip]; mac != "" {
				_ = m.ctx.Store.Exec(`UPDATE hosts SET name=NULL WHERE lower(mac)=? AND name=?`, mac, devName[ip])
				m.mu.Lock()
				if m.macName[mac] == devName[ip] {
					delete(m.macName, mac)
				}
				m.mu.Unlock()
			}
		}
	}
	// Loopback and other special addresses never carry a name from anywhere.
	_ = m.ctx.Store.Exec(`UPDATE hosts SET name=NULL WHERE ip IN ('127.0.0.1','::1','0.0.0.0','::') AND name IS NOT NULL`)
	_ = m.ctx.Store.Exec(`DELETE FROM dns_names WHERE ip IN ('127.0.0.1','::1','0.0.0.0','::') OR ip LIKE 'fe80:%' OR ip LIKE '169.254.%'`)
	// Repair what an earlier release did: local addresses named after a
	// resolver answer. Where the row's name is exactly what the resolver
	// said for that address and nothing live names it, the name goes.
	if rows, err := m.ctx.Store.Rows(`SELECT h.ip AS ip FROM hosts h JOIN dns_names d ON d.ip = h.ip AND lower(d.name) = lower(h.name) WHERE h.is_local = 1 AND h.name IS NOT NULL AND h.name <> ''`); err == nil {
		for _, r := range rows {
			ip, _ := r["ip"].(string)
			if ip != "" && names[ip] == "" && m.IsLocal(ip) {
				_ = m.ctx.Store.Exec(`UPDATE hosts SET name=NULL WHERE ip=?`, ip)
			}
		}
	}
	// Fold identities into the hosts table so reports carry names.
	var ups []core.HostUpdate
	for ip, mac := range macs {
		if !m.IsLocal(ip) {
			continue
		}
		ups = append(ups, core.HostUpdate{IP: ip, MAC: mac, Name: names[ip], Vendor: m.Vendor(mac),
			Source: "identity", IsLocal: ptr(true)})
	}
	for ip, n := range names {
		if _, done := macs[ip]; done || !m.IsLocal(ip) {
			continue
		}
		ups = append(ups, core.HostUpdate{IP: ip, Name: n, Source: "identity", IsLocal: ptr(true)})
	}
	// Write the address memory down every cycle, so a restart does not throw
	// away every association not currently in the neighbour cache.
	m.saveSeen()
	return m.ctx.Store.UpsertHosts(ups)
}

func ptr(b bool) *bool { return &b }

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

var macRe = regexp.MustCompile(`(?i)^([0-9a-f]{1,2}:){5}[0-9a-f]{1,2}$`)

func normMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if !macRe.MatchString(s) {
		return ""
	}
	parts := strings.Split(s, ":")
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return strings.Join(parts, ":")
}

// readLeases parses dnsmasq, ISC dhcpd and Kea lease files, whichever exist.
func (m *Module) readLeases() map[string]Lease {
	out := map[string]Lease{}
	files := append([]string(nil), m.ctx.Platform.DHCPLeases...)
	files = append(files, core.Strs(m.ctx.Settings(), "extra_lease_files")...)
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		switch {
		case strings.Contains(f, "dnsmasq"):
			parseDnsmasq(fh, out)
		case strings.HasSuffix(f, ".csv"):
			parseKea(fh, out)
		default:
			parseISC(fh, out)
		}
		fh.Close()
	}
	return out
}

func parseDnsmasq(fh *os.File, out map[string]Lease) {
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) < 4 {
			continue
		}
		// IPv6 lines carry a DUID, not a MAC; keep IPv4 identity only.
		mac := normMAC(p[1])
		if mac == "" || strings.Contains(p[2], ":") {
			continue
		}
		var exp int64
		if v, err := parseInt(p[0]); err == nil {
			exp = v
		}
		name := p[3]
		if name == "*" {
			name = ""
		}
		out[mac] = Lease{MAC: mac, IP: p[2], Hostname: name, Expires: exp, Source: "dnsmasq"}
	}
}

func parseISC(fh *os.File, out map[string]Lease) {
	sc := bufio.NewScanner(fh)
	var cur Lease
	var active bool
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "lease "):
			cur = Lease{IP: strings.Fields(line)[1], Source: "isc"}
			active = true
		case strings.HasPrefix(line, "hardware ethernet "):
			cur.MAC = normMAC(strings.TrimSuffix(strings.Fields(line)[2], ";"))
		case strings.HasPrefix(line, "client-hostname "):
			cur.Hostname = strings.Trim(strings.TrimSuffix(strings.TrimPrefix(line, "client-hostname "), ";"), `"`)
		case strings.HasPrefix(line, "binding state "):
			active = strings.Contains(line, "active")
		case line == "}":
			if cur.MAC != "" && active {
				out[cur.MAC] = cur
			}
		}
	}
}

func parseKea(fh *os.File, out map[string]Lease) {
	r := csv.NewReader(fh)
	r.FieldsPerRecord = -1
	recs, err := r.ReadAll()
	if err != nil || len(recs) < 2 {
		return
	}
	idx := map[string]int{}
	for i, h := range recs[0] {
		idx[h] = i
	}
	for _, rec := range recs[1:] {
		get := func(k string) string {
			if i, ok := idx[k]; ok && i < len(rec) {
				return rec[i]
			}
			return ""
		}
		mac := normMAC(get("hwaddr"))
		if mac == "" || get("state") == "1" {
			continue
		}
		out[mac] = Lease{MAC: mac, IP: get("address"), Hostname: strings.TrimSuffix(get("hostname"), "."),
			Source: "kea"}
	}
}

func parseInt(s string) (int64, error) {
	var v int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, os.ErrInvalid
		}
		v = v*10 + int64(c-'0')
	}
	return v, nil
}

// readReservations picks names out of dnsmasq dhcp-host lines and /etc/hosts.
func (m *Module) readReservations() map[string]string {
	out := map[string]string{}
	dir := m.ctx.Platform.DnsmasqConfDir
	var files []string
	if m.ctx.Platform.Family == "freebsd" {
		files = append(files, "/usr/local/etc/dnsmasq.conf")
	} else {
		files = append(files, "/etc/dnsmasq.conf")
	}
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".conf") {
				files = append(files, dir+"/"+e.Name())
			}
		}
	}
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if !strings.HasPrefix(line, "dhcp-host=") {
				continue
			}
			parts := strings.Split(strings.TrimPrefix(line, "dhcp-host="), ",")
			var ip, name string
			for _, p := range parts {
				p = strings.TrimSpace(p)
				switch {
				case net.ParseIP(p) != nil:
					ip = p
				case strings.HasPrefix(p, "set:"), strings.HasPrefix(p, "id:"), normMAC(p) != "",
					strings.HasSuffix(p, "h"), strings.HasSuffix(p, "m"), p == "infinite", p == "ignore":
				default:
					if name == "" && !strings.Contains(p, ":") {
						name = p
					}
				}
			}
			if ip != "" && name != "" {
				out[ip] = name
			}
		}
		fh.Close()
	}
	if fh, err := os.Open("/etc/hosts"); err == nil {
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || line[0] == '#' {
				continue
			}
			p := strings.Fields(line)
			if len(p) >= 2 && net.ParseIP(p[0]) != nil && !net.ParseIP(p[0]).IsLoopback() {
				if _, ok := out[p[0]]; !ok {
					out[p[0]] = p[1]
				}
			}
		}
		fh.Close()
	}
	return out
}

// localNets returns the configured local networks, or the firewall's own
// interface networks.
func (m *Module) localNets() []*net.IPNet {
	var out []*net.IPNet
	for _, s := range core.Strs(m.ctx.Settings(), "local_networks") {
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
		}
	}
	if len(out) > 0 {
		return dedupeNets(out)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	wan := defaultRouteInterface()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 || ifc.Name == wan {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok || n.IP.IsLinkLocalUnicast() {
				continue
			}
			ones, bits := n.Mask.Size()
			// A /32 or a public /64 on WAN is not a LAN. Keep RFC1918/ULA and
			// anything with a real prefix on IPv4.
			if n.IP.To4() != nil {
				if ones >= 31 || !n.IP.IsPrivate() {
					continue
				}
			} else if !n.IP.IsPrivate() && ones == bits {
				continue
			}
			nn := &net.IPNet{IP: n.IP.Mask(n.Mask), Mask: n.Mask}
			out = append(out, nn)
		}
	}
	return dedupeNets(out)
}

// dedupeNets drops repeats (an alias address, a second interface on the
// same subnet) while keeping the first occurrence's order.
func dedupeNets(in []*net.IPNet) []*net.IPNet {
	seen := map[string]bool{}
	out := in[:0]
	for _, n := range in {
		k := n.String()
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, n)
	}
	return out
}

// defaultRouteInterface names the interface carrying the default route: the
// WAN, whose network is never "local" even when it happens to be RFC1918.
func defaultRouteInterface() string {
	if out, err := core.Run(5*time.Second, "/sbin/route", "-n", "get", "default"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			if f := strings.Fields(line); len(f) == 2 && f[0] == "interface:" {
				return f[1]
			}
		}
	}
	if out, err := core.Run(5*time.Second, "ip", "-4", "route", "show", "default"); err == nil {
		f := strings.Fields(out)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "dev" {
				return f[i+1]
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------- OUI

// loadOUI reads the vendor registry shipped with the package (share dir) or
// the operating system's copy. Format: "aa:bb:cc<TAB>Vendor" or manuf style.
func (m *Module) loadOUI() {
	cands := []string{
		m.ctx.Platform.ShareDir + "/oui.txt",
		"/usr/local/share/flowsight/oui.txt",
		"/usr/share/flowsight/oui.txt",
		"/usr/local/share/ntopng/httpdocs/other/EtherOUI.txt",
		"/usr/share/ieee-data/oui.txt",
		"/usr/share/misc/oui.txt",
		"/usr/local/share/wireshark/manuf",
		"/usr/share/wireshark/manuf",
	}
	vend := map[string]string{}
	for _, f := range cands {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<16), 1<<20)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || line[0] == '#' {
				continue
			}
			// ieee oui.txt: "00-00-0C   (hex)\t\tCisco Systems, Inc"
			if strings.Contains(line, "(hex)") {
				p := strings.SplitN(line, "(hex)", 2)
				pre := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p[0]), "-", ":"))
				vend[pre] = strings.TrimSpace(p[1])
				continue
			}
			fields := strings.Split(line, "\t")
			if len(fields) < 2 {
				fields = strings.Fields(line)
			}
			if len(fields) < 2 {
				continue
			}
			pre := strings.ToLower(strings.TrimSpace(fields[0]))
			name := strings.TrimSpace(fields[len(fields)-1])
			if len(fields) >= 3 && strings.TrimSpace(fields[2]) != "" {
				name = strings.TrimSpace(fields[2]) // manuf long name
			}
			if i := strings.Index(pre, "/"); i > 0 {
				pre = pre[:i]
			}
			pre = strings.ReplaceAll(pre, "-", ":")
			if len(pre) >= 8 {
				if len(pre) > 13 {
					pre = pre[:13]
				} else if len(pre) > 8 {
					pre = pre[:8]
				}
				vend[pre] = name
			}
		}
		fh.Close()
		if len(vend) > 1000 {
			break
		}
	}
	m.mu.Lock()
	m.vendors = vend
	m.mu.Unlock()
	if len(vend) == 0 {
		m.ctx.Log.Warn("no OUI registry found; vendor names will be empty")
	}
}

func (m *Module) loadOverrides() {
	var o map[string]string
	if m.ctx.Store.KVGet("identity.names", &o) && o != nil {
		m.mu.Lock()
		m.overr = o
		m.mu.Unlock()
	}
}

// readNeighbours reads the ARP and NDP tables through the OS tools. On
// FreeBSD that is arp(8)/ndp(8); on Linux ip(8).
func (m *Module) readNeighbours() map[string]string {
	out := map[string]string{}
	if m.ctx.Platform.Family == "freebsd" {
		if s, err := core.Run(10*time.Second, "/usr/sbin/arp", "-an"); err == nil {
			for _, line := range strings.Split(s, "\n") {
				// ? (192.168.1.5) at 00:11:22:33:44:55 on vtnet0 expires in 1180 seconds [ethernet]
				f := strings.Fields(line)
				if len(f) >= 4 && f[2] == "at" {
					ip := strings.Trim(f[1], "()")
					if mac := normMAC(f[3]); mac != "" {
						out[ip] = mac
					}
				}
			}
		}
		if s, err := core.Run(10*time.Second, "/usr/sbin/ndp", "-an"); err == nil {
			for _, line := range strings.Split(s, "\n") {
				f := strings.Fields(line)
				if len(f) >= 2 && strings.Contains(f[0], ":") {
					if mac := normMAC(f[1]); mac != "" {
						ip := f[0]
						if i := strings.Index(ip, "%"); i > 0 {
							ip = ip[:i]
						}
						if !strings.HasPrefix(ip, "fe80") {
							out[ip] = mac
						}
					}
				}
			}
		}
		return out
	}
	if s, err := core.Run(10*time.Second, "ip", "-4", "neigh"); err == nil {
		for _, line := range strings.Split(s, "\n") {
			f := strings.Fields(line)
			for i := 0; i+1 < len(f); i++ {
				if f[i] == "lladdr" {
					if mac := normMAC(f[i+1]); mac != "" {
						out[f[0]] = mac
					}
				}
			}
		}
	}
	if s, err := core.Run(10*time.Second, "ip", "-6", "neigh"); err == nil {
		for _, line := range strings.Split(s, "\n") {
			f := strings.Fields(line)
			if len(f) > 0 && strings.HasPrefix(f[0], "fe80") {
				continue
			}
			for i := 0; i+1 < len(f); i++ {
				if f[i] == "lladdr" {
					if mac := normMAC(f[i+1]); mac != "" {
						out[f[0]] = mac
					}
				}
			}
		}
	}
	return out
}

// ---------------------------------------------------------------- API

func (m *Module) apiHosts(r *core.Req) (any, error) {
	since := r.Since(24)
	q := `SELECT h.*, COALESCE(d.zone, h.zone) AS zone FROM hosts h LEFT JOIN devices d ON d.mac = h.mac
		WHERE h.is_local=1`
	args := []any{}
	if r.Q("all", "") == "" {
		q += ` AND h.last_seen >= ?`
		args = append(args, since)
	}
	q += ` ORDER BY h.bytes_in + h.bytes_out DESC LIMIT 2000`
	rows, err := m.ctx.Store.Rows(q, args...)
	if err != nil {
		return nil, err
	}
	m.mu.RLock()
	for _, row := range rows {
		ip, _ := row["ip"].(string)
		info := m.NameInfo(ip)
		if n := m.overr[ip]; n != "" {
			row["name"] = n
		} else if n := m.names[ip]; n != "" && row["name"] == nil {
			row["name"] = n
		}
		// Add provenance information for names
		row["name_source"] = info.Source
		row["name_confidence"] = int(info.Confidence * 100) // Convert to 0-100 scale
		if mac, _ := row["mac"].(string); mac != "" {
			row["vendor"] = m.Vendor(mac)
			row["randomized"] = isRandomized(mac)
		}
	}
	m.mu.RUnlock()
	return map[string]any{"hosts": rows, "updated": m.updated.Unix()}, nil
}

func (m *Module) apiLookup(r *core.Req) (any, error) {
	ip := r.Q("ip", "")
	if net.ParseIP(ip) == nil {
		return nil, core.BadRequest("ip must be an address")
	}
	mac := m.MAC(ip)
	info := m.NameInfo(ip)
	return map[string]any{"ip": ip, "name": m.Name(ip), "mac": mac, "vendor": m.Vendor(mac),
		"local": m.IsLocal(ip), "randomized": isRandomized(mac),
		"name_source": info.Source, "name_confidence": int(info.Confidence * 100)}, nil
}

func (m *Module) apiLeases(r *core.Req) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []map[string]any
	for _, l := range m.leases {
		out = append(out, map[string]any{"mac": l.MAC, "ip": l.IP, "hostname": l.Hostname,
			"expires": l.Expires, "source": l.Source, "vendor": m.Vendor(l.MAC)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["ip"].(string) < out[j]["ip"].(string) })
	return map[string]any{"leases": out}, nil
}

var nameOK = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._'-]{0,63}$`)

func (m *Module) apiSetName(r *core.Req) (any, error) {
	var in struct {
		IP   string `json:"ip"`
		Name string `json:"name"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	if net.ParseIP(in.IP) == nil {
		return nil, core.BadRequest("ip must be an address")
	}
	if in.Name != "" && !nameOK.MatchString(in.Name) {
		return nil, core.BadRequest("name may contain letters, digits, space, dot, dash and underscore")
	}
	m.mu.Lock()
	if in.Name == "" {
		delete(m.overr, in.IP)
	} else {
		m.overr[in.IP] = in.Name
	}
	snapshot := map[string]string{}
	for k, v := range m.overr {
		snapshot[k] = v
	}
	m.mu.Unlock()
	if err := m.ctx.Store.KVSet("identity.names", snapshot); err != nil {
		return nil, err
	}
	_ = m.ctx.Store.UpsertHosts([]core.HostUpdate{{IP: in.IP, Name: in.Name, Source: "operator"}})
	go func() { _ = m.syncDHCPNames() }()
	return map[string]any{"ok": true}, nil
}
