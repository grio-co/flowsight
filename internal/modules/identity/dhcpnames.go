package identity

// Device names up through the DHCP server.
//
// A name given in FlowSight lives in FlowSight. With dhcp_names on, it also
// goes to the DHCP server, so the server hands that name to the device with
// its lease, lists the lease under it, and registers it in DNS the way it
// registers the names devices give themselves. On dnsmasq (OPNsense's
// Dnsmasq DNS & DHCP) FlowSight keeps its own host file of "MAC,name" lines,
// named by one dhcp-hostsfile line in its own include; dnsmasq re-reads the
// host file on SIGHUP, so a rename needs no restart and interrupts nothing.
// These lines give a name only, never an address.
//
// A device the operator already describes to the DHCP server (a static host
// in OPNsense, or a reservation FlowSight's placement writes) is left to that
// entry: two host lines for one MAC is a conflict the server resolves by
// order, and the operator's own entry must win.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

const (
	dhcpIncludeName = "flowsight-names.conf"
	dhcpHostsName   = "dnsmasq-names.hosts"
)

type dhcpEntry struct {
	MAC    string `json:"mac"`
	IP     string `json:"ip"`
	Name   string `json:"name"`
	Label  string `json:"label"`
	Status string `json:"status"` // sent, skipped
	Why    string `json:"why,omitempty"`
}

var (
	dhcpMu      sync.Mutex
	dhcpLast    []dhcpEntry
	dhcpLastRun time.Time
	dhcpLastErr string
	dhcpWritten string
)

// dnsLabel turns a display name into a host label: "Kitchen iPad (2)" ->
// "kitchen-ipad-2".
func dnsLabel(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
		} else if b.Len() > 0 && !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > 63 {
		s = strings.Trim(s[:63], "-")
	}
	return s
}

func (m *Module) dhcpPaths() (include, hosts string, ok bool) {
	pl := m.ctx.Platform
	if pl.DnsmasqConfDir == "" || pl.EtcDir == "" {
		return "", "", false
	}
	return filepath.Join(pl.DnsmasqConfDir, dhcpIncludeName), filepath.Join(pl.EtcDir, dhcpHostsName), true
}

func dnsmasqBinary() string {
	for _, p := range []string{"/usr/local/sbin/dnsmasq", "/usr/sbin/dnsmasq"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func dnsmasqMainConf() string {
	for _, p := range []string{"/usr/local/etc/dnsmasq.conf", "/etc/dnsmasq.conf"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

var (
	xmlHostRe  = regexp.MustCompile(`(?s)<hosts\b[^>]*>(.*?)</hosts>`)
	xmlHwRe    = regexp.MustCompile(`<hwaddr>([^<]*)</hwaddr>`)
	xmlHostnRe = regexp.MustCompile(`<host>([^<]*)</host>`)
	dhcpMACRe  = regexp.MustCompile(`(?i)([0-9a-f]{2}(:[0-9a-f]{2}){5})`)
)

// operatorHosts is every MAC the operator (or FlowSight's own placement)
// already describes to dnsmasq, with the name given there.
func (m *Module) operatorHosts() map[string]string {
	out := map[string]string{}
	if x := m.ctx.Platform.ConfigXML; x != "" {
		if b, err := os.ReadFile(x); err == nil {
			s := string(b)
			if i := strings.Index(s, "<dnsmasq>"); i >= 0 {
				if j := strings.Index(s[i:], "</dnsmasq>"); j > 0 {
					for _, h := range xmlHostRe.FindAllStringSubmatch(s[i:i+j], -1) {
						hw := xmlHwRe.FindStringSubmatch(h[1])
						name := xmlHostnRe.FindStringSubmatch(h[1])
						if hw != nil {
							for _, mac := range dhcpMACRe.FindAllString(hw[1], -1) {
								n := "a static host in OPNsense"
								if name != nil && name[1] != "" {
									n = "the OPNsense static host " + name[1]
								}
								out[strings.ToLower(mac)] = n
							}
						}
					}
				}
			}
		}
	}
	if dir := m.ctx.Platform.DnsmasqConfDir; dir != "" {
		if b, err := os.ReadFile(filepath.Join(dir, "flowsight-enroll.conf")); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "dhcp-host=") {
					if mac := dhcpMACRe.FindString(line); mac != "" {
						out[strings.ToLower(mac)] = "the reservation FlowSight's device placement writes"
					}
				}
			}
		}
	}
	return out
}

// dhcpWanted is what the host file should say: one line per named device.
func (m *Module) dhcpWanted() ([]dhcpEntry, string) {
	m.mu.RLock()
	overr := map[string]string{}
	for ip, n := range m.overr {
		overr[ip] = n
	}
	m.mu.RUnlock()
	// The DNS label a device already has, so DHCP and DNS say the same.
	var dnsRecs []struct {
		Label string `json:"label"`
		MAC   string `json:"mac"`
	}
	m.ctx.Store.KVGet("dns.local_names", &dnsRecs)
	dnsLabelOf := map[string]string{}
	for _, r := range dnsRecs {
		if r.MAC != "" {
			dnsLabelOf[strings.ToLower(r.MAC)] = r.Label
		}
	}
	taken := m.operatorHosts()
	// One entry per device: prefer its IPv4 address's name.
	byMAC := map[string]dhcpEntry{}
	ips := make([]string, 0, len(overr))
	for ip := range overr {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		a6, b6 := strings.Contains(ips[i], ":"), strings.Contains(ips[j], ":")
		if a6 != b6 {
			return !a6 // IPv4 first
		}
		return ips[i] < ips[j]
	})
	var out []dhcpEntry
	for _, ip := range ips {
		name := overr[ip]
		mac := strings.ToLower(m.MAC(ip))
		e := dhcpEntry{MAC: mac, IP: ip, Name: name}
		if mac == "" {
			e.Status, e.Why = "skipped", "no hardware address is known for "+ip
			out = append(out, e)
			continue
		}
		if _, seen := byMAC[mac]; seen {
			continue
		}
		e.Label = dnsLabelOf[mac]
		if e.Label == "" {
			e.Label = dnsLabel(name)
		}
		switch {
		case e.Label == "":
			e.Status, e.Why = "skipped", "the name has no letters or digits to make a host name from"
		case taken[mac] != "":
			e.Status, e.Why = "skipped", "already named to the DHCP server by "+taken[mac]
		default:
			e.Status = "sent"
		}
		byMAC[mac] = e
	}
	// Two devices given the same name would register one host name twice;
	// the later one gets its hardware address's end appended.
	used := map[string]string{}
	macs := make([]string, 0, len(byMAC))
	for mac := range byMAC {
		macs = append(macs, mac)
	}
	sort.Strings(macs)
	var b strings.Builder
	b.WriteString("# Generated by flowsight: device names given in FlowSight, one \"MAC,name\" per line. Edit the names in FlowSight.\n")
	for _, mac := range macs {
		e := byMAC[mac]
		if e.Status == "sent" {
			if other, dup := used[e.Label]; dup && other != mac {
				e.Label = e.Label + "-" + strings.ReplaceAll(mac[len(mac)-5:], ":", "")
			}
			used[e.Label] = mac
			fmt.Fprintf(&b, "%s,%s\n", mac, e.Label)
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, b.String()
}

// syncDHCPNames brings the DHCP server's view of names in line with
// FlowSight's. It is cheap when nothing changed.
func (m *Module) syncDHCPNames() error {
	dhcpMu.Lock()
	defer dhcpMu.Unlock()
	include, hosts, ok := m.dhcpPaths()
	on := core.Bool(m.ctx.Settings(), "dhcp_names", true)
	setErr := func(err error) error {
		dhcpLastErr = ""
		if err != nil {
			dhcpLastErr = err.Error()
		}
		dhcpLastRun = time.Now()
		return err
	}
	if !ok || dnsmasqBinary() == "" {
		dhcpLast = nil
		return setErr(nil) // no dnsmasq here: nothing to tell
	}
	entries, text := m.dhcpWanted()
	if !on {
		entries, text = nil, "# FlowSight: sending device names to the DHCP server is off (Settings › identity).\n"
	}
	dhcpLast = entries
	incText := "# Generated by flowsight: device names from FlowSight (Settings › identity › Send device names to the DHCP server).\n" +
		"dhcp-hostsfile=" + hosts + "\n"
	curInc, _ := os.ReadFile(include)
	curHosts, _ := os.ReadFile(hosts)
	needRestart := string(curInc) != incText
	if !needRestart && string(curHosts) == text {
		return setErr(nil)
	}
	if !on && len(curInc) == 0 {
		return setErr(nil) // never set up: nothing to undo
	}
	if err := os.MkdirAll(filepath.Dir(hosts), 0o755); err != nil {
		return setErr(err)
	}
	if err := writeAtomic(hosts, text); err != nil {
		return setErr(err)
	}
	if needRestart {
		if err := writeAtomic(include, incText); err != nil {
			return setErr(err)
		}
	}
	// The whole server configuration must still parse; if not, put back
	// what was there and say why.
	if conf := dnsmasqMainConf(); conf != "" {
		if out, err := core.Run(20*time.Second, dnsmasqBinary(), "--test", "-C", conf); err != nil {
			_ = restoreFile(hosts, curHosts)
			_ = restoreFile(include, curInc)
			return setErr(fmt.Errorf("dnsmasq rejected the names, reverted: %s", strings.TrimSpace(out)))
		}
	}
	if needRestart {
		// The dhcp-hostsfile line is read at start only.
		if out, err := m.ctx.Platform.Service("dnsmasq", "restart"); err != nil {
			return setErr(fmt.Errorf("dnsmasq restart failed: %v %s", err, strings.TrimSpace(out)))
		}
	} else if err := hupDnsmasq(); err != nil {
		return setErr(err)
	}
	sent := 0
	for _, e := range entries {
		if e.Status == "sent" {
			sent++
		}
	}
	if dhcpWritten != text {
		verb := "updated"
		if !on {
			verb = "cleared (switched off)"
		}
		_ = m.ctx.Store.RecordChange("identity", "dhcp-names", "flowsightd", "", "", "", fmt.Sprintf("DHCP server device names %s: %d devices", verb, sent))
	}
	dhcpWritten = text
	return setErr(nil)
}

func writeAtomic(path, text string) error {
	if err := os.WriteFile(path+".tmp", []byte(text), 0o644); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func restoreFile(path string, old []byte) error {
	if old == nil {
		return os.Remove(path)
	}
	return os.WriteFile(path, old, 0o644)
}

// hupDnsmasq makes dnsmasq re-read its host files without restarting.
func hupDnsmasq() error {
	for _, p := range []string{"/var/run/dnsmasq.pid", "/run/dnsmasq/dnsmasq.pid", "/var/run/dnsmasq/dnsmasq.pid"} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil || pid <= 1 {
			continue
		}
		return syscall.Kill(pid, syscall.SIGHUP)
	}
	return fmt.Errorf("dnsmasq is not running (no pid file)")
}

func (m *Module) apiDHCPNames(r *core.Req) (any, error) {
	if r.Method == "POST" {
		if err := m.syncDHCPNames(); err != nil {
			return map[string]any{"ok": false, "error": err.Error()}, nil
		}
	}
	dhcpMu.Lock()
	defer dhcpMu.Unlock()
	include, hosts, _ := m.dhcpPaths()
	last := int64(0)
	if !dhcpLastRun.IsZero() {
		last = dhcpLastRun.Unix()
	}
	server := "dnsmasq"
	if dnsmasqBinary() == "" {
		server = ""
	}
	return map[string]any{"ok": dhcpLastErr == "", "enabled": core.Bool(m.ctx.Settings(), "dhcp_names", true), "server": server,
		"include": include, "hosts_file": hosts, "entries": dhcpLast, "last_run": last, "error": dhcpLastErr}, nil
}

// DHCPName says what the DHCP server is told about a device, for the pages.
func (m *Module) DHCPName(mac string) (label, status, why string) {
	dhcpMu.Lock()
	defer dhcpMu.Unlock()
	mac = strings.ToLower(mac)
	for _, e := range dhcpLast {
		if e.MAC == mac {
			return e.Label, e.Status, e.Why
		}
	}
	return "", "", ""
}
