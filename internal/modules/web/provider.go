package web

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// provider renders the proxy configuration and the interception rules from
// the policy document. web.block terminates denied names at the ClientHello
// and serves the block page for plain HTTP; tls.inspect bumps selected
// clients with the FlowSight CA when the tls module has one.
type provider struct {
	m *Module
}

func (p *provider) Name() string { return "squid" }

func (p *provider) Capabilities() []string {
	caps := []string{core.CapWebBlock}
	if ca, ok := p.m.ctx.Service("ca").(CAProvider); ok && ca.SquidCertPath() != "" {
		caps = append(caps, core.CapTLSInspect)
	}
	return caps
}

var idRe = regexp.MustCompile(`[^a-z0-9_]+`)

func (p *provider) Compile(doc *core.PolicyDoc) (core.Artifact, error) {
	m := p.m
	s := m.ctx.Settings()
	res, _ := m.ctx.Service("member_resolver").(core.MemberResolver)
	now := time.Now()
	excluded := doc.ExcludedCIDRs(res)
	excluded = m.alsoOtherFamily(excluded)
	exclSet := map[string]bool{}
	for _, e := range excluded {
		exclSet[e] = true
	}
	var pols []squidPolicy
	for i := range doc.Policies {
		pol := &doc.Policies[i]
		if !pol.Enabled || !doc.Active(pol.Schedule, now) {
			continue
		}
		wantsWeb, wantsTLS := false, false
		for _, r := range pol.Requirements() {
			if r == core.CapWebBlock {
				wantsWeb = true
			}
			if r == core.CapTLSInspect {
				wantsTLS = true
			}
		}
		if !wantsWeb && !wantsTLS {
			continue
		}
		var members []string
		for _, mm := range doc.Members(pol, res) {
			if !exclSet[mm] {
				members = append(members, mm)
			}
		}
		if len(members) == 0 {
			continue
		}
		sp := squidPolicy{ID: idRe.ReplaceAllString(strings.ToLower(pol.Name), "_"), Members: members,
			Monitor: pol.Action == "monitor", Inspect: pol.TLS.Inspect, Bypass: pol.TLS.Bypass}
		if sp.Inspect {
			// Names whose clients pin their certificate cannot be decrypted by
			// anyone; relaying them keeps those sites working.
			sp.Bypass = append(append([]string(nil), sp.Bypass...), m.pinnedNames()...)
		}
		if wantsWeb {
			set := map[string]bool{}
			for _, d := range pol.Deny.Domains {
				set[d] = true
			}
			for _, c := range pol.Deny.Categories {
				if m.cats == nil {
					return core.Artifact{}, fmt.Errorf("policy %q uses category %q but the categories module is not loaded", pol.Name, c)
				}
				list, err := m.cats.Domains(c)
				if err != nil {
					return core.Artifact{}, fmt.Errorf("policy %q: %v", pol.Name, err)
				}
				for _, d := range list {
					set[d] = true
				}
			}
			for _, d := range pol.Allow.Domains {
				delete(set, d)
			}
			for _, d := range doc.Exclusions.Domains {
				delete(set, d)
			}
			for _, t := range pol.Deny.TLDs {
				set[t] = true // ".zip" in a dstdomain file matches every name under the TLD
			}
			for d := range set {
				sp.Domains = append(sp.Domains, d)
			}
			sort.Strings(sp.Domains)
			sp.Allow = append([]string(nil), pol.Allow.Domains...)
		}
		pols = append(pols, sp)
	}
	sort.Slice(pols, func(i, j int) bool { return pols[i].ID < pols[j].ID })

	nets := core.Strs(s, "networks")
	if len(nets) == 0 && m.identity != nil {
		nets = m.identity.LocalNetworks()
	}
	var v4nets []string
	for _, n := range nets {
		if !strings.Contains(n, ":") {
			v4nets = append(v4nets, n)
		}
	}
	caPath := ""
	if ca, ok := m.ctx.Service("ca").(CAProvider); ok {
		caPath = ca.SquidCertPath()
	}
	var dns []string
	if m.ctx.Platform.IsOPNsense() || m.ctx.Platform.Family == "freebsd" {
		dns = []string{"127.0.0.1"}
	}
	params := squidParams{
		HTTPPort: core.Int(s, "http_port", 3128), HTTPSPort: core.Int(s, "https_port", 3129),
		Dir: m.dir, LogDir: m.logDir, RunDir: m.runDir, User: m.squidUser(),
		Group:     pfGroup(m.ctx.Platform),
		LocalNets: nets, CAPath: caPath, CertDB: filepath.Join(m.ctx.Platform.DataDir, "ssl_db"),
		CertgenBin: m.certgenBin(), BlockPageURL: firstNonEmpty(doc.Options.BlockPageURL, m.blockPageURL()),
		PeekServerCert: core.Bool(s, "peek_server_cert", false), Policies: pols, Exclusions: excluded,
		ExclDomains: doc.Exclusions.Domains, DNSServers: dns, Workers: core.Int(s, "workers", 1),
		V6Listener: v6Listener(s),
	}
	// Stateful Packet Inspection, when the module is up and licensed, takes decrypted
	// requests from here.
	if deep, ok := p.m.ctx.Service("mitm").(interface {
		Peer() (int, int, []string, []string, bool)
		InspectEverything() bool
	}); ok {
		if port, preview, clients, names, on := deep.Peer(); on {
			params.DeepPort, params.DeepPreview = port, preview
			params.DeepClients, params.DeepNames = clients, names
			if deep.InspectEverything() && params.CAPath != "" {
				// Decrypt every intercepted client, not only those a policy
				// names. This widens who is inspected; it must not narrow what
				// is protected. A name the operator put on a policy's bypass
				// list is one they have said must never be decrypted, and they
				// did not mean "only on that device": a bank, a password
				// manager or a health service is not something to start
				// decrypting for the tablet because it was only ever named on
				// the laptop's policy. So every bypass list in the document is
				// honoured here, along with the exclusions and the names found
				// to pin.
				all := squidPolicy{ID: "deep_all", Members: params.LocalNets, Inspect: true, Monitor: true}
				seen := map[string]bool{}
				add := func(names []string) {
					for _, n := range names {
						n = strings.ToLower(strings.TrimSpace(n))
						if n == "" || seen[n] {
							continue
						}
						seen[n] = true
						all.Bypass = append(all.Bypass, n)
					}
				}
				add(doc.Exclusions.Domains)
				for i := range doc.Policies {
					add(doc.Policies[i].TLS.Bypass)
				}
				add(m.pinnedNames())
				params.Policies = append(params.Policies, all)
			}
		}
	}
	var spec core.RedirectSpec
	if m.rdr != nil {
		spec = redirectSpec(core.Strs(s, "interfaces"), v4nets, excluded, params.HTTPPort, params.HTTPSPort, params.V6Listener)
		params.Arrivals = m.rdr.Arrivals(spec)
		m.setSpec(spec)
	}
	_, files := params.render()
	out := map[string]string{}
	for name, text := range files {
		out[filepath.Join(m.dir, name)] = text
	}
	rdr := ""
	if m.wanted() && m.rdr != nil {
		rdr = m.rdr.RenderRedirects(spec)
	}
	out[m.redirectPath()] = rdr
	note := fmt.Sprintf("%d web polic(ies)", len(pols))
	if !m.wanted() {
		note += ", interception off"
	}
	return core.Artifact{Files: out, Note: note}, nil
}

// v6Listener returns the configured IPv6 listener address when it is a valid,
// non-loopback IPv6 address the firewall actually holds; anything else is
// ignored so a typo cannot blackhole IPv6 web traffic.
func v6Listener(s map[string]any) string {
	v := strings.TrimSpace(core.Str(s, "ipv6_listener", ""))
	if v == "" {
		return ""
	}
	ip := net.ParseIP(v)
	if ip == nil || ip.To4() != nil || ip.IsLoopback() {
		return ""
	}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return ip.String()
		}
	}
	return ""
}

// pfGroup returns the group that may open /dev/pf, when one is set up.
func pfGroup(p *core.Platform) string {
	if p.Family != "freebsd" {
		return ""
	}
	if st, err := os.Stat("/dev/pf"); err == nil {
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			if g, err := user.LookupGroupId(fmt.Sprint(sys.Gid)); err == nil && g.Name != "wheel" && g.Name != "root" {
				return g.Name
			}
		}
	}
	return ""
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (p *provider) Current() (core.Artifact, error) {
	files := map[string]string{}
	entries, _ := os.ReadDir(p.m.dir)
	for _, e := range entries {
		n := e.Name()
		if n == "placeholder.pem" || strings.HasSuffix(n, ".tmp") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(p.m.dir, n))
		if err == nil {
			files[filepath.Join(p.m.dir, n)] = string(b)
		}
	}
	if _, ok := files[p.m.redirectPath()]; !ok {
		files[p.m.redirectPath()] = ""
	}
	return core.Artifact{Files: files}, nil
}

// Apply writes the files, asks squid to parse them, reloads (or starts) it,
// then loads the interception rules last: traffic is never redirected to a
// proxy that has not accepted its configuration. On failure the previous
// files are restored.
func (p *provider) Apply(a core.Artifact) (string, error) {
	m := p.m
	cur, _ := p.Current()
	restore := func() {
		for path, text := range cur.Files {
			if text == "" {
				_ = os.Remove(path)
				continue
			}
			_ = os.WriteFile(path, []byte(text), 0o644)
		}
	}
	for path, text := range a.Files {
		if strings.TrimSpace(text) == "" && filepath.Base(path) != "squid.conf" {
			_ = os.Remove(path)
			continue
		}
		if err := os.WriteFile(path+".tmp", []byte(text), 0o644); err != nil {
			restore()
			return "", err
		}
		if err := os.Rename(path+".tmp", path); err != nil {
			restore()
			return "", err
		}
	}
	// Drop ACL files that are no longer referenced.
	entries, _ := os.ReadDir(m.dir)
	for _, e := range entries {
		n := e.Name()
		if strings.HasSuffix(n, ".acl") {
			if _, keep := a.Files[filepath.Join(m.dir, n)]; !keep {
				_ = os.Remove(filepath.Join(m.dir, n))
			}
		}
	}
	rdr := a.Files[m.redirectPath()]
	if !m.wanted() {
		if m.running() {
			m.stopSquid()
		}
		return "interception off; proxy stopped", nil
	}
	if err := m.reloadSquid(); err != nil {
		// Keep the rejected configuration beside the live one for inspection.
		_ = os.WriteFile(filepath.Join(m.dir, "squid.conf.rejected"), []byte(a.Files[filepath.Join(m.dir, "squid.conf")]), 0o644)
		restore()
		m.clearRedirects()
		m.setErr(err.Error())
		return "", err
	}
	if !m.waitListening(15 * time.Second) {
		m.clearRedirects()
		m.setErr("proxy accepted the configuration but is not listening; interception withheld")
		return "", fmt.Errorf("proxy is not accepting connections on its ports; interception withheld (see %s/cache.log)", m.logDir)
	}
	m.setErr("")
	if m.rdr == nil {
		return "proxy reconfigured; no firewall module to load the interception rules into", nil
	}
	if err := m.rdr.LoadRedirects(redirectName, rdr); err != nil {
		return "", fmt.Errorf("proxy reloaded but interception rules failed: %v", err)
	}
	sum := sha256.Sum256([]byte(a.Files[filepath.Join(m.dir, "squid.conf")]))
	return "proxy reconfigured, interception loaded (" + hex.EncodeToString(sum[:5]) + ")", nil
}

// alsoOtherFamily widens an exclusion written in one address family to cover
// the same devices in the other.
//
// An operator who excludes 192.168.2.0/24 means "those things over there",
// not "those things over there, but only when they speak IPv4". The devices
// that most need excluding are the ones that cannot be excluded any other
// way: appliances with no writable trust store, which are also the ones most
// likely to be IPv6-native. And on a flat network their IPv6 addresses sit in
// the same prefix as everything else, so there is no range to write even if
// the operator wanted to.
//
// So the range is resolved to the devices inside it, and every other address
// those devices hold is added. The link between the two is the MAC, which is
// the only identifier that spans both families.
func (m *Module) alsoOtherFamily(excluded []string) []string {
	if len(excluded) == 0 || m.ctx.Store == nil {
		return excluded
	}
	var nets []*net.IPNet
	have := map[string]bool{}
	for _, e := range excluded {
		have[e] = true
		if _, n, err := net.ParseCIDR(e); err == nil {
			nets = append(nets, n)
		} else if ip := net.ParseIP(e); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	if len(nets) == 0 {
		return excluded
	}
	// Only addresses seen this week. A device keeps every address it has
	// ever held in the table, and IPv6 privacy addresses rotate daily, so
	// without a cutoff the list grows without bound and nearly all of it is
	// addresses nothing answers to any more.
	rows, err := m.ctx.Store.Rows(`SELECT ip, mac FROM hosts WHERE mac IS NOT NULL AND mac <> '' AND last_seen > ?`,
		time.Now().Add(-7*24*time.Hour).Unix())
	if err != nil {
		return excluded
	}
	// Which devices fall inside an excluded range, and every address each holds.
	macs := map[string]bool{}
	byMAC := map[string][]string{}
	for _, r := range rows {
		ipStr, _ := r["ip"].(string)
		mac, _ := r["mac"].(string)
		ip := net.ParseIP(ipStr)
		if ip == nil || mac == "" {
			continue
		}
		byMAC[mac] = append(byMAC[mac], ipStr)
		for _, n := range nets {
			if n.Contains(ip) {
				macs[mac] = true
				break
			}
		}
	}
	out := append([]string(nil), excluded...)
	for mac := range macs {
		for _, ipStr := range byMAC[mac] {
			if have[ipStr] {
				continue
			}
			// Only widen into the family the range did not already cover.
			ip := net.ParseIP(ipStr)
			covered := false
			for _, n := range nets {
				if n.Contains(ip) {
					covered = true
					break
				}
			}
			if covered {
				continue
			}
			have[ipStr] = true
			out = append(out, ipStr)
		}
	}
	sort.Strings(out)
	return out
}
