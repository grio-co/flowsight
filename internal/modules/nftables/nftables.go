// Package nftables is FlowSight's enforcer on a Linux gateway: the same
// contracts pf serves on FreeBSD (core/enforce.go), over one nftables table
// of FlowSight's own, `inet flowsight`. See render.go for why that table can
// only ever take traffic away.
package nftables

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
	"github.com/grioghar/flowsight/internal/modules/firewall"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

type Module struct {
	ctx       *core.Context
	nft       string
	conntrack string
	dir       string
	identity  core.Identity

	mu      sync.Mutex
	lastErr string
	chains  map[string]string // chain -> the last transaction loaded for it, reloaded if the table vanishes
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name: "nftables", Version: "1.0",
		Description:  "FlowSight's enforcer on Linux: policy blocks, interception redirects and zone isolation in its own nftables table.",
		Capabilities: []string{},
		Requires:     []string{"nftables"},
		After:        []string{"identity"},
	}
}

// available says whether this machine's firewall is nftables and FlowSight
// may use it. pf, where present, stays the enforcer.
func (m *Module) available() bool {
	if m.ctx.Platform.Firewall != "nft" || m.nft == "" {
		return false
	}
	_, err := core.Run(10*time.Second, m.nft, "list", "tables")
	return err == nil
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.chains = map[string]string{}
	m.identity, _ = ctx.Service("identity").(core.Identity)
	m.dir = filepath.Join(ctx.Platform.EtcDir, "nftables")
	for _, p := range []string{"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"} {
		if _, err := os.Stat(p); err == nil {
			m.nft = p
			break
		}
	}
	for _, p := range []string{"/usr/sbin/conntrack", "/sbin/conntrack", "/usr/bin/conntrack"} {
		if _, err := os.Stat(p); err == nil {
			m.conntrack = p
			break
		}
	}
	if !m.available() {
		return nil
	}
	if err := os.MkdirAll(m.dir, 0o755); err != nil {
		return err
	}
	if err := m.load(skeleton()); err != nil {
		return fmt.Errorf("creating FlowSight's nftables table: %w", err)
	}
	e := &enforcer{m: m}
	ctx.Publish(core.ServiceEnforcer, e)
	ctx.Publish(core.ServiceIsolator, e)
	// Not the redirector yet. nftables' redirect delivers a connection to
	// the incoming interface's own address, and FlowSight's squid listens on
	// loopback only; redirecting now would send the LAN's web traffic to a
	// port nothing answers on, while the web module's fail-open check (which
	// probes loopback) passed: interception failing closed. The rendering
	// and loading are done and proven in the lab; the redirector is published
	// once the web module listens on the LAN side as well.
	if m.conntrack != "" {
		ctx.Publish(core.ServiceConnStates, e)
	}
	ctx.Provider(&provider{m: m})
	ctx.Every("upkeep", 60*time.Second, m.upkeep)
	return nil
}

func (m *Module) Health() core.Health {
	if m.ctx == nil || !m.available() {
		return core.Health{OK: true, Detail: "not the enforcer here (no nftables, or pf is)"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastErr != "" {
		return core.Health{OK: false, Detail: m.lastErr}
	}
	detail := fmt.Sprintf("table inet flowsight, %d chain(s) loaded", len(m.chains))
	if m.conntrack == "" {
		detail += "; conntrack is not installed, so connections cannot be listed or cut"
	}
	return core.Health{OK: true, Detail: detail}
}

// load checks a transaction with nft -c, then applies it; nftables applies a
// file as one transaction, so a rejected load changes nothing.
func (m *Module) load(tx string) error {
	f, err := os.CreateTemp(m.dirOrTmp(), "tx-*.nft")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(tx); err != nil {
		f.Close()
		return err
	}
	f.Close()
	if out, err := core.Run(30*time.Second, m.nft, "-c", "-f", f.Name()); err != nil {
		return fmt.Errorf("nft rejected the rules: %s", firstLines(out, 4))
	}
	if out, err := core.Run(30*time.Second, m.nft, "-f", f.Name()); err != nil {
		return fmt.Errorf("nft load: %s", firstLines(out, 4))
	}
	return nil
}

func (m *Module) dirOrTmp() string {
	if m.dir != "" {
		if _, err := os.Stat(m.dir); err == nil {
			return m.dir
		}
	}
	return os.TempDir()
}

// loadChain replaces one consumer's chain and remembers it, so upkeep can
// put it back if the table is flushed (a firewall reload, say).
func (m *Module) loadChain(chain, tx string) error {
	if err := m.load(tx); err != nil {
		m.setErr(err.Error())
		return err
	}
	m.mu.Lock()
	m.chains[chain] = tx
	m.lastErr = ""
	m.mu.Unlock()
	return nil
}

func (m *Module) clearChain(chain string) error {
	m.mu.Lock()
	delete(m.chains, chain)
	m.mu.Unlock()
	return m.load(skeleton() + fmt.Sprintf("flush chain %s %s\n", table, chain))
}

func (m *Module) setErr(s string) {
	m.mu.Lock()
	m.lastErr = s
	m.mu.Unlock()
}

// upkeep puts the table back if something removed it, reloading every
// chain from what was last loaded, and keeps the local-network sets current.
func (m *Module) upkeep() error {
	if _, err := core.Run(10*time.Second, m.nft, "list", "table", "inet", "flowsight"); err != nil {
		if err := m.load(skeleton()); err != nil {
			m.setErr("FlowSight's nftables table is missing and could not be recreated: " + err.Error())
			return err
		}
		m.mu.Lock()
		saved := make([]string, 0, len(m.chains))
		for _, tx := range m.chains {
			saved = append(saved, tx)
		}
		m.mu.Unlock()
		for _, tx := range saved {
			_ = m.load(tx)
		}
		m.ctx.Event("firewall", "FlowSight's nftables table had been removed and was put back", nil)
	}
	if m.identity == nil {
		return nil
	}
	v4, v6 := family(m.identity.LocalNetworks())
	tx := fmt.Sprintf("flush set %s local_v4\nflush set %s local_v6\n", table, table)
	if len(v4) > 0 {
		tx += fmt.Sprintf("add element %s local_v4 %s\n", table, elems(v4))
	}
	if len(v6) > 0 {
		tx += fmt.Sprintf("add element %s local_v6 %s\n", table, elems(v6))
	}
	return m.load(skeleton() + tx)
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "; ")
}

// ---------------------------------------------------------------- enforcer

// enforcer serves the contracts in core/enforce.go over the table.
type enforcer struct{ m *Module }

var (
	_ core.Enforcer    = (*enforcer)(nil)
	_ core.StateReader = (*enforcer)(nil)
	_ core.Redirector  = (*enforcer)(nil)
	_ core.Isolator    = (*enforcer)(nil)
)

func (e *enforcer) Name() string    { return "nftables" }
func (e *enforcer) Available() bool { return e.m.available() }

func (e *enforcer) Capabilities() []string {
	caps := []string{core.CapSetV4, core.CapSetV6}
	if e.m.conntrack != "" {
		caps = append(caps, core.CapKillStates, core.CapConnStates)
	}
	return caps
}

// setTx fills the v4 and v6 halves of a set the policy chain declared.
func setTx(set string, addrs []string, replace bool) string {
	v4, v6 := family(addrs)
	var b strings.Builder
	if replace {
		fmt.Fprintf(&b, "flush set %s %s_v4\nflush set %s %s_v6\n", table, set, table, set)
	}
	if len(v4) > 0 {
		fmt.Fprintf(&b, "add element %s %s_v4 %s\n", table, set, elems(v4))
	}
	if len(v6) > 0 {
		fmt.Fprintf(&b, "add element %s %s_v6 %s\n", table, set, elems(v6))
	}
	return b.String()
}

func (e *enforcer) ReplaceSet(set string, addrs []string) error {
	return e.m.load(setTx(set, addrs, true))
}

func (e *enforcer) AddToSet(set string, addrs []string) error {
	tx := setTx(set, addrs, false)
	if tx == "" {
		return nil
	}
	return e.m.load(tx)
}

// KillStates removes established connections from conntrack. Deleting none
// is not a failure.
func (e *enforcer) KillStates(src, dst string) error {
	if e.m.conntrack == "" {
		return errors.New("conntrack is not installed")
	}
	args := []string{"-D"}
	if src != "" {
		args = append(args, "-s", src)
	}
	if dst != "" {
		args = append(args, "-d", dst)
	}
	out, err := core.Run(15*time.Second, e.m.conntrack, args...)
	if err != nil && strings.Contains(out, "0 flow entries") {
		return nil
	}
	return err
}

func (e *enforcer) States() ([]core.ConnState, error) {
	out, err := core.Run(30*time.Second, e.m.conntrack, "-L", "-o", "extended")
	if err != nil && !strings.Contains(out, "flow entries") {
		return nil, fmt.Errorf("conntrack: %s", firstLines(out, 2))
	}
	return ParseConntrack(out), nil
}

func (e *enforcer) RenderRedirects(spec core.RedirectSpec) string { return renderRedirects(spec) }
func (e *enforcer) LoadRedirects(name, text string) error         { return e.m.loadChain(chainWeb, text) }
func (e *enforcer) ClearRedirects(name string) error              { return e.m.clearChain(chainWeb) }

func (e *enforcer) RenderIsolation(spec core.IsolationSpec) string { return renderIsolation(spec) }
func (e *enforcer) LoadIsolation(name, text string) error          { return e.m.loadChain(chainEnroll, text) }
func (e *enforcer) ClearIsolation(name string) error               { return e.m.clearChain(chainEnroll) }

// ParseConntrack reads `conntrack -L -o extended`. Each line has the
// original tuple (the opener's view, before any translation) and then the
// reply tuple (the far end as the connection was delivered, and the opener
// after source translation). Byte counts appear when the kernel's
// accounting is on (net.netfilter.nf_conntrack_acct).
//
//	ipv4 2 tcp 6 431999 ESTABLISHED src=10.10.0.2 dst=203.0.113.9 sport=40000 dport=443 packets=5 bytes=300 src=203.0.113.9 dst=198.51.100.2 sport=443 dport=40000 packets=4 bytes=500 [ASSURED] mark=0 use=1
func ParseConntrack(text string) []core.ConnState {
	var out []core.ConnState
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || (f[0] != "ipv4" && f[0] != "ipv6") {
			continue
		}
		st := core.ConnState{Proto: f[2]}
		if secs, err := strconv.Atoi(f[4]); err == nil {
			st.Expires = time.Duration(secs) * time.Second
		}
		if f[2] == "tcp" && len(f) > 5 && !strings.Contains(f[5], "=") {
			st.Status = f[5]
		}
		var tuples [2]map[string]string
		t := -1
		for _, kv := range f[5:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			if k == "src" {
				t++
				if t > 1 {
					break
				}
				tuples[t] = map[string]string{}
			}
			if t >= 0 && t <= 1 {
				tuples[t][k] = v
			}
		}
		if tuples[0] == nil || tuples[1] == nil {
			continue
		}
		port := func(m map[string]string, k string) int { n, _ := strconv.Atoi(m[k]); return n }
		num := func(m map[string]string, k string) int64 { n, _ := strconv.ParseInt(m[k], 10, 64); return n }
		o, r := tuples[0], tuples[1]
		st.Initiator = core.Endpoint{Addr: o["src"], Port: port(o, "sport")}
		st.Responder = core.Endpoint{Addr: o["dst"], Port: port(o, "dport")}
		st.ResponderTranslated = core.Endpoint{Addr: r["src"], Port: port(r, "sport")}
		st.InitiatorTranslated = core.Endpoint{Addr: r["dst"], Port: port(r, "dport")}
		st.Sent, st.PktsSent = num(o, "bytes"), num(o, "packets")
		st.Received, st.PktsReceived = num(r, "bytes"), num(r, "packets")
		out = append(out, st)
	}
	return out
}

// ---------------------------------------------------------------- policy

// provider compiles net.block and app.block into the policy chain, as the
// pf provider does into flowsight/policy: per policy and address family, a
// rule per denied port range, one for internet access, and a set the
// app-control module fills with the addresses of denied applications. The
// set names are the pf table names (firewall.TableFor) with _v4 and _v6.
type provider struct{ m *Module }

func (p *provider) Name() string           { return "nftables" }
func (p *provider) Capabilities() []string { return []string{core.CapNetBlock, core.CapAppBlock} }

func (p *provider) path() string { return filepath.Join(p.m.dir, "policy.nft") }

func (p *provider) Compile(doc *core.PolicyDoc) (core.Artifact, error) {
	res, _ := p.m.ctx.Service("member_resolver").(core.MemberResolver)
	tx, n, err := compilePolicy(doc, res, time.Now())
	if err != nil {
		return core.Artifact{}, err
	}
	return core.Artifact{Files: map[string]string{p.path(): tx}, Note: fmt.Sprintf("%d rule(s)", n)}, nil
}

func compilePolicy(doc *core.PolicyDoc, res core.MemberResolver, now time.Time) (string, int, error) {
	excluded := map[string]bool{}
	for _, c := range doc.ExcludedCIDRs(res) {
		excluded[c] = true
	}
	var sets, rules []string
	for i := range doc.Policies {
		pol := &doc.Policies[i]
		if !pol.Enabled || !doc.Active(pol.Schedule, now) {
			continue
		}
		needsNet, needsApp := false, false
		for _, r := range pol.Requirements() {
			needsNet = needsNet || r == core.CapNetBlock
			needsApp = needsApp || r == core.CapAppBlock
		}
		if !needsNet && !needsApp {
			continue
		}
		if len(pol.Deny.Countries) > 0 || len(pol.Deny.CountriesExcept) > 0 {
			return "", 0, fmt.Errorf("policy %q denies countries, which the nftables enforcer does not do yet", pol.Name)
		}
		var members []string
		for _, mb := range doc.Members(pol, res) {
			if !excluded[mb] || pol.Match.EvenExcluded {
				members = append(members, mb)
			}
		}
		if len(members) == 0 {
			continue
		}
		verdict := " reject"
		if pol.Action == "monitor" {
			verdict = "" // count, never drop
		}
		appSet := firewall.TableFor(pol.Name)
		if needsApp {
			sets = append(sets, setDecls(appSet)...)
		}
		m4, m6 := family(members)
		for _, fm := range []struct {
			fam, suf string
			src      []string
		}{{"ip", "_v4", m4}, {"ip6", "_v6", m6}} {
			if len(fm.src) == 0 {
				continue
			}
			from := fmt.Sprintf("%s saddr %s", fm.fam, elems(fm.src))
			// counter, then the verdict, then the comment: nftables wants a
			// comment last.
			tail := func(kind string) string {
				return fmt.Sprintf(" counter%s comment %q", verdict, "flowsight:"+commentSafe(pol.Name)+":"+kind)
			}
			if needsApp {
				rules = append(rules, fmt.Sprintf("%s %s daddr @%s%s%s", from, fm.fam, appSet, fm.suf, tail("app")))
			}
			if pol.Deny.Internet {
				rules = append(rules, fmt.Sprintf("%s %s daddr != @local%s%s", from, fm.fam, fm.suf, tail("internet")))
			}
			for _, port := range pol.Deny.Ports {
				proto, rng, _ := strings.Cut(strings.ToLower(port), "/")
				match := proto + " dport " + rng
				if proto == "any" {
					match = "meta l4proto { tcp, udp } th dport " + rng
				}
				rules = append(rules, fmt.Sprintf("%s %s%s", from, match, tail("port")))
			}
		}
	}
	sort.Strings(rules)
	return replaceChain(chainPolicy, sets, rules), len(rules), nil
}

// commentSafe keeps a policy name usable inside an nftables comment.
func commentSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r < 0x20 {
			return '_'
		}
		return r
	}, s)
}

func (p *provider) Current() (core.Artifact, error) {
	b, _ := os.ReadFile(p.path())
	return core.Artifact{Files: map[string]string{p.path(): string(b)}}, nil
}

// Apply checks the transaction with nft -c and loads it; a rejected one
// changes nothing, and the previous rules stay in force.
func (p *provider) Apply(a core.Artifact) (string, error) {
	tx := a.Files[p.path()]
	if err := p.m.loadChain(chainPolicy, tx); err != nil {
		return "", err
	}
	if err := os.WriteFile(p.path(), []byte(tx), 0o644); err != nil {
		return "", err
	}
	return "nftables policy chain loaded", nil
}
