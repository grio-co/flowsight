// Package dns gives resolver visibility and DNS-level enforcement.
//
// Visibility comes from Unbound's own reply log, which every Unbound can
// produce and which names client, query, type, rcode and timing on one line.
// The resolver cache, read through unbound-control, supplies the address to
// name map that lets a flow to 142.250.x.x read as "youtube.com".
//
// Enforcement is a policy provider: per-group views that answer REFUSED for
// denied domains, categories and TLDs, plus safe-search rewrites. REFUSED is
// used rather than NXDOMAIN so a FlowSight block is distinguishable in the
// log from a name that genuinely does not exist.
package dns

import (
	"bufio"
	"database/sql"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

type Module struct {
	logPath  string
	ctx      *core.Context
	tail     *core.Tailer
	mu       sync.Mutex
	lastErr  string
	lines    int64
	names    int
	identity core.Identity
	compiled []compiledPolicy
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name: "dns", Version: "1.0",
		Description:  "Resolver visibility from Unbound's reply log and cache; per-group DNS blocking and safe search.",
		Capabilities: []string{core.CapDNSObserve},
		Requires:     []string{"unbound"},
		After:        []string{"identity", "categories"},
		Defaults: map[string]any{
			"log_path":            "",
			"cache_names_seconds": 60,
			"manage_logging":      true,
			"max_zone_domains":    1500000,
			"local_domain":        "",
		},
		Schema: []core.SettingField{
			{Key: "log_path", Label: "Resolver log", Type: "string",
				Help: "File that receives Unbound's log. Empty uses the platform default."},
			{Key: "manage_logging", Label: "Enable reply logging in Unbound", Type: "bool",
				Help: "Writes a small include that turns on log-replies; without it there is nothing to read."},
			{Key: "cache_names_seconds", Label: "Cache snapshot interval (s)", Type: "int"},
			{Key: "max_zone_domains", Label: "Max domains per policy zone", Type: "int",
				Help: "Each policy becomes one response policy zone; memory grows with its size. The compiler refuses larger ones."},
			{Key: "local_domain", Label: "Local domain for device names", Type: "string", Placeholder: "grio.co",
				Help: "The domain offered first when you give a device a DNS name. Empty: the one your host overrides and Pi-holes use most."},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.identity, _ = ctx.Service("identity").(core.Identity)
	path := core.Str(ctx.Settings(), "log_path", "")
	if path == "" {
		path = ctx.Platform.UnboundLog
	}
	if path == "" {
		path = "/var/log/unbound.log"
	}
	m.tail = core.NewTailer(path)
	m.logPath = path
	ctx.Every("tail", 5*time.Second, m.pollLog)
	every := time.Duration(core.Int(ctx.Settings(), "cache_names_seconds", 60)) * time.Second
	if every > 0 {
		ctx.Every("cache-names", every, m.snapshotCache, core.Delayed())
	}
	// Unbound's logging and DNS policy exist only where Unbound does. Without
	// it (a container, a host beside the firewall) the module still reads
	// whatever resolver log it is given, and offers no dns.block: a policy
	// asking for it is shown as having no provider here instead of failing
	// on every reconcile.
	if m.unboundPresent() {
		if core.Bool(ctx.Settings(), "manage_logging", true) {
			ctx.Every("ensure-logging", 10*time.Minute, m.ensureLogging)
		}
		ctx.Provider(&provider{m: m})
	}
	ctx.Route("GET", "/api/dns/summary", m.apiSummary, core.Doc("Query summary with volumes, block rates, top domains, clients and lists"),
		core.Query("hours", "integer", "Time window in hours", false, 24),
		core.Query("limit", "integer", "Max results per category", false, 15),
		core.Returns("DNS summary", map[string]any{
			"totals":  map[string]any{"queries": 10000, "blocked": 234, "clients": 5, "domains": 50},
			"live":    map[string]any{"queries": 100, "blocked": 2, "avg_ms": 25},
			"top":     []map[string]any{{"domain": "google.com", "queries": 500, "clients": 3}},
			"blocked": []map[string]any{{"domain": "ads.com", "queries": 50, "list": "adblock"}},
		}))
	ctx.Route("GET", "/api/dns/log", m.apiLog, core.Doc("Historical DNS query log with optional filtering by domain or client"),
		core.Query("client", "string", "Filter by client IP address", false, "192.168.1.10"),
		core.Query("domain", "string", "Filter domain by substring match", false, "google.com"),
		core.Query("blocked", "boolean", "Show only blocked queries", false, false),
		core.Query("limit", "integer", "Maximum results to return", false, 200),
		core.Returns("Query log", map[string]any{
			"queries": []map[string]any{{"ts": 1790376243, "client": "192.168.1.10", "domain": "google.com", "action": "pass"}},
		}))
	ctx.Route("GET", "/api/dns/lookup", m.apiLookup, core.Doc("Retrieve hostname assignments given to a specific IP address"),
		core.Query("ip", "string", "IP address to look up", true, "192.168.1.10"),
		core.Returns("Address lookup", map[string]any{
			"ip": "192.168.1.10", "name": map[string]any{"name": "gateway", "ts": 1790376243},
		}))
	ctx.Route("GET", "/api/dns/timeseries", m.apiTimeseries, core.Doc("Time series of DNS queries and blocks with automatic step adjustment"),
		core.Query("hours", "integer", "Time window in hours", false, 24),
		core.Returns("Time series data", map[string]any{
			"series": []map[string]any{{"t": 1790376243, "queries": 100, "blocked": 2}},
			"step":   300,
		}))
	m.registerNameRoutes(ctx)
	ctx.Panel(core.Panel{ID: "dns", Title: "DNS", Group: "Monitor", Order: 50, Icon: "dns"})
	return nil
}

// unboundPresent reports whether this machine has Unbound to manage.
func (m *Module) unboundPresent() bool {
	for _, p := range []string{m.ctx.Platform.UnboundControl, m.ctx.Platform.UnboundCheckconf} {
		if p == "" {
			return false
		}
		if _, err := os.Stat(p); err != nil {
			return false
		}
	}
	return true
}

func (m *Module) Health() core.Health {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastErr != "" {
		return core.Health{OK: false, Detail: m.lastErr}
	}
	if !m.unboundPresent() {
		return core.Health{OK: true, Detail: fmt.Sprintf("Unbound is not installed here: no DNS policy or reply logging; %d log lines read", m.lines)}
	}
	return core.Health{OK: true, Detail: fmt.Sprintf("%d log lines read, %d names cached", m.lines, m.names)}
}

// ------------------------------------------------------------- reply log

// Unbound reply log line, after the syslog prefix:
//
//	info: 10.99.0.100 example.com. A IN NOERROR 0.023456 0 45
//
// With log-tag-queryreply the word "reply:" precedes the client.
// Plain: "info: 10.0.0.5 example.com. A IN NOERROR 0.02 0 99"; with
// log-tag-queryreply the tag replaces the level: "reply: 10.0.0.5 example.com. A IN ...".
var replyRe = regexp.MustCompile(`(?:info|reply): (?:reply: )?(\S+) (\S+)\. (\S+) IN (\S+) ([0-9.]+) (\d) (\d+)`)

// rpz: applied [kids-web] example.com. nxdomain 10.99.0.162@40311 example.com. A IN
var rpzRe = regexp.MustCompile(`rpz: applied \[([^\]]+)\] (\S+)\. (\S+) (\S+)@\d+`)
var tsRe = regexp.MustCompile(`(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?([+-]\d{2}:\d{2}|Z)`)

func (m *Module) pollLog() error {
	var recs []core.DNSRecord
	type hit struct {
		list string
		at   time.Time
	}
	blocked := map[string]hit{} // client|qname -> policy that blocked it
	n, err := m.tail.Lines(func(line []byte) {
		s := string(line)
		if rz := rpzRe.FindStringSubmatch(s); rz != nil {
			client := rz[4]
			blocked[client+"|"+strings.ToLower(rz[2])] = hit{list: rz[1], at: time.Now()}
			return
		}
		mm := replyRe.FindStringSubmatch(s)
		if mm == nil {
			return
		}
		ts := time.Now().Unix()
		if t := tsRe.FindStringSubmatch(s); t != nil {
			if parsed, err := time.Parse(time.RFC3339, t[1]+t[2]); err == nil {
				ts = parsed.Unix()
			}
		} else if i := strings.Index(s, "] unbound["); i > 1 {
			if v, err := strconv.ParseFloat(strings.Trim(s[:i], "[]"), 64); err == nil {
				ts = int64(v)
			}
		}
		client := mm[1]
		if i := strings.Index(client, "@"); i > 0 {
			client = client[:i]
		}
		rcode := mm[4]
		secs, _ := strconv.ParseFloat(mm[5], 64)
		src := "recursion"
		if mm[6] == "1" {
			src = "cache"
		}
		action, list := "pass", ""
		qname := strings.ToLower(mm[2])
		if h, ok := blocked[client+"|"+qname]; ok {
			action, list = "block", h.list
			delete(blocked, client+"|"+qname)
		} else if rcode == "REFUSED" {
			action = "block"
		}
		recs = append(recs, core.DNSRecord{TS: ts, Client: client, Domain: qname,
			QType: mm[3], Action: action, List: list, RCode: rcode, AnswerSource: src, MS: secs * 1000, Source: "unbound"})
	})
	// An rpz line whose reply line has not arrived yet (split across reads)
	// is still a block worth recording.
	for k, h := range blocked {
		parts := strings.SplitN(k, "|", 2)
		recs = append(recs, core.DNSRecord{TS: time.Now().Unix(), Client: parts[0], Domain: parts[1], QType: "A",
			Action: "block", List: h.list, RCode: "NXDOMAIN", Source: "unbound"})
	}
	m.mu.Lock()
	if err != nil {
		if os.IsNotExist(err) {
			m.lastErr = "resolver log not found at " + m.tail.Path + " (is reply logging enabled?)"
		} else {
			m.lastErr = err.Error()
		}
	} else {
		m.lastErr = ""
		m.lines += int64(n)
	}
	m.mu.Unlock()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(recs) == 0 {
		return nil
	}
	// A REFUSED without an rpz line: attribute it by membership when possible.
	if pol := m.currentPolicies(); len(pol) > 0 {
		for i := range recs {
			if recs[i].Action == "block" && recs[i].List == "" {
				recs[i].List = m.policyFor(pol, recs[i].Client, recs[i].Domain)
			}
		}
	}
	agg := map[string]*core.HostUpdate{}
	for _, r := range recs {
		if r.Action != "pass" && r.Client != "" {
			h := agg[r.Client]
			if h == nil {
				h = &core.HostUpdate{IP: r.Client, Source: "dns"}
				agg[r.Client] = h
			}
			h.Blocked++
		}
	}
	var ups []core.HostUpdate
	for _, h := range agg {
		ups = append(ups, *h)
	}
	_ = m.ctx.Store.UpsertHosts(ups)
	return m.ctx.Store.AddDNS(recs)
}

// ensureLogging drops an include that turns on reply logging. On OPNsense the
// resolver reads /usr/local/etc/unbound.opnsense.d/*.conf; elsewhere the
// configured include directory. Written once, only when absent or changed.
func (m *Module) ensureLogging() error {
	want := "# Generated by flowsight. Reply logging feeds the DNS report.\nserver:\n    log-replies: yes\n    log-tag-queryreply: yes\n    log-local-actions: yes\n"
	paths := IncludePaths(m.ctx.Platform, "flowsight-logging.conf")
	changed := false
	for _, path := range paths {
		if cur, err := os.ReadFile(path); err == nil && string(cur) == want {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path+".tmp", []byte(want), 0o644); err != nil {
			return err
		}
		if err := os.Rename(path+".tmp", path); err != nil {
			return err
		}
		changed = true
	}
	if !changed {
		return nil
	}
	if out, err := m.ctx.Platform.UnboundCheck(); err != nil {
		for _, p := range paths {
			_ = os.Remove(p)
		}
		return fmt.Errorf("unbound-checkconf rejected the logging include, removed it: %s", out)
	}
	_, err := m.ctx.Platform.Service("unbound", "reload")
	m.ctx.Event("config", "enabled Unbound reply logging", map[string]any{"paths": paths})
	return err
}

// IncludePaths returns where a FlowSight include must be written so that it
// is both live now and survives a resolver reconfigure. On OPNsense the
// running config includes /var/unbound/etc/*.conf, and the GUI copies
// /usr/local/etc/unbound.opnsense.d/*.conf there whenever it regenerates, so
// the file goes to both. Elsewhere the include directory is the live one.
func IncludePaths(p *core.Platform, name string) []string {
	if p.IsOPNsense() {
		return []string{filepath.Join("/usr/local/etc/unbound.opnsense.d", name),
			filepath.Join("/var/unbound/etc", name)}
	}
	return []string{filepath.Join(filepath.Dir(p.UnboundInclude), name)}
}

// ------------------------------------------------------------- cache names

// snapshotCache folds the resolver cache into dns_names so flows can be named
// by what the client actually asked for.
func (m *Module) snapshotCache() error {
	args := []string{}
	if m.ctx.Platform.UnboundConfig != "" {
		args = append(args, "-c", m.ctx.Platform.UnboundConfig)
	}
	args = append(args, "dump_cache")
	out, err := core.Run(60*time.Second, m.ctx.Platform.UnboundControl, args...)
	if err != nil {
		return fmt.Errorf("unbound-control dump_cache: %v", err)
	}
	now := time.Now().Unix()
	// CNAME chains: collect A/AAAA and CNAME, resolve the chain to the name
	// the client asked for where possible.
	cname := map[string]string{} // alias -> target
	type rr struct{ ip, name string }
	var addrs []rr
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 || f[2] != "IN" {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(f[0], "."))
		switch f[3] {
		case "A", "AAAA":
			if net.ParseIP(f[4]) != nil {
				addrs = append(addrs, rr{f[4], name})
			}
		case "CNAME":
			cname[strings.ToLower(strings.TrimSuffix(f[4], "."))] = name
		}
	}
	// Prefer the original query name over a CDN target: walk aliases back.
	best := map[string]string{}
	for _, a := range addrs {
		n := a.name
		for i := 0; i < 6; i++ {
			if alias, ok := cname[n]; ok && alias != n {
				n = alias
			} else {
				break
			}
		}
		if cur, ok := best[a.ip]; !ok || len(n) < len(cur) {
			best[a.ip] = n
		}
	}
	if len(best) == 0 {
		return nil
	}
	err = m.ctx.Store.Tx(func(tx *sql.Tx) error {
		st, err := tx.Prepare(`INSERT OR REPLACE INTO dns_names(ip,name,ts) VALUES(?,?,?)`)
		if err != nil {
			return err
		}
		defer st.Close()
		for ip, name := range best {
			if core.IsSpecialIP(ip) {
				continue // a blocklist answering 127.0.0.1 names nothing
			}
			if _, err := st.Exec(ip, name, now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.names = len(best)
	m.mu.Unlock()
	return nil
}

// ------------------------------------------------------------- API

func (m *Module) name(ip string) string {
	if m.identity == nil {
		return ""
	}
	return m.identity.Name(ip)
}

func (m *Module) apiSummary(r *core.Req) (any, error) {
	since := r.Since(24)
	st := m.ctx.Store
	tot, _ := st.Row(`SELECT SUM(queries) AS queries, SUM(CASE WHEN action<>'pass' THEN queries ELSE 0 END) AS blocked,
		COUNT(DISTINCT client) AS clients, COUNT(DISTINCT domain) AS domains FROM rollup_dns WHERE bucket>=?`, since)
	live, _ := st.Row(`SELECT COUNT(*) AS queries, SUM(CASE WHEN action<>'pass' THEN 1 ELSE 0 END) AS blocked,
		SUM(CASE WHEN answer_source='cache' THEN 1 ELSE 0 END) AS cached, AVG(ms) AS avg_ms,
		SUM(CASE WHEN rcode='NXDOMAIN' THEN 1 ELSE 0 END) AS nxdomain,
		SUM(CASE WHEN rcode='SERVFAIL' THEN 1 ELSE 0 END) AS servfail FROM dns WHERE ts>=?`, since)
	limit := r.QInt("limit", 15, 1, 100)
	top, _ := st.Rows(`SELECT domain, SUM(queries) AS queries, COUNT(DISTINCT client) AS clients FROM rollup_dns
		WHERE bucket>=? AND action='pass' GROUP BY domain ORDER BY queries DESC LIMIT ?`, since, limit)
	blocked, _ := st.Rows(`SELECT domain, MAX(list) AS list, SUM(queries) AS queries, COUNT(DISTINCT client) AS clients
		FROM rollup_dns WHERE bucket>=? AND action<>'pass' GROUP BY domain ORDER BY queries DESC LIMIT ?`, since, limit)
	clients, _ := st.Rows(`SELECT client AS ip, SUM(queries) AS queries,
		SUM(CASE WHEN action<>'pass' THEN queries ELSE 0 END) AS blocked FROM rollup_dns WHERE bucket>=?
		GROUP BY client ORDER BY queries DESC LIMIT ?`, since, limit)
	for _, c := range clients {
		ip, _ := c["ip"].(string)
		if n := m.name(ip); n != "" {
			c["name"] = n
		}
	}
	types, _ := st.Rows(`SELECT qtype, COUNT(*) AS queries FROM dns WHERE ts>=? GROUP BY qtype ORDER BY queries DESC LIMIT 10`, since)
	rcodes, _ := st.Rows(`SELECT rcode, COUNT(*) AS queries FROM dns WHERE ts>=? GROUP BY rcode ORDER BY queries DESC`, since)
	lists, _ := st.Rows(`SELECT COALESCE(NULLIF(list,''),'(unattributed)') AS list, SUM(queries) AS queries FROM rollup_dns
		WHERE bucket>=? AND action<>'pass' GROUP BY 1 ORDER BY queries DESC`, since)
	m.mu.Lock()
	lastErr := m.lastErr
	m.mu.Unlock()
	return map[string]any{"totals": tot, "live": live, "top": top, "blocked": blocked, "clients": clients,
		"types": types, "rcodes": rcodes, "lists": lists, "source_error": lastErr, "hours": r.Hours(24)}, nil
}

func (m *Module) apiLog(r *core.Req) (any, error) {
	client, err := r.QSafe("client", "", 64)
	if err != nil {
		return nil, err
	}
	domain, err := r.QSafe("domain", "", 128)
	if err != nil {
		return nil, err
	}
	q := `SELECT ts, client, domain, qtype, action, list, rcode, answer_source, ms, source FROM dns WHERE 1=1`
	args := []any{}
	if client != "" {
		q += ` AND client=?`
		args = append(args, client)
	}
	if domain != "" {
		q += ` AND domain LIKE ?`
		args = append(args, "%"+strings.ToLower(domain)+"%")
	}
	if r.Q("blocked", "") != "" {
		q += ` AND action<>'pass'`
	}
	q += ` ORDER BY ts DESC, id DESC LIMIT ?`
	args = append(args, r.QInt("limit", 200, 1, 5000))
	rows, err := m.ctx.Store.Rows(q, args...)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		ip, _ := row["client"].(string)
		if n := m.name(ip); n != "" {
			row["client_name"] = n
		}
	}
	return map[string]any{"queries": rows}, nil
}

func (m *Module) apiLookup(r *core.Req) (any, error) {
	ip := r.Q("ip", "")
	if net.ParseIP(ip) == nil {
		return nil, core.BadRequest("ip must be an address")
	}
	row, _ := m.ctx.Store.Row(`SELECT name, ts FROM dns_names WHERE ip=?`, ip)
	return map[string]any{"ip": ip, "name": row}, nil
}

func (m *Module) apiTimeseries(r *core.Req) (any, error) {
	since := r.Since(24)
	hours := r.Hours(24)
	step := 300
	if hours > 48 {
		step = 3600
	}
	rows, err := m.ctx.Store.Rows(`SELECT (bucket/?)*? AS t, SUM(queries) AS queries,
		SUM(CASE WHEN action<>'pass' THEN queries ELSE 0 END) AS blocked FROM rollup_dns WHERE bucket>=?
		GROUP BY t ORDER BY t`, step, step, since)
	return map[string]any{"series": rows, "step": step}, err
}

// ------------------------------------------------------------- policy hooks

type compiledPolicy struct {
	name    string
	members []*net.IPNet
	domains map[string]bool
}

func (m *Module) currentPolicies() []compiledPolicy {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.compiled
}

func (m *Module) policyFor(pol []compiledPolicy, client, domain string) string {
	ip := net.ParseIP(client)
	if ip == nil {
		return ""
	}
	for _, p := range pol {
		hit := false
		for _, n := range p.members {
			if n.Contains(ip) {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		d := domain
		for d != "" {
			if p.domains[d] {
				return p.name
			}
			i := strings.Index(d, ".")
			if i < 0 {
				break
			}
			d = d[i+1:]
		}
	}
	return ""
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// EffectiveSettings reports the resolver log actually followed.
func (m *Module) EffectiveSettings() map[string]any { return map[string]any{"log_path": m.logPath} }
