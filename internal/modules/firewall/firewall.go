// Package firewall owns FlowSight's pf anchors. Every rule FlowSight needs,
// whether a policy block, a proxy redirect or a zone boundary, is loaded into
// a sub-anchor of "flowsight" with pfctl and never touches the operator's own
// ruleset. On OPNsense the plugin hook references the anchor from the
// generated ruleset; on plain FreeBSD the operator adds two lines to pf.conf.
//
// It is also the net.block provider: per-policy blocks on ports, on internet
// access, and on dynamic address tables that the app-control module fills.
package firewall

import (
	"encoding/json"
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

const rootAnchor = "flowsight"

type Module struct {
	legacyLocalFlushed bool
	ctx                *core.Context
	dir                string
	mu                 sync.Mutex
	lastErr            string
	identity           core.Identity
	loaded             map[string]string     // anchor -> hash of rules loaded
	geoTables          map[string]*TableInfo // geo table info
	geoFilling         bool                  // a background fill is running
	geoPending         bool                  // another fill was asked for meanwhile

	// The filter log: where the last read stopped and what it has yielded.
	logStarted                    bool
	logOff, logSize, logAt        int64
	logLines, logHits, logUnknown int64
	logErr                        string
	labels                        map[int]string // anchor rule number -> label
	labelsAt                      time.Time
}

// TableInfo holds information about a pf table.
type TableInfo struct {
	Name      string   `json:"name"`
	Countries []string `json:"countries"`
	Invert    bool     `json:"invert,omitempty"` // holds every country except Countries
	Prefixes  int      `json:"prefixes"`
	// SkippedAnycast counts ranges left out because they are anycast.
	SkippedAnycast int `json:"skipped_anycast"`
	// Kernel is what pf itself reports holding, read at status time.
	Kernel  int   `json:"kernel_addresses"`
	Epoch   int64 `json:"epoch"` // database build epoch when last filled
	Updated int64 `json:"updated"`
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name: "firewall", Version: "1.0",
		Description:  "FlowSight's own pf anchors: policy blocks, proxy redirects and dynamic address tables.",
		Capabilities: []string{},
		Requires:     []string{"pf"},
		After:        []string{"identity"},
		Defaults: map[string]any{
			"filter_log": "/var/log/filter/latest.log",
			"log_blocks": true,
		},
		Schema: []core.SettingField{
			{Key: "log_blocks", Label: "Log blocked packets to pflog", Type: "bool"},
			{Key: "filter_log", Label: "Filter log to read policy matches from", Type: "text",
				Help: "OPNsense writes pf's log here. Lines from FlowSight's policy anchor become the per-packet record behind Policies > Matches. Empty turns the reader off."},
		},
	}
}

// Firewall is the service other modules use.
type Firewall interface {
	// LoadAnchor replaces the rules of sub-anchor name (e.g. "web").
	LoadAnchor(name, rules string) error
	// FlushAnchor removes a sub-anchor's rules.
	FlushAnchor(name string) error
	// ReplaceTable sets the contents of a table inside a sub-anchor.
	ReplaceTable(anchor, table string, addrs []string) error
	// AddToTable adds addresses to a table inside a sub-anchor.
	AddToTable(anchor, table string, addrs []string) error
	// KillStates drops existing states between two hosts (either may be "").
	KillStates(src, dst string) error
	// Counters returns per-rule evaluation and packet counters for an anchor.
	Counters(anchor string) ([]RuleCounter, error)
	// LocalTable is the name of the table holding local networks.
	LocalTable() string
	Available() bool
}

type RuleCounter struct {
	Rule        string `json:"rule"`
	Label       string `json:"label"`
	Evaluations int64  `json:"evaluations"`
	Packets     int64  `json:"packets"`
	Bytes       int64  `json:"bytes"`
	States      int64  `json:"states"`
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.identity, _ = ctx.Service("identity").(core.Identity)
	m.dir = filepath.Join(ctx.Platform.EtcDir, "pf")
	m.loaded = map[string]string{}
	m.geoTables = make(map[string]*TableInfo)
	if err := os.MkdirAll(m.dir, 0o755); err != nil {
		return err
	}
	ctx.Publish("firewall", m)
	if m.Available() {
		// The contracts are pf's only where pf works; elsewhere another
		// enforcer (nftables) serves them, or none does.
		enf := &pfEnforcer{m: m}
		ctx.Publish(core.ServiceEnforcer, enf)
		ctx.Publish(core.ServiceConnStates, enf)
		ctx.Publish(core.ServiceRules, enf)
		ctx.Publish(core.ServiceRedirector, enf)
		ctx.Publish(core.ServiceIsolator, enf)
		ctx.Publish(core.ServiceShaper, newShaper(m))
	}
	if m.Available() {
		ctx.Provider(&provider{m: m})
		ctx.Every("local-table", 60*time.Second, m.refreshLocal)
		ctx.Every("anchor-check", 60*time.Second, m.checkAnchor)
		ctx.Every("geo-tables", time.Hour, m.refreshGeoTables, core.Delayed())
		// What was filled before this process started: the tables persist
		// in pf across a daemon restart, so the record of them should too.
		// Half a minute in, the tables are checked against the kernel and
		// the database build, and refilled only when one of them moved.
		m.loadGeoTableInfo()
		time.AfterFunc(30*time.Second, func() { _ = m.refreshGeoTables() })
		if err := ctx.Store.Exec(hitsSchema); err != nil {
			return err
		}
		_ = m.dedupeHits()
		ctx.Every("filter-log", 10*time.Second, m.readLog)
		ctx.Every("hits-prune", time.Hour, m.pruneHits, core.Delayed())
	}
	ctx.Route("GET", "/api/firewall/hits", m.apiHits,
		core.Doc("Get policy rule matches from the firewall log: when matched, which policy, source and destination"),
		core.Query("policy", "string", "Filter to only this policy's rule matches", false, "default"),
		core.Query("hours", "integer", "Time window in hours (default 24, max 168)", false, 24),
		core.Query("limit", "integer", "Maximum rows to return (default 500, max 5000)", false, 500),
		core.Query("debug", "string", "Include raw log tail and rule labels when set", false, "false"),
		core.Returns("Policy rule matches from firewall log", map[string]any{
			"hits": []map[string]any{
				{"ts": 1790376243, "policy": "default", "label": "block-ads", "action": "block", "dir": "out", "iface": "em0", "proto": "tcp", "src_ip": "192.168.1.10", "src_port": 54321, "dst_ip": "203.0.113.1", "dst_port": 443},
			},
			"log":   map[string]any{"lines": 1000, "offset": 5000, "size": 100000},
			"since": 1790289843,
		}))
	ctx.Route("GET", "/api/firewall/status", m.apiStatus,
		core.Doc("Get firewall status: anchors loaded, rule counters, geo table state, and kernel reference"),
		core.Returns("Firewall module status", map[string]any{
			"available": true,
			"anchors":   []string{"policy", "proxy"},
			"counters": map[string]any{
				"policy": []map[string]any{
					{"rule": "pass", "label": "allow-web", "evaluations": 50000, "packets": 1000, "bytes": 5000000, "states": 45},
				},
			},
			"referenced": true,
			"geo_tables": []map[string]any{
				{"name": "fs_geo_us", "countries": []string{"US"}, "prefixes": 12345, "kernel_addresses": 12340, "epoch": 1790376243},
			},
			"geo_filling": false,
		}))
	ctx.Route("GET", "/api/firewall/table", m.apiTable,
		core.Doc("Query a policy table: count of addresses loaded in kernel and membership test for a single IP"),
		core.Query("name", "string", "Table name to query (fs_geo_<cc>, fs_geox_<policy>, fs_app_<policy>)", true, "fs_geo_us"),
		core.Query("ip", "string", "Test whether this IP address is in the table", false, "203.0.113.1"),
		core.Query("debug", "string", "Include raw pfctl output when set", false, "false"),
		core.Returns("Table information and membership status", map[string]any{
			"name":             "fs_geo_us",
			"kernel_addresses": 12340,
			"ip":               "203.0.113.1",
			"in_table":         true,
			"detail":           "203.0.113.1 match",
		}))
	return nil
}

func (m *Module) Available() bool {
	return m.ctx.Platform.Firewall == "pf" && m.ctx.Platform.Pfctl != ""
}

func (m *Module) Health() core.Health {
	if !m.Available() {
		return core.Health{OK: true, Detail: "no pf on this platform; net.block unavailable"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastErr != "" {
		return core.Health{OK: false, Detail: m.lastErr}
	}
	return core.Health{OK: true, Detail: fmt.Sprintf("%d anchor(s) loaded", len(m.loaded))}
}

func (m *Module) LocalTable() string { return "flowsight_local" }

func (m *Module) pfctl(args ...string) (string, error) {
	return core.Run(30*time.Second, m.ctx.Platform.Pfctl, args...)
}

var anchorNameRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,30}$`)

func (m *Module) LoadAnchor(name, rules string) error {
	if !anchorNameRe.MatchString(name) {
		return fmt.Errorf("invalid anchor name %q", name)
	}
	path := filepath.Join(m.dir, name+".conf")
	if strings.TrimSpace(rules) == "" {
		return m.FlushAnchor(name)
	}
	if err := os.WriteFile(path+".tmp", []byte(rules), 0o644); err != nil {
		return err
	}
	// Syntax check without loading, then load.
	if out, err := m.pfctl("-a", rootAnchor+"/"+name, "-n", "-f", path+".tmp"); err != nil {
		_ = os.Remove(path + ".tmp")
		return fmt.Errorf("pfctl rejected anchor %s: %s", name, strings.TrimSpace(out))
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return err
	}
	if out, err := m.pfctl("-a", rootAnchor+"/"+name, "-f", path); err != nil {
		return fmt.Errorf("pfctl load %s: %s", name, strings.TrimSpace(out))
	}
	m.mu.Lock()
	m.loaded[name] = fmt.Sprint(len(rules))
	m.mu.Unlock()
	return nil
}

func (m *Module) FlushAnchor(name string) error {
	_, _ = m.pfctl("-a", rootAnchor+"/"+name, "-F", "rules")
	_, _ = m.pfctl("-a", rootAnchor+"/"+name, "-F", "nat")
	_ = os.Remove(filepath.Join(m.dir, name+".conf"))
	m.mu.Lock()
	delete(m.loaded, name)
	m.mu.Unlock()
	return nil
}

var tableRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,40}$`)

func (m *Module) tableCmd(anchor, table, op string, addrs []string) error {
	if !tableRe.MatchString(table) {
		return fmt.Errorf("invalid table name %q", table)
	}
	args := []string{}
	if anchor != "" {
		args = append(args, "-a", rootAnchor+"/"+anchor)
	}
	args = append(args, "-t", table, "-T", op)
	if op != "flush" {
		if len(addrs) == 0 {
			if op == "replace" {
				op = "flush"
				args[len(args)-1] = "flush"
			} else {
				return nil
			}
		}
		if op != "flush" {
			// Feed addresses through a file to stay clear of argv limits.
			f, err := os.CreateTemp(m.dir, "table-*")
			if err != nil {
				return err
			}
			defer os.Remove(f.Name())
			for _, a := range addrs {
				if net.ParseIP(a) == nil {
					if _, _, err := net.ParseCIDR(a); err != nil {
						continue
					}
				}
				fmt.Fprintln(f, a)
			}
			f.Close()
			args = append(args, "-f", f.Name())
		}
	}
	if out, err := m.pfctl(args...); err != nil {
		return fmt.Errorf("pfctl table %s: %s", table, strings.TrimSpace(out))
	}
	return nil
}

func (m *Module) ReplaceTable(anchor, table string, addrs []string) error {
	return m.tableCmd(anchor, table, "replace", addrs)
}

func (m *Module) AddToTable(anchor, table string, addrs []string) error {
	return m.tableCmd(anchor, table, "add", addrs)
}

func (m *Module) KillStates(src, dst string) error {
	args := []string{"-k"}
	if src == "" {
		src = "0.0.0.0/0"
	}
	args = append(args, src)
	if dst != "" {
		args = append(args, "-k", dst)
	}
	_, err := m.pfctl(args...)
	return err
}

var counterRe = regexp.MustCompile(`Evaluations: (\d+)\s+Packets: (\d+)\s+Bytes: (\d+)\s+States: (\d+)`)
var labelRe = regexp.MustCompile(`label "([^"]*)"`)

func (m *Module) Counters(anchor string) ([]RuleCounter, error) {
	out, err := m.pfctl("-a", rootAnchor+"/"+anchor, "-vsr")
	if err != nil {
		return nil, err
	}
	var res []RuleCounter
	var cur *RuleCounter
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "[") {
			if cur != nil {
				if mm := counterRe.FindStringSubmatch(t); mm != nil {
					cur.Evaluations, _ = strconv.ParseInt(mm[1], 10, 64)
					cur.Packets, _ = strconv.ParseInt(mm[2], 10, 64)
					cur.Bytes, _ = strconv.ParseInt(mm[3], 10, 64)
					cur.States, _ = strconv.ParseInt(mm[4], 10, 64)
				}
			}
			continue
		}
		res = append(res, RuleCounter{Rule: t})
		cur = &res[len(res)-1]
		if lm := labelRe.FindStringSubmatch(t); lm != nil {
			cur.Label = lm[1]
		}
	}
	return res, nil
}

// refreshLocal keeps the local-networks table current so "internet" denies
// can be expressed as "to anything not local".
func (m *Module) refreshLocal() error {
	var nets []string
	if m.identity != nil {
		nets = m.identity.LocalNetworks()
	}
	nets = append(nets, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10",
		"127.0.0.0/8", "::1/128", "169.254.0.0/16", "224.0.0.0/4", "ff00::/8")
	// The table must live in the root ruleset: a rule inside an anchor that
	// names a table the anchor does not define falls through to the root
	// table of that name. Defining it inside an anchor (or inside the anchor
	// that references it) would give each anchor its own empty copy, and
	// "to ! <local>" would then match everything.
	if !m.legacyLocalFlushed {
		// Earlier releases defined the table inside anchors; a persist
		// table outlives the rules that defined it, so kill those copies
		// or they keep shadowing the root table.
		_ = m.FlushAnchor("local")
		for _, a := range []string{"local", "policy", "web"} {
			_, _ = m.pfctl("-a", rootAnchor+"/"+a, "-t", m.LocalTable(), "-T", "kill")
		}
		m.legacyLocalFlushed = true
	}
	return m.tableCmd("", m.LocalTable(), "replace", nets)
}

// checkAnchor verifies the main ruleset references our anchor and records a
// finding when it does not, which is the difference between blocking and
// silently doing nothing.
func (m *Module) checkAnchor() error {
	out, err := m.pfctl("-sr")
	if err != nil {
		return err
	}
	ok := strings.Contains(out, `anchor "flowsight/*"`) || strings.Contains(out, "anchor \"flowsight")
	if !ok {
		hint := "reference it from the main ruleset"
		if m.ctx.Platform.IsOPNsense() {
			hint = "enable FlowSight in the plugin and apply firewall changes so the anchor is generated"
		} else {
			hint = "add 'anchor \"flowsight/*\"' and 'rdr-anchor \"flowsight/*\"' to pf.conf"
		}
		_, _ = m.ctx.Store.AddFinding("firewall", "anchor-missing", "high", "pf",
			"FlowSight's pf anchor is not in the active ruleset",
			"Rules loaded into flowsight/* are never evaluated: "+hint+".", "firewall:anchor")
		m.mu.Lock()
		m.lastErr = "anchor flowsight/* is not referenced by the active ruleset"
		m.mu.Unlock()
		return nil
	}
	_, _ = m.ctx.Store.ResolveFindings("firewall", map[string]bool{})
	m.mu.Lock()
	m.lastErr = ""
	m.mu.Unlock()
	return nil
}

func (m *Module) apiStatus(r *core.Req) (any, error) {
	if !m.Available() {
		return map[string]any{"available": false}, nil
	}
	anchors, _ := m.pfctl("-a", rootAnchor, "-sA")
	var list []string
	for _, a := range strings.Split(anchors, "\n") {
		if t := strings.TrimSpace(a); t != "" {
			list = append(list, t)
		}
	}
	sort.Strings(list)
	counters := map[string]any{}
	for _, a := range list {
		name := strings.TrimPrefix(a, rootAnchor+"/")
		c, err := m.Counters(name)
		if err == nil {
			counters[name] = c
		}
	}
	m.mu.Lock()
	geoTables := make([]*TableInfo, 0, len(m.geoTables))
	for _, ti := range m.geoTables {
		geoTables = append(geoTables, ti)
	}
	sort.Slice(geoTables, func(i, j int) bool { return geoTables[i].Name < geoTables[j].Name })
	m.mu.Unlock()
	if len(geoTables) > 0 {
		sizes := m.tableSizes("policy")
		for i, t := range geoTables {
			cp := *t
			cp.Kernel = sizes[t.Name]
			geoTables[i] = &cp
		}
	}
	main, _ := m.pfctl("-sr")
	return map[string]any{"available": true, "anchors": list, "counters": counters,
		"referenced": strings.Contains(main, "flowsight"), "geo_tables": geoTables, "geo_filling": m.geoFilling}, nil
}

// tableSizes reads the kernel's own address counts for the tables of an
// anchor, from pfctl -vvsT ("Addresses: N" under each table line).
func (m *Module) tableSizes(anchor string) map[string]int {
	// -vv: one -v prints flags and names only; the address counts come with two.
	out, err := m.pfctl("-a", rootAnchor+"/"+anchor, "-vvsT")
	if err != nil {
		return nil
	}
	sizes := map[string]int{}
	cur := ""
	for _, l := range strings.Split(out, "\n") {
		t := strings.TrimSpace(l)
		if t == "" {
			continue
		}
		if !strings.HasPrefix(l, " ") && !strings.HasPrefix(l, "\t") {
			// "<flags>\t<name>[\t<anchor>]": a table in an anchor carries the
			// anchor path as a third column, so the name is the second field.
			f := strings.Fields(t)
			cur = ""
			if len(f) >= 2 && tableRe.MatchString(f[1]) {
				cur = f[1]
			}
			continue
		}
		if cur != "" && strings.HasPrefix(t, "Addresses:") {
			n, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(t, "Addresses:")))
			sizes[cur] = n
		}
	}
	return sizes
}

func (m *Module) apiTable(r *core.Req) (any, error) {
	name := r.Q("name", "")
	if !tableRe.MatchString(name) {
		return nil, fmt.Errorf("name must be a table name")
	}
	if !m.Available() {
		return map[string]any{"available": false}, nil
	}
	out := map[string]any{"name": name, "kernel_addresses": m.tableSizes("policy")[name]}
	if r.Q("debug", "") != "" {
		raw, _ := m.pfctl("-a", rootAnchor+"/policy", "-vvsT")
		if len(raw) > 4000 {
			raw = raw[:4000]
		}
		out["raw"] = raw
	}
	if ip := strings.TrimSpace(r.Q("ip", "")); ip != "" {
		if net.ParseIP(ip) == nil {
			return nil, fmt.Errorf("ip must be an address")
		}
		res, err := m.pfctl("-a", rootAnchor+"/policy", "-t", name, "-T", "test", ip)
		// pfctl exits non-zero when the address is not in the table; the text
		// says which of the two it was.
		out["ip"] = ip
		out["in_table"] = err == nil && strings.Contains(res, "match")
		out["detail"] = strings.TrimSpace(res)
	}
	return out, nil
}

func (m *Module) geoInfoPath() string { return filepath.Join(m.dir, "geo-tables.json") }

func (m *Module) loadGeoTableInfo() {
	b, err := os.ReadFile(m.geoInfoPath())
	if err != nil {
		return
	}
	var list []*TableInfo
	if json.Unmarshal(b, &list) != nil {
		return
	}
	m.mu.Lock()
	for _, t := range list {
		if t != nil && t.Name != "" {
			m.geoTables[t.Name] = t
		}
	}
	m.mu.Unlock()
}

func (m *Module) saveGeoTableInfo() {
	m.mu.Lock()
	list := make([]*TableInfo, 0, len(m.geoTables))
	for _, t := range m.geoTables {
		list = append(list, t)
	}
	m.mu.Unlock()
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	b, _ := json.MarshalIndent(list, "", " ")
	_ = os.WriteFile(m.geoInfoPath(), b, 0o644)
}

// anchorHasRules asks pf whether sub-anchor name currently holds any rule.
// An error (pf not reachable) counts as loaded, so a transient failure does
// not trigger a reload storm.
func (m *Module) anchorHasRules(name string) bool {
	out, err := m.pfctl("-a", rootAnchor+"/"+name, "-sr")
	if err != nil {
		return true
	}
	return strings.TrimSpace(out) != ""
}
