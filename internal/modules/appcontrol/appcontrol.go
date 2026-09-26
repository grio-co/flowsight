// Package appcontrol enforces application denials without an inline packet
// engine. nDPI (through ntopng) names the application on the first packets
// of a flow; when a flow from a policed client is a denied application, the
// far end goes into that policy's pf table, the existing state is killed,
// and every later connection to it is dropped at the first packet. The
// first flow lives for a fraction of a second; the application does not.
//
// The pf tables are declared by the firewall provider from the policy
// document; this module only fills them and reports what it did.
package appcontrol

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
	"github.com/grioghar/flowsight/internal/modules/firewall"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

type policyDoc interface {
	Doc() *core.PolicyDoc
}

type Module struct {
	ctx      *core.Context
	fw       core.Enforcer
	catalog  core.Classifier
	identity core.Identity
	mu       sync.Mutex
	rules    []rule           // compiled from the policy document
	added    map[string]int64 // table|addr -> when added
	blocked  int64
	lastErr  string
	lastDoc  time.Time
}

type rule struct {
	policy  string
	table   string
	monitor bool
	members []*net.IPNet
	apps    map[string]bool // lowercase app names
	appCats map[string]bool // lowercase nDPI categories
	allow   map[string]bool
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name: "appcontrol", Version: "1.0",
		Description:  "Application control: denied applications, identified by nDPI, are cut off at the firewall.",
		Capabilities: []string{core.CapAppObserve},
		After:        []string{"identity", "visibility", "firewall", "policy"},
		Defaults: map[string]any{
			"kill_states":     true,
			"table_ttl_hours": 24,
		},
		Schema: []core.SettingField{
			{Key: "kill_states", Label: "Kill existing connections on a match", Type: "bool"},
			{Key: "table_ttl_hours", Label: "Forget blocked addresses after (hours)", Type: "int",
				Help: "Addresses of denied applications age out so a shared CDN address is not blocked forever."},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.fw, _ = ctx.Service(core.ServiceEnforcer).(core.Enforcer)
	m.catalog, _ = ctx.Service(core.ServiceClassifier).(core.Classifier)
	m.identity, _ = ctx.Service("identity").(core.Identity)
	m.added = map[string]int64{}
	// Application names come from a classifier; without one no flow can
	// ever match an application and nothing here would happen.
	if m.catalog == nil {
		return fmt.Errorf("an application classifier is required (the visibility module, ntopng with nDPI)")
	}
	bus, ok := ctx.Service(core.ServiceFlowBus).(*core.FlowBus)
	if !ok {
		return fmt.Errorf("core flow bus missing")
	}
	bus.Subscribe(m.onFlows)
	ctx.Every("refresh-rules", 30*time.Second, m.refresh)
	ctx.Every("expire", 10*time.Minute, m.expire, core.Delayed())
	ctx.Route("GET", "/api/appcontrol/status", m.apiStatus, core.Doc("Retrieve active application control rules with current block counts and enforcement status"),
		core.Returns("Application control status", map[string]any{
			"rules": []map[string]any{
				{"policy": "block", "table": "apps-1", "apps": []string{"Chrome", "Safari"}, "blocked_addresses": 42},
			},
			"matches": 42, "error": "", "enforcing": true,
		}))
	ctx.Route("GET", "/api/appcontrol/blocked", m.apiBlocked, core.Doc("List recent application blocks with timestamps and details"),
		core.Query("hours", "integer", "Time window in hours", false, 24),
		core.Query("limit", "integer", "Maximum results to return", false, 200),
		core.Returns("Application blocks", map[string]any{
			"blocks": []map[string]any{
				{"ts": 1790376243, "source": "appcontrol", "app": "Chrome", "blocked": true},
			},
		}))
	ctx.Panel(core.Panel{ID: "appcontrol", Title: "Applications (L7)", Group: "Protect", Order: 98, Icon: "apps"})
	return nil
}

func (m *Module) Health() core.Health {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fw == nil || !m.fw.Available() {
		return core.Health{OK: true, Detail: "pf unavailable: application denials are recorded, not enforced"}
	}
	if m.lastErr != "" {
		return core.Health{OK: false, Detail: m.lastErr}
	}
	return core.Health{OK: true, Detail: fmt.Sprintf("%d rule(s), %d address(es) blocked", len(m.rules), len(m.added))}
}

// refresh recompiles the rule set from the policy document on the interval,
// so schedules and edits take effect without a restart.
func (m *Module) refresh() error {
	pm, ok := m.ctx.Service("policy_doc").(policyDoc)
	if !ok {
		return nil
	}
	doc := pm.Doc()
	res, _ := m.ctx.Service("member_resolver").(core.MemberResolver)
	enforce := core.Bool(m.ctx.Config.Module("policy"), "enforce", false)
	now := time.Now()
	var rules []rule
	for i := range doc.Policies {
		pol := &doc.Policies[i]
		if !pol.Enabled || !doc.Active(pol.Schedule, now) {
			continue
		}
		if len(pol.Deny.Apps) == 0 && len(pol.Deny.AppCategories) == 0 {
			continue
		}
		r := rule{policy: pol.Name, table: firewall.TableFor(pol.Name), monitor: pol.Action == "monitor" || !enforce,
			apps: map[string]bool{}, appCats: map[string]bool{}, allow: map[string]bool{}}
		for _, a := range pol.Deny.Apps {
			r.apps[strings.ToLower(a)] = true
		}
		for _, c := range pol.Deny.AppCategories {
			r.appCats[strings.ToLower(c)] = true
		}
		for _, a := range pol.Allow.Apps {
			r.allow[strings.ToLower(a)] = true
		}
		for _, mem := range doc.Members(pol, res) {
			if _, n, err := net.ParseCIDR(mem); err == nil {
				r.members = append(r.members, n)
			}
		}
		rules = append(rules, r)
	}
	m.mu.Lock()
	m.rules = rules
	m.lastDoc = now
	m.mu.Unlock()
	return nil
}

func (m *Module) match(r *rule, f *core.Flow) bool {
	src := net.ParseIP(f.SrcIP)
	if src == nil {
		return false
	}
	hit := false
	for _, n := range r.members {
		if n.Contains(src) {
			hit = true
			break
		}
	}
	if !hit {
		return false
	}
	app := strings.ToLower(f.App)
	if r.allow[app] {
		return false
	}
	if r.apps[app] {
		return true
	}
	cat := strings.ToLower(f.Category)
	if cat == "" && m.catalog != nil {
		cat = strings.ToLower(m.catalog.AppCategory(f.App))
	}
	return cat != "" && r.appCats[cat]
}

// onFlows is called by the visibility module with every batch of observed flows.
func (m *Module) onFlows(flows []core.Flow) {
	m.mu.Lock()
	rules := m.rules
	m.mu.Unlock()
	if len(rules) == 0 {
		return
	}
	kill := core.Bool(m.ctx.Settings(), "kill_states", true)
	type add struct {
		table, addr string
	}
	var adds []add
	var events []core.Event
	var upd []core.Flow
	now := time.Now().Unix()
	for i := range flows {
		f := &flows[i]
		if f.DstIP == "" || (m.identity != nil && m.identity.IsLocal(f.DstIP)) {
			continue // never block a local destination on an app match
		}
		for ri := range rules {
			r := &rules[ri]
			if !m.match(r, f) {
				continue
			}
			key := r.table + "|" + f.DstIP
			m.mu.Lock()
			_, seen := m.added[key]
			if !r.monitor {
				m.added[key] = now
			}
			m.blocked++
			m.mu.Unlock()
			verdict := "blocked"
			if r.monitor {
				verdict = "observed"
			}
			if !seen {
				if !r.monitor {
					adds = append(adds, add{r.table, f.DstIP})
				}
				msg := fmt.Sprintf("%s reached %s (%s) at %s", f.SrcIP, f.App, f.Category, f.DstIP)
				if r.monitor {
					msg = "would block: " + msg
				} else {
					msg = "blocked: " + msg
				}
				events = append(events, core.Event{TS: now, Kind: "block", Source: "appcontrol", Severity: "info",
					Verdict: verdict, ActorIP: f.SrcIP, TargetIP: f.DstIP, TargetDomain: f.Domain, RuleName: r.policy,
					Category: f.App, Message: msg})
			}
			// Mark the flow itself so reports count it.
			ff := *f
			ff.Verdict = verdict
			ff.Policy = r.policy
			upd = append(upd, ff)
			if !r.monitor && kill && m.fw != nil && m.fw.Available() {
				_ = m.fw.KillStates(f.SrcIP, f.DstIP)
			}
			break
		}
	}
	if len(adds) > 0 && m.fw != nil && m.fw.Available() {
		byTable := map[string][]string{}
		for _, a := range adds {
			byTable[a.table] = append(byTable[a.table], a.addr)
		}
		for t, addrs := range byTable {
			if err := m.fw.AddToSet(t, addrs); err != nil {
				m.mu.Lock()
				m.lastErr = err.Error()
				m.mu.Unlock()
				m.ctx.Log.Warn("table add failed", "table", t, "error", err.Error())
			} else {
				m.mu.Lock()
				m.lastErr = ""
				m.mu.Unlock()
			}
		}
	}
	if len(events) > 0 {
		_ = m.ctx.Store.AddEvents(events)
	}
	if len(upd) > 0 {
		_ = m.ctx.Store.AddFlows(upd)
	}
}

// expire rebuilds every table from the entries younger than the TTL.
func (m *Module) expire() error {
	ttl := int64(core.Int(m.ctx.Settings(), "table_ttl_hours", 24)) * 3600
	cut := time.Now().Unix() - ttl
	m.mu.Lock()
	byTable := map[string][]string{}
	for k, at := range m.added {
		table, addr, _ := strings.Cut(k, "|")
		if at < cut {
			delete(m.added, k)
			continue
		}
		byTable[table] = append(byTable[table], addr)
	}
	tables := map[string]bool{}
	for _, r := range m.rules {
		tables[r.table] = true
	}
	m.mu.Unlock()
	if m.fw == nil || !m.fw.Available() {
		return nil
	}
	for t := range tables {
		if err := m.fw.ReplaceSet(t, byTable[t]); err != nil {
			return err
		}
	}
	return nil
}

func (m *Module) apiStatus(r *core.Req) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var rules []map[string]any
	for _, ru := range m.rules {
		apps := make([]string, 0, len(ru.apps))
		for a := range ru.apps {
			apps = append(apps, a)
		}
		cats := make([]string, 0, len(ru.appCats))
		for c := range ru.appCats {
			cats = append(cats, c)
		}
		sort.Strings(apps)
		sort.Strings(cats)
		n := 0
		for k := range m.added {
			if strings.HasPrefix(k, ru.table+"|") {
				n++
			}
		}
		rules = append(rules, map[string]any{"policy": ru.policy, "table": ru.table, "monitor": ru.monitor,
			"apps": apps, "app_categories": cats, "members": len(ru.members), "blocked_addresses": n})
	}
	return map[string]any{"rules": rules, "matches": m.blocked, "error": m.lastErr,
		"enforcing": m.fw != nil && m.fw.Available()}, nil
}

func (m *Module) apiBlocked(r *core.Req) (any, error) {
	rows, err := m.ctx.Store.Rows(`SELECT * FROM events WHERE source='appcontrol' AND ts>=? ORDER BY ts DESC LIMIT ?`,
		r.Since(24), r.QInt("limit", 200, 1, 2000))
	return map[string]any{"blocks": rows}, err
}
