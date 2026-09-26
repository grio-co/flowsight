// Package qos decides who waits when the link is full.
//
// Every other module here answers "what is happening". This one changes it,
// which makes it the most dangerous thing in the product and the one with the
// most ways to look like it is working while doing nothing.
//
// Two things have to be true before a priority means anything.
//
// The first is that the bottleneck has to be on this firewall. When an uplink
// fills, the queue that decides what waits belongs to the modem or the
// carrier, and no rule here can reach into it. So shaping starts by sending
// everything through a pipe sized a little under what the link really
// carries, which moves that queue to this side. That is why the link speeds
// are settings and why they have to be honest: a pipe set above the real rate
// never fills, the carrier's queue stays the real bottleneck, and every
// weight below is decoration.
//
// The second is that the direction has to be the one you can actually
// control. Upload is straightforward: this firewall is the sender. Download
// is not, because the packets have already crossed the bottleneck by the time
// they arrive; shaping them works only by holding them back so the senders
// slow down, which is real but blunter. Anyone expecting downloads to be
// prioritised as crisply as uploads is going to be disappointed, and the
// interface says so rather than pretending.
package qos

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

// Module implements core.Module.
type Module struct {
	ctx      *core.Context
	shaper   core.Shaper
	identity core.Identity

	mu        sync.Mutex
	applied   bool
	lastErr   string
	lastPlan  core.ShapePlan
	rules     []Rule
	addrs     map[string][]string
	appliedAt time.Time
	sp        *speedState // bandwidth tests, see speed.go
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name:        "qos",
		Version:     "1.0",
		Tier:        "pro",
		Description: "Decides who waits when the link is full. Moves the queue off the carrier and onto this firewall, then shares the link by weight, with optional ceilings per device or service.",
		After:       []string{"firewall", "identity", "web"},
		Defaults: map[string]any{
			"enabled":          true,
			"active":           false,
			"lan_interface":    "",
			"wan_interface":    "",
			"download_mbit":    0,
			"upload_mbit":      0,
			"headroom_percent": 7,
			"weight_high":      70,
			"weight_normal":    25,
			"weight_low":       5,
			"default_class":    "normal",
			"rules":            []string{},
		},
		Schema: []core.SettingField{
			{Key: "active", Label: "Shape traffic", Type: "bool",
				Help: "Off: nothing is queued and the link behaves exactly as it does now. On: all traffic passes through a pipe on this firewall and the rules below decide who waits. Turn this on deliberately; it changes how every packet on the network is handled."},
			{Key: "download_mbit", Label: "Download the link really carries (Mbit/s)", Type: "int",
				Help: "Measure it, do not copy it off the bill. Shaping works by making this firewall the bottleneck, so this has to be a little under the true rate. Set it too high and the carrier stays the bottleneck and nothing below has any effect."},
			{Key: "upload_mbit", Label: "Upload the link really carries (Mbit/s)", Type: "int",
				Help: "The more important of the two. A saturated upload delays the acknowledgements that downloads depend on, so an uncontrolled upload ruins streaming in both directions."},
			{Key: "headroom_percent", Label: "Keep back (percent)", Type: "int",
				Help: "How far under the measured rate the pipes are sized. A few percent is what keeps the queue on this side of the link."},
			{Key: "wan_interface", Label: "WAN interface", Type: "string", Placeholder: "detected from the default route", Help: "The interface whose counters the bandwidth test reads. Empty: the interface the default route leaves by."},
			{Key: "lan_interface", Label: "LAN interface", Type: "string",
				Help: "Where shaping is applied. Addresses are still untranslated here, so a rule can name a device on this network. Empty: detected from the local networks."},
			{Key: "default_class", Label: "Class for everything not named", Type: "choice", Choices: []string{"high", "normal", "low"}},
			{Key: "weight_high", Label: "Weight: high", Type: "int",
				Help: "Shares, not reservations. A class with twice the weight gets twice the link when both want it, and none of it is wasted when one does not."},
			{Key: "weight_normal", Label: "Weight: normal", Type: "int"},
			{Key: "weight_low", Label: "Weight: low", Type: "int"},
			{Key: "rules", Label: "Rules", Type: "list",
				Help: "One per line, written as \"what = class\". The left side is an address, a CIDR or a domain. Add a rate to cap it as well.\n\n    192.168.1.178 = low\n    redgifs.com = high\n    10.0.5.0/24 = low, 20Mbit\n\nA domain matches the addresses this network has actually been seen using for it, so a name nobody has looked up yet matches nothing until they do."},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.shaper, _ = ctx.Service(core.ServiceShaper).(core.Shaper)
	m.identity, _ = ctx.Service("identity").(core.Identity)
	m.addrs = map[string][]string{}
	ctx.Every("apply", 60*time.Second, m.reconcile)
	ctx.Every("resolve", 120*time.Second, m.resolve)
	ctx.Route("GET", "/api/qos/speedtests", m.apiSpeedTests, core.Needs("qos.shape"),
		core.Doc("Bandwidth tests run from this firewall: the built-in measurement, the WAN interface's own counters during it (so the capacity estimate includes the load already on the link), the speedtest.net comparison, divergence and reruns. Newest first; the last 50 are kept."),
		core.Returns("Bandwidth tests", map[string]any{
			"running": false, "stage": "", "interface": "vtnet1",
			"tests": []map[string]any{{"id": "1790480000000000000", "ts": 1790480000, "attempt": 1, "rerun": false, "down_mbit": 912.4, "up_mbit": 38.1,
				"iface_down_mbit": 940.2, "iface_up_mbit": 39.0, "base_down_mbit": 12.3, "base_up_mbit": 0.8, "load_down_mbit": 27.8, "load_up_mbit": 0.9,
				"ookla_server": "Kansas City, MO, United States", "ookla_sponsor": "Example ISP", "ookla_down_mbit": 905.0, "ookla_up_mbit": 37.9, "ookla_latency_ms": 11.2,
				"diverge_down": 0.008, "diverge_up": 0.005, "suggest_down_mbit": 940, "suggest_up_mbit": 39, "note": "the two measurements agree"}}}))
	ctx.Route("POST", "/api/qos/speedtest", m.apiSpeedTestRun, core.Write(), core.Needs("qos.shape"),
		core.Doc("Start a bandwidth test now. It runs in the background for about a minute (twice that when a rerun is needed); poll /api/qos/speedtests for the stage and the result."),
		core.Returns("Started", map[string]any{"started": true, "reason": ""}))
	ctx.Route("POST", "/api/qos/speedtest/apply", m.apiSpeedTestApply, core.Write(), core.Needs("qos.shape"),
		core.Doc("Set the link's download and upload capacity from a test's suggestion, which is the interface's peak during the test (the test plus the load already present)."),
		core.Body(core.Fld("id", "string", true, "The test to take the numbers from", "1790480000000000000")),
		core.Returns("Applied", map[string]any{"ok": true, "download_mbit": 940, "upload_mbit": 39}))
	ctx.Route("GET", "/api/qos/status", m.apiStatus, core.Needs("qos.shape"),
		core.Doc("Get current traffic shaping status including enabled pipes, rules and queue statistics"),
		core.Returns("QoS status", map[string]any{
			"enabled": true,
			"pipes": []map[string]any{
				{"name": "download", "bandwidth_mbps": 100, "queue_bytes": 50000},
			},
			"rules": 5,
		}))
	ctx.Route("GET", "/api/qos/preview", m.apiPreview, core.Needs("qos.shape"),
		core.Doc("Preview firewall rules that would be generated from current QoS settings without applying them"),
		core.Returns("Rules preview", map[string]any{
			"rules": []map[string]any{
				{"priority": 1, "action": "queue", "pipe": "download"},
			},
		}))
	ctx.Route("GET", "/api/qos/rules", m.apiGetRules,
		core.Doc("List all configured traffic shaping rules with their criteria and priority order"),
		core.Returns("QoS rules list", map[string]any{
			"rules": []map[string]any{
				{"id": "rule-1", "name": "Video Streaming", "priority": 1, "enabled": true},
			},
		}))
	ctx.Route("POST", "/api/qos/rules", m.apiCreateRule, core.Write(),
		core.Doc("Create a new traffic shaping rule to prioritize or limit specific network traffic"),
		core.Body(
			core.Fld("name", "string", true, "Rule name", "Video Streaming"),
			core.Fld("priority", "integer", true, "Priority (lower=higher)", 1),
			core.Fld("criteria", "object", true, "Match criteria (protocol, ports, etc)", map[string]any{}),
		),
		core.Returns("Created rule", map[string]any{
			"id": "rule-1",
			"ok": true,
		}))
	ctx.Route("DELETE", "/api/qos/rules/{id}", m.apiDeleteRule, core.Write(),
		core.PathParam("id", "string", "QoS rule ID", "rule-1"),
		core.Doc("Delete a traffic shaping rule and recalculate policy priority"),
		core.Returns("Deletion result", map[string]any{"ok": true}))
	ctx.Panel(core.Panel{ID: "qos", Title: "Priority", Group: "Protect", Order: 105, Icon: "qos", Feature: "qos.shape"})
	return nil
}

func (m *Module) OnConfigChange(map[string]any) error { return m.reconcile() }

func (m *Module) Stop() error { return m.tearDown() }

func (m *Module) Health() core.Health {
	if !core.Bool(m.ctx.Settings(), "active", false) {
		return core.Health{OK: true, Detail: "off; nothing is queued"}
	}
	if err := m.ctx.License().Allowed("qos.shape"); err != nil {
		return core.Health{OK: true, Detail: "needs the pro tier"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastErr != "" {
		return core.Health{OK: false, Detail: m.lastErr}
	}
	if !m.applied {
		return core.Health{OK: false, Detail: "not applied yet"}
	}
	return core.Health{OK: true, Detail: fmt.Sprintf("shaping %.0f down / %.0f up Mbit/s, %d rules",
		m.lastPlan.DownMbit, m.lastPlan.UpMbit, len(valid(m.rules)))}
}

// ---------------------------------------------------------------- applying

func (m *Module) reconcile() error {
	s := m.ctx.Settings()
	want := core.Bool(s, "active", false) && m.ctx.License().Allowed("qos.shape") == nil
	if !want {
		return m.tearDown()
	}
	if m.shaper == nil {
		m.fail("no firewall module; shaping is unavailable")
		return nil
	}
	if !m.shaper.Available() {
		m.fail("no " + m.shaper.Name() + " on this platform; shaping is unavailable")
		return nil
	}
	down := float64(core.Int(s, "download_mbit", 0))
	up := float64(core.Int(s, "upload_mbit", 0))
	if down <= 0 || up <= 0 {
		m.fail("set the download and upload rates the link really carries; without them there is nothing to share out")
		return nil
	}
	lan := strings.TrimSpace(core.Str(s, "lan_interface", ""))
	if lan == "" {
		lan = m.detectLAN()
	}
	if lan == "" {
		m.fail("could not work out which interface faces the local network; set it by hand")
		return nil
	}
	if err := m.shaper.Ready(); err != nil {
		m.fail(err.Error())
		return nil
	}

	head := float64(core.Int(s, "headroom_percent", 7))
	if head < 0 || head > 50 {
		head = 7
	}
	scale := 1 - head/100

	rules := parseRules(core.Strs(s, "rules"))
	m.mu.Lock()
	addrs := m.addrs
	m.mu.Unlock()
	p := m.plan(lan, rules, addrs, scale)
	if err := m.shaper.Apply(p); err != nil {
		m.fail(err.Error())
		return nil
	}

	m.mu.Lock()
	first := !m.applied
	m.applied, m.lastErr, m.lastPlan, m.rules, m.appliedAt = true, "", p, rules, time.Now()
	m.mu.Unlock()
	if first {
		m.ctx.Event("qos", fmt.Sprintf("traffic shaping is on: %.0f Mbit/s down, %.0f up, %d rules",
			p.DownMbit, p.UpMbit, len(valid(rules))), map[string]any{"down": p.DownMbit, "up": p.UpMbit})
	}
	return nil
}

func (m *Module) fail(msg string) {
	m.mu.Lock()
	changed := m.lastErr != msg
	m.lastErr = msg
	m.mu.Unlock()
	if changed {
		m.ctx.Log.Warn("traffic shaping not applied", "reason", msg)
	}
}

func (m *Module) tearDown() error {
	m.mu.Lock()
	was := m.applied
	m.applied, m.lastErr = false, ""
	m.mu.Unlock()
	if !was {
		return nil
	}
	if m.shaper != nil {
		m.shaper.Clear()
	}
	m.ctx.Event("qos", "traffic shaping is off; the link is unmanaged again", nil)
	return nil
}

// isLocal says whether an address rule names something on this network. A
// CIDR counts as local when its first address does, which is what an operator
// means by writing one.
func (m *Module) isLocal(s string) bool {
	if m.identity == nil {
		return true // no better information; a bare address most often means a device here
	}
	ip := s
	if i, _, err := net.ParseCIDR(s); err == nil {
		ip = i.String()
	}
	return m.identity.IsLocal(ip)
}

// detectLAN picks the interface holding a local network, which is where
// addresses are still untranslated and a rule can name a device here.
func (m *Module) detectLAN() string {
	if m.identity == nil {
		return ""
	}
	var nets []*net.IPNet
	for _, c := range m.identity.LocalNetworks() {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err != nil {
				continue
			}
			for _, n := range nets {
				if n.Contains(ip) {
					return i.Name
				}
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------- names

// resolve keeps the address tables for domain rules current. A pf table holds
// addresses, so a rule naming a service matches the addresses this network has
// actually been seen using for it: the server names in handshakes and the
// answers the resolver gave.
func (m *Module) resolve() error {
	rules := parseRules(core.Strs(m.ctx.Settings(), "rules"))
	want := map[string]bool{}
	for _, r := range valid(rules) {
		if !r.IsHost {
			want[r.Match] = true
		}
	}
	if len(want) == 0 {
		return nil
	}
	found := map[string]map[string]bool{}
	for name := range want {
		found[name] = map[string]bool{}
	}
	add := func(host, ip string) {
		host = strings.TrimSuffix(strings.ToLower(host), ".")
		for name := range want {
			if host == name || strings.HasSuffix(host, "."+name) {
				found[name][ip] = true
			}
		}
	}
	since := time.Now().Add(-7 * 24 * time.Hour).Unix()
	if rows, err := m.ctx.Store.Rows(
		`SELECT sni, dst_ip FROM tls_sessions WHERE ts >= ? AND sni <> '' GROUP BY sni, dst_ip LIMIT 50000`, since); err == nil {
		for _, r := range rows {
			s, _ := r["sni"].(string)
			ip, _ := r["dst_ip"].(string)
			if s != "" && ip != "" {
				add(s, ip)
			}
		}
	}
	if rows, err := m.ctx.Store.Rows(`SELECT ip, name FROM dns_names WHERE name <> '' LIMIT 50000`); err == nil {
		for _, r := range rows {
			ip, _ := r["ip"].(string)
			n, _ := r["name"].(string)
			if ip != "" && n != "" {
				add(n, ip)
			}
		}
	}
	out := map[string][]string{}
	for name, set := range found {
		for ip := range set {
			out[name] = append(out[name], ip)
		}
	}
	m.mu.Lock()
	changed := len(out) != len(m.addrs)
	if !changed {
		for k, v := range out {
			if len(v) != len(m.addrs[k]) {
				changed = true
				break
			}
		}
	}
	m.addrs = out
	m.mu.Unlock()
	if changed {
		return m.reconcile()
	}
	return nil
}

// ---------------------------------------------------------------- API

func (m *Module) apiStatus(r *core.Req) (any, error) {
	s := m.ctx.Settings()
	m.mu.Lock()
	applied, err, p, rules, at := m.applied, m.lastErr, m.lastPlan, m.rules, m.appliedAt
	addrs := map[string]int{}
	for k, v := range m.addrs {
		addrs[k] = len(v)
	}
	m.mu.Unlock()
	if rules == nil {
		rules = parseRules(core.Strs(s, "rules"))
	}
	var queues []map[string]any
	if m.shaper != nil {
		stats, _ := m.shaper.Stats()
		for _, q := range stats {
			queues = append(queues, map[string]any{"queue": q.Queue, "name": q.Name, "detail": q.Detail})
		}
	}
	return map[string]any{
		"active":    core.Bool(s, "active", false),
		"applied":   applied,
		"error":     err,
		"since":     at.Unix(),
		"down_mbit": p.DownMbit, "up_mbit": p.UpMbit,
		"rules":    rules,
		"resolved": addrs,
		"queues":   queues,
		"note":     "Weights are shares, not reservations: a class only holds anything back when something else wants the link at the same moment. Download shaping is blunter than upload, because those packets have already crossed the carrier's bottleneck by the time this firewall sees them.",
	}, nil
}

func (m *Module) apiPreview(r *core.Req) (any, error) {
	s := m.ctx.Settings()
	lan := strings.TrimSpace(core.Str(s, "lan_interface", ""))
	if lan == "" {
		lan = m.detectLAN()
	}
	rules := parseRules(core.Strs(s, "rules"))
	m.mu.Lock()
	addrs := m.addrs
	m.mu.Unlock()
	text, tables := "", map[string][]string{}
	if m.shaper != nil {
		text, tables = m.shaper.Render(m.plan(lan, rules, addrs, 1))
	}
	counts := map[string]int{}
	for t, a := range tables {
		counts[t] = len(a)
	}
	return map[string]any{"lan": lan, "rules": rules, "anchor": text, "tables": counts}, nil
}

// plan turns the settings and the rules into what the shaper applies. scale
// takes the headroom off the link rates.
func (m *Module) plan(lan string, rules []Rule, addrs map[string][]string, scale float64) core.ShapePlan {
	s := m.ctx.Settings()
	def := Class(core.Str(s, "default_class", "normal"))
	if !def.valid() {
		def = Normal
	}
	p := core.ShapePlan{
		LAN:      lan,
		DownMbit: float64(core.Int(s, "download_mbit", 0)) * scale, UpMbit: float64(core.Int(s, "upload_mbit", 0)) * scale,
		WeightHigh: core.Int(s, "weight_high", 70), WeightNormal: core.Int(s, "weight_normal", 25),
		WeightLow: core.Int(s, "weight_low", 5), DefaultClass: string(def),
	}
	for _, r := range valid(rules) {
		a := []string{r.Match}
		if !r.IsHost {
			a = addrs[r.Match]
		}
		// A device here is the source going out; something out there is the
		// reverse. A name is always out there. An address is whichever side
		// of the local networks it falls.
		p.Rules = append(p.Rules, core.ShapeRule{Key: r.Match, Label: strings.TrimSpace(r.Raw), Addrs: a,
			Local: r.IsHost && m.isLocal(r.Match), Class: string(r.Class), CeilingMbit: r.Ceiling})
	}
	return p
}
