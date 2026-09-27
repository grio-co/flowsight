// Package advisor finds the problems a person notices on a device ("my phone
// can't browse", "notifications stopped") whose cause is a DNS answer rather
// than a firewall rule: the network passes every packet, yet a resolver
// quietly turns a feature off. It reads the DNS log FlowSight already keeps
// (the gateway resolver and any connected Pi-hole) and raises one finding per
// device and problem, with what the person sees, which resolver answered,
// from which list, and how to fix it. Findings resolve on their own once the
// failing answers stop.
package advisor

import (
	"fmt"

	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

type Module struct {
	ctx     *core.Context
	mu      sync.Mutex
	lastRun time.Time
	lastErr string
	open    int
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name: "advisor", Version: "1.0",
		Description: "Device advisories: DNS answers that break something on a device (Private Relay, connectivity checks, time, certificates, push, updates), with the fix.",
		After:       []string{"dns", "pihole", "identity"},
		Defaults:    map[string]any{"window_minutes": 15, "ignore_clients": []string{}},
		Schema: []core.SettingField{
			{Key: "window_minutes", Label: "Look-back window (minutes)", Type: "int",
				Help: "An advisory stays open while failing answers keep arriving inside this window, and closes once they stop."},
			{Key: "ignore_clients", Label: "Ignore these clients", Type: "list",
				Help: "Addresses whose DNS answers are not advised on, such as a lab machine that is meant to be locked down."},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	ctx.Every("scan", time.Minute, m.scan, core.Delayed())
	ctx.Route("GET", "/api/advisor/status", m.apiStatus,
		core.Doc("The device advisory catalogue (what each rule watches, what the person sees, how to fix it) and the last scan"),
		core.Returns("Advisor status", map[string]any{
			"last_run": 1790485200, "open": 1, "window_minutes": 15,
			"rules": []map[string]any{{"kind": "private_relay_blocked", "severity": "high", "title": "iCloud Private Relay is blocked",
				"effect": "Safari can stall…", "fix": "Allow mask.icloud.com…", "devices": "iPhone, iPad and Mac", "names": []string{"mask.icloud.com"}}},
		}))
	return nil
}

func (m *Module) Health() core.Health {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastErr != "" {
		return core.Health{OK: false, Detail: m.lastErr}
	}
	if m.lastRun.IsZero() {
		return core.Health{OK: true, Detail: "first scan pending"}
	}
	return core.Health{OK: true, Detail: fmt.Sprintf("%d open advisories; scanned %s ago", m.open, time.Since(m.lastRun).Round(time.Second))}
}

// agg is one (client, name, answer) group from the DNS log.
type agg struct {
	Client, Domain, Action, List, Rcode, Source string
	Count                                       int
	First, Last                                 int64
}

type device struct {
	Key, IP, Name, MAC, Vendor string
	Addresses                  []string
}

// advice is one finding before it is written.
type advice struct {
	Kind, Severity, Title, Detail, Fingerprint, Subject string
	Attrs                                               map[string]any
}

func (m *Module) scan() error {
	s := m.ctx.Settings()
	window := time.Duration(core.Int(s, "window_minutes", 15)) * time.Minute
	since := time.Now().Add(-window).Unix()
	ignore := map[string]bool{"127.0.0.1": true, "::1": true}
	for _, c := range core.Strs(s, "ignore_clients") {
		ignore[strings.TrimSpace(c)] = true
	}
	st := m.ctx.Store
	rows, err := st.Rows(`SELECT client, domain, action, COALESCE(list,'') AS list, COALESCE(rcode,'') AS rcode,
		COALESCE(source,'') AS source, COUNT(*) AS n, MIN(ts) AS first, MAX(ts) AS last
		FROM dns WHERE ts>=? AND (action<>'pass' OR rcode IN ('NXDOMAIN','SERVFAIL','REFUSED'))
		GROUP BY client, domain, action, list, rcode, source`, since)
	if err != nil {
		m.setErr(err.Error())
		return err
	}
	var groups []agg
	for _, r := range rows {
		a := agg{Client: str(r["client"]), Domain: strings.ToLower(str(r["domain"])), Action: str(r["action"]),
			List: str(r["list"]), Rcode: str(r["rcode"]), Source: str(r["source"]),
			Count: int(num(r["n"])), First: int64(num(r["first"])), Last: int64(num(r["last"]))}
		if !ignore[a.Client] {
			groups = append(groups, a)
		}
	}
	tots, err := st.Rows(`SELECT client, COUNT(*) AS n, SUM(CASE WHEN rcode IN ('SERVFAIL','REFUSED') THEN 1 ELSE 0 END) AS bad,
		MAX(COALESCE(source,'')) AS source FROM dns WHERE ts>=? GROUP BY client`, since)
	if err != nil {
		m.setErr(err.Error())
		return err
	}
	totals := map[string][2]int{}
	sources := map[string]string{}
	for _, r := range tots {
		c := str(r["client"])
		if !ignore[c] {
			totals[c] = [2]int{int(num(r["n"])), int(num(r["bad"]))}
			sources[c] = str(r["source"])
		}
	}
	out := evaluate(groups, totals, sources, m.deviceFor, int(window/time.Minute))
	keep := map[string]bool{}
	for _, a := range out {
		keep[a.Fingerprint] = true
		if _, err := st.AddFindingWith("advisor", a.Kind, a.Severity, a.Subject, a.Title, a.Detail, a.Fingerprint, a.Attrs); err != nil {
			m.setErr(err.Error())
			return err
		}
	}
	if _, err := st.ResolveFindings("advisor", keep); err != nil {
		m.setErr(err.Error())
		return err
	}
	m.mu.Lock()
	m.lastRun, m.lastErr, m.open = time.Now(), "", len(out)
	m.mu.Unlock()
	return nil
}

func (m *Module) setErr(e string) {
	m.mu.Lock()
	m.lastErr = e
	m.mu.Unlock()
}

// deviceFor gathers what is known about the device behind an address: its
// MAC, name, vendor, and its other addresses, so the IPv4 and IPv6 queries
// of one phone count as one phone.
func (m *Module) deviceFor(ip string) device {
	d := device{Key: ip, IP: ip}
	rows, _ := m.ctx.Store.Rows(`SELECT COALESCE(mac,'') AS mac, COALESCE(name,'') AS name, COALESCE(vendor,'') AS vendor FROM hosts WHERE ip=?`, ip)
	if len(rows) > 0 {
		d.MAC, d.Name, d.Vendor = str(rows[0]["mac"]), str(rows[0]["name"]), str(rows[0]["vendor"])
	}
	if d.Name == "" {
		if n, _ := m.ctx.Store.Rows(`SELECT name FROM dns_names WHERE ip=?`, ip); len(n) > 0 {
			d.Name = str(n[0]["name"])
		}
	}
	if d.MAC != "" {
		d.Key = strings.ToLower(d.MAC)
		if all, _ := m.ctx.Store.Rows(`SELECT ip FROM hosts WHERE mac=? ORDER BY last_seen DESC LIMIT 16`, d.MAC); len(all) > 0 {
			for _, r := range all {
				d.Addresses = append(d.Addresses, str(r["ip"]))
			}
		}
	}
	return d
}

// hit collects the DNS log groups behind one advisory.
type hit struct {
	rule        *rule
	dev         device
	domains     map[string]int
	lists       map[string]int
	rcodes      map[string]int
	sources     map[string]int
	count       int
	first, last int64
}

func newHit(r *rule, d device, first int64) *hit {
	return &hit{rule: r, dev: d, domains: map[string]int{}, lists: map[string]int{}, rcodes: map[string]int{}, sources: map[string]int{}, first: first}
}

func (h *hit) add(g agg) {
	h.count += g.Count
	h.domains[g.Domain] += g.Count
	if g.List != "" {
		h.lists[g.List] += g.Count
	}
	rc := g.Rcode
	if rc == "" || rc == "NOERROR" {
		rc = g.Action // a blocked answer served as 0.0.0.0 says NOERROR; "block" is the truth
	}
	h.rcodes[rc] += g.Count
	h.sources[g.Source] += g.Count
	if g.First < h.first || h.first == 0 {
		h.first = g.First
	}
	if g.Last > h.last {
		h.last = g.Last
	}
}

func top(m map[string]int) string {
	best, n := "", -1
	for k, v := range m {
		if v > n || (v == n && k < best) {
			best, n = k, v
		}
	}
	return best
}

func keys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if m[out[i]] != m[out[j]] {
			return m[out[i]] > m[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}

func (h *hit) advice(windowMin int) advice {
	d := h.dev
	domain := top(h.domains)
	list, source, rcode := top(h.lists), top(h.sources), top(h.rcodes)
	answered := strings.ToUpper(rcode)
	if rcode == "block" {
		answered = "a block"
	}
	how := fmt.Sprintf("%s answered %s", resolverName(source), answered)
	if list != "" {
		how += " (" + list + ")"
	}
	var kind, sev, title, effect, fix, devices string
	if h.rule != nil {
		kind, sev, title, effect, devices = h.rule.Kind, h.rule.Severity, h.rule.Title, h.rule.Effect, h.rule.Devices
		fix = fixFor(h.rule, source, list)
	} else {
		kind, sev, title = kindRetryStorm, "low", "An app keeps retrying a blocked name"
		effect = "Whatever needs " + domain + " on this device is not working, and it keeps retrying, which costs battery and data."
		fix = "Decide whether " + domain + " should be allowed. If the block is intended, the feature that needs it will not work on this device; if it is not, allow the name on " + resolverName(source) + "."
		devices = "this device"
	}
	names := keys(h.domains)
	shown := names
	if len(shown) > 3 {
		shown = shown[:3]
	}
	detail := fmt.Sprintf("%s asked for %s %d times in the last %d minutes; %s. %s",
		label(d), strings.Join(shown, ", "), h.count, windowMin, how, effect)
	fp := "advisor:" + kind + ":" + d.Key
	if h.rule == nil {
		fp += ":" + domain
	}
	a := advice{
		Kind: kind, Severity: sev, Title: title, Detail: detail, Subject: d.IP, Fingerprint: fp,
		Attrs: map[string]any{
			"who":   who(d),
			"what":  map[string]any{"kind": "dns", "domain": domain, "domains": names, "queries": h.count},
			"where": map[string]any{"name": resolverName(source), "ip": resolverIP(source), "kind": "resolver", "list": list},
			"why": map[string]any{"kind": kind, "count": h.count, "window_min": windowMin, "answer": answered, "list": list,
				"resolver": source, "first": h.first, "last": h.last, "effect": effect, "fix": fix, "devices": devices},
		},
	}
	why := a.Attrs["why"].(map[string]any)
	if t := allowTarget(source, list, names); t != nil {
		why["allow"] = t
	}
	if t := switchTarget(h.rule, source, list); t != nil {
		why["switch"] = t
	}
	return a
}

// allowTarget says where a one-click "allow" would go: a connected Pi-hole
// that blocked the names from a list (not a built-in special domain, which
// has its own switch).
func allowTarget(source, list string, names []string) map[string]any {
	if !strings.HasPrefix(source, "pihole:") || list == "" || list == "pihole special domain" {
		return nil
	}
	return map[string]any{"server": resolverIP(source), "domains": names}
}

// switchTarget names the Pi-hole setting behind a built-in "special
// domain" answer, so the page can offer to flip it where it lives.
func switchTarget(r *rule, source, list string) map[string]any {
	if r == nil || r.Kind != "private_relay_blocked" || list != "pihole special domain" || !strings.HasPrefix(source, "pihole:") {
		return nil
	}
	return map[string]any{"server": resolverIP(source), "key": "dns.specialDomains.iCloudPrivateRelay", "value": false,
		"label": "Let Private Relay work on this Pi-hole"}
}

func label(d device) string {
	if d.Name != "" {
		return d.Name + " (" + d.IP + ")"
	}
	return d.IP
}

func who(d device) map[string]any {
	w := map[string]any{"ip": d.IP}
	if d.Name != "" {
		w["name"] = d.Name
	}
	if d.MAC != "" {
		w["mac"] = d.MAC
	}
	if d.Vendor != "" {
		w["vendor"] = d.Vendor
	}
	if len(d.Addresses) > 1 {
		w["addresses"] = d.Addresses
	}
	return w
}

// evaluate turns the DNS log groups into advisories, one per device and
// problem. It is pure so the rules can be tested without a store.
func evaluate(groups []agg, totals map[string][2]int, sources map[string]string, lookup func(string) device, windowMin int) []advice {
	devs := map[string]device{}
	dev := func(ip string) device {
		d, ok := devs[ip]
		if !ok {
			d = lookup(ip)
			if d.Key == "" {
				d.Key, d.IP = ip, ip
			}
			devs[ip] = d
		}
		return d
	}
	hits := map[string]*hit{}
	storm := map[string]*hit{}
	for _, g := range groups {
		d := dev(g.Client)
		if r := ruleFor(g.Domain); r != nil {
			k := r.Kind + "|" + d.Key
			if hits[k] == nil {
				hits[k] = newHit(r, d, g.First)
			}
			hits[k].add(g)
			continue
		}
		// A single name blocked over and over is an app that cannot do
		// something and keeps trying.
		if g.Action == "pass" {
			continue
		}
		k := d.Key + "|" + g.Domain
		if storm[k] == nil {
			storm[k] = newHit(nil, d, g.First)
		}
		storm[k].add(g)
	}
	var out []advice
	for _, h := range hits {
		if h.count >= h.rule.Min {
			out = append(out, h.advice(windowMin))
		}
	}
	for _, h := range storm {
		if h.count >= retryStormMin {
			out = append(out, h.advice(windowMin))
		}
	}
	// Resolution failures: a device whose lookups fail outright.
	byDev := map[string]*[2]int{}
	devOf := map[string]device{}
	for c, t := range totals {
		d := dev(c)
		if byDev[d.Key] == nil {
			byDev[d.Key] = &[2]int{}
			devOf[d.Key] = d
		}
		byDev[d.Key][0] += t[0]
		byDev[d.Key][1] += t[1]
	}
	for k, v := range byDev {
		if v[0] < failingQueryMin || v[1]*100 < failingPctMin*v[0] {
			continue
		}
		d := devOf[k]
		src := sources[d.IP]
		effect := "Names fail to resolve intermittently: pages and apps fail to load, then work on retry."
		out = append(out, advice{
			Kind: kindDNSFailing, Severity: "medium", Subject: d.IP, Fingerprint: "advisor:" + kindDNSFailing + ":" + d.Key,
			Title: "Name lookups are failing",
			Detail: fmt.Sprintf("%s: %d of %d lookups in the last %d minutes failed (SERVFAIL or REFUSED) at %s. %s",
				label(d), v[1], v[0], windowMin, resolverName(src), effect),
			Attrs: map[string]any{
				"who":   who(d),
				"what":  map[string]any{"kind": "dns", "queries": v[0], "failed": v[1]},
				"where": map[string]any{"name": resolverName(src), "ip": resolverIP(src), "kind": "resolver"},
				"why": map[string]any{"kind": kindDNSFailing, "percent": v[1] * 100 / v[0], "threshold": failingPctMin, "window_min": windowMin,
					"effect": effect, "resolver": src,
					"fix": "Check the resolver's upstream servers and DNSSEC setting. If the device uses a Pi-hole directly, check that the Pi-hole reaches its upstream."},
			},
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	return out
}

func (m *Module) apiStatus(r *core.Req) (any, error) {
	m.mu.Lock()
	last, open := m.lastRun, m.open
	m.mu.Unlock()
	var list []map[string]any
	for _, x := range rules {
		names := append(append([]string{}, x.Exact...), prefixStar(x.Suffix)...)
		list = append(list, map[string]any{"kind": x.Kind, "severity": x.Severity, "title": x.Title, "effect": x.Effect,
			"fix": x.Fix, "devices": x.Devices, "names": names, "min": x.Min})
	}
	list = append(list,
		map[string]any{"kind": kindDNSFailing, "severity": "medium", "title": "Name lookups are failing", "devices": "any device",
			"effect": "Pages and apps fail to load at random.", "fix": "Check the resolver's upstream servers and DNSSEC.",
			"names": []string{fmt.Sprintf("%d%% or more of at least %d lookups fail", failingPctMin, failingQueryMin)}},
		map[string]any{"kind": kindRetryStorm, "severity": "low", "title": "An app keeps retrying a blocked name", "devices": "any device",
			"effect": "A feature on the device is not working and keeps retrying.", "fix": "Allow the name, or accept that the feature stays off.",
			"names": []string{fmt.Sprintf("any single blocked name asked for %d times or more", retryStormMin)}})
	lr := int64(0)
	if !last.IsZero() {
		lr = last.Unix()
	}
	return map[string]any{"last_run": lr, "open": open, "window_minutes": core.Int(m.ctx.Settings(), "window_minutes", 15), "rules": list}, nil
}

func prefixStar(s []string) []string {
	out := make([]string, len(s))
	for i, x := range s {
		out[i] = "*" + x
	}
	return out
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

func num(v any) float64 {
	switch t := v.(type) {
	case int64:
		return float64(t)
	case int:
		return float64(t)
	case float64:
		return t
	}
	return 0
}
