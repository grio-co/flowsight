package core

// SmartSearch, the whole-of-FlowSight half. The top bar filters the page in
// view as the operator types; this answers "where else is this?": the
// devices, DNS names, domains, applications, findings, policies, settings and
// pages that match, each with links to every page that shows the same thing,
// so a search for a phone's name offers its device page, its sessions and its
// DNS lookups side by side.
//
// Everything here reads small tables: the per-hour rollups rather than the
// flow log, so a query costs milliseconds and can run on every keystroke.

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

type searchLink struct {
	Label string `json:"label"`
	Href  string `json:"href"`
}

type searchHit struct {
	Title string       `json:"title"`
	Sub   string       `json:"sub,omitempty"`
	Href  string       `json:"href"`
	Links []searchLink `json:"links,omitempty"`
	score float64
}

type searchGroup struct {
	Kind    string      `json:"kind"`
	Title   string      `json:"title"`
	Results []searchHit `json:"results"`
}

// matchScore ranks a candidate string against the query terms: every term
// must appear; an exact match beats a prefix beats a substring.
func matchScore(q []string, fields ...string) float64 {
	hay := strings.ToLower(strings.Join(fields, " \x00 "))
	best := 0.0
	for _, t := range q {
		if !strings.Contains(hay, t) {
			return 0
		}
	}
	for _, f := range fields {
		f = strings.ToLower(f)
		whole := strings.Join(q, " ")
		switch {
		case f == whole:
			best = max(best, 3)
		case strings.HasPrefix(f, whole):
			best = max(best, 2)
		case strings.Contains(f, whole):
			best = max(best, 1.5)
		}
	}
	return max(best, 1)
}

func likeArg(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(strings.ToLower(s)) + "%"
}

func esc(s string) string { return url.QueryEscape(s) }

func sOf(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	}
	return fmt.Sprint(v)
}

func nOf(v any) float64 {
	switch t := v.(type) {
	case int64:
		return float64(t)
	case float64:
		return t
	}
	return 0
}

func (c *Core) apiSearch(r *Req) (any, error) {
	raw, err := r.QSafe("q", "", 120)
	if err != nil {
		return nil, err
	}
	raw = strings.TrimSpace(raw)
	limit := r.QInt("limit", 8, 1, 30)
	terms := strings.Fields(strings.ToLower(raw))
	if len([]rune(raw)) < 2 || len(terms) == 0 {
		return map[string]any{"q": raw, "groups": []searchGroup{}}, nil
	}
	// SQL narrows by the longest term; matchScore checks them all.
	key := terms[0]
	for _, t := range terms {
		if len(t) > len(key) {
			key = t
		}
	}
	like := likeArg(key)
	day := time.Now().Add(-24 * time.Hour).Unix()
	month := time.Now().Add(-30 * 24 * time.Hour).Unix()
	var groups []searchGroup
	add := func(kind, title string, hits []searchHit) {
		sort.SliceStable(hits, func(i, j int) bool { return hits[i].score > hits[j].score })
		if len(hits) > limit {
			hits = hits[:limit]
		}
		if len(hits) > 0 {
			groups = append(groups, searchGroup{Kind: kind, Title: title, Results: hits})
		}
	}
	deviceLinks := func(ip string) []searchLink {
		return []searchLink{{"Device", "#host/" + esc(ip)}, {"Sessions", "#flows?ip=" + esc(ip)},
			{"DNS lookups", "#dns?client=" + esc(ip)}, {"Findings", "#host/" + esc(ip)}}
	}

	// Devices: the inventory joined to the host table, by name, address,
	// hardware address or maker.
	{
		rows, _ := c.Store.Rows(`SELECT h.ip, h.mac, h.name, h.vendor, h.last_seen, d.hostname, d.zone, d.class
			FROM hosts h LEFT JOIN devices d ON lower(d.mac)=lower(h.mac)
			WHERE h.last_seen>=? AND h.is_local=1 AND (lower(h.ip) LIKE ? ESCAPE '\' OR lower(h.mac) LIKE ? ESCAPE '\'
			  OR lower(h.name) LIKE ? ESCAPE '\' OR lower(h.vendor) LIKE ? ESCAPE '\' OR lower(d.hostname) LIKE ? ESCAPE '\')
			ORDER BY h.last_seen DESC LIMIT 200`, month, like, like, like, like, like)
		// One device has several address rows (IPv4, IPv6, old leases):
		// merge them, and take the name and the IPv4 address from
		// whichever row has them.
		type devAgg struct {
			ip, mac, name, vendor, zone, host string
			fields                            []string
		}
		var order []string
		devs := map[string]*devAgg{}
		for _, row := range rows {
			ip, mac := sOf(row["ip"]), strings.ToLower(sOf(row["mac"]))
			k := mac
			if k == "" {
				k = ip
			}
			d := devs[k]
			if d == nil {
				d = &devAgg{ip: ip, mac: mac}
				devs[k] = d
				order = append(order, k)
			}
			if strings.Contains(d.ip, ":") && !strings.Contains(ip, ":") {
				d.ip = ip // a device page reads best under its IPv4 address
			}
			if d.name == "" {
				d.name = sOf(row["name"])
			}
			if d.host == "" {
				d.host = sOf(row["hostname"])
			}
			if d.vendor == "" {
				d.vendor = sOf(row["vendor"])
			}
			if d.zone == "" {
				d.zone = sOf(row["zone"])
			}
			d.fields = append(d.fields, ip)
		}
		var hits []searchHit
		for _, k := range order {
			d := devs[k]
			name := d.name
			if name == "" {
				name = d.host
			}
			sc := matchScore(terms, append([]string{name, d.mac, d.vendor, d.host}, d.fields...)...)
			if sc == 0 {
				continue
			}
			title := name
			if title == "" {
				title = d.ip
			}
			sub := strings.Join(nonEmpty(d.ip, d.mac, d.vendor, d.zone), " · ")
			hits = append(hits, searchHit{Title: title, Sub: sub, Href: "#host/" + esc(d.ip), Links: deviceLinks(d.ip), score: sc + 0.5})
		}
		add("devices", "Devices", hits)
	}

	// Device names FlowSight put in DNS.
	{
		var recs []struct {
			FQDN    string   `json:"fqdn"`
			Display string   `json:"display"`
			Addrs   []string `json:"addresses"`
		}
		c.Store.KVGet("dns.local_names", &recs)
		var hits []searchHit
		for _, rec := range recs {
			sc := matchScore(terms, rec.FQDN, rec.Display, strings.Join(rec.Addrs, " "))
			if sc == 0 || len(rec.Addrs) == 0 {
				continue
			}
			hits = append(hits, searchHit{Title: rec.FQDN, Sub: strings.Join(rec.Addrs, ", "), Href: "#modules/dns?tab=names",
				Links: append([]searchLink{{"Device names", "#modules/dns?tab=names"}}, deviceLinks(rec.Addrs[0])[:2]...), score: sc})
		}
		add("names", "DNS names", hits)
	}

	// Domains: looked up (DNS) or connected to (sessions) in the last day.
	{
		type dom struct {
			queries, flows float64
			clients        map[string]bool
		}
		doms := map[string]*dom{}
		get := func(d string) *dom {
			if doms[d] == nil {
				doms[d] = &dom{clients: map[string]bool{}}
			}
			return doms[d]
		}
		rows, _ := c.Store.Rows(`SELECT domain, client, SUM(queries) AS n FROM rollup_dns WHERE bucket>=? AND lower(domain) LIKE ? ESCAPE '\'
			GROUP BY domain, client ORDER BY n DESC LIMIT 400`, day, like)
		for _, row := range rows {
			d := get(sOf(row["domain"]))
			d.queries += nOf(row["n"])
			d.clients[sOf(row["client"])] = true
		}
		rows, _ = c.Store.Rows(`SELECT domain, src_ip, SUM(flows) AS n FROM rollup_domain WHERE bucket>=? AND lower(domain) LIKE ? ESCAPE '\'
			GROUP BY domain, src_ip ORDER BY n DESC LIMIT 400`, day, like)
		for _, row := range rows {
			d := get(sOf(row["domain"]))
			d.flows += nOf(row["n"])
			d.clients[sOf(row["src_ip"])] = true
		}
		var hits []searchHit
		for name, d := range doms {
			sc := matchScore(terms, name)
			if sc == 0 {
				continue
			}
			hits = append(hits, searchHit{Title: name,
				Sub:  fmt.Sprintf("%s lookups · %s sessions · %d devices, last day", humanN(d.queries), humanN(d.flows), len(d.clients)),
				Href: "#dns?domain=" + esc(name),
				Links: []searchLink{{"DNS lookups", "#dns?domain=" + esc(name)}, {"Sessions", "#flows?domain=" + esc(name)},
					{"Web", "#web?domain=" + esc(name)}},
				score: sc + (d.queries+d.flows)/(1+d.queries+d.flows)})
		}
		add("domains", "Domains", hits)
	}

	// Applications seen in the last day.
	{
		rows, _ := c.Store.Rows(`SELECT app, MAX(category) AS category, SUM(flows) AS n, COUNT(DISTINCT src_ip) AS devices
			FROM rollup_app WHERE bucket>=? AND (lower(app) LIKE ? ESCAPE '\' OR lower(category) LIKE ? ESCAPE '\')
			GROUP BY app ORDER BY n DESC LIMIT 60`, day, like, like)
		var hits []searchHit
		for _, row := range rows {
			app := sOf(row["app"])
			sc := matchScore(terms, app, sOf(row["category"]))
			if sc == 0 {
				continue
			}
			hits = append(hits, searchHit{Title: app, Sub: strings.Join(nonEmpty(sOf(row["category"]),
				fmt.Sprintf("%s sessions on %d devices, last day", humanN(nOf(row["n"])), int(nOf(row["devices"])))), " · "),
				Href:  "#app/" + esc(app),
				Links: []searchLink{{"Application", "#app/" + esc(app)}, {"Sessions", "#flows?app=" + esc(app)}, {"Control", "#appcontrol"}},
				score: sc})
		}
		add("apps", "Applications", hits)
	}

	// Open findings.
	{
		rows, _ := c.Store.Rows(`SELECT id, module, severity, subject, title, detail FROM findings WHERE resolved_ts IS NULL AND
			(lower(title) LIKE ? ESCAPE '\' OR lower(subject) LIKE ? ESCAPE '\' OR lower(detail) LIKE ? ESCAPE '\' OR lower(attrs) LIKE ? ESCAPE '\')
			ORDER BY ts DESC LIMIT 100`, like, like, like, like)
		var hits []searchHit
		for _, row := range rows {
			sc := matchScore(terms, sOf(row["title"]), sOf(row["subject"]), sOf(row["detail"]))
			if sc == 0 {
				// Matched only inside the structured detail: worth showing for
				// an address or hardware address, noise for a word.
				if !strings.ContainsAny(raw, "0123456789:") {
					continue
				}
				sc = 0.5
			}
			links := []searchLink{{"Findings", "#findings"}}
			subj := sOf(row["subject"])
			if looksLikeIP(subj) {
				links = append(links, searchLink{"Device", "#host/" + esc(subj)})
			}
			hits = append(hits, searchHit{Title: sOf(row["title"]), Sub: sOf(row["severity"]) + " · " + sOf(row["module"]) + " · " + subj,
				Href: links[len(links)-1].Href, Links: links, score: sc})
		}
		add("findings", "Open findings", hits)
	}

	// Policies, groups and schedules.
	if svc, ok := c.Services["policy_doc"].(interface{ Doc() *PolicyDoc }); ok {
		if doc := svc.Doc(); doc != nil {
			var hits []searchHit
			for _, p := range doc.Policies {
				if sc := matchScore(terms, p.Name, p.Description); sc > 0 {
					hits = append(hits, searchHit{Title: p.Name, Sub: "policy · " + p.Action + " · " + p.Description, Href: "#policy",
						Links: []searchLink{{"Policies", "#policy"}, {"Matches", "#policy-matches?name=" + esc(p.Name)}}, score: sc})
				}
			}
			for name, g := range doc.Groups {
				if sc := matchScore(terms, name, g.Description, strings.Join(g.Members, " ")); sc > 0 {
					hits = append(hits, searchHit{Title: name, Sub: fmt.Sprintf("group · %d members · %s", len(g.Members), g.Description),
						Href: "#groups", Links: []searchLink{{"Groups & Schedules", "#groups"}}, score: sc})
				}
			}
			for name, s := range doc.Schedules {
				if sc := matchScore(terms, name, s.Description); sc > 0 {
					hits = append(hits, searchHit{Title: name, Sub: "schedule · " + s.Description, Href: "#groups",
						Links: []searchLink{{"Groups & Schedules", "#groups"}}, score: sc})
				}
			}
			add("policy", "Policies and groups", hits)
		}
	}

	// Settings: every module setting by its label, key or help.
	{
		c.mu.RLock()
		infos := make([]ModuleInfo, 0, len(c.Infos))
		for _, in := range c.Infos {
			infos = append(infos, in)
		}
		c.mu.RUnlock()
		var hits []searchHit
		for _, in := range infos {
			if sc := matchScore(terms, in.Name, in.Description); sc > 0 {
				hits = append(hits, searchHit{Title: "Settings › " + in.Name, Sub: in.Description, Href: "#modules/" + esc(in.Name), score: sc})
			}
			for _, f := range in.Schema {
				if sc := matchScore(terms, f.Label, f.Key, f.Help); sc > 0 {
					hits = append(hits, searchHit{Title: f.Label, Sub: "Settings › " + in.Name + " · " + f.Key, Href: "#modules/" + esc(in.Name), score: sc})
				}
			}
		}
		add("settings", "Settings", hits)
	}

	// Pages.
	{
		c.mu.RLock()
		ps := append([]Panel(nil), c.Panels...)
		c.mu.RUnlock()
		ps = append(ps, Panel{ID: "findings", Title: "Findings", Group: "Administration"}, Panel{ID: "events", Title: "Events", Group: "Administration"},
			Panel{ID: "system", Title: "Status", Group: "Administration"}, Panel{ID: "modules", Title: "Settings", Group: "Administration"})
		var hits []searchHit
		for _, p := range ps {
			if p.Detail {
				continue
			}
			if sc := matchScore(terms, p.Title, p.ID, p.Group); sc > 0 {
				hits = append(hits, searchHit{Title: p.Title, Sub: p.Group, Href: "#" + p.ID, score: sc})
			}
		}
		add("pages", "Pages", hits)
	}
	return map[string]any{"q": raw, "groups": groups}, nil
}

func nonEmpty(s ...string) []string {
	var out []string
	for _, x := range s {
		if strings.TrimSpace(x) != "" {
			out = append(out, x)
		}
	}
	return out
}

func looksLikeIP(s string) bool {
	return strings.Count(s, ".") == 3 || strings.Count(s, ":") >= 2
}

func humanN(f float64) string {
	switch {
	case f >= 1e6:
		return fmt.Sprintf("%.1fM", f/1e6)
	case f >= 1e4:
		return fmt.Sprintf("%.0fk", f/1e3)
	case f >= 1e3:
		return fmt.Sprintf("%.1fk", f/1e3)
	}
	return fmt.Sprintf("%.0f", f)
}
