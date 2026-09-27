package visibility

// One application, one application category, and the unknown.
//
// The Applications page is a table; a name in it is a link to nowhere
// until this file. An application's page answers what the thing is (the
// notes), who uses it here, where it goes, how much, when, and what policy
// says about it. A category's page does the same for every application in
// the category. And "Unknown", the largest row on most networks, is taken
// apart by what else is known about each flow: the name asked for, the
// port, the network that announces the far end, so the reader sees "TLS to
// apple.com on 5223" instead of one number, and can give a signature a
// name that the pages then use.

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// policyDocReader is the part of the policy module this needs.
type policyDocReader interface{ Doc() *core.PolicyDoc }

func (m *Module) registerAppRoutes(ctx *core.Context) {
	ctx.Route("GET", "/api/visibility/app", m.apiApp,
		core.Query("name", "string", "Application name as nDPI reports it (TLS.Dropbox, QUIC, BitTorrent)", true, "BitTorrent"),
		core.Query("hours", "integer", "Time window in hours (default 24)", false, 24),
		core.Doc("Everything about one application: what it is for and what to look for (curated notes, or the category's), its nDPI category and breed, who uses it, where it goes, ports, countries, how much, when, which policies deny it and how many sessions were blocked"),
		core.Returns("Application detail", map[string]any{
			"app": "BitTorrent", "category": "Download", "breed": "Unsafe",
			"note":         map[string]any{"purpose": "Peer-to-peer file sharing.", "risk": "Heavy sustained upload.", "look_for": []string{"The device running it"}, "source": "curated"},
			"totals":       map[string]any{"flows": 1200, "bytes_in": 5e9, "bytes_out": 9e9, "blocked": 0, "hosts": 1, "first_seen": 1790300000, "last_seen": 1790480000},
			"devices":      []map[string]any{{"ip": "192.168.1.128", "name": "seedbox", "flows": 1200, "bytes_in": 5e9, "bytes_out": 9e9}},
			"domains":      []map[string]any{{"domain": "tracker.example.org", "flows": 40}},
			"destinations": []map[string]any{{"ip": "203.0.113.9", "port": 6881, "proto": "tcp", "country": "NL", "flows": 30, "bytes": 1e8}},
			"ports":        []map[string]any{{"port": 6881, "proto": "tcp", "flows": 900}},
			"countries":    []map[string]any{{"country": "NL", "flows": 300}},
			"visibility":   map[string]any{"opaque": 1100, "sni": 100},
			"timeline":     []map[string]any{{"t": 1790470800, "flows": 60, "bytes_in": 2e8, "bytes_out": 4e8}},
			"policies":     []map[string]any{{"name": "no-torrents", "enabled": true, "action": "block", "by": "app", "members": 3}},
		}))
	ctx.Route("GET", "/api/visibility/app-category", m.apiAppCategory,
		core.Query("name", "string", "nDPI category name (Media, Cloud, SoftwareUpdate…)", true, "Media"),
		core.Query("hours", "integer", "Time window in hours (default 24)", false, 24),
		core.Doc("One application category: what it covers, every application in it with sessions, bytes, hosts and breed, the devices that use it most, and the policies that deny the category"),
		core.Returns("Category detail", map[string]any{
			"category": "Media", "note": map[string]any{"purpose": "Audio and video.", "risk": "Volume."},
			"apps":     []map[string]any{{"app": "YouTube", "breed": "Fun", "flows": 500, "bytes_in": 3e9, "bytes_out": 1e8, "hosts": 4}},
			"devices":  []map[string]any{{"ip": "192.168.1.10", "name": "Living room TV", "flows": 300, "bytes_in": 2e9}},
			"totals":   map[string]any{"flows": 800, "bytes_in": 4e9, "bytes_out": 2e8, "hosts": 5},
			"policies": []map[string]any{{"name": "kids-evening", "enabled": true, "action": "block", "by": "app_category", "members": 2}},
		}))
	ctx.Route("GET", "/api/visibility/unknown", m.apiUnknown,
		core.Query("hours", "integer", "Time window in hours (default 24)", false, 24),
		core.Query("limit", "integer", "Signatures to return (default 100)", false, 100),
		core.Doc("The catalogue of what nDPI could not name, grouped by signature: the name asked for or the far end's network, the port and protocol. Each row carries a derived label, the devices using it, sessions, bytes and first/last seen, and the name the operator gave it, if any"),
		core.Returns("Unknown traffic catalogue", map[string]any{
			"total_flows": 4200, "signatures": []map[string]any{{"signature": "tcp/5223 apple.com", "label": "TLS to apple.com on 5223 (push notifications)", "name": "", "flows": 900, "bytes_in": 1e7, "bytes_out": 2e6, "hosts": 3, "first_seen": 1790300000, "last_seen": 1790480000, "sample_ip": "17.57.144.86", "asn": "714", "devices": []map[string]any{{"ip": "192.168.1.119", "name": "MacBookPro", "flows": 600}}}},
			"named": map[string]any{"udp/40317 23.23.189.0/24": "Echo keepalive"},
		}))
	ctx.Route("POST", "/api/visibility/unknown/name", m.apiUnknownName, core.Write(),
		core.Body(core.Fld("signature", "string", true, "The signature as the catalogue reports it", "udp/40317 amazonaws.com"),
			core.Fld("name", "string", false, "The name to give it; empty forgets a name", "Echo keepalive")),
		core.Doc("Name an unknown signature. The catalogue and the Applications page then show the name; it is remembered in the store"),
		core.Returns("Saved", map[string]any{"ok": true, "named": 3}))
}

const unknownNamesKV = "visibility.unknown_names"

func (m *Module) unknownNames() map[string]string {
	out := map[string]string{}
	_ = m.ctx.Store.KVGet(unknownNamesKV, &out)
	return out
}

// policiesFor lists the policies whose deny list names an application or
// its category, with how many members each reaches.
func (m *Module) policiesFor(app, category string) []map[string]any {
	pm, ok := m.ctx.Service("policy_doc").(policyDocReader)
	if !ok {
		return nil
	}
	doc := pm.Doc()
	if doc == nil {
		return nil
	}
	res, _ := m.ctx.Service("member_resolver").(core.MemberResolver)
	var out []map[string]any
	for i := range doc.Policies {
		p := &doc.Policies[i]
		by := ""
		for _, a := range p.Deny.Apps {
			if app != "" && strings.EqualFold(a, app) {
				by = "app"
			}
		}
		for _, c := range p.Deny.AppCategories {
			if category != "" && strings.EqualFold(c, category) && by == "" {
				by = "app_category"
			}
		}
		allowed := false
		for _, a := range p.Allow.Apps {
			if app != "" && strings.EqualFold(a, app) {
				allowed = true
			}
		}
		if by == "" && !allowed {
			continue
		}
		row := map[string]any{"name": p.Name, "enabled": p.Enabled, "action": p.Action, "by": by, "schedule": p.Schedule, "allowed": allowed}
		if res != nil {
			row["members"] = len(doc.Members(p, res))
		}
		out = append(out, row)
	}
	return out
}

func (m *Module) apiApp(r *core.Req) (any, error) {
	app := strings.TrimSpace(r.Q("name", ""))
	if app == "" {
		return nil, core.BadRequest("name is required")
	}
	hours := r.QInt("hours", 24, 1, 24*30)
	since := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	st := m.ctx.Store
	m.mu.Lock()
	info := m.apps[app]
	m.mu.Unlock()
	category := info.Category
	if category == "" {
		if rows, err := st.Rows(`SELECT category FROM flows WHERE app=? AND category<>'' ORDER BY ts DESC LIMIT 1`, app); err == nil && len(rows) > 0 {
			category, _ = rows[0]["category"].(string)
		}
	}
	out := map[string]any{"app": app, "category": category, "breed": info.Breed, "hours": hours,
		"note": noteFor(app, category, info.Breed)}
	tot, _ := st.Rows(`SELECT COUNT(*) AS flows, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out,
		SUM(CASE WHEN verdict='blocked' THEN 1 ELSE 0 END) AS blocked, COUNT(DISTINCT src_ip) AS hosts,
		MIN(ts) AS first_seen, MAX(COALESCE(end_ts,ts)) AS last_seen FROM flows WHERE app=? AND ts>=?`, app, since)
	if len(tot) > 0 {
		out["totals"] = tot[0]
	}
	devs, _ := st.Rows(`SELECT src_ip AS ip, COUNT(*) AS flows, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out, MAX(COALESCE(end_ts,ts)) AS last_seen
		FROM flows WHERE app=? AND ts>=? GROUP BY src_ip ORDER BY flows DESC LIMIT 25`, app, since)
	m.decorate(devs, "ip", "name")
	out["devices"] = devs
	doms, _ := st.Rows(`SELECT COALESCE(NULLIF(domain,''), NULLIF(tls_sni,'')) AS domain, COUNT(*) AS flows, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out
		FROM flows WHERE app=? AND ts>=? AND (domain<>'' OR tls_sni<>'') GROUP BY 1 ORDER BY flows DESC LIMIT 25`, app, since)
	out["domains"] = doms
	dsts, _ := st.Rows(`SELECT dst_ip AS ip, dst_port AS port, proto, MAX(country) AS country, MAX(asn) AS asn, COUNT(*) AS flows, SUM(bytes_in+bytes_out) AS bytes
		FROM flows WHERE app=? AND ts>=? GROUP BY dst_ip, dst_port, proto ORDER BY bytes DESC LIMIT 25`, app, since)
	m.decorate(dsts, "ip", "name")
	out["destinations"] = dsts
	ports, _ := st.Rows(`SELECT dst_port AS port, proto, COUNT(*) AS flows FROM flows WHERE app=? AND ts>=? GROUP BY dst_port, proto ORDER BY flows DESC LIMIT 12`, app, since)
	out["ports"] = ports
	ccs, _ := st.Rows(`SELECT upper(country) AS country, COUNT(*) AS flows, SUM(bytes_in+bytes_out) AS bytes FROM flows WHERE app=? AND ts>=? AND country<>'' GROUP BY 1 ORDER BY flows DESC LIMIT 12`, app, since)
	out["countries"] = ccs
	vis := map[string]int64{}
	if rows, err := st.Rows(`SELECT COALESCE(visibility,'') AS v, COUNT(*) AS n FROM flows WHERE app=? AND ts>=? GROUP BY v`, app, since); err == nil {
		for _, r := range rows {
			v, _ := r["v"].(string)
			if v == "" {
				v = "unknown"
			}
			vis[v] = toI(r["n"])
		}
	}
	out["visibility"] = vis
	bucket := int64(3600)
	if hours <= 6 {
		bucket = 300
	} else if hours <= 48 {
		bucket = 900
	}
	tl, _ := st.Rows(fmt.Sprintf(`SELECT (ts/%d)*%d AS t, COUNT(*) AS flows, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out FROM flows WHERE app=? AND ts>=? GROUP BY t ORDER BY t`, bucket, bucket), app, since)
	out["timeline"] = tl
	out["policies"] = m.policiesFor(app, category)
	return out, nil
}

func (m *Module) apiAppCategory(r *core.Req) (any, error) {
	cat := strings.TrimSpace(r.Q("name", ""))
	if cat == "" {
		return nil, core.BadRequest("name is required")
	}
	hours := r.QInt("hours", 24, 1, 24*30)
	since := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	st := m.ctx.Store
	note := categoryNotes[cat]
	note.Source = "category"
	out := map[string]any{"category": cat, "hours": hours, "note": note}
	apps, _ := st.Rows(`SELECT app, COUNT(*) AS flows, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out,
		SUM(CASE WHEN verdict='blocked' THEN 1 ELSE 0 END) AS blocked, COUNT(DISTINCT src_ip) AS hosts, MAX(COALESCE(end_ts,ts)) AS last_seen
		FROM flows WHERE category=? AND ts>=? GROUP BY app ORDER BY flows DESC LIMIT 100`, cat, since)
	m.mu.Lock()
	for _, a := range apps {
		name, _ := a["app"].(string)
		a["breed"] = m.apps[name].Breed
	}
	m.mu.Unlock()
	out["apps"] = apps
	devs, _ := st.Rows(`SELECT src_ip AS ip, COUNT(*) AS flows, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out
		FROM flows WHERE category=? AND ts>=? GROUP BY src_ip ORDER BY flows DESC LIMIT 25`, cat, since)
	m.decorate(devs, "ip", "name")
	out["devices"] = devs
	tot, _ := st.Rows(`SELECT COUNT(*) AS flows, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out, COUNT(DISTINCT src_ip) AS hosts FROM flows WHERE category=? AND ts>=?`, cat, since)
	if len(tot) > 0 {
		out["totals"] = tot[0]
	}
	out["policies"] = m.policiesFor("", cat)
	return out, nil
}

// unknownSignature is the key an unnamed flow is filed under: the
// registrable name when there is one, else the far end's network (or /24
// when even that is unknown), with port and protocol.
func unknownSignature(proto string, port int64, domain, sni, ip, asn string) (sig, label string) {
	proto = strings.ToLower(proto)
	name := domain
	if name == "" {
		name = sni
	}
	name = registrableName(name)
	svc := portLabel(port, proto)
	switch {
	case name != "":
		return fmt.Sprintf("%s/%d %s", proto, port, name), fmt.Sprintf("%s to %s%s", strings.ToUpper(proto), name, svc)
	case asn != "":
		return fmt.Sprintf("%s/%d AS%s", proto, port, asn), fmt.Sprintf("%s to AS%s%s", strings.ToUpper(proto), asn, svc)
	default:
		net := ip
		if i := strings.LastIndex(ip, "."); i > 0 {
			net = ip[:i] + ".0/24"
		} else if j := strings.Index(ip, ":"); j > 0 {
			parts := strings.Split(ip, ":")
			if len(parts) >= 4 {
				net = strings.Join(parts[:4], ":") + "::/64"
			}
		}
		return fmt.Sprintf("%s/%d %s", proto, port, net), fmt.Sprintf("%s to %s%s", strings.ToUpper(proto), net, svc)
	}
}

// portLabel names the well-known ports the unknown row keeps landing on.
func portLabel(port int64, proto string) string {
	names := map[int64]string{443: "HTTPS", 80: "HTTP", 53: "DNS", 123: "NTP", 22: "SSH", 5223: "push notifications", 5228: "push notifications",
		3478: "STUN", 19302: "STUN", 33434: "traceroute", 1900: "SSDP", 5353: "mDNS", 8883: "MQTT over TLS", 1883: "MQTT", 25: "SMTP", 587: "SMTP",
		993: "IMAP", 465: "SMTP", 51820: "WireGuard", 41641: "Tailscale", 500: "IPsec", 4500: "IPsec", 3074: "Xbox Live", 27015: "Steam", 32400: "Plex"}
	if n, ok := names[port]; ok {
		return fmt.Sprintf(" on %d (%s)", port, n)
	}
	if port >= 32768 {
		return " on a high port"
	}
	return fmt.Sprintf(" on %d", port)
}

func registrableName(name string) string {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return ""
	}
	parts := strings.Split(name, ".")
	if len(parts) <= 2 {
		return name
	}
	last2 := parts[len(parts)-2]
	if len(last2) <= 3 && len(parts) >= 3 {
		switch last2 {
		case "co", "com", "net", "org", "gov", "ac", "edu":
			return strings.Join(parts[len(parts)-3:], ".")
		}
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func (m *Module) apiUnknown(r *core.Req) (any, error) {
	hours := r.QInt("hours", 24, 1, 24*30)
	limit := r.QInt("limit", 100, 1, 1000)
	since := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	rows, err := m.ctx.Store.Rows(`SELECT src_ip, dst_ip, dst_port, proto, COALESCE(domain,'') AS domain, COALESCE(tls_sni,'') AS sni, COALESCE(asn,'') AS asn,
		COUNT(*) AS flows, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out, MIN(ts) AS first_seen, MAX(COALESCE(end_ts,ts)) AS last_seen
		FROM flows WHERE (app='' OR app='Unknown' OR app IS NULL) AND ts>=? GROUP BY src_ip, dst_ip, dst_port, proto, domain, sni, asn LIMIT 50000`, since)
	if err != nil {
		return nil, err
	}
	type dev struct {
		ip    string
		flows int64
	}
	type sigRow struct {
		Signature string           `json:"signature"`
		Label     string           `json:"label"`
		Name      string           `json:"name,omitempty"`
		Flows     int64            `json:"flows"`
		BytesIn   int64            `json:"bytes_in"`
		BytesOut  int64            `json:"bytes_out"`
		First     int64            `json:"first_seen"`
		Last      int64            `json:"last_seen"`
		SampleIP  string           `json:"sample_ip"`
		ASN       string           `json:"asn,omitempty"`
		Port      int64            `json:"port"`
		Proto     string           `json:"proto"`
		devs      map[string]int64 `json:"-"`
		Devices   []map[string]any `json:"devices"`
		Hosts     int              `json:"hosts"`
	}
	named := m.unknownNames()
	agg := map[string]*sigRow{}
	var total int64
	for _, x := range rows {
		proto, _ := x["proto"].(string)
		port := toI(x["dst_port"])
		dom, _ := x["domain"].(string)
		sni, _ := x["sni"].(string)
		ip, _ := x["dst_ip"].(string)
		asn, _ := x["asn"].(string)
		src, _ := x["src_ip"].(string)
		sig, label := unknownSignature(proto, port, dom, sni, ip, asn)
		s := agg[sig]
		if s == nil {
			s = &sigRow{Signature: sig, Label: label, Name: named[sig], SampleIP: ip, ASN: asn, Port: port, Proto: proto, devs: map[string]int64{}, First: toI(x["first_seen"])}
			agg[sig] = s
		}
		n := toI(x["flows"])
		total += n
		s.Flows += n
		s.BytesIn += toI(x["bytes_in"])
		s.BytesOut += toI(x["bytes_out"])
		if f := toI(x["first_seen"]); f > 0 && f < s.First {
			s.First = f
		}
		if l := toI(x["last_seen"]); l > s.Last {
			s.Last = l
		}
		s.devs[src] += n
	}
	out := make([]*sigRow, 0, len(agg))
	for _, s := range agg {
		type kv struct {
			ip string
			n  int64
		}
		var ds []kv
		for ip, n := range s.devs {
			ds = append(ds, kv{ip, n})
		}
		sort.Slice(ds, func(i, j int) bool { return ds[i].n > ds[j].n })
		s.Hosts = len(ds)
		if len(ds) > 5 {
			ds = ds[:5]
		}
		for _, d := range ds {
			s.Devices = append(s.Devices, map[string]any{"ip": d.ip, "name": m.name(d.ip), "flows": d.n})
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Flows > out[j].Flows })
	if len(out) > limit {
		out = out[:limit]
	}
	return map[string]any{"hours": hours, "total_flows": total, "signatures": out, "named": named,
		"note": "nDPI names an application from a flow's own packets; these flows matched nothing it knows. Each row groups them by what else was seen: the name the device asked for, the network that announces the far end, and the port. Name a row and the pages use your name from then on."}, nil
}

func (m *Module) apiUnknownName(r *core.Req) (any, error) {
	var in struct {
		Signature string `json:"signature"`
		Name      string `json:"name"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	in.Signature = strings.TrimSpace(in.Signature)
	in.Name = strings.TrimSpace(in.Name)
	if in.Signature == "" || len(in.Signature) > 200 || len(in.Name) > 80 {
		return nil, core.BadRequest("signature is required; the name is at most 80 characters")
	}
	names := m.unknownNames()
	if in.Name == "" {
		delete(names, in.Signature)
	} else {
		names[in.Signature] = in.Name
	}
	if err := m.ctx.Store.KVSet(unknownNamesKV, names); err != nil {
		return nil, err
	}
	m.ctx.Event("audit", "unknown application named: "+in.Signature+" = "+in.Name, map[string]any{"actor_name": r.User})
	return map[string]any{"ok": true, "named": len(names)}, nil
}
