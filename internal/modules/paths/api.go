package paths

// What the page asks for.
//
// Enrichment happens here rather than at trace time. Names and locations
// change, databases get updated, and a route measured last week should be
// read with today's answers rather than the ones that were current when the
// probe went out.

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
	"github.com/grioghar/flowsight/internal/modules/enrich"
)

func (m *Module) apiStatus(r *core.Req) (any, error) {
	m.mu.Lock()
	last, traced, err := m.lastRun, m.traced, m.lastErr
	m.mu.Unlock()
	var dsts, hops int64
	if rows, e := m.ctx.Store.Rows(`SELECT COUNT(*) AS n FROM path_runs`); e == nil && len(rows) > 0 {
		dsts = asInt(rows[0]["n"])
	}
	if rows, e := m.ctx.Store.Rows(`SELECT COUNT(*) AS n FROM path_hops WHERE ip <> ''`); e == nil && len(rows) > 0 {
		hops = asInt(rows[0]["n"])
	}
	// These take the module lock themselves; gathered before it is held
	// here, or the status call deadlocks and takes every graph build with it.
	gf, ai, idn, sh := m.geofeedStatus(), m.assistStatus(), m.identifyStatus(), m.shodanStatus()
	m.mu.Lock()
	fccSt := m.fcc
	fccSum := m.fccSum
	m.mu.Unlock()
	fccInfo := map[string]any{"on": fccSt.On, "as_of": fccSt.AsOf, "files": fccSt.Files, "checked_at": fccSt.CheckedAt, "error": fccSt.Error}
	if fccSum != nil {
		fccInfo["providers"] = len(fccSum.Providers)
		fccInfo["state"] = fccSum.StateName
		fccInfo["places"] = len(fccSum.Places)
		fccInfo["pulled_at"] = fccSum.PulledAt
		if len(fccSum.Errors) > 0 {
			fccInfo["error"] = strings.Join(fccSum.Errors, "; ")
		}
	}
	m.mu.Lock()
	sources := map[string]any{
		"cables":       map[string]any{"on": core.Bool(m.ctx.Settings(), "cables", false), "loaded": len(m.cables), "error": m.cableErr},
		"land_routes":  map[string]any{"on": core.Bool(m.ctx.Settings(), "terrestrial", false), "loaded": m.landRoutes, "error": m.landErr},
		"osm_telecom":  m.osm,
		"providers":    m.provider,
		"geofeeds":     gf,
		"assistant":    ai,
		"identify":     idn,
		"shodan":       sh,
		"fcc":          fccInfo,
		"reputation":   map[string]any{"on": m.abuseKey() != "", "asked_this_session": m.abuseAsked, "known": m.ctx.Store.KVCount(abuseKV), "error": m.abuseErr},
		"ipmap":        map[string]any{"on": m.ipmapOn(), "answered": m.ctx.Store.KVCount(ipmapKV), "this_session": m.ipmapAnswered, "queued": len(m.geoPending), "per_minute": m.ipmapPerMinute(), "backing_off_until": epoch(m.ipmapUntil)},
		"registry":     map[string]any{"on": m.registryOK(), "queued": len(m.pending)},
		"facilities":   map[string]any{"on": m.facilitiesOK()},
		"router_names": map[string]any{"on": true, "codes": len(pops)},
	}
	cfix, xfix := m.fixCounts()
	sources["corrections"] = map[string]any{"on": m.fixes.on, "prefixes": cfix, "set_aside": xfix}
	m.mu.Unlock()
	return map[string]any{
		"active":   core.Bool(m.ctx.Settings(), "active", false),
		"last_run": epoch(last), "traced_this_session": traced,
		"destinations": dsts, "hops": hops, "error": err,
		"sources": sources,
		"note":    "Routes are measured to destinations this network has already contacted. Nothing else is probed.",
	}, nil
}

func (m *Module) apiDestinations(r *core.Req) (any, error) {
	hours := r.QInt("hours", 24, 1, 24*30)
	rows, err := m.ctx.Store.Rows(`
		SELECT r.dst AS dst, r.ts AS ts, r.hops AS hops, r.complete AS complete, r.err AS err,
		       (SELECT COUNT(*) FROM path_hops h WHERE h.dst = r.dst AND h.ip <> '') AS answered
		FROM path_runs r ORDER BY r.ts DESC LIMIT ?`, r.QInt("limit", 200, 1, 2000))
	if err != nil {
		return nil, err
	}
	// Traffic comes from the rollups in one query, not from the flow table
	// twice per destination: there is no index on the destination column of
	// flows, so each of those subqueries was a scan of every flow the store
	// holds -- four hundred scans of a million rows to draw one table.
	in, out := m.trafficTo(hours)
	ips := make([]string, 0, len(rows))
	for _, x := range rows {
		if s, _ := x["dst"].(string); s != "" {
			ips = append(ips, s)
			x["bytes_in"], x["bytes_out"] = in[s], out[s]
		}
	}
	info := m.enrich(ips)
	for _, x := range rows {
		if s, _ := x["dst"].(string); s != "" {
			if i, ok := info[s]; ok {
				x["name"], x["country"], x["city"] = i.Name, i.Country, i.City
			}
		}
	}
	return map[string]any{"destinations": rows}, nil
}

func (m *Module) apiPath(r *core.Req) (any, error) {
	dst := strings.TrimSpace(r.Q("dst", ""))
	if dst == "" {
		return nil, core.BadRequest("dst is required")
	}
	rows, err := m.hops(`WHERE dst = ?`, dst)
	if err != nil {
		return nil, err
	}
	g := buildGraph(rows)
	h := m.home()
	m.locate(g.Nodes, h)
	m.checkPlausible(g.Nodes, h)
	setAsideImpossible(&g)
	sort.Slice(g.Nodes, func(i, j int) bool { return g.Nodes[i].Index < g.Nodes[j].Index })
	nodes, reached, probed, last := trimTrail(g.Nodes, dst)
	out := map[string]any{"destination": dst, "hops": nodes, "home": h, "reached": reached, "probed_to": probed, "last_answer": last,
		"note": "A hop with several addresses answered from more than one router, which is how a carrier balances across parallel links. A silent hop did not answer; the traffic still passed through it."}
	// A route starts inside the network, not at the first router that
	// answered. Without this the trail begins mid-journey and a reader has to
	// supply the first step from memory.
	if inside := m.insideFor(dst, strings.TrimSpace(r.Q("device", ""))); inside != nil {
		out["inside"] = inside
	}
	// Whose traffic this route carried, and what it was: the near end of
	// the journey, beside the far end.
	if t := m.talkersFor(dst, r.QInt("hours", 24, 1, 24*30)); t != nil {
		out["talkers"] = t
	}
	return out, nil
}

// Inside is where a route begins: the address on this network that reached
// the destination, and the device it belongs to.
type Inside struct {
	Addresses []string `json:"addresses"`
	Name      string   `json:"name,omitempty"`
	Vendor    string   `json:"vendor,omitempty"`
}

// insideFor finds which device on this network talked to a destination.
//
// Several may have. When a device is being filtered on, that one answers;
// otherwise the busiest does, because a trail has one beginning and picking
// the loudest speaker is at least a rule a reader can be told. The count is
// over flows, not addresses, so a laptop that rotates through a dozen IPv6
// addresses does not outrank a device that simply talked more.
func (m *Module) insideFor(dst, device string) *Inside {
	// From the rollups, which carry a flow count per source and destination
	// and are indexed by destination; the flow table is not, and this used to
	// be a scan of it for every trail opened.
	var args []any
	where := `WHERE dst_ip = ? AND bucket >= ? AND src_ip <> ''`
	args = append(args, dst, time.Now().Add(-30*24*time.Hour).Unix())
	if device != "" {
		addrs := m.addressesOf(device)
		ph := make([]string, len(addrs))
		for i, a := range addrs {
			ph[i] = "?"
			args = append(args, a)
		}
		where += ` AND src_ip IN (` + strings.Join(ph, ",") + `)`
	}
	rows, err := m.ctx.Store.Rows(
		`SELECT src_ip AS ip, SUM(flows) AS n FROM rollup_dst `+where+` GROUP BY src_ip ORDER BY n DESC`, args...)
	if err != nil || len(rows) == 0 {
		return nil
	}
	first, _ := rows[0]["ip"].(string)
	if first == "" {
		return nil
	}
	in := &Inside{Addresses: []string{first}}
	if m.identity != nil {
		in.Name = m.identity.Name(first)
		if mac := m.identity.MAC(first); mac != "" {
			in.Vendor = m.identity.Vendor(mac)
			// Every address of the same device, so the trail begins with the
			// whole of what is there rather than the address that happened to
			// carry the most flows.
			for _, a := range m.addressesOf(first) {
				if !contains(in.Addresses, a) {
					in.Addresses = append(in.Addresses, a)
				}
			}
		}
	}
	return in
}

func (m *Module) cachedGraph(key string) (Graph, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.graphCache[key]
	if !ok || time.Since(c.at) >= 20*time.Second {
		return Graph{}, false
	}
	return c.g, true
}

func (m *Module) apiGraph(r *core.Req) (any, error) {
	where, args := "", []any{}
	// A device filter is a join: the device's flows name destinations, and
	// those destinations have routes. No device is ever traced.
	//
	// The filter takes every address the device holds, not the one that was
	// clicked. A laptop answers to an IPv4 lease and a fistful of rotating
	// IPv6 privacy addresses, and filtering on one of them would show a
	// fraction of where that laptop has actually been.
	// Several devices at once (a comma-separated list) is what a hop click
	// produces: every device whose traffic ran through that hop.
	if dev := strings.TrimSpace(r.Q("device", "")); dev != "" {
		var ph []string
		seen := map[string]bool{}
		for _, one := range strings.Split(dev, ",") {
			one = strings.TrimSpace(one)
			if one == "" {
				continue
			}
			for _, a := range m.addressesOf(one) {
				if !seen[a] {
					seen[a] = true
					ph = append(ph, "?")
					args = append(args, a)
				}
			}
		}
		if len(ph) > 0 {
			where = `WHERE dst IN (SELECT DISTINCT dst_ip FROM flows WHERE dst_ip <> '' AND src_ip IN (` +
				strings.Join(ph, ",") + `))`
		}
	}
	// Built once and kept briefly. The page asks for this every couple of
	// minutes on its own, several readers may be looking at once, and the
	// build walks seven thousand nodes through placement, interpolation and
	// the plausibility check. Twenty seconds is short enough that a settings
	// change is felt at once and long enough to absorb a burst.
	key := strings.Join([]string{r.Q("device", ""), r.Q("country", ""), r.Q("max_latency", ""), r.Q("max_hops", ""), r.Q("hours", "")}, "|")
	if g, ok := m.cachedGraph(key); ok {
		return g, nil
	}
	// One build at a time. Several tabs asking in the same second used to
	// each walk the whole graph; now the first builds and the rest find it
	// waiting when their turn comes.
	m.graphBuild.Lock()
	defer m.graphBuild.Unlock()
	if g, ok := m.cachedGraph(key); ok {
		return g, nil
	}
	buildStart := time.Now()

	// Each stage is timed. A build that takes longer than a page load should
	// say which part did, or the next slow one is guesswork again.
	started := time.Now()
	var stages []any
	stage := func(name string) {
		stages = append(stages, name, time.Since(started).Round(time.Millisecond).String())
		started = time.Now()
	}
	rows, err := m.hops(where, args...)
	if err != nil {
		return nil, err
	}
	stage("sql")
	g := buildGraph(rows)
	stage("build")
	h := m.home()
	m.locate(g.Nodes, h)
	m.tallyHopBoxes(g.Nodes)
	stage("locate")
	// The physics first, so a placement it rules out is set aside before
	// anything is interpolated from it or drawn through it.
	m.checkPlausible(g.Nodes, h)
	setAsideImpossible(&g)
	// Interpolate before bridging: a hop put between two others is a hop, and
	// the route should run through it rather than over it. Bridge before
	// anything measures the legs: a placed hop whose neighbours could not be
	// placed would otherwise be drawn with nothing attached.
	// Endpoints of known anycast operators before interpolation: an edge
	// address of Google's or Apple's that a route ends at is served from
	// many sites, and a registered or remotely measured position for it is
	// the wrong kind of fact. Their backbone routers on the way are not
	// anycast and are left to the ordinary rules.
	markEndpoints(&g)
	markOperatorAnycast(&g)
	interpolateGaps(&g)
	bridgeGaps(&g)
	markEndpoints(&g)
	m.attachTraffic(&g, r.QInt("hours", 24, 1, 24*30))
	stage("shape")
	m.checkPlausible(g.Nodes, h)
	stage("check")
	m.annotateCables(g)
	stage("cables")
	g = filterGraph(g, r.Q("country", ""), float64(r.QInt("max_latency", 0, 0, 100000)), r.QInt("max_hops", 0, 0, 64))
	dropSilent(&g)
	g.Home = &h
	if total := time.Since(buildStart); total > 3*time.Second && m.ctx != nil && m.ctx.Log != nil {
		m.ctx.Log.Info("slow graph build", append([]any{"total", total.Round(time.Millisecond).String(), "nodes", len(g.Nodes)}, stages...)...)
	}

	m.mu.Lock()
	if m.graphCache == nil || len(m.graphCache) > 32 {
		m.graphCache = map[string]cachedGraph{} // a filter typed once should not live forever
	}
	m.graphCache[key] = cachedGraph{at: time.Now(), g: g}
	m.mu.Unlock()
	return g, nil
}

type cachedGraph struct {
	at time.Time
	g  Graph
}

// attachTraffic puts the traffic that went to each endpoint on the endpoint.
// A router on the way carries none as a destination, which makes the
// difference between the two kinds of node visible.
func (m *Module) attachTraffic(g *Graph, hours int) {
	in, out := m.trafficTo(hours)
	for i := range g.Nodes {
		n := &g.Nodes[i]
		if !n.Endpoint {
			continue
		}
		for _, d := range n.Reaches {
			n.BytesIn += in[d]
			n.BytesOut += out[d]
		}
	}
}

// trafficTo is the bytes each traced destination received and sent over the
// last so many hours, read from the five-minute rollups the core keeps
// rather than from the flows themselves. The rollups are the same numbers
// already summed, a fraction of the rows, and keyed by time first, so the
// window is a range read; the figure lags the last flow by at most the
// rollup interval, which for a total over hours is nothing.
func (m *Module) trafficTo(hours int) (in, out map[string]int64) {
	in, out = map[string]int64{}, map[string]int64{}
	if m.ctx == nil || m.ctx.Store == nil {
		return in, out
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	rows, err := m.ctx.Store.Rows(`
		SELECT dst_ip AS ip, COALESCE(SUM(bytes_in),0) AS bi, COALESCE(SUM(bytes_out),0) AS bo
		FROM rollup_dst WHERE bucket >= ? AND dst_ip IN (SELECT dst FROM path_runs)
		GROUP BY dst_ip`, since-since%300)
	if err != nil {
		return in, out
	}
	for _, row := range rows {
		ip, _ := row["ip"].(string)
		in[ip], out[ip] = asInt(row["bi"]), asInt(row["bo"])
	}
	return in, out
}

// apiCables hands the map over for drawing, thinned to the number of points
// asked for. The full file carries far more detail than a line a few hundred
// pixels long can show.
func (m *Module) apiCables(r *core.Req) (any, error) {
	m.mu.Lock()
	cables, cerr := m.cables, m.cableErr
	m.mu.Unlock()
	detail := r.QInt("detail", 40, 4, 400)
	type outCable struct {
		Name string         `json:"name"`
		KM   float64        `json:"km"`
		Runs [][][2]float64 `json:"runs"` // lon,lat, as GeoJSON has it
	}
	out := make([]outCable, 0, len(cables))
	for _, c := range cables {
		oc := outCable{Name: c.Name, KM: math.Round(c.KM)}
		for _, run := range c.Legs {
			step := len(run) / detail
			if step < 1 {
				step = 1
			}
			pts := make([][2]float64, 0, len(run)/step+2)
			for i := 0; i < len(run); i += step {
				pts = append(pts, [2]float64{run[i].Lon, run[i].Lat})
			}
			last := run[len(run)-1]
			if len(pts) == 0 || pts[len(pts)-1] != [2]float64{last.Lon, last.Lat} {
				pts = append(pts, [2]float64{last.Lon, last.Lat})
			}
			if len(pts) >= 2 {
				oc.Runs = append(oc.Runs, pts)
			}
		}
		if len(oc.Runs) > 0 {
			out = append(out, oc)
		}
	}
	return map[string]any{"cables": out, "error": cerr,
		"attribution": "Submarine cable routes from TeleGeography's public cable map.",
		"note":        "Drawn for context. A traceroute never names a cable, so no leg is claimed to follow one."}, nil
}

func (m *Module) apiGetHome(r *core.Req) (any, error) {
	h := m.home()
	out := map[string]any{
		"configured": core.Str(m.ctx.Settings(), "home", ""),
		"ok":         h.OK, "lat": h.Lat, "lon": h.Lon, "source": h.Source,
		"note": "Declaring this matters more than it looks: it is the reference for deciding whether a hop could be where the database claims. An origin that is out by a few hundred kilometres turns correct placements into impossible ones and back again.",
	}
	// The gateway's own addresses on the public internet. Both families are
	// reported, not just the one the origin was worked out from: a reader
	// checking where the map thinks they are wants to see the address that
	// produced the answer, and on a dual-stack line the other one is the
	// first thing they will ask about.
	v4, v6 := m.publicAddresses()
	out["public_v4"], out["public_v6"] = v4, v6
	if ip := m.publicAddress(); ip != "" {
		out["public_address"] = ip
		if m.rdns != nil {
			if info, ok := m.rdns.Lookup([]string{ip})[ip]; ok {
				out["detected"] = map[string]any{
					"lat": info.Lat, "lon": info.Lon, "city": info.City,
					"region": info.Region, "country": info.Country,
				}
			}
		}
	}
	return out, nil
}

func (m *Module) apiSetHome(r *core.Req) (any, error) {
	var in struct {
		Lat   float64 `json:"lat"`
		Lon   float64 `json:"lon"`
		Clear bool    `json:"clear"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	value := ""
	if !in.Clear {
		v := strconv.FormatFloat(in.Lat, 'f', 4, 64) + "," + strconv.FormatFloat(in.Lon, 'f', 4, 64)
		if _, _, ok := parseLatLon(v); !ok {
			return nil, core.BadRequest("latitude must be between -90 and 90, longitude between -180 and 180")
		}
		value = v
	}
	if err := m.ctx.Config.SetModule("paths", map[string]any{"home": value}); err != nil {
		return nil, err
	}
	h := m.home()
	return map[string]any{"ok": true, "lat": h.Lat, "lon": h.Lon, "source": h.Source}, nil
}

// addressesOf expands one address into every address the same device holds,
// found through its hardware address. An address with no device behind it,
// or one FlowSight has never seen, stands for itself.
func (m *Module) addressesOf(addr string) []string {
	rows, err := m.ctx.Store.Rows(
		`SELECT ip FROM hosts WHERE mac <> '' AND mac = (SELECT mac FROM hosts WHERE ip = ? LIMIT 1)`, addr)
	if err != nil || len(rows) == 0 {
		return []string{addr}
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if ip, _ := r["ip"].(string); ip != "" {
			out = append(out, ip)
		}
	}
	if len(out) == 0 {
		return []string{addr}
	}
	return out
}

// apiDevices lists the devices whose traffic has a measured route, one entry
// per device rather than one per address: a laptop with an IPv4 lease and six
// rotating IPv6 addresses is one thing to filter by, not seven.
func (m *Module) apiDevices(r *core.Req) (any, error) {
	// The last month of rollups rather than every flow ever stored: the
	// list is who to filter the map by, and a device that has not spoken in
	// a month has no route worth filtering to.
	rows, err := m.ctx.Store.Rows(`
		SELECT f.src_ip AS ip, COUNT(DISTINCT f.dst_ip) AS destinations
		FROM rollup_dst f JOIN path_runs p ON p.dst = f.dst_ip
		WHERE f.bucket >= ? AND f.src_ip <> '' GROUP BY f.src_ip`, time.Now().Add(-30*24*time.Hour).Unix())
	if err != nil {
		return nil, err
	}
	type dev struct {
		Key          string   `json:"key"`
		Name         string   `json:"name,omitempty"`
		Addresses    []string `json:"addresses"`
		Destinations int      `json:"destinations"`
	}
	byKey := map[string]*dev{}
	for _, row := range rows {
		ip, _ := row["ip"].(string)
		if ip == "" {
			continue
		}
		key, name := ip, ""
		if m.identity != nil {
			if mac := m.identity.MAC(ip); mac != "" {
				key = mac
			}
			name = m.identity.Name(ip)
		}
		d := byKey[key]
		if d == nil {
			d = &dev{Key: ip, Name: name} // the key the filter uses is an address
			byKey[key] = d
		}
		if d.Name == "" {
			d.Name = name
		}
		d.Addresses = append(d.Addresses, ip)
		d.Destinations += int(asInt(row["destinations"]))
	}
	out := make([]dev, 0, len(byKey))
	for _, k := range sortedKeys(byKey) {
		d := byKey[k]
		sort.Strings(d.Addresses)
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Destinations > out[j].Destinations })
	return map[string]any{"devices": out,
		"note": "One entry per device. Filtering by one covers every address it holds, which for anything speaking IPv6 is several."}, nil
}

// hops reads stored hops, optionally narrowed.
func (m *Module) hops(where string, args ...any) ([]hopRow, error) {
	rows, err := m.ctx.Store.Rows(`SELECT dst, idx, ip, rtt_ms FROM path_hops `+where+` ORDER BY dst, idx`, args...)
	if err != nil {
		return nil, err
	}
	out := make([]hopRow, 0, len(rows))
	for _, x := range rows {
		dst, _ := x["dst"].(string)
		ip, _ := x["ip"].(string)
		rtt := -1.0
		if v, ok := x["rtt_ms"].(float64); ok {
			rtt = v
		}
		out = append(out, hopRow{Dst: dst, Index: int(asInt(x["idx"])), IP: ip, RTT: rtt})
	}
	return out, nil
}

// locate fills in names and coordinates for every node.
func (m *Module) locate(nodes []Node, h Home) {
	var ips []string
	for _, n := range nodes {
		ips = append(ips, n.IPs...)
	}
	info := m.enrich(ips)
	for i := range nodes {
		n := &nodes[i]
		for _, ip := range n.IPs {
			x, ok := info[ip]
			if !ok {
				continue
			}
			if x.Name != "" && !contains(n.Names, x.Name) {
				n.Names = append(n.Names, x.Name)
			}
			// The first address that has a location speaks for the node. They
			// are parallel links in the same place; if they disagree, one of
			// them is wrong and averaging would invent a third answer.
			if !n.Located && (x.Lat != 0 || x.Lon != 0) {
				n.Lat, n.Lon, n.Located, n.Source = x.Lat, x.Lon, true, "database"
			}
			if n.Country == "" {
				n.Country, n.Region, n.City = x.Country, x.Region, x.City
			}
		}
	}
	m.describe(nodes, h)
}

// describe attaches operator detail, and lets a router's own name overrule the
// address database about where it is.
//
// The override is the point rather than a side effect. A database places a
// carrier's equipment wherever the block was registered, which is how a
// Microsoft router in Los Angeles ends up drawn in London on a range RIPE
// holds. When the operator has written the site into the hostname, that is
// first-hand and the database is not, so the name wins -- and what the
// database claimed is kept alongside, because this is an inference and a
// reader is entitled to check it.
func (m *Module) describe(nodes []Node, h Home) {
	pairs := map[string]string{}
	for i := range nodes {
		n := &nodes[i]
		for j, ip := range n.IPs {
			host := ""
			if j < len(n.Names) {
				host = n.Names[j]
			} else if len(n.Names) > 0 {
				host = n.Names[0]
			}
			pairs[ip] = host
		}
	}
	if len(pairs) == 0 {
		return
	}
	// No cap here: reading a site out of a name already in hand costs nothing,
	// and capping it would leave hops placed by the address database purely
	// because of where they fell in a map iteration. describeFast rations the
	// part that actually costs something.
	// A reader waits for this, so it gets a budget rather than a promise.
	detail, cold := m.describeFast(pairs, 6*time.Second)
	m.note(cold)
	var want []string
	for i := range nodes {
		n := &nodes[i]
		for _, ip := range n.IPs {
			d, ok := detail[ip]
			if !ok {
				continue
			}
			if n.Detail == nil {
				c := d
				c.Abuse = m.reputationFor(ip)
				c.FCC = m.fccProviderFor(d.Org)
				n.Detail = &c
			}
			if d.Name != "" && !contains(n.Names, d.Name) {
				n.Names = append(n.Names, d.Name)
			}
			// What has been learned before about this block or this
			// coordinate. A correction moves the hop to where a router of
			// the same prefix was shown to be; a distrusted coordinate is
			// the registrant's address and is not used at all.
			if n.Located && n.Source == "database" {
				if c := m.correctionFor(ip); c != nil && greatCircleKM(n.Lat, n.Lon, c.Lat, c.Lon) > 250 && (n.RTT <= 0 || reachable(h, c.Lat, c.Lon, n.RTT)) {
					n.DatabaseSaid = strings.Join(nonEmpty(n.City, n.Region, n.Country), ", ")
					n.MovedKM = greatCircleKM(n.Lat, n.Lon, c.Lat, c.Lon)
					n.DBLat, n.DBLon = n.Lat, n.Lon
					n.Lat, n.Lon, n.Source = c.Lat, c.Lon, "corrected"
					n.City, n.Region, n.Country = c.City, c.Region, c.Country
					n.CorrectedBy, n.CorrectedAt = c.By, c.At.Unix()
				} else if x := m.distrusted(detailASN(&d), n.Lat, n.Lon); x != nil {
					n.SetAside = fmt.Sprintf("the database put it at %s, the registrant's address for AS%d; %d of that network's routers there have been shown to be elsewhere, so the database is not believed about it",
						firstNonEmptyStr(x.Place, strings.Join(nonEmpty(n.City, n.Region, n.Country), ", ")), x.ASN, x.Count)
					n.DBLat, n.DBLon = n.Lat, n.Lon
					n.Lat, n.Lon, n.Located, n.Source = 0, 0, false, ""
					n.City, n.Region, n.Country = "", "", ""
				}
			}
			// What the provider itself publishes about the range. The
			// operator's own statement of where a prefix is announced
			// outranks the database and a measurement; an anycast range has
			// no single place, so nothing but the timing may place it.
			if pr := m.providerPlace(ip); pr != nil {
				if pr.Anycast && pr.Census {
					// Decided later, once endpoints are known.
					n.censusHint = pr
				} else if pr.Anycast {
					n.Anycast = true
					n.Provider = pr.Provider + " anycast"
					n.anycastSites, n.AnycastSites = pr.Sites, pr.SiteTotal
					if n.Located && n.Source != "name" {
						n.SetAside = fmt.Sprintf("%s announces this range from many places at once (anycast); the %s's position for it is meaningless, so it is placed by timing", pr.Provider, sourceNoun(n.Source))
						n.DBLat, n.DBLon = n.Lat, n.Lon
						n.Lat, n.Lon, n.Located, n.Source = 0, 0, false, ""
						n.City, n.Region, n.Country = "", "", ""
					}
					// The server itself is the one authority on which
					// instance answered. Asked once a week; placed here
					// when it said, and the clock agreed.
					if id := m.identityFor(ip); id != nil {
						ii := *id
						n.Identity = &ii
						if id.Located {
							n.Lat, n.Lon, n.Located, n.Source = id.Lat, id.Lon, true, "identified"
							n.City, n.Region, n.Country = splitPlace(id.Site)
							n.SetAside = ""
							n.Inferred = false
						}
					} else if n.RTT > 0 {
						m.wantIdentity(ip, n.RTT)
					}
				} else if !n.Located || n.Source == "database" || n.Source == "corrected" {
					if n.Located && n.Source == "database" {
						if km := greatCircleKM(n.Lat, n.Lon, pr.Lat, pr.Lon); km > 250 {
							n.DatabaseSaid = strings.Join(nonEmpty(n.City, n.Region, n.Country), ", ")
							n.MovedKM = km
							n.DBLat, n.DBLon = n.Lat, n.Lon
						}
					}
					n.Lat, n.Lon, n.Located, n.Source = pr.Lat, pr.Lon, true, "provider"
					n.City, n.Region, n.Country = splitPlace(pr.City)
					n.Provider = pr.Provider + " " + pr.Region
					n.Inferred = false
					n.CorrectedBy, n.CorrectedAt = "", 0
				}
			}
			// What somebody measured, if they have. This outranks the address
			// database -- which says where a block was registered -- and is
			// asked for whenever nothing better is known.
			if n.Anycast {
				// Nothing to ask; a measurement of an anycast address is
				// wherever the probes happened to be.
			} else if p, plat, plon, known := m.knownPlace(ip); known {
				if p.OK && (!n.Located || n.Source == "database" || n.Source == "corrected") {
					if n.Located && n.Source == "database" {
						if km := greatCircleKM(n.Lat, n.Lon, plat, plon); km > 250 {
							n.DatabaseSaid = strings.Join(nonEmpty(n.City, n.Region, n.Country), ", ")
							n.MovedKM = km
							n.DBLat, n.DBLon = n.Lat, n.Lon
							// Learned only when the round trip could reach the
							// measured place from here. An anycast address is
							// measured wherever most probes see it, and a
							// 19 ms answer from Kansas was never Johannesburg.
							if km > learnKM && reachable(h, plat, plon, n.RTT) {
								m.learn(ip, &d, "RIPE IPmap", n.DBLat, n.DBLon, n.DatabaseSaid, plat, plon, p.City, p.Region, p.Country, km)
							}
						}
					}
					n.Lat, n.Lon, n.Located, n.Source = plat, plon, true, "measured"
					n.City, n.Region, n.Country = p.City, p.Region, p.Country
					n.Inferred = false
				}
			} else {
				want = append(want, ip)
			}

			// Where the name points is decided here, against the clock.
			// A name is a proposal; the round trip is evidence, and a
			// reading it rules out is not used however well it reads.
			match, score, why := m.placeFromName(d.Name, n.RTT, h)
			if score <= 0 || match.Pop.City == "" {
				if n.Detail != nil {
					n.Detail.PoPWhy = why
				}
				// Nothing read the name. If nothing else placed the hop
				// either, the assistant may have -- or may be asked.
				if !n.Located && !n.Anycast && n.RTT > 0 {
					if g := m.guessFor(ip); g != nil {
						if !g.Unknown && reachable(h, g.Lat, g.Lon, n.RTT) {
							n.Lat, n.Lon, n.Located, n.Source = g.Lat, g.Lon, true, "assistant"
							n.City, n.Region, n.Country = g.City, g.Region, g.Country
							n.Inferred = true
							gg := *g
							n.Guess = &gg
						}
					} else {
						m.wantAssist(ip, d.Name, n.Detail, n.RTT)
					}
				}
				continue
			}
			if n.Detail != nil {
				n.Detail.PoPCode, n.Detail.PoPCity = match.Code, match.Pop.City
				n.Detail.PoPLat, n.Detail.PoPLon = match.Pop.Lat, match.Pop.Lon
				n.Detail.PoPScore, n.Detail.PoPHow, n.Detail.PoPWhy = score, match.Kind, why
			}
			// A reading has to be worth more than the database to replace it.
			// A published code clears this easily; a contraction clears it
			// only when the round trip actually fits, which is the line
			// between reading a name and guessing at one.
			if score < 0.55 {
				continue
			}
			if n.Located && n.Source == "database" {
				if km := greatCircleKM(n.Lat, n.Lon, match.Pop.Lat, match.Pop.Lon); km > 250 {
					n.DatabaseSaid = strings.Join(nonEmpty(n.City, n.Region, n.Country), ", ")
					n.MovedKM = km
					n.DBLat, n.DBLon = n.Lat, n.Lon
					if km > learnKM && reachable(h, match.Pop.Lat, match.Pop.Lon, n.RTT) {
						city, region, country := splitPlace(match.Pop.City)
						m.learn(ip, &d, d.Name, n.DBLat, n.DBLon, n.DatabaseSaid, match.Pop.Lat, match.Pop.Lon, city, region, country, km)
					}
				}
			}
			n.Lat, n.Lon, n.Located, n.Source = match.Pop.Lat, match.Pop.Lon, true, "name"
			n.City, n.Region, n.Country = splitPlace(match.Pop.City)
			n.Inferred = false
			break
		}
	}
	m.wantPlace(want)
}

// splitPlace turns "Los Angeles, CA, US" back into its parts.
// (describe ends by queueing whatever has not been asked about yet.)

func splitPlace(s string) (city, region, country string) {
	f := strings.Split(s, ",")
	for i := range f {
		f[i] = strings.TrimSpace(f[i])
	}
	switch len(f) {
	case 0:
		return "", "", ""
	case 1:
		return f[0], "", ""
	case 2:
		return f[0], "", f[1]
	default:
		return f[0], f[1], f[2]
	}
}

func nonEmpty(xs ...string) []string {
	var out []string
	for _, x := range xs {
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

func (m *Module) enrich(ips []string) map[string]enrich.Info {
	if m.rdns == nil || len(ips) == 0 {
		return map[string]enrich.Info{}
	}
	if len(ips) > 500 {
		ips = ips[:500]
	}
	return m.rdns.Lookup(ips)
}

// filterGraph narrows a graph, then drops legs whose ends no longer exist.
func filterGraph(g Graph, country string, maxLatency float64, maxHops int) Graph {
	country = strings.ToUpper(strings.TrimSpace(country))
	keep := map[string]bool{}
	var nodes []Node
	for _, n := range g.Nodes {
		if country != "" && strings.ToUpper(n.Country) != country {
			continue
		}
		if maxLatency > 0 && n.RTT > maxLatency {
			continue
		}
		if maxHops > 0 && n.Index > maxHops {
			continue
		}
		keep[n.ID] = true
		nodes = append(nodes, n)
	}
	var legs []Leg
	for _, l := range g.Legs {
		if keep[l.From] && keep[l.To] {
			legs = append(legs, l)
		}
	}
	g.Nodes, g.Legs = nodes, legs
	return g
}

// epoch reports a zero time as zero rather than as the year 1, which is what
// Unix() does with it and what a page then has to special-case.
func epoch(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func asInt(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case float64:
		return int64(x)
	}
	return 0
}

// reachable says whether a round trip could have come back from a place: it
// must not beat light through glass over the straight line from the origin.
// A hop with no timing is not evidence either way, and teaches nothing.
func reachable(h Home, lat, lon, rtt float64) bool {
	if rtt <= 0 || !h.OK {
		return false
	}
	return rtt >= floorMS(greatCircleKM(h.Lat, h.Lon, lat, lon))
}

// markOperatorAnycast treats the endpoints of known anycast operators as
// anycast when nothing first-hand placed them.
func markOperatorAnycast(g *Graph) {
	for i := range g.Nodes {
		n := &g.Nodes[i]
		if !n.Endpoint || n.Anycast || n.Source == "name" || n.Source == "identified" || n.Source == "provider" {
			continue
		}
		who := ""
		if n.censusHint != nil {
			who = n.censusHint.Provider
			n.anycastSites, n.AnycastSites = n.censusHint.Sites, n.censusHint.SiteTotal
		} else if n.Detail != nil {
			if w, ok := anycastOperator(n.Detail.ASN); ok {
				who = w + " (anycast operator)"
			}
		}
		if who == "" {
			continue
		}
		n.Anycast = true
		if n.Provider == "" {
			n.Provider = who
		}
		if n.Located && (n.Source == "database" || n.Source == "measured" || n.Source == "corrected") {
			n.SetAside = fmt.Sprintf("%s: this address is served from many sites at once (anycast); the %s's position for it is meaningless, so it is placed by timing", who, sourceNoun(n.Source))
			n.DBLat, n.DBLon = n.Lat, n.Lon
			n.Lat, n.Lon, n.Located, n.Source = 0, 0, false, ""
			n.City, n.Region, n.Country = "", "", ""
			n.Impossible, n.Tight, n.Why = false, false, ""
		}
	}
}

// apiWho answers "who made the requests that ran through here": the devices
// whose traffic reached any of the given destinations in the window, one
// entry per device with every address it used. The map asks this when a hop
// is clicked and sets its device filter to the answer.
func (m *Module) apiWho(r *core.Req) (any, error) {
	var dsts []string
	for _, d := range strings.Split(r.Q("dsts", ""), ",") {
		if d = strings.TrimSpace(d); d != "" && len(dsts) < 200 {
			dsts = append(dsts, d)
		}
	}
	hours := r.QInt("hours", 24, 1, 24*30)
	if len(dsts) == 0 {
		return map[string]any{"devices": []any{}, "hours": hours}, nil
	}
	ph := make([]string, len(dsts))
	args := []any{time.Now().Add(-time.Duration(hours) * time.Hour).Unix()}
	for i, d := range dsts {
		ph[i] = "?"
		args = append(args, d)
	}
	rows, err := m.ctx.Store.Rows(`SELECT src_ip AS ip, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out, SUM(flows) AS flows,
		COUNT(DISTINCT dst_ip) AS destinations FROM rollup_dst WHERE bucket >= ? AND src_ip <> '' AND dst_ip IN (`+strings.Join(ph, ",")+`) GROUP BY src_ip`, args...)
	if err != nil {
		return nil, err
	}
	type dev struct {
		Key          string   `json:"key"`
		Name         string   `json:"name,omitempty"`
		Vendor       string   `json:"vendor,omitempty"`
		Addresses    []string `json:"addresses"`
		BytesIn      int64    `json:"bytes_in"`
		BytesOut     int64    `json:"bytes_out"`
		Flows        int64    `json:"flows"`
		Destinations int      `json:"destinations"`
	}
	byKey := map[string]*dev{}
	var order []string
	for _, row := range rows {
		ip, _ := row["ip"].(string)
		if ip == "" || (m.identity != nil && !m.identity.IsLocal(ip)) {
			continue
		}
		key, name, vendor := ip, "", ""
		if m.identity != nil {
			if mac := m.identity.MAC(ip); mac != "" {
				key = mac
				vendor = m.identity.Vendor(mac)
			}
			name = m.identity.Name(ip)
		}
		d := byKey[key]
		if d == nil {
			d = &dev{Key: ip, Name: name, Vendor: vendor}
			byKey[key] = d
			order = append(order, key)
		}
		if d.Name == "" {
			d.Name = name
		}
		d.Addresses = append(d.Addresses, ip)
		d.BytesIn += asInt(row["bytes_in"])
		d.BytesOut += asInt(row["bytes_out"])
		d.Flows += asInt(row["flows"])
		if n := int(asInt(row["destinations"])); n > d.Destinations {
			d.Destinations = n
		}
	}
	out := make([]dev, 0, len(order))
	for _, k := range order {
		d := byKey[k]
		sort.Strings(d.Addresses)
		// The IPv4 address as the key when there is one: it is the one a
		// reader recognises, and the filter expands it to the rest anyway.
		for _, a := range d.Addresses {
			if !strings.Contains(a, ":") {
				d.Key = a
				break
			}
		}
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BytesIn+out[i].BytesOut > out[j].BytesIn+out[j].BytesOut })
	return map[string]any{"devices": out, "hours": hours, "destinations": len(dsts)}, nil
}

// trimTrail cuts a route where the story ends. Once the destination itself
// answered there is nothing after it worth a row; when it never answered,
// the run of silent hops the probe went on through says only "no reply",
// which one sentence says better than fifteen rows. Returns the hops to
// show, whether the destination answered, how far the probe went, and the
// index of the last hop that answered.
func trimTrail(nodes []Node, dst string) (out []Node, reached bool, probedTo, lastAnswer int) {
	for _, n := range nodes {
		if n.Index > probedTo {
			probedTo = n.Index
		}
	}
	for i, n := range nodes {
		for _, ip := range n.IPs {
			if ip == dst {
				return nodes[:i+1], true, probedTo, n.Index
			}
		}
		if n.Endpoint && len(n.IPs) > 0 {
			return nodes[:i+1], true, probedTo, n.Index
		}
	}
	end := len(nodes)
	for end > 0 && nodes[end-1].Silent {
		end--
	}
	if end > 0 {
		lastAnswer = nodes[end-1].Index
	}
	return nodes[:end], false, probedTo, lastAnswer
}

// apiTraceNow traces one destination outside the timer. A reader who has
// clicked "Map" beside an address wants the route to it, and the timer may
// not reach that address for an hour; this runs it now, once, and the page
// polls for the answer. One trace per destination at a time.
func (m *Module) apiTraceNow(r *core.Req) (any, error) {
	var in struct {
		Dst string `json:"dst"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	dst := strings.TrimSpace(in.Dst)
	if dst == "" || !looksLikeAddress(dst) {
		return nil, core.BadRequest("dst must be an IP address")
	}
	if m.identity != nil && m.identity.IsLocal(dst) {
		return nil, core.BadRequest("addresses on this network have no route worth tracing")
	}
	m.mu.Lock()
	if m.tracingNow == nil {
		m.tracingNow = map[string]bool{}
	}
	running := m.tracingNow[dst]
	if !running {
		m.tracingNow[dst] = true
	}
	m.mu.Unlock()
	if running {
		return map[string]any{"started": false, "already_running": true, "dst": dst}, nil
	}
	go func() {
		defer func() {
			m.mu.Lock()
			delete(m.tracingNow, dst)
			m.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		t := m.trace(ctx, dst, strings.Contains(dst, ":"))
		if err := m.save(t); err != nil {
			m.fail(err.Error())
		}
	}()
	return map[string]any{"started": true, "already_running": false, "dst": dst}, nil
}
