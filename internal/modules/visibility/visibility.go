// Package visibility reads flows, hosts and application identity from ntopng
// (nDPI underneath) and keeps them in the store. It publishes a flow bus so
// enforcement modules react to what was just seen without polling.
package visibility

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

// FlowBus lets modules subscribe to flows as they are observed.
type FlowBus struct {
	mu   sync.RWMutex
	subs []func([]core.Flow)
}

func (b *FlowBus) Subscribe(fn func([]core.Flow)) {
	b.mu.Lock()
	b.subs = append(b.subs, fn)
	b.mu.Unlock()
}

func (b *FlowBus) publish(fl []core.Flow) {
	b.mu.RLock()
	subs := make([]func([]core.Flow), len(b.subs))
	copy(subs, b.subs)
	b.mu.RUnlock()
	for _, s := range subs {
		func() {
			defer func() { recover() }()
			s(fl)
		}()
	}
}

type Module struct {
	epMu     sync.Mutex              // guards the site->endpoint memo below
	epBest   map[string]endpointPick // site -> endpoint, from the last join
	epKey    string                  // what that join was for
	epAt     time.Time               // and when
	ctx      *core.Context
	nt       *ntopng
	bus      *FlowBus
	mu       sync.Mutex
	seen     map[string]flowState // flow key -> last cumulative counters
	apps     map[string]appInfo   // l7 name -> category/breed
	ifs      []iface
	lastErr  string
	lastOK   time.Time
	identity core.Identity

	lastProvision time.Time
}

type flowState struct {
	bytesIn, bytesOut int64
	seenAt            time.Time
}

type appInfo = core.AppInfo

type iface struct {
	ID   int    `json:"ifid"`
	Name string `json:"ifname"`
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name: "visibility", Version: "1.0",
		Description:  "Flows, hosts, applications and throughput from ntopng/nDPI.",
		Capabilities: []string{core.CapTrafficObserve, core.CapAppObserve, core.CapHostInventory},
		Requires:     []string{"ntopng"},
		After:        []string{"identity"},
		Defaults: map[string]any{
			"ntopng_url":      "",
			"ntopng_user":     "admin",
			"ntopng_password": "admin",
			"ntopng_token":    "",
			"redis_addr":      "127.0.0.1:6379",
			"auto_account":    true,
			"poll_seconds":    10,
			"max_flows":       2000,
			"timeout_seconds": 15,
		},
		Schema: []core.SettingField{
			{Key: "ntopng_url", Label: "ntopng URL", Type: "string", Placeholder: "http://127.0.0.1:3000",
				Help: "Empty uses the platform default."},
			{Key: "ntopng_user", Label: "ntopng user", Type: "string"},
			{Key: "ntopng_password", Label: "ntopng password", Type: "secret"},
			{Key: "ntopng_token", Label: "ntopng API token", Type: "secret",
				Help: "Preferred over a password when set."},
			{Key: "auto_account", Label: "Create an ntopng account automatically", Type: "bool",
				Help: "When ntopng refuses the configured credentials, provision a 'flowsight' user through redis."},
			{Key: "redis_addr", Label: "ntopng redis address", Type: "string"},
			{Key: "poll_seconds", Label: "Poll interval (s)", Type: "int"},
			{Key: "max_flows", Label: "Flows per poll", Type: "int"},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.bus = &FlowBus{}
	m.seen = map[string]flowState{}
	m.apps = map[string]appInfo{}
	m.identity, _ = ctx.Service("identity").(core.Identity)
	m.configure(ctx.Settings())
	ctx.Publish("flow_bus", m.bus)
	ctx.Publish("app_catalog", m)
	every := time.Duration(core.Int(ctx.Settings(), "poll_seconds", 10)) * time.Second
	if every < 3*time.Second {
		every = 3 * time.Second
	}
	ctx.Every("poll", every, m.poll)
	ctx.Every("catalog", time.Hour, m.loadCatalog)

	ctx.Route("GET", "/api/visibility/summary", m.apiSummary,
		core.Doc("Get current network statistics including throughput, active flow count, and connected hosts"),
		core.Returns("Network summary statistics", map[string]any{
			"throughput_bps": 1000000,
			"active_flows":   250,
			"active_hosts":   50,
			"timestamp":      1790376243,
		}))
	// Flows recorded before country lookup was on, or before this release,
	// have no country; fill them in behind the scenes, a few hundred a minute,
	// so the "abroad" views cover the whole retention window.
	ctx.Every("country_backfill", time.Minute, m.backfillCountries, core.Delayed())
	// Sessions labelled by the probe's stale name cache for a shared address
	// (see decodeFlow): the one label known to be wrong is cleared; rows with
	// a client-stated name (SNI) are untouched.
	_ = ctx.Store.Exec(`UPDATE flows SET domain=NULL WHERE domain='example.com' AND (tls_sni IS NULL OR tls_sni='')`)
	// Sessions recorded before the readability value existed get one from
	// what was stored (protocol, port, TLS version, name); bounded to a week.
	since := time.Now().Add(-7 * 24 * time.Hour).Unix()
	for _, q := range []string{
		`UPDATE flows SET visibility='dns' WHERE visibility IS NULL AND ts>=? AND proto='udp' AND dst_port=53`,
		`UPDATE flows SET visibility='quic' WHERE visibility IS NULL AND ts>=? AND proto='udp' AND dst_port=443`,
		`UPDATE flows SET visibility='http' WHERE visibility IS NULL AND ts>=? AND dst_port=80`,
		`UPDATE flows SET visibility='inspected' WHERE visibility IS NULL AND ts>=? AND source='squid'`,
		`UPDATE flows SET visibility='sni' WHERE visibility IS NULL AND ts>=? AND (COALESCE(tls_version,'')<>'' OR dst_port=443) AND COALESCE(domain,'')<>''`,
		`UPDATE flows SET visibility='opaque' WHERE visibility IS NULL AND ts>=? AND (COALESCE(tls_version,'')<>'' OR dst_port=443)`,
		`UPDATE flows SET visibility='plain' WHERE visibility IS NULL AND ts>=?`,
	} {
		_ = ctx.Store.Exec(q, since)
	}
	ctx.Route("GET", "/api/visibility/abroad", m.apiAbroad,
		core.Query("hours", "integer", "Time window in hours (default 24)", false, 24),
		core.Query("ip", "string", "One device: any of its addresses (all of them are matched)", false, "192.168.1.10"),
		core.Query("limit", "integer", "Devices to return, busiest first (default 50); devices_total says how many there were", false, 50),
		core.Query("offset", "integer", "Skip this many devices (paging with limit)", false, 0),
		core.Query("detail", "string", "summary: one small row per device with sessions per country and no destinations. Start here for an overview of the whole network, then ask for one device with ip= for the destinations.", false, "summary"),
		core.Doc("Show per-device traffic to foreign countries with session and byte counts by country. detail=summary fits the whole network in one answer; the default lists the destinations behind each country and is large, so page it with limit and offset or ask per device with ip="),
		core.Returns("Destination countries by device", map[string]any{
			"devices": []map[string]any{
				{"ip": "192.168.1.10", "countries": map[string]any{
					"US": map[string]any{"sessions": 100, "bytes": 500000},
				}},
			},
		}))
	ctx.Route("GET", "/api/visibility/flows", m.apiFlows,
		core.Query("minutes", "integer", "Time window in minutes (default varies)", false, 60),
		core.Query("ip", "string", "Filter by device IP or remote address", false, "192.168.1.10"),
		core.Query("app", "string", "Filter by application or category name", false, "youtube"),
		core.Query("limit", "integer", "Maximum flows to return (default 500)", false, 500),
		core.Query("country", "string", "Filter by far-end country code (ISO 3166-1)", false, "US"),
		core.Query("abroad", "boolean", "Only flows to destinations outside home country", false, false),
		core.Query("blocked", "boolean", "Only blocked flows (default shows all)", false, false),
		core.Query("anycast", "boolean", "Only sessions whose far end is anycast", false, false),
		core.Query("source", "string", "Only sessions from this source (ntopng, squid, netflow:<exporter>)", false, "ntopng"),
		core.Query("visibility", "string", "Only sessions with this readability (inspected, sni, http, quic, ech, opaque, dns, plain)", false, "opaque"),
		core.Doc("List recent network flows with detailed source, destination and application information"),
		core.Returns("Network flows list", map[string]any{
			"flows": []map[string]any{
				{"src": "192.168.1.10", "dst": "142.250.1.1", "app": "youtube", "duration_sec": 30, "bytes": 10000},
			},
		}))
	ctx.Route("GET", "/api/visibility/apps", m.apiApps,
		core.Query("hours", "integer", "Time window in hours (default 24)", false, 24),
		core.Query("ip", "string", "Analyze single device by IP address", false, "192.168.1.10"),
		core.Doc("Breakdown of network traffic by application type with byte counts and session metrics"),
		core.Returns("Application traffic breakdown", map[string]any{
			"applications": []map[string]any{
				{"name": "youtube", "bytes": 5000000, "sessions": 50},
			},
			"total_bytes": 10000000,
		}))
	ctx.Route("GET", "/api/visibility/top", m.apiTop,
		core.Query("hours", "integer", "Time window in hours (default 24)", false, 24),
		core.Query("limit", "integer", "Number of top results to return (default 20)", false, 20),
		core.Doc("Top hosts, applications, categories and destinations ranked by traffic volume"),
		core.Returns("Top network elements", map[string]any{
			"top_hosts": []map[string]any{
				{"ip": "142.250.1.1", "bytes": 5000000},
			},
			"top_apps": []map[string]any{
				{"name": "youtube", "bytes": 3000000},
			},
		}))
	ctx.Route("GET", "/api/visibility/timeseries", m.apiTimeseries,
		core.Query("hours", "integer", "Time window in hours (default 24)", false, 24),
		core.Query("metric", "string", "Metric name to retrieve (throughput, flows, hosts, etc.)", true, "throughput"),
		core.Query("step", "integer", "Data point interval in seconds (default 60)", false, 60),
		core.Doc("Fetch metric time series data for building charts and analyzing traffic trends"),
		core.Returns("Time series metric data", map[string]any{
			"metric": "throughput",
			"points": []map[string]any{
				{"time": 1790376243, "value": 1000000},
			},
		}))
	ctx.Route("GET", "/api/visibility/host", m.apiHost,
		core.Query("ip", "string", "Device or host IP address to analyze", true, "192.168.1.10"),
		core.Query("hours", "integer", "Time window in hours (default 24)", false, 24),
		core.Doc("Comprehensive analysis of a single host including connections, applications and countries"),
		core.Returns("Host analysis data", map[string]any{
			"ip":           "192.168.1.10",
			"name":         "MacBook",
			"applications": []string{"youtube", "facebook"},
			"countries":    map[string]any{"US": 5000000},
		}))
	ctx.Route("GET", "/api/visibility/catalog", m.apiCatalog,
		core.Doc("List all known applications and content categories available for filtering and classification"),
		core.Returns("Application and category catalog", map[string]any{
			"applications": []map[string]any{
				{"name": "youtube", "category": "video"},
			},
			"categories": []string{"video", "social", "gaming"},
		}))
	ctx.Route("GET", "/api/visibility/visibility", m.apiVisibilityBreakdown,
		core.Query("ip", "string", "Device address to summarise", true, "192.168.1.10"),
		core.Query("hours", "integer", "Time window in hours (default 24)", false, 24),
		core.Doc("What FlowSight could see of one device's sessions over the window: counts per readability value"),
		core.Returns("Readability counts", map[string]any{"ip": "192.168.1.10", "hours": 24,
			"visibility": map[string]any{"inspected": 18, "sni": 40, "opaque": 16, "quic": 5, "dns": 120, "plain": 15}}))
	ctx.Panel(core.Panel{ID: "overview", Title: "Overview", Group: "Monitor", Order: 1, Icon: "overview"})
	ctx.Panel(core.Panel{ID: "flows", Title: "Sessions", Group: "Monitor", Order: 30, Icon: "flows"})
	ctx.Panel(core.Panel{ID: "apps", Title: "Applications", Group: "Monitor", Order: 40, Icon: "apps"})

	// Schedule dark traffic checking
	ctx.Every("check_dark_traffic", 30*time.Minute, func() error {
		return m.checkDarkTraffic(24)
	})

	return nil
}

func (m *Module) configure(s map[string]any) {
	base := core.Str(s, "ntopng_url", "")
	if base == "" {
		base = m.ctx.Platform.NtopngURL
	}
	to := time.Duration(core.Int(s, "timeout_seconds", 15)) * time.Second
	m.mu.Lock()
	m.nt = newNtopng(base, core.Str(s, "ntopng_user", ""), core.Str(s, "ntopng_password", ""),
		core.Str(s, "ntopng_token", ""), to)
	m.mu.Unlock()
}

func (m *Module) OnConfigChange(s map[string]any) error { m.configure(s); return nil }

func (m *Module) Health() core.Health {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastErr != "" {
		return core.Health{OK: false, Detail: m.lastErr}
	}
	if m.lastOK.IsZero() {
		return core.Health{OK: true, Detail: "waiting for first poll"}
	}
	return core.Health{OK: true, Detail: fmt.Sprintf("%d interfaces, %d flows tracked", len(m.ifs), len(m.seen))}
}

// AppCategory implements the catalog service: nDPI category for an app name.
func (m *Module) AppCategory(app string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.apps[app].Category
}

// Apps returns the catalog.
func (m *Module) Apps() map[string]appInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]appInfo, len(m.apps))
	for k, v := range m.apps {
		out[k] = v
	}
	return out
}

// ---------------------------------------------------------------- polling

func (m *Module) loadCatalog() error {
	var rawCats json.RawMessage
	catNames := map[int]string{}
	if err := m.nt.get("l7/category/consts.lua", nil, &rawCats); err == nil {
		for _, c := range asList(rawCats) {
			if n := c.str("name", "cat_name"); n != "" {
				catNames[int(c.num("cat_id", "id"))] = n
			}
		}
	}
	var raw json.RawMessage
	if err := m.nt.get("l7/application/consts.lua", nil, &raw); err != nil {
		return err
	}
	apps := map[string]appInfo{}
	for _, a := range asList(raw) {
		name := a.str("name", "application")
		if name == "" {
			continue
		}
		cat := a.str("cat_name")
		if c := a.sub("category"); c != nil {
			cat = c.str("name", "cat_name")
		}
		if cat == "" {
			cat = catNames[int(a.num("cat_id"))]
		}
		apps[name] = appInfo{Category: cat, Breed: a.str("breed"), ID: int(a.num("appl_id", "id", "app_id"))}
	}
	// Breeds (Safe/Acceptable/Fun/Unsafe/Dangerous) come from the interface
	// l7 breakdown, which lists only apps seen so far; merge what it knows.
	var rawL7 json.RawMessage
	if err := m.nt.get("interface/l7/data.lua", url.Values{"ifid": {"0"}}, &rawL7); err == nil {
		for _, a := range asList(rawL7) {
			app := a.sub("application")
			if app == nil {
				continue
			}
			if ai, ok := apps[app.str("name")]; ok {
				ai.Breed = a.str("breed")
				apps[app.str("name")] = ai
			}
		}
	}
	if len(apps) == 0 {
		return fmt.Errorf("ntopng returned an empty application catalog")
	}
	m.mu.Lock()
	m.apps = apps
	m.mu.Unlock()
	return nil
}

// recoverAuth provisions a dedicated ntopng account when the configured one
// is refused. ntopng's default admin password cannot be used until it is
// changed interactively, which is the state every fresh install is in.
func (m *Module) recoverAuth() bool {
	s := m.ctx.Settings()
	if !core.Bool(s, "auto_account", true) {
		return false
	}
	m.mu.Lock()
	if time.Since(m.lastProvision) < 10*time.Minute {
		m.mu.Unlock()
		return false
	}
	m.lastProvision = time.Now()
	m.mu.Unlock()
	addr := core.Str(s, "redis_addr", "127.0.0.1:6379")
	pw, err := provisionNtopngUser(addr, "flowsight")
	if err != nil {
		m.ctx.Log.Warn("could not provision ntopng account", "error", err.Error())
		return false
	}
	if err := m.ctx.Config.SetModule(m.ctx.Name, map[string]any{"ntopng_user": "flowsight",
		"ntopng_password": pw, "ntopng_token": ""}); err != nil {
		m.ctx.Log.Warn("could not save ntopng credentials", "error", err.Error())
		return false
	}
	m.configure(m.ctx.Settings())
	m.ctx.Log.Info("provisioned ntopng account 'flowsight' through redis")
	m.ctx.Event("config", "provisioned an ntopng account for FlowSight", nil)
	return true
}

func (m *Module) fail(err error) error {
	m.mu.Lock()
	m.lastErr = err.Error()
	m.mu.Unlock()
	return err
}

func (m *Module) poll() error {
	var rawIfs json.RawMessage
	if err := m.nt.get("ntopng/interfaces.lua", nil, &rawIfs); err != nil {
		if errors.Is(err, errAuth) && m.recoverAuth() {
			err = m.nt.get("ntopng/interfaces.lua", nil, &rawIfs)
		}
		if err != nil {
			return m.fail(err)
		}
	}
	var ifs []iface
	for _, o := range asList(rawIfs) {
		ifs = append(ifs, iface{ID: int(o.num("ifid")), Name: o.str("ifname", "name")})
	}
	if len(ifs) == 0 {
		return m.fail(fmt.Errorf("ntopng reports no interfaces"))
	}
	m.mu.Lock()
	m.ifs = ifs
	if len(m.apps) == 0 {
		m.mu.Unlock()
		_ = m.loadCatalog()
	} else {
		m.mu.Unlock()
	}

	now := time.Now().Unix()
	var metrics []core.Metric
	var flows []core.Flow
	hostAgg := map[string]*core.HostUpdate{}
	maxFlows := core.Int(m.ctx.Settings(), "max_flows", 2000)

	for _, ifc := range ifs {
		q := url.Values{"ifid": {fmt.Sprint(ifc.ID)}}
		var data map[string]any
		if err := m.nt.get("interface/data.lua", q, &data); err != nil {
			return m.fail(err)
		}
		d := obj(data)
		lab := map[string]string{"interface": ifc.Name}
		bps, pps := d.num("throughput_bps"), d.num("throughput_pps")
		if th := d.sub("throughput"); th != nil {
			for _, dir := range []string{"upload", "download"} {
				if x := th.sub(dir); x != nil {
					bps += x.num("bps")
					pps += x.num("pps")
				}
			}
			if up := th.sub("upload"); up != nil {
				metrics = append(metrics, core.Metric{Name: "throughput_upload_bps", Labels: lab, Value: up.num("bps")})
			}
			if dn := th.sub("download"); dn != nil {
				metrics = append(metrics, core.Metric{Name: "throughput_download_bps", Labels: lab, Value: dn.num("bps")})
			}
		}
		metrics = append(metrics,
			core.Metric{Name: "throughput_bps", Labels: lab, Value: bps},
			core.Metric{Name: "throughput_pps", Labels: lab, Value: pps},
			core.Metric{Name: "active_flows", Labels: lab, Value: d.num("num_flows")},
			core.Metric{Name: "active_hosts", Labels: lab, Value: d.num("num_hosts", "num_local_hosts")},
			core.Metric{Name: "active_devices", Labels: lab, Value: d.num("num_devices")},
			core.Metric{Name: "bytes_total", Labels: lab, Value: d.num("bytes")},
			core.Metric{Name: "packets_total", Labels: lab, Value: d.num("packets")},
			core.Metric{Name: "drops_total", Labels: lab, Value: d.num("drops")},
			core.Metric{Name: "alerted_flows", Labels: lab, Value: d.num("alerted_flows")},
		)
		if v := d.num("bytes_upload"); v > 0 {
			metrics = append(metrics, core.Metric{Name: "bytes_upload_total", Labels: lab, Value: v},
				core.Metric{Name: "bytes_download_total", Labels: lab, Value: d.num("bytes_download")})
		}

		fq := url.Values{"ifid": {fmt.Sprint(ifc.ID)}, "perPage": {fmt.Sprint(maxFlows)},
			"currentPage": {"1"}, "sortColumn": {"column_last_seen"}, "sortOrder": {"desc"}}
		var rawFlows json.RawMessage
		if err := m.nt.get("flow/active.lua", fq, &rawFlows); err != nil {
			return m.fail(err)
		}
		for _, f := range asList(rawFlows) {
			fl, ok := m.decodeFlow(f, ifc.Name, now)
			if !ok {
				continue
			}
			flows = append(flows, fl)
		}
	}

	// Byte deltas per flow feed the host counters; cumulative totals feed the
	// flow row itself (upserted by key).
	m.mu.Lock()
	cutoff := time.Now().Add(-10 * time.Minute)
	for k, st := range m.seen {
		if st.seenAt.Before(cutoff) {
			delete(m.seen, k)
		}
	}
	for i := range flows {
		f := &flows[i]
		prev, had := m.seen[f.Key]
		dIn, dOut := f.BytesIn, f.BytesOut
		if had {
			// Judge growth by the total: the per-direction split comes from
			// a shifting percentage and one side can read lower while the
			// flow grew (see core.FlowDelta).
			dIn, dOut = core.FlowDelta(prev.bytesIn, prev.bytesOut, f.BytesIn, f.BytesOut)
		}
		m.seen[f.Key] = flowState{bytesIn: f.BytesIn, bytesOut: f.BytesOut, seenAt: time.Now()}
		for _, ip := range []string{f.SrcIP, f.DstIP} {
			if ip == "" || m.identity == nil || !m.identity.IsLocal(ip) {
				continue
			}
			h := hostAgg[ip]
			if h == nil {
				h = &core.HostUpdate{IP: ip, Source: "visibility"}
				hostAgg[ip] = h
			}
			if ip == f.SrcIP {
				h.BytesOut += dOut
				h.BytesIn += dIn
			} else {
				h.BytesIn += dOut
				h.BytesOut += dIn
			}
			if !had {
				h.Flows++
			}
		}
	}
	m.lastErr = ""
	m.lastOK = time.Now()
	m.mu.Unlock()

	if err := m.ctx.Store.AddMetrics(now, metrics); err != nil {
		return err
	}
	look, _ := m.ctx.Service("enrich").(core.CountryLookup)
	anyc, _ := m.ctx.Service("anycast").(core.AnycastLookup)
	var isLocal func(string) bool
	if m.identity != nil {
		isLocal = m.identity.IsLocal
	}
	core.FillCountries(flows, look, anyc, isLocal)
	if err := m.ctx.Store.AddFlows(flows); err != nil {
		return err
	}
	ups := make([]core.HostUpdate, 0, len(hostAgg))
	for _, h := range hostAgg {
		ups = append(ups, *h)
	}
	if err := m.ctx.Store.UpsertHosts(ups); err != nil {
		return err
	}
	m.bus.publish(flows)
	return nil
}

// decodeFlow turns one ntopng flow record into a core.Flow. The client is
// treated as the source: on a gateway that is the device that opened the
// connection, which is what policy and reports care about.
func (m *Module) decodeFlow(f obj, ifname string, now int64) (core.Flow, bool) {
	cli, srv := f.sub("client", "cli"), f.sub("server", "srv")
	if cli == nil || srv == nil {
		return core.Flow{}, false
	}
	proto := f.sub("protocol", "proto")
	l7, l4 := "", ""
	if proto != nil {
		l7 = proto.str("l7", "l7_proto", "ndpi")
		l4 = proto.str("l4", "l4_proto")
	} else {
		l7 = f.str("l7_proto_name", "l7proto", "application")
		l4 = f.str("l4_proto_name", "l4proto")
	}
	// "TLS.Google" -> app Google, master TLS. Keep the specific name.
	app := l7
	if i := strings.Index(app, "."); i > 0 && i < len(app)-1 {
		app = app[i+1:]
	}
	var in, out int64
	if bytes := f.sub("bytes"); bytes != nil {
		out = bytes.i64("sent", "cli2srv")
		in = bytes.i64("rcvd", "srv2cli")
		if in == 0 && out == 0 {
			out = bytes.i64("total")
		}
	} else if total := f.i64("bytes"); total > 0 {
		// ntopng 6 gives a total plus a percentage breakdown per direction.
		if bd := f.sub("breakdown"); bd != nil {
			out = total * bd.i64("cli2srv") / 100
			in = total - out
		} else {
			out = total
		}
	} else {
		out = f.i64("cli2srv_bytes", "bytes_sent")
		in = f.i64("srv2cli_bytes", "bytes_rcvd")
	}
	first := f.i64("first_seen", "seen.first")
	if first == 0 {
		first = now - int64(f.num("duration"))
	}
	key := f.str("key", "hash_id", "flow_key")
	srcIP, dstIP := hostIP(cli), hostIP(srv)
	if key == "" {
		key = fmt.Sprintf("%s:%d-%s:%d/%s@%d", srcIP, int(cli.num("port")), dstIP, int(srv.num("port")), l4, first)
	} else {
		key = ifname + "/" + key
	}
	// Track domain source: SNI > HTTP Host > probe name > resolver answer > none
	domain := strings.TrimSpace(f.str("info", "server_name", "host_server_name", "sni"))
	domainSource := "none"
	if domain != "" {
		// Domain came from SNI or server_name field (client-provided)
		if strings.HasPrefix(domain, "http") {
			if u, err := url.Parse(domain); err == nil {
				domain = u.Host
				domainSource = "http_host"
			}
		} else {
			domainSource = "sni"
		}
	}
	if domain == "" {
		// The probe's own name for the far end comes from whatever DNS answer
		// it last saw point at that address. For an address shared by many
		// sites (a CDN or any anycast range) that is a coincidence, not a
		// label: one probe of example.com from the gateway had every session
		// to Cloudflare reading "example.com" for a day. Only an address that
		// is not anycast takes the probe's name; the rest stay unnamed until
		// the client says a name itself (SNI, Host, the DNS query).
		if n := srv.str("name"); n != "" && n != dstIP && net.ParseIP(n) == nil && !strings.Contains(n, "@") {
			shared := false
			if anyc, ok := m.ctx.Service("anycast").(core.AnycastLookup); ok {
				shared, _ = anyc.Anycast(dstIP)
			}
			if !shared {
				domain = strings.ToLower(strings.TrimSuffix(n, "."))
				domainSource = "probe_name"
			}
		}
	}
	if domain != "" && (net.ParseIP(domain) != nil || strings.ContainsAny(domain, " /")) {
		domain = ""
	}
	if domain == "" {
		// Stored as NULL, not "none": a later poll of the same flow that has
		// no name must not overwrite the source recorded when it had one
		// (the update uses COALESCE, so NULL keeps what is there).
		domainSource = ""
	}
	m.mu.Lock()
	cat := m.apps[app].Category
	if cat == "" {
		cat = m.apps[l7].Category
	}
	m.mu.Unlock()
	if c := f.sub("category"); c != nil && cat == "" {
		cat = c.str("name")
	}
	if cat == "" {
		cat = f.str("category_name", "cat_name")
	}
	// Country source is always from the enrichment database when present
	countrySource := "none"
	if country := srv.str("country"); country != "" && country != "-" {
		countrySource = "database"
	}

	fl := core.Flow{
		TS: first, Key: key, SrcIP: srcIP, SrcPort: int(cli.num("port")), DstIP: dstIP,
		DstPort: int(srv.num("port")), Proto: strings.ToLower(l4), App: app, Category: cat, Domain: domain,
		DomainSource: domainSource, BytesIn: in, BytesOut: out, Packets: f.i64("packets", "num_packets"),
		Duration: f.num("duration"), Source: "ntopng", Iface: ifname,
		Country: srv.str("country"), CountrySource: countrySource, TLSVersion: f.str("tls_version"),
	}
	if e := f.str("encrypted"); e == "true" && fl.TLSVersion == "" {
		fl.TLSVersion = "TLS"
	}
	// Derive visibility: whether and how the flow is readable
	fl.Visibility = m.deriveVisibility(fl, l7)

	if fl.SrcIP == "" || fl.DstIP == "" {
		return core.Flow{}, false
	}
	return fl, true
}

// deriveVisibility determines why a flow is or is not readable.
func (m *Module) deriveVisibility(fl core.Flow, l7 string) string {
	// DNS: always readable
	if fl.Proto == "udp" && (fl.DstPort == 53 || strings.Contains(strings.ToLower(l7), "dns")) {
		return "dns"
	}
	// QUIC: encrypted, usually no server name available
	if fl.Proto == "udp" && fl.DstPort == 443 && strings.Contains(strings.ToLower(l7), "quic") {
		if fl.Domain != "" {
			return "quic"
		}
		return "quic"
	}
	// Plain HTTP: unencrypted
	if fl.DstPort == 80 || (strings.ToLower(fl.App) == "http" && fl.TLSVersion == "") {
		return "http"
	}
	// TLS encrypted
	if fl.TLSVersion != "" {
		// If we have a domain/SNI, it came from ClientHello
		if fl.Domain != "" {
			return "sni"
		}
		// Check if ECH was detected by the inspect module
		tlsObs, ok := m.ctx.Service("tls_observations").(interface {
			HasECH(src, dst string, dstPort int) bool
		})
		if ok && tlsObs.HasECH(fl.SrcIP, fl.DstIP, fl.DstPort) {
			return "ech"
		}
		// Otherwise encrypted with no visible name
		return "opaque"
	}
	// Everything else: encrypted without a handshake we could read, or plain.
	// Never empty: a session always says what could be seen of it.
	if fl.DstPort == 443 || isLikelyEncrypted(l7, fl.DstPort) {
		if fl.Domain != "" {
			return "sni"
		}
		return "opaque"
	}
	return "plain"
}

// isLikelyEncrypted checks if a protocol or port suggests encrypted traffic
func isLikelyEncrypted(l7 string, dstPort int) bool {
	lower := strings.ToLower(l7)
	// Known encrypted protocols
	if strings.Contains(lower, "tls") || strings.Contains(lower, "ssl") ||
		strings.Contains(lower, "quic") || strings.Contains(lower, "https") ||
		strings.Contains(lower, "ssh") || strings.Contains(lower, "wireguard") ||
		strings.Contains(lower, "tailscale") {
		return true
	}
	// Common encrypted ports
	if dstPort == 443 || dstPort == 8443 || dstPort == 22 {
		return true
	}
	return false
}

// ---------------------------------------------------------------- API

func (m *Module) name(ip string) string {
	if m.identity == nil {
		return ""
	}
	return m.identity.Name(ip)
}

func (m *Module) apiSummary(r *core.Req) (any, error) {
	st := m.ctx.Store
	now := time.Now().Unix()
	latest := func(name string) float64 {
		return st.Float(`SELECT SUM(value) FROM metrics WHERE name=? AND ts=(SELECT MAX(ts) FROM metrics WHERE name=?)`,
			name, name)
	}
	m.mu.Lock()
	ifs := append([]iface(nil), m.ifs...)
	lastErr, lastOK := m.lastErr, m.lastOK
	m.mu.Unlock()
	return map[string]any{
		"throughput_bps": latest("throughput_bps"), "throughput_pps": latest("throughput_pps"),
		"throughput_download_bps": latest("throughput_download_bps"), "throughput_upload_bps": latest("throughput_upload_bps"),
		"active_flows": latest("active_flows"), "active_hosts": latest("active_hosts"),
		"active_devices":        latest("active_devices"),
		"flows_last_hour":       st.Int(`SELECT COUNT(*) FROM flows WHERE ts>=?`, now-3600),
		"hosts_last_hour":       st.Int(`SELECT COUNT(*) FROM hosts WHERE is_local=1 AND last_seen>=?`, now-3600),
		"blocked_last_hour":     st.Int(`SELECT COUNT(*) FROM flows WHERE ts>=? AND verdict='blocked'`, now-3600),
		"alerts_last_hour":      st.Int(`SELECT COUNT(*) FROM alerts WHERE ts>=?`, now-3600),
		"dns_last_hour":         st.Int(`SELECT COUNT(*) FROM dns WHERE ts>=?`, now-3600),
		"dns_blocked_last_hour": st.Int(`SELECT COUNT(*) FROM dns WHERE ts>=? AND action<>'pass'`, now-3600),
		"interfaces":            ifs, "source_ok": lastErr == "", "source_error": lastErr, "source_updated": lastOK.Unix(),
	}, nil
}

func (m *Module) apiFlows(r *core.Req) (any, error) {
	minutes := r.QInt("minutes", 15, 1, 24*60*7)
	limit := r.QInt("limit", 200, 1, 5000)
	ip, err := r.QSafe("ip", "", 64)
	if err != nil {
		return nil, err
	}
	app, err := r.QSafe("app", "", 64)
	if err != nil {
		return nil, err
	}
	q := `SELECT id,ts,end_ts,src_ip,src_port,dst_ip,dst_port,proto,app,category,domain,domain_source,bytes_in,bytes_out,
		duration,verdict,policy,source,iface,tls_version,tls_sni,country,country_source,anycast,visibility FROM flows WHERE COALESCE(end_ts,ts)>=?`
	args := []any{time.Now().Unix() - int64(minutes)*60}
	if ip != "" {
		q += ` AND (src_ip=? OR dst_ip=?)`
		args = append(args, ip, ip)
	}
	if app != "" {
		q += ` AND app=?`
		args = append(args, app)
	}
	source, err := r.QSafe("source", "", 128)
	if err != nil {
		return nil, err
	}
	if source != "" {
		// Source can be exact match or prefix match (e.g., "netflow5:" matches all netflow5 sources)
		q += ` AND source=?`
		args = append(args, source)
	}
	if r.Q("blocked", "") != "" {
		q += ` AND verdict='blocked'`
	}
	if vis, _ := r.QSafe("visibility", "", 16); vis != "" {
		q += ` AND visibility=?`
		args = append(args, vis)
	}
	// Where the far end is. "country=DE" is one country; "abroad=1" is any
	// country other than the one this gateway sits in.
	if cc, _ := r.QSafe("country", "", 2); cc != "" {
		q += ` AND upper(country)=?`
		args = append(args, strings.ToUpper(cc))
	}
	home := m.homeCountry()
	// "abroad" leaves anycast far ends out: their country is a registration,
	// not a place. "anycast=1" shows exactly those.
	if r.Q("abroad", "") != "" && home != "" {
		q += ` AND country<>'' AND country<>'-' AND upper(country)<>? AND COALESCE(anycast,0)=0`
		args = append(args, home)
	}
	if r.Q("anycast", "") != "" {
		q += ` AND anycast=1`
	}
	q += ` ORDER BY COALESCE(end_ts,ts) DESC LIMIT ?`
	args = append(args, limit)
	rows, err := m.ctx.Store.Rows(q, args...)
	if err != nil {
		return nil, err
	}
	m.decorate(rows, "src_ip", "src_name")
	m.decorate(rows, "dst_ip", "dst_name")
	return map[string]any{"flows": rows, "home_country": home}, nil
}

// homeCountry asks the paths module where this gateway is.
func (m *Module) homeCountry() string {
	if h, ok := m.ctx.Service("home").(interface{ HomeCountry() string }); ok && h != nil {
		return h.HomeCountry()
	}
	return ""
}

// apiAbroad answers "which of my devices talk to other countries, and to
// whom": per local device, the foreign countries it reached in the window,
// sessions and bytes per country, and the destinations behind them. Built
// from the flow table (which carries the far end's country), so it needs
// no database of its own. A device with no foreign traffic is absent.
func (m *Module) apiAbroad(r *core.Req) (any, error) {
	hours := r.Hours(24)
	since := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	devLimit := r.QInt("limit", 50, 1, 1000)
	offset := r.QInt("offset", 0, 0, 100000)
	summary := r.Q("detail", "") == "summary"
	ip, err := r.QSafe("ip", "", 64)
	if err != nil {
		return nil, err
	}
	home := m.homeCountry()
	q := `SELECT src_ip, upper(country) AS cc, dst_ip, MAX(domain) AS domain, COUNT(*) AS sessions, MAX(COALESCE(anycast,0)) AS anycast,
		SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out, MAX(COALESCE(end_ts,ts)) AS last_seen
		FROM flows WHERE COALESCE(end_ts,ts)>=? AND country<>'' AND country<>'-'`
	args := []any{since}
	if home != "" {
		q += ` AND upper(country)<>?`
		args = append(args, home)
	}
	if ip != "" {
		// The address stands for its device: every address the device
		// holds, v4 and v6, or the rows for an IPv6-only lease go unseen.
		addrs := []string{ip}
		if ab, ok := m.ctx.Service("identity").(core.AddressBook); ok {
			if list := ab.Addresses(ip); len(list) > 0 {
				addrs = list
			}
		}
		q += ` AND src_ip IN (?` + strings.Repeat(",?", len(addrs)-1) + `)`
		for _, a := range addrs {
			args = append(args, a)
		}
	}
	q += ` GROUP BY src_ip, cc, dst_ip ORDER BY sessions DESC`
	rows, err := m.ctx.Store.Rows(q, args...)
	if err != nil {
		return nil, err
	}
	type dest struct {
		IP       string `json:"ip"`
		Name     string `json:"name,omitempty"`
		Domain   string `json:"domain,omitempty"`
		Sessions int64  `json:"sessions"`
		Bytes    int64  `json:"bytes"`
	}
	type country struct {
		Country  string  `json:"country"`
		Sessions int64   `json:"sessions"`
		BytesIn  int64   `json:"bytes_in"`
		BytesOut int64   `json:"bytes_out"`
		LastSeen int64   `json:"last_seen"`
		Dests    []*dest `json:"destinations"`
	}
	type device struct {
		IP       string   `json:"ip"`
		IPs      []string `json:"other_ips,omitempty"`
		Name     string   `json:"name,omitempty"`
		MAC      string   `json:"mac,omitempty"`
		Sessions int64    `json:"sessions"`
		// Anycast far ends are counted apart: they are reached at a nearby
		// site, so their registered country says nothing about where the
		// traffic went.
		AnycastSessions int64               `json:"anycast_sessions"`
		AnycastDests    []*dest             `json:"anycast_destinations,omitempty"`
		Countries       []*country          `json:"countries"`
		byCC            map[string]*country `json:"-"`
	}
	devs := map[string]*device{}
	var order []string
	for _, row := range rows {
		src, _ := row["src_ip"].(string)
		if src == "" || (m.identity != nil && !m.identity.IsLocal(src)) {
			continue
		}
		cc, _ := row["cc"].(string)
		// One row per device: addresses (v4 and v6) fold into their MAC.
		mac := ""
		if m.identity != nil {
			mac = m.identity.MAC(src)
		}
		key := src
		if mac != "" {
			key = mac
		}
		d := devs[key]
		if d == nil {
			d = &device{IP: src, Name: m.name(src), MAC: mac, byCC: map[string]*country{}}
			devs[key] = d
			order = append(order, key)
		} else if d.IP != src && !containsStr(d.IPs, src) {
			d.IPs = append(d.IPs, src)
		}
		n := toI(row["sessions"])
		if toI(row["anycast"]) != 0 {
			d.AnycastSessions += n
			if len(d.AnycastDests) < 5 {
				dip, _ := row["dst_ip"].(string)
				dom, _ := row["domain"].(string)
				d.AnycastDests = append(d.AnycastDests, &dest{IP: dip, Name: m.name(dip), Domain: dom, Sessions: n, Bytes: toI(row["bytes_in"]) + toI(row["bytes_out"])})
			}
			continue
		}
		c := d.byCC[cc]
		if c == nil {
			c = &country{Country: cc}
			d.byCC[cc] = c
			d.Countries = append(d.Countries, c)
		}
		c.Sessions += n
		d.Sessions += n
		c.BytesIn += toI(row["bytes_in"])
		c.BytesOut += toI(row["bytes_out"])
		if ls := toI(row["last_seen"]); ls > c.LastSeen {
			c.LastSeen = ls
		}
		if len(c.Dests) < 5 {
			dip, _ := row["dst_ip"].(string)
			dom, _ := row["domain"].(string)
			c.Dests = append(c.Dests, &dest{IP: dip, Name: m.name(dip), Domain: dom, Sessions: n, Bytes: toI(row["bytes_in"]) + toI(row["bytes_out"])})
		}
	}
	out := make([]*device, 0, len(order))
	for _, k := range order {
		d := devs[k]
		if len(d.Countries) == 0 {
			continue // only anycast far ends: nothing we can say left the country
		}
		sort.Slice(d.Countries, func(i, j int) bool { return d.Countries[i].Sessions > d.Countries[j].Sessions })
		out = append(out, d)
	}
	total := len(out)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Sessions > out[j].Sessions })
	if offset >= len(out) {
		out = nil
	} else {
		out = out[offset:]
	}
	if len(out) > devLimit {
		out = out[:devLimit]
	}
	res := map[string]any{"home_country": home, "devices_total": total, "limit": devLimit, "offset": offset, "hours": hours}
	if !summary {
		res["devices"] = out
		return res, nil
	}
	// The summary is the overview: one small row per device, countries as
	// session counts, no destinations. Twenty times smaller, so a whole
	// network fits in one answer; detail follows per device with ip=.
	type brief struct {
		IP              string           `json:"ip"`
		Name            string           `json:"name,omitempty"`
		MAC             string           `json:"mac,omitempty"`
		Sessions        int64            `json:"sessions"`
		AnycastSessions int64            `json:"anycast_sessions,omitempty"`
		Countries       map[string]int64 `json:"countries"`
	}
	briefs := make([]brief, 0, len(out))
	for _, d := range out {
		b := brief{IP: d.IP, Name: d.Name, MAC: d.MAC, Sessions: d.Sessions, AnycastSessions: d.AnycastSessions, Countries: map[string]int64{}}
		for _, c := range d.Countries {
			b.Countries[c.Country] = c.Sessions
		}
		briefs = append(briefs, b)
	}
	res["detail"] = "summary"
	res["devices"] = briefs
	return res, nil
}

// topHostsBy answers "who does this": for each key (an app, a category, a
// site) the hosts that used it most, by sessions, named. Bytes ride along.
// keyExpr is the SQL expression that yields the key from the rollup row.
func (m *Module) topHostsBy(table, keyExpr string, keys []string, since int64, per int) map[string][]map[string]any {
	out := map[string][]map[string]any{}
	if len(keys) == 0 {
		return out
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(keys)), ",")
	args := []any{since}
	for _, k := range keys {
		args = append(args, k)
	}
	rows, err := m.ctx.Store.Rows(`SELECT `+keyExpr+` AS k, src_ip AS ip, SUM(flows) AS flows, SUM(bytes_in) AS bytes_in,
		SUM(bytes_out) AS bytes_out, MAX(bucket) AS last_seen FROM `+table+` WHERE bucket>=? AND `+keyExpr+` IN (`+ph+`)
		GROUP BY 1, 2 ORDER BY 1, flows DESC`, args...)
	if err != nil {
		return out
	}
	// One device, not one address: a laptop with an IPv4 lease and five
	// rotating IPv6 addresses is one host doing this, so rows fold by the
	// hardware address when identity knows it.
	type acc struct {
		row  map[string]any
		seen map[string]bool
	}
	byKey := map[string]map[string]*acc{}
	order := map[string][]string{}
	for _, r := range rows {
		k, _ := r["k"].(string)
		ip, _ := r["ip"].(string)
		dev := ip
		if m.identity != nil {
			if mac := m.identity.MAC(ip); mac != "" {
				dev = "mac:" + mac
			}
		}
		if byKey[k] == nil {
			byKey[k] = map[string]*acc{}
		}
		a := byKey[k][dev]
		if a == nil {
			a = &acc{row: map[string]any{"ip": ip, "flows": int64(0), "bytes_in": int64(0), "bytes_out": int64(0), "last_seen": int64(0)}, seen: map[string]bool{}}
			if n := m.name(ip); n != "" {
				a.row["name"] = n
			}
			byKey[k][dev] = a
			order[k] = append(order[k], dev)
		}
		a.row["flows"] = toI(a.row["flows"]) + toI(r["flows"])
		a.row["bytes_in"] = toI(a.row["bytes_in"]) + toI(r["bytes_in"])
		a.row["bytes_out"] = toI(a.row["bytes_out"]) + toI(r["bytes_out"])
		if toI(r["last_seen"]) > toI(a.row["last_seen"]) {
			a.row["last_seen"] = toI(r["last_seen"])
		}
		// Prefer the IPv4 address as the device's face when it has one.
		if cur, _ := a.row["ip"].(string); strings.Contains(cur, ":") && !strings.Contains(ip, ":") {
			a.row["ip"] = ip
			if n := m.name(ip); n != "" {
				a.row["name"] = n
			}
		}
		a.seen[ip] = true
	}
	for k, devs := range byKey {
		list := make([]map[string]any, 0, len(devs))
		for _, dev := range order[k] {
			list = append(list, devs[dev].row)
		}
		sort.SliceStable(list, func(i, j int) bool { return toI(list[i]["flows"]) > toI(list[j]["flows"]) })
		total := len(list)
		if len(list) > per {
			list = list[:per]
		}
		// The first entry carries the device count for the key.
		if len(list) > 0 {
			list[0]["_devices"] = int64(total)
		}
		out[k] = list
	}
	return out
}

// attachTopHosts puts top_hosts on each row, keyed by keyCol, and replaces
// the address count with the device count where it was folded.
func attachTopHosts(rows []map[string]any, keyCol string, top map[string][]map[string]any) {
	for _, r := range rows {
		k, _ := r[keyCol].(string)
		th := top[k]
		if th == nil {
			r["top_hosts"] = []map[string]any{}
			continue
		}
		if len(th) > 0 {
			if n, ok := th[0]["_devices"].(int64); ok {
				r["hosts"] = n
				delete(th[0], "_devices")
			}
		}
		r["top_hosts"] = th
	}
}

func keysOf(rows []map[string]any, col string) []string {
	var ks []string
	for _, r := range rows {
		if k, _ := r[col].(string); k != "" {
			ks = append(ks, k)
		}
	}
	return ks
}

func (m *Module) decorate(rows []map[string]any, ipKey, nameKey string) {
	for _, row := range rows {
		ip, _ := row[ipKey].(string)
		if n := m.name(ip); n != "" {
			row[nameKey] = n
		}
	}
}

func (m *Module) apiApps(r *core.Req) (any, error) {
	since := r.Since(24)
	ip, err := r.QSafe("ip", "", 64)
	if err != nil {
		return nil, err
	}
	q := `SELECT app, MAX(category) AS category, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out,
		SUM(flows) AS flows, SUM(CASE WHEN verdict='blocked' THEN flows ELSE 0 END) AS blocked,
		COUNT(DISTINCT src_ip) AS hosts, MAX(bucket) AS last_seen FROM rollup_app WHERE bucket>=?`
	args := []any{since}
	if ip != "" {
		q += ` AND src_ip=?`
		args = append(args, ip)
	}
	q += ` GROUP BY app ORDER BY flows DESC LIMIT 500`
	rows, err := m.ctx.Store.Rows(q, args...)
	if err != nil {
		return nil, err
	}
	// The current, unrolled bucket adds what happened in the last few minutes.
	live, _ := m.ctx.Store.Rows(`SELECT app, MAX(category) AS category, SUM(bytes_in) AS bytes_in,
		SUM(bytes_out) AS bytes_out, COUNT(*) AS flows FROM flows WHERE ts>=? `+
		func() string {
			if ip != "" {
				return "AND src_ip=? "
			}
			return ""
		}()+`GROUP BY app`, append([]any{time.Now().Unix() - time.Now().Unix()%300}, func() []any {
		if ip != "" {
			return []any{ip}
		}
		return nil
	}()...)...)
	idx := map[string]map[string]any{}
	for _, row := range rows {
		idx[row["app"].(string)] = row
	}
	for _, l := range live {
		a, _ := l["app"].(string)
		if row, ok := idx[a]; ok {
			row["bytes_in"] = toI(row["bytes_in"]) + toI(l["bytes_in"])
			row["bytes_out"] = toI(row["bytes_out"]) + toI(l["bytes_out"])
			row["flows"] = toI(row["flows"]) + toI(l["flows"])
		} else {
			l["blocked"], l["hosts"] = 0, 1
			rows = append(rows, l)
		}
	}
	m.mu.Lock()
	for _, row := range rows {
		a, _ := row["app"].(string)
		row["breed"] = m.apps[a].Breed
		if row["category"] == nil || row["category"] == "" {
			row["category"] = m.apps[a].Category
		}
	}
	m.mu.Unlock()
	// Activity first: sessions, then bytes as the tie-break.
	sort.Slice(rows, func(i, j int) bool {
		if toI(rows[i]["flows"]) != toI(rows[j]["flows"]) {
			return toI(rows[i]["flows"]) > toI(rows[j]["flows"])
		}
		return toI(rows[i]["bytes_in"])+toI(rows[i]["bytes_out"]) > toI(rows[j]["bytes_in"])+toI(rows[j]["bytes_out"])
	})
	if ip == "" {
		top := rows
		if len(top) > 60 {
			top = top[:60]
		}
		attachTopHosts(rows, "app", m.topHostsBy("rollup_app", "app", keysOf(top, "app"), since, 3))
	}
	return map[string]any{"apps": rows}, nil
}

func toI(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case float64:
		return int64(x)
	case int:
		return int64(x)
	}
	return 0
}

func (m *Module) apiTop(r *core.Req) (any, error) {
	since := r.Since(24)
	limit := r.QInt("limit", 15, 1, 200)
	st := m.ctx.Store
	// Ranked by activity (sessions), not bytes: one backup moving a terabyte
	// is not what the household is doing. Bytes ride along for the tooltip,
	// and every row says which hosts did it.
	hosts, err := st.Rows(`SELECT src_ip AS ip, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out,
		SUM(flows) AS flows, SUM(CASE WHEN verdict='blocked' THEN flows ELSE 0 END) AS blocked, MAX(bucket) AS last_seen,
		COUNT(DISTINCT app) AS apps
		FROM rollup_app WHERE bucket>=? GROUP BY src_ip ORDER BY flows DESC LIMIT ?`, since, limit*4)
	if err != nil {
		return nil, err
	}
	m.decorate(hosts, "ip", "name")
	hosts = m.foldHostsByDevice(hosts, limit)
	apps, _ := st.Rows(`SELECT app, MAX(category) AS category, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out,
		SUM(flows) AS flows, COUNT(DISTINCT src_ip) AS hosts, MAX(bucket) AS last_seen
		FROM rollup_app WHERE bucket>=? GROUP BY app ORDER BY flows DESC LIMIT ?`,
		since, limit)
	attachTopHosts(apps, "app", m.topHostsBy("rollup_app", "app", keysOf(apps, "app"), since, 3))
	cats, _ := st.Rows(`SELECT COALESCE(NULLIF(category,''),'Unknown') AS category, SUM(bytes_in) AS bytes_in,
		SUM(bytes_out) AS bytes_out, SUM(flows) AS flows, COUNT(DISTINCT src_ip) AS hosts, MAX(bucket) AS last_seen
		FROM rollup_app WHERE bucket>=? GROUP BY 1
		ORDER BY flows DESC LIMIT ?`, since, limit)
	attachTopHosts(cats, "category", m.topHostsBy("rollup_app", "COALESCE(NULLIF(category,''),'Unknown')", keysOf(cats, "category"), since, 3))
	domains, _ := st.Rows(`SELECT domain, MAX(category) AS category, SUM(bytes_in) AS bytes_in,
		SUM(bytes_out) AS bytes_out, SUM(flows) AS flows, COUNT(DISTINCT src_ip) AS hosts, MAX(bucket) AS last_seen
		FROM rollup_domain WHERE bucket>=? GROUP BY domain ORDER BY flows DESC LIMIT ?`, since, limit)
	attachTopHosts(domains, "domain", m.topHostsBy("rollup_domain", "domain", keysOf(domains, "domain"), since, 3))
	m.endpointsFor(domains, since)
	dsts, _ := st.Rows(`SELECT dst_ip AS ip, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out,
		SUM(flows) AS flows, COUNT(DISTINCT src_ip) AS hosts FROM rollup_dst WHERE bucket>=?
		GROUP BY dst_ip ORDER BY bytes_in+bytes_out DESC LIMIT ?`, since, limit)
	m.decorate(dsts, "ip", "name")
	for _, d := range dsts {
		if d["name"] == nil {
			ip, _ := d["ip"].(string)
			if n, _ := st.Row(`SELECT name FROM dns_names WHERE ip=?`, ip); n != nil {
				d["name"] = n["name"]
			}
		}
	}
	blocked, _ := st.Rows(`SELECT src_ip AS ip, app, SUM(flows) AS flows FROM rollup_app WHERE bucket>=? AND
		verdict='blocked' GROUP BY src_ip, app ORDER BY flows DESC LIMIT ?`, since, limit)
	m.decorate(blocked, "ip", "name")
	return map[string]any{"hosts": hosts, "apps": apps, "categories": cats, "domains": domains,
		"destinations": dsts, "blocked": blocked}, nil
}

// endpointsFor puts, on each top site, the address that site's traffic
// actually went to -- the endpoint the Map page can show the route to. A
// site is a name and a route is to an address; the flows join the two. Where
// several addresses served the name, one with a measured route wins, then
// the busiest. Rows gain dst_ip and traced; a site nothing can be found for
// gains nothing.
func (m *Module) endpointsFor(domains []map[string]any, since int64) {
	if len(domains) == 0 {
		return
	}
	names := make([]string, 0, len(domains))
	args := []any{since}
	ph := make([]string, 0, len(domains))
	for _, d := range domains {
		if n, _ := d["domain"].(string); n != "" {
			names = append(names, n)
			args = append(args, n)
			ph = append(ph, "?")
		}
	}
	if len(names) == 0 {
		return
	}
	// The Overview asks every couple of minutes and the answer moves slower
	// than that; the join is remembered briefly against the sites asked
	// about, so a page refresh is a lookup rather than a pass over the day.
	memoKey := fmt.Sprintf("%d|%s", since-since%300, strings.Join(names, ","))
	m.epMu.Lock()
	if m.epAt.Add(2*time.Minute).After(time.Now()) && m.epKey == memoKey {
		for _, d := range domains {
			if n, _ := d["domain"].(string); n != "" {
				if p, ok := m.epBest[n]; ok {
					d["dst_ip"], d["traced"] = p.ip, p.traced
				}
			}
		}
		m.epMu.Unlock()
		return
	}
	m.epMu.Unlock()
	in := strings.Join(ph, ",")
	rows, err := m.ctx.Store.Rows(`SELECT f.domain AS domain, f.dst_ip AS ip, SUM(f.bytes_in+f.bytes_out) AS b,
		MAX(CASE WHEN p.dst IS NULL THEN 0 ELSE 1 END) AS traced
		FROM flows f LEFT JOIN path_runs p ON p.dst = f.dst_ip
		WHERE f.ts > ? AND f.dst_ip <> '' AND f.domain IN (`+in+`) GROUP BY f.domain, f.dst_ip`, args...)
	if err != nil {
		// Without the paths module there is no path_runs table; the busiest
		// address still answers the question.
		rows, err = m.ctx.Store.Rows(`SELECT domain, dst_ip AS ip, SUM(bytes_in+bytes_out) AS b, 0 AS traced
			FROM flows WHERE ts > ? AND dst_ip <> '' AND domain IN (`+in+`) GROUP BY domain, dst_ip`, args...)
		if err != nil {
			return
		}
	}
	best := map[string]endpointPick{}
	for _, r := range rows {
		dom, _ := r["domain"].(string)
		ip, _ := r["ip"].(string)
		b := asInt64(r["b"])
		traced := asInt64(r["traced"]) > 0
		cur, ok := best[dom]
		if !ok || (traced && !cur.traced) || (traced == cur.traced && b > cur.b) {
			best[dom] = endpointPick{ip, b, traced}
		}
	}
	m.epMu.Lock()
	m.epBest, m.epKey, m.epAt = best, memoKey, time.Now()
	m.epMu.Unlock()
	for _, d := range domains {
		if n, _ := d["domain"].(string); n != "" {
			if p, ok := best[n]; ok {
				d["dst_ip"], d["traced"] = p.ip, p.traced
			}
		}
	}
}

// endpointPick is one site's endpoint: the address, how much went there,
// and whether the map has a route to it.
type endpointPick struct {
	ip     string
	b      int64
	traced bool
}

func asInt64(v any) int64 {
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

func (m *Module) apiTimeseries(r *core.Req) (any, error) {
	hours := r.Hours(24)
	since := time.Now().Unix() - int64(hours)*3600
	step := r.QInt("step", 0, 0, 86400)
	if step == 0 {
		switch {
		case hours <= 3:
			step = 60
		case hours <= 24:
			step = 300
		case hours <= 24*7:
			step = 1800
		default:
			step = 3600
		}
	}
	metric, err := r.QSafe("metric", "", 40)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"step": step, "since": since}
	series := func(name string) []map[string]any {
		rows, _ := m.ctx.Store.Rows(`SELECT (ts/?)*? AS t, AVG(v) AS v FROM (SELECT ts, SUM(value) AS v FROM metrics
			WHERE name=? AND ts>=? GROUP BY ts) GROUP BY t ORDER BY t`, step, step, name, since)
		return rows
	}
	names := []string{"throughput_bps", "throughput_download_bps", "throughput_upload_bps", "active_flows", "active_hosts"}
	if metric != "" {
		names = []string{metric}
	}
	for _, n := range names {
		out[n] = series(n)
	}
	if metric == "" || metric == "traffic" {
		out["traffic"], _ = m.ctx.Store.Rows(`SELECT (bucket/?)*? AS t, SUM(bytes_in) AS bytes_in,
			SUM(bytes_out) AS bytes_out, SUM(flows) AS flows,
			SUM(CASE WHEN verdict='blocked' THEN flows ELSE 0 END) AS blocked
			FROM rollup_app WHERE bucket>=? GROUP BY t ORDER BY t`, step, step, since)
	}
	if metric == "" || metric == "dns" {
		out["dns"], _ = m.ctx.Store.Rows(`SELECT (bucket/?)*? AS t, SUM(queries) AS queries,
			SUM(CASE WHEN action<>'pass' THEN queries ELSE 0 END) AS blocked FROM rollup_dns
			WHERE bucket>=? GROUP BY t ORDER BY t`, step, step, since)
	}
	if metric == "" || metric == "alerts" {
		out["alerts"], _ = m.ctx.Store.Rows(`SELECT (ts/?)*? AS t, COUNT(*) AS alerts FROM alerts
			WHERE ts>=? GROUP BY t ORDER BY t`, step, step, since)
	}
	return out, nil
}

func (m *Module) apiHost(r *core.Req) (any, error) {
	ip := r.Q("ip", "")
	if net.ParseIP(ip) == nil {
		return nil, core.BadRequest("ip must be an address")
	}
	since := r.Since(24)
	st := m.ctx.Store
	host, _ := st.Row(`SELECT * FROM hosts WHERE ip=?`, ip)
	if host == nil {
		host = map[string]any{"ip": ip}
	}
	if m.identity != nil {
		if n := m.identity.Name(ip); n != "" {
			host["name"] = n
		}
		mac, _ := host["mac"].(string)
		if mac == "" {
			mac = m.identity.MAC(ip)
			host["mac"] = mac
		}
		host["vendor"] = m.identity.Vendor(mac)
	}
	device, _ := st.Row(`SELECT * FROM devices WHERE mac=?`, host["mac"])

	// Get proxmox reference if available
	type ProxmoxGuestRef interface {
		GuestFor(macOrIP string) (any, bool)
	}
	if proxmoxSvc, ok := m.ctx.Service("proxmox").(ProxmoxGuestRef); ok {
		mac, _ := host["mac"].(string)
		if ref, found := proxmoxSvc.GuestFor(mac); found {
			if refMap, ok := ref.(map[string]interface{}); ok {
				device["proxmox"] = refMap
			}
		} else if ref, found := proxmoxSvc.GuestFor(ip); found {
			if refMap, ok := ref.(map[string]interface{}); ok {
				device["proxmox"] = refMap
			}
		}
	}

	apps, _ := st.Rows(`SELECT app, MAX(category) AS category, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out,
		SUM(flows) AS flows, SUM(CASE WHEN verdict='blocked' THEN flows ELSE 0 END) AS blocked FROM rollup_app
		WHERE bucket>=? AND src_ip=? GROUP BY app ORDER BY bytes_in+bytes_out DESC LIMIT 50`, since, ip)
	domains, _ := st.Rows(`SELECT domain, MAX(category) AS category, SUM(bytes_in) AS bytes_in,
		SUM(bytes_out) AS bytes_out, SUM(flows) AS flows FROM rollup_domain WHERE bucket>=? AND src_ip=?
		GROUP BY domain ORDER BY bytes_in+bytes_out DESC LIMIT 50`, since, ip)
	dsts, _ := st.Rows(`SELECT dst_ip AS ip, dst_port AS port, proto, SUM(bytes_in) AS bytes_in,
		SUM(bytes_out) AS bytes_out, SUM(flows) AS flows FROM rollup_dst WHERE bucket>=? AND src_ip=?
		GROUP BY dst_ip, dst_port, proto ORDER BY bytes_in+bytes_out DESC LIMIT 50`, since, ip)
	for _, d := range dsts {
		dip, _ := d["ip"].(string)
		if n, _ := st.Row(`SELECT name FROM dns_names WHERE ip=?`, dip); n != nil {
			d["name"] = n["name"]
		}
	}
	timeline, _ := st.Rows(`SELECT bucket AS t, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out, SUM(flows) AS flows,
		SUM(CASE WHEN verdict='blocked' THEN flows ELSE 0 END) AS blocked FROM rollup_app WHERE bucket>=? AND src_ip=?
		GROUP BY bucket ORDER BY bucket`, since, ip)
	dns, _ := st.Rows(`SELECT domain, action, MAX(list) AS list, SUM(queries) AS queries FROM rollup_dns
		WHERE bucket>=? AND client=? GROUP BY domain, action ORDER BY queries DESC LIMIT 50`, since, ip)
	dnsBlocked, _ := st.Rows(`SELECT ts, domain, qtype, list, rcode, source FROM dns WHERE client=? AND action<>'pass' AND ts>=?
		ORDER BY ts DESC LIMIT 100`, ip, since)
	dnsTotals, _ := st.Row(`SELECT SUM(queries) AS queries, SUM(CASE WHEN action<>'pass' THEN queries ELSE 0 END) AS blocked,
		COUNT(DISTINCT domain) AS domains FROM rollup_dns WHERE bucket>=? AND client=?`, since, ip)
	alerts, _ := st.Rows(`SELECT * FROM alerts WHERE ts>=? AND (src_ip=? OR dst_ip=?) ORDER BY ts DESC LIMIT 50`,
		since, ip, ip)
	flows, _ := st.Rows(`SELECT ts,end_ts,dst_ip,dst_port,proto,app,category,domain,bytes_in,bytes_out,duration,verdict,policy
		FROM flows WHERE src_ip=? ORDER BY COALESCE(end_ts,ts) DESC LIMIT 100`, ip)
	m.decorate(flows, "dst_ip", "dst_name")
	tls, _ := st.Rows(`SELECT sni, version, mode, COUNT(*) AS sessions FROM tls_sessions WHERE ts>=? AND src_ip=?
		GROUP BY sni, version, mode ORDER BY sessions DESC LIMIT 50`, since, ip)
	totals, _ := st.Row(`SELECT SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out, SUM(flows) AS flows,
		SUM(CASE WHEN verdict='blocked' THEN flows ELSE 0 END) AS blocked FROM rollup_app WHERE bucket>=? AND src_ip=?`,
		since, ip)
	findings, _ := st.Rows(`SELECT * FROM findings WHERE resolved_ts IS NULL AND subject=? ORDER BY ts DESC LIMIT 20`, ip)
	return map[string]any{"host": host, "device": device, "apps": apps, "domains": domains, "destinations": dsts,
		"timeline": timeline, "dns": dns, "dns_blocked": dnsBlocked, "dns_totals": dnsTotals, "alerts": alerts, "flows": flows, "tls": tls,
		"addresses": m.addressesOf(ip),
		"totals":    totals, "findings": findings, "hours": r.Hours(24)}, nil
}

func (m *Module) apiCatalog(r *core.Req) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cats := map[string]int{}
	apps := make([]map[string]any, 0, len(m.apps))
	for name, a := range m.apps {
		apps = append(apps, map[string]any{"app": name, "category": a.Category, "breed": a.Breed, "id": a.ID})
		cats[a.Category]++
	}
	sort.Slice(apps, func(i, j int) bool { return apps[i]["app"].(string) < apps[j]["app"].(string) })
	var catList []map[string]any
	for c, n := range cats {
		catList = append(catList, map[string]any{"category": c, "apps": n})
	}
	sort.Slice(catList, func(i, j int) bool { return catList[i]["category"].(string) < catList[j]["category"].(string) })
	return map[string]any{"apps": apps, "categories": catList, "host": hostname()}, nil
}

func hostname() string { h, _ := os.Hostname(); return h }

// EffectiveSettings reports the ntopng endpoint in use when the setting is empty.
func (m *Module) EffectiveSettings() map[string]any {
	base := core.Str(m.ctx.Settings(), "ntopng_url", "")
	if base == "" {
		base = "http://127.0.0.1:3000"
	}
	return map[string]any{"ntopng_url": base}
}

// addressesOf lists every address the device at ip holds, so a host page
// says so and links them; IPv6 is treated exactly like IPv4.
func (m *Module) addressesOf(ip string) []string {
	if ab, ok := m.ctx.Service("identity").(core.AddressBook); ok {
		list := ab.Addresses(ip)
		if len(list) > 1 {
			return list
		}
	}
	return nil
}

// backfillCountries stamps countries, and the anycast flag, on recent flows
// that lack one. A second pass, run once per database, walks the last seven
// days of flows that already had a country to set the anycast flag, which
// arrived later than the country column.
func (m *Module) backfillCountries() error {
	look, _ := m.ctx.Service("enrich").(core.CountryLookup)
	anyc, _ := m.ctx.Service("anycast").(core.AnycastLookup)
	if look == nil && anyc == nil {
		return nil
	}
	since := time.Now().Add(-7 * 24 * time.Hour).Unix()
	type ans struct {
		cc      string
		anycast bool
	}
	memo := map[string]ans{}
	far := func(ip string) ans {
		if ip == "" || (m.identity != nil && m.identity.IsLocal(ip)) {
			return ans{}
		}
		if v, ok := memo[ip]; ok {
			return v
		}
		var v ans
		if look != nil {
			v.cc = look.CountryOf(ip)
		}
		if anyc != nil {
			v.anycast, _ = anyc.Anycast(ip)
		}
		memo[ip] = v
		return v
	}
	rows, err := m.ctx.Store.Rows(`SELECT id, src_ip, dst_ip FROM flows WHERE ts >= ? AND (country IS NULL OR country='') ORDER BY id DESC LIMIT 500`, since)
	if err != nil {
		return err
	}
	for _, r := range rows {
		dst, _ := r["dst_ip"].(string)
		src, _ := r["src_ip"].(string)
		v := far(dst)
		if v.cc == "" && !v.anycast {
			v = far(src)
		}
		cc := v.cc
		if cc == "" {
			cc = "-" // looked at, nothing to say: do not look again
		}
		_ = m.ctx.Store.Exec(`UPDATE flows SET country=?, anycast=? WHERE id=?`, cc, boolInt(v.anycast), toI(r["id"]))
	}
	if anyc == nil {
		return nil
	}
	// One-time anycast pass, resumable, newest first, 2000 rows a minute.
	var after int64 = -1
	if mrow, err := m.ctx.Store.Rows(`SELECT value FROM meta WHERE key='anycast_backfill_before'`); err == nil && len(mrow) > 0 {
		after = toI(mrow[0]["value"])
	}
	if after == 0 {
		return nil // finished
	}
	q := `SELECT id, src_ip, dst_ip FROM flows WHERE ts >= ? AND country<>'' AND country<>'-'`
	args := []any{since}
	if after > 0 {
		q += ` AND id < ?`
		args = append(args, after)
	}
	q += ` ORDER BY id DESC LIMIT 2000`
	rows, err = m.ctx.Store.Rows(q, args...)
	if err != nil {
		return err
	}
	last := int64(0)
	for _, r := range rows {
		dst, _ := r["dst_ip"].(string)
		src, _ := r["src_ip"].(string)
		id := toI(r["id"])
		last = id
		a := far(dst).anycast || far(src).anycast
		if a {
			_ = m.ctx.Store.Exec(`UPDATE flows SET anycast=1 WHERE id=?`, id)
		}
	}
	if len(rows) < 2000 {
		last = 0 // done
	}
	return m.ctx.Store.Exec(`INSERT OR REPLACE INTO meta VALUES('anycast_backfill_before', ?)`, fmt.Sprint(last))
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// foldHostsByDevice makes the top-hosts list one row per device: a laptop
// with an IPv4 lease and a few IPv6 addresses is one entry, its traffic
// summed, the IPv4 address as the row's address and the rest listed.
func (m *Module) foldHostsByDevice(rows []map[string]any, limit int) []map[string]any {
	if m.identity == nil {
		if len(rows) > limit {
			rows = rows[:limit]
		}
		return rows
	}
	type acc struct {
		row   map[string]any
		addrs []string
	}
	byKey := map[string]*acc{}
	var order []string
	for _, r := range rows {
		ip, _ := r["ip"].(string)
		key := ip
		if mac := m.identity.MAC(ip); mac != "" {
			key = mac
			r["mac"] = mac
		}
		a := byKey[key]
		if a == nil {
			a = &acc{row: r}
			byKey[key] = a
			order = append(order, key)
		} else {
			for _, k := range []string{"bytes_in", "bytes_out", "flows", "blocked"} {
				a.row[k] = toI(a.row[k]) + toI(r[k])
			}
			if toI(r["apps"]) > toI(a.row["apps"]) {
				a.row["apps"] = r["apps"]
			}
			if toI(r["last_seen"]) > toI(a.row["last_seen"]) {
				a.row["last_seen"] = r["last_seen"]
			}
			if n, _ := r["name"].(string); n != "" {
				if cur, _ := a.row["name"].(string); cur == "" {
					a.row["name"] = n
				}
			}
			cur, _ := a.row["ip"].(string)
			if strings.Contains(cur, ":") && !strings.Contains(ip, ":") {
				a.row["ip"] = ip
			}
		}
		a.addrs = append(a.addrs, ip)
	}
	out := make([]map[string]any, 0, len(order))
	for _, k := range order {
		a := byKey[k]
		sort.Strings(a.addrs)
		a.row["addresses"] = a.addrs
		out = append(out, a.row)
	}
	sort.SliceStable(out, func(i, j int) bool { return toI(out[i]["flows"]) > toI(out[j]["flows"]) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// apiVisibilityBreakdown returns visibility breakdown for a device
func (m *Module) apiVisibilityBreakdown(r *core.Req) (any, error) {
	ip := r.Q("ip", "")
	if net.ParseIP(ip) == nil {
		return nil, core.BadRequest("ip must be an address")
	}
	hours := r.QInt("hours", 24, 1, 24*30*12)
	since := time.Now().Unix() - int64(hours)*3600

	st := m.ctx.Store
	// Count flows by visibility
	visibilities := []string{"inspected", "sni", "http", "quic", "ech", "opaque", "dns", "plain"}
	counts := make(map[string]int64)
	for _, vis := range visibilities {
		count := st.Int(`SELECT COUNT(*) FROM flows WHERE src_ip=? AND ts>=? AND visibility=?`,
			ip, since, vis)
		if count > 0 {
			counts[vis] = count
		}
	}

	return map[string]any{
		"ip":         ip,
		"hours":      hours,
		"visibility": counts,
	}, nil
}

// checkDarkTraffic checks if any device has dark traffic above threshold and creates findings
func (m *Module) checkDarkTraffic(hours int) error {
	threshold := 50 // Default 50% threshold
	minSessions := int64(50)

	st := m.ctx.Store
	since := time.Now().Unix() - int64(hours)*3600

	// Get all devices and their dark traffic breakdown
	devices, _ := st.Rows(`SELECT src_ip, COUNT(*) as total_flows FROM flows WHERE ts>=?
		GROUP BY src_ip`, since)

	keep := make(map[string]bool)
	for _, d := range devices {
		ip := d["src_ip"].(string)
		totalFlows := int64(d["total_flows"].(float64))
		if totalFlows < minSessions {
			continue
		}

		// Count dark traffic (opaque + ech + quic)
		darkFlows := st.Int(`SELECT COUNT(*) FROM flows WHERE src_ip=? AND ts>=? AND
			(visibility='opaque' OR visibility='ech' OR visibility='quic')`,
			ip, since)

		darkPct := int(darkFlows * 100 / totalFlows)
		if darkPct >= threshold {
			fp := "visibility:dark_traffic:" + ip
			keep[fp] = true
			title := fmt.Sprintf("Device %s: %d%% dark traffic", ip, darkPct)
			detail := fmt.Sprintf("Over the last %d hours, %d of %d sessions (%d%%) are encrypted with no name visible (opaque, ECH, or QUIC).",
				hours, darkFlows, totalFlows, darkPct)
			st.AddFinding("visibility", "dark_traffic", "info", ip, title, detail, fp)
		}
	}

	// Resolve findings for devices no longer exceeding threshold
	_, err := st.ResolveFindings("visibility", keep)
	return err
}
