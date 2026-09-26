// Package egress answers one question continuously: what is leaving this
// network right now, and to whom.
//
// Every other source of that answer in FlowSight is retrospective. The proxy
// writes its log line when a session closes, so a device that spends twenty
// minutes uploading appears once, twenty minutes late. Rollups are later
// still. That is the wrong end of the event for anyone who wants to notice
// data leaving rather than read about it afterwards.
//
// So this module does not read logs. It reads pf's live state table, which
// counts every byte of every open connection and updates as they move, and
// it samples it every few seconds. That has one large consequence: it sees
// everything. A pinned session that refuses inspection still has a state. So
// does a spliced one, a QUIC session on UDP 443 that never reaches the
// proxy, and a WireGuard tunnel carrying who knows what. None of those can
// be decrypted, and all of them can be measured.
//
// What it cannot tell you is what was inside. For that, on the sessions that
// can be decrypted, stateful packet inspection reads the request itself. The two are
// meant to be read together: this says a device is sending four gigabytes to
// a cloud storage provider, and if that session was decrypted, deep
// inspection says which files.
package egress

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
	"github.com/grioghar/flowsight/internal/modules/enrich"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

// reverseLookup is the part of the enrich module this needs: the name an
// address answers to. Without it a destination that has only ever been
// reached by address, never by name, looks anonymous when it is not.
type reverseLookup interface {
	Lookup(ips []string) map[string]enrich.Info
}

// Module implements core.Module.
type Module struct {
	ctx      *core.Context
	identity core.Identity
	enf      core.Enforcer
	states   core.StateReader
	rdns     reverseLookup

	mu       sync.Mutex
	prev     map[string]State     // the previous sample, for rates
	live     map[string]*Transfer // what is moving now
	names    map[string]string    // peer address -> name, refreshed periodically
	namesAt  time.Time
	firstUse map[string]int64 // device|group -> when first seen
	sampled  time.Time
	lastErr  string
	subs     []func(Event)
	events   []Event
	raised   map[string]bool // one line per transfer per kind, not one per sample
	pending  map[string]bool // addresses the sample could not name, for the names job
}

// Transfer is one connection, as it stands at the latest sample.
type Transfer struct {
	Key       string  `json:"key"`
	Local     string  `json:"local"`
	LocalName string  `json:"local_name,omitempty"`
	Peer      string  `json:"peer"`
	PeerName  string  `json:"peer_name,omitempty"`
	PeerPort  int     `json:"peer_port"`
	Proto     string  `json:"proto"`
	Group     string  `json:"group"`
	GroupName string  `json:"group_title"`
	Service   string  `json:"service,omitempty"`
	Out       int64   `json:"out"`
	In        int64   `json:"in"`
	RateOut   float64 `json:"rate_out"`
	RateIn    float64 `json:"rate_in"`
	Age       float64 `json:"age"`
	// Serving marks a connection the far side opened: a server here
	// answering the internet rather than a device reaching out.
	Serving bool     `json:"serving"`
	Flags   []string `json:"flags,omitempty"`
	Since   int64    `json:"since"`
}

// Event is what this module publishes when a transfer crosses a line. Later
// modules subscribe to it; that is how a rule that stops something will be
// wired in, without this module needing to know about it.
type Event struct {
	TS       int64    `json:"ts"`
	Kind     string   `json:"kind"` // volume, rate, ratio, first-use, unnamed, tunnel
	Severity string   `json:"severity"`
	Transfer Transfer `json:"transfer"`
	Message  string   `json:"message"`
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name:         "egress",
		Version:      "1.0",
		Tier:         "business",
		Description:  "What is leaving the network right now. Reads pf's live connection counters every few seconds, so it sees pinned sessions, QUIC and tunnels that no proxy can decrypt, and raises an event while a transfer is still running rather than after it finished.",
		After:        []string{"firewall", "identity", "web"},
		Capabilities: []string{core.CapWebObserve},
		Defaults: map[string]any{
			"enabled":          true,
			"interval_seconds": 5,
			"watch_groups":     watchedByDefault(),
			"alert_upload_mb":  250,
			"alert_rate_mbps":  25,
			"sustain_seconds":  30,
			"ratio_floor_mb":   20,
			"ratio":            4,
			"flag_unnamed":     true,
			"flag_first_use":   true,
			"quiet_hours":      "",
			"keep_events":      500,
			"min_report_kb":    64,
		},
		Schema: []core.SettingField{
			{Key: "interval_seconds", Label: "Sample the connection table every (seconds)", Type: "int",
				Help: "How often pf's counters are read. Five seconds is enough to catch a transfer in its first few megabytes and costs almost nothing. This is the whole difference between noticing data leaving and reading about it later."},
			{Key: "watch_groups", Label: "Destination groups to watch", Type: "list",
				Help: "Which kinds of destination raise an event when a device uploads to them. The rest are still measured and still shown; they just do not raise anything on their own."},
			{Key: "alert_upload_mb", Label: "Flag a single transfer above (MB sent)", Type: "int",
				Help: "Raised while the transfer is still running, not when it ends."},
			{Key: "alert_rate_mbps", Label: "Flag a sustained upload rate above (Mbit/s)", Type: "int"},
			{Key: "sustain_seconds", Label: "...held for at least (seconds)", Type: "int",
				Help: "Stops a brief burst from raising anything."},
			{Key: "ratio_floor_mb", Label: "Flag upload-dominant transfers above (MB sent)", Type: "int",
				Help: "Ordinary use pulls far more than it pushes. A session that pushes several times what it pulls is the shape of data leaving, whatever the volume."},
			{Key: "ratio", Label: "...when sent exceeds received by a factor of", Type: "int"},
			{Key: "flag_unnamed", Label: "Flag uploads to a destination with no name", Type: "bool",
				Help: "An address FlowSight can put no name to, from DNS, from a server name or from a reverse lookup. This is the one most worth reading."},
			{Key: "flag_first_use", Label: "Flag the first time a device uses a watched group", Type: "bool",
				Help: "A thermostat that has never spoken to cloud storage and now does is worth a line, whatever the volume."},
			{Key: "quiet_hours", Label: "Treat these hours as quiet", Type: "string", Placeholder: "23:00-06:00",
				Help: "Anything flagged inside this window is raised one severity higher. Empty: every hour is treated alike."},
			{Key: "min_report_kb", Label: "Ignore connections smaller than (KB)", Type: "int",
				Help: "Keeps the live view to things that are actually moving data."},
			{Key: "keep_events", Label: "Events kept in memory", Type: "int"},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.identity, _ = ctx.Service("identity").(core.Identity)
	m.enf, _ = ctx.Service(core.ServiceEnforcer).(core.Enforcer)
	m.states, _ = ctx.Service(core.ServiceConnStates).(core.StateReader)
	m.rdns, _ = ctx.Service("enrich").(reverseLookup)
	m.prev = map[string]State{}
	m.live = map[string]*Transfer{}
	m.names = map[string]string{}
	m.firstUse = map[string]int64{}
	m.pending = map[string]bool{}
	_ = m.ctx.Store.KVGet("egress.first_use", &m.firstUse)

	every := time.Duration(core.Int(ctx.Settings(), "interval_seconds", 5)) * time.Second
	if every < time.Second {
		every = time.Second
	}
	// Sampling and naming are separate jobs on purpose. The sample has to be
	// quick, because it runs every few seconds and its whole value is being
	// current; naming means reading two tables that grow all year. Putting
	// them in one job made a five-second sampler take twelve seconds.
	ctx.Every("watch", every, m.sweep)
	ctx.Every("names", 60*time.Second, m.refreshNames)
	ctx.Route("GET", "/api/egress/live", m.apiLive, core.Needs("egress.watch"),
		core.Doc("Show live connections carrying data with rates and traffic totals by device"),
		core.Query("group", "string", "Filter by destination group name", false, "workload"),
		core.Query("min_kb", "integer", "Minimum traffic in kilobytes to show", false, 0),
		core.Returns("Live transfers", map[string]any{
			"transfers": []map[string]any{
				{"local": "192.168.1.10", "group": "workload", "out": 1000000, "in": 500000, "rate_out": 100.5},
			},
			"sampled": 1790376243, "error": "",
		}))
	ctx.Route("GET", "/api/egress/summary", m.apiSummary, core.Needs("egress.watch"),
		core.Doc("Total outbound traffic aggregated by device and destination group"),
		core.Returns("Egress summary", map[string]any{
			"devices":   []map[string]any{{"key": "192.168.1.10", "name": "MacBook", "out": 5000000}},
			"groups":    []map[string]any{{"key": "workload", "title": "Work", "out": 5000000}},
			"total_out": 5000000, "total_in": 2500000, "rate_out": 250.0,
		}))
	ctx.Route("GET", "/api/egress/events", m.apiEvents, core.Needs("egress.watch"),
		core.Doc("Connection lifecycle events from the firewall connection table"),
		core.Query("limit", "integer", "Maximum results to return", false, 200),
		core.Returns("Connection events", map[string]any{
			"events": []map[string]any{
				{"ts": 1790376243, "type": "start", "local": "192.168.1.10", "remote": "8.8.8.8", "bytes": 100000},
			},
		}))
	ctx.Route("POST", "/api/egress/stop", m.apiStop, core.Write(), core.Needs("egress.watch"),
		core.Doc("Terminate an active outbound transfer connection at the firewall gateway"),
		core.Body(
			core.Fld("local", "string", true, "Local source IP address", "192.168.1.10"),
			core.Fld("peer", "string", true, "Remote peer IP address", "8.8.8.8"),
			core.Fld("port", "integer", true, "Remote port number", 443),
		),
		core.Returns("Stop result", map[string]any{"ok": true}))
	ctx.Panel(core.Panel{ID: "egress", Title: "DLP", Group: "Protect", Order: 72, Icon: "egress", Feature: "egress.watch"})
	ctx.Publish("egress", m)
	return nil
}

// Subscribe registers a listener for threshold events. It is the seam later
// modules attach to, so that deciding what to do about a transfer never has
// to live in the code that measures one.
func (m *Module) Subscribe(fn func(Event)) {
	m.mu.Lock()
	m.subs = append(m.subs, fn)
	m.mu.Unlock()
}

func (m *Module) Health() core.Health {
	if m.states == nil || !m.states.Available() {
		return core.Health{OK: true, Detail: "no firewall connection table on this platform; live egress is unavailable"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastErr != "" {
		return core.Health{OK: false, Detail: m.lastErr}
	}
	if m.sampled.IsZero() {
		return core.Health{OK: true, Detail: "waiting for the first sample"}
	}
	return core.Health{OK: true, Detail: fmt.Sprintf("%d transfers moving, sampled %s ago",
		len(m.live), time.Since(m.sampled).Round(time.Second))}
}

// ---------------------------------------------------------------- the sweep

func (m *Module) sweep() error {
	if m.states == nil || !m.states.Available() {
		return nil
	}
	isLocal := func(ip string) bool { return m.identity != nil && m.identity.IsLocal(ip) }
	states, err := readStates(m.states, isLocal)
	if err != nil {
		m.mu.Lock()
		m.lastErr = err.Error()
		m.mu.Unlock()
		return nil // a failed sample is not a failed job; the next one may work
	}
	now := time.Now()
	floor := int64(core.Int(m.ctx.Settings(), "min_report_kb", 64)) * 1024
	m.mu.Lock()
	gap := now.Sub(m.sampled).Seconds()
	if m.sampled.IsZero() || gap <= 0 {
		gap = 1
	}
	prev := m.prev
	next := make(map[string]State, len(states))
	live := make(map[string]*Transfer, len(states))
	names := m.names
	m.mu.Unlock()

	var fresh []Event
	var unnamed []string
	for _, s := range states {
		next[s.Key()] = s
		if s.Out+s.In < floor || !offNetwork(s.Peer) {
			continue
		}
		name := names[s.Peer]
		if name == "" {
			unnamed = append(unnamed, s.Peer)
		}
		group, service := classify(name, s.PeerPort, s.Proto)
		t := &Transfer{
			Key: s.Key(), Local: s.Local, Peer: s.Peer, PeerPort: s.PeerPort, Proto: s.Proto,
			PeerName: name, Group: group, GroupName: groupTitle(group), Service: service,
			Out: s.Out, In: s.In, Age: s.Age.Seconds(), Since: now.Add(-s.Age).Unix(),
			Serving: s.Inbound,
		}
		if m.identity != nil {
			t.LocalName = m.identity.Name(s.Local)
		}
		if p, ok := prev[s.Key()]; ok {
			if d := s.Out - p.Out; d > 0 {
				t.RateOut = float64(d) / gap
			}
			if d := s.In - p.In; d > 0 {
				t.RateIn = float64(d) / gap
			}
		}
		live[s.Key()] = t
		fresh = append(fresh, m.evaluate(t, now)...)
	}

	m.mu.Lock()
	m.prev, m.live, m.sampled, m.lastErr = next, live, now, ""
	for _, ip := range unnamed {
		if m.pending == nil {
			m.pending = map[string]bool{}
		}
		m.pending[ip] = true
	}
	keep := core.Int(m.ctx.Settings(), "keep_events", 500)
	m.events = append(m.events, fresh...)
	if len(m.events) > keep && keep > 0 {
		m.events = m.events[len(m.events)-keep:]
	}
	subs := append([]func(Event){}, m.subs...)
	m.mu.Unlock()

	for _, e := range fresh {
		for _, fn := range subs {
			fn(e)
		}
	}
	return nil
}

// evaluate applies the thresholds to one transfer and returns what it tripped.
// A transfer is only flagged once per kind, because it is sampled every few
// seconds and nobody needs the same upload reported four hundred times.
func (m *Module) evaluate(t *Transfer, now time.Time) []Event {
	s := m.ctx.Settings()
	watched := map[string]bool{}
	for _, g := range core.Strs(s, "watch_groups") {
		watched[g] = true
	}
	if len(watched) == 0 {
		for _, g := range watchedByDefault() {
			watched[g] = true
		}
	}
	// A connection the far side opened is a server here answering the
	// internet. A Plex server streaming three gigabytes to a viewer has
	// genuinely sent three gigabytes, and it is not data leaving in the sense
	// anyone means by it. Those rows are shown, labelled, and not alerted on.
	if t.Serving {
		return nil
	}
	var out []Event
	add := func(kind, sev, msg string) {
		if !m.firstTime("flag|" + t.Key + "|" + kind) {
			return
		}
		if m.inQuietHours(now) {
			sev = raise(sev)
		}
		t.Flags = append(t.Flags, kind)
		e := Event{TS: now.Unix(), Kind: kind, Severity: sev, Transfer: *t, Message: msg}
		out = append(out, e)
		m.ctx.Event("egress", msg, map[string]any{
			"device": t.Local, "peer": t.Peer, "name": t.PeerName, "group": t.Group,
			"sent": t.Out, "received": t.In, "kind": kind})
		_, _ = m.ctx.Store.AddFinding("egress", kind, sev, t.Local, msg,
			m.detail(t), "egress:"+kind+":"+t.Key)
	}
	who := t.describe()

	if watched[t.Group] {
		if mb := int64(core.Int(s, "alert_upload_mb", 250)); mb > 0 && t.Out >= mb*1024*1024 {
			add("volume", "medium", fmt.Sprintf("%s has sent %s to %s", who, human(t.Out), t.dest()))
		}
		if rate := float64(core.Int(s, "alert_rate_mbps", 25)); rate > 0 &&
			t.RateOut*8/1e6 >= rate && t.Age >= float64(core.Int(s, "sustain_seconds", 30)) {
			add("rate", "medium", fmt.Sprintf("%s is uploading to %s at %.0f Mbit/s", who, t.dest(), t.RateOut*8/1e6))
		}
		if floor := int64(core.Int(s, "ratio_floor_mb", 20)) * 1024 * 1024; floor > 0 && t.Out >= floor {
			if r := int64(core.Int(s, "ratio", 4)); r > 0 && t.Out > t.In*r {
				add("ratio", "medium", fmt.Sprintf("%s has sent %s to %s and received only %s", who, human(t.Out), t.dest(), human(t.In)))
			}
		}
		// "used Other for the first time" says nothing; the catch-all and the
		// nameless group are reported through their own rules instead.
		if core.Bool(s, "flag_first_use", true) && t.Out > 0 && t.Group != "other" && t.Group != "unknown" {
			k := t.Local + "|" + t.Group
			m.mu.Lock()
			_, seen := m.firstUse[k]
			if !seen {
				m.firstUse[k] = now.Unix()
			}
			m.mu.Unlock()
			if !seen {
				_ = m.ctx.Store.KVSet("egress.first_use", m.firstUse)
				add("first-use", "low", fmt.Sprintf("%s has reached %s for the first time, at %s",
					who, strings.ToLower(t.GroupName), t.dest()))
			}
		}
	}
	if t.Group == "unknown" && core.Bool(s, "flag_unnamed", true) {
		if floor := int64(core.Int(s, "ratio_floor_mb", 20)) * 1024 * 1024; t.Out >= floor {
			add("unnamed", "high", fmt.Sprintf("%s has sent %s to %s, which has no name in DNS or in any handshake", who, human(t.Out), t.Peer))
		}
	}
	return out
}

func (t *Transfer) describe() string {
	if t.LocalName != "" {
		return t.LocalName
	}
	return t.Local
}

func (t *Transfer) dest() string {
	switch {
	case t.Service != "":
		return t.Service
	case t.PeerName != "":
		return t.PeerName
	default:
		return t.Peer
	}
}

func (m *Module) detail(t *Transfer) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s has sent %s and received %s over %s, to %s",
		t.describe(), human(t.Out), human(t.In), dur(t.Age), t.dest())
	if t.PeerName != "" && t.PeerName != t.dest() {
		fmt.Fprintf(&b, " (%s)", t.PeerName)
	}
	fmt.Fprintf(&b, " at %s port %d.", t.Peer, t.PeerPort)
	switch t.Group {
	case "tunnel":
		b.WriteString(" This is an encrypted tunnel, so nothing inside it can be seen by any inspection: the volume, the far end and the timing are the whole of what is knowable.")
	case "unknown":
		b.WriteString(" Nothing names this address: no DNS answer, no server name in a handshake and no reverse lookup. That is unusual for ordinary traffic.")
	default:
		b.WriteString(" Whether the contents are readable depends on whether a policy decrypts this device and whether the far end pins its certificate; see the TLS and Stateful Packet Inspection pages.")
	}
	return b.String()
}

// firstTime reports whether this is the first time a key has been raised,
// so a transfer sampled every five seconds is reported once.
func (m *Module) firstTime(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.raised == nil {
		m.raised = map[string]bool{}
	}
	if m.raised[key] {
		return false
	}
	m.raised[key] = true
	return true
}

func (m *Module) inQuietHours(now time.Time) bool {
	spec := strings.TrimSpace(core.Str(m.ctx.Settings(), "quiet_hours", ""))
	if spec == "" {
		return false
	}
	from, to, ok := strings.Cut(spec, "-")
	if !ok {
		return false
	}
	f, okF := hhmm(from)
	t, okT := hhmm(to)
	if !okF || !okT {
		return false
	}
	cur := now.Hour()*60 + now.Minute()
	if f <= t {
		return cur >= f && cur < t
	}
	return cur >= f || cur < t // a window that crosses midnight
}

func hhmm(s string) (int, bool) {
	h, m, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return 0, false
	}
	var hh, mm int
	if _, err := fmt.Sscanf(h, "%d", &hh); err != nil {
		return 0, false
	}
	if _, err := fmt.Sscanf(m, "%d", &mm); err != nil {
		return 0, false
	}
	return hh*60 + mm, true
}

func raise(sev string) string {
	switch sev {
	case "low":
		return "medium"
	case "medium":
		return "high"
	}
	return sev
}

// refreshNames rebuilds the address-to-name map from what FlowSight already
// knows: the server name in a handshake and the answer to a DNS query. It is
// its own job rather than part of the sample, because these two tables grow
// all year and the sample has to stay quick to be worth anything.
//
// An address the sample could not name is looked up individually here, so
// that a destination first contacted seconds ago is asked about directly
// before anything calls it nameless. That is the loudest thing this module
// says and it must not be said about a name that had simply not been cached.
func (m *Module) refreshNames() error {
	names := map[string]string{}
	since := time.Now().Add(-6 * time.Hour).Unix()
	if rows, err := m.ctx.Store.Rows(
		`SELECT dst_ip AS ip, sni AS name, MAX(ts) AS t FROM tls_sessions
		 WHERE ts >= ? AND sni <> '' GROUP BY dst_ip LIMIT 20000`, since); err == nil {
		for _, r := range rows {
			ip, _ := r["ip"].(string)
			n, _ := r["name"].(string)
			if ip != "" && n != "" {
				names[ip] = n
			}
		}
	}
	if rows, err := m.ctx.Store.Rows(`SELECT ip, name FROM dns_names WHERE name <> '' LIMIT 20000`); err == nil {
		for _, r := range rows {
			ip, _ := r["ip"].(string)
			n, _ := r["name"].(string)
			if ip != "" && n != "" && names[ip] == "" {
				names[ip] = n
			}
		}
	}
	m.mu.Lock()
	pending := m.pending
	m.pending = map[string]bool{}
	for ip, n := range m.names {
		if names[ip] == "" {
			names[ip] = n // keep what an individual lookup found earlier
		}
	}
	m.names, m.namesAt = names, time.Now()
	m.mu.Unlock()

	// Anything still without a name gets one direct question each, capped so
	// a network full of unnamed destinations cannot turn this into a scan.
	asked := 0
	var stillUnnamed []string
	for ip := range pending {
		m.mu.Lock()
		known := m.names[ip] != ""
		m.mu.Unlock()
		if known {
			continue
		}
		if asked < 50 {
			asked++
			if m.lookupOne(ip) != "" {
				continue
			}
		}
		stillUnnamed = append(stillUnnamed, ip)
	}
	// Last resort: the reverse lookup. Plenty of destinations are only ever
	// reached by address, and calling one of those nameless when it answers
	// to a perfectly ordinary name would be the wrong alarm entirely.
	if m.rdns != nil && len(stillUnnamed) > 0 {
		if len(stillUnnamed) > 50 {
			stillUnnamed = stillUnnamed[:50]
		}
		for ip, info := range m.rdns.Lookup(stillUnnamed) {
			if info.Name != "" {
				m.remember(ip, info.Name)
			}
		}
	}
	return nil
}

// lookupOne asks the store for one address's name and caches the answer.
func (m *Module) lookupOne(ip string) string {
	rows, err := m.ctx.Store.Rows(
		`SELECT sni AS name FROM tls_sessions WHERE dst_ip = ? AND sni <> '' ORDER BY ts DESC LIMIT 1`, ip)
	if err == nil && len(rows) > 0 {
		if n, _ := rows[0]["name"].(string); n != "" {
			m.remember(ip, n)
			return n
		}
	}
	rows, err = m.ctx.Store.Rows(`SELECT name FROM dns_names WHERE ip = ? AND name <> '' LIMIT 1`, ip)
	if err == nil && len(rows) > 0 {
		if n, _ := rows[0]["name"].(string); n != "" {
			m.remember(ip, n)
			return n
		}
	}
	return ""
}

func (m *Module) remember(ip, name string) {
	m.mu.Lock()
	if m.names != nil {
		m.names[ip] = name
	}
	m.mu.Unlock()
}

// ---------------------------------------------------------------- helpers

func human(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d bytes", n)
}

func dur(sec float64) string {
	d := time.Duration(sec) * time.Second
	if d < time.Minute {
		return fmt.Sprintf("%.0f seconds", sec)
	}
	return d.Round(time.Minute).String()
}

// ---------------------------------------------------------------- API

func (m *Module) apiLive(r *core.Req) (any, error) {
	group := r.Q("group", "")
	minKB := int64(r.QInt("min_kb", 0, 0, 1<<30)) * 1024
	m.mu.Lock()
	rows := make([]Transfer, 0, len(m.live))
	for _, t := range m.live {
		if group != "" && t.Group != group {
			continue
		}
		if t.Out+t.In < minKB {
			continue
		}
		rows = append(rows, *t)
	}
	sampled, err := m.sampled, m.lastErr
	m.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].RateOut != rows[j].RateOut {
			return rows[i].RateOut > rows[j].RateOut
		}
		return rows[i].Out > rows[j].Out
	})
	return map[string]any{"transfers": rows, "sampled": sampled.Unix(), "error": err,
		"groups": groups,
		"note":   "Read from the firewall's own connection counters, so this includes sessions no proxy can decrypt: pinned certificates, QUIC and encrypted tunnels."}, nil
}

func (m *Module) apiSummary(r *core.Req) (any, error) {
	type agg struct {
		Key     string  `json:"key"`
		Name    string  `json:"name,omitempty"`
		Title   string  `json:"title,omitempty"`
		Out     int64   `json:"out"`
		In      int64   `json:"in"`
		RateOut float64 `json:"rate_out"`
		Flows   int     `json:"flows"`
	}
	byDevice := map[string]*agg{}
	byGroup := map[string]*agg{}
	var totalOut, totalIn int64
	var rateOut float64
	m.mu.Lock()
	for _, t := range m.live {
		d := byDevice[t.Local]
		if d == nil {
			d = &agg{Key: t.Local, Name: t.LocalName}
			byDevice[t.Local] = d
		}
		g := byGroup[t.Group]
		if g == nil {
			g = &agg{Key: t.Group, Title: t.GroupName}
			byGroup[t.Group] = g
		}
		for _, a := range []*agg{d, g} {
			a.Out += t.Out
			a.In += t.In
			a.RateOut += t.RateOut
			a.Flows++
		}
		totalOut += t.Out
		totalIn += t.In
		rateOut += t.RateOut
	}
	sampled, n := m.sampled, len(m.live)
	m.mu.Unlock()
	flat := func(mm map[string]*agg) []agg {
		out := make([]agg, 0, len(mm))
		for _, v := range mm {
			out = append(out, *v)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Out > out[j].Out })
		return out
	}
	return map[string]any{"devices": flat(byDevice), "groups": flat(byGroup),
		"total_out": totalOut, "total_in": totalIn, "rate_out": rateOut,
		"transfers": n, "sampled": sampled.Unix()}, nil
}

func (m *Module) apiEvents(r *core.Req) (any, error) {
	limit := r.QInt("limit", 200, 1, 2000)
	m.mu.Lock()
	out := make([]Event, 0, limit)
	for i := len(m.events) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, m.events[i])
	}
	m.mu.Unlock()
	return map[string]any{"events": out}, nil
}

// apiStop ends a transfer that is running. The state is dropped at the
// firewall, which stops the transfer immediately; it does not stop the device
// opening another, which is a policy decision and belongs in policy.
func (m *Module) apiStop(r *core.Req) (any, error) {
	var in struct {
		Local string `json:"local"`
		Peer  string `json:"peer"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	if in.Local == "" || in.Peer == "" {
		return nil, core.BadRequest("local and peer are both required")
	}
	if m.enf == nil || !m.enf.Available() {
		return nil, core.BadRequest("no firewall on this platform")
	}
	if err := m.enf.KillStates(in.Local, in.Peer); err != nil {
		return nil, err
	}
	m.ctx.Event("egress", fmt.Sprintf("transfer from %s to %s was stopped by hand", in.Local, in.Peer),
		map[string]any{"device": in.Local, "peer": in.Peer})
	return map[string]any{"ok": true}, nil
}
