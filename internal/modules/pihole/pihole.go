// Package pihole pulls the query log from one or more Pi-hole servers and
// folds it into FlowSight's DNS history, so a network whose clients resolve
// through Pi-hole instead of the firewall's own resolver still gets DNS
// visibility per device: what was asked, what was blocked and by which list,
// with the client names Pi-hole knows.
//
// Pi-hole v6 is read through its REST API (/api/auth, /api/queries) with an
// app password; Pi-hole v5 through /admin/api.php?getAllQueries with the API
// token. Records are pulled incrementally by time, deduplicated by Pi-hole's
// own query id, and written as dns rows with source "pihole:<host>".
package pihole

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

type serverState struct {
	URL       string  `json:"url"`
	Host      string  `json:"host"`
	Version   string  `json:"version"` // "v6" or "v5"
	LastTime  float64 `json:"last_time"`
	LastID    int64   `json:"last_id"`
	LastPull  int64   `json:"last_pull"`
	Imported  int64   `json:"imported"`
	LastError string  `json:"last_error"`
	sid       string
	sidUntil  time.Time
}

type Module struct {
	ctx      *core.Context
	identity core.Identity
	client   *http.Client
	insecure *http.Client

	mu      sync.Mutex
	servers map[string]*serverState
	pulling sync.Mutex // one pull at a time: overlapping pulls double-import and race on the session
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name:        "pihole",
		Version:     "1.0",
		Description: "Pulls the query log from Pi-hole servers into the DNS history: queries, blocks and the lists that blocked them, per client.",
		After:       []string{"identity"},
		Defaults: map[string]any{
			"enabled":       true,
			"servers":       []string{},
			"password":      "",
			"verify_tls":    false,
			"poll_seconds":  30,
			"history_hours": 24,
			"import_names":  true,
			"skip_local":    true,
		},
		Schema: []core.SettingField{
			{Key: "servers", Label: "Pi-hole servers", Type: "list",
				Help: "One URL per line, e.g. https://192.168.1.53 (Pi-hole v6) or http://pihole.lan (v5). Empty: the module idles."},
			{Key: "password", Label: "App password / API token", Type: "secret",
				Help: "Pi-hole v6: an app password (Settings › Web interface / API › Configure app password) or the web password. Pi-hole v5: the API token or the web password. Shared by every server listed."},
			{Key: "verify_tls", Label: "Verify TLS certificates", Type: "bool",
				Help: "Off by default because Pi-hole v6 serves a self-signed certificate. Turn on when yours has a real one."},
			{Key: "poll_seconds", Label: "Poll interval (s)", Type: "int"},
			{Key: "history_hours", Label: "History to import on first contact (hours)", Type: "int"},
			{Key: "import_names", Label: "Use Pi-hole client names", Type: "bool",
				Help: "Fill in a host's name from Pi-hole when FlowSight has none of its own."},
			{Key: "skip_local", Label: "Skip Pi-hole's own queries", Type: "bool",
				Help: "Ignore queries from 127.0.0.1 and ::1 (the Pi-hole resolving for itself)."},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.identity, _ = ctx.Service("identity").(core.Identity)
	m.client = &http.Client{Timeout: 30 * time.Second}
	m.insecure = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	m.servers = map[string]*serverState{}
	ctx.Store.KVGet("pihole.servers", &m.servers)
	for k, s := range m.servers {
		if s == nil {
			delete(m.servers, k)
		}
	}
	every := time.Duration(core.Int(ctx.Settings(), "poll_seconds", 30)) * time.Second
	if every < 10*time.Second {
		every = 10 * time.Second
	}
	ctx.Every("pull", every, m.pull)
	ctx.Route("GET", "/api/pihole/status", m.apiStatus, core.Doc("Retrieve Pi-hole server status with pull history and error details"), core.Returns("Pi-hole server status", map[string]any{
		"servers": []map[string]any{
			{"url": "https://192.168.1.53", "host": "pihole.local", "version": "v6", "last_pull": 1790376243, "imported": 5000, "last_error": "", "watermark": 1790376243},
		},
		"configured": 1, "connected": 1, "password_set": true,
	}))
	ctx.Route("POST", "/api/pihole/pull", m.apiPull, core.Write(), core.Doc("Pull from every server now"), core.Returns("Success", map[string]any{"ok": true}))
	m.registerConfigRoutes(ctx)
	ctx.Publish("pihole", m)
	return nil
}

func (m *Module) Health() core.Health {
	urls := core.Strs(m.ctx.Settings(), "servers")
	if len(urls) == 0 {
		return core.Health{OK: true, Detail: "no Pi-hole servers configured"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var bad []string
	var total int64
	for _, u := range urls {
		s := m.servers[u]
		if s == nil {
			continue
		}
		total += s.Imported
		if s.LastError != "" {
			bad = append(bad, s.Host+": "+s.LastError)
		}
	}
	if len(bad) > 0 {
		return core.Health{OK: false, Detail: strings.Join(bad, "; ")}
	}
	return core.Health{OK: true, Detail: fmt.Sprintf("%d server(s), %d queries imported", len(urls), total)}
}

// OnConfigChange pulls right away when the list or the password changes.
func (m *Module) OnConfigChange(settings map[string]any) error {
	go func() { _ = m.pull() }()
	return nil
}

// ---------------------------------------------------------------- pulling

func (m *Module) httpClient() *http.Client {
	if core.Bool(m.ctx.Settings(), "verify_tls", false) {
		return m.client
	}
	return m.insecure
}

func (m *Module) state(u string) *serverState {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.servers[u]
	if s == nil {
		s = &serverState{URL: u}
		if p, err := url.Parse(u); err == nil {
			s.Host = p.Hostname()
		}
		m.servers[u] = s
	}
	return s
}

func (m *Module) save() {
	m.mu.Lock()
	cp := map[string]*serverState{}
	for k, v := range m.servers {
		c := *v
		cp[k] = &c
	}
	m.mu.Unlock()
	_ = m.ctx.Store.KVSet("pihole.servers", cp)
}

func (m *Module) pull() error {
	if !m.pulling.TryLock() {
		return nil // a pull is already running (settings change and timer can coincide)
	}
	defer m.pulling.Unlock()
	urls := m.serverURLs()
	if len(urls) == 0 {
		return nil
	}
	pw := core.Str(m.ctx.Settings(), "password", "")
	var firstErr error
	for _, u := range urls {
		s := m.state(u)
		n, err := m.pullOne(s, pw)
		m.mu.Lock()
		s.LastPull = time.Now().Unix()
		if err != nil {
			s.LastError = err.Error()
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %v", s.Host, err)
			}
		} else {
			s.LastError = ""
			s.Imported += int64(n)
		}
		m.mu.Unlock()
	}
	m.save()
	return firstErr
}

// pullOne fetches everything newer than the server's watermark and stores it.
func (m *Module) pullOne(s *serverState, pw string) (int, error) {
	if pw == "" {
		return 0, errors.New("no app password or API token configured")
	}
	m.mu.Lock()
	since := s.LastTime
	lastID := s.LastID
	ver := s.Version
	m.mu.Unlock()
	if since == 0 {
		h := core.Int(m.ctx.Settings(), "history_hours", 24)
		if h < 1 {
			h = 1
		}
		since = float64(time.Now().Add(-time.Duration(h) * time.Hour).Unix())
	}
	var recs []rec
	var err error
	switch ver {
	case "v5":
		recs, err = m.fetchV5(s, pw, since)
	default:
		recs, err = m.fetchV6(s, pw, since)
		if err != nil && ver == "" && isNotFound(err) {
			// No /api on this box: try the v5 endpoint once.
			recs, err = m.fetchV5(s, pw, since)
			if err == nil {
				m.mu.Lock()
				s.Version = "v5"
				m.mu.Unlock()
			}
		} else if err == nil && ver == "" {
			m.mu.Lock()
			s.Version = "v6"
			m.mu.Unlock()
		}
	}
	if err != nil {
		return 0, err
	}
	// Drop what we already have (same second, id at or below the watermark).
	sort.Slice(recs, func(i, j int) bool { return recs[i].id < recs[j].id })
	var fresh []rec
	var newest float64
	var newestID int64
	for _, r := range recs {
		if r.id != 0 && r.id <= lastID {
			continue
		}
		fresh = append(fresh, r)
		if r.t > newest {
			newest = r.t
		}
		if r.id > newestID {
			newestID = r.id
		}
	}
	if len(fresh) == 0 {
		return 0, nil
	}
	if err := m.store(s, fresh); err != nil {
		return 0, err
	}
	m.mu.Lock()
	if newest > s.LastTime {
		s.LastTime = newest
	}
	if newestID > s.LastID {
		s.LastID = newestID
	}
	m.mu.Unlock()
	return len(fresh), nil
}

// rec is a Pi-hole query in the shape we care about.
type rec struct {
	id         int64
	t          float64
	client     string
	clientName string
	domain     string
	qtype      string
	status     string
	reply      string
	replyMS    float64
	upstream   string
	listID     string
	dnssec     string
	cname      string
}

func isNotFound(err error) bool { return strings.Contains(err.Error(), "HTTP 404") }

// ---------------------------------------------------------------- Pi-hole v6

type v6Query struct {
	ID       int64   `json:"id"`
	Time     float64 `json:"time"`
	Type     string  `json:"type"`
	Status   string  `json:"status"`
	DNSSEC   string  `json:"dnssec"`
	Domain   string  `json:"domain"`
	Upstream *string `json:"upstream"`
	Reply    struct {
		Type string  `json:"type"`
		Time float64 `json:"time"`
	} `json:"reply"`
	Client struct {
		IP   string `json:"ip"`
		Name string `json:"name"`
	} `json:"client"`
	ListID *int64  `json:"list_id"`
	CNAME  *string `json:"cname"`
}

func (m *Module) v6Session(s *serverState, pw string) (string, error) {
	m.mu.Lock()
	if s.sid != "" && time.Now().Before(s.sidUntil) {
		sid := s.sid
		m.mu.Unlock()
		return sid, nil
	}
	m.mu.Unlock()
	body, _ := json.Marshal(map[string]string{"password": pw})
	req, _ := http.NewRequest("POST", s.URL+"/api/auth", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode == 404 {
		return "", fmt.Errorf("HTTP 404 from /api/auth")
	}
	var out struct {
		Session struct {
			Valid    bool   `json:"valid"`
			SID      string `json:"sid"`
			Validity int    `json:"validity"`
			Message  string `json:"message"`
		} `json:"session"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &out)
	if !out.Session.Valid || out.Session.SID == "" {
		msg := out.Session.Message
		if msg == "" {
			msg = out.Error.Message
		}
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return "", fmt.Errorf("authentication refused (%s); check the app password", msg)
	}
	m.mu.Lock()
	s.sid = out.Session.SID
	v := out.Session.Validity
	if v <= 0 {
		v = 300
	}
	s.sidUntil = time.Now().Add(time.Duration(v-30) * time.Second)
	m.mu.Unlock()
	return out.Session.SID, nil
}

func (m *Module) fetchV6(s *serverState, pw string, since float64) ([]rec, error) {
	sid, err := m.v6Session(s, pw)
	if err != nil {
		return nil, err
	}
	const page = 5000
	var all []rec
	var cursor int64
	from := strconv.FormatInt(int64(since), 10)
	until := strconv.FormatInt(time.Now().Unix()+1, 10)
	for start := 0; start < 200000; start += page {
		q := url.Values{"from": {from}, "until": {until}, "length": {strconv.Itoa(page)}, "start": {strconv.Itoa(start)}}
		if cursor != 0 {
			q.Set("cursor", strconv.FormatInt(cursor, 10))
		}
		req, _ := http.NewRequest("GET", s.URL+"/api/queries?"+q.Encode(), nil)
		req.Header.Set("sid", sid)
		resp, err := m.httpClient().Do(req)
		if err != nil {
			return nil, err
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		if resp.StatusCode == 401 {
			m.mu.Lock()
			s.sid = ""
			m.mu.Unlock()
			return nil, errors.New("session rejected; will re-authenticate")
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("HTTP %d from /api/queries", resp.StatusCode)
		}
		var out struct {
			Queries         []v6Query `json:"queries"`
			Cursor          int64     `json:"cursor"`
			RecordsFiltered int       `json:"recordsFiltered"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("bad JSON from /api/queries: %v", err)
		}
		cursor = out.Cursor
		for _, q := range out.Queries {
			r := rec{id: q.ID, t: q.Time, client: q.Client.IP, clientName: q.Client.Name, domain: strings.ToLower(q.Domain),
				qtype: q.Type, status: q.Status, reply: q.Reply.Type, replyMS: q.Reply.Time * 1000, dnssec: q.DNSSEC}
			if q.Upstream != nil {
				r.upstream = *q.Upstream
			}
			if q.ListID != nil {
				r.listID = strconv.FormatInt(*q.ListID, 10)
			}
			if q.CNAME != nil {
				r.cname = *q.CNAME
			}
			all = append(all, r)
		}
		if len(out.Queries) < page || start+page >= out.RecordsFiltered {
			break
		}
	}
	return all, nil
}

// ---------------------------------------------------------------- Pi-hole v5

func (m *Module) fetchV5(s *serverState, pw string, since float64) ([]rec, error) {
	token := pw
	if len(pw) != 64 || !isHex(pw) {
		// The v5 API token is the web password hashed twice.
		h1 := sha256.Sum256([]byte(pw))
		h2 := sha256.Sum256([]byte(hex.EncodeToString(h1[:])))
		token = hex.EncodeToString(h2[:])
	}
	q := url.Values{"getAllQueries": {fmt.Sprintf("%d-%d", int64(since), time.Now().Unix()+1)}, "auth": {token}}
	resp, err := m.httpClient().Get(s.URL + "/admin/api.php?" + q.Encode())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d from /admin/api.php", resp.StatusCode)
	}
	var out struct {
		Data [][]any `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || (len(out.Data) == 0 && bytes.Contains(raw, []byte("[]"))) {
		if err != nil {
			return nil, errors.New("v5 API answered without data; is the token right?")
		}
	}
	var all []rec
	for _, row := range out.Data {
		// [timestamp, type, domain, client, status, dnssec, reply_type, reply_time, cname?, ... ]
		if len(row) < 5 {
			continue
		}
		r := rec{t: toF(row[0]), qtype: toS(row[1]), domain: strings.ToLower(toS(row[2])), client: toS(row[3])}
		r.status = v5Status(toS(row[4]))
		if len(row) > 5 {
			r.dnssec = toS(row[5])
		}
		if len(row) > 7 {
			r.replyMS = toF(row[7]) / 10 // v5 reports tenths of ms
		}
		r.id = int64(r.t * 1000) // v5 has no id; time to the millisecond is the best we have
		all = append(all, r)
	}
	return all, nil
}

func v5Status(code string) string {
	switch code {
	case "1":
		return "GRAVITY"
	case "2":
		return "FORWARDED"
	case "3":
		return "CACHE"
	case "4":
		return "REGEX"
	case "5":
		return "DENYLIST"
	case "6", "7", "8":
		return "EXTERNAL_BLOCKED"
	case "9":
		return "GRAVITY_CNAME"
	case "10":
		return "REGEX_CNAME"
	case "11":
		return "DENYLIST_CNAME"
	case "12":
		return "RETRIED"
	case "14":
		return "IN_PROGRESS"
	case "15":
		return "DBBUSY"
	case "16":
		return "SPECIAL_DOMAIN"
	case "17":
		return "CACHE_STALE"
	}
	return "UNKNOWN"
}

func isHex(s string) bool { _, err := hex.DecodeString(s); return err == nil }
func toS(v any) string    { return fmt.Sprint(v) }
func toF(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case string:
		f, _ := strconv.ParseFloat(x, 64)
		return f
	}
	return 0
}

// ---------------------------------------------------------------- storing

// blockedStatus maps Pi-hole's status names to a block verdict and list label.
func blockedStatus(status string) (blocked bool, list string) {
	switch {
	case status == "GRAVITY", status == "GRAVITY_CNAME":
		return true, "pihole gravity"
	case status == "REGEX", status == "REGEX_CNAME":
		return true, "pihole regex"
	case status == "DENYLIST", status == "DENYLIST_CNAME":
		return true, "pihole denylist"
	case strings.HasPrefix(status, "EXTERNAL_BLOCKED"):
		return true, "upstream blocked"
	case status == "SPECIAL_DOMAIN":
		return true, "pihole special domain"
	case status == "DBBUSY":
		return true, "pihole (database busy)"
	}
	return false, ""
}

func rcodeOf(reply string) string {
	switch reply {
	case "NXDOMAIN", "NODATA", "REFUSED", "SERVFAIL", "NOTIMP":
		return reply
	case "", "UNKNOWN":
		return ""
	}
	return "NOERROR"
}

func (m *Module) store(s *serverState, recs []rec) error {
	skipLocal := core.Bool(m.ctx.Settings(), "skip_local", true)
	importNames := core.Bool(m.ctx.Settings(), "import_names", true)
	src := "pihole:" + s.Host
	var out []core.DNSRecord
	names := map[string]string{}
	for _, r := range recs {
		if skipLocal && (r.client == "127.0.0.1" || r.client == "::1") {
			continue
		}
		blocked, list := blockedStatus(r.status)
		action := "pass"
		if blocked {
			action = "block"
			if r.listID != "" && !strings.HasPrefix(r.listID, "-") { // negative ids are Pi-hole's built-ins
				list += " #" + r.listID
			}
		}
		ans := ""
		switch {
		case blocked:
			ans = "pihole"
		case strings.HasPrefix(r.status, "CACHE"):
			ans = "cache"
		case r.status == "FORWARDED":
			ans = "forward"
			if r.upstream != "" {
				ans = "forward " + r.upstream
			}
		}
		d := core.DNSRecord{TS: int64(r.t), Client: r.client, Domain: r.domain, QType: r.qtype, Action: action, List: list,
			RCode: rcodeOf(r.reply), AnswerSource: ans, DNSSEC: strings.ToLower(r.dnssec), MS: r.replyMS, Source: src}
		if r.cname != "" {
			d.Answers = []string{"CNAME " + r.cname}
		}
		out = append(out, d)
		if importNames && r.clientName != "" && r.clientName != r.client && r.clientName != "localhost" && net.ParseIP(r.clientName) == nil {
			names[r.client] = strings.TrimSuffix(r.clientName, ".")
		}
	}
	if err := m.ctx.Store.AddDNS(out); err != nil {
		return err
	}
	m.associate(names)
	return nil
}

// associate gives hosts Pi-hole's client name when FlowSight has none of
// its own (identity from DHCP, ARP or the resolver always wins).
func (m *Module) associate(names map[string]string) {
	if len(names) == 0 {
		return
	}
	var ups []core.HostUpdate
	for ip, name := range names {
		if m.identity != nil && m.identity.Name(ip) != "" {
			continue
		}
		// Pi-hole's client name is second-hand: its own reverse lookups,
		// which go stale when a lease moves. A name that is some other
		// device's own name (its lease hostname or a name someone chose)
		// stays with that device; an Amazon speaker at the address a
		// laptop once had is not "Mac".
		if owner, ok := m.identity.(interface{ NameOwner(string) string }); ok && m.identity != nil {
			if o := owner.NameOwner(name); o != "" && o != m.identity.MAC(ip) {
				continue
			}
		}
		row, err := m.ctx.Store.Row(`SELECT name FROM hosts WHERE ip=?`, ip)
		if err == nil && row != nil {
			if cur, _ := row["name"].(string); cur != "" {
				continue
			}
		}
		local := true
		if m.identity != nil && !m.identity.IsLocal(ip) {
			local = false
		}
		ups = append(ups, core.HostUpdate{IP: ip, Name: name, Source: "pihole", IsLocal: &local})
	}
	if len(ups) > 0 {
		_ = m.ctx.Store.UpsertHosts(ups)
	}
}

// ---------------------------------------------------------------- API

func (m *Module) apiStatus(r *core.Req) (any, error) {
	urls := core.Strs(m.ctx.Settings(), "servers")
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []map[string]any
	for _, u := range urls {
		u = strings.TrimRight(strings.TrimSpace(u), "/")
		if !strings.Contains(u, "://") {
			u = "https://" + u
		}
		s := m.servers[u]
		row := map[string]any{"url": u}
		if s != nil {
			row["host"], row["version"], row["last_pull"], row["imported"], row["last_error"], row["watermark"] =
				s.Host, s.Version, s.LastPull, s.Imported, s.LastError, int64(s.LastTime)
		}
		out = append(out, row)
	}
	connected := 0
	for _, u := range m.serverURLs() {
		if s := m.servers[u]; s != nil && s.Version == "v6" && s.LastPull > 0 && s.LastError == "" {
			connected++
		}
	}
	return map[string]any{"servers": out, "configured": len(urls), "connected": connected,
		"password_set": core.Str(m.ctx.Settings(), "password", "") != ""}, nil
}

func (m *Module) apiPull(r *core.Req) (any, error) {
	err := m.pull()
	st, _ := m.apiStatus(r)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error(), "status": st}, nil
	}
	return map[string]any{"ok": true, "status": st}, nil
}
