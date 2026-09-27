// Package ids reads Suricata's EVE log: alerts become normalised alerts, TLS
// records feed the certificate inventory and session table, and the counts
// drive the threat report. Suricata itself stays the engine; this is the
// reader and, later, the rule manager.
package ids

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

type Module struct {
	evePath  string
	ctx      *core.Context
	tails    map[string]*core.Tailer // by file; evePath may be a pattern
	polled   bool
	mu       sync.Mutex
	lastErr  string
	alerts   int64
	tls      int64
	identity core.Identity
	// localMissing: there is no EVE log on this machine, which is normal
	// when Suricata runs elsewhere and sends its events as a provider.
	localMissing bool
	remote       int64 // records received from providers
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name: "ids", Version: "1.0",
		Description:  "Suricata alerts and TLS observations from the EVE log.",
		Capabilities: []string{core.CapThreatDetect, core.CapTLSObserve},
		Requires:     []string{"suricata"},
		After:        []string{"identity", "providers"},
		Defaults: map[string]any{
			"eve_path":     "",
			"poll_seconds": 5,
			"tls_records":  true,
		},
		Schema: []core.SettingField{
			{Key: "eve_path", Label: "EVE log path", Type: "string", Help: "Empty uses the platform default. May be a pattern (/var/log/suricata/*/eve.json) to read one log per interface."},
			{Key: "poll_seconds", Label: "Poll interval (s)", Type: "int"},
			{Key: "tls_records", Label: "Record TLS sessions and certificates", Type: "bool"},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.identity, _ = ctx.Service("identity").(core.Identity)
	path := core.Str(ctx.Settings(), "eve_path", "")
	if path == "" {
		path = ctx.Platform.SuricataEve
	}
	m.tails = map[string]*core.Tailer{}
	m.evePath = path
	every := time.Duration(core.Int(ctx.Settings(), "poll_seconds", 5)) * time.Second
	ctx.Every("tail", every, m.poll)
	// Suricata in another container or on another host sends the same EVE
	// events through the provider protocol; they are read exactly as the
	// local log is, and marked with the provider's name.
	if hub, ok := ctx.Service(core.ServiceProviderHub).(core.ProviderHub); ok {
		hub.Accept("suricata-eve", m.fromProvider)
	}
	ctx.Route("GET", "/api/ids/summary", m.apiSummary,
		core.Query("hours", "integer", "Time window in hours for alert analysis (default 24)", false, 24),
		core.Doc("Get summary of IDS alerts grouped by severity, category, signature and source host"),
		core.Returns("Alert summary", map[string]any{
			"counts": map[string]any{
				"critical": 2,
				"high":     5,
				"medium":   10,
			},
			"by_category": map[string]any{
				"trojan":  3,
				"exploit": 2,
			},
		}))
	ctx.Route("GET", "/api/ids/alerts", m.apiAlerts,
		core.Query("hours", "integer", "Time window in hours for alert retrieval (default 24)", false, 24),
		core.Query("severity", "string", "Filter by alert severity (critical, high, medium, low)", false, "high"),
		core.Query("ip", "string", "Filter by source or destination IP address", false, "192.168.1.10"),
		core.Query("unacked", "boolean", "Show only unacknowledged alerts", false, false),
		core.Query("limit", "integer", "Maximum alerts to return (default 500)", false, 500),
		core.Doc("List recent IDS alerts with filtering by severity, IP address and acknowledgment status"),
		core.Returns("Alerts list", map[string]any{
			"alerts": []map[string]any{
				{"id": "alert-1", "severity": "high", "category": "trojan", "src_ip": "203.0.113.1", "dst_ip": "192.168.1.10", "timestamp": 1790376243},
			},
		}))
	ctx.Route("POST", "/api/ids/alerts/ack", m.apiAck, core.Write(),
		core.Doc("Acknowledge one or multiple IDS alerts to mark them as reviewed"),
		core.Body(
			core.Fld("alert_ids", "array", true, "List of alert IDs to acknowledge", []string{"alert-1"}),
		),
		core.Returns("Acknowledgment result", map[string]any{"ok": true}))
	ctx.Panel(core.Panel{ID: "threats", Title: "Threats", Group: "Protect", Order: 60, Icon: "threats"})
	return nil
}

func (m *Module) Health() core.Health {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastErr != "" {
		return core.Health{OK: false, Detail: m.lastErr}
	}
	if m.localMissing && m.remote == 0 {
		return core.Health{OK: false, Detail: "no EVE log at " + m.evePath + " and no Suricata provider has sent events"}
	}
	return core.Health{OK: true, Detail: fmt.Sprintf("%d alerts, %d tls records read (%d from providers)", m.alerts, m.tls, m.remote)}
}

var severityMap = map[int]string{1: "critical", 2: "high", 3: "medium", 4: "low"}

type eve struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	InIface   string `json:"in_iface"`
	Alert     *struct {
		Action      string `json:"action"`
		SignatureID int64  `json:"signature_id"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
	} `json:"alert"`
	TLS *struct {
		Subject     string `json:"subject"`
		IssuerDN    string `json:"issuerdn"`
		Serial      string `json:"serial"`
		Fingerprint string `json:"fingerprint"`
		SNI         string `json:"sni"`
		Version     string `json:"version"`
		NotBefore   string `json:"notbefore"`
		NotAfter    string `json:"notafter"`
		JA3         *struct {
			Hash string `json:"hash"`
		} `json:"ja3"`
		JA3S *struct {
			Hash string `json:"hash"`
		} `json:"ja3s"`
		JA4 string `json:"ja4"`
	} `json:"tls"`
}

func parseTS(s string) int64 {
	for _, layout := range []string{"2006-01-02T15:04:05.000000-0700", "2006-01-02T15:04:05.999999-07:00",
		time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			// A clock far in the future is a bad clock, not a future alert.
			if d := time.Until(t); d > time.Hour || d < -365*24*time.Hour {
				return time.Now().Unix()
			}
			return t.Unix()
		}
	}
	return time.Now().Unix()
}

// eveFiles is every EVE log the path names. It may be a pattern: pfSense's
// Suricata package writes one log per interface, in a directory per
// instance, and an interface added later is picked up on the next poll.
func (m *Module) eveFiles() []string {
	if !strings.ContainsAny(m.evePath, "*?[") {
		return []string{m.evePath}
	}
	files, _ := filepath.Glob(m.evePath)
	return files
}

func (m *Module) poll() error {
	var lines [][]byte
	var firstErr error
	read := 0
	for _, f := range m.eveFiles() {
		t := m.tails[f]
		if t == nil {
			t = core.NewTailer(f)
			// A log that appears after the first poll is new (an
			// interface added since): read it from its start.
			t.StartAtEnd = !m.polled
			m.tails[f] = t
		}
		_, err := t.Lines(func(line []byte) {
			lines = append(lines, append([]byte(nil), line...))
		})
		switch {
		case err == nil:
			read++
		case os.IsNotExist(err):
			// rotated away or not written yet; reported through Health
		case firstErr == nil:
			firstErr = fmt.Errorf("cannot read %s: %w", f, err)
		}
	}
	m.polled = true
	m.mu.Lock()
	m.localMissing = read == 0 && firstErr == nil
	m.lastErr = ""
	if firstErr != nil {
		m.lastErr = firstErr.Error()
	}
	m.mu.Unlock()
	if len(lines) > 0 {
		if _, err := m.ingest(lines, "suricata"); err != nil {
			return err
		}
	}
	return firstErr
}

// fromProvider takes a batch of EVE events from a Suricata provider.
func (m *Module) fromProvider(name string, records []json.RawMessage) (int, error) {
	lines := make([][]byte, len(records))
	for i, r := range records {
		lines[i] = r
	}
	n, err := m.ingest(lines, "suricata@"+name)
	m.mu.Lock()
	m.remote += int64(len(records))
	m.mu.Unlock()
	return n, err
}

// ingest reads EVE events, from the local log or from a provider, into
// alerts, TLS sessions and the certificate inventory. It returns how many
// records it used.
func (m *Module) ingest(lines [][]byte, source string) (int, error) {
	var alerts []core.Alert
	var sessions []tlsSession
	certs := map[string]certSeen{}
	wantTLS := core.Bool(m.ctx.Settings(), "tls_records", true)
	used := 0
	for _, line := range lines {
		var e eve
		if json.Unmarshal(line, &e) != nil {
			continue
		}
		switch e.EventType {
		case "alert":
			if e.Alert == nil {
				continue
			}
			sev := severityMap[e.Alert.Severity]
			if sev == "" {
				sev = "medium"
			}
			verdict := "observed"
			if e.Alert.Action == "blocked" {
				verdict = "blocked"
			}
			alerts = append(alerts, core.Alert{TS: parseTS(e.Timestamp), Source: source, Severity: sev,
				Verdict: verdict, SigID: fmt.Sprint(e.Alert.SignatureID), Signature: e.Alert.Signature,
				Category: e.Alert.Category, SrcIP: e.SrcIP, SrcPort: e.SrcPort, DstIP: e.DestIP,
				DstPort: e.DestPort, Proto: strings.ToLower(e.Proto), Iface: e.InIface,
				Message: e.Alert.Signature})
			used++
		case "tls":
			if !wantTLS || e.TLS == nil {
				continue
			}
			ts := parseTS(e.Timestamp)
			s := tlsSession{ts: ts, src: e.SrcIP, dst: e.DestIP, port: e.DestPort, sni: e.TLS.SNI,
				version: e.TLS.Version, fp: e.TLS.Fingerprint, ja4: e.TLS.JA4}
			if e.TLS.JA3 != nil {
				s.ja3 = e.TLS.JA3.Hash
			}
			if e.TLS.JA3S != nil {
				s.ja3s = e.TLS.JA3S.Hash
			}
			sessions = append(sessions, s)
			if e.TLS.Fingerprint != "" {
				c := certs[e.TLS.Fingerprint]
				c.subject, c.issuer, c.serial = e.TLS.Subject, e.TLS.IssuerDN, e.TLS.Serial
				c.notBefore, c.notAfter = parseCertTime(e.TLS.NotBefore), parseCertTime(e.TLS.NotAfter)
				c.host, c.sni = e.DestIP, e.TLS.SNI
				certs[e.TLS.Fingerprint] = c
			}
			used++
		}
	}
	m.mu.Lock()
	m.alerts += int64(len(alerts))
	m.tls += int64(len(sessions))
	m.mu.Unlock()
	if err := m.ctx.Store.AddAlerts(alerts); err != nil {
		return used, err
	}
	agg := map[string]*core.HostUpdate{}
	for _, a := range alerts {
		for _, ip := range []string{a.SrcIP, a.DstIP} {
			if m.identity != nil && m.identity.IsLocal(ip) {
				h := agg[ip]
				if h == nil {
					h = &core.HostUpdate{IP: ip, Source: "ids"}
					agg[ip] = h
				}
				h.Alerts++
			}
		}
	}
	var ups []core.HostUpdate
	for _, h := range agg {
		ups = append(ups, *h)
	}
	_ = m.ctx.Store.UpsertHosts(ups)
	if len(sessions) > 0 {
		if err := m.writeTLS(sessions, certs); err != nil {
			return used, err
		}
	}
	return used, nil
}

type tlsSession struct {
	ts                          int64
	src, dst                    string
	port                        int
	sni, version, fp, ja3, ja3s string
	ja4                         string
}

type certSeen struct {
	subject, issuer, serial string
	notBefore, notAfter     int64
	host, sni               string
}

func parseCertTime(s string) int64 {
	for _, layout := range []string{"2006-01-02T15:04:05", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.Unix()
		}
	}
	return 0
}

func (m *Module) writeTLS(sessions []tlsSession, certs map[string]certSeen) error {
	st := m.ctx.Store
	return st.Tx(func(tx *sql.Tx) error {
		ins, err := tx.Prepare(`INSERT INTO tls_sessions(ts,src_ip,dst_ip,dst_port,sni,version,ja3,ja3s,ja4,
			fingerprint,mode,source) VALUES(?,?,?,?,?,?,?,?,?,?,'passive','suricata')`)
		if err != nil {
			return err
		}
		defer ins.Close()
		for _, s := range sessions {
			if _, err := ins.Exec(s.ts, s.src, s.dst, s.port, nz(s.sni), nz(s.version), nz(s.ja3), nz(s.ja3s),
				nz(s.ja4), nz(s.fp)); err != nil {
				return err
			}
		}
		up, err := tx.Prepare(`INSERT INTO tls_certs(fingerprint,subject,issuer,serial,not_before,not_after,self_signed,
			first_seen,last_seen,seen,hosts,snis,source) VALUES(?,?,?,?,?,?,?,?,?,1,?,?,'suricata')
			ON CONFLICT(fingerprint) DO UPDATE SET last_seen=excluded.last_seen, seen=seen+1,
			subject=COALESCE(excluded.subject,subject), issuer=COALESCE(excluded.issuer,issuer),
			not_after=CASE WHEN excluded.not_after>0 THEN excluded.not_after ELSE not_after END`)
		if err != nil {
			return err
		}
		defer up.Close()
		now := time.Now().Unix()
		for fp, c := range certs {
			self := 0
			if c.subject != "" && c.subject == c.issuer {
				self = 1
			}
			hosts, _ := json.Marshal([]string{c.host})
			snis, _ := json.Marshal(filterEmpty([]string{c.sni}))
			if _, err := up.Exec(fp, nz(c.subject), nz(c.issuer), nz(c.serial), c.notBefore, c.notAfter, self,
				now, now, string(hosts), string(snis)); err != nil {
				return err
			}
		}
		return nil
	})
}

func nz(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func filterEmpty(xs []string) []string {
	var out []string
	for _, x := range xs {
		if x != "" {
			out = append(out, x)
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}

// ---------------------------------------------------------------- API

func (m *Module) name(ip string) string {
	if m.identity == nil {
		return ""
	}
	return m.identity.Name(ip)
}

func (m *Module) apiSummary(r *core.Req) (any, error) {
	since := r.Since(24)
	st := m.ctx.Store
	bySev, _ := st.Rows(`SELECT severity, COUNT(*) AS alerts FROM alerts WHERE ts>=? GROUP BY severity`, since)
	byCat, _ := st.Rows(`SELECT category, COUNT(*) AS alerts FROM alerts WHERE ts>=? GROUP BY category ORDER BY alerts DESC LIMIT 20`, since)
	bySig, _ := st.Rows(`SELECT sig_id, signature, MAX(severity) AS severity, COUNT(*) AS alerts,
		COUNT(DISTINCT src_ip) AS sources FROM alerts WHERE ts>=? GROUP BY sig_id ORDER BY alerts DESC LIMIT 25`, since)
	bySrc, _ := st.Rows(`SELECT src_ip AS ip, COUNT(*) AS alerts FROM alerts WHERE ts>=? GROUP BY src_ip ORDER BY alerts DESC LIMIT 15`, since)
	byDst, _ := st.Rows(`SELECT dst_ip AS ip, COUNT(*) AS alerts FROM alerts WHERE ts>=? GROUP BY dst_ip ORDER BY alerts DESC LIMIT 15`, since)
	for _, rows := range [][]map[string]any{bySrc, byDst} {
		for _, row := range rows {
			ip, _ := row["ip"].(string)
			if n := m.name(ip); n != "" {
				row["name"] = n
			}
			row["local"] = m.identity != nil && m.identity.IsLocal(ip)
		}
	}
	total := st.Int(`SELECT COUNT(*) FROM alerts WHERE ts>=?`, since)
	blocked := st.Int(`SELECT COUNT(*) FROM alerts WHERE ts>=? AND verdict='blocked'`, since)
	m.mu.Lock()
	lastErr := m.lastErr
	m.mu.Unlock()
	return map[string]any{"total": total, "blocked": blocked, "by_severity": bySev, "by_category": byCat,
		"by_signature": bySig, "by_source": bySrc, "by_destination": byDst, "source_error": lastErr,
		"hours": r.Hours(24)}, nil
}

func (m *Module) apiAlerts(r *core.Req) (any, error) {
	since := r.Since(24)
	sev, err := r.QSafe("severity", "", 10)
	if err != nil {
		return nil, err
	}
	ip, err := r.QSafe("ip", "", 64)
	if err != nil {
		return nil, err
	}
	q := `SELECT * FROM alerts WHERE ts>=?`
	args := []any{since}
	if sev != "" {
		q += ` AND severity=?`
		args = append(args, sev)
	}
	if ip != "" {
		q += ` AND (src_ip=? OR dst_ip=?)`
		args = append(args, ip, ip)
	}
	if r.Q("unacked", "") != "" {
		q += ` AND acked=0`
	}
	q += ` ORDER BY ts DESC LIMIT ?`
	args = append(args, r.QInt("limit", 200, 1, 5000))
	rows, err := m.ctx.Store.Rows(q, args...)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		for _, k := range []string{"src_ip", "dst_ip"} {
			ipv, _ := row[k].(string)
			if n := m.name(ipv); n != "" {
				row[k+"_name"] = n
			}
		}
	}
	return map[string]any{"alerts": rows}, nil
}

func (m *Module) apiAck(r *core.Req) (any, error) {
	ids, _ := r.Body()["ids"].([]any)
	for _, v := range ids {
		if f, ok := v.(float64); ok {
			_ = m.ctx.Store.Exec(`UPDATE alerts SET acked=1 WHERE id=?`, int64(f))
		}
	}
	return map[string]any{"ok": true}, nil
}

// EffectiveSettings reports the EVE log actually followed.
func (m *Module) EffectiveSettings() map[string]any { return map[string]any{"eve_path": m.evePath} }
