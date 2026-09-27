// Package baseline implements anomaly detection based on learned per-device profiles.
// It learns normal behavior for devices over a configurable period (default 7 days),
// then detects first-seen countries, ports, destinations, irregular beaconing patterns,
// and DNS tunneling heuristics.
package baseline

import (
	"database/sql"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

type Module struct {
	ctx       *core.Context
	identity  core.Identity
	enricher  interface{}
	alerting  core.AlertingSend
	mu        sync.RWMutex
	learning  map[string]time.Time // mac -> learning start time
	devStates map[string]*deviceState
	cooldowns map[string]time.Time // dedup key -> cooldown until
	settings  Settings
}

type Settings struct {
	LearningDays         int      `json:"learning_days"`
	MaxDestinations      int      `json:"max_destinations"`
	BytesMultiplier      float64  `json:"bytes_multiplier"`
	BeaconingMinSessions int      `json:"beaconing_min_sessions"`
	BeaconingCVThreshold float64  `json:"beaconing_cv_threshold"`
	DNSTunnelMinLength   int      `json:"dns_tunnel_min_length"`
	DNSTunnelMinEntropy  float64  `json:"dns_tunnel_min_entropy"`
	DNSTunnelMinRate     float64  `json:"dns_tunnel_min_rate"`
	CooldownMinutes      int      `json:"cooldown_minutes"`
	ExcludedZones        []string `json:"excluded_zones"`
}

type deviceState struct {
	Mac          string
	FirstSeen    int64
	Countries    map[string]*countryRecord
	Ports        map[string]*portRecord // proto:port -> record
	Destinations map[string]*dstRecord  // ip or domain -> record
	Activities   [24]int64              // hourly byte count
	DailyBytes   []int64                // rolling window of daily sums
	DNSStats     DNSStats
}

type countryRecord struct {
	Country   string
	FirstSeen int64
	LastSeen  int64
	Count     int64
	Bytes     int64
}

type portRecord struct {
	Proto     string
	Port      int
	FirstSeen int64
	LastSeen  int64
	Count     int64
	Bytes     int64
}

type dstRecord struct {
	Destination string
	FirstSeen   int64
	LastSeen    int64
	Count       int64
	Bytes       int64
}

type DNSStats struct {
	Domains     map[string]*dnsRecord // registered domain -> record
	GlobalCount int64
	NXDOMAIN    int64
}

type dnsRecord struct {
	RegisteredDomain string
	Queries          int64
	NXDOMAIN         int64
	UniqueSubdomains map[string]bool
	MeanLabelLength  float64
	Entropy          float64
	FirstSeen        int64
	LastSeen         int64
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name: "baseline", Version: "1.0",
		Description:  "Detects anomalies: first-seen countries, ports, destinations, irregular beaconing, and DNS tunneling.",
		Capabilities: []string{core.CapThreatDetect},
		After:        []string{"identity", "enrich", "alerting"},
		Defaults: map[string]any{
			"learning_days":          7,
			"max_destinations":       50,
			"bytes_multiplier":       2.0,
			"beaconing_min_sessions": 5,
			"beaconing_cv_threshold": 0.2,
			"dns_tunnel_min_length":  20,
			"dns_tunnel_min_entropy": 5.0,
			"dns_tunnel_min_rate":    0.3,
			"cooldown_minutes":       60,
			"excluded_zones":         []string{},
		},
		Schema: []core.SettingField{
			{Key: "learning_days", Label: "Learning period (days)", Type: "int", Section: "Detection"},
			{Key: "max_destinations", Label: "Max destinations per device", Type: "int", Section: "Detection",
				Help: "Cap for in-memory destination tracking; the most frequent are kept."},
			{Key: "bytes_multiplier", Label: "Bytes threshold multiplier", Type: "int", Section: "Detection",
				Help: "Flag outbound bytes above N × device daily median."},
			{Key: "beaconing_min_sessions", Label: "Beaconing: min sessions", Type: "int", Section: "Beaconing"},
			{Key: "beaconing_cv_threshold", Label: "Beaconing: regularity threshold", Type: "int", Section: "Beaconing",
				Help: "Coefficient of variation; lower = more regular. Flag when CV is below this."},
			{Key: "dns_tunnel_min_length", Label: "DNS: min label length", Type: "int", Section: "DNS Tunneling"},
			{Key: "dns_tunnel_min_entropy", Label: "DNS: min entropy", Type: "int", Section: "DNS Tunneling"},
			{Key: "dns_tunnel_min_rate", Label: "DNS: NXDOMAIN rate", Type: "int", Section: "DNS Tunneling",
				Help: "Flag when NXDOMAIN rate (0-1) exceeds this and is far above device baseline."},
			{Key: "cooldown_minutes", Label: "Finding cooldown (minutes)", Type: "int", Section: "Deduplication"},
			{Key: "excluded_zones", Label: "Excluded zones", Type: "list", Section: "Exclusions",
				Help: "Devices in these zones are never flagged."},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.learning = map[string]time.Time{}
	m.devStates = map[string]*deviceState{}
	m.cooldowns = map[string]time.Time{}

	if err := ctx.Decode(&m.settings); err != nil {
		return err
	}

	id := ctx.Service("identity")
	if id == nil {
		return fmt.Errorf("baseline: identity service not available")
	}
	m.identity = id.(core.Identity)

	m.enricher = ctx.Service("enricher")
	a := ctx.Service("alerting")
	if a != nil {
		if as, ok := a.(core.AlertingSend); ok {
			m.alerting = as
		}
	}

	// Initialize schema
	if err := m.initSchema(); err != nil {
		return err
	}

	// Publish API routes
	ctx.Route("GET", "/api/baseline/anomalies", m.apiAnomalies, core.Doc("Get all unresolved baseline anomalies detected across devices"),
		core.Returns("List of baseline anomalies", map[string]any{
			"anomalies": []map[string]any{
				{"id": 1, "ts": 1790376243, "device": "client-laptop", "mac": "aa:bb:cc:dd:ee:ff", "kind": "new_country", "severity": "info", "title": "New country detected", "detail": "Traffic to Russia (RU)", "acked": 0},
			},
		}))
	ctx.Route("GET", "/api/baseline/profile", m.apiProfile, core.Doc("Get the learned baseline profile for a device including countries, ports, and destinations"),
		core.Query("ip", "string", "Device IP address (either ip or mac required)", false, "192.168.1.10"),
		core.Query("mac", "string", "Device MAC address (either ip or mac required)", false, "aa:bb:cc:dd:ee:ff"),
		core.Returns("Device baseline profile", map[string]any{
			"profile": map[string]any{
				"mac":          "aa:bb:cc:dd:ee:ff",
				"first_seen":   1790376243,
				"countries":    map[string]any{"US": map[string]any{"first_seen": 1790376243, "last_seen": 1790376343, "count": 100, "bytes": 1000000}},
				"ports":        map[string]any{"tcp:443": map[string]any{"first_seen": 1790376243, "count": 50, "bytes": 500000}},
				"destinations": map[string]any{"example.com": map[string]any{"first_seen": 1790376243, "count": 25, "bytes": 250000}},
			},
		}))
	ctx.Route("POST", "/api/baseline/ack", m.apiAck, core.Write(), core.Doc("Mark a baseline anomaly as acknowledged by the user"),
		core.Body(
			core.Fld("id", "integer", true, "Anomaly ID to acknowledge", 1),
		),
		core.Returns("Acknowledgment successful", map[string]any{"ok": true}))
	ctx.Route("GET", "/api/baseline/status", m.apiStatus, core.Doc("Get module status: learning progress, device count, and detection settings"),
		core.Returns("Baseline module status", map[string]any{
			"devices": 15,
			"settings": map[string]any{
				"learning_days":          7,
				"max_destinations":       50,
				"bytes_multiplier":       2.0,
				"beaconing_min_sessions": 5,
				"beaconing_cv_threshold": 0.2,
				"dns_tunnel_min_length":  20,
				"dns_tunnel_min_entropy": 5.0,
				"dns_tunnel_min_rate":    0.3,
				"cooldown_minutes":       60,
			},
		}))

	// Register panel
	ctx.Panel(core.Panel{ID: "anomalies", Title: "Anomalies", Group: "Protect", Order: 30, Icon: "alert"})

	// Start learning and detection jobs
	ctx.Every("learn", 5*time.Minute, m.learnJob)
	ctx.Every("detect", 5*time.Minute, m.detectJob)

	return nil
}

func (m *Module) initSchema() error {
	if err := m.ctx.Store.Exec(`
CREATE TABLE IF NOT EXISTS baseline_profile (
	device TEXT NOT NULL,
	kind TEXT NOT NULL,
	value TEXT NOT NULL,
	first_seen INTEGER,
	last_seen INTEGER,
	count INTEGER DEFAULT 0,
	bytes INTEGER DEFAULT 0,
	PRIMARY KEY (device, kind, value)
)
	`); err != nil {
		return err
	}

	if err := m.ctx.Store.Exec(`
CREATE INDEX IF NOT EXISTS baseline_device ON baseline_profile(device)
	`); err != nil {
		return err
	}

	if err := m.ctx.Store.Exec(`
CREATE TABLE IF NOT EXISTS baseline_anomalies (
	id INTEGER PRIMARY KEY,
	ts INTEGER NOT NULL,
	device TEXT NOT NULL,
	mac TEXT NOT NULL,
	kind TEXT NOT NULL,
	severity TEXT NOT NULL,
	title TEXT NOT NULL,
	detail TEXT NOT NULL,
	fingerprint TEXT,
	acked INTEGER DEFAULT 0,
	resolved_ts INTEGER
)
	`); err != nil {
		return err
	}

	if err := m.ctx.Store.Exec(`
CREATE INDEX IF NOT EXISTS baseline_anomalies_device ON baseline_anomalies(device, ts)
	`); err != nil {
		return err
	}

	return m.ctx.Store.Exec(`
CREATE INDEX IF NOT EXISTS baseline_anomalies_fp ON baseline_anomalies(fingerprint)
	`)
}

func (m *Module) learnJob() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	window := 5 * time.Minute
	windowStart := now.Add(-window).Unix()

	// Fetch flows from the last window
	rows, err := m.ctx.Store.DB().Query(`
		SELECT src_ip, dst_ip, dst_port, proto, country, asn, bytes_out
		FROM flows
		WHERE ts > ? AND ts <= ? AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
	`, windowStart, now.Unix())
	if err != nil {
		return err
	}
	defer rows.Close()

	// Fold by device (MAC via identity)
	flowsByDevice := map[string][]*Flow{}
	for rows.Next() {
		var f Flow
		var country, asn sql.NullString
		if err := rows.Scan(&f.SrcIP, &f.DstIP, &f.DstPort, &f.Proto, &country, &asn, &f.BytesOut); err != nil {
			return err
		}
		if country.Valid {
			f.Country = country.String
		}
		if asn.Valid {
			f.ASN = asn.String
		}
		mac := m.identity.MAC(f.SrcIP)
		if mac == "" {
			continue // Skip unknown devices
		}
		flowsByDevice[mac] = append(flowsByDevice[mac], &f)
	}

	// Update per-device profiles
	for mac, flows := range flowsByDevice {
		state, ok := m.devStates[mac]
		if !ok {
			state = &deviceState{
				Mac:          mac,
				FirstSeen:    now.Unix(),
				Countries:    map[string]*countryRecord{},
				Ports:        map[string]*portRecord{},
				Destinations: map[string]*dstRecord{},
				DailyBytes:   []int64{},
				DNSStats:     DNSStats{Domains: map[string]*dnsRecord{}},
			}
			m.devStates[mac] = state
			m.learning[mac] = now
		}

		for _, f := range flows {
			// Country
			if f.Country != "" {
				cr := state.Countries[f.Country]
				if cr == nil {
					cr = &countryRecord{Country: f.Country, FirstSeen: now.Unix()}
					state.Countries[f.Country] = cr
				}
				cr.LastSeen = now.Unix()
				cr.Count++
				cr.Bytes += f.BytesOut
			}

			// Port + Proto
			key := fmt.Sprintf("%s:%d", f.Proto, f.DstPort)
			pr := state.Ports[key]
			if pr == nil {
				pr = &portRecord{Proto: f.Proto, Port: f.DstPort, FirstSeen: now.Unix()}
				state.Ports[key] = pr
			}
			pr.LastSeen = now.Unix()
			pr.Count++
			pr.Bytes += f.BytesOut

			// Destination
			if f.DstIP != "" {
				dr := state.Destinations[f.DstIP]
				if dr == nil {
					dr = &dstRecord{Destination: f.DstIP, FirstSeen: now.Unix()}
					state.Destinations[f.DstIP] = dr
				}
				dr.LastSeen = now.Unix()
				dr.Count++
				dr.Bytes += f.BytesOut
			}
		}

		// Update hour-of-day activity
		hour := now.Hour()
		bytes := int64(0)
		for _, f := range flows {
			bytes += f.BytesOut
		}
		state.Activities[hour] += bytes
	}

	// Persist profiles to database
	for mac, state := range m.devStates {
		for country, cr := range state.Countries {
			if err := m.upsertProfile(mac, "country", country, cr.FirstSeen, cr.LastSeen, cr.Count, cr.Bytes); err != nil {
				return err
			}
		}
		for key, pr := range state.Ports {
			if err := m.upsertProfile(mac, "port", key, pr.FirstSeen, pr.LastSeen, pr.Count, pr.Bytes); err != nil {
				return err
			}
		}
		// Keep only most frequent destinations
		if len(state.Destinations) > m.settings.MaxDestinations {
			dests := make([]*dstRecord, 0, len(state.Destinations))
			for _, dr := range state.Destinations {
				dests = append(dests, dr)
			}
			sort.Slice(dests, func(i, j int) bool { return dests[i].Count > dests[j].Count })
			kept := dests[:m.settings.MaxDestinations]
			newMap := map[string]*dstRecord{}
			for _, dr := range kept {
				newMap[dr.Destination] = dr
			}
			state.Destinations = newMap
		}
		for dst, dr := range state.Destinations {
			if err := m.upsertProfile(mac, "destination", dst, dr.FirstSeen, dr.LastSeen, dr.Count, dr.Bytes); err != nil {
				return err
			}
		}
	}

	return nil
}

func (m *Module) upsertProfile(mac, kind, value string, firstSeen, lastSeen, count, bytes int64) error {
	return m.ctx.Store.Tx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`
			INSERT INTO baseline_profile (device, kind, value, first_seen, last_seen, count, bytes)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(device, kind, value) DO UPDATE SET
			last_seen = ?, count = count + ?, bytes = bytes + ?
		`, mac, kind, value, firstSeen, lastSeen, count, bytes,
			lastSeen, count, bytes)
		return err
	})
}

func (m *Module) detectJob() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	learningDays := time.Duration(m.settings.LearningDays) * 24 * time.Hour

	// Prepare to keep findings
	keep := map[string]bool{}

	for mac, state := range m.devStates {
		// Check if still in learning period
		inLearning := time.Unix(state.FirstSeen, 0).Add(learningDays).After(now)
		if inLearning {
			continue
		}

		// Get device name and zone
		ip := m.getDeviceIP(mac)
		if ip == "" {
			continue
		}
		name := m.identity.Name(ip)
		zone := "" // Would need to look this up from policy

		// Check exclusions
		excluded := false
		for _, z := range m.settings.ExcludedZones {
			if zone == z {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}

		// Detect first-seen countries
		m.detectCountries(mac, name, ip, state, keep)

		// Detect first-seen ports
		m.detectPorts(mac, name, ip, state, keep)

		// Detect first-seen destinations
		m.detectDestinations(mac, name, ip, state, keep)

		// Detect beaconing
		m.detectBeaconing(mac, name, ip, state, keep)

		// Detect DNS tunneling
		m.detectDNSTunneling(mac, name, ip, state, keep)
	}

	// Cleanup resolved findings (not in keep)
	_ = m.ctx.Store.Exec(`
		UPDATE baseline_anomalies SET resolved_ts = ?
		WHERE device NOT IN (SELECT DISTINCT device FROM baseline_anomalies)
		AND resolved_ts IS NULL AND ts < ?
	`, now.Unix(), now.Add(-24*time.Hour).Unix())

	return nil
}

func (m *Module) detectCountries(mac, name, ip string, state *deviceState, keep map[string]bool) {
	window := 5 * time.Minute
	now := time.Now()

	rows, _ := m.ctx.Store.DB().Query(`
		SELECT DISTINCT country FROM flows
		WHERE src_ip = ? AND ts > ?
	`, ip, now.Add(-window).Unix())
	if rows == nil {
		return
	}
	defer rows.Close()

	seen := map[string]bool{}
	for rows.Next() {
		var country string
		if err := rows.Scan(&country); err == nil && country != "" {
			seen[country] = true
			// Check if this is a first-seen country
			baseline, exists := state.Countries[country]
			if !exists || (baseline != nil && baseline.FirstSeen > now.Add(-24*time.Hour).Unix()) {
				// New country
				fp := fmt.Sprintf("baseline:%s:country:%s", mac, country)
				keep[fp] = true
				days := (now.Unix() - state.FirstSeen) / 86400
				baselineCountries := m.getCountriesString(state.Countries)
				deviceName := m.identity.Name(ip)
				if deviceName == "" || deviceName == ip {
					deviceName = name
				}
				m.addAnomaly(mac, name, "new_country", "high",
					fmt.Sprintf("First time in %s", country),
					fmt.Sprintf("First time %s (%s) talked to %s; %d days of history had %s",
						deviceName, mac, country, days, baselineCountries), anomalyAttrs(ip, mac, deviceName, map[string]any{"country": country}, map[string]any{"days": days, "baseline": baselineCountries}))
			}
		}
	}
}

func (m *Module) detectPorts(mac, name, ip string, state *deviceState, keep map[string]bool) {
	window := 5 * time.Minute
	now := time.Now()

	rows, _ := m.ctx.Store.DB().Query(`
		SELECT DISTINCT proto, dst_port FROM flows
		WHERE src_ip = ? AND ts > ?
	`, ip, now.Add(-window).Unix())
	if rows == nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var proto string
		var port int
		if err := rows.Scan(&proto, &port); err == nil {
			key := fmt.Sprintf("%s:%d", proto, port)
			baseline, exists := state.Ports[key]
			if !exists || (baseline != nil && baseline.FirstSeen > now.Add(-24*time.Hour).Unix()) {
				fp := fmt.Sprintf("baseline:%s:port:%s", mac, key)
				keep[fp] = true
				days := (now.Unix() - state.FirstSeen) / 86400
				baselinePorts := m.getPortsString(state.Ports)
				deviceName := m.identity.Name(ip)
				if deviceName == "" || deviceName == ip {
					deviceName = name
				}
				m.addAnomaly(mac, name, "new_port", "medium",
					fmt.Sprintf("First connection to %s/%d", proto, port),
					fmt.Sprintf("First time %s (%s) talked to %s/%d; %d days of history had %s",
						deviceName, mac, proto, port, days, baselinePorts), anomalyAttrs(ip, mac, m.identity.Name(ip), map[string]any{"port": port, "proto": proto}, map[string]any{"days": days, "baseline": baselinePorts}))
			}
		}
	}
}

func (m *Module) detectDestinations(mac, name, ip string, state *deviceState, keep map[string]bool) {
	window := 5 * time.Minute
	now := time.Now()

	// Only flag for small, stable destination sets (IoT characteristic)
	if len(state.Destinations) > 20 {
		return
	}

	rows, _ := m.ctx.Store.DB().Query(`
		SELECT DISTINCT COALESCE(domain, dst_ip) FROM flows
		WHERE src_ip = ? AND ts > ?
	`, ip, now.Add(-window).Unix())
	if rows == nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var dst string
		if err := rows.Scan(&dst); err == nil && dst != "" {
			baseline, exists := state.Destinations[dst]
			if !exists || (baseline != nil && baseline.FirstSeen > now.Add(-24*time.Hour).Unix()) {
				fp := fmt.Sprintf("baseline:%s:destination:%s", mac, dst)
				keep[fp] = true
				days := (now.Unix() - state.FirstSeen) / 86400
				baselineDestinations := m.getDestinationsString(state.Destinations)
				deviceName := m.identity.Name(ip)
				if deviceName == "" || deviceName == ip {
					deviceName = name
				}
				m.addAnomaly(mac, name, "new_destination", "medium",
					fmt.Sprintf("First connection to %s", dst),
					fmt.Sprintf("First time %s (%s) talked to %s; %d days of history had %s",
						deviceName, mac, dst, days, baselineDestinations), anomalyAttrs(ip, mac, deviceName, map[string]any{"ip": dst}, map[string]any{"days": days, "baseline": baselineDestinations}))
			}
		}
	}
}

func (m *Module) detectBeaconing(mac, name, ip string, state *deviceState, keep map[string]bool) {
	now := time.Now()
	window := 24 * time.Hour

	// For each destination with many sessions, analyze inter-arrival times
	rows, _ := m.ctx.Store.DB().Query(`
		SELECT COALESCE(domain, dst_ip), COUNT(*) as cnt, AVG(bytes_out) as avg_bytes
		FROM flows
		WHERE src_ip = ? AND ts > ?
		GROUP BY COALESCE(domain, dst_ip)
		HAVING COUNT(*) >= ?
	`, ip, now.Add(-window).Unix(), m.settings.BeaconingMinSessions)
	if rows == nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var dst string
		var count int
		var avgBytes sql.NullFloat64
		if err := rows.Scan(&dst, &count, &avgBytes); err != nil {
			continue
		}

		// Get inter-arrival times
		times, _ := m.getInterarrivalTimes(ip, dst, window)
		if len(times) < m.settings.BeaconingMinSessions {
			continue
		}

		// Calculate coefficient of variation
		mean, stddev := m.calcStats(times)
		if mean == 0 {
			continue
		}
		cv := stddev / mean
		if cv < float64(m.settings.BeaconingCVThreshold) {
			period := m.estimatePeriod(times)
			fp := fmt.Sprintf("baseline:%s:beacon:%s", mac, dst)
			keep[fp] = true
			avgBytesVal := 0.0
			if avgBytes.Valid {
				avgBytesVal = avgBytes.Float64
			}
			days := (now.Unix() - state.FirstSeen) / 86400
			deviceName := m.identity.Name(ip)
			if deviceName == "" || deviceName == ip {
				deviceName = name
			}
			m.addAnomaly(mac, name, "beaconing", "high",
				fmt.Sprintf("Beacon to %s (~%.0fs period)", dst, period.Seconds()),
				fmt.Sprintf("Regular beacon from %s (%s) to %s: ~%.0fs interval, %.0f bytes per packet; %d days of history showed no such pattern",
					deviceName, mac, dst, period.Seconds(), avgBytesVal, days),
				anomalyAttrs(ip, mac, deviceName, map[string]any{"ip": dst}, map[string]any{"period_s": period.Seconds(), "bytes_per_packet": avgBytesVal, "days": days}))
		}
	}
}

func (m *Module) detectDNSTunneling(mac, name, ip string, state *deviceState, keep map[string]bool) {
	now := time.Now()
	window := 1 * time.Hour

	rows, _ := m.ctx.Store.DB().Query(`
		SELECT domain, COUNT(*) as cnt,
		SUM(CASE WHEN rcode='NXDOMAIN' THEN 1 ELSE 0 END) as nxdomain
		FROM dns
		WHERE client = ? AND ts > ?
		GROUP BY domain
	`, ip, now.Add(-window).Unix())
	if rows == nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var domain string
		var count int
		var nxdomain int
		if err := rows.Scan(&domain, &count, &nxdomain); err != nil {
			continue
		}

		nxRate := float64(nxdomain) / float64(count)
		if nxRate > float64(m.settings.DNSTunnelMinRate) {
			entropy := m.calcDNSEntropy(domain)
			meanLabelLen := m.calcMeanLabelLength(domain)
			if entropy >= float64(m.settings.DNSTunnelMinEntropy) &&
				meanLabelLen >= float64(m.settings.DNSTunnelMinLength) {
				fp := fmt.Sprintf("baseline:%s:dns_tunnel:%s", mac, domain)
				keep[fp] = true
				days := (now.Unix() - state.FirstSeen) / 86400
				deviceName := m.identity.Name(ip)
				if deviceName == "" || deviceName == ip {
					deviceName = name
				}
				m.addAnomaly(mac, name, "dns_tunneling", "high",
					fmt.Sprintf("Possible DNS tunneling to %s", domain),
					fmt.Sprintf("DNS tunneling indicators from %s (%s) to %s: %d%% NXDOMAIN (far above baseline), entropy %.1f, label length %.0f; %d days of history showed normal patterns",
						deviceName, mac, domain, int(nxRate*100), entropy, meanLabelLen, days), anomalyAttrs(ip, mac, deviceName, map[string]any{"domain": domain}, map[string]any{"nxdomain_pct": int(nxRate * 100), "entropy": entropy, "mean_label_len": meanLabelLen, "days": days}))
			}
		}
	}
}

func (m *Module) addAnomaly(mac, name, kind, severity, title, detail string, attrs map[string]any) {
	now := time.Now()
	fp := fmt.Sprintf("baseline:%s:%s", mac, kind)
	cooldown, hasCooldown := m.cooldowns[fp]
	if hasCooldown && cooldown.After(now) {
		return // Still in cooldown
	}

	_ = m.ctx.Store.Exec(`
		INSERT INTO baseline_anomalies
		(ts, device, mac, kind, severity, title, detail, fingerprint, acked)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
		ON CONFLICT(fingerprint) DO UPDATE SET
		ts = ?, title = ?, detail = ?
		WHERE resolved_ts IS NULL
	`, now.Unix(), name, mac, kind, severity, title, detail, fp,
		now.Unix(), title, detail)

	m.cooldowns[fp] = now.Add(time.Duration(m.settings.CooldownMinutes) * time.Minute)

	// Also create a finding in the main findings table
	_, _ = m.ctx.Store.AddFindingWith("baseline", kind, severity, mac, title, detail, fp, attrs)

	// Send alert if alerting is available
	if m.alerting != nil {
		_ = m.alerting.Send("default", core.Message{
			Subject: fmt.Sprintf("[%s] %s", severity, title),
			Text:    detail,
		})
	}
}

// Helper functions

func (m *Module) getDeviceIP(mac string) string {
	rows, _ := m.ctx.Store.DB().Query(`SELECT ip FROM devices WHERE mac = ?`, mac)
	if rows == nil {
		return ""
	}
	defer rows.Close()
	if rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err == nil {
			return ip
		}
	}
	return ""
}

func (m *Module) getInterarrivalTimes(ip, dst string, window time.Duration) ([]float64, error) {
	now := time.Now()
	rows, err := m.ctx.Store.DB().Query(`
		SELECT ts FROM flows
		WHERE src_ip = ? AND COALESCE(domain, dst_ip) = ? AND ts > ?
		ORDER BY ts
	`, ip, dst, now.Add(-window).Unix())
	if err != nil || rows == nil {
		return nil, err
	}
	defer rows.Close()

	var times []int64
	for rows.Next() {
		var ts int64
		if err := rows.Scan(&ts); err != nil {
			return nil, err
		}
		times = append(times, ts)
	}

	var intervals []float64
	for i := 1; i < len(times); i++ {
		intervals = append(intervals, float64(times[i]-times[i-1]))
	}
	return intervals, nil
}

func (m *Module) getCountriesString(countries map[string]*countryRecord) string {
	if len(countries) == 0 {
		return "none"
	}
	countryStrs := make([]string, 0, len(countries))
	for c := range countries {
		countryStrs = append(countryStrs, c)
	}
	sort.Strings(countryStrs)
	const maxItems = 8
	result := ""
	if len(countryStrs) > maxItems {
		result = strings.Join(countryStrs[:maxItems], ", ") + fmt.Sprintf(" (+%d more)", len(countryStrs)-maxItems)
	} else {
		result = strings.Join(countryStrs, ", ") + " only"
	}
	return result
}

func (m *Module) getPortsString(ports map[string]*portRecord) string {
	if len(ports) == 0 {
		return "none"
	}
	portStrs := make([]string, 0, len(ports))
	for p := range ports {
		portStrs = append(portStrs, p)
	}
	sort.Strings(portStrs)
	const maxItems = 8
	result := ""
	if len(portStrs) > maxItems {
		result = strings.Join(portStrs[:maxItems], ", ") + fmt.Sprintf(" (+%d more)", len(portStrs)-maxItems)
	} else {
		result = strings.Join(portStrs, ", ") + " only"
	}
	return result
}

func (m *Module) getDestinationsString(dests map[string]*dstRecord) string {
	if len(dests) == 0 {
		return "none"
	}
	destStrs := make([]string, 0, len(dests))
	for d := range dests {
		destStrs = append(destStrs, d)
	}
	sort.Strings(destStrs)
	const maxItems = 8
	result := ""
	if len(destStrs) > maxItems {
		result = strings.Join(destStrs[:maxItems], ", ") + fmt.Sprintf(" (+%d more)", len(destStrs)-maxItems)
	} else {
		result = strings.Join(destStrs, ", ") + " only"
	}
	return result
}

func (m *Module) calcStats(values []float64) (mean, stddev float64) {
	if len(values) == 0 {
		return 0, 0
	}
	for _, v := range values {
		mean += v
	}
	mean /= float64(len(values))
	for _, v := range values {
		stddev += (v - mean) * (v - mean)
	}
	stddev = math.Sqrt(stddev / float64(len(values)))
	return
}

func (m *Module) estimatePeriod(intervals []float64) time.Duration {
	if len(intervals) == 0 {
		return 0
	}
	mean, _ := m.calcStats(intervals)
	return time.Duration(mean) * time.Second
}

func (m *Module) calcDNSEntropy(domain string) float64 {
	freq := map[rune]int{}
	for _, r := range domain {
		freq[r]++
	}
	var entropy float64
	for _, count := range freq {
		p := float64(count) / float64(len(domain))
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func (m *Module) calcMeanLabelLength(domain string) float64 {
	parts := strings.Split(domain, ".")
	if len(parts) == 0 {
		return 0
	}
	var sum int
	for _, part := range parts {
		sum += len(part)
	}
	return float64(sum) / float64(len(parts))
}

// API handlers

func (m *Module) apiAnomalies(req *core.Req) (any, error) {
	rows, err := m.ctx.Store.DB().Query(`
		SELECT id, ts, device, mac, kind, severity, title, detail, acked
		FROM baseline_anomalies
		WHERE resolved_ts IS NULL
		ORDER BY ts DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type Anomaly struct {
		ID       int    `json:"id"`
		Ts       int64  `json:"ts"`
		Device   string `json:"device"`
		MAC      string `json:"mac"`
		Kind     string `json:"kind"`
		Severity string `json:"severity"`
		Title    string `json:"title"`
		Detail   string `json:"detail"`
		Acked    int    `json:"acked"`
	}

	var anomalies []Anomaly
	for rows.Next() {
		var a Anomaly
		if err := rows.Scan(&a.ID, &a.Ts, &a.Device, &a.MAC, &a.Kind, &a.Severity, &a.Title, &a.Detail, &a.Acked); err != nil {
			return nil, err
		}
		anomalies = append(anomalies, a)
	}

	return map[string]any{"anomalies": anomalies}, nil
}

func (m *Module) apiProfile(req *core.Req) (any, error) {
	ip := req.Q("ip", "")
	mac := req.Q("mac", "")
	if ip == "" && mac == "" {
		return nil, &core.Error{Status: 400, Message: "ip or mac required"}
	}

	if ip != "" {
		mac = m.identity.MAC(ip)
	}
	if mac == "" {
		return nil, &core.Error{Status: 404, Message: "unknown device"}
	}

	m.mu.RLock()
	state, exists := m.devStates[mac]
	m.mu.RUnlock()
	if !exists {
		return map[string]any{"mac": mac, "profile": nil}, nil
	}

	profile := map[string]any{
		"mac":          mac,
		"first_seen":   state.FirstSeen,
		"countries":    state.Countries,
		"ports":        state.Ports,
		"destinations": state.Destinations,
	}

	return map[string]any{"profile": profile}, nil
}

func (m *Module) apiAck(req *core.Req) (any, error) {
	var body struct {
		ID int `json:"id"`
	}
	if err := req.Decode(&body); err != nil {
		return nil, err
	}

	err := m.ctx.Store.Exec(`
		UPDATE baseline_anomalies SET acked = 1 WHERE id = ?
	`, body.ID)
	return map[string]any{"ok": err == nil}, err
}

func (m *Module) apiStatus(req *core.Req) (any, error) {
	m.mu.RLock()
	numDevices := len(m.devStates)
	m.mu.RUnlock()

	return map[string]any{
		"devices":  numDevices,
		"settings": m.settings,
	}, nil
}

type Flow struct {
	SrcIP    string
	DstIP    string
	DstPort  int
	Proto    string
	Country  string
	ASN      string
	BytesOut int64
}

// anomalyAttrs is the who / where / why of an anomaly, for the findings
// list to show in columns beside the sentence.
func anomalyAttrs(ip, mac, name string, where, why map[string]any) map[string]any {
	return map[string]any{"who": map[string]any{"ip": ip, "mac": mac, "name": name}, "where": where, "why": why}
}
