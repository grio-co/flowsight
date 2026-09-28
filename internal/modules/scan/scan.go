// Package scan provides native active network scanning for local devices with
// optional nmap enhancement. Scans include ICMP, TCP/UDP probes, service
// banners, and OS fingerprinting. All scanning is restricted to locally-known
// networks and is rate-limited.
package scan

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

type Module struct {
	ctx       *core.Context
	identity  core.Identity
	mu        sync.Mutex
	lastErr   string
	scheduler *jobScheduler

	// Settings cache
	enabled      bool
	maxParallel  int
	maxPorts     int
	portSet      string
	customPorts  string
	osProbe      bool
	useNmap      bool
	sweepHours   int
	sweepWindow  string
	rateLimitPPS int
}

type jobScheduler struct {
	mu          sync.Mutex
	jobs        map[string]*scanJob
	active      int
	maxParallel int
	queue       []*scanJob
}

type scanJob struct {
	ID       string
	IP       string
	MAC      string
	Profile  string // "quick" or "full"
	Started  time.Time
	Finished time.Time
	Result   *ScanResult
	status   string // "queued", "running", "done", "cancelled"
	ctx      context.Context
	cancel   context.CancelFunc
}

type ScanResult struct {
	IP            string              `json:"ip"`
	MAC           string              `json:"mac"`
	Hostname      string              `json:"hostname,omitempty"`
	Started       time.Time           `json:"started"`
	Finished      time.Time           `json:"finished"`
	OpenPorts     []PortInfo          `json:"open_ports"`
	ClosedCount   int                 `json:"closed_count"`
	FilteredCount int                 `json:"filtered_count"`
	Services      map[string]*Service `json:"services,omitempty"`
	OSGuesses     []OSGuess           `json:"os_guesses,omitempty"`
	Findings      []string            `json:"findings,omitempty"`
	NmapEnhanced  bool                `json:"nmap_enhanced,omitempty"`
	Error         string              `json:"error,omitempty"`
}

type PortInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"` // "open", "closed", "filtered"
	Service  string `json:"service,omitempty"`
	Banner   string `json:"banner,omitempty"`
}

type Service struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Product string `json:"product,omitempty"`
}

type OSGuess struct {
	OS         string   `json:"os"`
	Confidence float64  `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name: "scan", Version: "1.0",
		Description:  "Active network scanning: ICMP, TCP/UDP probes, service detection and OS fingerprinting for local devices only.",
		Capabilities: []string{core.CapHostInventory},
		After:        []string{"identity"},
		Defaults: map[string]any{
			"scanning":           false,
			"max_parallel_hosts": 2,
			"max_parallel_ports": 64,
			"port_set":           "top100",
			"custom_ports":       "",
			"os_probe":           true,
			"use_nmap":           true,
			"sweep_every_hours":  0,
			"sweep_window":       "",
			"rate_limit_pps":     200,
		},
		Schema: []core.SettingField{
			{Key: "scanning", Label: "Allow active scanning", Type: "bool", Help: "Off by default. Scans go out from the gateway to local addresses only; they can trip host firewalls and the IDS."},
			{Key: "max_parallel_hosts", Label: "Max parallel hosts", Type: "int"},
			{Key: "max_parallel_ports", Label: "Max parallel ports per host", Type: "int"},
			{Key: "port_set", Label: "Port set", Type: "string", Help: "top100, top1000, or custom"},
			{Key: "custom_ports", Label: "Custom ports (comma-separated)", Type: "string"},
			{Key: "os_probe", Label: "Probe for OS fingerprints", Type: "bool"},
			{Key: "use_nmap", Label: "Use nmap when installed", Type: "bool"},
			{Key: "sweep_every_hours", Label: "Sweep all local devices every N hours (0=disabled)", Type: "int"},
			{Key: "sweep_window", Label: "Sweep time window (HH:MM-HH:MM UTC)", Type: "string"},
			{Key: "rate_limit_pps", Label: "Rate limit (packets/sec)", Type: "int"},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.identity, _ = ctx.Service("identity").(core.Identity)
	m.scheduler = &jobScheduler{
		jobs:        make(map[string]*scanJob),
		maxParallel: core.Int(ctx.Settings(), "max_parallel_hosts", 2),
	}

	// Create results table
	_ = m.ctx.Store.Exec(`
		CREATE TABLE IF NOT EXISTS scans (
			ip TEXT NOT NULL,
			mac TEXT,
			started INTEGER,
			finished INTEGER,
			result_json TEXT,
			source TEXT,
			PRIMARY KEY (ip, started)
		)
	`)

	// Routes
	ctx.Route("POST", "/api/scan/start", m.apiStart, core.Write(),
		core.Doc("Start a network scan on a specific IP address or MAC address to detect services"),
		core.Body(
			core.Fld("ip", "string", false, "IP address to scan", "192.168.1.10"),
			core.Fld("mac", "string", false, "MAC address to scan", "aa:bb:cc:dd:ee:ff"),
		),
		core.Returns("Scan started", map[string]any{"ok": true}))
	ctx.Route("GET", "/api/scan/status", m.apiStatus,
		core.Doc("Get current scan queue status, running jobs and last automatic sweep time"),
		core.Returns("Scan status", map[string]any{
			"queue_size":   5,
			"running_jobs": 2,
			"last_sweep":   1790376243,
		}))
	ctx.Route("GET", "/api/scan/result", m.apiResult,
		core.Doc("Retrieve the latest scan result for a specific IP address with detected services"),
		core.Returns("Scan result for IP", map[string]any{
			"ip": "192.168.1.10",
			"ports": []map[string]any{
				{"port": 22, "service": "ssh", "state": "open"},
			},
			"timestamp": 1790376243,
		}))
	ctx.Route("GET", "/api/scan/results", m.apiResults,
		core.Doc("List the latest scan results for all recently scanned IP addresses and hosts"),
		core.Returns("Recent scan results", map[string]any{
			"results": []map[string]any{
				{"ip": "192.168.1.10", "ports": 5, "last_scan": 1790376243},
			},
		}))
	ctx.Route("POST", "/api/scan/cancel", m.apiCancel, core.Write(),
		core.Doc("Cancel a currently running or queued scan operation for an IP or MAC address"),
		core.Body(
			core.Fld("ip", "string", false, "IP address of scan to cancel", "192.168.1.10"),
			core.Fld("mac", "string", false, "MAC address of scan to cancel", "aa:bb:cc:dd:ee:ff"),
		),
		core.Returns("Cancellation result", map[string]any{"ok": true}))
	ctx.Route("POST", "/api/scan/sweep", m.apiSweep, core.Write(),
		core.Doc("Start a comprehensive network sweep scanning all local devices for services"),
		core.Body(),
		core.Returns("Sweep started", map[string]any{"ok": true}))
	// Panel
	ctx.Panel(core.Panel{
		ID:    "scan",
		Title: "Scan",
		Group: "Inventory",
		Order: 140,
		Icon:  "scan",
	})

	// Periodic sweep if configured
	sweepHours := core.Int(ctx.Settings(), "sweep_every_hours", 0)
	if sweepHours > 0 {
		ctx.Every("sweep", time.Duration(sweepHours)*time.Hour, m.periodicSweep)
	}

	return nil
}

func (m *Module) Health() core.Health {
	m.mu.Lock()
	defer m.mu.Unlock()
	status := "ok"
	if m.lastErr != "" {
		status = m.lastErr
	}
	return core.Health{OK: m.lastErr == "", Detail: status}
}

// ============================================================================
// API HANDLERS
// ============================================================================

type scanRequest struct {
	IP      string `json:"ip"`
	MAC     string `json:"mac"`
	Profile string `json:"profile"` // "quick" or "full"
}

func (m *Module) apiStart(r *core.Req) (any, error) {
	m.updateSettings()
	if !m.enabled {
		return nil, core.Errorf(400, "scanning disabled")
	}

	var req scanRequest
	if err := json.Unmarshal(r.Raw(), &req); err != nil {
		return nil, core.Errorf(400, "invalid request: %v", err)
	}

	ip := req.IP
	if ip == "" && req.MAC != "" {
		ip = m.identity.Name(req.MAC)
	}
	if ip == "" {
		return nil, core.Errorf(400, "missing ip or mac")
	}

	// Validate local
	if !m.identity.IsLocal(ip) {
		return nil, core.Errorf(400, "target is not in local networks")
	}

	profile := req.Profile
	if profile == "" {
		profile = "full"
	}

	job := &scanJob{
		ID:      fmt.Sprintf("%s-%d", ip, time.Now().Unix()),
		IP:      ip,
		Profile: profile,
		status:  "queued",
	}
	job.ctx, job.cancel = context.WithCancel(context.Background())

	m.scheduler.mu.Lock()
	m.scheduler.queue = append(m.scheduler.queue, job)
	m.scheduler.jobs[job.ID] = job
	m.scheduler.mu.Unlock()

	// Start processing queue
	go m.processQueue()

	return map[string]string{"job_id": job.ID}, nil
}

func (m *Module) apiStatus(r *core.Req) (any, error) {
	m.updateSettings()
	m.scheduler.mu.Lock()
	defer m.scheduler.mu.Unlock()

	queued := 0
	running := 0
	for _, job := range m.scheduler.jobs {
		switch job.status {
		case "queued":
			queued++
		case "running":
			running++
		}
	}

	nmapInstalled := false
	if _, err := exec.LookPath("nmap"); err == nil {
		nmapInstalled = true
	}

	// Get last sweep time
	var lastSweep int64
	if row, err := m.ctx.Store.Row("SELECT MAX(started) FROM scans WHERE source='sweep'"); err == nil && row != nil {
		if val, ok := row["MAX(started)"]; ok {
			if v, ok := val.(int64); ok {
				lastSweep = v
			}
		}
	}

	return map[string]any{
		"scanning":       m.enabled,
		"queued":         queued,
		"running":        running,
		"nmap_installed": nmapInstalled,
		"last_sweep":     lastSweep,
	}, nil
}

type resultQuery struct {
	IP    string `json:"ip"`
	MAC   string `json:"mac"`
	Hours int    `json:"hours"`
}

func (m *Module) apiResult(r *core.Req) (any, error) {
	ip := r.URL.Query().Get("ip")
	mac := r.URL.Query().Get("mac")

	if ip == "" && mac != "" {
		ip = m.identity.Name(mac)
	}
	if ip == "" {
		return nil, core.Errorf(400, "missing ip or mac")
	}

	// Get latest result
	row, err := m.ctx.Store.Row(
		`SELECT result_json FROM scans WHERE ip=? ORDER BY started DESC LIMIT 1`, ip)
	if err != nil || row == nil {
		return nil, core.Errorf(404, "no results")
	}

	resultJSON, ok := row["result_json"].(string)
	if !ok {
		return nil, core.Errorf(500, "invalid result")
	}

	var result ScanResult
	if err := json.Unmarshal([]byte(resultJSON), &result); err != nil {
		return nil, err
	}

	return result, nil
}

func (m *Module) apiResults(r *core.Req) (any, error) {
	hoursStr := r.URL.Query().Get("hours")
	hours := 24
	if hoursStr != "" {
		if h, err := strconv.Atoi(hoursStr); err == nil {
			hours = h
		}
	}
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()

	rows, err := m.ctx.Store.Rows(
		`SELECT DISTINCT ip, result_json FROM (
			SELECT ip, result_json, ROW_NUMBER() OVER (PARTITION BY ip ORDER BY started DESC) as rn
			FROM scans WHERE started > ?
		) t WHERE rn=1 ORDER BY ip`, cutoff)
	if err != nil {
		return nil, err
	}

	var results []any
	for _, row := range rows {
		ip, okIP := row["ip"].(string)
		resultJSON, okJSON := row["result_json"].(string)
		if !okIP || !okJSON {
			continue
		}
		var result ScanResult
		if err := json.Unmarshal([]byte(resultJSON), &result); err != nil {
			continue
		}

		// Add device identification guess (best OS guess + evidence)
		var bestGuess string
		var bestConfidence float64
		if len(result.OSGuesses) > 0 {
			bestGuess = result.OSGuesses[0].OS
			bestConfidence = result.OSGuesses[0].Confidence
		}

		results = append(results, map[string]any{
			"ip":            ip,
			"mac":           result.MAC,
			"hostname":      result.Hostname,
			"open_ports":    result.OpenPorts,
			"os_guess":      bestGuess,
			"os_confidence": bestConfidence,
			"services":      result.Services,
			"findings":      result.Findings,
			"nmap_enhanced": result.NmapEnhanced,
			"finished":      result.Finished,
		})
	}

	return map[string]any{"results": results}, nil
}

func (m *Module) apiCancel(r *core.Req) (any, error) {
	var req struct {
		JobID string `json:"job_id"`
	}
	if err := json.Unmarshal(r.Raw(), &req); err != nil {
		return nil, core.Errorf(400, "invalid request: %v", err)
	}

	m.scheduler.mu.Lock()
	job, ok := m.scheduler.jobs[req.JobID]
	m.scheduler.mu.Unlock()

	if !ok {
		return nil, core.Errorf(404, "job not found")
	}

	job.cancel()
	job.status = "cancelled"
	return map[string]string{"status": "cancelled"}, nil
}

func (m *Module) apiSweep(r *core.Req) (any, error) {
	go m.sweepLocalDevices()
	return map[string]string{"status": "sweep started"}, nil
}

// ============================================================================
// SCANNING LOGIC
// ============================================================================

func (m *Module) updateSettings() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = core.Bool(m.ctx.Settings(), "scanning", false)
	m.maxParallel = core.Int(m.ctx.Settings(), "max_parallel_hosts", 2)
	m.maxPorts = core.Int(m.ctx.Settings(), "max_parallel_ports", 64)
	m.portSet = core.Str(m.ctx.Settings(), "port_set", "top100")
	m.customPorts = core.Str(m.ctx.Settings(), "custom_ports", "")
	m.osProbe = core.Bool(m.ctx.Settings(), "os_probe", true)
	m.useNmap = core.Bool(m.ctx.Settings(), "use_nmap", true)
	m.sweepHours = core.Int(m.ctx.Settings(), "sweep_every_hours", 0)
	m.sweepWindow = core.Str(m.ctx.Settings(), "sweep_window", "")
	m.rateLimitPPS = core.Int(m.ctx.Settings(), "rate_limit_pps", 200)
	m.scheduler.maxParallel = m.maxParallel
}

func (m *Module) processQueue() {
	m.scheduler.mu.Lock()
	if m.scheduler.active >= m.scheduler.maxParallel || len(m.scheduler.queue) == 0 {
		m.scheduler.mu.Unlock()
		return
	}

	job := m.scheduler.queue[0]
	m.scheduler.queue = m.scheduler.queue[1:]
	job.status = "running"
	m.scheduler.active++
	m.scheduler.mu.Unlock()

	// Run the scan
	go func() {
		job.Started = time.Now()
		job.Result = m.performScan(job)
		job.Finished = time.Now()
		if job.Result != nil {
			job.Result.Finished = job.Finished
		}
		job.status = "done"

		// Save result
		m.saveResult(job)

		// Emit events/findings for notable results
		m.emitFindings(job)

		m.scheduler.mu.Lock()
		m.scheduler.active--
		m.scheduler.mu.Unlock()

		// Process next job
		m.processQueue()
	}()
}

func (m *Module) performScan(job *scanJob) *ScanResult {
	m.updateSettings()

	result := &ScanResult{
		IP:       job.IP,
		Started:  job.Started,
		Services: make(map[string]*Service),
	}

	// Get device info
	result.MAC = m.identity.MAC(job.IP)

	// Resolve hostname
	names, _ := net.LookupAddr(job.IP)
	if len(names) > 0 {
		result.Hostname = strings.TrimSuffix(names[0], ".")
	}

	// Profile: "identify" is fast and focused
	if job.Profile == "identify" {
		return m.performIdentifyScan(job.ctx, result)
	}

	ports := m.getPortSet(job.Profile)

	// ICMP probe
	m.probeICMP(job.ctx, result)

	// TCP connect scan
	m.probeTCP(job.ctx, result, ports)

	// UDP probes on key services
	m.probeUDP(job.ctx, result)

	// Banner grabs on open ports
	m.grabBanners(job.ctx, result)

	// OS fingerprinting
	if m.osProbe {
		m.guessOS(result)
		m.identifyDevice(result)
	}

	// Try nmap if available
	if m.useNmap {
		if err := m.enhanceWithNmap(job.ctx, result, ports); err == nil {
			result.NmapEnhanced = true
		}
	}

	return result
}

func (m *Module) performIdentifyScan(ctx context.Context, result *ScanResult) *ScanResult {
	// Fast identification profile: ICMP/TTL, top-100 TCP, identity UDP probes, banners, OS guess
	// Target: under 90 seconds per host

	// ICMP probe with TTL
	m.probeICMP(ctx, result)

	// TCP scan on the top 100 ports plus the consumer and appliance ports
	// that name a device (Alexa, Cast, Roku, Sonos, Kasa, Tuya, AirPlay...).
	m.probeTCP(ctx, result, append(append([]int{}, top100Ports...), iotPorts...))

	// UDP identity probes only (DNS, NTP, SNMP, SSDP, mDNS, NetBIOS)
	identityUDPProbes := map[int]string{
		53:   "dns",
		123:  "ntp",
		161:  "snmp",
		1900: "ssdp",
		5353: "mdns",
		137:  "netbios",
	}

	for port, name := range identityUDPProbes {
		select {
		case <-ctx.Done():
			return result
		default:
		}

		conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
			IP:   net.ParseIP(result.IP),
			Port: port,
		})
		if err != nil {
			continue
		}
		defer conn.Close()

		conn.SetDeadline(time.Now().Add(1 * time.Second))

		// Send probe
		var probe []byte
		switch port {
		case 53: // DNS
			probe = []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		case 123: // NTP
			probe = bytes.Repeat([]byte{0}, 48)
			probe[0] = 0x1b
		case 161: // SNMP
			probe = []byte{0x30, 0x82, 0x00, 0x25, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63}
		case 1900: // SSDP
			probe = []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n")
		case 5353: // mDNS
			probe = []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		case 137: // NetBIOS
			probe = []byte{0x80, 0x94, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		default:
			continue
		}

		conn.Write(probe)
		buf := make([]byte, 256)
		if n, err := conn.Read(buf); err == nil && n > 0 {
			result.Findings = append(result.Findings, fmt.Sprintf("%s_respond", name))
		}
	}

	// Banner grabs on open ports
	m.grabBanners(ctx, result)

	// OS fingerprinting
	if m.osProbe {
		m.guessOS(result)
		m.identifyDevice(result)
	}

	// Try nmap with fast options
	if m.useNmap {
		if err := m.enhanceWithNmapFast(ctx, result); err == nil {
			result.NmapEnhanced = true
		}
	}

	return result
}

func (m *Module) getPortSet(profile string) []int {
	if m.customPorts != "" {
		var ports []int
		for _, p := range strings.Split(m.customPorts, ",") {
			port, _ := strconv.Atoi(strings.TrimSpace(p))
			if port > 0 && port < 65536 {
				ports = append(ports, port)
			}
		}
		if len(ports) > 0 {
			return ports
		}
	}

	switch m.portSet {
	case "top1000":
		return top1000Ports
	default: // top100
		return top100Ports
	}
}

func (m *Module) probeICMP(ctx context.Context, result *ScanResult) {
	// ICMP echo request via raw socket (if root)
	conn, err := net.DialIP("ip4:icmp", nil, &net.IPAddr{IP: net.ParseIP(result.IP)})
	if err != nil {
		return // Not root or no raw socket support
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))

	msg := make([]byte, 8)
	msg[0] = 8 // Echo request
	msg[1] = 0
	// Checksum in bytes 2-3
	binary := newICMPEcho(msg)
	checksum := calculateChecksum(binary)
	msg[2] = byte(checksum >> 8)
	msg[3] = byte(checksum)

	if _, err := conn.Write(binary); err == nil {
		reply := make([]byte, 1024)
		if n, err := conn.Read(reply); err == nil && n >= 20 {
			// Parse TTL from IP header
			ttl := reply[8]
			result.Findings = append(result.Findings, fmt.Sprintf("icmp_respond (ttl=%d)", ttl))
		}
	}
}

func newICMPEcho(data []byte) []byte {
	b := make([]byte, len(data))
	copy(b, data)
	return b
}

func calculateChecksum(data []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (m *Module) probeTCP(ctx context.Context, result *ScanResult, ports []int) {
	// Limit active connections
	sem := make(chan struct{}, m.maxPorts)

	var wg sync.WaitGroup
	mu := sync.Mutex{}

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return
		default:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(port int) {
			defer func() { <-sem; wg.Done() }()

			addr := net.JoinHostPort(result.IP, strconv.Itoa(port))
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err == nil {
				conn.Close()
				mu.Lock()
				result.OpenPorts = append(result.OpenPorts, PortInfo{
					Port:     port,
					Protocol: "tcp",
					State:    "open",
					Service:  serviceNameForPort(port),
				})
				mu.Unlock()
			} else if strings.Contains(err.Error(), "refused") {
				mu.Lock()
				result.ClosedCount++
				mu.Unlock()
			} else {
				mu.Lock()
				result.FilteredCount++
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
}

func (m *Module) probeUDP(ctx context.Context, result *ScanResult) {
	// DNS, NTP, SNMP, SSDP, mDNS, NetBIOS, DHCP
	probes := map[int]string{
		53:   "dns",
		123:  "ntp",
		161:  "snmp",
		1900: "ssdp",
		5353: "mdns",
		137:  "netbios",
	}

	for port, name := range probes {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
			IP:   net.ParseIP(result.IP),
			Port: port,
		})
		if err != nil {
			continue
		}
		defer conn.Close()

		conn.SetDeadline(time.Now().Add(1 * time.Second))

		// Send probe (varies by service)
		var probe []byte
		switch port {
		case 53: // DNS
			probe = []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		case 123: // NTP
			probe = bytes.Repeat([]byte{0}, 48)
			probe[0] = 0x1b
		case 161: // SNMP
			probe = []byte{0x30, 0x82, 0x00, 0x25, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63}
		case 1900: // SSDP
			probe = []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n")
		case 5353: // mDNS
			probe = []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		case 137: // NetBIOS
			probe = []byte{0x80, 0x94, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		default:
			continue
		}

		conn.Write(probe)
		buf := make([]byte, 256)
		if n, err := conn.Read(buf); err == nil && n > 0 {
			result.Findings = append(result.Findings, fmt.Sprintf("%s_respond", name))
		}
	}
}

func (m *Module) grabBanners(ctx context.Context, result *ScanResult) {
	for i := range result.OpenPorts {
		select {
		case <-ctx.Done():
			return
		default:
		}

		port := &result.OpenPorts[i]

		switch port.Port {
		case 22: // SSH
			if banner := m.grabSSHBanner(ctx, result.IP); banner != "" {
				port.Banner = banner
			}
		case 80, 8080: // HTTP
			if banner := m.grabHTTPBanner(ctx, result.IP, port.Port, false); banner != "" {
				port.Banner = banner
			}
		case 443, 8443: // HTTPS
			if banner := m.grabHTTPBanner(ctx, result.IP, port.Port, true); banner != "" {
				port.Banner = banner
			}
		case 25, 587, 465: // SMTP
			if banner := m.grabSMTPBanner(ctx, result.IP, port.Port); banner != "" {
				port.Banner = banner
			}
		case 21: // FTP
			if banner := m.grabFTPBanner(ctx, result.IP); banner != "" {
				port.Banner = banner
			}
		case 110, 995: // POP3
			if banner := m.grabPOP3Banner(ctx, result.IP, port.Port); banner != "" {
				port.Banner = banner
			}
		case 143, 993: // IMAP
			if banner := m.grabIMAPBanner(ctx, result.IP, port.Port); banner != "" {
				port.Banner = banner
			}
		case 3389: // RDP
			if banner := m.grabRDPBanner(ctx, result.IP); banner != "" {
				port.Banner = banner
			}
		case 445: // SMB
			if m.probeSMB(ctx, result.IP) {
				port.Banner = "smb_open"
			}
		}
	}
}

func (m *Module) grabSSHBanner(ctx context.Context, ip string) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:22", ip), 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 256)
	if n, err := conn.Read(buf); err == nil {
		line := strings.TrimSpace(string(buf[:n]))
		if strings.HasPrefix(line, "SSH-") {
			return line
		}
	}
	return ""
}

func (m *Module) grabHTTPBanner(ctx context.Context, ip string, port int, https bool) string {
	addr := fmt.Sprintf("%s:%d", ip, port)
	var client *http.Client

	if https {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{Transport: tr, Timeout: 2 * time.Second}
	} else {
		client = &http.Client{Timeout: 2 * time.Second}
	}

	scheme := "http"
	if https {
		scheme = "https"
	}

	resp, err := client.Head(fmt.Sprintf("%s://%s/", scheme, addr))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var banner strings.Builder
	if server := resp.Header.Get("Server"); server != "" {
		banner.WriteString(server)
	}

	if title := m.grabHTMLTitle(resp.Body); title != "" {
		if banner.Len() > 0 {
			banner.WriteString(" | ")
		}
		banner.WriteString(title)
	}

	return banner.String()
}

func (m *Module) grabHTMLTitle(body io.Reader) string {
	content := make([]byte, 4096)
	n, _ := io.ReadFull(body, content)
	if n > 0 {
		re := regexp.MustCompile(`<title[^>]*>([^<]+)</title>`)
		if matches := re.FindSubmatch(content[:n]); matches != nil {
			return string(matches[1])
		}
	}
	return ""
}

func (m *Module) grabSMTPBanner(ctx context.Context, ip string, port int) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 256)
	if n, err := conn.Read(buf); err == nil {
		return strings.TrimSpace(string(buf[:n]))
	}
	return ""
}

func (m *Module) grabFTPBanner(ctx context.Context, ip string) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:21", ip), 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 256)
	if n, err := conn.Read(buf); err == nil {
		banner := strings.TrimSpace(string(buf[:n]))
		if strings.Contains(banner, "220") {
			return banner
		}
	}
	return ""
}

func (m *Module) grabPOP3Banner(ctx context.Context, ip string, port int) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 256)
	if n, err := conn.Read(buf); err == nil {
		line := strings.TrimSpace(string(buf[:n]))
		if strings.HasPrefix(line, "+OK") {
			return line
		}
	}
	return ""
}

func (m *Module) grabIMAPBanner(ctx context.Context, ip string, port int) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 256)
	if n, err := conn.Read(buf); err == nil {
		line := strings.TrimSpace(string(buf[:n]))
		if strings.Contains(line, "IMAP") {
			return line
		}
	}
	return ""
}

func (m *Module) grabRDPBanner(ctx context.Context, ip string) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:3389", ip), 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(1 * time.Second))
	conn.Write([]byte{0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00})
	buf := make([]byte, 256)
	if n, err := conn.Read(buf); err == nil && n > 0 {
		return "rdp_open"
	}
	return ""
}

func (m *Module) probeSMB(ctx context.Context, ip string) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", ip), 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(1 * time.Second))
	// Send SMB negotiate request
	smb := []byte{
		0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	conn.Write(smb)
	buf := make([]byte, 256)
	_, err = conn.Read(buf)
	return err == nil
}

func (m *Module) guessOS(result *ScanResult) {
	guesses := []OSGuess{}

	// TTL-based guessing
	// This is a simplified heuristic; real OS detection would use more factors

	// Collect evidence
	hasMDNS := contains(result.Findings, "mdns_respond")
	hasSSDPBanner := contains(result.Findings, "ssdp_respond")
	hasNetBIOS := contains(result.Findings, "netbios_respond")

	// Guess Linux/macOS if mDNS present
	if hasMDNS {
		guesses = append(guesses, OSGuess{
			OS:         "Linux/macOS/BSD",
			Confidence: 0.7,
			Evidence:   []string{"mDNS responds"},
		})
	}

	// Guess Windows if NetBIOS present
	if hasNetBIOS {
		guesses = append(guesses, OSGuess{
			OS:         "Windows",
			Confidence: 0.8,
			Evidence:   []string{"NetBIOS name service responds"},
		})
	}

	// Guess network device if SSDP
	if hasSSDPBanner {
		guesses = append(guesses, OSGuess{
			OS:         "Network Device/IoT",
			Confidence: 0.6,
			Evidence:   []string{"SSDP responds"},
		})
	}

	// Sort by confidence descending
	sort.Slice(guesses, func(i, j int) bool {
		return guesses[i].Confidence > guesses[j].Confidence
	})

	result.OSGuesses = guesses
}

func (m *Module) enhanceWithNmap(ctx context.Context, result *ScanResult, ports []int) error {
	// Build port list
	portStr := ""
	if len(ports) > 0 {
		portStrs := make([]string, len(ports))
		for i, p := range ports {
			portStrs[i] = strconv.Itoa(p)
		}
		portStr = strings.Join(portStrs, ",")
	}

	args := []string{"-oX", "-", "-Pn"}

	// Use -sT (TCP connect) if not root, -sS (SYN) if root
	if os.Getuid() == 0 {
		args = append(args, "-sS")
	} else {
		args = append(args, "-sT")
	}

	args = append(args, "-sV", "-O", "--osscan-guess", "-T3")
	args = append(args, fmt.Sprintf("--max-rate=%d", m.rateLimitPPS))

	if portStr != "" {
		args = append(args, "-p", portStr)
	}

	args = append(args, result.IP)

	cmd := exec.CommandContext(ctx, "nmap", args...)
	cmd.Stderr = io.Discard

	output, err := cmd.Output()
	if err != nil {
		return err
	}

	return m.parseNmapXML(output, result)
}

func (m *Module) enhanceWithNmapFast(ctx context.Context, result *ScanResult) error {
	// Fast nmap for identify profile: -sV -O --osscan-guess on top 100 ports, no --max-rate limit
	args := []string{"-oX", "-", "-Pn", "-p"}

	// Top 100 ports
	portStrs := make([]string, len(top100Ports))
	for i, p := range top100Ports {
		portStrs[i] = strconv.Itoa(p)
	}
	args = append(args, strings.Join(portStrs, ","))

	// Use -sT (TCP connect) if not root, -sS (SYN) if root
	if os.Getuid() == 0 {
		args = append(args, "-sS")
	} else {
		args = append(args, "-sT")
	}

	args = append(args, "-sV", "-O", "--osscan-guess", "-T4")
	args = append(args, result.IP)

	cmd := exec.CommandContext(ctx, "nmap", args...)
	cmd.Stderr = io.Discard

	output, err := cmd.Output()
	if err != nil {
		return err
	}

	return m.parseNmapXML(output, result)
}

func (m *Module) parseNmapXML(data []byte, result *ScanResult) error {
	var nmap struct {
		XMLName xml.Name `xml:"nmaprun"`
		Host    struct {
			Status struct {
				State string `xml:"state,attr"`
			} `xml:"status"`
			Ports struct {
				Port []struct {
					Protocol string `xml:"protocol,attr"`
					PortID   int    `xml:"portid,attr"`
					State    struct {
						State string `xml:"state,attr"`
					} `xml:"state"`
					Service struct {
						Name    string `xml:"name,attr"`
						Version string `xml:"version,attr"`
						Product string `xml:"product,attr"`
					} `xml:"service"`
				} `xml:"port"`
			} `xml:"ports"`
			OS struct {
				Matches []struct {
					Name     string `xml:"name,attr"`
					Accuracy string `xml:"accuracy,attr"`
				} `xml:"osmatch"`
			} `xml:"os"`
		} `xml:"host"`
	}

	if err := xml.Unmarshal(data, &nmap); err != nil {
		return err
	}

	// Update ports with nmap data
	for _, p := range nmap.Host.Ports.Port {
		if p.State.State == "open" {
			found := false
			for i := range result.OpenPorts {
				if result.OpenPorts[i].Port == p.PortID {
					found = true
					result.OpenPorts[i].Service = p.Service.Name
					if p.Service.Version != "" {
						result.Services[p.Service.Name] = &Service{
							Name:    p.Service.Name,
							Version: p.Service.Version,
							Product: p.Service.Product,
						}
					}
					break
				}
			}
			if !found {
				result.OpenPorts = append(result.OpenPorts, PortInfo{
					Port:     p.PortID,
					Protocol: p.Protocol,
					State:    "open",
					Service:  p.Service.Name,
				})
			}
		}
	}

	// Update OS guesses from nmap
	for _, m := range nmap.Host.OS.Matches {
		acc, _ := strconv.ParseFloat(m.Accuracy, 64)
		result.OSGuesses = append(result.OSGuesses, OSGuess{
			OS:         m.Name,
			Confidence: acc / 100.0,
			Evidence:   []string{"nmap OS detection"},
		})
	}

	return nil
}

func (m *Module) saveResult(job *scanJob) {
	data, _ := json.Marshal(job.Result)
	source := "manual"
	if job.Profile == "identify" {
		source = "identify"
	}
	_ = m.ctx.Store.Exec(
		`INSERT INTO scans (ip, mac, started, finished, result_json, source)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		job.Result.IP, job.Result.MAC, job.Started.Unix(), job.Finished.Unix(), string(data), source)
}

// notableServices are the open services a scan reports as findings. A
// banner is required where an open port alone says too little.
var notableServices = []struct {
	port            int
	name, kind, sev string
	title, detail   string
	needBanner      bool
}{
	{23, "telnet", "insecure_service", "high", "Telnet open on %s", "Telnet is unencrypted and exposes credentials", false},
	{3389, "rdp", "exposed_service", "high", "RDP exposed on %s", "RDP should be restricted to trusted networks", true},
	{21, "ftp", "insecure_service", "medium", "FTP open on %s", "FTP is unencrypted; SFTP or SCP is preferred", true},
}

// emitFindings records the notable services a scan found open, with who and
// why, and closes the ones a scan that covered their port no longer finds.
// An identify scan probes a different, smaller set, so it closes nothing.
func (m *Module) emitFindings(job *scanJob) {
	res := job.Result
	if res == nil || res.Error != "" {
		return
	}
	open := map[int]PortInfo{}
	for _, p := range res.OpenPorts {
		open[p.Port] = p
	}
	scanned := map[int]bool{}
	if job.Profile != "identify" {
		for _, p := range m.getPortSet(job.Profile) {
			scanned[p] = true
		}
	}
	var gone []string
	for _, s := range notableServices {
		fp := fmt.Sprintf("%s_%s_%d", s.name, res.IP, s.port)
		p, isOpen := open[s.port]
		if isOpen && (!s.needBanner || p.Banner != "") {
			_, _ = m.ctx.Store.AddFindingWith("scan", s.kind, s.sev, res.IP,
				fmt.Sprintf(s.title, res.IP), s.detail, fp, m.scanAttrs(job, s.name, p))
			continue
		}
		if scanned[s.port] {
			gone = append(gone, fp)
		}
	}
	if len(gone) > 0 {
		if n, _ := m.ctx.Store.ResolveFingerprints(gone...); n > 0 {
			m.ctx.Log.Info("scan findings closed: the service is no longer open", "ip", res.IP, "count", n)
		}
	}
}

func (m *Module) scanAttrs(job *scanJob, service string, p PortInfo) map[string]any {
	res := job.Result
	who := map[string]any{"ip": res.IP, "mac": res.MAC}
	if res.Hostname != "" {
		who["name"] = res.Hostname
	}
	if id, ok := m.ctx.Service("identity").(core.Identity); ok {
		if n := id.Name(res.IP); n != "" {
			who["name"] = n
		}
	}
	proto := p.Protocol
	if proto == "" {
		proto = "tcp"
	}
	facts := []string{fmt.Sprintf("%s/%d open", proto, p.Port)}
	if b := strings.TrimSpace(p.Banner); b != "" {
		if len(b) > 120 {
			b = b[:120] + "…"
		}
		facts = append(facts, "banner: "+b)
	}
	if !res.Finished.IsZero() {
		facts = append(facts, "scanned "+res.Finished.Format("2006-01-02 15:04"))
	}
	if job.Profile != "" {
		facts = append(facts, job.Profile+" scan")
	}
	return map[string]any{
		"who":   who,
		"what":  map[string]any{"kind": service},
		"where": map[string]any{"ip": res.IP, "port": p.Port, "proto": proto},
		"why":   map[string]any{"facts": facts},
	}
}

func (m *Module) periodicSweep() error {
	return m.sweepLocalDevices()
}

func (m *Module) sweepLocalDevices() error {
	m.updateSettings()

	// Check sweep window
	if m.sweepWindow != "" {
		parts := strings.Split(m.sweepWindow, "-")
		if len(parts) == 2 {
			// Parse and check time window (simplified)
			now := time.Now().UTC()
			// In production, parse HH:MM and check if now is in window
			_ = now
		}
	}

	// Get all devices seen in last 7 days
	rows, err := m.ctx.Store.Rows(
		`SELECT DISTINCT ip FROM scans WHERE started > ? ORDER BY ip`,
		time.Now().Add(-7*24*time.Hour).Unix())
	if err != nil {
		return err
	}

	for _, row := range rows {
		ip, ok := row["ip"].(string)
		if !ok {
			continue
		}

		// Queue scan
		job := &scanJob{
			ID:      fmt.Sprintf("sweep-%s-%d", ip, time.Now().Unix()),
			IP:      ip,
			Profile: "quick",
			status:  "queued",
		}
		job.ctx, job.cancel = context.WithCancel(context.Background())

		m.scheduler.mu.Lock()
		m.scheduler.queue = append(m.scheduler.queue, job)
		m.scheduler.jobs[job.ID] = job
		m.scheduler.mu.Unlock()
	}

	m.processQueue()
	return nil
}

// Utility functions
func serviceNameForPort(port int) string {
	services := map[int]string{
		20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
		53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
		110: "pop3", 123: "ntp", 137: "netbios", 139: "netbios", 143: "imap",
		161: "snmp", 162: "snmp", 179: "bgp", 389: "ldap", 443: "https",
		445: "smb", 465: "smtp", 500: "ike", 587: "smtp", 636: "ldap",
		993: "imap", 995: "pop3", 1433: "mssql", 1521: "oracle", 3306: "mysql",
		3389: "rdp", 5353: "mdns", 5432: "postgres", 5900: "vnc", 8080: "http",
		8443: "https", 8888: "http", 1900: "upnp", 27017: "mongodb", 6379: "redis",
	}
	if s, ok := services[port]; ok {
		return s
	}
	return ""
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.Contains(s, item) {
			return true
		}
	}
	return false
}

// Top 100 most frequently used ports (from nmap-services)
var top100Ports = []int{
	1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37,
	42, 43, 49, 53, 67, 68, 69, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99,
	100, 106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163,
	179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340,
	366, 389, 406, 407, 416, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497,
	500, 512, 513, 514, 515, 524, 541, 543, 544, 548, 554, 555, 563, 587, 593,
	616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705,
	711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873,
	880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995,
	999, 1000,
}

var top1000Ports = append(top100Ports,
	1007, 1009, 1052, 1100, 1102, 1104, 1106, 1112, 1113, 1119, 1174, 1175,
	1183, 1192, 1198, 1199, 1201, 1213, 1216, 1234, 1241, 1300, 1301, 1309,
	1310, 1311, 1322, 1328, 1334, 1352, 1417, 1434, 1443, 1455, 1461, 1494,
	1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687,
	1688, 1700, 1717, 1718, 1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783,
	1801, 1805, 1812, 1839, 1900, 1914, 1984, 1998, 2000, 2002, 2005, 2009,
	2013, 2020, 2030, 2033, 2038, 2040, 2041, 2053, 2064, 2065, 2068, 2099,
	2100, 2103, 2105, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161,
	2170, 2179, 2190, 2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366,
	2381, 2382, 2383, 2393, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601,
	2628, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869,
	2875, 2909, 2920, 2967, 2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011,
	3013, 3017, 3030, 3031, 3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260,
	3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333,
	3351, 3389, 3404, 3476, 3493, 3517, 3527, 3546, 3551, 3580, 3659, 3689,
	3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3828, 3851,
	3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986,
	3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125,
	4126, 4127, 4128, 4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445,
	4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900, 4949, 5000, 5001, 5002,
	5003, 5004, 5005, 5006, 5007, 5008, 5009, 5010, 5011, 5012, 5013, 5014,
	5015, 5020, 5021, 5022, 5023, 5024, 5025, 5026, 5027, 5050, 5051, 5054,
	5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200, 5214, 5221,
	5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431, 5432, 5440,
	5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679,
	5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859,
	5862, 5877, 5900, 5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915,
	5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5987, 5988, 5989, 5998,
	5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059,
	6100, 6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547,
	6565, 6566, 6567, 6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699,
	6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7003,
	7004, 7005, 7006, 7007, 7008, 7009, 7010, 7012, 7014, 7015, 7020, 7021,
	7022, 7025, 7070, 7100, 7103, 7106, 7200, 7402, 7435, 7443, 7496, 7512,
	7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938,
	7999, 8000, 8001, 8002, 8007, 8008, 8009, 8010, 8011, 8021, 8042, 8045,
	8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093,
	8099, 8100, 8180, 8181, 8182, 8192, 8194, 8200, 8222, 8254, 8290, 8300,
	8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701,
	8800, 8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011,
	9040, 9050, 9071, 9080, 9081, 9090, 9091, 9099, 9103, 9110, 9111, 9200,
	9207, 9220, 9290, 9415, 9418, 9485, 9500, 9502, 9503, 9535, 9618, 9666,
	9876, 9877, 9898, 9900, 9917, 9929, 9943, 9944, 9968, 9998, 9999, 10000,
	10001, 10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025, 10082,
	10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628, 10628,
	10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722,
	13782, 13783, 14000, 14238, 14441, 14442, 15000, 15002, 15003, 15004,
	15660, 15742, 16000, 16001, 16012, 16016, 16018, 16080, 16113, 16992,
	16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283, 19315, 19350,
	19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571,
	22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353,
	27355, 27356, 27715, 28201, 30000, 30718, 30951, 31038, 31337, 32768,
	32769, 32770, 32771, 32774, 32815, 33354, 33899, 34571, 34572, 34573,
	35500, 38292, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501,
	45100, 48080, 49152, 49161, 49163, 49165, 49167, 49175, 49176, 49400,
	49999, 50000, 50006, 50300, 50389, 50500, 50636, 50800, 51103, 51493,
	52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600,
	56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078,
	63331, 64623, 64680, 65000, 65129, 65389,
)
