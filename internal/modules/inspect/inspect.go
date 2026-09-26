// Package inspect provides packet inspection: stateful inspection (SPI) from
// the firewall's state table and deep packet inspection (DPI) via tcpdump capture.
package inspect

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
	mu        sync.RWMutex
	captureID string
	capture   *CaptureSession
	captures  map[string]*CaptureInfo
	states    []*PFState

	// Settings
	maxStates        int
	stateAgeSeconds  int
	snaplen          int
	maxCaptureSecs   int
	maxCaptureFiles  int
	maxCaptureBytes  int64
	payloadAllowed   bool
	statePollSeconds int
	synFloodThresh   int
	portScanThresh   int

	// TLS observations for ECH detection (5-tuple/3-tuple -> ECH flag, expires after 1 min)
	tlsObservations map[string]tlsObservation // key: src:dst:dstport or src:dst:dstport:proto

	// Data directory
	dataDir string
}

type tlsObservation struct {
	ECH       bool
	Timestamp time.Time
}

type PFState struct {
	Proto     string    `json:"proto"`
	Direction string    `json:"direction"`
	Src       string    `json:"src"`
	Dst       string    `json:"dst"`
	SrcPort   int       `json:"src_port"`
	DstPort   int       `json:"dst_port"`
	State     string    `json:"state"`
	Age       int       `json:"age"`
	Expires   int       `json:"expires"`
	PktsSrc   int64     `json:"pkts_src"`
	BytesSrc  int64     `json:"bytes_src"`
	PktsDst   int64     `json:"pkts_dst"`
	BytesDst  int64     `json:"bytes_dst"`
	RuleID    int       `json:"rule_id"`
	Interface string    `json:"interface"`
	Timestamp time.Time `json:"timestamp"`
	Hostname  string    `json:"hostname,omitempty"`
}

type CaptureSession struct {
	ID       string
	Iface    string
	Filter   string
	Started  time.Time
	cmd      *exec.Cmd
	ctx      context.Context
	cancel   context.CancelFunc
	Duration int
	Snaplen  int
	Payload  bool
}

type CaptureInfo struct {
	ID        string           `json:"id"`
	Iface     string           `json:"iface"`
	Filter    string           `json:"filter"`
	Started   time.Time        `json:"started"`
	Ended     *time.Time       `json:"ended,omitempty"`
	Packets   int64            `json:"packets"`
	Bytes     int64            `json:"bytes"`
	Files     []string         `json:"files"`
	Analysis  *CaptureAnalysis `json:"analysis,omitempty"`
	Timestamp time.Time        `json:"timestamp"`
}

type CaptureAnalysis struct {
	PacketCount    int64            `json:"packet_count"`
	ByteCount      int64            `json:"byte_count"`
	Conversations  []Conversation   `json:"conversations,omitempty"`
	ProtocolCounts map[string]int64 `json:"protocol_counts,omitempty"`
	DNSQueries     []DNSRecord      `json:"dns_queries,omitempty"`
	TLSHandshakes  []TLSInfo        `json:"tls_handshakes,omitempty"`
	HTTPRequests   []HTTPRequest    `json:"http_requests,omitempty"`
	ExpertNotes    []ExpertNote     `json:"expert_notes,omitempty"`
	TopTalkers     []TopTalker      `json:"top_talkers,omitempty"`
	Timeline       []TimelineEvent  `json:"timeline,omitempty"`
}

type Conversation struct {
	FiveTuple       string    `json:"five_tuple"`
	Proto           string    `json:"proto"`
	Src             string    `json:"src"`
	SrcPort         int       `json:"src_port"`
	Dst             string    `json:"dst"`
	DstPort         int       `json:"dst_port"`
	PktsFwd         int64     `json:"pkts_fwd"`
	BytesFwd        int64     `json:"bytes_fwd"`
	PktsRev         int64     `json:"pkts_rev"`
	BytesRev        int64     `json:"bytes_rev"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	TCPFlags        string    `json:"tcp_flags,omitempty"`
	Retransmissions int       `json:"retransmissions,omitempty"`
	OutOfOrder      int       `json:"out_of_order,omitempty"`
	ZeroWindow      int       `json:"zero_window,omitempty"`
	Resets          int       `json:"resets,omitempty"`
	RTTEstimate     float64   `json:"rtt_estimate,omitempty"`
}

type DNSRecord struct {
	Query     string    `json:"query"`
	Type      string    `json:"type"`
	Answers   []string  `json:"answers,omitempty"`
	Src       string    `json:"src"`
	Dst       string    `json:"dst"`
	Timestamp time.Time `json:"timestamp"`
}

type TLSInfo struct {
	SNI       string    `json:"sni,omitempty"`
	JA3       string    `json:"ja3,omitempty"`
	Src       string    `json:"src"`
	Dst       string    `json:"dst"`
	CertCN    string    `json:"cert_cn,omitempty"`
	CertSAN   []string  `json:"cert_san,omitempty"`
	ECH       bool      `json:"ech,omitempty"` // encrypted_client_hello extension detected
	Timestamp time.Time `json:"timestamp"`
}

type HTTPRequest struct {
	Method    string    `json:"method"`
	Host      string    `json:"host"`
	Path      string    `json:"path"`
	UserAgent string    `json:"user_agent,omitempty"`
	Src       string    `json:"src"`
	Dst       string    `json:"dst"`
	Timestamp time.Time `json:"timestamp"`
}

type ExpertNote struct {
	Type      string    `json:"type"` // "retransmission", "dup_ack", "zero_window", "reset", "port_reuse", "arp_conflict", "dns_no_query"
	Src       string    `json:"src"`
	Dst       string    `json:"dst"`
	Detail    string    `json:"detail"`
	Severity  string    `json:"severity"` // "info", "warn"
	Timestamp time.Time `json:"timestamp"`
}

type TopTalker struct {
	IP    string `json:"ip"`
	Bytes int64  `json:"bytes"`
	Pkts  int64  `json:"pkts"`
}

type TimelineEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"` // "syn", "ack", "dns", "tls", "http"
	Src       string    `json:"src"`
	Dst       string    `json:"dst"`
}

type StatesSummary struct {
	TotalStates     int            `json:"total_states"`
	ByProto         map[string]int `json:"by_proto"`
	ByState         map[string]int `json:"by_state"`
	HalfOpenCount   int            `json:"half_open_count"`
	TableUtilPct    float64        `json:"table_util_pct"`
	NewStatesPerSec float64        `json:"new_states_per_sec"`
	States          []*PFState     `json:"states,omitempty"`
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name:         "inspect",
		Version:      "1.0",
		Description:  "Packet inspection: stateful inspection from firewall state table and deep packet inspection via tcpdump capture.",
		Capabilities: []string{core.CapTrafficObserve},
		Requires:     []string{"FreeBSD", "pf"},
		Defaults: map[string]any{
			"max_states":          20000,
			"state_age_seconds":   300,
			"snaplen":             96,
			"max_capture_secs":    600,
			"max_capture_files":   5,
			"max_capture_bytes":   104857600,
			"payload_allowed":     false,
			"state_poll_seconds":  30,
			"syn_flood_threshold": 100,
			"port_scan_threshold": 50,
		},
		Schema: []core.SettingField{
			{Key: "max_states", Label: "Max firewall states in memory", Type: "int", Help: "Keep the newest N states; older ones are discarded to cap memory usage."},
			{Key: "state_age_seconds", Label: "State age threshold (seconds)", Type: "int", Help: "States older than this are flagged for cleanup detection."},
			{Key: "snaplen", Label: "Default snaplen (bytes)", Type: "int", Help: "96 for headers only, 65535 for full payload. Payload captures contain sensitive data."},
			{Key: "max_capture_secs", Label: "Max capture duration (seconds)", Type: "int", Help: "Hard limit on how long a single capture can run."},
			{Key: "max_capture_files", Label: "Max rotated capture files", Type: "int", Help: "tcpdump -W limit: number of files in the ring."},
			{Key: "max_capture_bytes", Label: "Max total capture bytes (MB)", Type: "int", Help: "Hard cap on cumulative capture storage; oldest captures deleted when exceeded."},
			{Key: "payload_allowed", Label: "Allow payload capture", Type: "bool", Help: "When off, captures are headers-only (96 bytes); when on, users can select full payload (65535 bytes). Payload captures are sensitive."},
			{Key: "state_poll_seconds", Label: "State poll interval (seconds)", Type: "int", Help: "How often to read the firewall's connection table."},
			{Key: "syn_flood_threshold", Label: "SYN flood alert threshold", Type: "int", Help: "Alert if SYN_SENT states from one source exceed this in the poll window."},
			{Key: "port_scan_threshold", Label: "Port scan alert threshold", Type: "int", Help: "Alert if one source has this many non-established destinations in one poll."},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx

	// Load settings
	settings := ctx.Settings()
	m.maxStates = asInt(settings["max_states"], 20000)
	m.stateAgeSeconds = asInt(settings["state_age_seconds"], 300)
	m.snaplen = asInt(settings["snaplen"], 96)
	m.maxCaptureSecs = asInt(settings["max_capture_secs"], 600)
	m.maxCaptureFiles = asInt(settings["max_capture_files"], 5)
	m.maxCaptureBytes = int64(asInt(settings["max_capture_bytes"], 100)) * 1024 * 1024
	m.payloadAllowed = asBool(settings["payload_allowed"], false)
	m.statePollSeconds = asInt(settings["state_poll_seconds"], 30)
	m.synFloodThresh = asInt(settings["syn_flood_threshold"], 100)
	m.portScanThresh = asInt(settings["port_scan_threshold"], 50)

	// Initialize data directory
	m.dataDir = filepath.Join(ctx.Platform.DataDir, "captures")
	if err := os.MkdirAll(m.dataDir, 0700); err != nil {
		return fmt.Errorf("failed to create captures directory: %w", err)
	}

	m.captures = make(map[string]*CaptureInfo)
	m.tlsObservations = make(map[string]tlsObservation)
	m.states = []*PFState{}

	// Load existing captures from disk
	if err := m.loadCaptures(); err != nil {
		ctx.Log.Warn("failed to load captures", "error", err)
	}

	// Register API routes
	ctx.Route("GET", "/api/inspect/states", m.apiStates,
		core.Doc("Get firewall connection states with optional filtering by host, protocol, or state"),
		core.Query("host", "string", "Filter by source or destination IP address", false, "192.168.1.10"),
		core.Query("proto", "string", "Filter by protocol (tcp, udp, icmp, etc.)", false, "tcp"),
		core.Query("state", "string", "Filter by state (ESTABLISHED, SYN_SENT, etc.)", false, "ESTABLISHED"),
		core.Query("limit", "integer", "Maximum results to return (default 100)", false, 100),
		core.Returns("Firewall states list", map[string]any{
			"states": []map[string]any{
				{"proto": "tcp", "direction": "in", "src": "203.0.113.1", "dst": "192.168.1.10", "src_port": 443, "dst_port": 54321, "state": "ESTABLISHED", "age": 120, "expires": 7680, "pkts_src": 150, "bytes_src": 65432, "pkts_dst": 180, "bytes_dst": 98765, "rule_id": 0, "interface": "em0", "timestamp": 1790376243, "hostname": "external.example.com"},
			},
			"count": 1,
		}))
	ctx.Route("GET", "/api/inspect/states/summary", m.apiStatesSummary,
		core.Doc("Get aggregated statistics on firewall states by protocol and state"),
		core.Returns("States summary statistics", map[string]any{
			"total_states": 45, "by_proto": map[string]int{"tcp": 40, "udp": 5}, "by_state": map[string]int{"ESTABLISHED": 42, "SYN_SENT": 3}, "half_open_count": 3, "table_util_pct": 12.5, "new_states_per_sec": 0.5,
		}))
	ctx.Route("GET", "/api/inspect/rules", m.apiRules,
		core.Doc("Get rule evaluation counters and matches from the firewall"),
		core.Returns("The active ruleset with its counters, in the firewall's own syntax", map[string]any{
			"backend": "pf", "syntax": "pf",
			"rules": []map[string]any{
				{"text": `pass in quick on em0 inet proto tcp from any to any port = 22 flags S/SA keep state label "allow-ssh"`,
					"label": "allow-ssh", "evaluations": 5000, "packets": 150, "bytes": 1024000, "states": 2},
			},
			"rule_count": 1,
			"raw":        `pass in quick on em0 inet proto tcp from any to any port = 22 flags S/SA keep state label "allow-ssh"`,
		}))
	ctx.Route("POST", "/api/inspect/capture/start", m.apiCaptureStart, core.Write(),
		core.Doc("Start a new packet capture on a network interface with optional BPF filter"),
		core.Body(
			core.Fld("iface", "string", true, "Network interface name (em0, em1, etc.)", "em0"),
			core.Fld("filter", "string", false, "BPF filter expression (tcpdump syntax)", "tcp port 443"),
			core.Fld("seconds", "integer", false, "Capture duration in seconds", 60),
			core.Fld("snaplen", "integer", false, "Bytes to capture per packet (96=headers, 65535=full)", 96),
			core.Fld("payload", "boolean", false, "Include full packet payload (security sensitive)", false),
		),
		core.Returns("Capture started successfully", map[string]any{
			"id": "cap_1790376243", "status": "started", "iface": "em0", "filter": "tcp port 443", "seconds": 60,
		}))
	ctx.Route("POST", "/api/inspect/capture/stop", m.apiCaptureStop, core.Write(),
		core.Doc("Stop the currently running packet capture session"),
		core.Returns("Capture stop initiated", map[string]any{"status": "stopping"}))
	ctx.Route("GET", "/api/inspect/captures", m.apiCaptures,
		core.Doc("List all saved packet capture sessions with metadata"),
		core.Returns("List of capture sessions", map[string]any{
			"captures": []map[string]any{{"id": "cap_123", "iface": "em0", "packets": 5000}},
		}))
	ctx.Route("GET", "/api/inspect/capture/{id}", m.apiCaptureDetail,
		core.Doc("Get detailed analysis of a specific packet capture"),
		core.PathParam("id", "string", "Capture session ID", "cap_1790376243"),
		core.Returns("Capture analysis with insights", map[string]any{
			"id": "cap_1790376243", "iface": "em0", "filter": "tcp port 443", "started": 1790376243, "packets": 5000, "bytes": 1000000, "analysis": map[string]any{"packet_count": 5000, "byte_count": 1000000},
		}))
	ctx.Route("GET", "/api/inspect/capture/{id}/conversations", m.apiCaptureConversations,
		core.Doc("Get bidirectional conversations extracted from the captured traffic"),
		core.PathParam("id", "string", "Capture session ID", "cap_1790376243"),
		core.Returns("List of network conversations", map[string]any{
			"conversations": []map[string]any{
				{"five_tuple": "192.168.1.10:54321>203.0.113.1:443", "proto": "tcp", "src": "192.168.1.10", "src_port": 54321, "dst": "203.0.113.1", "dst_port": 443, "pkts_fwd": 150, "bytes_fwd": 65432, "pkts_rev": 180, "bytes_rev": 98765, "first_seen": 1790376243, "last_seen": 1790376303},
			},
		}))
	ctx.Route("GET", "/api/inspect/capture/{id}/dns", m.apiCaptureDNS,
		core.Doc("Get DNS queries and responses from the captured traffic"),
		core.PathParam("id", "string", "Capture session ID", "cap_1790376243"),
		core.Returns("DNS records from capture", map[string]any{
			"dns_queries": []map[string]any{
				{"query": "example.com", "type": "A", "answers": []string{"203.0.113.1"}, "src": "192.168.1.10", "dst": "8.8.8.8", "timestamp": 1790376243},
			},
		}))
	ctx.Route("GET", "/api/inspect/capture/{id}/tls", m.apiCaptureTLS,
		core.Doc("Get TLS handshakes and certificate information from captured traffic"),
		core.PathParam("id", "string", "Capture session ID", "cap_1790376243"),
		core.Returns("TLS handshake details", map[string]any{
			"tls_handshakes": []map[string]any{
				{"sni": "example.com", "ja3": "12345abcde...", "src": "192.168.1.10", "dst": "203.0.113.1", "cert_cn": "example.com", "cert_san": []string{"*.example.com"}, "ech": false, "timestamp": 1790376243},
			},
		}))
	ctx.Route("GET", "/api/inspect/capture/{id}/http", m.apiCaptureHTTP,
		core.Doc("Get HTTP requests extracted from unencrypted traffic in the capture"),
		core.PathParam("id", "string", "Capture session ID", "cap_1790376243"),
		core.Returns("HTTP requests from capture", map[string]any{
			"http_requests": []map[string]any{
				{"method": "GET", "host": "example.com", "path": "/api/data", "user_agent": "Mozilla/5.0", "src": "192.168.1.10", "dst": "203.0.113.1", "timestamp": 1790376243},
			},
		}))
	ctx.Route("GET", "/api/inspect/capture/{id}/expert", m.apiCaptureExpert,
		core.Doc("Get expert analysis notes on potential network issues in the capture"),
		core.PathParam("id", "string", "Capture session ID", "cap_1790376243"),
		core.Returns("Expert analysis notes", map[string]any{
			"expert_notes": []map[string]any{
				{"type": "retransmission", "src": "192.168.1.10", "dst": "203.0.113.1", "detail": "TCP retransmissions detected", "severity": "warn", "timestamp": 1790376243},
			},
		}))
	ctx.Route("GET", "/api/inspect/capture/{id}/download", m.apiCaptureDownload,
		core.Doc("Download the packet capture file in standard tcpdump PCAP format"),
		core.PathParam("id", "string", "Capture session ID", "cap_1790376243"),
		core.Returns("PCAP file data for download", map[string]any{"content_type": "application/vnd.tcpdump.pcap"}))
	ctx.Route("DELETE", "/api/inspect/capture/{id}", m.apiCaptureDelete, core.Write(),
		core.Doc("Delete a saved packet capture and its associated files"),
		core.PathParam("id", "string", "Capture session ID", "cap_1790376243"),
		core.Returns("Capture deleted successfully", map[string]any{"status": "deleted"}))
	ctx.Route("GET", "/api/inspect/live", m.apiLiveStream,
		core.Doc("Stream live packet summaries from a network interface as text lines"),
		core.Query("iface", "string", "Network interface to capture from", true, "em0"),
		core.Query("filter", "string", "Optional BPF filter expression", false, "tcp port 443"),
		core.Query("seconds", "integer", "Stream duration in seconds (default 10)", false, 10),
		core.Returns("Live packet stream data", map[string]any{
			"status": "completed", "lines": []string{"10:15:30.123456 IP 192.168.1.10.54321 > 203.0.113.1.443: Flags [S], seq 0"}, "count": 1,
		}))

	// Register panel
	ctx.Panel(core.Panel{
		ID:    "inspect",
		Title: "Packet Inspection",
		Group: "Protect",
		Order: 76,
		Icon:  "inspect",
	})

	// Schedule state polling job
	ctx.Every("state_poller", time.Duration(m.statePollSeconds)*time.Second, m.pollStates)

	// Publish TLS observation service for visibility module to query ECH
	ctx.Publish("tls_observations", m)

	return nil
}

func (m *Module) pollStates() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	states, err := m.getPFStates()
	if err != nil {
		m.ctx.Log.Warn("failed to poll states", "error", err)
		return err
	}

	m.states = states

	// Detect anomalies and emit findings
	m.detectAnomalies(states)

	return nil
}

func (m *Module) getPFStates() ([]*PFState, error) {
	r, ok := m.ctx.Service(core.ServiceConnStates).(core.StateReader)
	if !ok || !r.Available() {
		return nil, nil // no connection table on this platform
	}
	conns, err := r.States()
	if err != nil {
		return nil, fmt.Errorf("reading %s states: %w", r.Name(), err)
	}
	states := toPFStates(conns, time.Now())

	// Keep only the newest maxStates
	if len(states) > m.maxStates {
		sort.Slice(states, func(i, j int) bool {
			return states[i].Timestamp.After(states[j].Timestamp)
		})
		states = states[:m.maxStates]
	}

	return states, nil
}

// toPFStates describes connections the way this page always has: source and
// destination as the state is oriented on its interface. A state created
// going out names its opener as the source; one created coming in names the
// local end first, as pf prints it. The byte and packet counters are always
// what the opener sent first (the source column going out, the destination
// column coming in).
func toPFStates(conns []core.ConnState, now time.Time) []*PFState {
	states := make([]*PFState, 0, len(conns))
	for _, c := range conns {
		src, dst := c.Initiator, c.Responder
		dir := c.Direction
		if dir == "in" {
			src, dst = c.Responder, c.Initiator
		} else if dir == "" {
			dir = "out"
		}
		st := &PFState{Proto: c.Proto, Direction: dir, Interface: c.Iface, State: c.Status,
			Src: src.Addr, SrcPort: src.Port, Dst: dst.Addr, DstPort: dst.Port,
			Age: int(c.Age / time.Second), Expires: int(c.Expires / time.Second),
			PktsSrc: c.PktsSent, PktsDst: c.PktsReceived, BytesSrc: c.Sent, BytesDst: c.Received,
			Timestamp: now}
		if n, ok := strings.CutPrefix(c.Rule, "rule "); ok {
			st.RuleID, _ = strconv.Atoi(n)
		}
		states = append(states, st)
	}
	return states
}

func (m *Module) detectAnomalies(states []*PFState) {
	// Skip anomaly detection if context is not available (e.g., in tests)
	if m.ctx == nil || m.ctx.Store == nil {
		return
	}
	for _, f := range findAnomalies(states, m.synFloodThresh, m.portScanThresh) {
		m.ctx.Store.AddFinding("inspect", f.Kind, f.Severity, f.Subject, f.Title, f.Detail, f.Key)
	}
}

// anomaly is one finding from the state table.
type anomaly struct {
	Kind, Severity, Subject, Title, Detail, Key string
}

// openerState is the TCP state of the end that opened the connection. pf
// prints the pair as "opener:responder", SYN_SENT:CLOSED for a handshake
// nobody answered, so a comparison with a single word never matched.
func openerState(s *PFState) string {
	st, _, _ := strings.Cut(s.State, ":")
	return st
}

// opener is the address that opened the connection. A state created coming
// in is shown with the local end as its source, the way pf prints it, so the
// opener is then the destination column.
func opener(s *PFState) string {
	if s.Direction == "in" {
		return s.Dst
	}
	return s.Src
}

// halfOpen reports a TCP handshake the far end has not answered.
func halfOpen(s *PFState) bool { return s.Proto == "tcp" && openerState(s) == "SYN_SENT" }

// findAnomalies reads the state table for two patterns, per opener: many
// unanswered handshakes (a SYN flood) and unanswered handshakes to many
// destinations (a scan). Only TCP counts: UDP and ICMP states never look
// "established", and counting them made every busy client a scanner.
func findAnomalies(states []*PFState, synThresh, scanThresh int) []anomaly {
	half := map[string]int{}
	dests := map[string]map[string]bool{}
	for _, s := range states {
		if !halfOpen(s) {
			continue
		}
		src := opener(s)
		half[src]++
		dst, port := s.Dst, s.DstPort
		if s.Direction == "in" {
			dst, port = s.Src, s.SrcPort
		}
		if dests[src] == nil {
			dests[src] = map[string]bool{}
		}
		dests[src][fmt.Sprintf("%s:%d", dst, port)] = true
	}
	var out []anomaly
	for _, src := range sortedKeys(half) {
		if n := half[src]; n > synThresh {
			out = append(out, anomaly{Kind: "syn_flood", Severity: "high", Subject: src,
				Title: fmt.Sprintf("SYN flood detected from %s", src), Detail: fmt.Sprintf("%d half-open connections", n),
				Key: "syn_flood_" + src})
		}
		if n := len(dests[src]); n > scanThresh {
			out = append(out, anomaly{Kind: "port_scan", Severity: "medium", Subject: src,
				Title:  fmt.Sprintf("Possible port scan from %s", src),
				Detail: fmt.Sprintf("Unanswered connection attempts to %d different destinations", n),
				Key:    "port_scan_" + src})
		}
	}
	return out
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// API Handlers

func (m *Module) apiStates(r *core.Req) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	host := r.Q("host", "")
	proto := r.Q("proto", "")
	state := r.Q("state", "")
	limit := r.QInt("limit", 100, 1, 10000)

	filtered := m.states
	if host != "" {
		var tmp []*PFState
		for _, s := range filtered {
			if s.Src == host || s.Dst == host {
				tmp = append(tmp, s)
			}
		}
		filtered = tmp
	}
	if proto != "" {
		var tmp []*PFState
		for _, s := range filtered {
			if s.Proto == proto {
				tmp = append(tmp, s)
			}
		}
		filtered = tmp
	}
	if state != "" {
		var tmp []*PFState
		for _, s := range filtered {
			if s.State == state {
				tmp = append(tmp, s)
			}
		}
		filtered = tmp
	}

	if len(filtered) > limit {
		filtered = filtered[:limit]
	}

	return map[string]any{
		"states": filtered,
		"count":  len(filtered),
	}, nil
}

func (m *Module) apiStatesSummary(r *core.Req) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	summary := &StatesSummary{
		TotalStates: len(m.states),
		ByProto:     make(map[string]int),
		ByState:     make(map[string]int),
	}

	for _, s := range m.states {
		summary.ByProto[s.Proto]++
		summary.ByState[s.State]++
		if halfOpen(s) {
			summary.HalfOpenCount++
		}
	}

	return summary, nil
}

func (m *Module) apiRules(r *core.Req) (any, error) {
	rr, ok := m.ctx.Service(core.ServiceRules).(core.RuleReader)
	if !ok || !rr.Available() {
		return nil, core.BadRequest("no firewall ruleset to read on this platform")
	}
	rules, err := rr.Rules()
	if err != nil {
		return nil, fmt.Errorf("reading %s rules: %w", rr.Name(), err)
	}
	texts := make([]string, len(rules))
	for i, ru := range rules {
		texts[i] = ru.Text
	}
	return map[string]any{
		"backend":    rr.Name(),
		"syntax":     rr.Syntax(),
		"rules":      rules,
		"rule_count": len(rules),
		"raw":        strings.Join(texts, "\n"),
	}, nil
}

func (m *Module) apiCaptureStart(r *core.Req) (any, error) {
	var req struct {
		Iface   string `json:"iface"`
		Filter  string `json:"filter"`
		Seconds int    `json:"seconds"`
		Snaplen int    `json:"snaplen"`
		Payload bool   `json:"payload"`
	}

	if err := r.Decode(&req); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.capture != nil {
		return nil, core.BadRequest("capture already in progress")
	}

	// Validate
	if req.Iface == "" {
		return nil, core.BadRequest("iface required")
	}
	if req.Seconds <= 0 || req.Seconds > m.maxCaptureSecs {
		req.Seconds = m.maxCaptureSecs
	}
	if req.Snaplen == 0 {
		req.Snaplen = m.snaplen
	}
	if req.Payload && !m.payloadAllowed {
		return nil, core.Forbidden("payload capture not allowed by policy")
	}

	// Validate BPF filter
	if req.Filter != "" {
		if err := m.validateBPFFilter(req.Filter); err != nil {
			return nil, core.BadRequest("invalid BPF filter: %v", err)
		}
	}

	id := fmt.Sprintf("cap_%d", time.Now().Unix())
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.Seconds)*time.Second+30*time.Second)

	m.capture = &CaptureSession{
		ID:       id,
		Iface:    req.Iface,
		Filter:   req.Filter,
		Started:  time.Now(),
		Duration: req.Seconds,
		Snaplen:  req.Snaplen,
		Payload:  req.Payload,
		ctx:      ctx,
		cancel:   cancel,
	}

	go m.runCapture()

	return map[string]any{
		"id":      id,
		"status":  "started",
		"iface":   req.Iface,
		"filter":  req.Filter,
		"seconds": req.Seconds,
	}, nil
}

func (m *Module) apiCaptureStop(r *core.Req) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.capture == nil {
		return nil, core.NotFound("no capture in progress")
	}

	m.capture.cancel()
	return map[string]string{"status": "stopping"}, nil
}

func (m *Module) apiCaptures(r *core.Req) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	captures := make([]*CaptureInfo, 0, len(m.captures))
	for _, c := range m.captures {
		captures = append(captures, c)
	}

	// Sort by started, newest first
	sort.Slice(captures, func(i, j int) bool {
		return captures[i].Started.After(captures[j].Started)
	})

	return map[string]any{"captures": captures}, nil
}

func (m *Module) apiCaptureDetail(r *core.Req) (any, error) {
	id := r.Params["id"]
	if id == "" {
		return nil, core.BadRequest("id required")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	cap, ok := m.captures[id]
	if !ok {
		return nil, core.NotFound("capture not found")
	}

	return cap, nil
}

func (m *Module) apiCaptureConversations(r *core.Req) (any, error) {
	id := r.Params["id"]
	m.mu.RLock()
	cap, ok := m.captures[id]
	m.mu.RUnlock()

	if !ok {
		return nil, core.NotFound("capture not found")
	}

	if cap.Analysis == nil {
		return map[string]any{"conversations": []Conversation{}}, nil
	}

	return map[string]any{"conversations": cap.Analysis.Conversations}, nil
}

func (m *Module) apiCaptureDNS(r *core.Req) (any, error) {
	id := r.Params["id"]
	m.mu.RLock()
	cap, ok := m.captures[id]
	m.mu.RUnlock()

	if !ok {
		return nil, core.NotFound("capture not found")
	}

	if cap.Analysis == nil {
		return map[string]any{"dns": []DNSRecord{}}, nil
	}

	return map[string]any{"dns": cap.Analysis.DNSQueries}, nil
}

func (m *Module) apiCaptureTLS(r *core.Req) (any, error) {
	id := r.Params["id"]
	m.mu.RLock()
	cap, ok := m.captures[id]
	m.mu.RUnlock()

	if !ok {
		return nil, core.NotFound("capture not found")
	}

	if cap.Analysis == nil {
		return map[string]any{"tls": []TLSInfo{}}, nil
	}

	return map[string]any{"tls": cap.Analysis.TLSHandshakes}, nil
}

func (m *Module) apiCaptureHTTP(r *core.Req) (any, error) {
	id := r.Params["id"]
	m.mu.RLock()
	cap, ok := m.captures[id]
	m.mu.RUnlock()

	if !ok {
		return nil, core.NotFound("capture not found")
	}

	if cap.Analysis == nil {
		return map[string]any{"http": []HTTPRequest{}}, nil
	}

	return map[string]any{"http": cap.Analysis.HTTPRequests}, nil
}

func (m *Module) apiCaptureExpert(r *core.Req) (any, error) {
	id := r.Params["id"]
	m.mu.RLock()
	cap, ok := m.captures[id]
	m.mu.RUnlock()

	if !ok {
		return nil, core.NotFound("capture not found")
	}

	if cap.Analysis == nil {
		return map[string]any{"notes": []ExpertNote{}}, nil
	}

	return map[string]any{"notes": cap.Analysis.ExpertNotes}, nil
}

func (m *Module) apiCaptureDownload(r *core.Req) (any, error) {
	id := r.Params["id"]
	m.mu.RLock()
	_, ok := m.captures[id]
	m.mu.RUnlock()

	if !ok {
		return nil, core.NotFound("capture not found")
	}

	// Merge pcap files and return as Raw response
	reader, err := m.downloadCapture(id)
	if err != nil {
		return nil, core.Errorf(500, "failed to merge pcap files: %v", err)
	}

	// Read the merged data
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, core.Errorf(500, "failed to read pcap data: %v", err)
	}

	// Return as Raw binary response
	return core.Raw{
		ContentType: "application/vnd.tcpdump.pcap",
		Filename:    fmt.Sprintf("flowsight-%s.pcap", id),
		Body:        data,
	}, nil
}

func (m *Module) apiCaptureDelete(r *core.Req) (any, error) {
	id := r.Params["id"]

	m.mu.Lock()
	defer m.mu.Unlock()

	cap, ok := m.captures[id]
	if !ok {
		return nil, core.NotFound("capture not found")
	}

	// Delete files
	for _, f := range cap.Files {
		_ = os.Remove(filepath.Join(m.dataDir, f))
	}

	delete(m.captures, id)

	return map[string]string{"status": "deleted"}, nil
}

func (m *Module) apiLiveStream(r *core.Req) (any, error) {
	iface := r.Q("iface", "")
	filter := r.Q("filter", "")
	seconds := r.QInt("seconds", 10, 1, 30)

	if iface == "" {
		return nil, core.BadRequest("iface required")
	}

	// Validate BPF filter if provided
	if filter != "" {
		if err := m.validateBPFFilter(filter); err != nil {
			return nil, core.BadRequest("invalid filter: %s", err.Error())
		}
	}

	// Start tcpdump in background and capture output
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds+5)*time.Second)
	defer cancel()

	// Build tcpdump command
	args := []string{
		"-l", "-n", "-tttt", "-q",
		"-i", iface,
	}
	if filter != "" {
		args = append(args, filter)
	}

	cmd := exec.CommandContext(ctx, "tcpdump", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, core.Errorf(500, "failed to create pipe")
	}

	if err := cmd.Start(); err != nil {
		return nil, core.Errorf(500, "failed to start tcpdump")
	}

	// Collect output for up to the timeout
	var lines []string
	scanner := bufio.NewScanner(stdout)
	timeout := time.After(time.Duration(seconds) * time.Second)

	for {
		select {
		case <-timeout:
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return map[string]any{
				"status": "completed",
				"lines":  lines,
				"count":  len(lines),
			}, nil
		default:
			if !scanner.Scan() {
				_ = cmd.Wait()
				return map[string]any{
					"status": "completed",
					"lines":  lines,
					"count":  len(lines),
				}, nil
			}
			if len(lines) < 1000 {
				lines = append(lines, scanner.Text())
			}
		}
	}
}

func (m *Module) loadCaptures() error {
	// Load existing captures from disk
	// This would scan the captures directory and load metadata and cached analysis
	return nil
}

// Helper functions

func (m *Module) validateBPFFilter(filter string) error {
	// Empty filter is valid
	if filter == "" {
		return nil
	}

	// Length check
	if len(filter) > 1000 {
		return fmt.Errorf("filter too long")
	}

	// Character validation (basic)
	for _, c := range filter {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == ' ' || c == '.' || c == ',' || c == ':' || c == '-' || c == '(' || c == ')' ||
			c == '[' || c == ']' || c == '!' || c == '&' || c == '|' || c == '=') {
			return fmt.Errorf("invalid character: %c", c)
		}
	}

	// Try to compile with tcpdump (skip if not available)
	cmd := exec.Command("tcpdump", "-d", filter)
	if err := cmd.Run(); err != nil {
		// Only return error if the tool is available but the syntax is invalid
		// If tcpdump is not available, we skip this validation
		if _, ok := err.(*exec.ExitError); !ok {
			// Tool not found is OK; let it through
			return nil
		}
		return fmt.Errorf("invalid BPF: %w", err)
	}

	return nil
}

func (m *Module) runCapture() {
	defer func() {
		m.mu.Lock()
		m.capture = nil
		m.mu.Unlock()
	}()

	if m.capture == nil {
		return
	}

	id := m.capture.ID
	iface := m.capture.Iface
	filter := m.capture.Filter
	snaplen := m.capture.Snaplen

	// Build output filename
	capFile := filepath.Join(m.dataDir, fmt.Sprintf("%s.pcap", id))

	// Build tcpdump command
	args := []string{
		"-i", iface,
		"-w", capFile,
		"-C", "20", // rotate at 20MB
		"-W", fmt.Sprintf("%d", m.maxCaptureFiles),
		"-s", fmt.Sprintf("%d", snaplen),
		"-U",
	}

	if filter != "" {
		args = append(args, filter)
	}

	cmd := exec.CommandContext(m.capture.ctx, "tcpdump", args...)
	if err := cmd.Run(); err != nil {
		m.ctx.Log.Warn("tcpdump failed", "error", err)
	}

	// Record capture
	m.mu.Lock()
	now := time.Now()
	m.captures[id] = &CaptureInfo{
		ID:        id,
		Iface:     iface,
		Filter:    filter,
		Started:   m.capture.Started,
		Ended:     &now,
		Files:     []string{fmt.Sprintf("%s.pcap", id)},
		Timestamp: now,
	}
	m.mu.Unlock()

	// Analyze capture
	_ = m.analyzeCapture(id)
}

// Utility functions

func asInt(v any, def int) int {
	switch x := v.(type) {
	case int:
		return x
	case float64:
		return int(x)
	case string:
		if i, err := strconv.Atoi(x); err == nil {
			return i
		}
	}
	return def
}

func asBool(v any, def bool) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true" || x == "1" || x == "yes"
	}
	return def
}

// recordTLSObservation stores ECH detection for a flow (3-tuple: src, dst, dstport)
// for the visibility module to query. Observations expire after 1 minute.
func (m *Module) recordTLSObservation(src, dst string, dstPort int, ech bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s:%s:%d", src, dst, dstPort)
	m.tlsObservations[key] = tlsObservation{ECH: ech, Timestamp: time.Now()}
}

// queryTLSObservation checks if a 3-tuple had ECH in the last minute
func (m *Module) queryTLSObservation(src, dst string, dstPort int) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := fmt.Sprintf("%s:%s:%d", src, dst, dstPort)
	if obs, ok := m.tlsObservations[key]; ok {
		if time.Since(obs.Timestamp) < time.Minute {
			return obs.ECH
		}
	}
	return false
}

// TLSObservationService allows other modules to query TLS observations
type TLSObservationService interface {
	HasECH(src, dst string, dstPort int) bool
}

// HasECH returns true if a TLS connection to (dst:dstPort) from src had ECH
func (m *Module) HasECH(src, dst string, dstPort int) bool {
	return m.queryTLSObservation(src, dst, dstPort)
}
