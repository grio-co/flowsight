// Package proxmox maps Proxmox VE host and guest information into FlowSight
// for inventory, enrichment, and optional notes write-back.
package proxmox

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

type Module struct {
	ctx           *core.Context
	client        *http.Client
	insecureHTTP  *http.Client
	mu            sync.Mutex
	inventory     *Inventory
	lastPollTime  int64
	lastPollError string
	sockEdges     []Edge   // from the optional in-VM socket probe
	sockNotes     []string // per-VM probe failures, for the status card
	sockAt        int64
	notesMu       sync.Mutex
	notesWritten  int
	notesSkippedN int
	notesFailed   int
	notesLastErr  string
	notesAt       int64
	polling       sync.Mutex
}

type Inventory struct {
	Nodes  []Node   `json:"nodes"`
	Guests []Guest  `json:"guests"`
	LastAt int64    `json:"last_at"`
	Errors []string `json:"errors"`
}

type Node struct {
	Name       string `json:"name"`
	PVEVersion string `json:"pve_version"`
	CPU        int    `json:"cpu"`         // percentage * 100
	MemPercent int    `json:"mem_percent"` // percentage * 100
	Uptime     int64  `json:"uptime"`
	Load       string `json:"load"`
	RootFSPct  int    `json:"rootfs_pct"`
	Kernel     string `json:"kernel"`
}

type Guest struct {
	VMID           int                    `json:"vmid"`
	Type           string                 `json:"type"` // "qemu" or "lxc"
	Node           string                 `json:"node"`
	Name           string                 `json:"name"`
	Status         string                 `json:"status"` // "running", "stopped"
	Tags           []string               `json:"tags"`
	MACs           []string               `json:"macs"`
	IPs            []string               `json:"ips"`
	OS             string                 `json:"os"`
	OSType         string                 `json:"ostype,omitempty"`
	Hostname       string                 `json:"hostname"`
	Cores          int                    `json:"cores"`
	Memory         int64                  `json:"memory"`
	Uptime         int64                  `json:"uptime,omitempty"`
	AgentState     string                 `json:"agent_state"`
	Description    string                 `json:"description"`
	NotesSyncedAt  int64                  `json:"notes_synced_at"`
	DescriptionSet bool                   `json:"description_set"`
	RawConfig      map[string]interface{} `json:"-"` // unpublished; used to parse declared requirements
	HostURL        string                 `json:"-"` // which API host serves this guest
}

type GuestRef struct {
	VMID int    `json:"vmid"`
	Type string `json:"type"`
	Node string `json:"node"`
	Name string `json:"name"`
	OS   string `json:"os"`
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name:         "proxmox",
		Version:      "1.0",
		Description:  "Proxmox VE inventory: host, node, and guest information with optional notes write-back and enrichment",
		Capabilities: []string{core.CapHostInventory},
		After:        []string{"identity"},
		Defaults: map[string]any{
			"enabled":        true,
			"hosts":          []string{},
			"token_id":       "",
			"token_secret":   "",
			"fingerprint":    "",
			"token_id_2":     "",
			"token_secret_2": "",
			"fingerprint_2":  "",
			"token_id_3":     "",
			"token_secret_3": "",
			"fingerprint_3":  "",
			"verify_tls":     false,
			"poll_minutes":   5,
			"write_notes":    false,
			"notes_targets":  "guests",
			"exclude_vmids":  []string{},
			"name_guests":    true,
			"probe_sockets":  false,
			"gateway_url":    "",
		},
		Schema: []core.SettingField{
			{Key: "hosts", Label: "Proxmox nodes", Type: "list",
				Help: "One URL per line, e.g. https://pve.local:8006. Empty: module idles. The first line uses the token and fingerprint below; the second and third lines use their own when set (standalone nodes have different tokens and certificates), else the same ones."},
			{Key: "token_id", Label: "API token ID", Type: "string",
				Help: "Format: user@realm!tokenname, e.g. flowsight@pve!flowsight"},
			{Key: "token_secret", Label: "API token secret", Type: "secret"},
			{Key: "fingerprint", Label: "TLS fingerprint (SHA-256)", Type: "string",
				Help: "Colon-separated hex, e.g. 4C:9E:F6:... Pinned cert verification."},
			{Section: "Second node", Key: "token_id_2", Label: "API token ID (node 2)", Type: "string", Help: "For the second URL in the list. Empty: the first node's."},
			{Section: "Second node", Key: "token_secret_2", Label: "API token secret (node 2)", Type: "secret"},
			{Section: "Second node", Key: "fingerprint_2", Label: "TLS fingerprint (node 2)", Type: "string", Help: "SHA-256 of the second node's certificate. Empty: the first node's."},
			{Section: "Third node", Key: "token_id_3", Label: "API token ID (node 3)", Type: "string"},
			{Section: "Third node", Key: "token_secret_3", Label: "API token secret (node 3)", Type: "secret"},
			{Section: "Third node", Key: "fingerprint_3", Label: "TLS fingerprint (node 3)", Type: "string"},
			{Key: "verify_tls", Label: "Verify TLS with system roots", Type: "bool",
				Help: "Off: use fingerprint pinning. On: system CA roots + pinned cert if set."},
			{Key: "poll_minutes", Label: "Poll interval (minutes)", Type: "int"},
			{Key: "write_notes", Label: "Write notes to guest descriptions", Type: "bool"},
			{Key: "notes_targets", Label: "Write notes to", Type: "string",
				Help: "guests or guests+nodes"},
			{Key: "exclude_vmids", Label: "Exclude VMs (comma-separated vmids)", Type: "list"},
			{Key: "name_guests", Label: "Use guest names when no lease hostname", Type: "bool"},
			{Key: "gateway_url", Label: "FlowSight URL for links in Notes", Type: "string", Placeholder: "https://opnsense.example.lan", Help: "Used only to build the link back to the host page inside each guest's Notes."},
			{Key: "probe_sockets", Label: "Ask VMs for their connections", Type: "bool", Help: "Off by default. Runs one fixed command (ss -Htn state established) inside running VMs through the guest agent, which needs the VM.Monitor privilege on the token. Shows container-to-VM and VM-to-VM traffic the gateway never sees."},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.inventory = &Inventory{Guests: []Guest{}, Nodes: []Node{}}

	// Set up HTTP clients
	tlsConfig := &tls.Config{}
	if !core.Bool(ctx.Settings(), "verify_tls", false) {
		tlsConfig.InsecureSkipVerify = true
	}
	m.insecureHTTP = &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}
	m.client = m.insecureHTTP

	if fingerprint := core.Str(ctx.Settings(), "fingerprint", ""); fingerprint != "" {
		m.client = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					VerifyPeerCertificate: m.makePinVerifier(fingerprint),
					InsecureSkipVerify:    true,
				},
			},
		}
	}

	// Load inventory from KV
	_ = m.ctx.Store.KVGet("proxmox.inventory", m.inventory)

	// Register routes
	ctx.Route("GET", "/api/proxmox/inventory", m.apiInventory,
		core.Doc("List all Proxmox nodes and virtual machines with their status and configuration"),
		core.Returns("Proxmox inventory", map[string]any{
			"nodes": []map[string]any{
				{"name": "pve1", "status": "online", "uptime": 86400},
			},
			"guests": []map[string]any{
				{"vmid": 100, "name": "container1", "node": "pve1", "status": "running"},
			},
		}))
	ctx.Route("GET", "/api/proxmox/status", m.apiStatus,
		core.Doc("Check Proxmox connection status and display timestamp of last successful poll"),
		core.Returns("Connection status", map[string]any{
			"connected": true,
			"last_poll": 1790376243,
			"error":     "",
		}))
	ctx.Route("POST", "/api/proxmox/poll", m.apiPoll, core.Write(),
		core.Doc("Trigger an immediate poll of Proxmox API for latest node and VM status"),
		core.Body(),
		core.Returns("Poll result", map[string]any{
			"ok":      true,
			"message": "Poll completed",
		}))
	ctx.Route("GET", "/api/proxmox/guest", m.apiGuest,
		core.Query("vmid", "integer", "Virtual machine ID or LXC container ID", true, 100),
		core.Query("node", "string", "Proxmox node name where guest resides", true, "pve1"),
		core.Doc("Retrieve detailed configuration and status for a specific virtual machine or container"),
		core.Returns("Guest details", map[string]any{
			"vmid":   100,
			"name":   "container1",
			"node":   "pve1",
			"status": "running",
			"cpu":    4,
			"memory": 2048,
		}))
	ctx.Route("GET", "/api/proxmox/notes/preview", m.apiNotesPreview,
		core.Query("vmid", "integer", "Virtual machine ID", true, 100),
		core.Query("node", "string", "Proxmox node name", true, "pve1"),
		core.Doc("Preview the formatted notes section for a guest container or virtual machine"),
		core.Returns("Notes preview", map[string]any{
			"content": "Guest notes here",
			"html":    "<p>Guest notes here</p>",
		}))
	ctx.Route("POST", "/api/proxmox/notes/write", m.apiNotesWrite, core.Write(),
		core.Doc("Update the notes section for a Proxmox guest with new content and formatting"),
		core.Body(
			core.Fld("vmid", "integer", true, "Virtual machine or container ID", 100),
			core.Fld("node", "string", true, "Proxmox node name", "pve1"),
			core.Fld("description", "string", true, "New notes content", "Updated notes"),
		),
		core.Returns("Write result", map[string]any{"ok": true}))
	ctx.Route("GET", "/api/proxmox/map", m.apiMap,
		core.Query("hours", "integer", "Time window in hours for network traffic analysis (default 24)", false, 24),
		core.Doc("Show network dependencies and traffic patterns between guests and external destinations"),
		core.Returns("Network dependency map", map[string]any{
			"nodes": []map[string]any{
				{"name": "container1", "type": "guest"},
			},
			"edges": []map[string]any{
				{"src": "container1", "dst": "external-host", "bytes": 100000},
			},
		}))
	ctx.Route("GET", "/api/proxmox/requirements", m.apiRequirements,
		core.Query("vmid", "integer", "Virtual machine ID to analyze", true, 100),
		core.Query("node", "string", "Proxmox node name where guest resides", true, "pve1"),
		core.Query("hours", "integer", "Time window in hours for metrics (default 24)", false, 24),
		core.Doc("Analyze a guest's resource requirements based on historical usage patterns and current load"),
		core.Returns("Resource requirements analysis", map[string]any{
			"vmid":                  100,
			"cpu_cores_needed":      4,
			"memory_mb_needed":      2048,
			"network_capacity_mbps": 100,
		}))

	// Register panel
	ctx.Panel(core.Panel{
		ID:    "proxmox",
		Title: "Proxmox",
		Group: "Inventory",
		Order: 160,
		Icon:  "proxmox",
	})

	// Periodic poll
	pollMin := core.Int(ctx.Settings(), "poll_minutes", 5)
	if pollMin > 0 && len(core.Strs(ctx.Settings(), "hosts")) > 0 {
		ctx.Every("proxmox_poll", time.Duration(pollMin)*time.Minute, m.doPoll)
	}

	// Publish the inventory service
	ctx.Publish("proxmox_inventory", m)
	ctx.Publish("proxmox", m) // the name the Devices and host pages ask for

	return nil
}

// Parsers

type pveNodes struct {
	Data []struct {
		Node           string  `json:"node"`
		CPU            float64 `json:"cpu"`
		MaxCPU         int     `json:"maxcpu"`
		Memory         int64   `json:"mem"`
		MaxMemory      int64   `json:"maxmem"`
		Disk           int64   `json:"disk"`
		MaxDisk        int64   `json:"maxdisk"`
		Uptime         int64   `json:"uptime"`
		SSLFingerprint string  `json:"ssl_fingerprint"`
		Status         string  `json:"status"`
	} `json:"data"`
}

type pveNodeStatus struct {
	Data struct {
		PVEVersion    string                      `json:"pveversion"`
		CPUInfo       struct{ Cores int }         `json:"cpuinfo"`
		Memory        struct{ Used, Total int64 } `json:"memory"`
		Rootfs        struct{ Used, Total int64 } `json:"rootfs"`
		Uptime        int64                       `json:"uptime"`
		LoadAvg       []string                    `json:"loadavg"`
		CurrentKernel struct {
			Release string `json:"release"`
		} `json:"current-kernel"`
	} `json:"data"`
}

type pveVersion struct {
	Data struct {
		Release string `json:"release"`
		Version string `json:"version"`
	} `json:"data"`
}

type pveQEMUList struct {
	Data []struct {
		VMID   int    `json:"vmid"`
		Name   string `json:"name"`
		Status string `json:"status"`
		Node   string `json:"node"`
		Tags   string `json:"tags"`
		Config struct {
			Cores       int    `json:"cores"`
			Memory      int    `json:"memory"`
			OSType      string `json:"ostype"`
			Description string `json:"description"`
		} `json:"config"`
	} `json:"data"`
}

// pveQEMUConfig is /nodes/{n}/qemu/{vmid}/config. Proxmox 9 sends memory
// as a string ("8192") and agent as "1" or "enabled=1,fstrim_cloned_disks=1",
// so both are read loosely; a strict int here made the whole config
// unreadable and left every VM without addresses.
type pveQEMUConfig struct {
	Data struct {
		Cores       int         `json:"cores"`
		Memory      looseString `json:"memory"`
		OSType      string      `json:"ostype"`
		Description string      `json:"description"`
		Digest      string      `json:"digest"`
		Agent       looseString `json:"agent"`
	} `json:"data"`
}

// looseString accepts a JSON string or number.
type looseString string

func (l *looseString) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*l = looseString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*l = looseString(n.String())
	return nil
}

func (l looseString) String() string { return string(l) }

// splitTags reads a Proxmox tag list, which is ";"-separated (","
// accepted on the way in).
func splitTags(s string) []string {
	var out []string
	for _, t := range strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ',' || r == ' ' }) {
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// unwrapData returns the object inside {"data": ...} when the API wrapped
// its answer, else the body as it came (pvesh output is unwrapped).
func unwrapData(body []byte) []byte {
	var w struct {
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(body, &w) == nil && len(w.Data) > 0 && string(w.Data) != "null" {
		return w.Data
	}
	return body
}

// agentEnabled reads the qemu "agent" config value in both of its forms.
func agentEnabled(v string) bool {
	v = strings.TrimSpace(v)
	return v == "1" || strings.HasPrefix(v, "1,") || strings.Contains(v, "enabled=1")
}

type pveLXCList struct {
	Data []struct {
		VMID   int    `json:"vmid"`
		Name   string `json:"name"`
		Status string `json:"status"`
		Node   string `json:"node"`
		Tags   string `json:"tags"`
	} `json:"data"`
}

type pveLXCConfig struct {
	Data struct {
		Cores       int    `json:"cores"`
		Memory      int    `json:"memory"`
		OSType      string `json:"ostype"`
		Description string `json:"description"`
		Digest      string `json:"digest"`
	} `json:"data"`
}

type pveQEMUStatus struct {
	Data struct {
		Status string `json:"status"`
		Uptime int64  `json:"uptime"`
	} `json:"data"`
}

type pveLXCStatus struct {
	Data struct {
		Status string `json:"status"`
		Uptime int64  `json:"uptime"`
	} `json:"data"`
}

type pveAgentNetworkResp struct {
	Result []struct {
		HardwareAddress string `json:"hardware-address"`
		IPAddresses     []struct {
			IPAddress string `json:"ip-address"`
			Type      string `json:"ip-address-type"`
		} `json:"ip-addresses"`
		Name string `json:"name"`
	} `json:"result"`
}

type pveAgentHostname struct {
	Result struct {
		HostName string `json:"host-name"`
	} `json:"result"`
}

type pveAgentOSInfo struct {
	Result struct {
		KernelRelease string `json:"kernel-release"`
		KernelVersion string `json:"kernel-version"`
		Machine       string `json:"machine"`
	} `json:"result"`
}

// pveLXCInterfaces is /nodes/{n}/lxc/{vmid}/interfaces as PVE 8/9 return
// it: hwaddr and hardware-address both present, addresses as a list of
// {ip-address, ip-address-type} plus inet/inet6 CIDR strings.
type pveLXCInterfaces struct {
	Data []struct {
		Name            string `json:"name"`
		HwAddr          string `json:"hwaddr"`
		HardwareAddress string `json:"hardware-address"`
		Inet            string `json:"inet"`
		Inet6           string `json:"inet6"`
		IPAddresses     []struct {
			IPAddress string `json:"ip-address"`
			Type      string `json:"ip-address-type"`
		} `json:"ip-addresses"`
	} `json:"data"`
}

// usableIP is an address worth recording: not loopback, not link-local.
func usableIP(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "/"); i > 0 {
		s = s[:i]
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return "", false
	}
	return ip.String(), true
}

// HTTP and polling

func (m *Module) makePinVerifier(fingerprint string) func([][]byte, [][]*x509.Certificate) error {
	parts := strings.Split(strings.ToLower(fingerprint), ":")
	if len(parts) != 32 {
		return nil
	}
	var pinned [32]byte
	for i, p := range parts {
		var b byte
		fmt.Sscanf(p, "%2x", &b)
		pinned[i] = b
	}

	return func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("no peer certificate")
		}
		h := sha256.Sum256(rawCerts[0])
		if h != pinned {
			return fmt.Errorf("cert fingerprint mismatch: got %s, expected %s", hex.EncodeToString(h[:]), fingerprint)
		}
		return nil
	}
}

// httpClient is built from the settings as they are now. Proxmox speaks TLS
// with a self-signed certificate on a private address, so trust is either
// the pinned SHA-256 fingerprint of that certificate or, when the operator
// has installed a real one, the system roots. Neither configured means no
// connection: FlowSight never talks to a hypervisor unverified.
// nodeCreds is what one URL in the hosts list is spoken to with. The first
// URL uses the plain settings; the second and third may carry their own
// token and certificate (standalone nodes share neither), and fall back to
// the first's when theirs are empty.
type nodeCreds struct {
	TokenID, TokenSecret, Fingerprint string
}

func (m *Module) credsFor(hostURL string) nodeCreds {
	st := m.ctx.Settings()
	c := nodeCreds{
		TokenID:     core.Str(st, "token_id", ""),
		TokenSecret: core.Str(st, "token_secret", ""),
		Fingerprint: core.Str(st, "fingerprint", ""),
	}
	want := strings.TrimRight(strings.TrimSpace(hostURL), "/")
	for i, h := range core.Strs(st, "hosts") {
		if strings.TrimRight(strings.TrimSpace(h), "/") != want || i == 0 || i > 2 {
			continue
		}
		sfx := fmt.Sprintf("_%d", i+1)
		if v := core.Str(st, "token_id"+sfx, ""); v != "" {
			c.TokenID = v
		}
		if v := core.Str(st, "token_secret"+sfx, ""); v != "" {
			c.TokenSecret = v
		}
		if v := core.Str(st, "fingerprint"+sfx, ""); v != "" {
			c.Fingerprint = v
		}
		break
	}
	return c
}

func (m *Module) httpClient(hostURL string) (*http.Client, error) {
	fp := normalizeFingerprint(m.credsFor(hostURL).Fingerprint)
	switch {
	case fp == "invalid":
		return nil, fmt.Errorf("proxmox: the certificate fingerprint must be the SHA-256 of the server certificate, 32 hex pairs")
	case fp != "":
		verify := m.makePinVerifier(fp)
		if verify == nil {
			return nil, fmt.Errorf("proxmox: the certificate fingerprint could not be parsed")
		}
		return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, VerifyPeerCertificate: verify}}}, nil
	case core.Bool(m.ctx.Settings(), "verify_tls", false):
		return &http.Client{Timeout: 30 * time.Second}, nil
	}
	return nil, fmt.Errorf("proxmox: set the certificate fingerprint or turn on verify_tls; connections are never made unverified")
}

// normalizeFingerprint returns "" for none, "invalid" for something that is
// not 32 hex pairs, else the colon-separated lower-case form.
func normalizeFingerprint(s string) string {
	h := strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(s)))
	if h == "" {
		return ""
	}
	if len(h) != 64 {
		return "invalid"
	}
	for _, c := range h {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return "invalid"
		}
	}
	parts := make([]string, 0, 32)
	for i := 0; i < 64; i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

func (m *Module) get(hostURL, path string) ([]byte, error) {
	u, err := url.Parse(hostURL)
	if err != nil {
		return nil, err
	}
	u.Path = path
	req, _ := http.NewRequest("GET", u.String(), nil)
	cr := m.credsFor(hostURL)
	req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", cr.TokenID, cr.TokenSecret))

	client, err := m.httpClient(hostURL)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return io.ReadAll(resp.Body)
}

func (m *Module) put(hostURL, path string, form map[string]string) ([]byte, error) {
	u, err := url.Parse(hostURL)
	if err != nil {
		return nil, err
	}
	u.Path = path

	vals := url.Values{}
	for k, v := range form {
		vals.Set(k, v)
	}

	req, _ := http.NewRequest("PUT", u.String(), strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cr := m.credsFor(hostURL)
	req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", cr.TokenID, cr.TokenSecret))

	client, err := m.httpClient(hostURL)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return io.ReadAll(resp.Body)
}

func (m *Module) extractMACs(config map[string]interface{}) []string {
	var macs []string
	netRe := regexp.MustCompile(`^net\d+$`)
	macRe := regexp.MustCompile(`(?i)[a-f0-9]{2}(?::[a-f0-9]{2}){5}`)

	for k, v := range config {
		if netRe.MatchString(k) {
			if s, ok := v.(string); ok {
				if matches := macRe.FindAllString(s, -1); len(matches) > 0 {
					macs = append(macs, strings.ToLower(matches[0]))
				}
			}
		}
	}
	return macs
}

// snapshotGuests copies the guest list out from under the lock.
func (m *Module) snapshotGuests() []Guest {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inventory == nil {
		return nil
	}
	return append([]Guest(nil), m.inventory.Guests...)
}

// setInventory swaps in a finished poll under the lock and nothing else:
// no network, no calls that take the lock again.
func (m *Module) setInventory(inventory *Inventory) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inventory = inventory
	m.lastPollTime = time.Now().Unix()
	m.lastPollError = strings.Join(inventory.Errors, "; ")
}

func (m *Module) doPoll() error {
	m.polling.Lock()
	defer m.polling.Unlock()

	hosts := core.Strs(m.ctx.Settings(), "hosts")
	if len(hosts) == 0 {
		return nil
	}

	inventory := &Inventory{
		Guests: []Guest{},
		Nodes:  []Node{},
		LastAt: time.Now().Unix(),
		Errors: []string{},
	}

	excludeVMIDs := make(map[string]bool)
	for _, vmid := range core.Strs(m.ctx.Settings(), "exclude_vmids") {
		excludeVMIDs[vmid] = true
	}

	identity, _ := m.ctx.Service("identity").(core.Identity)

	for _, hostURL := range hosts {
		if err := m.pollHost(hostURL, inventory, excludeVMIDs, identity); err != nil {
			inventory.Errors = append(inventory.Errors, fmt.Sprintf("%s: %v", hostURL, err))
			m.ctx.Log.Warn("proxmox: node poll failed", "host", hostURL, "err", err.Error())
		}
	}
	m.mu.Lock()
	m.lastPollError = strings.Join(inventory.Errors, "; ")
	m.mu.Unlock()

	// Enrichment: UpsertHosts and notes write
	m.enrichment(inventory, excludeVMIDs, identity)

	// The socket probe talks to the network and takes the module lock
	// itself, so it runs before the lock is held, never inside it.
	m.probeSockets(inventory)

	// Save inventory
	m.setInventory(inventory)

	// Notes write-back: only guests whose block changed.
	m.writeAllNotes(append([]Guest(nil), inventory.Guests...), false)

	m.ctx.Store.KVSet("proxmox.inventory", inventory)

	return nil
}

func (m *Module) pollHost(hostURL string, inv *Inventory, excludeVMIDs map[string]bool, identity core.Identity) error {
	// GET /nodes
	body, err := m.get(hostURL, "/api2/json/nodes")
	if err != nil {
		return fmt.Errorf("nodes: %w", err)
	}
	var nodesList pveNodes
	if err := json.Unmarshal(body, &nodesList); err != nil {
		return fmt.Errorf("parse nodes: %w", err)
	}

	for _, nodeData := range nodesList.Data {
		node := Node{Name: nodeData.Node}

		// GET /nodes/{n}/status
		statusBody, err := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/status", nodeData.Node))
		if err == nil {
			var status pveNodeStatus
			if err := json.Unmarshal(statusBody, &status); err == nil {
				node.PVEVersion = status.Data.PVEVersion
				node.CPU = int(float64(status.Data.CPUInfo.Cores) * 100)
				if status.Data.Memory.Total > 0 {
					node.MemPercent = int(status.Data.Memory.Used * 100 / status.Data.Memory.Total)
				}
				node.Uptime = status.Data.Uptime
				if len(status.Data.LoadAvg) > 0 {
					node.Load = status.Data.LoadAvg[0]
				}
				if status.Data.Rootfs.Total > 0 {
					node.RootFSPct = int(status.Data.Rootfs.Used * 100 / status.Data.Rootfs.Total)
				}
				node.Kernel = status.Data.CurrentKernel.Release
			}
		}

		inv.Nodes = append(inv.Nodes, node)

		// Poll QEMU guests
		qemuBody, _ := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/qemu", nodeData.Node))
		var qemuList pveQEMUList
		if err := json.Unmarshal(qemuBody, &qemuList); err == nil {
			for _, qData := range qemuList.Data {
				if excludeVMIDs[fmt.Sprintf("%d", qData.VMID)] {
					continue
				}

				g := Guest{
					VMID:        qData.VMID,
					Type:        "qemu",
					Node:        nodeData.Node,
					Name:        qData.Name,
					Status:      qData.Status,
					Description: qData.Config.Description,
					Cores:       qData.Config.Cores,
					Memory:      int64(qData.Config.Memory),
					Tags:        splitTags(qData.Tags),
					OSType:      qData.Config.OSType,
				}

				// Get config for MACs and digest
				configBody, _ := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/config", nodeData.Node, qData.VMID))
				var qConfig pveQEMUConfig
				if err := json.Unmarshal(configBody, &qConfig); err == nil {
					configMap := make(map[string]interface{})
					json.Unmarshal(configBody, &configMap)
					if cfg, ok := configMap["data"].(map[string]interface{}); ok {
						g.MACs = m.extractMACs(cfg)
					}

					// Get status and agent info if running
					if g.Status == "running" {
						statusBody, _ := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/status/current", nodeData.Node, qData.VMID))
						var qStatus pveQEMUStatus
						if err := json.Unmarshal(statusBody, &qStatus); err == nil {
							g.Uptime = qStatus.Data.Uptime
						}

						// Agent network if available
						if agentEnabled(qConfig.Data.Agent.String()) {
							netBody, _ := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/agent/network-get-interfaces", nodeData.Node, qData.VMID))
							var agentNet pveAgentNetworkResp
							if err := json.Unmarshal(unwrapData(netBody), &agentNet); err == nil && agentNet.Result != nil {
								for _, iface := range agentNet.Result {
									if iface.HardwareAddress != "" && iface.HardwareAddress != "00:00:00:00:00:00" {
										g.MACs = append(g.MACs, strings.ToLower(iface.HardwareAddress))
									}
									// The agent reports the family as inet/inet6 (PVE 9)
									// or ipv4/ipv6 (older); the address decides.
									for _, addr := range iface.IPAddresses {
										if ip, ok := usableIP(addr.IPAddress); ok {
											g.IPs = append(g.IPs, ip)
										}
									}
								}
								g.AgentState = "responding"
							} else {
								g.AgentState = "not responding"
							}

							// Agent hostname
							hostnameBody, _ := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/agent/get-host-name", nodeData.Node, qData.VMID))
							var agentHostname pveAgentHostname
							if err := json.Unmarshal(unwrapData(hostnameBody), &agentHostname); err == nil && agentHostname.Result.HostName != "" {
								g.Hostname = agentHostname.Result.HostName
							}

							// Agent osinfo
							osinfoBody, _ := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/agent/get-osinfo", nodeData.Node, qData.VMID))
							var agentOS pveAgentOSInfo
							if err := json.Unmarshal(unwrapData(osinfoBody), &agentOS); err == nil && agentOS.Result.KernelRelease != "" {
								g.OS = agentOS.Result.KernelRelease
								if agentOS.Result.KernelVersion != "" {
									g.OS += " (" + agentOS.Result.KernelVersion + ")"
								}
							}
						}
					}
				}

				g.HostURL = hostURL
				inv.Guests = append(inv.Guests, g)
			}
		}

		// Poll LXC containers
		lxcBody, _ := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/lxc", nodeData.Node))
		var lxcList pveLXCList
		if err := json.Unmarshal(lxcBody, &lxcList); err == nil {
			for _, lxcData := range lxcList.Data {
				if excludeVMIDs[fmt.Sprintf("%d", lxcData.VMID)] {
					continue
				}

				g := Guest{
					VMID:   lxcData.VMID,
					Type:   "lxc",
					Node:   nodeData.Node,
					Name:   lxcData.Name,
					Status: lxcData.Status,
					Tags:   splitTags(lxcData.Tags),
				}

				// Get config for memory
				configBody, _ := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/lxc/%d/config", nodeData.Node, lxcData.VMID))
				var lxcConfig pveLXCConfig
				if err := json.Unmarshal(configBody, &lxcConfig); err == nil {
					g.Memory = int64(lxcConfig.Data.Memory)
					g.Cores = lxcConfig.Data.Cores
					g.OSType = lxcConfig.Data.OSType
					g.Description = lxcConfig.Data.Description
				}

				// Get status
				if g.Status == "running" {
					statusBody, _ := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/lxc/%d/status/current", nodeData.Node, lxcData.VMID))
					var lxcStatus pveLXCStatus
					if err := json.Unmarshal(statusBody, &lxcStatus); err == nil {
						g.Uptime = lxcStatus.Data.Uptime
					}

					// Get interfaces
					ifBody, _ := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/lxc/%d/interfaces", nodeData.Node, lxcData.VMID))
					var ifaces pveLXCInterfaces
					if err := json.Unmarshal(ifBody, &ifaces); err == nil && ifaces.Data != nil {
						for _, iface := range ifaces.Data {
							mac := iface.HwAddr
							if mac == "" {
								mac = iface.HardwareAddress
							}
							if mac != "" && mac != "00:00:00:00:00:00" {
								g.MACs = append(g.MACs, strings.ToLower(mac))
							}
							for _, addr := range iface.IPAddresses {
								if ip, ok := usableIP(addr.IPAddress); ok {
									g.IPs = append(g.IPs, ip)
								}
							}
							if len(iface.IPAddresses) == 0 {
								for _, cidr := range []string{iface.Inet, iface.Inet6} {
									if ip, ok := usableIP(cidr); ok {
										g.IPs = append(g.IPs, ip)
									}
								}
							}
						}
					}
				}

				g.HostURL = hostURL
				inv.Guests = append(inv.Guests, g)
			}
		}
	}

	return nil
}

func (m *Module) enrichment(inv *Inventory, excludeVMIDs map[string]bool, identity core.Identity) {
	// UpsertHosts for each guest
	var updates []core.HostUpdate

	for _, guest := range inv.Guests {
		if excludeVMIDs[fmt.Sprintf("%d", guest.VMID)] {
			continue
		}

		vendor := fmt.Sprintf("Proxmox VE %s on %s", guest.Type, guest.Node)

		// For each IP, create a host update
		for _, ip := range guest.IPs {
			name := ""
			if core.Bool(m.ctx.Settings(), "name_guests", true) {
				// Only use guest name if no identity (lease hostname) for this IP
				identityName := ""
				if identity != nil {
					identityName = identity.Name(ip)
				}
				// If identity has no name for this IP, use guest name
				if identityName == "" {
					name = guest.Name
				}
			}

			update := core.HostUpdate{
				IP:         ip,
				Name:       name,
				Vendor:     vendor,
				OS:         guest.OS,
				DeviceType: "vm",
				Source:     "proxmox",
				IsLocal:    boolPtr(true),
				LastSeen:   time.Now().Unix(),
			}

			// Add MACs for the first update (we don't have a good way to map IPs to MACs right now)
			for _, mac := range guest.MACs {
				updates = append(updates, core.HostUpdate{
					MAC:        mac,
					Vendor:     vendor,
					OS:         guest.OS,
					DeviceType: "vm",
					Source:     "proxmox",
					IsLocal:    boolPtr(true),
					LastSeen:   time.Now().Unix(),
				})
				break
			}

			updates = append(updates, update)
		}
	}

	if len(updates) > 0 {
		m.ctx.Store.UpsertHosts(updates)
	}
}

func boolPtr(b bool) *bool {
	return &b
}

// GuestFor returns a guest reference map for a device identified by MAC or IP address
// Returns as map[string]interface{} to avoid import cycles with other modules
func (m *Module) GuestFor(macOrIP string) (any, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.inventory == nil {
		return nil, false
	}

	// Search by IP first
	for i := range m.inventory.Guests {
		g := &m.inventory.Guests[i]
		for _, ip := range g.IPs {
			if ip == macOrIP {
				return map[string]interface{}{
					"vmid": g.VMID,
					"type": g.Type,
					"node": g.Node,
					"name": g.Name,
					"os":   g.OS,
				}, true
			}
		}
	}

	// Search by MAC
	for i := range m.inventory.Guests {
		g := &m.inventory.Guests[i]
		for _, mac := range g.MACs {
			if strings.EqualFold(mac, macOrIP) {
				return map[string]interface{}{
					"vmid": g.VMID,
					"type": g.Type,
					"node": g.Node,
					"name": g.Name,
					"os":   g.OS,
				}, true
			}
		}
	}

	return nil, false
}

// API routes

func (m *Module) apiInventory(r *core.Req) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inventory == nil {
		return map[string]interface{}{"nodes": []Node{}, "guests": []Guest{}}, nil
	}
	return map[string]interface{}{"nodes": m.inventory.Nodes, "guests": m.inventory.Guests, "last_at": m.inventory.LastAt, "errors": m.inventory.Errors}, nil
}

func (m *Module) apiStatus(r *core.Req) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	status := map[string]interface{}{
		"last_poll":   m.lastPollTime,
		"error":       m.lastPollError,
		"node_count":  0,
		"guest_count": 0,
	}

	if m.inventory != nil {
		status["node_count"] = len(m.inventory.Nodes)
		status["guest_count"] = len(m.inventory.Guests)
		// A node that could not be polled is the first thing to know.
		status["errors"] = m.inventory.Errors
		status["hosts"] = core.Strs(m.ctx.Settings(), "hosts")
	}
	status["write_notes"] = core.Bool(m.ctx.Settings(), "write_notes", false)
	status["notes"] = map[string]any{"written": m.notesWritten, "skipped": m.notesSkippedN, "failed": m.notesFailed, "last_error": m.notesLastErr, "at": m.notesAt}
	status["sockets"] = map[string]any{"on": core.Bool(m.ctx.Settings(), "probe_sockets", false), "edges": len(m.sockEdges), "notes": m.sockNotes, "at": m.sockAt}

	return status, nil
}

func (m *Module) apiPoll(r *core.Req) (any, error) {
	go m.doPoll()
	return map[string]bool{"polling": true}, nil
}

func (m *Module) apiGuest(r *core.Req) (any, error) {
	vmid := r.Q("vmid", "")
	node := r.Q("node", "")

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.inventory == nil {
		return nil, errors.New("no inventory")
	}

	for _, g := range m.inventory.Guests {
		if fmt.Sprintf("%d", g.VMID) == vmid && g.Node == node {
			return g, nil
		}
	}

	return nil, errors.New("guest not found")
}

func (m *Module) apiNotesPreview(r *core.Req) (any, error) {
	vmid := r.Q("vmid", "")
	node := r.Q("node", "")

	m.mu.Lock()
	guest, found := m.findGuest(vmid, node)
	m.mu.Unlock()

	if !found {
		return nil, errors.New("guest not found")
	}

	block := m.buildNotesBlock(guest)
	return map[string]string{"block": block}, nil
}

func (m *Module) apiNotesWrite(r *core.Req) (any, error) {
	if !core.Bool(m.ctx.Settings(), "write_notes", false) {
		return nil, errors.New("notes writing is disabled: turn on write notes under Settings \u203a proxmox")
	}
	var req struct {
		VMID *int   `json:"vmid"`
		Node string `json:"node"`
		All  bool   `json:"all"`
	}
	_ = r.Decode(&req)
	guests := m.snapshotGuests()
	if len(guests) == 0 {
		return nil, errors.New("no inventory yet; poll first")
	}
	if req.VMID != nil {
		for i := range guests {
			if guests[i].VMID == *req.VMID && (req.Node == "" || guests[i].Node == req.Node) {
				if skip, why := m.notesSkipped(guests[i]); skip {
					return nil, fmt.Errorf("not written: %s", why)
				}
				if err := m.writeGuestNotes(&guests[i]); err != nil {
					return nil, err
				}
				m.mu.Lock()
				m.notesWritten++
				m.mu.Unlock()
				return map[string]any{"written": 1, "vmid": *req.VMID}, nil
			}
		}
		return nil, errors.New("guest not found")
	}
	// Everything, in the background; the status card reports progress.
	go m.writeAllNotes(guests, true)
	return map[string]any{"queued": len(guests)}, nil
}

// notesSkipped says whether a guest is kept out of the write-back, and why.
func (m *Module) notesSkipped(g Guest) (bool, string) {
	for _, t := range g.Tags {
		if strings.EqualFold(t, "flowsight:off") {
			return true, "tagged flowsight:off"
		}
	}
	for _, v := range core.Strs(m.ctx.Settings(), "exclude_vmids") {
		if strings.TrimSpace(v) == fmt.Sprintf("%d", g.VMID) {
			return true, "listed in exclude_vmids"
		}
	}
	return false, ""
}

// writeAllNotes writes the block for every eligible guest whose content
// changed since the last write (the hash is kept in the KV store), one
// guest at a time. force rewrites unchanged ones too.
func (m *Module) writeAllNotes(guests []Guest, force bool) {
	if !core.Bool(m.ctx.Settings(), "write_notes", false) {
		return
	}
	m.notesMu.Lock()
	defer m.notesMu.Unlock()
	hashes := map[string]string{}
	_ = m.ctx.Store.KVGet("proxmox.notes.hashes", &hashes)
	written, skipped, failed := 0, 0, 0
	var lastErr string
	for i := range guests {
		g := guests[i]
		if skip, _ := m.notesSkipped(g); skip {
			skipped++
			continue
		}
		key := fmt.Sprintf("%s/%s/%d", g.Node, g.Type, g.VMID)
		block := m.buildNotesBlock(g)
		// The timestamp line changes every time; hash the block without it.
		sum := sha256.Sum256([]byte(stripUpdatedLine(block)))
		h := hex.EncodeToString(sum[:8])
		if !force && hashes[key] == h {
			skipped++
			continue
		}
		if err := m.writeGuestNotes(&g); err != nil {
			failed++
			lastErr = fmt.Sprintf("%s: %v", g.Name, err)
			continue
		}
		hashes[key] = h
		written++
	}
	_ = m.ctx.Store.KVSet("proxmox.notes.hashes", hashes)
	m.mu.Lock()
	m.notesWritten, m.notesSkippedN, m.notesFailed, m.notesLastErr, m.notesAt = written, skipped, failed, lastErr, time.Now().Unix()
	m.mu.Unlock()
}

// stripUpdatedLine removes the "Updated ... by FlowSight" line so that a
// block whose facts did not change hashes the same.
func stripUpdatedLine(block string) string {
	var out []string
	for _, l := range strings.Split(block, "\n") {
		if strings.HasPrefix(l, "_Updated ") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func (m *Module) findGuest(vmidStr, node string) (Guest, bool) {
	if m.inventory == nil {
		return Guest{}, false
	}
	for _, g := range m.inventory.Guests {
		if fmt.Sprintf("%d", g.VMID) == vmidStr && g.Node == node {
			return g, true
		}
	}
	return Guest{}, false
}

// notesFacts is everything the block says, gathered before rendering so
// the renderer is pure and testable.
type notesFacts struct {
	Guest      Guest
	Device     string // FlowSight's name for it
	Class      string
	Zone       string
	Vendor     string
	FirstSeen  int64
	LastSeen   int64
	BytesIn    int64
	BytesOut   int64
	OSGuess    string
	OSConf     float64
	OpenPorts  []string
	GatewayURL string
	Now        time.Time
}

// gatherNotesFacts reads the device table, the traffic rollup and the latest
// scan for the guest's addresses.
func (m *Module) gatherNotesFacts(g Guest) notesFacts {
	f := notesFacts{Guest: g, Now: time.Now()}
	if m.ctx == nil {
		return f
	}
	f.GatewayURL = strings.TrimRight(core.Str(m.ctx.Settings(), "gateway_url", ""), "/")
	if m.ctx.Store == nil {
		return f
	}
	for _, mac := range g.MACs {
		row, err := m.ctx.Store.Row(`SELECT hostname, class, zone, vendor, first_seen, last_seen FROM devices WHERE lower(mac)=?`, strings.ToLower(mac))
		if err != nil || row == nil {
			continue
		}
		f.Device, _ = row["hostname"].(string)
		f.Class, _ = row["class"].(string)
		f.Zone, _ = row["zone"].(string)
		f.Vendor, _ = row["vendor"].(string)
		f.FirstSeen = toInt64(row["first_seen"])
		f.LastSeen = toInt64(row["last_seen"])
		break
	}
	if len(g.IPs) > 0 {
		ph := strings.TrimSuffix(strings.Repeat("?,", len(g.IPs)), ",")
		args := []any{time.Now().Add(-24 * time.Hour).Unix()}
		for _, ip := range g.IPs {
			args = append(args, ip)
		}
		if row, err := m.ctx.Store.Row(`SELECT SUM(bytes_in) AS bi, SUM(bytes_out) AS bo FROM rollup_app WHERE bucket >= ? AND src_ip IN (`+ph+`)`, args...); err == nil && row != nil {
			f.BytesIn, f.BytesOut = toInt64(row["bi"]), toInt64(row["bo"])
		}
		args = args[1:]
		if row, err := m.ctx.Store.Row(`SELECT result_json FROM scans WHERE ip IN (`+ph+`) AND finished IS NOT NULL ORDER BY started DESC LIMIT 1`, args...); err == nil && row != nil {
			if js, _ := row["result_json"].(string); js != "" {
				var res struct {
					OpenPorts []struct {
						Port    int    `json:"port"`
						Service string `json:"service"`
					} `json:"open_ports"`
					OSGuesses []struct {
						OS         string  `json:"os"`
						Confidence float64 `json:"confidence"`
					} `json:"os_guesses"`
				}
				if json.Unmarshal([]byte(js), &res) == nil {
					if len(res.OSGuesses) > 0 {
						f.OSGuess, f.OSConf = res.OSGuesses[0].OS, res.OSGuesses[0].Confidence
					}
					for _, p := range res.OpenPorts {
						if p.Service != "" {
							f.OpenPorts = append(f.OpenPorts, fmt.Sprintf("%d %s", p.Port, p.Service))
						} else {
							f.OpenPorts = append(f.OpenPorts, fmt.Sprintf("%d", p.Port))
						}
					}
				}
			}
		}
	}
	return f
}

func toInt64(v any) int64 {
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

// mdCell makes a string safe inside a Markdown table cell in Proxmox Notes:
// no pipes, no newlines, no HTML, no backticks, and never the marker text.
func mdCell(v string) string {
	r := strings.NewReplacer("|", "\\|", "\n", " ", "\r", " ", "<", "&lt;", ">", "&gt;", "`", "'", "flowsight:begin", "flowsight begin", "flowsight:end", "flowsight end")
	v = r.Replace(v)
	if len(v) > 300 {
		v = v[:300] + "\u2026"
	}
	return v
}

func humanBytes(b int64) string {
	const k = 1024
	switch {
	case b >= k*k*k:
		return fmt.Sprintf("%.1f GB", float64(b)/(k*k*k))
	case b >= k*k:
		return fmt.Sprintf("%.1f MB", float64(b)/(k*k))
	case b >= k:
		return fmt.Sprintf("%.0f KB", float64(b)/k)
	}
	return fmt.Sprintf("%d B", b)
}

// renderNotesBlock is the Markdown Proxmox shows between the markers.
func renderNotesBlock(f notesFacts) string {
	g := f.Guest
	var b bytes.Buffer
	b.WriteString("<!-- flowsight:begin -->\n")
	name := f.Device
	if name == "" {
		name = g.Name
	}
	b.WriteString(fmt.Sprintf("### FlowSight: %s\n\n", mdCell(name)))
	b.WriteString("| | |\n|---|---|\n")
	// Names, hostnames and banners came from devices and their DHCP
	// requests; they must not be able to close the table, inject HTML or
	// break out of the block.
	row := func(k, v string) {
		v = mdCell(v)
		if strings.TrimSpace(v) != "" {
			b.WriteString(fmt.Sprintf("| %s | %s |\n", k, v))
		}
	}
	kind := g.Type
	if kind == "qemu" {
		kind = "VM"
	} else if kind == "lxc" {
		kind = "container"
	}
	row("Guest", fmt.Sprintf("%s %d on %s", kind, g.VMID, g.Node))
	if f.Class != "" || f.Zone != "" {
		row("Class / zone", strings.TrimSpace(strings.Trim(f.Class+" / "+f.Zone, " /")))
	}
	row("Addresses", strings.Join(g.IPs, ", "))
	row("Hardware", strings.Join(g.MACs, ", "))
	row("Maker", f.Vendor)
	if g.OS != "" {
		row("OS (agent)", g.OS)
	}
	if g.Hostname != "" && g.Hostname != g.Name {
		row("Hostname", g.Hostname)
	}
	if f.OSGuess != "" {
		row("Identified as", fmt.Sprintf("%s (%.0f%%)", f.OSGuess, f.OSConf*100))
	}
	if len(f.OpenPorts) > 0 {
		row("Open ports", strings.Join(f.OpenPorts, ", "))
	}
	if f.BytesIn+f.BytesOut > 0 {
		row("Traffic, last 24 h", fmt.Sprintf("%s down, %s up", humanBytes(f.BytesIn), humanBytes(f.BytesOut)))
	}
	if f.FirstSeen > 0 {
		row("First seen", time.Unix(f.FirstSeen, 0).UTC().Format("2006-01-02"))
	}
	if f.LastSeen > 0 {
		row("Last seen", time.Unix(f.LastSeen, 0).UTC().Format("2006-01-02 15:04 UTC"))
	}
	if g.AgentState != "" {
		row("Guest agent", g.AgentState)
	}
	if f.GatewayURL != "" && len(g.IPs) > 0 {
		row("In FlowSight", fmt.Sprintf("%s/flowsight.php?page=hosts#host/%s", f.GatewayURL, g.IPs[0]))
	}
	b.WriteString(fmt.Sprintf("\n_Updated %s by FlowSight. Edit outside the markers; this block is rewritten._\n", f.Now.UTC().Format("2006-01-02 15:04 UTC")))
	b.WriteString("<!-- flowsight:end -->\n")
	return b.String()
}

func (m *Module) buildNotesBlock(guest Guest) string {
	return renderNotesBlock(m.gatherNotesFacts(guest))
}

func (m *Module) writeGuestNotes(guest *Guest) error {
	hosts := core.Strs(m.ctx.Settings(), "hosts")
	if len(hosts) == 0 {
		return errors.New("no hosts configured")
	}

	hostURL := guest.HostURL
	if hostURL == "" {
		hostURL = hosts[0]
	}
	newBlock := m.buildNotesBlock(*guest)

	// Get current config with digest
	configBody, err := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/%s/%d/config", guest.Node, guest.Type, guest.VMID))
	if err != nil {
		return fmt.Errorf("get config: %w", err)
	}

	var configResp struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(configBody, &configResp); err != nil {
		return err
	}

	digest, _ := configResp.Data["digest"].(string)
	currentDesc, _ := configResp.Data["description"].(string)

	// Merge notes block
	newDesc := m.mergeNotesBlock(currentDesc, newBlock)

	// Write back
	form := map[string]string{
		"description": newDesc,
	}
	if digest != "" {
		form["digest"] = digest
	}

	_, err = m.put(hostURL, fmt.Sprintf("/api2/json/nodes/%s/%s/%d/config", guest.Node, guest.Type, guest.VMID), form)
	if err != nil {
		// Retry once on digest mismatch
		if strings.Contains(err.Error(), "digest") {
			configBody, _ := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/%s/%d/config", guest.Node, guest.Type, guest.VMID))
			json.Unmarshal(configBody, &configResp)
			digest, _ = configResp.Data["digest"].(string)
			currentDesc, _ = configResp.Data["description"].(string)
			newDesc = m.mergeNotesBlock(currentDesc, newBlock)
			form["description"] = newDesc
			form["digest"] = digest
			_, err = m.put(hostURL, fmt.Sprintf("/api2/json/nodes/%s/%s/%d/config", guest.Node, guest.Type, guest.VMID), form)
		}
		if err != nil {
			return err
		}
	}

	guest.NotesSyncedAt = time.Now().Unix()
	return nil
}

func (m *Module) mergeNotesBlock(currentDesc, newBlock string) string {
	const begin = "<!-- flowsight:begin -->"
	const end = "<!-- flowsight:end -->"

	startIdx := strings.Index(currentDesc, begin)
	endIdx := strings.Index(currentDesc, end)

	if startIdx == -1 || endIdx == -1 {
		// No existing block, append
		if currentDesc != "" && !strings.HasSuffix(currentDesc, "\n") {
			currentDesc += "\n"
		}
		return currentDesc + "\n" + newBlock
	}

	// Replace the block
	before := currentDesc[:startIdx]
	after := currentDesc[endIdx+len(end):]
	return before + newBlock + after
}

func readAllLimited(resp *http.Response) ([]byte, error) {
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}
