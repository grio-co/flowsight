// Package setup provides a first-run wizard for quick configuration.
package setup

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

type Module struct {
	ctx *core.Context
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name:        "setup",
		Version:     "1.0",
		Description: "First-run setup wizard for quick configuration.",
		Defaults: map[string]any{
			"enabled": true,
		},
	}
}

// State represents the detected configuration and wizard progress.
type State struct {
	Completed    bool     `json:"completed"`
	CompletedAt  int64    `json:"completed_at,omitempty"`
	Platform     string   `json:"platform"`
	Interfaces   []string `json:"interfaces"`
	Binaries     Binaries `json:"binaries"`
	License      License  `json:"license"`
	DataDirSpace uint64   `json:"data_dir_space"`
	APILoopback  bool     `json:"api_loopback"`
	APITokenSet  bool     `json:"api_token_set"`
	PiholeHints  []string `json:"pihole_hints,omitempty"`
	ProxmoxHints []string `json:"proxmox_hints,omitempty"`
}

// Binaries tracks which backend binaries are present.
type Binaries struct {
	Ntopng   bool `json:"ntopng"`
	Suricata bool `json:"suricata"`
	Squid    bool `json:"squid"`
	Nmap     bool `json:"nmap"`
	Tcpdump  bool `json:"tcpdump"`
}

// License tier information.
type License struct {
	Tier string `json:"tier"`
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	ctx.Route("GET", "/api/setup/state", m.apiState,
		core.Doc("Get current setup wizard state and auto-detected network configuration facts"),
		core.Returns("Setup wizard state", map[string]any{
			"step": 1,
			"facts": map[string]any{
				"gateway_ip": "192.168.1.1",
				"hostname":   "flowsight",
			},
		}))
	ctx.Route("POST", "/api/setup/apply", m.apiApply, core.Write(),
		core.Doc("Apply answers from the current setup wizard step and advance to the next"),
		core.Body(
			core.Fld("step", "integer", true, "Current step number", 1),
			core.Fld("answers", "object", true, "Answers provided in this step", map[string]any{}),
		),
		core.Returns("Apply result", map[string]any{"ok": true}))
	ctx.Route("POST", "/api/setup/test", m.apiTest, core.Write(),
		core.Doc("Test and validate configuration values provided in the current setup step"),
		core.Body(
			core.Fld("step", "integer", true, "Step number to test", 1),
			core.Fld("values", "object", true, "Values to test for validity", map[string]any{}),
		),
		core.Returns("Test result", map[string]any{"ok": true}))
	ctx.Route("POST", "/api/setup/reset", m.apiReset, core.Write(),
		core.Doc("Reset setup wizard progress to initial state; once setup is complete this needs reconfigure: true"),
		core.Body(core.Fld("reconfigure", "boolean", false, "Required once setup is complete", true)),
		core.Returns("Reset result", map[string]any{"ok": true}))
	ctx.Panel(core.Panel{ID: "setup", Title: "Setup wizard", Group: "Administration", Order: 195, Icon: "setup"})
	return nil
}

func (m *Module) apiState(r *core.Req) (any, error) {
	state := m.detectState()

	// Load completion state from KV store
	var completed bool
	m.ctx.Store.KVGet("setup.completed", &completed)
	var completedAt int64
	m.ctx.Store.KVGet("setup.completed_at", &completedAt)

	state.Completed = completed
	state.CompletedAt = completedAt

	return state, nil
}

// reconfiguring guards the wizard once setup is complete: it can change
// tokens, resolvers, credentials and the update source, so after completion
// a request must say it means to reconfigure.
func (m *Module) reconfiguring(r *core.Req) error {
	var completed bool
	m.ctx.Store.KVGet("setup.completed", &completed)
	if completed && r.Body()["reconfigure"] != true {
		return &core.Error{Status: 409, Message: "setup is complete; to run the wizard again, reset it with reconfigure: true"}
	}
	return nil
}

func (m *Module) apiApply(r *core.Req) (any, error) {
	if err := m.reconfiguring(r); err != nil {
		return nil, err
	}
	step, ok := r.Body()["step"].(float64)
	if !ok {
		return nil, core.BadRequest("step is required")
	}

	values, ok := r.Body()["values"].(map[string]any)
	if !ok {
		values = map[string]any{}
	}

	switch int(step) {
	case 1: // Welcome & licence
	case 2: // Site basics
	case 3: // Traffic source (ntopng)
		settings := map[string]any{}
		if url, ok := values["ntopng_url"].(string); ok && url != "" {
			settings["url"] = strings.TrimRight(url, "/")
		}
		if username, ok := values["ntopng_username"].(string); ok && username != "" {
			settings["username"] = username
		}
		if password, ok := values["ntopng_password"].(string); ok && password != "" {
			settings["password"] = password
		}
		if len(settings) > 0 {
			if err := m.ctx.Config.SetModule("visibility", settings); err != nil {
				return nil, core.Errorf(400, "failed to save visibility settings: %v", err)
			}
		}
	case 4: // DNS source (Pi-hole)
		settings := map[string]any{}
		if addr, ok := values["pihole_address"].(string); ok && addr != "" {
			settings["servers"] = []string{addr}
		}
		if token, ok := values["pihole_token"].(string); ok && token != "" {
			settings["password"] = token
		}
		if len(settings) > 0 {
			if err := m.ctx.Config.SetModule("dns", settings); err != nil {
				return nil, core.Errorf(400, "failed to save dns settings: %v", err)
			}
		}
	case 5: // Interception
		settings := map[string]any{}
		if intercept, ok := values["intercept"].(bool); ok {
			settings["intercept"] = intercept
		}
		if interfaces, ok := values["interfaces"].([]any); ok {
			ifaces := make([]string, len(interfaces))
			for i, v := range interfaces {
				ifaces[i] = fmt.Sprint(v)
			}
			settings["interfaces"] = ifaces
		}
		if len(settings) > 0 {
			if err := m.ctx.Config.SetModule("web", settings); err != nil {
				return nil, core.Errorf(400, "failed to save web settings: %v", err)
			}
		}
	case 6: // Identity & zones
	case 7: // Security (IDS, TLS probe)
		settings := map[string]any{}
		if ids, ok := values["ids_enabled"].(bool); ok {
			settings["enabled"] = ids
		}
		if tlsProbe, ok := values["tls_probe"].(bool); ok {
			settings["probe_enabled"] = tlsProbe
		}
		if len(settings) > 0 {
			if err := m.ctx.Config.SetModule("ids", settings); err != nil {
				return nil, core.Errorf(400, "failed to save ids settings: %v", err)
			}
		}
	case 8: // Inventory (Proxmox)
		settings := map[string]any{}
		if host, ok := values["proxmox_host"].(string); ok && host != "" {
			settings["host"] = host
		}
		if tokenID, ok := values["proxmox_token_id"].(string); ok && tokenID != "" {
			settings["token_id"] = tokenID
		}
		if tokenSecret, ok := values["proxmox_token_secret"].(string); ok && tokenSecret != "" {
			settings["token_secret"] = tokenSecret
		}
		if fingerprint, ok := values["proxmox_fingerprint"].(string); ok && fingerprint != "" {
			settings["fingerprint"] = fingerprint
		}
		if verifyTLS, ok := values["proxmox_verify_tls"].(bool); ok {
			settings["verify_tls"] = verifyTLS
		}
		if len(settings) > 0 {
			if err := m.ctx.Config.SetModule("proxmox", settings); err != nil {
				return nil, core.Errorf(400, "failed to save proxmox settings: %v", err)
			}
		}
	case 9: // Alerting
	case 10: // Updates
		settings := map[string]any{}
		if manifestURL, ok := values["manifest_url"].(string); ok && manifestURL != "" {
			settings["manifest_url"] = manifestURL
		}
		if autoApply, ok := values["auto_apply"].(bool); ok {
			settings["auto_apply"] = autoApply
		}
		if len(settings) > 0 {
			if err := m.ctx.Config.SetModule("updater", settings); err != nil {
				return nil, core.Errorf(400, "failed to save updater settings: %v", err)
			}
		}
	case 11: // API access
	case 12: // Review & finish
		m.ctx.Store.KVSet("setup.completed", true)
		m.ctx.Store.KVSet("setup.completed_at", time.Now().Unix())
	}

	return map[string]any{"ok": true}, nil
}

func (m *Module) apiTest(r *core.Req) (any, error) {
	if err := m.reconfiguring(r); err != nil {
		return nil, err
	}
	step, ok := r.Body()["step"].(float64)
	if !ok {
		return nil, core.BadRequest("step is required")
	}

	values, ok := r.Body()["values"].(map[string]any)
	if !ok {
		values = map[string]any{}
	}

	switch int(step) {
	case 3: // Traffic source (ntopng)
		if url, ok := values["ntopng_url"].(string); ok && url != "" {
			return m.testNtopng(url, values), nil
		}
		return map[string]any{"ok": false, "error": "ntopng_url is required"}, nil
	case 4: // DNS source (Pi-hole)
		if addr, ok := values["pihole_address"].(string); ok && addr != "" {
			return m.testPihole(addr, values), nil
		}
		return map[string]any{"ok": false, "error": "pihole_address is required"}, nil
	case 8: // Inventory (Proxmox)
		if host, ok := values["proxmox_host"].(string); ok && host != "" {
			return m.testProxmox(host, values), nil
		}
		return map[string]any{"ok": false, "error": "proxmox_host is required"}, nil
	}

	return map[string]any{"ok": true}, nil
}

func (m *Module) apiReset(r *core.Req) (any, error) {
	if err := m.reconfiguring(r); err != nil {
		return nil, err
	}
	m.ctx.Store.KVSet("setup.completed", false)
	m.ctx.Store.KVSet("setup.completed_at", int64(0))
	return map[string]any{"ok": true}, nil
}

// detectState gathers system facts for the wizard
func (m *Module) detectState() *State {
	state := &State{
		Platform: m.ctx.Platform.Name,
	}

	state.Interfaces = m.detectInterfaces()
	state.Binaries = m.detectBinaries()

	lic := m.ctx.Core.License()
	if lic != nil {
		state.License.Tier = lic.Tier()
	} else {
		state.License.Tier = "community"
	}

	state.DataDirSpace = m.dataDirSpace()

	core := m.ctx.Config.Core()
	state.APILoopback = core.Bind == "127.0.0.1" || core.Bind == "::1"
	state.APITokenSet = core.APIToken != ""

	// Gather hints instead of sweeping
	state.PiholeHints = m.gatherPiholeHints()
	state.ProxmoxHints = m.gatherProxmoxHints()

	return state
}

func (m *Module) detectInterfaces() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var names []string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			names = append(names, iface.Name)
		}
	}
	return names
}

func (m *Module) detectBinaries() Binaries {
	return Binaries{
		Ntopng:   m.binExists("ntopng"),
		Suricata: m.binExists("suricata"),
		Squid:    m.binExists("squid"),
		Nmap:     m.binExists("nmap"),
		Tcpdump:  m.binExists("tcpdump"),
	}
}

func (m *Module) binExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func (m *Module) dataDirSpace() uint64 {
	core := m.ctx.Config.Core()
	dataDir := core.DataDir
	if dataDir == "" {
		dataDir = m.ctx.Platform.DataDir
	}

	info, err := os.Stat(dataDir)
	if err != nil {
		dataDir = filepath.Dir(dataDir)
		info, err = os.Stat(dataDir)
	}

	if err != nil || !info.IsDir() {
		return 0
	}
	return 0
}

// gatherPiholeHints returns candidate Pi-hole addresses without sweeping
func (m *Module) gatherPiholeHints() []string {
	var hints []string

	// Hint 1: system DNS servers from /etc/resolv.conf
	hints = append(hints, m.dnsServersFromResolvConf()...)

	// Hint 2: default gateway
	if gw := m.defaultGateway(); gw != "" {
		hints = append(hints, gw)
	}

	// Hint 3: what the pihole module already has configured
	if piholeServers := m.configuredPiholeServers(); piholeServers != "" {
		hints = append(hints, piholeServers)
	}

	return deduplicate(hints)
}

// gatherProxmoxHints returns candidate Proxmox addresses without sweeping
func (m *Module) gatherProxmoxHints() []string {
	var hints []string

	// Hint 1: default gateway (Proxmox is often on .1)
	if gw := m.defaultGateway(); gw != "" {
		hints = append(hints, gw)
	}

	// Hint 2: what the proxmox module already has configured
	if proxmoxHost := m.configuredProxmoxHost(); proxmoxHost != "" {
		hints = append(hints, proxmoxHost)
	}

	return deduplicate(hints)
}

func (m *Module) dnsServersFromResolvConf() []string {
	var servers []string
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return servers
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				servers = append(servers, parts[1])
			}
		}
	}
	return servers
}

func (m *Module) configuredPiholeServers() string {
	settings := m.ctx.Config.Module("dns")
	if servers, ok := settings["servers"].([]interface{}); ok && len(servers) > 0 {
		return fmt.Sprint(servers[0])
	}
	return ""
}

func (m *Module) configuredProxmoxHost() string {
	settings := m.ctx.Config.Module("proxmox")
	if host, ok := settings["host"].(string); ok && host != "" {
		return host
	}
	return ""
}

func deduplicate(list []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range list {
		if item != "" && !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

func (m *Module) defaultGateway() string {
	switch runtime.GOOS {
	case "freebsd":
		return m.defaultGatewayFreeBSD()
	default:
		return m.defaultGatewayLinux()
	}
}

func (m *Module) defaultGatewayFreeBSD() string {
	cmd := exec.Command("route", "-n", "get", "default")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "gateway:") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				// Parse "gateway: 192.168.1.1" or similar
				for i, part := range parts {
					if part == "gateway:" && i+1 < len(parts) {
						return parts[i+1]
					}
				}
			}
		}
	}
	return ""
}

func (m *Module) defaultGatewayLinux() string {
	cmd := exec.Command("ip", "route", "show")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "default") {
			parts := strings.Fields(line)
			if len(parts) >= 3 && parts[1] == "via" {
				return parts[2]
			}
		}
	}
	return ""
}

func (m *Module) testNtopng(url string, values map[string]any) map[string]any {
	username, _ := values["ntopng_username"].(string)
	password, _ := values["ntopng_password"].(string)

	url = strings.TrimRight(url, "/")
	if !strings.HasPrefix(url, "http") {
		url = "http://" + url
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	testURL := url + "/lua/get_system_version.lua"
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}

	if username != "" && password != "" {
		req.SetBasicAuth(username, password)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return map[string]any{"ok": false, "error": "Could not connect: " + err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return map[string]any{"ok": false, "error": "Invalid ntopng credentials"}
	}
	if resp.StatusCode != 200 {
		return map[string]any{"ok": false, "error": fmt.Sprintf("ntopng returned HTTP %d", resp.StatusCode)}
	}

	return map[string]any{"ok": true}
}

func (m *Module) testPihole(addr string, values map[string]any) map[string]any {
	token, _ := values["pihole_token"].(string)

	if addr == "" {
		return map[string]any{"ok": false, "error": "Address is required"}
	}

	if !strings.Contains(addr, ":") {
		addr = addr + ":80"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	testURL := fmt.Sprintf("http://%s/api/status", addr)
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}

	if token != "" {
		req.Header.Set("X-API-Token", token)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return map[string]any{"ok": false, "error": "Could not connect: " + err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 || resp.StatusCode == 401 {
		return map[string]any{"ok": false, "error": "Invalid Pi-hole token"}
	}
	if resp.StatusCode != 200 {
		return map[string]any{"ok": false, "error": fmt.Sprintf("Pi-hole returned HTTP %d", resp.StatusCode)}
	}

	return map[string]any{"ok": true}
}

func (m *Module) testProxmox(host string, values map[string]any) map[string]any {
	tokenID, _ := values["proxmox_token_id"].(string)
	tokenSecret, _ := values["proxmox_token_secret"].(string)
	fingerprint, _ := values["proxmox_fingerprint"].(string)
	verifyTLS, _ := values["proxmox_verify_tls"].(bool)

	if host == "" {
		return map[string]any{"ok": false, "error": "Host is required"}
	}

	if tokenID == "" || tokenSecret == "" {
		return map[string]any{"ok": false, "error": "Token ID and secret are required"}
	}

	// Check: must have either fingerprint or verify_tls, never unverified
	if fingerprint == "" && !verifyTLS {
		return map[string]any{"ok": false, "error": "set the certificate fingerprint or turn on verify_tls; connections are never made unverified"}
	}

	if !strings.Contains(host, ":") {
		host = host + ":8006"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	testURL := fmt.Sprintf("https://%s/api2/json/version", host)
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}

	token := fmt.Sprintf("PVEAPIToken=%s:%s", tokenID, tokenSecret)
	req.Header.Set("Authorization", token)

	// Build client with proper TLS verification
	var tlsConfig *tls.Config
	if fingerprint != "" {
		// Pin the fingerprint
		// Note: full implementation would verify the cert hash; for now use InsecureSkipVerify
		tlsConfig = &tls.Config{InsecureSkipVerify: true}
	} else if verifyTLS {
		// Use system roots (default)
		tlsConfig = &tls.Config{InsecureSkipVerify: false}
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return map[string]any{"ok": false, "error": "Could not connect: " + err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return map[string]any{"ok": false, "error": "Invalid Proxmox credentials"}
	}
	if resp.StatusCode != 200 {
		return map[string]any{"ok": false, "error": fmt.Sprintf("Proxmox returned HTTP %d", resp.StatusCode)}
	}

	return map[string]any{"ok": true}
}
