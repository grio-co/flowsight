// Package updater implements in-line self-update for the daemon.
package updater

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

// PublicKeyBase64 holds the base64-encoded ed25519 public key that release
// assets are verified against. Release builds set it with
//
//	-ldflags "-X github.com/grioghar/flowsight/internal/modules/updater.PublicKeyBase64=<key>"
//
// (see packaging/release/release.sh). A build without it refuses to apply
// updates, so a developer build can never be replaced by an unsigned binary.
var PublicKeyBase64 = ""

// Module checks for and applies updates to the daemon.
type Module struct {
	ctx           *core.Context
	manifestURL   string
	checkInterval time.Duration
	autoApply     bool
	client        *http.Client

	latest    *Manifest
	lastCheck time.Time
	noRelease bool
	lastError string
}

// Manifest describes an available release.
type Manifest struct {
	Version   string  `json:"version"`
	Channel   string  `json:"channel"`
	Published string  `json:"published"`
	Notes     string  `json:"notes"`
	Assets    []Asset `json:"assets"`
}

// Asset describes one downloadable binary.
type Asset struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Sig    string `json:"sig"` // base64 ed25519 signature over the sha256 hex
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name:        "updater",
		Version:     "1.0",
		Description: "In-line self-update with manifest, signature and sha256 verification.",
		Defaults: map[string]any{
			"enabled":      true,
			"channel":      "stable",
			"manifest_url": "https://github.com/grioghar/flowsight/releases/latest/download/manifest.json",
			"check_hours":  6,
			"auto_apply":   false,
		},
		Schema: []core.SettingField{
			{Key: "enabled", Label: "Enabled", Type: "bool"},
			{Key: "channel", Label: "Release channel", Type: "choice",
				Choices: []string{"stable", "beta"}},
			{Key: "manifest_url", Label: "Manifest URL", Type: "string"},
			{Key: "check_hours", Label: "Check interval (hours)", Type: "int"},
			{Key: "auto_apply", Label: "Apply updates automatically", Type: "bool"},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	// The manifest is small but a release binary is tens of megabytes over
	// whatever link the firewall has; a short overall timeout would cut a
	// slow download in half. Bound the connect and the idle read instead.
	m.client = &http.Client{
		Timeout: 30 * time.Minute,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       90 * time.Second,
		},
	}

	settings := ctx.Settings()
	m.manifestURL = core.Str(settings, "manifest_url",
		"https://github.com/grioghar/flowsight/releases/latest/download/manifest.json")
	m.checkInterval = time.Duration(core.Int(settings, "check_hours", 6)) * time.Hour
	m.autoApply = core.Bool(settings, "auto_apply", false)

	// Schedule periodic checks
	ctx.Every("check", m.checkInterval, m.checkForUpdates, core.Delayed())

	// API routes
	ctx.Route("GET", "/api/updater/status", m.apiStatus,
		core.Doc("Get current application version, latest available version and update readiness status"),
		core.Returns("Update status", map[string]any{
			"current_version": "0.9.8r202609220604",
			"latest_version":  "0.9.8r202609220605",
			"available":       true,
			"last_check":      1790376243,
		}))
	ctx.Route("POST", "/api/updater/check", m.apiCheck, core.Write(),
		core.Doc("Trigger an immediate check for newer application versions from the update server"),
		core.Body(),
		core.Returns("Check result", map[string]any{
			"ok":          true,
			"new_version": "0.9.8r202609220605",
		}))
	ctx.Route("POST", "/api/updater/apply", m.apiApply, core.Write(),
		core.Doc("Download and apply the latest available update to the application"),
		core.Body(),
		core.Returns("Apply result", map[string]any{"ok": true}))
	ctx.Route("POST", "/api/updater/rollback", m.apiRollback, core.Write(),
		core.Doc("Revert to the previous application version if current update has issues"),
		core.Body(),
		core.Returns("Rollback result", map[string]any{"ok": true}))
	// Panel
	ctx.Panel(core.Panel{
		ID:    "updates",
		Title: "Updates",
		Group: "Administration",
		Order: 240,
		Icon:  "updates",
	})

	return nil
}

func (m *Module) Health() core.Health {
	if m.lastError != "" {
		return core.Health{OK: false, Detail: m.lastError}
	}
	if m.lastCheck.IsZero() {
		return core.Health{OK: true, Detail: "checking for updates"}
	}
	if m.noRelease {
		return core.Health{OK: true, Detail: "no release published at the manifest URL yet"}
	}
	return core.Health{OK: true, Detail: fmt.Sprintf("last checked %s ago",
		time.Since(m.lastCheck).Round(time.Second))}
}

func (m *Module) checkForUpdates() error {
	manifest, err := m.fetchManifest()
	if err != nil {
		// No release published yet is the normal state of a development
		// install, not a fault.
		if strings.Contains(err.Error(), "404") {
			m.lastError = ""
			m.lastCheck = time.Now()
			m.noRelease = true
			return nil
		}
		m.lastError = fmt.Sprintf("manifest fetch failed: %v", err)
		return nil
	}
	m.noRelease = false

	m.latest = manifest
	m.lastCheck = time.Now()
	m.lastError = ""
	if core.Bool(m.ctx.Settings(), "auto_apply", false) && PublicKeyBase64 != "" &&
		compareVersions(m.ctx.Core.Version, manifest.Version) < 0 {
		if _, err := m.apiApply(nil); err != nil {
			m.lastError = fmt.Sprintf("automatic update to %s failed: %v", manifest.Version, err)
		}
	}
	return nil
}

// url returns the manifest URL as currently configured, so a change made in
// the settings page takes effect at the next check without a restart.
func (m *Module) url() string {
	if u := strings.TrimSpace(core.Str(m.ctx.Settings(), "manifest_url", "")); u != "" {
		m.manifestURL = u
	}
	return m.manifestURL
}

// manifestURLAllowed says whether a manifest URL may be used at all. The
// signature on every asset is what protects the binary; this guards the
// channel: https anywhere, or plain http only to a private or loopback
// host (an operator's own relay on the LAN). A plain-http public URL is
// refused, since a network attacker could then choose which signed build
// (an old one, say) the daemon sees.
func manifestURLAllowed(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("manifest_url is not a valid URL")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host == "localhost" || (ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())) {
			return nil
		}
		return fmt.Errorf("manifest_url over plain http is allowed only to a private or loopback host")
	}
	return fmt.Errorf("manifest_url must be https (or http to a private host)")
}

func (m *Module) fetchManifest() (*Manifest, error) {
	if err := manifestURLAllowed(m.url()); err != nil {
		return nil, err
	}
	req, _ := http.NewRequest("GET", m.url(), nil)
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
	var manifest Manifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func (m *Module) apiStatus(req *core.Req) (any, error) {
	status := map[string]any{
		"current_version": m.ctx.Core.Version,
		"last_check":      m.lastCheck.Unix(),
		"available":       false,
		"latest_version":  "",
		"notes":           "",
		"applicable":      false,
	}

	if m.latest != nil {
		status["latest_version"] = m.latest.Version
		status["notes"] = m.latest.Notes
		status["available"] = compareVersions(m.ctx.Core.Version, m.latest.Version) < 0
		status["applicable"] = PublicKeyBase64 != "" && status["available"].(bool)
	}

	if m.lastError != "" {
		status["error"] = m.lastError
	}
	status["manifest_url"] = m.url()
	status["no_release"] = m.noRelease
	status["signed_builds"] = PublicKeyBase64 != ""

	return status, nil
}

func (m *Module) apiCheck(req *core.Req) (any, error) {
	if err := m.checkForUpdates(); err != nil {
		return nil, core.Errorf(500, "check failed: %v", err)
	}
	return m.apiStatus(req)
}

func (m *Module) apiApply(req *core.Req) (any, error) {
	if m.latest == nil {
		return nil, core.BadRequest("no update available")
	}

	if PublicKeyBase64 == "" {
		return nil, core.Errorf(403, "update signature verification not configured "+
			"(this build carries no release public key)")
	}
	if compareVersions(m.ctx.Core.Version, m.latest.Version) >= 0 {
		return nil, core.BadRequest("already running %s; the manifest offers %s",
			m.ctx.Core.Version, m.latest.Version)
	}

	asset := m.findAsset()
	if asset == nil {
		return nil, core.BadRequest("no binary available for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	// Download to temp file in the same directory as the running binary
	exe, err := os.Executable()
	if err != nil {
		return nil, core.Errorf(500, "cannot determine executable path: %v", err)
	}

	dir := filepath.Dir(exe)
	tmpFile := filepath.Join(dir, "flowsightd.tmp")
	defer os.Remove(tmpFile)

	if err := m.downloadAndVerify(asset, tmpFile); err != nil {
		return nil, core.Errorf(400, "verification failed: %v", err)
	}

	// Make it executable
	if err := os.Chmod(tmpFile, 0o755); err != nil {
		return nil, core.Errorf(500, "chmod failed: %v", err)
	}

	// Atomically rename: current -> .previous, new -> current
	previousFile := exe + ".previous"
	if err := os.Rename(exe, previousFile); err != nil {
		return nil, core.Errorf(500, "cannot backup current binary: %v", err)
	}
	if err := os.Rename(tmpFile, exe); err != nil {
		// Try to restore if rename failed
		_ = os.Rename(previousFile, exe)
		return nil, core.Errorf(500, "cannot install new binary: %v", err)
	}

	// Record event
	m.ctx.Event("update", "daemon updated and restarting", map[string]any{
		"from": m.ctx.Core.Version,
		"to":   m.latest.Version,
	})

	// Restart the daemon
	go m.restartDaemon()

	return map[string]any{
		"ok":          true,
		"restarting":  true,
		"new_version": m.latest.Version,
	}, nil
}

func (m *Module) apiRollback(req *core.Req) (any, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, core.Errorf(500, "cannot determine executable path: %v", err)
	}

	previousFile := exe + ".previous"
	if _, err := os.Stat(previousFile); err != nil {
		return nil, core.BadRequest("no previous version available")
	}

	// Swap: current -> .tmp, .previous -> current, .tmp -> .previous
	tmpFile := exe + ".tmp"
	if err := os.Rename(exe, tmpFile); err != nil {
		return nil, core.Errorf(500, "cannot backup current: %v", err)
	}
	if err := os.Rename(previousFile, exe); err != nil {
		_ = os.Rename(tmpFile, exe)
		return nil, core.Errorf(500, "cannot restore previous: %v", err)
	}
	if err := os.Rename(tmpFile, previousFile); err != nil {
		_ = os.Rename(exe, tmpFile)
		_ = os.Rename(previousFile, exe)
		return nil, core.Errorf(500, "cannot update backup: %v", err)
	}

	// Record event
	m.ctx.Event("rollback", "daemon rolled back and restarting", map[string]any{})

	// Restart the daemon
	go m.restartDaemon()

	return map[string]any{
		"ok":         true,
		"restarting": true,
	}, nil
}

func (m *Module) findAsset() *Asset {
	if m.latest == nil {
		return nil
	}
	for i := range m.latest.Assets {
		if m.latest.Assets[i].OS == runtime.GOOS && m.latest.Assets[i].Arch == runtime.GOARCH {
			return &m.latest.Assets[i]
		}
	}
	return nil
}

func (m *Module) downloadAndVerify(asset *Asset, dest string) error {
	// Download file
	req, _ := http.NewRequest("GET", asset.URL, nil)
	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("download failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// A release binary is tens of megabytes; nothing larger is read, and a
	// size the manifest states must match before the signature is checked.
	const maxAsset = 512 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAsset+1))
	if err != nil {
		return fmt.Errorf("read failed: %v", err)
	}
	if len(body) > maxAsset {
		return fmt.Errorf("download larger than %d MB, refused", maxAsset>>20)
	}
	if asset.Size > 0 && int64(len(body)) != asset.Size {
		return fmt.Errorf("download is %d bytes, the manifest says %d", len(body), asset.Size)
	}

	// Verify sha256
	hash := sha256.Sum256(body)
	hashHex := hex.EncodeToString(hash[:])
	if hashHex != asset.SHA256 {
		return fmt.Errorf("sha256 mismatch: got %s, expected %s", hashHex, asset.SHA256)
	}

	// Verify signature
	if err := m.verifySignature(asset.SHA256, asset.Sig); err != nil {
		return fmt.Errorf("signature verification failed: %v", err)
	}

	// Write to dest
	if err := os.WriteFile(dest, body, 0o600); err != nil {
		return fmt.Errorf("write failed: %v", err)
	}

	return nil
}

func (m *Module) verifySignature(shaHex, sigB64 string) error {
	// Decode the public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(PublicKeyBase64)
	if err != nil {
		return fmt.Errorf("invalid public key encoding: %v", err)
	}

	pubKey := ed25519.PublicKey(pubKeyBytes)

	// Decode the signature
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %v", err)
	}

	// Verify signature over the sha256 hex string
	if !ed25519.Verify(pubKey, []byte(shaHex), sig) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

func (m *Module) restartDaemon() {
	time.Sleep(1 * time.Second)

	switch runtime.GOOS {
	case "freebsd", "openbsd", "netbsd":
		// FreeBSD: use service command via daemon
		cmd := exec.Command("/usr/sbin/daemon", "-f", "/usr/sbin/service", "flowsight", "restart")
		_ = cmd.Start()
	default:
		// Linux: use systemctl via daemon
		cmd := exec.Command("systemctl", "restart", "flowsight")
		_ = cmd.Start()
	}
}

// compareVersions returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2.
// "dev" is always older than any released version.
//
// Versions are major.minor.patch with an optional revision suffix
// "r<YYYYMMDDHHMM>" (a fix issued without a version increment, e.g.
// 0.9.8r202609211730). A revision is newer than its base and revisions order
// by their timestamp; anything after the numbers (a "-dev" tag) is ignored.
func compareVersions(v1, v2 string) int {
	if v1 == v2 {
		return 0
	}
	if v1 == "dev" && v2 != "dev" {
		return -1
	}
	if v2 == "dev" && v1 != "dev" {
		return 1
	}
	a, b := parseVersion(v1), parseVersion(v2)
	for i := 0; i < 4; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

var versionRe = regexp.MustCompile(`^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:r(\d{8,14}))?`)

// parseVersion returns [major, minor, patch, revision]; missing parts are 0.
func parseVersion(v string) [4]int64 {
	var out [4]int64
	m := versionRe.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return out
	}
	for i := 1; i <= 4 && i < len(m); i++ {
		if m[i] == "" {
			continue
		}
		n, _ := strconv.ParseInt(m[i], 10, 64)
		out[i-1] = n
	}
	return out
}
