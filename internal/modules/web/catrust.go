package web

// CA trust gate: decrypt a device only once it trusts the inspection CA.
//
// Bumping a device that does not trust the FlowSight CA does not inspect
// it; it breaks it. Every application that validates certificates (a
// desktop chat client, an AI assistant, an updater) sees a forged
// certificate and refuses, and to the person at the keyboard the network
// is simply broken. So a device a policy would inspect is first asked.
//
// Until it answers, its HTTPS is relayed untouched, exactly as for a device
// no policy inspects, and the operating system's own connectivity probe
// (Windows NCSI, Apple, Android, Firefox, GNOME) is redirected to the trust
// page. That is what makes Windows show "Action needed / Sign in to this
// network" and open the page by itself. The page offers two choices:
//
//   - Install the certificate. The page then loads an image from a second
//     listener whose certificate the inspection CA signed. A browser only
//     completes that request if the device trusts the CA, so the request
//     arriving is the proof; the device is recorded as trusted and is
//     inspected from the next configuration apply.
//   - Continue without it. The device is recorded as declined, is never
//     decrypted, and is not asked again. Server names, timing and volume
//     are still recorded, as for any spliced device.
//
// A bumped connection that carries a request is the same proof, so a device
// that was already inspected successfully is recorded as trusted on its own.

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

const caTrustKV = "web.ca_trust"

// Trust states.
const (
	trustTrusted  = "trusted"
	trustDeclined = "declined"
)

// trustEntry is one device's answer.
type trustEntry struct {
	Key   string `json:"key"` // MAC when known, else the address
	MAC   string `json:"mac,omitempty"`
	IP    string `json:"ip"`
	Name  string `json:"name,omitempty"`
	State string `json:"state"`
	At    int64  `json:"at"`
	Via   string `json:"via"` // check, portal, inspected, api
}

type caTrust struct {
	mu      sync.Mutex
	entries map[string]*trustEntry

	certMu  sync.Mutex
	certSum [32]byte // hash of the CA the current certificate was issued under
	cert    *tls.Certificate

	ca any // set by tests only
}

// portalProbeHosts are the names operating systems and browsers fetch over
// plain HTTP to decide whether a network has a sign-in page.
var portalProbeHosts = []string{
	"www.msftconnecttest.com", "ipv6.msftconnecttest.com", "www.msftncsi.com", // Windows
	"captive.apple.com",                                                                     // Apple
	"connectivitycheck.gstatic.com", "connectivitycheck.android.com", "clients3.google.com", // Android, ChromeOS
	"detectportal.firefox.com",                     // Firefox
	"nmcheck.gnome.org", "network-test.debian.org", // NetworkManager
}

// trustGate reports the setting; on by default because bumping a device
// that does not trust the CA breaks every application on it.
func (m *Module) trustGate() bool {
	return core.Bool(m.ctx.Settings(), "ca_trust_gate", true)
}

func (m *Module) loadTrust() {
	m.trust = &caTrust{entries: map[string]*trustEntry{}}
	var list []trustEntry
	if m.ctx.Store.KVGet(caTrustKV, &list) {
		for i := range list {
			e := list[i]
			m.trust.entries[e.Key] = &e
		}
	}
}

func (m *Module) saveTrust() {
	m.trust.mu.Lock()
	out := make([]trustEntry, 0, len(m.trust.entries))
	for _, e := range m.trust.entries {
		out = append(out, *e)
	}
	m.trust.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	_ = m.ctx.Store.KVSet(caTrustKV, out)
}

// trustKey names a device by its MAC when identity knows it, so the answer
// survives a new lease; otherwise by the address.
func (m *Module) trustKey(ip string) (key, mac string) {
	if m.identity != nil {
		mac = strings.ToLower(m.identity.MAC(ip))
	}
	if mac != "" {
		return mac, mac
	}
	return ip, ""
}

// trustState returns the recorded answer for the device holding ip.
func (m *Module) trustState(ip string) string {
	if m.trust == nil {
		return ""
	}
	key, _ := m.trustKey(ip)
	m.trust.mu.Lock()
	defer m.trust.mu.Unlock()
	if e := m.trust.entries[key]; e != nil {
		return e.State
	}
	return ""
}

// setTrust records an answer for the device holding ip. A trusted device
// stays trusted when something later calls it declined only through the
// portal: the check is proof, a click is not.
func (m *Module) setTrust(ip, state, via string) {
	if m.trust == nil || net.ParseIP(ip) == nil {
		return
	}
	key, mac := m.trustKey(ip)
	m.trust.mu.Lock()
	e := m.trust.entries[key]
	if e != nil && e.State == state && e.IP == ip {
		m.trust.mu.Unlock()
		return
	}
	if e != nil && e.State == trustTrusted && state == trustDeclined && via == "portal" {
		m.trust.mu.Unlock()
		return
	}
	name := ""
	if m.identity != nil {
		name = m.identity.Name(ip)
	}
	m.trust.entries[key] = &trustEntry{Key: key, MAC: mac, IP: ip, Name: name, State: state, At: time.Now().Unix(), Via: via}
	m.trust.mu.Unlock()
	m.saveTrust()
	who := ip
	if name != "" {
		who = name + " (" + ip + ")"
	}
	msg := who + " installed the inspection CA; it is inspected from the next apply"
	if state == trustDeclined {
		msg = who + " declined the inspection CA; it is relayed without decryption"
	}
	m.ctx.Event("web", msg, map[string]any{"ip": ip, "mac": mac, "state": state, "via": via})
}

func (m *Module) clearTrust(key string) bool {
	if m.trust == nil {
		return false
	}
	m.trust.mu.Lock()
	_, ok := m.trust.entries[key]
	delete(m.trust.entries, key)
	m.trust.mu.Unlock()
	if ok {
		m.saveTrust()
	}
	return ok
}

// trustAddrs returns every address held by the devices in a state, both
// families, so a device that answered over IPv4 is treated the same on IPv6.
func (m *Module) trustAddrs(state string) []string {
	if m.trust == nil {
		return nil
	}
	m.trust.mu.Lock()
	var ips []string
	for _, e := range m.trust.entries {
		if e.State == state {
			ips = append(ips, e.IP)
		}
	}
	m.trust.mu.Unlock()
	book, _ := m.identity.(core.AddressBook)
	seen := map[string]bool{}
	var out []string
	for _, ip := range ips {
		all := []string{ip}
		if book != nil {
			all = book.Addresses(ip)
		}
		for _, a := range all {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------- pages

func (m *Module) gatewayAddr() string {
	if a := firstLocalAddr(); a != "" {
		return a
	}
	return "127.0.0.1"
}

func (m *Module) portalURL() string {
	port := core.Int(m.ctx.Settings(), "block_page_port", 8082)
	return fmt.Sprintf("http://%s:%d/trust", m.gatewayAddr(), port)
}

func (m *Module) checkURL() string {
	port := core.Int(m.ctx.Settings(), "trust_check_port", 8084)
	return fmt.Sprintf("https://%s:%d/trust/ok", m.gatewayAddr(), port)
}

// caService is the tls module's CA; tests substitute their own.
func (m *Module) caService() any {
	if m.trust != nil && m.trust.ca != nil {
		return m.trust.ca
	}
	return m.ctx.Service("ca")
}

// caPEM returns the inspection CA certificate, or nil when there is none.
func (m *Module) caPEM() []byte {
	ca, ok := m.caService().(interface{ CACertPEM() ([]byte, error) })
	if !ok {
		return nil
	}
	b, err := ca.CACertPEM()
	if err != nil {
		return nil
	}
	return b
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// registerTrustPages adds the trust page to the block page listener.
func (m *Module) registerTrustPages(mux *http.ServeMux) {
	mux.HandleFunc("/trust", func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if m.caPEM() == nil {
			fmt.Fprint(w, trustNoCAHTML)
			return
		}
		fmt.Fprintf(w, trustHTML, htmlEscape(m.trustState(ip)), htmlEscape(m.checkURL()))
	})
	mux.HandleFunc("/trust/flowsight-ca.crt", func(w http.ResponseWriter, r *http.Request) {
		b := m.caPEM()
		if b == nil {
			http.NotFound(w, r)
			return
		}
		// DER: Windows, macOS, iOS and Android all open it as a certificate
		// to install; a PEM file is offered alongside for Linux and Firefox.
		if blk, _ := pem.Decode(b); blk != nil && r.URL.Query().Get("format") != "pem" {
			b = blk.Bytes
		}
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", `attachment; filename="flowsight-ca.crt"`)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/trust/decline", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Redirect(w, r, "/trust", http.StatusSeeOther)
			return
		}
		m.setTrust(clientIP(r), trustDeclined, "portal")
		http.Redirect(w, r, "/trust", http.StatusSeeOther)
	})
	mux.HandleFunc("/trust/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"state": m.trustState(clientIP(r))})
	})
}

// gif1x1 is a transparent pixel: the trust check is an <img>, which needs
// no script and no CORS.
var gif1x1 = []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b}

// startTrustCheck serves the proof listener: HTTPS under a certificate the
// inspection CA signs. Any request that reaches the handler came over a
// handshake the client accepted, so the client trusts the CA.
func (m *Module) startTrustCheck() {
	port := core.Int(m.ctx.Settings(), "trust_check_port", 8084)
	if port <= 0 {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/trust/ok", m.trustOK)
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		m.ctx.Log.Warn("trust check listener failed", "error", err.Error())
		return
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: m.trustCert}}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	m.trustSrv = srv
}

func (m *Module) trustOK(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		return // only a completed handshake is proof
	}
	m.setTrust(clientIP(r), trustTrusted, "check")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "image/gif")
	_, _ = w.Write(gif1x1)
}

// trustCert issues the check listener's certificate under the current CA,
// again whenever the CA is replaced, so the check never vouches for an old one.
func (m *Module) trustCert(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	b := m.caPEM()
	if b == nil {
		return nil, fmt.Errorf("no inspection CA")
	}
	sum := sha256.Sum256(b)
	t := m.trust
	t.certMu.Lock()
	defer t.certMu.Unlock()
	if t.cert != nil && bytes.Equal(sum[:], t.certSum[:]) && time.Until(t.cert.Leaf.NotAfter) > 24*time.Hour {
		return t.cert, nil
	}
	ca, ok := m.caService().(interface {
		IssueServerCert(names []string, ips []net.IP, days int) ([]byte, []byte, error)
	})
	if !ok {
		return nil, fmt.Errorf("no CA service")
	}
	var ips []net.IP
	if ip := net.ParseIP(m.gatewayAddr()); ip != nil {
		ips = append(ips, ip)
	}
	certPEM, keyPEM, err := ca.IssueServerCert([]string{"flowsight"}, ips, 90)
	if err != nil {
		return nil, err
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	t.cert, t.certSum = &c, sum
	return t.cert, nil
}

// ---------------------------------------------------------------- API

func (m *Module) apiTrust(r *core.Req) (any, error) {
	m.trust.mu.Lock()
	out := make([]trustEntry, 0, len(m.trust.entries))
	for _, e := range m.trust.entries {
		out = append(out, *e)
	}
	m.trust.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].At > out[j].At })
	return map[string]any{"devices": out, "gate": m.trustGate(), "portal": m.portalURL(), "check": m.checkURL()}, nil
}

func (m *Module) apiTrustSet(r *core.Req) (any, error) {
	var in struct {
		IP    string `json:"ip"`
		Key   string `json:"key"`
		State string `json:"state"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	switch in.State {
	case "clear":
		key := strings.ToLower(strings.TrimSpace(in.Key))
		if key == "" && in.IP != "" {
			key, _ = m.trustKey(strings.TrimSpace(in.IP))
		}
		if key == "" {
			return nil, core.BadRequest("ip or key is required")
		}
		return map[string]any{"ok": m.clearTrust(key)}, nil
	case trustTrusted, trustDeclined:
		ip := strings.TrimSpace(in.IP)
		if net.ParseIP(ip) == nil {
			return nil, core.BadRequest("a valid ip is required")
		}
		m.setTrust(ip, in.State, "api")
		return map[string]any{"ok": true}, nil
	}
	return nil, core.BadRequest("state must be trusted, declined or clear")
}

// ---------------------------------------------------------------- HTML

const trustNoCAHTML = `<!doctype html><html><head><meta charset="utf-8"><title>FlowSight</title>
<meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="font-family:system-ui,sans-serif;padding:40px"><p>This network has no inspection certificate. Nothing to install.</p></body></html>`

// trustHTML takes the device's current state and the check URL.
const trustHTML = `<!doctype html><html><head><meta charset="utf-8"><title>Network certificate</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:system-ui,sans-serif;background:#f6f7f9;color:#1c2430;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{background:#fff;border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,.08);padding:36px;max-width:600px;margin:16px}
h1{font-size:22px;margin:0 0 12px}h2{font-size:15px;margin:20px 0 6px}p,li{line-height:1.5}ol{padding-left:20px}
code{background:#eef1f5;padding:2px 6px;border-radius:4px;font-size:13px;word-break:break-all}
.btns{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0 8px}
.btn{border:0;border-radius:8px;padding:11px 18px;font-size:15px;cursor:pointer;text-decoration:none;display:inline-block}
.pri{background:#2456d6;color:#fff}.sec{background:#eef1f5;color:#1c2430}
.ok{background:#e6f6ec;color:#17603a;border-radius:8px;padding:12px 14px}
.no{background:#eef1f5;border-radius:8px;padding:12px 14px}
.hide{display:none}small{color:#5b6573}</style></head>
<body><div class="card">
<div id="s-ok" class="ok hide"><b>This device trusts the network certificate.</b> You can close this page; secure sites work normally.</div>
<div id="s-no" class="no hide"><b>You chose to continue without the certificate.</b> Your secure connections are relayed without being decrypted. You can install it here at any time.</div>
<h1>This network can inspect secure web traffic</h1>
<p>The network you are on uses FlowSight. For devices that install its certificate, it can decrypt and inspect HTTPS traffic (including its content) to apply this network's security policy. Devices without it are not decrypted; the names of the sites they visit, and how much data, are still visible to the network.</p>
<p>Until you choose, your connections are not decrypted and everything works as usual.</p>
<div class="btns">
<a class="btn pri" href="/trust/flowsight-ca.crt">Download certificate</a>
<form method="post" action="/trust/decline" style="margin:0"><button class="btn sec" type="submit">Continue without it</button></form>
</div>
<h2>Windows</h2>
<ol><li>Open the downloaded <code>flowsight-ca.crt</code> and choose <b>Install Certificate…</b></li>
<li>Choose <b>Local Machine</b>, then <b>Place all certificates in the following store</b> › <b>Trusted Root Certification Authorities</b>.</li>
<li>Finish, then restart apps that were failing (Discord, Claude, browsers).</li></ol>
<p><small>Or, in an administrator PowerShell in the download folder: <code>Import-Certificate -FilePath .\flowsight-ca.crt -CertStoreLocation Cert:\LocalMachine\Root</code></small></p>
<h2>macOS / iOS / Android / Linux</h2>
<p><small>macOS: open it in Keychain Access, add to <b>System</b>, set <b>Always Trust</b>. iOS: install the profile, then enable it under Settings › General › About › Certificate Trust Settings. Android: Settings › Security › Install a certificate › CA certificate. Linux: <a href="/trust/flowsight-ca.crt?format=pem">PEM file</a> into your system trust store.</small></p>
<p id="checking"><small>After installing, this page notices on its own within a few seconds.</small></p>
<img id="probe" alt="" width="1" height="1" style="position:absolute;left:-9999px">
</div>
<script>
(function(){
  var state="%s", check="%s";
  function show(s){document.getElementById("s-ok").className=s==="trusted"?"ok":"ok hide";
    document.getElementById("s-no").className=s==="declined"?"no":"no hide";}
  show(state);
  if(state==="trusted")return;
  var img=document.getElementById("probe"),timer;
  img.onload=function(){show("trusted");clearInterval(timer);document.getElementById("checking").className="hide";};
  function probe(){img.src=check+"?t="+Date.now();}
  probe();timer=setInterval(probe,4000);
})();
</script></body></html>`
