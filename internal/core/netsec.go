package core

// Who may reach the API, over what, with which powers.
//
//   - api_allow: addresses and networks that may reach the web interface and
//     API at all. Loopback always may: that is how the OPNsense GUI proxies
//     in, so a mistake here never locks anyone out of the GUI route.
//   - https_port: an HTTPS listener, with a certificate from the inspection
//     CA (trusted wherever the CA is installed) or a self-signed one.
//   - http_local_only: plain HTTP serves only loopback (and the category
//     feeds Pi-holes subscribe to); anything else is sent to HTTPS.
//   - api_token_local_only: the unnamed api_token (the one the OPNsense
//     plugin reads) is accepted only from loopback, so a copy of it is
//     useless anywhere else.
//   - token scopes: a named token is "admin" (default) or "read"; a read
//     token, and the sessions it opens, can read everything and change
//     nothing.
//   - failed logins and bad tokens are throttled per address.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ScopeAdmin = "admin"
	ScopeRead  = "read"
)

func isLoopback(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && p.IsLoopback()
}

// allowed reports whether a client address may reach the API at all.
func (a *API) allowed(client string) bool {
	if isLoopback(client) {
		return true
	}
	list := a.core.Config.Core().APIAllow
	if len(list) == 0 {
		return true
	}
	ip := net.ParseIP(client)
	if ip == nil {
		return false
	}
	for _, e := range list {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			if _, n, err := net.ParseCIDR(e); err == nil && n.Contains(ip) {
				return true
			}
		} else if p := net.ParseIP(e); p != nil && p.Equal(ip) {
			return true
		}
	}
	return false
}

// scopeOf is the scope a token name carries: the unnamed token and named
// tokens without a scope are admin.
func (a *API) scopeOf(name string) string {
	if !strings.HasPrefix(name, "token:") {
		return ScopeAdmin
	}
	for _, t := range a.core.Config.Core().APITokens {
		if "token:"+t.Name == name {
			if t.Scope == ScopeRead {
				return ScopeRead
			}
			return ScopeAdmin
		}
	}
	return ScopeAdmin
}

// ------------------------------------------------------------ throttling

type failRec struct {
	n     int
	first time.Time
	until time.Time
}

var (
	failMu sync.Mutex
	fails  = map[string]*failRec{}
)

const (
	failWindow = 15 * time.Minute
	failLimit  = 8
)

// throttled reports whether an address is locked out after repeated
// failures, and for how long.
func throttled(client string) (bool, time.Duration) {
	failMu.Lock()
	defer failMu.Unlock()
	f := fails[client]
	if f == nil {
		return false, 0
	}
	if d := time.Until(f.until); d > 0 {
		return true, d
	}
	return false, 0
}

// failed records a failed login or a bad token. After failLimit failures in
// failWindow the address waits, doubling each time it fails again.
func failed(client string) {
	if isLoopback(client) {
		return // never throttle the GUI's own route: that would be a lockout
	}
	failMu.Lock()
	defer failMu.Unlock()
	now := time.Now()
	f := fails[client]
	if f == nil || now.Sub(f.first) > failWindow && now.After(f.until) {
		f = &failRec{first: now}
		fails[client] = f
	}
	f.n++
	if f.n >= failLimit {
		wait := time.Minute << uint(minInt(f.n-failLimit, 6)) // 1 min … 64 min
		f.until = now.Add(wait)
	}
	if len(fails) > 10000 { // a flood of addresses cannot grow memory without bound
		for k, v := range fails {
			if now.Sub(v.first) > failWindow && now.After(v.until) {
				delete(fails, k)
			}
		}
	}
}

func succeeded(client string) {
	failMu.Lock()
	delete(fails, client)
	failMu.Unlock()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// dropSession ends the session a request carries.
func (a *API) dropSession(r *http.Request) {
	if c, err := r.Cookie("fs_session"); err == nil {
		a.sessMu.Lock()
		delete(a.sessions, c.Value)
		a.sessMu.Unlock()
	}
}

// ------------------------------------------------------------ HTTPS

// APICertIssuer is what the TLS module offers: a server certificate signed
// by the inspection CA.
type APICertIssuer interface {
	IssueServerCert(names []string, ips []net.IP, days int) ([]byte, []byte, error)
}

type apiCert struct {
	cert     *tls.Certificate
	leaf     *x509.Certificate
	signedBy string
}

var currentAPICert atomic.Pointer[apiCert]

// apiNames is what the certificate must cover: this host's names and every
// address it holds.
func apiNames() ([]string, []net.IP) {
	host, _ := os.Hostname()
	names := []string{"localhost"}
	if host != "" {
		names = append(names, host)
		if i := strings.IndexByte(host, '.'); i > 0 {
			names = append(names, host[:i])
		}
	}
	var ips []net.IP
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && !n.IP.IsLinkLocalUnicast() {
				ips = append(ips, n.IP)
			}
		}
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].String() < ips[j].String() })
	return names, ips
}

func coverSignature(names []string, ips []net.IP) string {
	parts := append([]string{}, names...)
	for _, ip := range ips {
		parts = append(parts, ip.String())
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, ",")))
	return hex.EncodeToString(sum[:8])
}

// ensureAPICert loads the API certificate, or makes a new one when it is
// missing, due to expire within 30 days, or no longer covers this host's
// addresses. It prefers the inspection CA.
func (c *Core) ensureAPICert() error {
	dir := c.Platform.EtcDir
	if dir == "" {
		dir = c.Config.Core().DataDir
	}
	certPath, keyPath, sigPath := filepath.Join(dir, "api-tls.crt"), filepath.Join(dir, "api-tls.key"), filepath.Join(dir, "api-tls.cover")
	names, ips := apiNames()
	want := coverSignature(names, ips)
	if cb, err := os.ReadFile(certPath); err == nil {
		kb, _ := os.ReadFile(keyPath)
		sig, _ := os.ReadFile(sigPath)
		if pair, err := tls.X509KeyPair(cb, kb); err == nil {
			leaf, _ := x509.ParseCertificate(pair.Certificate[0])
			if leaf != nil && time.Until(leaf.NotAfter) > 30*24*time.Hour && strings.TrimSpace(string(sig)) == want {
				pair.Leaf = leaf
				currentAPICert.Store(&apiCert{cert: &pair, leaf: leaf, signedBy: leaf.Issuer.CommonName})
				return nil
			}
		}
	}
	var certPEM, keyPEM []byte
	var err error
	c.mu.RLock()
	issuer, _ := c.Services["ca"].(APICertIssuer)
	c.mu.RUnlock()
	if issuer != nil {
		certPEM, keyPEM, err = issuer.IssueServerCert(names, ips, 397)
	}
	if issuer == nil || err != nil {
		certPEM, keyPEM, err = selfSigned(names, ips)
		if err != nil {
			return err
		}
	}
	if err := os.WriteFile(keyPath+".tmp", keyPEM, 0o600); err != nil {
		return err
	}
	if err := os.Rename(keyPath+".tmp", keyPath); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return err
	}
	_ = os.WriteFile(sigPath, []byte(want+"\n"), 0o644)
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	pair.Leaf = leaf
	currentAPICert.Store(&apiCert{cert: &pair, leaf: leaf, signedBy: leaf.Issuer.CommonName})
	c.Log.Info("api certificate issued", "signed_by", leaf.Issuer.CommonName, "until", leaf.NotAfter.Format("2006-01-02"))
	return nil
}

func selfSigned(names []string, ips []net.IP) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "FlowSight (self-signed)"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 0, 397),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: names, IPAddresses: ips}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), nil
}

// ListenTLS serves the API over HTTPS on the given port.
func (a *API) ListenTLS(bind string, port int) (*http.Server, error) {
	if currentAPICert.Load() == nil {
		return nil, errors.New("no API certificate")
	}
	addr := net.JoinHostPort(bind, strconv.Itoa(port))
	srv := &http.Server{Addr: addr, Handler: a, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 60 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 90 * time.Second,
		MaxHeaderBytes: 64 << 10,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return currentAPICert.Load().cert, nil }}}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	a.log.Info("listening", "addr", "https://"+addr, "certificate", currentAPICert.Load().signedBy)
	go func() {
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.log.Error("https server stopped", "error", err.Error())
		}
	}()
	return srv, nil
}

// httpsURL is where a plain-HTTP request should go instead.
func (a *API) httpsURL(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return "https://" + host + ":" + strconv.Itoa(a.core.Config.Core().HTTPSPort) + r.URL.RequestURI()
}
