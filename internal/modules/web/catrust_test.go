package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func gateParams(trusted, declined []string) squidParams {
	return squidParams{
		Dir: "/d", CAPath: "/ca.pem",
		Policies:  []squidPolicy{{ID: "office", Members: []string{"192.168.1.0/24"}, Inspect: true}},
		TrustGate: true, TrustedClients: trusted, DeclinedClients: declined,
		PortalURL: "http://192.168.1.1:8082/trust", ProbeHosts: portalProbeHosts,
	}
}

// With the gate on and nobody trusted, nobody is bumped: a device without
// the CA must get the servers' own certificates, not forged ones.
func TestTrustGateBumpsNobodyUntilTrusted(t *testing.T) {
	conf, files := gateParams(nil, nil).render()
	if strings.Contains(conf, "ssl_bump bump") || strings.Contains(conf, "ssl_bump stare") {
		t.Fatalf("an untrusted client is bumped:\n%s", conf)
	}
	if strings.Contains(conf, "sslproxy_cert_error deny") {
		t.Fatal("cert errors refused for a client that is spliced")
	}
	if files["ca-trusted.acl"] != "" || strings.Contains(conf, "fs_ca_ok") {
		t.Fatal("an empty trusted list produced an ACL")
	}
	if !strings.Contains(conf, "deny_info 302:http://192.168.1.1:8082/trust?url=%U fs_portal_probe") ||
		!strings.Contains(conf, "http_access deny fs_src_office fs_portal_probe\n") {
		t.Fatalf("sign-in probe not sent to the certificate page:\n%s", conf)
	}
	if !strings.Contains(files["portal-probes.acl"], "www.msftconnecttest.com\n") {
		t.Fatal("Windows probe host missing")
	}
	if strings.Index(conf, "fs_portal_probe\n") > strings.Index(conf, "http_access allow localnet") {
		t.Fatal("probe redirect comes after the allow that would match first")
	}
}

func TestTrustGateBumpsOnlyTrusted(t *testing.T) {
	conf, files := gateParams([]string{"192.168.1.10"}, []string{"192.168.1.11"}).render()
	for _, want := range []string{
		"ssl_bump stare fs_src_office fs_ca_ok step2",
		"ssl_bump bump fs_src_office fs_ca_ok step3",
		"sslproxy_cert_error deny fs_src_office fs_ca_ok",
		"http_access deny fs_src_office !fs_ca_ok !fs_ca_declined fs_portal_probe",
	} {
		if !strings.Contains(conf, want+"\n") {
			t.Fatalf("missing %q:\n%s", want, conf)
		}
	}
	if files["ca-trusted.acl"] != "192.168.1.10\n" || files["ca-declined.acl"] != "192.168.1.11\n" {
		t.Fatalf("trust lists wrong: %q %q", files["ca-trusted.acl"], files["ca-declined.acl"])
	}
	if strings.Contains(conf, "ssl_bump bump fs_src_office step3") {
		t.Fatal("an ungated bump rule was written")
	}
}

// Gate off: behaviour is exactly as before.
func TestTrustGateOffKeepsOldRules(t *testing.T) {
	p := gateParams([]string{"192.168.1.10"}, nil)
	p.TrustGate = false
	conf, files := p.render()
	if !strings.Contains(conf, "ssl_bump bump fs_src_office step3\n") || strings.Contains(conf, "fs_ca_ok") ||
		strings.Contains(conf, "fs_portal_probe") || files["portal-probes.acl"] != "" {
		t.Fatalf("gate off changed the configuration:\n%s", conf)
	}
}

// No CA: nothing to install, so no probe redirect.
func TestTrustGateWithoutCARedirectsNothing(t *testing.T) {
	p := gateParams(nil, nil)
	p.CAPath = ""
	conf, _ := p.render()
	if strings.Contains(conf, "fs_portal_probe") {
		t.Fatal("probe redirected with no CA to offer")
	}
}

// fakeCA signs server certificates the way the tls module does.
type fakeCA struct {
	pem  []byte
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newFakeCA(t *testing.T) *fakeCA {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour * 30),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &fakeCA{pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert: c, key: key}
}

func (f *fakeCA) CACertPEM() ([]byte, error) { return f.pem, nil }

func (f *fakeCA) IssueServerCert(names []string, ips []net.IP, days int) ([]byte, []byte, error) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 0, days),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: names,
		IPAddresses: append(ips, net.ParseIP("127.0.0.1"))}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.cert, &key.PublicKey, f.key)
	if err != nil {
		return nil, nil, err
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), f.pem...),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), nil
}

// The check is the proof: a client that does not trust the CA cannot
// complete the request, and one that does is recorded as trusted.
func TestTrustCheckRecordsOnlyClientsThatTrustTheCA(t *testing.T) {
	m := pinnedTestModule(t)
	ca := newFakeCA(t)
	m.trust.ca = ca
	srv := httptest.NewUnstartedServer(http.HandlerFunc(m.trustOK))
	srv.TLS = &tls.Config{GetCertificate: m.trustCert}
	srv.StartTLS()
	defer srv.Close()

	untrusting := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "flowsight"}}}
	if _, err := untrusting.Get(srv.URL + "/trust/ok"); err == nil {
		t.Fatal("a client without the CA completed the check")
	}
	if s := m.trustState("127.0.0.1"); s != "" {
		t.Fatalf("untrusting client recorded as %q", s)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.pem)
	trusting := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "flowsight"}}}
	resp, err := trusting.Get(srv.URL + "/trust/ok")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if s := m.trustState("127.0.0.1"); s != trustTrusted {
		t.Fatalf("trusting client recorded as %q", s)
	}
	if got := m.trustAddrs(trustTrusted); len(got) != 1 || got[0] != "127.0.0.1" {
		t.Fatalf("trusted addresses %v", got)
	}

	// A later click on "continue without" does not undo the proof.
	m.setTrust("127.0.0.1", trustDeclined, "portal")
	if s := m.trustState("127.0.0.1"); s != trustTrusted {
		t.Fatalf("portal decline overrode a passed check: %q", s)
	}
	// It survives a restart.
	m.loadTrust()
	if s := m.trustState("127.0.0.1"); s != trustTrusted {
		t.Fatal("trust not persisted")
	}
}

func TestTrustPortalDeclineAndDownload(t *testing.T) {
	m := pinnedTestModule(t)
	m.trust.ca = newFakeCA(t)
	mux := http.NewServeMux()
	m.registerTrustPages(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/trust", nil))
	if !strings.Contains(rec.Body.String(), "Continue without it") {
		t.Fatal("page lacks the choice")
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/trust/flowsight-ca.crt", nil))
	if _, err := x509.ParseCertificate(rec.Body.Bytes()); err != nil {
		t.Fatalf("download is not a DER certificate: %v", err)
	}
	req := httptest.NewRequest("POST", "/trust/decline", nil)
	req.RemoteAddr = "192.168.1.50:5555"
	mux.ServeHTTP(httptest.NewRecorder(), req)
	if s := m.trustState("192.168.1.50"); s != trustDeclined {
		t.Fatalf("decline recorded as %q", s)
	}
}
