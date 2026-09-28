package tls

import (
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// An expiring certificate's finding names the device that last fetched it,
// counts the others, and gives the server and the dates.
func TestCertificateFindingCarriesWhoWhereWhy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := core.New("0.9.8r000000000000", "", t.TempDir(), nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	c.LoadModules()
	m, ok := c.Modules["tls"].(*Module)
	if !ok {
		t.Fatal("tls module not loaded")
	}
	now := time.Now().Unix()
	st := m.ctx.Store
	if err := st.Exec(`INSERT INTO tls_certs(fingerprint,subject,issuer,not_after,self_signed,first_seen,last_seen,seen,hosts,snis,source)
		VALUES('fp1','/CN=shop.example','/CN=Test CA',?,0,?,?,5,'["203.0.113.7"]','["shop.example"]','squid')`, now+3*86400, now-100, now-10); err != nil {
		t.Fatal(err)
	}
	for i, src := range []string{"192.168.1.20", "192.168.1.21", "192.168.1.22"} {
		if err := st.Exec(`INSERT INTO tls_sessions(ts,src_ip,dst_ip,dst_port,sni) VALUES(?,?,?,443,'shop.example')`, now-int64(100-i), src, "203.0.113.7"); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.findings(); err != nil {
		t.Fatal(err)
	}
	rows, _ := st.Rows(`SELECT kind, attrs FROM findings WHERE module='tls' AND resolved_ts IS NULL`)
	if len(rows) != 1 || rows[0]["kind"] != "expiring-certificate" {
		t.Fatalf("findings: %v", rows)
	}
	var a map[string]map[string]any
	if err := json.Unmarshal([]byte(rows[0]["attrs"].(string)), &a); err != nil {
		t.Fatal(err)
	}
	if a["who"]["ip"] != "192.168.1.22" || a["who"]["others"] != float64(2) {
		t.Fatalf("who: %v", a["who"])
	}
	if a["where"]["ip"] != "203.0.113.7" || a["where"]["domain"] != "shop.example" {
		t.Fatalf("where: %v", a["where"])
	}
	facts, _ := a["why"]["facts"].([]any)
	if len(facts) == 0 || !strings.Contains(facts[0].(string), "in 2 days") && !strings.Contains(facts[0].(string), "in 3 days") {
		t.Fatalf("why: %v", a["why"])
	}
}

// A certificate the proxy saw has no TLS session row; the device comes from
// the flows by name instead.
func TestCertificateWhoFallsBackToFlowsByName(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := core.New("0.9.8r000000000000", "", t.TempDir(), nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	c.LoadModules()
	m := c.Modules["tls"].(*Module)
	now := time.Now().Unix()
	st := m.ctx.Store
	_ = st.Exec(`INSERT INTO tls_certs(fingerprint,subject,not_after,self_signed,first_seen,last_seen,seen,hosts,snis,source)
		VALUES('fp2','/CN=old.example',?,0,?,?,1,'[]','["old.example"]','squid')`, now-86400, now-100, now-10)
	_ = st.Exec(`INSERT INTO flows(ts,src_ip,dst_ip,dst_port,domain) VALUES(?,?,?,443,'old.example')`, now-50, "192.168.1.40", "198.51.100.9")
	if err := m.findings(); err != nil {
		t.Fatal(err)
	}
	rows, _ := st.Rows(`SELECT attrs FROM findings WHERE module='tls' AND kind='expired-certificate'`)
	a := ""
	if len(rows) == 1 {
		a, _ = rows[0]["attrs"].(string)
	}
	if !strings.Contains(a, `"ip":"192.168.1.40"`) || !strings.Contains(a, "seen once") {
		t.Fatalf("attrs: %s", a)
	}
}
