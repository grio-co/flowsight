package providers_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grioghar/flowsight/internal/core"
	_ "github.com/grioghar/flowsight/internal/modules"
	"github.com/grioghar/flowsight/internal/provideragent"
)

// A real core, its API behind a real HTTP server, a named token for the
// provider and an unnamed one beside it.
func newCore(t *testing.T) (*core.Core, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "flowsight.json")
	doc := `{"api_token":"unnamed-token-0123456789abcdef01","api_tokens":[{"name":"suricata-lab","token":"lab-token-0123456789abcdef012345"}],
	         "modules":{"ids":{"eve_path":"` + filepath.Join(dir, "no-local-eve.json") + `"}}}`
	if err := os.WriteFile(cfg, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 100}))
	c, err := core.New("test", cfg, dir, nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	c.LoadModules()
	srv := httptest.NewServer(c.API)
	t.Cleanup(srv.Close)
	return c, srv
}

const eveAlert = `{"timestamp":"2026-09-27T12:00:00.000000+0000","event_type":"alert","src_ip":"10.99.0.162","src_port":40000,` +
	`"dest_ip":"203.0.113.9","dest_port":80,"proto":"TCP","alert":{"action":"allowed","signature_id":9000001,` +
	`"signature":"FlowSight provider test","category":"Misc activity","severity":2}}`

// Suricata's EVE, tailed by the agent, arrives in the core's store through
// the protocol, read exactly as the local log is and marked with the
// provider's name.
func TestSuricataEventsReachTheStoreThroughTheProtocol(t *testing.T) {
	c, srv := newCore(t)
	eve := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(eve, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	a := provideragent.New(provideragent.Config{Core: srv.URL, Token: "lab-token-0123456789abcdef012345", EVE: eve, Version: "test"}, func(s string) { t.Log(s) })
	a.Step()
	f, _ := os.OpenFile(eve, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString(eveAlert + "\n" + `{"event_type":"flow"}` + "\n")
	f.Close()
	a.Step()

	rows, err := c.Store.Rows(`SELECT source, signature, severity, src_ip FROM alerts`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["source"] != "suricata@suricata-lab" || rows[0]["signature"] != "FlowSight provider test" ||
		rows[0]["severity"] != "high" || rows[0]["src_ip"] != "10.99.0.162" {
		t.Fatalf("alerts: %v", rows)
	}

	req, _ := http.NewRequest("GET", srv.URL+"/api/provider/v1/providers", nil)
	req.Header.Set("X-Flowsight-Token", "unnamed-token-0123456789abcdef01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Providers []struct {
			Name      string `json:"name"`
			Kind      string `json:"kind"`
			Connected bool   `json:"connected"`
			Events    int64  `json:"events"`
		} `json:"providers"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	if len(list.Providers) != 1 || list.Providers[0].Name != "suricata-lab" || !list.Providers[0].Connected || list.Providers[0].Events != 1 {
		t.Fatalf("providers: %+v", list.Providers)
	}
	h := c.Modules["ids"].(core.Healther).Health()
	if !h.OK || !strings.Contains(h.Detail, "from providers") {
		t.Fatalf("ids health with no local EVE log but a provider: %+v", h)
	}
}

func post(t *testing.T, srv *httptest.Server, token, path, body string) int {
	t.Helper()
	req, _ := http.NewRequest("POST", srv.URL+path, bytes.NewBufferString(body))
	req.Header.Set("X-Flowsight-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// Only a named token identifies a provider; no token is no access; events
// need a hello first; an unknown protocol version is refused.
func TestProviderAccessRules(t *testing.T) {
	_, srv := newCore(t)
	hello := `{"protocol":1,"role":"detector","kind":"suricata","formats":["suricata-eve"]}`
	events := `{"format":"suricata-eve","records":[` + eveAlert + `]}`
	if got := post(t, srv, "", "/api/provider/v1/hello", hello); got != http.StatusUnauthorized && got != http.StatusForbidden {
		t.Errorf("no token: %d", got)
	}
	if got := post(t, srv, "unnamed-token-0123456789abcdef01", "/api/provider/v1/hello", hello); got != http.StatusForbidden {
		t.Errorf("unnamed token: %d", got)
	}
	if got := post(t, srv, "lab-token-0123456789abcdef012345", "/api/provider/v1/events", events); got != http.StatusConflict {
		t.Errorf("events before hello: %d", got)
	}
	if got := post(t, srv, "lab-token-0123456789abcdef012345", "/api/provider/v1/hello", `{"protocol":2,"formats":[]}`); got != http.StatusBadRequest {
		t.Errorf("protocol 2: %d", got)
	}
	if got := post(t, srv, "lab-token-0123456789abcdef012345", "/api/provider/v1/hello", hello); got != http.StatusOK {
		t.Errorf("hello: %d", got)
	}
	if got := post(t, srv, "lab-token-0123456789abcdef012345", "/api/provider/v1/events", `{"format":"nonsense","records":[]}`); got != http.StatusBadRequest {
		t.Errorf("unknown format: %d", got)
	}
	if got := post(t, srv, "lab-token-0123456789abcdef012345", "/api/provider/v1/events", events); got != http.StatusOK {
		t.Errorf("events: %d", got)
	}
}
