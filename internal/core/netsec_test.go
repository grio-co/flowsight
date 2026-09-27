package core

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func newTestAPI(t *testing.T, mut func(*CoreSettings)) *Core {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := New("0.9.8r000000000000", "", t.TempDir(), nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	c.LoadModules()
	if c.API.routes["GET /api/system/info"] == nil {
		c.systemRoutes()
	}
	c.Config.mu.Lock()
	c.Config.core.APIToken = "gui-token-0123456789"
	c.Config.core.APITokens = []NamedToken{{Name: "operator", Token: "operator-token-0123456789"}, {Name: "reader", Token: "reader-token-0123456789", Scope: ScopeRead}}
	if mut != nil {
		mut(&c.Config.core)
	}
	c.Config.mu.Unlock()
	failMu.Lock()
	fails = map[string]*failRec{}
	failMu.Unlock()
	return c
}

func do(c *Core, method, path, remote, token string, body string, tlsOn bool) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, path, rd)
	r.RemoteAddr = net.JoinHostPort(remote, "5555")
	if token != "" {
		r.Header.Set("X-Flowsight-Token", token)
	}
	if tlsOn {
		r.TLS = &tls.ConnectionState{}
	}
	w := httptest.NewRecorder()
	c.API.ServeHTTP(w, r)
	return w
}

func TestAllowlistAlwaysKeepsLoopback(t *testing.T) {
	c := newTestAPI(t, func(cs *CoreSettings) { cs.APIAllow = []string{"192.168.1.119", "10.8.0.0/24"} })
	for remote, want := range map[string]int{"127.0.0.1": 200, "::1": 200, "192.168.1.119": 200, "10.8.0.7": 200, "192.168.2.47": 403, "192.168.1.120": 403} {
		if got := do(c, "GET", "/api/system/info", remote, "operator-token-0123456789", "", false).Code; got != want {
			t.Errorf("%s: %d want %d", remote, got, want)
		}
	}
	// Pi-holes fetch feeds from anywhere; the key protects those.
	if got := do(c, "GET", "/feeds/categories/x.txt?key=bad", "192.168.2.47", "", "", false).Code; got != 404 {
		t.Errorf("feed from a disallowed address: %d, want the feed's own 404", got)
	}
}

func TestGUITokenLocalOnlyAndReadScope(t *testing.T) {
	c := newTestAPI(t, func(cs *CoreSettings) { cs.APITokenLocalOnly = true })
	if got := do(c, "GET", "/api/system/info", "127.0.0.1", "gui-token-0123456789", "", false).Code; got != 200 {
		t.Fatalf("GUI token on loopback: %d", got)
	}
	if got := do(c, "GET", "/api/system/info", "192.168.1.119", "gui-token-0123456789", "", false).Code; got != 401 {
		t.Fatalf("GUI token off the box must fail: %d", got)
	}
	if got := do(c, "GET", "/api/system/info", "192.168.1.119", "reader-token-0123456789", "", false).Code; got != 200 {
		t.Fatalf("read token reads: %d", got)
	}
	w := do(c, "POST", "/api/system/findings/ack", "192.168.1.119", "reader-token-0123456789", `{"id":1}`, false)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "read-only") {
		t.Fatalf("read token must not write: %d %s", w.Code, w.Body.String())
	}
	if got := do(c, "POST", "/api/system/findings/ack", "192.168.1.119", "operator-token-0123456789", `{"id":1}`, false).Code; got == 403 || got == 401 {
		t.Fatalf("admin token writes: %d", got)
	}
}

func TestLoginThrottleAndRealLogout(t *testing.T) {
	c := newTestAPI(t, nil)
	for i := 0; i < failLimit; i++ {
		do(c, "POST", "/api/login", "192.168.2.66", "", `{"token":"wrong"}`, false)
	}
	if got := do(c, "POST", "/api/login", "192.168.2.66", "", `{"token":"operator-token-0123456789"}`, false).Code; got != 429 {
		t.Fatalf("after %d failures the address waits: %d", failLimit, got)
	}
	if got := do(c, "GET", "/api/system/info", "192.168.2.66", "operator-token-0123456789", "", false).Code; got != 429 {
		t.Fatalf("a throttled address waits for tokens too: %d", got)
	}
	// Another address is unaffected, and logs in.
	w := do(c, "POST", "/api/login", "192.168.1.119", "", `{"token":"operator-token-0123456789"}`, true)
	if w.Code != 200 {
		t.Fatalf("login: %d", w.Code)
	}
	ck := w.Result().Cookies()
	if len(ck) == 0 || !ck[0].Secure {
		t.Fatalf("session cookie over HTTPS must be Secure: %+v", ck)
	}
	with := func(method, path string) int {
		r := httptest.NewRequest(method, path, nil)
		r.RemoteAddr = "192.168.1.119:5555"
		r.AddCookie(ck[0])
		rw := httptest.NewRecorder()
		c.API.ServeHTTP(rw, r)
		return rw.Code
	}
	if got := with("GET", "/api/system/info"); got != 200 {
		t.Fatalf("session works: %d", got)
	}
	if got := with("GET", "/api/system/logout"); got != 200 {
		t.Fatalf("logout: %d", got)
	}
	if got := with("GET", "/api/system/info"); got != 401 {
		t.Fatalf("the session must be gone after logout: %d", got)
	}
}

func TestHTTPLocalOnlyRedirects(t *testing.T) {
	c := newTestAPI(t, func(cs *CoreSettings) { cs.HTTPLocalOnly = true; cs.HTTPSPort = 8443 })
	w := do(c, "GET", "/", "192.168.1.119", "", "", false)
	if w.Code != 301 || !strings.HasPrefix(w.Header().Get("Location"), "https://") || !strings.Contains(w.Header().Get("Location"), ":8443/") {
		t.Fatalf("plain HTTP off the box goes to HTTPS: %d %q", w.Code, w.Header().Get("Location"))
	}
	if got := do(c, "GET", "/api/system/info", "127.0.0.1", "gui-token-0123456789", "", false).Code; got != 200 {
		t.Fatalf("loopback keeps plain HTTP (the GUI proxy): %d", got)
	}
	if got := do(c, "GET", "/api/system/info", "192.168.1.119", "operator-token-0123456789", "", true).Code; got != 200 {
		t.Fatalf("HTTPS works: %d", got)
	}
}

func TestAPICertCoversThisHost(t *testing.T) {
	c := newTestAPI(t, nil)
	c.Platform.EtcDir = t.TempDir()
	if err := c.ensureAPICert(); err != nil {
		t.Fatal(err)
	}
	cur := currentAPICert.Load()
	if cur == nil || len(cur.leaf.IPAddresses) == 0 {
		t.Fatalf("certificate: %+v", cur)
	}
	st, err := os.Stat(c.Platform.EtcDir + "/api-tls.key")
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode: %v %v", st.Mode(), err)
	}
	first := cur.leaf.SerialNumber.String()
	_ = c.ensureAPICert()
	if currentAPICert.Load().leaf.SerialNumber.String() != first {
		t.Fatal("a valid certificate is kept, not reissued")
	}
	_ = http.StatusOK
}

func TestLoopbackIsNeverThrottled(t *testing.T) {
	c := newTestAPI(t, nil)
	for i := 0; i < failLimit+2; i++ {
		failed("127.0.0.1")
	}
	if got := do(c, "GET", "/api/system/info", "127.0.0.1", "gui-token-0123456789", "", false).Code; got != 200 {
		t.Fatalf("loopback must never be locked out: %d", got)
	}
}

// The store and its companions are readable by the daemon only.
func TestStoreFilesArePrivate(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(dir+"/dns-names.json", []byte("{}"), 0o644)
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.KVSet("x", 1)
	s.Close()
	s, _ = OpenStore(dir)
	defer s.Close()
	for _, f := range []string{"flowsight.db", "dns-names.json"} {
		st, err := os.Stat(dir + "/" + f)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", f, st.Mode(), err)
		}
	}
}

// Outbound requests never reach link-local (cloud metadata) or multicast.
func TestOutboundGuard(t *testing.T) {
	for _, s := range []string{"169.254.169.254", "fe80::1", "224.0.0.1", "0.0.0.0"} {
		if !blockedDestination(net.ParseIP(s)) {
			t.Errorf("%s must be blocked", s)
		}
	}
	for _, s := range []string{"127.0.0.1", "192.168.1.53", "8.8.8.8", "2600:1700::1"} {
		if blockedDestination(net.ParseIP(s)) {
			t.Errorf("%s must be allowed", s)
		}
	}
	c := &http.Client{Timeout: 3 * time.Second}
	if _, err := c.Get("http://169.254.169.254/latest/meta-data/"); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("the default transport must refuse metadata addresses: %v", err)
	}
}
