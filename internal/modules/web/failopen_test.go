package web

// Interception must never fail closed: the redirects to the proxy exist only
// while the proxy answers. These tests drive the supervisor and the provider
// through every way the proxy can be missing or deaf and check that the
// redirects are withdrawn, and never loaded, in each; and that they are
// loaded when the proxy is up and listening.

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// redirects records what the web module asks of the firewall.
type redirects struct {
	mu      sync.Mutex
	loaded  []string // text of every load
	cleared int
}

func (r *redirects) load(text string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loaded = append(r.loaded, text)
}

func (r *redirects) clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleared++
}

func (r *redirects) counts() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.loaded), r.cleared
}

// freePort returns a TCP port nothing listens on.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

// listenOn keeps a listener open on 127.0.0.1:port for the test.
func listenOn(t *testing.T, port int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	t.Cleanup(func() { l.Close() })
}

type failOpenBed struct {
	m    *Module
	fw   *redirects
	http int
	tls  int
}

// newFailOpenBed builds a web module with interception on, a rendered
// configuration and redirect rules on disk, no squid binary, and the
// recording fake in place of the firewall.
func newFailOpenBed(t *testing.T) *failOpenBed {
	t.Helper()
	// Never find a real squid, even on a gateway that has one.
	oldFallbacks := squidFallbacks
	squidFallbacks = nil
	t.Cleanup(func() { squidFallbacks = oldFallbacks })
	root := t.TempDir()
	cfg, err := core.LoadConfig(filepath.Join(root, "flowsight.json"))
	if err != nil {
		t.Fatal(err)
	}
	b := &failOpenBed{fw: &redirects{}, http: freePort(t), tls: freePort(t)}
	cfg.DeclareModule("web", map[string]any{"intercept": true, "http_port": b.http, "https_port": b.tls})
	pl := &core.Platform{SquidBin: filepath.Join(root, "no-squid-here"), DataDir: root}
	b.m = &Module{
		ctx:    &core.Context{Name: "web", Config: cfg, Platform: pl},
		dir:    filepath.Join(root, "squid"),
		logDir: filepath.Join(root, "log"),
		runDir: filepath.Join(root, "run"),
	}
	b.m.rdr = newFakeRedirector(b.fw)
	for _, d := range []string{b.m.dir, b.m.logDir, b.m.runDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, b.m.confPath(), "http_port 3128\n")
	write(t, filepath.Join(b.m.dir, "pf-web.conf"), "rdr pass on lan0 inet proto tcp from 192.0.2.0/24 to any port 80 -> 127.0.0.1 port 3128\n")
	return b
}

func write(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

// running makes the module believe squid is up: a pid file naming a live
// process (this one).
func (b *failOpenBed) running(t *testing.T) {
	write(t, b.m.pidPath(), strconv.Itoa(os.Getpid())+"\n")
}

func withListenWait(t *testing.T, d time.Duration) {
	old := superviseListenWait
	superviseListenWait = d
	t.Cleanup(func() { superviseListenWait = old })
}

func TestSuperviseWithdrawsRedirectsWhenSquidCannotStart(t *testing.T) {
	b := newFailOpenBed(t)
	if err := b.m.supervise(); err == nil {
		t.Fatal("supervise should report that squid could not start")
	}
	loads, clears := b.fw.counts()
	if loads != 0 || clears == 0 {
		t.Fatalf("squid missing: want redirects cleared and never loaded, got %d load(s), %d clear(s)", loads, clears)
	}
}

func TestSuperviseWithdrawsRedirectsWhenProxyIsDeaf(t *testing.T) {
	withListenWait(t, 200*time.Millisecond)
	b := newFailOpenBed(t)
	b.running(t) // a process, but nothing on the listener ports
	if err := b.m.supervise(); err == nil {
		t.Fatal("supervise should report that the proxy is not listening")
	}
	loads, clears := b.fw.counts()
	if loads != 0 || clears == 0 {
		t.Fatalf("proxy deaf: want redirects cleared and never loaded, got %d load(s), %d clear(s)", loads, clears)
	}
}

func TestSuperviseLoadsRedirectsOnlyWhenProxyListens(t *testing.T) {
	withListenWait(t, 200*time.Millisecond)
	b := newFailOpenBed(t)
	b.running(t)
	listenOn(t, b.http)
	listenOn(t, b.tls)
	if err := b.m.supervise(); err != nil {
		t.Fatalf("supervise with a listening proxy: %v", err)
	}
	loads, clears := b.fw.counts()
	if loads != 1 || clears != 0 {
		t.Fatalf("proxy up: want one load and no clear, got %d load(s), %d clear(s)", loads, clears)
	}
}

func TestApplyWithdrawsRedirectsWhenSquidRejects(t *testing.T) {
	b := newFailOpenBed(t)
	p := &provider{m: b.m}
	art := core.Artifact{Files: map[string]string{
		b.m.confPath():                        "http_port 3128\n",
		filepath.Join(b.m.dir, "pf-web.conf"): "rdr pass on lan0 inet proto tcp from 192.0.2.0/24 to any port 443 -> 127.0.0.1 port 3129\n",
	}}
	if _, err := p.Apply(art); err == nil {
		t.Fatal("apply without squid should fail")
	}
	loads, clears := b.fw.counts()
	if loads != 0 || clears == 0 {
		t.Fatalf("squid rejected: want redirects cleared and never loaded, got %d load(s), %d clear(s)", loads, clears)
	}
}

// The spec web asks for is the one the firewall's golden test renders
// (firewall/redirect_test.go, webSpec), so the rules loaded into pf are the
// ones this module loaded before its renderer moved there.
func TestRedirectSpecMatchesFirewallGolden(t *testing.T) {
	got := redirectSpec([]string{"vtnet0", "igb1"}, []string{"192.168.1.0/24", "10.99.0.0/16"},
		[]string{"192.168.1.50", "fd00::5"}, 3128, 3129, "fd00::1")
	nets := []string{"192.168.1.0/24", "10.99.0.0/16"}
	want := core.RedirectSpec{
		Interfaces: []string{"vtnet0", "igb1"},
		Excluded:   []string{"192.168.1.50", "fd00::5"},
		Rules: []core.RedirectRule{
			{Family: "inet", Sources: nets, Port: 80, To: core.Endpoint{Addr: "127.0.0.1", Port: 3128}},
			{Family: "inet", Sources: nets, Port: 443, To: core.Endpoint{Addr: "127.0.0.1", Port: 3129}},
			{Family: "inet6", Port: 80, To: core.Endpoint{Addr: "fd00::1", Port: 3128}},
			{Family: "inet6", Port: 443, To: core.Endpoint{Addr: "fd00::1", Port: 3129}},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("spec changed:\n got %+v\nwant %+v", got, want)
	}
	if empty := redirectSpec(nil, nil, []string{"192.168.1.50"}, 3128, 3129, "fd00::1"); len(empty.Rules) != 0 {
		t.Fatalf("no IPv4 networks must mean no redirects, got %+v", empty.Rules)
	}
}
