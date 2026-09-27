package nftables

// The nftables lab: real nftables, real traffic. It runs only when
// FLOWSIGHT_NFT_LAB=1, as root in a privileged Linux container with nft,
// conntrack and ip, and a labserver binary (testdata/labserver) at
// $FLOWSIGHT_LAB_SERVER. It builds its own network, so nothing outside the
// container is touched:
//
//	client netns 10.10.0.2 --- 10.10.0.1  this container  10.20.0.1 --- 10.20.0.2 server netns
//	                           (the gateway, forwarding)
//
// FlowSight's rules are loaded into this container's netns, where the
// client's traffic is forwarded.

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func sh(t *testing.T, cmd string) string {
	t.Helper()
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", cmd, err, out)
	}
	return string(out)
}

// fetch asks from the client netns; "" means the connection failed.
func fetch(port int) string { return fetchFrom("client", fmt.Sprintf("http://10.20.0.2:%d/", port)) }

// fetchFrom asks from a netns, or from the gateway itself with ns "".
func fetchFrom(ns, url string) string {
	args := []string{"curl", "-s", "-m", "3", url}
	if ns != "" {
		args = append([]string{"ip", "netns", "exec", ns}, args...)
	}
	out, err := exec.Command(args[0], args[1:]...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

type labIdentity struct{ core.Identity }

// labGeo is a country database in which the lab's server network, and
// nothing else, is in country XX.
type labGeo struct {
	core.GeoService
	asked [][]string
}

func (g *labGeo) DatabaseEpoch() int64 { return 1 }
func (g *labGeo) NetworksFor(ccs []string, invert bool, skip func(string) bool) ([]string, int, error) {
	g.asked = append(g.asked, append([]string(nil), ccs...))
	if contains(ccs, "XX") != invert {
		return []string{"10.20.0.0/24"}, 0, nil
	}
	return nil, 0, nil
}

type labHome struct{}

func (labHome) HomeCountry() string { return "us" }

func (labIdentity) LocalNetworks() []string { return []string{"10.10.0.0/24"} }

func labModule(t *testing.T) *Module {
	t.Helper()
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m := &Module{nft: "/usr/sbin/nft", conntrack: "/usr/sbin/conntrack", dir: t.TempDir(), chains: map[string]string{},
		identity: labIdentity{}, geo: map[string]geoInfo{},
		ctx: &core.Context{Core: &core.Core{Services: map[string]any{"geo": &labGeo{}, "home": labHome{}}}, Name: "nftables", Store: store,
			Platform: &core.Platform{Firewall: "nft"}}}
	if err := m.load(skeleton()); err != nil {
		t.Fatal(err)
	}
	if err := m.upkeep(); err != nil { // fills local_v4
		t.Fatal(err)
	}
	return m
}

func TestLab(t *testing.T) {
	if os.Getenv("FLOWSIGHT_NFT_LAB") != "1" {
		t.Skip("the nftables lab runs in a privileged Linux container; set FLOWSIGHT_NFT_LAB=1")
	}
	srv := os.Getenv("FLOWSIGHT_LAB_SERVER")
	// A failed run may have left anything behind; start from nothing.
	sh(t, `pkill -x labserver; nft flush ruleset; ip netns del client; ip netns del server; ip link del vc; ip link del vs; true`)
	sh(t, `sysctl -qw net.ipv4.ip_forward=1 net.netfilter.nf_conntrack_acct=1 2>/dev/null || sysctl -qw net.ipv4.ip_forward=1
ip netns add client; ip netns add server
ip link add vc type veth peer name vc0 netns client
ip link add vs type veth peer name vs0 netns server
ip addr add 10.10.0.1/24 dev vc; ip link set vc up
ip addr add 10.20.0.1/24 dev vs; ip link set vs up
ip -n client addr add 10.10.0.2/24 dev vc0; ip -n client link set vc0 up; ip -n client link set lo up; ip -n client route add default via 10.10.0.1
ip -n server addr add 10.20.0.2/24 dev vs0; ip -n server link set vs0 up; ip -n server link set lo up; ip -n server route add default via 10.20.0.1`)
	sh(t, fmt.Sprintf(`(ip netns exec server %s 10.20.0.2:80 10.20.0.2:25 10.20.0.2:8080 >/dev/null 2>&1 &)
(%s 127.0.0.1:3128 >/dev/null 2>&1 &)
sleep 1`, srv, srv))
	t.Cleanup(func() {
		exec.Command("sh", "-c", `pkill -x labserver; nft flush ruleset; ip netns del client; ip netns del server; ip link del vc; ip link del vs`).Run()
	})
	if got := fetch(80); got != "answered by 10.20.0.2:80" {
		t.Fatalf("the lab network does not forward: %q", got)
	}
	m := labModule(t)
	e := &enforcer{m: m}

	t.Run("ports and internet", func(t *testing.T) {
		doc := &core.PolicyDoc{Policies: []core.Policy{{Name: "Kids", Enabled: true, Action: "block",
			Match: core.Match{Members: []string{"10.10.0.2/32"}}, Deny: core.Deny{Ports: []string{"tcp/25"}}}}}
		tx, _, err := compilePolicy(doc, nil, false, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := m.loadChain(chainPolicy, tx); err != nil {
			t.Fatal(err)
		}
		if fetch(80) == "" || fetch(25) != "" {
			t.Fatalf("port 25 must be blocked and 80 not: 80=%q 25=%q", fetch(80), fetch(25))
		}
		doc.Policies[0].Deny = core.Deny{Internet: true}
		tx, _, _ = compilePolicy(doc, nil, false, time.Now())
		if err := m.loadChain(chainPolicy, tx); err != nil {
			t.Fatal(err)
		}
		if fetch(80) != "" {
			t.Fatal("internet access must be blocked")
		}
		doc.Policies[0].Action = "monitor"
		tx, _, _ = compilePolicy(doc, nil, false, time.Now())
		if err := m.loadChain(chainPolicy, tx); err != nil {
			t.Fatal(err)
		}
		if fetch(80) == "" {
			t.Fatal("a monitor policy must not block")
		}
		if !strings.Contains(sh(t, "nft list chain inet flowsight fs_policy"), "counter packets") {
			t.Fatal("a monitor policy must count")
		}
	})

	t.Run("application set and connection kill", func(t *testing.T) {
		doc := &core.PolicyDoc{Policies: []core.Policy{{Name: "Apps", Enabled: true, Action: "block",
			Match: core.Match{Members: []string{"10.10.0.2/32"}}, Deny: core.Deny{Apps: []string{"Example"}}}}}
		tx, _, _ := compilePolicy(doc, nil, false, time.Now())
		if err := m.loadChain(chainPolicy, tx); err != nil {
			t.Fatal(err)
		}
		if fetch(80) == "" {
			t.Fatal("an empty application set must block nothing")
		}
		if err := e.AddToSet("fs_app_apps", []string{"10.20.0.2"}); err != nil {
			t.Fatal(err)
		}
		if fetch(80) != "" {
			t.Fatal("an address in the application set must be blocked")
		}
		if err := e.ReplaceSet("fs_app_apps", nil); err != nil {
			t.Fatal(err)
		}
		if fetch(80) == "" {
			t.Fatal("an emptied set must block nothing again")
		}
		if err := e.KillStates("10.10.0.2", "10.20.0.2"); err != nil {
			t.Fatalf("kill states: %v", err)
		}
	})

	t.Run("connection table", func(t *testing.T) {
		_ = fetch(8080)
		states, err := e.States()
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, s := range states {
			if s.Initiator.Addr == "10.10.0.2" && s.Responder == (core.Endpoint{Addr: "10.20.0.2", Port: 8080}) {
				found = true
			}
		}
		if !found {
			t.Fatalf("the client's connection is not in the table: %+v", states)
		}
	})

	t.Run("redirects, and withdrawing them", func(t *testing.T) {
		if err := m.loadChain(chainPolicy, replaceChain(chainPolicy, nil, nil)); err != nil {
			t.Fatal(err)
		}
		spec := core.RedirectSpec{Rules: []core.RedirectRule{{Family: "inet", Sources: []string{"10.10.0.0/24"}, Port: 80,
			To: core.Endpoint{Addr: "127.0.0.1", Port: 3128}}}}
		// The redirect delivers to the LAN interface's address, which is
		// what Arrivals must say, and where a loopback-only proxy is deaf.
		if got := e.Arrivals(spec); strings.Join(got, " ") != "10.10.0.1" {
			t.Fatalf("arrivals: %v", got)
		}
		if err := e.LoadRedirects("web", e.RenderRedirects(spec)); err != nil {
			t.Fatal(err)
		}
		if got := fetch(80); got != "" {
			t.Fatalf("a proxy on loopback alone must not receive redirected traffic: %q", got)
		}
		if got := fetchFrom("", "http://10.10.0.1:3128/"); got != "" {
			t.Fatalf("the fail-open probe of the arrival address must fail too: %q", got)
		}
		sh(t, fmt.Sprintf(`(%s 10.10.0.1:3128 >/dev/null 2>&1 &) ; sleep 1`, srv))
		if got := fetch(80); got != "answered by 10.10.0.1:3128" {
			t.Fatalf("port 80 must reach the proxy at the arrival address: %q", got)
		}
		if got := fetchFrom("", "http://10.10.0.1:3128/"); got != "answered by 10.10.0.1:3128" {
			t.Fatalf("the gateway's own probe must pass the input guard: %q", got)
		}
		if got := fetchFrom("client", "http://10.10.0.1:3128/"); got != "" {
			t.Fatalf("a client connecting to the proxy directly must be turned away: %q", got)
		}
		if got := fetch(8080); got != "answered by 10.20.0.2:8080" {
			t.Fatalf("other ports must not be redirected: %q", got)
		}
		spec.Excluded = []string{"10.10.0.2"}
		if err := e.LoadRedirects("web", e.RenderRedirects(spec)); err != nil {
			t.Fatal(err)
		}
		if got := fetch(80); got != "answered by 10.20.0.2:80" {
			t.Fatalf("an excluded client must not be redirected: %q", got)
		}
		spec.Excluded = nil
		_ = e.LoadRedirects("web", e.RenderRedirects(spec))
		if err := e.ClearRedirects("web"); err != nil {
			t.Fatal(err)
		}
		if got := fetch(80); got != "answered by 10.20.0.2:80" {
			t.Fatalf("withdrawn redirects must let traffic through untouched: %q", got)
		}
	})

	t.Run("zone isolation", func(t *testing.T) {
		spec := core.IsolationSpec{Zones: []core.IsolationZone{
			{ID: "lan", Subnet: "10.10.0.0/24", Internet: true},
			{ID: "srv", Subnet: "10.20.0.0/24", Internet: true},
		}}
		if err := e.LoadIsolation("enroll", e.RenderIsolation(spec)); err != nil {
			t.Fatal(err)
		}
		if fetch(80) != "" {
			t.Fatal("a zone must not reach another it is not allowed to")
		}
		spec.Zones[0].Reach = []string{"srv"}
		_ = e.LoadIsolation("enroll", e.RenderIsolation(spec))
		if fetch(80) == "" {
			t.Fatal("a zone must reach one it is allowed to")
		}
		spec.Zones[0] = core.IsolationZone{ID: "lan", Subnet: "10.10.0.0/24", Captive: true, Gateway: "10.20.0.2"}
		_ = e.LoadIsolation("enroll", e.RenderIsolation(spec))
		if fetch(80) == "" {
			t.Fatal("a captive zone must reach its gateway")
		}
		spec.Zones[0].Gateway = "10.10.0.1"
		_ = e.LoadIsolation("enroll", e.RenderIsolation(spec))
		if fetch(80) != "" {
			t.Fatal("a captive zone must reach nothing but its gateway")
		}
		if err := e.ClearIsolation("enroll"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("another table cannot be overridden, and is not opened", func(t *testing.T) {
		sh(t, `nft add table inet distro
nft 'add chain inet distro forward { type filter hook forward priority filter; policy accept; }'
nft add rule inet distro forward tcp dport 8080 drop
nft add rule inet distro forward tcp dport 25 accept`)
		doc := &core.PolicyDoc{Policies: []core.Policy{{Name: "Kids", Enabled: true, Action: "block",
			Match: core.Match{Members: []string{"10.10.0.2/32"}}, Deny: core.Deny{Ports: []string{"tcp/25"}}}}}
		tx, _, _ := compilePolicy(doc, nil, false, time.Now())
		if err := m.loadChain(chainPolicy, tx); err != nil {
			t.Fatal(err)
		}
		if fetch(25) != "" {
			t.Fatal("another table's accept overrode FlowSight's block")
		}
		if fetch(8080) != "" {
			t.Fatal("FlowSight opened what another table blocks")
		}
		sh(t, `nft delete table inet distro`)
	})

	t.Run("countries", func(t *testing.T) {
		geo := m.ctx.Core.Services["geo"].(*labGeo)
		m.mu.Lock()
		before := m.chains[chainPolicy]
		m.mu.Unlock()
		doc := &core.PolicyDoc{Policies: []core.Policy{{Name: "Geo", Enabled: true, Action: "block",
			Match: core.Match{Members: []string{"10.10.0.2/32"}}, Deny: core.Deny{Countries: []string{"YY"}}}}}
		apply := func() {
			t.Helper()
			tx, _, err := compilePolicy(doc, nil, true, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if err := m.loadChain(chainPolicy, tx); err != nil {
				t.Fatal(err)
			}
			if err := m.fillGeoSets(geoSets(tx), true); err != nil {
				t.Fatal(err)
			}
		}
		apply()
		if fetch(80) == "" {
			t.Fatal("a country the server is not in must not block it")
		}
		doc.Policies[0].Deny.Countries = []string{"XX"}
		apply()
		if fetch(80) != "" {
			t.Fatal("the server's country must be blocked")
		}
		doc.Policies[0].Deny = core.Deny{CountriesExcept: []string{"XX"}}
		apply()
		if fetch(80) == "" {
			t.Fatal("every country except the server's must not block it")
		}
		if last := geo.asked[len(geo.asked)-1]; !contains(last, "US") {
			t.Fatalf("the home country must always be allowed: asked for everything except %v", last)
		}
		doc.Policies[0].Deny = core.Deny{CountriesExcept: []string{"YY"}}
		apply()
		if fetch(80) != "" {
			t.Fatal("every country except another must block the server")
		}
		// A flush empties the sets; upkeep puts back the chain and fills them.
		sh(t, `nft flush ruleset`)
		if fetch(80) == "" {
			t.Fatal("with the ruleset flushed nothing should block")
		}
		if err := m.upkeep(); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(10 * time.Second)
		for fetch(80) != "" {
			if time.Now().After(deadline) {
				t.Fatalf("the country set was not refilled after a flush:\n%s", sh(t, "nft list table inet flowsight"))
			}
			time.Sleep(200 * time.Millisecond)
		}
		if err := m.loadChain(chainPolicy, before); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("the table comes back after a flush", func(t *testing.T) {
		sh(t, `nft flush ruleset`)
		if fetch(25) == "" {
			t.Fatal("with the ruleset flushed nothing should block")
		}
		if err := m.upkeep(); err != nil {
			t.Fatal(err)
		}
		if fetch(25) != "" {
			t.Fatal("upkeep must restore FlowSight's table and its chains")
		}
	})
}
