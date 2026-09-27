package tc

// The tc lab: real queues, real traffic, measured rates. It runs only when
// FLOWSIGHT_TC_LAB=1, as root in a privileged Linux container with tc, ip
// and curl, and a labserver binary at $FLOWSIGHT_LAB_SERVER (see
// test/tc-lab.sh). It builds its own network:
//
//	client netns 10.10.0.2 --- vc 10.10.0.1  this container  10.20.0.1 vs --- 10.20.0.2, .3 server netns
//	                           (LAN)                          (WAN)
//
// Where the kernel has no ifb (Docker Desktop's), only the download path
// can be loaded, and the lab checks that Ready says what is missing; on a
// full kernel it runs the whole shaper, upload included.

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"

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

// mbit measures one transfer from the client, in Mbit/s.
func mbit(t *testing.T, args ...string) float64 {
	t.Helper()
	out, err := exec.Command("ip", append([]string{"netns", "exec", "client", "curl", "-s", "-m", "60", "-o", "/dev/null"}, args...)...).Output()
	if err != nil {
		t.Fatalf("curl %v: %v", args, err)
	}
	f, _ := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	return f * 8 / 1e6
}

func down(t *testing.T, server string, mb int) float64 {
	return mbit(t, "-w", "%{speed_download}", fmt.Sprintf("http://%s/bytes/%d", server, mb<<20))
}

func up(t *testing.T, mb int) float64 {
	sh(t, fmt.Sprintf("head -c %d /dev/zero > /tmp/up.bin", mb<<20))
	return mbit(t, "-w", "%{speed_upload}", "-T", "/tmp/up.bin", "http://10.20.0.2/")
}

func near(got, want float64) bool { return got > want*0.75 && got < want*1.15 }

func TestLab(t *testing.T) {
	if os.Getenv("FLOWSIGHT_TC_LAB") != "1" {
		t.Skip("the tc lab runs in a privileged Linux container; set FLOWSIGHT_TC_LAB=1")
	}
	srv := os.Getenv("FLOWSIGHT_LAB_SERVER")
	reset := `pkill -x labserver; tc qdisc del dev vs root; ip netns del client; ip netns del server; ip link del vc; ip link del vs; ip link del fsifb0; true`
	sh(t, reset)
	sh(t, `sysctl -qw net.ipv4.ip_forward=1
ip netns add client; ip netns add server
ip link add vc type veth peer name vc0 netns client
ip link add vs type veth peer name vs0 netns server
ip addr add 10.10.0.1/24 dev vc; ip link set vc up
ip addr add 10.20.0.1/24 dev vs; ip link set vs up
ip -n client addr add 10.10.0.2/24 dev vc0; ip -n client link set vc0 up; ip -n client route add default via 10.10.0.1
ip -n server addr add 10.20.0.2/24 dev vs0; ip -n server addr add 10.20.0.3/24 dev vs0; ip -n server link set vs0 up
ip -n server route add default via 10.20.0.1`)
	sh(t, fmt.Sprintf(`(ip netns exec server %s 10.20.0.2:80 10.20.0.3:80 >/dev/null 2>&1 &) ; sleep 1`, srv))
	t.Cleanup(func() { exec.Command("sh", "-c", reset).Run() })

	fast := down(t, "10.20.0.2", 20)
	t.Logf("unshaped download: %.0f Mbit/s", fast)
	if fast < 200 {
		t.Fatalf("the lab link is too slow to show shaping: %.0f Mbit/s", fast)
	}
	// An operator's own queueing on another interface, which must survive.
	sh(t, `tc qdisc add dev vs root handle 1: htb default 10`)

	m := &Module{tc: "/usr/sbin/tc", ip: "/usr/sbin/ip", dir: t.TempDir(), leaf: "fq_codel",
		ctx: &core.Context{Core: &core.Core{Services: map[string]any{}}, Platform: &core.Platform{Family: "linux"}}}
	s := &shaper{m: m}
	p := core.ShapePlan{LAN: "vc", DownMbit: 40, UpMbit: 20, WeightHigh: 70, WeightNormal: 25, WeightLow: 5, DefaultClass: "normal"}

	full := s.Ready() == nil
	apply := func(p core.ShapePlan) {
		t.Helper()
		if full {
			if err := s.Apply(p); err != nil {
				t.Fatal(err)
			}
			return
		}
		m.clearDev(p.LAN)
		b := render(p, m.leaf)
		if err := m.load(batch{Down: b.Down}); err != nil && strings.Contains(err.Error(), "qdisc kind is unknown") {
			m.leaf = ""
			m.clearDev(p.LAN)
			err = m.load(batch{Down: render(p, "").Down})
			if err != nil {
				t.Fatal(err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if !full {
		err := s.Ready()
		t.Logf("no ifb in this kernel; the download path only: %v", err)
		if !strings.Contains(err.Error(), "modprobe ifb") {
			t.Fatalf("Ready must say how to get an ifb: %v", err)
		}
	}

	t.Run("the link is held to the plan's rate", func(t *testing.T) {
		apply(p)
		if got := down(t, "10.20.0.2", 10); !near(got, 40) {
			t.Fatalf("download at %.1f Mbit/s, want about 40", got)
		}
		if full {
			if got := up(t, 5); !near(got, 20) {
				t.Fatalf("upload at %.1f Mbit/s, want about 20", got)
			}
		}
	})

	t.Run("a ceiling caps a device", func(t *testing.T) {
		q := p
		q.Rules = []core.ShapeRule{{Key: "client", Addrs: []string{"10.10.0.2"}, Local: true, Class: "normal", CeilingMbit: 8}}
		apply(q)
		if got := down(t, "10.20.0.2", 4); !near(got, 8) {
			t.Fatalf("download at %.1f Mbit/s, want about 8", got)
		}
		if full {
			if got := up(t, 2); !near(got, 8) {
				t.Fatalf("upload at %.1f Mbit/s, want about 8", got)
			}
		}
	})

	t.Run("weights share a full link", func(t *testing.T) {
		q := p
		q.Rules = []core.ShapeRule{
			{Key: "a", Addrs: []string{"10.20.0.2"}, Class: "high"},
			{Key: "b", Addrs: []string{"10.20.0.3"}, Class: "low"},
		}
		apply(q)
		// Both download for the same four seconds, so the link is full
		// throughout and each gets its share of it.
		window := func(server string) float64 {
			out, _ := exec.Command("ip", "netns", "exec", "client", "curl", "-s", "-m", "4", "-o", "/dev/null",
				"-w", "%{size_download}", fmt.Sprintf("http://%s/bytes/%d", server, 1<<30)).Output()
			n, _ := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
			return n * 8 / 4 / 1e6
		}
		var wg sync.WaitGroup
		var hi, lo float64
		wg.Add(2)
		go func() { defer wg.Done(); hi = window("10.20.0.2") }()
		go func() { defer wg.Done(); lo = window("10.20.0.3") }()
		wg.Wait()
		t.Logf("sharing a 40 Mbit/s link: high %.1f Mbit/s, low %.1f Mbit/s", hi, lo)
		if hi < 5*lo || !near(hi+lo, 40) {
			t.Fatalf("weights 70 and 5 must give high most of a full link: high %.1f, low %.1f", hi, lo)
		}
	})

	t.Run("an unchanged plan is not reloaded", func(t *testing.T) {
		if !full {
			t.Skip("needs the whole shaper")
		}
		if err := s.Apply(p); err != nil {
			t.Fatal(err)
		}
		_ = down(t, "10.20.0.2", 1)
		counters := func() string { return sh(t, "tc -s class show dev vc | grep -A1 'f5:20 ' | tail -1") }
		sent := counters()
		if strings.Contains(sent, "Sent 0 bytes") {
			t.Fatalf("the default class saw nothing: %s", sent)
		}
		if err := s.Apply(p); err != nil {
			t.Fatal(err)
		}
		if again := counters(); again != sent {
			t.Fatalf("reapplying the same plan rebuilt the queues: %q, then %q", sent, again)
		}
		stats, err := s.Stats()
		if err != nil || len(stats) < 6 {
			t.Fatalf("stats: %v %+v", err, stats)
		}
	})

	t.Run("a rejected plan leaves the last good one", func(t *testing.T) {
		if !full {
			t.Skip("needs the whole shaper")
		}
		if err := s.Apply(p); err != nil {
			t.Fatal(err)
		}
		bad := p
		bad.LAN = "nosuchif0"
		if err := s.Apply(bad); err == nil {
			t.Fatal("a plan for a missing interface must be refused")
		}
		if got := down(t, "10.20.0.2", 10); !near(got, 40) {
			t.Fatalf("after a refused plan the last good one must be in force: %.1f Mbit/s", got)
		}
	})

	t.Run("clear removes FlowSight's shaping and nothing else", func(t *testing.T) {
		s.Clear()
		if !full {
			m.clearDev("vc")
		}
		q := sh(t, "tc qdisc show")
		if strings.Contains(q, "f5:") || strings.Contains(sh(t, "ip link"), "fsifb0") {
			t.Fatalf("left behind:\n%s", q)
		}
		if !strings.Contains(q, "qdisc htb 1: dev vs root") {
			t.Fatalf("the operator's own qdisc was removed:\n%s", q)
		}
		if got := down(t, "10.20.0.2", 20); got < 200 {
			t.Fatalf("after clearing the link must be unshaped: %.0f Mbit/s", got)
		}
	})
}
