package qos

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// Mirrors are ranked by their connect time, nearest first, and one that
// does not answer is left out.
func TestRankMirrorsNearestFirst(t *testing.T) {
	old := dialFunc
	defer func() { dialFunc = old }()
	dialFunc = func(ctx context.Context, addr string) (net.Conn, error) {
		switch {
		case strings.HasPrefix(addr, "speedtest.dallas.linode.com"):
			time.Sleep(5 * time.Millisecond)
		case strings.HasPrefix(addr, "ash-speed.hetzner.com"):
			time.Sleep(15 * time.Millisecond)
		case strings.HasPrefix(addr, "proof.ovh.net"):
			return nil, errors.New("refused")
		default:
			time.Sleep(40 * time.Millisecond)
		}
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}
	got := rankMirrors(context.Background())
	if len(got) != len(downloadMirrors)-1 {
		t.Fatalf("expected every mirror but the refusing one, got %d of %d", len(got), len(downloadMirrors))
	}
	if got[0].Name != "Linode Dallas" || got[1].Name != "Hetzner Ashburn" {
		t.Fatalf("order: %s, %s", got[0].Name, got[1].Name)
	}
	for _, m := range got {
		if m.Name == "OVH Roubaix" {
			t.Fatal("a mirror that refused should be left out")
		}
	}
}

func TestRateLimitedMeansARefusal(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{{errors.New("HTTP 429 from speed.cloudflare.com"), true}, {errors.New("HTTP 403 from speed.cloudflare.com"), true},
		{errors.New("HTTP 500 from speed.cloudflare.com"), false}, {errors.New("dial tcp: timeout"), false}, {nil, false}} {
		if rateLimited(c.err) != c.want {
			t.Errorf("%v: want %v", c.err, c.want)
		}
	}
}

// Every mirror is an https URL of a file, not a page.
func TestMirrorListIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range downloadMirrors {
		if !strings.HasPrefix(m.URL, "https://") || m.Name == "" || seen[m.URL] {
			t.Errorf("bad or repeated mirror: %+v", m)
		}
		seen[m.URL] = true
	}
}
