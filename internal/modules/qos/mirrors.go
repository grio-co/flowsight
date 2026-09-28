package qos

import (
	"context"
	"net"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// The built-in download is Cloudflare's speed endpoint, which refuses a
// repeat burst from one address (HTTP 429 or 403) for a while. When it does,
// the download is taken from one of these instead: public test files that
// hosting providers publish for exactly this, large enough that each stream
// is a few whole requests. All answered a range request from a gateway on
// 2026-09-28. They serve downloads only; the upload stays on Cloudflare,
// which has not refused one.
var downloadMirrors = []struct{ Name, URL string }{
	{"Vultr Amsterdam", "https://ams-nl-ping.vultr.com/vultr.com.100MB.bin"},
	{"Vultr Frankfurt", "https://fra-de-ping.vultr.com/vultr.com.100MB.bin"},
	{"Vultr London", "https://lon-gb-ping.vultr.com/vultr.com.100MB.bin"},
	{"Vultr Paris", "https://par-fr-ping.vultr.com/vultr.com.100MB.bin"},
	{"Vultr New Jersey", "https://nj-us-ping.vultr.com/vultr.com.100MB.bin"},
	{"Vultr Chicago", "https://il-us-ping.vultr.com/vultr.com.100MB.bin"},
	{"Vultr Miami", "https://fl-us-ping.vultr.com/vultr.com.100MB.bin"},
	{"Vultr Dallas", "https://tx-us-ping.vultr.com/vultr.com.100MB.bin"},
	{"Vultr Los Angeles", "https://lax-ca-us-ping.vultr.com/vultr.com.100MB.bin"},
	{"Vultr Silicon Valley", "https://sjo-ca-us-ping.vultr.com/vultr.com.100MB.bin"},
	{"Vultr Toronto", "https://tor-ca-ping.vultr.com/vultr.com.100MB.bin"},
	{"Vultr Singapore", "https://sgp-ping.vultr.com/vultr.com.100MB.bin"},
	{"Vultr Tokyo", "https://hnd-jp-ping.vultr.com/vultr.com.100MB.bin"},
	{"Vultr Sydney", "https://syd-au-ping.vultr.com/vultr.com.100MB.bin"},
	{"Linode Newark", "https://speedtest.newark.linode.com/100MB-newark.bin"},
	{"Linode Atlanta", "https://speedtest.atlanta.linode.com/100MB-atlanta.bin"},
	{"Linode Dallas", "https://speedtest.dallas.linode.com/100MB-dallas.bin"},
	{"Linode Fremont", "https://speedtest.fremont.linode.com/100MB-fremont.bin"},
	{"Linode Toronto", "https://speedtest.toronto1.linode.com/100MB-toronto1.bin"},
	{"Linode London", "https://speedtest.london.linode.com/100MB-london.bin"},
	{"Linode Frankfurt", "https://speedtest.frankfurt.linode.com/100MB-frankfurt.bin"},
	{"Linode Mumbai", "https://speedtest.mumbai1.linode.com/100MB-mumbai1.bin"},
	{"Linode Singapore", "https://speedtest.singapore.linode.com/100MB-singapore.bin"},
	{"Linode Tokyo", "https://speedtest.tokyo2.linode.com/100MB-tokyo2.bin"},
	{"Hetzner Ashburn", "https://ash-speed.hetzner.com/100MB.bin"},
	{"Hetzner Hillsboro", "https://hil-speed.hetzner.com/100MB.bin"},
	{"Hetzner Falkenstein", "https://fsn1-speed.hetzner.com/100MB.bin"},
	{"Hetzner Nuremberg", "https://nbg1-speed.hetzner.com/100MB.bin"},
	{"Hetzner Helsinki", "https://hel1-speed.hetzner.com/100MB.bin"},
	{"Hetzner Singapore", "https://sin-speed.hetzner.com/100MB.bin"},
	{"OVH Roubaix", "https://proof.ovh.net/files/100Mb.dat"},
}

type rankedMirror struct {
	Name, URL string
	RTT       time.Duration
}

// dialFunc is how a mirror's round trip is taken; tests replace it.
var dialFunc = func(ctx context.Context, addr string) (net.Conn, error) {
	return core.GuardedDial(ctx, "tcp", addr)
}

// rankMirrors times a TCP connect to every mirror, twice, keeping the
// quicker, and returns those that answered, nearest first. A connect is one
// round trip, which is what distance costs a download; a whole HTTPS request
// would add the server's own delay to it.
func rankMirrors(ctx context.Context) []rankedMirror {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	var mu sync.Mutex
	var out []rankedMirror
	var wg sync.WaitGroup
	for _, mr := range downloadMirrors {
		u, err := url.Parse(mr.URL)
		if err != nil {
			continue
		}
		host := u.Host
		if u.Port() == "" {
			host = net.JoinHostPort(u.Hostname(), "443")
		}
		wg.Add(1)
		go func(name, link, addr string) {
			defer wg.Done()
			best := time.Duration(0)
			for i := 0; i < 2; i++ {
				t0 := time.Now()
				c, err := dialFunc(ctx, addr)
				if err != nil {
					continue
				}
				d := time.Since(t0)
				c.Close()
				if best == 0 || d < best {
					best = d
				}
			}
			if best > 0 {
				mu.Lock()
				out = append(out, rankedMirror{name, link, best})
				mu.Unlock()
			}
		}(mr.Name, mr.URL, host)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].RTT < out[j].RTT })
	return out
}
