package qos

// What the link really carries, measured from the firewall itself.
//
// Shaping needs one honest number per direction: the rate the carrier
// actually delivers, not the one on the bill. This measures it. A burst of
// parallel downloads and uploads runs from the gateway for a few seconds
// each, and the WAN interface's own byte counters are read once a second
// throughout. The counters see everything the link carried, the test's
// traffic and everyone else's, so the capacity estimate is the interface's
// peak, and the difference between that and the tester's own throughput is
// the load that was already there. A test run at 8 pm while two people
// stream is not wrong, it is just measured beside them.
//
// A second measurement is taken against speedtest.net's public servers,
// using their plain HTTP test files, because that is the number people
// compare against. When the two disagree by two percent or more both are
// run again, once, so a single congested moment does not become the
// setting. Every attempt is logged.
//
// No third-party code: the speedtest.net exchange is three HTTP requests
// (server list, download of random data, upload of random data), and the
// built-in test uses Cloudflare's speed endpoints the same way.

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// SpeedTest is one complete run: the built-in measurement, the speedtest.net
// measurement, the load seen on the interface, and what was concluded.
type SpeedTest struct {
	ID        string  `json:"id"`
	TS        int64   `json:"ts"`
	Duration  float64 `json:"duration_s"`
	Interface string  `json:"interface"`
	Attempt   int     `json:"attempt"` // 1, or 2 after a rerun
	Rerun     bool    `json:"rerun"`   // this attempt was caused by divergence
	// The tester's own throughput, Mbit/s.
	DownMbit float64 `json:"down_mbit"`
	UpMbit   float64 `json:"up_mbit"`
	// What the interface carried at the same time, Mbit/s: the test plus
	// everything else. This is the capacity estimate.
	IfaceDownMbit float64 `json:"iface_down_mbit"`
	IfaceUpMbit   float64 `json:"iface_up_mbit"`
	// The load that was already there: the interface's rate in the seconds
	// before the test, and the difference during it.
	BaseDownMbit float64 `json:"base_down_mbit"`
	BaseUpMbit   float64 `json:"base_up_mbit"`
	LoadDownMbit float64 `json:"load_down_mbit"`
	LoadUpMbit   float64 `json:"load_up_mbit"`
	// speedtest.net, when it answered.
	OoklaServer   string  `json:"ookla_server,omitempty"`
	OoklaSponsor  string  `json:"ookla_sponsor,omitempty"`
	OoklaDownMbit float64 `json:"ookla_down_mbit,omitempty"`
	OoklaUpMbit   float64 `json:"ookla_up_mbit,omitempty"`
	OoklaLatency  float64 `json:"ookla_latency_ms,omitempty"`
	OoklaError    string  `json:"ookla_error,omitempty"`
	// How far the two measurements were apart, as a fraction of the larger.
	DivergeDown float64 `json:"diverge_down"`
	DivergeUp   float64 `json:"diverge_up"`
	// The numbers to put in the settings: the interface peak, which counts
	// the load already present, rounded down to whole Mbit/s.
	SuggestDown int    `json:"suggest_down_mbit"`
	SuggestUp   int    `json:"suggest_up_mbit"`
	Error       string `json:"error,omitempty"`
	Note        string `json:"note,omitempty"`
}

const (
	speedTestsKV    = "qos.speedtests"
	speedTestsKeep  = 50
	divergenceLimit = 0.02
	testSeconds     = 8
	testStreams     = 6
	baselineSeconds = 4
)

type speedState struct {
	mu      sync.Mutex
	running bool
	stage   string
	since   time.Time
	tests   []SpeedTest
	loaded  bool
}

func (m *Module) speed() *speedState {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sp == nil {
		m.sp = &speedState{}
	}
	return m.sp
}

func (m *Module) loadSpeedTests() {
	sp := m.speed()
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if sp.loaded {
		return
	}
	sp.loaded = true
	var tests []SpeedTest
	if m.ctx != nil && m.ctx.Store != nil && m.ctx.Store.KVGet(speedTestsKV, &tests) {
		sp.tests = tests
	}
}

func (m *Module) recordSpeedTest(t SpeedTest) {
	sp := m.speed()
	sp.mu.Lock()
	sp.tests = append(sp.tests, t)
	if len(sp.tests) > speedTestsKeep {
		sp.tests = sp.tests[len(sp.tests)-speedTestsKeep:]
	}
	tests := append([]SpeedTest(nil), sp.tests...)
	sp.mu.Unlock()
	if m.ctx != nil && m.ctx.Store != nil {
		_ = m.ctx.Store.KVSet(speedTestsKV, tests)
	}
}

// ---------------------------------------------------------------- maths

// mbitPerSec converts bytes over seconds to megabits per second.
func mbitPerSec(bytesN float64, seconds float64) float64 {
	if seconds <= 0 {
		return 0
	}
	return bytesN * 8 / seconds / 1e6
}

// divergence is how far apart two rates are, as a fraction of the larger.
// Two zeros do not diverge; one zero against anything does entirely.
func divergence(a, b float64) float64 {
	hi := math.Max(a, b)
	if hi <= 0 {
		return 0
	}
	return math.Abs(a-b) / hi
}

// needsRerun says whether a first attempt's two measurements disagree
// enough to be run again. A speedtest.net failure is not a disagreement.
func needsRerun(t SpeedTest) bool {
	if t.OoklaError != "" || (t.OoklaDownMbit == 0 && t.OoklaUpMbit == 0) {
		return false
	}
	return t.DivergeDown >= divergenceLimit || t.DivergeUp >= divergenceLimit
}

// peakRate is the largest one-second rate in a series of per-second byte
// counts, ignoring the first sample (ramp-up) when there are enough.
func peakRate(perSecond []float64) float64 {
	if len(perSecond) == 0 {
		return 0
	}
	start := 0
	if len(perSecond) > 3 {
		start = 1
	}
	best := 0.0
	for _, v := range perSecond[start:] {
		if v > best {
			best = v
		}
	}
	return best
}

// meanRate is the average of a series, ramp-up excluded the same way.
func meanRate(perSecond []float64) float64 {
	if len(perSecond) == 0 {
		return 0
	}
	start := 0
	if len(perSecond) > 3 {
		start = 1
	}
	sum := 0.0
	for _, v := range perSecond[start:] {
		sum += v
	}
	return sum / float64(len(perSecond)-start)
}

// suggest turns a measured capacity into a whole-Mbit setting, never above
// what was seen and never below one.
func suggest(capacityMbit float64) int {
	n := int(math.Floor(capacityMbit))
	if n < 1 && capacityMbit > 0 {
		return 1
	}
	return n
}

// ---------------------------------------------------------------- interface counters

// ifaceCounters reads bytes in and out for an interface from the platform.
type ifaceCounters struct{ in, out float64 }

var netstatLineRe = regexp.MustCompile(`^(\S+)\s+\d+\s+<Link#\d+>\s+(?:\S+\s+)?(\d+)\s+\d+\s+\d+\s+(\d+)\s+(\d+)\s+\d+\s+(\d+)`)

// parseNetstatIB reads the <Link#> line of `netstat -ibn -I <if>` (FreeBSD):
// Name Mtu Network Address Ipkts Ierrs Idrop Ibytes Opkts Oerrs Obytes Coll.
func parseNetstatIB(out, iface string) (ifaceCounters, bool) {
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 11 || f[0] != iface || !strings.HasPrefix(f[2], "<Link#") {
			continue
		}
		// With a hardware address the byte columns sit at 7 and 10; a
		// link without one shifts everything left by one.
		off := 0
		if _, err := strconv.ParseUint(f[3], 10, 64); err == nil {
			off = -1
		}
		in, err1 := strconv.ParseFloat(f[7+off], 64)
		outB, err2 := strconv.ParseFloat(f[10+off], 64)
		if err1 == nil && err2 == nil {
			return ifaceCounters{in: in, out: outB}, true
		}
	}
	return ifaceCounters{}, false
}

// parseProcNetDev reads /proc/net/dev (Linux) for one interface.
func parseProcNetDev(out, iface string) (ifaceCounters, bool) {
	for _, l := range strings.Split(out, "\n") {
		name, rest, ok := strings.Cut(strings.TrimSpace(l), ":")
		if !ok || strings.TrimSpace(name) != iface {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			return ifaceCounters{}, false
		}
		in, err1 := strconv.ParseFloat(f[0], 64)
		outB, err2 := strconv.ParseFloat(f[8], 64)
		if err1 == nil && err2 == nil {
			return ifaceCounters{in: in, out: outB}, true
		}
	}
	return ifaceCounters{}, false
}

func (m *Module) readCounters(iface string) (ifaceCounters, error) {
	if runtime.GOOS == "linux" {
		out, err := core.Run(5*time.Second, "cat", "/proc/net/dev")
		if err != nil {
			return ifaceCounters{}, err
		}
		if c, ok := parseProcNetDev(out, iface); ok {
			return c, nil
		}
		return ifaceCounters{}, fmt.Errorf("no counters for %s", iface)
	}
	out, err := core.Run(5*time.Second, "netstat", "-ibn", "-I", iface)
	if err != nil {
		return ifaceCounters{}, err
	}
	if c, ok := parseNetstatIB(out, iface); ok {
		return c, nil
	}
	return ifaceCounters{}, fmt.Errorf("no counters for %s", iface)
}

// wanInterface is the interface the default route leaves by, unless the
// operator named one.
func (m *Module) wanInterface() string {
	if s := strings.TrimSpace(core.Str(m.ctx.Settings(), "wan_interface", "")); s != "" {
		return s
	}
	if runtime.GOOS == "linux" {
		out, _ := core.Run(5*time.Second, "sh", "-c", "ip route show default 2>/dev/null | head -1")
		f := strings.Fields(out)
		for i, w := range f {
			if w == "dev" && i+1 < len(f) {
				return f[i+1]
			}
		}
		return ""
	}
	out, _ := core.Run(5*time.Second, "route", "-n", "get", "default")
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), ":"); ok && strings.TrimSpace(k) == "interface" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// sampler reads the interface once a second and keeps per-second deltas.
type sampler struct {
	m     *Module
	iface string
	stop  chan struct{}
	done  chan struct{}
	mu    sync.Mutex
	in    []float64 // bytes per second
	out   []float64
	err   error
}

func (m *Module) startSampler(iface string) *sampler {
	s := &sampler{m: m, iface: iface, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		prev, err := m.readCounters(iface)
		if err != nil {
			s.mu.Lock()
			s.err = err
			s.mu.Unlock()
			return
		}
		t := time.NewTicker(time.Second)
		defer t.Stop()
		last := time.Now()
		for {
			select {
			case <-s.stop:
				return
			case now := <-t.C:
				cur, err := m.readCounters(iface)
				if err != nil {
					continue
				}
				dt := now.Sub(last).Seconds()
				last = now
				if dt <= 0 {
					continue
				}
				s.mu.Lock()
				s.in = append(s.in, math.Max(0, cur.in-prev.in)/dt)
				s.out = append(s.out, math.Max(0, cur.out-prev.out)/dt)
				s.mu.Unlock()
				prev = cur
			}
		}
	}()
	return s
}

// take returns the samples gathered since the last take and clears them.
func (s *sampler) take() (in, out []float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	in, out = s.in, s.out
	s.in, s.out = nil, nil
	return
}

func (s *sampler) close() error {
	close(s.stop)
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// ---------------------------------------------------------------- the built-in test

// speedClient makes the requests. Timeouts are generous: a saturated link
// is exactly the condition being measured.
func speedClient() *http.Client {
	return &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{
		MaxIdleConnsPerHost: testStreams, DisableCompression: true, Proxy: nil}}
}

// downloadFor pulls url from n streams for d seconds and returns the bytes
// received and the time it actually took.
func downloadFor(ctx context.Context, client *http.Client, url string, n int, d time.Duration) (float64, float64, error) {
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	var total int64
	var wg sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex
	start := time.Now()
	buf := make([][]byte, n)
	for i := 0; i < n; i++ {
		buf[i] = make([]byte, 256<<10)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for ctx.Err() == nil {
				req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
				if err != nil {
					return
				}
				req.Header.Set("User-Agent", "FlowSight/1 (gateway bandwidth check)")
				resp, err := client.Do(req)
				if err == nil && resp.StatusCode >= 400 {
					err = fmt.Errorf("HTTP %d from %s", resp.StatusCode, req.URL.Host)
					resp.Body.Close()
				}
				if err != nil {
					if ctx.Err() == nil {
						errMu.Lock()
						if firstErr == nil {
							firstErr = err
						}
						errMu.Unlock()
						time.Sleep(200 * time.Millisecond)
					}
					continue
				}
				for {
					k, err := resp.Body.Read(buf[i])
					atomic.AddInt64(&total, int64(k))
					if err != nil {
						break
					}
				}
				resp.Body.Close()
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	if total == 0 && firstErr != nil {
		return 0, elapsed, firstErr
	}
	return float64(total), elapsed, nil
}

// randomBody is a reader of random bytes: compressible zeros would flatter
// an upload through any middlebox that compresses.
type randomBody struct {
	left int64
	src  []byte
	pos  int
}

func newRandomBody(n int64) *randomBody {
	src := make([]byte, 1<<20)
	_, _ = rand.Read(src)
	return &randomBody{left: n, src: src}
}

func (r *randomBody) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.left {
		p = p[:r.left]
	}
	k := copy(p, r.src[r.pos:])
	r.pos = (r.pos + k) % len(r.src)
	r.left -= int64(k)
	return k, nil
}

// uploadFor posts random data to url from n streams for d seconds.
func uploadFor(ctx context.Context, client *http.Client, url string, n int, d time.Duration) (float64, float64, error) {
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	var total int64
	var wg sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex
	start := time.Now()
	const chunk = 8 << 20
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				body := &countingReader{r: newRandomBody(chunk), n: &total}
				req, err := http.NewRequestWithContext(ctx, "POST", url, body)
				if err != nil {
					return
				}
				req.ContentLength = chunk
				req.Header.Set("Content-Type", "application/octet-stream")
				req.Header.Set("User-Agent", "FlowSight/1 (gateway bandwidth check)")
				resp, err := client.Do(req)
				if err == nil && resp.StatusCode >= 400 {
					err = fmt.Errorf("HTTP %d from %s", resp.StatusCode, req.URL.Host)
					resp.Body.Close()
				}
				if err != nil {
					if ctx.Err() == nil {
						errMu.Lock()
						if firstErr == nil {
							firstErr = err
						}
						errMu.Unlock()
						time.Sleep(200 * time.Millisecond)
					}
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	if total == 0 && firstErr != nil {
		return 0, elapsed, firstErr
	}
	return float64(total), elapsed, nil
}

type countingReader struct {
	r io.Reader
	n *int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	k, err := c.r.Read(p)
	atomic.AddInt64(c.n, int64(k))
	return k, err
}

const (
	cfDown = "https://speed.cloudflare.com/__down?bytes=25000000"
	cfUp   = "https://speed.cloudflare.com/__up"
)

// ---------------------------------------------------------------- speedtest.net

type ooklaServer struct {
	URL     string  `xml:"url,attr"`
	Lat     float64 `xml:"lat,attr"`
	Lon     float64 `xml:"lon,attr"`
	Name    string  `xml:"name,attr"`
	Country string  `xml:"country,attr"`
	Sponsor string  `xml:"sponsor,attr"`
	Host    string  `xml:"host,attr"`
	ID      string  `xml:"id,attr"`
	latency float64
}

type ooklaList struct {
	Servers []ooklaServer `xml:"servers>server"`
}

func parseOoklaServers(b []byte) ([]ooklaServer, error) {
	var l ooklaList
	if err := xml.Unmarshal(b, &l); err != nil {
		return nil, err
	}
	return l.Servers, nil
}

// nearestOokla orders servers by distance from a point, nearest first.
func nearestOokla(servers []ooklaServer, lat, lon float64, n int) []ooklaServer {
	out := append([]ooklaServer(nil), servers...)
	if lat != 0 || lon != 0 {
		sort.Slice(out, func(i, j int) bool {
			return distKm(lat, lon, out[i].Lat, out[i].Lon) < distKm(lat, lon, out[j].Lat, out[j].Lon)
		})
	}
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// ooklaBase turns a server's upload URL into its test-file base.
func ooklaBase(u string) string {
	u = strings.TrimSpace(u)
	if i := strings.LastIndex(u, "/"); i > 0 {
		return u[:i+1]
	}
	return u
}

// ooklaJSONServer is one entry of speedtest.net's current server directory.
type ooklaJSONServer struct {
	URL     string `json:"url"`
	Host    string `json:"host"`
	Name    string `json:"name"`
	Country string `json:"country"`
	Sponsor string `json:"sponsor"`
	ID      any    `json:"id"`
	Lat     string `json:"lat"`
	Lon     string `json:"lon"`
}

func parseOoklaJSON(b []byte) ([]ooklaServer, error) {
	var list []ooklaJSONServer
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	out := make([]ooklaServer, 0, len(list))
	for _, x := range list {
		lat, _ := strconv.ParseFloat(x.Lat, 64)
		lon, _ := strconv.ParseFloat(x.Lon, 64)
		out = append(out, ooklaServer{URL: x.URL, Host: x.Host, Name: x.Name, Country: x.Country, Sponsor: x.Sponsor, ID: fmt.Sprint(x.ID), Lat: lat, Lon: lon})
	}
	return out, nil
}

// ooklaEndpoints returns the download and upload URLs for a server: the
// current servers serve /download?size=N and /upload over HTTPS on their
// host; the legacy ones serve random files beside upload.php.
func ooklaEndpoints(s ooklaServer, id string) (down, up string) {
	if s.Host != "" {
		return "https://" + s.Host + "/download?nocache=" + id + "&size=25000000", "https://" + s.Host + "/upload?nocache=" + id
	}
	base := ooklaBase(s.URL)
	return base + "random4000x4000.jpg?x=" + id, base + "upload.php?x=" + id
}

// ooklaPick chooses the speedtest.net server to compare against: the
// nearest dozen from the current directory (the static list when that is
// unreachable), then the quickest of them to answer. Distance is a guess;
// the round trip is a measurement.
func (m *Module) ooklaPick(ctx context.Context, client *http.Client) (ooklaServer, error) {
	var lat, lon float64
	if h, ok := m.ctx.Service("home").(interface {
		HomeLatLon() (float64, float64, bool)
	}); ok {
		if la, lo, ok := h.HomeLatLon(); ok {
			lat, lon = la, lo
		}
	}
	fetch := func(url string) ([]byte, error) {
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		req.Header.Set("User-Agent", "FlowSight/1 (gateway bandwidth check)")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	}
	var servers []ooklaServer
	dir := "https://www.speedtest.net/api/js/servers?engine=js&https_functional=true&limit=12"
	if lat != 0 || lon != 0 {
		dir += fmt.Sprintf("&lat=%.4f&lon=%.4f", lat, lon)
	}
	if b, err := fetch(dir); err == nil {
		servers, _ = parseOoklaJSON(b)
	}
	if len(servers) == 0 {
		b, err := fetch("https://www.speedtest.net/speedtest-servers-static.php")
		if err != nil {
			return ooklaServer{}, err
		}
		servers, err = parseOoklaServers(b)
		if err != nil || len(servers) == 0 {
			return ooklaServer{}, fmt.Errorf("speedtest.net server list unreadable")
		}
	}
	cands := nearestOokla(servers, lat, lon, 10)
	best := ooklaServer{}
	bestMs := math.MaxFloat64
	for _, s := range cands {
		probe := ooklaBase(s.URL) + "latency.txt?x=" + strconv.FormatInt(time.Now().UnixNano(), 10)
		if s.Host != "" {
			probe = "https://" + s.Host + "/hello?nocache=" + strconv.FormatInt(time.Now().UnixNano(), 10)
		}
		t0 := time.Now()
		r, _ := http.NewRequestWithContext(ctx, "GET", probe, nil)
		r.Header.Set("User-Agent", "FlowSight/1 (gateway bandwidth check)")
		resp, err := client.Do(r)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		ms := float64(time.Since(t0).Microseconds()) / 1000
		if ms < bestMs {
			bestMs, best = ms, s
			best.latency = ms
		}
	}
	if best.URL == "" && best.Host == "" {
		return ooklaServer{}, fmt.Errorf("no speedtest.net server answered")
	}
	return best, nil
}

// ---------------------------------------------------------------- the run

// runSpeedTest performs one attempt and returns it. The sampler on the WAN
// interface runs throughout; the baseline is what it saw before any test
// traffic started.
func (m *Module) runSpeedTest(ctx context.Context, attempt int, rerun bool) (t SpeedTest) {
	t = SpeedTest{ID: fmt.Sprintf("%d", time.Now().UnixNano()), TS: time.Now().Unix(), Attempt: attempt, Rerun: rerun}
	start := time.Now()
	defer func() { t.Duration = math.Round(time.Since(start).Seconds()*10) / 10 }()
	t.Interface = m.wanInterface()
	if t.Interface == "" {
		t.Error = "no WAN interface: set wan_interface under Settings › qos"
		return t
	}
	sp := m.speed()
	setStage := func(s string) { sp.mu.Lock(); sp.stage = s; sp.mu.Unlock() }
	smp := m.startSampler(t.Interface)
	client := speedClient()

	setStage("measuring the load already on the link")
	time.Sleep(baselineSeconds * time.Second)
	bin, bout := smp.take()
	t.BaseDownMbit, t.BaseUpMbit = mbitPerSec(meanRate(bin), 1), mbitPerSec(meanRate(bout), 1)

	setStage("downloading")
	dBytes, dSec, dErr := downloadFor(ctx, client, cfDown, testStreams, testSeconds*time.Second)
	if dBytes == 0 && dErr != nil && strings.Contains(dErr.Error(), "429") {
		setStage("download rate-limited; waiting to try again")
		select {
		case <-time.After(20 * time.Second):
		case <-ctx.Done():
		}
		smp.take()
		dBytes, dSec, dErr = downloadFor(ctx, client, cfDown, testStreams, testSeconds*time.Second)
	}
	din, _ := smp.take()
	t.DownMbit = mbitPerSec(dBytes, dSec)
	t.IfaceDownMbit = mbitPerSec(peakRate(din), 1)

	setStage("uploading")
	uBytes, uSec, uErr := uploadFor(ctx, client, cfUp, testStreams, testSeconds*time.Second)
	_, uout := smp.take()
	t.UpMbit = mbitPerSec(uBytes, uSec)
	t.IfaceUpMbit = mbitPerSec(peakRate(uout), 1)
	var problems []string
	if dErr != nil {
		problems = append(problems, "download: "+dErr.Error())
	} else if dBytes == 0 {
		problems = append(problems, "download: no data received")
	}
	if uErr != nil {
		problems = append(problems, "upload: "+uErr.Error())
	} else if uBytes == 0 {
		problems = append(problems, "upload: no data sent")
	}
	if len(problems) > 0 {
		t.Error = "built-in test: " + strings.Join(problems, "; ")
	}
	// The load that shared the link with the test.
	t.LoadDownMbit = math.Max(0, t.IfaceDownMbit-t.DownMbit)
	t.LoadUpMbit = math.Max(0, t.IfaceUpMbit-t.UpMbit)

	setStage("speedtest.net")
	if srv, err := m.ooklaPick(ctx, client); err != nil {
		t.OoklaError = err.Error()
	} else {
		downURL, upURL := ooklaEndpoints(srv, t.ID)
		t.OoklaServer, t.OoklaSponsor, t.OoklaLatency = srv.Name+", "+srv.Country, srv.Sponsor, srv.latency
		ob, os, oerr := downloadFor(ctx, client, downURL, testStreams, testSeconds*time.Second)
		t.OoklaDownMbit = mbitPerSec(ob, os)
		ub, us, uerr := uploadFor(ctx, client, upURL, testStreams, testSeconds*time.Second)
		t.OoklaUpMbit = mbitPerSec(ub, us)
		if oerr != nil && uerr != nil {
			t.OoklaError = "speedtest.net did not answer: " + oerr.Error()
		}
	}
	_ = smp.close()
	setStage("")

	t.DivergeDown = divergence(t.DownMbit, t.OoklaDownMbit)
	t.DivergeUp = divergence(t.UpMbit, t.OoklaUpMbit)
	// The suggestion is what the interface carried at its peak, which is
	// the test plus whatever else was running: the link's capacity as
	// observed, not the tester's share of it.
	t.SuggestDown = suggest(math.Max(t.IfaceDownMbit, math.Max(t.DownMbit, t.OoklaDownMbit)))
	t.SuggestUp = suggest(math.Max(t.IfaceUpMbit, math.Max(t.UpMbit, t.OoklaUpMbit)))
	far := ""
	if t.OoklaLatency > 80 {
		far = fmt.Sprintf(" (the nearest speedtest.net server that answered is %.0f ms away and its plain-HTTP test files read low; treat its number as a floor)", t.OoklaLatency)
	}
	switch {
	case t.Error != "":
		t.Note = "the built-in test did not complete in both directions" + far
	case t.OoklaError != "":
		t.Note = "speedtest.net could not be compared; the built-in measurement stands alone"
	case needsRerun(t) && attempt == 1:
		t.Note = fmt.Sprintf("the two measurements differ by %.1f%% down / %.1f%% up, more than the 2%% allowed, so the test runs again", t.DivergeDown*100, t.DivergeUp*100)
	case needsRerun(t):
		t.Note = "still apart after a rerun; the higher of the two is taken as what the link can carry" + far
	default:
		t.Note = "the two measurements agree" + far
	}
	return t
}

// startSpeedTest runs a test (and a rerun when needed) in the background.
func (m *Module) startSpeedTest() (bool, string) {
	sp := m.speed()
	sp.mu.Lock()
	if sp.running {
		since := sp.since
		sp.mu.Unlock()
		return false, fmt.Sprintf("a test has been running for %s", time.Since(since).Round(time.Second))
	}
	sp.running, sp.since, sp.stage = true, time.Now(), "starting"
	sp.mu.Unlock()
	go func() {
		defer func() {
			sp.mu.Lock()
			sp.running, sp.stage = false, ""
			sp.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
		defer cancel()
		first := m.runSpeedTest(ctx, 1, false)
		m.recordSpeedTest(first)
		if first.Error == "" && needsRerun(first) {
			// The endpoint rate-limits a second burst that follows the first
			// too closely; half a minute between them is enough.
			sp.mu.Lock()
			sp.stage = "waiting before the rerun"
			sp.mu.Unlock()
			select {
			case <-time.After(30 * time.Second):
			case <-ctx.Done():
				return
			}
			second := m.runSpeedTest(ctx, 2, true)
			m.recordSpeedTest(second)
		}
	}()
	return true, ""
}

// ---------------------------------------------------------------- API

func (m *Module) apiSpeedTests(r *core.Req) (any, error) {
	m.loadSpeedTests()
	sp := m.speed()
	sp.mu.Lock()
	tests := make([]SpeedTest, 0, len(sp.tests))
	for i := len(sp.tests) - 1; i >= 0; i-- {
		tests = append(tests, sp.tests[i])
	}
	running, stage, since := sp.running, sp.stage, sp.since
	sp.mu.Unlock()
	out := map[string]any{"tests": tests, "running": running, "stage": stage, "interface": m.wanInterface(),
		"note": "The built-in test runs from this firewall against Cloudflare's speed endpoints while the WAN interface's own counters are read every second, so the capacity estimate includes whatever else was using the link. speedtest.net is measured the same way for comparison; a difference of 2% or more runs both again once. Every attempt is kept here."}
	if running {
		out["running_for_s"] = int(time.Since(since).Seconds())
	}
	return out, nil
}

func (m *Module) apiSpeedTestRun(r *core.Req) (any, error) {
	m.loadSpeedTests()
	started, why := m.startSpeedTest()
	return map[string]any{"started": started, "reason": why}, nil
}

// apiSpeedTestApply writes a test's suggestion into the link settings.
func (m *Module) apiSpeedTestApply(r *core.Req) (any, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	m.loadSpeedTests()
	sp := m.speed()
	sp.mu.Lock()
	var found *SpeedTest
	for i := range sp.tests {
		if sp.tests[i].ID == in.ID {
			t := sp.tests[i]
			found = &t
		}
	}
	sp.mu.Unlock()
	if found == nil {
		return nil, core.NotFound("no such test")
	}
	if found.SuggestDown <= 0 || found.SuggestUp <= 0 {
		return nil, core.BadRequest("that test did not produce usable numbers")
	}
	s := m.ctx.Settings()
	s["download_mbit"] = found.SuggestDown
	s["upload_mbit"] = found.SuggestUp
	if err := m.ctx.Config.SetModule(m.ctx.Name, s); err != nil {
		return nil, err
	}
	m.ctx.Event("audit", fmt.Sprintf("qos link set from bandwidth test: %d/%d Mbit/s", found.SuggestDown, found.SuggestUp), map[string]any{"actor_name": r.User, "via": "test " + in.ID})
	return map[string]any{"ok": true, "download_mbit": found.SuggestDown, "upload_mbit": found.SuggestUp}, nil
}

// distKm is the great-circle distance between two points, for picking the
// nearest speedtest.net servers.
func distKm(lat1, lon1, lat2, lon2 float64) float64 {
	const r = 6371.0
	rad := func(d float64) float64 { return d * math.Pi / 180 }
	dlat, dlon := rad(lat2-lat1), rad(lon2-lon1)
	a := math.Sin(dlat/2)*math.Sin(dlat/2) + math.Cos(rad(lat1))*math.Cos(rad(lat2))*math.Sin(dlon/2)*math.Sin(dlon/2)
	return 2 * r * math.Asin(math.Min(1, math.Sqrt(a)))
}
