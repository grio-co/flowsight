package provideragent

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// fakeCore speaks the core side of the protocol, can be taken down, and can
// forget providers as a restarted core would.
type fakeCore struct {
	mu       sync.Mutex
	down     bool
	known    bool
	hellos   int
	records  []string
	dropped  int64
	badToken int
}

func (c *fakeCore) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		if r.Header.Get("X-Flowsight-Token") != "lab-token" {
			c.badToken++
			http.Error(w, "unauthorised", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/provider/v1/hello":
			var h core.ProviderHello
			_ = json.NewDecoder(r.Body).Decode(&h)
			c.hellos++
			c.known = true
			_ = json.NewEncoder(w).Encode(core.ProviderWelcome{Protocol: 1, Name: "suricata-lab",
				Accepts: []string{"suricata-eve"}, HeartbeatSeconds: 30})
		case "/api/provider/v1/events":
			if !c.known {
				http.Error(w, "say hello first", http.StatusConflict)
				return
			}
			var ev core.ProviderEvents
			_ = json.NewDecoder(r.Body).Decode(&ev)
			for _, rec := range ev.Records {
				var e struct {
					EventType string `json:"event_type"`
					Seq       int    `json:"seq"`
				}
				_ = json.Unmarshal(rec, &e)
				c.records = append(c.records, fmt.Sprintf("%s:%d", e.EventType, e.Seq))
			}
			c.dropped += ev.Dropped
			_ = json.NewEncoder(w).Encode(map[string]int{"accepted": len(ev.Records)})
		}
	})
}

type bed struct {
	t     *testing.T
	core  *fakeCore
	srv   *httptest.Server
	eve   string
	agent *Agent
	clock time.Time
	seq   int
}

func newBed(t *testing.T, cfg Config) *bed {
	b := &bed{t: t, core: &fakeCore{}, clock: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
	b.srv = httptest.NewServer(b.core.handler())
	t.Cleanup(b.srv.Close)
	dir := t.TempDir()
	b.eve = filepath.Join(dir, "eve.json")
	if err := os.WriteFile(b.eve, []byte(`{"event_type":"alert","seq":-1}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg.Core, cfg.Token, cfg.EVE = b.srv.URL, "lab-token", b.eve
	b.agent = New(cfg, func(string) {})
	b.agent.now = func() time.Time { return b.clock }
	b.agent.Step() // opens the log at its end: history is not replayed
	return b
}

func (b *bed) write(types ...string) {
	f, err := os.OpenFile(b.eve, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		b.t.Fatal(err)
	}
	defer f.Close()
	for _, typ := range types {
		fmt.Fprintf(f, `{"timestamp":"2026-09-27T12:00:00.000000+0000","event_type":%q,"seq":%d}`+"\n", typ, b.seq)
		b.seq++
	}
}

func (b *bed) step(d time.Duration) {
	b.clock = b.clock.Add(d)
	b.agent.Step()
}

func (b *bed) got() []string {
	b.core.mu.Lock()
	defer b.core.mu.Unlock()
	return append([]string(nil), b.core.records...)
}

func TestSendsOnlyWhatTheCoreUses(t *testing.T) {
	b := newBed(t, Config{})
	b.write("alert", "flow", "dns", "tls", "stats", "alert")
	b.step(time.Second)
	want := []string{"alert:0", "tls:3", "alert:5"}
	if fmt.Sprint(b.got()) != fmt.Sprint(want) {
		t.Fatalf("sent %v, want %v", b.got(), want)
	}
	if b.core.hellos != 1 {
		t.Fatalf("hellos: %d", b.core.hellos)
	}
}

// While the core is down records wait, in order, and are delivered when it
// is back; nothing was dropped, so nothing is reported as dropped.
func TestOutageDelaysButLosesNothing(t *testing.T) {
	b := newBed(t, Config{})
	b.step(time.Second)
	b.core.down = true
	b.write("alert", "alert")
	b.step(time.Second)
	b.write("alert")
	b.step(40 * time.Second)
	if len(b.got()) != 0 {
		t.Fatal("delivered while down")
	}
	b.core.down = false
	b.step(40 * time.Second)
	if fmt.Sprint(b.got()) != "[alert:0 alert:1 alert:2]" || b.core.dropped != 0 {
		t.Fatalf("after the outage: %v dropped=%d", b.got(), b.core.dropped)
	}
}

// Past the buffer, the oldest records go and the loss is reported.
func TestBufferBoundDropsOldestAndSaysSo(t *testing.T) {
	b := newBed(t, Config{Buffer: 3})
	b.step(time.Second)
	b.core.down = true
	b.write("alert", "alert", "alert", "alert", "alert")
	b.step(time.Second)
	b.core.down = false
	b.step(40 * time.Second)
	if fmt.Sprint(b.got()) != "[alert:2 alert:3 alert:4]" || b.core.dropped != 2 {
		t.Fatalf("after overflow: %v dropped=%d", b.got(), b.core.dropped)
	}
}

// A core that restarted has forgotten the provider: the agent introduces
// itself again and the batch goes through.
func TestReintroducesItselfToARestartedCore(t *testing.T) {
	b := newBed(t, Config{})
	b.write("alert")
	b.step(time.Second)
	b.core.known = false
	b.write("alert")
	b.step(time.Second) // 409, back-off
	b.step(5 * time.Second)
	if fmt.Sprint(b.got()) != "[alert:0 alert:1]" || b.core.hellos != 2 {
		t.Fatalf("after a core restart: %v hellos=%d", b.got(), b.core.hellos)
	}
}

// With a state file a restarted agent carries on where it stopped: what was
// delivered is not sent twice, and what was written meanwhile is not lost.
func TestStateFileResumes(t *testing.T) {
	state := filepath.Join(t.TempDir(), "position")
	b := newBed(t, Config{State: state})
	b.write("alert")
	b.step(time.Second)
	b.write("alert") // written while no agent runs
	b.agent = New(Config{Core: b.srv.URL, Token: "lab-token", EVE: b.eve, State: state}, func(string) {})
	b.agent.now = func() time.Time { return b.clock }
	b.step(time.Second)
	if fmt.Sprint(b.got()) != "[alert:0 alert:1]" {
		t.Fatalf("after an agent restart: %v", b.got())
	}
}

func TestBatchesStayUnderTheSizeLimit(t *testing.T) {
	b := newBed(t, Config{Batch: 2})
	b.write("alert", "alert", "alert", "alert", "alert")
	b.step(time.Second)
	if len(b.got()) != 5 {
		t.Fatalf("records: %v", b.got())
	}
}
