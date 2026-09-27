// Package provideragent is the provider side of the provider protocol
// (core/provider.go): it runs next to a backend in another container or on
// another host, reads what the backend writes, and sends it to the core.
// The first backend is Suricata: the agent tails its EVE log.
package provideragent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// Config is what the agent needs.
type Config struct {
	Core     string   // the core's base URL, e.g. http://flowsight:8080
	Token    string   // a named API token; its name is this provider's name
	EVE      string   // Suricata's EVE log
	Types    []string // EVE event types to send; the core uses alert and tls
	State    string   // where to keep the read position across restarts; "" for none
	Version  string
	Batch    int // records per batch
	Buffer   int // records kept while the core cannot be reached
	MaxBytes int // bytes per batch, under the core's 4 MB request limit
}

// Agent sends a Suricata EVE log to the core.
type Agent struct {
	cfg     Config
	client  *http.Client
	tail    *core.Tailer
	pending [][]byte
	dropped int64

	welcomed  bool
	name      string
	lastHello time.Time
	heartbeat time.Duration
	backoff   time.Duration
	retryAt   time.Time

	now func() time.Time
	log func(string)
}

// New makes an agent. The tail starts at the end of the log, or where the
// state file says the last run stopped.
func New(cfg Config, log func(string)) *Agent {
	if len(cfg.Types) == 0 {
		cfg.Types = []string{"alert", "tls"}
	}
	if cfg.Batch <= 0 {
		cfg.Batch = 500
	}
	if cfg.Buffer <= 0 {
		cfg.Buffer = 20000
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = 2 << 20
	}
	a := &Agent{cfg: cfg, client: &http.Client{Timeout: 15 * time.Second}, tail: core.NewTailer(cfg.EVE),
		heartbeat: 30 * time.Second, now: time.Now, log: log}
	if off, ino, ok := readState(cfg.State); ok {
		a.tail.Restore(off, ino)
	}
	return a
}

// Run steps until stop is closed.
func (a *Agent) Run(stop <-chan struct{}) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		a.Step()
		select {
		case <-stop:
			return
		case <-t.C:
		}
	}
}

// Step reads what is new and sends what it can. It never blocks for long:
// a core that cannot be reached is retried with a growing back-off while
// the records wait, up to the buffer's bound.
func (a *Agent) Step() {
	a.read()
	if a.now().Before(a.retryAt) {
		return
	}
	if !a.welcomed || a.now().Sub(a.lastHello) >= a.heartbeat {
		if err := a.hello(); err != nil {
			a.fail("hello", err)
			return
		}
	}
	for len(a.pending) > 0 {
		n := a.batchSize()
		if err := a.send(a.pending[:n]); err != nil {
			a.fail("sending events", err)
			return
		}
		a.pending = a.pending[n:]
		a.dropped = 0
		a.saveState()
	}
	a.backoff = 0
}

func (a *Agent) fail(what string, err error) {
	if a.backoff == 0 {
		a.backoff = time.Second
	} else if a.backoff < 30*time.Second {
		a.backoff *= 2
	}
	a.retryAt = a.now().Add(a.backoff)
	a.log(fmt.Sprintf("%s: %v; retrying in %s with %d records waiting", what, err, a.backoff, len(a.pending)))
}

// read takes new lines of the wanted types, keeping at most Buffer of them;
// the oldest go first, and are counted.
func (a *Agent) read() {
	_, err := a.tail.Lines(func(line []byte) {
		if !a.wanted(line) {
			return
		}
		a.pending = append(a.pending, append([]byte(nil), line...))
	})
	if err != nil && !os.IsNotExist(err) {
		a.log("reading " + a.cfg.EVE + ": " + err.Error())
	}
	if over := len(a.pending) - a.cfg.Buffer; over > 0 {
		a.pending = a.pending[over:]
		a.dropped += int64(over)
	}
	if len(a.pending) == 0 {
		a.saveState() // nothing wanted was read, but the position moved
	}
}

func (a *Agent) wanted(line []byte) bool {
	var e struct {
		EventType string `json:"event_type"`
	}
	if json.Unmarshal(line, &e) != nil {
		return false
	}
	for _, t := range a.cfg.Types {
		if e.EventType == t {
			return true
		}
	}
	return false
}

func (a *Agent) batchSize() int {
	size, n := 0, 0
	for n < len(a.pending) && n < a.cfg.Batch {
		size += len(a.pending[n]) + 1
		if size > a.cfg.MaxBytes && n > 0 {
			break
		}
		n++
	}
	return n
}

func (a *Agent) hello() error {
	var w core.ProviderWelcome
	err := a.post("/api/provider/v1/hello", core.ProviderHello{Protocol: core.ProviderProtocol, Role: "detector",
		Kind: "suricata", Version: a.cfg.Version, Formats: []string{"suricata-eve"}}, &w)
	if err != nil {
		a.welcomed = false
		return err
	}
	if !a.welcomed {
		a.log(fmt.Sprintf("connected to %s as provider %q (protocol %d)", a.cfg.Core, w.Name, w.Protocol))
	}
	a.welcomed, a.name, a.lastHello = true, w.Name, a.now()
	if w.HeartbeatSeconds > 0 {
		a.heartbeat = time.Duration(w.HeartbeatSeconds) * time.Second
	}
	accepted := false
	for _, f := range w.Accepts {
		if f == "suricata-eve" {
			accepted = true
		}
	}
	if !accepted {
		return errors.New("the core does not consume suricata-eve (is its ids module loaded?)")
	}
	return nil
}

func (a *Agent) send(records [][]byte) error {
	raw := make([]json.RawMessage, len(records))
	for i, r := range records {
		raw[i] = r
	}
	err := a.post("/api/provider/v1/events", core.ProviderEvents{Format: "suricata-eve", Records: raw, Dropped: a.dropped}, nil)
	var he *httpError
	if errors.As(err, &he) && he.status == http.StatusConflict {
		a.welcomed = false // the core restarted and forgot this provider
	}
	return err
}

type httpError struct {
	status int
	body   string
}

func (e *httpError) Error() string { return fmt.Sprintf("the core answered %d: %s", e.status, e.body) }

func (a *Agent) post(path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", strings.TrimRight(a.cfg.Core, "/")+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Flowsight-Token", a.cfg.Token)
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return &httpError{status: resp.StatusCode, body: strings.TrimSpace(string(rb))}
	}
	if out != nil {
		return json.Unmarshal(rb, out)
	}
	return nil
}

// The state file holds "offset inode" of the EVE log, written after each
// delivered batch, so a restart neither replays nor skips events.
func readState(path string) (int64, uint64, bool) {
	if path == "" {
		return 0, 0, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, false
	}
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return 0, 0, false
	}
	off, err1 := strconv.ParseInt(f[0], 10, 64)
	ino, err2 := strconv.ParseUint(f[1], 10, 64)
	return off, ino, err1 == nil && err2 == nil
}

func (a *Agent) saveState() {
	if a.cfg.State == "" || len(a.pending) > 0 {
		return // only a position with nothing waiting behind it is safe to resume from
	}
	off, ino := a.tail.Position()
	tmp := a.cfg.State + ".tmp"
	if os.WriteFile(tmp, []byte(fmt.Sprintf("%d %d\n", off, ino)), 0o600) == nil {
		_ = os.Rename(tmp, a.cfg.State)
	}
}
