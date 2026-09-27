// Package mitm is stateful packet inspection: the stage that sees inside a decrypted
// session, not just its server name.
//
// FlowSight already terminates TLS for the devices a policy names, with its
// own CA, through the proxy the web module runs. That yields the request
// line and the response code. Everything else a request carries, its
// headers, its content type, the question inside a DNS-over-HTTPS query,
// lives one layer deeper, and a proxy access log cannot reach it.
//
// This module is that layer. The proxy hands each decrypted request and
// response over as it passes (ICAP, see icap.go), FlowSight reads what it
// needs and answers "no modification", and the exchange continues untouched.
//
// What it never does: store a body. Bodies are previewed to answer a
// question (which name did this DNS-over-HTTPS query ask for, what content
// type is this) and dropped. There is no setting to keep them.
package mitm

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/grioghar/flowsight/internal/core"
	"github.com/grioghar/flowsight/internal/modules/web"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

// Module implements core.Module.
type Module struct {
	ctx *core.Context

	mu       sync.Mutex
	ln       net.Listener
	lastErr  string
	started  time.Time
	requests atomic.Int64
	decoded  atomic.Int64
	bytes    atomic.Int64
	recent   []Request
}

// Request is one exchange, as the operator sees it. No body is kept.
type Request struct {
	TS       int64             `json:"ts"`
	Client   string            `json:"client"`
	Method   string            `json:"method"`
	URL      string            `json:"url"`
	Host     string            `json:"host"`
	Status   int               `json:"status"`
	Type     string            `json:"content_type,omitempty"`
	BytesIn  int64             `json:"bytes_in"`
	BytesOut int64             `json:"bytes_out"`
	MS       float64           `json:"ms"`
	Headers  map[string]string `json:"headers,omitempty"`
	Note     string            `json:"note,omitempty"`
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name:         "mitm",
		Version:      "1.0",
		Tier:         "business",
		Description:  "Stateful Packet Inspection of decrypted sessions: headers, content types and the questions inside DNS-over-HTTPS. Bodies are previewed to decode them and never stored.",
		After:        []string{"web", "tls"},
		Capabilities: []string{core.CapWebObserve},
		Defaults: map[string]any{
			"enabled":        true,
			"active":         false,
			"port":           1344,
			"clients":        []string{},
			"names":          []string{},
			"all_clients":    false,
			"record_headers": true,
			"decode_doh":     true,
			"preview_bytes":  4096,
			"keep_requests":  500,
		},
		Schema: []core.SettingField{
			{Key: "active", Label: "Inspect decrypted sessions", Type: "bool",
				Help: "Off: nothing is handed over and the proxy behaves as before. On: every request and response the proxy decrypts is read here as it passes. Only sessions a policy already decrypts ever arrive."},
			{Key: "all_clients", Label: "Inspect everything that crosses the firewall", Type: "bool",
				Help: "Off: only the devices a policy decrypts. On: FlowSight decrypts every intercepted client, phones, televisions and appliances included. A device that does not trust the FlowSight CA will fail to connect until FlowSight sees the refusal and starts relaying that name untouched (see TLS › Pinned sites), so an appliance you cannot install a certificate on ends up relayed rather than broken. Excluded hosts are never touched."},
			{Key: "port", Label: "ICAP port (loopback)", Type: "int", Restart: true,
				Help: "Where the proxy hands requests over. Loopback only; nothing else can reach it."},
			{Key: "clients", Label: "Limit to these clients", Type: "list",
				Help: "Addresses or CIDRs. Empty: every client whose sessions are decrypted."},
			{Key: "names", Label: "Limit to these names", Type: "list",
				Help: "Server names, one per line. Empty: every decrypted name. A pinned name is never decrypted, so it never arrives here."},
			{Key: "record_headers", Label: "Record request headers", Type: "bool",
				Help: "Header names and values for each request. Cookies and authorization headers are recorded as their length only, never their value."},
			{Key: "decode_doh", Label: "Decode DNS-over-HTTPS queries", Type: "bool",
				Help: "Read the question out of a DoH request and file it in the DNS history, so a browser resolving over HTTPS is as visible as one using the network's resolver."},
			{Key: "preview_bytes", Label: "Body preview (bytes)", Type: "int",
				Help: "How much of each body the proxy sends for decoding. A DNS-over-HTTPS question needs a few hundred bytes. Nothing is stored."},
			{Key: "keep_requests", Label: "Recent requests kept in memory", Type: "int"},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	ctx.Every("scrub-urls", 24*time.Hour, m.scrubStoredURLs, core.Delayed())
	ctx.Route("GET", "/api/mitm/status", m.apiStatus, core.Doc("Check if deep packet inspection is listening and retrieve decoded traffic statistics"),
		core.Returns("Inspection status", map[string]any{
			"active": true, "licensed": true, "listening": true, "port": 1344,
			"requests": 5000, "decoded": 3000, "bytes": 1000000000, "error": "",
		}))
	ctx.Route("GET", "/api/mitm/requests", m.apiRequests, core.Needs("deep.inspect"),
		core.Doc("Retrieve recent decrypted HTTPS requests with headers, methods and hostnames"),
		core.Query("limit", "integer", "Maximum results to return", false, 200),
		core.Query("q", "string", "Search filter by URL or client", false, "github.com"),
		core.Returns("Captured requests", map[string]any{
			"requests": []map[string]any{
				{"ts": 1790376243, "client": "192.168.1.10", "url": "https://github.com", "method": "GET"},
			},
		}))
	ctx.Panel(core.Panel{ID: "deep", Title: "Stateful Packet Inspection", Group: "Protect", Order: 75, Icon: "deep", Feature: "deep.inspect"})
	ctx.Every("supervise", 30*time.Second, m.supervise)
	ctx.Publish("mitm", m)
	return m.start()
}

// Enabled reports whether the proxy should hand requests over: switched on,
// licensed, and listening.
func (m *Module) Enabled() bool {
	if !core.Bool(m.ctx.Settings(), "active", false) {
		return false
	}
	if err := m.ctx.License().Allowed("deep.inspect"); err != nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ln != nil
}

// Peer is what the proxy needs: the ICAP port, the preview size, and which
// clients and names to hand over.
func (m *Module) Peer() (port, preview int, clients, names []string, ok bool) {
	if !m.Enabled() {
		return 0, 0, nil, nil, false
	}
	s := m.ctx.Settings()
	return core.Int(s, "port", 1344), core.Int(s, "preview_bytes", 4096),
		core.Strs(s, "clients"), core.Strs(s, "names"), true
}

// InspectEverything reports the switch that makes the proxy decrypt every
// intercepted client rather than only those a policy names.
func (m *Module) InspectEverything() bool {
	return m.Enabled() && core.Bool(m.ctx.Settings(), "all_clients", false)
}

func (m *Module) Health() core.Health {
	if !core.Bool(m.ctx.Settings(), "active", false) {
		return core.Health{OK: true, Detail: "off"}
	}
	if err := m.ctx.License().Allowed("deep.inspect"); err != nil {
		return core.Health{OK: true, Detail: "needs the business tier"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ln == nil {
		return core.Health{OK: false, Detail: "not listening: " + m.lastErr}
	}
	return core.Health{OK: true, Detail: fmt.Sprintf("listening, %d exchanges read, %d decoded",
		m.requests.Load(), m.decoded.Load())}
}

func (m *Module) OnConfigChange(map[string]any) error { return m.start() }

func (m *Module) Stop() error {
	m.mu.Lock()
	ln := m.ln
	m.ln = nil
	m.mu.Unlock()
	if ln != nil {
		return ln.Close()
	}
	return nil
}

func (m *Module) supervise() error {
	want := core.Bool(m.ctx.Settings(), "active", false) && m.ctx.License().Allowed("deep.inspect") == nil
	m.mu.Lock()
	up := m.ln != nil
	m.mu.Unlock()
	switch {
	case want && !up:
		return m.start()
	case !want && up:
		return m.Stop()
	}
	return nil
}

func (m *Module) start() error {
	if err := m.Stop(); err != nil {
		return err
	}
	if !core.Bool(m.ctx.Settings(), "active", false) {
		return nil
	}
	if err := m.ctx.License().Allowed("deep.inspect"); err != nil {
		m.mu.Lock()
		m.lastErr = "not licensed"
		m.mu.Unlock()
		return nil
	}
	port := core.Int(m.ctx.Settings(), "port", 1344)
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		m.mu.Lock()
		m.lastErr = err.Error()
		m.mu.Unlock()
		return nil // the supervisor tries again
	}
	m.mu.Lock()
	m.ln, m.lastErr, m.started = ln, "", time.Now()
	m.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				m.mu.Lock()
				m.lastErr = err.Error()
				m.mu.Unlock()
				return
			}
			go m.icapServe(c)
		}
	}()
	m.ctx.Log.Info("stateful packet inspection listening", "icap_port", port)
	return nil
}

// ---------------------------------------------------------------- recording

func (m *Module) record(rec Request, body []byte, isResponse bool) {
	m.requests.Add(1)
	m.bytes.Add(rec.BytesIn)
	if core.Bool(m.ctx.Settings(), "decode_doh", true) && !isResponse && len(body) > 0 {
		if n := m.decodeDoH(rec, body); n > 0 {
			m.decoded.Add(int64(n))
			rec.Note = strings.TrimSpace(rec.Note + " DNS-over-HTTPS question recorded")
		}
	}
	keep := core.Int(m.ctx.Settings(), "keep_requests", 500)
	if keep < 1 {
		keep = 1
	}
	m.mu.Lock()
	// A response completes the request logged a moment earlier; merge rather
	// than list the same exchange twice.
	merged := false
	if isResponse {
		for i := len(m.recent) - 1; i >= 0 && i > len(m.recent)-20; i-- {
			if m.recent[i].URL == rec.URL && m.recent[i].Client == rec.Client && m.recent[i].Status == 0 {
				m.recent[i].Status, m.recent[i].Type = rec.Status, rec.Type
				if rec.BytesIn > 0 {
					m.recent[i].BytesIn = rec.BytesIn
				}
				merged = true
				break
			}
		}
	}
	if !merged {
		m.recent = append(m.recent, rec)
		if len(m.recent) > keep {
			m.recent = m.recent[len(m.recent)-keep:]
		}
	}
	m.mu.Unlock()
	if isResponse || rec.URL == "" {
		return
	}
	// One flow row so the request joins the history the rest of the product
	// reads; the proxy logged the session, this says what was inside it.
	fl := core.Flow{TS: rec.TS, EndTS: rec.TS, Key: fmt.Sprintf("mitm/%s/%s/%d", rec.Client, rec.Host, rec.TS),
		SrcIP: rec.Client, Domain: hostOnly(rec.Host), Proto: "tls", DstPort: portOf(rec.Host),
		BytesIn: rec.BytesIn, Verdict: "observed", Source: "mitm",
		Attrs: map[string]any{"url": rec.URL, "method": rec.Method, "deep": true}}
	if rec.Type != "" {
		fl.Attrs["content_type"] = rec.Type
	}
	_ = m.ctx.Store.AddFlows([]core.Flow{fl})
}

// decodeDoH reads the DNS question out of a DNS-over-HTTPS request body,
// which is where every browser puts it, and files it in the DNS history.
func (m *Module) decodeDoH(rec Request, body []byte) int {
	if !strings.Contains(strings.ToLower(rec.URL), "dns-query") {
		return 0
	}
	name, qtype, ok := web.DNSQuestion(body)
	if !ok {
		return 0
	}
	provider := hostOnly(rec.Host)
	_ = m.ctx.Store.AddDNS([]core.DNSRecord{{
		TS: rec.TS, Client: rec.Client, Domain: name, QType: qtype, Action: "pass",
		RCode: "NOERROR", AnswerSource: "doh " + provider, MS: rec.MS, Source: "doh:" + provider,
	}})
	return 1
}

func hostOnly(h string) string {
	if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h[i:], "]") {
		return h[:i]
	}
	return h
}

func portOf(h string) int {
	if i := strings.LastIndexByte(h, ':'); i > 0 {
		if n, err := strconv.Atoi(h[i+1:]); err == nil {
			return n
		}
	}
	return 443
}

// ---------------------------------------------------------------- API

func (m *Module) apiStatus(r *core.Req) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string]any{
		"active":     core.Bool(m.ctx.Settings(), "active", false),
		"licensed":   m.ctx.License().Allowed("deep.inspect") == nil,
		"listening":  m.ln != nil,
		"port":       core.Int(m.ctx.Settings(), "port", 1344),
		"error":      m.lastErr,
		"since":      m.started.Unix(),
		"requests":   m.requests.Load(),
		"decoded":    m.decoded.Load(),
		"bytes":      m.bytes.Load(),
		"clients":    core.Strs(m.ctx.Settings(), "clients"),
		"names":      core.Strs(m.ctx.Settings(), "names"),
		"everything": core.Bool(m.ctx.Settings(), "all_clients", false),
		"note":       "Bodies are previewed only by the decoders that are switched on, and never stored.",
	}, nil
}

func (m *Module) apiRequests(r *core.Req) (any, error) {
	q := strings.ToLower(r.Q("q", ""))
	limit := r.QInt("limit", 200, 1, 2000)
	m.mu.Lock()
	rows := make([]Request, 0, len(m.recent))
	for i := len(m.recent) - 1; i >= 0 && len(rows) < limit; i-- {
		x := m.recent[i]
		if q != "" && !strings.Contains(strings.ToLower(x.URL+" "+x.Client+" "+x.Type), q) {
			continue
		}
		rows = append(rows, x)
	}
	m.mu.Unlock()
	return map[string]any{"requests": rows}, nil
}
