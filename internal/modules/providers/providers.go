// Package providers is the core side of the provider protocol (see
// core/provider.go): it keeps the list of providers that have introduced
// themselves, and hands each batch they send to the module that consumes its
// format.
package providers

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

const (
	heartbeat  = 30 * time.Second
	maxRecords = 5000
)

type Module struct {
	ctx   *core.Context
	mu    sync.Mutex
	sinks map[string]core.ProviderSink
	seen  map[string]*provider
}

// provider is what the core knows about one provider.
type provider struct {
	Name         string   `json:"name"`
	Role         string   `json:"role"`
	Kind         string   `json:"kind"`
	Version      string   `json:"version"`
	Capabilities []string `json:"capabilities,omitempty"`
	Formats      []string `json:"formats"`
	Client       string   `json:"client"`
	FirstSeen    int64    `json:"first_seen"`
	LastSeen     int64    `json:"last_seen"`
	Events       int64    `json:"events"`
	Dropped      int64    `json:"dropped"`
	LastError    string   `json:"last_error,omitempty"`
	Connected    bool     `json:"connected"`
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name: "providers", Version: "1.0",
		Description: "Backends in other processes, containers or hosts (the provider protocol): who is connected and what they send.",
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.sinks = map[string]core.ProviderSink{}
	m.seen = map[string]*provider{}
	ctx.Publish(core.ServiceProviderHub, m)
	ctx.Route("POST", "/api/provider/v1/hello", m.apiHello, core.Write(),
		core.Doc("Introduce a provider to the core, or keep it marked alive; the provider's name is the name of the API token it presents"),
		core.Body(
			core.Fld("protocol", "integer", true, "Provider protocol version the provider speaks", 1),
			core.Fld("role", "string", true, "Role it fills: detector", "detector"),
			core.Fld("kind", "string", true, "Backend: suricata", "suricata"),
			core.Fld("version", "string", false, "Version of the provider agent", "0.9.8"),
			core.Fld("formats", "array", true, "Formats it will send", []string{"suricata-eve"}),
		),
		core.Returns("Welcome", map[string]any{"protocol": 1, "name": "suricata-lab", "accepts": []string{"suricata-eve"}, "heartbeat_seconds": 30}))
	ctx.Route("POST", "/api/provider/v1/events", m.apiEvents, core.Write(),
		core.Doc("Deliver a batch of records in one format from a provider to the module that consumes that format"),
		core.Body(
			core.Fld("format", "string", true, "Format of every record in the batch", "suricata-eve"),
			core.Fld("records", "array", true, "Records, each one JSON value (for suricata-eve, one EVE event)", []map[string]any{{"event_type": "alert"}}),
			core.Fld("dropped", "integer", false, "Records the provider discarded while the core was unreachable", 0),
		),
		core.Returns("Accepted", map[string]any{"accepted": 120}))
	ctx.Route("GET", "/api/provider/v1/providers", m.apiList,
		core.Doc("List the providers that have introduced themselves, whether each is connected, and what it has sent"),
		core.Returns("Providers", map[string]any{"providers": []map[string]any{
			{"name": "suricata-lab", "role": "detector", "kind": "suricata", "connected": true, "events": 1200, "dropped": 0}}}))
	return nil
}

// Accept registers the module that consumes a format.
func (m *Module) Accept(format string, sink core.ProviderSink) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sinks[format] = sink
}

func (m *Module) Health() core.Health {
	m.mu.Lock()
	defer m.mu.Unlock()
	up := 0
	for _, p := range m.seen {
		if m.connected(p) {
			up++
		}
	}
	return core.Health{OK: true, Detail: fmt.Sprintf("%d provider(s), %d connected", len(m.seen), up)}
}

func (m *Module) connected(p *provider) bool {
	return time.Since(time.Unix(p.LastSeen, 0)) < 3*heartbeat
}

// name is the provider's identity: the name of the named API token it
// presented. Sessions, loopback trust and the unnamed token do not identify
// a provider, so they are refused.
func name(r *core.Req) (string, error) {
	n, ok := strings.CutPrefix(r.User, "token:")
	if !ok || n == "" {
		return "", &core.Error{Status: 403, Message: "a provider must present a named API token (api_tokens); its name is the provider's name"}
	}
	return n, nil
}

func (m *Module) apiHello(r *core.Req) (any, error) {
	n, err := name(r)
	if err != nil {
		return nil, err
	}
	var in core.ProviderHello
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	if in.Protocol != core.ProviderProtocol {
		return nil, core.BadRequest("provider protocol %d is not spoken here; this core speaks %d", in.Protocol, core.ProviderProtocol)
	}
	now := time.Now().Unix()
	m.mu.Lock()
	p := m.seen[n]
	if p == nil {
		p = &provider{Name: n, FirstSeen: now}
		m.seen[n] = p
	}
	p.Role, p.Kind, p.Version, p.Capabilities, p.Formats = in.Role, in.Kind, in.Version, in.Capabilities, in.Formats
	p.Client, p.LastSeen = r.Client, now
	var accepts []string
	for f := range m.sinks {
		accepts = append(accepts, f)
	}
	m.mu.Unlock()
	sort.Strings(accepts)
	return core.ProviderWelcome{Protocol: core.ProviderProtocol, Name: n, Accepts: accepts,
		HeartbeatSeconds: int(heartbeat / time.Second)}, nil
}

func (m *Module) apiEvents(r *core.Req) (any, error) {
	n, err := name(r)
	if err != nil {
		return nil, err
	}
	var in core.ProviderEvents
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	if len(in.Records) > maxRecords {
		return nil, core.BadRequest("%d records in one batch; send at most %d", len(in.Records), maxRecords)
	}
	m.mu.Lock()
	sink := m.sinks[in.Format]
	p := m.seen[n]
	if p == nil {
		m.mu.Unlock()
		return nil, &core.Error{Status: 409, Message: "say hello first: POST /api/provider/v1/hello"}
	}
	p.LastSeen = time.Now().Unix()
	p.Dropped += in.Dropped
	m.mu.Unlock()
	if sink == nil {
		return nil, core.BadRequest("no module here consumes %q", in.Format)
	}
	took, err := sink(n, in.Records)
	m.mu.Lock()
	p.Events += int64(took)
	if err != nil {
		p.LastError = err.Error()
	} else {
		p.LastError = ""
	}
	m.mu.Unlock()
	if in.Dropped > 0 {
		m.ctx.Event("provider", fmt.Sprintf("provider %s discarded %d records while it could not reach the core", n, in.Dropped),
			map[string]any{"provider": n, "dropped": in.Dropped})
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"accepted": took}, nil
}

func (m *Module) apiList(r *core.Req) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]provider, 0, len(m.seen))
	for _, p := range m.seen {
		c := *p
		c.Connected = m.connected(p)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return map[string]any{"providers": out}, nil
}
