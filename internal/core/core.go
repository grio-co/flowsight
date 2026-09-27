package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/grioghar/flowsight/internal/licensing"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"strings"
	"sync"
	"time"
)

// Core wires everything together. Modules register themselves at build time
// through Register(); Core instantiates the ones the config enables, in
// dependency order, and runs them.
type Core struct {
	profileMu   sync.Mutex // guards lastGC
	lastGC      time.Time  // when a heap profile last forced a collection
	lastMemWarn time.Time  // when watchMemory last complained
	sinceMu     sync.Mutex // guards the data-since cache
	sinceAt     time.Time
	sinceVal    int64
	Version     string
	Platform    *Platform
	Config      *Config
	Store       *Store
	Scheduler   *Scheduler
	API         *API
	Log         *slog.Logger
	Started     time.Time

	mu        sync.RWMutex
	Modules   map[string]Module
	Infos     map[string]ModuleInfo
	Errors    map[string]string
	Providers []Provider
	Panels    []Panel
	Services  map[string]any
	readOnly  bool
}

var registry []func() Module

// Register adds a module constructor. Called from each module's init().
func Register(ctor func() Module) { registry = append(registry, ctor) }

// TagMap maps module names to OpenAPI tag hierarchies (area/page).
// Two-level hierarchy: Area / Page matching the sidebar structure.
var TagMap = map[string][]string{
	// Monitor
	"visibility": {"Monitor", "Overview"},
	"identity":   {"Monitor", "Hosts"},
	"flows":      {"Monitor", "Sessions"},
	"apps":       {"Monitor", "Applications"},
	"appcontrol": {"Monitor", "Applications"},
	"web":        {"Monitor", "Web"},
	"dns":        {"Monitor", "DNS"},
	"paths":      {"Monitor", "Map"},
	"egress":     {"Monitor", "DLP"},
	// Inventory
	"enroll": {"Inventory", "Devices"},
	// Protect
	"policy":      {"Protect", "Policies"},
	"qos":         {"Protect", "Priority"},
	"categories":  {"Protect", "Categories"},
	"tls":         {"Protect", "TLS"},
	"mitm":        {"Protect", "Stateful Packet Inspection"},
	"ids":         {"Protect", "Threats"},
	"firewall":    {"Protect", "Firewall"},
	"rulehygiene": {"Protect", "Firewall"},
	// Administration
	"reports":   {"Administration", "Reports"},
	"alerting":  {"Administration", "Alerts"},
	"updater":   {"Administration", "Updates"},
	"license":   {"Administration", "License"},
	"ui":        {"Administration", "Settings"},
	"pihole":    {"Administration", "Settings"},
	"enrich":    {"Administration", "Settings"},
	"telemetry": {"Administration", "Settings"},
}

// New builds a Core. configPath "" means the platform default.
func New(version, configPath, dataDir string, static fs.FS, log *slog.Logger) (*Core, error) {
	p := DetectPlatform()
	if configPath == "" {
		configPath = os.Getenv("FLOWSIGHT_CONFIG")
	}
	if configPath == "" {
		configPath = filepath.Join(p.EtcDir, "flowsight.json")
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return nil, err
	}
	if cfg.LoadNote != "" {
		slog.Warn("configuration recovered", "note", cfg.LoadNote)
	}
	applyPathOverrides(p, cfg.Core().Paths)
	if dataDir == "" {
		dataDir = cfg.Core().DataDir
	}
	if dataDir == "" {
		dataDir = p.DataDir
	}
	st, err := OpenStore(dataDir)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	c := &Core{Version: version, Platform: p, Config: cfg, Store: st, Log: log,
		Started: time.Now(), Modules: map[string]Module{}, Infos: map[string]ModuleInfo{},
		Errors: map[string]string{}, Services: map[string]any{}}
	c.Scheduler = NewScheduler(cfg.Core().Workers, log.With("component", "scheduler"))
	c.API = NewAPI(c, static, log.With("component", "api"))
	return c, nil
}

func applyPathOverrides(p *Platform, over map[string]any) {
	if len(over) == 0 {
		return
	}
	b, _ := json.Marshal(over)
	_ = json.Unmarshal(b, p)
}

// ReadOnly is true when the instance refuses writes (a future entitlement or
// an operator lock can set it).
func (c *Core) ReadOnly() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.readOnly
}

// LoadModules instantiates and sets up every enabled module.
func (c *Core) LoadModules() {
	type cand struct {
		m    Module
		info ModuleInfo
	}
	cands := map[string]cand{}
	for _, ctor := range registry {
		m := ctor()
		info := m.Info()
		cands[info.Name] = cand{m, info}
		c.Config.DeclareModule(info.Name, info.Defaults)
	}
	var order []string
	seen := map[string]bool{}
	var visit func(string)
	visit = func(n string) {
		if seen[n] {
			return
		}
		cd, ok := cands[n]
		if !ok {
			return
		}
		seen[n] = true
		for _, dep := range cd.info.After {
			visit(dep)
		}
		order = append(order, n)
	}
	names := make([]string, 0, len(cands))
	for n := range cands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		visit(n)
	}
	for _, n := range order {
		cd := cands[n]
		c.Infos[n] = cd.info
		if !Bool(c.Config.Module(n), "enabled", true) {
			c.Log.Info("module disabled", "module", n)
			continue
		}
		ctx := &Context{Core: c, Name: n, Store: c.Store, Platform: c.Platform, Config: c.Config,
			Log: c.Log.With("module", n)}
		if err := c.setup(cd.m, ctx); err != nil {
			c.Errors[n] = err.Error()
			c.Log.Error("module setup failed", "module", n, "error", err.Error())
			continue
		}
		c.mu.Lock()
		c.Modules[n] = cd.m
		c.mu.Unlock()
		c.Log.Info("module loaded", "module", n, "version", cd.info.Version)
	}
}

func (c *Core) setup(m Module, ctx *Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return m.Setup(ctx)
}

// ProviderList returns a snapshot of registered providers.
func (c *Core) ProviderList() []Provider {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]Provider(nil), c.Providers...)
}

// Capabilities returns capability -> modules offering it.
func (c *Core) Capabilities() map[string][]string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := map[string][]string{}
	for n := range c.Modules {
		for _, cap := range c.Infos[n].Capabilities {
			out[cap] = append(out[cap], n)
		}
	}
	for _, p := range c.Providers {
		for _, cap := range p.Capabilities() {
			out[cap] = append(out[cap], "provider:"+p.Name())
		}
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

func (c *Core) audit(user, method, p string, body map[string]any, client string) {
	keys := make([]string, 0, len(body))
	for k := range body {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 12 {
		keys = keys[:12]
	}
	attrs := map[string]any{"keys": strings.Join(keys, ",")}
	// What was touched, when the body says: the module of a settings save,
	// the name of a policy, rule, channel or definition.
	for _, k := range []string{"module", "name", "id", "definition", "policy"} {
		if v, ok := body[k].(string); ok && v != "" && len(v) <= 80 {
			attrs[k] = v
		}
	}
	via := "token"
	switch {
	case strings.Contains(user, "(gui"):
		via = "gui"
	case strings.HasPrefix(user, "session"):
		via = "session"
	case user == "local":
		via = "local"
	case strings.HasPrefix(user, "token:"):
		via = user
	}
	attrs["via"] = via
	_ = c.Store.AddEvents([]Event{{TS: time.Now().Unix(), Kind: "audit", Source: "api",
		Severity: "info", Verdict: "observed", ActorName: user, ActorIP: client,
		Message: method + " " + p, Attrs: attrs}})
}

// Run starts jobs and the API and blocks until stop is closed.
func (c *Core) Run(stop <-chan struct{}) error {
	c.systemRoutes()
	c.LoadModules()
	c.Scheduler.Add(&Job{Name: "rollup", Module: "core", Every: 5 * time.Minute,
		Fn: c.Store.Rollup, nextRun: time.Now().Add(20 * time.Second)})
	c.Scheduler.Add(&Job{Name: "memory", Module: "core", Every: time.Minute,
		Fn: c.watchMemory, nextRun: time.Now().Add(90 * time.Second)})
	c.Scheduler.Add(&Job{Name: "prune", Module: "core", Every: time.Hour,
		Fn: func() error {
			return c.Store.Prune(CapRetention(c.Config.Core().Retention, c.License().Limit(licensing.LimitRetentionDays)))
		},
		nextRun: time.Now().Add(2 * time.Minute)})
	c.Scheduler.Start()
	_ = c.Store.AddEvents([]Event{{TS: time.Now().Unix(), Kind: "system", Source: "core",
		Message: "flowsightd " + c.Version + " started"}})
	cs := c.Config.Core()
	srv, err := c.API.Listen(cs.Bind, cs.Port)
	if err != nil {
		return err
	}
	// HTTPS beside HTTP. A failure here is logged, not fatal: the GUI route
	// over loopback keeps working whatever happens to the certificate.
	var srvTLS *http.Server
	if cs.HTTPSPort > 0 {
		if err := c.ensureAPICert(); err != nil {
			c.Log.Error("api certificate", "error", err.Error())
		} else if s, err := c.API.ListenTLS(cs.Bind, cs.HTTPSPort); err != nil {
			c.Log.Error("https listener", "error", err.Error())
		} else {
			srvTLS = s
		}
		c.Scheduler.Add(&Job{Name: "api-cert", Module: "core", Every: 12 * time.Hour,
			Fn: c.ensureAPICert, nextRun: time.Now().Add(12 * time.Hour)})
	}
	<-stop
	c.Log.Info("stopping")
	c.Scheduler.Stop()
	c.mu.RLock()
	for _, m := range c.Modules {
		if s, ok := m.(Stopper); ok {
			s.Stop()
		}
	}
	c.mu.RUnlock()
	ctxTimeout := 5 * time.Second
	srv.SetKeepAlivesEnabled(false)
	done := make(chan struct{})
	go func() {
		_ = srv.Close()
		if srvTLS != nil {
			_ = srvTLS.Close()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(ctxTimeout):
	}
	return c.Store.Close()
}

// ------------------------------------------------------------ system API

func (c *Core) systemRoutes() {
	a := c.API
	a.Add("GET", "/api/system/info", c.apiInfo, "system", Doc("Version, platform, uptime, site"))
	a.Add("GET", "/api/system/health", c.apiHealth, "system", Doc("Module and job health, capabilities, store size"))
	a.Add("GET", "/api/system/profile", c.apiProfile, "system", Doc("Runtime profile for diagnosis, in pprof format"),
		Params("kind", "heap (default), allocs, goroutine or cpu", "seconds", "for cpu: how long to sample, 1-30 (default 10)"))
	a.Add("GET", "/api/system/panels", c.apiPanels, "system", Doc("UI panels contributed by loaded modules"))
	a.Add("GET", "/api/search", c.apiSearch, "system",
		Doc("SmartSearch across FlowSight: devices, DNS names, domains, applications, open findings, policies, settings and pages, each with links to the pages that show it"),
		Params("q", "what to find; every word must match (at least two characters)", "limit", "results per group, 1-30 (default 8)"),
		Returns("Grouped results", map[string]any{"q": "iphone", "groups": []map[string]any{{"kind": "devices", "title": "Devices", "results": []map[string]any{{
			"title": "iPhone", "sub": "192.168.1.69 · ca:51:71:75:2f:b9 · personal", "href": "#host/192.168.1.69",
			"links": []map[string]any{{"label": "Device", "href": "#host/192.168.1.69"}, {"label": "Sessions", "href": "#flows?ip=192.168.1.69"}}}}}}}))
	a.Add("GET", "/api/system/modules", c.apiModules, "system", Doc("Every module with settings and schema"))
	a.Add("POST", "/api/system/modules/save", c.apiModuleSave, "system", Write(), Doc("Save one module's settings"))
	a.Add("POST", "/api/system/jobs/run", c.apiJobRun, "system", Write(), Doc("Run a scheduled job now"))
	a.Add("GET", "/api/system/audit", c.apiAudit, "system", Doc("Recent write operations"), Params("limit", "rows"))
	a.Add("GET", "/api/system/events", c.apiEvents, "system", Doc("Normalised events"),
		Params("kind", "event kind", "hours", "window", "limit", "rows"))
	a.Add("GET", "/api/system/findings", c.apiFindings, "system", Doc("Open findings across modules"),
		Params("module", "filter by module", "host", "only findings about this device: an address or MAC; every address the device has used counts"))
	a.Add("POST", "/api/system/findings/ack", c.apiFindingAck, "system", Write(), Doc("Acknowledge a finding"))
	a.Add("GET", "/api/system/changes", c.apiChanges, "system", Doc("Configuration change history"),
		Params("limit", "rows", "module", "filter"))
	a.Add("GET", "/api/openapi.json", func(r *Req) (any, error) { return a.OpenAPI(), nil }, "system",
		Doc("This document, generated from the route table"))
	a.Add("GET", "/api/system/logout", func(r *Req) (any, error) { return map[string]any{"ok": true}, nil },
		"system", Doc("Drop the session"))
}

// dataSince is when the oldest traffic record starts, so a window wider than
// the history can say so instead of looking broken. Read once an hour.
func (c *Core) dataSince() int64 {
	c.sinceMu.Lock()
	defer c.sinceMu.Unlock()
	if time.Since(c.sinceAt) < time.Hour && c.sinceVal != 0 {
		return c.sinceVal
	}
	c.sinceAt = time.Now()
	if c.Store != nil {
		if row, err := c.Store.Row(`SELECT MIN(bucket) AS b FROM rollup_app`); err == nil && row != nil {
			switch v := row["b"].(type) {
			case int64:
				c.sinceVal = v
			case float64:
				c.sinceVal = int64(v)
			}
		}
	}
	return c.sinceVal
}

func (c *Core) apiInfo(r *Req) (any, error) {
	host, _ := os.Hostname()
	cs := c.Config.Core()
	site := cs.SiteName
	if site == "" {
		site = host
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return map[string]any{"version": c.Version, "platform": c.Platform, "hostname": host,
		"site": site, "started": c.Started.Unix(), "uptime": int(time.Since(c.Started).Seconds()),
		"data_since": c.dataSince(),
		"user":       r.User, "go": runtime.Version(), "auth": cs.APIToken != "",
		"read_only": c.ReadOnly(), "goroutines": runtime.NumGoroutine(),
		"memory": map[string]any{"heap_alloc": ms.HeapAlloc, "heap_sys": ms.HeapSys, "heap_inuse": ms.HeapInuse,
			"heap_released": ms.HeapReleased, "sys": ms.Sys, "num_gc": ms.NumGC}}, nil
}

// watchMemory says so, loudly and early, when the live heap has outgrown the
// memory limit. The limit is a soft target the collector steers towards; a
// live heap well above it cannot be steered anywhere, and the collector's
// answer is to run continuously, which on a four-core gateway once meant all
// four cores and a guest that stopped answering its own management agent.
// Nothing here can free that memory -- only whatever holds it can -- but a
// log line pointing at /api/system/profile turns a mystery into a lookup.
func (c *Core) watchMemory() error {
	limit := int64(c.Config.Core().MemoryLimitMB)
	if limit <= 0 {
		limit = 256
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	live := int64(ms.HeapInuse) >> 20
	if live <= 2*limit {
		return nil
	}
	c.profileMu.Lock()
	recent := time.Since(c.lastMemWarn) < 10*time.Minute
	if !recent {
		c.lastMemWarn = time.Now()
	}
	c.profileMu.Unlock()
	if recent {
		return nil
	}
	c.Log.Warn("live heap far above the memory limit; the collector will run continuously",
		"heap_mb", live, "limit_mb", limit, "gc_per_min", ms.NumGC, "see", "/api/system/profile?kind=heap")
	return nil
}

// apiProfile hands out a runtime profile so a daemon that is heavier than it
// should be can be read with `go tool pprof` rather than guessed at. Heap and
// allocation profiles are stack traces and byte counts; a goroutine profile
// is stack traces. None carries the data the daemon holds.
func (c *Core) apiProfile(r *Req) (any, error) {
	kind := r.Q("kind", "heap")
	switch kind {
	case "heap", "allocs", "goroutine", "cpu":
	default:
		return nil, BadRequest("kind must be heap, allocs, goroutine or cpu")
	}
	if kind == "cpu" {
		// Where the time goes, sampled for a few seconds. One at a time:
		// the runtime allows a single CPU profile, and two callers would
		// otherwise see the second fail for no reason they could act on.
		secs := r.QInt("seconds", 10, 1, 30)
		c.profileMu.Lock()
		defer c.profileMu.Unlock()
		var buf bytes.Buffer
		if err := pprof.StartCPUProfile(&buf); err != nil {
			return nil, err
		}
		time.Sleep(time.Duration(secs) * time.Second)
		pprof.StopCPUProfile()
		return Raw{ContentType: "application/octet-stream", Filename: "flowsight-cpu.pprof", Body: buf.Bytes()}, nil
	}
	if kind == "heap" {
		// A heap profile is of the last collection, so one is forced -- but
		// not more often than every few seconds, since a forced collection
		// is a stop-the-world pause anyone holding the token could otherwise
		// repeat in a loop.
		c.profileMu.Lock()
		if time.Since(c.lastGC) > 5*time.Second {
			runtime.GC()
			c.lastGC = time.Now()
		}
		c.profileMu.Unlock()
	}
	var buf bytes.Buffer
	if err := pprof.Lookup(kind).WriteTo(&buf, 0); err != nil {
		return nil, err
	}
	return Raw{ContentType: "application/octet-stream", Filename: "flowsight-" + kind + ".pprof", Body: buf.Bytes()}, nil
}

func (c *Core) apiHealth(r *Req) (any, error) {
	c.mu.RLock()
	mods := map[string]any{}
	allOK := true
	jobs := c.Scheduler.Jobs()
	for n, m := range c.Modules {
		h := Health{OK: true}
		if hh, ok := m.(Healther); ok {
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						h = Health{OK: false, Detail: fmt.Sprint("health panic: ", rec)}
					}
				}()
				h = hh.Health()
			}()
		} else {
			var bad []string
			for _, j := range jobs {
				if j["module"] == n {
					if ok, _ := j["ok"].(bool); j["ok"] != nil && !ok {
						bad = append(bad, fmt.Sprintf("%s: %s", j["name"], j["error"]))
					}
				}
			}
			if len(bad) > 0 {
				h = Health{OK: false, Detail: strings.Join(bad, "; ")}
			}
		}
		if !h.OK {
			allOK = false
		}
		info := c.Infos[n]
		mods[n] = map[string]any{"ok": h.OK, "detail": h.Detail, "extra": h.Extra,
			"version": info.Version, "capabilities": info.Capabilities, "description": info.Description}
	}
	for n, e := range c.Errors {
		allOK = false
		mods[n] = map[string]any{"ok": false, "detail": e, "failed": true}
	}
	var provs []map[string]any
	for _, p := range c.Providers {
		provs = append(provs, map[string]any{"name": p.Name(), "capabilities": p.Capabilities()})
	}
	c.mu.RUnlock()
	caps := c.Capabilities()
	var observe, enforce []string
	for k := range caps {
		if EnforceCaps[k] {
			enforce = append(enforce, k)
		} else {
			observe = append(observe, k)
		}
	}
	sort.Strings(observe)
	sort.Strings(enforce)
	return map[string]any{"ok": allOK, "modules": mods, "jobs": jobs,
		"observe_capabilities": observe, "enforce_capabilities": enforce, "capability_owners": caps,
		"providers": provs, "store": c.Store.Stats(),
		"uptime": int(time.Since(c.Started).Seconds())}, nil
}

func (c *Core) apiPanels(r *Req) (any, error) {
	c.mu.RLock()
	ps := append([]Panel(nil), c.Panels...)
	c.mu.RUnlock()
	sort.SliceStable(ps, func(i, j int) bool {
		if ps[i].Order != ps[j].Order {
			return ps[i].Order < ps[j].Order
		}
		return ps[i].Title < ps[j].Title
	})
	lic := c.License()
	out := make([]map[string]any, 0, len(ps))
	for _, p := range ps {
		row := map[string]any{"id": p.ID, "title": p.Title, "group": p.Group, "order": p.Order, "icon": p.Icon, "detail": p.Detail}
		if p.Feature != "" {
			row["feature"] = p.Feature
			row["required"] = licensing.FeatureTier(p.Feature)
			row["locked"] = lic.Allowed(p.Feature) != nil
		}
		out = append(out, row)
	}
	return map[string]any{"panels": out, "tier": lic.Tier()}, nil
}

func (c *Core) apiModules(r *Req) (any, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	names := make([]string, 0, len(c.Infos))
	for n := range c.Infos {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []map[string]any
	for _, n := range names {
		info := c.Infos[n]
		m, loaded := c.Modules[n]
		settings := c.Config.Module(n)
		for _, f := range info.Schema {
			if f.Type == "secret" {
				if v, ok := settings[f.Key].(string); ok && v != "" {
					settings[f.Key] = "********"
				}
			}
		}
		var effective map[string]any
		if e, ok := m.(Effective); ok && m != nil {
			effective = e.EffectiveSettings()
		}
		out = append(out, map[string]any{"name": n, "loaded": loaded, "version": info.Version, "effective": effective,
			"description": info.Description, "capabilities": info.Capabilities,
			"requires": info.Requires, "settings": settings, "schema": info.Schema,
			"tier": info.Tier, "error": c.Errors[n]})
	}
	return map[string]any{"modules": out}, nil
}

// lockedKeys may never be changed through the API: they decide where the
// daemon listens and what it executes.
var lockedKeys = map[string]bool{"bind": true, "port": true, "api_token": true, "data_dir": true,
	"workers": true, "paths": true}

// lockedSetting says whether a key in a module save must be refused. The
// locked names are the daemon's own (its bind address and port, its token,
// its data directory), which no module declares. A module that declares a
// setting called "port" in its schema means its own listener (the decoder's
// loopback port, the captive portal's), and saving it is what its settings
// page is for; refusing it made "enable stateful inspection" fail with a
// message about the API. Anything naming a binary stays refused.
func lockedSetting(key string, declared bool) bool {
	if strings.Contains(key, "_bin") || strings.Contains(key, "binary") {
		return true
	}
	switch key {
	case "port", "bind":
		return !declared // a module's own listener when its schema names it
	}
	return lockedKeys[key]
}

func (c *Core) apiModuleSave(r *Req) (any, error) {
	var in struct {
		Module   string         `json:"module"`
		Settings map[string]any `json:"settings"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	c.mu.RLock()
	info, known := c.Infos[in.Module]
	m := c.Modules[in.Module]
	c.mu.RUnlock()
	if !known {
		return nil, NotFound("unknown module %q", in.Module)
	}
	if in.Settings == nil {
		return nil, BadRequest("settings must be an object")
	}
	schema := map[string]SettingField{}
	for _, f := range info.Schema {
		schema[f.Key] = f
	}
	for k, v := range in.Settings {
		f, ok := schema[k]
		if lockedSetting(k, ok) {
			return nil, Forbidden("%q cannot be changed through the API", k)
		}
		if !ok && k != "enabled" {
			return nil, BadRequest("unknown setting %q", k)
		}
		switch f.Type {
		case "int":
			n, ok := v.(float64)
			if !ok || n != float64(int64(n)) {
				return nil, BadRequest("%s must be an integer", k)
			}
			in.Settings[k] = int(n)
		case "bool":
			if _, ok := v.(bool); !ok {
				return nil, BadRequest("%s must be true or false", k)
			}
		case "choice":
			s, _ := v.(string)
			found := false
			for _, ch := range f.Choices {
				if ch == s {
					found = true
				}
			}
			if !found {
				return nil, BadRequest("%s must be one of %s", k, strings.Join(f.Choices, ", "))
			}
		case "secret":
			if s, _ := v.(string); s == "********" {
				delete(in.Settings, k) // unchanged placeholder
			}
		case "list":
			if _, ok := v.([]any); !ok {
				return nil, BadRequest("%s must be a list", k)
			}
		}
	}
	if info.Tier != "" {
		if en, ok := in.Settings["enabled"].(bool); ok && en {
			if cur := c.License().Tier(); licensing.Rank(cur) < licensing.Rank(info.Tier) {
				return nil, &Error{Status: 402, Message: fmt.Sprintf("the %s module requires the %s tier (this installation is %s)", in.Module, info.Tier, cur),
					Extra: map[string]any{"locked": true, "required": info.Tier, "tier": cur}}
			}
			if c.License().Expired() {
				return nil, ExpiredError("module:" + in.Module)
			}
		}
	}
	before := c.Config.Module(in.Module)
	if err := c.Config.SetModule(in.Module, in.Settings); err != nil {
		return nil, err
	}
	after := c.Config.Module(in.Module)
	if rc, ok := m.(Reconfigurable); ok && m != nil {
		if err := rc.OnConfigChange(after); err != nil {
			return nil, BadRequest("saved, but the module rejected the change: %v", err)
		}
	}
	bb, _ := json.MarshalIndent(before, "", " ")
	ab, _ := json.MarshalIndent(after, "", " ")
	keys := make([]string, 0, len(in.Settings))
	for k := range in.Settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	_ = c.Store.RecordChange("system", "module:"+in.Module, r.User, "", "",
		"--- before\n"+string(bb)+"\n+++ after\n"+string(ab), "settings changed: "+strings.Join(keys, ", "))
	note := ""
	if Bool(before, "enabled", true) != Bool(after, "enabled", true) {
		note = "restart flowsightd to apply the enable/disable change"
	}
	// The answer must not carry the secret just written: mask it exactly as
	// the listing does, so a caller with write access learns nothing it did
	// not already know.
	for _, f := range info.Schema {
		if f.Type == "secret" {
			if v, ok := after[f.Key].(string); ok && v != "" {
				after[f.Key] = "********"
			}
		}
	}
	return map[string]any{"ok": true, "settings": after, "note": note}, nil
}

func (c *Core) apiJobRun(r *Req) (any, error) {
	b := r.Body()
	name, _ := b["job"].(string)
	module, _ := b["module"].(string)
	if !c.Scheduler.RunNow(module, name) {
		return nil, NotFound("unknown job %q", name)
	}
	return map[string]any{"ok": true}, nil
}

func (c *Core) apiAudit(r *Req) (any, error) {
	rows, err := c.Store.Rows(`SELECT * FROM events WHERE kind='audit' ORDER BY ts DESC LIMIT ?`,
		r.QInt("limit", 100, 1, 1000))
	return map[string]any{"events": rows}, err
}

func (c *Core) apiEvents(r *Req) (any, error) {
	kind, err := r.QSafe("kind", "", 40)
	if err != nil {
		return nil, err
	}
	q := `SELECT * FROM events WHERE ts>=?`
	args := []any{r.Since(24)}
	if kind != "" {
		q += ` AND kind=?`
		args = append(args, kind)
	}
	q += ` ORDER BY ts DESC LIMIT ?`
	args = append(args, r.QInt("limit", 200, 1, 5000))
	rows, err := c.Store.Rows(q, args...)
	return map[string]any{"events": rows}, err
}

func (c *Core) apiFindings(r *Req) (any, error) {
	module, err := r.QSafe("module", "", 40)
	if err != nil {
		return nil, err
	}
	q := `SELECT * FROM findings WHERE resolved_ts IS NULL`
	args := []any{}
	if module != "" {
		q += ` AND module=?`
		args = append(args, module)
	}
	host, err := r.QSafe("host", "", 64)
	if err != nil {
		return nil, err
	}
	q += ` ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
		WHEN 'low' THEN 3 ELSE 4 END, ts DESC LIMIT 500`
	rows, err := c.Store.Rows(q, args...)
	for _, r := range rows {
		if a, _ := r["attrs"].(string); a != "" {
			var obj map[string]any
			if json.Unmarshal([]byte(a), &obj) == nil {
				r["attrs"] = obj
			}
		}
	}
	if host != "" {
		ids := c.deviceIdentities(host)
		kept := rows[:0]
		for _, r := range rows {
			if findingAbout(r, ids) {
				kept = append(kept, r)
			}
		}
		rows = kept
	}
	return map[string]any{"findings": rows}, err
}

// deviceIdentities returns every address and MAC one device is known by,
// lower-cased: the one asked about, its MAC, and the other addresses that
// MAC has used. A phone's IPv4 and IPv6 addresses are the same phone.
func (c *Core) deviceIdentities(host string) map[string]bool {
	h := strings.ToLower(strings.TrimSpace(host))
	ids := map[string]bool{h: true}
	mac := ""
	if strings.Count(h, ":") == 5 && len(h) == 17 {
		mac = h
	} else if rows, _ := c.Store.Rows(`SELECT COALESCE(mac,'') AS mac FROM hosts WHERE ip=?`, host); len(rows) > 0 {
		mac, _ = rows[0]["mac"].(string)
		mac = strings.ToLower(mac)
	}
	if mac != "" {
		ids[mac] = true
		if rows, _ := c.Store.Rows(`SELECT ip FROM hosts WHERE lower(mac)=? LIMIT 32`, mac); len(rows) > 0 {
			for _, r := range rows {
				if ip, _ := r["ip"].(string); ip != "" {
					ids[strings.ToLower(ip)] = true
				}
			}
		}
	}
	return ids
}

// findingAbout reports whether a finding names one of a device's identities
// as its subject or in its who.
func findingAbout(r map[string]any, ids map[string]bool) bool {
	if s, _ := r["subject"].(string); ids[strings.ToLower(s)] {
		return true
	}
	a, _ := r["attrs"].(map[string]any)
	w, _ := a["who"].(map[string]any)
	for _, k := range []string{"ip", "mac"} {
		if v, _ := w[k].(string); v != "" && ids[strings.ToLower(v)] {
			return true
		}
	}
	if addrs, _ := w["addresses"].([]any); addrs != nil {
		for _, x := range addrs {
			if v, _ := x.(string); ids[strings.ToLower(v)] {
				return true
			}
		}
	}
	return false
}

func (c *Core) apiFindingAck(r *Req) (any, error) {
	id, _ := r.Body()["id"].(float64)
	if id <= 0 {
		return nil, BadRequest("id is required")
	}
	return map[string]any{"ok": true}, c.Store.Exec(`UPDATE findings SET acked=1 WHERE id=?`, int64(id))
}

func (c *Core) apiChanges(r *Req) (any, error) {
	module, err := r.QSafe("module", "", 40)
	if err != nil {
		return nil, err
	}
	q := `SELECT id,ts,module,subject,actor,summary,before_hash,after_hash,LENGTH(diff) AS diff_bytes FROM changes`
	args := []any{}
	if module != "" {
		q += ` WHERE module=?`
		args = append(args, module)
	}
	q += ` ORDER BY ts DESC LIMIT ?`
	args = append(args, r.QInt("limit", 100, 1, 1000))
	rows, err := c.Store.Rows(q, args...)
	if err != nil {
		return nil, err
	}
	if id := r.QInt("id", 0, 0, 0); id > 0 {
		row, err := c.Store.Row(`SELECT * FROM changes WHERE id=?`, id)
		if err != nil {
			return nil, err
		}
		return map[string]any{"change": row}, nil
	}
	return map[string]any{"changes": rows}, nil
}

// Helper for modules: serve a plain HTTP handler (e.g. a block page) on a
// separate listener owned by the module.
func ServeOn(addr string, h http.Handler) (*http.Server, error) {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() { _ = srv.Serve(ln) }()
	return srv, nil
}
