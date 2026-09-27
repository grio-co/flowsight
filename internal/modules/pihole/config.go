package pihole

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// serverURLs is the configured server list, normalised. A line starting with
// "#" is a server the operator has parked: it is kept in the list but not
// contacted.
func (m *Module) serverURLs() []string {
	var out []string
	for _, raw := range core.Strs(m.ctx.Settings(), "servers") {
		u := strings.TrimRight(strings.TrimSpace(raw), "/")
		if u == "" || strings.HasPrefix(u, "#") {
			continue
		}
		if !strings.Contains(u, "://") {
			u = "https://" + u
		}
		out = append(out, u)
	}
	return out
}

// connected returns the v6 servers the last pull reached. Only Pi-hole v6
// has a configuration API; v5 servers are imported from but not configured.
func (m *Module) connected() []*serverState {
	var out []*serverState
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.serverURLs() {
		if s := m.servers[u]; s != nil && s.Version == "v6" && s.LastPull > 0 && s.LastError == "" {
			out = append(out, s)
		}
	}
	return out
}

// pick selects servers by "all", a URL, a host name or an address.
func (m *Module) pick(which string) ([]*serverState, error) {
	all := m.connected()
	if len(all) == 0 {
		return nil, core.BadRequest("no Pi-hole v6 server is connected")
	}
	which = strings.TrimRight(strings.TrimSpace(which), "/")
	if which == "" || which == "all" {
		return all, nil
	}
	for _, s := range all {
		if s.URL == which || s.Host == which {
			return []*serverState{s}, nil
		}
		if p, err := url.Parse(s.URL); err == nil && p.Hostname() == which {
			return []*serverState{s}, nil
		}
	}
	return nil, core.BadRequest("no connected Pi-hole called %s", which)
}

// call makes one authenticated request to a Pi-hole v6 API, renewing the
// session once if the Pi-hole has forgotten it.
func (m *Module) call(s *serverState, method, path string, body any) (map[string]any, int, error) {
	pw := core.Str(m.ctx.Settings(), "password", "")
	for attempt := 0; attempt < 2; attempt++ {
		sid, err := m.v6Session(s, pw)
		if err != nil {
			return nil, 0, err
		}
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, s.URL+path, rd)
		req.Header.Set("sid", sid)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := m.httpClient().Do(req)
		if err != nil {
			return nil, 0, err
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if resp.StatusCode == 401 && attempt == 0 {
			m.mu.Lock()
			s.sid = ""
			m.mu.Unlock()
			continue
		}
		out := map[string]any{}
		_ = json.Unmarshal(raw, &out)
		if resp.StatusCode >= 300 {
			msg := ""
			if e, ok := out["error"].(map[string]any); ok {
				msg = strings.TrimSpace(fmt.Sprint(e["message"], " ", valueOr(e["hint"], "")))
			}
			if msg == "" {
				msg = strings.TrimSpace(string(raw))
			}
			return out, resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
		}
		return out, resp.StatusCode, nil
	}
	return nil, 401, errors.New("session refused twice")
}

func valueOr(v any, def string) string {
	if v == nil {
		return def
	}
	return fmt.Sprint(v)
}

// flatten turns Pi-hole's detailed config tree into dotted keys.
func flatten(prefix string, node any, out map[string]map[string]any) {
	m, ok := node.(map[string]any)
	if !ok {
		return
	}
	if _, hasV := m["value"]; hasV {
		if _, hasD := m["description"]; hasD {
			out[prefix] = m
			return
		}
	}
	for k, v := range m {
		p := k
		if prefix != "" {
			p = prefix + "." + k
		}
		flatten(p, v, out)
	}
}

type serverView struct {
	s        *serverState
	settings map[string]map[string]any
	blocking map[string]any
	version  string
	err      error
}

// readAll reads every picked server's detailed configuration in parallel.
func (m *Module) readAll(servers []*serverState) []*serverView {
	views := make([]*serverView, len(servers))
	var wg sync.WaitGroup
	for i, s := range servers {
		wg.Add(1)
		go func(i int, s *serverState) {
			defer wg.Done()
			v := &serverView{s: s, settings: map[string]map[string]any{}}
			views[i] = v
			cfg, _, err := m.call(s, "GET", "/api/config?detailed=true", nil)
			if err != nil {
				v.err = err
				return
			}
			flatten("", cfg["config"], v.settings)
			v.blocking, _, _ = m.call(s, "GET", "/api/dns/blocking", nil)
			if ver, _, err := m.call(s, "GET", "/api/info/version", nil); err == nil {
				if c, ok := ver["version"].(map[string]any); ok {
					if core2, ok := c["core"].(map[string]any); ok {
						if l, ok := core2["local"].(map[string]any); ok {
							v.version = fmt.Sprint(l["version"])
						}
					}
				}
			}
		}(i, s)
	}
	wg.Wait()
	return views
}

func (m *Module) apiConfig(r *core.Req) (any, error) {
	servers, err := m.pick(r.Q("server", "all"))
	if err != nil {
		return nil, err
	}
	views := m.readAll(servers)
	var srv []map[string]any
	var warnings []string
	for _, v := range views {
		row := map[string]any{"url": v.s.URL, "host": v.s.Host}
		if v.err != nil {
			row["error"] = v.err.Error()
			srv = append(srv, row)
			continue
		}
		writable := v.settings["webserver.api.app_sudo"]["value"] == true
		row["writable"] = writable
		row["version"] = v.version
		if !writable {
			row["read_only_reason"] = "This Pi-hole lets an app password read settings but not change them. Turn on “Permit app password to modify config” on the Pi-hole (Settings › Web interface / API, Expert mode), or run: sudo pihole-FTL --config webserver.api.app_sudo true"
		}
		if v.blocking != nil {
			row["blocking"] = v.blocking["blocking"]
			row["blocking_timer"] = v.blocking["timer"]
		}
		if x := v.settings["dns.queryLogging"]; x != nil && x["value"] == false {
			warnings = append(warnings, v.s.Host+" is not logging queries: FlowSight sees none of its DNS traffic.")
		}
		if x := v.settings["misc.privacylevel"]; x != nil {
			if n, _ := x["value"].(float64); n > 0 {
				warnings = append(warnings, fmt.Sprintf("%s hides detail from its log (privacy level %v): FlowSight cannot tell which device asked what.", v.s.Host, n))
			}
		}
		srv = append(srv, row)
	}
	var sections []map[string]any
	for _, sec := range phSections {
		var items []map[string]any
		for _, c := range phCatalogue {
			if c.Section != sec.ID {
				continue
			}
			item := map[string]any{"key": c.Key, "label": c.Label, "guide": c.Guide}
			if c.Recommend != nil {
				item["recommend"] = c.Recommend
			}
			for k, v := range map[string]string{"why": c.Why, "caution": c.Caution, "read_only": c.ReadOnly} {
				if v != "" {
					item[k] = v
				}
			}
			values := map[string]any{}
			var first any
			differs, have := false, 0
			for _, v := range views {
				d := v.settings[c.Key]
				if d == nil {
					continue
				}
				if have == 0 {
					item["pihole_description"] = d["description"]
					item["type"] = d["type"]
					item["allowed"] = d["allowed"]
					item["default"] = d["default"]
					if f, ok := d["flags"].(map[string]any); ok {
						item["restarts_dns"] = f["restart_dnsmasq"] == true
					}
					first = d["value"]
				} else if !sameValue(first, d["value"]) {
					differs = true
				}
				values[v.s.URL] = d["value"]
				have++
			}
			if have == 0 {
				continue // this Pi-hole release does not have the setting
			}
			item["values"] = values
			item["differs"] = differs
			items = append(items, item)
		}
		if len(items) > 0 {
			sections = append(sections, map[string]any{"id": sec.ID, "title": sec.Title, "intro": sec.Intro, "settings": items})
		}
	}
	return map[string]any{"servers": srv, "sections": sections, "warnings": warnings}, nil
}

func sameValue(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// coerce turns what the page sent into the type the Pi-hole expects.
func coerce(typ string, v any) (any, error) {
	t := strings.ToLower(typ)
	switch {
	case strings.Contains(t, "array"):
		switch x := v.(type) {
		case []any:
			out := []string{}
			for _, e := range x {
				if s := strings.TrimSpace(fmt.Sprint(e)); s != "" {
					out = append(out, s)
				}
			}
			return out, nil
		case string:
			out := []string{}
			for _, line := range strings.Split(x, "\n") {
				if s := strings.TrimSpace(line); s != "" {
					out = append(out, s)
				}
			}
			return out, nil
		}
		return nil, fmt.Errorf("expected a list")
	case t == "boolean":
		switch x := v.(type) {
		case bool:
			return x, nil
		case string:
			return strconv.ParseBool(x)
		}
		return nil, fmt.Errorf("expected true or false")
	case strings.Contains(t, "integer"):
		switch x := v.(type) {
		case float64:
			return int64(x), nil
		case string:
			n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("expected a whole number")
			}
			if strings.Contains(t, "unsigned") && n < 0 {
				return nil, fmt.Errorf("expected a number of zero or more")
			}
			return n, nil
		}
		return nil, fmt.Errorf("expected a number")
	}
	return strings.TrimSpace(fmt.Sprint(v)), nil
}

// nest builds {"dns":{"blocking":{"mode":v}}} from "dns.blocking.mode".
func nest(key string, v any) map[string]any {
	parts := strings.Split(key, ".")
	var cur any = v
	for i := len(parts) - 1; i >= 0; i-- {
		cur = map[string]any{parts[i]: cur}
	}
	return cur.(map[string]any)
}

func (m *Module) apiSetConfig(r *core.Req) (any, error) {
	var in struct {
		Server string `json:"server"`
		Key    string `json:"key"`
		Value  any    `json:"value"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	c := settingFor(in.Key)
	if c == nil {
		return nil, core.BadRequest("FlowSight does not change %s; use the Pi-hole's own page for it", in.Key)
	}
	if c.ReadOnly != "" {
		return nil, core.BadRequest("%s is view only here: %s", c.Label, c.ReadOnly)
	}
	servers, err := m.pick(in.Server)
	if err != nil {
		return nil, err
	}
	views := m.readAll(servers)
	var results []map[string]any
	ok := 0
	for _, v := range views {
		res := map[string]any{"url": v.s.URL, "host": v.s.Host}
		results = append(results, res)
		if v.err != nil {
			res["error"] = v.err.Error()
			continue
		}
		d := v.settings[c.Key]
		if d == nil {
			res["error"] = "this Pi-hole release has no " + c.Key
			continue
		}
		val, err := coerce(fmt.Sprint(d["type"]), in.Value)
		if err != nil {
			res["error"] = c.Label + ": " + err.Error()
			continue
		}
		if v.settings["webserver.api.app_sudo"]["value"] != true {
			res["error"] = "read only: turn on “Permit app password to modify config” on this Pi-hole (sudo pihole-FTL --config webserver.api.app_sudo true)"
			continue
		}
		before := d["value"]
		if _, _, err := m.call(v.s, "PATCH", "/api/config", map[string]any{"config": nest(c.Key, val)}); err != nil {
			res["error"] = err.Error()
			continue
		}
		res["ok"], res["before"], res["after"] = true, before, val
		ok++
		bj, _ := json.Marshal(before)
		aj, _ := json.Marshal(val)
		_ = m.ctx.Store.RecordChange("pihole", v.s.Host+":"+c.Key, r.User, string(bj), string(aj),
			fmt.Sprintf("%s: %s -> %s", c.Key, bj, aj), fmt.Sprintf("Pi-hole %s: %s set to %s", v.s.Host, c.Label, aj))
	}
	return map[string]any{"ok": ok == len(views), "applied": ok, "results": results}, nil
}

func (m *Module) apiBlocking(r *core.Req) (any, error) {
	var in struct {
		Server   string `json:"server"`
		Blocking bool   `json:"blocking"`
		Minutes  int    `json:"minutes"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	servers, err := m.pick(in.Server)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"blocking": in.Blocking, "timer": nil}
	if !in.Blocking && in.Minutes > 0 {
		if in.Minutes > 24*60 {
			return nil, core.BadRequest("pause for at most a day; turn blocking off in the settings for longer")
		}
		body["timer"] = in.Minutes * 60
	}
	var results []map[string]any
	ok := 0
	for _, s := range servers {
		res := map[string]any{"url": s.URL, "host": s.Host}
		out, _, err := m.call(s, "POST", "/api/dns/blocking", body)
		if err != nil {
			res["error"] = err.Error()
		} else {
			res["ok"], res["blocking"], res["timer"] = true, out["blocking"], out["timer"]
			ok++
			what := "resumed"
			if !in.Blocking {
				what = "paused"
				if in.Minutes > 0 {
					what += fmt.Sprintf(" for %d minutes", in.Minutes)
				}
			}
			_ = m.ctx.Store.RecordChange("pihole", s.Host+":blocking", r.User, "", fmt.Sprint(in.Blocking), "", "Pi-hole "+s.Host+": blocking "+what)
		}
		results = append(results, res)
	}
	return map[string]any{"ok": ok == len(servers), "results": results}, nil
}

// apiDomains lists the allow and deny entries on every connected Pi-hole,
// one row per entry with the servers that carry it.
func (m *Module) apiDomains(r *core.Req) (any, error) {
	servers, err := m.pick(r.Q("server", "all"))
	if err != nil {
		return nil, err
	}
	type entry struct {
		Domain  string          `json:"domain"`
		Type    string          `json:"type"`
		Kind    string          `json:"kind"`
		Comment string          `json:"comment"`
		Enabled bool            `json:"enabled"`
		Changed int64           `json:"changed"`
		Servers map[string]bool `json:"servers"`
	}
	byKey := map[string]*entry{}
	var errs []string
	for _, s := range servers {
		out, _, err := m.call(s, "GET", "/api/domains", nil)
		if err != nil {
			errs = append(errs, s.Host+": "+err.Error())
			continue
		}
		list, _ := out["domains"].([]any)
		for _, x := range list {
			d, _ := x.(map[string]any)
			e := &entry{Domain: fmt.Sprint(d["domain"]), Type: fmt.Sprint(d["type"]), Kind: fmt.Sprint(d["kind"]),
				Comment: valueOr(d["comment"], ""), Enabled: d["enabled"] == true, Servers: map[string]bool{}}
			if f, ok := d["date_modified"].(float64); ok {
				e.Changed = int64(f)
			}
			k := e.Type + "|" + e.Kind + "|" + e.Domain
			if byKey[k] == nil {
				byKey[k] = e
			}
			byKey[k].Servers[s.URL] = true
		}
	}
	rows := make([]*entry, 0, len(byKey))
	for _, e := range byKey {
		rows = append(rows, e)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Type != rows[j].Type {
			return rows[i].Type < rows[j].Type
		}
		return rows[i].Domain < rows[j].Domain
	})
	var urls []string
	for _, s := range servers {
		urls = append(urls, s.URL)
	}
	return map[string]any{"domains": rows, "servers": urls, "errors": errs}, nil
}

func (m *Module) apiDomainChange(r *core.Req) (any, error) {
	var in struct {
		Server  string   `json:"server"`
		Action  string   `json:"action"`
		Type    string   `json:"type"`
		Kind    string   `json:"kind"`
		Domains []string `json:"domains"`
		Comment string   `json:"comment"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	if in.Type != "allow" && in.Type != "deny" {
		return nil, core.BadRequest("type is allow or deny")
	}
	if in.Kind == "" {
		in.Kind = "exact"
	}
	if in.Kind != "exact" && in.Kind != "regex" {
		return nil, core.BadRequest("kind is exact or regex")
	}
	if in.Action != "add" && in.Action != "remove" {
		return nil, core.BadRequest("action is add or remove")
	}
	var doms []string
	for _, d := range in.Domains {
		d = strings.TrimSpace(d)
		if in.Kind == "exact" {
			d = strings.TrimSuffix(strings.ToLower(d), ".")
		}
		if d != "" && len(d) <= 253 {
			doms = append(doms, d)
		}
	}
	if len(doms) == 0 || len(doms) > 100 {
		return nil, core.BadRequest("give between 1 and 100 domains")
	}
	servers, err := m.pick(in.Server)
	if err != nil {
		return nil, err
	}
	comment := in.Comment
	if comment == "" {
		comment = "FlowSight " + time.Now().Format("2006-01-02")
	}
	var results []map[string]any
	ok := 0
	for _, s := range servers {
		res := map[string]any{"url": s.URL, "host": s.Host}
		var err error
		if in.Action == "add" {
			_, _, err = m.call(s, "POST", "/api/domains/"+in.Type+"/"+in.Kind, map[string]any{"domain": doms, "comment": comment, "enabled": true})
		} else {
			for _, d := range doms {
				if _, code, e := m.call(s, "DELETE", "/api/domains/"+in.Type+"/"+in.Kind+"/"+url.PathEscape(d), nil); e != nil && code != 404 {
					err = e
				}
			}
		}
		if err != nil {
			res["error"] = err.Error()
		} else {
			res["ok"] = true
			ok++
			_ = m.ctx.Store.RecordChange("pihole", s.Host+":"+in.Type+"list", r.User, "", strings.Join(doms, ","), "",
				fmt.Sprintf("Pi-hole %s: %s %s %s (%s)", s.Host, map[string]string{"add": "added", "remove": "removed"}[in.Action], strings.Join(doms, ", "),
					map[string]string{"add": "to", "remove": "from"}[in.Action]+" the "+in.Type+" list", in.Kind))
		}
		results = append(results, res)
	}
	return map[string]any{"ok": ok == len(servers), "results": results}, nil
}

func (m *Module) registerConfigRoutes(ctx *core.Context) {
	server := core.Query("server", "string", "One Pi-hole by URL, host name or address; empty or \"all\" means every connected Pi-hole", false, "192.168.1.53")
	ctx.Route("GET", "/api/pihole/config", m.apiConfig,
		core.Doc("Curated Pi-hole settings with FlowSight's guidance, Pi-hole's own description, and each connected server's current value"),
		server,
		core.Returns("Pi-hole settings", map[string]any{
			"servers":  []map[string]any{{"url": "https://192.168.1.53", "host": "192.168.1.53", "version": "v6.2", "writable": false, "blocking": "enabled", "read_only_reason": "…app_sudo…"}},
			"warnings": []string{},
			"sections": []map[string]any{{"id": "special", "title": "Device-specific behaviour", "intro": "…", "settings": []map[string]any{{
				"key": "dns.specialDomains.iCloudPrivateRelay", "label": "Block iCloud Private Relay", "guide": "…", "type": "boolean",
				"values": map[string]any{"https://192.168.1.53": false}, "differs": false, "restarts_dns": false}}}},
		}))
	ctx.Route("POST", "/api/pihole/config", m.apiSetConfig, core.Write(),
		core.Doc("Change one curated Pi-hole setting on one or every connected Pi-hole; recorded in the change history"),
		core.Body(core.Fld("key", "string", true, "Setting key from GET /api/pihole/config", "dns.specialDomains.iCloudPrivateRelay"),
			core.Fld("value", "any", true, "New value: boolean, number, text, or a list (array or one item per line)", false),
			core.Fld("server", "string", false, "One Pi-hole, or empty / \"all\" for every connected Pi-hole", "all")),
		core.Returns("Per-server result", map[string]any{"ok": true, "applied": 1, "results": []map[string]any{{"url": "https://192.168.1.53", "ok": true, "before": true, "after": false}}}))
	ctx.Route("POST", "/api/pihole/blocking", m.apiBlocking, core.Write(),
		core.Doc("Pause blocking for some minutes, or resume it, on one or every connected Pi-hole"),
		core.Body(core.Fld("blocking", "boolean", true, "false pauses, true resumes", false),
			core.Fld("minutes", "integer", false, "Pause length; blocking comes back on its own. 0 with blocking=false pauses until resumed", 5),
			core.Fld("server", "string", false, "One Pi-hole, or empty for all", "all")),
		core.Returns("Per-server result", map[string]any{"ok": true, "results": []map[string]any{{"url": "https://192.168.1.53", "ok": true, "blocking": "disabled", "timer": 300}}}))
	ctx.Route("GET", "/api/pihole/domains", m.apiDomains,
		core.Doc("Allow-list and deny-list entries across the connected Pi-holes, with the servers that carry each"),
		server,
		core.Returns("Domain entries", map[string]any{"servers": []string{"https://192.168.1.53"}, "errors": []string{},
			"domains": []map[string]any{{"domain": "mask.icloud.com", "type": "allow", "kind": "exact", "comment": "FlowSight", "enabled": true, "changed": 1790485200, "servers": map[string]bool{"https://192.168.1.53": true}}}}))
	ctx.Route("POST", "/api/pihole/domains", m.apiDomainChange, core.Write(),
		core.Doc("Add names to, or remove them from, a Pi-hole allow or deny list; recorded in the change history"),
		core.Body(core.Fld("action", "string", true, "add or remove", "add"),
			core.Fld("type", "string", true, "allow or deny", "allow"),
			core.Fld("kind", "string", false, "exact (default) or regex", "exact"),
			core.FldArr("domains", true, "Names (1 to 100)", core.Fld("", "string", false, "", "")),
			core.Fld("comment", "string", false, "Note kept on the Pi-hole", "Allowed from a FlowSight device advisory"),
			core.Fld("server", "string", false, "One Pi-hole, or empty for all", "all")),
		core.Returns("Per-server result", map[string]any{"ok": true, "results": []map[string]any{{"url": "https://192.168.1.53", "ok": true}}}))
}
