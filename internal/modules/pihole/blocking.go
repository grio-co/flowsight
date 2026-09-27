package pihole

// Blocking management: what each Pi-hole blocks, and for whom.
//
// A Pi-hole blocks from lists (subscriptions to blocklists and allowlists by
// URL), from single domain entries (exact or regex, allow or deny), and it
// applies both per group: every list, entry and client belongs to groups,
// and a client is filtered by the lists and entries of its groups. FlowSight
// manages all four on one Pi-hole or on every connected Pi-hole at once.
//
// Groups are known to FlowSight by name. Each Pi-hole numbers its groups
// itself, so "Kids" may be group 3 on one and group 5 on the other; every
// write translates names to that Pi-hole's numbers, and creates a group a
// Pi-hole does not have yet, which is what makes "update all" work.
//
// A FlowSight category can be a Pi-hole list: FlowSight serves it as a
// keyed feed (core/feed.go) and the Pi-hole subscribes to its URL like any
// other blocklist, fetching it on every gravity run.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

type phState struct {
	s                               *serverState
	groups, lists, clients, domains []map[string]any
	gid                             map[string]int
	gname                           map[int]string
	writable                        bool
	err                             error
}

func (st *phState) names(v any) []string {
	var out []string
	arr, _ := v.([]any)
	for _, x := range arr {
		if f, ok := x.(float64); ok {
			if n, ok := st.gname[int(f)]; ok {
				out = append(out, n)
			} else {
				out = append(out, "#"+strconv.Itoa(int(f)))
			}
		}
	}
	sort.Strings(out)
	return out
}

func (m *Module) loadOne(s *serverState) *phState {
	st := &phState{s: s, gid: map[string]int{}, gname: map[int]string{}}
	get := func(path, key string) []map[string]any {
		out, _, err := m.call(s, "GET", path, nil)
		if err != nil {
			if st.err == nil {
				st.err = err
			}
			return nil
		}
		var rows []map[string]any
		if arr, ok := out[key].([]any); ok {
			for _, x := range arr {
				if r, ok := x.(map[string]any); ok {
					rows = append(rows, r)
				}
			}
		}
		return rows
	}
	st.groups = get("/api/groups", "groups")
	for _, g := range st.groups {
		id := int(toF(g["id"]))
		name := fmt.Sprint(g["name"])
		st.gid[name] = id
		st.gname[id] = name
	}
	st.lists = get("/api/lists", "lists")
	st.clients = get("/api/clients", "clients")
	st.domains = get("/api/domains", "domains")
	if cfg, _, err := m.call(s, "GET", "/api/config/webserver/api/app_sudo", nil); err == nil {
		if c, ok := cfg["config"].(map[string]any); ok {
			if w, ok := c["webserver"].(map[string]any); ok {
				if a, ok := w["api"].(map[string]any); ok {
					st.writable = a["app_sudo"] == true
				}
			}
		}
	}
	return st
}

func (m *Module) loadStates(servers []*serverState) []*phState {
	out := make([]*phState, len(servers))
	var wg sync.WaitGroup
	for i, s := range servers {
		wg.Add(1)
		go func(i int, s *serverState) { defer wg.Done(); out[i] = m.loadOne(s) }(i, s)
	}
	wg.Wait()
	return out
}

// groupIDs translates names into this Pi-hole's group numbers, creating
// the groups it lacks. An empty list means the Default group (0).
func (m *Module) groupIDs(st *phState, names []string) ([]int, error) {
	if len(names) == 0 {
		return []int{0}, nil
	}
	var ids []int
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		id, ok := st.gid[n]
		if !ok {
			if _, _, err := m.call(st.s, "POST", "/api/groups", map[string]any{"name": n, "enabled": true, "comment": "Created by FlowSight"}); err != nil && !isUnique(err) {
				return nil, fmt.Errorf("creating group %s: %v", n, err)
			}
			fresh := m.loadOne(st.s)
			st.gid, st.gname, st.groups = fresh.gid, fresh.gname, fresh.groups
			if id, ok = st.gid[n]; !ok {
				return nil, fmt.Errorf("group %s could not be created", n)
			}
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		ids = []int{0}
	}
	return ids, nil
}

func isUnique(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "HTTP 409") || strings.Contains(err.Error(), "already"))
}

func isMissing(code int, err error) bool {
	return code == 404 || (err != nil && strings.Contains(err.Error(), "HTTP 404"))
}

// each runs fn on every chosen Pi-hole and collects one result per server.
func (m *Module) each(which string, fn func(st *phState, res map[string]any) error) ([]map[string]any, int, error) {
	servers, err := m.pick(which)
	if err != nil {
		return nil, 0, err
	}
	states := m.loadStates(servers)
	results := make([]map[string]any, len(states))
	ok := 0
	for i, st := range states {
		res := map[string]any{"url": st.s.URL, "host": st.s.Host}
		results[i] = res
		switch {
		case st.err != nil:
			res["error"] = st.err.Error()
		case !st.writable:
			res["error"] = "read only: turn on “Permit app password to modify config” on this Pi-hole (sudo pihole-FTL --config webserver.api.app_sudo true)"
		default:
			if err := fn(st, res); err != nil {
				res["error"] = err.Error()
			} else {
				res["ok"] = true
				ok++
			}
		}
	}
	targetsMu.Lock()
	targetsAt = time.Time{}
	targetsMu.Unlock()
	return results, ok, nil
}

func find(rows []map[string]any, match func(map[string]any) bool) map[string]any {
	for _, r := range rows {
		if match(r) {
			return r
		}
	}
	return nil
}

func strOr(v any, def string) string {
	if s, ok := v.(string); ok {
		return s
	}
	return def
}

// ------------------------------------------------------------ the view

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

var (
	feedRe = regexp.MustCompile(`/feeds/categories/([a-z0-9_-]+)\.txt`)
	keyRe  = regexp.MustCompile(`key=[0-9a-f]{16,}`)
)

func (m *Module) apiBlockingState(r *core.Req) (any, error) {
	servers, err := m.pick(r.Q("server", "all"))
	if err != nil {
		return nil, err
	}
	states := m.loadStates(servers)
	var srv []map[string]any
	type merged struct {
		row     map[string]any
		servers map[string]map[string]any
		keyVals []string
		differs bool
	}
	merge := func(kind string, key func(map[string]any) string, view func(*phState, map[string]any) (map[string]any, []string)) []map[string]any {
		byKey := map[string]*merged{}
		var order []string
		for _, st := range states {
			if st.err != nil {
				continue
			}
			var rows []map[string]any
			switch kind {
			case "groups":
				rows = st.groups
			case "lists":
				rows = st.lists
			case "clients":
				rows = st.clients
			case "domains":
				rows = st.domains
			}
			for _, x := range rows {
				k := key(x)
				row, cmp := view(st, x)
				e := byKey[k]
				if e == nil {
					e = &merged{row: row, servers: map[string]map[string]any{}, keyVals: cmp}
					byKey[k] = e
					order = append(order, k)
				} else if !sameStrings(e.keyVals, cmp) {
					e.differs = true
				}
				per := map[string]any{"id": x["id"], "enabled": x["enabled"]}
				for _, f := range []string{"number", "status", "date_updated", "invalid_domains", "abp_entries"} {
					if v, ok := x[f]; ok {
						per[f] = v
					}
				}
				e.servers[st.s.URL] = per
			}
		}
		live := 0
		for _, st := range states {
			if st.err == nil {
				live++
			}
		}
		out := make([]map[string]any, 0, len(order))
		for _, k := range order {
			e := byKey[k]
			e.row["servers"] = e.servers
			e.row["differs"] = e.differs
			e.row["missing"] = live - len(e.servers)
			out = append(out, e.row)
		}
		return out
	}
	groups := merge("groups", func(x map[string]any) string { return fmt.Sprint(x["name"]) }, func(st *phState, x map[string]any) (map[string]any, []string) {
		row := map[string]any{"name": x["name"], "comment": x["comment"], "enabled": x["enabled"], "default": toF(x["id"]) == 0}
		return row, []string{fmt.Sprint(x["enabled"]), strOr(x["comment"], "")}
	})
	lists := merge("lists", func(x map[string]any) string { return fmt.Sprint(x["type"]) + "|" + fmt.Sprint(x["address"]) }, func(st *phState, x map[string]any) (map[string]any, []string) {
		g := st.names(x["groups"])
		row := map[string]any{"address": x["address"], "type": x["type"], "comment": x["comment"], "enabled": x["enabled"], "groups": g}
		if mm := feedRe.FindStringSubmatch(fmt.Sprint(x["address"])); mm != nil {
			row["category"] = mm[1]
		}
		return row, []string{fmt.Sprint(x["enabled"]), strings.Join(g, ",")}
	})
	clients := merge("clients", func(x map[string]any) string { return fmt.Sprint(x["client"]) }, func(st *phState, x map[string]any) (map[string]any, []string) {
		g := st.names(x["groups"])
		row := map[string]any{"client": x["client"], "name": x["name"], "comment": x["comment"], "groups": g}
		if m.identity != nil {
			if n := m.identity.Name(fmt.Sprint(x["client"])); n != "" {
				row["flowsight_name"] = n
			}
		}
		return row, []string{strings.Join(g, ",")}
	})
	domains := merge("domains", func(x map[string]any) string {
		return fmt.Sprint(x["type"]) + "|" + fmt.Sprint(x["kind"]) + "|" + fmt.Sprint(x["domain"])
	}, func(st *phState, x map[string]any) (map[string]any, []string) {
		g := st.names(x["groups"])
		row := map[string]any{"domain": x["domain"], "type": x["type"], "kind": x["kind"], "comment": x["comment"], "enabled": x["enabled"], "groups": g}
		return row, []string{fmt.Sprint(x["enabled"]), strings.Join(g, ",")}
	})
	for _, st := range states {
		row := map[string]any{"url": st.s.URL, "host": st.s.Host, "writable": st.writable}
		if st.err != nil {
			row["error"] = st.err.Error()
		}
		gravityMu.Lock()
		if g := gravity[st.s.URL]; g != nil {
			row["gravity"] = g.view()
		}
		gravityMu.Unlock()
		srv = append(srv, row)
	}
	return map[string]any{"servers": srv, "groups": groups, "lists": lists, "clients": clients, "domains": domains,
		"categories": m.categoryFeeds(states)}, nil
}

// ------------------------------------------------------------ groups

var groupNameRe = regexp.MustCompile(`^[\p{L}\p{N} _.-]{1,64}$`)

func (m *Module) apiGroupChange(r *core.Req) (any, error) {
	var in struct {
		Server, Action, Name, NewName, Comment string
		Enabled                                *bool
	}
	var raw map[string]any
	if err := r.Decode(&raw); err != nil {
		return nil, err
	}
	b, _ := json.Marshal(raw)
	_ = json.Unmarshal(b, &in)
	if v, ok := raw["new_name"].(string); ok {
		in.NewName = v
	}
	in.Name = strings.TrimSpace(in.Name)
	if !groupNameRe.MatchString(in.Name) {
		return nil, core.BadRequest("a group name is 1 to 64 letters, digits, spaces, dots, dashes or underscores")
	}
	if in.NewName != "" && !groupNameRe.MatchString(in.NewName) {
		return nil, core.BadRequest("the new name is not a valid group name")
	}
	if in.Action == "remove" && strings.EqualFold(in.Name, "Default") {
		return nil, core.BadRequest("the Default group cannot be removed; every client without another group is in it")
	}
	results, ok, err := m.each(in.Server, func(st *phState, res map[string]any) error {
		cur := find(st.groups, func(x map[string]any) bool { return fmt.Sprint(x["name"]) == in.Name })
		switch in.Action {
		case "remove":
			if cur == nil {
				res["unchanged"] = true
				return nil
			}
			_, code, err := m.call(st.s, "DELETE", "/api/groups/"+url.PathEscape(in.Name), nil)
			if isMissing(code, err) {
				return nil
			}
			return err
		case "add", "update":
			body := map[string]any{"name": in.Name, "enabled": true, "comment": in.Comment}
			if cur != nil {
				body["enabled"], body["comment"] = cur["enabled"], strOr(cur["comment"], "")
			}
			if in.Enabled != nil {
				body["enabled"] = *in.Enabled
			}
			if _, has := raw["comment"]; has {
				body["comment"] = in.Comment
			}
			if cur == nil {
				_, _, err := m.call(st.s, "POST", "/api/groups", body)
				return err
			}
			if in.NewName != "" {
				body["name"] = in.NewName
			}
			_, _, err := m.call(st.s, "PUT", "/api/groups/"+url.PathEscape(in.Name), body)
			return err
		}
		return fmt.Errorf("action is add, update or remove")
	})
	if err != nil {
		return nil, err
	}
	m.record(r, "groups", fmt.Sprintf("group %s %s", in.Name, in.Action), results)
	return map[string]any{"ok": ok == len(results), "results": results}, nil
}

// ------------------------------------------------------------ lists

func validListAddress(a string) bool {
	u, err := url.Parse(a)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https" || u.Scheme == "file") && len(a) <= 2048 && (u.Host != "" || u.Scheme == "file")
}

type listChange struct {
	Server, Action, Address, Type, Comment string
	Enabled                                *bool
	Groups                                 []string
	GroupsSet                              bool
	CommentSet                             bool
	Gravity                                *bool
}

func (m *Module) applyList(st *phState, c listChange, address string) error {
	cur := find(st.lists, func(x map[string]any) bool {
		return fmt.Sprint(x["address"]) == address && fmt.Sprint(x["type"]) == c.Type
	})
	q := "?type=" + url.QueryEscape(c.Type)
	if c.Action == "remove" {
		if cur == nil {
			return nil
		}
		_, code, err := m.call(st.s, "DELETE", "/api/lists/"+url.PathEscape(address)+q, nil)
		if isMissing(code, err) {
			return nil
		}
		return err
	}
	body := map[string]any{"enabled": true, "comment": c.Comment}
	var groups []string
	if cur != nil {
		body["enabled"], body["comment"] = cur["enabled"], strOr(cur["comment"], "")
		groups = st.names(cur["groups"])
	}
	if c.Enabled != nil {
		body["enabled"] = *c.Enabled
	}
	if c.CommentSet {
		body["comment"] = c.Comment
	}
	if c.GroupsSet || cur == nil {
		groups = c.Groups
	}
	ids, err := m.groupIDs(st, groups)
	if err != nil {
		return err
	}
	body["groups"] = ids
	if cur == nil {
		body["address"] = address
		_, _, err := m.call(st.s, "POST", "/api/lists"+q, body)
		return err
	}
	_, _, err = m.call(st.s, "PUT", "/api/lists/"+url.PathEscape(address)+q, body)
	return err
}

func (m *Module) apiListChange(r *core.Req) (any, error) {
	var raw map[string]any
	if err := r.Decode(&raw); err != nil {
		return nil, err
	}
	c := decodeListChange(raw)
	if c.Type != "block" && c.Type != "allow" {
		return nil, core.BadRequest("type is block or allow")
	}
	if c.Action != "add" && c.Action != "update" && c.Action != "remove" {
		return nil, core.BadRequest("action is add, update or remove")
	}
	if !validListAddress(c.Address) {
		return nil, core.BadRequest("a list is an http(s) or file URL")
	}
	results, ok, err := m.each(c.Server, func(st *phState, res map[string]any) error { return m.applyList(st, c, c.Address) })
	if err != nil {
		return nil, err
	}
	m.record(r, "lists", fmt.Sprintf("%slist %s %s", c.Type, c.Address, c.Action), results)
	out := map[string]any{"ok": ok == len(results), "results": results}
	if c.Gravity == nil || *c.Gravity {
		out["gravity"] = m.startGravity(results)
	}
	return out, nil
}

func decodeListChange(raw map[string]any) listChange {
	c := listChange{}
	c.Server, _ = raw["server"].(string)
	c.Action, _ = raw["action"].(string)
	c.Address, _ = raw["address"].(string)
	c.Address = strings.TrimSpace(c.Address)
	c.Type, _ = raw["type"].(string)
	if c.Type == "" {
		c.Type = "block"
	}
	if v, ok := raw["comment"].(string); ok {
		c.Comment, c.CommentSet = v, true
	}
	if v, ok := raw["enabled"].(bool); ok {
		c.Enabled = &v
	}
	if v, ok := raw["gravity"].(bool); ok {
		c.Gravity = &v
	}
	if arr, ok := raw["groups"].([]any); ok {
		c.GroupsSet = true
		for _, x := range arr {
			if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
				c.Groups = append(c.Groups, strings.TrimSpace(s))
			}
		}
	}
	return c
}

// ------------------------------------------------------------ clients

var clientRe = regexp.MustCompile(`^(:[a-z0-9._-]+|[0-9a-fA-F:.]+(/[0-9]{1,3})?|([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}|[a-zA-Z0-9._-]{1,253})$`)

func (m *Module) apiClientChange(r *core.Req) (any, error) {
	var raw map[string]any
	if err := r.Decode(&raw); err != nil {
		return nil, err
	}
	server, _ := raw["server"].(string)
	action, _ := raw["action"].(string)
	client, _ := raw["client"].(string)
	client = strings.TrimSpace(client)
	comment, commentSet := raw["comment"].(string)
	var groups []string
	_, groupsSet := raw["groups"]
	if arr, ok := raw["groups"].([]any); ok {
		for _, x := range arr {
			if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
				groups = append(groups, strings.TrimSpace(s))
			}
		}
	}
	if !clientRe.MatchString(client) {
		return nil, core.BadRequest("a client is an address, a network (CIDR), a hardware address, a host name, or :interface")
	}
	if action != "add" && action != "update" && action != "remove" {
		return nil, core.BadRequest("action is add, update or remove")
	}
	results, ok, err := m.each(server, func(st *phState, res map[string]any) error {
		cur := find(st.clients, func(x map[string]any) bool { return strings.EqualFold(fmt.Sprint(x["client"]), client) })
		if action == "remove" {
			if cur == nil {
				return nil
			}
			_, code, err := m.call(st.s, "DELETE", "/api/clients/"+url.PathEscape(client), nil)
			if isMissing(code, err) {
				return nil
			}
			return err
		}
		body := map[string]any{"comment": comment}
		gs := groups
		if cur != nil {
			if !commentSet {
				body["comment"] = strOr(cur["comment"], "")
			}
			if !groupsSet {
				gs = st.names(cur["groups"])
			}
		}
		ids, err := m.groupIDs(st, gs)
		if err != nil {
			return err
		}
		body["groups"] = ids
		if cur == nil {
			body["client"] = client
			_, _, err := m.call(st.s, "POST", "/api/clients", body)
			return err
		}
		_, _, err = m.call(st.s, "PUT", "/api/clients/"+url.PathEscape(client), body)
		return err
	})
	if err != nil {
		return nil, err
	}
	m.record(r, "clients", fmt.Sprintf("client %s %s (groups %s)", client, action, strings.Join(groups, ", ")), results)
	return map[string]any{"ok": ok == len(results), "results": results}, nil
}

// ------------------------------------------------------------ gravity

type gravityRun struct {
	Running  bool     `json:"running"`
	Started  int64    `json:"started"`
	Finished int64    `json:"finished,omitempty"`
	OK       bool     `json:"ok"`
	Error    string   `json:"error,omitempty"`
	Tail     []string `json:"tail"`
}

func (g *gravityRun) view() gravityRun { c := *g; c.Tail = append([]string(nil), g.Tail...); return c }

var (
	gravityMu sync.Mutex
	gravity   = map[string]*gravityRun{}
)

// startGravity rebuilds the lists on every server a change reached. Gravity
// downloads every list, so it runs in the background; its progress is in
// GET /api/pihole/blocking.
func (m *Module) startGravity(results []map[string]any) []string {
	var started []string
	for _, res := range results {
		if res["ok"] != true || res["unchanged"] == true {
			continue
		}
		u, _ := res["url"].(string)
		for _, s := range m.connected() {
			if s.URL == u && m.runGravity(s) {
				started = append(started, s.Host)
			}
		}
	}
	return started
}

func (m *Module) runGravity(s *serverState) bool {
	gravityMu.Lock()
	if g := gravity[s.URL]; g != nil && g.Running {
		gravityMu.Unlock()
		return false
	}
	run := &gravityRun{Running: true, Started: time.Now().Unix()}
	gravity[s.URL] = run
	gravityMu.Unlock()
	go func() {
		err := m.streamGravity(s, run)
		gravityMu.Lock()
		run.Running, run.Finished = false, time.Now().Unix()
		if err != nil {
			run.Error = err.Error()
		} else {
			run.OK = true
			for _, l := range run.Tail {
				if strings.Contains(l, "[✗]") || strings.Contains(strings.ToLower(l), "error") {
					run.OK = false
				}
			}
		}
		gravityMu.Unlock()
		_ = m.ctx.Store.RecordChange("pihole", s.Host+":gravity", "flowsightd", "", "", "", fmt.Sprintf("Pi-hole %s: gravity rebuilt (%s)", s.Host, map[bool]string{true: "ok", false: "with problems"}[run.OK]))
	}()
	return true
}

func (m *Module) streamGravity(s *serverState, run *gravityRun) error {
	sid, err := m.v6Session(s, core.Str(m.ctx.Settings(), "password", ""))
	if err != nil {
		return err
	}
	req, _ := http.NewRequest("POST", s.URL+"/api/action/gravity", nil)
	req.Header.Set("sid", sid)
	client := &http.Client{Timeout: 15 * time.Minute, Transport: m.httpClient().Transport}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	ansi := regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
	for sc.Scan() {
		// The feed key is a secret of this installation; the output is shown.
		line := keyRe.ReplaceAllString(strings.TrimSpace(ansi.ReplaceAllString(sc.Text(), "")), "key=…")
		if line == "" {
			continue
		}
		gravityMu.Lock()
		run.Tail = append(run.Tail, line)
		if len(run.Tail) > 40 {
			run.Tail = run.Tail[len(run.Tail)-40:]
		}
		gravityMu.Unlock()
	}
	return sc.Err()
}

func (m *Module) apiGravity(r *core.Req) (any, error) {
	var in struct {
		Server string `json:"server"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	servers, err := m.pick(in.Server)
	if err != nil {
		return nil, err
	}
	var started, busy []string
	for _, s := range servers {
		if m.runGravity(s) {
			started = append(started, s.Host)
		} else {
			busy = append(busy, s.Host)
		}
	}
	return map[string]any{"ok": true, "started": started, "already_running": busy}, nil
}

// ------------------------------------------------------------ categories

// feedBase is the address a Pi-hole reaches FlowSight at: the gateway's own
// address on the path to that Pi-hole, and the API port.
func (m *Module) feedBase(s *serverState) (string, error) {
	cs := m.ctx.Core.Config.Core()
	if cs.Bind == "127.0.0.1" || cs.Bind == "::1" || cs.Bind == "localhost" {
		return "", fmt.Errorf("FlowSight listens only on %s, which a Pi-hole cannot reach; set bind to 0.0.0.0 (or a LAN address) to serve category feeds", cs.Bind)
	}
	c, err := net.DialTimeout("udp", net.JoinHostPort(s.Host, "53"), 2*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	ip := c.LocalAddr().(*net.UDPAddr).IP
	if cs.Bind != "" && cs.Bind != "0.0.0.0" && cs.Bind != "::" {
		ip = net.ParseIP(cs.Bind)
	}
	return "http://" + net.JoinHostPort(ip.String(), strconv.Itoa(cs.Port)), nil
}

func (m *Module) categoryFeeds(states []*phState) []map[string]any {
	svc, _ := m.ctx.Service("categories").(interface{ List() []core.CategoryInfo })
	if svc == nil {
		return nil
	}
	sub := map[string]map[string]string{} // category -> server -> list type
	for _, st := range states {
		for _, l := range st.lists {
			if mm := feedRe.FindStringSubmatch(fmt.Sprint(l["address"])); mm != nil {
				if sub[mm[1]] == nil {
					sub[mm[1]] = map[string]string{}
				}
				sub[mm[1]][st.s.URL] = fmt.Sprint(l["type"])
			}
		}
	}
	var out []map[string]any
	for _, c := range svc.List() {
		out = append(out, map[string]any{"name": c.Name, "domains": c.Domains, "source": c.Source, "subscribed": sub[c.Name]})
	}
	sort.Slice(out, func(i, j int) bool { return fmt.Sprint(out[i]["name"]) < fmt.Sprint(out[j]["name"]) })
	return out
}

func (m *Module) apiCategoryChange(r *core.Req) (any, error) {
	var raw map[string]any
	if err := r.Decode(&raw); err != nil {
		return nil, err
	}
	category, _ := raw["category"].(string)
	category = strings.ToLower(strings.TrimSpace(category))
	action, _ := raw["action"].(string)
	svc, _ := m.ctx.Service("categories").(interface {
		Domains(string) ([]string, error)
	})
	if svc == nil {
		return nil, core.BadRequest("the categories module is not running")
	}
	if _, err := svc.Domains(category); err != nil || !regexp.MustCompile(`^[a-z0-9_-]+$`).MatchString(category) {
		return nil, core.BadRequest("no category %q", category)
	}
	if action != "subscribe" && action != "unsubscribe" && action != "update" {
		return nil, core.BadRequest("action is subscribe, update or unsubscribe")
	}
	c := decodeListChange(raw)
	if c.Type != "block" && c.Type != "allow" {
		return nil, core.BadRequest("type is block or allow")
	}
	c.Action = map[string]string{"subscribe": "add", "update": "update", "unsubscribe": "remove"}[action]
	if !c.CommentSet {
		c.Comment, c.CommentSet = "FlowSight category "+category, true
	}
	results, ok, err := m.each(c.Server, func(st *phState, res map[string]any) error {
		// Whatever feed URL this Pi-hole already has for the category is
		// the one to change or remove; a new one is built for it.
		var existing string
		for _, l := range st.lists {
			if mm := feedRe.FindStringSubmatch(fmt.Sprint(l["address"])); mm != nil && mm[1] == category && fmt.Sprint(l["type"]) == c.Type {
				existing = fmt.Sprint(l["address"])
			}
		}
		if c.Action == "remove" {
			if existing == "" {
				res["unchanged"] = true
				return nil
			}
			return m.applyList(st, c, existing)
		}
		addr := existing
		if addr == "" {
			base, err := m.feedBase(st.s)
			if err != nil {
				return err
			}
			addr = base + m.ctx.Core.FeedPath(category)
		}
		res["address"] = strings.SplitN(addr, "?", 2)[0] + "?key=…"
		return m.applyList(st, c, addr)
	})
	if err != nil {
		return nil, err
	}
	m.record(r, "lists", fmt.Sprintf("FlowSight category %s %s as a %slist", category, action, c.Type), results)
	out := map[string]any{"ok": ok == len(results), "results": results}
	if c.Gravity == nil || *c.Gravity {
		out["gravity"] = m.startGravity(results)
	}
	return out, nil
}

// ------------------------------------------------------------ sync

// apiSync makes other Pi-holes match one: its groups, lists, clients and
// domain entries are added where missing and corrected where they differ;
// with remove_extra, what the others have beyond it is removed too.
func (m *Module) apiSync(r *core.Req) (any, error) {
	var raw map[string]any
	if err := r.Decode(&raw); err != nil {
		return nil, err
	}
	from, _ := raw["from"].(string)
	to, _ := raw["to"].(string)
	removeExtra, _ := raw["remove_extra"].(bool)
	parts := map[string]bool{"groups": true, "lists": true, "clients": true, "domains": true}
	if arr, ok := raw["parts"].([]any); ok && len(arr) > 0 {
		parts = map[string]bool{}
		for _, x := range arr {
			if s, ok := x.(string); ok {
				parts[s] = true
			}
		}
	}
	src, err := m.pick(from)
	if err != nil || len(src) != 1 {
		return nil, core.BadRequest("from must name one connected Pi-hole")
	}
	source := m.loadOne(src[0])
	if source.err != nil {
		return nil, core.BadRequest("reading %s: %v", src[0].Host, source.err)
	}
	if to == "" {
		to = "all"
	}
	results, ok, err := m.each(to, func(st *phState, res map[string]any) error {
		if st.s.URL == source.s.URL {
			res["unchanged"], res["note"] = true, "the source"
			return nil
		}
		var changes []string
		if parts["groups"] {
			for _, g := range source.groups {
				name := fmt.Sprint(g["name"])
				cur := find(st.groups, func(x map[string]any) bool { return fmt.Sprint(x["name"]) == name })
				body := map[string]any{"name": name, "enabled": g["enabled"], "comment": strOr(g["comment"], "")}
				if cur == nil {
					if _, _, err := m.call(st.s, "POST", "/api/groups", body); err != nil && !isUnique(err) {
						return fmt.Errorf("group %s: %v", name, err)
					}
					changes = append(changes, "+group "+name)
				} else if cur["enabled"] != g["enabled"] || strOr(cur["comment"], "") != strOr(g["comment"], "") {
					if _, _, err := m.call(st.s, "PUT", "/api/groups/"+url.PathEscape(name), body); err != nil {
						return fmt.Errorf("group %s: %v", name, err)
					}
					changes = append(changes, "~group "+name)
				}
			}
			fresh := m.loadOne(st.s)
			st.gid, st.gname, st.groups = fresh.gid, fresh.gname, fresh.groups
			if removeExtra {
				for _, g := range st.groups {
					name := fmt.Sprint(g["name"])
					if toF(g["id"]) != 0 && find(source.groups, func(x map[string]any) bool { return fmt.Sprint(x["name"]) == name }) == nil {
						_, _, _ = m.call(st.s, "DELETE", "/api/groups/"+url.PathEscape(name), nil)
						changes = append(changes, "-group "+name)
					}
				}
			}
		}
		if parts["lists"] {
			for _, l := range source.lists {
				addr, typ := fmt.Sprint(l["address"]), fmt.Sprint(l["type"])
				en := l["enabled"] == true
				c := listChange{Action: "update", Type: typ, Comment: strOr(l["comment"], ""), CommentSet: true, Enabled: &en, Groups: source.names(l["groups"]), GroupsSet: true}
				cur := find(st.lists, func(x map[string]any) bool { return fmt.Sprint(x["address"]) == addr && fmt.Sprint(x["type"]) == typ })
				if cur != nil && cur["enabled"] == l["enabled"] && sameStrings(st.names(cur["groups"]), source.names(l["groups"])) && strOr(cur["comment"], "") == strOr(l["comment"], "") {
					continue
				}
				if err := m.applyList(st, c, addr); err != nil {
					return fmt.Errorf("list %s: %v", addr, err)
				}
				changes = append(changes, map[bool]string{true: "~list ", false: "+list "}[cur != nil]+addr)
			}
			if removeExtra {
				for _, l := range st.lists {
					addr, typ := fmt.Sprint(l["address"]), fmt.Sprint(l["type"])
					if find(source.lists, func(x map[string]any) bool { return fmt.Sprint(x["address"]) == addr && fmt.Sprint(x["type"]) == typ }) == nil {
						if err := m.applyList(st, listChange{Action: "remove", Type: typ}, addr); err == nil {
							changes = append(changes, "-list "+addr)
						}
					}
				}
			}
		}
		if parts["clients"] {
			for _, c := range source.clients {
				client := fmt.Sprint(c["client"])
				ids, err := m.groupIDs(st, source.names(c["groups"]))
				if err != nil {
					return err
				}
				cur := find(st.clients, func(x map[string]any) bool { return fmt.Sprint(x["client"]) == client })
				body := map[string]any{"comment": strOr(c["comment"], ""), "groups": ids}
				if cur == nil {
					body["client"] = client
					if _, _, err := m.call(st.s, "POST", "/api/clients", body); err != nil {
						return fmt.Errorf("client %s: %v", client, err)
					}
					changes = append(changes, "+client "+client)
				} else if !sameStrings(st.names(cur["groups"]), source.names(c["groups"])) || strOr(cur["comment"], "") != strOr(c["comment"], "") {
					if _, _, err := m.call(st.s, "PUT", "/api/clients/"+url.PathEscape(client), body); err != nil {
						return fmt.Errorf("client %s: %v", client, err)
					}
					changes = append(changes, "~client "+client)
				}
			}
			if removeExtra {
				for _, c := range st.clients {
					client := fmt.Sprint(c["client"])
					if find(source.clients, func(x map[string]any) bool { return fmt.Sprint(x["client"]) == client }) == nil {
						_, _, _ = m.call(st.s, "DELETE", "/api/clients/"+url.PathEscape(client), nil)
						changes = append(changes, "-client "+client)
					}
				}
			}
		}
		if parts["domains"] {
			for _, d := range source.domains {
				dom, typ, kind := fmt.Sprint(d["domain"]), fmt.Sprint(d["type"]), fmt.Sprint(d["kind"])
				ids, err := m.groupIDs(st, source.names(d["groups"]))
				if err != nil {
					return err
				}
				cur := find(st.domains, func(x map[string]any) bool {
					return fmt.Sprint(x["domain"]) == dom && fmt.Sprint(x["type"]) == typ && fmt.Sprint(x["kind"]) == kind
				})
				body := map[string]any{"comment": strOr(d["comment"], ""), "groups": ids, "enabled": d["enabled"]}
				path := "/api/domains/" + typ + "/" + kind
				if cur == nil {
					body["domain"] = dom
					if _, _, err := m.call(st.s, "POST", path, body); err != nil && !isUnique(err) {
						return fmt.Errorf("domain %s: %v", dom, err)
					}
					changes = append(changes, "+"+typ+" "+dom)
				} else if cur["enabled"] != d["enabled"] || !sameStrings(st.names(cur["groups"]), source.names(d["groups"])) || strOr(cur["comment"], "") != strOr(d["comment"], "") {
					body["type"], body["kind"] = typ, kind
					if _, _, err := m.call(st.s, "PUT", path+"/"+url.PathEscape(dom), body); err != nil {
						return fmt.Errorf("domain %s: %v", dom, err)
					}
					changes = append(changes, "~"+typ+" "+dom)
				}
			}
			if removeExtra {
				for _, d := range st.domains {
					dom, typ, kind := fmt.Sprint(d["domain"]), fmt.Sprint(d["type"]), fmt.Sprint(d["kind"])
					if find(source.domains, func(x map[string]any) bool {
						return fmt.Sprint(x["domain"]) == dom && fmt.Sprint(x["type"]) == typ && fmt.Sprint(x["kind"]) == kind
					}) == nil {
						_, _, _ = m.call(st.s, "DELETE", "/api/domains/"+typ+"/"+kind+"/"+url.PathEscape(dom), nil)
						changes = append(changes, "-"+typ+" "+dom)
					}
				}
			}
		}
		res["changes"] = changes
		if len(changes) == 0 {
			res["unchanged"] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	m.record(r, "sync", "synced from "+source.s.Host, results)
	out := map[string]any{"ok": ok == len(results), "from": source.s.Host, "results": results}
	if parts["lists"] {
		out["gravity"] = m.startGravity(results)
	}
	return out, nil
}

// record writes one change-history line per Pi-hole a change reached.
func (m *Module) record(r *core.Req, what, summary string, results []map[string]any) {
	for _, res := range results {
		if res["ok"] == true && res["unchanged"] != true {
			host, _ := res["host"].(string)
			_ = m.ctx.Store.RecordChange("pihole", host+":"+what, r.User, "", "", "", "Pi-hole "+host+": "+summary)
		}
	}
}
