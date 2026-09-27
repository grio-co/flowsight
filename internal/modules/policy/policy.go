// Package policy owns the declarative policy document: editing, validation,
// compilation onto every registered provider, and continuous reconciliation.
//
// Nothing is written to a backend until the operator turns enforcement on.
// From then on the module keeps providers in step with the document: a
// schedule window opening, a category feed refreshing or a file edited by
// hand all converge back within a minute, and every apply is recorded with
// its diff.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
	"github.com/grioghar/flowsight/internal/licensing"
	"gopkg.in/yaml.v3"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

type Module struct {
	ctx      *core.Context
	path     string
	mu       sync.RWMutex
	doc      *core.PolicyDoc
	loadErr  string
	lastPlan *Plan
	applying bool
	lastSig  string // inputs of the last clean, in-sync plan; unchanged inputs skip recompiling
	cycles   int
}

// Plan is what apply would do, per provider.
type Plan struct {
	At        int64          `json:"at"`
	Enforce   bool           `json:"enforce"`
	Providers []ProviderPlan `json:"providers"`
	Unmet     []string       `json:"unmet"` // capabilities no provider offers
	Errors    []string       `json:"errors"`
	Warnings  []string       `json:"warnings,omitempty"`
	Changes   int            `json:"changes"`
	Policies  []PolicyStatus `json:"policies"`
}

type ProviderPlan struct {
	Name         string   `json:"name"`
	Capabilities []string `json:"capabilities"`
	Files        []string `json:"files"`
	Changed      bool     `json:"changed"`
	Diff         string   `json:"diff"`
	Error        string   `json:"error,omitempty"`
	Note         string   `json:"note,omitempty"`
	Hash         string   `json:"hash"`
}

type PolicyStatus struct {
	Name     string   `json:"name"`
	Enabled  bool     `json:"enabled"`
	Active   bool     `json:"active"` // schedule in effect now
	Action   string   `json:"action"`
	Requires []string `json:"requires"`
	Unmet    []string `json:"unmet"`
	Members  int      `json:"members"`
	// Excluded counts members that are in the exclusions list; Warning is
	// set when that leaves nothing for the firewall and DNS to enforce.
	Excluded int    `json:"excluded,omitempty"`
	Warning  string `json:"warning,omitempty"`
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name: "policy", Version: "1.0",
		Description: "The declarative policy document, its compiler and continuous reconciliation onto every backend.",
		After:       []string{"identity", "categories", "dns", "web", "appcontrol", "tls"},
		Defaults: map[string]any{
			"enforce":           false,
			"reconcile_seconds": 60,
		},
		Schema: []core.SettingField{
			{Key: "enforce", Label: "Enforce policy", Type: "bool",
				Help: "Off: the document is compiled and planned but never written to a backend. On: every provider is kept in step with it."},
			{Key: "reconcile_seconds", Label: "Reconcile interval (s)", Type: "int"},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.path = filepath.Join(ctx.Platform.EtcDir, "policy.json")
	m.load()
	ctx.Publish("policy_doc", m)
	every := time.Duration(core.Int(ctx.Settings(), "reconcile_seconds", 60)) * time.Second
	if every < 15*time.Second {
		every = 15 * time.Second
	}
	ctx.Every("reconcile", every, m.reconcile, core.Delayed())
	ctx.Route("GET", "/api/policy", m.apiGet,
		core.Doc("Retrieve the current policy document, its compilation status, plan, and enforcement state"),
		core.Returns("Policy document with status", map[string]any{
			"document": map[string]any{"version": 1, "policies": []any{}, "groups": map[string]any{}, "schedules": map[string]any{}},
			"enforce":  true,
			"error":    "",
			"plan":     map[string]any{"at": 1790376243, "enforce": true, "changes": 0},
			"path":     "/etc/flowsight/policy.json",
		}))
	ctx.Route("POST", "/api/policy", m.apiPut, core.Write(),
		core.Doc("Replace the entire policy document after validation and preview compilation"),
		core.Body(
			core.Fld("version", "integer", true, "Document version", 1),
			core.Fld("policies", "array", true, "List of policies", []map[string]any{}),
			core.Fld("groups", "object", true, "Device groups keyed by name", map[string]any{}),
			core.Fld("schedules", "object", true, "Schedule rules keyed by name", map[string]any{}),
		),
		core.Returns("Success response", map[string]any{"ok": true}))
	ctx.Route("GET", "/api/policy/plan", m.apiPlan,
		core.Doc("Compile the policy onto every registered provider and show what would change without applying"),
		core.Returns("Compilation plan across all providers", map[string]any{
			"plan": map[string]any{
				"at":      1790376243,
				"enforce": true,
				"changes": 2,
				"providers": []map[string]any{
					{"name": "firewall", "capabilities": []string{"country-block"}, "changed": true, "hash": "abc123"},
				},
				"policies": []map[string]any{
					{"name": "block-ads", "enabled": true, "active": true, "members": 15},
				},
			},
		}))
	ctx.Route("GET", "/api/policy/matches", m.apiMatches,
		core.Query("name", "string", "Policy name to inspect for matches", true, "block-ads"),
		core.Query("hours", "integer", "Time window in hours for match analysis", false, 24),
		core.Doc("Analyze which devices and far-ends match a specific policy rule, with session details and firewall log records"),
		core.Returns("Policy match analysis", map[string]any{
			"devices": []map[string]any{
				{"name": "MacBookPro", "ip": "192.168.1.10", "matches": 42},
			},
		}))
	ctx.Route("POST", "/api/policy/apply", m.apiApply, core.Write(),
		core.Doc("Apply the current plan immediately to all providers (requires enforcement to be enabled)"),
		core.Returns("Apply result with plan", map[string]any{
			"ok":    true,
			"plan":  map[string]any{"changes": 2, "errors": []string{}},
			"error": "",
		}))
	ctx.Route("POST", "/api/policy/policy", m.apiSavePolicy, core.Write(),
		core.Doc("Create a new policy or update an existing one with validation and compilation"),
		core.Body(
			core.Fld("original", "string", false, "Previous policy name when editing", ""),
			core.Fld("policy", "object", true, "Policy definition with name, action, and match rules", map[string]any{}),
		),
		core.Returns("Success response", map[string]any{"ok": true}))
	ctx.Route("POST", "/api/policy/policy/delete", m.apiDeletePolicy, core.Write(),
		core.Doc("Delete a policy from the document by name with validation and recompilation"),
		core.Body(
			core.Fld("name", "string", true, "Name of the policy to delete", "block-ads"),
		),
		core.Returns("Success response", map[string]any{"ok": true}))
	ctx.Route("POST", "/api/policy/policy/move", m.apiMovePolicy, core.Write(),
		core.Doc("Reorder policies in the document list for evaluation priority and display order"),
		core.Body(
			core.Fld("name", "string", true, "Policy name to move", "block-ads"),
			core.Fld("direction", "string", true, "Direction to move: 'up' or 'down'", "up"),
		),
		core.Returns("Success response", map[string]any{"ok": true}))
	ctx.Route("GET", "/api/policy/groups", m.apiGetGroups,
		core.Doc("List all device groups defined in the policy with their member counts"),
		core.Returns("All groups with definitions", map[string]any{
			"groups": map[string]any{
				"office": map[string]any{"members": 12},
			},
		}))
	ctx.Route("GET", "/api/policy/groups/{name}", m.apiGetGroup,
		core.PathParam("name", "string", "Device group name", "office"),
		core.Doc("Retrieve a specific device group definition with its member list and tags"),
		core.Returns("Device group definition", map[string]any{
			"name":    "office",
			"members": []string{"192.168.1.10", "192.168.1.11"},
		}))
	ctx.Route("POST", "/api/policy/group", m.apiSaveGroup, core.Write(),
		core.Doc("Create a new device group or update an existing one with member definitions"),
		core.Body(
			core.Fld("original", "string", false, "Previous group name when editing", ""),
			core.Fld("name", "string", true, "New or current group name", "office"),
			core.Fld("group", "object", true, "Group definition with members and rules", map[string]any{}),
		),
		core.Returns("Success response", map[string]any{"ok": true}))
	ctx.Route("PUT", "/api/policy/groups/{name}", m.apiUpdateGroup, core.Write(),
		core.PathParam("name", "string", "Device group name", "office"),
		core.Doc("Update an existing device group with new member definitions and properties"),
		core.Body(
			core.Fld("members", "array", false, "List of device identifiers", []string{"192.168.1.10"}),
		),
		core.Returns("Success response", map[string]any{"ok": true}))
	ctx.Route("POST", "/api/policy/group/delete", m.apiDeleteGroup, core.Write(),
		core.Doc("Delete a device group from the policy document with validation against usage"),
		core.Body(
			core.Fld("name", "string", true, "Device group name to delete", "office"),
		),
		core.Returns("Success response", map[string]any{"ok": true}))
	ctx.Route("DELETE", "/api/policy/groups/{name}", m.apiDeleteGroupByName, core.Write(),
		core.PathParam("name", "string", "Device group name", "office"),
		core.Doc("Delete a device group via REST DELETE method with validation against usage"),
		core.Returns("Success response", map[string]any{"ok": true}))
	ctx.Route("GET", "/api/policy/schedules", m.apiGetSchedules,
		core.Doc("List all schedules defined in the policy with their time windows and rules"),
		core.Returns("All schedules with definitions", map[string]any{
			"schedules": map[string]any{
				"business-hours": map[string]any{"start": "09:00", "end": "17:00"},
			},
		}))
	ctx.Route("GET", "/api/policy/schedules/{name}", m.apiGetSchedule,
		core.PathParam("name", "string", "Schedule name", "business-hours"),
		core.Doc("Retrieve a specific schedule definition with its time windows and active days"),
		core.Returns("Schedule definition", map[string]any{
			"name":  "business-hours",
			"start": "09:00",
			"end":   "17:00",
			"days":  []string{"Mon", "Tue", "Wed", "Thu", "Fri"},
		}))
	ctx.Route("POST", "/api/policy/schedule", m.apiSaveSchedule, core.Write(),
		core.Doc("Create a new schedule or update an existing one for policy time-based enforcement"),
		core.Body(
			core.Fld("original", "string", false, "Previous schedule name when editing", ""),
			core.Fld("name", "string", true, "Schedule name", "business-hours"),
			core.Fld("schedule", "object", true, "Schedule definition with time windows", map[string]any{}),
		),
		core.Returns("Success response", map[string]any{"ok": true}))
	ctx.Route("PUT", "/api/policy/schedules/{name}", m.apiUpdateSchedule, core.Write(),
		core.PathParam("name", "string", "Schedule name", "business-hours"),
		core.Doc("Update an existing schedule with new time windows and day-of-week rules"),
		core.Body(
			core.Fld("start", "string", false, "Start time in HH:MM format", "09:00"),
			core.Fld("end", "string", false, "End time in HH:MM format", "17:00"),
		),
		core.Returns("Success response", map[string]any{"ok": true}))
	ctx.Route("POST", "/api/policy/schedule/delete", m.apiDeleteSchedule, core.Write(),
		core.Doc("Delete a schedule from the policy document with validation against policy usage"),
		core.Body(
			core.Fld("name", "string", true, "Schedule name to delete", "business-hours"),
		),
		core.Returns("Success response", map[string]any{"ok": true}))
	ctx.Route("DELETE", "/api/policy/schedules/{name}", m.apiDeleteScheduleByName, core.Write(),
		core.PathParam("name", "string", "Schedule name", "business-hours"),
		core.Doc("Delete a schedule via REST DELETE method with validation against policy usage"),
		core.Returns("Success response", map[string]any{"ok": true}))
	ctx.Route("POST", "/api/policy/exclusions", m.apiExclusions, core.Write(),
		core.Doc("Replace the device exclusions list and global policy enforcement options"),
		core.Body(
			core.Fld("exclusions", "object", true, "Devices and CIDRs to exclude from policy", map[string]any{}),
			core.Fld("options", "object", true, "Global policy options like even-excluded enforcement", map[string]any{}),
		),
		core.Returns("Success response", map[string]any{"ok": true}))
	ctx.Route("GET", "/api/policy/export", m.apiExport,
		core.Doc("Export the entire policy document in YAML format for version control or sharing"),
		core.Returns("YAML-formatted policy document", map[string]any{
			"content_type": "application/yaml",
			"filename":     "flowsight-policy.yaml",
		}))
	ctx.Route("POST", "/api/policy/import", m.apiImport, core.Write(),
		core.Doc("Replace the policy document from YAML or JSON text with validation and compilation"),
		core.Body(
			core.Fld("text", "string", true, "YAML or JSON policy document content", "version: 1\npolicies: []"),
		),
		core.Returns("Import result with policy count", map[string]any{
			"ok":       true,
			"policies": 5,
		}))
	ctx.Route("GET", "/api/policy/capabilities", m.apiCapabilities,
		core.Doc("List all registered providers, their capabilities, and what policies require"),
		core.Returns("Capabilities across all providers", map[string]any{
			"providers": []map[string]any{
				{"name": "firewall", "capabilities": []string{"country-block", "app-control"}},
			},
			"categories": []map[string]any{
				{"name": "ads", "domains": 5000},
			},
			"apps": []map[string]any{
				{"app": "netflix", "category": "streaming"},
			},
		}))
	ctx.Panel(core.Panel{ID: "policy", Title: "Policies", Group: "Protect", Order: 100, Icon: "policy"})
	ctx.Panel(core.Panel{ID: "groups", Title: "Groups & Schedules", Group: "Protect", Order: 110, Icon: "groups"})
	return nil
}

func (m *Module) Health() core.Health {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.loadErr != "" {
		return core.Health{OK: false, Detail: "policy document: " + m.loadErr}
	}
	if m.lastPlan != nil && len(m.lastPlan.Errors) > 0 {
		return core.Health{OK: false, Detail: strings.Join(m.lastPlan.Errors, "; ")}
	}
	n := 0
	if m.doc != nil {
		n = len(m.doc.Policies)
	}
	state := "monitor"
	if core.Bool(m.ctx.Settings(), "enforce", false) {
		state = "enforcing"
	}
	return core.Health{OK: true, Detail: fmt.Sprintf("%d policies, %s", n, state)}
}

// ---------------------------------------------------------------- document

func emptyDoc() *core.PolicyDoc {
	return &core.PolicyDoc{Version: 1, Groups: map[string]core.Group{}, Schedules: map[string]core.Schedule{}}
}

func (m *Module) load() {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, err := os.ReadFile(m.path)
	if os.IsNotExist(err) {
		m.doc = emptyDoc()
		m.loadErr = ""
		return
	}
	if err != nil {
		m.loadErr = err.Error()
		if m.doc == nil {
			m.doc = emptyDoc()
		}
		return
	}
	doc := emptyDoc()
	if err := json.Unmarshal(b, doc); err != nil {
		m.loadErr = err.Error()
		if m.doc == nil {
			m.doc = emptyDoc()
		}
		return
	}
	if err := doc.Validate(); err != nil {
		m.loadErr = err.Error()
	} else {
		m.loadErr = ""
	}
	m.doc = doc
}

// Doc returns a deep copy for editing.
func (m *Module) Doc() *core.PolicyDoc {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, _ := json.Marshal(m.doc)
	out := emptyDoc()
	_ = json.Unmarshal(b, out)
	if out.Groups == nil {
		out.Groups = map[string]core.Group{}
	}
	if out.Schedules == nil {
		out.Schedules = map[string]core.Schedule{}
	}
	if out.Policies == nil {
		out.Policies = []core.Policy{} // an empty document must never reach the API as null
	}
	return out
}

// save validates, records the change with a diff, and writes atomically.
func (m *Module) save(doc *core.PolicyDoc, actor, summary string) error {
	if err := doc.Validate(); err != nil {
		return core.BadRequest("%v", err)
	}
	after, _ := json.MarshalIndent(doc, "", "  ")
	before, _ := json.MarshalIndent(m.Doc(), "", "  ")
	if string(before) == string(after) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0o755); err != nil {
		return err
	}
	if b, err := os.ReadFile(m.path); err == nil {
		_ = os.WriteFile(m.path+".bak", b, 0o600)
	}
	if err := os.WriteFile(m.path+".tmp", append(after, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(m.path+".tmp", m.path); err != nil {
		return err
	}
	m.mu.Lock()
	m.doc = doc
	m.loadErr = ""
	m.lastSig = ""
	m.mu.Unlock()
	_ = m.ctx.Store.RecordChange("policy", "policy.json", actor, hash(before), hash(after),
		unifiedDiff(string(before), string(after), "policy.json"), summary)
	m.ctx.Event("audit", "policy changed: "+summary, map[string]any{"actor_name": actor})
	go func() { _, _ = m.plan(true) }()
	return nil
}

func hash(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:8])
}

// ---------------------------------------------------------------- compile

func (m *Module) providers() []core.Provider { return m.ctx.Core.ProviderList() }

// plan compiles the document onto every provider. With apply=true and
// enforcement on, changed providers are applied, one after another, each
// validating and reverting on its own failure.
func (m *Module) plan(apply bool) (*Plan, error) {
	doc := m.Doc()
	m.applyWhitelist(doc)
	m.mu.RLock()
	loadErr := m.loadErr
	m.mu.RUnlock()
	enforce := core.Bool(m.ctx.Settings(), "enforce", false)
	p := &Plan{At: time.Now().Unix(), Enforce: enforce}
	if loadErr != "" {
		p.Errors = append(p.Errors, "policy document invalid: "+loadErr)
		m.setPlan(p)
		return p, nil
	}
	provs := m.providers()
	have := map[string]bool{}
	for _, pr := range provs {
		for _, c := range pr.Capabilities() {
			have[c] = true
		}
	}
	res, _ := m.ctx.Service("member_resolver").(core.MemberResolver)
	ab, _ := m.ctx.Service("identity").(core.AddressBook)
	now := time.Now()
	unmet := map[string]bool{}
	excl := map[string]bool{}
	for _, c := range doc.ExcludedCIDRs(res) {
		excl[c] = true
	}
	for i := range doc.Policies {
		pol := &doc.Policies[i]
		mems := doc.Members(pol, res)
		ps := PolicyStatus{Name: pol.Name, Enabled: pol.Enabled, Action: pol.Action,
			Active: pol.Enabled && doc.Active(pol.Schedule, now), Requires: pol.Requirements(),
			Members: len(mems)}
		for _, mm := range mems {
			if excl[mm] {
				ps.Excluded++
			}
		}
		if pol.Enabled && len(mems) > 0 && ps.Excluded == len(mems) && !pol.Match.EvenExcluded {
			ps.Warning = "every member is in the exclusions list, so the firewall and DNS enforce nothing for this policy; tick \"even excluded hosts\" on it or change the exclusions"
			p.Warnings = append(p.Warnings, pol.Name+": "+ps.Warning)
		}

		// Check for IPv6 devices without IPv6 subnet resolution
		if pol.Enabled && len(mems) > 0 && ps.Warning == "" {
			hasIPv6Member := false
			for _, mem := range mems {
				if strings.HasSuffix(mem, "/128") {
					hasIPv6Member = true
					break
				}
			}
			if !hasIPv6Member && ab != nil {
				// Check if any zone member has devices with IPv6 addresses
				var zoneIDs []string
				for _, member := range pol.Match.Members {
					if strings.HasPrefix(member, "zone:") {
						zoneIDs = append(zoneIDs, strings.TrimPrefix(member, "zone:"))
					}
				}
				if len(zoneIDs) > 0 {
					// Check device IPv6 addresses for each zone
					ipv6DeviceCount := 0
					for _, zoneID := range zoneIDs {
						enrollChecker, ok := m.ctx.Service("enroll").(interface {
							CheckZoneIPv6Devices(zoneID string) int
						})
						if ok && enrollChecker != nil {
							count := enrollChecker.CheckZoneIPv6Devices(zoneID)
							ipv6DeviceCount += count
						}
					}
					if ipv6DeviceCount > 0 {
						ps.Warning = fmt.Sprintf("members resolve to IPv4 only; %d device(s) also use IPv6 (add the zone's IPv6 subnet or use device:/mac: members)", ipv6DeviceCount)
						p.Warnings = append(p.Warnings, pol.Name+": "+ps.Warning)
					}
				}
			}
		}
		for _, c := range ps.Requires {
			if !have[c] {
				ps.Unmet = append(ps.Unmet, c)
				if pol.Enabled {
					unmet[c] = true
				}
			}
		}
		p.Policies = append(p.Policies, ps)
	}
	for c := range unmet {
		p.Unmet = append(p.Unmet, c)
	}
	sort.Strings(p.Unmet)

	m.mu.Lock()
	if m.applying {
		m.mu.Unlock()
		return m.lastPlan, fmt.Errorf("an apply is already running")
	}
	m.applying = apply
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.applying = false
		m.mu.Unlock()
	}()

	for _, pr := range provs {
		pp := ProviderPlan{Name: pr.Name(), Capabilities: pr.Capabilities()}
		desired, err := pr.Compile(doc)
		if err != nil {
			pp.Error = err.Error()
			p.Errors = append(p.Errors, pr.Name()+": "+err.Error())
			p.Providers = append(p.Providers, pp)
			continue
		}
		current, err := pr.Current()
		if err != nil {
			pp.Error = "cannot read current state: " + err.Error()
			p.Errors = append(p.Errors, pr.Name()+": "+pp.Error)
			p.Providers = append(p.Providers, pp)
			continue
		}
		pp.Note = desired.Note
		var diffs []string
		files := make([]string, 0, len(desired.Files))
		for f := range desired.Files {
			files = append(files, f)
		}
		sort.Strings(files)
		var all strings.Builder
		for _, f := range files {
			all.WriteString(f)
			all.WriteString("\n")
			all.WriteString(desired.Files[f])
			if strings.TrimSpace(desired.Files[f]) != strings.TrimSpace(current.Files[f]) {
				diffs = append(diffs, unifiedDiff(current.Files[f], desired.Files[f], f))
			}
		}
		pp.Files = files
		pp.Hash = hash([]byte(all.String()))
		pp.Changed = len(diffs) > 0
		pp.Diff = strings.Join(diffs, "\n")
		if len(pp.Diff) > 200000 {
			pp.Diff = pp.Diff[:200000] + "\n... (truncated)"
		}
		if pp.Changed {
			p.Changes++
		}
		if apply && enforce && pp.Changed {
			note, err := pr.Apply(desired)
			if err != nil {
				pp.Error = "apply failed: " + err.Error()
				p.Errors = append(p.Errors, pr.Name()+": "+pp.Error)
				m.ctx.Event("policy", "apply failed on "+pr.Name()+": "+err.Error(),
					map[string]any{"severity": "high", "verdict": "observed"})
			} else {
				pp.Note = note
				pp.Changed = false
				// The artifact itself can be tens of megabytes (a category zone);
				// the hash and the file list are enough to know what is in place.
				_ = m.ctx.Store.Exec(`INSERT OR REPLACE INTO policy_state(provider,hash,applied_ts,artifact,note)
					VALUES(?,?,?,?,?)`, pr.Name(), pp.Hash, time.Now().Unix(), strings.Join(files, "\n"), note)
				_ = m.ctx.Store.RecordChange("policy", "provider:"+pr.Name(), "flowsightd", "", pp.Hash,
					strings.Join(diffs, "\n"), "applied to "+pr.Name()+": "+note)
				m.ctx.Event("policy", "applied to "+pr.Name()+": "+note, nil)
			}
		}
		p.Providers = append(p.Providers, pp)
	}
	m.setPlan(p)
	return p, nil
}

func (m *Module) setPlan(p *Plan) {
	m.mu.Lock()
	m.lastPlan = p
	m.mu.Unlock()
}

// signature summarises everything a compile depends on apart from the
// providers' current files: the document, the category feeds, which
// schedules are active and the enforcement flag. Compiling a policy with a
// 300,000-name category allocates tens of megabytes; doing that every minute
// when nothing changed is what made the daemon's footprint balloon.
func (m *Module) signature() string {
	doc := m.Doc()
	h := sha256.New()
	b, _ := json.Marshal(doc)
	h.Write(b)
	now := time.Now()
	for _, p := range doc.Policies {
		fmt.Fprintf(h, "%s=%v;", p.Name, doc.Active(p.Schedule, now))
	}
	// Membership is an input: a device that picks up a new address (a rotated
	// temporary IPv6 address, a new lease) must recompile, or policy would
	// quietly stop applying to it.
	if res, ok := m.ctx.Service("member_resolver").(core.MemberResolver); ok {
		for i := range doc.Policies {
			for _, mem := range doc.Members(&doc.Policies[i], res) {
				fmt.Fprintf(h, "%s,", mem)
			}
			h.Write([]byte(";"))
		}
	}
	if c, ok := m.ctx.Service("categories").(core.Categories); ok {
		// The whitelist is an input to every policy, so its contents, not
		// only its size, are part of the signature.
		if wl, err := c.Domains(whitelistCategory); err == nil {
			for _, d := range wl {
				fmt.Fprintf(h, "wl:%s,", d)
			}
		}
		for _, ci := range c.List() {
			fmt.Fprintf(h, "%s:%d:%d;", ci.Name, ci.Domains, ci.Updated)
		}
	}
	fmt.Fprintf(h, "enforce=%v;", core.Bool(m.ctx.Settings(), "enforce", false))
	// Every module whose settings change what a provider writes belongs here.
	// Stateful Packet Inspection does: it decides the proxy's ICAP service and, with
	// "inspect everything", adds a policy covering every local network. Leaving
	// it out made that switch appear to do nothing for up to ten minutes, until
	// an unrelated change happened to force a recompile.
	for _, mod := range []string{"web", "dns", "firewall", "mitm"} {
		b, _ := json.Marshal(m.ctx.Config.Module(mod))
		h.Write(b)
	}
	// Names found to pin their certificate change what the proxy is told.
	if p, ok := m.ctx.Service("pinned").(interface{ PinnedNames() []string }); ok {
		for _, n := range p.PinnedNames() {
			fmt.Fprintf(h, "pin:%s;", n)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// reconcile runs on the interval: plan, and apply when enforcing. When the
// inputs have not changed since the last plan that left every provider in
// sync, the expensive compile is skipped; a provider whose files were edited
// by hand is caught on the next input change or every tenth cycle.
func (m *Module) reconcile() error {
	sig := m.signature()
	m.mu.Lock()
	last := m.lastPlan
	skip := sig == m.lastSig && last != nil && len(last.Errors) == 0 && last.Changes == 0 &&
		m.cycles%10 != 0
	m.cycles++
	m.mu.Unlock()
	if skip {
		return nil
	}
	p, err := m.plan(true)
	if err == nil && len(p.Errors) == 0 && p.Changes == 0 {
		m.mu.Lock()
		m.lastSig = sig
		m.mu.Unlock()
	}
	if err != nil {
		return err
	}
	if len(p.Errors) > 0 {
		return fmt.Errorf("%s", strings.Join(p.Errors, "; "))
	}
	return nil
}

// ---------------------------------------------------------------- API

func (m *Module) apiGet(r *core.Req) (any, error) {
	m.mu.RLock()
	plan := m.lastPlan
	loadErr := m.loadErr
	m.mu.RUnlock()
	return map[string]any{"document": m.Doc(), "error": loadErr, "plan": plan,
		"enforce": core.Bool(m.ctx.Settings(), "enforce", false), "path": m.path}, nil
}

func (m *Module) apiPut(r *core.Req) (any, error) {
	doc := emptyDoc()
	if err := r.Decode(doc); err != nil {
		return nil, err
	}
	if err := m.save(doc, r.User, "document replaced"); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

func (m *Module) apiPlan(r *core.Req) (any, error) {
	p, err := m.plan(false)
	if err != nil {
		return nil, err
	}
	return map[string]any{"plan": p}, nil
}

func (m *Module) apiApply(r *core.Req) (any, error) {
	if !core.Bool(m.ctx.Settings(), "enforce", false) {
		return nil, core.Forbidden("enforcement is off: turn on 'Enforce policy' in the policy module settings first")
	}
	p, err := m.plan(true)
	if err != nil {
		return nil, err
	}
	ok := len(p.Errors) == 0
	return map[string]any{"ok": ok, "plan": p, "error": strings.Join(p.Errors, "; ")}, nil
}

func (m *Module) apiSavePolicy(r *core.Req) (any, error) {
	var in struct {
		Original string      `json:"original"` // name being edited, "" for new
		Policy   core.Policy `json:"policy"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	doc := m.Doc()
	idx := -1
	for i, p := range doc.Policies {
		if p.Name == in.Original && in.Original != "" {
			idx = i
		}
	}
	if idx >= 0 {
		doc.Policies[idx] = in.Policy
	} else {
		for _, p := range doc.Policies {
			if p.Name == in.Policy.Name {
				return nil, core.BadRequest("a policy named %q already exists", p.Name)
			}
		}
		if lim := m.ctx.License().Limit(licensing.LimitPolicies); lim > 0 && len(doc.Policies) >= lim {
			return nil, core.LimitError("policies", lim, "policy.unlimited")
		}
		doc.Policies = append(doc.Policies, in.Policy)
	}
	verb := "updated"
	if idx < 0 {
		verb = "created"
	}
	if err := m.save(doc, r.User, "policy "+in.Policy.Name+" "+verb); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

func (m *Module) apiDeletePolicy(r *core.Req) (any, error) {
	name, _ := r.Body()["name"].(string)
	doc := m.Doc()
	var kept []core.Policy
	for _, p := range doc.Policies {
		if p.Name != name {
			kept = append(kept, p)
		}
	}
	if len(kept) == len(doc.Policies) {
		return nil, core.NotFound("no policy named %q", name)
	}
	doc.Policies = kept
	if err := m.save(doc, r.User, "policy "+name+" deleted"); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

func (m *Module) apiMovePolicy(r *core.Req) (any, error) {
	b := r.Body()
	name, _ := b["name"].(string)
	dir, _ := b["direction"].(string)
	doc := m.Doc()
	for i, p := range doc.Policies {
		if p.Name != name {
			continue
		}
		j := i - 1
		if dir == "down" {
			j = i + 1
		}
		if j < 0 || j >= len(doc.Policies) {
			return map[string]any{"ok": true}, nil
		}
		doc.Policies[i], doc.Policies[j] = doc.Policies[j], doc.Policies[i]
		return map[string]any{"ok": true}, m.save(doc, r.User, "policy "+name+" moved "+dir)
	}
	return nil, core.NotFound("no policy named %q", name)
}

func (m *Module) apiSaveGroup(r *core.Req) (any, error) {
	var in struct {
		Original string     `json:"original"`
		Name     string     `json:"name"`
		Group    core.Group `json:"group"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	doc := m.Doc()
	if in.Original != "" && in.Original != in.Name {
		delete(doc.Groups, in.Original)
		for i := range doc.Policies {
			for j, g := range doc.Policies[i].Match.Groups {
				if g == in.Original {
					doc.Policies[i].Match.Groups[j] = in.Name
				}
			}
		}
	}
	doc.Groups[in.Name] = in.Group
	return map[string]any{"ok": true}, m.save(doc, r.User, "group "+in.Name+" saved")
}

func (m *Module) apiDeleteGroup(r *core.Req) (any, error) {
	name, _ := r.Body()["name"].(string)
	doc := m.Doc()
	if _, ok := doc.Groups[name]; !ok {
		return nil, core.NotFound("no group named %q", name)
	}
	for _, p := range doc.Policies {
		for _, g := range p.Match.Groups {
			if g == name {
				return nil, core.BadRequest("group %q is used by policy %q", name, p.Name)
			}
		}
	}
	delete(doc.Groups, name)
	return map[string]any{"ok": true}, m.save(doc, r.User, "group "+name+" deleted")
}

func (m *Module) apiSaveSchedule(r *core.Req) (any, error) {
	var in struct {
		Original string        `json:"original"`
		Name     string        `json:"name"`
		Schedule core.Schedule `json:"schedule"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	doc := m.Doc()
	if in.Original != "" && in.Original != in.Name {
		delete(doc.Schedules, in.Original)
		for i := range doc.Policies {
			if doc.Policies[i].Schedule == in.Original {
				doc.Policies[i].Schedule = in.Name
			}
		}
	}
	if _, exists := doc.Schedules[in.Name]; !exists {
		if lim := m.ctx.License().Limit(licensing.LimitSchedules); lim > 0 && len(doc.Schedules) >= lim {
			return nil, core.LimitError("schedules", lim, "policy.unlimited")
		}
	}
	doc.Schedules[in.Name] = in.Schedule
	return map[string]any{"ok": true}, m.save(doc, r.User, "schedule "+in.Name+" saved")
}

func (m *Module) apiDeleteSchedule(r *core.Req) (any, error) {
	name, _ := r.Body()["name"].(string)
	doc := m.Doc()
	if _, ok := doc.Schedules[name]; !ok {
		return nil, core.NotFound("no schedule named %q", name)
	}
	for _, p := range doc.Policies {
		if p.Schedule == name {
			return nil, core.BadRequest("schedule %q is used by policy %q", name, p.Name)
		}
	}
	delete(doc.Schedules, name)
	return map[string]any{"ok": true}, m.save(doc, r.User, "schedule "+name+" deleted")
}

func (m *Module) apiExclusions(r *core.Req) (any, error) {
	var in struct {
		Exclusions core.Exclusions `json:"exclusions"`
		Options    core.Options    `json:"options"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	doc := m.Doc()
	doc.Exclusions = in.Exclusions
	doc.Options = in.Options
	return map[string]any{"ok": true}, m.save(doc, r.User, "exclusions and options saved")
}

func (m *Module) apiExport(r *core.Req) (any, error) {
	b, err := yaml.Marshal(m.Doc())
	if err != nil {
		return nil, err
	}
	return core.Raw{ContentType: "application/yaml; charset=utf-8", Filename: "flowsight-policy.yaml", Body: b}, nil
}

func (m *Module) apiImport(r *core.Req) (any, error) {
	text, _ := r.Body()["text"].(string)
	if strings.TrimSpace(text) == "" {
		return nil, core.BadRequest("text is required")
	}
	doc := emptyDoc()
	if err := yaml.Unmarshal([]byte(text), doc); err != nil {
		return nil, core.BadRequest("cannot parse: %v", err)
	}
	if err := m.save(doc, r.User, "document imported"); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "policies": len(doc.Policies)}, nil
}

func (m *Module) apiCapabilities(r *core.Req) (any, error) {
	var provs []map[string]any
	for _, p := range m.providers() {
		provs = append(provs, map[string]any{"name": p.Name(), "capabilities": p.Capabilities()})
	}
	var cats []core.CategoryInfo
	if c, ok := m.ctx.Service("categories").(core.Categories); ok {
		cats = c.List()
	}
	var apps []map[string]any
	appCats := map[string]bool{}
	if ac, ok := m.ctx.Service("app_catalog").(core.AppCatalog); ok {
		for name, a := range ac.Apps() {
			apps = append(apps, map[string]any{"app": name, "category": a.Category, "breed": a.Breed})
			if a.Category != "" {
				appCats[a.Category] = true
			}
		}
		sort.Slice(apps, func(i, j int) bool { return apps[i]["app"].(string) < apps[j]["app"].(string) })
	}
	var appCatList []string
	for c := range appCats {
		appCatList = append(appCatList, c)
	}
	sort.Strings(appCatList)
	return map[string]any{"providers": provs, "capabilities": m.ctx.Core.Capabilities(),
		"categories": cats, "apps": apps, "app_categories": appCatList}, nil
}

// whitelistCategory is the one web category that means the opposite of the
// others: names in it are never blocked by any policy. It is a custom
// category on the Categories page, so it is edited like any other list,
// and it is folded into every policy's allow-list at compile time, which
// is how the DNS and web providers already carry exceptions.
const whitelistCategory = "whitelist"

func (m *Module) applyWhitelist(doc *core.PolicyDoc) {
	c, ok := m.ctx.Service("categories").(core.Categories)
	if !ok || doc == nil {
		return
	}
	wl, err := c.Domains(whitelistCategory)
	if err != nil || len(wl) == 0 {
		return
	}
	for i := range doc.Policies {
		have := map[string]bool{}
		for _, d := range doc.Policies[i].Allow.Domains {
			have[strings.ToLower(d)] = true
		}
		for _, d := range wl {
			if d = strings.ToLower(strings.TrimSpace(d)); d != "" && !have[d] {
				doc.Policies[i].Allow.Domains = append(doc.Policies[i].Allow.Domains, d)
				have[d] = true
			}
		}
	}
}
