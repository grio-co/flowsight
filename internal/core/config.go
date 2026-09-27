package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Config is the operator's single JSON document plus per-module defaults.
//
// The file holds only what the operator changed; defaults are merged at load
// time, so a fresh install has every key and an upgrade that adds a key needs
// no migration. Module settings live under "modules.<name>".
type Config struct {
	// LoadNote says when the file was recovered from its previous copy; the daemon logs it.
	LoadNote string
	Path     string

	mu       sync.RWMutex
	user     map[string]any            // exactly what is on disk
	defaults map[string]map[string]any // module name -> defaults
	core     CoreSettings
}

// CoreSettings are the keys the daemon itself reads. They are never settable
// through the API: whoever can change where the daemon listens or what it
// executes is root, so those are changed in the file, by root.
type CoreSettings struct {
	SiteName string `json:"site_name"`
	Bind     string `json:"bind"`
	Port     int    `json:"port"`
	APIToken string `json:"api_token"`
	// APITokens are named tokens beside APIToken: the audit log records
	// which one acted. Each is {"name": "...", "token": "..."}.
	APITokens []NamedToken `json:"api_tokens"`
	// APITokenLocalOnly accepts the unnamed api_token only from loopback
	// (the OPNsense plugin's proxy), so a copy of it is useless elsewhere.
	APITokenLocalOnly bool `json:"api_token_local_only"`
	// APIAllow lists the addresses and networks that may reach the web
	// interface and API; empty means any. Loopback is always allowed.
	APIAllow []string `json:"api_allow"`
	// HTTPSPort serves the API over HTTPS too (0: off).
	HTTPSPort int `json:"https_port"`
	// HTTPLocalOnly serves plain HTTP to loopback only (and the category
	// feeds); anything else is sent to HTTPS.
	HTTPLocalOnly bool   `json:"http_local_only"`
	LogLevel      string `json:"log_level"`
	DataDir       string `json:"data_dir"`
	Workers       int    `json:"workers"`
	// MemoryLimitMB is the Go soft memory limit (default 256).
	MemoryLimitMB int       `json:"memory_limit_mb"`
	Retention     Retention `json:"retention"`
	// Overrides for platform paths, applied on top of detection.
	Paths map[string]any `json:"paths"`
}

type Retention struct {
	FlowsDays  int `json:"flows_days"`
	DNSDays    int `json:"dns_days"`
	AlertsDays int `json:"alerts_days"`
	EventsDays int `json:"events_days"`
	RollupDays int `json:"rollup_days"`
	TLSDays    int `json:"tls_days"`
}

func defaultCore() CoreSettings {
	return CoreSettings{
		Bind: "127.0.0.1", Port: 8080, HTTPSPort: 8443, LogLevel: "info", Workers: 4,
		Retention: Retention{FlowsDays: 7, DNSDays: 7, AlertsDays: 30, EventsDays: 30,
			RollupDays: 400, TLSDays: 90},
	}
}

// LoadConfig reads the document at path (missing is fine: all defaults).
func LoadConfig(path string) (*Config, error) {
	c := &Config{Path: path, user: map[string]any{}, defaults: map[string]map[string]any{}}
	if err := c.Reload(); err != nil {
		return nil, err
	}
	return c, nil
}

// prevPath is the copy of the previous contents kept beside the file on
// every save. It is what a save falls back to when the file itself has
// gone: a virtual machine backed up or reset between a rename and the data
// reaching the disk comes back with an empty flowsight.json, and running on
// an empty configuration (loopback bind, no token, no module settings) and
// then saving would lose everything.
func (c *Config) prevPath() string { return c.Path + ".prev" }

func (c *Config) Reload() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	user := map[string]any{}
	c.LoadNote = ""
	data, err := os.ReadFile(c.Path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		err, data = nil, nil
	case err != nil:
		return err
	}
	if len(data) > 0 {
		err = json.Unmarshal(data, &user)
	}
	if prev, perr := os.ReadFile(c.prevPath()); perr == nil && len(prev) > 0 && (err != nil || len(data) == 0) {
		// The file is empty or unreadable but a previous copy is here:
		// that copy is the configuration, and the file is rewritten from
		// it so the next save does not start from nothing.
		recovered := map[string]any{}
		if json.Unmarshal(prev, &recovered) == nil && len(recovered) > 0 {
			why := "empty"
			if err != nil {
				why = err.Error()
			}
			c.LoadNote = fmt.Sprintf("%s was %s; restored from %s", c.Path, why, c.prevPath())
			user, err = recovered, nil
			_ = writeDurably(c.Path, prev)
		}
	}
	if err != nil {
		return fmt.Errorf("%s: %w", c.Path, err)
	}
	c.user = user
	core := defaultCore()
	// Re-marshal the top level (without modules) into the typed struct.
	top := map[string]any{}
	for k, v := range user {
		if k != "modules" {
			top[k] = v
		}
	}
	b, _ := json.Marshal(top)
	if err := json.Unmarshal(b, &core); err != nil {
		return fmt.Errorf("%s: %w", c.Path, err)
	}
	c.core = core
	return nil
}

func (c *Config) Core() CoreSettings {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.core
}

// DeclareModule registers a module's defaults so Module() can merge them.
func (c *Config) DeclareModule(name string, defaults map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	d := map[string]any{"enabled": true}
	for k, v := range defaults {
		d[k] = v
	}
	c.defaults[name] = d
}

// Module returns the merged settings for one module.
func (c *Config) Module(name string) map[string]any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := map[string]any{}
	for k, v := range c.defaults[name] {
		out[k] = v
	}
	if mods, ok := c.user["modules"].(map[string]any); ok {
		if m, ok := mods[name].(map[string]any); ok {
			for k, v := range m {
				out[k] = v
			}
		}
	}
	if _, ok := out["enabled"]; !ok {
		out["enabled"] = true
	}
	return out
}

// Settings decodes one module's merged settings into a typed struct.
func (c *Config) Settings(name string, into any) error {
	b, _ := json.Marshal(c.Module(name))
	return json.Unmarshal(b, into)
}

// SetModule replaces the operator's overrides for a module and writes the file.
func (c *Config) SetModule(name string, values map[string]any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	mods, _ := c.user["modules"].(map[string]any)
	if mods == nil {
		mods = map[string]any{}
	}
	cur, _ := mods[name].(map[string]any)
	if cur == nil {
		cur = map[string]any{}
	}
	for k, v := range values {
		cur[k] = v
	}
	mods[name] = cur
	c.user["modules"] = mods
	return c.saveLocked()
}

// SetCore writes one top-level key (used by install/setup, never by the API).
func (c *Config) SetCore(key string, value any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.user[key] = value
	if err := c.saveLocked(); err != nil {
		return err
	}
	c.mu.Unlock()
	err := c.Reload()
	c.mu.Lock()
	return err
}

func (c *Config) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(c.Path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c.user, "", "  ")
	if err != nil {
		return err
	}
	// Keep what is there now beside the file before replacing it.
	if old, err := os.ReadFile(c.Path); err == nil && len(old) > 0 {
		_ = writeDurably(c.prevPath(), old)
	}
	return writeDurably(c.Path, append(b, '\n'))
}

// writeDurably writes through a temporary file, syncs the data and then
// the directory entry, and renames into place, so the file is either the
// old contents or the new ones however the machine stops.
func writeDurably(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// Helpers for module code reading loosely typed settings.

func Str(m map[string]any, key, def string) string {
	if v, ok := m[key].(string); ok && v != "" {
		return v
	}
	return def
}

func Int(m map[string]any, key string, def int) int {
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return int(i)
		}
	}
	return def
}

func Bool(m map[string]any, key string, def bool) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return def
}

// Strs reads a list setting, with commented-out entries removed. Every list
// in the product goes through here, so a bypass list, a rule list and a feed
// list all comment the same way.
func Strs(m map[string]any, key string) []string {
	var raw []string
	switch v := m[key].(type) {
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				raw = append(raw, s)
			}
		}
	case []string:
		raw = v
	}
	return StripComments(raw)
}

// StripComments removes the entries of a list that have been commented out.
//
// Keeping a line while switching it off is how people actually work: an
// entry is taken out to test something and put back an hour later, and
// deleting it loses both the spelling and the reason it was there. Three
// forms are understood, and they are the three people already type:
//
//	# this line is off
//	// so is this one
//	/* everything from here
//	   to here is off */
//
// Only a marker at the start of a line counts. That is deliberate rather
// than lazy: entries in these lists are addresses, domains and feed URLs, and
// a URL contains "//" in the middle of every single one. Treating that as a
// comment would quietly delete half the list.
func StripComments(lines []string) []string {
	var out []string
	inBlock := false
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if inBlock {
			if i := strings.Index(t, "*/"); i >= 0 {
				inBlock = false
				// Anything after the close on the same line still counts.
				if rest := strings.TrimSpace(t[i+2:]); rest != "" && !commented(rest) {
					out = append(out, rest)
				}
			}
			continue
		}
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "/*") {
			if i := strings.Index(t, "*/"); i >= 0 {
				if rest := strings.TrimSpace(t[i+2:]); rest != "" && !commented(rest) {
					out = append(out, rest)
				}
				continue
			}
			inBlock = true
			continue
		}
		if commented(t) {
			continue
		}
		out = append(out, line)
	}
	return out
}

func commented(t string) bool {
	return strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//")
}

// NamedToken is one API token with the name the audit log shows for it.
type NamedToken struct {
	Name  string `json:"name"`
	Token string `json:"token"`
	// Scope is "admin" (the default) or "read": a read token can read
	// everything and change nothing.
	Scope string `json:"scope,omitempty"`
}
