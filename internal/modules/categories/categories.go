// Package categories maps web-content categories to domain lists from open
// feeds, cached on disk so a policy compile never depends on the network.
// It also classifies observed domains back into categories for reports.
package categories

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

// Open feeds, one per category. blocklistproject and hagezi publish plain
// domain lists under permissive licences; both are in hosts or domain
// format, which one parser handles.
var defaultFeeds = map[string]string{
	"ads":          "https://raw.githubusercontent.com/blocklistproject/Lists/master/ads.txt",
	"tracking":     "https://raw.githubusercontent.com/blocklistproject/Lists/master/tracking.txt",
	"malware":      "https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt",
	"phishing":     "https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt",
	"ransomware":   "https://raw.githubusercontent.com/blocklistproject/Lists/master/ransomware.txt",
	"scam":         "https://raw.githubusercontent.com/blocklistproject/Lists/master/scam.txt",
	"fraud":        "https://raw.githubusercontent.com/blocklistproject/Lists/master/fraud.txt",
	"abuse":        "https://raw.githubusercontent.com/blocklistproject/Lists/master/abuse.txt",
	"gambling":     "https://raw.githubusercontent.com/blocklistproject/Lists/master/gambling.txt",
	"adult":        "https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt",
	"drugs":        "https://raw.githubusercontent.com/blocklistproject/Lists/master/drugs.txt",
	"piracy":       "https://raw.githubusercontent.com/blocklistproject/Lists/master/piracy.txt",
	"torrent":      "https://raw.githubusercontent.com/blocklistproject/Lists/master/torrent.txt",
	"crypto":       "https://raw.githubusercontent.com/blocklistproject/Lists/master/crypto.txt",
	"vaping":       "https://raw.githubusercontent.com/blocklistproject/Lists/master/vaping.txt",
	"redirect":     "https://raw.githubusercontent.com/blocklistproject/Lists/master/redirect.txt",
	"smart-tv":     "https://raw.githubusercontent.com/blocklistproject/Lists/master/smart-tv.txt",
	"facebook":     "https://raw.githubusercontent.com/blocklistproject/Lists/master/facebook.txt",
	"tiktok":       "https://raw.githubusercontent.com/blocklistproject/Lists/master/tiktok.txt",
	"twitter":      "https://raw.githubusercontent.com/blocklistproject/Lists/master/twitter.txt",
	"youtube":      "https://raw.githubusercontent.com/blocklistproject/Lists/master/youtube.txt",
	"whatsapp":     "https://raw.githubusercontent.com/blocklistproject/Lists/master/whatsapp.txt",
	"dyndns":       "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/dyndns-onlydomains.txt",
	"vpn-bypass":   "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
	"threat-intel": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt",
	"nsfw":         "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt",
	"fake-shops":   "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/fake-onlydomains.txt",
	"file-hosters": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/hoster-onlydomains.txt",
	"popup-ads":    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/popupads-onlydomains.txt",
}

// Short descriptions for the UI.
var descriptions = map[string]string{
	"whitelist": "Never blocked by any policy: a name here is let through by every policy, whatever else it denies. Edit it like any custom list.",
	"ads":       "Advertising networks", "tracking": "Telemetry and trackers", "malware": "Malware distribution",
	"phishing": "Credential phishing", "ransomware": "Ransomware C2 and payloads", "scam": "Scam sites",
	"fraud": "Fraud", "abuse": "Abuse and exploitation", "gambling": "Gambling", "adult": "Adult content",
	"drugs": "Drugs", "piracy": "Piracy", "torrent": "Torrent trackers and indexes", "crypto": "Cryptocurrency and mining",
	"vaping": "Vaping and tobacco", "redirect": "URL redirectors", "smart-tv": "Smart TV telemetry",
	"facebook": "Facebook and Instagram", "tiktok": "TikTok", "twitter": "X / Twitter", "youtube": "YouTube",
	"whatsapp": "WhatsApp", "dyndns": "Dynamic DNS providers", "vpn-bypass": "DoH, VPN and proxy bypass services",
	"threat-intel": "Threat intelligence (hagezi TIF medium)", "nsfw": "Adult and NSFW (hagezi)",
	"fake-shops": "Fake shops and counterfeit stores", "file-hosters": "File hosters and sharing sites",
	"popup-ads": "Popup and aggressive advertising",
}

var hostsLine = regexp.MustCompile(`^(?:0\.0\.0\.0|127\.0\.0\.1|::1?|\|\|)?\s*([A-Za-z0-9_.-]+?)(\^|\s|$)`)
var domainRe = regexp.MustCompile(`^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$`)

type Module struct {
	ctx    *core.Context
	dir    string
	mu     sync.RWMutex
	info   map[string]core.CategoryInfo
	index  []indexEntry        // sorted by hash: fnv(domain) -> category bitmask (for Classify)
	bits   []string            // bit -> category name
	custom map[string][]string // operator-defined categories from settings
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name: "categories", Version: "1.0",
		Description: "Web-content categories from open domain feeds, cached for policy and used to classify traffic.",
		Defaults: map[string]any{
			"update_hours": 24,
			"feeds":        map[string]any{},
			"classify":     true,
			"classify_max": 3000000,
			"custom":       map[string]any{},
			"disabled":     []string{},
		},
		Schema: []core.SettingField{
			{Key: "update_hours", Label: "Refresh interval (h)", Type: "int"},
			{Key: "classify", Label: "Classify observed domains", Type: "bool",
				Help: "Keeps the lists in memory to tag flows and DNS with categories. Costs roughly 60 bytes per domain."},
			{Key: "classify_max", Label: "Max domains held in memory", Type: "int"},
			{Key: "disabled", Label: "Disabled categories", Type: "list"},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.dir = filepath.Join(ctx.Platform.ShareDir, "categories")
	if err := os.MkdirAll(m.dir, 0o755); err != nil {
		return err
	}
	m.info = map[string]core.CategoryInfo{}
	m.loadCustom()
	m.scan()
	m.rebuildIndex()
	ctx.Publish("categories", m)
	hours := core.Int(ctx.Settings(), "update_hours", 24)
	ctx.Every("update", time.Duration(hours)*time.Hour, m.updateAll, core.Delayed())
	ctx.Every("bootstrap", 24*time.Hour, m.bootstrap)
	m.seedWhitelist()
	ctx.Route("GET", "/api/categories", m.apiList, core.Doc("List all category feeds with their domain counts and update status"),
		core.Returns("Category list with statistics", map[string]any{
			"categories": []map[string]any{
				{"name": "ads", "domains": 50000, "updated": 1790376243, "source": "https://blocklistproject.github.io/Lists/ads.txt", "error": "", "description": "Advertisement servers", "classified": true},
			},
			"indexed_domains": 250000,
		}))
	ctx.Route("POST", "/api/categories/update", m.apiUpdate, core.Write(), core.Doc("Refresh one or all feed sources now in the background"),
		core.Body(
			core.Fld("category", "string", false, "Specific category to refresh; omit to refresh all", "ads"),
		),
		core.Returns("Background refresh initiated", map[string]any{"ok": true, "note": "refreshing 1 feed(s) in the background"}))
	ctx.Route("GET", "/api/categories/{name}/domains", m.apiDomains,
		core.PathParam("name", "string", "Category name", "ads"),
		core.Query("q", "string", "Only domains containing this text", false, "doubleclick"),
		core.Query("offset", "integer", "Skip this many matching domains (paging)", false, 0),
		core.Query("limit", "integer", "Domains to return (default 200, max 2000)", false, 200),
		core.Doc("Read a category's downloaded (or custom) domain list: the file as cached on the gateway, searchable and paged, so what a category blocks can be seen rather than taken on trust"),
		core.Returns("Domains", map[string]any{"name": "ads", "total": 50000, "matched": 12, "offset": 0, "limit": 200, "source": "https://…/ads.txt", "updated": 1790376243,
			"domains": []string{"ads.example.net", "track.example.org"}}))
	ctx.Route("GET", "/api/categories/{name}/download", m.apiDownload,
		core.PathParam("name", "string", "Category name", "ads"),
		core.Doc("The category's cached domain list as plain text, one domain per line, as downloaded from its source (or as entered, for a custom category)"),
		core.Returns("Plain text", map[string]any{"content_type": "text/plain", "body": "ads.example.net\ntrack.example.org\n"}))
	ctx.Route("GET", "/api/categories/lookup", m.apiLookup, core.Doc("Look up which categories a domain belongs to"),
		core.Query("domain", "string", "Domain name to classify", true, "example.com"),
		core.Returns("Domain classification results", map[string]any{
			"domain": "example.com", "categories": []string{"ads", "tracking"},
		}))
	ctx.Route("POST", "/api/categories/custom", m.apiCustom, core.Write(), core.Doc("Create or replace a custom category with a domain list"),
		core.Body(
			core.Fld("name", "string", true, "Category name (lowercase, letters/digits/dashes)", "my-block-list"),
			core.Fld("domains", "array", false, "List of domains to block", []string{"bad.example.com"}),
			core.Fld("delete", "boolean", false, "Remove the category instead of creating it", false),
		),
		core.Returns("Category saved successfully", map[string]any{"ok": true}))
	ctx.Route("DELETE", "/api/categories/{name}", m.apiDeleteCategoryByName, core.Write(), core.Doc("Delete a custom category by name"),
		core.PathParam("name", "string", "Custom category name to delete", "my-block-list"),
		core.Returns("Category deleted successfully", map[string]any{"ok": true}))
	ctx.Panel(core.Panel{ID: "categories", Title: "Categories", Group: "Protect", Order: 120, Icon: "categories"})
	return nil
}

func (m *Module) OnConfigChange(s map[string]any) error {
	m.loadCustom()
	m.rebuildIndex()
	return nil
}

func (m *Module) feeds() map[string]string {
	out := map[string]string{}
	for k, v := range defaultFeeds {
		out[k] = v
	}
	if extra, ok := m.ctx.Settings()["feeds"].(map[string]any); ok {
		for k, v := range extra {
			if s, ok := v.(string); ok {
				if s == "" {
					delete(out, k)
				} else {
					out[k] = s
				}
			}
		}
	}
	for _, d := range core.Strs(m.ctx.Settings(), "disabled") {
		delete(out, d)
	}
	return out
}

// builtinLists are categories FlowSight ships itself, because they are
// short, stable and awkward to source: no download, always present.
var builtinLists = map[string][]string{
	// Encrypted DNS endpoints. Denying this category sends a client back to
	// the network's own resolver, which is the only way to see its lookups:
	// a DoH query travels inside the HTTPS body, so even decrypting the
	// session does not show the name unless the client uses the GET form.
	// use-application-dns.net is Firefox's canary: answering it with
	// NXDOMAIN makes Firefox turn its own DNS-over-HTTPS off.
	"encrypted-dns": {
		"use-application-dns.net",
		"cloudflare-dns.com", "one.one.one.one", "mozilla.cloudflare-dns.com", "security.cloudflare-dns.com", "family.cloudflare-dns.com",
		"dns.google", "dns64.dns.google", "8888.google",
		"dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
		"doh.opendns.com", "doh.familyshield.opendns.com", "doh.cleanbrowsing.org",
		"dns.nextdns.io", "dns.adguard.com", "dns.adguard-dns.com", "unfiltered.adguard-dns.com", "family.adguard-dns.com",
		"doh.mullvad.net", "adblock.doh.mullvad.net", "dns.controld.com", "freedns.controld.com",
		"dns.alidns.com", "doh.pub", "doh.360.cn", "dns.twnic.tw", "doh.dns.sb", "doh.libredns.gr",
		"doh.applied-privacy.net", "dns.digitale-gesellschaft.ch", "dnsforge.de", "doh.ffmuc.net",
		"chrome.cloudflare-dns.com", "dns.brave.com", "basic.rethinkdns.com", "sky.rethinkdns.com",
	},
}

func (m *Module) loadCustom() {
	custom := map[string][]string{}
	if c, ok := m.ctx.Settings()["custom"].(map[string]any); ok {
		for name, v := range c {
			var list []string
			switch x := v.(type) {
			case []any:
				for _, d := range x {
					if s, ok := d.(string); ok {
						if n, err := core.NormalizeDomain(s); err == nil {
							list = append(list, n)
						}
					}
				}
			case string:
				for _, s := range strings.Fields(strings.ReplaceAll(x, ",", " ")) {
					if n, err := core.NormalizeDomain(s); err == nil {
						list = append(list, n)
					}
				}
			}
			sort.Strings(list)
			custom[name] = list
		}
	}
	for name, list := range builtinLists {
		if _, taken := custom[name]; taken {
			continue // an operator list of the same name wins
		}
		cp := append([]string(nil), list...)
		sort.Strings(cp)
		custom[name] = cp
	}
	m.mu.Lock()
	m.custom = custom
	m.mu.Unlock()
}

func (m *Module) path(name string) string { return filepath.Join(m.dir, name+".list") }

// scan reads sizes and timestamps of cached lists without loading them.
func (m *Module) scan() {
	info := map[string]core.CategoryInfo{}
	for name, url := range m.feeds() {
		ci := core.CategoryInfo{Name: name, Source: url}
		if st, err := os.Stat(m.path(name)); err == nil {
			ci.Updated = st.ModTime().Unix()
			ci.Domains = countLines(m.path(name))
		}
		info[name] = ci
	}
	m.mu.Lock()
	for name, list := range m.custom {
		src := "custom"
		if _, builtin := builtinLists[name]; builtin {
			src = "built-in"
		}
		info[name] = core.CategoryInfo{Name: name, Domains: len(list), Source: src, Updated: time.Now().Unix()}
	}
	// keep previous errors
	for k, v := range m.info {
		if v.Error != "" {
			if ci, ok := info[k]; ok {
				ci.Error = v.Error
				info[k] = ci
			}
		}
	}
	m.info = info
	m.mu.Unlock()
}

func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if len(sc.Bytes()) > 0 {
			n++
		}
	}
	return n
}

// bootstrap fetches every feed that has never been cached (first run).
func (m *Module) bootstrap() error {
	var missing []string
	m.mu.RLock()
	for name, ci := range m.info {
		if ci.Source != "custom" && ci.Domains == 0 {
			missing = append(missing, name)
		}
	}
	m.mu.RUnlock()
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return m.update(missing)
}

func (m *Module) updateAll() error {
	names := make([]string, 0)
	for n := range m.feeds() {
		names = append(names, n)
	}
	sort.Strings(names)
	return m.update(names)
}

// update fetches feeds one at a time. A feed that parses to nothing is
// treated as a failure and the old cache is kept: that is nearly always an
// error page, and replacing a good list with it would silently disable
// blocking.
func (m *Module) update(names []string) error {
	feeds := m.feeds()
	client := &http.Client{Timeout: 3 * time.Minute}
	var failures []string
	for _, name := range names {
		url, ok := feeds[name]
		if !ok {
			continue
		}
		domains, err := fetch(client, url)
		m.mu.Lock()
		ci := m.info[name]
		ci.Name, ci.Source = name, url
		if err != nil {
			ci.Error = err.Error()
			m.info[name] = ci
			m.mu.Unlock()
			failures = append(failures, name+": "+err.Error())
			continue
		}
		m.mu.Unlock()
		tmp := m.path(name) + ".tmp"
		if err := os.WriteFile(tmp, []byte(strings.Join(domains, "\n")+"\n"), 0o644); err != nil {
			return err
		}
		if err := os.Rename(tmp, m.path(name)); err != nil {
			return err
		}
		m.mu.Lock()
		ci.Error = ""
		ci.Domains = len(domains)
		ci.Updated = time.Now().Unix()
		m.info[name] = ci
		m.mu.Unlock()
	}
	m.rebuildIndex()
	if len(failures) > 0 {
		return fmt.Errorf("%d feed(s) failed: %s", len(failures), strings.Join(failures, "; "))
	}
	return nil
}

func fetch(client *http.Client, url string) ([]string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	set := map[string]bool{}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 256<<20))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}
		mm := hostsLine.FindStringSubmatch(line)
		if mm == nil {
			continue
		}
		d := strings.ToLower(strings.TrimSuffix(mm[1], "."))
		switch d {
		case "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback", "0.0.0.0":
			continue
		}
		if domainRe.MatchString(d) {
			set[d] = true
		}
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("feed parsed to zero domains; keeping the previous list")
	}
	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	sort.Strings(out)
	return out, nil
}

// rebuildIndex loads lists into memory for classification, up to the
// configured budget, smallest categories first so the specific ones win.
func (m *Module) rebuildIndex() {
	if !core.Bool(m.ctx.Settings(), "classify", true) {
		m.mu.Lock()
		m.index, m.bits = nil, nil
		m.mu.Unlock()
		return
	}
	budget := core.Int(m.ctx.Settings(), "classify_max", 2000000)
	m.mu.RLock()
	type sz struct {
		name string
		n    int
	}
	var order []sz
	for name, ci := range m.info {
		order = append(order, sz{name, ci.Domains})
	}
	custom := m.custom
	m.mu.RUnlock()
	sort.Slice(order, func(i, j int) bool { return order[i].n < order[j].n })
	var entries []indexEntry
	var bits []string
	total := 0
	for _, o := range order {
		if len(bits) >= 63 || total+o.n > budget {
			continue
		}
		bit := uint64(1) << uint(len(bits))
		bits = append(bits, o.name)
		if list, ok := custom[o.name]; ok {
			for _, d := range list {
				entries = append(entries, indexEntry{fnv(d), bit})
			}
			total += len(list)
			continue
		}
		f, err := os.Open(m.path(o.name))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			if d := sc.Bytes(); len(d) > 0 {
				entries = append(entries, indexEntry{fnvBytes(d), bit})
			}
		}
		f.Close()
		total += o.n
	}
	// Sort and merge duplicates (a domain in several categories) so lookups
	// are a binary search over 16 bytes per entry: two million names in
	// about 32 MB, a third of what a map needs.
	sort.Slice(entries, func(i, j int) bool { return entries[i].h < entries[j].h })
	merged := entries[:0]
	for _, e := range entries {
		if n := len(merged); n > 0 && merged[n-1].h == e.h {
			merged[n-1].mask |= e.mask
			continue
		}
		merged = append(merged, e)
	}
	m.mu.Lock()
	m.index, m.bits = merged, bits
	m.mu.Unlock()
}

type indexEntry struct {
	h    uint64
	mask uint64
}

func (m *Module) lookup(h uint64) uint64 {
	i := sort.Search(len(m.index), func(i int) bool { return m.index[i].h >= h })
	if i < len(m.index) && m.index[i].h == h {
		return m.index[i].mask
	}
	return 0
}

// fnv is a 64-bit FNV-1a hash; the index keys on it rather than on the
// string to keep two million names in tens of megabytes instead of hundreds.
func fnv(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

func fnvBytes(b []byte) uint64 {
	h := uint64(14695981039346656037)
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

// ---------------------------------------------------------------- service

func (m *Module) Domains(category string) ([]string, error) {
	m.mu.RLock()
	if list, ok := m.custom[category]; ok {
		m.mu.RUnlock()
		return append([]string(nil), list...), nil
	}
	m.mu.RUnlock()
	if _, ok := m.feeds()[category]; !ok {
		return nil, fmt.Errorf("unknown category %q", category)
	}
	f, err := os.Open(m.path(category))
	if err != nil {
		return nil, fmt.Errorf("category %q has no cached feed yet; refresh categories first", category)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if d := sc.Text(); d != "" {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("category %q cache is empty", category)
	}
	return out, nil
}

func (m *Module) List() []core.CategoryInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]core.CategoryInfo, 0, len(m.info))
	for _, ci := range m.info {
		out = append(out, ci)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Classify walks the domain and its parents against the in-memory index.
func (m *Module) Classify(domain string) []string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	m.mu.RLock()
	defer m.mu.RUnlock()
	var mask uint64
	d := domain
	for d != "" {
		mask |= m.lookup(fnv(d))
		i := strings.Index(d, ".")
		if i < 0 {
			break
		}
		d = d[i+1:]
	}
	if mask == 0 {
		return nil
	}
	var out []string
	for i, name := range m.bits {
		if mask&(1<<uint(i)) != 0 {
			out = append(out, name)
		}
	}
	return out
}

// ---------------------------------------------------------------- API

func (m *Module) apiList(r *core.Req) (any, error) {
	list := m.List()
	var out []map[string]any
	m.mu.RLock()
	indexed := map[string]bool{}
	for _, b := range m.bits {
		indexed[b] = true
	}
	n := len(m.index)
	m.mu.RUnlock()
	for _, ci := range list {
		out = append(out, map[string]any{"name": ci.Name, "domains": ci.Domains, "updated": ci.Updated,
			"source": ci.Source, "error": ci.Error, "description": descriptions[ci.Name],
			"classified": indexed[ci.Name]})
	}
	return map[string]any{"categories": out, "indexed_domains": n}, nil
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)

func (m *Module) apiUpdate(r *core.Req) (any, error) {
	name, _ := r.Body()["category"].(string)
	var names []string
	if name != "" {
		if !nameRe.MatchString(name) {
			return nil, core.BadRequest("invalid category name")
		}
		names = []string{name}
	} else {
		for n := range m.feeds() {
			names = append(names, n)
		}
		sort.Strings(names)
	}
	go func() {
		if err := m.update(names); err != nil {
			m.ctx.Log.Warn("category update", "error", err.Error())
		}
	}()
	return map[string]any{"ok": true, "note": fmt.Sprintf("refreshing %d feed(s) in the background", len(names))}, nil
}

func (m *Module) apiLookup(r *core.Req) (any, error) {
	d, err := core.NormalizeDomain(r.Q("domain", ""))
	if err != nil {
		return nil, core.BadRequest("%v", err)
	}
	return map[string]any{"domain": d, "categories": m.Classify(d)}, nil
}

func (m *Module) apiCustom(r *core.Req) (any, error) {
	var in struct {
		Name    string   `json:"name"`
		Domains []string `json:"domains"`
		Delete  bool     `json:"delete"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	if !nameRe.MatchString(in.Name) {
		return nil, core.BadRequest("name must be lowercase letters, digits and dashes")
	}
	if _, clash := defaultFeeds[in.Name]; clash {
		return nil, core.BadRequest("%q is a built-in category", in.Name)
	}
	cur, _ := m.ctx.Settings()["custom"].(map[string]any)
	next := map[string]any{}
	for k, v := range cur {
		next[k] = v
	}
	if in.Delete {
		delete(next, in.Name)
	} else {
		var list []string
		for _, d := range in.Domains {
			n, err := core.NormalizeDomain(d)
			if err != nil {
				return nil, core.BadRequest("%v", err)
			}
			list = append(list, n)
		}
		if len(list) == 0 {
			return nil, core.BadRequest("a custom category needs at least one domain")
		}
		next[in.Name] = list
	}
	if err := m.ctx.Config.SetModule(m.ctx.Name, map[string]any{"custom": next}); err != nil {
		return nil, err
	}
	m.loadCustom()
	m.scan()
	m.rebuildIndex()
	return map[string]any{"ok": true}, nil
}

// apiDomains shows the list behind a category. A category is a claim
// about fifty thousand names; the operator should be able to read the
// claim, search it, and see the source and its age.
func (m *Module) apiDomains(r *core.Req) (any, error) {
	name := strings.ToLower(strings.TrimSpace(r.Params["name"]))
	q := strings.ToLower(strings.TrimSpace(r.Q("q", "")))
	offset := r.QInt("offset", 0, 0, 10_000_000)
	limit := r.QInt("limit", 200, 1, 2000)
	all, err := m.Domains(name)
	if err != nil {
		return nil, core.NotFound("%v", err)
	}
	var info core.CategoryInfo
	for _, ci := range m.List() {
		if ci.Name == name {
			info = ci
		}
	}
	matched := 0
	out := make([]string, 0, limit)
	for _, d := range all {
		if q != "" && !strings.Contains(d, q) {
			continue
		}
		if matched >= offset && len(out) < limit {
			out = append(out, d)
		}
		matched++
	}
	return map[string]any{"name": name, "total": len(all), "matched": matched, "offset": offset, "limit": limit,
		"source": info.Source, "updated": info.Updated, "domains": out}, nil
}

// apiDownload serves the list as the text file it is.
func (m *Module) apiDownload(r *core.Req) (any, error) {
	name := strings.ToLower(strings.TrimSpace(r.Params["name"]))
	all, err := m.Domains(name)
	if err != nil {
		return nil, core.NotFound("%v", err)
	}
	return core.Raw{ContentType: "text/plain; charset=utf-8", Body: []byte(strings.Join(all, "\n") + "\n"),
		Filename: "flowsight-category-" + name + ".txt"}, nil
}

// seedWhitelist makes sure the reserved "whitelist" category exists, empty
// until the operator fills it. Names in it are never blocked by any policy;
// the policy compiler folds them into every policy's allow-list.
func (m *Module) seedWhitelist() {
	cur, _ := m.ctx.Settings()["custom"].(map[string]any)
	if _, ok := cur["whitelist"]; ok {
		return
	}
	next := map[string]any{}
	for k, v := range cur {
		next[k] = v
	}
	next["whitelist"] = []string{}
	if err := m.ctx.Config.SetModule(m.ctx.Name, map[string]any{"custom": next}); err != nil {
		return
	}
	m.loadCustom()
}
