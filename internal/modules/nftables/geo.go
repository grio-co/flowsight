package nftables

// Country blocking, as the pf provider does it: a set per denied country
// (fs_geo_<cc>_v4/_v6, the pf table names with the family), or one per
// policy holding every country but the allowed ones (fs_geox_<policy>).
// The policy chain declares the sets and references them; each set's
// contents are listed in the transaction as a comment,
//
//	# geo-set fs_geo_cn CN
//	# geo-set fs_geox_kids !US,CA
//
// so Apply, the hourly refresh and upkeep after a flush can fill them from
// the artifact alone. Filling runs in the background: a set of every
// country but one holds hundreds of thousands of prefixes, and the rules
// are in force (matching nothing yet) meanwhile. The home country is never
// in an "every country except" set, and anycast ranges are in none: they
// are served from nearby whatever country registered them.

import (
	"fmt"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

type geoSet struct {
	Name      string
	Countries []string
	Invert    bool
}

func (g geoSet) comment() string {
	list := strings.Join(g.Countries, ",")
	if g.Invert {
		list = "!" + list
	}
	return "# geo-set " + g.Name + " " + list
}

// geoSets reads the geo-set comments back out of a policy transaction.
func geoSets(tx string) []geoSet {
	var out []geoSet
	for _, l := range strings.Split(tx, "\n") {
		f := strings.Fields(l)
		if len(f) != 4 || f[0] != "#" || f[1] != "geo-set" {
			continue
		}
		g := geoSet{Name: f[2]}
		list := f[3]
		if strings.HasPrefix(list, "!") {
			g.Invert, list = true, list[1:]
		}
		g.Countries = strings.Split(list, ",")
		out = append(out, g)
	}
	return out
}

// countryCode keeps what can be a set name: two letters, upper case.
func countryCode(cc string) (string, bool) {
	cc = strings.ToUpper(strings.TrimSpace(cc))
	if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
		return "", false
	}
	return cc, true
}

// geoInfo is what the module knows about a filled set.
type geoInfo struct {
	Prefixes int
	Epoch    int64
	Updated  time.Time
	Err      string
}

// fillGeoSets fills each set in one pass over the country database. With
// force false a set already filled from the current database build is left
// alone.
func (m *Module) fillGeoSets(sets []geoSet, force bool) error {
	geo, _ := m.ctx.Service("geo").(core.GeoService)
	if geo == nil {
		return fmt.Errorf("the country database is not available (Settings › enrich › Country lookup)")
	}
	epoch := geo.DatabaseEpoch()
	if epoch == 0 {
		return fmt.Errorf("the country database is not loaded yet")
	}
	home := ""
	if h, ok := m.ctx.Service("home").(core.HomeService); ok {
		home = strings.ToUpper(h.HomeCountry())
	}
	var skip func(string) bool
	if anyc, ok := m.ctx.Service("anycast").(core.AnycastLookup); ok {
		skip = func(prefix string) bool {
			ip, _, _ := strings.Cut(prefix, "/")
			a, _ := anyc.Anycast(ip)
			return a
		}
	}
	var firstErr error
	for _, g := range sets {
		m.mu.Lock()
		cur := m.geo[g.Name]
		m.mu.Unlock()
		if !force && cur.Epoch == epoch && cur.Err == "" {
			continue
		}
		ccs := g.Countries
		if g.Invert && home != "" && !contains(ccs, home) {
			ccs = append(append([]string(nil), ccs...), home)
		}
		prefixes, _, err := geo.NetworksFor(ccs, g.Invert, skip)
		if err == nil {
			err = m.load(setTx(g.Name, prefixes, true))
		}
		info := geoInfo{Prefixes: len(prefixes), Epoch: epoch, Updated: time.Now()}
		if err != nil {
			info = geoInfo{Err: err.Error()}
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", g.Name, err)
			}
		}
		m.mu.Lock()
		m.geo[g.Name] = info
		m.mu.Unlock()
	}
	return firstErr
}

// fillGeoAsync fills in the background, one fill at a time; a request made
// while one runs is kept and run after it, with the latest sets.
func (m *Module) fillGeoAsync(sets []geoSet, force bool) {
	if len(sets) == 0 {
		return
	}
	m.mu.Lock()
	if m.geoFilling {
		m.geoNext, m.geoNextForce = sets, m.geoNextForce || force
		m.mu.Unlock()
		return
	}
	m.geoFilling = true
	m.mu.Unlock()
	go func() {
		for {
			if err := m.fillGeoSets(sets, force); err != nil {
				m.ctx.Event("firewall", "country sets could not all be filled: "+err.Error(), nil)
			}
			m.mu.Lock()
			if m.geoNext == nil {
				m.geoFilling = false
				m.mu.Unlock()
				return
			}
			sets, force = m.geoNext, m.geoNextForce
			m.geoNext, m.geoNextForce = nil, false
			m.mu.Unlock()
		}
	}()
}

// refreshGeo follows the database's updates: sets filled from an older
// build are filled again.
func (m *Module) refreshGeo() error {
	m.mu.Lock()
	tx := m.chains[chainPolicy]
	m.mu.Unlock()
	if sets := geoSets(tx); len(sets) > 0 {
		return m.fillGeoSets(sets, false)
	}
	return nil
}
