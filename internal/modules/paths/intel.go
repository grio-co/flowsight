package paths

// Who runs a hop, and where it actually is.
//
// A traceroute gives an address and a time. Everything else a reader wants to
// know -- whose router this is, which network announces it, what building it
// might be in -- has to come from somewhere else, and the sources disagree in
// ways that matter:
//
//   the router's own name   a site code the operator wrote down. Best evidence
//                           of the city, when it is there at all.
//   the routing table       which network announces the address today. This is
//                           who runs it, and it is current.
//   the registry            who the block is allocated to, and the postal
//                           address on that allocation. That address is a head
//                           office, not a data centre, and saying otherwise
//                           would put every Lumen router in Monroe, Louisiana.
//   PeeringDB               buildings an operator has said it occupies, with
//                           street addresses. Real addresses, but presence in
//                           a city is not proof that this router is in it, so
//                           these are only offered once the name has already
//                           given us the city, and are always a short list.
//
// Each is labelled where it came from. None of them is allowed to speak for
// another.

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// Detail is everything known about a hop beyond the measurement itself.
type Detail struct {
	// Name is the reverse-DNS name, resolved here rather than inherited.
	Name string `json:"name,omitempty"`

	// From the router's name.
	PoPCode string  `json:"pop_code,omitempty"`
	PoPCity string  `json:"pop_city,omitempty"`
	PoPLat  float64 `json:"pop_lat,omitempty"`
	PoPLon  float64 `json:"pop_lon,omitempty"`
	// How much to believe it, nought to one, and why. A published code
	// checked against the clock scores near one; a contraction the clock
	// merely fails to contradict scores far less, and says so.
	PoPScore float64 `json:"pop_score,omitempty"`
	PoPHow   string  `json:"pop_how,omitempty"`
	PoPWhy   string  `json:"pop_why,omitempty"`

	// From the abuse databases, when a key is configured.
	Abuse *Reputation `json:"abuse,omitempty"`

	// From Shodan, when looked up.
	Shodan *ShodanRecord `json:"shodan,omitempty"`

	// From the FCC broadband map, when the operator is a US broadband provider.
	FCC *fccProvider `json:"fcc,omitempty"`

	// From the routing table.
	ASN    string `json:"asn,omitempty"`
	ASName string `json:"as_name,omitempty"`
	Prefix string `json:"prefix,omitempty"`

	// From the registry.
	RIR       string `json:"rir,omitempty"`
	Allocated string `json:"allocated,omitempty"`
	NetName   string `json:"net_name,omitempty"`
	Org       string `json:"org,omitempty"`
	// OrgAddr is the address on the allocation. It is a head office. The
	// field name says address and the label in the interface has to say so
	// too, or a reader will take it for the router's address.
	OrgAddr string `json:"org_addr,omitempty"`

	// From PeeringDB.
	Facilities []Facility `json:"facilities,omitempty"`
	// Scoped says the list was narrowed to the city the router's name gave.
	// False means these are simply everywhere the operator is, which is not
	// evidence about this hop, and the interface must not present it as such.
	Scoped bool `json:"facilities_scoped"`
}

// Facility is a building an operator has published a presence in.
type Facility struct {
	Name    string  `json:"name"`
	Address string  `json:"address,omitempty"`
	City    string  `json:"city,omitempty"`
	Lat     float64 `json:"lat,omitempty"`
	Lon     float64 `json:"lon,omitempty"`
}

var labelSplit = regexp.MustCompile(`[-_]`)

// decodePoP reads a site out of a router's hostname.
//
// The site code sits nearer the domain than the interface does -- the name is
// built interface-first, ae10.edge1.dal2.sp.lumen.tech -- so the labels are
// read back to front and the first place name wins. The registered domain is
// dropped first, because plenty of operators have a country or a city in it.
func decodePoP(host string) (code string, p pop, ok bool) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return "", pop{}, false
	}
	labels := strings.Split(host, ".")
	if len(labels) > 2 {
		labels = labels[:len(labels)-2]
	}
	var parts []string
	for _, l := range labels {
		for _, x := range labelSplit.Split(l, -1) {
			if x != "" {
				parts = append(parts, x)
			}
		}
	}
	for i := len(parts) - 1; i >= 0; i-- {
		x := parts[i]
		if skip[x] {
			continue
		}
		// The digits are a unit number, not part of the place: dfw01, Dallas3
		// and londen12 all name somewhere, and none of them name it with the
		// number attached.
		base := strings.TrimRight(x, "0123456789")
		if len(base) < 2 {
			continue
		}
		if q, hit := pops[base]; hit {
			return base, q, true
		}
		// Carriers that spell the place out: Level 3 writes ear1.Dallas3,
		// bar1.Portland1, ear2.SanJose1. The names come from the table itself,
		// so a code and its spelled-out form can never disagree.
		if q, hit := cityNames[base]; hit {
			return base, q, true
		}
		// City plus a state or country, run together. NTT writes dllstx14 for
		// Dallas, Texas and londen12 for London; AT&T writes tpkaks for
		// Topeka, Kansas. The split is four and two or three and three, so
		// both are tried, longest first.
		if len(base) >= 6 {
			for _, n := range []int{4, 3} {
				if q, hit := pops[base[:n]]; hit {
					return base[:n], q, true
				}
			}
		}
	}
	return "", pop{}, false
}

// cityNames maps a spelled-out city to the same place its code names, built
// from the code table so the two cannot drift apart. "Dallas, TX, US" becomes
// "dallas"; "Los Angeles, CA, US" becomes "losangeles".
var cityNames = func() map[string]pop {
	out := map[string]pop{}
	for _, p := range pops {
		city := p.City
		if i := strings.IndexByte(city, ','); i >= 0 {
			city = city[:i]
		}
		key := strings.ToLower(strings.NewReplacer(" ", "", "-", "", ".", "", "'", "").Replace(city))
		if len(key) >= 4 {
			out[key] = p
		}
	}
	return out
}()

// reverseName asks what a router calls itself. Most do not answer: a hop with
// no name is the common case, not a fault, and the caller must carry on.
func reverseName(ip string) string {
	if !validIP(ip) {
		return ""
	}
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// ---- routing table, via DNS ----

// originASN and asName live in core (core.OriginASN, core.ASName) so the
// DLP module can name networks too; these wrappers keep the call sites.
func originASN(ip string) (asn, prefix, rir, allocated string) { return core.OriginASN(ip) }

func asName(asn string) string { return core.ASName(asn) }

func reverseV4(ip string) (string, bool) {
	a := net.ParseIP(ip)
	if a == nil || a.To4() == nil {
		return "", false
	}
	p := strings.Split(a.To4().String(), ".")
	return p[3] + "." + p[2] + "." + p[1] + "." + p[0], true
}

func splitPipe(s string) []string {
	f := strings.Split(strings.Trim(s, `"`), "|")
	for i := range f {
		f[i] = strings.TrimSpace(f[i])
	}
	return f
}

// ---- registry, via RDAP ----

type rdapReply struct {
	Name     string `json:"name"`
	Entities []struct {
		Roles      []string        `json:"roles"`
		VCardArray json.RawMessage `json:"vcardArray"`
	} `json:"entities"`
	// Where an operator says its own geofeed is: a remark or a link.
	Remarks []struct {
		Title       string   `json:"title"`
		Description []string `json:"description"`
	} `json:"remarks"`
	Links []struct {
		Rel  string `json:"rel"`
		Href string `json:"href"`
	} `json:"links"`
}

// rdapNet reads the allocation and the registrant off the registry.
//
// rdap.org is a redirector to whichever registry holds the block, so one URL
// covers all five. The address arrives in a vCard, and not where a reader of
// the spec would expect: the structured value is empty and the whole thing is
// in the "label" parameter, which is why this decodes the raw array instead of
// unmarshalling into a struct.
func rdapNet(c *http.Client, ip string) (netName, org, addr string) {
	netName, org, addr, _ = rdapNetFeed(c, ip)
	return
}

// rdapNetFeed is rdapNet with the geofeed URL the object named, if any.
func rdapNetFeed(c *http.Client, ip string) (netName, org, addr, geofeed string) {
	if !validIP(ip) {
		return "", "", "", ""
	}
	resp, err := c.Get("https://rdap.org/ip/" + url.PathEscape(ip))
	if err != nil {
		return "", "", "", ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", "", ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", "", ""
	}
	var r rdapReply
	if json.Unmarshal(body, &r) != nil {
		return "", "", "", ""
	}
	netName = r.Name
	for _, e := range r.Entities {
		if !hasRole(e.Roles, "registrant") {
			continue
		}
		o, a := vcard(e.VCardArray)
		if o != "" {
			org = o
		}
		if a != "" {
			addr = a
		}
	}
	geofeed = geofeedFromRDAP(&r)
	return netName, org, addr, geofeed
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

// vcard pulls the display name and the postal label out of a jCard.
func vcard(raw json.RawMessage) (name, addr string) {
	if len(raw) == 0 {
		return "", ""
	}
	var outer []json.RawMessage
	if json.Unmarshal(raw, &outer) != nil || len(outer) < 2 {
		return "", ""
	}
	var entries [][]json.RawMessage
	if json.Unmarshal(outer[1], &entries) != nil {
		return "", ""
	}
	for _, e := range entries {
		if len(e) < 4 {
			continue
		}
		var kind string
		if json.Unmarshal(e[0], &kind) != nil {
			continue
		}
		switch kind {
		case "fn":
			var v string
			if json.Unmarshal(e[3], &v) == nil {
				name = v
			}
		case "adr":
			var params struct {
				Label string `json:"label"`
			}
			if json.Unmarshal(e[1], &params) == nil && params.Label != "" {
				addr = strings.Join(nonEmptyLines(params.Label), ", ")
			}
		}
	}
	return name, addr
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// ---- buildings, via PeeringDB ----

type pdbNet struct {
	Data []struct {
		ID       int `json:"id"`
		FacCount int `json:"fac_count"`
	} `json:"data"`
}

type pdbNetFac struct {
	Data []struct {
		Name  string `json:"name"`
		FacID int    `json:"fac_id"`
		City  string `json:"city"`
	} `json:"data"`
}

type pdbFac struct {
	Data []struct {
		Name     string  `json:"name"`
		Address1 string  `json:"address1"`
		City     string  `json:"city"`
		State    string  `json:"state"`
		Zipcode  string  `json:"zipcode"`
		Country  string  `json:"country"`
		Lat      float64 `json:"latitude"`
		Lon      float64 `json:"longitude"`
	} `json:"data"`
}

// facilitiesFor lists buildings an operator has published, narrowed to a city
// when one is known.
//
// The narrowing is the whole point. An operator the size of Cloudflare
// publishes presence in three hundred buildings, and handing a reader all of
// them under the heading of one hop would be worse than saying nothing. When
// the city is known the list is short and genuinely about this router; when it
// is not, the caller is told so through Scoped and has to present it as the
// unrelated list that it is.
func facilitiesFor(c *http.Client, asn, city string) (out []Facility, scoped bool) {
	if asn == "" || strings.Trim(asn, "0123456789") != "" {
		return nil, false // an AS number is digits; anything else is not going in a URL
	}
	var n pdbNet
	if !getJSON(c, "https://www.peeringdb.com/api/net?asn="+asn, &n) || len(n.Data) == 0 {
		return nil, false
	}
	if n.Data[0].FacCount == 0 {
		return nil, false // plenty of large carriers publish nothing
	}
	var nf pdbNetFac
	if !getJSON(c, fmt.Sprintf("https://www.peeringdb.com/api/netfac?net_id=%d", n.Data[0].ID), &nf) {
		return nil, false
	}
	city = strings.ToLower(strings.TrimSpace(strings.SplitN(city, ",", 2)[0]))
	var want []int
	for _, r := range nf.Data {
		if city != "" && strings.ToLower(r.City) == city {
			want = append(want, r.FacID)
		}
	}
	scoped = len(want) > 0
	if !scoped {
		for i, r := range nf.Data {
			if i >= 3 {
				break
			}
			want = append(want, r.FacID)
		}
	}
	if len(want) > 4 {
		want = want[:4]
	}
	for _, id := range want {
		var f pdbFac
		if !getJSON(c, fmt.Sprintf("https://www.peeringdb.com/api/fac/%d", id), &f) || len(f.Data) == 0 {
			continue
		}
		d := f.Data[0]
		parts := []string{}
		for _, x := range []string{d.Address1, d.City, d.State, d.Zipcode, d.Country} {
			if x != "" {
				parts = append(parts, x)
			}
		}
		out = append(out, Facility{Name: d.Name, Address: strings.Join(parts, ", "),
			City: d.City, Lat: d.Lat, Lon: d.Lon})
	}
	return out, scoped
}

func getJSON(c *http.Client, url string, into any) bool {
	resp, err := c.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return false
	}
	return json.Unmarshal(body, into) == nil
}

// ---- assembling and caching ----

func (m *Module) registryOK() bool {
	return core.Bool(m.ctx.Settings(), "registry", true)
}

func (m *Module) facilitiesOK() bool {
	return core.Bool(m.ctx.Settings(), "facilities", true)
}

const detailKV = "paths.detail."

// detailTTL is long because none of this changes quickly. An allocation
// outlives most networks; a building does not move. Re-asking hourly would
// spend someone else's rate limit to learn nothing.
const detailTTL = 30 * 24 * time.Hour

// detailSchema is bumped whenever what gets gathered changes -- and that
// includes how it is worked out, not just which fields exist. Teaching
// decodePoP a new naming convention changes the answer for addresses already
// cached, and without a bump the month-old answer stands and the improvement
// is invisible. It was, once: the decoder learned four carriers' spellings and
// the map went on showing the same forty-eight sites it had before.
const detailSchema = 3

type cachedDetail struct {
	At time.Time `json:"at"`
	V  int       `json:"v"`
	D  Detail    `json:"d"`
}

// cached returns what is already known about an address, if anything.
func (m *Module) cached(ip string) (Detail, bool) {
	var c cachedDetail
	if m.ctx.Store.KVGet(detailKV+ip, &c) && c.V == detailSchema && time.Since(c.At) < detailTTL {
		return c.D, true
	}
	return Detail{}, false
}

// detailFor gathers everything known about one address.
//
// This is the slow path and it is not for a waiting reader: a registry and
// PeeringDB are two round trips across the internet each, and a graph with
// four hundred hops in it once took long enough that the page gave up before
// the answer arrived. It runs on a timer instead, filling the cache a few
// addresses at a time, and the page shows what has been gathered so far.
func (m *Module) detailFor(ip, host string) Detail {
	if d, ok := m.cached(ip); ok {
		return d
	}
	var d Detail
	// Resolve the name here rather than take whatever the enrichment module
	// happened to have. Everything below hangs off this one string, and
	// depending on another module's optional setting for it means the whole
	// inference goes quiet without anything looking broken -- which is
	// precisely what it did: seven hundred hops, not one name, no sites read.
	if host == "" {
		host = reverseName(ip)
	}
	d = fromName(host)
	d.ASN, d.Prefix, d.RIR, d.Allocated = originASN(ip)
	d.ASName = asName(d.ASN)

	if m.registryOK() {
		client := &http.Client{Timeout: 15 * time.Second}
		var feed string
		d.NetName, d.Org, d.OrgAddr, feed = rdapNetFeed(client, ip)
		m.noteGeofeed(feed, ip)
		if m.facilitiesOK() {
			d.Facilities, d.Scoped = facilitiesFor(client, d.ASN, d.PoPCity)
		}
	}
	_ = m.ctx.Store.KVSet(detailKV+ip, cachedDetail{At: time.Now(), V: detailSchema, D: d})
	return d
}

// describeFast is what a waiting reader gets.
//
// The work splits in two, and keeping it split is the point. Reading a site
// out of a name already in hand is arithmetic: no network, no waiting, and
// nothing that can fail. Finding a name for an address is a DNS lookup that
// routinely takes seconds and usually comes back empty.
//
// Running both under one deadline let the second starve the first. Hops whose
// names were already known sat in the queue behind lookups that were going to
// time out, the budget ran down, and they were left with the address
// database's answer -- so whether a router was placed in London or in Ashburn
// came down to where it happened to sit in the queue. The free pass now runs
// first and completely, for every address, and only the lookups are rationed.
func (m *Module) describeFast(pairs map[string]string, budget time.Duration) (map[string]Detail, []string) {
	out := make(map[string]Detail, len(pairs))
	var cold, needName []string

	for ip, host := range pairs {
		if d, ok := m.cached(ip); ok {
			out[ip] = d
			continue
		}
		cold = append(cold, ip)
		if host == "" {
			needName = append(needName, ip)
			continue
		}
		out[ip] = fromName(host)
	}

	// Only the lookups are rationed, and only so many of them: this runs while
	// somebody waits for a page.
	sort.Strings(needName)
	if len(needName) > 400 {
		needName = needName[:400]
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	deadline := time.Now().Add(budget)
	for _, ip := range needName {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			if time.Now().After(deadline) {
				return
			}
			sem <- struct{}{}
			defer func() { <-sem }()
			if time.Now().After(deadline) {
				return
			}
			host := reverseName(ip)
			if host == "" {
				return
			}
			// Deliberately not cached: this is a partial answer, and writing
			// it under the same key the warmer uses would make "not asked
			// yet" indistinguishable from "asked, and there is nothing".
			mu.Lock()
			out[ip] = fromName(host)
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return out, cold
}

// fromName records the name. Where it points is settled later, in describe(),
// because that needs the round trip and the origin -- and because a decision
// that depends on a measurement must not be cached against an address as
// though it were a property of it.
func fromName(host string) Detail {
	return Detail{Name: host}
}

// note remembers addresses that still need the slow lookup.
func (m *Module) note(ips []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == nil {
		m.pending = map[string]bool{}
	}
	for _, ip := range ips {
		if len(m.pending) >= 2000 {
			return
		}
		m.pending[ip] = true
	}
}

// warm fills the cache for a few addresses at a time.
//
// Small, and on a timer. Two of these sources are free services run by other
// people, and a gateway that empties its whole backlog at them in one burst is
// how a source stops answering for everybody.
func (m *Module) warm() error {
	if !m.registryOK() {
		return nil
	}
	m.mu.Lock()
	var batch []string
	for ip := range m.pending {
		batch = append(batch, ip)
		delete(m.pending, ip)
		if len(batch) >= 12 {
			break
		}
	}
	m.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 3)
	for _, ip := range batch {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			m.detailFor(ip, "")
		}(ip)
	}
	wg.Wait()
	return nil
}
