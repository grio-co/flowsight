package paths

// Where "here" is.
//
// The map needs an origin for two reasons. It is the point every route leaves
// from, and it is the reference for the only check that can falsify a
// placement: light in fibre covers about 200,000 km per second, so a round
// trip cannot beat twice the straight-line distance divided by that, before
// any routing detour or equipment delay is added. A hop that answers faster
// than that floor is not in the place the database says it is.
//
// Left alone, "here" is worked out from the gateway's own public address. That
// is usually the right town and occasionally the wrong state, because it is
// where the carrier registered the block rather than where the wire ends. So
// it can be declared instead, and the page offers two ways to fill it in: ask
// the browser, which knows precisely and asks permission, or take the
// database's answer for the public address.

import (
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// earthKM is the mean radius; fibreKMS is light in glass, about two thirds of
// its speed in vacuum.
const (
	earthKM  = 6371.0
	fibreKMS = 200000.0
)

// Home is the origin the map is drawn from.
type Home struct {
	Lat, Lon float64
	Source   string // "declared" or "public address"
	OK       bool
}

// home returns the origin: what was declared, or failing that the database's
// answer for this gateway's own public address.
func (m *Module) home() Home {
	if lat, lon, ok := parseLatLon(core.Str(m.ctx.Settings(), "home", "")); ok {
		return Home{Lat: lat, Lon: lon, Source: "declared", OK: true}
	}
	if ip := m.publicAddress(); ip != "" && m.rdns != nil {
		if info, found := m.rdns.Lookup([]string{ip})[ip]; found && (info.Lat != 0 || info.Lon != 0) {
			return Home{Lat: info.Lat, Lon: info.Lon, Source: "public address", OK: true}
		}
	}
	return Home{}
}

// publicAddresses are this gateway's own addresses on the public internet,
// read from its interfaces rather than asked of anyone outside. IPv4 first,
// then IPv6, each sorted, so the answer is the same every time it is asked.
//
// "Not private" is not enough to find them. A delegated IPv6 prefix is
// globally routable and still belongs to this network, so the LAN address
// matches every test for a public one. Identity knows which prefixes are
// ours, and that is the only thing that can tell them apart.
func (m *Module) publicAddresses() (v4, v6 []string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err != nil || ip == nil {
				continue
			}
			if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
				continue
			}
			s := ip.String()
			if isPrivate(s) {
				continue
			}
			if m.identity != nil && m.identity.IsLocal(s) {
				continue // routable, but on this side of the firewall
			}
			if ip.To4() != nil {
				if !contains(v4, s) {
					v4 = append(v4, s)
				}
			} else if !contains(v6, s) {
				v6 = append(v6, s)
			}
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6
}

// publicAddress is the one address the origin is worked out from.
//
// IPv4 by preference, and not as a matter of taste: the interface walk has no
// defined order, so taking whichever address turned up first meant a
// dual-stack gateway could locate itself from v6 on one run and v4 on the
// next. The origin is what decides whether a hop could be where the database
// claims, so an origin that moves between restarts quietly moves the line
// between a placement that is ruled out and one that stands. IPv4 also
// geolocates better, v6 blocks being newer and more coarsely registered.
func (m *Module) publicAddress() string {
	v4, v6 := m.publicAddresses()
	if len(v4) > 0 {
		return v4[0]
	}
	if len(v6) > 0 {
		return v6[0]
	}
	return ""
}

func parseLatLon(s string) (float64, float64, bool) {
	a, b, ok := strings.Cut(strings.TrimSpace(s), ",")
	if !ok {
		return 0, 0, false
	}
	lat, err1 := strconv.ParseFloat(strings.TrimSpace(a), 64)
	lon, err2 := strconv.ParseFloat(strings.TrimSpace(b), 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	if lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		return 0, 0, false
	}
	if lat == 0 && lon == 0 {
		return 0, 0, false // the point in the Gulf of Guinea that means "unset"
	}
	return lat, lon, true
}

// greatCircleKM is the straight-line distance over the earth's surface.
func greatCircleKM(lat1, lon1, lat2, lon2 float64) float64 {
	p1, p2 := lat1*math.Pi/180, lat2*math.Pi/180
	dp, dl := (lat2-lat1)*math.Pi/180, (lon2-lon1)*math.Pi/180
	a := math.Sin(dp/2)*math.Sin(dp/2) + math.Cos(p1)*math.Cos(p2)*math.Sin(dl/2)*math.Sin(dl/2)
	return earthKM * 2 * math.Asin(math.Sqrt(a))
}

// floorMS is the fastest a round trip to a point could possibly be: straight
// there and straight back through glass, with nothing in between.
func floorMS(km float64) float64 { return 2 * km / fibreKMS * 1000 }

// checkPlausible marks the placements the measured latency rules out. It never
// moves a point or invents one; it says which ones cannot be where they claim.

func (m *Module) checkPlausible(nodes []Node, h Home) {
	if !h.OK {
		return
	}
	hop := m.hopDelayMS()
	// How far the origin itself might be wrong.
	//
	// Every floor is measured from here, and "here" is usually worked out
	// from the gateway's own public address -- which is where the carrier
	// registered the block, not where the wire ends. That is routinely tens
	// of kilometres out and occasionally hundreds. Calling a placement
	// impossible on a margin thinner than that error is claiming a precision
	// the origin does not have: on this network the tightest such verdict was
	// a hop in Montreal missing its floor by 0.2 ms over 2,000 km, which is
	// one per cent, and one per cent of the origin is a rounding error.
	//
	// So the hard verdict is measured from the nearest point the origin could
	// honestly be. It only ever withdraws accusations, never adds them, and a
	// declared origin gets no allowance because the reader said where it is.
	slack := 0.0
	if h.Source != "declared" {
		slack = float64(m.originSlackKM())
	}
	for i := range nodes {
		n := &nodes[i]
		if !n.Located || n.RTT <= 0 {
			continue
		}
		// Two numbers, answering two different questions.
		//
		// The floor is what light forbids, measured along the cables where a
		// crossing has to follow one. It is a proof, and it is rigorous
		// because it assumes a perfect path: dead straight, nothing attached.
		//
		// The expectation is what a route that exists could manage: fibre on
		// land runs about a third longer than the crow flies, a sea crossing
		// is as long as its cable, and every router on the way holds the
		// packet for a moment before passing it on. A hop under this is not
		// disproved -- it is beating anything anyone has built, which is a
		// different and softer claim, and the two must not be run together.
		km, via := m.pathKM(h.Lat, h.Lon, n.Lat, n.Lon)
		n.DistanceKM = math.Round(km)
		n.Via = via
		// The floor that rules is the one the origin's own uncertainty
		// allows; the floor that is reported is that same number, so the
		// arithmetic on screen is the arithmetic that was applied.
		nearest := km - slack
		if nearest < 0 {
			nearest = 0
		}
		floor := floorMS(nearest)
		n.FloorMS = math.Round(floor*10) / 10
		n.SlackKM = math.Round(slack)

		ekm, evia := m.expectedKM(h.Lat, h.Lon, n.Lat, n.Lon)
		if ekm < km {
			ekm = km // an expectation below the bound is not an expectation
		}
		expected := floorMS(ekm) + hop*float64(n.Index)
		n.ExpectedKM = math.Round(ekm)
		n.ExpectedMS = math.Round(expected*10) / 10
		n.ExpectedVia = evia

		switch {
		case n.RTT < floor:
			n.Impossible = true
			n.Why = fmt.Sprintf("answers in %.1f ms, but %.0f km away%s cannot answer in less than %.0f ms%s",
				n.RTT, km, viaPhrase(via), floor, slackPhrase(slack))
		case expected > floor && n.RTT < expected:
			n.Tight = true
			n.Why = fmt.Sprintf("answers in %.1f ms, which light allows over %.0f km%s but no built route does: %s comes to %.0f ms, and %d hop%s add %.1f ms more",
				n.RTT, km, viaPhrase(via), expectedPhrase(ekm, evia), floorMS(ekm), n.Index, plural(n.Index), hop*float64(n.Index))
		}
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// expectedPhrase says where the realistic distance came from, because a
// number a reader cannot trace is one they have to take on trust.
func expectedPhrase(km float64, via string) string {
	if via != "" {
		return fmt.Sprintf("%.0f km along %s", km, via)
	}
	return fmt.Sprintf("%.0f km once fibre's detours are allowed for", km)
}

// viaPhrase names the cable a distance was measured along, when one was.
func viaPhrase(via string) string {
	if via == "" {
		return ""
	}
	return " by the shortest cable route (" + via + ")"
}

// originSlackKM is how far the origin might be wrong, in kilometres.
func (m *Module) originSlackKM() int {
	if m.ctx == nil {
		return 100
	}
	v := core.Int(m.ctx.Settings(), "origin_slack_km", 100)
	if v < 0 {
		v = 0
	}
	return v
}

// slackPhrase says that the origin was given the benefit of the doubt.
func slackPhrase(slack float64) string {
	if slack <= 0 {
		return ""
	}
	return fmt.Sprintf(" (measured from %.0f km nearer, in case your own position is out)", slack)
}

// HomeCountry is the ISO 3166-1 alpha-2 code of the country this gateway's
// public address is in, "" when it cannot be told (no database, no public
// address yet). It is what "abroad" means elsewhere in FlowSight.
func (m *Module) HomeCountry() string {
	m.mu.Lock()
	if m.homeCC != "" && time.Since(m.homeCCAt) < time.Hour {
		cc := m.homeCC
		m.mu.Unlock()
		return cc
	}
	m.mu.Unlock()
	cc := ""
	if ip := m.publicAddress(); ip != "" && m.rdns != nil {
		if info, ok := m.rdns.Lookup([]string{ip})[ip]; ok {
			cc = strings.ToUpper(info.Country)
		}
	}
	m.mu.Lock()
	m.homeCC, m.homeCCAt = cc, time.Now()
	m.mu.Unlock()
	return cc
}

// HomeLatLon is where this network is, for anything that wants the nearest
// of something (the bandwidth test picks speedtest.net servers by it).
func (m *Module) HomeLatLon() (float64, float64, bool) {
	h := m.home()
	if !h.OK {
		return 0, 0, false
	}
	return h.Lat, h.Lon, true
}
