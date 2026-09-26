package egress

// Reading the firewall's live connection table.
//
// A proxy log line is written when a session closes. A device that spends
// twenty minutes uploading appears in it once, twenty minutes late, which is
// the wrong end of the event for anyone who wants to notice data leaving.
//
// The firewall already counts every byte of every open connection and
// updates the counters continuously, so that is what this reads. It covers
// what the proxy never sees: pinned sessions, spliced sessions, QUIC on UDP
// 443, VPN and mesh tunnels, and every protocol that is not HTTP at all.
//
// The connections come from the core.StateReader service, described by who
// opened them (see core.ConnState); pf's own format is read in
// firewall.ParseStates. Which byte counter is "leaving this network" depends
// on who opened the connection and which end is local, and getting it
// backwards would report every download as an upload. states_test.go pins it
// against a real capture.

import (
	"strconv"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// State is one live connection seen from this network.
type State struct {
	Proto    string
	Local    string // the address on this network
	Peer     string // the address on the far side
	PeerPort int
	Out      int64 // bytes the local address has sent
	In       int64 // bytes it has received
	Age      time.Duration
	Rule     string
	// Inbound is true when the far side opened this connection: a server on
	// this network answering the internet, rather than a device reaching out.
	// The bytes are real either way, but only one of the two is data leaving
	// in the sense anyone means by it.
	Inbound bool
}

// Key identifies a state across samples.
func (s State) Key() string {
	return s.Local + "|" + s.Peer + "|" + strconv.Itoa(s.PeerPort) + "|" + s.Proto
}

// readStates reads the firewall's live connection table and keeps the
// connections a device on this network is part of.
func readStates(r core.StateReader, isLocal func(string) bool) ([]State, error) {
	conns, err := r.States()
	if err != nil {
		return nil, err
	}
	return fromConns(conns, isLocal), nil
}

// isLoopback recognises the proxy's own end of a redirected session. It has
// to be excluded explicitly: a redirect names 127.0.0.1 as one endpoint, and
// the identity module quite correctly calls that local, which would make both
// ends of every intercepted session look local and discard it.
func isLoopback(ip string) bool {
	return ip == "::1" || strings.HasPrefix(ip, "127.")
}

// fromConns turns connections into states seen from this network: which end
// is the device, which is the far side, and which byte counter is its upload.
func fromConns(conns []core.ConnState, isLocal func(string) bool) []State {
	// A device is a local address that is not the proxy's own loopback end.
	device := func(ip string) bool { return !isLoopback(ip) && isLocal(ip) }
	var states []State
	for _, c := range conns {
		if st, ok := orient(c, device); ok {
			states = append(states, st)
		}
	}
	return states
}

// orient decides which end of a connection is the device. The initiator is
// judged by the address it had on the wire and the responder by where the
// connection was delivered, because those are the addresses that are
// actually on this network. The far side is reported as the opener addressed
// it, so a session redirected to the proxy names the site the device asked
// for, not the proxy.
func orient(c core.ConnState, isDevice func(string) bool) (State, bool) {
	switch c.Proto {
	case "tcp", "udp":
	default:
		return State{}, false // icmp and the rest carry no payload worth watching
	}
	st := State{Proto: c.Proto, Age: c.Age, Rule: c.Rule}
	iw, ra := c.InitiatorTranslated, c.ResponderTranslated
	asInitiator := func(local, peer core.Endpoint) {
		st.Local, st.Peer, st.PeerPort = local.Addr, peer.Addr, peer.Port
		st.Out, st.In = c.Sent, c.Received
	}
	asResponder := func(local, peer core.Endpoint) {
		st.Local, st.Peer, st.PeerPort = local.Addr, peer.Addr, peer.Port
		st.Out, st.In = c.Received, c.Sent
		st.Inbound = true
	}
	switch {
	case isDevice(iw.Addr) && !isDevice(ra.Addr):
		// The device opened it. A redirected session names the proxy as
		// the responder, with the address the device asked for before the
		// redirect; that address, not the proxy, is where the data goes.
		peer := ra
		if c.Responder != ra && !isDevice(c.Responder.Addr) {
			peer = c.Responder
		}
		asInitiator(iw, peer)
	case isDevice(ra.Addr) && !isDevice(iw.Addr):
		// The far side opened it: a server here answering the internet.
		peer := iw
		if c.Initiator != iw && !isDevice(c.Initiator.Addr) {
			peer = c.Initiator
		}
		asResponder(ra, peer)
	case c.Initiator != iw && isDevice(c.Initiator.Addr):
		// Neither end is local on the wire, which is an ordinary outbound
		// session: the gateway's own address is on the wire and the device
		// is the address before translation.
		asInitiator(c.Initiator, c.Responder)
	case c.Responder != ra && isDevice(c.Responder.Addr):
		asResponder(c.Responder, c.Initiator)
	default:
		return State{}, false
	}
	if st.Local == "" || st.Peer == "" {
		return State{}, false
	}
	return st, true
}
