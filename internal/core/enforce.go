package core

import "time"

// The enforcement seam. Modules that fill address sets, cut connections or
// read the live connection table ask for these services instead of a
// particular firewall, so the same module works over pf today and over
// nftables, a firewall's API or another engine later. See
// docs/DESIGN-PLATFORM.md ("Roles and providers").
//
// Declaring the sets and the rules that use them stays with the firewall's
// policy provider, which compiles them from the policy document. These
// services only fill what the provider declared and report what is live.

// Service names under which the contracts are published.
const (
	ServiceEnforcer   = "enforcer"
	ServiceConnStates = "conn_states"
)

// Capabilities an Enforcer or StateReader can report.
const (
	CapSetV4      = "set.v4"      // IPv4 addresses and prefixes in sets
	CapSetV6      = "set.v6"      // IPv6 addresses and prefixes in sets
	CapKillStates = "kill.states" // drop established connections
	CapConnStates = "conn.states" // read live connections with byte counters
)

// Enforcer holds L3 verdicts in named address sets that the firewall's policy
// provider declared. A set name is what the provider handed out (for example
// firewall.TableFor); the enforcer maps it to its own object.
type Enforcer interface {
	// Name is the backend, for display: "pf", "nftables", ...
	Name() string
	Capabilities() []string
	// Available reports whether the backend is present and usable. When it
	// is false every other call fails, and callers record instead of enforce.
	Available() bool
	// ReplaceSet makes the set hold exactly addrs. An empty list empties it.
	ReplaceSet(set string, addrs []string) error
	// AddToSet adds addrs to the set, leaving what is there.
	AddToSet(set string, addrs []string) error
	// KillStates drops established connections from src to dst. Either may
	// be empty, meaning any address.
	KillStates(src, dst string) error
}

// Endpoint is one end of a connection.
type Endpoint struct {
	Addr string
	Port int
}

// ConnState is one live connection, described by who opened it rather than
// by how a particular firewall prints it.
//
// A translated connection has two addresses for one end: the address the
// packets carried before translation and the one they carried after.
// Initiator is the opener as it addressed its own packets; InitiatorWire is
// that end after source translation (outbound NAT). Responder is the far end
// as the opener addressed it; ResponderActual is where the connection was
// delivered after destination translation (a redirect or a port forward).
// Without translation each pair is equal.
type ConnState struct {
	Proto           string // "tcp", "udp", "icmp", ...
	Initiator       Endpoint
	InitiatorWire   Endpoint
	Responder       Endpoint
	ResponderActual Endpoint
	// Sent counts bytes from the initiator, Received bytes to it.
	Sent, Received int64
	Age            time.Duration
	// Rule names the rule that created the state, in the backend's own
	// terms ("rule 3", "anchor 4"), for display only.
	Rule string
}

// StateReader reads the live connection table.
type StateReader interface {
	Name() string
	Available() bool
	States() ([]ConnState, error)
}
