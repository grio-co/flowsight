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
	ServiceRules      = "fw_rules"
	ServiceRedirector = "redirector"
)

// Capabilities an Enforcer or StateReader can report.
const (
	CapSetV4      = "set.v4"      // IPv4 addresses and prefixes in sets
	CapSetV6      = "set.v6"      // IPv6 addresses and prefixes in sets
	CapKillStates = "kill.states" // drop established connections
	CapConnStates = "conn.states" // read live connections with byte counters
	CapRules      = "rules.read"  // read the active ruleset with counters
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
// A translated connection has two addresses for one end. Initiator is the
// opener as it addressed its own packets; InitiatorTranslated is that end
// after source translation (outbound NAT). Responder is the far end as the
// opener addressed it; ResponderTranslated is where the connection was
// delivered after destination translation (a redirect or a port forward).
// Without translation each pair is equal.
type ConnState struct {
	Proto               string // "tcp", "udp", "icmp", ...
	Initiator           Endpoint
	InitiatorTranslated Endpoint
	Responder           Endpoint
	ResponderTranslated Endpoint
	// Sent counts what the initiator sent, Received what it was sent.
	Sent, Received         int64 // bytes
	PktsSent, PktsReceived int64
	Age, Expires           time.Duration
	// Iface is the interface the state is bound to ("all" when floating),
	// and Direction whether it was created by a packet coming in on it
	// ("in") or going out ("out"). Either is empty when the backend does
	// not say.
	Iface, Direction string
	// Status is the backend's own protocol state ("ESTABLISHED:ESTABLISHED")
	// and Rule the rule that created it ("rule 3"), both for display.
	Status, Rule string
}

// StateReader reads the live connection table.
type StateReader interface {
	Name() string
	Available() bool
	States() ([]ConnState, error)
}

// Rule is one rule of the active ruleset, in the backend's own syntax, with
// the counters the backend keeps for it.
type Rule struct {
	Text        string `json:"text"`
	Label       string `json:"label,omitempty"`
	Evaluations int64  `json:"evaluations"`
	Packets     int64  `json:"packets"`
	Bytes       int64  `json:"bytes"`
	States      int64  `json:"states"`
}

// RuleReader reads the active ruleset. Syntax names the language Rule.Text
// is written in ("pf", "nft"), so an analyser knows whether it can read it.
// Rule.Text is the rule as the backend prints it.
type RuleReader interface {
	Name() string
	Syntax() string
	Available() bool
	Rules() ([]Rule, error)
	// CountersSince is when the rule counters started counting, usually
	// when the ruleset was loaded. It is zero when the backend cannot say,
	// and counters that cannot be dated must not be judged.
	CountersSince() time.Time
}

// RedirectSpec describes interception: new TCP connections from some
// sources to some ports are steered to a local listener. Redirects never
// apply to destinations on the local networks, and a source in Excluded is
// never redirected in either address family.
type RedirectSpec struct {
	Interfaces []string // where to redirect; empty means any interface
	Excluded   []string // addresses and prefixes left alone
	Rules      []RedirectRule
}

// RedirectRule is one family and port to steer.
type RedirectRule struct {
	Family  string   // "inet" or "inet6"
	Sources []string // addresses and prefixes; empty means the local networks
	Port    int      // destination port matched
	To      Endpoint // the listener
}

// Redirector installs and withdraws interception. Interception must never
// fail closed, so the caller loads redirects only while its listener
// answers, and clears them the moment it does not.
type Redirector interface {
	// Name is the backend, for display and for naming the rendered file.
	Name() string
	Available() bool
	// RenderRedirects compiles a spec into the backend's own text without
	// touching the system. The caller keeps the text with its other
	// configuration, so what will be loaded can be shown and compared.
	RenderRedirects(spec RedirectSpec) string
	// LoadRedirects checks text with the backend's own validator and loads
	// it under name, replacing what was there.
	LoadRedirects(name, text string) error
	// ClearRedirects removes everything loaded under name. It is the
	// fail-open path: safe to repeat, and it must not depend on the
	// listener or on anything the caller has rendered.
	ClearRedirects(name string) error
}
