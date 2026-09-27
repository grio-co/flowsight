package core

import "encoding/json"

// The provider protocol, version 1: how a backend that is not in this
// process (Suricata in its own container, on another host) reaches the
// core. The provider dials the core over the HTTP API and authenticates
// with a named API token; the token's name is the provider's name, so the
// audit log and the provider list say who sent what, and revoking the token
// disconnects it. See docs/DESIGN-PLATFORM.md ("Providers out of process").
//
//	POST /api/provider/v1/hello   ProviderHello  -> ProviderWelcome (also the heartbeat)
//	POST /api/provider/v1/events  ProviderEvents -> {"accepted": n}
//	GET  /api/provider/v1/providers                 who is connected
//
// Version 1 carries one direction, provider to core, which is all a
// detector needs. Roles the core must call into (enforcers, redirectors)
// come with a later version.

// ProviderProtocol is the version this core speaks.
const ProviderProtocol = 1

// ServiceProviderHub is where modules register the formats they consume.
const ServiceProviderHub = "provider_hub"

// ProviderHello introduces a provider and, repeated, keeps it marked alive.
type ProviderHello struct {
	Protocol     int      `json:"protocol"`
	Role         string   `json:"role"`    // detector, ...
	Kind         string   `json:"kind"`    // suricata, ...
	Version      string   `json:"version"` // of the provider agent
	Capabilities []string `json:"capabilities,omitempty"`
	Formats      []string `json:"formats"` // what it will send
}

// ProviderWelcome is the core's answer to a hello.
type ProviderWelcome struct {
	Protocol         int      `json:"protocol"`
	Name             string   `json:"name"`    // the provider's name, from its token
	Accepts          []string `json:"accepts"` // formats some module here consumes
	HeartbeatSeconds int      `json:"heartbeat_seconds"`
}

// ProviderEvents is a batch of records in one format. Dropped counts
// records the provider had to discard while the core was unreachable, so
// the loss is visible rather than silent.
type ProviderEvents struct {
	Format  string            `json:"format"`
	Records []json.RawMessage `json:"records"`
	Dropped int64             `json:"dropped,omitempty"`
}

// ProviderSink consumes a batch for one format; provider is the sender's
// name. It returns how many records it took.
type ProviderSink func(provider string, records []json.RawMessage) (int, error)

// ProviderHub is published by the providers module.
type ProviderHub interface {
	// Accept registers the module that consumes a format.
	Accept(format string, sink ProviderSink)
}
