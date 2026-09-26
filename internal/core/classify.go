package core

import "sync"

// The classification seam. Flows reach the modules that react to them over
// one bus that any source may publish to, and application names come from
// whichever classifier the installation has. Today the visibility module is
// both: it reads flows from ntopng, which names applications with nDPI. See
// docs/DESIGN-PLATFORM.md ("Roles and providers").

// Service names for the classification contracts.
const (
	ServiceFlowBus    = "flow_bus"
	ServiceClassifier = "classifier"
)

// FlowBus carries flows, as they are observed, to the modules that react to
// them without polling the store. Core owns it, so any source can publish
// and a subscriber does not depend on which module produced a flow.
type FlowBus struct {
	mu   sync.RWMutex
	subs []func([]Flow)
}

// Subscribe registers fn to receive every batch published from now on.
func (b *FlowBus) Subscribe(fn func([]Flow)) {
	b.mu.Lock()
	b.subs = append(b.subs, fn)
	b.mu.Unlock()
}

// Publish hands a batch to every subscriber, in the caller's goroutine. A
// subscriber that panics is contained, so one module cannot stop flows
// reaching the others.
func (b *FlowBus) Publish(fl []Flow) {
	b.mu.RLock()
	subs := make([]func([]Flow), len(b.subs))
	copy(subs, b.subs)
	b.mu.RUnlock()
	for _, s := range subs {
		func() {
			defer func() { recover() }()
			s(fl)
		}()
	}
}

// Classifier names applications. Its catalogue is the vocabulary policy is
// written in: an application a policy denies must be a name the classifier
// can put on a flow, and Flow.App carries that name.
type Classifier interface {
	// Name is the engine, for display: "ndpi", ...
	Name() string
	AppCatalog
}
