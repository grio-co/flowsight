package web

import "github.com/grioghar/flowsight/internal/modules/firewall"

// fakeFirewall stands in for pf: loading and flushing the "web" anchor are
// recorded, everything else is inert.
type fakeFirewall struct{ r *redirects }

func newFakeRedirector(r *redirects) *fakeFirewall { return &fakeFirewall{r: r} }

func (f *fakeFirewall) LoadAnchor(name, rules string) error {
	if name == "web" {
		f.r.load(rules)
	}
	return nil
}

func (f *fakeFirewall) FlushAnchor(name string) error {
	if name == "web" {
		f.r.clear()
	}
	return nil
}

func (f *fakeFirewall) ReplaceTable(anchor, table string, addrs []string) error { return nil }
func (f *fakeFirewall) AddToTable(anchor, table string, addrs []string) error   { return nil }
func (f *fakeFirewall) KillStates(src, dst string) error                        { return nil }
func (f *fakeFirewall) Counters(anchor string) ([]firewall.RuleCounter, error)  { return nil, nil }
func (f *fakeFirewall) LocalTable() string                                      { return "flowsight_local" }
func (f *fakeFirewall) Available() bool                                         { return true }
