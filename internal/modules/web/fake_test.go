package web

import "github.com/grioghar/flowsight/internal/core"

// fakeRedirector stands in for the firewall: loading and clearing the web
// redirects are recorded, rendering is inert.
type fakeRedirector struct{ r *redirects }

func newFakeRedirector(r *redirects) *fakeRedirector { return &fakeRedirector{r: r} }

func (f *fakeRedirector) Name() string                                  { return "pf" }
func (f *fakeRedirector) Available() bool                               { return true }
func (f *fakeRedirector) RenderRedirects(spec core.RedirectSpec) string { return "" }

func (f *fakeRedirector) LoadRedirects(name, text string) error {
	if name == "web" {
		f.r.load(text)
	}
	return nil
}

func (f *fakeRedirector) ClearRedirects(name string) error {
	if name == "web" {
		f.r.clear()
	}
	return nil
}
