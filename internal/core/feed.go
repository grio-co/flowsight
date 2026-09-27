package core

// Feeds: read-only lists another system subscribes to by URL.
//
// A Pi-hole blocklist is a URL the Pi-hole fetches on every gravity run, so
// a FlowSight category can only become a Pi-hole list if FlowSight serves it
// at a URL the Pi-hole can fetch without FlowSight's API token. These are
// that URL: /feeds/categories/<name>.txt?key=<feed key>, one domain per line.
// The key is a random secret of this installation, compared in constant
// time; a wrong key, like an unknown category, gets a plain 404, so the
// feed does not say what exists. Nothing but category lists is served here.

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const feedKeyKV = "core.feed_key"

// FeedKey returns the installation's feed key, creating it on first use.
func (c *Core) FeedKey() string {
	var k string
	if c.Store.KVGet(feedKeyKV, &k) && len(k) >= 32 {
		return k
	}
	return c.RotateFeedKey()
}

// RotateFeedKey replaces the feed key; every subscribed URL changes with it.
func (c *Core) RotateFeedKey() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	k := hex.EncodeToString(b)
	_ = c.Store.KVSet(feedKeyKV, k)
	return k
}

// FeedPath is the path, key included, of a category's feed.
func (c *Core) FeedPath(category string) string {
	return "/feeds/categories/" + category + ".txt?key=" + c.FeedKey()
}

func (a *API) serveFeed(w http.ResponseWriter, r *http.Request, p string) {
	notFound := func() { http.Error(w, "not found", http.StatusNotFound) }
	want := a.core.FeedKey()
	got := r.URL.Query().Get("key")
	if len(got) != len(want) || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		time.Sleep(200 * time.Millisecond)
		notFound()
		return
	}
	name := strings.TrimSuffix(strings.TrimPrefix(p, "/feeds/categories/"), ".txt")
	if name == "" || strings.ContainsAny(name, "/\\. ") || !strings.HasPrefix(p, "/feeds/categories/") {
		notFound()
		return
	}
	a.core.mu.RLock()
	svc, _ := a.core.Services["categories"].(interface {
		Domains(string) ([]string, error)
	})
	a.core.mu.RUnlock()
	if svc == nil {
		notFound()
		return
	}
	doms, err := svc.Domains(strings.ToLower(name))
	if err != nil {
		notFound()
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# FlowSight category %s: %d domains, %s\n", name, len(doms), time.Now().UTC().Format(time.RFC3339))
	for _, d := range doms {
		d = strings.TrimSpace(d)
		if d != "" && !strings.HasPrefix(d, "#") {
			b.WriteString(d)
			b.WriteByte('\n')
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(b.String()))
}
