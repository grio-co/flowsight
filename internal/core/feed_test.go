package core

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeCats struct{}

func (fakeCats) Domains(name string) ([]string, error) {
	if name != "ads" {
		return nil, errors.New("no such category")
	}
	return []string{"ads.example.com", " tracker.example.net ", ""}, nil
}

// A category feed is served only with the installation's key, as one
// domain per line; a wrong key and an unknown category look the same.
func TestCategoryFeed(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := &Core{Store: s, Services: map[string]any{"categories": fakeCats{}}}
	a := &API{core: c}
	key := c.FeedKey()
	if len(key) < 32 || c.FeedKey() != key {
		t.Fatal("the key is created once and kept")
	}
	get := func(u string) (int, string) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", u, nil)
		a.serveFeed(w, r, r.URL.Path)
		return w.Code, w.Body.String()
	}
	code, body := get("/feeds/categories/ads.txt?key=" + key)
	if code != 200 || !strings.Contains(body, "\nads.example.com\ntracker.example.net\n") || !strings.HasPrefix(body, "# FlowSight category ads") {
		t.Fatalf("feed: %d %q", code, body)
	}
	for _, u := range []string{"/feeds/categories/ads.txt?key=wrong", "/feeds/categories/ads.txt", "/feeds/categories/nope.txt?key=" + key,
		"/feeds/categories/../x.txt?key=" + key} {
		if code, _ := get(u); code != 404 {
			t.Errorf("%s: %d, want 404", u, code)
		}
	}
	if c.RotateFeedKey() == key {
		t.Fatal("rotation changes the key")
	}
	if code, _ := get("/feeds/categories/ads.txt?key=" + key); code != 404 {
		t.Fatal("the old key stops working")
	}
}
