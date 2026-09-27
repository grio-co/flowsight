package pihole

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/grioghar/flowsight/internal/core"
)

func TestPinnedClientPinsThenRefusesAChange(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()
	s, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m := &Module{ctx: &core.Context{Store: s, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	c := m.pinnedClient()
	for i := 0; i < 2; i++ { // first contact pins, second matches
		resp, err := c.Get(srv.URL)
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		resp.Body.Close()
	}
	addr := strings.TrimPrefix(srv.URL, "https://")
	if p := m.pins()[addr]; len(p) != 64 {
		t.Fatalf("pin not recorded for %s: %v", addr, m.pins())
	}
	// Somebody else's certificate at the same address.
	_ = s.KVSet(pinsKV, map[string]string{addr: strings.Repeat("0", 64)})
	c2 := m.pinnedClient()
	if _, err := c2.Get(srv.URL); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("a different certificate must be refused: %v", err)
	}
}
