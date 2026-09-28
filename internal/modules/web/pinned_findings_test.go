package web

import (
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/grioghar/flowsight/internal/core"
)

func pinnedTestModule(t *testing.T) *Module {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := core.New("0.9.8r000000000000", "", t.TempDir(), nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	c.LoadModules()
	m, ok := c.Modules["web"].(*Module)
	if !ok || m.pin == nil {
		t.Fatal("web module not loaded")
	}
	return m
}

func openPinned(t *testing.T, m *Module) map[string]map[string]any {
	t.Helper()
	rows, err := m.ctx.Store.Rows(`SELECT subject, attrs FROM findings WHERE module='web' AND resolved_ts IS NULL`)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, r := range rows {
		var a map[string]any
		if s, _ := r["attrs"].(string); s != "" {
			_ = json.Unmarshal([]byte(s), &a)
		}
		out[r["subject"].(string)] = a
	}
	return out
}

// A pinned name's finding says who was refused, and closes once the name
// leaves the list (here: an inspected handshake completed).
func TestPinnedFindingCarriesWhoAndResolves(t *testing.T) {
	m := pinnedTestModule(t)
	for _, c := range []string{"192.168.1.50", "192.168.1.51", "192.168.1.50"} {
		m.noteBumpResult("pinned.example.com", c, false)
	}
	m.flushPinned()
	open := openPinned(t, m)
	a := open["pinned.example.com"]
	if a == nil {
		t.Fatalf("no open finding: %v", open)
	}
	who := a["who"].(map[string]any)
	if who["ip"] != "192.168.1.50" || who["others"] != float64(1) {
		t.Fatalf("who: %v", who)
	}
	if a["where"].(map[string]any)["domain"] != "pinned.example.com" || len(a["why"].(map[string]any)["facts"].([]any)) == 0 {
		t.Fatalf("attrs: %v", a)
	}
	m.noteBumpResult("pinned.example.com", "192.168.1.50", true)
	m.flushPinned()
	if _, still := openPinned(t, m)["pinned.example.com"]; still {
		t.Fatal("finding should close when the name is no longer pinned")
	}
}

// Findings raised before attrs existed are filled in by the reconcile, and
// one for a name no longer on the list is closed.
func TestReconcileBackfillsAndClosesOrphans(t *testing.T) {
	m := pinnedTestModule(t)
	_, _ = m.ctx.Store.AddFinding("web", "pinned", "info", "old.example.com", "t", "d", "web:pinned:old.example.com")
	_, _ = m.ctx.Store.AddFinding("web", "pinned", "info", "gone.example.com", "t", "d", "web:pinned:gone.example.com")
	m.pin.mu.Lock()
	m.pin.entries["old.example.com"] = &pinnedEntry{Name: "old.example.com", Failures: 4, First: 1, Last: 9e9, SeenBy: []string{"10.0.0.9"}}
	m.pin.mu.Unlock()
	m.reconcilePinned()
	open := openPinned(t, m)
	if _, ok := open["gone.example.com"]; ok {
		t.Fatal("orphan finding should close")
	}
	if a := open["old.example.com"]; a == nil || a["who"].(map[string]any)["ip"] != "10.0.0.9" {
		t.Fatalf("old finding should gain attrs: %v", open)
	}
}
