package proxmox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/grioghar/flowsight/internal/core"
)

// The second node in the list gets its own token and certificate when they
// are set, and the first node's when they are not.
func TestCredsForFallBackToTheFirstNode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flowsight.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DeclareModule("proxmox", map[string]any{
		"hosts":          []string{"https://pve1:8006", "https://pve2:8006/", "https://pve3:8006"},
		"token_id":       "flowsight@pve!a",
		"token_secret":   "s1",
		"fingerprint":    "AA",
		"token_secret_2": "s2",
		"fingerprint_2":  "BB",
	})
	m := &Module{ctx: &core.Context{Name: "proxmox", Config: cfg}}
	c1 := m.credsFor("https://pve1:8006")
	c2 := m.credsFor("https://pve2:8006")
	c3 := m.credsFor("https://pve3:8006")
	if c1.TokenSecret != "s1" || c1.Fingerprint != "AA" {
		t.Fatalf("first node: %+v", c1)
	}
	if c2.TokenID != "flowsight@pve!a" || c2.TokenSecret != "s2" || c2.Fingerprint != "BB" {
		t.Fatalf("second node: %+v", c2)
	}
	if c3.TokenSecret != "s1" || c3.Fingerprint != "AA" {
		t.Fatalf("third node falls back: %+v", c3)
	}
}
