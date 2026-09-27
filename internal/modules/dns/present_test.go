package dns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grioghar/flowsight/internal/core"
)

// Without Unbound the module neither makes Unbound's directories nor offers
// DNS policy. Found in a container, where the logging job tried to create
// /etc/unbound on a read-only root every ten minutes, and on a host beside
// the firewall, where it left an empty /etc/unbound behind.
func TestNoUnboundMeansNoLoggingJobAndNoProvider(t *testing.T) {
	root := t.TempDir()
	cfg, err := core.LoadConfig(filepath.Join(root, "flowsight.json"))
	if err != nil {
		t.Fatal(err)
	}
	c := &core.Core{Services: map[string]any{}, Config: cfg}
	pl := &core.Platform{UnboundControl: filepath.Join(root, "absent", "unbound-control"),
		UnboundCheckconf: filepath.Join(root, "absent", "unbound-checkconf"),
		UnboundInclude:   filepath.Join(root, "etc", "unbound", "unbound.conf.d", "flowsight-policy.conf")}
	m := &Module{ctx: &core.Context{Core: c, Name: "dns", Config: cfg, Platform: pl}}
	if m.unboundPresent() {
		t.Fatal("unbound reported present")
	}
	if h := m.Health(); !h.OK || !strings.Contains(h.Detail, "not installed") {
		t.Fatalf("health: %+v", h)
	}
	if _, err := os.Stat(filepath.Join(root, "etc", "unbound")); err == nil {
		t.Fatal("Unbound's directory was created")
	}

	// With both programs present it is.
	for _, p := range []string{pl.UnboundControl, pl.UnboundCheckconf} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if !m.unboundPresent() {
		t.Fatal("unbound not reported present")
	}
}
