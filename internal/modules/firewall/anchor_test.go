package firewall

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestAnchorRefs(t *testing.T) {
	cases := []struct {
		name       string
		rules      string
		ref, quick bool
	}{
		{"none", "block drop in log inet all\npass out all keep state\n", false, false},
		{"plain", "scrub in all fragment reassemble\nanchor \"flowsight/*\" all\nblock drop in log inet all\n", true, false},
		{"quick", "anchor \"flowsight/*\" quick all\nblock drop in log inet all\n", true, true},
		{"named child", "anchor \"flowsight/policy\" all\n", true, false},
		{"other anchor quick", "anchor \"acme-client/*\" quick all\nanchor \"flowsight/*\" all\n", true, false},
		{"quick only in a label", "anchor \"flowsight/*\" all\npass in quick on em0 all label \"quick\"\n", true, false},
		{"rdr anchor is not a filter anchor", "rdr-anchor \"flowsight/*\" all\n", false, false},
	}
	for _, c := range cases {
		ref, quick := anchorRefs(c.rules)
		if ref != c.ref || quick != c.quick {
			t.Errorf("%s: got referenced=%v quick=%v, want %v %v", c.name, ref, quick, c.ref, c.quick)
		}
	}
}

// The OPNsense plugin once registered the filter anchor quick. On OPNsense
// 26.7 that stopped pf evaluating every rule after it, which left the
// firewall's own ruleset unenforced. Neither plugin, the pfSense package
// included, nor the manual may bring it back.
func TestFilterAnchorIsNeverQuick(t *testing.T) {
	root := filepath.Join("..", "..", "..")

	inc, err := os.ReadFile(filepath.Join(root, "plugin", "os-flowsight", "src", "etc", "inc", "plugins.inc.d", "flowsight.inc"))
	if err != nil {
		t.Fatal(err)
	}
	fw := regexp.MustCompile(`registerAnchor\(\s*'flowsight/\*'\s*,\s*'fw'[^)]*\)`).FindAll(inc, -1)
	if len(fw) != 1 {
		t.Fatalf("expected one filter anchor registration in the plugin, found %d", len(fw))
	}
	if regexp.MustCompile(`(?i)\btrue\b`).Match(fw[0]) {
		t.Errorf("the plugin registers the filter anchor quick: %s", fw[0])
	}

	// pfSense: the package's filter hook returns the anchor line as text.
	pf, err := os.ReadFile(filepath.Join(root, "plugin", "pfSense-pkg-flowsight", "files", "usr", "local", "pkg", "flowsight.inc"))
	if err != nil {
		t.Fatal(err)
	}
	hook := regexp.MustCompile(`(?m)^[^\n]*"anchor \\"flowsight/\*\\"[^\n]*$`).FindAll(pf, -1)
	if len(hook) != 1 {
		t.Fatalf("expected one filter anchor line in the pfSense package, found %d", len(hook))
	}
	if regexp.MustCompile(`\bquick\b`).Match(hook[0]) {
		t.Errorf("the pfSense package writes the filter anchor quick: %s", hook[0])
	}

	docs, err := filepath.Glob(filepath.Join(root, "docs", "*.md"))
	if err != nil || len(docs) == 0 {
		t.Fatalf("no manual pages found: %v", err)
	}
	line := regexp.MustCompile(`(?m)^\s*anchor "flowsight[^"]*"[^\n]*\bquick\b`)
	for _, p := range docs {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if m := line.Find(b); m != nil {
			t.Errorf("%s tells the reader to write a quick anchor: %q", filepath.Base(p), m)
		}
	}
}
