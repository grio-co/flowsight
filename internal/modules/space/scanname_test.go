package space

import (
	"path/filepath"
	"strings"
	"testing"
)

// A client-supplied scan name can never leave the scan folder.
func TestSafeScanName(t *testing.T) {
	for in, want := range map[string]string{
		"room.glb": "room.glb", "../../../../usr/local/etc/x.json": "x.json", `..\..\evil.obj`: "evil.obj",
		"a b;rm -rf.ply": "a_b_rm_-rf.ply", "..": "scan", "": "scan", ".hidden.json": "hidden.json",
	} {
		got := safeScanName(in)
		if got != want {
			t.Errorf("%q: %q want %q", in, got, want)
		}
		full := filepath.Join("/data/space", "scan-20260927-120000-"+got)
		if !strings.HasPrefix(filepath.Clean(full), "/data/space/") {
			t.Errorf("%q escapes: %s", in, full)
		}
	}
}
