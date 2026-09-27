package core

import "testing"

// The rc(8) PATH gains /usr/local, and an operator's order is kept.
func TestWithSystemDirs(t *testing.T) {
	got := withSystemDirs("/sbin:/bin:/usr/sbin:/usr/bin")
	if got != "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin" {
		t.Fatalf("rc PATH: %q", got)
	}
	got = withSystemDirs("/opt/bin:/usr/local/bin::/opt/bin")
	if got != "/opt/bin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin" {
		t.Fatalf("operator PATH: %q", got)
	}
}
