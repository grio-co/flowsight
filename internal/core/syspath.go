package core

import (
	"os"
	"path/filepath"
	"strings"
)

// systemBinDirs are where the tools FlowSight runs live across the platforms
// it supports. On OPNsense ssh, unbound-control and dnsmasq are all under
// /usr/local, and a daemon restarted by the updater or rc(8) inherits
// PATH=/sbin:/bin:/usr/sbin:/usr/bin, which finds none of them.
var systemBinDirs = []string{"/sbin", "/bin", "/usr/sbin", "/usr/bin", "/usr/local/sbin", "/usr/local/bin"}

// EnsureSystemPath appends any of systemBinDirs missing from PATH, keeping
// the existing order so an operator's own PATH still wins.
func EnsureSystemPath() {
	os.Setenv("PATH", withSystemDirs(os.Getenv("PATH")))
}

func withSystemDirs(path string) string {
	have := map[string]bool{}
	var dirs []string
	for _, d := range filepath.SplitList(path) {
		if d != "" && !have[d] {
			have[d] = true
			dirs = append(dirs, d)
		}
	}
	for _, d := range systemBinDirs {
		if !have[d] {
			have[d] = true
			dirs = append(dirs, d)
		}
	}
	return strings.Join(dirs, string(os.PathListSeparator))
}
