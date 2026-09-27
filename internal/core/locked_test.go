package core

import "testing"

// The daemon's own keys are refused; a module's declared "port" is its own
// listener and saves like any other setting.
func TestLockedSettingSparesDeclaredModulePorts(t *testing.T) {
	if !lockedSetting("port", false) || !lockedSetting("bind", false) {
		t.Fatal("an undeclared port or bind is the daemon's and must be refused")
	}
	if lockedSetting("port", true) || lockedSetting("bind", true) {
		t.Fatal("a port or bind a module declares in its schema must be saveable")
	}
	for _, k := range []string{"api_token", "data_dir", "workers", "paths"} {
		if !lockedSetting(k, true) {
			t.Fatalf("%s is never a module setting", k)
		}
	}
	if !lockedSetting("tcpdump_bin", true) || !lockedSetting("binary_path", true) {
		t.Fatal("anything naming a binary stays refused even when declared")
	}
	if lockedSetting("keep_requests", true) {
		t.Fatal("an ordinary setting must pass")
	}
}
