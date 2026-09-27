package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------- plan files

func writePlanFile(t *testing.T, p any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "site.json")
	b, _ := json.Marshal(p)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPlanFileFromTheSameKindOfMachine(t *testing.T) {
	m := machine(t, "linux")
	m.files["/etc/os-release"] = "ID=debian\n"
	m.cmds["ip route show default"] = "default via 192.168.1.1 dev eth0"
	f := Detect(m.env_())
	saved := MakePlan(f, time.Now())
	saved.Questions[0].Answer = "mikrotik 192.168.1.1"
	file, err := ReadPlan(writePlanFile(t, saved))
	if err != nil {
		t.Fatal(err)
	}
	p, err := FromFile(f, file, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if p.Questions[0].ID != "firewall" || p.Questions[0].Answer != "mikrotik 192.168.1.1" {
		t.Fatalf("the answer did not carry over: %+v", p.Questions)
	}
	if !strings.Contains(p.Explain(), "-> mikrotik 192.168.1.1") {
		t.Error("the plan should show the answer")
	}
}

func TestPlanFileFromAnotherKindOfMachineIsRefused(t *testing.T) {
	m := machine(t, "linux")
	m.files["/etc/os-release"] = "ID=debian\n"
	f := Detect(m.env_())
	file := Plan{Format: PlanFormat, Platform: "opnsense", Service: "opnsense-plugin"}
	if _, err := FromFile(f, file, time.Now()); err == nil || !strings.Contains(err.Error(), "another kind of machine") ||
		!strings.Contains(err.Error(), `platform "opnsense"`) {
		t.Fatalf("mismatch not refused: %v", err)
	}
}

func TestHandWrittenPlanFileWithOnlyAnswers(t *testing.T) {
	m := machine(t, "linux")
	m.files["/etc/os-release"] = "ID=debian\n"
	m.files["/.dockerenv"] = ""
	path := writePlanFile(t, map[string]any{"format": 1, "questions": []map[string]string{
		{"id": "firewall", "answer": "opnsense 10.0.0.1"}, {"id": "site", "answer": "lisbon"}}})
	file, err := ReadPlan(path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := FromFile(Detect(m.env_()), file, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, q := range p.Questions {
		got[q.ID] = q.Answer
	}
	if got["firewall"] != "opnsense 10.0.0.1" || got["site"] != "lisbon" {
		t.Fatalf("answers: %v", got)
	}
	if !strings.Contains(strings.Join(p.Warnings, "|"), "answers site") {
		t.Error("an answer to a question not asked here should be reported")
	}
}

func TestPlanFileFormatIsChecked(t *testing.T) {
	if _, err := ReadPlan(writePlanFile(t, map[string]any{"format": 99})); err == nil || !strings.Contains(err.Error(), "format 99") {
		t.Fatalf("unknown format accepted: %v", err)
	}
}

// ---------------------------------------------------------------- uninstall

func (b *applyBed) uninstall(t *testing.T, purge bool) (UninstallPlan, error) {
	t.Helper()
	f := Detect(b.env)
	u, err := PlanUninstall(b.env, f, purge)
	if err != nil {
		return u, err
	}
	b.applying = true
	defer func() { b.applying = false }()
	return u, Uninstall(b.env, u, func(string) {})
}

func (b *applyBed) exists(p string) bool {
	_, err := os.Stat(b.env.path(p))
	return err == nil
}

func TestUninstallAFreshInstallLeavesOnlyTheConfiguration(t *testing.T) {
	b := newApplyBed(t, "linux", debianRoot)
	if _, err := b.apply(t); err != nil {
		t.Fatal(err)
	}
	b.cmds = nil
	u, err := b.uninstall(t, false)
	if err != nil {
		t.Fatal(err)
	}
	if b.exists(binaryPath) || b.exists(unitPath) {
		t.Fatal("the binary or the unit is still there")
	}
	if !b.exists("/etc/flowsight/flowsight.json") || !b.exists("/var/lib/flowsight") {
		t.Fatal("the configuration and data are kept unless purged")
	}
	if !b.exists("/var/lib/flowsight/install.json.uninstalled") || b.exists("/var/lib/flowsight/install.json") {
		t.Fatal("the install record should be kept aside")
	}
	if !strings.Contains(strings.Join(b.cmds, "|"), "systemctl disable --now flowsight") {
		t.Fatalf("service not stopped: %v", b.cmds)
	}
	if len(u.Keeps) == 0 {
		t.Error("what is kept should be said")
	}
	// A second uninstall finds no record.
	if _, err := PlanUninstall(b.env, Detect(b.env), false); err == nil {
		t.Fatal("an uninstalled machine has nothing left to uninstall")
	}
}

func TestUninstallPurgeRemovesEverything(t *testing.T) {
	b := newApplyBed(t, "linux", debianRoot)
	if _, err := b.apply(t); err != nil {
		t.Fatal(err)
	}
	if _, err := b.uninstall(t, true); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{binaryPath, unitPath, "/etc/flowsight", "/var/lib/flowsight", "/var/log/flowsight"} {
		if b.exists(p) {
			t.Errorf("%s survived a purge", p)
		}
	}
}

// What the first install replaced comes back, even after later runs made
// their own backups.
func TestUninstallRestoresWhatTheFirstInstallReplaced(t *testing.T) {
	b := newApplyBed(t, "linux", func(m *fakeMachine) {
		debianRoot(m)
		m.files[binaryPath] = "the build that was here before"
		m.files[unitPath] = "[Unit]\nDescription=hand-written\n"
	})
	if _, err := b.apply(t); err != nil {
		t.Fatal(err)
	}
	// A second install with another build replaces the binary again.
	if err := os.WriteFile(b.exe, []byte("an even newer build"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := MakePlan(Detect(b.env), time.Now())
	if _, err := Apply(b.env, p, "0.9.8-test2", time.Date(2026, 9, 27, 1, 0, 0, 0, time.UTC), func(string) {}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.uninstall(t, false); err != nil {
		t.Fatal(err)
	}
	if got := b.read(t, binaryPath); got != "the build that was here before" {
		t.Fatalf("binary after uninstall: %q", got)
	}
	if !strings.Contains(b.read(t, unitPath), "hand-written") {
		t.Fatal("the hand-written unit was not restored")
	}
	entries, _ := os.ReadDir(b.env.path("/usr/local/sbin"))
	for _, e := range entries {
		if strings.Contains(e.Name(), "flowsight-backup") || strings.HasSuffix(e.Name(), ".previous") {
			t.Errorf("backup left behind: %s", e.Name())
		}
	}
}

// Redirects are withdrawn before the service stops: the other order can
// leave traffic pointed at a proxy that is gone.
func TestUninstallWithdrawsBeforeStopping(t *testing.T) {
	b := newApplyBed(t, "freebsd", func(m *fakeMachine) {
		m.files["/dev/pf"] = ""
		m.files["/usr/local/etc/flowsight/squid/squid.conf"] = "http_port 3128\n"
		m.files["/usr/local/etc/unbound/conf.d/flowsight-policy.conf"] = "server:\n"
	})
	if _, err := b.apply(t); err != nil {
		t.Fatal(err)
	}
	b.cmds = nil
	if _, err := b.uninstall(t, false); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(b.cmds, "|")
	flush := strings.Index(all, "pfctl -a flowsight -F all")
	squid := strings.Index(all, "squid -k shutdown")
	stop := strings.Index(all, "service flowsight stop")
	if flush < 0 || squid < 0 || stop < 0 || flush > stop || squid > stop {
		t.Fatalf("withdraw must come before stop: %v", b.cmds)
	}
	if b.exists("/usr/local/etc/unbound/conf.d/flowsight-policy.conf") {
		t.Fatal("the resolver include was left in place")
	}
	if !strings.Contains(all, "sysrc -q -x flowsight_enable") {
		t.Fatalf("service not disabled: %v", b.cmds)
	}
}

func TestUninstallRefusesAPackagedInstall(t *testing.T) {
	b := newApplyBed(t, "linux", func(m *fakeMachine) {
		debianRoot(m)
		m.files[binaryPath] = "package build"
		m.files[unitPath] = "[Unit]\n"
	})
	if _, err := b.applyPackaged(t); err != nil {
		t.Fatal(err)
	}
	_, err := PlanUninstall(b.env, Detect(b.env), false)
	if err == nil || !strings.Contains(err.Error(), "apt remove flowsight") {
		t.Fatalf("a packaged install must be left to the package manager: %v", err)
	}
	if !b.exists(binaryPath) {
		t.Fatal("nothing may be removed")
	}
}

// Without Unbound installed, the include directory the DNS module created is
// removed once empty; with Unbound installed it belongs to Unbound and stays.
// Found on the test client, where -purge left /etc/unbound behind.
func TestUninstallRemovesResolverDirectoriesOnlyFlowSightMade(t *testing.T) {
	b := newApplyBed(t, "linux", debianRoot)
	if _, err := b.apply(t); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(b.env.path("/etc/unbound/unbound.conf.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b.env.path("/etc/unbound/unbound.conf.d/flowsight-policy.conf"), []byte("server:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := b.uninstall(t, true); err != nil {
		t.Fatal(err)
	}
	if b.exists("/etc/unbound") {
		t.Fatal("the resolver directories FlowSight made were left behind")
	}

	b = newApplyBed(t, "linux", func(m *fakeMachine) {
		debianRoot(m)
		m.files["/usr/sbin/unbound"] = ""
		m.files["/etc/unbound/unbound.conf"] = "server:\n"
	})
	if _, err := b.apply(t); err != nil {
		t.Fatal(err)
	}
	if _, err := b.uninstall(t, true); err != nil {
		t.Fatal(err)
	}
	if !b.exists("/etc/unbound/unbound.conf") {
		t.Fatal("Unbound's own directory was touched")
	}
}

// A package's removal script withdraws FlowSight's resolver files without an
// install record. apt remove used to leave them, so Unbound went on blocking
// after FlowSight was gone.
func TestWithdrawForAPackageRemoval(t *testing.T) {
	b := newApplyBed(t, "linux", func(m *fakeMachine) {
		debianRoot(m)
		m.files["/usr/sbin/unbound"] = ""
		m.files["/etc/unbound/unbound.conf.d/flowsight-policy.conf"] = "server:\n"
		m.files["/etc/unbound/unbound.conf.d/flowsight-kids.rpz"] = "$TTL 300\n"
		m.files["/etc/unbound/unbound.conf.d/other.conf"] = "server:\n"
		m.files[binaryPath] = "package build"
	})
	u, err := PlanWithdraw(b.env, Detect(b.env))
	if err != nil {
		t.Fatal(err)
	}
	b.applying = true
	if err := Uninstall(b.env, u, func(string) {}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/etc/unbound/unbound.conf.d/flowsight-policy.conf", "/etc/unbound/unbound.conf.d/flowsight-kids.rpz"} {
		if b.exists(p) {
			t.Errorf("%s left in place", p)
		}
	}
	if !b.exists("/etc/unbound/unbound.conf.d/other.conf") || !b.exists(binaryPath) {
		t.Fatal("withdraw touched something that is not FlowSight's resolver file")
	}
	if !strings.Contains(strings.Join(b.cmds, "|"), "unbound-control reload") {
		t.Fatalf("the resolver must be reloaded: %v", b.cmds)
	}
}

// On a Linux gateway FlowSight's rules are one nftables table; withdrawing
// deletes it before the service stops.
func TestWithdrawDeletesTheNftablesTable(t *testing.T) {
	b := newApplyBed(t, "linux", func(m *fakeMachine) {
		debianRoot(m)
		m.bins["nft"] = true
	})
	u, err := PlanWithdraw(b.env, Detect(b.env))
	if err != nil {
		t.Fatal(err)
	}
	b.applying = true
	if err := Uninstall(b.env, u, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(b.cmds, "|"), "nft delete table inet flowsight") {
		t.Fatalf("commands: %v", b.cmds)
	}
}
