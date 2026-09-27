package install

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// applyBed is a fake machine to apply to, with a binary to install, a
// command log and a daemon health answer.
type applyBed struct {
	m        *fakeMachine
	env      Env
	cmds     []string // commands run by Apply; detection's read-only queries are not recorded
	applying bool
	health   string // JSON the daemon answers with; "" for no answer
	exe      string
	exeBytes []byte
}

func newApplyBed(t *testing.T, goos string, setup func(m *fakeMachine)) *applyBed {
	m := machine(t, goos)
	setup(m)
	b := &applyBed{m: m, health: `{"modules":{"dns":{"ok":true},"web":{"ok":true}}}`}
	b.env = m.env_()
	b.exe = filepath.Join(t.TempDir(), "flowsightd")
	b.exeBytes = []byte("new flowsightd build")
	if err := os.WriteFile(b.exe, b.exeBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	b.env.Exe = b.exe
	b.env.Run = func(name string, args ...string) (string, error) {
		if b.applying {
			b.cmds = append(b.cmds, strings.TrimSpace(name+" "+strings.Join(args, " ")))
		}
		return "", nil
	}
	b.env.Get = func(url string, hdr map[string]string) (int, []byte, error) {
		if b.health == "" {
			return 0, nil, errors.New("connection refused")
		}
		return 200, []byte(b.health), nil
	}
	b.env.Sleep = func(time.Duration) {}
	return b
}

func (b *applyBed) read(t *testing.T, p string) string {
	t.Helper()
	c, err := os.ReadFile(b.env.path(p))
	if err != nil {
		t.Fatalf("reading %s: %v", p, err)
	}
	return string(c)
}

func (b *applyBed) apply(t *testing.T) (Result, error) {
	t.Helper()
	// Detection runs against the fake machine's files; its commands are the
	// bed's recorder, which answers nothing, so only file facts count.
	p := MakePlan(Detect(b.env), time.Now())
	b.applying = true
	defer func() { b.applying = false }()
	return Apply(b.env, p, "0.9.8-test", time.Date(2026, 9, 26, 22, 0, 0, 0, time.UTC), func(string) {})
}

func debianRoot(m *fakeMachine) {
	m.files["/etc/os-release"] = "ID=debian\nVERSION_ID=\"13\"\n"
}

func actions(r Result) map[string]string {
	out := map[string]string{}
	for _, f := range r.Files {
		out[f.Path] = f.Action
	}
	return out
}

func TestApplyFreshLinux(t *testing.T) {
	b := newApplyBed(t, "linux", debianRoot)
	r, err := b.apply(t)
	if err != nil {
		t.Fatal(err)
	}
	a := actions(r)
	if a[binaryPath] != "created" || a[unitPath] != "created" || a["/etc/flowsight/flowsight.json"] != "created" {
		t.Fatalf("fresh install: %+v", r.Files)
	}
	if got := b.read(t, binaryPath); got != string(b.exeBytes) {
		t.Fatal("the running binary was not installed")
	}
	st, _ := os.Stat(b.env.path("/etc/flowsight/flowsight.json"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("the configuration holds the token and must be root-only, got %v", st.Mode().Perm())
	}
	var cfg map[string]string
	_ = json.Unmarshal([]byte(b.read(t, "/etc/flowsight/flowsight.json")), &cfg)
	if len(cfg["api_token"]) != 32 {
		t.Fatalf("token: %q", cfg["api_token"])
	}
	want := []string{"systemctl daemon-reload", "systemctl enable flowsight", "systemctl restart flowsight"}
	if strings.Join(b.cmds, "|") != strings.Join(want, "|") {
		t.Fatalf("commands: %v", b.cmds)
	}
	if r.Verify == nil || !r.Verify.Answering || r.Verify.Modules != 2 {
		t.Fatalf("verify: %+v", r.Verify)
	}
	for _, d := range []string{"/var/lib/flowsight", "/var/log/flowsight"} {
		if _, err := os.Stat(b.env.path(d)); err != nil {
			t.Errorf("directory %s not created", d)
		}
	}
	var runs []Result
	if err := json.Unmarshal([]byte(b.read(t, "/var/lib/flowsight/install.json")), &runs); err != nil || len(runs) != 1 {
		t.Fatalf("manifest: %v %d", err, len(runs))
	}
}

// Running it again changes nothing and keeps the configuration.
func TestApplyAgainChangesNothing(t *testing.T) {
	b := newApplyBed(t, "linux", debianRoot)
	if _, err := b.apply(t); err != nil {
		t.Fatal(err)
	}
	tok := b.read(t, "/etc/flowsight/flowsight.json")
	r, err := b.apply(t)
	if err != nil {
		t.Fatal(err)
	}
	a := actions(r)
	if a[binaryPath] != "unchanged" || a[unitPath] != "unchanged" || a["/etc/flowsight/flowsight.json"] != "kept" {
		t.Fatalf("second run: %+v", r.Files)
	}
	if b.read(t, "/etc/flowsight/flowsight.json") != tok {
		t.Fatal("the configuration was rewritten")
	}
	var runs []Result
	_ = json.Unmarshal([]byte(b.read(t, "/var/lib/flowsight/install.json")), &runs)
	if len(runs) != 2 {
		t.Fatalf("each run is recorded: %d", len(runs))
	}
}

// Replacing a binary or a unit keeps what was there.
func TestApplyKeepsWhatItReplaces(t *testing.T) {
	b := newApplyBed(t, "linux", func(m *fakeMachine) {
		debianRoot(m)
		m.files[binaryPath] = "old build"
		m.files[unitPath] = "[Unit]\nDescription=hand-written\n"
	})
	r, err := b.apply(t)
	if err != nil {
		t.Fatal(err)
	}
	var unitBackup string
	for _, f := range r.Files {
		switch f.Path {
		case binaryPath:
			if f.Action != "replaced" || b.read(t, f.Backup) != "old build" {
				t.Fatalf("binary: %+v", f)
			}
		case unitPath:
			unitBackup = f.Backup
		}
	}
	if unitBackup == "" || !strings.Contains(b.read(t, unitBackup), "hand-written") {
		t.Fatalf("the replaced unit was not kept: %q", unitBackup)
	}
}

// On FreeBSD pf.conf is read, never written, and a missing anchor is
// reported with the lines to add.
func TestApplyFreeBSDNeverEditsPFConf(t *testing.T) {
	const pfconf = "set skip on lo0\npass all\n"
	b := newApplyBed(t, "freebsd", func(m *fakeMachine) {
		m.files["/dev/pf"] = ""
		m.files["/etc/pf.conf"] = pfconf
	})
	// A router, so the plan includes the anchor check.
	b.env.Run = func(name string, args ...string) (string, error) {
		c := strings.TrimSpace(name + " " + strings.Join(args, " "))
		if b.applying {
			b.cmds = append(b.cmds, c)
		}
		if c == "sysctl -n net.inet.ip.forwarding" {
			return "1", nil
		}
		return "", nil
	}
	r, err := b.apply(t)
	if err != nil {
		t.Fatal(err)
	}
	if b.read(t, "/etc/pf.conf") != pfconf {
		t.Fatal("pf.conf was modified")
	}
	if actions(r)[rcPath] != "created" || !strings.Contains(strings.Join(b.cmds, "|"), "sysrc -q flowsight_enable=YES") {
		t.Fatalf("rc.d service: %+v %v", r.Files, b.cmds)
	}
	if !strings.Contains(strings.Join(r.Notes, "|"), `anchor "flowsight/*"`) {
		t.Fatalf("missing anchors must be reported: %v", r.Notes)
	}
}

func TestApplyOPNsenseNeedsThePackage(t *testing.T) {
	b := newApplyBed(t, "freebsd", func(m *fakeMachine) {
		m.files["/usr/local/sbin/opnsense-version"] = ""
		m.files["/dev/pf"] = ""
	})
	if _, err := b.apply(t); err == nil || !strings.Contains(err.Error(), "os-flowsight package") {
		t.Fatalf("without the package: %v", err)
	}
	if _, err := os.Stat(b.env.path(binaryPath)); err == nil {
		t.Fatal("the binary must come from the package on OPNsense")
	}

	b = newApplyBed(t, "freebsd", func(m *fakeMachine) {
		m.files["/usr/local/sbin/opnsense-version"] = ""
		m.files["/dev/pf"] = ""
		m.files["/usr/local/etc/flowsight/flowsight.json"] = `{"api_token":"x"}`
		m.files[binaryPath] = "package build"
	})
	r, err := b.apply(t)
	if err != nil {
		t.Fatal(err)
	}
	if b.read(t, binaryPath) != "package build" || actions(r)["/usr/local/etc/flowsight/flowsight.json"] != "kept" {
		t.Fatalf("with the package: %+v", r.Files)
	}
	if !strings.Contains(strings.Join(b.cmds, "|"), "service flowsight restart") {
		t.Fatalf("commands: %v", b.cmds)
	}
}

func TestApplyRefusesWithoutRoot(t *testing.T) {
	b := newApplyBed(t, "linux", func(m *fakeMachine) { debianRoot(m); m.uid = 1000 })
	if _, err := b.apply(t); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("not root: %v", err)
	}
	if _, err := os.Stat(b.env.path(binaryPath)); err == nil || len(b.cmds) != 0 {
		t.Fatal("nothing may be changed without root")
	}
}

func TestVerifyReportsDegradedAndSilentDaemons(t *testing.T) {
	b := newApplyBed(t, "linux", debianRoot)
	b.health = `{"modules":{"dns":{"ok":true},"web":{"ok":false,"detail":"squid is not installed"}}}`
	r, err := b.apply(t)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verify.Degraded["web"] != "squid is not installed" || !strings.Contains(r.Summary(), "1 not well") {
		t.Fatalf("degraded: %+v\n%s", r.Verify, r.Summary())
	}
	b = newApplyBed(t, "linux", debianRoot)
	b.health = ""
	r, _ = b.apply(t)
	if r.Verify == nil || r.Verify.Answering || !strings.Contains(r.Summary(), "did not answer") {
		t.Fatalf("silent daemon: %+v", r.Verify)
	}
}

// The rc script's start is one command continued over two lines. A doubled
// backslash parses (sh -n is happy) but ends the command early and runs
// flowsightd in the foreground on its own line.
func TestRCScriptStartsThroughTheSupervisor(t *testing.T) {
	joined := strings.ReplaceAll(rcScript, "\\\n", " ")
	var start string
	for _, line := range strings.Split(joined, "\n") {
		if strings.Contains(line, "/usr/sbin/daemon -f") {
			start = line
		}
	}
	if !strings.Contains(start, "${procname} -config /usr/local/etc/flowsight/flowsight.json") || strings.Contains(start, `\`) {
		t.Fatalf("daemon(8) must be given flowsightd on the same logical line: %q", start)
	}
	for _, need := range []string{"stop_cmd=flowsight_stop", "status_cmd=flowsight_status", "kill -TERM"} {
		if !strings.Contains(rcScript, need) {
			t.Errorf("rc script lacks %q: stop must act on the supervisor", need)
		}
	}
}
