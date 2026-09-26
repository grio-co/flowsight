package dns

// A DNS-block policy must survive the resolver restarting. On OPNsense,
// every Unbound start empties /var/unbound/etc and copies back only *.conf
// from unbound.opnsense.d, so a zone file kept beside the include vanished
// while the include naming it came back, and Unbound refused to start. The
// reconciler then tried to reload a stopped Unbound, failed, reverted, and
// DNS stayed down. These tests run the real provider against a simulated
// OPNsense: its start script, its control program and its configctl.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grioghar/flowsight/internal/core"
)

type fakeOPNsense struct {
	root, live, persist, zones string
	pl                         *core.Platform
}

// A shell script standing in for OPNsense's unbound start.sh plus unbound
// itself: empty the live directory, copy back *.conf, then refuse to run
// when an include names a zone file that does not exist.
const fakeStart = `#!/bin/sh
set -e
R="$(dirname "$0")"
rm -f "$R/live/"*
cp "$R/persist/"*.conf "$R/live/" 2>/dev/null || true
for z in $(grep -ho 'zonefile: "[^"]*"' "$R/live/"*.conf 2>/dev/null | sed 's/zonefile: "//; s/"$//'); do
	if [ ! -f "$z" ]; then echo "cannot open zonefile $z" >&2; rm -f "$R/running"; exit 1; fi
done
touch "$R/running"
`

// configctl: "unbound start" runs the start script; anything else succeeds.
const fakeConfigctl = `#!/bin/sh
R="$(dirname "$0")"
echo "$*" >> "$R/configctl.log"
if [ "$1 $2" = "unbound start" ]; then exec "$R/start.sh"; fi
exit 0
`

// unbound-control: status is the running flag; reload needs it too.
const fakeControl = `#!/bin/sh
R="$(dirname "$0")"
for a in "$@"; do last="$a"; done
case "$last" in
status) [ -f "$R/running" ] && exit 0; echo "unbound is stopped"; exit 3 ;;
reload) [ -f "$R/running" ] && exit 0; echo "connect: Connection refused"; exit 1 ;;
esac
exit 0
`

func newFakeOPNsense(t *testing.T, enabled bool) *fakeOPNsense {
	t.Helper()
	root := t.TempDir()
	f := &fakeOPNsense{root: root, live: filepath.Join(root, "live"), persist: filepath.Join(root, "persist"),
		zones: filepath.Join(root, "zones")}
	for _, d := range []string{f.live, f.persist} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, text := range map[string]string{"start.sh": fakeStart, "configctl": fakeConfigctl, "unbound-control": fakeControl} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(text), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	flag := "0"
	if enabled {
		flag = "1"
	}
	cfg := `<?xml version="1.0"?><opnsense><OPNsense><unboundplus><general><enabled>` + flag +
		`</enabled></general></unboundplus></OPNsense></opnsense>`
	if err := os.WriteFile(filepath.Join(root, "config.xml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	f.pl = &core.Platform{Name: "opnsense", Family: "freebsd",
		UnboundControl: filepath.Join(root, "unbound-control"), UnboundInclude: filepath.Join(f.live, "flowsight-policy.conf"),
		UnboundPersistDir: f.persist, UnboundZoneDir: f.zones,
		Configctl: filepath.Join(root, "configctl"), ConfigXML: filepath.Join(root, "config.xml")}
	return f
}

func (f *fakeOPNsense) running() bool {
	_, err := os.Stat(filepath.Join(f.root, "running"))
	return err == nil
}

// restart is what the GUI or a reboot does to Unbound.
func (f *fakeOPNsense) restart(t *testing.T) error {
	t.Helper()
	_, err := core.Run(10e9, f.pl.Configctl, "unbound", "start")
	return err
}

func blockDoc() *core.PolicyDoc {
	return &core.PolicyDoc{Policies: []core.Policy{{
		Name: "Kids web", Enabled: true, Action: "block",
		Match: core.Match{Members: []string{"10.99.0.0/24"}},
		Deny:  core.Deny{Domains: []string{"example.com"}},
	}}}
}

func newProvider(t *testing.T, pl *core.Platform) *provider {
	t.Helper()
	cfg, err := core.LoadConfig(filepath.Join(t.TempDir(), "flowsight.json"))
	if err != nil {
		t.Fatal(err)
	}
	return &provider{m: &Module{ctx: &core.Context{Core: &core.Core{Services: map[string]any{}}, Name: "dns", Config: cfg, Platform: pl}}}
}

func TestBlockPolicySurvivesUnboundRestart(t *testing.T) {
	f := newFakeOPNsense(t, true)
	if err := f.restart(t); err != nil {
		t.Fatalf("unbound should start with no FlowSight policy: %v", err)
	}
	p := newProvider(t, f.pl)
	art, err := p.Compile(blockDoc())
	if err != nil {
		t.Fatal(err)
	}
	for path := range art.Files {
		if strings.HasSuffix(path, ".rpz") && filepath.Dir(path) != f.zones {
			t.Fatalf("zone file compiled into %s, which the resolver empties on restart", filepath.Dir(path))
		}
	}
	if _, err := p.Apply(art); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := f.restart(t); err != nil {
		t.Fatalf("unbound must start again after a restart with the policy in place: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(f.live, "flowsight-policy.conf")); err != nil || !strings.Contains(string(b), f.zones) {
		t.Fatalf("include missing after restart or not naming the zone directory: %v %q", err, b)
	}
}

// A resolver that is down but enabled is started, not reloaded: reloading
// it could only fail, and the revert on that failure kept DNS down.
func TestApplyStartsAStoppedEnabledUnbound(t *testing.T) {
	f := newFakeOPNsense(t, true)
	p := newProvider(t, f.pl)
	art, err := p.Compile(blockDoc())
	if err != nil {
		t.Fatal(err)
	}
	note, err := p.Apply(art)
	if err != nil {
		t.Fatalf("apply on a stopped, enabled resolver: %v", err)
	}
	if !f.running() || !strings.Contains(note, "started") {
		t.Fatalf("unbound should have been started, note %q", note)
	}
}

// A resolver the operator switched off stays off.
func TestApplyNeverStartsADisabledUnbound(t *testing.T) {
	f := newFakeOPNsense(t, false)
	p := newProvider(t, f.pl)
	art, err := p.Compile(blockDoc())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Apply(art); err != nil {
		t.Fatalf("apply on a disabled resolver: %v", err)
	}
	if f.running() {
		t.Fatal("FlowSight started a resolver the operator had disabled")
	}
	if b, _ := os.ReadFile(filepath.Join(f.root, "configctl.log")); strings.Contains(string(b), "start") {
		t.Fatalf("configctl was asked to start unbound: %q", b)
	}
}

// Zone files older versions left in the include directories are removed
// once the policy is written the new way.
func TestOldZoneFilesAreCleanedUp(t *testing.T) {
	f := newFakeOPNsense(t, true)
	for _, d := range []string{f.live, f.persist} {
		if err := os.WriteFile(filepath.Join(d, "flowsight-kids-web.rpz"), []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(f.persist, "flowsight-logging.conf"), []byte("server:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := newProvider(t, f.pl)
	art, err := p.Compile(blockDoc())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Apply(art); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{f.live, f.persist} {
		if _, err := os.Stat(filepath.Join(d, "flowsight-kids-web.rpz")); err == nil {
			t.Errorf("old zone file left in %s", d)
		}
	}
	if _, err := os.Stat(filepath.Join(f.persist, "flowsight-logging.conf")); err != nil {
		t.Error("flowsight-logging.conf is not the policy provider's to remove")
	}
	if _, err := os.Stat(filepath.Join(f.zones, "flowsight-kids-web.rpz")); err != nil {
		t.Errorf("new zone file missing: %v", err)
	}
}
