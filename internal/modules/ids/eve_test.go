package ids

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/grioghar/flowsight/internal/core"
)

const alert = `{"timestamp":"2026-09-27T17:00:00.000000+0000","event_type":"alert","src_ip":"10.98.0.20","src_port":40000,"dest_ip":"203.0.113.9","dest_port":80,"proto":"TCP","alert":{"signature_id":1,"signature":"lab","category":"test","severity":2}}`

func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
}

// pfSense's Suricata package writes one EVE log per interface; every one
// is read, and one added later is read from its start.
func TestEveLogsByPattern(t *testing.T) {
	dir := t.TempDir()
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"suricata_vtnet1_1", "suricata_vtnet2_2", "suricata_vtnet3_3"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	a, b := filepath.Join(dir, "suricata_vtnet1_1", "eve.json"), filepath.Join(dir, "suricata_vtnet2_2", "eve.json")
	appendLine(t, a, alert) // before the first poll: history, skipped
	appendLine(t, b, alert)
	m := &Module{evePath: filepath.Join(dir, "*", "eve.json"), tails: map[string]*core.Tailer{},
		ctx: &core.Context{Core: &core.Core{Services: map[string]any{}}, Name: "ids", Store: store, Config: &core.Config{}}}
	if err := m.poll(); err != nil {
		t.Fatal(err)
	}
	if m.alerts != 0 || m.localMissing {
		t.Fatalf("history must be skipped and the logs found: alerts %d, missing %v", m.alerts, m.localMissing)
	}
	appendLine(t, a, alert)
	appendLine(t, b, alert)
	c := filepath.Join(dir, "suricata_vtnet3_3", "eve.json")
	appendLine(t, c, alert) // a new interface's log, after the first poll
	if err := m.poll(); err != nil {
		t.Fatal(err)
	}
	if m.alerts != 3 {
		t.Fatalf("one new alert per interface, the new log from its start: got %d", m.alerts)
	}
}

func TestNoEveLogIsMissingNotAnError(t *testing.T) {
	m := &Module{evePath: filepath.Join(t.TempDir(), "*", "eve.json"), tails: map[string]*core.Tailer{}}
	if err := m.poll(); err != nil || !m.localMissing || m.lastErr != "" {
		t.Fatalf("err %v, missing %v, lastErr %q", err, m.localMissing, m.lastErr)
	}
}
