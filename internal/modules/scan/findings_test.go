package scan

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func openScanFindings(t *testing.T, st *core.Store) map[string]string {
	t.Helper()
	rows, err := st.Rows(`SELECT fingerprint, attrs FROM findings WHERE module='scan' AND resolved_ts IS NULL`)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range rows {
		a, _ := r["attrs"].(string)
		out[r["fingerprint"].(string)] = a
	}
	return out
}

// A scan that finds telnet raises it with who and where; a later scan that
// covered port 23 and found it closed closes it; an identify scan, which
// probes other ports, leaves it alone.
func TestScanFindingsCarryAttrsAndCloseOnRescan(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := core.New("0.9.8r000000000000", "", t.TempDir(), nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	c.LoadModules()
	m, ok := c.Modules["scan"].(*Module)
	if !ok {
		t.Fatal("scan module not loaded")
	}
	st := m.ctx.Store
	job := func(profile string, ports ...PortInfo) *scanJob {
		return &scanJob{IP: "192.168.1.30", Profile: profile, Result: &ScanResult{IP: "192.168.1.30", MAC: "aa:bb:cc:dd:ee:ff",
			Finished: time.Now(), OpenPorts: ports}}
	}
	m.emitFindings(job("quick", PortInfo{Port: 23, Protocol: "tcp", Banner: "login:"}, PortInfo{Port: 21, Protocol: "tcp"}))
	open := openScanFindings(t, st)
	a, ok := open["telnet_192.168.1.30_23"]
	if !ok || len(open) != 1 {
		t.Fatalf("telnet only (FTP without a banner says too little): %v", open)
	}
	for _, want := range []string{`"mac":"aa:bb:cc:dd:ee:ff"`, `"port":23`, `banner: login:`} {
		if !strings.Contains(a, want) {
			t.Fatalf("attrs missing %s: %s", want, a)
		}
	}
	m.emitFindings(job("identify"))
	if _, ok := openScanFindings(t, st)["telnet_192.168.1.30_23"]; !ok {
		t.Fatal("an identify scan must not close it")
	}
	m.emitFindings(job("quick"))
	if len(openScanFindings(t, st)) != 0 {
		t.Fatal("a quick scan covering port 23 that finds it closed should close the finding")
	}
}
