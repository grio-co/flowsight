package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPfSenseIsRecognised(t *testing.T) {
	dir := t.TempDir()
	for content, want := range map[string]bool{"pfSense\n": true, "pfSense": true, "OPNsense\n": false, "": false} {
		p := filepath.Join(dir, "platform")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := isPfSense(p); got != want {
			t.Errorf("/etc/platform %q: %v, want %v", content, got, want)
		}
	}
	if isPfSense(filepath.Join(dir, "missing")) {
		t.Error("no platform file is not pfSense")
	}
}

// The layout found on pfSense CE 2.7.2.
func TestPfSenseLayout(t *testing.T) {
	p := pfsense()
	if !p.IsPfSense() || p.IsOPNsense() || p.Family != "freebsd" || p.Firewall != "pf" {
		t.Fatalf("identity: %+v", p)
	}
	for got, want := range map[string]string{
		p.UnboundConfig: "/var/unbound/unbound.conf", p.UnboundInclude: "/var/unbound/flowsight/flowsight-policy.conf",
		p.UnboundLog: "/var/log/resolver.log", p.ConfigXML: "/cf/conf/config.xml", p.Configctl: "",
		p.UnboundPersistDir: "", p.DHCPLeases[0]: "/var/dhcpd/var/db/dhcpd.leases", p.SuricataEve: "/var/log/suricata/*/eve.json",
	} {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func TestPfSenseUnboundEnabled(t *testing.T) {
	dir := t.TempDir()
	p := pfsense()
	p.ConfigXML = filepath.Join(dir, "config.xml")
	for xml, want := range map[string]bool{
		`<?xml version="1.0"?><pfsense><unbound><enable></enable><port></port></unbound></pfsense>`: true,
		`<?xml version="1.0"?><pfsense><unbound><port></port></unbound></pfsense>`:                  false,
		`<?xml version="1.0"?><pfsense></pfsense>`:                                                  false,
	} {
		if err := os.WriteFile(p.ConfigXML, []byte(xml), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := p.UnboundEnabled(); got != want {
			t.Errorf("%s: %v, want %v", xml, got, want)
		}
	}
}
