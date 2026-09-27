package core

import "testing"

// An address that moves to another device must not carry the previous
// device's maker, name or type: on 2026-09-27 a Mac that took over a
// Roborock vacuum's old lease was shown as "Beijing Roborock" and scanned
// as a vacuum.
func TestHostIdentityResetsWhenAddressChangesHands(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertHosts([]HostUpdate{{IP: "192.168.1.98", MAC: "b0:4a:39:ab:37:a1", Vendor: "Beijing Roborock Technology Co., Ltd.",
		Name: "roborock-vacuum-a72", DeviceType: "iot", OS: "Linux"}}); err != nil {
		t.Fatal(err)
	}
	// The same device again with nothing new keeps what is known.
	_ = s.UpsertHosts([]HostUpdate{{IP: "192.168.1.98", MAC: "b0:4a:39:ab:37:a1", Flows: 1}})
	if r, _ := s.Rows(`SELECT vendor, name FROM hosts WHERE ip='192.168.1.98'`); r[0]["vendor"] == nil || r[0]["name"] == nil {
		t.Fatalf("same device lost its identity: %v", r)
	}
	// A Mac with a private address takes the lease.
	_ = s.UpsertHosts([]HostUpdate{{IP: "192.168.1.98", MAC: "9a:af:f2:0d:2d:c6"}})
	r, _ := s.Rows(`SELECT mac, vendor, name, device_type, os FROM hosts WHERE ip='192.168.1.98'`)
	if r[0]["mac"] != "9a:af:f2:0d:2d:c6" || r[0]["vendor"] != nil || r[0]["name"] != nil || r[0]["device_type"] != nil || r[0]["os"] != nil {
		t.Fatalf("the new device inherited the old one's identity: %v", r)
	}
	// A maker name offered for a private address is refused.
	_ = s.UpsertHosts([]HostUpdate{{IP: "192.168.1.98", MAC: "9a:af:f2:0d:2d:c6", Vendor: "Beijing Roborock Technology Co., Ltd."}})
	if r, _ := s.Rows(`SELECT vendor FROM hosts WHERE ip='192.168.1.98'`); r[0]["vendor"] != nil {
		t.Fatalf("private address given a maker: %v", r)
	}
	_ = s.UpsertHosts([]HostUpdate{{IP: "192.168.1.98", MAC: "9a:af:f2:0d:2d:c6", Vendor: "Apple (private address)"}})
	if r, _ := s.Rows(`SELECT vendor FROM hosts WHERE ip='192.168.1.98'`); r[0]["vendor"] != "Apple (private address)" {
		t.Fatalf("a private-address guess is allowed: %v", r)
	}
}

// Rows already carrying a maker on a private address are repaired at start.
func TestMigrateClearsMakerOnPrivateAddresses(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO hosts(ip,mac,vendor) VALUES('192.168.1.98','9a:af:f2:0d:2d:c6','Beijing Roborock Technology Co., Ltd.')`,
		`INSERT INTO hosts(ip,mac,vendor) VALUES('192.168.1.99','b0:4a:39:ab:37:a1','Beijing Roborock Technology Co., Ltd.')`,
		`INSERT INTO hosts(ip,mac,vendor) VALUES('192.168.1.78','02:ea:e6:3d:7b:b5','Apple (private address)')`,
		`INSERT INTO devices(mac,vendor) VALUES('9a:af:f2:0d:2d:c6','Beijing Roborock Technology Co., Ltd.')`,
	} {
		if err := s.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.migrate(); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"192.168.1.98": nil, "192.168.1.99": "Beijing Roborock Technology Co., Ltd.", "192.168.1.78": "Apple (private address)"}
	rows, _ := s.Rows(`SELECT ip, vendor FROM hosts`)
	for _, r := range rows {
		if r["vendor"] != want[r["ip"].(string)] {
			t.Errorf("%v: vendor %v, want %v", r["ip"], r["vendor"], want[r["ip"].(string)])
		}
	}
	if d, _ := s.Rows(`SELECT vendor FROM devices`); d[0]["vendor"] != "" {
		t.Errorf("device vendor not cleared: %v", d)
	}
	for mac, want := range map[string]bool{"9a:af:f2:0d:2d:c6": true, "02:ea:e6:3d:7b:b5": true, "b0:4a:39:ab:37:a1": false, "bc:24:11:46:c1:5f": false, "": false} {
		if LocallyAdministered(mac) != want {
			t.Errorf("LocallyAdministered(%q) != %v", mac, want)
		}
	}
}
