package scan

import "testing"

// A private hardware address with a maker name that came from another
// device is not identified by that maker.
func TestPrivateAddressIgnoresRegisteredMaker(t *testing.T) {
	inv := privateVendor("9a:af:f2:0d:2d:c6", inventory{Vendor: "Beijing Roborock Technology Co., Ltd."})
	for _, g := range identify(&ScanResult{MAC: "9a:af:f2:0d:2d:c6"}, inv) {
		if g.OS == "Roborock vacuum" {
			t.Fatalf("private address identified by a registered maker: %+v", g)
		}
	}
	real := privateVendor("b0:4a:39:ab:37:a1", inventory{Vendor: "Beijing Roborock Technology Co., Ltd."})
	found := false
	for _, g := range identify(&ScanResult{MAC: "b0:4a:39:ab:37:a1"}, real) {
		found = found || g.OS == "Roborock vacuum"
	}
	if !found {
		t.Fatal("the real vacuum is still a vacuum")
	}
	if privateVendor("9a:af:f2:0d:2d:c6", inventory{Vendor: "Apple (private address)"}).Vendor != "Apple (private address)" {
		t.Fatal("a private-address guess is kept")
	}
}
