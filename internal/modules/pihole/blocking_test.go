package pihole

import (
	"testing"
)

func TestBlockingValidation(t *testing.T) {
	for a, ok := range map[string]bool{"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts": true, "http://192.168.0.1:8080/feeds/categories/ads.txt?key=x": true,
		"file:///etc/pihole/local.list": true, "ftp://x/y": false, "not a url": false, "https://": false} {
		if validListAddress(a) != ok {
			t.Errorf("list %q: want %v", a, ok)
		}
	}
	for c, ok := range map[string]bool{"192.168.1.68": true, "192.168.2.0/24": true, "2600:1700::1": true, "70:f0:88:2d:b0:32": true, "kids-ipad": true, ":eth0": true,
		"bad client!": false, "": false} {
		if clientRe.MatchString(c) != ok {
			t.Errorf("client %q: want %v", c, ok)
		}
	}
	for g, ok := range map[string]bool{"Kids": true, "Guest Wi-Fi": true, "IoT_2": true, "": false, "a/b": false} {
		if groupNameRe.MatchString(g) != ok {
			t.Errorf("group %q: want %v", g, ok)
		}
	}
	if mm := feedRe.FindStringSubmatch("http://192.168.0.1:8080/feeds/categories/ads.txt?key=abc"); mm == nil || mm[1] != "ads" {
		t.Fatal("a FlowSight feed is recognised by its category")
	}
}

// Group numbers are per Pi-hole; names are what FlowSight shows.
func TestGroupNamesFromIDs(t *testing.T) {
	st := &phState{gname: map[int]string{0: "Default", 3: "Kids"}}
	got := st.names([]any{float64(3), float64(0), float64(9)})
	if len(got) != 3 || got[0] != "#9" || got[1] != "Default" || got[2] != "Kids" {
		t.Fatalf("names: %v", got)
	}
}
