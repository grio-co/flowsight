package core

import (
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMatchScoreNeedsEveryWord(t *testing.T) {
	if matchScore([]string{"echo", "show"}, "Echo Show 7752") == 0 {
		t.Fatal("both words present")
	}
	if matchScore([]string{"echo", "show"}, "Echo 9a43") != 0 {
		t.Fatal("a missing word must not match")
	}
	if matchScore([]string{"iphone"}, "iPhone") <= matchScore([]string{"iphone"}, "Grio's iPhone 15") {
		t.Fatal("an exact match ranks above a substring")
	}
}

// A device with several address rows is one result, named from whichever
// row carries the name, linked under its IPv4 address.
func TestSearchMergesADevicesAddresses(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	for _, q := range []string{
		`INSERT INTO hosts(ip,mac,name,last_seen,is_local) VALUES('2600::5','18:74:2e:74:77:52',NULL,` + itoa(now) + `,1)`,
		`INSERT INTO hosts(ip,mac,name,last_seen,is_local) VALUES('192.168.1.122','18:74:2e:74:77:52','Echo Show 7752',` + itoa(now-60) + `,1)`,
	} {
		if err := s.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	c := &Core{Store: s, Infos: map[string]ModuleInfo{}, Services: map[string]any{}}
	out, err := c.apiSearch(&Req{Request: httptest.NewRequest("GET", "/api/search?q=echo+show", nil)})
	if err != nil {
		t.Fatal(err)
	}
	groups := out.(map[string]any)["groups"].([]searchGroup)
	if len(groups) == 0 || groups[0].Kind != "devices" || len(groups[0].Results) != 1 {
		t.Fatalf("groups: %+v", groups)
	}
	r := groups[0].Results[0]
	if r.Title != "Echo Show 7752" || !strings.HasSuffix(r.Href, "192.168.1.122") {
		t.Fatalf("result: %+v", r)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
