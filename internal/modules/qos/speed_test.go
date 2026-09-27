package qos

import (
	"math"
	"testing"
)

// Two measurements two percent apart or more mean a rerun; a speedtest.net
// failure is not a disagreement.
func TestDivergenceAndRerun(t *testing.T) {
	if d := divergence(100, 98); math.Abs(d-0.02) > 1e-9 {
		t.Fatalf("divergence 100 vs 98 = %v", d)
	}
	if divergence(0, 0) != 0 || divergence(0, 50) != 1 {
		t.Fatal("zero handling")
	}
	ok := SpeedTest{DownMbit: 900, UpMbit: 40, OoklaDownMbit: 895, OoklaUpMbit: 39.8}
	ok.DivergeDown, ok.DivergeUp = divergence(ok.DownMbit, ok.OoklaDownMbit), divergence(ok.UpMbit, ok.OoklaUpMbit)
	if needsRerun(ok) {
		t.Fatal("under 2% must not rerun")
	}
	far := SpeedTest{DownMbit: 900, UpMbit: 40, OoklaDownMbit: 850, OoklaUpMbit: 40}
	far.DivergeDown, far.DivergeUp = divergence(far.DownMbit, far.OoklaDownMbit), divergence(far.UpMbit, far.OoklaUpMbit)
	if !needsRerun(far) {
		t.Fatal("5.6% apart must rerun")
	}
	broken := far
	broken.OoklaError = "no server answered"
	if needsRerun(broken) {
		t.Fatal("a failed comparison is not a disagreement")
	}
}

// The capacity estimate is the interface's peak second, ramp-up excluded;
// the load already present is the difference from the tester's share.
func TestRatesAndSuggestion(t *testing.T) {
	per := []float64{10e6, 100e6, 118e6, 117e6, 119e6}
	if p := peakRate(per); p != 119e6 {
		t.Fatalf("peak %v", p)
	}
	if m := meanRate(per); math.Abs(m-113.5e6) > 1 {
		t.Fatalf("mean %v", m)
	}
	if peakRate([]float64{5e6, 6e6}) != 6e6 {
		t.Fatal("short series keeps every sample")
	}
	if mbitPerSec(125e6, 1) != 1000 {
		t.Fatal("125 MB/s is 1000 Mbit/s")
	}
	if suggest(939.7) != 939 || suggest(0.4) != 1 || suggest(0) != 0 {
		t.Fatal("suggestion rounds down to whole Mbit/s, never below one when something was measured")
	}
}

func TestInterfaceCounterParsers(t *testing.T) {
	bsd := `Name     Mtu Network                      Address                                     Ipkts Ierrs Idrop        Ibytes      Opkts Oerrs        Obytes  Coll
vtnet1  1500 <Link#2>                     bc:24:11:23:0d:37                       214571343     0     0  151274492454  579894139     0  472307287521     0
vtnet1     - fe80::%vtnet1/64             fe80::be24:11ff:fe23:d37%vtnet1              1629     -     -        117104       2791     -        193310     -`
	c, ok := parseNetstatIB(bsd, "vtnet1")
	if !ok || c.in != 151274492454 || c.out != 472307287521 {
		t.Fatalf("netstat: %+v %v", c, ok)
	}
	if _, ok := parseNetstatIB(bsd, "vtnet0"); ok {
		t.Fatal("another interface must not match")
	}
	linux := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  eth0: 1234567890 100 0 0 0 0 0 0 987654321 90 0 0 0 0 0 0`
	c, ok = parseProcNetDev(linux, "eth0")
	if !ok || c.in != 1234567890 || c.out != 987654321 {
		t.Fatalf("proc: %+v %v", c, ok)
	}
}

func TestOoklaServerListAndPick(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?><settings><servers>
<server url="http://a.example.net:8080/speedtest/upload.php" lat="39.10" lon="-94.58" name="Kansas City, MO" country="United States" sponsor="Sponsor A" id="1" host="a.example.net:8080"/>
<server url="http://b.example.net:8080/speedtest/upload.php" lat="41.88" lon="-87.63" name="Chicago, IL" country="United States" sponsor="Sponsor B" id="2" host="b.example.net:8080"/>
<server url="http://c.example.net:8080/speedtest/upload.php" lat="51.51" lon="-0.13" name="London" country="United Kingdom" sponsor="Sponsor C" id="3" host="c.example.net:8080"/>
</servers></settings>`
	servers, err := parseOoklaServers([]byte(xml))
	if err != nil || len(servers) != 3 {
		t.Fatalf("parse: %v %d", err, len(servers))
	}
	near := nearestOokla(servers, 39.18, -96.57, 2)
	if len(near) != 2 || near[0].Name != "Kansas City, MO" || near[1].Name != "Chicago, IL" {
		t.Fatalf("nearest: %+v", near)
	}
	if ooklaBase(servers[0].URL) != "http://a.example.net:8080/speedtest/" {
		t.Fatalf("base: %q", ooklaBase(servers[0].URL))
	}
	if d := distKm(39.18, -96.57, 39.10, -94.58); d < 160 || d > 180 {
		t.Fatalf("distance Manhattan KS to Kansas City = %v km", d)
	}
}

func TestOoklaCurrentDirectoryAndEndpoints(t *testing.T) {
	js := `[{"url":"http://a.example.net:8080/speedtest/upload.php","lat":"39.0997","lon":"-94.5786","name":"Kansas City, MO","country":"United States","sponsor":"Sponsor A","id":1,"host":"a.example.net:8080"}]`
	servers, err := parseOoklaJSON([]byte(js))
	if err != nil || len(servers) != 1 || servers[0].Lat < 39 || servers[0].Host != "a.example.net:8080" {
		t.Fatalf("json directory: %v %+v", err, servers)
	}
	d, u := ooklaEndpoints(servers[0], "x1")
	if d != "https://a.example.net:8080/download?nocache=x1&size=25000000" || u != "https://a.example.net:8080/upload?nocache=x1" {
		t.Fatalf("current endpoints: %s %s", d, u)
	}
	d, u = ooklaEndpoints(ooklaServer{URL: "http://b.example.net/speedtest/upload.php"}, "x2")
	if d != "http://b.example.net/speedtest/random4000x4000.jpg?x=x2" || u != "http://b.example.net/speedtest/upload.php?x=x2" {
		t.Fatalf("legacy endpoints: %s %s", d, u)
	}
}
