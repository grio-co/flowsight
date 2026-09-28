package core

import (
	"testing"
	"time"
)

const poll = 30 * time.Second

func TestFlowDeltaSplitsGrowthAndSeesOnlyRealResets(t *testing.T) {
	in, out := flowDelta(600, 400, 550, 550, poll)
	if in+out != 100 || in != 50 || out != 50 {
		t.Fatalf("growth should be 100 split by the current mix: %d %d", in, out)
	}
	if in, out := flowDelta(600, 400, 600, 400, poll); in != 0 || out != 0 {
		t.Fatalf("no growth: %d %d", in, out)
	}
	if in, out := flowDelta(600, 400, 10, 5, poll); in != 10 || out != 5 {
		t.Fatalf("reset should credit the new counters: %d %d", in, out)
	}
	if in, out := flowDelta(0, 0, 30, 70, poll); in != 30 || out != 70 {
		t.Fatalf("first sighting: %d %d", in, out)
	}
}

// The live fault of 2026-09-28: a WireGuard flow at 470 GB in and 1.67 TB
// out grew by 900 MB between polls, and grow*in overflowed int64, which made
// bytes_in negative and bytes_out larger than the growth.
func TestFlowDeltaDoesNotOverflowOnLargeFlows(t *testing.T) {
	pin, pout := int64(470_595_260_634), int64(1_668_474_105_882)
	in, out := flowDelta(pin, pout, pin+200_000_000, pout+700_000_000, poll)
	if in < 0 || out < 0 {
		t.Fatalf("a direction went negative: %d %d", in, out)
	}
	if in+out != 900_000_000 {
		t.Fatalf("growth must be preserved: %d + %d", in, out)
	}
	// The split follows the flow's current mix (about 22% in).
	if in < 190_000_000 || in > 210_000_000 {
		t.Fatalf("split off: in=%d", in)
	}
}

func TestFlowDeltaIgnoresCountersBelowZero(t *testing.T) {
	if in, out := flowDelta(100, 100, -5, 300, poll); in != 0 || out != 0 {
		t.Fatalf("a negative counter is a fault, not traffic: %d %d", in, out)
	}
	// A negative previous value counts as zero: the growth is judged from
	// the sound part of the baseline and split by the current mix.
	if in, out := flowDelta(-50, 100, 10, 120, poll); in < 0 || out < 0 || in+out != 30 {
		t.Fatalf("negative baseline: %d %d", in, out)
	}
}

func TestFlowDeltaCapsWhatTheLinkCouldCarry(t *testing.T) {
	// 100 GB in 30 s is 26 Gbit/s: impossible, so the credit is bounded by
	// 10 Gbit/s over the interval, keeping the split.
	in, out := flowDelta(0, 0, 25_000_000_000, 75_000_000_000, poll)
	limit := int64(poll.Seconds() * maxLinkBytesPerSec)
	if in+out != limit {
		t.Fatalf("credit should be the link cap %d, got %d", limit, in+out)
	}
	if in*3 < out-3 || in*3 > out+3 {
		t.Fatalf("split should survive the cap: %d %d", in, out)
	}
	// Polls a moment apart are judged over minDeltaInterval, so a real
	// 1 Gbit/s burst is never thrown away.
	if in, out := flowDelta(0, 0, 0, 1_000_000_000, time.Millisecond); out != 1_000_000_000 || in != 0 {
		t.Fatalf("burst within the floor interval lost: %d %d", in, out)
	}
}

func TestRepairByteCountersFoldsNegativesBack(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	must := func(q string, args ...any) {
		t.Helper()
		if _, err := s.db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	must(`INSERT INTO rollup_dst(bucket,src_ip,dst_ip,dst_port,proto,bytes_in,bytes_out,flows) VALUES(0,'10.0.0.2','89.187.180.27',51820,'udp',-150020520,9062444474,1)`)
	must(`INSERT INTO rollup_app(bucket,src_ip,app,category,verdict,bytes_in,bytes_out,flows) VALUES(0,'10.0.0.2','WireGuard','VPN','observed',300,-100,1)`)
	must(`INSERT INTO rollup_domain(bucket,src_ip,domain,category,verdict,bytes_in,bytes_out,flows) VALUES(0,'10.0.0.2','x','','observed',10,900000000000000,1)`)
	must(`INSERT INTO hosts(ip,bytes_in,bytes_out) VALUES('10.0.0.2',-7,20)`)
	must(`DELETE FROM meta WHERE key='repair_byte_counters'`)
	if err := s.repairByteCounters(); err != nil {
		t.Fatal(err)
	}
	row, _ := s.Row(`SELECT bytes_in, bytes_out FROM rollup_dst`)
	if toInt(row["bytes_in"]) != 0 || toInt(row["bytes_out"]) != 9062444474-150020520 {
		t.Fatalf("rollup_dst not folded: %v", row)
	}
	row, _ = s.Row(`SELECT bytes_in, bytes_out FROM rollup_app`)
	if toInt(row["bytes_in"]) != 200 || toInt(row["bytes_out"]) != 0 {
		t.Fatalf("rollup_app not folded: %v", row)
	}
	row, _ = s.Row(`SELECT bytes_in, bytes_out FROM rollup_domain`)
	if toInt(row["bytes_out"]) != int64(maxLinkBytesPerSec)*300 {
		t.Fatalf("impossible bucket not bounded: %v", row)
	}
	row, _ = s.Row(`SELECT bytes_in, bytes_out FROM hosts WHERE ip='10.0.0.2'`)
	if toInt(row["bytes_in"]) != 0 || toInt(row["bytes_out"]) != 13 {
		t.Fatalf("hosts not folded: %v", row)
	}
	var done string
	if err := s.db.QueryRow(`SELECT value FROM meta WHERE key='repair_byte_counters'`).Scan(&done); err != nil || done != "1" {
		t.Fatalf("repair should record itself: %q %v", done, err)
	}
}

func toInt(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case float64:
		return int64(x)
	}
	return -1
}
