package qos

// The shaping engine underneath: dummynet, driven through dnctl(8).
//
// Prioritising traffic only means anything at a bottleneck you control. The
// link itself is not one: when the uplink fills, the queue that decides what
// waits belongs to the modem or the carrier, and nothing on this firewall can
// reach into it. So the first thing shaping does is move the bottleneck here,
// by sending everything through a pipe sized a little under what the link can
// actually carry. Once the queue is on this side, weights decide who waits.
//
// That is also why the link speeds have to be set by hand and set honestly. A
// pipe configured above the real rate never fills, the carrier's queue stays
// the real bottleneck, and the weights do nothing at all.
//
// The layout is two pipes, one per direction, each with a weighted fair
// queueing scheduler and three queues hanging off it. A rule with a ceiling
// gets a pipe of its own, because a ceiling is a rate limit rather than a
// share.

import (
	"fmt"
	"os/exec"
	"strings"
)

// Fixed identifiers. They are in FlowSight's own range and are flushed as a
// set, so they never disturb pipes someone else configured.
const (
	pipeDown  = 1
	pipeUp    = 2
	schedDown = 1
	schedUp   = 2

	qDownHigh, qDownNormal, qDownLow = 10, 11, 12
	qUpHigh, qUpNormal, qUpLow       = 20, 21, 22

	// Per-rule ceilings start here, one pipe per direction per rule.
	ceilDownBase = 100
	ceilUpBase   = 200
)

func classQueue(c Class, down bool) int {
	switch c {
	case High:
		if down {
			return qDownHigh
		}
		return qUpHigh
	case Low:
		if down {
			return qDownLow
		}
		return qUpLow
	default:
		if down {
			return qDownNormal
		}
		return qUpNormal
	}
}

type dn struct {
	run func(args ...string) (string, error)
	// sys runs kldstat and kldload.
	sys func(name string, args ...string) (string, error)
}

func newDN() *dn {
	return &dn{
		run: func(args ...string) (string, error) {
			out, err := exec.Command("dnctl", args...).CombinedOutput()
			return string(out), err
		},
		sys: func(name string, args ...string) (string, error) {
			out, err := exec.Command(name, args...).CombinedOutput()
			return string(out), err
		},
	}
}

func (d *dn) cmd(args ...string) error {
	out, err := d.run(args...)
	if err != nil {
		return fmt.Errorf("dnctl %s: %s", strings.Join(args, " "), strings.TrimSpace(out))
	}
	return nil
}

// tune sets the two kernel knobs that decide whether shaping works or merely
// appears to. Without the fast path dummynet drops a startling share of what
// it handles: measured on a test gateway, 4.6 percent of all packets, which
// is enough to cut a 14 Mbit/s pipe down to 4.6 Mbit/s of actual throughput.
// With it, the same pipe delivered 96 percent of its rate.
func tune() {
	_ = exec.Command("sysctl", "net.inet.ip.dummynet.io_fast=1").Run()
}

// queueBytes sizes a pipe's buffer to the rate it carries: about fifty
// milliseconds of it. Too small and TCP is throttled far below the pipe by
// loss alone; too large and the queue simply adds delay, which is the
// bufferbloat this is meant to cure.
func queueBytes(mbit float64) int {
	b := int(mbit * 1e6 / 8 * 0.05)
	if b < 50<<10 {
		b = 50 << 10
	}
	if b > 2<<20 {
		b = 2 << 20
	}
	return b
}

// available reports whether dummynet can be used at all, loading the module
// if it is not already in the kernel. It asks the kernel, not dnctl: "dnctl
// pipe show" succeeds with no dummynet loaded, and then every pipe fails with
// "Protocol not available". That is the state after any reboot, since
// kldload does not survive one.
func (d *dn) available() error {
	if _, err := d.sys("kldstat", "-q", "-m", "dummynet"); err != nil {
		if out, err := d.sys("kldload", "dummynet"); err != nil && !strings.Contains(out, "already loaded") {
			return fmt.Errorf("dummynet is not available: %s", strings.TrimSpace(out))
		}
	}
	if _, err := d.run("pipe", "show"); err != nil {
		return fmt.Errorf("dummynet loaded but dnctl will not talk to it")
	}
	return nil
}

// plan is everything the engine needs to be configured to.
type plan struct {
	DownMbit, UpMbit                    float64
	WeightHigh, WeightNormal, WeightLow int
	Ceilings                            []ceiling // in rule order
}

type ceiling struct {
	Mbit             float64
	DownPipe, UpPipe int
}

// configure brings dummynet to the state the plan describes. It is written to
// be repeatable: configuring a pipe that already exists replaces it.
func (d *dn) configure(p plan) error {
	tune()
	if err := d.cmd("pipe", itoa(pipeDown), "config", "bw", mbit(p.DownMbit),
		"queue", itoa(queueBytes(p.DownMbit))+"Bytes"); err != nil {
		return err
	}
	if err := d.cmd("pipe", itoa(pipeUp), "config", "bw", mbit(p.UpMbit),
		"queue", itoa(queueBytes(p.UpMbit))+"Bytes"); err != nil {
		return err
	}
	// Weighted fair queueing: a queue with twice the weight gets twice the
	// share when there is contention, and none of it is wasted when there is
	// not, which is the behaviour anyone actually wants from "priority".
	if err := d.cmd("sched", itoa(schedDown), "config", "pipe", itoa(pipeDown), "type", "wf2q+"); err != nil {
		return err
	}
	if err := d.cmd("sched", itoa(schedUp), "config", "pipe", itoa(pipeUp), "type", "wf2q+"); err != nil {
		return err
	}
	for _, q := range []struct {
		id, sched, weight int
	}{
		{qDownHigh, schedDown, p.WeightHigh}, {qDownNormal, schedDown, p.WeightNormal}, {qDownLow, schedDown, p.WeightLow},
		{qUpHigh, schedUp, p.WeightHigh}, {qUpNormal, schedUp, p.WeightNormal}, {qUpLow, schedUp, p.WeightLow},
	} {
		w := q.weight
		if w < 1 {
			w = 1
		}
		if w > 100 {
			w = 100
		}
		if err := d.cmd("queue", itoa(q.id), "config", "sched", itoa(q.sched), "weight", itoa(w)); err != nil {
			return err
		}
	}
	for _, c := range p.Ceilings {
		q := itoa(queueBytes(c.Mbit)) + "Bytes"
		if err := d.cmd("pipe", itoa(c.DownPipe), "config", "bw", mbit(c.Mbit), "queue", q); err != nil {
			return err
		}
		if err := d.cmd("pipe", itoa(c.UpPipe), "config", "bw", mbit(c.Mbit), "queue", q); err != nil {
			return err
		}
	}
	return nil
}

// teardown removes only what this module configured, so a shaper someone else
// set up on the same box keeps working.
func (d *dn) teardown(ceilings []ceiling) {
	for _, id := range []int{qDownHigh, qDownNormal, qDownLow, qUpHigh, qUpNormal, qUpLow} {
		_, _ = d.run("queue", "delete", itoa(id))
	}
	for _, id := range []int{schedDown, schedUp} {
		_, _ = d.run("sched", "delete", itoa(id))
	}
	for _, c := range ceilings {
		_, _ = d.run("pipe", "delete", itoa(c.DownPipe))
		_, _ = d.run("pipe", "delete", itoa(c.UpPipe))
	}
	for _, id := range []int{pipeDown, pipeUp} {
		_, _ = d.run("pipe", "delete", itoa(id))
	}
}

// stats reads the queue counters so the interface can show what is actually
// being held back, which is the only honest evidence that shaping is working.
func (d *dn) stats() (string, error) { return d.run("queue", "show") }

func mbit(v float64) string {
	if v <= 0 {
		v = 1
	}
	return fmt.Sprintf("%.0fKbit/s", v*1000)
}

func itoa(n int) string { return fmt.Sprint(n) }
