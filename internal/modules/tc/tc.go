// Package tc is FlowSight's traffic shaper on Linux: core.Shaper over the
// kernel's traffic control (HTB, u32, an ifb device for the upload
// direction). The qos module decides what to shape; this carries it out.
// It is published only where pf's shaper is not.
package tc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

type Module struct {
	ctx *core.Context
	tc  string
	ip  string
	dir string

	mu      sync.Mutex
	applied string // the batch last loaded, as text
	good    *core.ShapePlan
	leaf    string
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name: "tc", Version: "1.0",
		Description:  "FlowSight's traffic shaper on Linux: the qos module's classes and ceilings as HTB queues on the LAN interface, both directions.",
		Capabilities: []string{},
		Requires:     []string{"tc"},
		After:        []string{"firewall", "nftables"},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.dir = filepath.Join(ctx.Platform.EtcDir, "tc")
	m.tc = firstExisting("/usr/sbin/tc", "/sbin/tc", "/usr/bin/tc")
	m.ip = firstExisting("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip")
	m.leaf = "fq_codel"
	if ctx.Platform.Family != "linux" || m.tc == "" || m.ip == "" {
		return nil
	}
	if _, taken := ctx.Service(core.ServiceShaper).(core.Shaper); taken {
		return nil // pf's shaper is here
	}
	ctx.Publish(core.ServiceShaper, &shaper{m: m})
	return nil
}

func (m *Module) Health() core.Health {
	if m.ctx == nil || m.tc == "" {
		return core.Health{OK: true, Detail: "not the shaper here (no tc)"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.applied == "" {
		return core.Health{OK: true, Detail: "no shaping configured"}
	}
	return core.Health{OK: true, Detail: "shaping on " + m.good.LAN}
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// ---------------------------------------------------------------- shaper

type shaper struct{ m *Module }

var _ core.Shaper = (*shaper)(nil)

func (s *shaper) Name() string    { return "tc" }
func (s *shaper) Available() bool { return s.m.tc != "" && s.m.ip != "" }

// Ready makes sure the ifb device the upload path needs can exist.
func (s *shaper) Ready() error {
	if !s.Available() {
		return errors.New("tc (iproute2) is not installed")
	}
	return s.m.ensureIFB()
}

func (s *shaper) Render(p core.ShapePlan) (string, map[string][]string) {
	sets := map[string][]string{}
	for _, r := range p.Rules {
		if len(r.Addrs) > 0 {
			sets[r.Key] = r.Addrs
		}
	}
	s.m.mu.Lock()
	leaf := s.m.leaf
	s.m.mu.Unlock()
	return render(p, leaf).String(), sets
}

// Apply loads the plan unless exactly it is already in place. The previous
// configuration is removed first; if the kernel rejects the new one, what
// was loaded is removed and the last good plan put back, so a bad plan
// never leaves half a tree behind.
func (s *shaper) Apply(p core.ShapePlan) error {
	m := s.m
	m.mu.Lock()
	leaf, applied := m.leaf, m.applied
	var prev *core.ShapePlan
	if m.good != nil {
		c := *m.good
		prev = &c
	}
	m.mu.Unlock()
	b := render(p, leaf)
	if b.String() == applied && m.inPlace(p.LAN) {
		return nil
	}
	if err := m.ensureIFB(); err != nil {
		return err
	}
	if prev != nil && prev.LAN != p.LAN {
		m.clearDev(prev.LAN)
	}
	m.clearDev(p.LAN)
	err := m.load(b)
	if err != nil && leaf != "" && strings.Contains(err.Error(), "qdisc kind is unknown") {
		// No fq_codel in this kernel: HTB's own leaves still shape.
		m.clearDev(p.LAN)
		m.mu.Lock()
		m.leaf = ""
		m.mu.Unlock()
		b = render(p, "")
		err = m.load(b)
	}
	if err != nil {
		m.clearDev(p.LAN)
		if prev != nil {
			m.mu.Lock()
			pl := m.leaf
			m.mu.Unlock()
			_ = m.load(render(*prev, pl))
		}
		return err
	}
	m.mu.Lock()
	m.applied, m.good = b.String(), &p
	m.mu.Unlock()
	_ = os.MkdirAll(m.dir, 0o755)
	_ = os.WriteFile(filepath.Join(m.dir, "shaping.tc"), []byte(b.String()), 0o644)
	return nil
}

// Clear removes FlowSight's trees wherever they are, found by their
// handle and by the redirect to its ifb, and the ifb itself; another
// queueing discipline, or an ingress not redirecting there, is left alone.
func (s *shaper) Clear() {
	m := s.m
	out, _ := core.Run(10*time.Second, m.tc, "qdisc", "show")
	for _, dev := range devsWithRoot(out) {
		m.clearDev(dev)
	}
	for _, dev := range devsWithIngress(out) {
		m.clearDev(dev)
	}
	_, _ = core.Run(10*time.Second, m.ip, "link", "del", ifb)
	m.mu.Lock()
	m.applied, m.good = "", nil
	m.mu.Unlock()
	_ = os.Remove(filepath.Join(m.dir, "shaping.tc"))
}

func (s *shaper) Stats() ([]core.QueueStat, error) {
	m := s.m
	m.mu.Lock()
	good := m.good
	m.mu.Unlock()
	if good == nil {
		return nil, nil
	}
	var res []core.QueueStat
	for _, d := range []struct {
		dev, name string
		base      int
	}{{good.LAN, "download", 0}, {ifb, "upload", 1000}} {
		out, err := core.Run(10*time.Second, m.tc, "-s", "class", "show", "dev", d.dev)
		if err != nil {
			return res, err
		}
		res = append(res, parseStats(out, d.name, d.base)...)
	}
	return res, nil
}

// ---------------------------------------------------------------- the kernel

func (m *Module) ensureIFB() error {
	if _, err := core.Run(10*time.Second, m.ip, "link", "show", ifb); err != nil {
		if out, err := core.Run(10*time.Second, m.ip, "link", "add", ifb, "type", "ifb"); err != nil {
			return fmt.Errorf("upload shaping needs an ifb device, which this kernel could not create (%s): "+
				"load the module with `modprobe ifb numifbs=0`", firstLine(out))
		}
	}
	if out, err := core.Run(10*time.Second, m.ip, "link", "set", ifb, "up"); err != nil {
		return fmt.Errorf("bringing %s up: %s", ifb, firstLine(out))
	}
	return nil
}

// load runs each path as one tc batch; tc stops at the first rejected line.
func (m *Module) load(b batch) error {
	for _, lines := range [][]string{b.Down, b.Up} {
		if len(lines) == 0 {
			continue
		}
		f, err := os.CreateTemp("", "fs-tc-*.batch")
		if err != nil {
			return err
		}
		_, _ = f.WriteString(strings.Join(lines, "\n") + "\n")
		f.Close()
		out, err := core.Run(30*time.Second, m.tc, "-batch", f.Name())
		os.Remove(f.Name())
		if err != nil {
			return fmt.Errorf("tc rejected the shaping: %s", errorLines(out))
		}
	}
	return nil
}

// clearDev removes FlowSight's root tree on dev, and its ingress when that
// redirects to FlowSight's ifb; the ifb's own tree goes with the ifb, but
// is removed here too so a reapply starts clean.
func (m *Module) clearDev(dev string) {
	if dev == "" {
		return
	}
	for _, d := range []string{dev, ifb} {
		if out, err := core.Run(10*time.Second, m.tc, "qdisc", "show", "dev", d, "root"); err == nil && strings.Contains(out, "htb "+handle+": root") {
			_, _ = core.Run(10*time.Second, m.tc, "qdisc", "del", "dev", d, "root")
		}
	}
	if out, err := core.Run(10*time.Second, m.tc, "filter", "show", "dev", dev, "ingress"); err == nil && strings.Contains(out, ifb) {
		_, _ = core.Run(10*time.Second, m.tc, "qdisc", "del", "dev", dev, "ingress")
	}
}

// inPlace says whether the kernel still holds FlowSight's trees on dev.
func (m *Module) inPlace(dev string) bool {
	out, err := core.Run(10*time.Second, m.tc, "qdisc", "show")
	if err != nil {
		return false
	}
	roots := devsWithRoot(out)
	return containsStr(roots, dev) && containsStr(roots, ifb) && containsStr(devsWithIngress(out), dev) &&
		m.redirects(dev)
}

func (m *Module) redirects(dev string) bool {
	out, err := core.Run(10*time.Second, m.tc, "filter", "show", "dev", dev, "ingress")
	return err == nil && strings.Contains(out, ifb)
}

var (
	rootRe    = regexp.MustCompile(`(?m)^qdisc htb ` + handle + `: dev (\S+) root`)
	ingressRe = regexp.MustCompile(`(?m)^qdisc ingress ffff: dev (\S+) `)
)

func devsWithRoot(qdiscs string) []string    { return matches(rootRe, qdiscs) }
func devsWithIngress(qdiscs string) []string { return matches(ingressRe, qdiscs) }

func matches(re *regexp.Regexp, s string) []string {
	var out []string
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// errorLines is tc's output without its warnings (HTB warns about quanta
// at some rates, and they are not why a batch failed).
func errorLines(s string) string {
	var keep []string
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "Warning") {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "; ")
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// parseStats reads `tc -s class show`: per class, what it sent, dropped
// and holds waiting.
//
//	class htb f5:10 parent f5:1 leaf 8010: prio 0 rate 7Mbit ceil 10Mbit burst 1598b cburst 1600b
//	 Sent 123456 bytes 321 pkt (dropped 2, overlimits 40 requeues 0)
//	 backlog 0b 0p requeues 0
func parseStats(out, direction string, base int) []core.QueueStat {
	names := map[int]string{0x10: "high", 0x20: "normal", 0x30: "low"}
	var res []core.QueueStat
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		f := strings.Fields(l)
		if len(f) < 3 || f[0] != "class" || f[1] != "htb" || !strings.HasPrefix(f[2], handle+":") {
			continue
		}
		minor, err := strconv.ParseInt(strings.TrimPrefix(f[2], handle+":"), 16, 32)
		if err != nil || minor == 1 {
			continue
		}
		name, ok := names[int(minor)]
		if !ok {
			name = fmt.Sprintf("ceiling %d", minor-0x100+1)
		}
		detail := []string{}
		for _, next := range lines[i+1 : min(i+3, len(lines))] {
			if t := strings.TrimSpace(next); strings.HasPrefix(t, "Sent") || strings.HasPrefix(t, "backlog") {
				detail = append(detail, t)
			}
		}
		res = append(res, core.QueueStat{Queue: base + int(minor), Name: direction + " " + name, Detail: strings.Join(detail, "; ")})
	}
	return res
}
