package firewall

// Traffic shaping over pf and dummynet, behind core.Shaper: dummynet holds
// the pipes and weighted queues, and match rules in the flowsight/qos anchor
// sort traffic into them.

import (
	"fmt"
	"strings"
	"sync"

	"github.com/grioghar/flowsight/internal/core"
)

const shapeAnchor = "qos"

type pfShaper struct {
	m  *Module
	dn *dn

	mu       sync.Mutex
	ceilings []ceiling // pipes the last Apply configured, for Clear
}

var _ core.Shaper = (*pfShaper)(nil)

func newShaper(m *Module) *pfShaper { return &pfShaper{m: m, dn: newDN()} }

func (s *pfShaper) Name() string    { return "pf" }
func (s *pfShaper) Available() bool { return s.m.Available() }
func (s *pfShaper) Ready() error    { return s.dn.available() }

func (s *pfShaper) Render(p core.ShapePlan) (string, map[string][]string) { return renderShaping(p) }

func (s *pfShaper) Apply(p core.ShapePlan) error {
	list, _ := shapeCeilings(p)
	if err := s.dn.configure(plan{DownMbit: p.DownMbit, UpMbit: p.UpMbit, WeightHigh: p.WeightHigh,
		WeightNormal: p.WeightNormal, WeightLow: p.WeightLow, Ceilings: list}); err != nil {
		return err
	}
	s.mu.Lock()
	s.ceilings = list
	s.mu.Unlock()
	text, tables := renderShaping(p)
	if err := s.m.LoadAnchor(shapeAnchor, text); err != nil {
		return err
	}
	for t, addrs := range tables {
		if err := s.m.ReplaceTable(shapeAnchor, t, addrs); err != nil {
			return err
		}
	}
	return nil
}

func (s *pfShaper) Clear() {
	_ = s.m.FlushAnchor(shapeAnchor)
	s.mu.Lock()
	ceils := s.ceilings
	s.ceilings = nil
	s.mu.Unlock()
	s.dn.teardown(ceils)
}

func (s *pfShaper) Stats() ([]core.QueueStat, error) {
	out, err := s.dn.stats()
	return parseQueueStats(out), err
}

// parseQueueStats turns `dnctl queue show` into something a page can render:
// per queue, how much is waiting and how much has been dropped.
func parseQueueStats(out string) []core.QueueStat {
	var res []core.QueueStat
	name := map[int]string{
		qDownHigh: "download high", qDownNormal: "download normal", qDownLow: "download low",
		qUpHigh: "upload high", qUpNormal: "upload normal", qUpLow: "upload low",
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "q") {
			continue
		}
		var id int
		if _, err := fmt.Sscanf(line, "q%d", &id); err != nil {
			continue
		}
		label, ok := name[id]
		if !ok {
			continue
		}
		res = append(res, core.QueueStat{Queue: id, Name: label, Detail: line})
	}
	return res
}
