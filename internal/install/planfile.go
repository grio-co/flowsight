package install

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// A plan file is how an install is repeated without questions: written by
// `flowsightd install -plan-out` on one machine, or by hand, and given to
// `flowsightd install -plan` on the next. It carries decisions, not facts:
// facts are always read from the machine the plan is applied on, and a plan
// made for another kind of machine is refused rather than bent to fit.
//
// A hand-written file needs only what it wants to decide:
//
//	{"format": 1, "questions": [{"id": "firewall", "answer": "opnsense 192.168.1.1"}]}

// ReadPlan reads a plan file.
func ReadPlan(path string) (Plan, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Plan{}, err
	}
	var p Plan
	if err := json.Unmarshal(b, &p); err != nil {
		return Plan{}, fmt.Errorf("%s is not a plan file: %w", path, err)
	}
	if p.Format != PlanFormat {
		return Plan{}, fmt.Errorf("%s has plan format %d; this flowsightd reads format %d", path, p.Format, PlanFormat)
	}
	return p, nil
}

// FromFile makes the plan for this machine and takes the file's decisions
// into it: packaged mode and the answers to its questions. It refuses when
// the file names a platform, service or position this machine does not have.
// An answer to a question this machine does not ask is kept, and reported.
func FromFile(f Facts, file Plan, now time.Time) (Plan, error) {
	p := MakePlan(f, now, Options{Packaged: file.Packaged})
	var diff []string
	check := func(what, want, got string) {
		if want != "" && want != got {
			diff = append(diff, fmt.Sprintf("%s %q (this machine: %q)", what, want, got))
		}
	}
	check("platform", file.Platform, p.Platform)
	check("service", file.Service, p.Service)
	check("position", file.Position, p.Position)
	if len(diff) > 0 {
		return p, fmt.Errorf("the plan file was made for another kind of machine: it says %s", strings.Join(diff, ", "))
	}
	answers := map[string]string{}
	for _, q := range file.Questions {
		if q.Answer != "" {
			answers[q.ID] = q.Answer
		}
	}
	for i := range p.Questions {
		if a, ok := answers[p.Questions[i].ID]; ok {
			p.Questions[i].Answer = a
			delete(answers, p.Questions[i].ID)
		}
	}
	for id, a := range answers {
		p.Questions = append(p.Questions, Question{ID: id, Ask: "(answered in the plan file; not asked on this machine)", Answer: a})
		p.Warnings = append(p.Warnings, "the plan file answers "+id+", which this machine does not ask about; the answer is kept")
	}
	return p, nil
}
