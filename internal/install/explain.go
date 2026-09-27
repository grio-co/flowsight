package install

import (
	"fmt"
	"sort"
	"strings"
)

// Explain writes the plan in plain words, for the operator to confirm.
func (p Plan) Explain() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	f := p.Facts

	host := f.System
	if f.Version != "" {
		host += " " + f.Version
	}
	where := "on bare metal or an unrecognised hypervisor"
	switch {
	case f.Container != "" && f.Kubernetes:
		where = "in a Kubernetes pod (" + f.Container + ")"
	case f.Container != "":
		where = "in a " + f.Container + " container"
	case f.Cloud != "":
		where = "on " + f.Cloud + " (" + f.Virtual + ")"
	case f.Virtual != "":
		where = "in a " + f.Virtual + " virtual machine"
	}
	w("This machine: %s, %s/%s, %d CPUs, %d MB, %s.", host, f.OS, f.Arch, f.CPUs, f.MemoryMB, where)
	if !p.Supported {
		w("")
		w("FlowSight cannot be installed here: %s.", p.Reason)
		return b.String()
	}
	w("Firewall: %s. Forwards packets: %s. Default gateway: %s.", f.Firewall, yesNo(f.Forwards), orNone(f.Gateway))
	w("")
	w("Position: %s, because %s.", p.Position, strings.Join(p.Why, "; "))
	w("")
	w("Providers (what is already here is what FlowSight uses):")
	keys := make([]string, 0, len(p.Providers))
	for k := range p.Providers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		w("  %-12s %s", k, p.Providers[k])
	}
	w("")
	w("Applying this plan would:")
	for i, s := range p.Steps {
		w("  %d. %s", i+1, s.Do)
		for _, c := range s.Changes {
			w("       %s", c)
		}
	}
	if len(p.Questions) > 0 {
		w("")
		w("Still to answer:")
		for _, q := range p.Questions {
			line := "  - " + q.Ask
			if q.Answer != "" {
				line += " -> " + q.Answer
			} else if q.Default != "" {
				line += " [" + q.Default + "]"
			}
			w("%s", line)
		}
	}
	if len(p.Warnings) > 0 {
		w("")
		for _, x := range p.Warnings {
			w("Note: %s.", x)
		}
	}
	return b.String()
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
