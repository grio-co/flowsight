package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Uninstall reverses what `flowsightd install` recorded in install.json.
//
// Order matters. Everything FlowSight put in front of traffic is withdrawn
// first, while the service may still be running: the pf anchors (so no
// redirect points at a proxy that is about to go), its own squid instance,
// and its resolver includes and zone files. Only then is the service stopped
// and disabled. Stopping first could leave redirects to a dead proxy, which
// is interception failing closed.
//
// Files are then put back: what the installer created is removed, what it
// replaced is restored from the backup the earliest run kept. The
// configuration, data and logs are kept unless purge is set. An install made
// by a package is the package manager's to remove, and is refused.

// UninstallStep is one thing uninstall does or would do.
type UninstallStep struct {
	Do      string `json:"do"`
	Command string `json:"command,omitempty"`
	Path    string `json:"path,omitempty"`
	From    string `json:"from,omitempty"` // for a move: Path is put back from here
	Done    bool   `json:"done"`
	Error   string `json:"error,omitempty"`
}

// UninstallPlan is what uninstall found and will do.
type UninstallPlan struct {
	Platform string          `json:"platform"`
	Service  string          `json:"service"`
	Steps    []UninstallStep `json:"steps"`
	Keeps    []string        `json:"keeps,omitempty"`
}

// PlanUninstall reads install.json and works out what to undo. It changes
// nothing.
func PlanUninstall(e Env, f Facts, purge bool) (UninstallPlan, error) {
	here := MakePlan(f, time.Now())
	u := UninstallPlan{Platform: here.Platform, Service: here.Service}
	if !here.Supported {
		return u, errors.New("nothing to uninstall here: " + here.Reason)
	}
	manifest := filepath.Join(here.Paths["data"], manifestOut)
	b, err := os.ReadFile(e.path(manifest))
	if err != nil {
		return u, fmt.Errorf("no record of an install by flowsightd install (%s): %w", manifest, err)
	}
	var runs []Result
	if err := json.Unmarshal(b, &runs); err != nil || len(runs) == 0 {
		return u, fmt.Errorf("%s cannot be read as an install record", manifest)
	}
	for _, r := range runs {
		if r.Packaged || r.Platform == "opnsense" {
			return u, errors.New("FlowSight was installed by a package; remove it with the package manager (" + packageRemover(here) + "), which withdraws and removes what the package put in place")
		}
	}
	add := func(s UninstallStep) { u.Steps = append(u.Steps, s) }

	// 1. Withdraw what stands in front of traffic.
	u.Steps = append(u.Steps, withdrawSteps(e, f, here)...)

	// 2. Stop and disable the service.
	switch here.Service {
	case "rc.d":
		add(UninstallStep{Do: "stop the service", Command: "service flowsight stop"})
		add(UninstallStep{Do: "disable the service", Command: "sysrc -q -x flowsight_enable"})
	case "systemd":
		add(UninstallStep{Do: "stop and disable the service", Command: "systemctl disable --now flowsight"})
	}

	// 3. Put files back. The first recorded action on a path says whose it
	// is: created by the installer (remove it), replaced (restore that run's
	// backup), or already there unchanged or kept (not the installer's, so
	// left alone). Backups made by later runs are intermediate and removed.
	first := map[string]FileChange{}
	later := map[string][]string{}
	for _, r := range runs {
		for _, fc := range r.Files {
			if _, seen := first[fc.Path]; !seen {
				first[fc.Path] = fc
			} else if fc.Backup != "" {
				later[fc.Path] = append(later[fc.Path], fc.Backup)
			}
		}
	}
	cfg := here.Paths["config"]
	paths := make([]string, 0, len(first))
	for p := range first {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		fc := first[p]
		if p == cfg && !purge {
			u.Keeps = append(u.Keeps, p+" (the configuration; -purge removes it)")
			continue
		}
		switch fc.Action {
		case "created":
			add(UninstallStep{Do: "remove what the installer created", Path: p})
		case "replaced":
			add(UninstallStep{Do: "restore what was there before the install", Path: p, From: fc.Backup})
		}
		for _, bk := range later[p] {
			if bk != fc.Backup {
				add(UninstallStep{Do: "remove a backup made by a later run", Path: bk})
			}
		}
	}
	// Replacing the binary also wrote flowsightd.previous, the updater's
	// rollback copy; it is the install's too.
	for _, r := range runs {
		if replacedBinary(r) {
			add(UninstallStep{Do: "remove the rollback copy the install wrote", Path: binaryPath + ".previous"})
			break
		}
	}
	if here.Service == "systemd" {
		add(UninstallStep{Do: "tell systemd the unit is gone", Command: "systemctl daemon-reload"})
	}

	// 4. Data and logs.
	if purge {
		for _, d := range []string{here.Paths["data"], here.Paths["log"], filepath.Dir(cfg)} {
			add(UninstallStep{Do: "remove the directory and everything in it", Path: d})
		}
	} else {
		add(UninstallStep{Do: "keep the install record beside the data", Path: manifest + ".uninstalled", From: manifest})
		u.Keeps = append(u.Keeps, here.Paths["data"]+" (data)", here.Paths["log"]+" (logs)")
	}
	return u, nil
}

// withdrawSteps take away everything FlowSight put in front of traffic: the
// pf anchors, its own squid instance, and its resolver files. They are the
// first part of an uninstall, and on their own they are what a package's
// removal script runs before stopping the service (uninstall -withdraw).
func withdrawSteps(e Env, f Facts, here Plan) []UninstallStep {
	var out []UninstallStep
	add := func(s UninstallStep) { out = append(out, s) }
	if f.Firewall == "pf" {
		add(UninstallStep{Do: "flush every FlowSight pf anchor (redirects, policy, zones, shaping)", Command: "pfctl -a flowsight -F all (and each sub-anchor)"})
	}
	squidConf := filepath.Join(filepath.Dir(here.Paths["config"]), "squid", "squid.conf")
	if _, err := os.Stat(e.path(squidConf)); err == nil {
		add(UninstallStep{Do: "stop FlowSight's own squid instance", Command: "squid -k shutdown -f " + squidConf + " -n flowsight"})
	}
	files := resolverFiles(e, here)
	for _, p := range files {
		add(UninstallStep{Do: "remove FlowSight's resolver file", Path: p})
	}
	if len(files) > 0 && f.HasBackend("unbound") {
		add(UninstallStep{Do: "reload the resolver without FlowSight's files", Command: "unbound-control reload"})
	}
	// Without Unbound installed, its include directories can only be the
	// ones FlowSight created for its files; remove them when empty.
	if !f.HasBackend("unbound") {
		for _, d := range resolverDirs(here) {
			if _, err := os.Stat(e.path(d)); err == nil {
				add(UninstallStep{Do: "remove the empty directory FlowSight made for resolver files", Path: d})
			}
		}
	}
	return out
}

// PlanWithdraw is uninstall's first part alone, for a package's removal
// script: it needs no install record.
func PlanWithdraw(e Env, f Facts) (UninstallPlan, error) {
	here := MakePlan(f, time.Now())
	if !here.Supported {
		return UninstallPlan{}, errors.New("nothing to withdraw here: " + here.Reason)
	}
	return UninstallPlan{Platform: here.Platform, Service: here.Service, Steps: withdrawSteps(e, f, here)}, nil
}

func packageRemover(p Plan) string {
	switch {
	case p.Platform == "opnsense" || p.Platform == "freebsd":
		return "pkg delete os-flowsight"
	case p.Facts.System == "debian" || p.Facts.System == "ubuntu":
		return "apt remove flowsight"
	default:
		return "dnf remove flowsight"
	}
}

// resolverDirs are the Unbound include directory and its parent, deepest
// first.
func resolverDirs(p Plan) []string {
	switch p.Platform {
	case "freebsd":
		return []string{"/usr/local/etc/unbound/conf.d", "/usr/local/etc/unbound"}
	case "linux":
		return []string{"/etc/unbound/unbound.conf.d", "/etc/unbound"}
	}
	return nil
}

// resolverFiles lists FlowSight's Unbound includes and zone files.
func resolverFiles(e Env, p Plan) []string {
	dirs := resolverDirs(p)
	if len(dirs) > 1 {
		dirs = dirs[:1] // the include directory only; its parent holds no files of ours
	}
	var out []string
	for _, d := range dirs {
		entries, _ := os.ReadDir(e.path(d))
		for _, en := range entries {
			n := en.Name()
			if strings.HasPrefix(n, "flowsight-") && (strings.HasSuffix(n, ".conf") || strings.HasSuffix(n, ".rpz")) {
				out = append(out, filepath.Join(d, n))
			}
		}
	}
	return out
}

// Uninstall carries out an uninstall plan. It goes on past a failed step, so
// one stubborn file does not leave the service running, and reports every
// failure.
func Uninstall(e Env, u UninstallPlan, say func(string)) error {
	var failed []string
	for i := range u.Steps {
		s := &u.Steps[i]
		say(s.Do + target(*s))
		var err error
		switch {
		case s.Command != "":
			err = runUninstallCommand(e, *s)
		case s.From != "":
			err = os.Rename(e.path(s.From), e.path(s.Path))
		case strings.HasPrefix(s.Do, "remove the directory"):
			err = os.RemoveAll(e.path(s.Path))
		case strings.HasPrefix(s.Do, "remove the empty directory"):
			// Something else in it means it is not only FlowSight's.
			if os.Remove(e.path(s.Path)) != nil {
				s.Done = true
				continue
			}
		case s.Path != "":
			err = os.Remove(e.path(s.Path))
			if errors.Is(err, os.ErrNotExist) {
				err = nil // already gone is what was wanted
			}
		}
		if err != nil {
			s.Error = err.Error()
			failed = append(failed, s.Do+target(*s)+": "+err.Error())
			continue
		}
		s.Done = true
	}
	if len(failed) > 0 {
		return errors.New(strings.Join(failed, "; "))
	}
	return nil
}

func target(s UninstallStep) string {
	switch {
	case s.From != "":
		return ": " + s.From + " -> " + s.Path
	case s.Path != "":
		return ": " + s.Path
	case s.Command != "":
		return ": " + s.Command
	}
	return ""
}

func runUninstallCommand(e Env, s UninstallStep) error {
	if e.Run == nil {
		return errors.New("cannot run commands")
	}
	switch {
	case strings.HasPrefix(s.Command, "pfctl -a flowsight -F all"):
		// Every sub-anchor, then the root. Failing to list them is not an
		// error on a machine where FlowSight never loaded any.
		subs, _ := e.Run("pfctl", "-a", "flowsight", "-sA")
		for _, a := range strings.Fields(subs) {
			if _, err := e.Run("pfctl", "-a", a, "-F", "all"); err != nil {
				return fmt.Errorf("flushing %s: %w", a, err)
			}
		}
		_, err := e.Run("pfctl", "-a", "flowsight", "-F", "all")
		return err
	case s.Command == "service flowsight stop":
		out, err := e.Run("service", "flowsight", "stop")
		if err != nil && strings.Contains(out, "not running") {
			return nil
		}
		return err
	}
	f := strings.Fields(s.Command)
	_, err := e.Run(f[0], f[1:]...)
	if err != nil && (f[0] == "squid" || f[0] == "unbound-control") {
		return nil // not running is the state wanted
	}
	return err
}

func replacedBinary(r Result) bool {
	for _, fc := range r.Files {
		if fc.Path == binaryPath && fc.Action == "replaced" {
			return true
		}
	}
	return false
}
