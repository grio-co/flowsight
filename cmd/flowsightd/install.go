package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/install"
)

// runInstall is `flowsightd install`: detect the machine, show the plan,
// and, once confirmed, apply and verify it. -dry-run stops after the plan.
func runInstall(args []string) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	dry := fs.Bool("dry-run", false, "detect and print the plan; change nothing")
	yes := fs.Bool("yes", false, "apply without asking (for unattended installs)")
	asJSON := fs.Bool("json", false, "print the plan as JSON (the plan file format) instead of plain words")
	out := fs.String("plan-out", "", "also write the plan to this file")
	planFile := fs.String("plan", "", "take decisions (answers, packaged mode) from this plan file; refused if it was made for another kind of machine")
	packaged := fs.Bool("packaged", false, "a package manager installed the binary and service file; leave them alone (used by the .deb, .rpm and pkg scripts)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	env := install.LocalEnv()
	facts := install.Detect(env)
	plan := install.MakePlan(facts, time.Now(), install.Options{Packaged: *packaged})
	if *planFile != "" {
		file, err := install.ReadPlan(*planFile)
		if err == nil {
			file.Packaged = file.Packaged || *packaged
			plan, err = install.FromFile(facts, file, time.Now())
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "flowsightd install:", err)
			return 1
		}
	}
	if *asJSON {
		b, _ := json.MarshalIndent(plan, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Print(plan.Explain())
	}
	if *out != "" {
		b, _ := json.MarshalIndent(plan, "", "  ")
		if err := os.WriteFile(*out, append(b, '\n'), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "flowsightd install:", err)
			return 1
		}
	}
	if !plan.Supported {
		return 1
	}
	if *dry {
		return 0
	}
	if !*yes && !confirm("Apply this plan?") {
		return 2
	}
	fmt.Println()
	res, err := install.Apply(env, plan, Version, time.Now(), func(s string) { fmt.Println("- " + s) })
	fmt.Println()
	fmt.Print(res.Summary())
	if err != nil {
		fmt.Fprintln(os.Stderr, "\nflowsightd install: stopped:", err)
		fmt.Fprintln(os.Stderr, "What was done up to this point is recorded in install.json in the data directory.")
		return 1
	}
	if res.Verify != nil && !res.Verify.Answering {
		return 1
	}
	return 0
}

// confirm asks on the terminal; without one it says how to go on unattended.
func confirm(question string) bool {
	if st, err := os.Stdin.Stat(); err != nil || st.Mode()&os.ModeCharDevice == 0 {
		fmt.Fprintln(os.Stderr, "\nNothing was changed: there is no terminal to confirm on. Run with -yes to go ahead without asking.")
		return false
	}
	fmt.Print("\n" + question + " [y/N] ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
		fmt.Println("Nothing was changed.")
		return false
	}
	return true
}

// runUninstall is `flowsightd uninstall`: reverse what flowsightd install
// recorded, after withdrawing everything FlowSight put in front of traffic.
func runUninstall(args []string) int {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	dry := fs.Bool("dry-run", false, "print what would be undone; change nothing")
	yes := fs.Bool("yes", false, "go ahead without asking")
	purge := fs.Bool("purge", false, "also remove the configuration, the data and the logs")
	withdraw := fs.Bool("withdraw", false, "only take away what FlowSight put in front of traffic (pf anchors, its squid, its resolver files); for package removal scripts")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	env := install.LocalEnv()
	facts := install.Detect(env)
	var u install.UninstallPlan
	var err error
	if *withdraw {
		u, err = install.PlanWithdraw(env, facts)
	} else {
		u, err = install.PlanUninstall(env, facts, *purge)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "flowsightd uninstall:", err)
		return 1
	}
	fmt.Println("Uninstalling would:")
	for i, s := range u.Steps {
		line := fmt.Sprintf("  %d. %s", i+1, s.Do)
		switch {
		case s.From != "":
			line += ": " + s.From + " -> " + s.Path
		case s.Path != "":
			line += ": " + s.Path
		case s.Command != "":
			line += ": " + s.Command
		}
		fmt.Println(line)
	}
	for _, k := range u.Keeps {
		fmt.Println("Kept: " + k + ".")
	}
	if *dry {
		return 0
	}
	if !facts.Root {
		fmt.Fprintln(os.Stderr, "flowsightd uninstall: needs root")
		return 1
	}
	if !*yes && !confirm("Uninstall FlowSight?") {
		return 2
	}
	fmt.Println()
	if err := install.Uninstall(env, u, func(s string) { fmt.Println("- " + s) }); err != nil {
		fmt.Fprintln(os.Stderr, "\nflowsightd uninstall: some steps failed:", err)
		return 1
	}
	if *withdraw {
		fmt.Println("\nFlowSight is no longer in front of any traffic.")
		return 0
	}
	fmt.Println("\nFlowSight is uninstalled.")
	return 0
}
