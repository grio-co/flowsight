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
	if err := fs.Parse(args); err != nil {
		return 2
	}
	env := install.LocalEnv()
	plan := install.MakePlan(install.Detect(env), time.Now())
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
	if !*yes {
		if st, err := os.Stdin.Stat(); err != nil || st.Mode()&os.ModeCharDevice == 0 {
			fmt.Fprintln(os.Stderr, "\nNot applied: no terminal to confirm on. Run with -yes to apply without asking.")
			return 2
		}
		fmt.Print("\nApply this plan? [y/N] ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			fmt.Println("Nothing was changed.")
			return 0
		}
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
