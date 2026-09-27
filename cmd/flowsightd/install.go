package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/grioghar/flowsight/internal/install"
)

// runInstall is `flowsightd install`: detect the machine, write a plan and,
// with -dry-run, stop there. Applying a plan is not built yet.
func runInstall(args []string) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	dry := fs.Bool("dry-run", false, "detect and print the plan; change nothing")
	asJSON := fs.Bool("json", false, "print the plan as JSON (the plan file format) instead of plain words")
	out := fs.String("plan-out", "", "also write the plan to this file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	plan := install.MakePlan(install.Detect(install.LocalEnv()), time.Now())
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
	if !*dry {
		fmt.Fprintln(os.Stderr, "\nApplying a plan is not built yet; nothing was changed. Use -dry-run to see the plan.")
		return 2
	}
	return 0
}
