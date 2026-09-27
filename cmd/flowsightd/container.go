package main

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/grioghar/flowsight/internal/install"
)

// runContainer is the FlowSight image's entrypoint: settle the
// configuration with the installer in container mode, then become the
// daemon, keeping process 1.
func runContainer(args []string) int {
	env := install.LocalEnv()
	plan := install.MakePlan(install.Detect(env), time.Now())
	if plan.Service != "container" {
		fmt.Fprintln(os.Stderr, "flowsightd container is the FlowSight image's entrypoint; on a host use flowsightd install")
		return 2
	}
	if err := install.PrepareContainer(env); err != nil {
		fmt.Fprintln(os.Stderr, "flowsightd container:", err)
		return 1
	}
	res, err := install.Apply(env, plan, Version, time.Now(), func(string) {})
	fmt.Print(res.Summary())
	if err != nil {
		fmt.Fprintln(os.Stderr, "flowsightd container:", err)
		return 1
	}
	cfg := plan.Paths["config"]
	if err := install.ContainerConfig(env, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "flowsightd container:", err)
		return 1
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "flowsightd container:", err)
		return 1
	}
	argv := append([]string{"flowsightd", "-config", cfg}, args...)
	err = syscall.Exec(exe, argv, os.Environ())
	fmt.Fprintln(os.Stderr, "flowsightd container: starting the daemon:", err)
	return 1
}

// runHealth exits 0 when the daemon answers on loopback: the image's health
// check and the Kubernetes probes.
func runHealth(args []string) int {
	env := install.LocalEnv()
	plan := install.MakePlan(install.Detect(env), time.Now())
	cfg := plan.Paths["config"]
	if len(args) > 0 {
		cfg = args[0]
	}
	if err := install.Probe(env, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "flowsightd health:", err)
		return 1
	}
	return 0
}
