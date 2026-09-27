package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/grioghar/flowsight/internal/provideragent"
)

// runProvider is `flowsightd provider suricata`: run beside Suricata (in its
// pod, its container or on its host), tail its EVE log and send it to the
// core over the provider protocol.
func runProvider(args []string) int {
	if len(args) == 0 || args[0] != "suricata" {
		fmt.Fprintln(os.Stderr, "usage: flowsightd provider suricata -core <url> [-eve <path>] [-state <path>] [-types alert,tls]")
		fmt.Fprintln(os.Stderr, "the token is a named API token, read from FLOWSIGHT_PROVIDER_TOKEN or -token-file")
		return 2
	}
	fs := flag.NewFlagSet("provider suricata", flag.ContinueOnError)
	coreURL := fs.String("core", "", "the core's URL, e.g. http://flowsight:8080")
	eve := fs.String("eve", "/var/log/suricata/eve.json", "Suricata's EVE log")
	tokenFile := fs.String("token-file", "", "file holding the named API token (else FLOWSIGHT_PROVIDER_TOKEN)")
	state := fs.String("state", "", "file to keep the read position in across restarts")
	types := fs.String("types", "alert,tls", "EVE event types to send")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	token := os.Getenv("FLOWSIGHT_PROVIDER_TOKEN")
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "flowsightd provider:", err)
			return 1
		}
		token = strings.TrimSpace(string(b))
	}
	if *coreURL == "" || token == "" {
		fmt.Fprintln(os.Stderr, "flowsightd provider: -core and a token (FLOWSIGHT_PROVIDER_TOKEN or -token-file) are required")
		return 2
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil)).With("provider", "suricata")
	a := provideragent.New(provideragent.Config{Core: *coreURL, Token: token, EVE: *eve, State: *state,
		Types: strings.Split(*types, ","), Version: Version}, func(s string) { log.Info(s) })
	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() { <-sig; close(stop) }()
	log.Info("sending Suricata's EVE log to the core", "eve", *eve, "core", *coreURL)
	a.Run(stop)
	return 0
}
