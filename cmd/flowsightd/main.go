// flowsightd is the FlowSight daemon: collection, storage, policy, API and UI
// in one static binary.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/grioghar/flowsight/internal/core"
	"github.com/grioghar/flowsight/internal/modules/assistant"
	_ "github.com/grioghar/flowsight/internal/modules"
	"github.com/grioghar/flowsight/web"
)

// Version is set at build time with -ldflags "-X main.Version=...".
var Version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	cfgPath := flag.String("config", "", "config file (default: platform etc dir)")
	dataDir := flag.String("data-dir", "", "store directory")
	level := flag.String("log-level", "", "debug, info, warn, error")
	check := flag.Bool("check", false, "load modules, print health as JSON, exit")
	version := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *version {
		fmt.Println("flowsightd", Version)
		return 0
	}

	// Handle subcommands
	args := flag.Args()
	if len(args) > 0 {
		switch args[0] {
		case "mcp":
			return runMCP(*cfgPath, *dataDir, *level)
		}
	}

	var static fs.FS
	if sub, err := fs.Sub(web.Files, "static"); err == nil {
		static = sub
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	c, err := core.New(Version, *cfgPath, *dataDir, static, logger)
	if err != nil {
		fmt.Fprintln(os.Stderr, "flowsightd:", err)
		return 1
	}
	lvl := *level
	if lvl == "" {
		lvl = c.Config.Core().LogLevel
	}
	logger = slog.New(slog.NewTextHandler(logWriter(c), &slog.HandlerOptions{Level: parseLevel(lvl)}))
	slog.SetDefault(logger)
	c.Log = logger
	c.Scheduler = core.NewScheduler(c.Config.Core().Workers, logger.With("component", "scheduler"))
	c.API = core.NewAPI(c, static, logger.With("component", "api"))

	if *check {
		c.LoadModules()
		h, _ := c.API.OpenAPI(), 0
		_ = h
		out := map[string]any{"version": Version, "platform": c.Platform,
			"modules": len(c.Modules), "errors": len(c.Errors)}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		if len(c.Errors) > 0 {
			for n, e := range c.Errors {
				fmt.Fprintf(os.Stderr, "module %s: %s\n", n, e)
			}
			return 2
		}
		return 0
	}

	// A firewall is not a place to let the heap sprawl: ask the collector to
	// keep the process near the limit and give memory back promptly. The soft
	// limit is a target, not a cap; correctness never depends on it.
	limit := c.Config.Core().MemoryLimitMB
	if limit <= 0 {
		limit = 256
	}
	debug.SetMemoryLimit(int64(limit) << 20)
	debug.SetGCPercent(50)

	stop := make(chan struct{})
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		close(stop)
	}()
	if err := c.Run(stop); err != nil {
		logger.Error("flowsightd stopped with error", "error", err.Error())
		return 1
	}
	return 0
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

// logWriter tees to stderr and a rotating file in the platform log dir.
func logWriter(c *core.Core) *teeWriter {
	tw := &teeWriter{}
	dir := c.Platform.LogDir
	if err := os.MkdirAll(dir, 0o755); err == nil {
		tw.path = filepath.Join(dir, "flowsightd.log")
		tw.open()
	}
	return tw
}

type teeWriter struct {
	path string
	f    *os.File
	size int64
}

func (t *teeWriter) open() {
	f, err := os.OpenFile(t.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return
	}
	if st, err := f.Stat(); err == nil {
		t.size = st.Size()
	}
	t.f = f
}

func (t *teeWriter) Write(p []byte) (int, error) {
	_, _ = os.Stderr.Write(p)
	if t.f != nil {
		n, _ := t.f.Write(p)
		t.size += int64(n)
		if t.size > 10<<20 {
			t.f.Close()
			_ = os.Rename(t.path, t.path+".1")
			t.size = 0
			t.open()
		}
	}
	return len(p), nil
}

// runMCP runs the MCP stdio server for Claude Code integration.
func runMCP(cfgPath, dataDir, level string) int {
	var static fs.FS
	if sub, err := fs.Sub(web.Files, "static"); err == nil {
		static = sub
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	c, err := core.New(Version, cfgPath, dataDir, static, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flowsightd mcp: %v\n", err)
		return 1
	}

	// Load modules
	c.LoadModules()

	// Create and run the MCP server
	server := assistant.NewMCPServer(context.Background(), c)
	if err := server.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "flowsightd mcp: %v\n", err)
		return 1
	}
	return 0
}
