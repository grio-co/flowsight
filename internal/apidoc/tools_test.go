package apidoc

import (
	"io"
	"log/slog"
	"testing"

	"github.com/grioghar/flowsight/internal/core"
	_ "github.com/grioghar/flowsight/internal/modules" // every module registers its routes
	"github.com/grioghar/flowsight/internal/modules/assistant"
)

// With every module loaded, the assistant exposes the whole read-only API
// as tools: one per GET route outside itself.
func TestAssistantToolsCoverTheAPI(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := core.New("0.9.8r000000000000", "", t.TempDir(), nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	c.LoadModules()
	m := c.Modules["assistant"].(*assistant.Module)
	gets := 0
	c.API.IterateRoutes(func(method, path string, _ *core.Route) {
		if method == "GET" && !contains(path, "/api/assistant") && !contains(path, "/api/mcp") {
			gets++
		}
	})
	if n := m.ToolCount(); n != gets || n < 100 {
		t.Fatalf("tools %d, GET routes %d", n, gets)
	}
	t.Logf("MCP tools on the real registry: %d", m.ToolCount())
}

func contains(s, sub string) bool {
	return len(sub) <= len(s) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
