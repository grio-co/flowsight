package assistant

// `flowsightd mcp`: the stdio face of the MCP server for clients that speak
// JSON-RPC over a pipe (Claude Code, the Agent SDK, Claude Desktop). It is
// deliberately thin: every request is forwarded to the running daemon's
// POST /api/mcp and the answer written back, so there is one implementation
// of the tools and this process never opens the daemon's store.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Bridge forwards JSON-RPC lines between a stdio client and the daemon.
type Bridge struct {
	Base   string // e.g. http://127.0.0.1:8080
	Token  string
	In     io.Reader
	Out    io.Writer
	Client *http.Client
}

// Target resolves where the daemon is: FLOWSIGHT_URL / FLOWSIGHT_TOKEN, else
// the daemon's own config file (bind, port, api_token at the top level).
func Target(configPath string) (base, token string) {
	base, token = os.Getenv("FLOWSIGHT_URL"), os.Getenv("FLOWSIGHT_TOKEN")
	if base != "" {
		return strings.TrimRight(base, "/"), token
	}
	host, port := "127.0.0.1", 8080
	if configPath != "" {
		if b, err := os.ReadFile(configPath); err == nil {
			var cfg struct {
				Bind     string `json:"bind"`
				Port     int    `json:"port"`
				APIToken string `json:"api_token"`
			}
			if json.Unmarshal(b, &cfg) == nil {
				if cfg.Port > 0 {
					port = cfg.Port
				}
				if cfg.Bind != "" && cfg.Bind != "0.0.0.0" && cfg.Bind != "::" && cfg.Bind != "[::]" {
					host = cfg.Bind
					if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
						host = "[" + host + "]"
					}
				}
				if token == "" {
					token = cfg.APIToken
				}
			}
		}
	}
	return fmt.Sprintf("http://%s:%d", host, port), token
}

// Run reads one JSON-RPC message per line until EOF.
func (b *Bridge) Run() error {
	if b.Client == nil {
		b.Client = &http.Client{Timeout: 120 * time.Second}
	}
	sc := bufio.NewScanner(b.In)
	sc.Buffer(make([]byte, 1<<20), 32<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var probe struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			b.write(map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": -32700, "message": "parse error: " + err.Error()}})
			continue
		}
		resp, err := b.forward(line)
		if err != nil {
			if len(probe.ID) == 0 || string(probe.ID) == "null" {
				continue // a notification: nothing to answer
			}
			b.write(map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(probe.ID), "error": map[string]any{"code": -32000, "message": err.Error()}})
			continue
		}
		if len(bytes.TrimSpace(resp)) == 0 || string(bytes.TrimSpace(resp)) == "null" {
			continue // notification acknowledged silently
		}
		fmt.Fprintf(b.Out, "%s\n", bytes.TrimSpace(resp))
	}
	return sc.Err()
}

func (b *Bridge) write(v any) {
	j, _ := json.Marshal(v)
	fmt.Fprintf(b.Out, "%s\n", j)
}

func (b *Bridge) forward(line []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", b.Base+"/api/mcp", bytes.NewReader(line))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "Flowsight")
	if b.Token != "" {
		req.Header.Set("X-Flowsight-Token", b.Token)
	}
	resp, err := b.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("flowsightd unreachable at %s: %v", b.Base, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, fmt.Errorf("flowsightd refused the token (HTTP %d); set FLOWSIGHT_TOKEN", resp.StatusCode)
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("flowsightd: HTTP %d", resp.StatusCode)
	}
	return body, nil
}

// RunStdio is what `flowsightd mcp` calls.
func RunStdio(configPath string) error {
	base, token := Target(configPath)
	b := &Bridge{Base: base, Token: token, In: os.Stdin, Out: os.Stdout}
	return b.Run()
}
