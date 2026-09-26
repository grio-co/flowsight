package assistant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// A real core with every module loaded, so the tool list is the real one.
func testModule(t *testing.T) *Module {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := core.New("0.9.8r000000000000", "", t.TempDir(), nil, logger)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	c.LoadModules()
	m, ok := c.Modules["assistant"].(*Module)
	if !ok {
		t.Fatal("assistant module not loaded")
	}
	m.config.MaxToolResultBytes = 65536
	m.config.MaxTurns = 4
	m.config.TimeoutSeconds = 30
	// This package's test binary links only the modules it imports, so the
	// registry here is small; a few routes shaped like the real ones stand
	// in. The full-registry count is asserted in internal/apidoc, which
	// imports every module.
	h := func(r *core.Req) (any, error) { return map[string]any{"ok": true}, nil }
	m.ctx.Route("GET", "/api/visibility/flows", h, core.Doc("Recent sessions with filters for testing"),
		core.Query("minutes", "integer", "window", false, 60), core.Query("ip", "string", "either end", false, "192.168.1.10"),
		core.Returns("flows", map[string]any{"flows": []any{}}))
	m.ctx.Route("GET", "/api/visibility/abroad", h, core.Doc("Devices talking to other countries, for testing"),
		core.Query("hours", "integer", "window", false, 24), core.Returns("devices", map[string]any{"devices": []any{}}))
	m.ctx.Route("GET", "/api/identity/hosts", h, core.Doc("Hosts seen recently, for testing"),
		core.Query("hours", "integer", "window", false, 24), core.Returns("hosts", map[string]any{"hosts": []any{}}))
	m.ctx.Route("POST", "/api/policy/apply", h, core.Write(), core.Doc("Apply the policy plan, for testing"), core.Returns("ok", map[string]any{"ok": true}))
	m.ctx.Route("POST", "/api/visibility/abroad", h, core.Write(), core.Doc("A write route sharing a read route's path, for testing"), core.Returns("ok", map[string]any{"ok": true}))
	m.ensureTools()
	return m
}

func TestRouteToToolName(t *testing.T) {
	for path, want := range map[string]string{"/api/visibility/flows": "visibility_flows", "/api/policy/matches": "policy_matches", "/api/paths/path/{ip}": "paths_path_by_ip", "/api/alerting/channel-types": "alerting_channel_types"} {
		if got := routeToToolName(path); got != want {
			t.Errorf("%s -> %s, want %s", path, got, want)
		}
	}
}

func TestToolsAreTheRealRoutesAndCallsReachTheDaemon(t *testing.T) {
	m := testModule(t)
	if len(m.tools) < 3 {
		t.Fatalf("expected the registered routes as tools, got %d", len(m.tools))
	}
	var seenPath, seenQuery, seenToken string
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath, seenQuery, seenToken = r.URL.Path, r.URL.RawQuery, r.Header.Get("X-Flowsight-Token")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"flows":[{"src_ip":"192.168.1.10","dst_ip":"8.8.8.8"}],"home_country":"US"}`)
	}))
	defer daemon.Close()
	t.Setenv("FLOWSIGHT_URL", daemon.URL)
	t.Setenv("FLOWSIGHT_TOKEN", "secret-1")
	req := []byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"visibility_flows","arguments":{"minutes":60,"ip":"192.168.1.10"}}}`)
	resp := m.handleMCPRequest(context.Background(), req)
	b, _ := json.Marshal(resp)
	if seenPath != "/api/visibility/flows" || !strings.Contains(seenQuery, "minutes=60") || !strings.Contains(seenQuery, "ip=192.168.1.10") {
		t.Fatalf("daemon saw %s?%s", seenPath, seenQuery)
	}
	if seenToken != "secret-1" {
		t.Fatalf("token not sent: %q", seenToken)
	}
	if !strings.Contains(string(b), "8.8.8.8") || strings.Contains(string(b), "would be called") {
		t.Fatalf("result not relayed: %s", b)
	}
	// A tool whose path also has a write route still calls the read route.
	var method string
	daemon2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { method = r.Method; fmt.Fprint(w, `{"devices":[]}`) }))
	defer daemon2.Close()
	t.Setenv("FLOWSIGHT_URL", daemon2.URL)
	m.handleMCPRequest(context.Background(), []byte(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"visibility_abroad","arguments":{"hours":24}}}`))
	if method != "GET" {
		t.Fatalf("expected the GET route, got %s", method)
	}
	t.Setenv("FLOWSIGHT_URL", daemon.URL)
	// Unknown tool is a JSON-RPC error, not a crash.
	resp = m.handleMCPRequest(context.Background(), []byte(`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"nope","arguments":{}}}`))
	if _, ok := resp["error"]; !ok {
		t.Fatal("unknown tool should error")
	}
	// A notification gets no reply.
	if m.handleMCPRequest(context.Background(), []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)) != nil {
		t.Fatal("notification answered")
	}
	// Write routes are absent unless allowed.
	for _, tl := range m.tools {
		if tl.Name == "policy_apply" {
			t.Fatal("write tool present without allow_writes")
		}
	}
}

// sse writes one Anthropic-style event stream.
func sse(w http.ResponseWriter, events ...string) {
	w.Header().Set("Content-Type", "text/event-stream")
	for _, e := range events {
		fmt.Fprintf(w, "data: %s\n\n", e)
	}
}

func TestAnthropicLoopCallsToolsAndStreams(t *testing.T) {
	m := testModule(t)
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/visibility/abroad" || r.URL.Query().Get("hours") != "24" {
			t.Errorf("unexpected daemon call %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		fmt.Fprint(w, `{"devices":[{"ip":"192.168.2.145","name":"roku","countries":[{"country":"CA","sessions":71}]}],"home_country":"US"}`)
	}))
	defer daemon.Close()
	t.Setenv("FLOWSIGHT_URL", daemon.URL)
	calls := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("x-api-key") != "k" || r.Header.Get("anthropic-version") == "" {
			t.Errorf("headers: %v", r.Header)
		}
		body, _ := io.ReadAll(r.Body)
		if calls == 1 {
			if !bytes.Contains(body, []byte(`"tools"`)) || !bytes.Contains(body, []byte(`visibility_abroad`)) {
				t.Errorf("first request lacks tools: %s", body[:200])
			}
			sse(w,
				`{"type":"message_start","message":{"usage":{"input_tokens":120}}}`,
				`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
				`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Let me look."}}`,
				`{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"tu_1","name":"visibility_abroad"}}`,
				`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"hours\""}}`,
				`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":": 24}"}}`,
				`{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":30}}`,
				`{"type":"message_stop"}`)
			return
		}
		if !bytes.Contains(body, []byte(`"tool_result"`)) || !bytes.Contains(body, []byte(`roku`)) {
			t.Errorf("second request lacks the tool result: %s", body)
		}
		sse(w,
			`{"type":"message_start","message":{"usage":{"input_tokens":300}}}`,
			`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
			`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"roku reached Canada "}}`,
			`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"71 times."}}`,
			`{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":12}}`,
			`{"type":"message_stop"}`)
	}))
	defer api.Close()
	t.Setenv("FLOWSIGHT_ANTHROPIC_URL", api.URL)
	cfg := m.config
	cfg.Provider, cfg.APIKey, cfg.Model = "anthropic", "k", "claude-sonnet-5"
	var types []string
	res, err := m.run(context.Background(), "who talked abroad?", cfg, func(ev Event) { types = append(types, ev.Type) })
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || res.Turns != 2 {
		t.Fatalf("calls %d turns %d", calls, res.Turns)
	}
	if !strings.Contains(res.Answer, "roku reached Canada 71 times.") {
		t.Fatalf("answer: %q", res.Answer)
	}
	if len(res.Calls) != 1 || res.Calls[0].ToolName != "visibility_abroad" || !strings.Contains(res.Calls[0].Route, "hours=24") {
		t.Fatalf("tool trail: %+v", res.Calls)
	}
	want := []string{"text", "tool_call", "tool_result", "text", "text"}
	if strings.Join(types, ",") != strings.Join(want, ",") {
		t.Fatalf("events %v", types)
	}
	if res.InputTokens != 420 || res.OutputTokens != 42 {
		t.Fatalf("tokens %d/%d", res.InputTokens, res.OutputTokens)
	}
}

func fakeClaude(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "claude")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestClaudeCodeProviderRelaysTheTranscript(t *testing.T) {
	m := testModule(t)
	script := fakeClaude(t, `
# the arguments Claude Code is given, for the assertion below
printf '%s\n' "$@" > "$(dirname "$0")/argv"
cat <<'JSON'
{"type":"system","subtype":"init","session_id":"s1","tools":["mcp__flowsight__visibility_flows"]}
{"type":"assistant","message":{"content":[{"type":"text","text":"Checking."},{"type":"tool_use","id":"t1","name":"mcp__flowsight__identity_hosts","input":{"hours":24}}],"usage":{"input_tokens":50,"output_tokens":10}}}
{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t1","content":"{\"hosts\":[{\"ip\":\"192.168.1.115\",\"name\":\"echo\"}]}"}]}}
{"type":"assistant","message":{"content":[{"type":"text","text":"192.168.1.115 is an Amazon Echo."}],"usage":{"input_tokens":80,"output_tokens":9}}}
{"type":"result","subtype":"success","result":"192.168.1.115 is an Amazon Echo.","num_turns":2,"total_cost_usd":0.01}
JSON
`)
	cfg := m.config
	cfg.Provider, cfg.ClaudePath, cfg.MaxTurns, cfg.TimeoutSeconds = "claude-code", script, 6, 20
	var types []string
	res, err := m.run(context.Background(), "what is 192.168.1.115?", cfg, func(ev Event) { types = append(types, ev.Type) })
	if err != nil {
		t.Fatal(err)
	}
	if res.Answer != "Checking.\n192.168.1.115 is an Amazon Echo." || res.Turns != 2 {
		t.Fatalf("answer %q turns %d", res.Answer, res.Turns)
	}
	if len(res.Calls) != 1 || res.Calls[0].ToolName != "identity_hosts" || res.Calls[0].Summary != "1 hosts" {
		t.Fatalf("trail %+v", res.Calls)
	}
	if strings.Join(types, ",") != "text,tool_call,tool_result,text" {
		t.Fatalf("events %v", types)
	}
	argv, _ := os.ReadFile(filepath.Join(filepath.Dir(script), "argv"))
	for _, want := range []string{"-p", "what is 192.168.1.115?", "--output-format", "stream-json", "--verbose", "--max-turns", "6", "--append-system-prompt", "--mcp-config", "--allowedTools", "mcp__flowsight__*", "--disallowedTools", "--permission-mode", "default"} {
		if !strings.Contains(string(argv), want+"\n") {
			t.Fatalf("argv lacks %q:\n%s", want, argv)
		}
	}
	if strings.Contains(string(argv), "x-api-key") {
		t.Fatal("no key must reach the CLI")
	}
}

func TestClaudeCodeProviderTimesOut(t *testing.T) {
	m := testModule(t)
	script := fakeClaude(t, "sleep 5\n")
	cfg := m.config
	cfg.Provider, cfg.ClaudePath, cfg.TimeoutSeconds = "claude-code", script, 1
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	_, err := m.run(ctx, "slow?", cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("expected a timeout error, got %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("the process was not killed at the deadline")
	}
}

func TestRedactIsStable(t *testing.T) {
	m := testModule(t)
	a := m.redact("192.168.1.10 talked to 8.8.8.8 and fd00::1 from aa:bb:cc:dd:ee:ff")
	b := m.redact("again 192.168.1.10")
	if strings.Contains(a, "192.168.1.10") || !strings.Contains(a, "8.8.8.8") || !strings.Contains(a, "host-1") || !strings.Contains(a, "host6-") || !strings.Contains(a, "mac-") {
		t.Fatalf("redaction: %q", a)
	}
	if !strings.Contains(b, "host-1") {
		t.Fatalf("placeholder not stable: %q", b)
	}
}

func TestBridgeForwardsToTheDaemon(t *testing.T) {
	var got []string
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = append(got, r.Header.Get("X-Flowsight-Token")+" "+r.URL.Path+" "+string(body))
		var probe struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.Unmarshal(body, &probe)
		if strings.HasPrefix(probe.Method, "notifications/") {
			fmt.Fprint(w, "null")
			return
		}
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"ok":"%s"}}`, probe.ID, probe.Method)
	}))
	defer daemon.Close()
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
		`not json` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n")
	var out bytes.Buffer
	b := &Bridge{Base: daemon.URL, Token: "tok", In: in, Out: &out}
	if err := b.Run(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 output lines (2 answers + 1 parse error), got %d: %s", len(lines), out.String())
	}
	if !strings.Contains(lines[0], `"initialize"`) || !strings.Contains(lines[1], "-32700") || !strings.Contains(lines[2], `"tools/list"`) {
		t.Fatalf("bridge output: %s", out.String())
	}
	if len(got) != 3 || !strings.HasPrefix(got[0], "tok /api/mcp") {
		t.Fatalf("daemon saw %v", got)
	}
}

func TestConversationsPersistInTheStore(t *testing.T) {
	m := testModule(t)
	m.saveConversation(&Conversation{ID: "c-1", Question: "q1", Answer: "a1", CreatedAt: 10})
	m.saveConversation(&Conversation{ID: "c-2", Question: "q2", Answer: "a2", CreatedAt: 20})
	if ids := m.convIndex(); len(ids) != 2 || ids[0] != "c-2" {
		t.Fatalf("index %v", ids)
	}
	if c := m.getConversation("c-1"); c == nil || c.Answer != "a1" {
		t.Fatal("c-1 not stored")
	}
	if !m.deleteConversation("c-1") || m.getConversation("c-1") != nil || m.deleteConversation("c-1") {
		t.Fatal("delete")
	}
	m.config.RetentionDays = 1
	if err := m.cleanConversations(); err != nil || m.getConversation("c-2") != nil {
		t.Fatal("retention did not remove an old conversation")
	}
}

func TestClaudeCodeOverSSHQuotesAndAttachesHTTPMCP(t *testing.T) {
	m := testModule(t)
	m.ctx.Platform.EtcDir = t.TempDir()
	fake := fakeClaude(t, `
printf '%s\n' "$@" > "$(dirname "$0")/argv"
cat <<'JSON'
{"type":"assistant","message":{"content":[{"type":"text","text":"echo it is"}],"usage":{"input_tokens":5,"output_tokens":3}}}
{"type":"result","subtype":"success","result":"echo it is","num_turns":1}
JSON
`)
	cfg := m.config
	cfg.Provider, cfg.ClaudeSSH, cfg.ClaudePath, cfg.SSHPath, cfg.MCPURL = "claude-code", "grio@192.168.1.190", "/home/grio/.local/bin/claude", fake, "http://192.168.0.1:8080/api/mcp"
	cfg.MaxTurns, cfg.TimeoutSeconds = 6, 20
	t.Setenv("FLOWSIGHT_TOKEN", "tok-1")
	res, err := m.run(context.Background(), "what's 192.168.1.115? it's \"the echo\"", cfg, nil)
	if err != nil || res.Answer != "echo it is" {
		t.Fatalf("answer %q err %v", res.Answer, err)
	}
	argv, _ := os.ReadFile(filepath.Join(filepath.Dir(fake), "argv"))
	a := string(argv)
	for _, want := range []string{"BatchMode=yes", "StrictHostKeyChecking=accept-new", "grio@192.168.1.190", "-T", "--"} {
		if !strings.Contains(a, want+"\n") {
			t.Fatalf("ssh argv lacks %q:\n%s", want, a)
		}
	}
	lines := strings.Split(strings.TrimSpace(a), "\n")
	remote := lines[len(lines)-1]
	for _, want := range []string{"'/home/grio/.local/bin/claude' '-p' 'what'\\''s 192.168.1.115? it'\\''s \"the echo\"'", "'--output-format' 'stream-json'", "'--mcp-config' '{\"mcpServers\":{\"flowsight\":{\"headers\":{\"X-Flowsight-Token\":\"tok-1\"},\"type\":\"http\",\"url\":\"http://192.168.0.1:8080/api/mcp\"}}}'", "'--allowedTools' 'mcp__flowsight__*'"} {
		if !strings.Contains(remote, want) {
			t.Fatalf("remote command lacks %q:\n%s", want, remote)
		}
	}
	if _, err := os.Stat(filepath.Join(m.ctx.Platform.EtcDir, "assistant_ssh_key")); err != nil {
		t.Fatal("ssh key was not generated")
	}
}

func TestGeneratedSSHKeyIsOpenSSHFormat(t *testing.T) {
	m := testModule(t)
	m.ctx.Platform.EtcDir = t.TempDir()
	cfg := m.config
	pub, err := m.sshPublicKey(cfg)
	if err != nil || !strings.HasPrefix(pub, "ssh-ed25519 AAAA") || !strings.HasSuffix(pub, " flowsight-assistant") {
		t.Fatalf("public key %q err %v", pub, err)
	}
	priv := filepath.Join(m.ctx.Platform.EtcDir, "assistant_ssh_key")
	if b, _ := os.ReadFile(priv); !bytes.HasPrefix(b, []byte("-----BEGIN OPENSSH PRIVATE KEY-----")) {
		t.Fatal("private key is not an OpenSSH file")
	}
	// The real ssh-keygen must accept it and derive the same public key.
	if kg, err := exec.LookPath("ssh-keygen"); err == nil {
		out, err := exec.Command(kg, "-y", "-f", priv).Output()
		if err != nil {
			t.Fatalf("ssh-keygen rejects the key: %v", err)
		}
		if strings.Fields(string(out))[1] != strings.Fields(pub)[1] {
			t.Fatalf("ssh-keygen derives a different public key:\n%s\n%s", out, pub)
		}
	}
	again, _ := m.sshPublicKey(cfg)
	if again != pub {
		t.Fatal("key regenerated on second call")
	}
}
