package assistant

// Two ways to put Claude to work on FlowSight's data. With the anthropic
// provider the daemon runs the agent loop itself against the Messages API:
// the model is given FlowSight's routes as tools, asks for the ones it
// wants, the daemon calls its own API and hands the results back, until the
// model answers. With the claude-code provider the loop belongs to Claude
// Code (the same harness the Agent SDK drives), run headless with FlowSight
// attached as an MCP server; the daemon relays its transcript. Either way
// the operator sees the same stream: text as it arrives, each tool call and
// what came back, then done.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// Event is one step of an answer as the page sees it.
type Event struct {
	Type         string         `json:"type"` // text | tool_call | tool_result | done | error
	Text         string         `json:"text,omitempty"`
	Tool         string         `json:"tool,omitempty"`
	Route        string         `json:"route,omitempty"`
	Args         map[string]any `json:"args,omitempty"`
	Summary      string         `json:"summary,omitempty"`
	Bytes        int            `json:"bytes,omitempty"`
	Error        string         `json:"error,omitempty"`
	ID           string         `json:"id,omitempty"`
	Turns        int            `json:"turns,omitempty"`
	InputTokens  int            `json:"input_tokens,omitempty"`
	OutputTokens int            `json:"output_tokens,omitempty"`
}

type runResult struct {
	Answer                    string
	Calls                     []ToolCallRecord
	Turns                     int
	InputTokens, OutputTokens int
}

const systemPrompt = `You are FlowSight's analyst. FlowSight is a network visibility and policy daemon on the operator's own gateway; every address, device name and domain you are shown belongs to their network and they are entitled to see it. Answer from FlowSight's data by calling its tools; do not guess what a tool can tell you. Prefer the narrowest tool and the smallest window that answers the question. Say which tools you looked at, in one short line at the end. Be brief and concrete: names, counts, times, countries. If the data does not say, say so.`

const anthropicURL = "https://api.anthropic.com/v1/messages"

// run answers one question with the configured provider, emitting events as
// it goes, and returns the collected answer and tool trail.
func (m *Module) run(ctx context.Context, question string, cfg assistConfig, emit func(Event)) (runResult, error) {
	if emit == nil {
		emit = func(Event) {}
	}
	switch cfg.Provider {
	case "anthropic":
		return m.runAnthropic(ctx, question, cfg, emit, true)
	case "claude-code":
		return m.runClaudeCode(ctx, question, cfg, emit)
	}
	return runResult{}, errors.New("the assistant is off")
}

// Complete is the plain form other modules use (the map's hop lookup): one
// prompt, one answer, no tools.
func (m *Module) Complete(ctx context.Context, prompt string) (string, error) {
	cfg := m.cfg()
	if !cfg.on() {
		return "", errors.New("the assistant is off")
	}
	if cfg.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(cfg.TimeoutSeconds)*time.Second)
		defer cancel()
	}
	var res runResult
	var err error
	if cfg.Provider == "anthropic" {
		res, err = m.runAnthropic(ctx, prompt, cfg, func(Event) {}, false)
	} else {
		res, err = m.runClaudeCodePlain(ctx, prompt, cfg)
	}
	return res.Answer, err
}

// ---------------------------------------------------------------- anthropic

type anthropicBlock struct {
	Type  string
	ID    string
	Name  string
	Text  strings.Builder
	Input strings.Builder
}

func (m *Module) anthropicEndpoint() string {
	if u := os.Getenv("FLOWSIGHT_ANTHROPIC_URL"); u != "" {
		return u
	}
	return anthropicURL
}

func (m *Module) runAnthropic(ctx context.Context, question string, cfg assistConfig, emit func(Event), withTools bool) (runResult, error) {
	var res runResult
	if cfg.APIKey == "" {
		return res, errors.New("the anthropic provider needs an API key (Settings › assistant)")
	}
	client := &http.Client{Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second}
	messages := []map[string]any{{"role": "user", "content": question}}
	var tools []map[string]any
	if withTools {
		tools = m.buildMCPToolsForAnthropic()
	}
	var answer strings.Builder
	for turn := 0; turn < cfg.MaxTurns; turn++ {
		res.Turns = turn + 1
		body := map[string]any{"model": cfg.Model, "max_tokens": 2048, "system": systemPrompt, "messages": messages, "stream": true}
		if len(tools) > 0 {
			body["tools"] = tools
		}
		b, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(ctx, "POST", m.anthropicEndpoint(), bytes.NewReader(b))
		if err != nil {
			return res, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", cfg.APIKey)
		req.Header.Set("anthropic-version", "2023-06-01")
		req.Header.Set("Accept", "text/event-stream")
		resp, err := client.Do(req)
		if err != nil {
			return res, err
		}
		if resp.StatusCode != 200 {
			eb, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			return res, fmt.Errorf("anthropic: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(eb)))
		}
		blocks, stop, in, out, err := readAnthropicStream(resp.Body, emit)
		resp.Body.Close()
		if err != nil {
			return res, err
		}
		res.InputTokens += in
		res.OutputTokens += out
		// The assistant turn, as the API wants it back.
		var content []map[string]any
		var toolUses []*anthropicBlock
		for _, bl := range blocks {
			switch bl.Type {
			case "text":
				answer.WriteString(bl.Text.String())
				content = append(content, map[string]any{"type": "text", "text": bl.Text.String()})
			case "tool_use":
				var input map[string]any
				if err := json.Unmarshal([]byte(bl.Input.String()), &input); err != nil || input == nil {
					input = map[string]any{}
				}
				content = append(content, map[string]any{"type": "tool_use", "id": bl.ID, "name": bl.Name, "input": input})
				toolUses = append(toolUses, bl)
			}
		}
		if len(toolUses) == 0 || stop == "end_turn" && len(toolUses) == 0 {
			break
		}
		messages = append(messages, map[string]any{"role": "assistant", "content": content})
		var results []map[string]any
		for _, tu := range toolUses {
			var input map[string]any
			_ = json.Unmarshal([]byte(tu.Input.String()), &input)
			if input == nil {
				input = map[string]any{}
			}
			rec, text := m.execTool(ctx, tu.Name, input, cfg, emit)
			res.Calls = append(res.Calls, rec)
			results = append(results, map[string]any{"type": "tool_result", "tool_use_id": tu.ID, "content": text})
		}
		messages = append(messages, map[string]any{"role": "user", "content": results})
		if answer.Len() > 0 {
			answer.WriteString("\n")
		}
	}
	res.Answer = strings.TrimSpace(answer.String())
	return res, nil
}

// readAnthropicStream reads one streamed message: text deltas are emitted
// as they come, tool inputs are accumulated, and the content blocks are
// returned in order with the stop reason and token counts.
func readAnthropicStream(r io.Reader, emit func(Event)) (blocks []*anthropicBlock, stop string, inTok, outTok int, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	byIndex := map[int]*anthropicBlock{}
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" || data == "[DONE]" {
			continue
		}
		var ev struct {
			Type         string `json:"type"`
			Index        int    `json:"index"`
			ContentBlock struct {
				Type string `json:"type"`
				ID   string `json:"id"`
				Name string `json:"name"`
				Text string `json:"text"`
			} `json:"content_block"`
			Delta struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				PartialJSON string `json:"partial_json"`
				StopReason  string `json:"stop_reason"`
			} `json:"delta"`
			Message struct {
				Usage struct {
					InputTokens int `json:"input_tokens"`
				} `json:"usage"`
			} `json:"message"`
			Usage struct {
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal([]byte(data), &ev) != nil {
			continue
		}
		switch ev.Type {
		case "message_start":
			inTok += ev.Message.Usage.InputTokens
		case "content_block_start":
			bl := &anthropicBlock{Type: ev.ContentBlock.Type, ID: ev.ContentBlock.ID, Name: ev.ContentBlock.Name}
			if ev.ContentBlock.Text != "" {
				bl.Text.WriteString(ev.ContentBlock.Text)
				emit(Event{Type: "text", Text: ev.ContentBlock.Text})
			}
			byIndex[ev.Index] = bl
			blocks = append(blocks, bl)
		case "content_block_delta":
			bl := byIndex[ev.Index]
			if bl == nil {
				continue
			}
			switch ev.Delta.Type {
			case "text_delta":
				bl.Text.WriteString(ev.Delta.Text)
				emit(Event{Type: "text", Text: ev.Delta.Text})
			case "input_json_delta":
				bl.Input.WriteString(ev.Delta.PartialJSON)
			}
		case "message_delta":
			if ev.Delta.StopReason != "" {
				stop = ev.Delta.StopReason
			}
			outTok += ev.Usage.OutputTokens
		case "error":
			return blocks, stop, inTok, outTok, fmt.Errorf("anthropic: %s", ev.Error.Message)
		case "message_stop":
			return blocks, stop, inTok, outTok, nil
		}
	}
	return blocks, stop, inTok, outTok, sc.Err()
}

// execTool runs one tool for the model and tells the page about it.
func (m *Module) execTool(ctx context.Context, name string, input map[string]any, cfg assistConfig, emit func(Event)) (ToolCallRecord, string) {
	name = strings.TrimPrefix(name, "mcp__flowsight__")
	route := m.routeFor(name)
	emit(Event{Type: "tool_call", Tool: name, Route: route, Args: input})
	text, err := m.callToolHTTP(ctx, name, input)
	if err != nil {
		text = "error: " + err.Error()
	}
	if cfg.RedactAddresses {
		text = m.redact(text)
	}
	rec := ToolCallRecord{ToolName: name, Route: routeWithArgs(route, input), Summary: summarise(text), Timestamp: time.Now().Unix()}
	emit(Event{Type: "tool_result", Tool: name, Route: rec.Route, Summary: rec.Summary, Bytes: len(text)})
	return rec, text
}

// routeFor is "GET /api/..." for a tool name.
func (m *Module) routeFor(name string) string {
	out := ""
	m.ctx.Core.API.IterateRoutes(func(method, path string, _ *core.Route) {
		if routeToToolName(path) == name && out == "" {
			out = method + " " + path
		}
	})
	return out
}

func routeWithArgs(route string, args map[string]any) string {
	if len(args) == 0 {
		return route
	}
	var parts []string
	for k, v := range args {
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}
	return route + "?" + strings.Join(parts, "&")
}

// summarise says in a few words what a tool result was: the row count of
// the first array in it, or its first line.
func summarise(text string) string {
	var v any
	if json.Unmarshal([]byte(text), &v) == nil {
		if mm, ok := v.(map[string]any); ok {
			for k, x := range mm {
				if arr, ok := x.([]any); ok {
					return fmt.Sprintf("%d %s", len(arr), k)
				}
			}
			if e, ok := mm["error"].(string); ok {
				return "error: " + e
			}
			return fmt.Sprintf("%d fields", len(mm))
		}
		if arr, ok := v.([]any); ok {
			return fmt.Sprintf("%d rows", len(arr))
		}
	}
	first := strings.TrimSpace(strings.SplitN(text, "\n", 2)[0])
	if len(first) > 80 {
		first = first[:80] + "…"
	}
	return first
}

// ---------------------------------------------------------------- claude-code

// claudeArgs is the invocation, in one place so the docs and tests agree.
func claudeArgs(question string, cfg assistConfig, mcpConfigPath string) []string {
	args := []string{"-p", question, "--output-format", "stream-json", "--verbose",
		"--max-turns", strconv.Itoa(cfg.MaxTurns), "--append-system-prompt", systemPrompt}
	if mcpConfigPath != "" {
		args = append(args, "--mcp-config", mcpConfigPath, "--allowedTools", "mcp__flowsight__*", "--permission-mode", "default")
	}
	return args
}

// runClaudeCode runs Claude Code headless with FlowSight attached as an MCP
// server and relays its transcript.
func (m *Module) runClaudeCode(ctx context.Context, question string, cfg assistConfig, emit func(Event)) (runResult, error) {
	var res runResult
	bin, err := exec.LookPath(cfg.ClaudePath)
	if err != nil {
		return res, fmt.Errorf("claude not found at %q: install Claude Code or set claude_path", cfg.ClaudePath)
	}
	exe, err := os.Executable()
	if err != nil {
		return res, err
	}
	dir, err := os.MkdirTemp("", "flowsight-ask-*")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(dir)
	mcp := map[string]any{"mcpServers": map[string]any{"flowsight": map[string]any{
		"command": exe, "args": []string{"mcp"},
		"env": map[string]string{"FLOWSIGHT_URL": m.getFlowSightURL(), "FLOWSIGHT_TOKEN": m.getFlowSightToken()}}}}
	mb, _ := json.Marshal(mcp)
	mcpPath := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(mcpPath, mb, 0o600); err != nil {
		return res, err
	}
	cmd := exec.CommandContext(ctx, bin, claudeArgs(question, cfg, mcpPath)...)
	cmd.Dir = dir
	cmd.Env = claudeEnv()
	cmd.Stdin = nil
	ownProcessGroup(cmd)
	cmd.WaitDelay = 2 * time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return res, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return res, err
	}
	answer, calls, turns, in, out := relayClaudeStream(stdout, emit)
	res.Answer, res.Calls, res.Turns, res.InputTokens, res.OutputTokens = answer, calls, turns, in, out
	werr := cmd.Wait()
	if ctx.Err() != nil {
		return res, fmt.Errorf("claude did not finish within %d s", cfg.TimeoutSeconds)
	}
	if werr != nil && res.Answer == "" {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 400 {
			msg = msg[:400]
		}
		return res, fmt.Errorf("claude exited: %v %s", werr, msg)
	}
	return res, nil
}

// runClaudeCodePlain: one prompt, no tools, the result text.
func (m *Module) runClaudeCodePlain(ctx context.Context, prompt string, cfg assistConfig) (runResult, error) {
	var res runResult
	bin, err := exec.LookPath(cfg.ClaudePath)
	if err != nil {
		return res, fmt.Errorf("claude not found at %q", cfg.ClaudePath)
	}
	cmd := exec.CommandContext(ctx, bin, "-p", prompt, "--output-format", "json", "--max-turns", "1")
	cmd.Env = claudeEnv()
	out, err := cmd.Output()
	if err != nil {
		return res, err
	}
	var r struct {
		Result string `json:"result"`
	}
	if json.Unmarshal(out, &r) == nil && r.Result != "" {
		res.Answer = r.Result
	} else {
		res.Answer = strings.TrimSpace(string(out))
	}
	return res, nil
}

// claudeEnv is what the CLI gets: its own login and PATH, nothing of ours.
func claudeEnv() []string {
	var env []string
	for _, k := range []string{"PATH", "HOME", "USER", "LANG", "TMPDIR", "XDG_CONFIG_HOME"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// relayClaudeStream turns Claude Code's stream-json lines into events.
func relayClaudeStream(r io.Reader, emit func(Event)) (answer string, calls []ToolCallRecord, turns, inTok, outTok int) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	var text strings.Builder
	pending := map[string]ToolCallRecord{} // tool_use id -> record awaiting its result
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var ev struct {
			Type    string `json:"type"`
			Subtype string `json:"subtype"`
			Message struct {
				Content []struct {
					Type      string          `json:"type"`
					Text      string          `json:"text"`
					ID        string          `json:"id"`
					Name      string          `json:"name"`
					Input     map[string]any  `json:"input"`
					ToolUseID string          `json:"tool_use_id"`
					Content   json.RawMessage `json:"content"`
				} `json:"content"`
				Usage struct {
					InputTokens  int `json:"input_tokens"`
					OutputTokens int `json:"output_tokens"`
				} `json:"usage"`
			} `json:"message"`
			Result   string `json:"result"`
			NumTurns int    `json:"num_turns"`
			IsError  bool   `json:"is_error"`
		}
		if json.Unmarshal(line, &ev) != nil {
			continue
		}
		switch ev.Type {
		case "assistant":
			turns++
			inTok += ev.Message.Usage.InputTokens
			outTok += ev.Message.Usage.OutputTokens
			for _, c := range ev.Message.Content {
				switch c.Type {
				case "text":
					if c.Text != "" {
						if text.Len() > 0 {
							text.WriteString("\n")
						}
						text.WriteString(c.Text)
						emit(Event{Type: "text", Text: c.Text})
					}
				case "tool_use":
					name := strings.TrimPrefix(c.Name, "mcp__flowsight__")
					rec := ToolCallRecord{ToolName: name, Route: routeWithArgs(name, c.Input), Timestamp: time.Now().Unix()}
					pending[c.ID] = rec
					emit(Event{Type: "tool_call", Tool: name, Route: rec.Route, Args: c.Input})
				}
			}
		case "user":
			for _, c := range ev.Message.Content {
				if c.Type != "tool_result" {
					continue
				}
				rec, ok := pending[c.ToolUseID]
				if !ok {
					rec = ToolCallRecord{ToolName: "tool", Timestamp: time.Now().Unix()}
				}
				body := string(c.Content)
				var s string
				if json.Unmarshal(c.Content, &s) == nil {
					body = s
				} else {
					var parts []struct {
						Text string `json:"text"`
					}
					if json.Unmarshal(c.Content, &parts) == nil && len(parts) > 0 {
						body = parts[0].Text
					}
				}
				rec.Summary = summarise(body)
				calls = append(calls, rec)
				delete(pending, c.ToolUseID)
				emit(Event{Type: "tool_result", Tool: rec.ToolName, Route: rec.Route, Summary: rec.Summary, Bytes: len(body)})
			}
		case "result":
			if ev.NumTurns > 0 {
				turns = ev.NumTurns
			}
			if ev.Result != "" && text.Len() == 0 {
				text.WriteString(ev.Result)
				emit(Event{Type: "text", Text: ev.Result})
			}
			if ev.IsError && ev.Result != "" {
				emit(Event{Type: "error", Error: ev.Result})
			}
		}
	}
	return strings.TrimSpace(text.String()), calls, turns, inTok, outTok
}

// buildMCPToolsForAnthropic is the tool list in the Messages API's shape.
func (m *Module) buildMCPToolsForAnthropic() []map[string]any {
	m.ensureTools()
	m.toolsMu.RLock()
	defer m.toolsMu.RUnlock()
	tools := make([]map[string]any, 0, len(m.tools))
	for _, t := range m.tools {
		tools = append(tools, map[string]any{"name": t.Name, "description": t.Description, "input_schema": t.InputSchema})
	}
	return tools
}
