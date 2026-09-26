// Package assistant adds Claude as FlowSight's analyst, and provides
// FlowSight's routes as tools to the Claude Code Agent SDK through
// a Model Context Protocol (MCP) server.
package assistant

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

// Module implements core.Module for the assistant.
type Module struct {
	ctx *core.Context
	mu  sync.Mutex

	config  assistConfig
	lastErr string

	convMu sync.Mutex // serialises writes to the conversation index

	redactMu  sync.Mutex
	redactMap map[string]string

	// Tool generation
	toolsMu sync.RWMutex
	tools   []*Tool
	toolMap map[string]*Tool
}

// Conversation stores a question, answer, and tool calls.
type Conversation struct {
	ID           string           `json:"id"`
	Question     string           `json:"question"`
	Answer       string           `json:"answer"`
	ToolCalls    []ToolCallRecord `json:"tool_calls"`
	CreatedAt    int64            `json:"created_at"`
	UpdatedAt    int64            `json:"updated_at"`
	InputTokens  int              `json:"input_tokens,omitempty"`
	OutputTokens int              `json:"output_tokens,omitempty"`
	Error        string           `json:"error,omitempty"`
}

// ToolCallRecord is a summary of a tool call in a conversation.
type ToolCallRecord struct {
	ToolName  string `json:"tool_name"`
	Route     string `json:"route"`
	Summary   string `json:"summary"`
	Timestamp int64  `json:"timestamp"`
}

// Tool represents a FlowSight route exposed as an MCP tool.
type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema any    `json:"inputSchema"`
}

// assistConfig is what the settings say.
type assistConfig struct {
	Provider           string
	APIKey             string
	WorkspaceID        string
	Model              string
	ClaudePath         string
	ClaudeSSH          string // user@host: run claude there over ssh
	SSHKey             string // private key path; generated when missing
	SSHPath            string // the ssh binary
	MCPURL             string // where a remote claude reaches FlowSight (HTTP MCP)
	MaxTurns           int
	MaxToolResultBytes int
	AllowWrites        bool
	MCPAllowWrites     bool
	TimeoutSeconds     int
	RetentionDays      int
	RedactAddresses    bool
}

func (c assistConfig) on() bool { return c.Provider == "anthropic" || c.Provider == "claude-code" }

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name:        "assistant",
		Version:     "1.0",
		Description: "Claude as an analyst: ask questions in English and get answers by tool use; expose FlowSight to Claude Code via MCP.",
		After:       []string{"web"},
		Defaults: map[string]any{
			"provider":              "off",
			"api_key":               "",
			"workspace_id":          "",
			"model":                 "claude-sonnet-5",
			"claude_path":           "claude",
			"claude_ssh":            "",
			"claude_ssh_key":        "",
			"ssh_path":              "ssh",
			"mcp_url":               "",
			"max_turns":             8,
			"max_tool_result_bytes": 65536,
			"allow_writes":          false,
			"mcp_allow_writes":      false,
			"timeout_seconds":       120,
			"retention_days":        7,
			"redact_addresses":      false,
		},
		Schema: []core.SettingField{
			{Section: "Provider", Key: "provider", Label: "AI Provider", Type: "choice", Help: "off: assistant disabled. anthropic: Anthropic's Messages API. claude-code: Claude Code CLI / Agent SDK.",
				Choices: []string{"off", "anthropic", "claude-code"}},
			{Section: "Provider", Key: "api_key", Label: "API Key", Type: "secret", Help: "For anthropic provider only. Your Anthropic API key. Never shown; reads from secure storage."},
			{Section: "Provider", Key: "workspace_id", Label: "Anthropic workspace id", Type: "string", Help: "Only for an organisation-level key: the workspace the requests are billed to (sent as anthropic-workspace-id). A key created inside a workspace needs nothing here."},
			{Section: "Provider", Key: "model", Label: "Model", Type: "string", Help: "For anthropic provider: claude-fable-5-1, claude-haiku-4-5-20251001, claude-sonnet-5, claude-opus-5-5. claude-code ignores this."},
			{Section: "Provider", Key: "claude_path", Label: "Claude CLI path", Type: "string", Help: "claude-code provider: the claude binary, on PATH or absolute. With claude_ssh set this is the path on the remote machine (for example /home/you/.local/bin/claude)."},
			{Section: "Provider", Key: "claude_ssh", Label: "Run Claude Code over SSH on", Type: "string", Placeholder: "user@host", Help: "Leave empty to run claude on this gateway. Set user@host to run it on another machine where Claude Code is installed and logged in (a VM or container); FlowSight connects with its own key (shown in the status as ssh_public_key; add it to that user's authorized_keys) and the remote Claude reaches FlowSight at mcp_url."},
			{Section: "Provider", Key: "mcp_url", Label: "MCP URL for a remote Claude", Type: "string", Placeholder: "http://192.168.0.1:8080/api/mcp", Help: "Required with claude_ssh: the address of this daemon's /api/mcp as seen from the remote machine. The API token is passed along; use a named token (api_tokens) so it can be rotated on its own."},
			{Section: "Provider", Key: "claude_ssh_key", Label: "SSH private key", Type: "string", Help: "Path of the key used for claude_ssh. Empty: assistant_ssh_key under FlowSight's config directory, generated on first use."},
			{Section: "Provider", Key: "ssh_path", Label: "ssh binary", Type: "string", Help: "Normally just ssh."},
			{Section: "Behavior", Key: "max_turns", Label: "Max conversation turns", Type: "int", Help: "Maximum number of request/response cycles before stopping."},
			{Section: "Behavior", Key: "max_tool_result_bytes", Label: "Max tool result bytes", Type: "int", Help: "Results larger than this are truncated."},
			{Section: "Behavior", Key: "allow_writes", Label: "Allow write operations", Type: "bool", Help: "If on, the assistant can POST/PUT/DELETE to FlowSight's API. Default off for safety."},
			{Section: "Behavior", Key: "mcp_allow_writes", Label: "MCP: Allow write operations", Type: "bool", Help: "If on, MCP clients can call write routes. Default off."},
			{Section: "Behavior", Key: "timeout_seconds", Label: "Question timeout (seconds)", Type: "int", Help: "Max time to spend answering one question."},
			{Section: "Behavior", Key: "retention_days", Label: "Conversation retention (days)", Type: "int", Help: "How long to keep old conversations in the store. 0 = forever."},
			{Section: "Privacy", Key: "redact_addresses", Label: "Redact internal addresses in results", Type: "bool", Help: "If on, RFC1918 and local addresses in tool results are replaced with placeholders before sending to the provider."},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.toolMap = map[string]*Tool{}

	// Register this module as a service so other modules can use it
	ctx.Publish("assistant", m)
	ctx.Panel(core.Panel{ID: "ask", Title: "Ask", Group: "Monitor", Order: 80, Icon: "ask"})

	// Register routes
	ctx.Route("GET", "/api/assistant/status", m.apiStatus,
		core.Doc("The assistant's state: which provider is configured, whether it is ready to answer and if not why, the model, how many FlowSight tools it can call"),
		core.Returns("Assistant status", map[string]any{"provider": "anthropic", "enabled": true, "ready": true, "model": "claude-sonnet-5", "tools": 190, "questions": 12}))
	ctx.Route("POST", "/api/assistant/ask", m.apiAsk,
		core.Doc("Ask a question in plain English; the model answers by calling FlowSight's own API. With Accept: text/event-stream the answer streams as events (text, tool_call, tool_result, done, error); otherwise the whole answer is returned as JSON"),
		core.Body(
			core.Fld("question", "string", true, "The question", "Which devices talked to a country other than mine today?"),
			core.Fld("conversation_id", "string", false, "Reserved: a conversation to continue", nil),
		),
		core.Returns("The answer, the tools it looked at, and the conversation id", map[string]any{"id": "c-1790376243-1", "answer": "Three devices reached Canada today: roku-stick-4k (71 sessions, Plex) …",
			"tool_calls": []map[string]any{{"tool_name": "visibility_abroad", "route": "GET /api/visibility/abroad?hours=24", "summary": "5 devices"}}, "turns": 2}))
	ctx.Route("GET", "/api/assistant/conversations", m.apiConversationsList,
		core.Doc("Recent questions and answers kept in the store, newest first, with the tools each answer used"),
		core.Query("limit", "integer", "How many to return (default 50)", false, 50),
		core.Query("offset", "integer", "Skip this many, for paging", false, 0),
		core.Returns("Conversations", map[string]any{"conversations": []map[string]any{{"id": "c-1790376243-1", "question": "What is 192.168.1.115?", "answer": "An Amazon Echo …", "created_at": 1790376243}}, "total": 12}))
	ctx.Route("GET", "/api/assistant/conversations/{id}", m.apiConversationsGet,
		core.Doc("One saved conversation: the question, the full answer and every tool call with its route"),
		core.PathParam("id", "string", "Conversation id", "c-1790376243-1"),
		core.Returns("Conversation", map[string]any{"conversation": map[string]any{"id": "c-1790376243-1", "question": "What is 192.168.1.115?", "answer": "An Amazon Echo …", "tool_calls": []map[string]any{{"tool_name": "identity_hosts", "route": "GET /api/identity/hosts?hours=24", "summary": "262 rows"}}}}))
	ctx.Route("DELETE", "/api/assistant/conversations/{id}", m.apiConversationsDelete,
		core.Doc("Forget one saved conversation; the answer and its tool trail are removed from the store"),
		core.PathParam("id", "string", "Conversation id", "c-1790376243-1"),
		core.Write(), core.Returns("Acknowledgement", map[string]any{"ok": true}))
	ctx.Route("GET", "/api/assistant/ssh_key", m.apiSSHKey,
		core.Doc("The public half of the key FlowSight uses to run Claude Code on another machine (claude_ssh); generated on first request. Add it to that user's authorized_keys"),
		core.Returns("Public key", map[string]any{"public_key": "ssh-ed25519 AAAA… flowsight-assistant", "path": "/usr/local/etc/flowsight/assistant_ssh_key"}))
	ctx.Route("GET", "/api/assistant/tools", m.apiTools,
		core.Doc("The FlowSight tools the model and MCP clients can call: one per documented API route, with its input schema"),
		core.Returns("Tools", map[string]any{"tools": []map[string]any{{"name": "visibility_flows", "description": "Recent sessions …", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"minutes": map[string]any{"type": "integer"}}}}}, "count": 190}))
	ctx.Route("POST", "/api/mcp", m.apiMCP,
		core.Doc("Model Context Protocol over HTTP (JSON-RPC 2.0, streamable-HTTP style single responses): initialize, tools/list, tools/call, ping. What `flowsightd mcp` bridges to for stdio clients such as Claude Code"),
		core.Body(
			core.Fld("jsonrpc", "string", true, "Always \"2.0\"", "2.0"),
			core.Fld("id", "string", false, "Request id; absent for notifications", "1"),
			core.Fld("method", "string", true, "initialize | tools/list | tools/call | ping | notifications/initialized", "tools/call"),
			core.Fld("params", "object", false, "Method parameters; for tools/call: name and arguments", map[string]any{"name": "visibility_flows", "arguments": map[string]any{"minutes": 60}}),
		),
		core.Returns("JSON-RPC response", map[string]any{"jsonrpc": "2.0", "id": "1", "result": map[string]any{"content": []map[string]any{{"type": "text", "text": "{\"flows\": []}"}}}}))

	// Tools are generated on first use, not here: modules that set up after
	// this one have not registered their routes yet. They are regenerated
	// every few minutes so a settings change (allow_writes) is picked up.
	ctx.Every("tools", 5*time.Minute, m.generateTools, core.Delayed())

	// Load config
	m.loadConfig()

	// Start cleanup job
	ctx.Every("clean-conversations", 1*time.Hour, m.cleanConversations)

	return nil
}

// cfg is the current configuration: settings are read at every use, so a
// change saved on the Settings page takes effect on the next question.
func (m *Module) cfg() assistConfig {
	m.loadConfig()
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.config
}

func (m *Module) loadConfig() {
	s := m.ctx.Settings()
	m.mu.Lock()
	defer m.mu.Unlock()

	provider := strings.TrimSpace(core.Str(s, "provider", "off"))
	provider = strings.ToLower(provider)

	m.config = assistConfig{
		Provider:           provider,
		APIKey:             strings.TrimSpace(core.Str(s, "api_key", "")),
		WorkspaceID:        strings.TrimSpace(core.Str(s, "workspace_id", "")),
		Model:              strings.TrimSpace(core.Str(s, "model", "claude-sonnet-5")),
		ClaudePath:         strings.TrimSpace(core.Str(s, "claude_path", "claude")),
		ClaudeSSH:          strings.TrimSpace(core.Str(s, "claude_ssh", "")),
		SSHKey:             strings.TrimSpace(core.Str(s, "claude_ssh_key", "")),
		SSHPath:            strings.TrimSpace(core.Str(s, "ssh_path", "ssh")),
		MCPURL:             strings.TrimSpace(core.Str(s, "mcp_url", "")),
		MaxTurns:           core.Int(s, "max_turns", 8),
		MaxToolResultBytes: core.Int(s, "max_tool_result_bytes", 65536),
		AllowWrites:        core.Bool(s, "allow_writes", false),
		MCPAllowWrites:     core.Bool(s, "mcp_allow_writes", false),
		TimeoutSeconds:     core.Int(s, "timeout_seconds", 120),
		RetentionDays:      core.Int(s, "retention_days", 7),
		RedactAddresses:    core.Bool(s, "redact_addresses", false),
	}

	// One key serves both: with no key of its own, the assistant uses the
	// one the map's hop lookup (paths, setting ai_key) already has.
	if m.config.APIKey == "" && m.ctx != nil && m.ctx.Core != nil {
		m.config.APIKey = strings.TrimSpace(core.Str(m.ctx.Core.Config.Module("paths"), "ai_key", ""))
	}
	if m.config.MaxTurns < 1 {
		m.config.MaxTurns = 1
	}
	if m.config.MaxTurns > 20 {
		m.config.MaxTurns = 20
	}
	if m.config.MaxToolResultBytes < 1024 {
		m.config.MaxToolResultBytes = 1024
	}
	if m.config.MaxToolResultBytes > 10<<20 {
		m.config.MaxToolResultBytes = 10 << 20
	}
	if m.config.TimeoutSeconds < 5 {
		m.config.TimeoutSeconds = 5
	}
	if m.config.TimeoutSeconds > 600 {
		m.config.TimeoutSeconds = 600
	}
}

// ToolCount is how many FlowSight tools the model and MCP clients can call.
func (m *Module) ToolCount() int {
	m.ensureTools()
	m.toolsMu.RLock()
	defer m.toolsMu.RUnlock()
	return len(m.tools)
}

// ToolNames lists the tools, for tests and diagnostics.
func (m *Module) ToolNames() []string {
	m.ensureTools()
	m.toolsMu.RLock()
	defer m.toolsMu.RUnlock()
	out := make([]string, 0, len(m.tools))
	for _, t := range m.tools {
		out = append(out, t.Name)
	}
	return out
}

// ensureTools builds the tool list the first time anything asks for it.
func (m *Module) ensureTools() {
	m.toolsMu.RLock()
	n := len(m.tools)
	m.toolsMu.RUnlock()
	if n == 0 {
		_ = m.generateTools()
	}
}

func (m *Module) generateTools() error {
	m.toolsMu.Lock()
	defer m.toolsMu.Unlock()

	m.tools = []*Tool{}
	m.toolMap = map[string]*Tool{}

	// Get all routes from the core API by iterating
	m.ctx.Core.API.IterateRoutes(func(method, path string, route *core.Route) {
		// Skip the MCP endpoints themselves
		if strings.Contains(path, "/api/mcp") || strings.Contains(path, "/api/assistant") {
			return
		}

		// For read-only operations or when writes allowed
		if method != "GET" && !m.config.AllowWrites {
			return
		}

		tool := &Tool{
			Name:        routeToToolName(path),
			Description: route.Description,
			InputSchema: routeToInputSchema(route),
		}

		m.tools = append(m.tools, tool)
		m.toolMap[tool.Name] = tool
	})

	return nil
}

// routeToToolName converts a path like /api/visibility/flows to visibility_flows.
func routeToToolName(path string) string {
	// /api/alerting/channels/{id} -> alerting_channels_by_id: the parameter
	// stays in the name so a collection and one of its items are two tools.
	path = strings.TrimPrefix(path, "/api/")
	var parts []string
	for _, seg := range strings.Split(path, "/") {
		if seg == "" {
			continue
		}
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			parts = append(parts, "by_"+strings.Trim(seg, "{}"))
			continue
		}
		parts = append(parts, seg)
	}
	name := strings.Join(parts, "_")
	name = strings.NewReplacer(".", "_", "-", "_").Replace(name)
	for strings.Contains(name, "__") {
		name = strings.ReplaceAll(name, "__", "_")
	}
	return strings.Trim(name, "_")
}

// routeToInputSchema builds a JSON schema for the tool's input from the route parameters.
func routeToInputSchema(route *core.Route) map[string]any {
	properties := map[string]any{}
	required := []string{}

	// Handle query and path parameters
	for _, param := range route.Parameters {
		prop := map[string]any{
			"type":        paramTypeToJSON(param.Type),
			"description": param.Description,
		}
		if param.Example != nil {
			prop["example"] = param.Example
		}
		properties[param.Name] = prop

		if param.Required {
			required = append(required, param.Name)
		}
	}

	// Handle request body
	if route.RequestBody != nil {
		for name, field := range route.RequestBody.Properties {
			prop := fieldToJSONSchema(field)
			properties[name] = prop
			if field.Required {
				required = append(required, name)
			}
		}
	}

	schema := map[string]any{
		"type":       "object",
		"properties": properties,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func paramTypeToJSON(t string) string {
	switch t {
	case "integer":
		return "number"
	case "boolean":
		return "boolean"
	case "string":
		return "string"
	default:
		return "string"
	}
}

func fieldToJSONSchema(f *core.Field) map[string]any {
	schema := map[string]any{
		"type": f.Type,
	}
	if f.Description != "" {
		schema["description"] = f.Description
	}
	if f.Example != nil {
		schema["example"] = f.Example
	}
	if f.Type == "array" && f.Items != nil {
		schema["items"] = fieldToJSONSchema(f.Items)
	}
	if f.Type == "object" && f.Properties != nil {
		props := map[string]any{}
		for name, prop := range f.Properties {
			props[name] = fieldToJSONSchema(prop)
		}
		schema["properties"] = props
	}
	return schema
}

// apiStatus returns the current status.
func (m *Module) apiStatus(r *core.Req) (any, error) {
	cfg := m.cfg()
	m.mu.Lock()
	lastErr := m.lastErr
	m.mu.Unlock()

	m.ensureTools()
	m.toolsMu.RLock()
	toolCount := len(m.tools)
	m.toolsMu.RUnlock()

	status := map[string]any{
		"provider":  cfg.Provider,
		"enabled":   cfg.Provider != "" && cfg.Provider != "off",
		"model":     cfg.Model,
		"tools":     toolCount,
		"questions": len(m.convIndex()),
	}

	if cfg.Provider == "off" || cfg.Provider == "" {
		status["ready"] = false
		status["reason"] = "assistant is disabled"
	} else if cfg.Provider == "anthropic" && cfg.APIKey == "" {
		status["ready"] = false
		status["reason"] = "anthropic provider requires api_key"
	} else if cfg.Provider == "claude-code" && cfg.ClaudeSSH != "" {
		pub, err := m.sshPublicKey(cfg)
		status["ssh_public_key"] = pub
		status["claude_ssh"] = cfg.ClaudeSSH
		switch {
		case err != nil:
			status["ready"] = false
			status["reason"] = "ssh key: " + err.Error()
		case cfg.MCPURL == "":
			status["ready"] = false
			status["reason"] = "mcp_url is required with claude_ssh: the address of this daemon's /api/mcp as the remote machine sees it"
		default:
			status["ready"] = true
		}
	} else if cfg.Provider == "claude-code" {
		// Check if claude binary exists
		if _, err := exec.LookPath(cfg.ClaudePath); err != nil {
			status["ready"] = false
			status["reason"] = fmt.Sprintf("claude binary not found at %q", cfg.ClaudePath)
		} else {
			status["ready"] = true
		}
	} else if cfg.Provider == "anthropic" {
		status["ready"] = true
	} else {
		status["ready"] = false
		status["reason"] = fmt.Sprintf("unknown provider %q", cfg.Provider)
	}

	if lastErr != "" {
		status["last_error"] = lastErr
	}

	return status, nil
}

// apiAsk answers one question. With Accept: text/event-stream the answer
// streams as it is produced (text deltas, tool calls and their results,
// then done); otherwise the handler waits and returns everything at once.
func (m *Module) apiAsk(r *core.Req) (any, error) {
	var req struct {
		Question       string `json:"question"`
		ConversationID string `json:"conversation_id"`
	}
	if err := r.Decode(&req); err != nil {
		return nil, err
	}
	q := strings.TrimSpace(req.Question)
	if q == "" {
		return nil, core.BadRequest("question is required")
	}
	if len(q) > 4000 {
		return nil, core.BadRequest("question is too long (4000 characters at most)")
	}
	cfg := m.cfg()
	m.mu.Lock()
	m.mu.Unlock()
	if !cfg.on() {
		return nil, core.Errorf(400, "the assistant is off: choose a provider under Settings › assistant")
	}
	if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		return core.Stream(func(w http.ResponseWriter) {
			h := w.Header()
			h.Set("Content-Type", "text/event-stream")
			h.Set("Cache-Control", "no-store")
			h.Set("X-Accel-Buffering", "no")
			w.WriteHeader(200)
			fl, _ := w.(http.Flusher)
			send := func(ev Event) {
				b, _ := json.Marshal(ev)
				fmt.Fprintf(w, "data: %s\n\n", b)
				if fl != nil {
					fl.Flush()
				}
			}
			ctx, cancel := context.WithTimeout(r.Context(), time.Duration(cfg.TimeoutSeconds)*time.Second)
			defer cancel()
			conv := &Conversation{ID: newConvID(), Question: q, CreatedAt: time.Now().Unix()}
			res, err := m.run(ctx, q, cfg, send)
			conv.Answer, conv.ToolCalls, conv.InputTokens, conv.OutputTokens = res.Answer, res.Calls, res.InputTokens, res.OutputTokens
			conv.UpdatedAt = time.Now().Unix()
			if err != nil {
				conv.Error = err.Error()
				m.setLastErr(err.Error())
				send(Event{Type: "error", Error: err.Error()})
			}
			m.saveConversation(conv)
			send(Event{Type: "done", ID: conv.ID, Turns: res.Turns, InputTokens: res.InputTokens, OutputTokens: res.OutputTokens})
		}), nil
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(cfg.TimeoutSeconds)*time.Second)
	defer cancel()
	conv := &Conversation{ID: newConvID(), Question: q, CreatedAt: time.Now().Unix()}
	var events []Event
	res, err := m.run(ctx, q, cfg, func(ev Event) {
		if ev.Type != "text" {
			events = append(events, ev)
		}
	})
	conv.Answer, conv.ToolCalls, conv.InputTokens, conv.OutputTokens = res.Answer, res.Calls, res.InputTokens, res.OutputTokens
	conv.UpdatedAt = time.Now().Unix()
	if err != nil {
		conv.Error = err.Error()
		m.setLastErr(err.Error())
	}
	m.saveConversation(conv)
	out := map[string]any{"id": conv.ID, "answer": res.Answer, "tool_calls": res.Calls, "turns": res.Turns, "events": events}
	if err != nil {
		out["error"] = err.Error()
	}
	return out, nil
}

func (m *Module) setLastErr(s string) {
	m.mu.Lock()
	m.lastErr = s
	m.mu.Unlock()
}

// ---------------------------------------------------------------- conversations (store)

const convIndexKey = "assistant.conversations"
const convKeyPrefix = "assistant.conv:"
const convKeep = 500

var convSeq uint64

func newConvID() string {
	convSeq++
	return fmt.Sprintf("c-%d-%d", time.Now().Unix(), convSeq)
}

func (m *Module) convIndex() []string {
	var ids []string
	m.ctx.Store.KVGet(convIndexKey, &ids)
	return ids
}

func (m *Module) saveConversation(c *Conversation) {
	m.convMu.Lock()
	defer m.convMu.Unlock()
	_ = m.ctx.Store.KVSet(convKeyPrefix+c.ID, c)
	ids := append([]string{c.ID}, m.convIndex()...)
	if len(ids) > convKeep {
		for _, old := range ids[convKeep:] {
			_ = m.ctx.Store.KVDelete(convKeyPrefix + old)
		}
		ids = ids[:convKeep]
	}
	_ = m.ctx.Store.KVSet(convIndexKey, ids)
}

func (m *Module) getConversation(id string) *Conversation {
	var c Conversation
	if !m.ctx.Store.KVGet(convKeyPrefix+id, &c) || c.ID == "" {
		return nil
	}
	return &c
}

func (m *Module) deleteConversation(id string) bool {
	m.convMu.Lock()
	defer m.convMu.Unlock()
	ids := m.convIndex()
	kept := ids[:0]
	found := false
	for _, x := range ids {
		if x == id {
			found = true
			continue
		}
		kept = append(kept, x)
	}
	if found {
		_ = m.ctx.Store.KVDelete(convKeyPrefix + id)
		_ = m.ctx.Store.KVSet(convIndexKey, kept)
	}
	return found
}

// cleanConversations forgets conversations older than the retention.
func (m *Module) cleanConversations() error {
	m.mu.Lock()
	days := m.config.RetentionDays
	m.mu.Unlock()
	if days <= 0 {
		return nil
	}
	cut := time.Now().Add(-time.Duration(days) * 24 * time.Hour).Unix()
	for _, id := range m.convIndex() {
		if c := m.getConversation(id); c != nil && c.CreatedAt < cut {
			m.deleteConversation(id)
		}
	}
	return nil
}

func (m *Module) apiConversationsList(r *core.Req) (any, error) {
	limit := r.QInt("limit", 50, 1, 500)
	offset := r.QInt("offset", 0, 0, 1<<20)
	ids := m.convIndex()
	total := len(ids)
	if offset > len(ids) {
		offset = len(ids)
	}
	ids = ids[offset:]
	if len(ids) > limit {
		ids = ids[:limit]
	}
	out := make([]*Conversation, 0, len(ids))
	for _, id := range ids {
		if c := m.getConversation(id); c != nil {
			out = append(out, c)
		}
	}
	return map[string]any{"conversations": out, "total": total, "limit": limit, "offset": offset}, nil
}

func (m *Module) apiConversationsGet(r *core.Req) (any, error) {
	c := m.getConversation(r.Params["id"])
	if c == nil {
		return nil, core.NotFound("no such conversation")
	}
	return map[string]any{"conversation": c}, nil
}

func (m *Module) apiConversationsDelete(r *core.Req) (any, error) {
	if !m.deleteConversation(r.Params["id"]) {
		return nil, core.NotFound("no such conversation")
	}
	return nil, nil
}

func (m *Module) apiTools(r *core.Req) (any, error) {
	m.ensureTools()
	m.toolsMu.RLock()
	tools := append([]*Tool{}, m.tools...)
	m.toolsMu.RUnlock()

	return map[string]any{"tools": tools}, nil
}

// apiMCP handles the /api/mcp endpoint for HTTP-based MCP transport.
func (m *Module) apiMCP(r *core.Req) (any, error) {
	var req json.RawMessage
	if err := r.Decode(&req); err != nil {
		return nil, err
	}

	// Parse as JSON-RPC 2.0
	result := m.handleMCPRequest(r.Context(), req)
	return result, nil
}

func (m *Module) handleMCPRequest(ctx context.Context, req json.RawMessage) map[string]any {
	var jsonRPC struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
		ID      any             `json:"id"`
	}

	if err := json.Unmarshal(req, &jsonRPC); err != nil {
		return map[string]any{
			"jsonrpc": "2.0",
			"error":   map[string]any{"code": -32700, "message": "Parse error"},
			"id":      nil,
		}
	}

	if strings.HasPrefix(jsonRPC.Method, "notifications/") {
		return nil // a notification is not answered
	}
	// Handle MCP methods
	switch jsonRPC.Method {
	case "initialize":
		return m.mcpInitialize(jsonRPC.ID)
	case "tools/list":
		return m.mcpToolsList(jsonRPC.ID)
	case "tools/call":
		return m.mcpToolsCall(ctx, jsonRPC.Params, jsonRPC.ID)
	case "ping":
		return map[string]any{
			"jsonrpc": "2.0",
			"result":  map[string]any{},
			"id":      jsonRPC.ID,
		}
	default:
		return map[string]any{
			"jsonrpc": "2.0",
			"error":   map[string]any{"code": -32601, "message": "Method not found"},
			"id":      jsonRPC.ID,
		}
	}
}

func (m *Module) mcpInitialize(id any) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"result": map[string]any{
			"protocolVersion": "2025-06-18",
			"serverInfo": map[string]any{
				"name":    "flowsight",
				"version": m.ctx.Core.Version,
			},
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
		},
		"id": id,
	}
}

func (m *Module) mcpToolsList(id any) map[string]any {
	m.ensureTools()
	m.toolsMu.RLock()
	tools := make([]map[string]any, len(m.tools))
	for i, t := range m.tools {
		tools[i] = map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": t.InputSchema,
		}
	}
	m.toolsMu.RUnlock()

	return map[string]any{
		"jsonrpc": "2.0",
		"result": map[string]any{
			"tools": tools,
		},
		"id": id,
	}
}

func (m *Module) mcpToolsCall(ctx context.Context, params json.RawMessage, id any) map[string]any {
	var req struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return map[string]any{
			"jsonrpc": "2.0",
			"error":   map[string]any{"code": -32602, "message": "Invalid params"},
			"id":      id,
		}
	}

	m.ensureTools()
	m.toolsMu.RLock()
	tool, ok := m.toolMap[req.Name]
	m.toolsMu.RUnlock()

	if !ok {
		return map[string]any{
			"jsonrpc": "2.0",
			"error":   map[string]any{"code": -32602, "message": fmt.Sprintf("Tool not found: %s", req.Name)},
			"id":      id,
		}
	}

	// Call the tool (make HTTP request to the daemon's API)
	result := m.callTool(ctx, tool, req.Arguments)

	return map[string]any{
		"jsonrpc": "2.0",
		"result": map[string]any{
			"content": []map[string]any{
				{
					"type": "text",
					"text": result,
				},
			},
		},
		"id": id,
	}
}

func (m *Module) callTool(ctx context.Context, tool *Tool, args json.RawMessage) string {
	// Parse arguments
	var argMap map[string]any
	if err := json.Unmarshal(args, &argMap); err != nil {
		return fmt.Sprintf("error: invalid arguments: %v", err)
	}

	// Call the tool via HTTP
	result, err := m.callToolHTTP(ctx, tool.Name, argMap)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	return result
}

func (m *Module) apiSSHKey(r *core.Req) (any, error) {
	cfg := m.cfg()
	pub, err := m.sshPublicKey(cfg)
	if err != nil {
		return nil, err
	}
	return map[string]any{"public_key": pub, "path": m.sshKeyPath(cfg)}, nil
}
