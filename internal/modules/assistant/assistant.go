// Package assistant adds Claude as FlowSight's analyst, and provides
// FlowSight's routes as tools to the Claude Code Agent SDK through
// a Model Context Protocol (MCP) server.
package assistant

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
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

	// Conversation store
	convMu        sync.RWMutex
	conversations map[string]*Conversation

	// Tool generation
	toolsMu sync.RWMutex
	tools   []*Tool
	toolMap map[string]*Tool
}

// Conversation stores a question, answer, and tool calls.
type Conversation struct {
	ID          string                 `json:"id"`
	Question    string                 `json:"question"`
	Answer      string                 `json:"answer"`
	ToolCalls   []ToolCallRecord       `json:"tool_calls"`
	CreatedAt   int64                  `json:"created_at"`
	UpdatedAt   int64                  `json:"updated_at"`
	InputTokens int                    `json:"input_tokens,omitempty"`
	OutputTokens int                  `json:"output_tokens,omitempty"`
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
	Provider             string
	APIKey               string
	Model                string
	ClaudePath           string
	MaxTurns             int
	MaxToolResultBytes   int
	AllowWrites          bool
	MCPAllowWrites       bool
	TimeoutSeconds       int
	RetentionDays        int
	RedactAddresses      bool
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name:        "assistant",
		Version:     "1.0",
		Description: "Claude as an analyst: ask questions in English and get answers by tool use; expose FlowSight to Claude Code via MCP.",
		After:       []string{"web"},
		Defaults: map[string]any{
			"enabled":                false,
			"provider":               "off",
			"api_key":                "",
			"model":                  "claude-sonnet-5",
			"claude_path":            "claude",
			"max_turns":              8,
			"max_tool_result_bytes":  65536,
			"allow_writes":           false,
			"mcp_allow_writes":       false,
			"timeout_seconds":        120,
			"retention_days":         7,
			"redact_addresses":       false,
		},
		Schema: []core.SettingField{
			{Section: "Provider", Key: "provider", Label: "AI Provider", Type: "choice", Help: "off: assistant disabled. anthropic: Anthropic's Messages API. claude-code: Claude Code CLI / Agent SDK.",
				Choices: []string{"off", "anthropic", "claude-code"}},
			{Section: "Provider", Key: "api_key", Label: "API Key", Type: "secret", Help: "For anthropic provider only. Your Anthropic API key. Never shown; reads from secure storage."},
			{Section: "Provider", Key: "model", Label: "Model", Type: "string", Help: "For anthropic provider: claude-fable-5-1, claude-haiku-4-5-20251001, claude-sonnet-5, claude-opus-5-5. claude-code ignores this."},
			{Section: "Provider", Key: "claude_path", Label: "Claude CLI Path", Type: "string", Help: "For claude-code provider: path to the claude binary (default: on PATH)."},
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
	m.conversations = map[string]*Conversation{}
	m.toolMap = map[string]*Tool{}

	// Register this module as a service so other modules can use it
	ctx.Publish("assistant", m)

	// Register routes
	ctx.Route("GET", "/api/assistant/status", m.apiStatus,
		core.Doc("Get assistant status: provider, ready state, tool count"))
	ctx.Route("POST", "/api/assistant/ask", m.apiAsk,
		core.Doc("Ask the assistant a question; stream answer as JSON-RPC 2.0 or SSE"),
		core.Body(
			core.Fld("question", "string", true, "The question to ask", "Which devices talked to a country other than mine today?"),
			core.Fld("conversation_id", "string", false, "Optional conversation to append to", nil),
		))
	ctx.Route("GET", "/api/assistant/conversations", m.apiConversationsList,
		core.Doc("List saved conversations"),
		core.Query("limit", "integer", "Max conversations to return", false, 50),
		core.Query("offset", "integer", "Offset for pagination", false, 0))
	ctx.Route("GET", "/api/assistant/conversations/{id}", m.apiConversationsGet,
		core.Doc("Get a conversation by ID"),
		core.PathParam("id", "string", "Conversation ID", "conv-123"))
	ctx.Route("DELETE", "/api/assistant/conversations/{id}", m.apiConversationsDelete,
		core.Doc("Delete a conversation"),
		core.PathParam("id", "string", "Conversation ID", "conv-123"),
		core.Write())
	ctx.Route("GET", "/api/assistant/tools", m.apiTools,
		core.Doc("List available tools the assistant can use"))
	ctx.Route("POST", "/api/mcp", m.apiMCP,
		core.Doc("MCP server: Model Context Protocol over HTTP (Streamable transport)"))

	// Generate tools from route registry
	if err := m.generateTools(); err != nil {
		return fmt.Errorf("generate tools: %w", err)
	}

	// Load config
	m.loadConfig()

	// Start cleanup job
	ctx.Every("clean-conversations", 1*time.Hour, m.cleanConversations)

	return nil
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
		Model:              strings.TrimSpace(core.Str(s, "model", "claude-sonnet-5")),
		ClaudePath:         strings.TrimSpace(core.Str(s, "claude_path", "claude")),
		MaxTurns:           core.Int(s, "max_turns", 8),
		MaxToolResultBytes: core.Int(s, "max_tool_result_bytes", 65536),
		AllowWrites:        core.Bool(s, "allow_writes", false),
		MCPAllowWrites:     core.Bool(s, "mcp_allow_writes", false),
		TimeoutSeconds:     core.Int(s, "timeout_seconds", 120),
		RetentionDays:      core.Int(s, "retention_days", 7),
		RedactAddresses:    core.Bool(s, "redact_addresses", false),
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
	// Remove /api/ prefix
	path = strings.TrimPrefix(path, "/api/")

	// Remove {id} or other path params - strip entire {*} blocks
	var result strings.Builder
	inBrace := false
	for _, r := range path {
		if r == '{' {
			inBrace = true
		} else if r == '}' {
			inBrace = false
		} else if !inBrace {
			result.WriteRune(r)
		}
	}
	path = result.String()

	// Convert slashes to underscores
	name := strings.ReplaceAll(path, "/", "_")
	// Clean up multiple underscores and leading/trailing underscores
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

func (m *Module) cleanConversations() error {
	if m.config.RetentionDays <= 0 {
		return nil // keep forever
	}

	cutoff := time.Now().Add(-time.Duration(m.config.RetentionDays) * 24 * time.Hour).Unix()

	m.convMu.Lock()
	defer m.convMu.Unlock()

	for id, conv := range m.conversations {
		if conv.CreatedAt < cutoff {
			delete(m.conversations, id)
		}
	}
	return nil
}

// apiStatus returns the current status.
func (m *Module) apiStatus(r *core.Req) (any, error) {
	m.mu.Lock()
	cfg := m.config
	lastErr := m.lastErr
	m.mu.Unlock()

	m.toolsMu.RLock()
	toolCount := len(m.tools)
	m.toolsMu.RUnlock()

	status := map[string]any{
		"provider": cfg.Provider,
		"enabled":  cfg.Provider != "" && cfg.Provider != "off",
		"model":    cfg.Model,
		"tools":    toolCount,
	}

	if cfg.Provider == "off" || cfg.Provider == "" {
		status["ready"] = false
		status["reason"] = "assistant is disabled"
	} else if cfg.Provider == "anthropic" && cfg.APIKey == "" {
		status["ready"] = false
		status["reason"] = "anthropic provider requires api_key"
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

// apiAsk handles the /api/assistant/ask endpoint.
func (m *Module) apiAsk(r *core.Req) (any, error) {
	var req struct {
		Question       string `json:"question"`
		ConversationID string `json:"conversation_id"`
	}
	if err := r.Decode(&req); err != nil {
		return nil, err
	}

	if strings.TrimSpace(req.Question) == "" {
		return nil, core.BadRequest("question is required")
	}

	m.mu.Lock()
	cfg := m.config
	m.mu.Unlock()

	if cfg.Provider == "off" || cfg.Provider == "" {
		return nil, core.Errorf(400, "assistant is disabled")
	}

	// Check if client wants SSE stream
	if r.Header.Get("Accept") == "text/event-stream" {
		return m.streamAnswer(r.Context(), req.Question, req.ConversationID, cfg)
	}

	// Otherwise, wait for full answer and return JSON
	return m.jsonAnswer(r.Context(), req.Question, req.ConversationID, cfg)
}

func (m *Module) apiConversationsList(r *core.Req) (any, error) {
	limit := r.QInt("limit", 50, 1, 1000)
	offset := r.QInt("offset", 0, 0, 1000000)

	m.convMu.RLock()
	defer m.convMu.RUnlock()

	convs := make([]*Conversation, 0, len(m.conversations))
	for _, c := range m.conversations {
		convs = append(convs, c)
	}

	// Sort by created_at descending
	sort.Slice(convs, func(i, j int) bool {
		return convs[i].CreatedAt > convs[j].CreatedAt
	})

	if offset >= len(convs) {
		return map[string]any{"conversations": []any{}, "total": len(convs)}, nil
	}

	if offset+limit > len(convs) {
		limit = len(convs) - offset
	}

	return map[string]any{
		"conversations": convs[offset : offset+limit],
		"total":         len(convs),
	}, nil
}

func (m *Module) apiConversationsGet(r *core.Req) (any, error) {
	id := r.Params["id"]
	if id == "" {
		return nil, core.BadRequest("id is required")
	}

	m.convMu.RLock()
	conv, ok := m.conversations[id]
	m.convMu.RUnlock()

	if !ok {
		return nil, core.NotFound("conversation not found")
	}

	return conv, nil
}

func (m *Module) apiConversationsDelete(r *core.Req) (any, error) {
	id := r.Params["id"]
	if id == "" {
		return nil, core.BadRequest("id is required")
	}

	m.convMu.Lock()
	delete(m.conversations, id)
	m.convMu.Unlock()

	return map[string]any{"deleted": id}, nil
}

func (m *Module) apiTools(r *core.Req) (any, error) {
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

