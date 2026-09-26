package assistant

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/grioghar/flowsight/internal/core"
)

// MCPServer is a Model Context Protocol server that speaks JSON-RPC 2.0 over stdio.
type MCPServer struct {
	ctx    context.Context
	core   *core.Core
	module *Module

	in  *bufio.Reader
	out io.Writer
	mu  sync.Mutex

	nextID     uint64
	idMu       sync.Mutex
	initialized bool
}

// NewMCPServer creates an MCP server bound to a FlowSight core.
func NewMCPServer(ctx context.Context, c *core.Core) *MCPServer {
	m := &MCPServer{
		ctx:  ctx,
		core: c,
		in:   bufio.NewReader(os.Stdin),
		out:  os.Stdout,
	}

	// Find the assistant module
	if am, ok := c.Modules["assistant"].(*Module); ok {
		m.module = am
	}

	return m
}

// Run starts the server loop, reading and responding to JSON-RPC requests.
func (s *MCPServer) Run() error {
	if s.module == nil {
		return fmt.Errorf("assistant module not found")
	}

	for {
		select {
		case <-s.ctx.Done():
			return nil
		default:
		}

		line, err := s.in.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		response := s.handleRawRequest(line)
		if response != nil {
			b, _ := json.Marshal(response)
			fmt.Fprintln(s.out, string(b))
		}
	}
}

// handleRawRequest parses and handles a JSON-RPC 2.0 request.
func (s *MCPServer) handleRawRequest(raw []byte) any {
	var jsonRPC struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
		ID      any             `json:"id"`
	}

	if err := json.Unmarshal(raw, &jsonRPC); err != nil {
		return map[string]any{
			"jsonrpc": "2.0",
			"error":   map[string]any{"code": -32700, "message": "Parse error"},
			"id":      nil,
		}
	}

	if jsonRPC.JSONRPC != "2.0" {
		return map[string]any{
			"jsonrpc": "2.0",
			"error":   map[string]any{"code": -32600, "message": "Invalid Request"},
			"id":      jsonRPC.ID,
		}
	}

	// Handle MCP methods
	switch jsonRPC.Method {
	case "initialize":
		s.initialized = true
		return s.mcpInitialize(jsonRPC.ID)
	case "notifications/initialized":
		return nil // Notification, no response
	case "tools/list":
		return s.mcpToolsList(jsonRPC.ID)
	case "tools/call":
		return s.mcpToolsCall(s.ctx, jsonRPC.Params, jsonRPC.ID)
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

func (s *MCPServer) mcpInitialize(id any) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"result": map[string]any{
			"protocolVersion": "2025-06-18",
			"serverInfo": map[string]any{
				"name":    "flowsight",
				"version": s.core.Version,
			},
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
		},
		"id": id,
	}
}

func (s *MCPServer) mcpToolsList(id any) map[string]any {
	s.module.toolsMu.RLock()
	tools := make([]map[string]any, len(s.module.tools))
	for i, t := range s.module.tools {
		tools[i] = map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": t.InputSchema,
		}
	}
	s.module.toolsMu.RUnlock()

	return map[string]any{
		"jsonrpc": "2.0",
		"result": map[string]any{
			"tools": tools,
		},
		"id": id,
	}
}

func (s *MCPServer) mcpToolsCall(ctx context.Context, params json.RawMessage, id any) map[string]any {
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

	s.module.toolsMu.RLock()
	_, ok := s.module.toolMap[req.Name]
	s.module.toolsMu.RUnlock()

	if !ok {
		return map[string]any{
			"jsonrpc": "2.0",
			"error":   map[string]any{"code": -32602, "message": fmt.Sprintf("Tool not found: %s", req.Name)},
			"id":      id,
		}
	}

	// Call the tool through the HTTP API
	result := s.callToolByName(ctx, req.Name, req.Arguments)

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

func (s *MCPServer) callToolByName(ctx context.Context, name string, args json.RawMessage) string {
	// Find the matching route
	var matchedPath string

	s.core.API.IterateRoutes(func(method, path string, route *core.Route) {
		if matchedPath == "" && routeToToolName(path) == name && method == "GET" {
			matchedPath = path
		}
	})

	if matchedPath == "" {
		return fmt.Sprintf("error: tool %q not found in routes", name)
	}

	// Parse arguments
	var argMap map[string]any
	if err := json.Unmarshal(args, &argMap); err != nil {
		return fmt.Sprintf("error: invalid arguments: %v", err)
	}

	// Make HTTP request to this daemon's API
	result, err := s.callRoute(ctx, matchedPath, argMap)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}

	// Truncate result if necessary
	if len(result) > s.module.config.MaxToolResultBytes {
		result = result[:s.module.config.MaxToolResultBytes] + "\n[truncated]"
	}

	return result
}

func (s *MCPServer) callRoute(ctx context.Context, path string, args map[string]any) (string, error) {
	// Convert tool name to HTTP request (build query string from args)
	// This is a placeholder; full implementation would make actual HTTP calls
	// For now, we'll return a summary

	var params []string
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := args[k]
		params = append(params, fmt.Sprintf("%s=%v", k, v))
	}

	return fmt.Sprintf("Called %s with: %s", path, strings.Join(params, "&")), nil
}
