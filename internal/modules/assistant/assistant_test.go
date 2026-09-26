package assistant

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/grioghar/flowsight/internal/core"
)

func TestRouteToToolName(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/api/visibility/flows", "visibility_flows"},
		{"/api/policy/matches", "policy_matches"},
		{"/api/identity/hosts", "identity_hosts"},
		{"/api/dns/log", "dns_log"},
		{"/api/paths/path/{ip}", "paths_path"},
	}

	for _, test := range tests {
		got := routeToToolName(test.path)
		if got != test.want {
			t.Errorf("routeToToolName(%q) = %q, want %q", test.path, got, test.want)
		}
	}
}

func TestInputSchema(t *testing.T) {
	// Create a test route
	route := &core.Route{
		Description: "Test route",
		Parameters: []*core.ParameterInfo{
			{
				Name:        "hours",
				In:          "query",
				Type:        "integer",
				Required:    false,
				Description: "Time window in hours",
				Example:     24,
			},
			{
				Name:        "id",
				In:          "path",
				Type:        "string",
				Required:    true,
				Description: "Resource ID",
				Example:     "abc123",
			},
		},
	}

	schema := routeToInputSchema(route)

	// Verify structure
	if props, ok := schema["properties"].(map[string]any); !ok {
		t.Fatalf("schema.properties is not a map")
	} else {
		if _, ok := props["hours"]; !ok {
			t.Error("hours parameter not in schema")
		}
		if _, ok := props["id"]; !ok {
			t.Error("id parameter not in schema")
		}
	}

	// Verify required field
	if required, ok := schema["required"].([]string); !ok || len(required) != 1 || required[0] != "id" {
		t.Errorf("required field incorrect: %v", schema["required"])
	}
}

func TestMCPInitialize(t *testing.T) {
	m := &Module{
		ctx: &core.Context{
			Core: &core.Core{Version: "1.0"},
		},
		tools:   []*Tool{},
		toolMap: map[string]*Tool{},
	}

	result := m.mcpInitialize("test-id")

	// Verify response structure
	if result["jsonrpc"] != "2.0" {
		t.Error("jsonrpc version incorrect")
	}

	if id, ok := result["id"]; !ok || id != "test-id" {
		t.Error("id not echoed correctly")
	}

	res, ok := result["result"].(map[string]any)
	if !ok {
		t.Fatalf("result is not a map")
	}

	if res["protocolVersion"] != "2025-06-18" {
		t.Error("protocolVersion incorrect")
	}

	serverInfo, ok := res["serverInfo"].(map[string]any)
	if !ok || serverInfo["name"] != "flowsight" {
		t.Error("serverInfo.name incorrect")
	}
}

func TestMCPToolsList(t *testing.T) {
	m := &Module{
		ctx: &core.Context{
			Core: &core.Core{Version: "1.0"},
		},
		tools: []*Tool{
			{
				Name:        "visibility_flows",
				Description: "Get visibility flows",
				InputSchema: map[string]any{
					"type":       "object",
					"properties": map[string]any{},
				},
			},
		},
		toolMap: map[string]*Tool{},
	}

	result := m.mcpToolsList("test-id")

	if result["jsonrpc"] != "2.0" {
		t.Error("jsonrpc version incorrect")
	}

	res, ok := result["result"].(map[string]any)
	if !ok {
		t.Fatalf("result is not a map")
	}

	tools, ok := res["tools"].([]map[string]any)
	if !ok || len(tools) != 1 {
		t.Errorf("tools list incorrect: %v", res["tools"])
	}

	if tools[0]["name"] != "visibility_flows" {
		t.Error("tool name incorrect")
	}
}

func TestAssistantAPI(t *testing.T) {
	// Create a minimal test core with the assistant module
	c := &core.Core{
		Version: "1.0",
		API:     &core.API{},
		Modules: map[string]core.Module{
			"assistant": &Module{
				tools:   []*Tool{},
				toolMap: map[string]*Tool{},
				conversations: map[string]*Conversation{},
				config: assistConfig{
					Provider: "anthropic",
					Model:    "claude-sonnet-5",
				},
			},
		},
	}

	m := c.Modules["assistant"].(*Module)
	m.ctx = &core.Context{
		Core: c,
	}

	// Test apiStatus
	req := &core.Req{}
	status, err := m.apiStatus(req)
	if err != nil {
		t.Fatalf("apiStatus failed: %v", err)
	}

	statusMap := status.(map[string]any)
	if statusMap["provider"] != "anthropic" {
		t.Errorf("provider incorrect: %v", statusMap["provider"])
	}

	// Test apiTools
	m.tools = []*Tool{
		{Name: "test_tool", Description: "A test tool"},
	}
	m.toolMap["test_tool"] = m.tools[0]

	tools, err := m.apiTools(req)
	if err != nil {
		t.Fatalf("apiTools failed: %v", err)
	}

	toolsMap := tools.(map[string]any)
	toolsList := toolsMap["tools"].([]*Tool)
	if len(toolsList) != 1 || toolsList[0].Name != "test_tool" {
		t.Errorf("tools list incorrect: %v", toolsList)
	}
}

func TestMCPHandleToolsCall(t *testing.T) {
	m := &Module{
		ctx: &core.Context{
			Core: &core.Core{Version: "1.0"},
		},
		tools: []*Tool{
			{
				Name:        "visibility_flows",
				Description: "Get flows",
				InputSchema: map[string]any{"type": "object"},
			},
		},
		toolMap: map[string]*Tool{
			"visibility_flows": {
				Name:        "visibility_flows",
				Description: "Get flows",
				InputSchema: map[string]any{"type": "object"},
			},
		},
	}

	params := map[string]any{
		"name":      "visibility_flows",
		"arguments": json.RawMessage(`{"hours": 24}`),
	}
	paramsJSON, _ := json.Marshal(params)

	result := m.mcpToolsCall(context.Background(), paramsJSON, "test-id")

	if result["error"] != nil {
		t.Errorf("tools/call returned error: %v", result["error"])
	}

	if result["jsonrpc"] != "2.0" {
		t.Error("jsonrpc version incorrect")
	}
}

func TestMCPHandleUnknownMethod(t *testing.T) {
	m := &Module{
		ctx: &core.Context{
			Core: &core.Core{Version: "1.0"},
		},
	}

	s := &MCPServer{
		ctx:    context.Background(),
		core:   m.ctx.Core,
		module: m,
	}

	req := []byte(`{"jsonrpc":"2.0","method":"unknown","id":"test"}`)
	result := s.handleRawRequest(req)

	if err, ok := result.(map[string]any)["error"]; !ok {
		t.Error("unexpected error response")
	} else if errMap, ok := err.(map[string]any); !ok || errMap["code"] != -32601 {
		t.Errorf("error code incorrect: %v", err)
	}
}

func TestConversationStorage(t *testing.T) {
	m := &Module{
		conversations: map[string]*Conversation{},
	}

	// Create mock request with deletion
	req := &core.Req{Request: httptest.NewRequest("DELETE", "/api/assistant/conversations/test-1", nil)}
	req.Params = map[string]string{"id": "test-1"}

	// Add a conversation
	m.conversations["test-1"] = &Conversation{ID: "test-1", Question: "Test Q"}

	// Test deletion
	result, err := m.apiConversationsDelete(req)
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	if _, ok := m.conversations["test-1"]; ok {
		t.Error("conversation not deleted")
	}

	resultMap := result.(map[string]any)
	if resultMap["deleted"] != "test-1" {
		t.Errorf("delete result incorrect: %v", resultMap)
	}
}
