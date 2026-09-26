package assistant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Complete answers a question using the configured provider.
// This is used by the paths module's AI lookup.
func (m *Module) Complete(ctx context.Context, prompt string) (string, error) {
	m.mu.Lock()
	cfg := m.config
	m.mu.Unlock()

	if cfg.Provider == "off" || cfg.Provider == "" {
		return "", fmt.Errorf("assistant is disabled")
	}

	if cfg.Provider == "anthropic" {
		return m.completeWithAnthropic(ctx, prompt, cfg)
	} else if cfg.Provider == "claude-code" {
		return m.completeWithClaudeCode(ctx, prompt, cfg)
	}

	return "", fmt.Errorf("unknown provider: %s", cfg.Provider)
}

func (m *Module) completeWithAnthropic(ctx context.Context, prompt string, cfg assistConfig) (string, error) {
	systemPrompt := `You are a network analyst helping understand network traffic. Answer questions about network addresses, flows, and security. Be brief and factual. Cite which tools you used to find your answer.`

	client := &http.Client{Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second}

	messages := []map[string]any{
		{"role": "user", "content": prompt},
	}

	// First request to the model
	answer := ""
	for turn := 0; turn < cfg.MaxTurns; turn++ {
		req := map[string]any{
			"model":       cfg.Model,
			"max_tokens":  1024,
			"system":      systemPrompt,
			"messages":    messages,
			"tools":       m.buildMCPToolsForAnthropic(),
		}

		body, _ := json.Marshal(req)
		httpReq, err := http.NewRequestWithContext(ctx, "POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
		if err != nil {
			return "", err
		}

		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("x-api-key", cfg.APIKey)
		httpReq.Header.Set("anthropic-version", "2023-06-01")

		resp, err := client.Do(httpReq)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("anthropic API error: %s", string(respBody))
		}

		var result struct {
			Content []struct {
				Type      string `json:"type"`
				Text      string `json:"text"`
				ID        string `json:"id"`
				Name      string `json:"name"`
				Input     json.RawMessage `json:"input"`
			} `json:"content"`
			StopReason string `json:"stop_reason"`
		}

		if err := json.Unmarshal(respBody, &result); err != nil {
			return "", err
		}

		// Process response content
		hasToolUse := false
		for _, block := range result.Content {
			if block.Type == "text" {
				answer += block.Text
			} else if block.Type == "tool_use" {
				hasToolUse = true
				// Call the tool
				toolResult := m.callToolWithName(ctx, block.Name, block.Input)
				// Add to messages for next turn
				messages = append(messages,
					map[string]any{"role": "assistant", "content": result.Content},
					map[string]any{
						"role": "user",
						"content": []map[string]any{
							{
								"type":       "tool_result",
								"tool_use_id": block.ID,
								"content":    toolResult,
							},
						},
					},
				)
			}
		}

		// If no tool use and stop_reason is end_turn, we're done
		if !hasToolUse || result.StopReason == "end_turn" {
			break
		}
	}

	return answer, nil
}

func (m *Module) completeWithClaudeCode(ctx context.Context, prompt string, cfg assistConfig) (string, error) {
	// Use the Claude Code CLI in headless mode
	// This is a placeholder; full implementation would invoke the CLI
	return fmt.Sprintf("Claude Code not yet implemented for query: %s", prompt), nil
}

func (m *Module) buildMCPToolsForAnthropic() []map[string]any {
	m.toolsMu.RLock()
	defer m.toolsMu.RUnlock()

	tools := make([]map[string]any, len(m.tools))
	for i, t := range m.tools {
		tools[i] = map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"input_schema": t.InputSchema,
		}
	}
	return tools
}

func (m *Module) callToolWithName(ctx context.Context, name string, inputRaw json.RawMessage) string {
	var input map[string]any
	if err := json.Unmarshal(inputRaw, &input); err != nil {
		return fmt.Sprintf("error parsing input: %v", err)
	}

	// Find the matching route and call it
	// This is a placeholder; full implementation in tools.go
	return fmt.Sprintf("Tool %q called with %v", name, input)
}

// JSONAnswer waits for a full answer and returns it as JSON.
func (m *Module) jsonAnswer(ctx context.Context, question, convID string, cfg assistConfig) (any, error) {
	// Implementation would stream to a channel and collect the result
	// Placeholder for now
	return map[string]any{"error": "not yet implemented"}, nil
}

// StreamAnswer streams the answer over SSE or JSON-RPC
func (m *Module) streamAnswer(ctx context.Context, question, convID string, cfg assistConfig) (chan any, error) {
	// Implementation would return a channel of events that get streamed to the client
	// Placeholder for now
	ch := make(chan any)
	go func() {
		ch <- map[string]any{"error": "not yet implemented"}
		close(ch)
	}()
	return ch, nil
}
