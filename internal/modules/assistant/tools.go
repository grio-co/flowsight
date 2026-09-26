package assistant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// toolRequest represents a tool call request.
type toolRequest struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// callToolHTTP executes a tool by making an HTTP request to the daemon's API.
func (m *Module) callToolHTTP(ctx context.Context, toolName string, args map[string]any) (string, error) {
	// Find the matching route
	var matchedRoute *core.Route
	var matchedPath string
	var matchedMethod string

	m.ctx.Core.API.IterateRoutes(func(method, path string, route *core.Route) {
		if routeToToolName(path) != toolName {
			return
		}
		// The read route wins; a write route of the same path is only
		// reachable when writes are allowed and no read route exists.
		if matchedRoute != nil && (matchedMethod == "GET" || (method != "GET" && !m.config.AllowWrites)) {
			return
		}
		if method != "GET" && !m.config.AllowWrites && !m.config.MCPAllowWrites {
			return
		}
		matchedRoute, matchedPath, matchedMethod = route, path, method
	})

	if matchedRoute == nil || matchedPath == "" {
		return "", fmt.Errorf("tool %q not found", toolName)
	}

	// Build the request URL
	baseURL := m.getFlowSightURL()
	fullURL := baseURL + matchedPath

	// Replace path parameters in the URL
	for _, param := range matchedRoute.Parameters {
		if param.In == "path" {
			if val, ok := args[param.Name]; ok {
				fullURL = strings.ReplaceAll(fullURL, "{"+param.Name+"}", fmt.Sprintf("%v", val))
			}
		}
	}

	// Build query string from arguments (for GET requests)
	queryVals := url.Values{}
	for _, param := range matchedRoute.Parameters {
		if param.In == "query" {
			if val, ok := args[param.Name]; ok {
				queryVals.Set(param.Name, fmt.Sprintf("%v", val))
			}
		}
	}
	if len(queryVals) > 0 {
		fullURL += "?" + queryVals.Encode()
	}

	// Make the HTTP request
	var req *http.Request
	var err error

	if matchedMethod == "GET" || matchedMethod == "DELETE" {
		req, err = http.NewRequestWithContext(ctx, matchedMethod, fullURL, nil)
	} else {
		// For POST/PUT, use request body
		var body io.Reader
		if matchedRoute.RequestBody != nil {
			bodyMap := map[string]any{}
			for name := range matchedRoute.RequestBody.Properties {
				if val, ok := args[name]; ok {
					bodyMap[name] = val
				}
			}
			bodyBytes, _ := json.Marshal(bodyMap)
			body = bytes.NewReader(bodyBytes)
		}
		req, err = http.NewRequestWithContext(ctx, matchedMethod, fullURL, body)
		if matchedRoute.RequestBody != nil {
			req.Header.Set("Content-Type", "application/json")
		}
	}

	if err != nil {
		return "", err
	}

	// Add API token
	if token := m.getFlowSightToken(); token != "" {
		req.Header.Set("X-Flowsight-Token", token)
	}
	req.Header.Set("X-Requested-With", "Flowsight")

	// Execute the request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, int64(m.config.MaxToolResultBytes+1000)))
	if err != nil {
		return "", err
	}

	// Handle errors
	if resp.StatusCode >= 400 {
		return fmt.Sprintf("error: HTTP %d: %s", resp.StatusCode, string(respBody)), nil
	}

	// Parse JSON response and pretty-print
	var parsed any
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		// Not JSON, return as-is
		result := string(respBody)
		if len(result) > m.config.MaxToolResultBytes {
			result = result[:m.config.MaxToolResultBytes] + "\n[result truncated: narrow the query with ip, hours, minutes or limit]"
		}
		return result, nil
	}

	// Pretty-print JSON
	prettyBytes, _ := json.MarshalIndent(parsed, "", "  ")
	result := string(prettyBytes)

	// Truncate if needed
	if len(result) > m.config.MaxToolResultBytes {
		result = result[:m.config.MaxToolResultBytes] + "\n[result truncated: narrow the query with ip, hours, minutes or limit]"
	}

	return result, nil
}

// getFlowSightURL returns the base URL for API calls.
func (m *Module) getFlowSightURL() string {
	// Check environment variables first
	if url := os.Getenv("FLOWSIGHT_URL"); url != "" {
		return strings.TrimSuffix(url, "/")
	}

	// Default to localhost on configured port
	cfg := m.ctx.Core.Config.Core()
	bind := cfg.Bind
	if bind == "" || bind == "0.0.0.0" {
		bind = "127.0.0.1"
	}
	port := cfg.Port
	if port == 0 {
		port = 8080
	}
	return fmt.Sprintf("http://%s:%d", bind, port)
}

// getFlowSightToken returns the API token for requests.
func (m *Module) getFlowSightToken() string {
	// Check environment variable first
	if token := os.Getenv("FLOWSIGHT_TOKEN"); token != "" {
		return token
	}
	// Fall back to config
	return m.ctx.Core.Config.Core().APIToken
}

var (
	rfc1918Re = regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b`)
	ulaRe     = regexp.MustCompile(`\b(f[cd][0-9a-f]{2}|fe80)(:[0-9a-f]{0,4}){2,7}\b`)
	macRe     = regexp.MustCompile(`\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b`)
)

// redact replaces the network's own addresses with stable placeholders
// before a tool result leaves for the provider: the same address always
// becomes the same placeholder within the daemon's lifetime, so the model
// can still reason about "host-3" across calls. Names and domains stay.
func (m *Module) redact(text string) string {
	m.redactMu.Lock()
	defer m.redactMu.Unlock()
	if m.redactMap == nil {
		m.redactMap = map[string]string{}
	}
	sub := func(prefix string) func(string) string {
		return func(s string) string {
			if p, ok := m.redactMap[s]; ok {
				return p
			}
			p := fmt.Sprintf("%s-%d", prefix, len(m.redactMap)+1)
			m.redactMap[s] = p
			return p
		}
	}
	text = rfc1918Re.ReplaceAllStringFunc(text, sub("host"))
	text = ulaRe.ReplaceAllStringFunc(text, sub("host6"))
	text = macRe.ReplaceAllStringFunc(text, sub("mac"))
	return text
}
