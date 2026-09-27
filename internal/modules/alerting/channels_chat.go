package alerting

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// SlackChannel sends notifications to Slack via incoming webhook or Bot token.
type SlackChannel struct{}

func (s *SlackChannel) Type() string  { return "slack" }
func (s *SlackChannel) Label() string { return "Slack" }

func (s *SlackChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "webhook_url", Label: "Incoming Webhook URL", Type: "url", Secret: true, Required: true, Help: "From Slack app: API > Incoming Webhooks"},
		{Key: "bot_token", Label: "Bot Token (optional)", Type: "password", Secret: true, Help: "For chat.postMessage; starts with xoxb-"},
		{Key: "channel", Label: "Channel", Type: "text", Help: "For bot token; leave blank for webhook default"},
	}
}

func (s *SlackChannel) Validate(config map[string]string) error {
	if config["webhook_url"] == "" && config["bot_token"] == "" {
		return fmt.Errorf("webhook_url or bot_token required")
	}
	return nil
}

func (s *SlackChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &SlackFormatter{BaseURL: ch.Config["base_url"]}
	payload, err := formatter.Format(msg)
	if err != nil {
		return 0, err
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// Use webhook URL if provided, otherwise use bot token
	if ch.Config["webhook_url"] != "" {
		req, _ := http.NewRequestWithContext(ctx, "POST", ch.Config["webhook_url"], bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			return time.Since(start).Milliseconds(), fmt.Errorf("slack returned %d", resp.StatusCode)
		}
	}

	return time.Since(start).Milliseconds(), nil
}

func (s *SlackChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "This is a test message from your FlowSight alerting system.",
	}
	return s.Send(ctx, ch, msg)
}

// DiscordChannel sends notifications to Discord via webhook.
type DiscordChannel struct{}

func (d *DiscordChannel) Type() string  { return "discord" }
func (d *DiscordChannel) Label() string { return "Discord" }

func (d *DiscordChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "webhook_url", Label: "Webhook URL", Type: "url", Secret: true, Required: true, Help: "From Discord server settings: Webhooks"},
	}
}

func (d *DiscordChannel) Validate(config map[string]string) error {
	if config["webhook_url"] == "" {
		return fmt.Errorf("webhook_url required")
	}
	return nil
}

func (d *DiscordChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	color := map[string]int{
		"critical": 0xFF0000,
		"high":     0xFF9900,
		"medium":   0xFFCC00,
		"low":      0x00CC00,
		"info":     0x0078D4,
	}[msg.Severity]
	if color == 0 {
		color = 0x808080
	}

	embed := map[string]interface{}{
		"title":     msg.Title,
		"color":     color,
		"timestamp": msg.Timestamp.Format(time.RFC3339),
		"fields": []map[string]interface{}{
			{
				"name":   "Severity",
				"value":  msg.Severity,
				"inline": true,
			},
			{
				"name":   "Module",
				"value":  msg.Module,
				"inline": true,
			},
		},
	}

	if msg.Device != nil && msg.Device.IP != "" {
		embed["fields"] = append(embed["fields"].([]map[string]interface{}), map[string]interface{}{
			"name":   "Device",
			"value":  fmt.Sprintf("%s (%s)", msg.Device.Name, msg.Device.IP),
			"inline": false,
		})
	}

	if msg.Body != "" {
		embed["description"] = msg.Body
	}

	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{embed},
	}

	body, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", ch.Config["webhook_url"], bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Since(start).Milliseconds(), fmt.Errorf("discord returned %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}

func (d *DiscordChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "This is a test message from your FlowSight alerting system.",
	}
	return d.Send(ctx, ch, msg)
}

// TeamsChannel sends to Microsoft Teams via webhook or Power Automate.
type TeamsChannel struct{}

func (t *TeamsChannel) Type() string  { return "teams" }
func (t *TeamsChannel) Label() string { return "Microsoft Teams" }

func (t *TeamsChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "webhook_url", Label: "Webhook URL", Type: "url", Secret: true, Required: true, Help: "From Teams: Connectors > Incoming Webhook"},
	}
}

func (t *TeamsChannel) Validate(config map[string]string) error {
	if config["webhook_url"] == "" {
		return fmt.Errorf("webhook_url required")
	}
	return nil
}

func (t *TeamsChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &TeamsFormatter{BaseURL: ch.Config["base_url"]}
	payload, err := formatter.Format(msg)
	if err != nil {
		return 0, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", ch.Config["webhook_url"], bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Since(start).Milliseconds(), fmt.Errorf("teams returned %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}

func (t *TeamsChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "This is a test message from your FlowSight alerting system.",
	}
	return t.Send(ctx, ch, msg)
}

// TelegramChannel sends via Telegram Bot API.
type TelegramChannel struct{}

func (t *TelegramChannel) Type() string  { return "telegram" }
func (t *TelegramChannel) Label() string { return "Telegram" }

func (t *TelegramChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "bot_token", Label: "Bot Token", Type: "password", Secret: true, Required: true, Help: "From BotFather; format: 123456:ABC-DEF..."},
		{Key: "chat_id", Label: "Chat ID", Type: "text", Required: true, Help: "Numeric chat/user ID or @channel"},
	}
}

func (t *TelegramChannel) Validate(config map[string]string) error {
	if config["bot_token"] == "" || config["chat_id"] == "" {
		return fmt.Errorf("bot_token and chat_id required")
	}
	return nil
}

func (t *TelegramChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &PlainTextFormatter{}
	text, _ := formatter.Format(msg)

	params := url.Values{
		"chat_id":    {ch.Config["chat_id"]},
		"text":       {text},
		"parse_mode": {"HTML"},
	}

	client := &http.Client{Timeout: 10 * time.Second}
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage?%s", ch.Config["bot_token"], params.Encode())
	req, _ := http.NewRequestWithContext(ctx, "GET", apiURL, nil)

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Since(start).Milliseconds(), fmt.Errorf("telegram returned %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}

func (t *TelegramChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "This is a test message from your FlowSight alerting system.",
	}
	return t.Send(ctx, ch, msg)
}

// NtfyChannel sends to ntfy.sh or self-hosted ntfy.
type NtfyChannel struct{}

func (n *NtfyChannel) Type() string  { return "ntfy" }
func (n *NtfyChannel) Label() string { return "ntfy" }

func (n *NtfyChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "server", Label: "Server URL", Type: "url", Required: true, Help: "e.g., https://ntfy.sh or your self-hosted instance"},
		{Key: "topic", Label: "Topic", Type: "text", Required: true, Help: "Topic name; uniqueness is security (no auth)"},
		{Key: "token", Label: "Access Token (optional)", Type: "password", Secret: true, Help: "For ntfy.sh Pro or self-hosted with auth"},
	}
}

func (n *NtfyChannel) Validate(config map[string]string) error {
	if config["server"] == "" || config["topic"] == "" {
		return fmt.Errorf("server and topic required")
	}
	return nil
}

func (n *NtfyChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &PlainTextFormatter{}
	text, _ := formatter.Format(msg)

	url := fmt.Sprintf("%s/%s", ch.Config["server"], ch.Config["topic"])
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBufferString(text))
	req.Header.Set("Title", msg.Title)
	req.Header.Set("Tags", msg.Module+","+msg.Severity)

	// Map severity to ntfy priority
	priority := map[string]string{
		"critical": "max",
		"high":     "high",
		"medium":   "default",
		"low":      "low",
		"info":     "min",
	}[msg.Severity]
	if priority != "" {
		req.Header.Set("Priority", priority)
	}

	if ch.Config["token"] != "" {
		req.Header.Set("Authorization", "Bearer "+ch.Config["token"])
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Since(start).Milliseconds(), fmt.Errorf("ntfy returned %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}

func (n *NtfyChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test message from FlowSight alerting.",
	}
	return n.Send(ctx, ch, msg)
}

// Placeholder implementations for other chat channels
// These follow the same pattern but are abbreviated for space

type MatrixChannel struct{}

func (m *MatrixChannel) Type() string  { return "matrix" }
func (m *MatrixChannel) Label() string { return "Matrix" }
func (m *MatrixChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "homeserver", Label: "Homeserver URL", Type: "url", Required: true, Help: "e.g., https://matrix.org or your homeserver instance"},
		{Key: "room_id", Label: "Room ID", Type: "text", Required: true, Help: "e.g., !abcdef123:matrix.org"},
		{Key: "access_token", Label: "Access Token", Type: "password", Secret: true, Required: true, Help: "User access token from homeserver"},
		{Key: "tls_verify", Label: "Verify TLS", Type: "select", Options: []string{"true", "false"}, Help: "Set to false for self-signed certificates"},
	}
}
func (m *MatrixChannel) Validate(config map[string]string) error {
	if config["homeserver"] == "" || config["room_id"] == "" || config["access_token"] == "" {
		return fmt.Errorf("homeserver, room_id, and access_token required")
	}
	u, err := url.Parse(config["homeserver"])
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid homeserver URL")
	}
	return nil
}
func (m *MatrixChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &PlainTextFormatter{}
	text, _ := formatter.Format(msg)

	// Use a transaction ID based on message timestamp
	txnID := fmt.Sprintf("flowsight-%d", msg.Timestamp.UnixNano())

	// Build the request URL
	hsURL := ch.Config["homeserver"]
	if !strings.HasSuffix(hsURL, "/") {
		hsURL += "/"
	}
	roomID := url.QueryEscape(ch.Config["room_id"])
	reqURL := fmt.Sprintf("%s_matrix/client/v3/rooms/%s/send/m.room.message/%s", hsURL, roomID, txnID)

	// Build the message body
	payload := map[string]interface{}{
		"msgtype":        "m.text",
		"body":           text,
		"formatted_body": text,
		"format":         "org.matrix.custom.html",
	}

	body, _ := json.Marshal(payload)

	tlsVerify := true
	if v, ok := ch.Config["tls_verify"]; ok && v == "false" {
		tlsVerify = false
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext:     core.GuardedDial,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !tlsVerify},
		},
	}

	req, _ := http.NewRequestWithContext(ctx, "PUT", reqURL, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ch.Config["access_token"]))

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("matrix returned %d: %s", resp.StatusCode, string(respBody))
	}

	return time.Since(start).Milliseconds(), nil
}
func (m *MatrixChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "This is a test message from your FlowSight alerting system.",
	}
	return m.Send(ctx, ch, msg)
}

type MattermostChannel struct{}

func (m *MattermostChannel) Type() string  { return "mattermost" }
func (m *MattermostChannel) Label() string { return "Mattermost" }
func (m *MattermostChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "webhook_url", Label: "Incoming Webhook URL", Type: "url", Secret: true, Required: true, Help: "From Mattermost: Integrations > Incoming Webhooks"},
		{Key: "channel", Label: "Channel (optional)", Type: "text", Help: "Override the default channel; leave blank to use webhook default"},
		{Key: "tls_verify", Label: "Verify TLS", Type: "select", Options: []string{"true", "false"}, Help: "Set to false for self-signed certificates"},
	}
}
func (m *MattermostChannel) Validate(config map[string]string) error {
	if config["webhook_url"] == "" {
		return fmt.Errorf("webhook_url required")
	}
	u, err := url.Parse(config["webhook_url"])
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid webhook URL")
	}
	return nil
}
func (m *MattermostChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	tlsVerify := true
	if v, ok := ch.Config["tls_verify"]; ok && v == "false" {
		tlsVerify = false
	}

	payload := map[string]interface{}{
		"text": fmt.Sprintf("**%s** [%s]\n%s", msg.Title, msg.Severity, msg.Body),
	}

	if ch.Config["channel"] != "" {
		payload["channel"] = ch.Config["channel"]
	}

	body, _ := json.Marshal(payload)

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext:     core.GuardedDial,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !tlsVerify},
		},
	}

	req, _ := http.NewRequestWithContext(ctx, "POST", ch.Config["webhook_url"], bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("mattermost returned %d: %s", resp.StatusCode, string(respBody))
	}

	return time.Since(start).Milliseconds(), nil
}
func (m *MattermostChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "This is a test message from your FlowSight alerting system.",
	}
	return m.Send(ctx, ch, msg)
}

type RocketChatChannel struct{}

func (r *RocketChatChannel) Type() string  { return "rocketchat" }
func (r *RocketChatChannel) Label() string { return "Rocket.Chat" }
func (r *RocketChatChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "webhook_url", Label: "Incoming Webhook URL", Type: "url", Secret: true, Required: true, Help: "From Rocket.Chat: Administration > Workspace > Integrations > Incoming Webhooks"},
		{Key: "channel", Label: "Channel (optional)", Type: "text", Help: "Override the default channel; leave blank to use webhook default"},
		{Key: "tls_verify", Label: "Verify TLS", Type: "select", Options: []string{"true", "false"}, Help: "Set to false for self-signed certificates"},
	}
}
func (r *RocketChatChannel) Validate(config map[string]string) error {
	if config["webhook_url"] == "" {
		return fmt.Errorf("webhook_url required")
	}
	u, err := url.Parse(config["webhook_url"])
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid webhook URL")
	}
	return nil
}
func (r *RocketChatChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	tlsVerify := true
	if v, ok := ch.Config["tls_verify"]; ok && v == "false" {
		tlsVerify = false
	}

	payload := map[string]interface{}{
		"text": fmt.Sprintf("**%s** [%s]\n%s", msg.Title, msg.Severity, msg.Body),
	}

	if ch.Config["channel"] != "" {
		payload["channel"] = ch.Config["channel"]
	}

	body, _ := json.Marshal(payload)

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext:     core.GuardedDial,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !tlsVerify},
		},
	}

	req, _ := http.NewRequestWithContext(ctx, "POST", ch.Config["webhook_url"], bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("rocketchat returned %d: %s", resp.StatusCode, string(respBody))
	}

	return time.Since(start).Milliseconds(), nil
}
func (r *RocketChatChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "This is a test message from your FlowSight alerting system.",
	}
	return r.Send(ctx, ch, msg)
}

type GoogleChatChannel struct{}

func (g *GoogleChatChannel) Type() string  { return "google_chat" }
func (g *GoogleChatChannel) Label() string { return "Google Chat" }
func (g *GoogleChatChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "webhook_url", Label: "Webhook URL", Type: "url", Secret: true, Required: true, Help: "From Google Chat: Create webhook in the space or DM"},
	}
}
func (g *GoogleChatChannel) Validate(config map[string]string) error {
	if config["webhook_url"] == "" {
		return fmt.Errorf("webhook_url required")
	}
	u, err := url.Parse(config["webhook_url"])
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid webhook URL")
	}
	return nil
}
func (g *GoogleChatChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	// Google Chat uses cardsV2 with structured card format
	payload := map[string]interface{}{
		"text": msg.Title,
		"cardsV2": []map[string]interface{}{
			{
				"cardId": "alert-card",
				"card": map[string]interface{}{
					"header": map[string]interface{}{
						"title":    msg.Title,
						"subtitle": fmt.Sprintf("[%s]", msg.Severity),
					},
					"sections": []map[string]interface{}{
						{
							"widgets": []map[string]interface{}{
								{
									"textParagraph": map[string]interface{}{
										"text": fmt.Sprintf("<b>Severity:</b> %s<br><b>Module:</b> %s<br><b>Category:</b> %s<br><b>Time:</b> %s",
											msg.Severity, msg.Module, msg.Category, msg.Timestamp.Format(time.RFC3339)),
									},
								},
								{
									"textParagraph": map[string]interface{}{
										"text": fmt.Sprintf("<b>Message:</b> %s", msg.Body),
									},
								},
							},
						},
					},
				},
			},
		},
	}

	body, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", ch.Config["webhook_url"], bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("google_chat returned %d: %s", resp.StatusCode, string(respBody))
	}

	return time.Since(start).Milliseconds(), nil
}
func (g *GoogleChatChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "This is a test message from your FlowSight alerting system.",
	}
	return g.Send(ctx, ch, msg)
}

type PushoverChannel struct{}

func (p *PushoverChannel) Type() string  { return "pushover" }
func (p *PushoverChannel) Label() string { return "Pushover" }
func (p *PushoverChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "user_key", Label: "User Key", Type: "password", Secret: true, Required: true, Help: "Your Pushover user key"},
		{Key: "app_token", Label: "App Token", Type: "password", Secret: true, Required: true, Help: "Your FlowSight app token from Pushover"},
		{Key: "device", Label: "Device (optional)", Type: "text", Help: "Specific device name; leave blank for all devices"},
	}
}
func (p *PushoverChannel) Validate(config map[string]string) error {
	if config["user_key"] == "" || config["app_token"] == "" {
		return fmt.Errorf("user_key and app_token required")
	}
	return nil
}
func (p *PushoverChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	// Map severity to Pushover priority (-1 to 2)
	priority := 0 // default
	switch msg.Severity {
	case "critical":
		priority = 2
	case "high":
		priority = 1
	case "medium":
		priority = 0
	case "low", "info":
		priority = -1
	}

	params := url.Values{
		"token":    {ch.Config["app_token"]},
		"user":     {ch.Config["user_key"]},
		"title":    {msg.Title},
		"message":  {msg.Body},
		"priority": {fmt.Sprintf("%d", priority)},
	}

	if ch.Config["device"] != "" {
		params.Set("device", ch.Config["device"])
	}

	if msg.Link != "" {
		params.Set("url", msg.Link)
		params.Set("url_title", "View Alert")
	}

	client := &http.Client{Timeout: 15 * time.Second}
	apiURL := fmt.Sprintf("https://api.pushover.net/1/messages.json?%s", params.Encode())
	req, _ := http.NewRequestWithContext(ctx, "POST", apiURL, nil)

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("pushover returned %d: %s", resp.StatusCode, string(respBody))
	}

	return time.Since(start).Milliseconds(), nil
}
func (p *PushoverChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "This is a test message from your FlowSight alerting system.",
	}
	return p.Send(ctx, ch, msg)
}

type PushbulletChannel struct{}

func (p *PushbulletChannel) Type() string  { return "pushbullet" }
func (p *PushbulletChannel) Label() string { return "Pushbullet" }
func (p *PushbulletChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "api_key", Label: "API Key", Type: "password", Secret: true, Required: true, Help: "Your Pushbullet API key"},
		{Key: "device_iden", Label: "Device ID (optional)", Type: "text", Help: "Specific device identifier; leave blank to send to all"},
	}
}
func (p *PushbulletChannel) Validate(config map[string]string) error {
	if config["api_key"] == "" {
		return fmt.Errorf("api_key required")
	}
	return nil
}
func (p *PushbulletChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	payload := map[string]interface{}{
		"type":  "note",
		"title": msg.Title,
		"body":  msg.Body,
	}

	if ch.Config["device_iden"] != "" {
		payload["device_iden"] = ch.Config["device_iden"]
	}

	body, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://api.pushbullet.com/v2/pushes", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Access-Token", ch.Config["api_key"])

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("pushbullet returned %d: %s", resp.StatusCode, string(respBody))
	}

	return time.Since(start).Milliseconds(), nil
}
func (p *PushbulletChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "This is a test message from your FlowSight alerting system.",
	}
	return p.Send(ctx, ch, msg)
}

type GotifyChannel struct{}

func (g *GotifyChannel) Type() string  { return "gotify" }
func (g *GotifyChannel) Label() string { return "Gotify" }
func (g *GotifyChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "server", Label: "Server URL", Type: "url", Required: true, Help: "e.g., https://gotify.example.com or your Gotify instance"},
		{Key: "token", Label: "App Token", Type: "password", Secret: true, Required: true, Help: "Token from Gotify app settings"},
		{Key: "tls_verify", Label: "Verify TLS", Type: "select", Options: []string{"true", "false"}, Help: "Set to false for self-signed certificates"},
	}
}
func (g *GotifyChannel) Validate(config map[string]string) error {
	if config["server"] == "" || config["token"] == "" {
		return fmt.Errorf("server and token required")
	}
	u, err := url.Parse(config["server"])
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid server URL")
	}
	return nil
}
func (g *GotifyChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	// Map severity to Gotify priority (1-10)
	priority := 5 // default
	switch msg.Severity {
	case "critical":
		priority = 10
	case "high":
		priority = 7
	case "medium":
		priority = 5
	case "low":
		priority = 3
	case "info":
		priority = 1
	}

	tlsVerify := true
	if v, ok := ch.Config["tls_verify"]; ok && v == "false" {
		tlsVerify = false
	}

	payload := map[string]interface{}{
		"title":    msg.Title,
		"message":  msg.Body,
		"priority": priority,
	}

	body, _ := json.Marshal(payload)

	serverURL := ch.Config["server"]
	if !strings.HasSuffix(serverURL, "/") {
		serverURL += "/"
	}
	reqURL := fmt.Sprintf("%smessage?token=%s", serverURL, url.QueryEscape(ch.Config["token"]))

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext:     core.GuardedDial,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !tlsVerify},
		},
	}

	req, _ := http.NewRequestWithContext(ctx, "POST", reqURL, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("gotify returned %d: %s", resp.StatusCode, string(respBody))
	}

	return time.Since(start).Milliseconds(), nil
}
func (g *GotifyChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "This is a test message from your FlowSight alerting system.",
	}
	return g.Send(ctx, ch, msg)
}

type HomeAssistantChannel struct{}

func (h *HomeAssistantChannel) Type() string  { return "homeassistant" }
func (h *HomeAssistantChannel) Label() string { return "Home Assistant" }
func (h *HomeAssistantChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "webhook_url", Label: "Webhook URL", Type: "url", Secret: true, Required: true, Help: "From Home Assistant: Settings > Automations & scenes > Create automation > Webhook trigger"},
		{Key: "tls_verify", Label: "Verify TLS", Type: "select", Options: []string{"true", "false"}, Help: "Set to false for self-signed certificates"},
	}
}
func (h *HomeAssistantChannel) Validate(config map[string]string) error {
	if config["webhook_url"] == "" {
		return fmt.Errorf("webhook_url required")
	}
	u, err := url.Parse(config["webhook_url"])
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid webhook URL")
	}
	return nil
}
func (h *HomeAssistantChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	tlsVerify := true
	if v, ok := ch.Config["tls_verify"]; ok && v == "false" {
		tlsVerify = false
	}

	payload := map[string]interface{}{
		"title":     msg.Title,
		"severity":  msg.Severity,
		"module":    msg.Module,
		"category":  msg.Category,
		"message":   msg.Body,
		"timestamp": msg.Timestamp.Unix(),
	}

	if msg.Device != nil {
		payload["device"] = map[string]interface{}{
			"ip":   msg.Device.IP,
			"mac":  msg.Device.MAC,
			"name": msg.Device.Name,
			"zone": msg.Device.Zone,
		}
	}

	body, _ := json.Marshal(payload)

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext:     core.GuardedDial,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !tlsVerify},
		},
	}

	req, _ := http.NewRequestWithContext(ctx, "POST", ch.Config["webhook_url"], bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("homeassistant returned %d: %s", resp.StatusCode, string(respBody))
	}

	return time.Since(start).Milliseconds(), nil
}
func (h *HomeAssistantChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "This is a test message from your FlowSight alerting system.",
	}
	return h.Send(ctx, ch, msg)
}

type SignalChannel struct{}

func (s *SignalChannel) Type() string  { return "signal" }
func (s *SignalChannel) Label() string { return "Signal" }
func (s *SignalChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "api_url", Label: "signal-cli-rest-api URL", Type: "url", Required: true, Help: "e.g., http://localhost:8080 (signal-cli REST API endpoint)"},
		{Key: "from_number", Label: "From Number", Type: "text", Required: true, Help: "Registered Signal number (e.g., +1234567890)"},
		{Key: "to_number", Label: "To Number", Type: "text", Required: true, Help: "Recipient number (e.g., +0987654321)"},
	}
}
func (s *SignalChannel) Validate(config map[string]string) error {
	if config["api_url"] == "" || config["from_number"] == "" || config["to_number"] == "" {
		return fmt.Errorf("api_url, from_number, and to_number required")
	}
	u, err := url.Parse(config["api_url"])
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid API URL")
	}
	return nil
}
func (s *SignalChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	// Format message body for Signal
	text := fmt.Sprintf("%s [%s]\n%s", msg.Title, msg.Severity, msg.Body)
	if msg.Link != "" {
		text += fmt.Sprintf("\n%s", msg.Link)
	}

	payload := map[string]interface{}{
		"message":    text,
		"number":     ch.Config["from_number"],
		"recipients": []string{ch.Config["to_number"]},
	}

	body, _ := json.Marshal(payload)

	apiURL := ch.Config["api_url"]
	if !strings.HasSuffix(apiURL, "/") {
		apiURL += "/"
	}
	reqURL := fmt.Sprintf("%sv2/send", apiURL)

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", reqURL, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("signal returned %d: %s", resp.StatusCode, string(respBody))
	}

	return time.Since(start).Milliseconds(), nil
}
func (s *SignalChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "This is a test message from your FlowSight alerting system.",
	}
	return s.Send(ctx, ch, msg)
}
