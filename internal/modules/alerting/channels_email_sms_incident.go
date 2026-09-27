package alerting

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// ==================== EMAIL CHANNELS ====================

// SMTPChannel sends via SMTP (STARTTLS or implicit TLS).
type SMTPChannel struct{}

func (s *SMTPChannel) Type() string  { return "smtp" }
func (s *SMTPChannel) Label() string { return "Email (SMTP)" }

func (s *SMTPChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "host", Label: "SMTP Host", Type: "text", Required: true, Help: "e.g., smtp.gmail.com"},
		{Key: "port", Label: "Port", Type: "number", Required: true, Help: "587 (STARTTLS) or 465 (implicit TLS)"},
		{Key: "user", Label: "Username", Type: "text"},
		{Key: "password", Label: "Password", Type: "password", Secret: true},
		{Key: "from", Label: "From Address", Type: "text", Required: true},
		{Key: "to", Label: "Recipients (comma-separated)", Type: "text", Required: true},
		{Key: "tls_mode", Label: "TLS Mode", Type: "select", Options: []string{"starttls", "implicit", "none"}, Required: true},
	}
}

func (s *SMTPChannel) Validate(config map[string]string) error {
	if config["host"] == "" || config["port"] == "" || config["from"] == "" || config["to"] == "" {
		return fmt.Errorf("host, port, from, and to required")
	}
	return nil
}

func (s *SMTPChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &PlainTextFormatter{}
	body, _ := formatter.Format(msg)

	// Parse recipients
	toAddrs := strings.Split(ch.Config["to"], ",")
	var recipients []*mail.Address
	for _, addr := range toAddrs {
		addr = strings.TrimSpace(addr)
		pa, err := mail.ParseAddress(addr)
		if err != nil {
			continue
		}
		recipients = append(recipients, pa)
	}
	if len(recipients) == 0 {
		return 0, fmt.Errorf("no valid recipients")
	}

	// Build message
	var msgBuf bytes.Buffer
	msgBuf.WriteString("From: " + ch.Config["from"] + "\r\n")
	msgBuf.WriteString("To: ")
	for i, r := range recipients {
		if i > 0 {
			msgBuf.WriteString(", ")
		}
		msgBuf.WriteString(r.String())
	}
	msgBuf.WriteString("\r\n")
	msgBuf.WriteString("Subject: [" + strings.ToUpper(msg.Severity[:1]) + "] " + msg.Title + "\r\n")
	msgBuf.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msgBuf.WriteString("\r\n")
	msgBuf.WriteString(body)

	// Send via SMTP
	addr := net.JoinHostPort(ch.Config["host"], ch.Config["port"])
	tlsMode := ch.Config["tls_mode"]
	tlsConfig := &tls.Config{ServerName: ch.Config["host"]}

	var client *smtp.Client
	var err error

	if tlsMode == "implicit" {
		// Implicit TLS
		tlsConn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return 0, fmt.Errorf("dial failed: %w", err)
		}
		defer tlsConn.Close()

		client, err = smtp.NewClient(tlsConn, ch.Config["host"])
		if err != nil {
			return 0, fmt.Errorf("client failed: %w", err)
		}
	} else {
		// Plain or STARTTLS
		plainConn, err := net.Dial("tcp", addr)
		if err != nil {
			return 0, fmt.Errorf("dial failed: %w", err)
		}
		defer plainConn.Close()

		client, err = smtp.NewClient(plainConn, ch.Config["host"])
		if err != nil {
			return 0, fmt.Errorf("client failed: %w", err)
		}

		if tlsMode == "starttls" {
			if ok, _ := client.Extension("STARTTLS"); ok {
				if err := client.StartTLS(tlsConfig); err != nil {
					client.Close()
					return 0, fmt.Errorf("starttls failed: %w", err)
				}
			}
		}
	}
	defer client.Close()

	// Authenticate
	if ch.Config["user"] != "" && ch.Config["password"] != "" {
		auth := smtp.PlainAuth("", ch.Config["user"], ch.Config["password"], ch.Config["host"])
		if err := client.Auth(auth); err != nil {
			return 0, fmt.Errorf("auth failed: %w", err)
		}
	}

	// Send message
	if err := client.Mail(ch.Config["from"]); err != nil {
		return 0, err
	}

	toAddrsStr := make([]string, len(recipients))
	for i, r := range recipients {
		toAddrsStr[i] = r.Address
	}

	for _, recipient := range toAddrsStr {
		if err := client.Rcpt(recipient); err != nil {
			return 0, err
		}
	}

	w, err := client.Data()
	if err != nil {
		return 0, err
	}
	_, _ = w.Write(msgBuf.Bytes())
	w.Close()

	if err := client.Quit(); err != nil {
		return 0, err
	}

	return time.Since(start).Milliseconds(), nil
}

func (s *SMTPChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Email",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "This is a test email from your FlowSight alerting system.",
	}
	return s.Send(ctx, ch, msg)
}

// SendGridChannel sends via SendGrid API.
type SendGridChannel struct{}

func (s *SendGridChannel) Type() string  { return "sendgrid" }
func (s *SendGridChannel) Label() string { return "SendGrid" }

func (s *SendGridChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "api_key", Label: "API Key", Type: "password", Secret: true, Required: true},
		{Key: "from", Label: "From Address", Type: "text", Required: true},
		{Key: "to", Label: "Recipients (comma-separated)", Type: "text", Required: true},
	}
}

func (s *SendGridChannel) Validate(config map[string]string) error {
	if config["api_key"] == "" || config["from"] == "" || config["to"] == "" {
		return fmt.Errorf("api_key, from, and to required")
	}
	return nil
}

func (s *SendGridChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &PlainTextFormatter{}
	body, _ := formatter.Format(msg)

	toAddrs := strings.Split(ch.Config["to"], ",")
	var recipients []map[string]string
	for _, addr := range toAddrs {
		addr = strings.TrimSpace(addr)
		if addr != "" {
			recipients = append(recipients, map[string]string{"email": addr})
		}
	}

	payload := map[string]interface{}{
		"personalizations": []map[string]interface{}{
			{
				"to": recipients,
			},
		},
		"from": map[string]string{
			"email": ch.Config["from"],
		},
		"subject": "[" + msg.Severity + "] " + msg.Title,
		"content": []map[string]string{
			{
				"type":  "text/plain",
				"value": body,
			},
		},
	}

	b, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://api.sendgrid.com/v3/mail/send", bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+ch.Config["api_key"])

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Since(start).Milliseconds(), fmt.Errorf("sendgrid returned %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}

func (s *SendGridChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test email from FlowSight.",
	}
	return s.Send(ctx, ch, msg)
}

// MailgunChannel sends via Mailgun API.
type MailgunChannel struct{}

func (m *MailgunChannel) Type() string  { return "mailgun" }
func (m *MailgunChannel) Label() string { return "Mailgun" }
func (m *MailgunChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "api_key", Label: "API Key", Type: "password", Secret: true, Required: true},
		{Key: "domain", Label: "Domain", Type: "text", Required: true, Help: "e.g., mail.example.com"},
		{Key: "from", Label: "From Address", Type: "text", Required: true},
		{Key: "to", Label: "Recipients (comma-separated)", Type: "text", Required: true},
		{Key: "region", Label: "Region", Type: "select", Options: []string{"us", "eu"}, Required: true, Help: "US (api.mailgun.net) or EU (api.eu.mailgun.net)"},
	}
}
func (m *MailgunChannel) Validate(config map[string]string) error {
	if config["api_key"] == "" || config["domain"] == "" || config["from"] == "" || config["to"] == "" {
		return fmt.Errorf("api_key, domain, from, and to required")
	}
	if config["region"] == "" {
		config["region"] = "us"
	}
	return nil
}
func (m *MailgunChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &PlainTextFormatter{}
	body, _ := formatter.Format(msg)

	region := ch.Config["region"]
	if region == "" {
		region = "us"
	}

	var baseURL string
	if region == "eu" {
		baseURL = "https://api.eu.mailgun.net"
	} else {
		baseURL = "https://api.mailgun.net"
	}

	data := url.Values{}
	data.Set("from", ch.Config["from"])

	// Parse recipients and add them
	toAddrs := strings.Split(ch.Config["to"], ",")
	for _, addr := range toAddrs {
		addr = strings.TrimSpace(addr)
		if addr != "" {
			data.Add("to", addr)
		}
	}

	data.Set("subject", "["+strings.ToUpper(msg.Severity[:1])+"] "+msg.Title)
	data.Set("text", body)

	apiURL := fmt.Sprintf("%s/v3/%s/messages", baseURL, ch.Config["domain"])

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("api", ch.Config["api_key"])

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("mailgun returned %d: %s", resp.StatusCode, string(body))
	}

	return time.Since(start).Milliseconds(), nil
}
func (m *MailgunChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Email",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test email from FlowSight alerting system.",
	}
	return m.Send(ctx, ch, msg)
}

// AmazonSESChannel sends via Amazon SES API with SigV4 signing.
type AmazonSESChannel struct{}

func (a *AmazonSESChannel) Type() string  { return "amazon_ses" }
func (a *AmazonSESChannel) Label() string { return "Amazon SES" }
func (a *AmazonSESChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "access_key", Label: "Access Key", Type: "password", Secret: true, Required: true},
		{Key: "secret_key", Label: "Secret Key", Type: "password", Secret: true, Required: true},
		{Key: "region", Label: "Region", Type: "text", Required: true, Help: "e.g., us-east-1"},
		{Key: "from", Label: "From Address", Type: "text", Required: true},
		{Key: "to", Label: "Recipients (comma-separated)", Type: "text", Required: true},
	}
}
func (a *AmazonSESChannel) Validate(config map[string]string) error {
	if config["access_key"] == "" || config["secret_key"] == "" || config["region"] == "" || config["from"] == "" || config["to"] == "" {
		return fmt.Errorf("access_key, secret_key, region, from, and to required")
	}
	return nil
}
func (a *AmazonSESChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &PlainTextFormatter{}
	body, _ := formatter.Format(msg)

	toAddrs := strings.Split(ch.Config["to"], ",")
	var recipients []string
	for _, addr := range toAddrs {
		addr = strings.TrimSpace(addr)
		if addr != "" {
			recipients = append(recipients, addr)
		}
	}

	if len(recipients) == 0 {
		return 0, fmt.Errorf("no valid recipients")
	}

	payload := map[string]interface{}{
		"Source": ch.Config["from"],
		"Destination": map[string]interface{}{
			"ToAddresses": recipients,
		},
		"Message": map[string]interface{}{
			"Subject": map[string]string{
				"Data": "[" + strings.ToUpper(msg.Severity[:1]) + "] " + msg.Title,
			},
			"Body": map[string]interface{}{
				"Text": map[string]string{
					"Data": body,
				},
			},
		},
	}

	jsonPayload, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 15 * time.Second}
	endpoint := fmt.Sprintf("https://email.%s.amazonaws.com/", ch.Config["region"])

	req, _ := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(jsonPayload))
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "Reach.SendEmail")

	// Sign the request with SigV4
	if err := SignRequest(req, ch.Config["access_key"], ch.Config["secret_key"], ch.Config["region"], "ses", jsonPayload); err != nil {
		return 0, fmt.Errorf("failed to sign request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("ses returned %d: %s", resp.StatusCode, string(body))
	}

	return time.Since(start).Milliseconds(), nil
}
func (a *AmazonSESChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Email",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test email from FlowSight alerting system.",
	}
	return a.Send(ctx, ch, msg)
}

// PostmarkChannel sends via Postmark API.
type PostmarkChannel struct{}

func (p *PostmarkChannel) Type() string  { return "postmark" }
func (p *PostmarkChannel) Label() string { return "Postmark" }
func (p *PostmarkChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "api_key", Label: "API Key", Type: "password", Secret: true, Required: true, Help: "Server token from Postmark"},
		{Key: "from", Label: "From Address", Type: "text", Required: true},
		{Key: "to", Label: "Recipients (comma-separated)", Type: "text", Required: true},
	}
}
func (p *PostmarkChannel) Validate(config map[string]string) error {
	if config["api_key"] == "" || config["from"] == "" || config["to"] == "" {
		return fmt.Errorf("api_key, from, and to required")
	}
	return nil
}
func (p *PostmarkChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &PlainTextFormatter{}
	body, _ := formatter.Format(msg)

	toAddrs := strings.Split(ch.Config["to"], ",")
	var recipients []map[string]string
	for _, addr := range toAddrs {
		addr = strings.TrimSpace(addr)
		if addr != "" {
			recipients = append(recipients, map[string]string{"Email": addr})
		}
	}

	if len(recipients) == 0 {
		return 0, fmt.Errorf("no valid recipients")
	}

	payload := map[string]interface{}{
		"From":     ch.Config["from"],
		"To":       strings.TrimSpace(ch.Config["to"]),
		"Subject":  "[" + strings.ToUpper(msg.Severity[:1]) + "] " + msg.Title,
		"TextBody": body,
	}

	jsonPayload, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://api.postmarkapp.com/email", bytes.NewBuffer(jsonPayload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Postmark-Server-Token", ch.Config["api_key"])

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("postmark returned %d: %s", resp.StatusCode, string(body))
	}

	return time.Since(start).Milliseconds(), nil
}
func (p *PostmarkChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Email",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test email from FlowSight alerting system.",
	}
	return p.Send(ctx, ch, msg)
}

// ==================== SMS/VOICE CHANNELS ====================

// TwilioChannel sends SMS and voice calls via Twilio.
type TwilioChannel struct{}

func (t *TwilioChannel) Type() string  { return "twilio" }
func (t *TwilioChannel) Label() string { return "Twilio" }

func (t *TwilioChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "account_sid", Label: "Account SID", Type: "text", Secret: true, Required: true},
		{Key: "auth_token", Label: "Auth Token", Type: "password", Secret: true, Required: true},
		{Key: "from_number", Label: "From Number", Type: "text", Required: true, Help: "E.164 format: +1234567890"},
		{Key: "to_number", Label: "To Number", Type: "text", Required: true, Help: "E.164 format: +1234567890"},
		{Key: "mode", Label: "Mode", Type: "select", Options: []string{"sms", "voice"}, Required: true, Help: "SMS or Voice call"},
	}
}

func (t *TwilioChannel) Validate(config map[string]string) error {
	if config["account_sid"] == "" || config["auth_token"] == "" || config["from_number"] == "" || config["to_number"] == "" || config["mode"] == "" {
		return fmt.Errorf("account_sid, auth_token, from_number, to_number, and mode required")
	}
	if config["mode"] != "sms" && config["mode"] != "voice" {
		return fmt.Errorf("mode must be 'sms' or 'voice'")
	}
	return nil
}

func (t *TwilioChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()
	client := &http.Client{Timeout: 15 * time.Second}

	mode := ch.Config["mode"]
	if mode == "voice" {
		return t.sendVoice(ctx, client, ch, msg, start)
	}

	// SMS mode
	formatter := &SMSFormatter{}
	body, _ := formatter.Format(msg)

	params := url.Values{
		"From": {ch.Config["from_number"]},
		"To":   {ch.Config["to_number"]},
		"Body": {body},
	}

	apiURL := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", ch.Config["account_sid"])
	req, _ := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(params.Encode()))
	req.SetBasicAuth(ch.Config["account_sid"], ch.Config["auth_token"])
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("twilio returned %d: %s", resp.StatusCode, string(body))
	}

	return time.Since(start).Milliseconds(), nil
}

func (t *TwilioChannel) sendVoice(ctx context.Context, client *http.Client, ch *Channel, msg *Message, start time.Time) (int64, error) {
	// Build TwiML for voice call
	twiml := `<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say voice="alice">FlowSight Alert: ` + msg.Title + `. Severity: ` + msg.Severity + `</Say>
</Response>`

	// URL-encode TwiML payload for form submission
	params := url.Values{
		"From":  {ch.Config["from_number"]},
		"To":    {ch.Config["to_number"]},
		"Twiml": {twiml},
	}

	apiURL := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Calls.json", ch.Config["account_sid"])
	req, _ := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(params.Encode()))
	req.SetBasicAuth(ch.Config["account_sid"], ch.Config["auth_token"])
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("twilio voice returned %d: %s", resp.StatusCode, string(body))
	}

	return time.Since(start).Milliseconds(), nil
}

func (t *TwilioChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test notification from FlowSight alerting.",
	}
	return t.Send(ctx, ch, msg)
}

// VonageChannel sends SMS via Vonage/Nexmo API.
type VonageChannel struct{}

func (v *VonageChannel) Type() string  { return "vonage" }
func (v *VonageChannel) Label() string { return "Vonage/Nexmo" }
func (v *VonageChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "api_key", Label: "API Key", Type: "text", Required: true},
		{Key: "api_secret", Label: "API Secret", Type: "password", Secret: true, Required: true},
		{Key: "from_number", Label: "From Number (or Name)", Type: "text", Required: true},
		{Key: "to_number", Label: "To Number", Type: "text", Required: true, Help: "E.164 format"},
	}
}
func (v *VonageChannel) Validate(config map[string]string) error {
	if config["api_key"] == "" || config["api_secret"] == "" || config["from_number"] == "" || config["to_number"] == "" {
		return fmt.Errorf("api_key, api_secret, from_number, and to_number required")
	}
	return nil
}
func (v *VonageChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &SMSFormatter{}
	body, _ := formatter.Format(msg)

	params := url.Values{
		"api_key":    {ch.Config["api_key"]},
		"api_secret": {ch.Config["api_secret"]},
		"from":       {ch.Config["from_number"]},
		"to":         {ch.Config["to_number"]},
		"text":       {body},
	}

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://rest.nexmo.com/sms/json", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("vonage returned %d: %s", resp.StatusCode, string(body))
	}

	return time.Since(start).Milliseconds(), nil
}
func (v *VonageChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test SMS from FlowSight.",
	}
	return v.Send(ctx, ch, msg)
}

// TelnyxChannel sends SMS via Telnyx API.
type TelnyxChannel struct{}

func (t *TelnyxChannel) Type() string  { return "telnyx" }
func (t *TelnyxChannel) Label() string { return "Telnyx" }
func (t *TelnyxChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "api_key", Label: "API Key", Type: "password", Secret: true, Required: true},
		{Key: "from_number", Label: "From Number", Type: "text", Required: true, Help: "E.164 format"},
		{Key: "to_number", Label: "To Number", Type: "text", Required: true, Help: "E.164 format"},
	}
}
func (t *TelnyxChannel) Validate(config map[string]string) error {
	if config["api_key"] == "" || config["from_number"] == "" || config["to_number"] == "" {
		return fmt.Errorf("api_key, from_number, and to_number required")
	}
	return nil
}
func (t *TelnyxChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &SMSFormatter{}
	body, _ := formatter.Format(msg)

	payload := map[string]interface{}{
		"from": ch.Config["from_number"],
		"to":   ch.Config["to_number"],
		"text": body,
	}

	jsonPayload, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://api.telnyx.com/v2/messages", bytes.NewBuffer(jsonPayload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+ch.Config["api_key"])

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("telnyx returned %d: %s", resp.StatusCode, string(body))
	}

	return time.Since(start).Milliseconds(), nil
}
func (t *TelnyxChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test SMS from FlowSight.",
	}
	return t.Send(ctx, ch, msg)
}

// AWSSNSChannel sends SMS/notifications via AWS SNS with SigV4 signing.
type AWSSNSChannel struct{}

func (a *AWSSNSChannel) Type() string  { return "aws_sns" }
func (a *AWSSNSChannel) Label() string { return "AWS SNS" }
func (a *AWSSNSChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "access_key", Label: "Access Key", Type: "password", Secret: true, Required: true},
		{Key: "secret_key", Label: "Secret Key", Type: "password", Secret: true, Required: true},
		{Key: "region", Label: "Region", Type: "text", Required: true, Help: "e.g., us-east-1"},
		{Key: "target", Label: "Phone Number or Topic ARN", Type: "text", Required: true, Help: "Phone: E.164 format; Topic: arn:aws:sns:..."},
	}
}
func (a *AWSSNSChannel) Validate(config map[string]string) error {
	if config["access_key"] == "" || config["secret_key"] == "" || config["region"] == "" || config["target"] == "" {
		return fmt.Errorf("access_key, secret_key, region, and target required")
	}
	return nil
}
func (a *AWSSNSChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &SMSFormatter{}
	body, _ := formatter.Format(msg)

	params := url.Values{}
	params.Set("Action", "Publish")
	params.Set("Message", body)

	target := ch.Config["target"]
	if strings.HasPrefix(target, "arn:aws:sns:") {
		params.Set("TopicArn", target)
	} else {
		params.Set("PhoneNumber", target)
	}

	params.Set("Version", "2010-03-31")

	payload := params.Encode()

	client := &http.Client{Timeout: 15 * time.Second}
	endpoint := fmt.Sprintf("https://sns.%s.amazonaws.com/", ch.Config["region"])
	req, _ := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Sign the request with SigV4
	if err := SignRequest(req, ch.Config["access_key"], ch.Config["secret_key"], ch.Config["region"], "sns", []byte(payload)); err != nil {
		return 0, fmt.Errorf("failed to sign request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("sns returned %d: %s", resp.StatusCode, string(body))
	}

	return time.Since(start).Milliseconds(), nil
}
func (a *AWSSNSChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test notification from FlowSight.",
	}
	return a.Send(ctx, ch, msg)
}

// PlivoChannel sends SMS via Plivo API.
type PlivoChannel struct{}

func (p *PlivoChannel) Type() string  { return "plivo" }
func (p *PlivoChannel) Label() string { return "Plivo" }
func (p *PlivoChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "auth_id", Label: "Auth ID", Type: "text", Required: true},
		{Key: "auth_token", Label: "Auth Token", Type: "password", Secret: true, Required: true},
		{Key: "from_number", Label: "From Number", Type: "text", Required: true, Help: "E.164 format"},
		{Key: "to_number", Label: "To Number", Type: "text", Required: true, Help: "E.164 format"},
	}
}
func (p *PlivoChannel) Validate(config map[string]string) error {
	if config["auth_id"] == "" || config["auth_token"] == "" || config["from_number"] == "" || config["to_number"] == "" {
		return fmt.Errorf("auth_id, auth_token, from_number, and to_number required")
	}
	return nil
}
func (p *PlivoChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &SMSFormatter{}
	body, _ := formatter.Format(msg)

	params := url.Values{
		"src":  {ch.Config["from_number"]},
		"dst":  {ch.Config["to_number"]},
		"text": {body},
	}

	client := &http.Client{Timeout: 15 * time.Second}
	apiURL := fmt.Sprintf("https://api.plivo.com/v1/Account/%s/Message/", ch.Config["auth_id"])
	req, _ := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(params.Encode()))
	req.SetBasicAuth(ch.Config["auth_id"], ch.Config["auth_token"])
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("plivo returned %d: %s", resp.StatusCode, string(body))
	}

	return time.Since(start).Milliseconds(), nil
}
func (p *PlivoChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test SMS from FlowSight.",
	}
	return p.Send(ctx, ch, msg)
}

// MessageBirdChannel sends SMS via MessageBird API.
type MessageBirdChannel struct{}

func (m *MessageBirdChannel) Type() string  { return "messagebird" }
func (m *MessageBirdChannel) Label() string { return "MessageBird" }
func (m *MessageBirdChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "api_key", Label: "API Key", Type: "password", Secret: true, Required: true},
		{Key: "from_number", Label: "From Number (or Name)", Type: "text", Required: true},
		{Key: "to_number", Label: "To Number", Type: "text", Required: true, Help: "E.164 format"},
	}
}
func (m *MessageBirdChannel) Validate(config map[string]string) error {
	if config["api_key"] == "" || config["from_number"] == "" || config["to_number"] == "" {
		return fmt.Errorf("api_key, from_number, and to_number required")
	}
	return nil
}
func (m *MessageBirdChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &SMSFormatter{}
	body, _ := formatter.Format(msg)

	params := url.Values{
		"originator": {ch.Config["from_number"]},
		"recipients": {ch.Config["to_number"]},
		"body":       {body},
	}

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://rest.messagebird.com/messages", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("AccessKey", ch.Config["api_key"])

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("messagebird returned %d: %s", resp.StatusCode, string(body))
	}

	return time.Since(start).Milliseconds(), nil
}
func (m *MessageBirdChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test SMS from FlowSight.",
	}
	return m.Send(ctx, ch, msg)
}

// ClickSendChannel sends SMS via ClickSend API.
type ClickSendChannel struct{}

func (c *ClickSendChannel) Type() string  { return "clicksend" }
func (c *ClickSendChannel) Label() string { return "ClickSend" }
func (c *ClickSendChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "username", Label: "Username", Type: "text", Required: true},
		{Key: "api_key", Label: "API Key", Type: "password", Secret: true, Required: true},
		{Key: "from_number", Label: "From Number", Type: "text", Required: true, Help: "E.164 format"},
		{Key: "to_number", Label: "To Number", Type: "text", Required: true, Help: "E.164 format"},
	}
}
func (c *ClickSendChannel) Validate(config map[string]string) error {
	if config["username"] == "" || config["api_key"] == "" || config["from_number"] == "" || config["to_number"] == "" {
		return fmt.Errorf("username, api_key, from_number, and to_number required")
	}
	return nil
}
func (c *ClickSendChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &SMSFormatter{}
	body, _ := formatter.Format(msg)

	payload := map[string]interface{}{
		"messages": []map[string]interface{}{
			{
				"from":    ch.Config["from_number"],
				"to":      ch.Config["to_number"],
				"content": body,
			},
		},
	}

	jsonPayload, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://rest.clicksend.com/v3/sms/send", bytes.NewBuffer(jsonPayload))
	req.Header.Set("Content-Type", "application/json")

	// Basic auth with username and API key
	auth := base64.StdEncoding.EncodeToString([]byte(ch.Config["username"] + ":" + ch.Config["api_key"]))
	req.Header.Set("Authorization", "Basic "+auth)

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("clicksend returned %d: %s", resp.StatusCode, string(body))
	}

	return time.Since(start).Milliseconds(), nil
}
func (c *ClickSendChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test SMS from FlowSight.",
	}
	return c.Send(ctx, ch, msg)
}

// ==================== INCIDENT/ON-CALL CHANNELS ====================

// PagerDutyChannel sends via PagerDuty Events v2 API.
type PagerDutyChannel struct{}

func (p *PagerDutyChannel) Type() string  { return "pagerduty" }
func (p *PagerDutyChannel) Label() string { return "PagerDuty" }

func (p *PagerDutyChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "routing_key", Label: "Routing Key", Type: "password", Secret: true, Required: true, Help: "From Integration > PagerDuty Events Integration"},
	}
}

func (p *PagerDutyChannel) Validate(config map[string]string) error {
	if config["routing_key"] == "" {
		return fmt.Errorf("routing_key required")
	}
	return nil
}

func (p *PagerDutyChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	severity := severityToPagerDuty(msg.Severity)

	payload := map[string]interface{}{
		"routing_key":  ch.Config["routing_key"],
		"event_action": "trigger",
		"dedup_key":    msg.AlertKey,
		"payload": map[string]interface{}{
			"summary":   msg.Title,
			"severity":  severity,
			"source":    msg.Module,
			"timestamp": msg.Timestamp.Format(time.RFC3339),
			"custom_details": map[string]interface{}{
				"category": msg.Category,
				"evidence": msg.Evidence,
			},
		},
	}

	if msg.Device != nil && msg.Device.IP != "" {
		payload["payload"].(map[string]interface{})["custom_details"].(map[string]interface{})["device"] = msg.Device.IP
	}

	b, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://events.pagerduty.com/v2/enqueue", bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("pagerduty returned %d: %s", resp.StatusCode, string(body))
	}

	return time.Since(start).Milliseconds(), nil
}

func (p *PagerDutyChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		AlertKey:  "test-alert-" + fmt.Sprint(time.Now().Unix()),
		Body:      "Test incident from FlowSight.",
	}
	return p.Send(ctx, ch, msg)
}

func severityToPagerDuty(severity string) string {
	switch severity {
	case "critical":
		return "critical"
	case "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "info"
	}
}

// OpsgenieChannel sends alerts via Opsgenie API.
type OpsgenieChannel struct{}

func (o *OpsgenieChannel) Type() string  { return "opsgenie" }
func (o *OpsgenieChannel) Label() string { return "Opsgenie" }
func (o *OpsgenieChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "api_key", Label: "API Key", Type: "password", Secret: true, Required: true},
		{Key: "region", Label: "Region", Type: "select", Options: []string{"us", "eu"}, Required: true, Help: "US or EU"},
	}
}
func (o *OpsgenieChannel) Validate(config map[string]string) error {
	if config["api_key"] == "" {
		return fmt.Errorf("api_key required")
	}
	if config["region"] == "" {
		config["region"] = "us"
	}
	return nil
}
func (o *OpsgenieChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	priority := severityToOpsgeniePriority(msg.Severity)

	payload := map[string]interface{}{
		"message":     msg.Title,
		"description": msg.Body,
		"priority":    priority,
		"source":      msg.Module,
		"tags":        []string{msg.Category, msg.Severity},
	}

	if msg.Device != nil && msg.Device.IP != "" {
		payload["details"] = map[string]string{
			"device_ip":   msg.Device.IP,
			"device_name": msg.Device.Name,
		}
	}

	jsonPayload, _ := json.Marshal(payload)

	region := ch.Config["region"]
	if region == "" {
		region = "us"
	}

	var baseURL string
	if region == "eu" {
		baseURL = "https://api.eu.opsgenie.com"
	} else {
		baseURL = "https://api.opsgenie.com"
	}

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", baseURL+"/v2/alerts", bytes.NewBuffer(jsonPayload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "GenieKey "+ch.Config["api_key"])

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("opsgenie returned %d: %s", resp.StatusCode, string(body))
	}

	return time.Since(start).Milliseconds(), nil
}
func (o *OpsgenieChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test alert from FlowSight.",
	}
	return o.Send(ctx, ch, msg)
}

func severityToOpsgeniePriority(severity string) string {
	switch severity {
	case "critical":
		return "P1"
	case "high":
		return "P2"
	case "medium":
		return "P3"
	case "low":
		return "P4"
	default:
		return "P5"
	}
}

// SplunkOnCallChannel sends alerts via Splunk On-Call (VictorOps) API.
type SplunkOnCallChannel struct{}

func (s *SplunkOnCallChannel) Type() string  { return "splunk_oncall" }
func (s *SplunkOnCallChannel) Label() string { return "Splunk On-Call" }
func (s *SplunkOnCallChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "webhook_url", Label: "REST Endpoint URL", Type: "url", Secret: true, Required: true, Help: "Includes routing key"},
	}
}
func (s *SplunkOnCallChannel) Validate(config map[string]string) error {
	if config["webhook_url"] == "" {
		return fmt.Errorf("webhook_url required")
	}
	return nil
}
func (s *SplunkOnCallChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	messageType := severityToSplunkOnCall(msg.Severity)

	payload := map[string]interface{}{
		"message_type": messageType,
		"title":        msg.Title,
		"description":  msg.Body,
		"source":       msg.Module,
		"entity_id":    msg.AlertKey,
		"severity":     msg.Severity,
	}

	if msg.Device != nil && msg.Device.IP != "" {
		payload["state_message"] = fmt.Sprintf("Device %s (%s)", msg.Device.Name, msg.Device.IP)
	}

	jsonPayload, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", ch.Config["webhook_url"], bytes.NewBuffer(jsonPayload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("splunk oncall returned %d: %s", resp.StatusCode, string(body))
	}

	return time.Since(start).Milliseconds(), nil
}
func (s *SplunkOnCallChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		AlertKey:  "test-alert-" + fmt.Sprint(time.Now().Unix()),
		Body:      "Test alert from FlowSight.",
	}
	return s.Send(ctx, ch, msg)
}

func severityToSplunkOnCall(severity string) string {
	switch severity {
	case "critical":
		return "CRITICAL"
	case "high":
		return "WARNING"
	case "medium":
		return "WARNING"
	default:
		return "INFO"
	}
}

// SquadcastChannel sends alerts via Squadcast webhook.
type SquadcastChannel struct{}

func (s *SquadcastChannel) Type() string  { return "squadcast" }
func (s *SquadcastChannel) Label() string { return "Squadcast" }
func (s *SquadcastChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "webhook_url", Label: "Webhook URL", Type: "url", Secret: true, Required: true},
	}
}
func (s *SquadcastChannel) Validate(config map[string]string) error {
	if config["webhook_url"] == "" {
		return fmt.Errorf("webhook_url required")
	}
	return nil
}
func (s *SquadcastChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	payload := map[string]interface{}{
		"message":   msg.Title,
		"details":   msg.Body,
		"severity":  msg.Severity,
		"timestamp": msg.Timestamp.Unix(),
	}

	if msg.Device != nil && msg.Device.IP != "" {
		payload["impacted_resource"] = msg.Device.IP
	}

	jsonPayload, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", ch.Config["webhook_url"], bytes.NewBuffer(jsonPayload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("squadcast returned %d: %s", resp.StatusCode, string(body))
	}

	return time.Since(start).Milliseconds(), nil
}
func (s *SquadcastChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test alert from FlowSight.",
	}
	return s.Send(ctx, ch, msg)
}

// IncidentIOChannel sends alerts via incident.io webhook.
type IncidentIOChannel struct{}

func (i *IncidentIOChannel) Type() string  { return "incident_io" }
func (i *IncidentIOChannel) Label() string { return "incident.io" }
func (i *IncidentIOChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "webhook_url", Label: "Webhook URL", Type: "url", Secret: true, Required: true},
	}
}
func (i *IncidentIOChannel) Validate(config map[string]string) error {
	if config["webhook_url"] == "" {
		return fmt.Errorf("webhook_url required")
	}
	return nil
}
func (i *IncidentIOChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	payload := map[string]interface{}{
		"title":       msg.Title,
		"description": msg.Body,
		"severity":    msg.Severity,
		"status":      "investigating",
		"created_at":  msg.Timestamp.Format(time.RFC3339),
	}

	if msg.Device != nil {
		payload["impact"] = map[string]interface{}{
			"service": msg.Module,
			"type":    "degraded",
		}
	}

	jsonPayload, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", ch.Config["webhook_url"], bytes.NewBuffer(jsonPayload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("incident.io returned %d: %s", resp.StatusCode, string(body))
	}

	return time.Since(start).Milliseconds(), nil
}
func (i *IncidentIOChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Body:      "Test alert from FlowSight.",
	}
	return i.Send(ctx, ch, msg)
}

// XMattersChannel sends alerts via xMatters webhook.
type XMattersChannel struct{}

func (x *XMattersChannel) Type() string  { return "xmatters" }
func (x *XMattersChannel) Label() string { return "xMatters" }
func (x *XMattersChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "webhook_url", Label: "Webhook URL", Type: "url", Secret: true, Required: true},
	}
}
func (x *XMattersChannel) Validate(config map[string]string) error {
	if config["webhook_url"] == "" {
		return fmt.Errorf("webhook_url required")
	}
	return nil
}
func (x *XMattersChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	payload := map[string]interface{}{
		"properties": map[string]interface{}{
			"severity":  msg.Severity,
			"title":     msg.Title,
			"body":      msg.Body,
			"source":    msg.Module,
			"alert_key": msg.AlertKey,
		},
	}

	if msg.Device != nil && msg.Device.IP != "" {
		payload["properties"].(map[string]interface{})["device_ip"] = msg.Device.IP
	}

	jsonPayload, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", ch.Config["webhook_url"], bytes.NewBuffer(jsonPayload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("xmatters returned %d: %s", resp.StatusCode, string(body))
	}

	return time.Since(start).Milliseconds(), nil
}
func (x *XMattersChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		AlertKey:  "test-alert-" + fmt.Sprint(time.Now().Unix()),
		Body:      "Test alert from FlowSight.",
	}
	return x.Send(ctx, ch, msg)
}

// ZendutySChannel sends alerts via Zenduty webhook.
type ZendutySChannel struct{}

func (z *ZendutySChannel) Type() string  { return "zenduty" }
func (z *ZendutySChannel) Label() string { return "Zenduty" }
func (z *ZendutySChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "webhook_url", Label: "Webhook URL", Type: "url", Secret: true, Required: true},
	}
}
func (z *ZendutySChannel) Validate(config map[string]string) error {
	if config["webhook_url"] == "" {
		return fmt.Errorf("webhook_url required")
	}
	return nil
}
func (z *ZendutySChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	payload := map[string]interface{}{
		"title":       msg.Title,
		"description": msg.Body,
		"severity":    severityToZenduty(msg.Severity),
		"created_by":  "flowsight",
		"alert_group": msg.AlertKey,
	}

	if msg.Device != nil && msg.Device.IP != "" {
		payload["entity_id"] = msg.Device.IP
	}

	jsonPayload, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", ch.Config["webhook_url"], bytes.NewBuffer(jsonPayload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("zenduty returned %d: %s", resp.StatusCode, string(body))
	}

	return time.Since(start).Milliseconds(), nil
}
func (z *ZendutySChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		AlertKey:  "test-alert-" + fmt.Sprint(time.Now().Unix()),
		Body:      "Test alert from FlowSight.",
	}
	return z.Send(ctx, ch, msg)
}

func severityToZenduty(severity string) string {
	switch severity {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}

// BetterStackChannel sends incidents to Better Stack via API.
type BetterStackChannel struct{}

func (b *BetterStackChannel) Type() string  { return "betterstack" }
func (b *BetterStackChannel) Label() string { return "Better Stack" }
func (b *BetterStackChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "api_token", Label: "API Token", Type: "password", Secret: true, Required: true},
	}
}
func (b *BetterStackChannel) Validate(config map[string]string) error {
	if config["api_token"] == "" {
		return fmt.Errorf("api_token required")
	}
	return nil
}
func (b *BetterStackChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	severity := severityToButterStack(msg.Severity)

	payload := map[string]interface{}{
		"incident": map[string]interface{}{
			"name":              msg.Title,
			"description":       msg.Body,
			"severity":          severity,
			"cause_of_incident": msg.AlertKey,
			"started_at":        msg.Timestamp.Format(time.RFC3339),
		},
	}

	jsonPayload, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://uptime.betterstack.com/api/v2/incidents", bytes.NewBuffer(jsonPayload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+ch.Config["api_token"])

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, core.MaxResponse))
		return time.Since(start).Milliseconds(), fmt.Errorf("betterstack returned %d: %s", resp.StatusCode, string(body))
	}

	return time.Since(start).Milliseconds(), nil
}
func (b *BetterStackChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		AlertKey:  "test-alert-" + fmt.Sprint(time.Now().Unix()),
		Body:      "Test alert from FlowSight.",
	}
	return b.Send(ctx, ch, msg)
}

func severityToButterStack(severity string) string {
	switch severity {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	default:
		return "low"
	}
}
