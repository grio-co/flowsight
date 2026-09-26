package paths

// An AI assistant, for the hops nothing else can place.
//
// After the router's name, the provider feeds, the registry's geofeeds, RIPE
// IPmap and the address database have all had their say, a few hops are
// still unplaced: a name in a convention nobody has decoded, an operator with
// no published ranges. With a key for a language model configured, those --
// and only those -- are put to it: the hostname, the network and operator,
// the round trip from here, and a request for a JSON answer with a city and
// a confidence. The answer is a hypothesis, not a fact. It is checked against
// the clock like a router name -- a place the round trip could not reach is
// discarded however confident the model was -- drawn as an inference, marked
// as the model's reading on the hop's card, and never allowed to overrule a
// source that actually knows. Off unless a key is set, because it sends
// hostnames to a third party and costs money; asked a few times an hour.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

const assistKV = "paths.ai:"
const assistTTL = 30 * 24 * time.Hour

// Guess is the model's answer, reduced and kept.
type Guess struct {
	City       string  `json:"city"`
	Region     string  `json:"region,omitempty"`
	Country    string  `json:"country,omitempty"`
	Lat        float64 `json:"lat"`
	Lon        float64 `json:"lon"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason,omitempty"`
	Model      string  `json:"model"`
	At         int64   `json:"at"`
	Unknown    bool    `json:"unknown,omitempty"` // the model declined
}

type cachedGuess struct {
	At time.Time
	G  *Guess
}

// assistConfig is what the settings say.
type assistConfig struct {
	Provider, Endpoint, Model, Key string
	PerHour                        int
}

func (m *Module) assist() assistConfig {
	if m.ctx == nil {
		return assistConfig{}
	}
	s := m.ctx.Settings()
	c := assistConfig{
		Provider: strings.ToLower(strings.TrimSpace(core.Str(s, "ai_provider", "off"))),
		Endpoint: strings.TrimSpace(core.Str(s, "ai_endpoint", "")),
		Model:    strings.TrimSpace(core.Str(s, "ai_model", "")),
		Key:      strings.TrimSpace(core.Str(s, "ai_key", "")),
		PerHour:  core.Int(s, "ai_per_hour", 20),
	}
	if c.PerHour < 1 {
		c.PerHour = 1
	}
	if c.PerHour > 600 {
		c.PerHour = 600
	}
	if c.Endpoint == "" {
		c.Endpoint = defaultEndpoint[c.Provider]
	}
	if c.Model == "" {
		c.Model = defaultModel[c.Provider]
	}
	return c
}

var defaultEndpoint = map[string]string{
	"anthropic": "https://api.anthropic.com/v1/messages",
	"openai":    "https://api.openai.com/v1/chat/completions",
	"google":    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
	"azure":     "", // https://<resource>.openai.azure.com/openai/deployments/<deployment>/chat/completions?api-version=2024-10-21
	"ollama":    "http://127.0.0.1:11434/api/chat",
	"custom":    "",
	"assistant": "", // internal; no endpoint
}

var defaultModel = map[string]string{
	"anthropic": "claude-haiku-4-5-20251001",
	"openai":    "gpt-4o-mini",
	"google":    "gemini-2.0-flash",
	"ollama":    "llama3.1",
}

// on says whether the assistant may be asked at all.
func (c assistConfig) on() bool {
	if c.Provider == "" || c.Provider == "off" || c.Endpoint == "" {
		return false
	}
	if c.Provider == "ollama" || c.Provider == "custom" {
		return true
	}
	return c.Key != ""
}

const assistPrompt = `You are a network engineer identifying where an Internet router is physically located.
Router hostname: %s
Address: %s
Network: AS%s %s
Registrant: %s
Round-trip time from %s: %.1f ms (light in fibre covers at most %.0f km in that time, there and back).
Using naming conventions (airport codes, city abbreviations, operator site codes) and what you know of the operator's footprint, give the most likely city.
Answer with JSON only, no prose: {"city":"...","region":"...","country":"CC","lat":0.0,"lon":0.0,"confidence":0.0,"reason":"..."}
If you cannot tell, answer {"unknown":true,"reason":"..."}.`

// guessFor is the cached answer, or nothing; never asks in the request path.
func (m *Module) guessFor(ip string) *Guess {
	if m.ctx == nil || m.ctx.Store == nil {
		return nil
	}
	var c cachedGuess
	if m.ctx.Store.KVGet(assistKV+ip, &c) && time.Since(c.At) < assistTTL {
		return c.G
	}
	return nil
}

func (m *Module) guessKnown(ip string) bool {
	var c cachedGuess
	return m.ctx.Store.KVGet(assistKV+ip, &c) && time.Since(c.At) < assistTTL
}

// askAssistant puts one hop to the model and caches whatever comes back,
// including a refusal, so the same hop is not asked about again this month.
func (m *Module) askAssistant(cfg assistConfig, ip, host string, d *Detail, h Home, rtt float64) error {
	origin := "the gateway"
	if h.OK {
		origin = fmt.Sprintf("%.2f, %.2f", h.Lat, h.Lon)
	}
	asn, asName, org := "", "", ""
	if d != nil {
		asn, asName, org = d.ASN, d.ASName, d.Org
	}
	prompt := fmt.Sprintf(assistPrompt, nz(host, "(none)"), ip, nz(asn, "?"), asName, nz(org, "(unknown)"), origin, rtt, rtt/2*200)
	text, err := m.callModel(cfg, prompt)
	g := &Guess{Model: cfg.Provider + "/" + cfg.Model, At: time.Now().Unix()}
	if err != nil {
		return err
	}
	if parsed, perr := parseGuess(text); perr == nil {
		parsed.Model, parsed.At = g.Model, g.At
		g = parsed
	} else {
		g.Unknown, g.Reason = true, "unparseable answer"
	}
	return m.ctx.Store.KVSet(assistKV+ip, cachedGuess{At: time.Now(), G: g})
}

var jsonBlockRe = regexp.MustCompile(`(?s)\{.*\}`)

// parseGuess reads the JSON out of whatever the model wrapped it in.
func parseGuess(text string) (*Guess, error) {
	raw := jsonBlockRe.FindString(text)
	if raw == "" {
		return nil, fmt.Errorf("no JSON in answer")
	}
	var g Guess
	if err := json.Unmarshal([]byte(raw), &g); err != nil {
		return nil, err
	}
	if g.Unknown {
		return &g, nil
	}
	if g.City == "" || (g.Lat == 0 && g.Lon == 0) || g.Lat < -90 || g.Lat > 90 || g.Lon < -180 || g.Lon > 180 {
		return nil, fmt.Errorf("answer has no usable place")
	}
	if g.Confidence < 0 {
		g.Confidence = 0
	}
	if g.Confidence > 1 {
		g.Confidence = 1
	}
	return &g, nil
}

// callModel speaks each provider's dialect and returns the text answer.
func (m *Module) callModel(cfg assistConfig, prompt string) (string, error) {
	// Special case: "assistant" provider delegates to the assistant module
	if cfg.Provider == "assistant" {
		if assistMod, ok := m.ctx.Service("assistant").(interface {
			Complete(context.Context, string) (string, error)
		}); ok {
			return assistMod.Complete(context.Background(), prompt)
		}
		return "", fmt.Errorf("assistant module not available")
	}

	var body any
	hdr := map[string]string{"Content-Type": "application/json"}
	endpoint := strings.ReplaceAll(cfg.Endpoint, "{model}", cfg.Model)
	switch cfg.Provider {
	case "anthropic":
		body = map[string]any{"model": cfg.Model, "max_tokens": 300,
			"messages": []map[string]any{{"role": "user", "content": prompt}}}
		hdr["x-api-key"] = cfg.Key
		hdr["anthropic-version"] = "2023-06-01"
	case "openai", "custom":
		body = map[string]any{"model": cfg.Model, "max_tokens": 300, "temperature": 0,
			"messages": []map[string]any{{"role": "user", "content": prompt}}}
		if cfg.Key != "" {
			hdr["Authorization"] = "Bearer " + cfg.Key
		}
	case "azure":
		body = map[string]any{"max_tokens": 300, "temperature": 0,
			"messages": []map[string]any{{"role": "user", "content": prompt}}}
		hdr["api-key"] = cfg.Key
	case "google":
		body = map[string]any{"contents": []map[string]any{{"parts": []map[string]any{{"text": prompt}}}},
			"generationConfig": map[string]any{"temperature": 0, "maxOutputTokens": 300}}
		hdr["x-goog-api-key"] = cfg.Key
	case "ollama":
		body = map[string]any{"model": cfg.Model, "stream": false, "format": "json",
			"messages": []map[string]any{{"role": "user", "content": prompt}}}
	default:
		return "", fmt.Errorf("unknown provider %q", cfg.Provider)
	}
	if cfg.Provider != "ollama" && cfg.Provider != "custom" {
		if err := checkFetchURL(endpoint); err != nil {
			return "", err
		}
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "FlowSight/"+m.version())
	client := safeClient(45 * time.Second)
	if cfg.Provider == "ollama" || cfg.Provider == "custom" {
		client = &http.Client{Timeout: 90 * time.Second} // a local model is allowed to be local
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s", resp.Status, firstLine(string(raw)))
	}
	return extractText(cfg.Provider, raw)
}

// extractText pulls the assistant's text out of each provider's envelope.
func extractText(provider string, raw []byte) (string, error) {
	switch provider {
	case "anthropic":
		var r struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(raw, &r); err != nil || len(r.Content) == 0 {
			return "", fmt.Errorf("anthropic: no content")
		}
		return r.Content[0].Text, nil
	case "openai", "azure", "custom":
		var r struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(raw, &r); err != nil || len(r.Choices) == 0 {
			return "", fmt.Errorf("no choices")
		}
		return r.Choices[0].Message.Content, nil
	case "google":
		var r struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text string `json:"text"`
					} `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
		}
		if err := json.Unmarshal(raw, &r); err != nil || len(r.Candidates) == 0 || len(r.Candidates[0].Content.Parts) == 0 {
			return "", fmt.Errorf("google: no candidates")
		}
		return r.Candidates[0].Content.Parts[0].Text, nil
	case "ollama":
		var r struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return "", err
		}
		return r.Message.Content, nil
	}
	return "", fmt.Errorf("unknown provider")
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}

func nz(s, dflt string) string {
	if strings.TrimSpace(s) == "" {
		return dflt
	}
	return s
}

// assistantJob asks about a handful of unplaced hops each run, within the
// hourly allowance. Candidates come from the last graph: hops that answered,
// have a name or an operator, and that nothing placed.
func (m *Module) assistantJob() error {
	cfg := m.assist()
	if !cfg.on() {
		return nil
	}
	m.mu.Lock()
	cands := append([]assistCandidate(nil), m.assistQueue...)
	m.assistQueue = nil
	// The allowance, as a sliding hour.
	now := time.Now()
	kept := m.assistAsked[:0]
	for _, t := range m.assistAsked {
		if now.Sub(t) < time.Hour {
			kept = append(kept, t)
		}
	}
	m.assistAsked = kept
	room := cfg.PerHour - len(kept)
	m.mu.Unlock()
	if room <= 0 || len(cands) == 0 {
		return nil
	}
	h := m.home()
	asked := 0
	for _, c := range cands {
		if asked >= room || asked >= 5 {
			break
		}
		if m.guessKnown(c.IP) {
			continue
		}
		if err := m.askAssistant(cfg, c.IP, c.Host, c.Detail, h, c.RTT); err != nil {
			m.mu.Lock()
			m.assistErr = err.Error()
			m.mu.Unlock()
			return nil
		}
		m.mu.Lock()
		m.assistErr = ""
		m.assistAsked = append(m.assistAsked, time.Now())
		m.assistTotal++
		m.mu.Unlock()
		asked++
	}
	return nil
}

// assistCandidate is a hop worth asking about.
type assistCandidate struct {
	IP, Host string
	Detail   *Detail
	RTT      float64
}

// wantAssist queues a hop for the next run.
func (m *Module) wantAssist(ip, host string, d *Detail, rtt float64) {
	if !m.assist().on() || rtt <= 0 || !validIP(ip) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.assistQueue {
		if c.IP == ip {
			return
		}
	}
	if len(m.assistQueue) < 200 {
		m.assistQueue = append(m.assistQueue, assistCandidate{ip, host, d, rtt})
	}
}

func (m *Module) assistStatus() map[string]any {
	cfg := m.assist()
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string]any{"on": cfg.on(), "provider": cfg.Provider, "model": cfg.Model, "per_hour": cfg.PerHour,
		"asked_this_session": m.assistTotal, "queued": len(m.assistQueue), "known": m.ctx.Store.KVCount(assistKV), "error": m.assistErr}
}
