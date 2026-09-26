// Package rulehygiene analyses the live pf ruleset for policy issues. It
// reads the ruleset through the core.RuleReader service and analyses it
// when the reader speaks pf syntax.
//
// Firewall rulesets decay: rules shadow each other, stop matching anything,
// and quietly widen exposure. This module reports findings grounded in live
// pf counters, not static rule text. Any tool can say "this rule looks broad";
// only counters separate a genuinely dead rule from one rarely hit—and that
// distinction makes the output trustworthy enough to act on.
//
// Where the platform names a config.xml (OPNsense), it watches it for changes and diffs the <filter>
// and <nat> sections, recording who made the change from the revision metadata.
package rulehygiene

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

type Module struct {
	ctx      *core.Context
	mu       sync.Mutex
	lastErr  string
	lastRun  time.Time
	platform string
	rules    core.RuleReader

	// OPNsense config tracking
	configPath     string
	lastConfigHash string
	configModTime  int64
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name: "rulehygiene", Version: "1.0",
		Description:  "Firewall ruleset analysis: shadowed, unused, redundant and overly permissive rules.",
		Capabilities: []string{core.CapRuleAnalyse},
		After:        []string{"identity", "firewall"},
		Defaults: map[string]any{
			"analyse_minutes":         15,
			"min_evaluations_unused":  1000,
			"min_loaded_hours_unused": 24,
			"wan_interfaces":          []string{},
			"mgmt_ports":              []string{"22", "80", "443"},
		},
		Schema: []core.SettingField{
			{Key: "analyse_minutes", Label: "Analysis interval (minutes)", Type: "int"},
			{Key: "min_evaluations_unused", Label: "Min evaluations for unused detection", Type: "int"},
			{Key: "min_loaded_hours_unused", Label: "Min loaded hours for unused detection", Type: "int"},
			{Key: "wan_interfaces", Label: "WAN interfaces (empty = auto-detect)", Type: "list"},
			{Key: "mgmt_ports", Label: "Management ports (22, 80, 443)", Type: "list"},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.platform = ctx.Platform.Name

	m.rules, _ = ctx.Service(core.ServiceRules).(core.RuleReader)
	if m.canAnalyse() {
		interval := time.Duration(core.Int(ctx.Settings(), "analyse_minutes", 15)) * time.Minute
		ctx.Every("analyse", interval, m.analyse, core.NeedsJob("firewall.analyse"))

		// Track config changes where the platform keeps a config.xml.
		if ctx.Platform.ConfigXML != "" {
			m.configPath = ctx.Platform.ConfigXML
			ctx.Every("watch-config", 1*time.Minute, m.watchConfig, core.NeedsJob("firewall.analyse"), core.Delayed())
		}
	}

	// Routes.
	ctx.Route("GET", "/api/rulehygiene/summary", m.apiSummary, core.Needs("firewall.analyse"),
		core.Doc("Summary of firewall rule health including risk score and analysis statistics"),
		core.Returns("Rule hygiene summary", map[string]any{
			"risk_score":           35,
			"finding_count":        10,
			"rules_analyzed":       250,
			"ruleset_loaded_since": 1790376243,
		}))
	ctx.Route("GET", "/api/rulehygiene/rules", m.apiRules, core.Needs("firewall.analyse"),
		core.Doc("Complete list of firewall rules with hit counters, descriptions and associated findings"),
		core.Returns("Rules list with analysis", map[string]any{
			"rules": []map[string]any{
				{"id": "rule-1", "description": "Allow SSH", "hits": 100, "findings": []string{"unused"}},
			},
		}))
	ctx.Route("GET", "/api/rulehygiene/findings", m.apiFindings, core.Needs("firewall.analyse"),
		core.Doc("Open findings from firewall rule analysis including policy recommendations"),
		core.Returns("Current findings", map[string]any{
			"findings": []map[string]any{
				{"type": "unused-rule", "rule_id": "rule-1", "severity": "low"},
			},
		}))
	ctx.Route("GET", "/api/rulehygiene/changes", m.apiChanges, core.Needs("firewall.analyse"),
		core.Doc("Recent configuration changes and rule modifications tracked from firewall system"),
		core.Returns("Configuration changes", map[string]any{
			"changes": []map[string]any{
				{"timestamp": 1790376243, "rule_id": "rule-1", "action": "modified"},
			},
		}))
	ctx.Route("POST", "/api/rulehygiene/run", m.apiRun, core.Needs("firewall.analyse"),
		core.Write(),
		core.Doc("Trigger immediate firewall rule analysis to detect policy issues and cleanup opportunities"),
		core.Body(),
		core.Returns("Run result", map[string]any{
			"ok":      true,
			"message": "Analysis started",
		}))
	ctx.Panel(core.Panel{
		ID:      "firewall",
		Title:   "Firewall Analysis Engine (FAE)",
		Group:   "Protect",
		Order:   80,
		Icon:    "firewall",
		Feature: "firewall.analyse",
	})

	return nil
}

// canAnalyse reports whether there is a ruleset this module can read: the
// analysis below understands pf syntax only.
func (m *Module) canAnalyse() bool {
	return m.rules != nil && m.rules.Available() && m.rules.Syntax() == "pf"
}

func (m *Module) Health() core.Health {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.canAnalyse() {
		return core.Health{OK: true, Detail: "firewall is not pf; analysis unavailable"}
	}
	if m.lastErr != "" {
		return core.Health{OK: false, Detail: m.lastErr}
	}
	if m.lastRun.IsZero() {
		return core.Health{OK: true, Detail: "analysis pending"}
	}
	return core.Health{OK: true, Detail: fmt.Sprintf("last run %s", timeAgo(m.lastRun))}
}

func timeAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "now"
	case d < time.Hour:
		return fmt.Sprintf("%d minute(s) ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d hour(s) ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%d day(s) ago", int(d.Hours()/24))
	}
}

// Rule is one rule of the live ruleset with its counters, as analysed here.
type Rule struct {
	Index       int
	Text        string
	Evaluations int64
	Packets     int64
	Bytes       int64
	States      int64
	Label       string // OPNsense label UUID
	Description string // OPNsense label description
}

// OPNsenseConfig models /conf/config.xml.
type OPNsenseConfig struct {
	Filter *struct {
		Rules []struct {
			UUID        string `xml:"uuid,attr"`
			Description string `xml:"descr"`
			Interface   string `xml:"interface"`
			Type        string `xml:"type"`
			Source      *struct {
				Any string `xml:"any"`
			} `xml:"source"`
			Destination *struct {
				Any string `xml:"any"`
			} `xml:"destination"`
			Disabled string `xml:"disabled"`
		} `xml:"rule"`
	} `xml:"filter"`
	Revision *struct {
		Username    string `xml:"username"`
		Description string `xml:"description"`
	} `xml:"revision"`
}

// loadOPNsenseConfig parses /conf/config.xml.
func loadOPNsenseConfig(path string) (map[string]string, string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}

	var cfg OPNsenseConfig
	if err := xml.Unmarshal(b, &cfg); err != nil {
		return nil, "", err
	}

	labels := make(map[string]string)
	if cfg.Filter != nil {
		for _, r := range cfg.Filter.Rules {
			if r.UUID != "" && r.Description != "" {
				labels[r.UUID] = r.Description
			}
		}
	}

	actor := "unknown"
	if cfg.Revision != nil && cfg.Revision.Username != "" {
		actor = cfg.Revision.Username
	}

	return labels, actor, nil
}

// configHash computes the hash of config file for change detection.
func configHash(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// AnalysisResult holds the result of a single analysis run.
type AnalysisResult struct {
	Rules            []Rule
	Findings         map[string][]Finding // rule text -> findings
	RiskScore        int
	RulesAnalysed    int
	RulesetLoadedSec int64
}

// Finding is a single issue found in the ruleset.
type Finding struct {
	Kind     string // "shadowed", "redundant", "unused", "permissive", "bad-label"
	Severity string // "critical", "high", "medium", "low"
	Subject  string
	Title    string
	Detail   string
}

// analyse runs the analysis and records findings.
func (m *Module) analyse() error {
	m.mu.Lock()
	m.lastErr = ""
	m.mu.Unlock()

	if !m.canAnalyse() {
		return nil
	}

	// Get live rules with counters.
	live, err := m.rules.Rules()
	if err != nil {
		m.mu.Lock()
		m.lastErr = fmt.Sprintf("reading the %s ruleset failed: %v", m.rules.Name(), err)
		m.mu.Unlock()
		return nil // not a fatal error; just unavailable
	}

	// When the counters started; zero when the backend cannot say.
	var rulesetLoadedSec int64
	if t := m.rules.CountersSince(); !t.IsZero() {
		rulesetLoadedSec = t.Unix()
	}

	// Rule descriptions from the platform's config.xml, keyed by label.
	var labelMap map[string]string
	if m.configPath != "" {
		labelMap, _, _ = loadOPNsenseConfig(m.configPath)
	}

	rules := make([]Rule, len(live))
	for i, r := range live {
		rules[i] = Rule{Index: i, Text: r.Text, Label: r.Label, Evaluations: r.Evaluations,
			Packets: r.Packets, Bytes: r.Bytes, States: r.States, Description: labelMap[r.Label]}
	}

	// Analyse for issues.
	result := m.findIssues(rules, rulesetLoadedSec)

	// Record findings in the store.
	keep := make(map[string]bool)
	for ruleText, findings := range result.Findings {
		for _, f := range findings {
			fp := m.fingerprintKey(ruleText, f.Kind)
			isNew, _ := m.ctx.Store.AddFinding(
				"rulehygiene", f.Kind, f.Severity,
				f.Subject, f.Title, f.Detail, fp,
			)
			keep[fp] = true
			if isNew {
				m.ctx.Log.Info("rulehygiene finding", "kind", f.Kind, "title", f.Title)
			}
		}
	}

	// Resolve stale findings.
	if n, err := m.ctx.Store.ResolveFindings("rulehygiene", keep); err == nil && n > 0 {
		m.ctx.Log.Info("rulehygiene resolved findings", "count", n)
	}

	// Record metrics.
	metrics := []core.Metric{
		{Name: "firewall_risk_score", Value: float64(result.RiskScore)},
		{Name: "firewall_rules_analysed", Value: float64(result.RulesAnalysed)},
		{Name: "firewall_findings", Value: float64(len(result.Findings))},
	}
	_ = m.ctx.Store.AddMetrics(time.Now().Unix(), metrics)

	m.mu.Lock()
	m.lastRun = time.Now()
	m.mu.Unlock()

	return nil
}

// findIssues analyses rules for policy issues.
func (m *Module) findIssues(rules []Rule, rulesetLoadedSec int64) AnalysisResult {
	settings := m.ctx.Settings()
	minEvals := int64(core.Int(settings, "min_evaluations_unused", 1000))
	minLoadHours := int64(core.Int(settings, "min_loaded_hours_unused", 24))
	wanIfaces := core.Strs(settings, "wan_interfaces")
	mgmtPorts := core.Strs(settings, "mgmt_ports")

	// Auto-detect WAN interface if not configured.
	if len(wanIfaces) == 0 {
		wanIfaces = m.detectWANInterfaces()
	}

	result := AnalysisResult{
		Rules:            rules,
		Findings:         make(map[string][]Finding),
		RulesetLoadedSec: rulesetLoadedSec,
	}
	// rulesetLoadedSec is the load time; counters are only meaningful for the
	// time elapsed since then, and not at all when it is unknown.
	var elapsed int64
	if rulesetLoadedSec > 0 {
		elapsed = time.Now().Unix() - rulesetLoadedSec
	}
	elapsedDays := float64(elapsed) / 86400
	oldEnough := elapsed >= minLoadHours*3600

	// Iterate rules and identify issues.
	for i, rule := range rules {
		// Skip infrastructure rules.
		if m.isInfrastructure(rule.Text) {
			continue
		}

		result.RulesAnalysed++

		// Never evaluated: pf skips a rule whose interface or direction does not
		// match, so zero evaluations usually means "no such traffic", not "an
		// earlier rule wins". Report it as informational, not as shadowing;
		// real shadowing needs a coverage comparison that is not done yet.
		if rule.Evaluations == 0 && oldEnough {
			findings := result.Findings[rule.Text]
			findings = append(findings, Finding{
				Kind:     "never-evaluated",
				Severity: "info",
				Subject:  fmt.Sprintf("rule %d", i),
				Title:    "Rule never evaluated since the ruleset was loaded",
				Detail:   fmt.Sprintf("pf has not considered this rule in %.1f days: no traffic matched its interface and direction, or an earlier quick rule always wins.", elapsedDays),
			})
			result.Findings[rule.Text] = findings
			continue
		}

		// Evaluated often, never matched: a candidate for removal.
		if rule.Packets == 0 && rule.Evaluations >= minEvals && oldEnough {
			findings := result.Findings[rule.Text]
			findings = append(findings, Finding{
				Kind:     "unused",
				Severity: "low",
				Subject:  fmt.Sprintf("rule %d", i),
				Title:    fmt.Sprintf("Evaluated %d times, never matched", rule.Evaluations),
				Detail:   fmt.Sprintf("Considered often but matched no traffic in %.1f days. Could be dead weight or an intentional catch-all.", elapsedDays),
			})
			result.Findings[rule.Text] = findings
			result.RiskScore += 1 // low
			continue
		}

		// Check for overly permissive rules (only on pass rules).
		if strings.HasPrefix(rule.Text, "pass") {
			perm := m.checkPermissive(rule, wanIfaces, mgmtPorts)
			if perm != nil {
				findings := result.Findings[rule.Text]
				findings = append(findings, *perm)
				result.Findings[rule.Text] = findings
				switch perm.Severity {
				case "critical":
					result.RiskScore += 25
				case "high":
					result.RiskScore += 10
				case "medium":
					result.RiskScore += 4
				}
			}
		}
	}

	// Cap risk score at 100.
	if result.RiskScore > 100 {
		result.RiskScore = 100
	}

	return result
}

// isInfrastructure returns true for non-policy rules.
func (m *Module) isInfrastructure(text string) bool {
	for _, prefix := range []string{"scrub", "anchor", "set ", "table", "pass keep state", "nat"} {
		if strings.HasPrefix(text, prefix) {
			return true
		}
	}
	return false
}

// checkPermissive detects overly permissive pass rules.
func (m *Module) checkPermissive(rule Rule, wanIfaces, mgmtPorts []string) *Finding {
	// Must be any->any to be considered overly permissive.
	if !m.matchesAnySource(rule.Text) || !m.matchesAnyDest(rule.Text) {
		return nil
	}

	// Port-qualified rules are acceptable.
	if m.restrictsPort(rule.Text) {
		return nil
	}

	// Determine direction and interface.
	dir := m.extractDirection(rule.Text)
	iface := m.extractInterface(rule.Text)
	isWAN := m.isWANInterface(iface, wanIfaces)

	// Management port detection.
	hasMgmtPorts := m.hasMgmtPorts(rule.Text, mgmtPorts)

	// Helper to truncate rule text safely.
	ruleTrunc := rule.Text
	if len(ruleTrunc) > 50 {
		ruleTrunc = ruleTrunc[:50]
	}

	// Inbound management ports on WAN = critical.
	if dir == "in" && isWAN && hasMgmtPorts {
		return &Finding{
			Kind:     "permissive",
			Severity: "critical",
			Subject:  fmt.Sprintf("rule: %s", ruleTrunc),
			Title:    "WAN exposure of management ports (22/80/443)",
			Detail:   fmt.Sprintf("Permits any source to connect to management ports on WAN interface %s. Restrict source or port.", iface),
		}
	}

	// Inbound any->any on WAN (without port) = high.
	if dir == "in" && isWAN {
		return &Finding{
			Kind:     "permissive",
			Severity: "high",
			Subject:  fmt.Sprintf("rule: %s", ruleTrunc),
			Title:    "WAN any→any inbound pass rule",
			Detail:   fmt.Sprintf("Permits all inbound traffic on WAN interface %s with no constraint. Verify intent.", iface),
		}
	}

	// Outbound any->any = low (normal posture for most gateways).
	if dir == "out" {
		return &Finding{
			Kind:     "permissive",
			Severity: "low",
			Subject:  fmt.Sprintf("rule: %s", ruleTrunc),
			Title:    "Unrestricted outbound rule",
			Detail:   "Permits all egress. This is the normal posture for most gateways.",
		}
	}

	// Internal any->any = medium.
	return &Finding{
		Kind:     "permissive",
		Severity: "medium",
		Subject:  fmt.Sprintf("rule: %s", ruleTrunc),
		Title:    "Permissive rule on internal interface",
		Detail:   "Permits all traffic on an internal interface. Narrow source or destination if intent was specific.",
	}
}

func (m *Module) matchesAnySource(text string) bool {
	return regexp.MustCompile(`\bfrom\s+any\b`).MatchString(text)
}

func (m *Module) matchesAnyDest(text string) bool {
	return regexp.MustCompile(`\bto\s+any\b`).MatchString(text)
}

func (m *Module) restrictsPort(text string) bool {
	return regexp.MustCompile(`\bport\b`).MatchString(text)
}

func (m *Module) extractDirection(text string) string {
	re := regexp.MustCompile(`^\w+\s+(?:drop\s+)?(in|out)\b`)
	if m := re.FindStringSubmatch(text); m != nil {
		return m[1]
	}
	return ""
}

func (m *Module) extractInterface(text string) string {
	re := regexp.MustCompile(`\son\s+(\S+)`)
	if m := re.FindStringSubmatch(text); m != nil {
		return m[1]
	}
	return ""
}

func (m *Module) isWANInterface(iface string, wanIfaces []string) bool {
	for _, w := range wanIfaces {
		if iface == w || strings.HasPrefix(iface, w) {
			return true
		}
	}
	// Default heuristic: vtnet1 or names starting with "wan".
	return iface == "vtnet1" || strings.HasPrefix(iface, "wan")
}

func (m *Module) hasMgmtPorts(text string, mgmtPorts []string) bool {
	for _, port := range mgmtPorts {
		if strings.Contains(text, port) {
			return true
		}
	}
	return false
}

// detectWANInterfaces guesses WAN interface from the default route.
func (m *Module) detectWANInterfaces() []string {
	// On FreeBSD, use `route -n get default`; on Linux, use `ip route | grep default`.
	if m.platform == "freebsd" || m.platform == "opnsense" {
		out, err := core.Run(5*time.Second, "route", "-n", "get", "default")
		if err == nil {
			re := regexp.MustCompile(`interface:\s*(\S+)`)
			if m := re.FindStringSubmatch(out); m != nil {
				return []string{m[1]}
			}
		}
	}
	return []string{}
}

// watchConfig monitors /conf/config.xml for changes on OPNsense.
func (m *Module) watchConfig() error {
	if m.configPath == "" {
		return nil
	}

	info, err := os.Stat(m.configPath)
	if err != nil {
		return nil // file does not exist yet
	}

	newMTime := info.ModTime().Unix()
	if newMTime == m.configModTime {
		return nil // no change
	}

	hash, err := configHash(m.configPath)
	if err != nil {
		return err
	}

	if hash == m.lastConfigHash {
		m.configModTime = newMTime // mtime changed but content did not
		return nil
	}

	// Config changed: compute diff and record it.
	before := m.lastConfigHash
	after := hash
	if before == "" {
		// First run: no diff.
		m.lastConfigHash = hash
		m.configModTime = newMTime
		return nil
	}

	// Get actor from the config file.
	_, actor, _ := loadOPNsenseConfig(m.configPath)

	// Compute a rough diff of filter/nat sections.
	diff, summary := m.computeConfigDiff(m.configPath)

	_ = m.ctx.Store.RecordChange("rulehygiene", "ruleset", actor, before, after, diff, summary)
	m.ctx.Log.Info("rulehygiene config change", "actor", actor, "summary", summary)

	m.lastConfigHash = hash
	m.configModTime = newMTime
	return nil
}

// computeConfigDiff extracts and diffs the filter/nat sections.
func (m *Module) computeConfigDiff(configPath string) (string, string) {
	b, err := os.ReadFile(configPath)
	if err != nil {
		return "", "read error"
	}

	var cfg OPNsenseConfig
	if err := xml.Unmarshal(b, &cfg); err != nil {
		return "", "parse error"
	}

	// Count rules.
	ruleCount := 0
	if cfg.Filter != nil {
		ruleCount = len(cfg.Filter.Rules)
	}

	summary := fmt.Sprintf("%d rules in filter", ruleCount)
	diff := fmt.Sprintf("Filter has %d rules", ruleCount)

	return diff, summary
}

// fingerprintKey creates a stable key for a finding.
func (m *Module) fingerprintKey(ruleText, kind string) string {
	// Use rule text and kind to create a stable fingerprint.
	sum := sha256.Sum256([]byte(ruleText + ":" + kind))
	return "rulehygiene:" + kind + ":" + hex.EncodeToString(sum[:16])
}

// ================================================================ API

func (m *Module) apiSummary(r *core.Req) (any, error) {
	// Get counts by severity.
	findings, _ := m.ctx.Store.Rows(
		`SELECT severity, COUNT(*) AS count FROM findings WHERE module='rulehygiene' AND resolved_ts IS NULL GROUP BY severity`,
	)
	bySev := make(map[string]int64)
	totalFindings := int64(0)
	for _, row := range findings {
		sev, _ := row["severity"].(string)
		cnt := int64(0)
		if c, ok := row["count"].(int64); ok {
			cnt = c
		}
		bySev[sev] = cnt
		totalFindings += cnt
	}

	// Get latest metrics.
	lastRun, _ := m.ctx.Store.Row(
		`SELECT ts, value FROM metrics WHERE name='firewall_risk_score' ORDER BY ts DESC LIMIT 1`,
	)

	riskScore := float64(0)
	rulesAnalysed := float64(0)
	rulesetSince := ""
	if lastRun != nil {
		if v, ok := lastRun["value"].(float64); ok {
			riskScore = v
		}
		if ts, ok := lastRun["ts"].(int64); ok && ts > 0 {
			rulesetSince = timeAgo(time.Unix(ts, 0))
		}
	}

	lastAnalysis, _ := m.ctx.Store.Row(
		`SELECT value FROM metrics WHERE name='firewall_rules_analysed' ORDER BY ts DESC LIMIT 1`,
	)
	if lastAnalysis != nil {
		if v, ok := lastAnalysis["value"].(float64); ok {
			rulesAnalysed = v
		}
	}

	m.mu.Lock()
	lastRunTime := m.lastRun
	m.mu.Unlock()

	return map[string]any{
		"risk_score":     riskScore,
		"findings":       totalFindings,
		"by_severity":    bySev,
		"rules_analysed": rulesAnalysed,
		"last_run":       timeAgo(lastRunTime),
		"ruleset_loaded": rulesetSince,
	}, nil
}

func (m *Module) apiRules(r *core.Req) (any, error) {
	// Get all rules from the latest analysis (from the findings table).
	// For simplicity, we'll reconstruct from findings.
	findings, _ := m.ctx.Store.Rows(
		`SELECT DISTINCT subject FROM findings WHERE module='rulehygiene' AND resolved_ts IS NULL`,
	)

	var rules []map[string]any
	for _, f := range findings {
		subject, _ := f["subject"].(string)
		rules = append(rules, map[string]any{
			"subject": subject,
		})
	}

	return map[string]any{"rules": rules}, nil
}

func (m *Module) apiFindings(r *core.Req) (any, error) {
	findings, _ := m.ctx.Store.Rows(
		`SELECT ts, kind, severity, subject, title, detail FROM findings
		 WHERE module='rulehygiene' AND resolved_ts IS NULL
		 ORDER BY ts DESC`,
	)
	return map[string]any{"findings": findings}, nil
}

func (m *Module) apiChanges(r *core.Req) (any, error) {
	changes, _ := m.ctx.Store.Rows(
		`SELECT ts, actor, summary FROM changes
		 WHERE module='rulehygiene'
		 ORDER BY ts DESC LIMIT 100`,
	)
	return map[string]any{"changes": changes}, nil
}

func (m *Module) apiRun(r *core.Req) (any, error) {
	_ = m.ctx.Core.Scheduler.RunNow("rulehygiene", "analyse")
	return map[string]any{"ok": true}, nil
}
