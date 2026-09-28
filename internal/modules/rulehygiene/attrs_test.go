package rulehygiene

import (
	"strings"
	"testing"
)

// A rule finding names the rule by its description and says what the
// counters were.
func TestRuleAttrsNameTheRuleAndItsCounters(t *testing.T) {
	a := ruleAttrs(Rule{Label: "abc", Description: "Allow LAN to any", Evaluations: 4231, Packets: 0, States: 0},
		"pass in quick on vtnet0 inet from 192.168.1.0/24 to any", 1790000000)
	if a["what"].(map[string]any)["kind"] != "Allow LAN to any" {
		t.Fatalf("what: %v", a["what"])
	}
	facts := a["why"].(map[string]any)["facts"].([]string)
	if len(facts) != 3 || !strings.HasPrefix(facts[0], "pass in quick") || !strings.Contains(facts[1], "evaluated 4231 times") {
		t.Fatalf("facts: %v", facts)
	}
	if b := ruleAttrs(Rule{Label: "8b59cf89"}, strings.Repeat("a", 300), 0); b["what"].(map[string]any)["kind"] != nil ||
		len([]rune(b["why"].(map[string]any)["facts"].([]string)[0])) != 161 {
		t.Fatalf("no hash for a name, and truncation: %v", b)
	}
}
