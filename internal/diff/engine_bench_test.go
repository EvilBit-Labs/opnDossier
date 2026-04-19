package diff

import (
	"context"
	"fmt"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// buildFirewallRuleFixture builds n firewall rules with stable UUIDs and
// predictable descriptions. It is used by BenchmarkCompareDiff_10k to
// exercise the per-change scoring + aggregate risk-summary path.
func buildFirewallRuleFixture(n int) []common.FirewallRule {
	rules := make([]common.FirewallRule, n)
	for i := range rules {
		rules[i] = common.FirewallRule{
			UUID:        fmt.Sprintf("uuid-%06d", i),
			Type:        common.RuleTypePass,
			Description: fmt.Sprintf("rule %d", i),
			Protocol:    "tcp",
			Interfaces:  []string{"wan"},
		}
	}
	return rules
}

// BenchmarkCompareDiff_10k measures the cost of diffing two configurations
// whose filter rules differ in every entry. The resulting diff surfaces ~10k
// modified changes, which is the pathological case for the per-change
// ChangeInput allocation paid by both Scorer.Score and the aggregate summary
// pass. It is the direct regression benchmark for PERF-M6.
func BenchmarkCompareDiff_10k(b *testing.B) {
	const ruleCount = 10_000

	oldRules := buildFirewallRuleFixture(ruleCount)
	newRules := buildFirewallRuleFixture(ruleCount)
	// Mutate each rule's protocol so CompareFirewallRules reports a ChangeModified.
	for i := range newRules {
		newRules[i].Protocol = "udp"
	}

	old := &common.CommonDevice{FirewallRules: oldRules}
	newCfg := &common.CommonDevice{FirewallRules: newRules}
	opts := Options{Sections: []string{"firewall"}}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		engine := NewEngine(old, newCfg, opts, nil)
		if _, err := engine.Compare(ctx); err != nil {
			b.Fatalf("Compare: %v", err)
		}
	}
}
