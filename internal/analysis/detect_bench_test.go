package analysis_test

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// buildRuleSet produces n distinct firewall rules on a single interface to
// exercise the duplicate-detection hot path in DetectDeadRules. Rules are
// intentionally unique so every rule hits a fresh hash bucket — this is the
// common-case workload the hash-based algorithm optimizes for.
func buildRuleSet(n int) *common.CommonDevice {
	rules := make([]common.FirewallRule, n)
	for i := range n {
		rules[i] = common.FirewallRule{
			Type:        common.RuleTypePass,
			IPProtocol:  common.IPProtocolInet,
			Interfaces:  []string{"lan"},
			StateType:   "keep state",
			Direction:   common.DirectionIn,
			Protocol:    "tcp",
			Quick:       true,
			Source:      common.RuleEndpoint{Address: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)},
			Destination: common.RuleEndpoint{Address: "any", Port: strconv.Itoa(1024 + i)},
		}
	}
	return &common.CommonDevice{FirewallRules: rules}
}

func BenchmarkDetectDeadRules_100Rules(b *testing.B) {
	cfg := buildRuleSet(100)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = analysis.DetectDeadRules(cfg)
	}
}

func BenchmarkDetectDeadRules_500Rules(b *testing.B) {
	cfg := buildRuleSet(500)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = analysis.DetectDeadRules(cfg)
	}
}

func BenchmarkDetectDeadRules_1000Rules(b *testing.B) {
	cfg := buildRuleSet(1000)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = analysis.DetectDeadRules(cfg)
	}
}
