// Benchmarks for the firewall-rules markdown table builder.
//
// BenchmarkFirewallRulesTable is the merge gate for NATS-38: it locks in the
// allocs/op baseline before the per-row formatter optimisations land and is
// re-run afterwards to validate the ≥30% allocs/op reduction target on the
// 500-row sub-bench.
package builder

import (
	"fmt"
	"strconv"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// generateFirewallRules returns n synthetic firewall rules with field shapes
// that exercise every formatter the per-row hot loop calls — multi-interface
// lists for FormatInterfacesAsLinks, descriptions with markdown-special
// characters for EscapeTableContent, mixed Disabled flags for
// FormatBoolInverted, and non-empty source/destination ports for the two
// EscapeTableContent calls on port fields.
//
// The fixture is deterministic so benchmark runs are comparable.
func generateFirewallRules(n int) []common.FirewallRule {
	rules := make([]common.FirewallRule, 0, n)
	for i := range n {
		rules = append(rules, common.FirewallRule{
			UUID:        fmt.Sprintf("rule-%d", i),
			Type:        common.RuleTypePass,
			IPProtocol:  common.IPProtocolInet,
			Protocol:    "tcp",
			Interfaces:  []string{"wan", fmt.Sprintf("opt%d", i%4)},
			Source:      common.RuleEndpoint{Address: fmt.Sprintf("10.0.%d.0/24", i%256), Port: "any"},
			Destination: common.RuleEndpoint{Address: "192.168.1.10", Port: strconv.Itoa(1024 + (i % 64512))},
			Target:      "",
			// Description includes markdown specials (pipe, asterisk, brackets,
			// backtick, underscore) so EscapeTableContent does real work.
			Description: fmt.Sprintf(
				"rule %d | allow *web* [_HTTPS_] `https://10.0.%d.0/24` -> 192.168.1.10:443",
				i,
				i%256,
			),
			Disabled: i%5 == 0,
		})
	}
	return rules
}

// BenchmarkFirewallRulesTable measures the allocs/op and ns/op cost of
// BuildFirewallRulesTableSet for representative table sizes. The 500-row
// sub-bench is the merge gate for the firewall-rule allocation work
// (>=30% allocs/op reduction target).
func BenchmarkFirewallRulesTable(b *testing.B) {
	for _, size := range []int{100, 500} {
		rules := generateFirewallRules(size)
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = BuildFirewallRulesTableSet(rules)
			}
		})
	}
}

// generateFirewallRulesWithInterfaceCount returns n rules whose Interfaces
// slices have the requested length, exercising the FormatInterfacesAsLinks
// branches for the empty-slice early return (count=0), single-link path
// (count=1), and multi-link separator path (count>=2).
func generateFirewallRulesWithInterfaceCount(n, ifaceCount int) []common.FirewallRule {
	rules := make([]common.FirewallRule, 0, n)
	for i := range n {
		ifaces := make([]string, 0, ifaceCount)
		for j := range ifaceCount {
			if j == 0 {
				ifaces = append(ifaces, "wan")
			} else {
				ifaces = append(ifaces, fmt.Sprintf("opt%d", j-1))
			}
		}
		rules = append(rules, common.FirewallRule{
			UUID:        fmt.Sprintf("rule-%d", i),
			Type:        common.RuleTypePass,
			Protocol:    "tcp",
			Interfaces:  ifaces,
			Source:      common.RuleEndpoint{Address: "10.0.0.0/24", Port: "any"},
			Destination: common.RuleEndpoint{Address: "192.168.1.10", Port: "443"},
			Description: fmt.Sprintf("rule %d", i),
		})
	}
	return rules
}

// BenchmarkFirewallRulesTable_InterfaceCount exercises the
// FormatInterfacesAsLinks paths the main bench under-covers — empty
// slice, single-element, and multi-element — at a fixed row count.
func BenchmarkFirewallRulesTable_InterfaceCount(b *testing.B) {
	const rowCount = 100
	for _, ifaceCount := range []int{0, 1, 4} {
		rules := generateFirewallRulesWithInterfaceCount(rowCount, ifaceCount)
		b.Run("ifaces="+strconv.Itoa(ifaceCount), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = BuildFirewallRulesTableSet(rules)
			}
		})
	}
}
