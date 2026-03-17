package analysis_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
)

func TestRulesEquivalent(t *testing.T) {
	t.Parallel()

	baseRule := common.FirewallRule{
		Type:       "pass",
		IPProtocol: "inet",
		Interfaces: []string{"wan", "lan"},
		StateType:  "keep state",
		Direction:  "in",
		Protocol:   "tcp",
		Quick:      true,
		Source: common.RuleEndpoint{
			Address: "192.168.1.0/24",
			Port:    "443",
			Negated: false,
		},
		Destination: common.RuleEndpoint{
			Address: "10.0.0.0/8",
			Port:    "80",
			Negated: false,
		},
	}

	tests := []struct {
		name     string
		ruleA    common.FirewallRule
		ruleB    common.FirewallRule
		expected bool
	}{
		{
			name:     "identical rules",
			ruleA:    baseRule,
			ruleB:    baseRule,
			expected: true,
		},
		{
			name:  "same interfaces different order",
			ruleA: baseRule,
			ruleB: func() common.FirewallRule {
				r := baseRule
				r.Interfaces = []string{"lan", "wan"}
				return r
			}(),
			expected: true,
		},
		{
			name:  "different type",
			ruleA: baseRule,
			ruleB: func() common.FirewallRule {
				r := baseRule
				r.Type = "block"
				return r
			}(),
			expected: false,
		},
		{
			name:  "different IP protocol",
			ruleA: baseRule,
			ruleB: func() common.FirewallRule {
				r := baseRule
				r.IPProtocol = "inet6"
				return r
			}(),
			expected: false,
		},
		{
			name:  "different interfaces",
			ruleA: baseRule,
			ruleB: func() common.FirewallRule {
				r := baseRule
				r.Interfaces = []string{"wan", "opt1"}
				return r
			}(),
			expected: false,
		},
		{
			name:  "different state type",
			ruleA: baseRule,
			ruleB: func() common.FirewallRule {
				r := baseRule
				r.StateType = "synproxy state"
				return r
			}(),
			expected: false,
		},
		{
			name:  "different direction",
			ruleA: baseRule,
			ruleB: func() common.FirewallRule {
				r := baseRule
				r.Direction = "out"
				return r
			}(),
			expected: false,
		},
		{
			name:  "different protocol",
			ruleA: baseRule,
			ruleB: func() common.FirewallRule {
				r := baseRule
				r.Protocol = "udp"
				return r
			}(),
			expected: false,
		},
		{
			name:  "different quick",
			ruleA: baseRule,
			ruleB: func() common.FirewallRule {
				r := baseRule
				r.Quick = false
				return r
			}(),
			expected: false,
		},
		{
			name:  "different source address",
			ruleA: baseRule,
			ruleB: func() common.FirewallRule {
				r := baseRule
				r.Source.Address = "172.16.0.0/12"
				return r
			}(),
			expected: false,
		},
		{
			name:  "different source port",
			ruleA: baseRule,
			ruleB: func() common.FirewallRule {
				r := baseRule
				r.Source.Port = "8080"
				return r
			}(),
			expected: false,
		},
		{
			name:  "different source negated",
			ruleA: baseRule,
			ruleB: func() common.FirewallRule {
				r := baseRule
				r.Source.Negated = true
				return r
			}(),
			expected: false,
		},
		{
			name:  "different destination address",
			ruleA: baseRule,
			ruleB: func() common.FirewallRule {
				r := baseRule
				r.Destination.Address = "0.0.0.0/0"
				return r
			}(),
			expected: false,
		},
		{
			name:  "different destination port",
			ruleA: baseRule,
			ruleB: func() common.FirewallRule {
				r := baseRule
				r.Destination.Port = "8443"
				return r
			}(),
			expected: false,
		},
		{
			name:  "different destination negated",
			ruleA: baseRule,
			ruleB: func() common.FirewallRule {
				r := baseRule
				r.Destination.Negated = true
				return r
			}(),
			expected: false,
		},
		{
			name:     "both empty rules",
			ruleA:    common.FirewallRule{},
			ruleB:    common.FirewallRule{},
			expected: true,
		},
		{
			name:     "nil vs empty interface slices",
			ruleA:    common.FirewallRule{Interfaces: nil},
			ruleB:    common.FirewallRule{Interfaces: []string{}},
			expected: true,
		},
		{
			name:  "different description does not affect equivalence",
			ruleA: baseRule,
			ruleB: func() common.FirewallRule {
				r := baseRule
				r.Description = "different description"
				return r
			}(),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, analysis.RulesEquivalent(tt.ruleA, tt.ruleB))
		})
	}
}

func TestRulesEquivalent_DoesNotMutateInputs(t *testing.T) {
	t.Parallel()

	a := common.FirewallRule{Interfaces: []string{"wan", "lan"}}
	b := common.FirewallRule{Interfaces: []string{"lan", "wan"}}

	analysis.RulesEquivalent(a, b)

	// Verify original slices were not sorted in place
	assert.Equal(t, []string{"wan", "lan"}, a.Interfaces)
	assert.Equal(t, []string{"lan", "wan"}, b.Interfaces)
}
