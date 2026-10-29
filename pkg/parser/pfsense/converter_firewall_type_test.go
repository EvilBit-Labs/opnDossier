package pfsense_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	pfsenseSchema "github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParser_ConfigPfSense_TypelessRulesArePass pins pfSense's reading of a
// rule with no <type>: filter.inc compiles it as pass. The port forward page
// writes its companion rule without one, and in the shipped fixture those two
// rules are the only WAN pass rules, so both port forwards must read as
// WAN-reachable.
func TestParser_ConfigPfSense_TypelessRulesArePass(t *testing.T) {
	t.Parallel()

	device, warnings := parseConfigPfSenseFixture(t)

	for _, w := range warnings {
		assert.NotEqual(t, "firewall rule has empty type", w.Message, w.Field)
	}

	var companions []common.FirewallRule
	for _, rule := range device.FirewallRules {
		assert.True(t, rule.Type.IsValid(), "rule %q has type %q", rule.Description, rule.Type)
		if rule.AssociatedRuleID != "" {
			companions = append(companions, rule)
		}
	}

	require.Len(t, companions, 2)
	for _, rule := range companions {
		assert.Equal(t, common.RuleTypePass, rule.Type, rule.Description)
	}

	require.Len(t, device.NAT.InboundRules, 2)
	for _, nat := range device.NAT.InboundRules {
		assert.Equal(t, analysis.WANReachable,
			analysis.InboundNATRuleReachability(nat, device.Interfaces, device.FirewallRules),
			nat.Description)
	}
}

// TestConverter_FirewallRules_TypelessRuleIsPass covers a rule with no <type>
// that no port forward created: filter.inc compiles it as pass all the same.
func TestConverter_FirewallRules_TypelessRuleIsPass(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.Filter.Rule = []pfsenseSchema.FilterRule{{
		Interface:   opnsense.InterfaceList{"wan"},
		Source:      opnsense.Source{Any: new(string)},
		Destination: opnsense.Destination{Any: new(string)},
	}}

	device, warnings, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Empty(t, nonGapWarnings(warnings))
	require.Len(t, device.FirewallRules, 1)
	assert.Equal(t, common.RuleTypePass, device.FirewallRules[0].Type)
}
