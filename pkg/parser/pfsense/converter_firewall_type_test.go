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

// TestConverter_FirewallRules_TypeReadsAsFilterIncCompilesIt follows the type
// test in filter_generate_user_rule: the comparison is exact, and any value that
// is not pass, block, reject or match compiles as pass, including one that names
// a different action in another case.
func TestConverter_FirewallRules_TypeReadsAsFilterIncCompilesIt(t *testing.T) {
	t.Parallel()

	const (
		keptAsStored = "unrecognized firewall rule type"
		readAsPass   = "unrecognized firewall rule type, which pfSense compiles as pass; it is reported as pass"
	)

	tests := []struct {
		stored       string
		want         common.FirewallRuleType
		wantSeverity common.Severity
		wantMessage  string
	}{
		{"pass", common.RuleTypePass, "", ""},
		{"block", common.RuleTypeBlock, "", ""},
		{"reject", common.RuleTypeReject, "", ""},
		{"", common.RuleTypePass, "", ""},
		{"match", "match", common.SeverityLow, keptAsStored},
		{"Pass", common.RuleTypePass, common.SeverityMedium, readAsPass},
		{"allow", common.RuleTypePass, common.SeverityMedium, readAsPass},
		{"Block", common.RuleTypePass, common.SeverityMedium, readAsPass},
		{"Match", common.RuleTypePass, common.SeverityMedium, readAsPass},
	}

	for _, tc := range tests {
		t.Run(tc.stored, func(t *testing.T) {
			t.Parallel()

			doc := pfsenseSchema.NewDocument()
			doc.Filter.Rule = []pfsenseSchema.FilterRule{{
				Type:        tc.stored,
				Interface:   opnsense.InterfaceList{"wan"},
				Source:      opnsense.Source{Any: new(string)},
				Destination: opnsense.Destination{Any: new(string)},
			}}

			device, warnings, err := pfsense.ConvertDocument(doc)
			require.NoError(t, err)
			require.Len(t, device.FirewallRules, 1)
			assert.Equal(t, tc.want, device.FirewallRules[0].Type)

			warnings = nonGapWarnings(warnings)
			if tc.wantSeverity == "" {
				assert.Empty(t, warnings)
				return
			}

			require.Len(t, warnings, 1)
			assert.Equal(t, "FirewallRules[0].Type", warnings[0].Field)
			assert.Equal(t, tc.stored, warnings[0].Value)
			assert.Equal(t, tc.wantSeverity, warnings[0].Severity)
			assert.Equal(t, tc.wantMessage, warnings[0].Message)
		})
	}
}
