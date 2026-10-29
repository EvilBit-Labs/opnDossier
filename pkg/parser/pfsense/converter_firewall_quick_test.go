package pfsense_test

import (
	"context"
	"os"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	"github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	pfsenseSchema "github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConverter_FirewallRules_QuickDefault pins pfSense's quick rule: a rule
// that is not floating is always quick, and a floating rule is quick only when
// it carries <quick> (filter.inc: !isset($rule['floating']) || isset($rule['quick'])).
func TestConverter_FirewallRules_QuickDefault(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		floating string
		quick    opnsense.BoolFlag
		want     bool
	}{
		{name: "interface rule", want: true},
		{name: "interface rule with quick", quick: true, want: true},
		{name: "floating rule", floating: "yes", want: false},
		{name: "floating rule with quick", floating: "yes", quick: true, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := pfsenseSchema.NewDocument()
			doc.Filter.Rule = []pfsenseSchema.FilterRule{{
				Type:      "pass",
				Interface: opnsense.InterfaceList{"lan"},
				Floating:  tt.floating,
				Quick:     tt.quick,
			}}

			device, _, err := pfsense.ConvertDocument(doc)
			require.NoError(t, err)
			require.Len(t, device.FirewallRules, 1)
			assert.Equal(t, tt.want, device.FirewallRules[0].Quick)
		})
	}
}

// TestConverter_ConfigPfSense_InterfaceRulesShadowFirstMatch drives the shipped
// pfSense config through the shadow analysis. Read as non-quick, its interface
// rules were evaluated last-match-wins, and each rule that leads an interface
// was reported as shadowed by the rules below it.
func TestConverter_ConfigPfSense_InterfaceRulesShadowFirstMatch(t *testing.T) {
	t.Parallel()

	f, err := os.Open("../../../testdata/pfsense/config-pfSense.xml")
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	device, _, err := pfsense.NewParser(nil).Parse(context.Background(), f)
	require.NoError(t, err)

	for i, rule := range device.FirewallRules {
		assert.Equal(t, !rule.Floating, rule.Quick, "rule %d", i)
	}

	for _, finding := range analysis.DetectShadowedRules(device) {
		if device.FirewallRules[finding.RuleIndex].Floating {
			continue
		}
		assert.Less(t, finding.ShadowedByIndex, finding.RuleIndex, finding.Description)
	}
}
