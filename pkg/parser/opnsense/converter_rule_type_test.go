package opnsense_test

import (
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConverter_FilterRules_LegacyTypeReadsAsParseTypeCompilesIt follows parseType
// in FilterRule.php through the full parser. It tests the value with empty(), so
// an absent element, an empty one and 0 all compile as pass, and any other value
// goes to pf as written. The block rule first in each config shows the type under
// test is read from its own rule.
func TestConverter_FilterRules_LegacyTypeReadsAsParseTypeCompilesIt(t *testing.T) {
	t.Parallel()

	const endpoints = `<interface>lan</interface><source><any>1</any></source><destination><any>1</any></destination>`

	tests := []struct {
		name         string
		element      string
		want         common.FirewallRuleType
		wantWarnings int
	}{
		{"no element", ``, common.RuleTypePass, 0},
		{"an empty element", `<type></type>`, common.RuleTypePass, 0},
		{"a self-closing element", `<type/>`, common.RuleTypePass, 0},
		{"zero", `<type>0</type>`, common.RuleTypePass, 0},
		{"pass", `<type>pass</type>`, common.RuleTypePass, 0},
		{"reject", `<type>reject</type>`, common.RuleTypeReject, 0},
		{"two zeros, which empty() does not take", `<type>00</type>`, "00", 1},
		{"a value pf does not know", `<type>allow</type>`, "allow", 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device, warnings := parseFilterRules(t,
				`<rule><type>block</type>`+endpoints+`</rule><rule>`+tc.element+endpoints+`</rule>`, "")

			require.Len(t, device.FirewallRules, 2)
			assert.Equal(t, common.RuleTypeBlock, device.FirewallRules[0].Type)
			assert.Equal(t, tc.want, device.FirewallRules[1].Type)
			assert.Len(t, warnings, tc.wantWarnings)
		})
	}
}
