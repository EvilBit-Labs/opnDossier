package opnsense_test

import (
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shadowSummaries returns the part of each shadow finding's description that
// names the two rules.
func shadowSummaries(device *common.CommonDevice) []string {
	var got []string

	for _, finding := range analysis.DetectShadowedRules(device) {
		text, _, _ := strings.Cut(finding.Description, ";")
		got = append(got, text)
	}

	return got
}

// TestConverter_FilterRules_ShadowAnalysisFollowsListOrder drives configs through
// parse, convert and the shadow analysis. The rule list is in the order the
// firewall evaluates it, so the analysis must keep that order rather than move
// floating rules first: the os-firewall plugin ran the filter model's rules ahead
// of every legacy rule, floating or not (GOTCHAS 3.8).
func TestConverter_FilterRules_ShadowAnalysisFollowsListOrder(t *testing.T) {
	t.Parallel()

	const (
		onLAN         = `<interface>lan</interface>`
		toNet         = `<destination_net>10.0.0.0/8</destination_net>`
		legacyAny     = `<source><any>1</any></source><destination><any>1</any></destination>`
		legacyToNet   = `<source><any>1</any></source><destination><address>10.0.0.0/8</address></destination>`
		quickFloating = `<floating>yes</floating><quick>1</quick><direction>in</direction>`
	)

	var (
		modelLANPass  = modelRuleXML("model lan pass", "1", "u1", `<action>pass</action>`+onLAN)
		modelLANBlock = modelRuleXML("model lan block", "1", "u1", `<action>block</action>`+onLAN)
		// A rule of the model on no interface, which the plugin ranked with the
		// rules on one interface, by sequence.
		modelAnyBlock = modelRuleXML("model block on no interface", "2", "u2", `<action>block</action>`+toNet)

		legacyBlock = `<rule><type>block</type>` + onLAN + `<descr>legacy floating block</descr>` +
			quickFloating + legacyToNet + `</rule>`
		legacyPass = `<rule><type>pass</type>` + onLAN + `<descr>legacy floating pass</descr>` +
			quickFloating + legacyAny + `</rule>`
		legacyAnyBlock = `<rule><type>block</type><interface></interface><descr>floating block on every interface</descr>` +
			quickFloating + legacyToNet + `</rule>`
		legacyAnyPass = `<rule><type>pass</type><interface></interface><descr>floating pass on every interface</descr>` +
			quickFloating + legacyAny + `</rule>`
	)

	tests := []struct {
		name    string
		version string
		legacy  string
		model   string
		order   []string
		want    []string
	}{
		{
			name:    "plugin: model rule on an interface runs before a legacy floating rule",
			version: "1.0.2",
			legacy:  legacyBlock,
			model:   modelLANPass,
			order:   []string{"model lan pass", "legacy floating block"},
			want:    []string{"Rule 2 (block) on interface lan (in) is fully shadowed by rule 1 (pass)"},
		},
		{
			name:    "plugin: the same with the actions swapped",
			version: "1.0.0",
			legacy:  legacyPass,
			model:   modelLANBlock,
			order:   []string{"model lan block", "legacy floating pass"},
			want:    []string{"Rule 2 (pass) on interface lan (in) is fully shadowed by rule 1 (block)"},
		},
		{
			name:    "plugin: a rule on no interface keeps its sequence",
			version: "1.0.1",
			model:   modelLANPass + modelAnyBlock,
			order:   []string{"model lan pass", "model block on no interface"},
			want:    []string{"Rule 2 (block) on interface lan (in) is fully shadowed by rule 1 (pass)"},
		},
		{
			name:    "core: the legacy floating rule runs first",
			version: "1.0.4",
			legacy:  legacyBlock,
			model:   modelLANPass,
			order:   []string{"legacy floating block", "model lan pass"},
		},
		{
			name:   "floating block on an interface above a floating pass on every interface wins",
			legacy: legacyBlock + legacyAnyPass,
			order:  []string{"legacy floating block", "floating pass on every interface"},
		},
		{
			name:   "floating pass on an interface above a floating block on every interface wins",
			legacy: legacyPass + legacyAnyBlock,
			order:  []string{"legacy floating pass", "floating block on every interface"},
			want:   []string{"Rule 2 (block) on interface lan (in) is fully shadowed by rule 1 (pass)"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, _ := parseFilterRulesAt(t, tt.version, tt.legacy, tt.model)
			assert.Equal(t, tt.order, descriptions(device.FirewallRules))
			assert.Equal(t, tt.want, shadowSummaries(device))
		})
	}
}

// TestConverter_FilterRules_ShadowAnalysisSkipsDisabledWinner drives disabled
// rules from both stores through the shadow analysis. OPNsense compiles one to a
// comment, so it can neither take traffic from a live rule nor end a group. It
// can still be reported as shadowed: it would be if it were enabled.
func TestConverter_FilterRules_ShadowAnalysisSkipsDisabledWinner(t *testing.T) {
	t.Parallel()

	const (
		onLAN   = `<interface>lan</interface>`
		off     = `<disabled>1</disabled>`
		toNet8  = `<source><any>1</any></source><destination><address>10.0.0.0/8</address></destination>`
		toNet16 = `<source><any>1</any></source><destination><address>10.1.0.0/16</address></destination>`
		anyAny  = `<source><any>1</any></source><destination><any>1</any></destination>`
		toHTTPS = `<protocol>tcp</protocol><source><any>1</any></source>` +
			`<destination><any>1</any><port>443</port></destination>`

		pass          = `<rule><type>pass</type>` + onLAN + toNet8 + `</rule>`
		disabledPass  = `<rule><type>pass</type>` + onLAN + off + toNet8 + `</rule>`
		block         = `<rule><type>block</type>` + onLAN + toNet16 + `</rule>`
		disabledBlock = `<rule><type>block</type>` + onLAN + off + toNet16 + `</rule>`
		defaultDeny   = `<rule><type>block</type>` + onLAN + anyAny + `</rule>`
		passHTTPS     = `<rule><type>pass</type>` + onLAN + toHTTPS + `</rule>`
		offHTTPS      = `<rule><type>pass</type>` + onLAN + off + toHTTPS + `</rule>`
		liveBlock     = `<rule><type>block</type>` + onLAN + `<disabled/>` + toNet16 + `</rule>`
		liveHTTPS     = `<rule><type>pass</type>` + onLAN + `<disabled/>` + toHTTPS + `</rule>`

		shadowedByAllow = "Rule 2 (block) on interface lan (in) is fully shadowed by rule 1 (pass)"
	)

	modelPassOff := modelRuleXML("model pass off", "1", "u1",
		`<enabled>0</enabled><action>pass</action>`+onLAN+`<destination_net>10.0.0.0/8</destination_net>`)

	tests := []struct {
		name   string
		legacy string
		model  string
		want   []string
	}{
		{name: "disabled legacy pass above a block", legacy: disabledPass + block},
		{name: "disabled model pass above a legacy block", legacy: block, model: modelPassOff},
		{
			name:   "disabled pass below the default deny",
			legacy: passHTTPS + defaultDeny + offHTTPS,
			want: []string{
				"Rule 3 (pass) on interface lan (in) is fully shadowed by rule 1 (pass)",
				"Rule 3 (pass) on interface lan (in) is fully shadowed by rule 2 (block)",
			},
		},
		{name: "live pass above a disabled block", legacy: pass + disabledBlock, want: []string{shadowedByAllow}},
		{name: "live pass above a live block", legacy: pass + block, want: []string{shadowedByAllow}},
		{
			name:   "empty disabled element on a block is a live block",
			legacy: liveBlock + pass,
			want:   []string{"Rule 2 (pass) on interface lan (in) is partially shadowed by rule 1 (block)"},
		},
		{
			name:   "empty disabled element below the default deny is the last rule",
			legacy: passHTTPS + defaultDeny + liveHTTPS,
			want: []string{
				"Rule 2 (block) on interface lan (in) is partially shadowed by rule 1 (pass)",
				"Rule 3 (pass) on interface lan (in) is fully shadowed by rule 1 (pass)",
				"Rule 3 (pass) on interface lan (in) is fully shadowed by rule 2 (block)",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, _ := parseFilterRulesAt(t, "1.0.4", tt.legacy, tt.model)
			assert.Equal(t, tt.want, shadowSummaries(device))
		})
	}
}

// TestConverter_FilterRules_LegacyDisabledElement pins how OPNsense reads
// <disabled> on a legacy rule. It comments the rule out on !empty() (Rule.php
// parseIsComment), so an empty element and a 0 leave the rule live, where a
// presence test would drop it from the analysis and lose a real finding, and any
// other text disables it. The rule under test is the second, with a neighbor
// that reads the other way, so that it cannot borrow the result.
func TestConverter_FilterRules_LegacyDisabledElement(t *testing.T) {
	t.Parallel()

	const (
		onLAN   = `<interface>lan</interface>`
		toNet8  = `<source><any>1</any></source><destination><address>10.0.0.0/8</address></destination>`
		toNet16 = `<source><any>1</any></source><destination><address>10.1.0.0/16</address></destination>`
		block   = `<rule><type>block</type>` + onLAN + toNet16 + `</rule>`

		shadowedByAllow = "Rule 3 (block) on interface lan (in) is fully shadowed by rule 2 (pass)"
	)

	tests := []struct {
		name         string
		element      string
		wantDisabled bool
	}{
		{name: "absent element"},
		{name: "self-closing element", element: `<disabled/>`},
		{name: "empty element", element: `<disabled></disabled>`},
		{name: "element holding 0", element: `<disabled>0</disabled>`},
		{name: "element holding 1", element: `<disabled>1</disabled>`, wantDisabled: true},
		{name: "element holding no", element: `<disabled>no</disabled>`, wantDisabled: true},
		{name: "element holding false", element: `<disabled>false</disabled>`, wantDisabled: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			neighbor := `<disabled>1</disabled>`
			if tt.wantDisabled {
				neighbor = ""
			}

			device, _ := parseFilterRulesAt(t, "1.0.4",
				`<rule><type>pass</type><interface>wan</interface>`+neighbor+`</rule>`+
					`<rule><type>pass</type>`+onLAN+tt.element+toNet8+`</rule>`+block, "")

			require.Len(t, device.FirewallRules, 3)
			assert.Equal(t, !tt.wantDisabled, device.FirewallRules[0].Disabled, "neighbor")
			assert.Equal(t, tt.wantDisabled, device.FirewallRules[1].Disabled)
			assert.False(t, device.FirewallRules[2].Disabled)

			var want []string
			if !tt.wantDisabled {
				want = []string{shadowedByAllow}
			}

			assert.Equal(t, want, shadowSummaries(device))
		})
	}
}

// TestConverter_FilterRules_DeadRulesSeeDisabledReading pins what the reading of
// <disabled> does to DetectDeadRules. That function hands RulesEquivalent the
// converted rules, and it does not hold a disabled rule equal to a live one, so a
// spelling the firewall reads differently from BoolFlag changes what counts as a
// duplicate. The element OPNsense writes, <disabled>1</disabled>, reads as it did.
func TestConverter_FilterRules_DeadRulesSeeDisabledReading(t *testing.T) {
	t.Parallel()

	const match = `<interface>lan</interface><protocol>tcp</protocol><source><any>1</any></source>` +
		`<destination><any>1</any><port>443</port></destination>`

	rule := func(element string) string {
		return `<rule><type>pass</type>` + element + match + `</rule>`
	}

	duplicateOfFirst := []common.DeadRuleFinding{
		{Kind: common.DeadRuleKindDuplicate, RuleIndex: 1, Interface: "lan"},
	}

	tests := []struct {
		name   string
		legacy string
		want   []common.DeadRuleFinding
	}{
		{name: "empty element above a live rule", legacy: rule(`<disabled/>`) + rule(""), want: duplicateOfFirst},
		{name: "empty element above a disabled rule", legacy: rule(`<disabled/>`) + rule(`<disabled>1</disabled>`)},
		{name: "element holding no above a live rule", legacy: rule(`<disabled>no</disabled>`) + rule("")},
		{
			name:   "element holding no above a disabled rule",
			legacy: rule(`<disabled>no</disabled>`) + rule(`<disabled>1</disabled>`),
			want:   duplicateOfFirst,
		},
		{name: "element holding 1 above a live rule", legacy: rule(`<disabled>1</disabled>`) + rule("")},
		{
			name:   "element holding 1 above another",
			legacy: rule(`<disabled>1</disabled>`) + rule(`<disabled>1</disabled>`),
			want:   duplicateOfFirst,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, _ := parseFilterRulesAt(t, "1.0.4", tt.legacy, "")

			var got []common.DeadRuleFinding

			for _, finding := range analysis.DetectDeadRules(device) {
				got = append(got, common.DeadRuleFinding{
					Kind:      finding.Kind,
					RuleIndex: finding.RuleIndex,
					Interface: finding.Interface,
				})
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

// TestConverter_FilterRules_ShadowClassOfRuleWithNoType drives a legacy rule with
// no <type> through parse, convert and the shadow analysis. OPNsense compiles it
// as pass (FilterRule.php parseType), so it is redundant below a pass rule and
// bypasses a block below it.
func TestConverter_FilterRules_ShadowClassOfRuleWithNoType(t *testing.T) {
	t.Parallel()

	const (
		match = `<interface>lan</interface><protocol>tcp</protocol><source><any>1</any></source>` +
			`<destination><address>10.0.2.2</address><port>443</port></destination>`

		typeless = `<rule>` + match + `</rule>`
		pass     = `<rule><type>pass</type>` + match + `</rule>`
		block    = `<rule><type>block</type>` + match + `</rule>`
	)

	tests := []struct {
		name      string
		legacy    string
		wantClass common.ImpactClass
		want      string
	}{
		{
			name:      "pass above the rule is redundant",
			legacy:    pass + typeless,
			wantClass: common.ImpactClassHygiene,
			want:      "Rule 2 (pass) on interface lan (in) is fully shadowed by rule 1 (pass)",
		},
		{
			name:      "the rule above a block bypasses the deny",
			legacy:    typeless + block,
			wantClass: common.ImpactClassSecurity,
			want:      "Rule 2 (block) on interface lan (in) is fully shadowed by rule 1 (pass)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, _ := parseFilterRulesAt(t, "1.0.4", tt.legacy, "")

			assert.Equal(t, []string{tt.want}, shadowSummaries(device))

			findings := analysis.DetectShadowedRules(device)
			require.Len(t, findings, 1)
			assert.Equal(t, tt.wantClass, findings[0].ImpactClass)
		})
	}
}
