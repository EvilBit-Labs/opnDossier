package pfsense_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parsePfSenseFilter runs the content of <filter> through the pfSense parser.
func parsePfSenseFilter(t *testing.T, filter string) *common.CommonDevice {
	t.Helper()

	config := `<?xml version="1.0"?><pfsense><interfaces><lan><if>em1</if></lan></interfaces>` +
		`<filter>` + filter + `</filter></pfsense>`

	device, _, err := pfsense.NewParser(nil).Parse(context.Background(), strings.NewReader(config))
	require.NoError(t, err)

	return device
}

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

// TestConverter_FirewallRules_QuickDefault pins how pfSense reads <floating> and
// <quick>. It decides whether a rule is floating, and whether it is quick, with
// isset(), so for those the element counts whatever it holds. A rule without it
// is always quick, and a floating rule is quick only when it carries <quick>
// (filter.inc L3387, L4295).
func TestConverter_FirewallRules_QuickDefault(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		elements     string
		wantFloating bool
		wantQuick    bool
	}{
		{name: "interface rule", wantQuick: true},
		{name: "interface rule with quick", elements: `<quick>yes</quick>`, wantQuick: true},
		{name: "floating rule", elements: `<floating>yes</floating>`, wantFloating: true},
		{
			name:         "floating rule with quick",
			elements:     `<floating>yes</floating><quick>yes</quick>`,
			wantFloating: true,
			wantQuick:    true,
		},
		{name: "empty floating element", elements: `<floating/>`, wantFloating: true},
		{
			name:         "empty floating element with quick",
			elements:     `<floating></floating><quick>yes</quick>`,
			wantFloating: true,
			wantQuick:    true,
		},
		{name: "floating element with another value", elements: `<floating>1</floating>`, wantFloating: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := parsePfSenseFilter(t,
				`<rule><type>pass</type><interface>lan</interface>`+tt.elements+`</rule>`)

			require.Len(t, device.FirewallRules, 1)
			assert.Equal(t, tt.wantFloating, device.FirewallRules[0].Floating)
			assert.Equal(t, tt.wantQuick, device.FirewallRules[0].Quick)
		})
	}
}

// TestConverter_FloatingRules_ShadowOrder drives floating rules through the
// shadow analysis. pfSense compiles them ahead of every interface rule, in the
// order they are listed, and its converter keeps document order, so the analysis
// has to supply that order (filter.inc rule_arr1 before rule_arr3).
func TestConverter_FloatingRules_ShadowOrder(t *testing.T) {
	t.Parallel()

	const (
		anyToAny = `<source><any/></source><destination><any/></destination>`
		anyToNet = `<source><any/></source><destination><address>203.0.113.0/24</address></destination>`
		floating = `<floating>yes</floating><quick>yes</quick><direction>in</direction>`
		onLAN    = `<interface>lan</interface>`

		interfacePass = `<rule><type>pass</type>` + onLAN + anyToAny + `</rule>`
		floatingBlock = `<rule><type>block</type>` + onLAN + floating + anyToNet + `</rule>`
		floatingPass  = `<rule><type>pass</type>` + onLAN + floating + anyToAny + `</rule>`
		unscopedBlock = `<rule><type>block</type>` + floating + anyToNet + `</rule>`
		unscopedPass  = `<rule><type>pass</type>` + floating + anyToAny + `</rule>`
	)

	tests := []struct {
		name   string
		filter string
		want   []string
	}{
		{
			name:   "floating block listed below an interface pass runs first",
			filter: interfacePass + floatingBlock,
		},
		{
			name:   "floating block on an interface above a floating pass on every interface wins",
			filter: floatingBlock + unscopedPass,
		},
		{
			name:   "floating pass on an interface above a floating block on every interface wins",
			filter: floatingPass + unscopedBlock,
			want:   []string{"Rule 2 (block) on interface lan (in) is fully shadowed by rule 1 (pass)"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, shadowSummaries(parsePfSenseFilter(t, tt.filter)))
		})
	}
}

// TestConverter_DisabledRules_ShadowAnalysis drives disabled rules through the
// shadow analysis. pfSense skips them (filter.inc L3256, L4267), so one can
// neither take traffic from a live rule nor end a group. It can still be
// reported as shadowed: it would be if it were enabled.
func TestConverter_DisabledRules_ShadowAnalysis(t *testing.T) {
	t.Parallel()

	const (
		onLAN    = `<interface>lan</interface>`
		off      = `<disabled/>`
		floating = `<floating>yes</floating><quick>yes</quick><direction>in</direction>`
		anyToAny = `<source><any/></source><destination><any/></destination>`
		toNet8   = `<source><any/></source><destination><address>10.0.0.0/8</address></destination>`
		toNet16  = `<source><any/></source><destination><address>10.1.0.0/16</address></destination>`
		toHTTPS  = `<protocol>tcp</protocol><source><any/></source><destination><any/><port>443</port></destination>`

		pass          = `<rule><type>pass</type>` + onLAN + toNet8 + `</rule>`
		disabledPass  = `<rule><type>pass</type>` + onLAN + off + toNet8 + `</rule>`
		disabledFloat = `<rule><type>pass</type>` + onLAN + off + floating + toNet8 + `</rule>`
		block         = `<rule><type>block</type>` + onLAN + toNet16 + `</rule>`
		disabledBlock = `<rule><type>block</type>` + onLAN + off + toNet16 + `</rule>`
		defaultDeny   = `<rule><type>block</type>` + onLAN + anyToAny + `</rule>`
		passHTTPS     = `<rule><type>pass</type>` + onLAN + toHTTPS + `</rule>`
		offHTTPS      = `<rule><type>pass</type>` + onLAN + off + toHTTPS + `</rule>`

		shadowedByAllow = "Rule 2 (block) on interface lan (in) is fully shadowed by rule 1 (pass)"
	)

	tests := []struct {
		name   string
		filter string
		want   []string
	}{
		{name: "disabled pass above a block", filter: disabledPass + block},
		{name: "disabled floating pass moved above a block", filter: block + disabledFloat},
		{
			name:   "disabled pass below the default deny",
			filter: passHTTPS + defaultDeny + offHTTPS,
			want: []string{
				"Rule 3 (pass) on interface lan (in) is fully shadowed by rule 1 (pass)",
				"Rule 3 (pass) on interface lan (in) is fully shadowed by rule 2 (block)",
			},
		},
		{name: "live pass above a disabled block", filter: pass + disabledBlock, want: []string{shadowedByAllow}},
		{name: "live pass above a live block", filter: pass + block, want: []string{shadowedByAllow}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, shadowSummaries(parsePfSenseFilter(t, tt.filter)))
		})
	}
}

// TestConverter_PortForwardRule_ShadowClass drives the filter rule pfSense adds
// for a port forward through parse, convert and the shadow analysis.
// firewall_nat.inc writes it with no <type>, which filter.inc compiles as pass,
// and appends it below the rules already on the interface.
func TestConverter_PortForwardRule_ShadowClass(t *testing.T) {
	t.Parallel()

	const (
		match = `<interface>wan</interface><protocol>tcp/udp</protocol><source><any></any></source>` +
			`<destination><address>10.0.2.2</address><port>443</port></destination>`

		forward = `<rule>` + match + `<associated-rule-id>nat_1</associated-rule-id></rule>`
		pass    = `<rule><type>pass</type>` + match + `</rule>`
		block   = `<rule><type>block</type>` + match + `</rule>`
	)

	tests := []struct {
		name      string
		filter    string
		wantClass common.ImpactClass
		want      string
	}{
		{
			name:      "pass above the port forward's rule is redundant",
			filter:    pass + forward,
			wantClass: common.ImpactClassHygiene,
			want:      "Rule 2 (pass) on interface wan (in) is fully shadowed by rule 1 (pass)",
		},
		{
			name:      "the port forward's rule above a block bypasses the deny",
			filter:    forward + block,
			wantClass: common.ImpactClassSecurity,
			want:      "Rule 2 (block) on interface wan (in) is fully shadowed by rule 1 (pass)",
		},
		{
			name:      "block above the port forward's rule stops the forward",
			filter:    block + forward,
			wantClass: common.ImpactClassTroubleshooting,
			want:      "Rule 2 (pass) on interface wan (in) is fully shadowed by rule 1 (block)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := parsePfSenseFilter(t, tt.filter)

			assert.Equal(t, []string{tt.want}, shadowSummaries(device))

			findings := analysis.DetectShadowedRules(device)
			require.Len(t, findings, 1)
			assert.Equal(t, tt.wantClass, findings[0].ImpactClass)
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
		if !rule.Floating {
			assert.True(t, rule.Quick, "rule %d", i)
		}
	}

	for _, finding := range analysis.DetectShadowedRules(device) {
		// A floating rule runs first wherever it is listed.
		if device.FirewallRules[finding.RuleIndex].Floating ||
			device.FirewallRules[finding.ShadowedByIndex].Floating {
			continue
		}

		assert.Less(t, finding.ShadowedByIndex, finding.RuleIndex, finding.Description)
	}
}
