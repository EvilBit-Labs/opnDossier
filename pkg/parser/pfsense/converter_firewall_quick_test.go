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
// isset(), so each element counts whatever it holds. A rule without <floating> is
// always quick, and a floating rule is quick only when it carries <quick>
// (filter.inc L3387, L4295). The rule under test is the second, with a neighbor
// that reads the other way on Quick, so that it cannot borrow the result.
func TestConverter_FirewallRules_QuickDefault(t *testing.T) {
	t.Parallel()

	const (
		floatingYes = `<floating>yes</floating>`
		floatingOne = `<floating>1</floating>`
	)

	tests := []struct {
		name         string
		elements     string
		wantFloating bool
		wantQuick    bool
	}{
		{name: "interface rule", wantQuick: true},
		{name: "interface rule with quick", elements: `<quick>yes</quick>`, wantQuick: true},
		{name: "interface rule with quick holding 0", elements: `<quick>0</quick>`, wantQuick: true},
		{name: "floating rule", elements: floatingYes, wantFloating: true},
		{
			name:         "floating rule with quick",
			elements:     floatingYes + `<quick>yes</quick>`,
			wantFloating: true,
			wantQuick:    true,
		},
		{
			name:         "floating rule with a self-closing quick",
			elements:     floatingYes + `<quick/>`,
			wantFloating: true,
			wantQuick:    true,
		},
		{
			name:         "floating rule with an empty quick",
			elements:     floatingYes + `<quick></quick>`,
			wantFloating: true,
			wantQuick:    true,
		},
		{
			name:         "floating rule with quick holding 0",
			elements:     floatingYes + `<quick>0</quick>`,
			wantFloating: true,
			wantQuick:    true,
		},
		{
			name:         "floating rule with quick holding no",
			elements:     floatingYes + `<quick>no</quick>`,
			wantFloating: true,
			wantQuick:    true,
		},
		{
			name:         "floating rule with quick holding false",
			elements:     floatingYes + `<quick>false</quick>`,
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
		{name: "floating element with another value", elements: floatingOne, wantFloating: true},
		{
			name:         "floating element with another value and quick holding 0",
			elements:     floatingOne + `<quick>0</quick>`,
			wantFloating: true,
			wantQuick:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			neighbor := ""
			if tt.wantQuick {
				neighbor = floatingYes
			}

			device := parsePfSenseFilter(t,
				`<rule><type>block</type><interface>lan</interface>`+neighbor+`</rule>`+
					`<rule><type>pass</type><interface>lan</interface>`+tt.elements+`</rule>`)

			require.Len(t, device.FirewallRules, 2)
			assert.Equal(t, !tt.wantQuick, device.FirewallRules[0].Quick, "neighbor")
			assert.Equal(t, tt.wantFloating, device.FirewallRules[1].Floating)
			assert.Equal(t, tt.wantQuick, device.FirewallRules[1].Quick)
		})
	}
}

// TestConverter_FloatingRules_QuickBodyShadowAnalysis drives <quick> through the
// shadow analysis. A floating pass that carries the element stops evaluation
// whatever the element holds, so the block below it never sees the traffic.
// Read as not quick, the same pair names the block as the winner and rates a
// bypass as troubleshooting.
func TestConverter_FloatingRules_QuickBodyShadowAnalysis(t *testing.T) {
	t.Parallel()

	const (
		onLAN    = `<interface>lan</interface>`
		toNet8   = `<source><any/></source><destination><address>10.0.0.0/8</address></destination>`
		toNet16  = `<source><any/></source><destination><address>10.1.0.0/16</address></destination>`
		floating = `<floating>yes</floating><direction>in</direction>`

		block = `<rule><type>block</type>` + onLAN + toNet16 + `</rule>`

		shadowedByAllow = "Rule 2 (block) on interface lan (in) is fully shadowed by rule 1 (pass)"
		lastMatch       = "Rule 1 (pass) on interface lan (in) is partially shadowed by rule 2 (block)"
	)

	tests := []struct {
		name      string
		elements  string
		want      string
		wantClass common.ImpactClass
	}{
		{name: "no quick", elements: floating, want: lastMatch, wantClass: common.ImpactClassTroubleshooting},
		{
			name:      "quick holding yes",
			elements:  floating + `<quick>yes</quick>`,
			want:      shadowedByAllow,
			wantClass: common.ImpactClassSecurity,
		},
		{
			name:      "empty quick",
			elements:  floating + `<quick></quick>`,
			want:      shadowedByAllow,
			wantClass: common.ImpactClassSecurity,
		},
		{
			name:      "quick holding 0",
			elements:  floating + `<quick>0</quick>`,
			want:      shadowedByAllow,
			wantClass: common.ImpactClassSecurity,
		},
		{
			name:      "quick holding no",
			elements:  floating + `<quick>no</quick>`,
			want:      shadowedByAllow,
			wantClass: common.ImpactClassSecurity,
		},
		{
			name:      "floating element holding 1 with quick holding off",
			elements:  `<floating>1</floating><quick>off</quick>`,
			want:      shadowedByAllow,
			wantClass: common.ImpactClassSecurity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := parsePfSenseFilter(t, `<rule><type>pass</type>`+onLAN+tt.elements+toNet8+`</rule>`+block)

			assert.Equal(t, []string{tt.want}, shadowSummaries(device))

			findings := analysis.DetectShadowedRules(device)
			require.Len(t, findings, 1)
			assert.Equal(t, tt.wantClass, findings[0].ImpactClass)
		})
	}
}

// TestConverter_FirewallRules_DisabledElement pins how pfSense reads <disabled>:
// isset(), so the rule is skipped whatever the element holds (filter.inc L3256,
// L4267). The rule under test is the second, with a neighbor that reads the other
// way, so that it cannot borrow the result.
func TestConverter_FirewallRules_DisabledElement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		element      string
		neighbor     string
		wantDisabled bool
	}{
		{name: "absent element", neighbor: `<disabled/>`},
		{name: "self-closing element", element: `<disabled/>`, wantDisabled: true},
		{name: "empty element", element: `<disabled></disabled>`, wantDisabled: true},
		{name: "element holding 1", element: `<disabled>1</disabled>`, wantDisabled: true},
		{name: "element holding 0", element: `<disabled>0</disabled>`, wantDisabled: true},
		{name: "element holding no", element: `<disabled>no</disabled>`, wantDisabled: true},
		{name: "element holding false", element: `<disabled>false</disabled>`, wantDisabled: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := parsePfSenseFilter(t,
				`<rule><type>block</type><interface>lan</interface>`+tt.neighbor+`</rule>`+
					`<rule><type>pass</type><interface>lan</interface>`+tt.element+`</rule>`)

			require.Len(t, device.FirewallRules, 2)
			assert.Equal(t, tt.neighbor != "", device.FirewallRules[0].Disabled, "neighbor")
			assert.Equal(t, tt.wantDisabled, device.FirewallRules[1].Disabled)
		})
	}
}

// TestConverter_FirewallRules_CompiledDirection pins the direction pfSense
// compiles a rule with (filter.inc L3376-L3383). Only a <floating> holding
// exactly yes keeps <direction>, and with none the rule gets no direction
// keyword. Every other rule compiles as in, which the model leaves empty.
func TestConverter_FirewallRules_CompiledDirection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		elements string
		want     common.FirewallDirection
	}{
		{name: "interface rule"},
		{name: "interface rule with direction in", elements: `<direction>in</direction>`},
		{name: "interface rule with direction out", elements: `<direction>out</direction>`},
		{name: "interface rule with direction any", elements: `<direction>any</direction>`},
		{name: "interface rule with an unknown direction", elements: `<direction>sideways</direction>`},
		{name: "floating rule with no direction", elements: `<floating>yes</floating>`, want: common.DirectionAny},
		{
			name:     "floating rule with direction in",
			elements: `<floating>yes</floating><direction>in</direction>`,
			want:     common.DirectionIn,
		},
		{
			name:     "floating rule with direction out",
			elements: `<floating>yes</floating><direction>out</direction>`,
			want:     common.DirectionOut,
		},
		{
			name:     "floating rule with direction any",
			elements: `<floating>yes</floating><direction>any</direction>`,
			want:     common.DirectionAny,
		},
		{name: "floating element holding 1", elements: `<floating>1</floating><direction>out</direction>`},
		{name: "floating element holding Yes", elements: `<floating>Yes</floating><direction>out</direction>`},
		{name: "empty floating element", elements: `<floating/><direction>out</direction>`},
		{name: "empty floating element with no direction", elements: `<floating/>`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := parsePfSenseFilter(t,
				`<rule><type>block</type><interface>lan</interface><floating>yes</floating>`+
					`<direction>out</direction></rule>`+
					`<rule><type>pass</type><interface>lan</interface>`+tt.elements+`</rule>`)

			require.Len(t, device.FirewallRules, 2)
			assert.Equal(t, common.DirectionOut, device.FirewallRules[0].Direction, "neighbor")
			assert.Equal(t, tt.want, device.FirewallRules[1].Direction)
		})
	}
}

// TestConverter_FirewallRules_DirectionShadowGroups drives those directions
// through the shadow analysis, where a rule read in the wrong group never pairs
// with the rule it shadows.
func TestConverter_FirewallRules_DirectionShadowGroups(t *testing.T) {
	t.Parallel()

	const (
		anyToNet8  = `<source><any/></source><destination><address>10.0.0.0/8</address></destination>`
		anyToNet16 = `<source><any/></source><destination><address>10.1.0.0/16</address></destination>`

		block    = `<rule><type>block</type><interface>lan</interface>` + anyToNet16 + `</rule>`
		outBlock = `<rule><type>block</type><interface>lan</interface><floating>yes</floating><quick>yes</quick>` +
			`<direction>out</direction>` + anyToNet16 + `</rule>`
	)

	pass := func(elements string) string {
		return `<rule><type>pass</type><interface>lan</interface>` + elements + anyToNet8 + `</rule>`
	}

	tests := []struct {
		name   string
		filter string
		want   []string
	}{
		{
			name:   "direction out on an interface pass still bypasses the block",
			filter: pass(`<direction>out</direction>`) + block,
			want:   []string{"Rule 2 (block) on interface lan (in) is fully shadowed by rule 1 (pass)"},
		},
		{
			name:   "direction any on an interface pass stays out of the out group",
			filter: pass(`<direction>any</direction>`) + outBlock,
		},
		{
			name:   "floating pass with no direction joins the out group",
			filter: pass(`<floating>yes</floating><quick>yes</quick>`) + outBlock,
			want:   []string{"Rule 2 (block) on interface lan (out) is fully shadowed by rule 1 (pass)"},
		},
		{
			name:   "floating element that does not hold yes compiles as in",
			filter: pass(`<floating>1</floating><quick>yes</quick><direction>out</direction>`) + block,
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

// TestConverter_DeadRules_SeeRulesAsCompiled pins what the pfSense reading does
// to DetectDeadRules. That function hands RulesEquivalent the converted rules,
// and it compares Quick, Direction and Disabled, so a rule the firewall compiles
// alike is now a duplicate of its twin and one it compiles differently no longer
// is. Only an element the GUI does not write tells these apart: the GUI writes
// <quick> and <direction> on floating rules alone, always with
// <floating>yes</floating> and a <direction>, and <disabled> empty, so the twins
// it writes stay as they were.
func TestConverter_DeadRules_SeeRulesAsCompiled(t *testing.T) {
	t.Parallel()

	const (
		match = `<interface>lan</interface><protocol>tcp</protocol><source><any/></source>` +
			`<destination><any/><port>443</port></destination>`

		plain = `<rule><type>pass</type>` + match + `</rule>`

		floatingYes = `<floating>yes</floating>`
		quickYes    = floatingYes + `<quick>yes</quick>`
	)

	rule := func(elements string) string {
		return `<rule><type>pass</type>` + elements + match + `</rule>`
	}

	duplicateOfFirst := []common.DeadRuleFinding{{Kind: "duplicate", RuleIndex: 1, Interface: "lan"}}

	tests := []struct {
		name   string
		filter string
		want   []common.DeadRuleFinding
	}{
		{name: "quick on an interface rule", filter: rule(`<quick>yes</quick>`) + plain, want: duplicateOfFirst},
		{
			name:   "direction on an interface rule",
			filter: rule(`<direction>out</direction>`) + plain,
			want:   duplicateOfFirst,
		},
		{name: "floating element holding 1 with no quick", filter: rule(`<floating>1</floating>`) + plain},
		{name: "empty floating element with no quick", filter: rule(`<floating/>`) + plain},
		{
			name:   "non-quick floating rule with the raw direction of an interface rule",
			filter: rule(`<floating>yes</floating><direction>in</direction>`) + rule(`<direction>in</direction>`),
		},
		{
			name:   "quick floating rule from the GUI above an interface rule",
			filter: rule(`<floating>yes</floating><quick>yes</quick><direction>in</direction>`) + plain,
		},
		{
			name:   "non-quick floating rule from the GUI above an interface rule",
			filter: rule(`<floating>yes</floating><direction>in</direction>`) + plain,
		},
		{
			name:   "floating rule with quick holding 0 above one with quick",
			filter: rule(floatingYes+`<quick>0</quick>`) + rule(quickYes),
			want:   duplicateOfFirst,
		},
		{
			name:   "floating rule with quick holding no above one with no quick",
			filter: rule(floatingYes+`<quick>no</quick>`) + rule(floatingYes),
		},
		{
			name:   "floating rule with no direction above one with direction any",
			filter: rule(quickYes) + rule(quickYes+`<direction>any</direction>`),
			want:   duplicateOfFirst,
		},
		{name: "floating rule with no direction above an interface rule", filter: rule(floatingYes) + plain},
		{name: "disabled element holding 0 above a live rule", filter: rule(`<disabled>0</disabled>`) + plain},
		{name: "disabled element holding no above a live rule", filter: rule(`<disabled>no</disabled>`) + plain},
		{
			name:   "disabled element holding 0 above an empty one",
			filter: rule(`<disabled>0</disabled>`) + rule(`<disabled></disabled>`),
			want:   duplicateOfFirst,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got []common.DeadRuleFinding

			for _, finding := range analysis.DetectDeadRules(parsePfSenseFilter(t, tt.filter)) {
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
		heldZeroPass  = `<rule><type>pass</type>` + onLAN + `<disabled>0</disabled>` + toNet8 + `</rule>`

		shadowedByAllow = "Rule 2 (block) on interface lan (in) is fully shadowed by rule 1 (pass)"
	)

	tests := []struct {
		name   string
		filter string
		want   []string
	}{
		{name: "disabled pass above a block", filter: disabledPass + block},
		{name: "element holding 0 still disables the pass", filter: heldZeroPass + block},
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
