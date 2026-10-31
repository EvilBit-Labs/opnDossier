package pfsense_test

import (
	"context"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	pfsenseSchema "github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseRuleTypeConfig runs rules, the content of <filter>, through the full
// pfSense parser with one host alias defined.
func parseRuleTypeConfig(t *testing.T, rules string) (*common.CommonDevice, []common.ConversionWarning) {
	t.Helper()

	config := `<?xml version="1.0"?><pfsense><version>19.1</version>` +
		`<aliases><alias><name>WEB_HOSTS</name><type>host</type><address>10.0.2.2</address></alias></aliases>` +
		`<filter>` + rules + `</filter></pfsense>`

	device, warnings, err := pfsense.NewParser(nil).Parse(context.Background(), strings.NewReader(config))
	require.NoError(t, err)

	return device, nonGapWarnings(warnings)
}

// TestParser_ConfigPfSense_TypelessRulesArePass pins pfSense's reading of a
// rule with no <type>: filter.inc compiles it as pass. The port forward page
// writes its companion rule without one, and in the shipped fixture those two
// rules are the only WAN pass rules, so both port forwards must read as
// WAN-reachable.
func TestParser_ConfigPfSense_TypelessRulesArePass(t *testing.T) {
	t.Parallel()

	device, _ := parseConfigPfSenseFixture(t)

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
		{"\tmatch\n", "match", common.SeverityLow, keptAsStored},
		{"Pass", common.RuleTypePass, common.SeverityMedium, readAsPass},
		{"allow", common.RuleTypePass, common.SeverityMedium, readAsPass},
		{"Block", common.RuleTypePass, common.SeverityMedium, readAsPass},
		{"Match", common.RuleTypePass, common.SeverityMedium, readAsPass},
		// cData in xmlparse.inc trims these three characters and no others.
		{"\n\t\tblock\r\n", common.RuleTypeBlock, "", ""},
		{"\n", common.RuleTypePass, "", ""},
		{" block", common.RuleTypePass, common.SeverityMedium, readAsPass},
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

// TestParser_FirewallRules_TypeWrappedAcrossLines drives a wrapped <type> through
// the decoder, which keeps the white space pfSense's parser trims. The rule is
// block on the firewall, and the pass rule before it shows the two are not mixed.
func TestParser_FirewallRules_TypeWrappedAcrossLines(t *testing.T) {
	t.Parallel()

	device, warnings := parseRuleTypeConfig(
		t,
		`<rule><type>pass</type><interface>wan</interface><source><any/></source><destination><any/></destination></rule>`+
			"<rule><type>\n\t\t\tblock\n\t\t</type><interface>lan</interface>"+
			`<source><any/></source><destination><any/></destination></rule>`,
	)

	assert.Empty(t, warnings)
	require.Len(t, device.FirewallRules, 2)
	assert.Equal(t, common.RuleTypePass, device.FirewallRules[0].Type)
	assert.Equal(t, common.RuleTypeBlock, device.FirewallRules[1].Type)
}

// TestParser_FirewallRules_StateTypeReadsAsFilterIncCompilesIt follows the state
// handling in filter_generate_user_rule: a rule that compiles as pass keeps state
// unless it says otherwise, however the type was spelled, and no other type takes
// a default. The first rule of each config shows a value is not carried over.
func TestParser_FirewallRules_StateTypeReadsAsFilterIncCompilesIt(t *testing.T) {
	t.Parallel()

	const (
		keepState = "keep state"
		match     = `<interface>wan</interface><protocol>tcp</protocol><source><any></any></source>` +
			`<destination><address>10.0.2.2</address><port>443</port></destination>`
		first = `<rule><type>block</type><statetype>sloppy state</statetype>` + match + `</rule>`
	)

	tests := []struct {
		name string
		body string
		want string
	}{
		{"no type and no state, as on a forward's rule", ``, keepState},
		{"type pass", `<type>pass</type>`, keepState},
		{"an empty element", `<type>pass</type><statetype></statetype>`, keepState},
		{"a type that compiles as pass", `<type>allow</type>`, keepState},
		{"a stored state", `<statetype>synproxy state</statetype>`, "synproxy state"},
		{"no state", `<statetype>none</statetype>`, "none"},
		{"block", `<type>block</type>`, ""},
		{"reject", `<type>reject</type>`, ""},
		{"match", `<type>match</type>`, ""},
		{"a state stored on block", `<type>block</type><statetype>sloppy state</statetype>`, "sloppy state"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device, _ := parseRuleTypeConfig(t, first+`<rule>`+tc.body+match+`</rule>`)
			require.Len(t, device.FirewallRules, 2)
			assert.Equal(t, "sloppy state", device.FirewallRules[0].StateType)
			assert.Equal(t, tc.want, device.FirewallRules[1].StateType)
		})
	}
}

// TestParser_FirewallRules_AnyWinsOverAddress pins the order of
// filter_generate_address, which tests isset(any) before network and address:
// whatever else an endpoint holds, pf gets any, and the value of <any> does not
// matter. The other endpoint of each rule keeps what it holds, and the alias
// beside <any> is not in the rule pf compiles, so it gets no reference.
func TestParser_FirewallRules_AnyWinsOverAddress(t *testing.T) {
	t.Parallel()

	device, warnings := parseRuleTypeConfig(t,
		`<rule><interface>wan</interface>`+
			`<source><any></any><network>lan</network></source>`+
			`<destination><address>WEB_HOSTS</address></destination></rule>`+
			`<rule><interface>wan</interface>`+
			`<source><address>WEB_HOSTS</address></source>`+
			`<destination><address>WEB_HOSTS</address><any/><port>443</port></destination></rule>`+
			`<rule><interface>wan</interface>`+
			`<source><any>0</any><address>WEB_HOSTS</address></source>`+
			`<destination><network>lan</network></destination></rule>`+
			`<rule><interface>wan</interface>`+
			`<source><network>lan</network></source>`+
			`<destination><network>lan</network><any></any></destination></rule>`)

	assert.Empty(t, warnings)
	require.Len(t, device.FirewallRules, 4)

	sourceAny := device.FirewallRules[0]
	assert.Equal(t, "any", sourceAny.Source.Address)
	assert.Equal(t, "WEB_HOSTS", sourceAny.Destination.Address)
	require.NotNil(t, sourceAny.Destination.AddressRef)
	assert.Equal(t, "WEB_HOSTS", sourceAny.Destination.AddressRef.Name)

	destinationAny := device.FirewallRules[1]
	assert.Equal(t, "WEB_HOSTS", destinationAny.Source.Address)
	assert.NotNil(t, destinationAny.Source.AddressRef)
	assert.Equal(t, "any", destinationAny.Destination.Address)
	assert.Nil(t, destinationAny.Destination.AddressRef)
	assert.Equal(t, "443", destinationAny.Destination.Port, "the port is read apart from the address")

	anyHoldingZero := device.FirewallRules[2]
	assert.Equal(t, "any", anyHoldingZero.Source.Address, "isset does not read the value")
	assert.Nil(t, anyHoldingZero.Source.AddressRef)
	assert.Equal(t, "lan", anyHoldingZero.Destination.Address)

	macroBesideAny := device.FirewallRules[3]
	assert.Equal(t, "lan", macroBesideAny.Source.Address)
	assert.Equal(t, "any", macroBesideAny.Destination.Address)
}

// TestParser_TypelessRuleIsDuplicateOfPassRule covers what reading a forward's
// rule as pass does to the dead rule view. The firewall loads both rules below
// as pass with one match, so the second is a duplicate of the first, and no rule
// is reported when the first blocks instead.
func TestParser_TypelessRuleIsDuplicateOfPassRule(t *testing.T) {
	t.Parallel()

	const (
		match = `<interface>wan</interface><protocol>tcp/udp</protocol><source><any></any></source>` +
			`<destination><address>10.0.2.2</address><port>443</port></destination>`
		forward = `<rule>` + match + `<associated-rule-id>nat_5e7bb3f7a503d5.68828728</associated-rule-id></rule>`
	)

	device, _ := parseRuleTypeConfig(t, `<rule><type>pass</type>`+match+`</rule>`+forward)

	findings := analysis.DetectDeadRules(device)
	require.Len(t, findings, 1)
	assert.Equal(t, common.DeadRuleKindDuplicate, findings[0].Kind)
	assert.Equal(t, 1, findings[0].RuleIndex)

	device, _ = parseRuleTypeConfig(t, `<rule><type>block</type>`+match+`</rule>`+forward)

	for _, finding := range analysis.DetectDeadRules(device) {
		assert.NotEqual(t, common.DeadRuleKindDuplicate, finding.Kind, finding.Description)
	}
}
