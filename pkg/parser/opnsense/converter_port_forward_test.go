package opnsense_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parsePortForwardFixture runs a fixture through the full parser pipeline.
func parsePortForwardFixture(t *testing.T, name string) (*common.CommonDevice, []common.ConversionWarning) {
	t.Helper()

	f, err := os.Open(filepath.Join("..", "..", "..", "testdata", name))
	require.NoError(t, err)
	defer f.Close()

	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, warnings, err := factory.CreateDevice(context.Background(), f, common.DeviceTypeUnknown, false)
	require.NoError(t, err)
	require.NotNil(t, device)

	return device, warnings
}

// parsePortForwards runs a config whose <nat> holds natInner through the full
// parser pipeline.
func parsePortForwards(t *testing.T, natInner string) (*common.CommonDevice, []common.ConversionWarning) {
	t.Helper()

	const configTemplate = `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>fw</hostname>
    <domain>example.com</domain>
  </system>
  <interfaces>
    <wan><if>vtnet0</if></wan>
    <lan><if>vtnet1</if></lan>
  </interfaces>
  <aliases>
    <alias><name>WEB_HOST</name><type>host</type><address>192.168.1.50</address></alias>
    <alias><name>WEB_PORTS</name><type>port</type><address>8080 8443</address></alias>
    <alias><name>lan</name><type>network</type><address>10.99.0.0/24</address></alias>
  </aliases>
  <nat><outbound><mode>automatic</mode></outbound>%s</nat>
</opnsense>`

	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, warnings, err := factory.CreateDevice(
		context.Background(),
		strings.NewReader(strings.Replace(configTemplate, "%s", natInner, 1)),
		common.DeviceTypeUnknown,
		false,
	)
	require.NoError(t, err)
	require.NotNil(t, device)

	return device, warnings
}

// TestParser_LegacyPortForwardsFixture drives a config in the shape OPNsense
// wrote up to 25.7 through parse and convert. No port forward on any OPNsense
// release reached the device model before, because the schema read a path the
// vendor does not write and the converter tests built their structs by hand.
func TestParser_LegacyPortForwardsFixture(t *testing.T) {
	t.Parallel()

	device, warnings := parsePortForwardFixture(t, "opnsense-legacy-port-forwards.xml")
	assert.Empty(t, warnings)

	rules := device.NAT.InboundRules
	require.Len(t, rules, 3)

	web := rules[0]
	assert.Equal(t, []string{"wan"}, web.Interfaces)
	assert.Equal(t, "tcp", web.Protocol)
	assert.Equal(t, "any", web.Source.Address)
	assert.Equal(t, "wanip", web.Destination.Address)
	assert.Equal(t, "443", web.Destination.Port)
	assert.Equal(t, "192.168.10.50", web.InternalIP)
	assert.Nil(t, web.InternalIPRef)
	assert.Equal(t, "8443", web.LocalPort)
	assert.Equal(t, "nat_68dd1c2a4b5c61.23456789", web.AssociatedRuleID)
	assert.Equal(t, "HTTPS to web server", web.Description)
	assert.False(t, web.Disabled)

	mail := rules[1]
	assert.Equal(t, []string{"wan", "opt1"}, mail.Interfaces)
	assert.Equal(t, "pass", mail.AssociatedRuleID)
	assert.Equal(t, "TRUSTED_NETS", mail.Source.Address)
	assert.True(t, mail.Source.Negated)
	require.NotNil(t, mail.Source.AddressRef)
	assert.Equal(t, "TRUSTED_NETS", mail.Source.AddressRef.Name)
	assert.Nil(t, mail.Destination.AddressRef, "wanip is a macro, not an alias")
	require.NotNil(t, mail.Destination.PortRef)
	assert.Equal(t, "MAIL_PORTS", mail.Destination.PortRef.Name)
	require.NotNil(t, mail.InternalIPRef)
	assert.Equal(t, "MAIL_HOST", mail.InternalIPRef.Name)
	require.NotNil(t, mail.LocalPortRef)
	assert.Equal(t, "MAIL_PORTS", mail.LocalPortRef.Name)
	assert.Equal(t, "purenat", mail.NATReflection)
	assert.True(t, mail.NoSync)
	assert.True(t, mail.Log)

	exempt := rules[2]
	assert.True(t, exempt.NoRDR)
	assert.True(t, exempt.Disabled)
	assert.Empty(t, exempt.InternalIP)

	assert.Equal(t, 3, analysis.ComputeStatistics(device).NATEntries)
	assert.Equal(t, []string{"SPARE_HOST"}, unusedAliases(device),
		"aliases used only by a port forward must not be reported as unused")
}

// TestParser_PortForwardsFixture is the same check for the shape 26.1 and later
// write. The fixture's rules are out of <sequence> order on purpose.
func TestParser_PortForwardsFixture(t *testing.T) {
	t.Parallel()

	device, warnings := parsePortForwardFixture(t, "opnsense-port-forwards.xml")
	assert.Empty(t, warnings)

	rules := device.NAT.InboundRules
	require.Len(t, rules, 4)

	priorities := make([]int, 0, len(rules))
	for _, r := range rules {
		priorities = append(priorities, r.Priority)
	}
	assert.Equal(t, []int{100, 200, 300, 400}, priorities, "rules are reported in evaluation order")

	web := rules[0]
	assert.Equal(t, "b2b2b2b2-0000-4000-8000-000000000001", web.UUID)
	assert.Equal(t, "any", web.Source.Address, "an empty <network/> matches everything")
	assert.Equal(t, "wanip", web.Destination.Address)
	assert.Equal(t, "443", web.Destination.Port)
	assert.Equal(t, "192.168.10.50", web.InternalIP)
	assert.Equal(t, "8443", web.LocalPort)
	assert.Empty(t, web.AssociatedRuleID)
	assert.False(t, web.Disabled, "<disabled>0</disabled> is an enabled rule")
	assert.False(t, web.Source.Negated)

	exempt := rules[1]
	assert.True(t, exempt.NoRDR)
	assert.False(t, exempt.Disabled)
	assert.Empty(t, exempt.InternalIP)
	assert.Equal(t, "(self)", exempt.Destination.Address)
	assert.Equal(t, "https", exempt.Destination.Port)

	mail := rules[2]
	assert.Equal(t, []string{"wan", "opt1"}, mail.Interfaces)
	assert.Equal(t, "pass", mail.AssociatedRuleID, "26.x keeps the association in <pass>")
	require.NotNil(t, mail.Source.AddressRef, "26.x keeps an alias in <network>")
	assert.Equal(t, "TRUSTED_NETS", mail.Source.AddressRef.Name)
	assert.Nil(t, mail.Destination.AddressRef)
	require.NotNil(t, mail.InternalIPRef)
	assert.Equal(t, "MAIL_HOST", mail.InternalIPRef.Name)
	require.NotNil(t, mail.LocalPortRef)
	assert.Equal(t, "purenat", mail.NATReflection)
	assert.True(t, mail.Log)

	jump := rules[3]
	assert.True(t, jump.Disabled)
	assert.Equal(t, "rule", jump.AssociatedRuleID)
	assert.Equal(t, "opt1", jump.Source.Address)
	assert.True(t, jump.Source.Negated)
	assert.Nil(t, jump.Source.AddressRef)
	assert.Equal(t, "any", jump.Destination.Address)
	assert.Equal(t, "ssh", jump.LocalPort)

	assert.Equal(t, []string{"SPARE_HOST"}, unusedAliases(device),
		"aliases used only by a port forward must not be reported as unused")
}

// unusedAliases returns the names DetectUnusedObjects reports, sorted.
func unusedAliases(device *common.CommonDevice) []string {
	var names []string
	for _, finding := range analysis.DetectUnusedObjects(device) {
		names = append(names, finding.Name)
	}

	return names
}

// TestConverter_PortForwards_EndToEnd_PlaceholderNotCounted covers the empty
// <rule/> OPNsense 18.7.10 to 25.7 leaves under <nat> once the last port forward
// is deleted. Reading it as a rule would report a port forward on a firewall
// that has none, with no description, so FIREWALL-054 would fail.
func TestConverter_PortForwards_EndToEnd_PlaceholderNotCounted(t *testing.T) {
	t.Parallel()

	const forward = `<rule><interface>wan</interface><protocol>tcp</protocol>` +
		`<target>192.168.1.50</target><local-port>8443</local-port>` +
		`<source><any>1</any></source><destination><network>wanip</network><port>443</port></destination></rule>`

	tests := []struct {
		name      string
		natInner  string
		wantRules int
	}{
		{name: "empty rule placeholder reports no port forward", natInner: `<rule/>`, wantRules: 0},
		{name: "expanded empty rule reports no port forward", natInner: `<rule></rule>`, wantRules: 0},
		{name: "populated rule is counted", natInner: forward, wantRules: 1},
		{name: "placeholder beside a real rule yields only the real one", natInner: `<rule/>` + forward, wantRules: 1},
		{
			name:      "rule holding only a disabled flag is retained",
			natInner:  `<rule><disabled>1</disabled></rule>`,
			wantRules: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, warnings := parsePortForwards(t, tt.natInner)

			assert.Len(t, device.NAT.InboundRules, tt.wantRules)
			assert.Equal(t, tt.wantRules, analysis.ComputeStatistics(device).NATEntries)

			if tt.wantRules == 0 {
				assert.Nil(t, device.NAT.InboundRules)
				assert.Empty(t, warnings, "a placeholder must not draw a warning")
			}
		})
	}
}

// TestConverter_PortForwards_WarningIndex_PointsAtOutputIndex pins the index in
// a warning's Field to the converted output. A placeholder shifts it one way
// and <sequence> ordering the other.
func TestConverter_PortForwards_WarningIndex_PointsAtOutputIndex(t *testing.T) {
	t.Parallel()

	const noTarget = `<descr>broken</descr><interface>wan</interface><source><any>1</any></source>`

	t.Run("after a skipped placeholder", func(t *testing.T) {
		t.Parallel()

		device, warnings := parsePortForwards(t, `<rule/><rule>`+noTarget+`</rule>`)
		require.Len(t, device.NAT.InboundRules, 1)
		require.Len(t, warnings, 1)
		assert.Equal(t, "NAT.InboundRules[0].InternalIP", warnings[0].Field)
	})

	t.Run("after ordering by sequence", func(t *testing.T) {
		t.Parallel()

		device, warnings := parsePortForwards(t,
			`<rule uuid="b"><sequence>200</sequence>`+noTarget+`</rule>`+
				`<rule uuid="a"><sequence>100</sequence><interface>wan</interface><target>192.168.1.50</target></rule>`)
		require.Len(t, device.NAT.InboundRules, 2)
		assert.Equal(t, "broken", device.NAT.InboundRules[1].Description)
		require.Len(t, warnings, 1)
		assert.Equal(t, "NAT.InboundRules[1].InternalIP", warnings[0].Field)
		assert.Equal(t, common.SeverityHigh, warnings[0].Severity)
	})
}

// TestConverter_PortForwards_NoRDRHasNoTarget covers the rule that exempts
// traffic from redirection. The vendor writes no target for it, so a missing
// one is not a defect.
func TestConverter_PortForwards_NoRDRHasNoTarget(t *testing.T) {
	t.Parallel()

	const head = `<interface>wan</interface><source><any>1</any></source>` +
		`<destination><network>wanip</network><port>443</port></destination>`

	tests := []struct {
		name         string
		rule         string
		wantWarnings int
	}{
		{name: "legacy no-RDR rule", rule: head + `<nordr>1</nordr>`, wantWarnings: 0},
		{name: "26.x no-RDR rule", rule: head + `<nordr>1</nordr><target/><local-port/>`, wantWarnings: 0},
		{name: "redirect without a target", rule: head + `<nordr>0</nordr><target/>`, wantWarnings: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, warnings := parsePortForwards(t, `<rule>`+tt.rule+`</rule>`)
			require.Len(t, device.NAT.InboundRules, 1)
			assert.Len(t, warnings, tt.wantWarnings)
		})
	}
}

// TestConverter_PortForwards_Order covers when <sequence> decides the order and
// when the document does.
func TestConverter_PortForwards_Order(t *testing.T) {
	t.Parallel()

	rule := func(descr, sequence string) string {
		return `<rule><descr>` + descr + `</descr>` + sequence +
			`<interface>wan</interface><target>192.168.1.50</target></rule>`
	}

	descriptions := func(device *common.CommonDevice) []string {
		out := make([]string, 0, len(device.NAT.InboundRules))
		for _, r := range device.NAT.InboundRules {
			out = append(out, r.Description)
		}

		return out
	}

	t.Run("every rule sequenced sorts numerically", func(t *testing.T) {
		t.Parallel()

		device, warnings := parsePortForwards(
			t,
			rule(
				"c",
				`<sequence>1000</sequence>`,
			)+rule(
				"b",
				`<sequence>200</sequence>`,
			)+rule(
				"a",
				`<sequence>30</sequence>`,
			),
		)
		assert.Empty(t, warnings)
		assert.Equal(t, []string{"a", "b", "c"}, descriptions(device))
	})

	t.Run("equal sequences keep document order", func(t *testing.T) {
		t.Parallel()

		device, _ := parsePortForwards(t,
			rule("first", `<sequence>100</sequence>`)+rule("second", `<sequence>100</sequence>`))
		assert.Equal(t, []string{"first", "second"}, descriptions(device))
	})

	t.Run("a padded sequence is still a number", func(t *testing.T) {
		t.Parallel()

		device, warnings := parsePortForwards(t,
			rule("b", `<sequence> 200 </sequence>`)+rule("a", `<sequence>100</sequence>`))
		assert.Empty(t, warnings)
		assert.Equal(t, []string{"a", "b"}, descriptions(device))
		assert.Equal(t, 200, device.NAT.InboundRules[1].Priority)
	})

	t.Run("legacy rules keep document order", func(t *testing.T) {
		t.Parallel()

		device, warnings := parsePortForwards(t, rule("z", "")+rule("y", ""))
		assert.Empty(t, warnings)
		assert.Equal(t, []string{"z", "y"}, descriptions(device))
		assert.Zero(t, device.NAT.InboundRules[0].Priority)
	})

	t.Run("a rule without a sequence goes after the sequenced ones", func(t *testing.T) {
		t.Parallel()

		device, warnings := parsePortForwards(t,
			rule("unsequenced", "")+rule("b", `<sequence>200</sequence>`)+rule("a", `<sequence>100</sequence>`))
		assert.Empty(t, warnings)
		assert.Equal(t, []string{"a", "b", "unsequenced"}, descriptions(device))
		assert.Zero(t, device.NAT.InboundRules[2].Priority, "an assigned place is not reported as a sequence")
	})

	t.Run("a placeholder does not stop the sort", func(t *testing.T) {
		t.Parallel()

		device, warnings := parsePortForwards(t,
			`<rule/>`+rule("b", `<sequence>200</sequence>`)+rule("a", `<sequence>100</sequence>`))
		assert.Empty(t, warnings)
		assert.Equal(t, []string{"a", "b"}, descriptions(device))
	})

	for _, bad := range []string{"first", "1.5", "99999999999999999999"} {
		t.Run("sequence "+bad+" warns and keeps document order", func(t *testing.T) {
			t.Parallel()

			device, warnings := parsePortForwards(t,
				rule("z", `<sequence>200</sequence>`)+rule("y", `<sequence>`+bad+`</sequence>`))
			assert.Equal(t, []string{"z", "y"}, descriptions(device))
			assert.Zero(t, device.NAT.InboundRules[1].Priority, "a rejected sequence is not reported")
			require.Len(t, warnings, 1)
			assert.Equal(t, "NAT.InboundRules[1].Priority", warnings[0].Field)
			assert.Equal(t, bad, warnings[0].Value)
			assert.Equal(t, common.SeverityLow, warnings[0].Severity)
		})
	}
}

// TestConverter_PortForwards_EndpointAlias covers which endpoint values are
// looked up as aliases, on both sides of the rule. The config defines an alias
// named "lan": OPNsense resolves a name that is both an interface and an alias
// to the alias, so the reference is kept.
func TestConverter_PortForwards_EndpointAlias(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		endpoint    string
		wantAddress string
		wantRef     string
	}{
		{
			name:        "legacy alias in address",
			endpoint:    `<address>WEB_HOST</address>`,
			wantAddress: "WEB_HOST",
			wantRef:     "WEB_HOST",
		},
		{
			name:        "26.x alias in network",
			endpoint:    `<network>WEB_HOST</network>`,
			wantAddress: "WEB_HOST",
			wantRef:     "WEB_HOST",
		},
		{name: "interface macro", endpoint: `<network>wan</network>`, wantAddress: "wan"},
		{name: "interface address macro", endpoint: `<network>wanip</network>`, wantAddress: "wanip"},
		{name: "the firewall itself", endpoint: `<network>(self)</network>`, wantAddress: "(self)"},
		{name: "alias named like an interface", endpoint: `<network>lan</network>`, wantAddress: "lan", wantRef: "lan"},
		{name: "literal network", endpoint: `<network>203.0.113.0/24</network>`, wantAddress: "203.0.113.0/24"},
		{name: "26.x any written out", endpoint: `<network>any</network>`, wantAddress: "any"},
		{name: "26.x any left empty", endpoint: `<network/><port/><not>0</not>`, wantAddress: "any"},
		{name: "legacy any", endpoint: `<any>1</any>`, wantAddress: "any"},
	}

	for _, tt := range tests {
		for _, side := range []string{"source", "destination"} {
			t.Run(tt.name+" as "+side, func(t *testing.T) {
				t.Parallel()

				device, _ := parsePortForwards(t,
					`<rule><interface>wan</interface><target>192.168.1.50</target><`+side+`>`+
						tt.endpoint+`</`+side+`></rule>`)
				require.Len(t, device.NAT.InboundRules, 1)

				endpoint := device.NAT.InboundRules[0].Source
				if side == "destination" {
					endpoint = device.NAT.InboundRules[0].Destination
				}

				assert.Equal(t, tt.wantAddress, endpoint.Address)

				if tt.wantRef == "" {
					assert.Nil(t, endpoint.AddressRef)

					return
				}

				require.NotNil(t, endpoint.AddressRef)
				assert.Equal(t, tt.wantRef, endpoint.AddressRef.Name)
			})
		}
	}
}

// TestConverter_PortForwards_EndpointPortAndNegation covers the port and <not>
// on each side of the rule, which neither fixture sets on both.
func TestConverter_PortForwards_EndpointPortAndNegation(t *testing.T) {
	t.Parallel()

	device, _ := parsePortForwards(t,
		`<rule><interface>wan</interface><protocol>tcp</protocol><target>192.168.1.50</target>`+
			`<source><network>lan</network><port>1024-65535</port><not>0</not></source>`+
			`<destination><network>WEB_HOST</network><port>WEB_PORTS</port><not>1</not></destination></rule>`+
			`<rule><interface>wan</interface><protocol>tcp</protocol><target>192.168.1.50</target>`+
			`<source><address>WEB_HOST</address><port>WEB_PORTS</port><not>1</not></source>`+
			`<destination><network>wanip</network><port>443</port></destination></rule>`)
	require.Len(t, device.NAT.InboundRules, 2)

	first := device.NAT.InboundRules[0]
	assert.Equal(t, "1024-65535", first.Source.Port)
	assert.Nil(t, first.Source.PortRef)
	assert.False(t, first.Source.Negated)
	assert.Equal(t, "WEB_PORTS", first.Destination.Port)
	require.NotNil(t, first.Destination.PortRef)
	assert.True(t, first.Destination.Negated)

	second := device.NAT.InboundRules[1]
	require.NotNil(t, second.Source.PortRef)
	assert.Equal(t, "WEB_PORTS", second.Source.PortRef.Name)
	assert.True(t, second.Source.Negated)
	assert.Equal(t, "443", second.Destination.Port)
	assert.False(t, second.Destination.Negated)
}

// TestConverter_PortForwards_RedirectAddress covers which element supplies the
// redirect address when a document carries both.
func TestConverter_PortForwards_RedirectAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rule schema.InboundRule
		want string
	}{
		{name: "target", rule: schema.InboundRule{Target: "192.168.1.50"}, want: "192.168.1.50"},
		{name: "internalip alone", rule: schema.InboundRule{InternalIP: "192.168.1.60"}, want: "192.168.1.60"},
		{
			name: "target wins over internalip",
			rule: schema.InboundRule{Target: "192.168.1.50", InternalIP: "192.168.1.60"},
			want: "192.168.1.50",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tt.rule.Interface = schema.InterfaceList{"wan"}
			doc := schema.NewOpnSenseDocument()
			doc.Nat.Inbound = []schema.InboundRule{tt.rule}

			device, warnings, err := opnsense.ConvertDocument(doc)
			require.NoError(t, err)
			assert.Empty(t, warnings)
			require.Len(t, device.NAT.InboundRules, 1)
			assert.Equal(t, tt.want, device.NAT.InboundRules[0].InternalIP)
		})
	}
}

// TestParser_PortForwardFixtures_CompanionRuleKeepsItsLink covers the pass rule
// a port forward stores for itself under <filter>. The rule carries the same
// <associated-rule-id> as the forward, which is the only thing tying the two
// together, and the filter rule schema did not bind it.
func TestParser_PortForwardFixtures_CompanionRuleKeepsItsLink(t *testing.T) {
	t.Parallel()

	const linkID = "nat_68dd1c2a4b5c61.23456789"

	for _, name := range []string{"opnsense-legacy-port-forwards.xml", "opnsense-port-forwards.xml"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			device, _ := parsePortForwardFixture(t, name)

			var linked []common.FirewallRule
			for _, rule := range device.FirewallRules {
				if rule.AssociatedRuleID != "" {
					linked = append(linked, rule)
				}
			}

			require.Len(t, linked, 1)
			assert.Equal(t, linkID, linked[0].AssociatedRuleID)
			assert.Equal(t, common.RuleTypePass, linked[0].Type)
			assert.Equal(t, "192.168.10.50", linked[0].Destination.Address)
			assert.Equal(t, "8443", linked[0].Destination.Port)
		})
	}

	legacy, _ := parsePortForwardFixture(t, "opnsense-legacy-port-forwards.xml")
	assert.Equal(t, linkID, legacy.NAT.InboundRules[0].AssociatedRuleID,
		"up to 25.7 the forward carries the same ID as its filter rule")
}
