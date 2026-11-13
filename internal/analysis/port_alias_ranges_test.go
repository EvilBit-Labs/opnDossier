package analysis_test

import (
	"cmp"
	"context"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	_ "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense" // self-registers the OPNsense parser
	_ "github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"  // self-registers the pfSense parser
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// portAliasOPNsenseConfig is an OPNsense 26.7 config with one port alias and
// three WAN rules in the filter model: rule 0 and rule 1 are the pair under
// test, and the trailing pass keeps rule 1 from being the terminal deny.
const portAliasOPNsenseConfig = `<?xml version="1.0"?>
<opnsense>
  <system><hostname>fw</hostname><domain>internal</domain></system>
  <interfaces>
    <wan><enable>1</enable><if>vtnet0</if><ipaddr>203.0.113.2</ipaddr><subnet>24</subnet></wan>
    <lan><enable>1</enable><if>vtnet1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <filter/>
  <OPNsense>
    <Firewall>
      <Alias version="1.0.1">
        <aliases>
          <alias uuid="a0000000-0000-4000-8000-000000000001">
            <enabled>1</enabled>
            <name>Ports</name>
            <type>port</type>
            <content>{{CONTENT}}</content>
            <description>ports</description>
          </alias>
        </aliases>
      </Alias>
      <Filter version="1.0.6">
        <rules>
          <rule uuid="b0000000-0000-4000-8000-000000000001">
            <sequence>1</sequence>
            <action>{{ACTION0}}</action>
            <interface>wan</interface>
            <protocol>TCP</protocol>
            <destination_port>{{PORT0}}</destination_port>
            <description>first</description>
          </rule>
          <rule uuid="b0000000-0000-4000-8000-000000000002">
            <sequence>2</sequence>
            <action>{{ACTION1}}</action>
            <interface>wan</interface>
            <protocol>TCP</protocol>
            <destination_port>{{PORT1}}</destination_port>
            <description>second</description>
          </rule>
          <rule uuid="b0000000-0000-4000-8000-000000000003">
            <sequence>3</sequence>
            <action>pass</action>
            <interface>wan</interface>
            <protocol>TCP</protocol>
            <destination_port>53</destination_port>
            <description>trailing pass</description>
          </rule>
        </rules>
      </Filter>
    </Firewall>
  </OPNsense>
</opnsense>`

// portAliasPfSenseConfig is the same layout as pfSense writes it: the alias
// members separated by spaces in <address>, and legacy rules.
const portAliasPfSenseConfig = `<?xml version="1.0"?>
<pfsense>
  <version>23.3</version>
  <system><hostname>fw</hostname><domain>internal</domain></system>
  <interfaces>
    <wan><enable/><if>vtnet0</if><ipaddr>203.0.113.2</ipaddr><subnet>24</subnet></wan>
    <lan><enable/><if>vtnet1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <aliases>
    <alias><name>Ports</name><type>port</type><address>{{CONTENT}}</address><descr>ports</descr></alias>
  </aliases>
  <filter>
    <rule>
      <type>{{ACTION0}}</type><interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><any/></source><destination><any/><port>{{PORT0}}</port></destination>
      <descr>first</descr><tracker>1</tracker>
    </rule>
    <rule>
      <type>{{ACTION1}}</type><interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><any/></source><destination><any/><port>{{PORT1}}</port></destination>
      <descr>second</descr><tracker>2</tracker>
    </rule>
    <rule>
      <type>pass</type><interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><any/></source><destination><any/><port>53</port></destination>
      <descr>trailing pass</descr><tracker>3</tracker>
    </rule>
  </filter>
</pfsense>`

// TestDetectShadowedRules_PortAliasVendorForms drives the forms a port alias
// member takes on the firewall through parse, convert and the shadow analysis.
// A pass to an alias holding a colon range or a service name sits above a
// block of a port inside it, or an any-port pass sits above a block to such an
// alias: either way the block never takes effect, which is a bypassed deny.
func TestDetectShadowedRules_PortAliasVendorForms(t *testing.T) {
	t.Parallel()

	type variant struct {
		name           string
		content        string
		port0, port1   string
		wantConfidence common.Confidence
	}

	variants := []variant{
		{name: "colon range then single port", content: "443\n8000:8100", port0: "Ports", port1: "8050"},
		{name: "colon range alone", content: "8000:8100", port0: "Ports", port1: "8050"},
		{name: "service names", content: "http\nhttps", port0: "Ports", port1: "443"},
		{name: "service name range", content: "http:https", port0: "Ports", port1: "100"},
		{name: "any port over a colon range", content: "443\n8000:8100", port0: "", port1: "Ports"},
		{
			name:    "a member the analysis cannot read is an advisory",
			content: "8000:8100\nno-such-service",
			port0:   "Ports", port1: "9000",
			wantConfidence: common.ConfidenceLow,
		},
	}

	vendors := []struct {
		name       string
		config     string
		deviceType common.DeviceType
		separator  string
	}{
		{name: "opnsense", config: portAliasOPNsenseConfig, deviceType: common.DeviceTypeOPNsense, separator: "\n"},
		{name: "pfsense", config: portAliasPfSenseConfig, deviceType: common.DeviceTypePfSense, separator: " "},
	}

	for _, vendor := range vendors {
		for _, v := range variants {
			t.Run(vendor.name+"/"+v.name, func(t *testing.T) {
				t.Parallel()

				xmlData := strings.NewReplacer(
					"{{CONTENT}}", strings.ReplaceAll(v.content, "\n", vendor.separator),
					"{{ACTION0}}", "pass",
					"{{ACTION1}}", "block",
					"{{PORT0}}", v.port0,
					"{{PORT1}}", v.port1,
				).Replace(vendor.config)

				device := parsePortAliasDevice(t, xmlData, vendor.deviceType)

				want := common.ConfidenceHigh
				if v.wantConfidence != "" {
					want = v.wantConfidence
				}

				finding, ok := findSecondShadowedByFirst(analysis.DetectShadowedRules(device))
				require.True(t, ok, "the block below the pass must be reported as shadowed")
				assert.Equal(t, common.ImpactClassSecurity, finding.ImpactClass)
				assert.Equal(t, want, finding.Confidence)
			})
		}
	}
}

// TestDetectShadowedRules_PortAliasOutsideRange is the control: a block of a
// port outside the alias's range is not shadowed.
func TestDetectShadowedRules_PortAliasOutsideRange(t *testing.T) {
	t.Parallel()

	xmlData := strings.NewReplacer(
		"{{CONTENT}}", "443\n8000:8100",
		"{{ACTION0}}", "pass",
		"{{ACTION1}}", "block",
		"{{PORT0}}", "Ports",
		"{{PORT1}}", "8101",
	).Replace(portAliasOPNsenseConfig)

	device := parsePortAliasDevice(t, xmlData, common.DeviceTypeOPNsense)

	_, ok := findSecondShadowedByFirst(analysis.DetectShadowedRules(device))
	assert.False(t, ok, "8101 lies outside 8000:8100")
}

// TestDetectShadowedRules_DisabledPortAlias drives a disabled port alias
// through parse, convert and the shadow analysis. OPNsense loads a disabled
// alias with no members, at any depth (filter.lib.inc L153), so a pass to it
// passes nothing and shadows no block. The enabled twin is the control.
func TestDetectShadowedRules_DisabledPortAlias(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		port0       string
		port1       string
		innerEnable string
		outerEnable string
		wantShadow  bool
	}{
		{name: "disabled alias", port0: "Inner", innerEnable: "0", outerEnable: "1"},
		{name: "disabled alias nested in an enabled one", port0: "Outer", innerEnable: "0", outerEnable: "1"},
		{
			name:  "disabled alias above an any-port block",
			port0: "Inner", port1: "any", innerEnable: "0", outerEnable: "0",
		},
		{
			name:  "pass above a block to a disabled alias",
			port0: "8050", port1: "Inner", innerEnable: "0", outerEnable: "0",
		},
		{
			name:  "any-port pass above a block to a disabled alias",
			port0: "any", port1: "Inner", innerEnable: "0", outerEnable: "0",
		},
		{
			name:  "any-port pass above a block to an enabled alias",
			port0: "any", port1: "Inner", innerEnable: "1", outerEnable: "0", wantShadow: true,
		},
		{
			name:        "enabled alias nested in an enabled one",
			port0:       "Outer",
			innerEnable: "1",
			outerEnable: "1",
			wantShadow:  true,
		},
		{name: "enabled alias", port0: "Inner", innerEnable: "1", outerEnable: "0", wantShadow: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			aliases := `<alias uuid="a0000000-0000-4000-8000-000000000001">
            <enabled>` + tt.innerEnable + `</enabled><name>Inner</name><type>port</type>
            <content>8000:8100</content><description>inner</description>
          </alias>
          <alias uuid="a0000000-0000-4000-8000-000000000002">
            <enabled>` + tt.outerEnable + `</enabled><name>Outer</name><type>port</type>
            <content>443
Inner</content><description>outer</description>
          </alias>`

			start := strings.Index(portAliasOPNsenseConfig, "<alias uuid")
			end := strings.Index(portAliasOPNsenseConfig, "</aliases>")
			config := portAliasOPNsenseConfig[:start] + aliases + "\n        " + portAliasOPNsenseConfig[end:]

			xmlData := strings.NewReplacer(
				"{{ACTION0}}", "pass",
				"{{ACTION1}}", "block",
				"{{PORT0}}", portOrAny(tt.port0),
				"{{PORT1}}", portOrAny(cmp.Or(tt.port1, "8050")),
			).Replace(config)

			factory := parser.NewFactory(cfgparser.NewXMLParser())
			device, _, err := factory.CreateDevice(
				context.Background(), strings.NewReader(xmlData), common.DeviceTypeOPNsense, false,
			)
			require.NoError(t, err)
			require.Equal(t, tt.innerEnable == "0", device.NamedObjects["Inner"].Disabled)

			_, ok := findSecondShadowedByFirst(analysis.DetectShadowedRules(device))
			assert.Equal(t, tt.wantShadow, ok)
		})
	}
}

// TestDetectShadowedRules_EmptyPortAlias pins that a block to an enabled
// port alias with no members, which the ruleset does not load, is shadowed by
// nothing, not even an any-port pass.
func TestDetectShadowedRules_EmptyPortAlias(t *testing.T) {
	t.Parallel()

	xmlData := strings.NewReplacer(
		"{{CONTENT}}", "",
		"{{ACTION0}}", "pass",
		"{{ACTION1}}", "block",
		"{{PORT0}}", "",
		"{{PORT1}}", "Ports",
	).Replace(portAliasOPNsenseConfig)

	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, _, err := factory.CreateDevice(
		context.Background(), strings.NewReader(xmlData), common.DeviceTypeOPNsense, false,
	)
	require.NoError(t, err)
	require.Empty(t, device.NamedObjects["Ports"].Members)

	_, ok := findSecondShadowedByFirst(analysis.DetectShadowedRules(device))
	assert.False(t, ok)
}

// portOrAny maps the "any" of a test table to the empty port element, the
// any-port form the filter model writes.
func portOrAny(port string) string {
	if port == "any" {
		return ""
	}

	return port
}

// TestDetectShadowedRules_UnreadablePortWording pins the advisory text when
// the only thing the analysis could not read is a port value: it must name
// the value and not send the reader looking for an alias.
func TestDetectShadowedRules_UnreadablePortWording(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		port0   string
	}{
		{name: "literal rule port", content: "443", port0: "syslog"},
		{name: "alias member", content: "443\nsyslog", port0: "Ports"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			xmlData := strings.NewReplacer(
				"{{CONTENT}}", tt.content,
				"{{ACTION0}}", "pass",
				"{{ACTION1}}", "block",
				"{{PORT0}}", tt.port0,
				"{{PORT1}}", "8050",
			).Replace(portAliasOPNsenseConfig)

			device := parsePortAliasDevice(t, xmlData, common.DeviceTypeOPNsense)

			finding, ok := findSecondShadowedByFirst(analysis.DetectShadowedRules(device))
			require.True(t, ok, "an unreadable port is unknown, not disjoint")
			assert.Equal(t, common.ConfidenceLow, finding.Confidence)
			assert.True(t, strings.HasPrefix(finding.Description, "(unconfirmed, unreadable port value)"))
			assert.NotContains(t, finding.Recommendation, "alias")
		})
	}
}

// TestDetectShadowedRules_MixedCausesNameTheAlias pins that an advisory with
// both an unresolved alias and an unreadable value behind it keeps the alias
// wording: the value text is only for a pair where every alias resolved. The
// alias names itself, which is a cycle, beside a service name the analysis
// does not know. Both paths are covered: the advisory scan, where nothing
// readable overlaps, and a confirmed overlap whose readable part covers the
// block.
func TestDetectShadowedRules_MixedCausesNameTheAlias(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
	}{
		{name: "advisory", content: "syslog\nPorts"},
		{name: "readable part covers the block", content: "8000:8100\nsyslog\nPorts"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			xmlData := strings.NewReplacer(
				"{{CONTENT}}", tt.content,
				"{{ACTION0}}", "pass",
				"{{ACTION1}}", "block",
				"{{PORT0}}", "Ports",
				"{{PORT1}}", "8050",
			).Replace(portAliasOPNsenseConfig)

			device := parsePortAliasDevice(t, xmlData, common.DeviceTypeOPNsense)

			finding, ok := findSecondShadowedByFirst(analysis.DetectShadowedRules(device))
			require.True(t, ok)
			assert.Equal(t, common.ConfidenceLow, finding.Confidence)
			assert.NotContains(t, finding.Description, "unreadable port value")
			assert.Contains(t, finding.Recommendation, "alias")
		})
	}
}

func parsePortAliasDevice(t *testing.T, xmlData string, deviceType common.DeviceType) *common.CommonDevice {
	t.Helper()

	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, _, err := factory.CreateDevice(context.Background(), strings.NewReader(xmlData), deviceType, false)
	require.NoError(t, err)
	require.Len(t, device.FirewallRules, 3)
	require.Contains(t, device.NamedObjects, "Ports")

	return device
}

// findSecondShadowedByFirst returns the finding that the first rule shadows
// the second, the pair every config in this file is built around.
func findSecondShadowedByFirst(findings []common.ShadowedRuleFinding) (common.ShadowedRuleFinding, bool) {
	for _, f := range findings {
		if f.RuleIndex == 1 && f.ShadowedByIndex == 0 {
			return f, true
		}
	}

	return common.ShadowedRuleFinding{}, false
}
