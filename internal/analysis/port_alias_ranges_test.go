package analysis_test

import (
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

				finding, ok := findShadow(analysis.DetectShadowedRules(device), 1, 0)
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

	_, ok := findShadow(analysis.DetectShadowedRules(device), 1, 0)
	assert.False(t, ok, "8101 lies outside 8000:8100")
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

func findShadow(findings []common.ShadowedRuleFinding, rule, by int) (common.ShadowedRuleFinding, bool) {
	for _, f := range findings {
		if f.RuleIndex == rule && f.ShadowedByIndex == by {
			return f, true
		}
	}

	return common.ShadowedRuleFinding{}, false
}
