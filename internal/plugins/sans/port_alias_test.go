package sans_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/sans"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	_ "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense" // self-registers the OPNsense parser
	_ "github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"  // self-registers the pfSense parser
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Control outcomes as RunChecks reports them.
const (
	statusFail    = "FAIL"
	statusPass    = "PASS"
	statusUnknown = "UNKNOWN"
)

// sansPortAliasOPNsense is an OPNsense 26.7 config with SSH on, two port
// aliases (Outer names Inner, so a rule to Outer exercises nesting), one pass
// rule in the filter model and one in the legacy store. A rule that does not
// apply is pointed at an unused port on LAN with a specific destination, so it
// trips none of the four controls.
const sansPortAliasOPNsense = `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>fw</hostname><domain>internal</domain>
    <ssh><enabled>enabled</enabled></ssh>
  </system>
  <interfaces>
    <wan><enable>1</enable><if>vtnet0</if><ipaddr>203.0.113.2</ipaddr><subnet>24</subnet></wan>
    <lan><enable>1</enable><if>vtnet1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <filter>
    <rule>
      <type>pass</type><interface>{{LEGACY_IF}}</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><any/></source>
      <destination><address>{{LEGACY_DST}}</address><port>{{LEGACY_PORT}}</port></destination>
      <descr>legacy</descr>
    </rule>
  </filter>
  <OPNsense>
    <Firewall>
      <Alias version="1.0.1">
        <aliases>
          <alias uuid="a0000000-0000-4000-8000-000000000001">
            <enabled>1</enabled><name>Inner</name><type>port</type>
            <content>{{INNER}}</content><description>inner</description>
          </alias>
          <alias uuid="a0000000-0000-4000-8000-000000000002">
            <enabled>1</enabled><name>Outer</name><type>port</type>
            <content>8443
Inner</content><description>outer</description>
          </alias>
        </aliases>
      </Alias>
      <Filter version="1.0.6">
        <rules>
          <rule uuid="b0000000-0000-4000-8000-000000000001">
            <action>pass</action><interface>{{MODEL_IF}}</interface><protocol>TCP</protocol>
            <destination_net>{{MODEL_DST}}</destination_net>
            <destination_port>{{MODEL_PORT}}</destination_port>
            <description>model</description>
          </rule>
        </rules>
      </Filter>
    </Firewall>
  </OPNsense>
</opnsense>`

// sansPortAliasPfSense is the pfSense twin: members separated by spaces in
// <address>, one legacy rule.
const sansPortAliasPfSense = `<?xml version="1.0"?>
<pfsense>
  <version>23.3</version>
  <system><hostname>fw</hostname><domain>internal</domain><ssh><enabled/></ssh></system>
  <interfaces>
    <wan><enable/><if>vtnet0</if><ipaddr>203.0.113.2</ipaddr><subnet>24</subnet></wan>
    <lan><enable/><if>vtnet1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <aliases>
    <alias><name>Inner</name><type>port</type><address>{{INNER}}</address><descr>inner</descr></alias>
    <alias><name>Outer</name><type>port</type><address>8443 Inner</address><descr>outer</descr></alias>
  </aliases>
  <filter>
    <rule>
      <type>pass</type><interface>{{MODEL_IF}}</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><any/></source>
      <destination><{{MODEL_DST_ELEMENT}}</destination>
      <descr>rule</descr><tracker>1</tracker>
    </rule>
  </filter>
</pfsense>`

// sansPortAliasCase places one rule to a port alias and states the outcome of
// each control it bears on. Controls left out of want must be unaffected.
type sansPortAliasCase struct {
	name   string
	inner  string // members of Inner, newline separated
	rule   string // "model" or "legacy": which OPNsense store holds the rule
	iface  string
	dst    string // "any" or an address
	port   string
	want   map[string]string
	vendor string // "" runs on both vendors; "opnsense" only there
}

// TestSANSChecks_ResolvePortAliases drives a rule to a port alias through
// parse, convert and the SANS plugin. Each control must read the alias's
// members, nested aliases and colon ranges included, the way it reads a
// literal port, and leave a port it cannot read undecided rather than pass it.
func TestSANSChecks_ResolvePortAliases(t *testing.T) {
	t.Parallel()

	cases := []sansPortAliasCase{
		{
			name: "telnet alias on WAN", inner: "23", rule: "model", iface: "wan", dst: "any", port: "Inner",
			want: map[string]string{"SANS-FW-014": statusFail, "SANS-FW-015": statusFail},
		},
		{
			name: "telnet among other members", inner: "22\n23", rule: "model", iface: "wan", dst: "any", port: "Inner",
			want: map[string]string{"SANS-FW-014": statusFail, "SANS-FW-015": statusFail},
		},
		{
			name: "telnet through a nested alias", inner: "23", rule: "model", iface: "wan", dst: "any", port: "Outer",
			want: map[string]string{"SANS-FW-014": statusFail, "SANS-FW-015": statusFail},
		},
		{
			name: "telnet by service name", inner: "telnet", rule: "model", iface: "wan", dst: "any", port: "Inner",
			want: map[string]string{"SANS-FW-014": statusFail, "SANS-FW-015": statusFail},
		},
		{
			name: "NetBIOS colon range", inner: "443\n135:139", rule: "model", iface: "wan", dst: "any", port: "Inner",
			want: map[string]string{"SANS-FW-014": statusFail, "SANS-FW-015": statusPass},
		},
		{
			name: "telnet alias in the legacy store", inner: "23", rule: "legacy", iface: "wan", dst: "any",
			port: "Inner", vendor: "opnsense",
			want: map[string]string{"SANS-FW-014": statusFail, "SANS-FW-015": statusFail},
		},
		{
			name: "SMTP alias to any destination", inner: "25\n587", rule: "model", iface: "lan", dst: "any",
			port: "Inner",
			want: map[string]string{"SANS-FW-017": statusFail},
		},
		{
			name: "SMTP alias to a mail server", inner: "25\n587", rule: "model", iface: "lan", dst: "192.168.1.25",
			port: "Inner",
			want: map[string]string{"SANS-FW-017": statusPass},
		},
		{
			name: "DNS alias on WAN from any source", inner: "domain", rule: "model", iface: "wan", dst: "any",
			port: "Inner",
			want: map[string]string{"SANS-FW-020": statusFail},
		},
		{
			name: "harmless alias", inner: "80\n443", rule: "model", iface: "wan", dst: "any", port: "Inner",
			want: map[string]string{
				"SANS-FW-014": statusPass, "SANS-FW-015": statusPass, "SANS-FW-020": statusPass,
			},
		},
		{
			name: "a member that cannot be read leaves the controls undecided", inner: "443\nno-such-service",
			rule: "model", iface: "wan", dst: "any", port: "Inner",
			want: map[string]string{
				"SANS-FW-014": statusUnknown, "SANS-FW-015": statusUnknown,
				"SANS-FW-017": statusUnknown, "SANS-FW-020": statusUnknown,
			},
		},
	}

	for _, vendor := range []string{"opnsense", "pfsense"} {
		for _, tc := range cases {
			if tc.vendor != "" && tc.vendor != vendor {
				continue
			}

			t.Run(vendor+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				device := parseSANSPortAliasDevice(t, vendor, tc)
				got := sansStatuses(t, device)

				for _, id := range []string{"SANS-FW-014", "SANS-FW-015", "SANS-FW-017", "SANS-FW-020"} {
					want, ok := tc.want[id]
					if !ok {
						want = baselineStatus(id)
					}

					assert.Equal(t, want, got[id], id)
				}
			})
		}
	}
}

// baselineStatus is each control's outcome when no rule bears on it: SSH is
// on, so 015 passes; 017 has no SMTP rule to judge.
func baselineStatus(id string) string {
	switch id {
	case "SANS-FW-017":
		return statusUnknown
	default:
		return statusPass
	}
}

func parseSANSPortAliasDevice(t *testing.T, vendor string, tc sansPortAliasCase) *common.CommonDevice {
	t.Helper()

	// The rule not under test points at LAN, a specific host and an unused
	// port, so it bears on no control.
	const idleIf, idleDst, idlePort = "lan", "192.168.1.9", "9999"

	var (
		xmlData    string
		deviceType common.DeviceType
	)

	switch vendor {
	case "opnsense":
		modelIf, modelDst, modelPort := idleIf, idleDst, idlePort
		legacyIf, legacyDst, legacyPort := idleIf, idleDst, idlePort

		if tc.rule == "legacy" {
			legacyIf, legacyDst, legacyPort = tc.iface, tc.dst, tc.port
		} else {
			modelIf, modelDst, modelPort = tc.iface, tc.dst, tc.port
		}

		xmlData = strings.NewReplacer(
			"{{INNER}}", tc.inner,
			"{{MODEL_IF}}", modelIf, "{{MODEL_DST}}", modelDst, "{{MODEL_PORT}}", modelPort,
			"{{LEGACY_IF}}", legacyIf, "{{LEGACY_DST}}", legacyDst, "{{LEGACY_PORT}}", legacyPort,
		).Replace(sansPortAliasOPNsense)
		deviceType = common.DeviceTypeOPNsense
	default:
		dst := "any/>"
		if tc.dst != "any" {
			dst = "address>" + tc.dst + "</address>"
		}

		xmlData = strings.NewReplacer(
			"{{INNER}}", strings.ReplaceAll(tc.inner, "\n", " "),
			"{{MODEL_IF}}", tc.iface,
			"{{MODEL_DST_ELEMENT}}", dst+"<port>"+tc.port+"</port>",
		).Replace(sansPortAliasPfSense)
		deviceType = common.DeviceTypePfSense
	}

	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, _, err := factory.CreateDevice(context.Background(), strings.NewReader(xmlData), deviceType, false)
	require.NoError(t, err)
	require.True(t, device.System.SSH.Enabled)
	require.True(t, slices.ContainsFunc(device.FirewallRules, func(r common.FirewallRule) bool {
		return r.Destination.PortRef != nil && r.Destination.PortRef.Name == tc.port
	}), "the rule under test must keep its alias reference")

	return device
}

func sansStatuses(t *testing.T, device *common.CommonDevice) map[string]string {
	t.Helper()

	findings, evaluated, err := sans.NewPlugin().RunChecks(device)
	require.NoError(t, err)

	statuses := make(map[string]string, len(evaluated))
	for _, id := range []string{"SANS-FW-014", "SANS-FW-015", "SANS-FW-017", "SANS-FW-020"} {
		statuses[id] = statusUnknown
	}

	for _, id := range evaluated {
		statuses[id] = statusPass
	}

	for _, f := range findings {
		statuses[f.Reference] = statusFail
	}

	return statuses
}
