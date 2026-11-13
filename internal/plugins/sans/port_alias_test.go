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
            <enabled>{{INNER_ENABLED}}</enabled><name>Inner</name><type>port</type>
            <content>{{INNER}}</content><description>inner</description>
          </alias>
          <alias uuid="a0000000-0000-4000-8000-000000000002">
            <enabled>1</enabled><name>Outer</name><type>port</type>
            <content>8443
Inner</content><description>outer</description>
          </alias>
          <alias uuid="a0000000-0000-4000-8000-000000000003">
            <enabled>1</enabled><name>Hosts</name><type>host</type>
            <content>192.168.1.20</content><description>hosts</description>
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
    <alias><name>Hosts</name><type>host</type><address>192.168.1.20</address><descr>hosts</descr></alias>
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
	// innerDisabled disables Inner. Only OPNsense's alias model can.
	innerDisabled bool
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
			name: "disabled telnet alias", inner: "23", rule: "model", iface: "wan", dst: "any", port: "Inner",
			vendor: "opnsense", innerDisabled: true,
			want: map[string]string{"SANS-FW-014": statusPass, "SANS-FW-015": statusPass},
		},
		{
			name: "disabled telnet alias nested", inner: "23", rule: "model", iface: "wan", dst: "any", port: "Outer",
			vendor: "opnsense", innerDisabled: true,
			want: map[string]string{"SANS-FW-014": statusPass, "SANS-FW-015": statusPass},
		},
		{
			name: "telnet beside a cycle", inner: "23\nOuter", rule: "model", iface: "wan", dst: "any", port: "Inner",
			want: map[string]string{
				"SANS-FW-014": statusFail, "SANS-FW-015": statusFail, "SANS-FW-020": statusUnknown,
			},
		},
		{
			name: "telnet beside a host alias", inner: "23\nHosts", rule: "model", iface: "wan", dst: "any",
			port: "Inner",
			want: map[string]string{
				"SANS-FW-014": statusFail, "SANS-FW-015": statusFail, "SANS-FW-020": statusUnknown,
			},
		},
		{
			name: "telnet beside an unknown service name", inner: "23\nsyslog", rule: "model", iface: "wan",
			dst: "any", port: "Inner",
			want: map[string]string{
				"SANS-FW-014": statusFail, "SANS-FW-015": statusFail, "SANS-FW-020": statusUnknown,
			},
		},
		{
			name: "service names are case sensitive", inner: "TELNET", rule: "model", iface: "wan", dst: "any",
			port: "Inner",
			want: map[string]string{
				"SANS-FW-014": statusUnknown, "SANS-FW-015": statusUnknown,
				"SANS-FW-017": statusUnknown, "SANS-FW-020": statusUnknown,
			},
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

func innerEnabled(tc sansPortAliasCase) string {
	if tc.innerDisabled {
		return "0"
	}

	return "1"
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
			"{{INNER_ENABLED}}", innerEnabled(tc),
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

// sansPortLiteralConfig is an OPNsense 26.7 config with two rules in the
// filter model and no aliases, for the controls' reading of literal ports.
const sansPortLiteralConfig = `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>fw</hostname><domain>internal</domain>
    <ssh><enabled>enabled</enabled></ssh>
  </system>
  <interfaces>
    <wan><enable>1</enable><if>vtnet0</if><ipaddr>203.0.113.2</ipaddr><subnet>24</subnet></wan>
    <lan><enable>1</enable><if>vtnet1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <filter/>
  <OPNsense>
    <Firewall>
      <Filter version="1.0.6">
        <rules>
          <rule uuid="b0000000-0000-4000-8000-000000000001">
            <sequence>1</sequence><action>pass</action><interface>{{A_IF}}</interface><protocol>TCP</protocol>
            <source_net>{{A_SRC}}</source_net><source_port>{{A_SPORT}}</source_port>
            <destination_net>{{A_DST}}</destination_net><destination_port>{{A_PORT}}</destination_port>
          </rule>
          <rule uuid="b0000000-0000-4000-8000-000000000002">
            <sequence>2</sequence><action>pass</action><interface>{{B_IF}}</interface><protocol>TCP</protocol>
            <destination_net>{{B_DST}}</destination_net><destination_port>{{B_PORT}}</destination_port>
          </rule>
        </rules>
      </Filter>
    </Firewall>
  </OPNsense>
</opnsense>`

// sansLiteralRule places one rule of sansPortLiteralConfig. Empty fields take
// the idle values, which bear on no control.
type sansLiteralRule struct {
	iface, src, sport, dst, port string
}

// TestSANSChecks_LiteralPorts covers the controls' reading of ports written in
// the rule itself: the source endpoint for SANS-FW-014, the any-source
// condition of SANS-FW-020, every SMTP port of SANS-FW-017, a rule open to
// every port written as a full range, a range that holds the port, a range of
// two service names, and an undecided rule beside a decided one.
func TestSANSChecks_LiteralPorts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b sansLiteralRule
		want map[string]string
	}{
		{
			name: "telnet as the source port on WAN",
			a:    sansLiteralRule{iface: "wan", sport: "23", dst: "any", port: "8443"},
			want: map[string]string{"SANS-FW-014": statusFail},
		},
		{
			name: "DNS on WAN from any source",
			a:    sansLiteralRule{iface: "wan", dst: "any", port: "53"},
			want: map[string]string{"SANS-FW-020": statusFail},
		},
		{
			name: "DNS on WAN from one source",
			a:    sansLiteralRule{iface: "wan", src: "198.51.100.7", dst: "any", port: "53"},
			want: map[string]string{"SANS-FW-020": statusPass},
		},
		{
			name: "a range holding DNS on WAN from any source",
			a:    sansLiteralRule{iface: "wan", dst: "any", port: "50-60"},
			want: map[string]string{"SANS-FW-020": statusFail},
		},
		{
			name: "SMTPS to any destination",
			a:    sansLiteralRule{dst: "any", port: "465"},
			want: map[string]string{"SANS-FW-017": statusFail},
		},
		{
			name: "a range holding telnet and SMTP",
			a:    sansLiteralRule{dst: "any", port: "20-25"},
			want: map[string]string{"SANS-FW-015": statusFail, "SANS-FW-017": statusFail},
		},
		{
			name: "every port written as a range on LAN",
			a:    sansLiteralRule{dst: "any", port: "1-65535"},
			want: map[string]string{},
		},
		{
			name: "every port written from zero on LAN",
			a:    sansLiteralRule{dst: "any", port: "0-65535"},
			want: map[string]string{},
		},
		{
			name: "every port written as a range on WAN still names the dangerous ones",
			a:    sansLiteralRule{iface: "wan", src: "198.51.100.7", dst: "any", port: "1-65535"},
			want: map[string]string{"SANS-FW-014": statusFail},
		},
		{
			name: "a range of two service names on WAN",
			a:    sansLiteralRule{iface: "wan", src: "198.51.100.7", dst: "any", port: "http-https"},
			want: map[string]string{"SANS-FW-014": statusFail},
		},
		{
			name: "a restricted SMTP rule decides SANS-FW-017",
			a:    sansLiteralRule{dst: "192.168.1.25", port: "25"},
			want: map[string]string{"SANS-FW-017": statusPass},
		},
		{
			name: "an unreadable rule to any destination leaves SANS-FW-017 undecided",
			a:    sansLiteralRule{dst: "192.168.1.25", port: "25"},
			b:    sansLiteralRule{dst: "any", port: "syslog"},
			want: map[string]string{"SANS-FW-015": statusUnknown, "SANS-FW-017": statusUnknown},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			idle := func(r sansLiteralRule) sansLiteralRule {
				if r.iface == "" {
					r.iface = "lan"
				}

				if r.src == "" {
					r.src = "any"
				}

				if r.dst == "" {
					r.dst = "192.168.1.9"
				}

				if r.port == "" {
					r.port = "9999"
				}

				return r
			}
			a, b := idle(tt.a), idle(tt.b)

			xmlData := strings.NewReplacer(
				"{{A_IF}}", a.iface, "{{A_SRC}}", a.src, "{{A_SPORT}}", a.sport,
				"{{A_DST}}", a.dst, "{{A_PORT}}", a.port,
				"{{B_IF}}", b.iface, "{{B_DST}}", b.dst, "{{B_PORT}}", b.port,
			).Replace(sansPortLiteralConfig)

			factory := parser.NewFactory(cfgparser.NewXMLParser())
			device, _, err := factory.CreateDevice(
				context.Background(), strings.NewReader(xmlData), common.DeviceTypeOPNsense, false,
			)
			require.NoError(t, err)
			require.Len(t, device.FirewallRules, 2)

			got := sansStatuses(t, device)

			for _, id := range []string{"SANS-FW-014", "SANS-FW-015", "SANS-FW-017", "SANS-FW-020"} {
				want, ok := tt.want[id]
				if !ok {
					want = baselineStatus(id)
				}

				assert.Equal(t, want, got[id], id)
			}
		})
	}
}
