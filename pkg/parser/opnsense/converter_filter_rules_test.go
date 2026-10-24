package opnsense_test

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseFilterRules runs a config through the full parser pipeline. legacy is
// the content of <filter> and model the content of the filter model's <rules>.
func parseFilterRules(t *testing.T, legacy, model string) (*common.CommonDevice, []common.ConversionWarning) {
	t.Helper()

	return parseFilterRulesAt(t, "", legacy, model)
}

// parseFilterRulesAt is parseFilterRules with the filter model at a version.
func parseFilterRulesAt(
	t *testing.T,
	version, legacy, model string,
) (*common.CommonDevice, []common.ConversionWarning) {
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
    <opt1><if>vtnet2</if></opt1>
    <G_IN><if>G_IN</if><type>group</type></G_IN>
    <G_OLD><if>G_OLD</if><type>group</type></G_OLD>
    <openvpn><if>openvpn</if><type>group</type></openvpn>
  </interfaces>
  <ifgroups>
    <ifgroupentry><ifname>G_IN</ifname><members>lan,opt1</members></ifgroupentry>
    <ifgroupentry><ifname>G_OLD</ifname><members>wan opt1</members><sequence>5</sequence></ifgroupentry>
  </ifgroups>
  <aliases>
    <alias><name>WEB_HOST</name><type>host</type><address>192.168.1.50</address></alias>
    <alias><name>DB_HOST</name><type>host</type><address>192.168.1.60</address></alias>
    <alias><name>WEB_PORTS</name><type>port</type><address>8080 8443</address></alias>
    <alias><name>opt1</name><type>network</type><address>10.99.0.0/24</address></alias>
    <alias><name>https</name><type>port</type><address>8443</address></alias>
  </aliases>
  <filter>LEGACY</filter>
  <OPNsense><Firewall><Filter VERSION><rules>MODEL</rules></Filter></Firewall></OPNsense>
</opnsense>`

	attribute := ""
	if version != "" {
		attribute = ` version="` + version + `"`
	}

	config := strings.NewReplacer(" VERSION", attribute, "LEGACY", legacy, "MODEL", model).Replace(configTemplate)

	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, warnings, err := factory.CreateDevice(
		context.Background(),
		strings.NewReader(config),
		common.DeviceTypeUnknown,
		false,
	)
	require.NoError(t, err)
	require.NotNil(t, device)

	return device, warnings
}

// descriptions returns the rules' descriptions in order.
func descriptions(rules []common.FirewallRule) []string {
	names := make([]string, 0, len(rules))
	for _, rule := range rules {
		names = append(names, rule.Description)
	}

	return names
}

// TestParser_FilterRulesFixture drives a config that holds rules in both
// stores through parse and convert. The rules of the firewall filter model
// reached no output before: the schema bound them as one string.
func TestParser_FilterRulesFixture(t *testing.T) {
	t.Parallel()

	device, warnings := parsePortForwardFixture(t, "opnsense-mvc-rules.xml")
	assert.Empty(t, warnings)

	rules := device.FirewallRules
	require.Equal(t, []string{
		// Floating rules, the filter model's by sequence, then the legacy one.
		"Drop the documentation range on every interface",
		"ICMPv6 echo and neighbour solicitation inside",
		"Echo requests on WAN and LAN",
		// Rules on an interface group, ahead of those on one interface though
		// its sequence is higher.
		"Inside may reach the firewall by SSH",
		// The rest, the same way. The empty <rule/> is not a rule.
		"Inside to the servers",
		"Web servers from the internet",
		"DMZ name lookups outside the private ranges",
		"Guest egress block, parked",
		"No remote desktop from outside",
		"Default allow LAN to any rule",
		"DMZ may not reach LAN",
		"Management to the web GUI",
	}, descriptions(rules))

	everywhere := rules[0]
	assert.Equal(t, common.RuleTypeBlock, everywhere.Type)
	assert.Empty(t, everywhere.Interfaces)
	assert.True(t, everywhere.Floating)
	assert.True(t, everywhere.Quick)
	assert.Equal(t, common.IPProtocolInet46, everywhere.IPProtocol)
	assert.Empty(t, everywhere.Protocol)
	assert.Equal(t, common.RuleEndpoint{Address: "192.0.2.0/24"}, everywhere.Source)
	assert.Equal(t, common.RuleEndpoint{Address: "any"}, everywhere.Destination)
	assert.True(t, everywhere.Log)

	icmp := rules[1]
	assert.Equal(t, []string{"lan", "opt1"}, icmp.Interfaces)
	assert.True(t, icmp.Floating)
	assert.False(t, icmp.Quick)
	assert.Equal(t, common.DirectionAny, icmp.Direction)
	assert.Equal(t, common.IPProtocolInet6, icmp.IPProtocol)
	assert.Equal(t, "ipv6-icmp", icmp.Protocol)
	assert.Equal(t, "echoreq,neighbrsol", icmp.ICMP6Type)

	assert.Equal(t, []string{"G_INSIDE"}, rules[3].Interfaces)
	assert.Equal(t, common.RuleEndpoint{Address: "(self)", Port: "22"}, rules[3].Destination)

	lists := rules[4]
	assert.Equal(t, "c3c3c3c3-0000-4000-8000-000000000002", lists.UUID)
	assert.False(t, lists.Floating)
	assert.Equal(t, "tcp/udp", lists.Protocol)
	assert.Equal(t, common.RuleEndpoint{
		Address:     "lan,MGMT_NETS",
		AddressRefs: []common.ObjectRef{{Name: "MGMT_NETS"}},
	}, lists.Source)
	assert.Equal(t, common.RuleEndpoint{
		Address:     "WEB_HOSTS,DB_HOSTS,opt1ip",
		AddressRefs: []common.ObjectRef{{Name: "WEB_HOSTS"}, {Name: "DB_HOSTS"}},
		Port:        "WEB_PORTS",
		PortRef:     &common.ObjectRef{Name: "WEB_PORTS"},
	}, lists.Destination)

	web := rules[5]
	assert.Equal(t, common.RuleTypePass, web.Type)
	assert.Equal(t, []string{"wan"}, web.Interfaces)
	assert.Equal(t, common.DirectionIn, web.Direction)
	assert.Equal(t, common.IPProtocolInet, web.IPProtocol)
	assert.Equal(t, "tcp", web.Protocol)
	assert.Equal(t, "keep state", web.StateType)
	assert.Equal(t, common.RuleEndpoint{
		Address:    "WEB_HOSTS",
		AddressRef: &common.ObjectRef{Name: "WEB_HOSTS"},
		Port:       "443",
	}, web.Destination)

	lookups := rules[6]
	assert.Equal(t, "none", lookups.StateType)
	assert.Equal(t, common.RuleEndpoint{Address: "192.168.0.0/16", Port: "53", Negated: true}, lookups.Destination)

	parked := rules[7]
	assert.True(t, parked.Disabled)
	assert.Equal(t, common.DirectionOut, parked.Direction)

	factory := rules[9]
	assert.Empty(t, factory.UUID)
	assert.False(t, factory.Disabled)
	assert.Equal(t, common.RuleEndpoint{Address: "lan"}, factory.Source)

	// A legacy address can hold a list too.
	assert.Equal(t, common.RuleEndpoint{
		Address:     "MGMT_NETS,LEGACY_PEERS",
		AddressRefs: []common.ObjectRef{{Name: "MGMT_NETS"}, {Name: "LEGACY_PEERS"}},
	}, rules[11].Source)

	assert.Equal(t, []string{"SPARE_HOST"}, unusedAliases(device))
}

// TestConverter_FilterRules_FactoryDefault reads the two rules of the 26.7
// factory default config, which keeps them in the filter model with no uuid and
// leaves <filter> empty.
func TestConverter_FilterRules_FactoryDefault(t *testing.T) {
	t.Parallel()

	const defaults = `<rule>
  <enabled>1</enabled><statetype>keep</statetype><state-policy/><sequence>1</sequence>
  <action>pass</action><quick>1</quick><interfacenot>0</interfacenot><interface>lan</interface>
  <direction>in</direction><ipprotocol>inet</ipprotocol><protocol>any</protocol>
  <source_net>lan</source_net><source_not>0</source_not><source_port/>
  <destination_net>any</destination_net><destination_not>0</destination_not>
  <disablereplyto>0</disablereplyto><log>0</log><allowopts>0</allowopts><nosync>0</nosync>
  <nopfsync>0</nopfsync><statetimeout/><tcpflags_any>0</tcpflags_any>
  <description>Default allow LAN to any rule</description>
</rule>
<rule>
  <enabled>1</enabled><statetype>keep</statetype><state-policy/><sequence>11</sequence>
  <action>pass</action><quick>1</quick><interfacenot>0</interfacenot><interface>lan</interface>
  <direction>in</direction><ipprotocol>inet6</ipprotocol><protocol>any</protocol>
  <source_net>lan</source_net><source_not>0</source_not>
  <destination_net>any</destination_net><destination_not>0</destination_not>
  <disablereplyto>0</disablereplyto><log>0</log><allowopts>0</allowopts><nosync>0</nosync>
  <nopfsync>0</nopfsync><tcpflags_any>0</tcpflags_any>
  <description>Default allow LAN IPv6 to any rule</description>
</rule>`

	device, warnings := parseFilterRules(t, "", defaults)
	assert.Empty(t, warnings)

	want := common.FirewallRule{
		Type:        common.RuleTypePass,
		Description: "Default allow LAN to any rule",
		Interfaces:  []string{"lan"},
		IPProtocol:  common.IPProtocolInet,
		StateType:   "keep state",
		Direction:   common.DirectionIn,
		Quick:       true,
		Source:      common.RuleEndpoint{Address: "lan"},
		Destination: common.RuleEndpoint{Address: "any"},
	}
	wantV6 := want
	wantV6.Description = "Default allow LAN IPv6 to any rule"
	wantV6.IPProtocol = common.IPProtocolInet6

	assert.Equal(t, []common.FirewallRule{want, wantV6}, device.FirewallRules)
}

// TestConverter_FilterRules_MigratedRuleReadsAsItsLegacyTwin takes a rule the
// legacy page saved and the rule OPNsense's migration assistant turns it into.
// The two stores spell values differently, and the same rule has to come out
// the same from both.
func TestConverter_FilterRules_MigratedRuleReadsAsItsLegacyTwin(t *testing.T) {
	t.Parallel()

	legacy, legacyWarnings := parseFilterRules(t, `<rule uuid="f9ca1f04-a1c9-45a8-a0a1-fe4366ffdf17">
  <type>pass</type><interface>wan</interface><ipprotocol>inet</ipprotocol>
  <statetype>keep state</statetype><descr>Allow HTTPS on WAN Address</descr>
  <direction>in</direction><log>1</log><quick>1</quick><protocol>tcp</protocol>
  <source><any>1</any></source>
  <destination><network>wanip</network><port>443</port></destination>
</rule>`, "")

	migrated, migratedWarnings := parseFilterRules(t, "", `<rule uuid="f9ca1f04-a1c9-45a8-a0a1-fe4366ffdf17">
  <enabled>1</enabled><statetype>keep</statetype><state-policy/><sequence>11</sequence>
  <action>pass</action><quick>1</quick><interfacenot>0</interfacenot><interface>wan</interface>
  <direction>in</direction><ipprotocol>inet</ipprotocol><protocol>TCP</protocol>
  <source_net>any</source_net><source_not>0</source_not><source_port/>
  <destination_net>wanip</destination_net><destination_not>0</destination_not>
  <destination_port>443</destination_port><log>1</log>
  <description>Allow HTTPS on WAN Address</description>
</rule>`)

	assert.Empty(t, legacyWarnings)
	assert.Empty(t, migratedWarnings)
	require.Len(t, legacy.FirewallRules, 1)
	assert.Equal(t, legacy.FirewallRules, migrated.FirewallRules)
}

// TestConverter_FilterRules_Defaults covers what a rule means when it leaves an
// element out, and when it holds one that is empty. OPNsense fills an absent
// element from the model and takes an empty one as it is.
func TestConverter_FilterRules_Defaults(t *testing.T) {
	t.Parallel()

	convert := func(t *testing.T, body string) common.FirewallRule {
		t.Helper()

		device, warnings := parseFilterRules(t, "", `<rule>`+body+`</rule>`)
		assert.Empty(t, warnings)
		require.Len(t, device.FirewallRules, 1)

		return device.FirewallRules[0]
	}

	t.Run("a rule with one element takes every default", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, common.FirewallRule{
			Type:        common.RuleTypePass,
			Description: "bare",
			IPProtocol:  common.IPProtocolInet,
			StateType:   "keep state",
			Direction:   common.DirectionIn,
			Floating:    true,
			Quick:       true,
			Source:      common.RuleEndpoint{Address: "any"},
			Destination: common.RuleEndpoint{Address: "any"},
		}, convert(t, `<description>bare</description>`))
	})

	t.Run("enabled", func(t *testing.T) {
		t.Parallel()

		assert.False(t, convert(t, `<enabled>1</enabled>`).Disabled)
		assert.True(t, convert(t, `<enabled>0</enabled>`).Disabled)
		assert.True(t, convert(t, `<enabled/>`).Disabled)
		// The firewall takes anything but nothing and 0 as set.
		assert.False(t, convert(t, `<enabled>2</enabled>`).Disabled)
		assert.False(t, convert(t, `<enabled>false</enabled>`).Disabled)
	})

	t.Run("quick", func(t *testing.T) {
		t.Parallel()

		assert.True(t, convert(t, `<quick>1</quick>`).Quick)
		assert.False(t, convert(t, `<quick>0</quick>`).Quick)
		assert.False(t, convert(t, `<quick/>`).Quick)
		assert.True(t, convert(t, `<quick>off</quick>`).Quick)
		assert.True(t, convert(t, `<interface>lan,wan</interface>`).Quick, "floating rules are quick too")
	})

	t.Run("address family", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, common.IPProtocolInet6, convert(t, `<ipprotocol>inet6</ipprotocol>`).IPProtocol)
		assert.Equal(t, common.IPProtocolInet46, convert(t, `<ipprotocol>inet46</ipprotocol>`).IPProtocol)
		assert.Empty(t, convert(t, `<ipprotocol/>`).IPProtocol, "an empty element names no family")
	})

	t.Run("an empty address drops the port, an absent one keeps it", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t,
			common.RuleEndpoint{Address: "any", Port: "443"},
			convert(t, `<destination_port>443</destination_port>`).Destination)
		assert.Equal(t,
			common.RuleEndpoint{Address: "any"},
			convert(t, `<destination_net/><destination_port>443</destination_port>`).Destination)
		assert.Equal(t,
			common.RuleEndpoint{Address: "any"},
			convert(t, `<source_net/><source_not>1</source_not><source_port>53</source_port>`).Source)
	})

	t.Run("action, direction and flags", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, common.RuleTypePass, convert(t, `<log>0</log><action/>`).Type)
		assert.Equal(t, common.RuleTypeReject, convert(t, `<action>reject</action>`).Type)
		assert.Equal(t, common.DirectionIn, convert(t, `<log>0</log><direction/>`).Direction)
		assert.Equal(t, common.DirectionOut, convert(t, `<direction>out</direction>`).Direction)

		assert.False(t, convert(t, `<quick>1</quick><log/>`).Log)
	})

	t.Run("each flag is read from its own element", func(t *testing.T) {
		t.Parallel()

		elements := []string{"log", "allowopts", "disablereplyto", "nopfsync", "nosync", "tcpflags_any"}
		for i, element := range elements {
			rule := convert(t, `<`+element+`>1</`+element+`>`)
			got := []bool{rule.Log, rule.AllowOpts, rule.DisableReplyTo, rule.NoPfSync, rule.NoSync, rule.TCPFlagsAny}

			want := make([]bool, len(elements))
			want[i] = true
			assert.Equalf(t, want, got, "<%s>", element)
		}
	})

	t.Run("fields carried as they are", func(t *testing.T) {
		t.Parallel()

		rule := convert(t, `<gateway>WAN_GW</gateway><icmptype>echoreq,unreach</icmptype>`+
			`<statetimeout>30</statetimeout><max-src-nodes>10</max-src-nodes><max-src-conn>20</max-src-conn>`+
			`<max-src-conn-rate>15</max-src-conn-rate><max-src-conn-rates>5</max-src-conn-rates>`+
			`<tag>out</tag><tagged>in</tagged><tcpflags1>syn</tcpflags1><tcpflags2>syn,ack</tcpflags2>`)
		assert.Equal(t, "WAN_GW", rule.Gateway)
		assert.Equal(t, "echoreq,unreach", rule.ICMPType)
		assert.Equal(t, "30", rule.StateTimeout)
		assert.Equal(t, "10", rule.MaxSrcNodes)
		assert.Equal(t, "20", rule.MaxSrcConn)
		assert.Equal(t, "15", rule.MaxSrcConnRate)
		assert.Equal(t, "5", rule.MaxSrcConnRates)
		assert.Equal(t, "out", rule.Tag)
		assert.Equal(t, "in", rule.Tagged)
		assert.Equal(t, "syn", rule.TCPFlags1)
		assert.Equal(t, "syn,ack", rule.TCPFlags2)
	})
}

// TestConverter_FilterRules_Vocabulary covers the values the filter model
// spells differently from the legacy store. They are converted to the legacy
// spelling, which is the one the checks read.
func TestConverter_FilterRules_Vocabulary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		got  func(common.FirewallRule) string
		want string
	}{
		{"state keep", `<statetype>keep</statetype>`, stateOf, "keep state"},
		{"state absent", ``, stateOf, "keep state"},
		{"state empty", `<statetype/>`, stateOf, "keep state"},
		{"state sloppy", `<statetype>sloppy</statetype>`, stateOf, "sloppy state"},
		{"state modulate", `<statetype>modulate</statetype>`, stateOf, "modulate state"},
		{"state synproxy", `<statetype>synproxy</statetype>`, stateOf, "synproxy state"},
		{"state none", `<statetype>none</statetype>`, stateOf, "none"},
		{"state unknown", `<statetype>later</statetype>`, stateOf, "later"},
		{"protocol upper case", `<protocol>TCP</protocol>`, protocolOf, "tcp"},
		{"protocol pair", `<protocol>TCP/UDP</protocol>`, protocolOf, "tcp/udp"},
		{"protocol any", `<protocol>any</protocol>`, protocolOf, ""},
		{"protocol absent", ``, protocolOf, ""},
		{"icmp6 numbers", `<icmp6type>1,128,201</icmp6type>`, icmp6Of, "unreach,echoreq,mtrace"},
		{"icmp6 number without a name", `<icmp6type>133,250</icmp6type>`, icmp6Of, "routersol,250"},
		{"icmp6 absent", ``, icmp6Of, ""},
		{"port number", `<destination_port>8080</destination_port>`, portOf, "8080"},
		{"port range", `<destination_port>8080-8090</destination_port>`, portOf, "8080-8090"},
		{"port service name", `<destination_port>https</destination_port>`, portOf, "443"},
		{"port service name in upper case", `<destination_port>SSH</destination_port>`, portOf, "22"},
		{"port alias", `<destination_port>WEB_PORTS</destination_port>`, portOf, "WEB_PORTS"},
		{"port name that is neither", `<destination_port>gopher</destination_port>`, portOf, "gopher"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, warnings := parseFilterRules(t, "", `<rule><description>x</description>`+tt.body+`</rule>`)
			assert.Empty(t, warnings)
			require.Len(t, device.FirewallRules, 1)
			assert.Equal(t, tt.want, tt.got(device.FirewallRules[0]))
		})
	}

	t.Run("a service name wins over an alias of that name", func(t *testing.T) {
		t.Parallel()

		device, _ := parseFilterRules(t, "",
			`<rule><sequence>1</sequence><destination_port>https</destination_port></rule>`+
				`<rule><sequence>2</sequence><destination_port>WEB_PORTS</destination_port></rule>`)
		require.Len(t, device.FirewallRules, 2)
		assert.Equal(t, common.RuleEndpoint{Address: "any", Port: "443"}, device.FirewallRules[0].Destination)
		assert.Equal(t, &common.ObjectRef{Name: "WEB_PORTS"}, device.FirewallRules[1].Destination.PortRef)
	})
}

func stateOf(rule common.FirewallRule) string    { return rule.StateType }
func protocolOf(rule common.FirewallRule) string { return rule.Protocol }
func icmp6Of(rule common.FirewallRule) string    { return rule.ICMP6Type }
func portOf(rule common.FirewallRule) string     { return rule.Destination.Port }

// TestConverter_FilterRules_Scope covers the interfaces a rule applies on. The
// filter model has no floating element: a rule floats when it names no single
// interface, and a rule that names none applies on all of them.
func TestConverter_FilterRules_Scope(t *testing.T) {
	t.Parallel()

	const (
		interfacePath = "FirewallRules[0].Interface"
		excluded      = `<interfacenot>1</interfacenot>`
	)

	tests := []struct {
		name           string
		body           string
		wantInterfaces []string
		wantFloating   bool
		wantDisabled   bool
		wantWarning    common.Severity
	}{
		{"no interface", ``, nil, true, false, ""},
		{"empty interface", `<interface/>`, nil, true, false, ""},
		{"one interface", `<interface>lan</interface>`, []string{"lan"}, false, false, ""},
		{"one group", `<interface>G_IN</interface>`, []string{"G_IN"}, false, false, ""},
		{"several interfaces", `<interface>lan,opt1</interface>`, []string{"lan", "opt1"}, true, false, ""},
		{"an empty entry", `<interface>lan,</interface>`, nil, true, false, common.SeverityMedium},
		{
			"an empty entry beside one not defined",
			`<interface>opt9,</interface>`,
			nil, true, false, common.SeverityMedium,
		},
		// The firewall does not load a rule on no interface it knows.
		{"not defined", `<interface>opt9</interface>`, []string{"opt9"}, false, true, common.SeverityMedium},
		{"one of several not defined", `<interface>lan,opt9</interface>`, []string{"lan", "opt9"}, true, false, ""},
		// A group that holds the excluded interface is left out: the rule does
		// not apply on all of it.
		{
			"every interface but one",
			`<interface>wan</interface>` + excluded,
			[]string{"G_IN", "lan", "openvpn", "opt1"},
			true, false, common.SeverityLow,
		},
		{
			"every interface outside a group",
			`<interface>G_IN</interface>` + excluded,
			[]string{"openvpn", "wan"},
			true, false, common.SeverityLow,
		},
		{
			"every interface outside a group whose members are separated by spaces",
			`<interface>G_OLD</interface>` + excluded,
			[]string{"lan", "openvpn"},
			true, false, common.SeverityLow,
		},
		{
			"every interface outside a group whose members are not in the config",
			`<interface>openvpn</interface>` + excluded,
			[]string{"G_IN", "G_OLD", "lan", "opt1", "wan"},
			true, false, common.SeverityMedium,
		},
		{"several excluded", `<interface>lan,wan</interface>` + excluded, nil, true, false, common.SeverityMedium},
		{"exclusion without an interface", excluded, nil, true, false, ""},
		{
			"exclusion of one not defined",
			`<interface>opt9</interface>` + excluded,
			[]string{"opt9"},
			true, true, common.SeverityMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, warnings := parseFilterRules(t, "", `<rule><description>x</description>`+tt.body+`</rule>`)
			require.Len(t, device.FirewallRules, 1)
			assert.Equal(t, tt.wantInterfaces, device.FirewallRules[0].Interfaces)
			assert.Equal(t, tt.wantFloating, device.FirewallRules[0].Floating)
			assert.Equal(t, tt.wantDisabled, device.FirewallRules[0].Disabled)

			if tt.wantWarning == "" {
				assert.Empty(t, warnings)

				return
			}

			require.Len(t, warnings, 1)
			assert.Equal(t, interfacePath, warnings[0].Field)
			assert.Equal(t, tt.wantWarning, warnings[0].Severity)
		})
	}
}

// TestConverter_FilterRules_ExcludesEveryInterface covers a rule that excludes
// the only interface the config defines. It has no interface left, and a rule
// with no interface reads as a rule on all of them, so it is reported as
// disabled instead.
func TestConverter_FilterRules_ExcludesEveryInterface(t *testing.T) {
	t.Parallel()

	device, warnings, err := opnsense.ConvertDocument(filterModelDocument(schema.FirewallFilterRule{
		Interface:    "wan",
		InterfaceNot: "1",
	}))
	require.NoError(t, err)
	require.Len(t, device.FirewallRules, 1)
	assert.Empty(t, device.FirewallRules[0].Interfaces)
	assert.True(t, device.FirewallRules[0].Disabled)

	require.Len(t, warnings, 1)
	assert.Equal(t, "FirewallRules[0].Interface", warnings[0].Field)
	assert.Equal(t, "wan", warnings[0].Value)
	assert.Equal(t, common.SeverityMedium, warnings[0].Severity)
}

// TestConverter_FilterRules_Endpoints covers the address element of the filter
// model when it holds one value: an alias, an interface name or an address.
func TestConverter_FilterRules_Endpoints(t *testing.T) {
	t.Parallel()

	web := &common.ObjectRef{Name: "WEB_HOST"}

	tests := []struct {
		name string
		body string
		want common.RuleEndpoint
	}{
		{"any", `<source_net>any</source_net>`, common.RuleEndpoint{Address: "any"}},
		{"an address", `<source_net>10.1.2.0/24</source_net>`, common.RuleEndpoint{Address: "10.1.2.0/24"}},
		{"an interface", `<source_net>lan</source_net>`, common.RuleEndpoint{Address: "lan"}},
		{"an interface address", `<source_net>lanip</source_net>`, common.RuleEndpoint{Address: "lanip"}},
		{"an alias", `<source_net>WEB_HOST</source_net>`, common.RuleEndpoint{Address: "WEB_HOST", AddressRef: web}},
		{
			"a name that is an interface and an alias is the alias",
			`<source_net>opt1</source_net>`,
			common.RuleEndpoint{Address: "opt1", AddressRef: &common.ObjectRef{Name: "opt1"}},
		},
		{
			"negation",
			`<source_net>WEB_HOST</source_net><source_not>1</source_not>`,
			common.RuleEndpoint{Address: "WEB_HOST", AddressRef: web, Negated: true},
		},
		{
			"negation by a flag that is not 0 or 1",
			`<source_net>WEB_HOST</source_net><source_not>no</source_not>`,
			common.RuleEndpoint{Address: "WEB_HOST", AddressRef: web, Negated: true},
		},
		{
			"negation of any is ignored",
			`<source_net>any</source_net><source_not>1</source_not>`,
			common.RuleEndpoint{Address: "any"},
		},
		{"negation of an absent address is ignored", `<source_not>1</source_not>`, common.RuleEndpoint{Address: "any"}},
		{
			"the port stays with the address",
			`<source_net>lan</source_net><source_port>WEB_PORTS</source_port>`,
			common.RuleEndpoint{Address: "lan", Port: "WEB_PORTS", PortRef: &common.ObjectRef{Name: "WEB_PORTS"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, warnings := parseFilterRules(t, "", `<rule><interface>lan</interface>`+tt.body+`</rule>`)
			assert.Empty(t, warnings)
			require.Len(t, device.FirewallRules, 1)
			assert.Equal(t, tt.want, device.FirewallRules[0].Source)
		})
	}
}

// TestConverter_FilterRules_EndpointLists covers an address element that holds
// several values. The firewall writes one rule for each, so the list matches
// all of them, and a list that holds any is reported as any. A negated list
// keeps its negation. The firewall negates each entry, so it matches every
// address outside the entries' overlap, all of them when the entries do not
// overlap; the checks for wide-open rules read it as any (analysis.IsAnyEndpoint).
func TestConverter_FilterRules_EndpointLists(t *testing.T) {
	t.Parallel()

	const sourcePath = "FirewallRules[0].Source"

	both := []common.ObjectRef{{Name: "WEB_HOST"}, {Name: "DB_HOST"}}

	tests := []struct {
		name        string
		body        string
		want        common.RuleEndpoint
		wantWarning bool
	}{
		{
			"a list",
			`<source_net>WEB_HOST, lan,DB_HOST,(self)</source_net>`,
			common.RuleEndpoint{Address: "WEB_HOST,lan,DB_HOST,(self)", AddressRefs: both},
			false,
		},
		{
			"a list without an alias",
			`<source_net>lan,wanip</source_net>`,
			common.RuleEndpoint{Address: "lan,wanip"},
			false,
		},
		{"a list that holds any", `<source_net>lan,any</source_net>`, common.RuleEndpoint{Address: "any"}, true},
		{"a list with an empty entry", `<source_net>10.0.0.5,</source_net>`, common.RuleEndpoint{Address: "any"}, true},
		{
			"a list that holds every IPv4 address",
			`<source_net>0.0.0.0/0,WEB_HOST</source_net>`,
			common.RuleEndpoint{Address: "any", AddressRefs: both[:1]},
			true,
		},
		{
			"a list that holds every IPv6 address",
			`<source_net>lan,::/0</source_net>`,
			common.RuleEndpoint{Address: "any"},
			true,
		},
		{
			"negation of a list",
			`<source_net>WEB_HOST,DB_HOST</source_net><source_not>1</source_not>`,
			common.RuleEndpoint{Address: "WEB_HOST,DB_HOST", Negated: true, AddressRefs: both},
			true,
		},
		{
			"negation of a list that holds any, which the firewall does not negate",
			`<source_net>lan,any</source_net><source_not>1</source_not>`,
			common.RuleEndpoint{Address: "any"},
			true,
		},
		{
			"negation of a list that holds every IPv4 address, which it does",
			`<source_net>0.0.0.0/0,WEB_HOST</source_net><source_not>1</source_not>`,
			common.RuleEndpoint{Address: "0.0.0.0/0,WEB_HOST", Negated: true, AddressRefs: both[:1]},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, warnings := parseFilterRules(t, "", `<rule><interface>lan</interface>`+tt.body+`</rule>`)
			require.Len(t, device.FirewallRules, 1)
			assert.Equal(t, tt.want, device.FirewallRules[0].Source)

			if !tt.wantWarning {
				assert.Empty(t, warnings)

				return
			}

			require.Len(t, warnings, 1)
			assert.Equal(t, sourcePath, warnings[0].Field)
			assert.Equal(t, common.SeverityMedium, warnings[0].Severity)
		})
	}

	t.Run("the destination is read the same way, and its aliases stay in use", func(t *testing.T) {
		t.Parallel()

		device, warnings := parseFilterRules(t, "", `<rule><interface>lan</interface>`+
			`<destination_net>WEB_HOST,DB_HOST</destination_net><destination_not>1</destination_not></rule>`)
		require.Len(t, device.FirewallRules, 1)
		assert.Equal(t, common.RuleEndpoint{Address: "WEB_HOST,DB_HOST", Negated: true, AddressRefs: both},
			device.FirewallRules[0].Destination)
		require.Len(t, warnings, 1)
		assert.Equal(t, "FirewallRules[0].Destination", warnings[0].Field)
		assert.Equal(t, []string{"WEB_PORTS", "https", "opt1"}, unusedAliases(device))
	})
}

// TestConverter_FilterRules_LegacyAddressList covers a list in the <address> of
// a rule under <filter>. Its aliases had no reference, so each was reported as
// unused.
func TestConverter_FilterRules_LegacyAddressList(t *testing.T) {
	t.Parallel()

	device, warnings := parseFilterRules(t, `<rule><type>pass</type><interface>lan</interface>
  <source><address>WEB_HOST,DB_HOST</address></source>
  <destination><address>WEB_HOST</address><port>WEB_PORTS</port></destination>
</rule>
<rule><type>pass</type><interface>lan</interface>
  <source><any>1</any></source>
  <destination><address>DB_HOST,WEB_HOST</address></destination>
</rule>`, "")
	assert.Empty(t, warnings)
	require.Len(t, device.FirewallRules, 2)

	assert.Equal(t, common.RuleEndpoint{
		Address:     "WEB_HOST,DB_HOST",
		AddressRefs: []common.ObjectRef{{Name: "WEB_HOST"}, {Name: "DB_HOST"}},
	}, device.FirewallRules[0].Source)
	assert.Equal(t, common.RuleEndpoint{
		Address:    "WEB_HOST",
		AddressRef: &common.ObjectRef{Name: "WEB_HOST"},
		Port:       "WEB_PORTS",
		PortRef:    &common.ObjectRef{Name: "WEB_PORTS"},
	}, device.FirewallRules[0].Destination)
	assert.Equal(t, common.RuleEndpoint{
		Address:     "DB_HOST,WEB_HOST",
		AddressRefs: []common.ObjectRef{{Name: "DB_HOST"}, {Name: "WEB_HOST"}},
	}, device.FirewallRules[1].Destination)
	assert.Equal(t, []string{"https", "opt1"}, unusedAliases(device))
}

// modelRuleXML returns a rule of the filter model. A sequence of "-" leaves the
// element out, and an empty uuid the attribute.
func modelRuleXML(description, sequence, uuid, body string) string {
	rule := `<rule`
	if uuid != "" {
		rule += ` uuid="` + uuid + `"`
	}

	rule += `><description>` + description + `</description>` + body
	if sequence != "-" {
		rule += `<sequence>` + sequence + `</sequence>`
	}

	return rule + `</rule>`
}

// legacyRuleXML returns a pass rule on lan as <filter> holds it.
func legacyRuleXML(description, body string) string {
	return legacyRuleOnXML(description, "lan", body)
}

// legacyRuleOnXML returns a pass rule on an interface as <filter> holds it.
func legacyRuleOnXML(description, iface, body string) string {
	return `<rule><type>pass</type><interface>` + iface + `</interface><descr>` + description + `</descr>` +
		`<source><any>1</any></source><destination><any>1</any></destination>` + body + `</rule>`
}

// TestConverter_FilterRules_Order covers the order of the rule list, which is
// the order the firewall evaluates the rules in and the only order the checks
// see.
//
//nolint:funlen // test table; length is in data not logic
func TestConverter_FilterRules_Order(t *testing.T) {
	t.Parallel()

	const onLAN = `<interface>lan</interface>`

	model, legacy, legacyOn := modelRuleXML, legacyRuleXML, legacyRuleOnXML

	// More rules than a sort keeps in order by accident.
	// Rules without a uuid in two alternating sequences, enough of them that
	// only a stable sort keeps each sequence in document order.
	var (
		unnumbered            strings.Builder
		firstNames, lastNames []string
	)

	for i := range 40 {
		name := "n" + strconv.Itoa(i)
		if i%2 == 0 {
			unnumbered.WriteString(model(name, "2", "", onLAN))
			lastNames = append(lastNames, name)
		} else {
			unnumbered.WriteString(model(name, "1", "", onLAN))
			firstNames = append(firstNames, name)
		}
	}

	tests := []struct {
		name   string
		legacy string
		model  string
		want   []string
	}{
		{
			name:  "by sequence, not document order",
			model: model("c", "300", "u3", onLAN) + model("a", "100", "u1", onLAN) + model("b", "200", "u2", onLAN),
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "sequences compare as numbers",
			model: model("b", "1000", "u1", onLAN) + model("a", "200", "u2", onLAN),
			want:  []string{"a", "b"},
		},
		{
			name: "sequences of one length",
			model: model("c", "534", "u1", onLAN) + model("b", "247", "u2", onLAN) +
				model("a", "19", "u3", onLAN) + model("d", "921", "u4", onLAN),
			want: []string{"a", "b", "c", "d"},
		},
		{
			name: "equal sequences go by uuid",
			model: model("b", "1", "f3aa1c2e-0000-4000-8000-000000000001", onLAN) +
				model("a", "1", "1a2b3c4d-0000-4000-8000-000000000001", onLAN),
			want: []string{"a", "b"},
		},
		{
			name: "a uuid's digits compare as a number",
			model: model("b", "1", "10aa1c2e-0000-4000-8000-000000000001", onLAN) +
				model("a", "1", "2a2b3c4d-0000-4000-8000-000000000001", onLAN),
			want: []string{"a", "b"},
		},
		{
			name:  "a rule without a sequence has sequence 1",
			model: model("b", "2", "u1", onLAN) + model("a", "-", "u2", onLAN),
			want:  []string{"a", "b"},
		},
		{
			// The firewall gives each a random uuid as it loads them, so their
			// order there is not fixed; document order stands in for it.
			name:  "rules without a uuid stay in document order within a sequence",
			model: unnumbered.String(),
			want:  append(firstNames, lastNames...),
		},
		{
			name: "a sequence that is not a number sorts next to the number it starts with",
			model: model("d", "11", "u4", onLAN) + model("c", "10a", "u3", onLAN) +
				model("b", "10", "u2", onLAN) + model("a", "9", "u1", onLAN),
			want: []string{"a", "b", "c", "d"},
		},
		// PHP reads a sequence with whitespace around it, or a sign, as a
		// number, and OPNsense saves it as typed.
		{
			name:  "a sequence with leading whitespace is the same number",
			model: model("b", " 100", "u2", onLAN) + model("a", "100", "u1", onLAN),
			want:  []string{"a", "b"},
		},
		{
			name:  "a sequence with trailing whitespace sorts ahead of the same number without it",
			model: model("b", "100", "u1", onLAN) + model("a", "100 ", "u2", onLAN),
			want:  []string{"a", "b"},
		},
		{
			name:  "and ahead of the same number with leading whitespace",
			model: model("b", " 100", "u1", onLAN) + model("a", "100 ", "u2", onLAN),
			want:  []string{"a", "b"},
		},
		{
			name:  "a signed sequence sorts ahead of every unsigned one",
			model: model("b", "50", "u1", onLAN) + model("a", "+100", "u2", onLAN),
			want:  []string{"a", "b"},
		},
		{
			name:  "an empty entry is not a rule",
			model: `<rule/>` + model("a", "100", "u1", onLAN) + `<rule uuid="u2"/>`,
			want:  []string{"a"},
		},
		{
			name:   "the filter model's rules come before the legacy ones",
			legacy: legacy("c", "") + legacy("d", ""),
			model:  model("b", "200", "u2", onLAN) + model("a", "100", "u1", onLAN),
			want:   []string{"a", "b", "c", "d"},
		},
		{
			name: "floating rules of both stores come before the rest",
			legacy: legacy("e", "") + legacy("c", `<floating>yes</floating>`) +
				legacy("d", `<floating>1</floating>`) + legacy("f", ""),
			model: model("g", "100", "u1", onLAN) + model("a", "200", "u2", "") +
				model("b", "300", "u3", `<interface>lan,opt1</interface>`),
			want: []string{"a", "b", "c", "d", "g", "e", "f"},
		},
		{
			name:   "legacy rules alone keep document order",
			legacy: legacy("a", "") + legacy("b", "") + legacy("c", ""),
			want:   []string{"a", "b", "c"},
		},
		{
			// G_IN stores no sequence and G_OLD stores 5.
			name:   "rules on an interface group come after the floating ones, by the group's sequence",
			legacy: legacy("g", "") + legacyOn("e", "G_OLD", "") + legacyOn("c", "G_IN", ""),
			model: model("f", "50", "u1", onLAN) + model("d", "100", "u2", `<interface>G_OLD</interface>`) +
				model("b", "300", "u3", `<interface>G_IN</interface>`) +
				model("a", "400", "u4", `<interface>wan,lan</interface>`),
			want: []string{"a", "b", "c", "d", "e", "f", "g"},
		},
		{
			// The filter model goes by the interface's type, the legacy store
			// by <ifgroups>, which does not list the built-in openvpn group.
			name:   "a group <ifgroups> does not list ranks only the filter model's rules as a group",
			legacy: legacyOn("d", "openvpn", "") + legacyOn("b", "G_IN", ""),
			model:  model("c", "100", "u1", onLAN) + model("a", "200", "u2", `<interface>openvpn</interface>`),
			want:   []string{"a", "b", "c", "d"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, warnings := parseFilterRules(t, tt.legacy, tt.model)
			assert.Empty(t, warnings)
			assert.Equal(t, tt.want, descriptions(device.FirewallRules))
		})
	}

	// These rules also draw a warning, which TestConverter_FilterRules_Scope
	// and TestConverter_FilterRules_UnrepresentedElements cover.
	warned := []struct {
		name   string
		legacy string
		model  string
		want   []string
	}{
		{
			name:   "a rule on no interface the config defines comes last",
			legacy: legacy("b", ""),
			model:  model("c", "1", "u1", `<interface>opt9</interface>`) + model("a", "2", "u2", onLAN),
			want:   []string{"a", "b", "c"},
		},
		{
			name:   "as does one received on no interface the config defines",
			legacy: legacy("b", ""),
			model:  model("c", "1", "u1", onLAN+`<received-on>opt9</received-on>`) + model("a", "2", "u2", onLAN),
			want:   []string{"a", "b", "c"},
		},
		{
			name: "an interface list with an empty entry ranks by its other entries",
			model: model(
				"b",
				"1",
				"u1",
				`<interface>lan,</interface>`,
			) + model(
				"a",
				"2",
				"u2",
				`<interface>lan,opt1</interface>`,
			),
			want: []string{"a", "b"},
		},
	}

	for _, tt := range warned {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, warnings := parseFilterRules(t, tt.legacy, tt.model)
			assert.NotEmpty(t, warnings)
			assert.Equal(t, tt.want, descriptions(device.FirewallRules))
		})
	}

	// Only the os-firewall plugin wrote versions 1.0.0 to 1.0.2. It ranked a
	// list of interfaces, then a group, then the rest, which includes a rule
	// on no interface, all ahead of the legacy rules. The core shares 1.0.3
	// between releases that ranked either way, and orders it as 26.7.2 does.
	byVersion := []struct {
		version string
		want    []string
	}{
		{"1.0.0", []string{"a", "b", "c", "d", "e", "f"}},
		{"1.0.1", []string{"a", "b", "c", "d", "e", "f"}},
		{"1.0.2", []string{"a", "b", "c", "d", "e", "f"}},
		{"1.0.3", []string{"a", "d", "e", "b", "c", "f"}},
	}

	for _, tt := range byVersion {
		t.Run("ranked as model version "+tt.version+" was", func(t *testing.T) {
			t.Parallel()

			device, warnings := parseFilterRulesAt(t, tt.version,
				legacy("e", `<floating>yes</floating>`)+legacy("f", ""),
				model("c", "1", "u1", onLAN)+model("a", "3", "u2", `<interface>lan,opt1</interface>`)+
					model("b", "2", "u3", `<interface>G_IN</interface>`)+model("d", "4", "u4", ""))
			assert.Empty(t, warnings)
			assert.Equal(t, tt.want, descriptions(device.FirewallRules))
		})
	}

	t.Run("no rule in either store", func(t *testing.T) {
		t.Parallel()

		device, warnings := parseFilterRules(t, "", "")
		assert.Empty(t, warnings)
		assert.Nil(t, device.FirewallRules)
	})
}

// TestConverter_FilterRules_ModelVersion covers the version of the filter model.
// A version this converter has not been checked against may name the rule
// elements differently, so it draws a warning, but only when there are rules.
func TestConverter_FilterRules_ModelVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		version string
		rules   bool
		warns   bool
	}{
		{"no version, as the factory default writes", "", true, false},
		{"one checked", "1.0.4", true, false},
		{"the latest checked", "1.0.6", true, false},
		{"one not checked", "1.0.9", true, true},
		{"one not checked, without rules", "1.0.9", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := filterModelDocument(schema.FirewallFilterRule{Interface: "wan"})
			doc.OPNsense.Firewall.Filter.Version = tt.version

			if !tt.rules {
				doc.OPNsense.Firewall.Filter.Rules = nil
			}

			_, warnings, err := opnsense.ConvertDocument(doc)
			require.NoError(t, err)

			if !tt.warns {
				assert.Empty(t, warnings)

				return
			}

			require.Len(t, warnings, 1)
			assert.Equal(t, "OPNsense.Firewall.Filter.Version", warnings[0].Field)
			assert.Equal(t, tt.version, warnings[0].Value)
			assert.Equal(t, common.SeverityMedium, warnings[0].Severity)
		})
	}
}

// TestConverter_FilterRules_UnrepresentedElements covers the elements of a rule
// that narrow what it matches or change what happens to the traffic but have no
// field in the common rule. Each one set draws a warning, so the report does not
// silently show the rule as broader than it is.
func TestConverter_FilterRules_UnrepresentedElements(t *testing.T) {
	t.Parallel()

	t.Run("each one set warns", func(t *testing.T) {
		t.Parallel()

		device, warnings := parseFilterRules(t, "", `<rule><interface>lan</interface><direction>out</direction>`+
			`<received-on>wan,opt9</received-on><tos>0x10</tos><prio>3</prio><sched>office</sched>`+
			`<max-pkt-rate-number>100</max-pkt-rate-number><max-pkt-rate-seconds>10</max-pkt-rate-seconds>`+
			`<divert-to>suricata</divert-to><replyto>WAN_GW</replyto><set-prio>5</set-prio></rule>`)
		require.Len(t, device.FirewallRules, 1)
		assert.False(t, device.FirewallRules[0].Disabled)

		type warning struct{ field, value string }

		got := make([]warning, 0, len(warnings))
		for _, w := range warnings {
			assert.Equal(t, common.SeverityMedium, w.Severity)
			got = append(got, warning{w.Field, w.Value})
		}

		assert.Equal(t, []warning{
			{"FirewallRules[0].ReceivedOn", "wan,opt9"},
			{"FirewallRules[0].TOS", "0x10"},
			{"FirewallRules[0].Prio", "3"},
			{"FirewallRules[0].MaxPktRateNumber", "100/10"},
			{"FirewallRules[0].Sched", "office"},
			{"FirewallRules[0].DivertTo", "suricata"},
			{"FirewallRules[0].ReplyTo", "WAN_GW"},
		}, got)
	})

	t.Run("a packet rate needs both parts, as on the firewall", func(t *testing.T) {
		t.Parallel()

		for _, body := range []string{
			`<max-pkt-rate-number>100</max-pkt-rate-number>`,
			`<max-pkt-rate-number>100</max-pkt-rate-number><max-pkt-rate-seconds>0</max-pkt-rate-seconds>`,
			`<max-pkt-rate-seconds>10</max-pkt-rate-seconds>`,
		} {
			_, warnings := parseFilterRules(t, "", `<rule><interface>lan</interface>`+body+`</rule>`)
			assert.Empty(t, warnings, body)
		}
	})

	// received-on is written out once for each entry, as <interface> is.
	receivedOn := []struct {
		name         string
		body         string
		wantDisabled bool
		wantMessage  string
	}{
		{
			"one interface",
			`<received-on>wan</received-on>`,
			false, "the rule only matches traffic that arrived on these interfaces, which is not reported",
		},
		{
			"one interface, negated",
			`<received-on>wan</received-on><received-on-not>1</received-on-not>`,
			false, "the rule only matches traffic that did not arrive on this interface, which is not reported",
		},
		{
			"several interfaces, negated, which together exclude nothing",
			`<received-on>wan,opt1</received-on><received-on-not>1</received-on-not>`,
			false,
			"received-on-not is applied to each interface on its own, so the rule matches traffic from any interface",
		},
		{
			// The firewall drops the copy on the undefined interface.
			"one defined interface and one not, negated",
			`<received-on>wan,opt9</received-on><received-on-not>1</received-on-not>`,
			false, "the rule only matches traffic that did not arrive on this interface, which is not reported",
		},
		{
			"one interface named twice, negated",
			`<received-on>wan,wan</received-on><received-on-not>1</received-on-not>`,
			false, "the rule only matches traffic that did not arrive on this interface, which is not reported",
		},
		{
			"no interface the config defines, which keeps the rule from loading",
			`<received-on>opt9</received-on><tos>0x10</tos>`,
			true, "no interface the rule's received-on names is defined, so the firewall does not load it; " +
				"it is reported as disabled",
		},
		{
			"an empty entry beside one not defined, which the firewall loads unrestricted",
			`<received-on>opt9,</received-on>`,
			false, "received-on list has an empty entry, which the firewall matches on traffic from any interface",
		},
	}

	for _, tt := range receivedOn {
		t.Run("received-on: "+tt.name, func(t *testing.T) {
			t.Parallel()

			device, warnings := parseFilterRules(t, "",
				`<rule><interface>lan</interface><direction>out</direction>`+tt.body+`</rule>`)
			require.Len(t, device.FirewallRules, 1)
			assert.Equal(t, tt.wantDisabled, device.FirewallRules[0].Disabled)
			require.Len(t, warnings, 1)
			assert.Equal(t, "FirewallRules[0].ReceivedOn", warnings[0].Field)
			assert.Equal(t, tt.wantMessage, warnings[0].Message)
			assert.Equal(t, common.SeverityMedium, warnings[0].Severity)
		})
	}
}

// TestConverter_FilterRules_RepeatedUUID covers a uuid that occurs more than
// once. OPNsense keeps the rules of the filter model by uuid, so a later rule
// replaces an earlier one. A rule under <filter> with the same uuid is a
// separate rule: the migration assistant leaves it there until the operator
// removes it, and the firewall loads both.
func TestConverter_FilterRules_RepeatedUUID(t *testing.T) {
	t.Parallel()

	const onLAN = `<interface>lan</interface>`

	device, warnings := parseFilterRules(t,
		`<rule uuid="u1"><type>pass</type><interface>lan</interface><descr>legacy twin</descr>`+
			`<source><any>1</any></source><destination><any>1</any></destination></rule>`,
		modelRuleXML("replaced", "1", "u1", onLAN)+modelRuleXML("other", "2", "u2", onLAN)+
			modelRuleXML("kept", "1", "u1", onLAN)+`<rule uuid="u1"/>`)

	assert.Equal(t, []string{"kept", "other", "legacy twin"}, descriptions(device.FirewallRules))
	require.Len(t, warnings, 1)
	assert.Equal(t, "OPNsense.Firewall.Filter.Rules", warnings[0].Field)
	assert.Equal(t, "u1", warnings[0].Value)
	assert.Equal(t, common.SeverityMedium, warnings[0].Severity)
}

// TestConverter_FilterRules_WarningIndex pins the index in a warning's field to
// the rule's place in the rule list, which is not its place in either store,
// and the value to what the rule stores.
func TestConverter_FilterRules_WarningIndex(t *testing.T) {
	t.Parallel()

	device, warnings := parseFilterRules(t,
		`<rule><interface>lan</interface><descr>legacy</descr>`+
			`<source><any>1</any></source><destination><any>1</any></destination></rule>`,
		modelRuleXML("last", "30", "u3", `<interface>opt9</interface>`+
			`<destination_net>WEB_HOST,DB_HOST</destination_net><destination_not>1</destination_not>`)+
			modelRuleXML("second", "20", "u2", `<interface>lan</interface><action>match</action>`)+
			modelRuleXML("first", "10", "u1", `<interface>wan</interface><interfacenot>1</interfacenot>`+
				`<source_net>lan,any</source_net>`))

	// The firewall does not load a rule on no interface it knows, and ranks it
	// after the legacy rules.
	require.Equal(t, []string{"first", "second", "legacy", "last"}, descriptions(device.FirewallRules))

	type warning struct{ field, value string }

	got := make([]warning, 0, len(warnings))
	for _, w := range warnings {
		got = append(got, warning{w.Field, w.Value})
	}

	assert.Equal(t, []warning{
		{"FirewallRules[0].Interface", "wan"},
		{"FirewallRules[0].Source", "lan,any"},
		{"FirewallRules[1].Type", "match"},
		{"FirewallRules[2].Type", ""},
		{"FirewallRules[3].Interface", "opt9"},
		{"FirewallRules[3].Destination", "WEB_HOST,DB_HOST"},
	}, got)
}
