package sans_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// protocolSpellings are protocol values a rule can carry, and whether each
// passes TCP and ICMP. An empty or any protocol passes every protocol. tcpOnly
// marks the spellings SANS-FW-024 reads, tcp in any case.
var protocolSpellings = []struct {
	protocol           string
	tcp, icmp, tcpOnly bool
}{
	{protocol: "tcp", tcp: true, tcpOnly: true},
	{protocol: "TCP", tcp: true, tcpOnly: true},
	{protocol: "tcp/udp", tcp: true},
	{protocol: "", tcp: true, icmp: true},
	{protocol: "any", tcp: true, icmp: true},
	{protocol: "udp"},
	{protocol: "icmp", icmp: true},
	{protocol: "ICMP", icmp: true},
	{protocol: "ipv6-icmp", icmp: true},
}

// TestSANSChecks_ProtocolSpellings runs one rule under each protocol spelling
// through the four controls that ask about a protocol. A tcp/udp or
// any-protocol rule passes TCP, an any-protocol or ipv6-icmp rule passes ICMP,
// and a udp rule passes neither. SANS-FW-024 reads tcp rules alone.
func TestSANSChecks_ProtocolSpellings(t *testing.T) {
	t.Parallel()

	// lanRule leaves state tracking to stateType; its source is pinned so it
	// does not read as any source.
	lanRule := func(stateType string) common.FirewallRule {
		return common.FirewallRule{
			Type: common.RuleTypePass, Interfaces: []string{"lan"}, StateType: stateType,
			Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
			Destination: common.RuleEndpoint{Address: "192.168.1.9"},
		}
	}

	cases := []struct {
		name string
		rule common.FirewallRule
		id   string
		// icmp says the control asks about ICMP rather than TCP, and tcpOnly
		// that it reads tcp rules alone.
		icmp, tcpOnly bool
		// matched is the outcome when the spelling passes the protocol the
		// control asks about, unmatched when it does not.
		matched, unmatched string
	}{
		{
			name: "DNS on WAN from any source",
			rule: common.FirewallRule{
				Type: common.RuleTypePass, Interfaces: []string{"wan"}, StateType: "keep state",
				Source:      common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{Address: "203.0.113.2", Port: "53"},
			},
			id: "SANS-FW-020", matched: statusFail, unmatched: statusPass,
		},
		{
			name: "no state type", rule: lanRule(""),
			id: "SANS-FW-007", matched: statusFail, unmatched: statusUnknown,
		},
		{
			name: "no state type", rule: lanRule(""),
			id: "SANS-FW-024", tcpOnly: true, matched: statusFail, unmatched: statusUnknown,
		},
		{
			name: "state type none", rule: lanRule("none"),
			id: "SANS-FW-007", matched: statusFail, unmatched: statusUnknown,
		},
		{
			name: "keep state", rule: lanRule("keep state"),
			id: "SANS-FW-007", matched: statusPass, unmatched: statusUnknown,
		},
		{
			name: "keep state", rule: lanRule("keep state"),
			id: "SANS-FW-024", tcpOnly: true, matched: statusPass, unmatched: statusUnknown,
		},
		{
			name: "ICMP on WAN",
			rule: common.FirewallRule{
				Type: common.RuleTypePass, Interfaces: []string{"wan"}, StateType: "keep state",
				Source:      common.RuleEndpoint{Address: "198.51.100.7"},
				Destination: common.RuleEndpoint{Address: "203.0.113.2"},
			},
			id: "SANS-FW-018", icmp: true, matched: statusFail, unmatched: statusPass,
		},
	}

	for _, spelling := range protocolSpellings {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("%s/%s/%q", tc.id, tc.name, spelling.protocol), func(t *testing.T) {
				t.Parallel()

				rule := tc.rule
				rule.Protocol = spelling.protocol

				matched := spelling.tcp
				switch {
				case tc.icmp:
					matched = spelling.icmp
				case tc.tcpOnly:
					matched = spelling.tcpOnly
				}

				want := tc.unmatched
				if matched {
					want = tc.matched
				}

				assert.Equal(t, want, controlStatus(t, protocolDevice(rule), tc.id))
			})
		}
	}
}

// TestSANSChecks_DNSZoneTransfer_AnyProtocolPorts pins how SANS-FW-020 reads
// the port of an any-protocol rule on WAN from any source. Neither firewall
// applies that port, so the rule passes TCP to every port; it is read by the
// port it names, as a tcp rule is, and a rule open to every port is not
// counted.
func TestSANSChecks_DNSZoneTransfer_AnyProtocolPorts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		protocol, port, want string
	}{
		{protocol: "", port: "53", want: statusFail},
		{protocol: "any", port: "50-60", want: statusFail},
		{protocol: "", port: "", want: statusPass},
		{protocol: "any", port: "1-65535", want: statusPass},
		{protocol: "tcp/udp", port: "", want: statusPass},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q to %q", tt.protocol, tt.port), func(t *testing.T) {
			t.Parallel()

			rule := common.FirewallRule{
				Type: common.RuleTypePass, Interfaces: []string{"wan"}, StateType: "keep state",
				Protocol:    tt.protocol,
				Source:      common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{Address: "203.0.113.2", Port: tt.port},
			}

			assert.Equal(t, tt.want, controlStatus(t, protocolDevice(rule), "SANS-FW-020"))
		})
	}
}

// protocolDevice holds rule beside one WAN and one LAN interface.
func protocolDevice(rule common.FirewallRule) *common.CommonDevice {
	return &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", Enabled: true},
			{Name: "lan", Enabled: true},
		},
		FirewallRules: []common.FirewallRule{rule},
	}
}

// controlStatus is the outcome RunChecks reports for id: UNKNOWN when the
// control was not evaluated.
func controlStatus(t *testing.T, device *common.CommonDevice, id string) string {
	t.Helper()

	if status, ok := sansStatuses(t, device)[id]; ok {
		return status
	}

	return statusUnknown
}

// sansProtocolOPNsenseLegacy holds the rule under test in OPNsense's legacy
// store.
const sansProtocolOPNsenseLegacy = `<?xml version="1.0"?>
<opnsense>
  <system><hostname>fw</hostname><domain>internal</domain></system>
  <interfaces>
    <wan><enable>1</enable><if>vtnet0</if><ipaddr>203.0.113.2</ipaddr><subnet>24</subnet></wan>
    <lan><enable>1</enable><if>vtnet1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <filter>
    <rule>
      <type>pass</type><interface>wan</interface><ipprotocol>{{FAMILY}}</ipprotocol>{{PROTOCOL}}
      <statetype>{{STATE}}</statetype>
      <source><any/></source>
      <destination><address>203.0.113.2</address>{{PORT}}</destination>
      <descr>rule under test</descr>
    </rule>
  </filter>
</opnsense>`

// sansProtocolOPNsenseModel holds the rule under test in OPNsense's filter
// model, which spells the protocol in upper case and writes any.
const sansProtocolOPNsenseModel = `<?xml version="1.0"?>
<opnsense>
  <system><hostname>fw</hostname><domain>internal</domain></system>
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
            <action>pass</action><interface>wan</interface><ipprotocol>{{FAMILY}}</ipprotocol>{{PROTOCOL}}
            <statetype>{{STATE}}</statetype>
            <source_net>any</source_net>
            <destination_net>203.0.113.2</destination_net>{{PORT}}
            <description>rule under test</description>
          </rule>
        </rules>
      </Filter>
    </Firewall>
  </OPNsense>
</opnsense>`

// sansProtocolPfSense holds the rule under test in pfSense's filter. pfSense
// writes no protocol element for any.
const sansProtocolPfSense = `<?xml version="1.0"?>
<pfsense>
  <version>23.3</version>
  <system><hostname>fw</hostname><domain>internal</domain></system>
  <interfaces>
    <wan><enable/><if>vtnet0</if><ipaddr>203.0.113.2</ipaddr><subnet>24</subnet></wan>
    <lan><enable/><if>vtnet1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <filter>
    <rule>
      <type>pass</type><interface>wan</interface><ipprotocol>{{FAMILY}}</ipprotocol>{{PROTOCOL}}
      <statetype>{{STATE}}</statetype>
      <source><any/></source>
      <destination><address>203.0.113.2</address>{{PORT}}</destination>
      <descr>rule under test</descr><tracker>1</tracker>
    </rule>
  </filter>
</pfsense>`

// TestSANSChecks_ProtocolSpellings_EndToEnd drives a WAN pass rule from any
// source, written the way each store writes it, through parse, convert and the
// SANS plugin, so the spellings are those the vendors write rather than those
// a hand-built rule carries. SANS-FW-024 reads tcp rules alone; the stateless
// rules here are pinned against it by
// TestSANSChecks_TCPStateEnforcement_StatelessWideRule.
func TestSANSChecks_ProtocolSpellings_EndToEnd(t *testing.T) {
	t.Parallel()

	const (
		legacy = protocolStoreLegacy
		model  = protocolStoreModel
		pf     = protocolStorePfSense
	)

	// A stateless tcp/udp rule to DNS fails the state and DNS controls and
	// passes the ICMP one.
	tcpUDPDNS := map[string]string{
		"SANS-FW-007": statusFail, "SANS-FW-018": statusPass, "SANS-FW-020": statusFail,
	}
	// A stateless any-protocol rule to every port fails the state and ICMP
	// controls; SANS-FW-020 does not count a rule open to every port.
	anyEveryPort := map[string]string{
		"SANS-FW-007": statusFail, "SANS-FW-018": statusFail, "SANS-FW-020": statusPass,
	}
	// An ICMPv6 rule fails SANS-FW-018 and passes no TCP.
	icmp6 := map[string]string{
		"SANS-FW-007": statusUnknown, "SANS-FW-018": statusFail, "SANS-FW-020": statusPass,
	}

	tests := []struct {
		name, store, protocol, family, port, state string
		want                                       map[string]string
	}{
		{
			name: "tcp/udp", store: legacy, protocol: "<protocol>tcp/udp</protocol>",
			port: "<port>53</port>", state: "none", want: tcpUDPDNS,
		},
		{
			name: "TCP/UDP", store: model, protocol: "<protocol>TCP/UDP</protocol>",
			port: "<destination_port>53</destination_port>", state: "none", want: tcpUDPDNS,
		},
		{
			name: "tcp/udp", store: pf, protocol: "<protocol>tcp/udp</protocol>",
			port: "<port>53</port>", state: "none", want: tcpUDPDNS,
		},
		{name: "no protocol", store: legacy, state: "none", want: anyEveryPort},
		{name: "any", store: model, protocol: "<protocol>any</protocol>", state: "none", want: anyEveryPort},
		{name: "no protocol", store: pf, state: "none", want: anyEveryPort},
		{
			name: "IPV6-ICMP", store: model, protocol: "<protocol>IPV6-ICMP</protocol>",
			family: "inet6", state: "keep", want: icmp6,
		},
		{
			name: "icmp with inet6", store: legacy, protocol: "<protocol>icmp</protocol>",
			family: "inet6", state: "keep state", want: icmp6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.store+"/"+tt.name, func(t *testing.T) {
			t.Parallel()

			device := parseProtocolRule(t, tt.store, tt.protocol, tt.family, tt.port, tt.state)

			for id, want := range tt.want {
				assert.Equal(t, want, controlStatus(t, device, id), id)
			}
		})
	}
}

// TestSANSChecks_TCPStateEnforcement_StatelessWideRule holds a stateless
// tcp/udp or any-protocol rule as the only rule that passes TCP. It fails
// SANS-FW-007 and must not pass SANS-FW-024, which cannot see a none state.
func TestSANSChecks_TCPStateEnforcement_StatelessWideRule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, store, protocol string
	}{
		{name: "tcp/udp", store: protocolStoreLegacy, protocol: "<protocol>tcp/udp</protocol>"},
		{name: "no protocol", store: protocolStoreLegacy},
		{name: "TCP/UDP", store: protocolStoreModel, protocol: "<protocol>TCP/UDP</protocol>"},
		{name: "any", store: protocolStoreModel, protocol: "<protocol>any</protocol>"},
		{name: "tcp/udp", store: protocolStorePfSense, protocol: "<protocol>tcp/udp</protocol>"},
		{name: "no protocol", store: protocolStorePfSense},
	}

	for _, tt := range tests {
		t.Run(tt.store+"/"+tt.name, func(t *testing.T) {
			t.Parallel()

			device := parseProtocolRule(t, tt.store, tt.protocol, "", "", "none")

			assert.Equal(t, statusFail, controlStatus(t, device, "SANS-FW-007"))
			assert.NotEqual(t, statusPass, controlStatus(t, device, "SANS-FW-024"))
		})
	}
}

// The stores parseProtocolRule can write a rule in.
const (
	protocolStoreLegacy  = "opnsense-legacy"
	protocolStoreModel   = "opnsense-model"
	protocolStorePfSense = "pfsense"
)

// parseProtocolRule writes the WAN pass rule of the store's template with the
// given protocol and port elements, address family (inet when empty) and state
// type, and parses and converts it.
func parseProtocolRule(t *testing.T, store, protocol, family, port, state string) *common.CommonDevice {
	t.Helper()

	template, deviceType := sansProtocolOPNsenseLegacy, common.DeviceTypeOPNsense

	switch store {
	case protocolStoreModel:
		template = sansProtocolOPNsenseModel
	case protocolStorePfSense:
		template, deviceType = sansProtocolPfSense, common.DeviceTypePfSense
	}

	if family == "" {
		family = "inet"
	}

	xmlData := strings.NewReplacer(
		"{{FAMILY}}", family, "{{PROTOCOL}}", protocol, "{{PORT}}", port, "{{STATE}}", state,
	).Replace(template)

	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, _, err := factory.CreateDevice(context.Background(), strings.NewReader(xmlData), deviceType, false)
	require.NoError(t, err)
	require.Len(t, device.FirewallRules, 1)

	return device
}
