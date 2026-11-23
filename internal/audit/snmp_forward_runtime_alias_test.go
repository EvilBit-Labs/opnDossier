package audit

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTargetHoldsLoopback_RuntimeAliases checks a forward's target that is, or
// names, an alias whose addresses OPNsense gets at runtime: a URL alias, a URL
// table, a URL table in JSON format, or an external alias. Its members in the
// config are URLs or nothing, so they cannot show what it holds, and it may
// hold a loopback address. Such a target counts, as does an alias that names
// one at any depth, an alias of that name read in place of an interface, and a
// disabled external alias, whose table OPNsense leaves as it is. A disabled URL
// table loads with no members, so it does not count, nor does a group naming
// only it; the same holds for a disabled host alias holding a loopback address. A GeoIP alias holds country networks, which no loopback address
// is in, and a network group naming only it and a LAN host holds no loopback,
// so neither counts, and a nesting loop among aliases with no such alias ends.
func TestTargetHoldsLoopback_RuntimeAliases(t *testing.T) {
	t.Parallel()

	alias := func(name string, aliasType common.NamedObjectType, members ...string) common.NamedObject {
		return common.NamedObject{Name: name, Type: aliasType, Members: members}
	}

	objects := common.NamedObjects{
		"URL_LIST":  alias("URL_LIST", common.NamedObjectTypeURL, "https://example.com/list.txt"),
		"URL_TABLE": alias("URL_TABLE", aliasTypeURLTable, "https://example.com/table.txt"),
		"URL_JSON":  alias("URL_JSON", aliasTypeURLJSON, "https://example.com/table.json"),
		"EXTERNAL":  alias("EXTERNAL", common.NamedObjectTypeExternal),
		"OFF_TABLE": {
			Name:     "OFF_TABLE",
			Type:     aliasTypeURLTable,
			Members:  []string{"https://example.com/off.txt"},
			Disabled: true,
		},
		"OFF_EXTERNAL": {Name: "OFF_EXTERNAL", Type: common.NamedObjectTypeExternal, Disabled: true},
		"OFF_GROUP":    alias("OFF_GROUP", aliasTypeNetworkGroup, "LAN_HOST", "OFF_TABLE"),
		"LOOP_HOST":    alias("LOOP_HOST", common.NamedObjectTypeHost, "127.0.0.1"),
		"OFF_LOOP_HOST": {
			Name:     "OFF_LOOP_HOST",
			Type:     common.NamedObjectTypeHost,
			Members:  []string{"127.0.0.1"},
			Disabled: true,
		},
		"OFF_LOOP_GROUP": alias("OFF_LOOP_GROUP", aliasTypeNetworkGroup, "LAN_HOST", "OFF_LOOP_HOST"),
		"COUNTRIES":      alias("COUNTRIES", common.NamedObjectTypeGeoIP, "NL"),
		"LAN_HOST":       alias("LAN_HOST", common.NamedObjectTypeHost, "192.168.1.50"),
		"TABLE_GROUP":    alias("TABLE_GROUP", aliasTypeNetworkGroup, "LAN_HOST", "URL_TABLE"),
		"OUTER_GROUP":    alias("OUTER_GROUP", aliasTypeNetworkGroup, "LAN_HOST", "TABLE_GROUP"),
		"JSON_HOST":      alias("JSON_HOST", common.NamedObjectTypeHost, "192.168.1.51", "URL_JSON"),
		"URL_NET":        alias("URL_NET", common.NamedObjectTypeNetwork, "192.168.2.0/24", "URL_LIST"),
		"GEO_GROUP":      alias("GEO_GROUP", aliasTypeNetworkGroup, "LAN_HOST", "COUNTRIES"),
		"LOOP_A":         alias("LOOP_A", aliasTypeNetworkGroup, "LAN_HOST", "LOOP_B"),
		"LOOP_B":         alias("LOOP_B", aliasTypeNetworkGroup, "LOOP_A"),
		"lan":            alias("lan", aliasTypeURLTable, "https://example.com/lan.txt"),
	}

	interfaces := []common.Interface{
		{Name: "wan", IPAddress: "198.51.100.2"},
		{Name: "lan", IPAddress: "192.168.1.1"},
	}

	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{name: "URL alias", target: "URL_LIST", want: true},
		{name: "URL table", target: "URL_TABLE", want: true},
		{name: "URL table in JSON format", target: "URL_JSON", want: true},
		{name: "external alias", target: "EXTERNAL", want: true},
		{name: "disabled URL table", target: "OFF_TABLE"},
		{name: "network group naming a disabled URL table", target: "OFF_GROUP"},
		{name: "disabled external alias", target: "OFF_EXTERNAL", want: true},
		{name: "host alias holding a loopback address", target: "LOOP_HOST", want: true},
		{name: "disabled host alias holding a loopback address", target: "OFF_LOOP_HOST"},
		{name: "network group naming that disabled host alias", target: "OFF_LOOP_GROUP"},
		{name: "network group naming the URL table second", target: "TABLE_GROUP", want: true},
		{name: "network group naming that group second", target: "OUTER_GROUP", want: true},
		{name: "host alias naming the JSON table second", target: "JSON_HOST", want: true},
		{name: "network alias naming the URL alias second", target: "URL_NET", want: true},
		{name: "URL table named like the lan interface", target: "lan", want: true},
		{name: "address of the lan interface", target: "lanip"},
		{name: "GeoIP alias", target: "COUNTRIES"},
		{name: "network group naming a LAN host and a GeoIP alias", target: "GEO_GROUP"},
		{name: "nesting loop with no runtime alias", target: "LOOP_A"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device := &common.CommonDevice{Interfaces: interfaces, NamedObjects: objects}
			assert.Equal(t, tc.want, targetHoldsLoopback(tc.target, device))
		})
	}
}

// TestSNMPAgent_ForwardToRuntimeAlias drives OPNsense configs with a net-snmp
// agent bound only to 127.0.0.1 through parse, convert and red mode. A WAN rule
// passes UDP 161 to any destination, which reaches the agent only if a forward
// can redirect that traffic to loopback. A WAN forward of UDP 161 to an alias
// whose addresses OPNsense gets at runtime, or to a network group naming one,
// may do so, so the agent keeps the exposure the rule gives it. With the rule
// to the URL table itself instead, the rule is the forward's own and is not
// read (forwardsToAnotherHost), so no rule passes WAN traffic to the agent, and
// the forward keeps the LAN reachability it has without one. A forward to a
// GeoIP alias, or no forward, leaves the agent Local.
func TestSNMPAgent_ForwardToRuntimeAlias(t *testing.T) {
	t.Parallel()

	aliases := snmpForwardAlias("e5e5e5e5-0000-4000-8000-000000000001", "LAN_HOST", "host", "192.168.1.50") +
		snmpForwardAlias("e5e5e5e5-0000-4000-8000-000000000002", "URL_TABLE", "urltable",
			"https://example.com/table.txt") +
		snmpForwardAlias("e5e5e5e5-0000-4000-8000-000000000003", "URL_LIST", "url",
			"https://example.com/list.txt") +
		snmpForwardAlias("e5e5e5e5-0000-4000-8000-000000000004", "URL_JSON", "urljson",
			"https://example.com/table.json") +
		snmpForwardAlias("e5e5e5e5-0000-4000-8000-000000000005", "EXTERNAL", "external", "") +
		snmpForwardAlias("e5e5e5e5-0000-4000-8000-000000000006", "COUNTRIES", "geoip", "NL") +
		snmpForwardAlias("e5e5e5e5-0000-4000-8000-000000000007", "TABLE_GROUP", "networkgroup",
			"LAN_HOST\nURL_TABLE")

	anyRule := snmpForwardAnyRule()

	tests := []struct {
		name     string
		target   string
		rules    string
		forwards string
		want     analysis.Reachability
	}{
		{
			name:     "rule to any, forward to a URL table",
			target:   "URL_TABLE",
			rules:    anyRule,
			forwards: snmpLegacyForward("URL_TABLE", "", ""),
			want:     analysis.WANReachable,
		},
		{
			name:     "rule to any, 26.1 forward to a URL table",
			target:   "URL_TABLE",
			rules:    anyRule,
			forwards: snmpModelForward("URL_TABLE", "0"),
			want:     analysis.WANReachable,
		},
		{
			name:     "rule to any, forward to a network group naming the URL table second",
			target:   "TABLE_GROUP",
			rules:    anyRule,
			forwards: snmpLegacyForward("TABLE_GROUP", "", ""),
			want:     analysis.WANReachable,
		},
		{
			name:     "rule to any, forward to a URL alias",
			target:   "URL_LIST",
			rules:    anyRule,
			forwards: snmpLegacyForward("URL_LIST", "", ""),
			want:     analysis.WANReachable,
		},
		{
			name:     "rule to any, forward to a URL table in JSON format",
			target:   "URL_JSON",
			rules:    anyRule,
			forwards: snmpLegacyForward("URL_JSON", "", ""),
			want:     analysis.WANReachable,
		},
		{
			name:     "rule to any, forward to an external alias",
			target:   "EXTERNAL",
			rules:    anyRule,
			forwards: snmpLegacyForward("EXTERNAL", "", ""),
			want:     analysis.WANReachable,
		},
		{
			name:     "rule to the URL table, forward to the URL table",
			target:   "URL_TABLE",
			rules:    snmpForwardRule("URL_TABLE", "nat_1"),
			forwards: snmpLegacyForward("URL_TABLE", "nat_1", ""),
			want:     analysis.LANOnly,
		},
		{
			name:     "rule to any, forward to a GeoIP alias",
			target:   "COUNTRIES",
			rules:    anyRule,
			forwards: snmpLegacyForward("COUNTRIES", "", ""),
			want:     analysis.Local,
		},
		{
			name:  "rule to any, no forward",
			rules: anyRule,
			want:  analysis.Local,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device := parseConfig(t, snmpForwardConfig("127.0.0.1", tc.rules, tc.forwards, aliases))
			require.Equal(t, []string{"127.0.0.1"}, device.SNMP.ListenAddresses)
			require.Equal(t, aliasTypeURLTable, device.NamedObjects["URL_TABLE"].Type, "URL table type")
			require.Equal(t, aliasTypeURLJSON, device.NamedObjects["URL_JSON"].Type, "JSON table type")

			if tc.target == "" {
				require.Empty(t, device.NAT.InboundRules)
			} else {
				require.Len(t, device.NAT.InboundRules, 1)
				require.Equal(t, tc.target, device.NAT.InboundRules[0].InternalIP, "target")
			}

			assertSNMPReachability(t, device, tc.want)
		})
	}
}

// snmpForwardAnyRule is a WAN pass rule for UDP 161 to any destination, with
// no link to a forward.
func snmpForwardAnyRule() string {
	return `
    <rule>
      <type>pass</type>
      <interface>wan</interface>
      <ipprotocol>inet</ipprotocol>
      <protocol>udp</protocol>
      <source>
        <any>1</any>
      </source>
      <destination>
        <any>1</any>
        <port>161</port>
      </destination>
      <descr>snmp</descr>
    </rule>`
}
