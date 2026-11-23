package audit

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTargetHoldsLoopback_HostnameMembers checks a forward's target that is, or
// names, a host alias holding a hostname. OPNsense resolves such a member
// through DNS when it loads the alias and keeps every address the answer
// holds, so the alias may hold a loopback address and counts, with or without
// a domain in the hostname, and so does a network group naming it. A member
// that is an address, a range of addresses, an IPv6 address, an address
// excluded with "!", or the name of another alias is not resolved, and a
// network alias holding a LAN network holds no loopback, so none of those
// counts. A target that is itself a hostname does not count either, since
// OPNsense disables a forward to it as an invalid target.
func TestTargetHoldsLoopback_HostnameMembers(t *testing.T) {
	t.Parallel()

	alias := func(name string, aliasType common.NamedObjectType, members ...string) common.NamedObject {
		return common.NamedObject{Name: name, Type: aliasType, Members: members}
	}

	objects := common.NamedObjects{
		"LAN_HOST":      alias("LAN_HOST", common.NamedObjectTypeHost, "192.168.1.50"),
		"FQDN_HOST":     alias("FQDN_HOST", common.NamedObjectTypeHost, "192.168.1.51", "snmp.example.com"),
		"SHORT_HOST":    alias("SHORT_HOST", common.NamedObjectTypeHost, "192.168.1.52", "snmp-agent"),
		"HOST_GROUP":    alias("HOST_GROUP", aliasTypeNetworkGroup, "LAN_HOST", "FQDN_HOST"),
		"RANGE_HOST":    alias("RANGE_HOST", common.NamedObjectTypeHost, "192.168.1.60-192.168.1.70"),
		"V6_HOST":       alias("V6_HOST", common.NamedObjectTypeHost, "2001:db8:1::50"),
		"EXCLUDED_HOST": alias("EXCLUDED_HOST", common.NamedObjectTypeHost, "192.168.1.0", "!192.168.1.53"),
		"NESTING_HOST":  alias("NESTING_HOST", common.NamedObjectTypeHost, "192.168.1.54", "LAN_HOST"),
		"LAN_NET":       alias("LAN_NET", common.NamedObjectTypeNetwork, "192.168.1.0/24"),
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
		{name: "host alias holding a hostname with a domain second", target: "FQDN_HOST", want: true},
		{name: "host alias holding a hostname with a hyphen and no domain second", target: "SHORT_HOST", want: true},
		{name: "network group naming that host alias second", target: "HOST_GROUP", want: true},
		{name: "host alias holding a LAN address", target: "LAN_HOST"},
		{name: "host alias holding a range of addresses", target: "RANGE_HOST"},
		{name: "host alias holding an IPv6 address", target: "V6_HOST"},
		{name: "host alias holding an address excluded with !", target: "EXCLUDED_HOST"},
		{name: "host alias naming another host alias second", target: "NESTING_HOST"},
		{name: "network alias holding a LAN network", target: "LAN_NET"},
		{name: "hostname with a domain as the target", target: "snmp.example.com"},
		{name: "hostname with a hyphen as the target", target: "snmp-agent"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device := &common.CommonDevice{Interfaces: interfaces, NamedObjects: objects}
			assert.Equal(t, tc.want, targetHoldsLoopback(tc.target, device))
		})
	}
}

// TestResolvedThroughDNS checks which entries of a host alias that name no
// alias OPNsense's alias loader resolves through DNS: every entry that is no
// address and no range of addresses, and none with "/" or "!".
func TestResolvedThroughDNS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		member string
		want   bool
	}{
		{member: "snmp.example.com", want: true},
		{member: "snmp.example.com.", want: true},
		{member: "snmp-agent", want: true},
		{member: "localhost", want: true},
		{member: "my-host.example.com", want: true},
		{member: "snmp-10.0.0.1", want: true},
		{member: "192.168.1.10-snmp", want: true},
		{member: ""},
		{member: "192.168.1.10"},
		{member: "127.0.0.1"},
		{member: "2001:db8::10"},
		{member: "192.168.1.10-192.168.1.20"},
		{member: "2001:db8::10-2001:db8::20"},
		{member: "192.168.1.0/24"},
		{member: "192.168.0.1/0.0.255.0"},
		{member: "!192.168.1.10"},
		{member: "!snmp.example.com"},
	}

	for _, tc := range tests {
		t.Run(tc.member, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, resolvedThroughDNS(tc.member))
		})
	}
}

// TestSNMPAgent_ForwardToHostnameAlias drives OPNsense configs with a net-snmp
// agent bound only to 127.0.0.1 through parse, convert and red mode. A WAN rule
// passes UDP 161 to any destination, which reaches the agent only if a forward
// can redirect that traffic to loopback. A WAN forward of UDP 161 to a host
// alias holding a hostname, or to a network group naming one, may do so, since
// the hostname may resolve to a loopback address, so the agent keeps the
// exposure the rule gives it. With the rule to the host alias itself instead,
// the rule is the forward's own and is not read (forwardsToAnotherHost), so the
// agent keeps the LAN reachability it has without a WAN rule. A forward to a
// host alias holding only a LAN address leaves the agent Local.
func TestSNMPAgent_ForwardToHostnameAlias(t *testing.T) {
	t.Parallel()

	aliases := snmpForwardAlias("f6f6f6f6-0000-4000-8000-000000000001", "LAN_HOST", "host", "192.168.1.50") +
		snmpForwardAlias("f6f6f6f6-0000-4000-8000-000000000002", "FQDN_HOST", "host",
			"192.168.1.51\nsnmp.example.com") +
		snmpForwardAlias("f6f6f6f6-0000-4000-8000-000000000003", "HOST_GROUP", "networkgroup",
			"LAN_HOST\nFQDN_HOST")

	anyRule := snmpForwardAnyRule()

	tests := []struct {
		name     string
		target   string
		rules    string
		forwards string
		want     analysis.Reachability
	}{
		{
			name:     "rule to any, forward to a host alias holding a hostname",
			target:   "FQDN_HOST",
			rules:    anyRule,
			forwards: snmpLegacyForward("FQDN_HOST", "", ""),
			want:     analysis.WANReachable,
		},
		{
			name:     "rule to any, 26.1 forward to a host alias holding a hostname",
			target:   "FQDN_HOST",
			rules:    anyRule,
			forwards: snmpModelForward("FQDN_HOST", "0"),
			want:     analysis.WANReachable,
		},
		{
			name:     "rule to any, forward to a network group naming that host alias second",
			target:   "HOST_GROUP",
			rules:    anyRule,
			forwards: snmpLegacyForward("HOST_GROUP", "", ""),
			want:     analysis.WANReachable,
		},
		{
			name:     "rule to the host alias, forward to the host alias",
			target:   "FQDN_HOST",
			rules:    snmpForwardRule("FQDN_HOST", "nat_1"),
			forwards: snmpLegacyForward("FQDN_HOST", "nat_1", ""),
			want:     analysis.LANOnly,
		},
		{
			name:     "rule to any, forward to a host alias holding a LAN address",
			target:   "LAN_HOST",
			rules:    anyRule,
			forwards: snmpLegacyForward("LAN_HOST", "", ""),
			want:     analysis.Local,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device := parseConfig(t, snmpForwardConfig("127.0.0.1", tc.rules, tc.forwards, aliases))
			require.Equal(t, []string{"127.0.0.1"}, device.SNMP.ListenAddresses)
			require.Equal(t, []string{"192.168.1.51", "snmp.example.com"}, device.NamedObjects["FQDN_HOST"].Members,
				"host alias members")
			require.Equal(t, common.NamedObjectTypeHost, device.NamedObjects["FQDN_HOST"].Type, "host alias type")
			require.Len(t, device.NAT.InboundRules, 1)
			require.Equal(t, tc.target, device.NAT.InboundRules[0].InternalIP, "target")

			assertSNMPReachability(t, device, tc.want)
		})
	}
}
