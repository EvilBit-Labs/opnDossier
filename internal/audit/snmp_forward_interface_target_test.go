package audit

import (
	"slices"
	"strings"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// snmpLoopbackInterface is the lo0 interface as OPNsense writes it into
// <interfaces>, then the closing </interfaces> tag it replaces.
const snmpLoopbackInterface = `
    <lo0>
      <internal_dynamic>1</internal_dynamic>
      <descr>Loopback</descr>
      <enable>1</enable>
      <if>lo0</if>
      <ipaddr>127.0.0.1</ipaddr>
      <ipaddrv6>::1</ipaddrv6>
      <subnet>8</subnet>
      <subnetv6>128</subnetv6>
      <type>none</type>
      <virtual>1</virtual>
    </lo0>
  </interfaces>`

// snmpForwardNetworkRule is snmpForwardRule, linked to the forward nat_1, with
// the destination written as a network element, the form a filter rule to an
// interface net or address takes.
func snmpForwardNetworkRule(network string) string {
	return strings.Replace(snmpForwardRule(network, "nat_1"),
		"<address>"+network+"</address>", "<network>"+network+"</network>", 1)
}

// TestSNMPAgent_ForwardToInterfaceTarget drives OPNsense configs with a
// net-snmp agent bound only to loopback through parse, convert and red mode,
// each with a WAN forward of UDP 161 and the rule that passes it. From 26.1.2
// OPNsense maps an interface's net (lan) or address (lanip) as a forward's
// target, and pf then redirects to that interface, where the agent does not
// listen, so the agent stays Local. lo0 holds loopback, so a forward to it
// keeps the agent exposed whether or not the config holds the lo0 interface, as
// do a forward to 127.0.0.1, to an alias holding it, and to a name no alias
// defines. So does a forward to This Firewall, (self), which pf reads as every
// address of every interface, lo0's ::1 among them. Through 26.1.1 OPNsense
// disables a forward to (self), or to an interface name no alias defines, as an
// invalid target, so there the lo0 and (self) cases over-report.
func TestSNMPAgent_ForwardToInterfaceTarget(t *testing.T) {
	t.Parallel()

	const loopHost = `127.0.0.1`

	aliases := snmpForwardAlias("d4d4d4d4-0000-4000-8000-000000000001", "LOOP_HOST", "host", loopHost)

	tests := []struct {
		name   string
		target string
		// network writes the rule's destination as a network element, and
		// listen replaces the agent's listen list of 127.0.0.1.
		network bool
		listen  string
		lo0     bool
		exposed bool
	}{
		{name: "forward to lanip", target: "lanip", network: true},
		{name: "forward to wanip", target: "wanip", network: true},
		{name: "forward to the lan net", target: "lan", network: true},
		{name: "forward to lanip with the lo0 interface", target: "lanip", network: true, lo0: true},
		{
			name:   "forward to lanip, agent bound to 127.0.0.1 and ::1",
			target: "lanip", network: true, listen: "127.0.0.1,::1", lo0: true,
		},
		{
			name:   "forward to the lo0 net with the lo0 interface",
			target: "lo0", network: true, lo0: true, exposed: true,
		},
		{
			name:   "forward to the lo0 net, agent bound to ::1",
			target: "lo0", network: true, listen: "::1", lo0: true, exposed: true,
		},
		{name: "forward to the lo0 net without the lo0 interface", target: "lo0", network: true, exposed: true},
		{
			name:   "forward to (self), agent bound to ::1",
			target: "(self)", network: true, listen: "::1", lo0: true, exposed: true,
		},
		{name: "forward to 127.0.0.1 with the lo0 interface", target: loopHost, lo0: true, exposed: true},
		{name: "forward to an alias holding 127.0.0.1", target: "LOOP_HOST", lo0: true, exposed: true},
		{name: "forward to a name no alias defines", target: "GONE", exposed: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rule := snmpForwardRule(tc.target, "nat_1")
			if tc.network {
				rule = snmpForwardNetworkRule(tc.target)
			}

			listen := loopHost
			if tc.listen != "" {
				listen = tc.listen
			}

			config := snmpForwardConfig(listen, rule, snmpLegacyForward(tc.target, "nat_1", ""), aliases)
			if tc.lo0 {
				config = strings.Replace(config, "\n  </interfaces>", snmpLoopbackInterface, 1)
			}

			device := parseConfig(t, config)
			require.Equal(t, strings.Split(listen, ","), device.SNMP.ListenAddresses)
			require.Len(t, device.NAT.InboundRules, 1)
			require.Equal(t, tc.target, device.NAT.InboundRules[0].InternalIP, "target")
			require.Equal(t, tc.lo0, slices.ContainsFunc(device.Interfaces, func(iface common.Interface) bool {
				return iface.Name == "lo0" && iface.IPAddress == loopHost
			}), "lo0 interface")

			assertSNMPForwardExposure(t, device, tc.exposed)
		})
	}
}

// TestTargetHoldsLoopback_InterfaceTargets checks how a forward's target that
// names an interface is read. It counts only when the interface's own IPv4 or
// IPv6 address is a loopback address, whatever the place of the interface in
// the list. An interface with a dynamic address, or none, holds no loopback.
// lo0ip counts beside a lo0 holding loopback, although OPNsense maps the key
// and "ip" only for wan, lan and optN, which over-reports. A name that matches
// no interface exactly, including one in another case, falls back to the
// alias-name reading and counts, as does lo0 on a config without the lo0
// interface. An alias named like an interface is read in place of the
// interface, as OPNsense's alias map from 26.1.2 adds every alias but a port
// alias after the interfaces, so it counts only when its members hold
// loopback, whatever the interface holds. A port alias is not in that map, so
// one named like an interface leaves the interface's reading in place, and one
// named like no interface does not count, since from 26.1.2 OPNsense disables
// a forward to it as an invalid target.
func TestTargetHoldsLoopback_InterfaceTargets(t *testing.T) {
	t.Parallel()

	lan := common.Interface{Name: "lan", IPAddress: "192.168.1.1", IPv6Address: "2001:db8:1::1"}
	wanDHCP := common.Interface{Name: "wan", IPAddress: "dhcp", IPv6Address: "dhcp6"}
	trackOnly := common.Interface{Name: "opt1", IPv6Address: "track6"}
	lo0 := common.Interface{Name: "lo0", IPAddress: "127.0.0.1", IPv6Address: "::1"}
	lo0IPv6Only := common.Interface{Name: "lo0", IPv6Address: "::1"}
	loopbackDevice := common.Interface{Name: "opt2", IPAddress: "127.0.0.2"}

	objects := common.NamedObjects{
		"LOOP_HOST": {Name: "LOOP_HOST", Type: common.NamedObjectTypeHost, Members: []string{"127.0.0.1"}},
	}

	// aliasesNamedLikeInterfaces holds an alias named like the lo0 interface
	// that holds no loopback, and aliases named like the lan interface and its
	// address that hold 127.0.0.1.
	aliasesNamedLikeInterfaces := common.NamedObjects{
		"lo0":   {Name: "lo0", Type: common.NamedObjectTypeHost, Members: []string{"192.0.2.10"}},
		"lan":   {Name: "lan", Type: common.NamedObjectTypeHost, Members: []string{"127.0.0.1"}},
		"lanip": {Name: "lanip", Type: common.NamedObjectTypeHost, Members: []string{"127.0.0.1"}},
	}

	// portAliases holds port aliases named like the lo0 interface, like the
	// lan address, and like no interface.
	portAliases := common.NamedObjects{
		"lo0":        {Name: "lo0", Type: common.NamedObjectTypePort, Members: []string{"161"}},
		"lanip":      {Name: "lanip", Type: common.NamedObjectTypePort, Members: []string{"161"}},
		"SNMP_PORTS": {Name: "SNMP_PORTS", Type: common.NamedObjectTypePort, Members: []string{"161"}},
	}

	tests := []struct {
		name       string
		target     string
		interfaces []common.Interface
		// objects replaces the device's aliases when set.
		objects common.NamedObjects
		want    bool
	}{
		{name: "lan net", target: "lan", interfaces: []common.Interface{lo0, lan}},
		{name: "lan address", target: "lanip", interfaces: []common.Interface{lo0, lan}},
		{name: "DHCP wan address", target: "wanip", interfaces: []common.Interface{wanDHCP, lo0}},
		{name: "DHCP wan net", target: "wan", interfaces: []common.Interface{wanDHCP}},
		{name: "interface with no IPv4 address", target: "opt1ip", interfaces: []common.Interface{trackOnly}},
		{name: "lo0 net", target: "lo0", interfaces: []common.Interface{lan, lo0}, want: true},
		{name: "lo0 holding only ::1", target: "lo0", interfaces: []common.Interface{lan, lo0IPv6Only}, want: true},
		{name: "lo0 without the lo0 interface", target: "lo0", interfaces: []common.Interface{lan}, want: true},
		{
			name:       "address of an assigned loopback device",
			target:     "opt2ip",
			interfaces: []common.Interface{lan, loopbackDevice},
			want:       true,
		},
		{
			name:       "lo0 address, a name OPNsense does not map",
			target:     "lo0ip",
			interfaces: []common.Interface{lan, lo0},
			want:       true,
		},
		{name: "interface name in another case", target: "LANip", interfaces: []common.Interface{lan}, want: true},
		{name: "127.0.0.1", target: "127.0.0.1", interfaces: []common.Interface{lan, lo0}, want: true},
		{name: "alias holding 127.0.0.1", target: "LOOP_HOST", interfaces: []common.Interface{lan}, want: true},
		{name: "name no alias or interface defines", target: "GONE", interfaces: []common.Interface{lan}, want: true},
		{
			name:       "alias named like lo0 holding no loopback",
			target:     "lo0",
			interfaces: []common.Interface{lan, lo0},
			objects:    aliasesNamedLikeInterfaces,
		},
		{
			name:       "alias named like lan holding 127.0.0.1",
			target:     "lan",
			interfaces: []common.Interface{lo0, lan},
			objects:    aliasesNamedLikeInterfaces,
			want:       true,
		},
		{
			name:       "alias named like lanip holding 127.0.0.1",
			target:     "lanip",
			interfaces: []common.Interface{lo0, lan},
			objects:    aliasesNamedLikeInterfaces,
			want:       true,
		},
		{
			name:       "port alias named like lo0",
			target:     "lo0",
			interfaces: []common.Interface{lan, lo0},
			objects:    portAliases,
			want:       true,
		},
		{
			name:       "port alias named like lanip",
			target:     "lanip",
			interfaces: []common.Interface{lo0, lan},
			objects:    portAliases,
		},
		{
			name:       "port alias named like no interface",
			target:     "SNMP_PORTS",
			interfaces: []common.Interface{lan, lo0},
			objects:    portAliases,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device := &common.CommonDevice{Interfaces: tc.interfaces, NamedObjects: objects}
			if tc.objects != nil {
				device.NamedObjects = tc.objects
			}

			assert.Equal(t, tc.want, targetHoldsLoopback(tc.target, device))
		})
	}
}

// TestSNMPAgent_ForwardToPortAliasName drives OPNsense configs with a net-snmp
// agent bound only to 127.0.0.1 and the lo0 interface through parse, convert
// and red mode, each with a WAN forward of UDP 161 to a name a port alias
// defines and a WAN rule passing UDP 161 to any destination. From 26.1.2
// OPNsense leaves port aliases out of the names a forward's target maps to, so
// a port alias named lo0 leaves the forward to the lo0 net, which keeps the
// agent exposed, and a forward to a port alias named like no interface is
// disabled as an invalid target, which leaves the agent Local. Through 26.1.1
// OPNsense maps a target to any alias of its name, port aliases included, so
// there the forward in the first case does not reach the lo0 net, and that
// case over-reports.
func TestSNMPAgent_ForwardToPortAliasName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		target  string
		exposed bool
	}{
		{name: "port alias named like the lo0 interface", target: "lo0", exposed: true},
		{name: "port alias named like no interface", target: "SNMP_PORTS"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rule := strings.Replace(snmpForwardRule(tc.target, ""),
				"<address>"+tc.target+"</address>", "<any>1</any>", 1)
			alias := snmpForwardAlias("d4d4d4d4-0000-4000-8000-000000000002", tc.target, "port", "161")
			config := strings.Replace(snmpForwardConfig("127.0.0.1", rule, snmpLegacyForward(tc.target, "", ""), alias),
				"\n  </interfaces>", snmpLoopbackInterface, 1)

			device := parseConfig(t, config)
			require.Equal(t, common.NamedObjectTypePort, device.NamedObjects[tc.target].Type, "alias type")
			require.Len(t, device.NAT.InboundRules, 1)
			require.Equal(t, tc.target, device.NAT.InboundRules[0].InternalIP, "target")

			assertSNMPForwardExposure(t, device, tc.exposed)
		})
	}
}
