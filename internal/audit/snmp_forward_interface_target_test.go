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
// each with a WAN forward of UDP 161 and the rule that passes it. OPNsense
// accepts an interface's net (lan) or address (lanip) as a forward's target,
// and pf then redirects to that interface, where the agent does not listen, so
// the agent stays Local. lo0 holds loopback, so a forward to it keeps the agent
// exposed whether or not the config holds the lo0 interface, as do a forward to
// 127.0.0.1, to an alias holding it, and to a name no alias defines. So does a
// forward to This Firewall, (self), which pf reads as every address of every
// interface, lo0's ::1 among them.
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
// the list. An interface with a dynamic address, or none, holds no loopback. A
// name that matches no interface exactly, including one in another case, falls
// back to the alias-name reading and counts, as does lo0 on a config without
// the lo0 interface. An alias named like an interface is read in place of the
// interface, as OPNsense's alias map adds aliases after interfaces, so it
// counts only when its members hold loopback, whatever the interface holds.
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
