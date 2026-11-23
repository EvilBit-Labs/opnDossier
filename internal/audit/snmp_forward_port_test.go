package audit

import (
	"strings"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// snmpDNSForward is a port forward sending LAN DNS queries to the firewall's
// resolver: TCP/UDP 53 on the LAN address to target port 53, in the shape
// snmpLegacyForward writes.
func snmpDNSForward(target string) string {
	return strings.NewReplacer(
		"<interface>wan</interface>", "<interface>lan</interface>",
		"<protocol>udp</protocol>", "<protocol>tcp/udp</protocol>",
		"<local-port>161</local-port>", "<local-port>53</local-port>",
		"<network>wanip</network>", "<network>lanip</network>",
		"<port>161</port>", "<port>53</port>",
	).Replace(snmpLegacyForward(target, "", ""))
}

// snmpWANAddressRule is a WAN pass rule for UDP 161 to the WAN address.
func snmpWANAddressRule() string {
	return strings.Replace(snmpForwardRule("", ""), "<address></address>", "<network>wanip</network>", 1)
}

// TestSNMPAgent_ForwardProtocolAndPortsDecideExposure drives OPNsense configs
// with a net-snmp agent bound only to 127.0.0.1 through parse, convert and red
// mode, with port forwards to 127.0.0.1 that differ in protocol and ports. Only
// a forward that can redirect UDP to port 161 reaches the agent and leaves it
// to the WAN rule; a DNS redirect to loopback, such as one sending LAN queries
// to the local resolver, leaves it local.
func TestSNMPAgent_ForwardProtocolAndPortsDecideExposure(t *testing.T) {
	t.Parallel()

	const loopHost = `127.0.0.1`

	tests := []struct {
		name     string
		rules    string
		forwards string
		// protocol, port and local are what the forward must convert to, so
		// a case cannot pass on a field the parser did not read.
		protocol, port, local string
		exposed               bool
	}{
		{
			name:     "WAN forward of UDP 1161 to 127.0.0.1 port 161",
			protocol: "udp", port: "1161", local: "161",
			rules: snmpForwardRule(loopHost, "nat_1"),
			forwards: strings.Replace(
				snmpLegacyForward(loopHost, "nat_1", ""), "<port>161<", "<port>1161<", 1),
			exposed: true,
		},
		{
			// OPNsense drops the ports of a forward with no protocol, so it
			// redirects UDP 161 to loopback with the port kept.
			name:  "26.1 forward of any protocol to 127.0.0.1",
			rules: snmpForwardRule(loopHost, "nat_1"),
			forwards: strings.NewReplacer(
				"<protocol>udp</protocol>", "<protocol/>",
				"<port>161</port>", "<port/>",
				"<local-port>161</local-port>", "<local-port/>",
			).Replace(snmpModelForward(loopHost, "0")),
			exposed: true,
		},
		{
			name:     "rule to 127.0.0.1 of its own, LAN forward of TCP/UDP 53 to 127.0.0.1 port 53",
			protocol: "tcp/udp", port: "53", local: "53",
			rules:    snmpForwardRule(loopHost, ""),
			forwards: snmpDNSForward(loopHost),
		},
		{
			name:     "rule to the WAN address, LAN forward of TCP/UDP 53 to 127.0.0.1 port 53",
			protocol: "tcp/udp", port: "53", local: "53",
			rules:    snmpWANAddressRule(),
			forwards: snmpDNSForward(loopHost),
		},
		{
			name:     "rule to 127.0.0.1 of its own, WAN forward of UDP 161 to 127.0.0.1 port 1161",
			protocol: "udp", port: "161", local: "1161",
			rules: snmpForwardRule(loopHost, ""),
			forwards: strings.Replace(
				snmpLegacyForward(loopHost, "", ""), "<local-port>161<", "<local-port>1161<", 1),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device := parseConfig(t, snmpForwardConfig(loopHost, tc.rules, tc.forwards, ""))
			require.Equal(t, []string{loopHost}, device.SNMP.ListenAddresses)
			require.Len(t, device.NAT.InboundRules, 1)
			forward := device.NAT.InboundRules[0]
			require.False(t, forward.Disabled, "disabled")
			require.Equal(t, tc.protocol, forward.Protocol, "protocol")
			require.Equal(t, tc.port, forward.Destination.Port, "destination port")
			require.Equal(t, tc.local, forward.LocalPort, "local port")

			assertSNMPForwardExposure(t, device, tc.exposed)
		})
	}
}

// TestForwardCanReachSNMPPort checks which port forwards can redirect UDP to
// port 161, where the os-net-snmp agent listens. OPNsense reads a forward's
// ports only for tcp, udp and tcp/udp, so a forward with no protocol reaches
// the agent whatever ports it names, and one for another protocol never does.
// For udp and tcp/udp the destination port decides without a local port, and
// the local port decides with one when the destination port is a single number
// or any port. A port alias is read as reaching the agent, as is a range
// mapped to a local port.
func TestForwardCanReachSNMPPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                       string
		protocol, dstPort, locPort string
		want                       bool
	}{
		{name: "no protocol, no ports", want: true},
		{name: "no protocol, DNS ports", dstPort: "53", locPort: "53", want: true},
		{name: "any protocol, DNS port", protocol: "any", dstPort: "53", want: true},
		{name: "ANY protocol", protocol: "ANY", dstPort: "53", want: true},
		{name: "udp to 161", protocol: "udp", dstPort: "161", want: true},
		{name: "UDP to 161 kept as 161", protocol: "UDP", dstPort: "161", locPort: "161", want: true},
		{name: "udp with surrounding space", protocol: " udp ", dstPort: "161", want: true},
		{name: "tcp/udp to 161", protocol: "tcp/udp", dstPort: "161", locPort: "161", want: true},
		{name: "TCP/UDP DNS redirect", protocol: "TCP/UDP", dstPort: "53", locPort: "53"},
		{name: "tcp to 161", protocol: "tcp", dstPort: "161", locPort: "161"},
		{name: "icmp", protocol: "icmp"},
		{name: "udplite to 161", protocol: "udplite", dstPort: "161"},
		{name: "udp, any destination port", protocol: "udp", want: true},
		{name: "udp, destination port any", protocol: "udp", dstPort: "any", want: true},
		{name: "udp to 53", protocol: "udp", dstPort: "53"},
		{name: "udp to a range holding 161", protocol: "udp", dstPort: "100-200", want: true},
		{name: "udp to a range below 161", protocol: "udp", dstPort: "1-100"},
		{name: "udp to a port alias", protocol: "udp", dstPort: "SNMP_PORTS", want: true},
		{name: "udp to the snmp service name", protocol: "udp", dstPort: "snmp", want: true},
		{name: "udp 1161 to local port 161", protocol: "udp", dstPort: "1161", locPort: "161", want: true},
		{name: "udp 161 to local port 1161", protocol: "udp", dstPort: "161", locPort: "1161"},
		{name: "udp 161 to local port 53", protocol: "udp", dstPort: "161", locPort: "53"},
		{name: "udp, any destination port, to local port 53", protocol: "udp", locPort: "53"},
		{
			name:     "udp, destination port any, to local port 161",
			protocol: "udp",
			dstPort:  "any",
			locPort:  "161",
			want:     true,
		},
		{name: "udp range mapped from local port 53", protocol: "udp", dstPort: "1000-2000", locPort: "53", want: true},
		{name: "udp alias mapped to local port 53", protocol: "udp", dstPort: "SNMP_PORTS", locPort: "53", want: true},
		{name: "udp 53 to a local port alias", protocol: "udp", dstPort: "53", locPort: "SNMP_PORTS", want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			nat := common.InboundNATRule{
				Protocol:    tc.protocol,
				Destination: common.RuleEndpoint{Port: tc.dstPort},
				LocalPort:   tc.locPort,
			}

			assert.Equal(t, tc.want, forwardCanReachSNMPPort(nat))
		})
	}
}

// TestForwardsToLoopback_PortAndTargetOnOneForward checks that the forward
// which can reach port 161 must also be the one whose target holds loopback: a
// DNS redirect to loopback beside an SNMP forward to a LAN host does not count,
// in either order, and an SNMP forward to loopback counts beside a DNS redirect
// to loopback, in either order.
func TestForwardsToLoopback_PortAndTargetOnOneForward(t *testing.T) {
	t.Parallel()

	dnsToLoopback := common.InboundNATRule{
		Protocol:    "tcp/udp",
		Destination: common.RuleEndpoint{Port: "53"},
		InternalIP:  "127.0.0.1",
		LocalPort:   "53",
	}
	snmpToLAN := common.InboundNATRule{
		Protocol:    "udp",
		Destination: common.RuleEndpoint{Port: "161"},
		InternalIP:  "192.168.1.50",
		LocalPort:   "161",
	}
	snmpToLoopback := snmpToLAN
	snmpToLoopback.InternalIP = "127.0.0.1"

	tests := []struct {
		name     string
		forwards []common.InboundNATRule
		want     bool
	}{
		{name: "DNS redirect to loopback alone", forwards: []common.InboundNATRule{dnsToLoopback}},
		{
			name:     "DNS redirect to loopback, then SNMP forward to a LAN host",
			forwards: []common.InboundNATRule{dnsToLoopback, snmpToLAN},
		},
		{
			name:     "SNMP forward to a LAN host, then DNS redirect to loopback",
			forwards: []common.InboundNATRule{snmpToLAN, dnsToLoopback},
		},
		{
			name:     "DNS redirect to loopback, then SNMP forward to loopback",
			forwards: []common.InboundNATRule{dnsToLoopback, snmpToLoopback},
			want:     true,
		},
		{
			name:     "SNMP forward to loopback, then DNS redirect to loopback",
			forwards: []common.InboundNATRule{snmpToLoopback, dnsToLoopback},
			want:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device := &common.CommonDevice{NAT: common.NATConfig{InboundRules: tc.forwards}}

			assert.Equal(t, tc.want, forwardsToLoopback(device))
		})
	}
}
