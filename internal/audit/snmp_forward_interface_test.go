package audit

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSNMPAgent_ForwardInterfaceIsNotRead pins what GOTCHAS.md section 8.4
// says of forwardsToLoopback: the forward's interface is not read. A LAN
// forward of UDP 161 to loopback lets LAN hosts reach an agent bound only to
// 127.0.0.1, and it also keeps the agent from being set Local, so a WAN rule
// passing UDP 161 to the firewall reports the agent as WAN-exposed. No WAN
// packet is redirected to the agent, so that over-reports, the safe direction.
func TestSNMPAgent_ForwardInterfaceIsNotRead(t *testing.T) {
	t.Parallel()

	const loopHost = `127.0.0.1`

	lanForward := strings.Replace(snmpLegacyForward(loopHost, "", ""),
		"<interface>wan</interface>", "<interface>lan</interface>", 1)

	tests := []struct {
		name  string
		rules string
	}{
		{name: "WAN rule to 127.0.0.1 of its own", rules: snmpForwardRule(loopHost, "")},
		{name: "WAN rule to the WAN address", rules: snmpWANAddressRule()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device := parseConfig(t, snmpForwardConfig(loopHost, tc.rules, lanForward, ""))
			require.Equal(t, []string{loopHost}, device.SNMP.ListenAddresses)
			require.Len(t, device.NAT.InboundRules, 1)
			forward := device.NAT.InboundRules[0]
			require.Equal(t, []string{"lan"}, forward.Interfaces, "interfaces")
			require.Equal(t, "udp", forward.Protocol, "protocol")
			require.Equal(t, loopHost, forward.InternalIP, "target")

			assertSNMPForwardExposure(t, device, true)
		})
	}
}
