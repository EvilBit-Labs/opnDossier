package analysis_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
)

// uplinkDevice holds an inside interface, a static second uplink on opt1 that
// selects its gateway, and a group per question asked of it. The interesting
// member of each group is listed second.
func uplinkDevice() *common.CommonDevice {
	return &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", Enabled: true, IPAddress: "dhcp"},
			{Name: "lan", Enabled: true, IPAddress: "192.168.1.1"},
			{Name: "opt1", Enabled: true, IPAddress: "198.51.100.2", Gateway: "ISP2_GW"},
			{Name: "opt2", Enabled: true, IPAddress: "10.0.2.1"},
			{Name: "UPLINKS", Enabled: true, Type: "group", Virtual: true},
		},
		InterfaceGroups: []common.InterfaceGroup{
			{Name: "UPLINKS", Members: []string{"lan", "opt1"}},
			{Name: "INSIDE", Members: []string{"lan", "opt2"}},
			{Name: "wanside", Members: []string{"lan", "opt2"}},
		},
		Routing: common.Routing{
			Gateways: []common.Gateway{
				{Name: "ISP2_GW", Interface: "opt1", Address: "198.51.100.1"},
				{Name: "CORE_GW", Interface: "opt2", Address: "10.0.2.254", DefaultGW: "0"},
			},
		},
	}
}

func TestIsWANInterface_UplinkSignals(t *testing.T) {
	t.Parallel()

	device := uplinkDevice()

	tests := []struct {
		name string
		want bool
	}{
		{"wan", true},
		{"opt1", true},
		{"lan", false},
		{"opt2", false},
		{"UPLINKS", true},
		{"INSIDE", false},
		// A listed group is decided by its members, not its name.
		{"wanside", false},
		// A name nothing defines keeps the key test.
		{"wan2", true},
		{"opt9", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, analysis.IsWANInterface(device, tt.name))
		})
	}
}

func TestInterfaceReachability_UplinkSignals(t *testing.T) {
	t.Parallel()

	device := uplinkDevice()
	device.Routing.Gateways = append(device.Routing.Gateways,
		common.Gateway{Name: "ISP3_GW", Interface: "opt3", Address: "203.0.113.1", DefaultGW: "1"},
		common.Gateway{Name: "ISP4_GW", Interface: "opt4", Address: "203.0.113.9", DefaultGW: "1", Disabled: true},
	)

	tests := []struct {
		name  string
		iface common.Interface
		want  analysis.Reachability
	}{
		{"selects a gateway", common.Interface{Name: "opt1", Enabled: true, Gateway: "ISP2_GW"}, analysis.WANReachable},
		{
			"selects an IPv6 gateway",
			common.Interface{Name: "opt5", Enabled: true, GatewayV6: "ISP2_GWv6"},
			analysis.WANReachable,
		},
		{
			"gateway selection disabled",
			common.Interface{Name: "opt5", Enabled: true, Gateway: "none"},
			analysis.LANOnly,
		},
		{
			"carries the default gateway",
			common.Interface{Name: "opt3", Enabled: true, IPAddress: "203.0.113.2"},
			analysis.WANReachable,
		},
		{
			"default gateway disabled",
			common.Interface{Name: "opt4", Enabled: true, IPAddress: "203.0.113.10"},
			analysis.LANOnly,
		},
		{
			"gateway that is not the default",
			common.Interface{Name: "opt2", Enabled: true, IPAddress: "10.0.2.1"},
			analysis.LANOnly,
		},
		{"pppoe", common.Interface{Name: "opt5", Enabled: true, IPAddress: "pppoe"}, analysis.WANReachable},
		{"dhcp", common.Interface{Name: "opt5", Enabled: true, IPAddress: "dhcp"}, analysis.WANReachable},
		{"slaac", common.Interface{Name: "opt5", Enabled: true, IPv6Address: "slaac"}, analysis.WANReachable},
		{"track6", common.Interface{Name: "opt5", Enabled: true, IPv6Address: "track6"}, analysis.LANOnly},
		{"disabled uplink", common.Interface{Name: "opt1", Gateway: "ISP2_GW"}, analysis.Local},
		// The entry OPNsense writes for a group under <interfaces> is not an
		// uplink of its own, so interface-level controls do not read it.
		{
			"group entry",
			common.Interface{Name: "UPLINKS", Enabled: true, Type: "group", Virtual: true},
			analysis.LANOnly,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, analysis.InterfaceReachability(tt.iface, device))
		})
	}
}

func TestDetectUnusedInterfaces_GroupRuleUsesMembers(t *testing.T) {
	t.Parallel()

	device := uplinkDevice()
	device.FirewallRules = []common.FirewallRule{
		{Type: common.RuleTypePass, Interfaces: []string{"UPLINKS"}},
	}

	unused := make([]string, 0, len(device.Interfaces))
	for _, finding := range analysis.DetectUnusedInterfaces(device) {
		unused = append(unused, finding.InterfaceName)
	}

	assert.NotContains(t, unused, "lan")
	assert.NotContains(t, unused, "opt1")
	assert.NotContains(t, unused, "UPLINKS")
	assert.Contains(t, unused, "opt2")
}
