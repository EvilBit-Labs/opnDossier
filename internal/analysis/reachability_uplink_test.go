package analysis_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
)

// uplinkDevice holds wan, inside interfaces, and a group per question asked of
// it. The interesting member of each group is listed second.
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
			{Name: "UPLINKS", Members: []string{"lan", "wan"}},
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
		{"opt1", false},
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
	assert.NotContains(t, unused, "wan")
	assert.NotContains(t, unused, "UPLINKS")
	assert.Contains(t, unused, "opt2")
}
