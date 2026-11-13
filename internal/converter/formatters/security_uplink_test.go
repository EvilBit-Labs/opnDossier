package formatters

import (
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// TestHasManagementOnWAN_UplinkShapes covers the security score's WAN test,
// which goes through the shared classifier: a management port open on a
// second uplink or on an interface group with a WAN member counts, and one on
// an inside group does not.
func TestHasManagementOnWAN_UplinkShapes(t *testing.T) {
	t.Parallel()

	device := func(iface string) *common.CommonDevice {
		return &common.CommonDevice{
			Interfaces: []common.Interface{
				{Name: "lan", Enabled: true, IPAddress: "192.168.1.1"},
				{Name: "opt1", Enabled: true, IPAddress: "pppoe"},
				{Name: "opt2", Enabled: true, IPAddress: "10.0.2.1"},
			},
			InterfaceGroups: []common.InterfaceGroup{
				{Name: "UPLINKS", Members: []string{"lan", "opt1"}},
				{Name: "INSIDE", Members: []string{"lan", "opt2"}},
			},
			FirewallRules: []common.FirewallRule{
				{
					Type:        common.RuleTypePass,
					Interfaces:  []string{iface},
					Destination: common.RuleEndpoint{Port: "443"},
				},
			},
		}
	}

	for _, tt := range []struct {
		iface string
		want  bool
	}{
		{"opt1", true},
		{"UPLINKS", true},
		{"INSIDE", false},
		{"opt2", false},
	} {
		t.Run(tt.iface, func(t *testing.T) {
			t.Parallel()

			if got := hasManagementOnWAN(device(tt.iface)); got != tt.want {
				t.Errorf("hasManagementOnWAN(rule on %s) = %v, want %v", tt.iface, got, tt.want)
			}
		})
	}
}
