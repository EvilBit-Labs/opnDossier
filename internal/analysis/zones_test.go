package analysis_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
)

func TestIsNetworkZone(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		iface common.Interface
		want  bool
	}{
		{name: "enabled network", iface: common.Interface{Name: "lan", Enabled: true, Type: "static"}, want: true},
		{name: "disabled network", iface: common.Interface{Name: "opt1", Type: "static"}},
		{name: "loopback", iface: common.Interface{Name: "lo0", Enabled: true, Type: "none", Virtual: true}},
		{name: "group", iface: common.Interface{Name: "mgmt", Enabled: true, Type: "group", Virtual: true}},
		{name: "group without virtual flag", iface: common.Interface{Name: "mgmt", Enabled: true, Type: "group"}},
		{name: "IPsec VTI", iface: common.Interface{Name: "ipsec1", Enabled: true, Type: "none"}, want: true},
		{name: "assigned loopback", iface: common.Interface{Name: "opt1", PhysicalIf: "lo1", Enabled: true}},
		{name: "VLAN", iface: common.Interface{Name: "opt2", PhysicalIf: "vtnet0_vlan10", Enabled: true}, want: true},
		{name: "bridge", iface: common.Interface{Name: "opt3", PhysicalIf: "bridge0", Enabled: true}, want: true},
		{name: "LAGG", iface: common.Interface{Name: "opt4", PhysicalIf: "lagg0", Enabled: true}, want: true},
		{name: "OpenVPN", iface: common.Interface{Name: "opt5", PhysicalIf: "ovpns1", Enabled: true}, want: true},
		{name: "WireGuard", iface: common.Interface{Name: "opt6", PhysicalIf: "wg0", Enabled: true}, want: true},
		{
			name:  "device named like loopback",
			iface: common.Interface{Name: "opt7", PhysicalIf: "lo1x", Enabled: true},
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, analysis.IsNetworkZone(tt.iface))
		})
	}
}

func TestCountNetworkZones(t *testing.T) {
	t.Parallel()

	assert.Zero(t, analysis.CountNetworkZones(nil))
	assert.Equal(t, 1, analysis.CountNetworkZones(&common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "lo0", Enabled: true, Virtual: true},
			{Name: "wan", Enabled: true},
			{Name: "lan"},
		},
	}))
}
