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
