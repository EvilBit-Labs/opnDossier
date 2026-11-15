package audit

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
)

// TestApplySNMPListen_OverridesEarlierReachability checks that an agent bound
// only to loopback is Local whatever reachability the list already gives it,
// WAN-reachable included, so no decision made before applySNMPListen can
// report it as exposed. The SNMP entry is second, ahead of SSH, and the other
// services keep their reachability. Any other listen list leaves every entry
// as it was.
func TestApplySNMPListen_OverridesEarlierReachability(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		listen []string
		before analysis.Reachability
		want   analysis.Reachability
	}{
		{
			name: "IPv4 loopback, WAN-reachable", listen: []string{"127.0.0.1"},
			before: analysis.WANReachable, want: analysis.Local,
		},
		{
			name: "IPv6 loopback, WAN-reachable", listen: []string{"::1"},
			before: analysis.WANReachable, want: analysis.Local,
		},
		{
			name: "both loopbacks, LAN-only", listen: []string{"127.0.0.1", "::1"},
			before: analysis.LANOnly, want: analysis.Local,
		},
		{
			name: "loopback and a LAN address", listen: []string{"127.0.0.1", "192.168.1.1"},
			before: analysis.WANReachable, want: analysis.WANReachable,
		},
		{
			name:   "no listen address",
			before: analysis.WANReachable, want: analysis.WANReachable,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device := &common.CommonDevice{SNMP: common.SNMPConfig{Enabled: true, ListenAddresses: tc.listen}}
			services := []exposedService{
				{kind: exploitKindWebGUI, name: "webgui", reachability: analysis.WANReachable},
				{kind: exploitKindSNMPNoCommunity, name: serviceNameSNMP, reachability: tc.before},
				{kind: exploitKindSSH, name: "ssh", reachability: analysis.WANReachable},
			}

			applySNMPListen(device, services)

			assert.Equal(t, analysis.WANReachable, services[0].reachability, "webgui")
			assert.Equal(t, tc.want, services[1].reachability, "snmp")
			assert.Equal(t, analysis.WANReachable, services[2].reachability, "ssh")
		})
	}
}

// TestApplySNMPListen_NoAgentChangesNothing checks that a loopback listen list
// with no SNMP entry in the list, as when the agent is not running, marks no
// other service Local.
func TestApplySNMPListen_NoAgentChangesNothing(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{SNMP: common.SNMPConfig{ListenAddresses: []string{"127.0.0.1"}}}
	services := []exposedService{
		{kind: exploitKindWebGUI, name: "webgui", reachability: analysis.WANReachable},
		{kind: exploitKindSSH, name: "ssh", reachability: analysis.LANOnly},
	}

	applySNMPListen(device, services)

	assert.Equal(t, analysis.WANReachable, services[0].reachability, "webgui")
	assert.Equal(t, analysis.LANOnly, services[1].reachability, "ssh")
}
