package formatters

import (
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// TestCalculateSecurityScore_PacketFilterDisabled checks that a device with pf
// off takes the missing-rules and management-on-WAN penalties once each,
// whatever its rules say, so the score cannot read as a filtered firewall's.
func TestCalculateSecurityScore_PacketFilterDisabled(t *testing.T) {
	t.Parallel()

	device := func(disabled bool) *common.CommonDevice {
		return &common.CommonDevice{
			System: common.System{PacketFilterDisabled: disabled},
			FirewallRules: []common.FirewallRule{
				{Type: common.RuleTypePass, Interfaces: []string{"lan"}},
			},
			Sysctl: []common.SysctlItem{
				{Tunable: "net.inet.ip.forwarding", Value: "0"},
				{Tunable: "net.inet6.ip6.forwarding", Value: "0"},
				{Tunable: "net.inet.tcp.blackhole", Value: "2"},
				{Tunable: "net.inet.udp.blackhole", Value: "1"},
			},
		}
	}

	if got := CalculateSecurityScore(device(false)); got != initialSecurityScore {
		t.Fatalf("filtering on: score = %d, want %d", got, initialSecurityScore)
	}

	want := initialSecurityScore - firewallMissingPenalty - managementOnWANPenalty
	if got := CalculateSecurityScore(device(true)); got != want {
		t.Errorf("filtering off: score = %d, want %d", got, want)
	}
}
