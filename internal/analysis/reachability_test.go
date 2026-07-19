package analysis_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
)

// TestIsWANInterfaceName_Characterization pins the current isWANInterface
// behavior (case-insensitive "wan" prefix match) that previously lived,
// duplicated, in internal/plugins/sans and internal/plugins/firewall. This
// characterization test is the baseline the U1 consolidation must not
// regress. Covers AE5.
func TestIsWANInterfaceName_Characterization(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want bool
	}{
		{"wan", true},
		{"WAN", true},
		{"wan2", true},
		{"WAN2", true},
		{"wanbackup", true},
		{"lan", false},
		{"LAN", false},
		{"opt1", false},
		{"dmz", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, analysis.IsWANInterfaceName(tt.name))
		})
	}
}

// TestInterfaceReachability covers AE5 (multi-WAN, case-insensitivity) and
// the loopback/local case named in U1's test scenarios.
func TestInterfaceReachability(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		iface common.Interface
		want  analysis.Reachability
	}{
		{
			name:  "wan lowercase",
			iface: common.Interface{Name: "wan", Enabled: true},
			want:  analysis.WANReachable,
		},
		{
			name:  "WAN uppercase",
			iface: common.Interface{Name: "WAN", Enabled: true},
			want:  analysis.WANReachable,
		},
		{
			name:  "wan2 multi-wan",
			iface: common.Interface{Name: "wan2", Enabled: true},
			want:  analysis.WANReachable,
		},
		{
			name:  "lan",
			iface: common.Interface{Name: "lan", Enabled: true},
			want:  analysis.LANOnly,
		},
		{
			name:  "disabled wan is local",
			iface: common.Interface{Name: "wan", Enabled: false},
			want:  analysis.Local,
		},
		{
			name:  "loopback is local",
			iface: common.Interface{Name: "lo0", Enabled: true},
			want:  analysis.Local,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, analysis.InterfaceReachability(tt.iface))
		})
	}
}

// TestRuleReachability covers AE6: floating rules, IPv6 WAN interfaces, and
// regression parity with the pre-consolidation single-WAN behavior.
func TestRuleReachability(t *testing.T) {
	t.Parallel()

	wanIface := common.Interface{Name: "wan", Enabled: true}
	lanIface := common.Interface{Name: "lan", Enabled: true}
	ifaces := []common.Interface{wanIface, lanIface}

	tests := []struct {
		name   string
		rule   common.FirewallRule
		ifaces []common.Interface
		want   analysis.Reachability
	}{
		{
			name:   "bound to wan interface",
			rule:   common.FirewallRule{Interfaces: []string{"wan"}},
			ifaces: ifaces,
			want:   analysis.WANReachable,
		},
		{
			name:   "bound to multi-wan wan2",
			rule:   common.FirewallRule{Interfaces: []string{"wan2"}},
			ifaces: []common.Interface{{Name: "wan2", Enabled: true}, lanIface},
			want:   analysis.WANReachable,
		},
		{
			name:   "bound to lan only",
			rule:   common.FirewallRule{Interfaces: []string{"lan"}},
			ifaces: ifaces,
			want:   analysis.LANOnly,
		},
		{
			name:   "floating rule with wan interface present",
			rule:   common.FirewallRule{Floating: true},
			ifaces: ifaces,
			want:   analysis.WANReachable,
		},
		{
			name:   "floating rule with no wan interface present",
			rule:   common.FirewallRule{Floating: true},
			ifaces: []common.Interface{lanIface},
			want:   analysis.LANOnly,
		},
		{
			name:   "floating rule whose only wan interface is disabled is lan-only",
			rule:   common.FirewallRule{Floating: true},
			ifaces: []common.Interface{{Name: "wan", Enabled: false}, lanIface},
			want:   analysis.LANOnly,
		},
		{
			name:   "interface-scoped floating rule to lan is not wan-reachable",
			rule:   common.FirewallRule{Floating: true, Interfaces: []string{"lan"}},
			ifaces: ifaces,
			want:   analysis.LANOnly,
		},
		{
			name:   "interface-scoped floating rule to wan is wan-reachable",
			rule:   common.FirewallRule{Floating: true, Interfaces: []string{"wan"}},
			ifaces: ifaces,
			want:   analysis.WANReachable,
		},
		{
			name: "ipv6 wan interface",
			rule: common.FirewallRule{
				Interfaces: []string{"wan"},
				IPProtocol: common.IPProtocolInet6,
			},
			ifaces: []common.Interface{{Name: "wan", Enabled: true, IPv6Address: "2001:db8::1"}, lanIface},
			want:   analysis.WANReachable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, analysis.RuleReachability(tt.rule, tt.ifaces))
		})
	}
}

// TestInboundNATRuleReachability covers the AE6 NAT-without-pass-rule case:
// NAT presence alone must never be reported WAN-reachable.
func TestInboundNATRuleReachability(t *testing.T) {
	t.Parallel()

	ifaces := []common.Interface{{Name: "wan", Enabled: true}, {Name: "lan", Enabled: true}}

	wanPassRule := common.FirewallRule{
		Type:       common.RuleTypePass,
		Interfaces: []string{"wan"},
	}

	tests := []struct {
		name      string
		nat       common.InboundNATRule
		passRules []common.FirewallRule
		want      analysis.Reachability
	}{
		{
			name:      "NAT on WAN with no matching pass rule is not WAN-reachable",
			nat:       common.InboundNATRule{Interfaces: []string{"wan"}},
			passRules: nil,
			want:      analysis.LANOnly,
		},
		{
			name:      "NAT on WAN with a matching enabled WAN pass rule is WAN-reachable",
			nat:       common.InboundNATRule{Interfaces: []string{"wan"}},
			passRules: []common.FirewallRule{wanPassRule},
			want:      analysis.WANReachable,
		},
		{
			name: "NAT on WAN with only a disabled pass rule is not WAN-reachable",
			nat:  common.InboundNATRule{Interfaces: []string{"wan"}},
			passRules: []common.FirewallRule{
				{Type: common.RuleTypePass, Interfaces: []string{"wan"}, Disabled: true},
			},
			want: analysis.LANOnly,
		},
		{
			name:      "disabled NAT rule is local regardless of pass rules",
			nat:       common.InboundNATRule{Interfaces: []string{"wan"}, Disabled: true},
			passRules: []common.FirewallRule{wanPassRule},
			want:      analysis.Local,
		},
		{
			name:      "NAT rule not bound to WAN is LAN-only",
			nat:       common.InboundNATRule{Interfaces: []string{"lan"}},
			passRules: []common.FirewallRule{wanPassRule},
			want:      analysis.LANOnly,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := analysis.InboundNATRuleReachability(tt.nat, ifaces, tt.passRules)
			assert.Equal(t, tt.want, got)
		})
	}
}
