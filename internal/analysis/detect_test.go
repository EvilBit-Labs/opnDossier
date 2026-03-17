package analysis_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeAnalysis(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                  string
		cfg                   *common.CommonDevice
		wantDeadRules         int
		wantUnusedInterfaces  int
		wantSecurityIssues    int
		wantPerformanceIssues int
		wantConsistencyIssues int
	}{
		{
			name: "minimal device produces no findings",
			cfg:  &common.CommonDevice{},
		},
		{
			name: "nil device produces no findings",
			cfg:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := analysis.ComputeAnalysis(tt.cfg)

			require.NotNil(t, result)
			assert.Len(t, result.DeadRules, tt.wantDeadRules)
			assert.Len(t, result.UnusedInterfaces, tt.wantUnusedInterfaces)
			assert.Len(t, result.SecurityIssues, tt.wantSecurityIssues)
			assert.Len(t, result.PerformanceIssues, tt.wantPerformanceIssues)
			assert.Len(t, result.ConsistencyIssues, tt.wantConsistencyIssues)
		})
	}
}

func TestDetectDeadRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		cfg          *common.CommonDevice
		wantCount    int
		wantIndex    int
		wantIface    string
		wantContains string
		wantKind     string
	}{
		{
			name:      "nil device",
			cfg:       nil,
			wantCount: 0,
		},
		{
			name:      "empty rules",
			cfg:       &common.CommonDevice{},
			wantCount: 0,
		},
		{
			name: "block-all with subsequent rules",
			cfg: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        "block",
						Interfaces:  []string{"wan"},
						Source:      common.RuleEndpoint{Address: "any"},
						Destination: common.RuleEndpoint{Address: "any"},
					},
					{
						Type:        "pass",
						Interfaces:  []string{"wan"},
						Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
						Destination: common.RuleEndpoint{Address: "10.0.0.0/8"},
					},
				},
			},
			wantCount:    1,
			wantIndex:    0,
			wantIface:    "wan",
			wantContains: "unreachable",
			wantKind:     common.DeadRuleKindUnreachable,
		},
		{
			name: "block-all as last rule produces no finding",
			cfg: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        "pass",
						Interfaces:  []string{"wan"},
						Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
						Destination: common.RuleEndpoint{Address: "any"},
					},
					{
						Type:        "block",
						Interfaces:  []string{"wan"},
						Source:      common.RuleEndpoint{Address: "any"},
						Destination: common.RuleEndpoint{Address: "any"},
					},
				},
			},
			wantCount: 0,
		},
		{
			name: "duplicate rules detected",
			cfg: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        "pass",
						IPProtocol:  "inet",
						Interfaces:  []string{"lan"},
						Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
						Destination: common.RuleEndpoint{Address: "any"},
					},
					{
						Type:        "pass",
						IPProtocol:  "inet",
						Interfaces:  []string{"lan"},
						Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
						Destination: common.RuleEndpoint{Address: "any"},
					},
				},
			},
			wantCount:    1,
			wantIndex:    1,
			wantIface:    "lan",
			wantContains: "duplicate",
			wantKind:     common.DeadRuleKindDuplicate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := analysis.DetectDeadRules(tt.cfg)

			require.Len(t, findings, tt.wantCount)
			if tt.wantCount > 0 {
				assert.Equal(t, tt.wantIndex, findings[0].RuleIndex)
				assert.Equal(t, tt.wantIface, findings[0].Interface)
				assert.Contains(t, findings[0].Description, tt.wantContains)
				assert.Equal(t, tt.wantKind, findings[0].Kind)
			}
		})
	}
}

func TestDetectUnusedInterfaces(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cfg       *common.CommonDevice
		wantCount int
		wantNames []string
	}{
		{
			name:      "nil device",
			cfg:       nil,
			wantCount: 0,
		},
		{
			name: "enabled unused interface flagged",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "wan", Enabled: true},
					{Name: "lan", Enabled: true},
					{Name: "opt1", Enabled: true},
					{Name: "opt2", Enabled: false},
				},
				FirewallRules: []common.FirewallRule{
					{Interfaces: []string{"wan"}},
					{Interfaces: []string{"lan"}},
				},
			},
			wantCount: 1,
			wantNames: []string{"opt1"},
		},
		{
			name: "used by DHCP not flagged",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "opt1", Enabled: true},
				},
				DHCP: []common.DHCPScope{
					{Interface: "opt1", Enabled: true},
				},
			},
			wantCount: 0,
		},
		{
			name: "used by OpenVPN server not flagged",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "opt1", Enabled: true},
				},
				VPN: common.VPN{
					OpenVPN: common.OpenVPNConfig{
						Servers: []common.OpenVPNServer{
							{Interface: "opt1"},
						},
					},
				},
			},
			wantCount: 0,
		},
		{
			name: "used by WireGuard not flagged",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "lan", Enabled: true},
				},
				VPN: common.VPN{
					WireGuard: common.WireGuardConfig{Enabled: true},
				},
			},
			wantCount: 0,
		},
		{
			name: "used by DNS not flagged",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "lan", Enabled: true},
				},
				DNS: common.DNSConfig{
					Unbound: common.UnboundConfig{Enabled: true},
				},
			},
			wantCount: 0,
		},
		{
			name: "used by DNSMasq not flagged",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "lan", Enabled: true},
				},
				DNS: common.DNSConfig{
					DNSMasq: common.DNSMasqConfig{Enabled: true},
				},
			},
			wantCount: 0,
		},
		{
			name: "used by OpenVPN client not flagged",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "opt1", Enabled: true},
				},
				VPN: common.VPN{
					OpenVPN: common.OpenVPNConfig{
						Clients: []common.OpenVPNClient{
							{Interface: "opt1"},
						},
					},
				},
			},
			wantCount: 0,
		},
		{
			name: "used by load balancer not flagged",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "lan", Enabled: true},
				},
				LoadBalancer: common.LoadBalancerConfig{
					MonitorTypes: []common.MonitorType{{Name: "http"}},
				},
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := analysis.DetectUnusedInterfaces(tt.cfg)

			require.Len(t, findings, tt.wantCount)
			for i, name := range tt.wantNames {
				assert.Equal(t, name, findings[i].InterfaceName)
			}
		})
	}
}

func TestDetectSecurityIssues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		cfg            *common.CommonDevice
		wantCount      int
		wantIssues     []string
		wantSeverities []string
	}{
		{
			name:      "nil device",
			cfg:       nil,
			wantCount: 0,
		},
		{
			name: "all three issue types",
			cfg: &common.CommonDevice{
				System: common.System{
					WebGUI: common.WebGUI{Protocol: "http"},
				},
				SNMP: common.SNMPConfig{ROCommunity: "public"},
				FirewallRules: []common.FirewallRule{
					{
						Type:       "pass",
						Interfaces: []string{"wan"},
						Source:     common.RuleEndpoint{Address: "any"},
					},
				},
			},
			wantCount: 3,
			wantIssues: []string{
				"Insecure Web GUI Protocol",
				"Default SNMP Community String",
				"Overly Permissive WAN Rule",
			},
			wantSeverities: []string{"critical", "high", "high"},
		},
		{
			name: "secure config produces no findings",
			cfg: &common.CommonDevice{
				System: common.System{
					WebGUI: common.WebGUI{Protocol: "https"},
				},
				SNMP: common.SNMPConfig{ROCommunity: "s3cr3t"},
			},
			wantCount: 0,
		},
		{
			name: "empty protocol not flagged",
			cfg: &common.CommonDevice{
				System: common.System{
					WebGUI: common.WebGUI{Protocol: ""},
				},
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := analysis.DetectSecurityIssues(tt.cfg)

			require.Len(t, findings, tt.wantCount)
			for i := range tt.wantIssues {
				assert.Equal(t, tt.wantIssues[i], findings[i].Issue)
				assert.Equal(t, tt.wantSeverities[i], findings[i].Severity)
			}
		})
	}
}

func TestDetectPerformanceIssues(t *testing.T) {
	t.Parallel()

	highRuleCount := make([]common.FirewallRule, 101)
	for i := range highRuleCount {
		highRuleCount[i] = common.FirewallRule{Type: "pass", Interfaces: []string{"lan"}}
	}

	tests := []struct {
		name           string
		cfg            *common.CommonDevice
		wantCount      int
		wantIssues     []string
		wantSeverities []string
	}{
		{
			name:      "nil device",
			cfg:       nil,
			wantCount: 0,
		},
		{
			name:      "no issues on empty device",
			cfg:       &common.CommonDevice{},
			wantCount: 0,
		},
		{
			name: "both offloading disabled",
			cfg: &common.CommonDevice{
				System: common.System{
					DisableChecksumOffloading:     true,
					DisableSegmentationOffloading: true,
				},
			},
			wantCount:      2,
			wantIssues:     []string{"Checksum Offloading Disabled", "Segmentation Offloading Disabled"},
			wantSeverities: []string{"low", "low"},
		},
		{
			name:           "high rule count",
			cfg:            &common.CommonDevice{FirewallRules: highRuleCount},
			wantCount:      1,
			wantIssues:     []string{"High Number of Firewall Rules"},
			wantSeverities: []string{"medium"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := analysis.DetectPerformanceIssues(tt.cfg)

			require.Len(t, findings, tt.wantCount)
			for i := range tt.wantIssues {
				assert.Equal(t, tt.wantIssues[i], findings[i].Issue)
				assert.Equal(t, tt.wantSeverities[i], findings[i].Severity)
			}
		})
	}
}

func TestDetectConsistency(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		cfg        *common.CommonDevice
		wantCount  int
		wantIssues []string
	}{
		{
			name:      "nil device",
			cfg:       nil,
			wantCount: 0,
		},
		{
			name: "no issues with valid config",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "lan", Enabled: true, IPAddress: "192.168.1.1"},
				},
				DHCP: []common.DHCPScope{
					{
						Interface: "lan",
						Enabled:   true,
						Range:     common.DHCPRange{From: "192.168.1.100", To: "192.168.1.200"},
					},
				},
				Users:  []common.User{{Name: "admin", GroupName: "wheel"}},
				Groups: []common.Group{{Name: "wheel"}},
			},
			wantCount: 0,
		},
		{
			name: "invalid gateway format",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "wan", IPAddress: "1.2.3.4", Subnet: "24", Gateway: "invalid-gw"},
				},
			},
			wantCount:  1,
			wantIssues: []string{"Invalid Gateway Format"},
		},
		{
			name: "valid gateway not flagged",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "wan", IPAddress: "1.2.3.4", Subnet: "24", Gateway: "1.2.3.1"},
				},
			},
			wantCount: 0,
		},
		{
			name: "valid IPv6 gateway not flagged",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "wan", IPAddress: "2001:db8::1", Subnet: "64", Gateway: "fe80::1"},
				},
			},
			wantCount: 0,
		},
		{
			name: "DHCP without interface IP and nonexistent group",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "lan", Enabled: true},
				},
				DHCP: []common.DHCPScope{
					{
						Interface: "lan",
						Enabled:   true,
						Range:     common.DHCPRange{From: "192.168.1.100", To: "192.168.1.200"},
					},
				},
				Users:  []common.User{{Name: "admin", GroupName: "nonexistent"}},
				Groups: []common.Group{{Name: "wheel"}},
			},
			wantCount:  2,
			wantIssues: []string{"DHCP Enabled Without Interface IP", "User References Non-existent Group"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := analysis.DetectConsistency(tt.cfg)

			require.Len(t, findings, tt.wantCount)
			for i, wantIssue := range tt.wantIssues {
				assert.Equal(t, wantIssue, findings[i].Issue)
			}
		})
	}
}
