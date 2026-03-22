package analysis_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeStatistics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		cfg                *common.CommonDevice
		wantInterfaces     int
		wantFirewallRules  int
		wantServices       int
		wantVLANs          int
		wantBridges        int
		wantCertificates   int
		wantCAs            int
		wantNATEntries     int
		wantNATMode        common.NATOutboundMode
		wantHasSecFeatures bool
		wantSecFeatures    []string
		wantServiceNames   []string
		wantPositiveScore  bool
		checkMapsNotNil    bool
	}{
		{
			name:            "nil device returns initialized empty stats",
			cfg:             nil,
			checkMapsNotNil: true,
		},
		{
			name:            "minimal empty device",
			cfg:             &common.CommonDevice{},
			checkMapsNotNil: true,
		},
		{
			name: "interfaces with security features",
			cfg: &common.CommonDevice{
				Interfaces: []common.Interface{
					{
						Name:         "wan",
						Type:         "ethernet",
						Enabled:      true,
						BlockPrivate: true,
						BlockBogons:  true,
						IPAddress:    "1.2.3.4",
					},
					{Name: "lan", Type: "ethernet", Enabled: true, IPAddress: "192.168.1.1"},
					{Name: "opt1", Type: "ethernet", Enabled: true},
				},
				FirewallRules: []common.FirewallRule{
					{Type: common.RuleTypePass, Interfaces: []string{"wan"}},
					{Type: common.RuleTypePass, Interfaces: []string{"lan"}},
					{Type: common.RuleTypeBlock, Interfaces: []string{"wan"}},
				},
				System: common.System{
					WebGUI: common.WebGUI{Protocol: "https"},
					SSH:    common.SSH{Group: "admins"},
				},
			},
			wantInterfaces:     3,
			wantFirewallRules:  3,
			wantHasSecFeatures: true,
			wantSecFeatures:    []string{"Block Private Networks", "Block Bogon Networks", "HTTPS Web GUI"},
			wantPositiveScore:  true,
		},
		{
			name: "NAT entries count both directions",
			cfg: &common.CommonDevice{
				NAT: common.NATConfig{
					OutboundMode: common.OutboundAutomatic,
					OutboundRules: []common.NATRule{
						{Description: "outbound1"},
						{Description: "outbound2"},
					},
					InboundRules: []common.InboundNATRule{
						{Description: "inbound1"},
					},
				},
			},
			wantNATEntries: 3,
			wantNATMode:    common.OutboundAutomatic,
		},
		{
			name: "network infrastructure counts",
			cfg: &common.CommonDevice{
				VLANs:   []common.VLAN{{Tag: "100"}, {Tag: "200"}},
				Bridges: []common.Bridge{{BridgeIf: "bridge0"}},
				Certificates: []common.Certificate{
					{Description: "cert1"},
					{Description: "cert2"},
					{Description: "cert3"},
				},
				CAs: []common.CertificateAuthority{{Description: "ca1"}},
			},
			wantVLANs:        2,
			wantBridges:      1,
			wantCertificates: 3,
			wantCAs:          1,
		},
		{
			name: "all service types detected",
			cfg: &common.CommonDevice{
				DHCP: []common.DHCPScope{
					{
						Interface: "lan",
						Enabled:   true,
						Range:     common.DHCPRange{From: "192.168.1.100", To: "192.168.1.200"},
					},
				},
				DNS: common.DNSConfig{Unbound: common.UnboundConfig{Enabled: true}},
				SNMP: common.SNMPConfig{
					ROCommunity: "mysecret",
					SysLocation: "rack1",
					SysContact:  "admin@example.com",
				},
				System: common.System{SSH: common.SSH{Group: "wheel"}},
				NTP:    common.NTPConfig{PreferredServer: "0.pool.ntp.org"},
			},
			wantServices: 5,
			wantServiceNames: []string{
				"DHCP Server (LAN)",
				"Unbound DNS Resolver",
				analysis.ServiceNameSNMP,
				"SSH Daemon",
				"NTP Daemon",
			},
		},
		{
			name: "SNMP community stored raw in service details",
			cfg: &common.CommonDevice{
				SNMP: common.SNMPConfig{ROCommunity: "secretcommunity"},
			},
			wantServices: 1,
		},
		{
			name: "NAT reflection disabled detected as security feature",
			cfg: &common.CommonDevice{
				System: common.System{DisableNATReflection: true},
			},
			wantHasSecFeatures: true,
			wantSecFeatures:    []string{"NAT Reflection Disabled"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stats := analysis.ComputeStatistics(tt.cfg)
			require.NotNil(t, stats)

			if tt.checkMapsNotNil {
				assert.NotNil(t, stats.InterfacesByType)
				assert.NotNil(t, stats.RulesByInterface)
				assert.NotNil(t, stats.RulesByType)
				assert.NotNil(t, stats.UsersByScope)
				assert.NotNil(t, stats.GroupsByScope)
				assert.NotNil(t, stats.EnabledServices)
				assert.NotNil(t, stats.ServiceDetails)
				assert.NotNil(t, stats.SecurityFeatures)
			}

			assert.Equal(t, tt.wantInterfaces, stats.TotalInterfaces)
			assert.Equal(t, tt.wantFirewallRules, stats.TotalFirewallRules)
			assert.Equal(t, tt.wantVLANs, stats.TotalVLANs)
			assert.Equal(t, tt.wantBridges, stats.TotalBridges)
			assert.Equal(t, tt.wantCertificates, stats.TotalCertificates)
			assert.Equal(t, tt.wantCAs, stats.TotalCAs)
			assert.Equal(t, tt.wantNATEntries, stats.NATEntries)
			assert.Equal(t, tt.wantNATMode, stats.NATMode)
			assert.Equal(t, tt.wantHasSecFeatures, stats.Summary.HasSecurityFeatures)

			if tt.wantPositiveScore {
				assert.Positive(t, stats.Summary.SecurityScore)
			}

			for _, feature := range tt.wantSecFeatures {
				assert.Contains(t, stats.SecurityFeatures, feature)
			}

			if tt.wantServices > 0 {
				assert.Equal(t, tt.wantServices, stats.TotalServices)
			}

			for _, name := range tt.wantServiceNames {
				assert.Contains(t, stats.EnabledServices, name)
			}
		})
	}
}

func TestComputeStatistics_UserAndGroupScopes(t *testing.T) {
	t.Parallel()

	cfg := &common.CommonDevice{
		Users: []common.User{
			{Name: "admin", Scope: "system"},
			{Name: "user1", Scope: "user"},
			{Name: "user2", Scope: "user"},
		},
		Groups: []common.Group{
			{Name: "admins", Scope: "system"},
			{Name: "users", Scope: "local"},
		},
	}

	stats := analysis.ComputeStatistics(cfg)

	assert.Equal(t, 3, stats.TotalUsers)
	assert.Equal(t, 2, stats.TotalGroups)
	assert.Equal(t, 1, stats.UsersByScope["system"])
	assert.Equal(t, 2, stats.UsersByScope["user"])
	assert.Equal(t, 1, stats.GroupsByScope["system"])
	assert.Equal(t, 1, stats.GroupsByScope["local"])
}

func TestComputeStatistics_SNMPCommunityRawValue(t *testing.T) {
	t.Parallel()

	cfg := &common.CommonDevice{
		SNMP: common.SNMPConfig{ROCommunity: "secretcommunity"},
	}

	stats := analysis.ComputeStatistics(cfg)

	require.Len(t, stats.ServiceDetails, 1)
	assert.Equal(t, analysis.ServiceNameSNMP, stats.ServiceDetails[0].Name)
	assert.Equal(t, "secretcommunity", stats.ServiceDetails[0].Details["community"])
}

func TestComputeStatistics_IDSContributesToSecurityScore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		ids       *common.IDSConfig
		wantScore int
	}{
		{
			name:      "IDS disabled",
			ids:       nil,
			wantScore: 0,
		},
		{
			name:      "IDS enabled detection only",
			ids:       &common.IDSConfig{Enabled: true},
			wantScore: 15,
		},
		{
			name:      "IDS enabled with IPS mode",
			ids:       &common.IDSConfig{Enabled: true, IPSMode: true},
			wantScore: 25,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := &common.CommonDevice{IDS: tt.ids}
			stats := analysis.ComputeStatistics(cfg)

			assert.Equal(t, tt.wantScore, stats.Summary.SecurityScore)
		})
	}
}

func TestComputeSecurityScore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cfg       *common.CommonDevice
		stats     *common.Statistics
		features  []string
		rules     int
		wantScore int
	}{
		{
			name:      "nil cfg returns zero",
			cfg:       nil,
			stats:     &common.Statistics{},
			wantScore: 0,
		},
		{
			name:      "nil stats returns zero",
			cfg:       &common.CommonDevice{},
			stats:     nil,
			wantScore: 0,
		},
		{
			name:      "no features",
			cfg:       &common.CommonDevice{},
			features:  []string{},
			rules:     0,
			wantScore: 0,
		},
		{
			name: "HTTPS and SSH",
			cfg: &common.CommonDevice{
				System: common.System{
					WebGUI: common.WebGUI{Protocol: "https"},
					SSH:    common.SSH{Group: "admins"},
				},
			},
			features:  []string{"HTTPS Web GUI"},
			rules:     5,
			wantScore: 55,
		},
		{
			name: "capped at max",
			cfg: &common.CommonDevice{
				System: common.System{
					WebGUI: common.WebGUI{Protocol: "https"},
					SSH:    common.SSH{Group: "admins"},
				},
				IDS: &common.IDSConfig{Enabled: true, IPSMode: true},
			},
			features:  []string{"f1", "f2", "f3", "f4", "f5", "f6"},
			rules:     10,
			wantScore: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stats := tt.stats
			if stats == nil {
				stats = &common.Statistics{
					SecurityFeatures:   tt.features,
					TotalFirewallRules: tt.rules,
				}
			}
			score := analysis.ComputeSecurityScore(tt.cfg, stats)
			assert.Equal(t, tt.wantScore, score)
		})
	}
}

func TestComputeConfigComplexity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		stats      *common.Statistics
		wantResult int
	}{
		{
			name:       "nil stats returns zero",
			stats:      nil,
			wantResult: 0,
		},
		{
			name:       "empty config",
			stats:      &common.Statistics{},
			wantResult: 0,
		},
		{
			name: "simple config",
			stats: &common.Statistics{
				TotalInterfaces:    2,
				TotalFirewallRules: 5,
				TotalUsers:         1,
			},
			wantResult: 2,
		},
		{
			name: "complex config",
			stats: &common.Statistics{
				TotalInterfaces:      10,
				TotalFirewallRules:   50,
				TotalUsers:           10,
				TotalGroups:          5,
				SysctlSettings:       20,
				TotalServices:        8,
				DHCPScopes:           5,
				LoadBalancerMonitors: 3,
				TotalGateways:        4,
				TotalGatewayGroups:   2,
			},
			wantResult: 38,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := analysis.ComputeConfigComplexity(tt.stats)
			assert.Equal(t, tt.wantResult, result)
		})
	}
}

func TestComputeTotalConfigItems(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		stats *common.Statistics
		want  int
	}{
		{
			name:  "nil stats returns zero",
			stats: nil,
			want:  0,
		},
		{
			name:  "empty stats",
			stats: &common.Statistics{},
			want:  0,
		},
		{
			name: "all fields populated",
			stats: &common.Statistics{
				TotalInterfaces:      3,
				TotalFirewallRules:   10,
				TotalUsers:           2,
				TotalGroups:          1,
				TotalServices:        4,
				TotalGateways:        2,
				TotalGatewayGroups:   1,
				SysctlSettings:       5,
				DHCPScopes:           2,
				LoadBalancerMonitors: 1,
				TotalVLANs:           3,
				TotalBridges:         1,
				TotalCertificates:    2,
				TotalCAs:             1,
			},
			want: 38,
		},
		{
			name: "network infrastructure only",
			stats: &common.Statistics{
				TotalVLANs:        5,
				TotalBridges:      2,
				TotalCertificates: 3,
				TotalCAs:          1,
			},
			want: 11,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, analysis.ComputeTotalConfigItems(tt.stats))
		})
	}
}
