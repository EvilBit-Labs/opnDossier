package enrichment

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnrichDocument(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *schema.OpnSenseDocument
		expected *EnrichedOpnSenseDocument
	}{
		{
			name:     "nil configuration",
			cfg:      nil,
			expected: nil,
		},
		{
			name: "basic configuration",
			cfg: &schema.OpnSenseDocument{
				System: schema.System{
					Hostname: "test-firewall",
					Domain:   "example.com",
					WebGUI: schema.WebGUIConfig{
						Protocol: "https",
					},
					SSH: struct {
						Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
					}{
						Group: "admin",
					},
					User: []schema.User{
						{
							Name:      "admin",
							UID:       "1000",
							Groupname: "admin",
							Scope:     "system",
							Descr:     "Administrator",
						},
					},
					Group: []schema.Group{
						{
							Name:        "admin",
							Gid:         "1000",
							Description: "Administrators",
							Scope:       "system",
							Member:      "admin",
							Priv:        "user-shell-access",
						},
					},
				},
				Interfaces: schema.Interfaces{
					Items: map[string]schema.Interface{
						"wan": {
							Enable:      "1",
							IPAddr:      "192.168.1.1",
							Subnet:      "24",
							BlockPriv:   "1",
							BlockBogons: "1",
						},
						"lan": {
							Enable: "1",
							IPAddr: "10.0.0.1",
							Subnet: "24",
						},
					},
				},
				Filter: schema.Filter{
					Rule: []schema.Rule{
						{
							Type:        "pass",
							Interface:   schema.InterfaceList{"wan"},
							IPProtocol:  "tcp",
							Source:      schema.Source{Network: "any"},
							Destination: schema.Destination{Network: "any"},
							Descr:       "Test rule",
						},
					},
				},
				Dhcpd: schema.Dhcpd{
					Items: map[string]schema.DhcpdInterface{
						"lan": {
							Enable: "1",
							Range: schema.Range{
								From: "10.0.0.100",
								To:   "10.0.0.200",
							},
						},
					},
				},
				Unbound: schema.Unbound{
					Enable: "1",
				},
				Snmpd: schema.Snmpd{
					ROCommunity: "public",
				},
				Ntpd: schema.Ntpd{
					Prefer: "pool.ntp.org",
				},
				Sysctl: []schema.SysctlItem{
					{
						Tunable: "net.inet.ip.forwarding",
						Value:   "1",
						Descr:   "Enable IP forwarding",
					},
				},
			},
			expected: &EnrichedOpnSenseDocument{
				OpnSenseDocument: &schema.OpnSenseDocument{},
				Statistics: &Statistics{
					TotalInterfaces:    2,
					InterfacesByType:   map[string]int{"wan": 1, "lan": 1},
					TotalFirewallRules: 1,
					RulesByInterface:   map[string]int{"wan": 1},
					RulesByType:        map[string]int{"pass": 1},
					NATEntries:         0,
					DHCPScopes:         1,
					TotalUsers:         1,
					UsersByScope:       map[string]int{"system": 1},
					TotalGroups:        1,
					GroupsByScope:      map[string]int{"system": 1},
					EnabledServices:    []string{"unbound", "snmpd", "ntpd"},
					TotalServices:      3,
					SysctlSettings:     1,
					SecurityFeatures:   []string{"https-web-gui", "ssh-access"},
				},
				Analysis: &Analysis{
					DeadRules:         []DeadRuleFinding{},
					UnusedInterfaces:  []UnusedInterfaceFinding{},
					SecurityIssues:    []SecurityFinding{},
					PerformanceIssues: []PerformanceFinding{},
					ConsistencyIssues: []ConsistencyFinding{},
				},
				SecurityAssessment: &SecurityAssessment{
					OverallScore:     100,
					SecurityFeatures: []string{"HTTPS Web GUI", "SSH Access Configured"},
					Vulnerabilities:  []string{},
					Recommendations:  []string{},
				},
				PerformanceMetrics: &PerformanceMetrics{
					ConfigComplexity: 4,
					RuleEfficiency:   98,
					ResourceUsage:    50,
				},
				ComplianceChecks: &ComplianceChecks{
					ComplianceScore: 100,
					ComplianceItems: []string{"HTTPS Web GUI", "SSH Access Configured"},
					Violations:      []string{},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EnrichDocument(tt.cfg)

			if tt.expected == nil {
				assert.Nil(t, result)
				return
			}

			require.NotNil(t, result)
			require.NotNil(t, result.Statistics)
			require.NotNil(t, result.Analysis)
			require.NotNil(t, result.SecurityAssessment)
			require.NotNil(t, result.PerformanceMetrics)
			require.NotNil(t, result.ComplianceChecks)

			// Test basic statistics
			assert.Equal(t, tt.expected.Statistics.TotalInterfaces, result.Statistics.TotalInterfaces)
			assert.Equal(t, tt.expected.Statistics.TotalFirewallRules, result.Statistics.TotalFirewallRules)
			assert.Equal(t, tt.expected.Statistics.TotalUsers, result.Statistics.TotalUsers)
			assert.Equal(t, tt.expected.Statistics.TotalGroups, result.Statistics.TotalGroups)
			assert.Equal(t, tt.expected.Statistics.TotalServices, result.Statistics.TotalServices)

			// Test security assessment
			assert.Equal(t, tt.expected.SecurityAssessment.OverallScore, result.SecurityAssessment.OverallScore)
			assert.Len(
				t,
				result.SecurityAssessment.SecurityFeatures,
				len(tt.expected.SecurityAssessment.SecurityFeatures),
			)

			// Test performance metrics
			assert.Equal(t, tt.expected.PerformanceMetrics.ConfigComplexity, result.PerformanceMetrics.ConfigComplexity)
			assert.Equal(t, tt.expected.PerformanceMetrics.RuleEfficiency, result.PerformanceMetrics.RuleEfficiency)

			// Test compliance checks
			assert.Equal(t, tt.expected.ComplianceChecks.ComplianceScore, result.ComplianceChecks.ComplianceScore)
			assert.Len(t, result.ComplianceChecks.ComplianceItems, len(tt.expected.ComplianceChecks.ComplianceItems))
		})
	}
}

func TestGenerateStatistics(t *testing.T) {
	cfg := &schema.OpnSenseDocument{
		System: schema.System{
			Hostname: "test-firewall",
			WebGUI: schema.WebGUIConfig{
				Protocol: "https",
			},
			SSH: struct {
				Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
			}{
				Group: "admin",
			},
		},
		Interfaces: schema.Interfaces{
			Items: map[string]schema.Interface{
				"wan": {
					Enable:      "1",
					IPAddr:      "192.168.1.1",
					Subnet:      "24",
					BlockPriv:   "1",
					BlockBogons: "1",
				},
				"lan": {
					Enable: "1",
					IPAddr: "10.0.0.1",
					Subnet: "24",
				},
			},
		},
		Filter: schema.Filter{
			Rule: []schema.Rule{
				{
					Type:        "pass",
					Interface:   schema.InterfaceList{"wan"},
					IPProtocol:  "tcp",
					Source:      schema.Source{Network: "any"},
					Destination: schema.Destination{Network: "any"},
					Descr:       "Test rule",
				},
				{
					Type:        "block",
					Interface:   schema.InterfaceList{"lan"},
					IPProtocol:  "tcp",
					Source:      schema.Source{Network: "any"},
					Destination: schema.Destination{Network: "any"},
					Descr:       "Block rule",
				},
			},
		},
	}

	stats := generateStatistics(cfg)

	assert.Equal(t, 2, stats.TotalInterfaces)
	assert.Equal(t, 2, stats.TotalFirewallRules)
	assert.Equal(t, 1, stats.RulesByInterface["wan"])
	assert.Equal(t, 1, stats.RulesByInterface["lan"])
	assert.Equal(t, 1, stats.RulesByType["pass"])
	assert.Equal(t, 1, stats.RulesByType["block"])
	assert.Len(t, stats.InterfaceDetails, 2)
	assert.Len(t, stats.SecurityFeatures, 2)
}

func TestGenerateAnalysis(t *testing.T) {
	cfg := &schema.OpnSenseDocument{
		System: schema.System{
			WebGUI: schema.WebGUIConfig{
				Protocol: "http", // Insecure
			},
		},
		Filter: schema.Filter{
			Rule: []schema.Rule{
				{
					Type:        "block",
					Interface:   schema.InterfaceList{"wan"},
					Source:      schema.Source{Network: "any"},
					Destination: schema.Destination{Network: "any"},
				},
				{
					Type:        "pass",
					Interface:   schema.InterfaceList{"wan"},
					Source:      schema.Source{Network: "any"},
					Destination: schema.Destination{Network: "any"},
					Descr:       "", // Missing description
				},
			},
		},
	}

	analysis := generateAnalysis(cfg)

	// Should have security issues due to HTTP and overly permissive rules
	assert.Len(t, analysis.SecurityIssues, 2)
	assert.Equal(t, "insecure-web-gui", analysis.SecurityIssues[0].Issue)

	// Should have consistency issues due to missing descriptions
	assert.Len(t, analysis.ConsistencyIssues, 2)
	assert.Equal(t, "missing-description", analysis.ConsistencyIssues[0].Issue)
}

func TestGenerateSecurityAssessment(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *schema.OpnSenseDocument
		expected int
	}{
		{
			name: "secure configuration",
			cfg: &schema.OpnSenseDocument{
				System: schema.System{
					WebGUI: schema.WebGUIConfig{Protocol: "https"},
					SSH: struct {
						Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
					}{Group: "admin"},
				},
			},
			expected: 100,
		},
		{
			name: "insecure configuration",
			cfg: &schema.OpnSenseDocument{
				System: schema.System{
					WebGUI: schema.WebGUIConfig{Protocol: "http"},
					SSH: struct {
						Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
					}{Group: ""},
				},
			},
			expected: 50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assessment := generateSecurityAssessment(tt.cfg)
			assert.Equal(t, tt.expected, assessment.OverallScore)
		})
	}
}

func TestGenerateAnalysis_SourceIsAnyPath(t *testing.T) {
	t.Parallel()
	// Test that rules using Source{Any: StringPtr("")} (the *string pattern)
	// are detected correctly by dead rule, security, and consistency analysis.
	cfg := &schema.OpnSenseDocument{
		System: schema.System{
			WebGUI: schema.WebGUIConfig{Protocol: "https"},
		},
		Filter: schema.Filter{
			Rule: []schema.Rule{
				{
					Type:      "block",
					Interface: schema.InterfaceList{"wan"},
					// Use Any pointer instead of Network: "any"
					Source:      schema.Source{Any: new("")},
					Destination: schema.Destination{Any: new("")},
				},
				{
					Type:      "pass",
					Interface: schema.InterfaceList{"wan"},
					// This rule after block-all should be detected as dead
					Source:      schema.Source{Network: "lan"},
					Destination: schema.Destination{Network: "lan"},
					Descr:       "Unreachable rule",
				},
			},
		},
	}

	analysis := generateAnalysis(cfg)

	// The block rule with Source{Any: StringPtr("")} should cause dead rule detection
	assert.NotEmpty(t, analysis.DeadRules, "expected dead rules when block-all uses Any pointer")

	// Verify the dead rule finding describes the unreachable rules
	found := false
	for _, dr := range analysis.DeadRules {
		if dr.RuleIndex == 1 && dr.Description != "" {
			found = true

			break
		}
	}
	assert.True(t, found, "expected dead rule finding for Source.IsAny() path")
}

func TestCalculateSecurityScore(t *testing.T) {
	cfg := &schema.OpnSenseDocument{
		System: schema.System{
			WebGUI: schema.WebGUIConfig{Protocol: "https"},
			SSH: struct {
				Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
			}{Group: "admin"},
		},
	}

	stats := &Statistics{
		SecurityFeatures: []string{"https-web-gui", "ssh-access"},
	}

	score := calculateSecurityScore(cfg, stats)
	assert.GreaterOrEqual(t, score, 80)
	assert.LessOrEqual(t, score, 100)
}

func TestCalculateConfigComplexity(t *testing.T) {
	stats := &Statistics{
		TotalFirewallRules: 10,
		TotalUsers:         5,
		TotalGroups:        3,
		TotalServices:      2,
	}

	complexity := calculateConfigComplexity(stats)
	assert.Equal(t, 34, complexity)
}

func TestDynamicInterfaceCounting(t *testing.T) {
	// Test with a configuration that has wan and lan interfaces
	cfg := &schema.OpnSenseDocument{
		Interfaces: schema.Interfaces{
			Items: map[string]schema.Interface{
				"wan": {
					Enable:      "1",
					IPAddr:      "dhcp",
					IPAddrv6:    "dhcp6",
					BlockPriv:   "1",
					BlockBogons: "1",
				},
				"lan": {
					Enable:      "1",
					IPAddr:      "192.168.1.1",
					Subnet:      "24",
					IPAddrv6:    "track6",
					Subnetv6:    "64",
					BlockPriv:   "",
					BlockBogons: "",
				},
				"opt0": {
					Enable:      "1",
					IPAddr:      "10.0.0.1",
					Subnet:      "24",
					BlockPriv:   "1",
					BlockBogons: "",
				},
			},
		},
		Dhcpd: schema.Dhcpd{
			Items: map[string]schema.DhcpdInterface{
				"lan": {
					Enable: "1",
					Range: schema.Range{
						From: "192.168.1.100",
						To:   "192.168.1.199",
					},
				},
				"opt0": {
					Enable: "1",
					Range: schema.Range{
						From: "10.0.0.100",
						To:   "10.0.0.199",
					},
				},
			},
		},
	}

	stats := generateStatistics(cfg)

	// Verify total interfaces count
	if stats.TotalInterfaces != 3 {
		t.Errorf("Expected 3 total interfaces, got %d", stats.TotalInterfaces)
	}

	// Verify interfaces by type
	expectedInterfaces := map[string]int{
		"wan":  1,
		"lan":  1,
		"opt0": 1,
	}
	for ifaceType, expectedCount := range expectedInterfaces {
		if count := stats.InterfacesByType[ifaceType]; count != expectedCount {
			t.Errorf("Expected %d %s interfaces, got %d", expectedCount, ifaceType, count)
		}
	}

	// Verify interface details
	if len(stats.InterfaceDetails) != 3 {
		t.Errorf("Expected 3 interface details, got %d", len(stats.InterfaceDetails))
	}

	// Verify DHCP scopes
	if stats.DHCPScopes != 2 {
		t.Errorf("Expected 2 DHCP scopes, got %d", stats.DHCPScopes)
	}

	// Verify DHCP scope details
	if len(stats.DHCPScopeDetails) != 2 {
		t.Errorf("Expected 2 DHCP scope details, got %d", len(stats.DHCPScopeDetails))
	}

	// Check specific interface properties
	for _, iface := range stats.InterfaceDetails {
		switch iface.Name {
		case "wan":
			if !iface.Enabled {
				t.Error("Expected WAN interface to be enabled")
			}

			if !iface.HasIPv4 {
				t.Error("Expected WAN interface to have IPv4 (DHCP)")
			}

			if !iface.HasIPv6 {
				t.Error("Expected WAN interface to have IPv6 (DHCP)")
			}

			if !iface.BlockPriv {
				t.Error("Expected WAN interface to block private networks")
			}

			if !iface.BlockBogons {
				t.Error("Expected WAN interface to block bogons")
			}

			if iface.HasDHCP {
				t.Error("Expected WAN interface to not have DHCP server")
			}
		case "lan":
			if !iface.Enabled {
				t.Error("Expected LAN interface to be enabled")
			}

			if !iface.HasIPv4 {
				t.Error("Expected LAN interface to have IPv4")
			}

			if !iface.HasIPv6 {
				t.Error("Expected LAN interface to have IPv6")
			}

			if iface.BlockPriv {
				t.Error("Expected LAN interface to not block private networks")
			}

			if iface.BlockBogons {
				t.Error("Expected LAN interface to not block bogons")
			}

			if !iface.HasDHCP {
				t.Error("Expected LAN interface to have DHCP server")
			}
		case "opt0":
			if !iface.Enabled {
				t.Error("Expected OPT0 interface to be enabled")
			}

			if !iface.HasIPv4 {
				t.Error("Expected OPT0 interface to have IPv4")
			}

			if iface.HasIPv6 {
				t.Error("Expected OPT0 interface to not have IPv6")
			}

			if !iface.BlockPriv {
				t.Error("Expected OPT0 interface to block private networks")
			}

			if iface.BlockBogons {
				t.Error("Expected OPT0 interface to not block bogons")
			}

			if !iface.HasDHCP {
				t.Error("Expected OPT0 interface to have DHCP server")
			}
		default:
			t.Errorf("Unexpected interface: %s", iface.Name)
		}
	}
}

func TestDynamicInterfaceAnalysis(t *testing.T) {
	// Test with a configuration that has wan, lan, and opt0 interfaces
	cfg := &schema.OpnSenseDocument{
		Interfaces: schema.Interfaces{
			Items: map[string]schema.Interface{
				"wan": {
					Enable: "1",
				},
				"lan": {
					Enable: "1",
				},
				"opt0": {
					Enable: "1",
				},
			},
		},
		Filter: schema.Filter{
			Rule: []schema.Rule{
				{
					Interface: schema.InterfaceList{"wan"},
					Type:      "pass",
				},
				{
					Interface: schema.InterfaceList{"lan"},
					Type:      "pass",
				},
				// Note: opt0 is not used in any rules
			},
		},
	}

	findings := analyzeUnusedInterfaces(cfg)

	// Should find that opt0 is unused
	if len(findings) != 1 {
		t.Errorf("Expected 1 unused interface finding, got %d", len(findings))
	}

	if findings[0].InterfaceName != "opt0" {
		t.Errorf("Expected unused interface to be 'opt0', got '%s'", findings[0].InterfaceName)
	}

	// Test with a configuration that has no unused interfaces
	cfg2 := &schema.OpnSenseDocument{
		Interfaces: schema.Interfaces{
			Items: map[string]schema.Interface{
				"wan": {
					Enable: "1",
				},
				"lan": {
					Enable: "1",
				},
			},
		},
		Filter: schema.Filter{
			Rule: []schema.Rule{
				{
					Interface: schema.InterfaceList{"wan"},
					Type:      "pass",
				},
				{
					Interface: schema.InterfaceList{"lan"},
					Type:      "pass",
				},
			},
		},
	}

	findings2 := analyzeUnusedInterfaces(cfg2)

	// Should find no unused interfaces
	if len(findings2) != 0 {
		t.Errorf("Expected 0 unused interface findings, got %d", len(findings2))
	}

	// Test with a configuration that has only wan interface
	cfg3 := &schema.OpnSenseDocument{
		Interfaces: schema.Interfaces{
			Items: map[string]schema.Interface{
				"wan": {
					Enable: "1",
				},
			},
		},
		Filter: schema.Filter{
			Rule: []schema.Rule{
				{
					Interface: schema.InterfaceList{"wan"},
					Type:      "pass",
				},
			},
		},
	}

	findings3 := analyzeUnusedInterfaces(cfg3)

	// Should find no unused interfaces
	if len(findings3) != 0 {
		t.Errorf("Expected 0 unused interface findings for single interface config, got %d", len(findings3))
	}
}

func TestCalculateTotalConfigItems(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		counts   ConfigItemCounts
		expected int
	}{
		{
			name:     "zero values",
			counts:   ConfigItemCounts{},
			expected: 0,
		},
		{
			name: "all ones",
			counts: ConfigItemCounts{
				Interfaces:     1,
				FirewallRules:  1,
				Users:          1,
				Groups:         1,
				Services:       1,
				Gateways:       1,
				GatewayGroups:  1,
				SysctlSettings: 1,
				DHCPScopes:     1,
				LBMonitors:     1,
			},
			expected: 10,
		},
		{
			name: "typical configuration",
			counts: ConfigItemCounts{
				Interfaces:     2,
				FirewallRules:  15,
				Users:          3,
				Groups:         2,
				Services:       5,
				Gateways:       2,
				GatewayGroups:  1,
				SysctlSettings: 8,
				DHCPScopes:     2,
				LBMonitors:     0,
			},
			expected: 40,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := CalculateTotalConfigItems(tt.counts)
			assert.Equal(t, tt.expected, result)
		})
	}
}
