package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnrichDocument(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *OpnSenseDocument
		expected *EnrichedOpnSenseDocument
	}{
		{
			name:     "nil configuration",
			cfg:      nil,
			expected: nil,
		},
		{
			name: "basic configuration",
			cfg: &OpnSenseDocument{
				System: System{
					Hostname: "test-firewall",
					Domain:   "example.com",
					WebGUI: struct {
						Protocol   string `xml:"protocol" json:"protocol" yaml:"protocol" validate:"required,oneof=http https"`
						SSLCertRef string `xml:"ssl-certref,omitempty" json:"sslCertRef,omitempty" yaml:"sslCertRef,omitempty"`
					}{
						Protocol: "https",
					},
					SSH: struct {
						Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
					}{
						Group: "admin",
					},
					User: []User{
						{
							Name:      "admin",
							UID:       "1000",
							Groupname: "admin",
							Scope:     "system",
							Descr:     "Administrator",
						},
					},
					Group: []Group{
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
				Interfaces: Interfaces{
					Items: map[string]Interface{
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
				Filter: Filter{
					Rule: []Rule{
						{
							Type:        "pass",
							Interface:   "wan",
							IPProtocol:  "tcp",
							Source:      Source{Network: "any"},
							Destination: Destination{Network: "any"},
							Descr:       "Test rule",
						},
					},
				},
				Dhcpd: Dhcpd{
					Items: map[string]DhcpdInterface{
						"lan": {
							Enable: "1",
							Range: Range{
								From: "10.0.0.100",
								To:   "10.0.0.200",
							},
						},
					},
				},
				Unbound: Unbound{
					Enable: "1",
				},
				Snmpd: Snmpd{
					ROCommunity: "public",
				},
				Ntpd: Ntpd{
					Prefer: "pool.ntp.org",
				},
				Sysctl: []SysctlItem{
					{
						Tunable: "net.inet.ip.forwarding",
						Value:   "1",
						Descr:   "Enable IP forwarding",
					},
				},
			},
			expected: &EnrichedOpnSenseDocument{
				OpnSenseDocument: &OpnSenseDocument{},
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
			assert.Len(t, result.SecurityAssessment.SecurityFeatures, len(tt.expected.SecurityAssessment.SecurityFeatures))

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
	cfg := &OpnSenseDocument{
		System: System{
			Hostname: "test-firewall",
			WebGUI: struct {
				Protocol   string `xml:"protocol" json:"protocol" yaml:"protocol" validate:"required,oneof=http https"`
				SSLCertRef string `xml:"ssl-certref,omitempty" json:"sslCertRef,omitempty" yaml:"sslCertRef,omitempty"`
			}{
				Protocol: "https",
			},
			SSH: struct {
				Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
			}{
				Group: "admin",
			},
		},
		Interfaces: Interfaces{
			Items: map[string]Interface{
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
		Filter: Filter{
			Rule: []Rule{
				{
					Type:        "pass",
					Interface:   "wan",
					IPProtocol:  "tcp",
					Source:      Source{Network: "any"},
					Destination: Destination{Network: "any"},
					Descr:       "Test rule",
				},
				{
					Type:        "block",
					Interface:   "lan",
					IPProtocol:  "tcp",
					Source:      Source{Network: "any"},
					Destination: Destination{Network: "any"},
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
	cfg := &OpnSenseDocument{
		System: System{
			WebGUI: struct {
				Protocol   string `xml:"protocol" json:"protocol" yaml:"protocol" validate:"required,oneof=http https"`
				SSLCertRef string `xml:"ssl-certref,omitempty" json:"sslCertRef,omitempty" yaml:"sslCertRef,omitempty"`
			}{
				Protocol: "http", // Insecure
			},
		},
		Filter: Filter{
			Rule: []Rule{
				{
					Type:        "block",
					Interface:   "wan",
					Source:      Source{Network: "any"},
					Destination: Destination{Network: "any"},
				},
				{
					Type:        "pass",
					Interface:   "wan",
					Source:      Source{Network: "any"},
					Destination: Destination{Network: "any"},
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
		cfg      *OpnSenseDocument
		expected int
	}{
		{
			name: "secure configuration",
			cfg: &OpnSenseDocument{
				System: System{
					WebGUI: struct {
						Protocol   string `xml:"protocol" json:"protocol" yaml:"protocol" validate:"required,oneof=http https"`
						SSLCertRef string `xml:"ssl-certref,omitempty" json:"sslCertRef,omitempty" yaml:"sslCertRef,omitempty"`
					}{Protocol: "https"},
					SSH: struct {
						Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
					}{Group: "admin"},
				},
			},
			expected: 100,
		},
		{
			name: "insecure configuration",
			cfg: &OpnSenseDocument{
				System: System{
					WebGUI: struct {
						Protocol   string `xml:"protocol" json:"protocol" yaml:"protocol" validate:"required,oneof=http https"`
						SSLCertRef string `xml:"ssl-certref,omitempty" json:"sslCertRef,omitempty" yaml:"sslCertRef,omitempty"`
					}{Protocol: "http"},
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

func TestCalculateSecurityScore(t *testing.T) {
	cfg := &OpnSenseDocument{
		System: System{
			WebGUI: struct {
				Protocol   string `xml:"protocol" json:"protocol" yaml:"protocol" validate:"required,oneof=http https"`
				SSLCertRef string `xml:"ssl-certref,omitempty" json:"sslCertRef,omitempty" yaml:"sslCertRef,omitempty"`
			}{Protocol: "https"},
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
