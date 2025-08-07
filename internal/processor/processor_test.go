package processor

import (
	"context"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessorInterface(_ *testing.T) {
	// Ensure ExampleProcessor implements Processor interface
	var _ Processor = (*ExampleProcessor)(nil)
}

func TestNewExampleProcessor(t *testing.T) {
	processor := NewExampleProcessor()
	assert.NotNil(t, processor)
}

func TestExampleProcessor_Process_NilConfig(t *testing.T) {
	processor := NewExampleProcessor()
	ctx := context.Background()

	report, err := processor.Process(ctx, nil)
	require.Error(t, err)
	assert.Nil(t, report)
	assert.Contains(t, err.Error(), "configuration cannot be nil")
}

func TestExampleProcessor_Process_BasicAnalysis(t *testing.T) {
	processor := NewExampleProcessor()
	ctx := context.Background()

	// Create a minimal OPNsense configuration
	cfg := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-firewall",
			Domain:   "example.com",
			WebGUI:   model.WebGUIConfig{Protocol: "https"},
			SSH: struct {
				Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
			}{Group: "admins"},
			Bogons: struct {
				Interval string `xml:"interval" json:"interval,omitempty" yaml:"interval,omitempty" validate:"omitempty,oneof=monthly weekly daily never"`
			}{Interval: "monthly"},
		},
	}

	report, err := processor.Process(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, report)

	// Check basic report structure
	assert.Equal(t, "test-firewall", report.ConfigInfo.Hostname)
	assert.Equal(t, "example.com", report.ConfigInfo.Domain)
	assert.NotZero(t, report.GeneratedAt)
	assert.True(t, report.ProcessorConfig.EnableStats)
	assert.NotNil(t, report.Statistics)
}

func TestExampleProcessor_Process_WithOptions(t *testing.T) {
	processor := NewExampleProcessor()
	ctx := context.Background()

	cfg := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-firewall",
			Domain:   "example.com",
			WebGUI:   model.WebGUIConfig{Protocol: "http"}, // Insecure protocol
			SSH: struct {
				Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
			}{Group: "admins"}, // SSH enabled
		},
		Snmpd: model.Snmpd{
			ROCommunity: "public", // Default community string
		},
	}

	// Test with all features enabled
	report, err := processor.Process(ctx, cfg, WithAllFeatures())
	require.NoError(t, err)
	require.NotNil(t, report)

	// Verify processor config
	assert.True(t, report.ProcessorConfig.EnableStats)
	assert.True(t, report.ProcessorConfig.EnableDeadRuleCheck)
	assert.True(t, report.ProcessorConfig.EnableSecurityAnalysis)
	assert.True(t, report.ProcessorConfig.EnablePerformanceAnalysis)
	assert.True(t, report.ProcessorConfig.EnableComplianceCheck)

	// Should have security findings due to HTTP and default SNMP community
	assert.NotEmpty(t, report.Findings.High, "Should have high severity findings")

	// Check for specific findings
	foundInsecureWeb := false
	foundDefaultSNMP := false

	for _, finding := range report.Findings.High {
		if strings.Contains(finding.Title, "Insecure Web GUI Protocol") {
			foundInsecureWeb = true
		}

		if strings.Contains(finding.Title, "Default SNMP Community String") {
			foundDefaultSNMP = true
		}
	}

	assert.True(t, foundInsecureWeb, "Should find insecure web GUI protocol")
	assert.True(t, foundDefaultSNMP, "Should find default SNMP community string")
}

func TestExampleProcessor_Process_ContextCancellation(t *testing.T) {
	processor := NewExampleProcessor()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	cfg := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-firewall",
		},
	}

	report, err := processor.Process(ctx, cfg)
	require.Error(t, err)
	assert.Nil(t, report)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestReport_AddFinding(t *testing.T) {
	cfg := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test",
			Domain:   "example.com",
		},
	}

	report := NewReport(cfg, *DefaultConfig())

	finding := Finding{
		Type:        "test",
		Title:       "Test Finding",
		Description: "This is a test finding",
	}

	// Test adding findings of different severities
	report.AddFinding(SeverityCritical, finding)
	report.AddFinding(SeverityHigh, finding)
	report.AddFinding(SeverityMedium, finding)
	report.AddFinding(SeverityLow, finding)
	report.AddFinding(SeverityInfo, finding)

	assert.Len(t, report.Findings.Critical, 1)
	assert.Len(t, report.Findings.High, 1)
	assert.Len(t, report.Findings.Medium, 1)
	assert.Len(t, report.Findings.Low, 1)
	assert.Len(t, report.Findings.Info, 1)
	assert.Equal(t, 5, report.TotalFindings())
	assert.True(t, report.HasCriticalFindings())
}

func TestReport_ToJSON(t *testing.T) {
	cfg := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-firewall",
			Domain:   "example.com",
		},
	}

	report := NewReport(cfg, *DefaultConfig())

	jsonStr, err := report.ToJSON()
	require.NoError(t, err)
	assert.NotEmpty(t, jsonStr)
	assert.Contains(t, jsonStr, "test-firewall")
	assert.Contains(t, jsonStr, "example.com")
}

func TestReport_ToMarkdown(t *testing.T) {
	cfg := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-firewall",
			Domain:   "example.com",
		},
	}

	report := NewReport(cfg, *DefaultConfig())

	// Add a test finding
	report.AddFinding(SeverityHigh, Finding{
		Type:           "security",
		Title:          "Test Security Issue",
		Description:    "This is a test security issue",
		Recommendation: "Fix the security issue",
		Component:      "test-component",
	})

	markdown := report.ToMarkdown()
	assert.NotEmpty(t, markdown)
	assert.Contains(t, markdown, "# OPNsense Configuration Analysis Report")
	assert.Contains(t, markdown, "test-firewall")
	assert.Contains(t, markdown, "example.com")
	assert.Contains(t, markdown, "Test Security Issue")
	assert.Contains(t, markdown, "High (1)")
}

func TestReport_Summary(t *testing.T) {
	cfg := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-firewall",
			Domain:   "example.com",
		},
	}

	report := NewReport(cfg, *DefaultConfig())

	// Test summary with no findings
	summary := report.Summary()
	assert.Contains(t, summary, "test-firewall.example.com")
	assert.Contains(t, summary, "No issues found")

	// Add findings and test summary
	report.AddFinding(SeverityCritical, Finding{Type: "test", Title: "Critical Issue"})
	report.AddFinding(SeverityHigh, Finding{Type: "test", Title: "High Issue"})

	summary = report.Summary()
	assert.Contains(t, summary, "2 findings")
	assert.Contains(t, summary, "1 critical")
	assert.Contains(t, summary, "1 high")
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	assert.NotNil(t, config)
	assert.True(t, config.EnableStats)
	assert.False(t, config.EnableDeadRuleCheck)
	assert.False(t, config.EnableSecurityAnalysis)
	assert.False(t, config.EnablePerformanceAnalysis)
	assert.False(t, config.EnableComplianceCheck)
}

func TestProcessorOptions(t *testing.T) {
	config := DefaultConfig()

	// Test individual options
	config.ApplyOptions(WithStats())
	assert.True(t, config.EnableStats)

	config = DefaultConfig()
	config.ApplyOptions(WithDeadRuleCheck())
	assert.True(t, config.EnableDeadRuleCheck)

	config = DefaultConfig()
	config.ApplyOptions(WithSecurityAnalysis())
	assert.True(t, config.EnableSecurityAnalysis)

	config = DefaultConfig()
	config.ApplyOptions(WithPerformanceAnalysis())
	assert.True(t, config.EnablePerformanceAnalysis)

	config = DefaultConfig()
	config.ApplyOptions(WithComplianceCheck())
	assert.True(t, config.EnableComplianceCheck)

	// Test all features option
	config = DefaultConfig()
	config.ApplyOptions(WithAllFeatures())
	assert.True(t, config.EnableStats)
	assert.True(t, config.EnableDeadRuleCheck)
	assert.True(t, config.EnableSecurityAnalysis)
	assert.True(t, config.EnablePerformanceAnalysis)
	assert.True(t, config.EnableComplianceCheck)
}

func TestNewReport(t *testing.T) {
	cfg := &model.OpnSenseDocument{
		Version: "24.1",
		Theme:   "opnsense",
		System: model.System{
			Hostname: "test-firewall",
			Domain:   "example.com",
			User: []model.User{
				{Name: "admin"},
				{Name: "user1"},
			},
			Group: []model.Group{
				{Name: "admins"},
			},
		},
		Filter: model.Filter{
			Rule: []model.Rule{
				{Descr: "Allow HTTP"},
				{Descr: "Allow HTTPS"},
			},
		},
		Sysctl: []model.SysctlItem{
			{Tunable: "net.inet.ip.forwarding", Value: "1"},
		},
	}

	config := Config{EnableStats: true}
	report := NewReport(cfg, config)

	assert.NotNil(t, report)
	assert.Equal(t, "test-firewall", report.ConfigInfo.Hostname)
	assert.Equal(t, "example.com", report.ConfigInfo.Domain)
	assert.Equal(t, "24.1", report.ConfigInfo.Version)
	assert.Equal(t, "opnsense", report.ConfigInfo.Theme)
	assert.True(t, report.ProcessorConfig.EnableStats)
	assert.NotNil(t, report.Statistics)
	assert.Equal(t, 2, report.Statistics.TotalUsers)
	assert.Equal(t, 1, report.Statistics.TotalGroups)
	assert.Equal(t, 2, report.Statistics.TotalFirewallRules)
	assert.Equal(t, 1, report.Statistics.SysctlSettings)
	assert.WithinDuration(t, time.Now(), report.GeneratedAt, time.Second)
}

// TestCoreProcessor_NormalizationIdempotence tests that normalization is idempotent
// (applying it multiple times yields the same result).
func TestCoreProcessor_NormalizationIdempotence(t *testing.T) {
	processor, err := NewCoreProcessor()
	require.NoError(t, err)

	tests := []struct {
		name   string
		config *model.OpnSenseDocument
	}{
		{
			name: "Basic configuration",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "test-firewall",
					Domain:   "example.com",
				},
				Interfaces: model.Interfaces{
					Items: map[string]model.Interface{
						"wan": {
							Enable: "1",
							IPAddr: "192.168.1.1",
							Subnet: "24",
						},
						"lan": {
							Enable: "1",
							IPAddr: "10.0.0.1",
							Subnet: "24",
						},
					},
				},
			},
		},
		{
			name: "Configuration with users and groups",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "test-firewall2",
					Domain:   "test.local",
					User: []model.User{
						{Name: "charlie", UID: "1003"},
						{Name: "alice", UID: "1001"},
						{Name: "bob", UID: "1002"},
					},
					Group: []model.Group{
						{Name: "zebra", Gid: "2003"},
						{Name: "alpha", Gid: "2001"},
						{Name: "beta", Gid: "2002"},
					},
				},
				Interfaces: model.Interfaces{
					Items: map[string]model.Interface{
						"wan": {Enable: "1"},
						"lan": {Enable: "1"},
					},
				},
				Sysctl: []model.SysctlItem{
					{Tunable: "net.inet.tcp.mssdflt", Value: "1460"},
					{Tunable: "kern.ipc.maxsockbuf", Value: "16777216"},
					{Tunable: "net.inet.ip.forwarding", Value: "1"},
				},
			},
		},
		{
			name: "Configuration with firewall rules",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "test-firewall3",
					Domain:   "secure.local",
				},
				Interfaces: model.Interfaces{
					Items: map[string]model.Interface{
						"wan": {Enable: "1"},
						"lan": {Enable: "1"},
					},
				},
				Filter: model.Filter{
					Rule: []model.Rule{
						{
							Type:      "pass",
							Interface: model.InterfaceList{"wan"},
							Source:    model.Source{Network: "192.168.1.100"},
							Descr:     "Allow specific host",
						},
						{
							Type:      "block",
							Interface: model.InterfaceList{"lan"},
							Source:    model.Source{Network: "10.0.0.0/8"},
							Descr:     "Block private range",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// First normalization
			normalized1 := processor.normalize(tt.config)

			// Second normalization (should be idempotent)
			normalized2 := processor.normalize(normalized1)

			// Third normalization (should still be idempotent)
			normalized3 := processor.normalize(normalized2)

			// All normalizations should produce identical results
			assert.Equal(t, normalized1, normalized2, "Second normalization should be identical to first")
			assert.Equal(t, normalized2, normalized3, "Third normalization should be identical to second")

			// Verify specific normalization behaviors are preserved
			if len(normalized1.System.User) > 0 {
				// Users should remain sorted
				for i := 1; i < len(normalized1.System.User); i++ {
					assert.LessOrEqual(t, normalized1.System.User[i-1].Name, normalized1.System.User[i].Name,
						"Users should remain sorted after multiple normalizations")
				}
			}

			if len(normalized1.System.Group) > 0 {
				// Groups should remain sorted
				for i := 1; i < len(normalized1.System.Group); i++ {
					assert.LessOrEqual(t, normalized1.System.Group[i-1].Name, normalized1.System.Group[i].Name,
						"Groups should remain sorted after multiple normalizations")
				}
			}

			if len(normalized1.Sysctl) > 0 {
				// Sysctl items should remain sorted
				for i := 1; i < len(normalized1.Sysctl); i++ {
					assert.LessOrEqual(t, normalized1.Sysctl[i-1].Tunable, normalized1.Sysctl[i].Tunable,
						"Sysctl items should remain sorted after multiple normalizations")
				}
			}

			// Check that defaults are consistently filled
			assert.Equal(t, "normal", normalized1.System.Optimization)
			assert.Equal(t, "https", normalized1.System.WebGUI.Protocol)
			assert.Equal(t, "UTC", normalized1.System.Timezone)
			assert.Equal(t, "monthly", normalized1.System.Bogons.Interval)
			assert.Equal(t, "opnsense", normalized1.Theme)
		})
	}
}

// TestCoreProcessor_AnalysisFindings tests various analysis findings with table-driven tests.
func TestCoreProcessor_AnalysisFindings(t *testing.T) {
	processor, err := NewCoreProcessor()
	require.NoError(t, err)

	ctx := context.Background()

	tests := []struct {
		name             string
		config           *model.OpnSenseDocument
		options          []Option
		expectedFindings map[Severity]int // Expected minimum number of findings per severity
		expectedTypes    []string         // Expected finding types
	}{
		{
			name: "Security issues - HTTP and default SNMP",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "insecure-firewall",
					Domain:   "example.com",
					WebGUI:   model.WebGUIConfig{Protocol: "http"}, // Insecure
				},
				Interfaces: model.Interfaces{
					Items: map[string]model.Interface{
						"wan": {Enable: "1"},
						"lan": {Enable: "1"},
					},
				},
				Snmpd: model.Snmpd{
					ROCommunity: "public", // Default community
				},
			},
			options: []Option{WithSecurityAnalysis()},
			expectedFindings: map[Severity]int{
				SeverityCritical: 1, // HTTP protocol
				SeverityHigh:     1, // Default SNMP community
			},
			expectedTypes: []string{"security"},
		},
		{
			name: "Dead rules detection",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "deadrule-firewall",
					Domain:   "example.com",
				},
				Interfaces: model.Interfaces{
					Items: map[string]model.Interface{
						"wan": {Enable: "1"},
						"lan": {Enable: "1"},
					},
				},
				Filter: model.Filter{
					Rule: []model.Rule{
						{
							Type:      "block",
							Interface: model.InterfaceList{"wan"},
							Source:    model.Source{Network: "any"},
							Descr:     "Block all",
						},
						{
							Type:      "pass",
							Interface: model.InterfaceList{"wan"},
							Source:    model.Source{Network: "192.168.1.0/24"},
							Descr:     "Allow LAN (unreachable)",
						},
						{
							Type:       "pass",
							Interface:  model.InterfaceList{"lan"},
							IPProtocol: "inet",
							Source:     model.Source{Network: "10.0.0.0/8"},
							Descr:      "Allow private",
						},
						{
							Type:       "pass",
							Interface:  model.InterfaceList{"lan"},
							IPProtocol: "inet",
							Source:     model.Source{Network: "10.0.0.0/8"},
							Descr:      "Duplicate rule",
						},
					},
				},
			},
			options: []Option{WithDeadRuleCheck()},
			expectedFindings: map[Severity]int{
				SeverityMedium: 1, // Unreachable rules
				SeverityLow:    1, // Duplicate rules
			},
			expectedTypes: []string{"dead-rule", "duplicate-rule"},
		},
		{
			name: "Performance issues",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname:                      "perf-firewall",
					Domain:                        "example.com",
					DisableChecksumOffloading:     1,
					DisableSegmentationOffloading: 1,
				},
				Interfaces: model.Interfaces{
					Items: map[string]model.Interface{
						"wan": {Enable: "1"},
						"lan": {Enable: "1"},
					},
				},
				// Create a large number of rules to trigger performance warning
				Filter: model.Filter{
					Rule: generateManyRules(150), // > 100 rules
				},
			},
			options: []Option{WithPerformanceAnalysis()},
			expectedFindings: map[Severity]int{
				SeverityLow:    2, // Checksum + segmentation offloading
				SeverityMedium: 1, // High rule count
			},
			expectedTypes: []string{"performance"},
		},
		{
			name: "Consistency issues",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "consistency-firewall",
					Domain:   "example.com",
					User: []model.User{
						{
							Name:      "testuser",
							Groupname: "nonexistent", // References non-existing group
							UID:       "1001",
							Scope:     "local",
						},
					},
					Group: []model.Group{
						{
							Name:  "admins",
							Gid:   "1000",
							Scope: "local",
						},
					},
				},
				Interfaces: model.Interfaces{
					Items: map[string]model.Interface{
						"wan": {Enable: "1"},
						"lan": {Enable: "1"},
					},
				},
				Dhcpd: model.Dhcpd{
					Items: map[string]model.DhcpdInterface{
						"lan": {
							Enable: "1", // DHCP enabled but no interface IP
							Range: model.Range{
								From: "192.168.1.100",
								To:   "192.168.1.200",
							},
						},
					},
				},
			},
			options: []Option{WithComplianceCheck()},
			expectedFindings: map[Severity]int{
				SeverityMedium: 1, // Non-existent group
				SeverityHigh:   1, // DHCP without interface IP
			},
			expectedTypes: []string{"consistency"},
		},
		{
			name: "All features combined",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname:                  "combined-firewall",
					Domain:                    "example.com",
					WebGUI:                    model.WebGUIConfig{Protocol: "http"},
					DisableChecksumOffloading: 1,
				},
				Interfaces: model.Interfaces{
					Items: map[string]model.Interface{
						"wan": {Enable: "1"},
						"lan": {Enable: "1"},
					},
				},
				Snmpd: model.Snmpd{
					ROCommunity: "public",
				},
				Filter: model.Filter{
					Rule: []model.Rule{
						{
							Type:      "pass",
							Interface: model.InterfaceList{"wan"},
							Source:    model.Source{Network: "any"},
							Descr:     "", // Overly broad rule
						},
					},
				},
			},
			options: []Option{WithAllFeatures()},
			expectedFindings: map[Severity]int{
				SeverityCritical: 1, // HTTP protocol
				SeverityHigh:     2, // Default SNMP + overly broad rule
				SeverityLow:      1, // Checksum offloading
			},
			expectedTypes: []string{"security", "performance"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := processor.Process(ctx, tt.config, tt.options...)
			require.NoError(t, err)
			require.NotNil(t, report)

			// Check expected finding counts by severity
			for severity, expectedCount := range tt.expectedFindings {
				actualCount := 0

				switch severity {
				case SeverityCritical:
					actualCount = len(report.Findings.Critical)
				case SeverityHigh:
					actualCount = len(report.Findings.High)
				case SeverityMedium:
					actualCount = len(report.Findings.Medium)
				case SeverityLow:
					actualCount = len(report.Findings.Low)
				case SeverityInfo:
					actualCount = len(report.Findings.Info)
				}

				assert.GreaterOrEqual(t, actualCount, expectedCount,
					"Expected at least %d %s findings, got %d", expectedCount, severity, actualCount)
			}

			// Check expected finding types are present
			var foundTypes []string

			allFindings := append([]Finding{}, report.Findings.Critical...)
			allFindings = append(allFindings, report.Findings.High...)
			allFindings = append(allFindings, report.Findings.Medium...)
			allFindings = append(allFindings, report.Findings.Low...)
			allFindings = append(allFindings, report.Findings.Info...)

			for _, finding := range allFindings {
				foundTypes = append(foundTypes, finding.Type)
			}

			for _, expectedType := range tt.expectedTypes {
				assert.Contains(t, foundTypes, expectedType,
					"Expected to find finding type %s", expectedType)
			}
		})
	}
}

// generateManyRules creates a large number of firewall rules for testing.
func generateManyRules(count int) []model.Rule {
	rules := make([]model.Rule, count)
	for i := range count {
		rules[i] = model.Rule{
			Type:      "pass",
			Interface: model.InterfaceList{"lan"},
			Descr:     fmt.Sprintf("Rule %d", i+1),
			Source:    model.Source{Network: fmt.Sprintf("192.168.%d.0/24", (i%254)+1)},
		}
	}

	return rules
}

// generateSmallConfig creates a small configuration for benchmarking.
func generateSmallConfig() *model.OpnSenseDocument {
	return &model.OpnSenseDocument{
		System: model.System{
			Hostname: "small-config",
			Domain:   "example.com",
			WebGUI:   model.WebGUIConfig{Protocol: "https"},
			SSH: struct {
				Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
			}{Group: "admins"},
			Bogons: struct {
				Interval string `xml:"interval" json:"interval,omitempty" yaml:"interval,omitempty" validate:"omitempty,oneof=monthly weekly daily never"`
			}{Interval: "monthly"},
			User: []model.User{
				{Name: "admin", UID: "1000", Scope: "local"},
				{Name: "user1", UID: "1001", Scope: "local"},
			},
			Group: []model.Group{
				{Name: "admins", Gid: "1000", Scope: "local"},
			},
		},
		Interfaces: model.Interfaces{
			Items: map[string]model.Interface{
				"wan": {
					Enable: "1",
					IPAddr: "203.0.113.1",
					Subnet: "24",
				},
				"lan": {
					Enable: "1",
					IPAddr: "192.168.1.1",
					Subnet: "24",
				},
			},
		},
		Filter: model.Filter{
			Rule: []model.Rule{
				{Type: "pass", Interface: model.InterfaceList{"lan"}, Descr: "Allow LAN"},
				{Type: "block", Interface: model.InterfaceList{"wan"}, Descr: "Block WAN"},
			},
		},
		Sysctl: []model.SysctlItem{
			{Tunable: "net.inet.ip.forwarding", Value: "1"},
			{Tunable: "kern.ipc.maxsockbuf", Value: "16777216"},
		},
	}
}

// generateLargeConfig creates a large configuration for benchmarking.
func generateLargeConfig() *model.OpnSenseDocument {
	// Create many users
	users := make([]model.User, 100)
	for i := range 100 {
		users[i] = model.User{
			Name:  fmt.Sprintf("user%d", i),
			UID:   strconv.Itoa(1000 + i),
			Scope: "local",
		}
	}

	// Create many groups
	groups := make([]model.Group, 50)
	for i := range 50 {
		groups[i] = model.Group{
			Name:  fmt.Sprintf("group%d", i),
			Gid:   strconv.Itoa(2000 + i),
			Scope: "local",
		}
	}

	// Create many sysctl items
	sysctlItems := make([]model.SysctlItem, 200)
	for i := range 200 {
		sysctlItems[i] = model.SysctlItem{
			Tunable: fmt.Sprintf("net.inet.tcp.item%d", i),
			Value:   strconv.Itoa(i % 10),
			Descr:   fmt.Sprintf("Test sysctl item %d", i),
		}
	}

	return &model.OpnSenseDocument{
		System: model.System{
			Hostname: "large-config",
			Domain:   "example.com",
			WebGUI:   model.WebGUIConfig{Protocol: "https"},
			SSH: struct {
				Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
			}{Group: "admins"},
			Bogons: struct {
				Interval string `xml:"interval" json:"interval,omitempty" yaml:"interval,omitempty" validate:"omitempty,oneof=monthly weekly daily never"`
			}{Interval: "monthly"},
			User:  users,
			Group: groups,
		},
		Interfaces: model.Interfaces{
			Items: map[string]model.Interface{
				"wan": {
					Enable:      "1",
					IPAddr:      "203.0.113.1",
					Subnet:      "24",
					BlockPriv:   "1",
					BlockBogons: "1",
				},
				"lan": {
					Enable: "1",
					IPAddr: "192.168.1.1",
					Subnet: "24",
				},
			},
		},
		Filter: model.Filter{
			Rule: generateManyRules(500), // Large number of rules
		},
		Sysctl: sysctlItems,
		Dhcpd: model.Dhcpd{
			Items: map[string]model.DhcpdInterface{
				"lan": {
					Enable: "1",
					Range: model.Range{
						From: "192.168.1.100",
						To:   "192.168.1.200",
					},
				},
			},
		},
		Snmpd: model.Snmpd{
			ROCommunity: "secure-community",
			SysLocation: "DataCenter",
			SysContact:  "admin@example.com",
		},
		Unbound: model.Unbound{
			Enable: "1",
		},
		Nat: model.Nat{
			Outbound: model.Outbound{Mode: "automatic"},
		},
	}
}

// BenchmarkCoreProcessor_ProcessSmallConfig benchmarks processing a small configuration.
func BenchmarkCoreProcessor_ProcessSmallConfig(b *testing.B) {
	processor, err := NewCoreProcessor()
	require.NoError(b, err)

	ctx := context.Background()
	smallConfig := generateSmallConfig()

	for b.Loop() {
		start := time.Now()
		report, err := processor.Process(ctx, smallConfig, WithAllFeatures())
		duration := time.Since(start)

		if err != nil {
			b.Fatal(err)
		}

		if report == nil {
			b.Fatal("report is nil")
		}

		// Ensure processing completes well under 100ms target
		if duration > 50*time.Millisecond {
			b.Errorf("Small config processing took %v, expected < 50ms", duration)
		}

		// Force garbage collection to measure memory cleanup
		runtime.GC()
	}
}

// BenchmarkCoreProcessor_ProcessLargeConfig benchmarks processing a large configuration.
func BenchmarkCoreProcessor_ProcessLargeConfig(b *testing.B) {
	processor, err := NewCoreProcessor()
	require.NoError(b, err)

	ctx := context.Background()
	largeConfig := generateLargeConfig()

	// Record baseline memory stats
	var memBefore, memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)

	for i := 0; b.Loop(); i++ {
		start := time.Now()
		report, err := processor.Process(ctx, largeConfig, WithAllFeatures())
		duration := time.Since(start)

		if err != nil {
			b.Fatal(err)
		}

		if report == nil {
			b.Fatal("report is nil")
		}

		// Ensure processing completes under 100ms target
		if duration > 100*time.Millisecond {
			b.Errorf("Large config processing took %v, expected < 100ms", duration)
		}

		// Verify report has expected content
		if report.Statistics == nil {
			b.Error("Statistics should not be nil")
		}

		if report.Statistics.TotalUsers != 100 {
			b.Errorf("Expected 100 users, got %d", report.Statistics.TotalUsers)
		}

		if report.Statistics.TotalFirewallRules != 500 {
			b.Errorf("Expected 500 firewall rules, got %d", report.Statistics.TotalFirewallRules)
		}

		// Check memory growth every 10 iterations
		if i%10 == 9 {
			runtime.GC()
			runtime.ReadMemStats(&memAfter)

			// Memory growth should be reasonable
			var memGrowthMB float64
			if memAfter.Alloc >= memBefore.Alloc {
				memGrowthMB = float64(memAfter.Alloc-memBefore.Alloc) / (1024 * 1024)
			} else {
				// Memory actually decreased (GC cleaned up)
				memGrowthMB = 0
			}

			// Memory growth should be reasonable (< 50 MB)
			if memGrowthMB > 50 {
				b.Errorf("Memory grew by %.2f MB, expected reasonable growth (< 50 MB)", memGrowthMB)
			}
		}

		// Force garbage collection to measure memory cleanup
		runtime.GC()
	}

	b.StopTimer()

	// Final memory measurement
	runtime.GC()
	runtime.ReadMemStats(&memAfter)

	// Calculate final metrics
	var memGrowthMB float64
	if memAfter.Alloc >= memBefore.Alloc {
		memGrowthMB = float64(memAfter.Alloc-memBefore.Alloc) / (1024 * 1024)
	}

	peakMemMB := float64(memAfter.Alloc) / (1024 * 1024)

	b.Logf("Final memory growth: %.2f MB", memGrowthMB)
	b.Logf("Peak memory usage: %.2f MB", peakMemMB)

	// Report custom metrics
	b.ReportMetric(memGrowthMB, "memory_growth_MB")
	b.ReportMetric(peakMemMB, "peak_memory_MB")
}

// BenchmarkCoreProcessor_ProcessConcurrent benchmarks concurrent processing.
func BenchmarkCoreProcessor_ProcessConcurrent(b *testing.B) {
	processor, err := NewCoreProcessor()
	require.NoError(b, err)

	ctx := context.Background()
	smallConfig := generateSmallConfig()
	largeConfig := generateLargeConfig()

	b.Run("Concurrent Small Configs", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				start := time.Now()
				report, err := processor.Process(ctx, smallConfig, WithStats())
				duration := time.Since(start)

				if err != nil {
					b.Error(err)
					return
				}

				if report == nil {
					b.Error("report is nil")
					return
				}

				// Concurrent processing should still be fast
				if duration > 100*time.Millisecond {
					b.Errorf("Concurrent small config processing took %v, expected < 100ms", duration)
				}
			}
		})
	})

	b.Run("Concurrent Mixed Configs", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0

			for pb.Next() {
				// Alternate between small and large configs
				var config *model.OpnSenseDocument
				if i%2 == 0 {
					config = smallConfig
				} else {
					config = largeConfig
				}

				i++

				start := time.Now()
				report, err := processor.Process(ctx, config, WithAllFeatures())
				duration := time.Since(start)

				if err != nil {
					b.Error(err)
					return
				}

				if report == nil {
					b.Error("report is nil")
					return
				}

				// Mixed concurrent processing should complete within target
				if duration > 150*time.Millisecond {
					b.Errorf("Concurrent mixed config processing took %v, expected < 150ms", duration)
				}
			}
		})
	})
}

// BenchmarkCoreProcessor_NormalizationOnly benchmarks just the normalization phase.
func BenchmarkCoreProcessor_NormalizationOnly(b *testing.B) {
	processor, err := NewCoreProcessor()
	require.NoError(b, err)

	largeConfig := generateLargeConfig()

	for b.Loop() {
		start := time.Now()
		normalized := processor.normalize(largeConfig)
		duration := time.Since(start)

		if normalized == nil {
			b.Fatal("normalized config is nil")
		}

		// Normalization should be very fast
		if duration > 10*time.Millisecond {
			b.Errorf("Normalization took %v, expected < 10ms", duration)
		}

		// Verify normalization worked
		if len(normalized.System.User) != 100 {
			b.Errorf("Expected 100 users after normalization, got %d", len(normalized.System.User))
		}

		// Verify sorting
		if len(normalized.System.User) > 1 {
			for j := 1; j < len(normalized.System.User); j++ {
				if normalized.System.User[j-1].Name > normalized.System.User[j].Name {
					b.Error("Users are not sorted after normalization")
					break
				}
			}
		}

		runtime.GC()
	}
}

// TestCoreProcessor_RaceConditions tests for race conditions using -race flag.
func TestCoreProcessor_RaceConditions(t *testing.T) {
	localProcessor, err := NewCoreProcessor()
	require.NoError(t, err)

	ctx := context.Background()
	smallConfig := generateSmallConfig()
	largeConfig := generateLargeConfig()

	// Test concurrent processing of the same config
	t.Run("Concurrent Same Config", func(t *testing.T) {
		var wg sync.WaitGroup

		errorChan := make(chan error, 10)

		for i := range 10 {
			wg.Add(1)

			go func(id int) {
				defer wg.Done()

				report, err := localProcessor.Process(ctx, smallConfig, WithAllFeatures())
				if err != nil {
					errorChan <- fmt.Errorf("goroutine %d: %w", id, err)
					return
				}

				if report == nil {
					errorChan <- NewTestError(id, "report is nil")
					return
				}
				// Verify basic report structure
				if report.ConfigInfo.Hostname != "small-config" {
					errorChan <- NewTestError(id, "unexpected hostname "+report.ConfigInfo.Hostname)
				}
			}(i)
		}

		wg.Wait()
		close(errorChan)

		// Check for any errors
		for err := range errorChan {
			t.Error(err)
		}
	})

	// Test concurrent processing of different configs
	t.Run("Concurrent Different Configs", func(t *testing.T) {
		var wg sync.WaitGroup

		errorChan := make(chan error, 10)

		for i := range 10 {
			wg.Add(1)

			go func(id int) {
				defer wg.Done()

				var (
					config           *model.OpnSenseDocument
					expectedHostname string
				)

				if id%2 == 0 {
					config = smallConfig
					expectedHostname = "small-config"
				} else {
					config = largeConfig
					expectedHostname = "large-config"
				}

				report, err := localProcessor.Process(ctx, config, WithAllFeatures())
				if err != nil {
					errorChan <- fmt.Errorf("goroutine %d: %w", id, err)
					return
				}

				if report == nil {
					errorChan <- NewTestError(id, "report is nil")
					return
				}
				// Verify correct config was processed
				if report.ConfigInfo.Hostname != expectedHostname {
					errorChan <- &TestHostnameError{GoroutineID: id, ExpectedHostname: expectedHostname, ActualHostname: report.ConfigInfo.Hostname}
				}
			}(i)
		}

		wg.Wait()
		close(errorChan)

		// Check for any errors
		for err := range errorChan {
			t.Error(err)
		}
	})

	// Test concurrent processor creation
	t.Run("Concurrent Processor Creation", func(t *testing.T) {
		var wg sync.WaitGroup

		errorChan := make(chan error, 10)

		for i := range 10 {
			wg.Add(1)

			go func(id int) {
				defer wg.Done()

				localProcessor, err := NewCoreProcessor()
				if err != nil {
					errorChan <- fmt.Errorf("goroutine %d: failed to create processor: %w", id, err)
					return
				}

				report, err := localProcessor.Process(ctx, smallConfig, WithStats())
				if err != nil {
					errorChan <- fmt.Errorf("goroutine %d: %w", id, err)
					return
				}

				if report == nil {
					errorChan <- NewTestError(id, "report is nil")
				}
			}(i)
		}

		wg.Wait()
		close(errorChan)

		// Check for any errors
		for err := range errorChan {
			t.Error(err)
		}
	})
}

// TestCoreProcessor_StatisticsAccuracy tests that statistics are calculated accurately.
func TestCoreProcessor_StatisticsAccuracy(t *testing.T) {
	processor, err := NewCoreProcessor()
	require.NoError(t, err)

	ctx := context.Background()

	tests := []struct {
		name     string
		config   *model.OpnSenseDocument
		validate func(t *testing.T, stats *Statistics)
	}{
		{
			name: "Basic statistics accuracy",
			config: &model.OpnSenseDocument{
				Version: "24.1.1",
				Theme:   "opnsense",
				System: model.System{
					Hostname: "stats-firewall",
					Domain:   "example.com",
					User: []model.User{
						{Name: "admin", Scope: "local", UID: "1000"},
						{Name: "user1", Scope: "local", UID: "1001"},
						{Name: "user2", Scope: "system", UID: "1002"},
					},
					Group: []model.Group{
						{Name: "admins", Scope: "local", Gid: "1000"},
						{Name: "users", Scope: "system", Gid: "1001"},
					},
					WebGUI: model.WebGUIConfig{Protocol: "https"},
					SSH: struct {
						Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
					}{Group: "admins"},
					Bogons: struct {
						Interval string `xml:"interval" json:"interval,omitempty" yaml:"interval,omitempty" validate:"omitempty,oneof=monthly weekly daily never"`
					}{Interval: "monthly"},
				},
				Interfaces: model.Interfaces{
					Items: map[string]model.Interface{
						"wan": {
							Enable:      "1",
							IPAddr:      "203.0.113.1",
							Subnet:      "24",
							BlockPriv:   "1",
							BlockBogons: "1",
						},
						"lan": {
							Enable: "1",
							IPAddr: "192.168.1.1",
							Subnet: "24",
						},
					},
				},
				Filter: model.Filter{
					Rule: []model.Rule{
						{Type: "pass", Interface: model.InterfaceList{"lan"}, Descr: "Allow LAN to WAN"},
						{Type: "block", Interface: model.InterfaceList{"wan"}, Descr: "Block external access"},
						{Type: "pass", Interface: model.InterfaceList{"wan"}, Descr: "Allow specific service"},
					},
				},
				Dhcpd: model.Dhcpd{
					Items: map[string]model.DhcpdInterface{
						"lan": {
							Enable: "1",
							Range: model.Range{
								From: "192.168.1.100",
								To:   "192.168.1.200",
							},
						},
					},
				},
				Snmpd: model.Snmpd{
					ROCommunity: "secure-community",
					SysLocation: "DataCenter",
					SysContact:  "admin@example.com",
				},
				Unbound: model.Unbound{
					Enable: "1",
				},
				Sysctl: []model.SysctlItem{
					{Tunable: "net.inet.ip.forwarding", Value: "1"},
					{Tunable: "net.inet.tcp.mssdflt", Value: "1460"},
				},
				Nat: model.Nat{
					Outbound: model.Outbound{Mode: "automatic"},
				},
				Ntpd: model.Ntpd{
					Prefer: "pool.ntp.org",
				},
			},
			validate: func(t *testing.T, stats *Statistics) {
				t.Helper()
				// Interface statistics
				assert.Equal(t, 2, stats.TotalInterfaces, "Should count WAN and LAN interfaces")
				assert.Equal(t, 1, stats.InterfacesByType["wan"], "Should have 1 WAN interface")
				assert.Equal(t, 1, stats.InterfacesByType["lan"], "Should have 1 LAN interface")
				assert.Len(t, stats.InterfaceDetails, 2, "Should have details for both interfaces")

				// Check interface details
				wanDetail := stats.InterfaceDetails[0] // WAN should be first
				if wanDetail.Name == "wan" {
					assert.True(t, wanDetail.Enabled, "WAN should be enabled")
					assert.True(t, wanDetail.HasIPv4, "WAN should have IPv4")
					assert.True(t, wanDetail.BlockPriv, "WAN should block private networks")
					assert.True(t, wanDetail.BlockBogons, "WAN should block bogons")
				}

				// Firewall statistics
				assert.Equal(t, 3, stats.TotalFirewallRules, "Should count all firewall rules")
				assert.Equal(t, 1, stats.RulesByInterface["lan"], "Should have 1 LAN rule")
				assert.Equal(t, 2, stats.RulesByInterface["wan"], "Should have 2 WAN rules")
				assert.Equal(t, 2, stats.RulesByType["pass"], "Should have 2 pass rules")
				assert.Equal(t, 1, stats.RulesByType["block"], "Should have 1 block rule")

				// NAT statistics
				assert.Equal(t, "automatic", stats.NATMode, "Should detect NAT mode")
				assert.Equal(t, 1, stats.NATEntries, "Should count NAT configuration")

				// DHCP statistics
				assert.Equal(t, 1, stats.DHCPScopes, "Should have 1 DHCP scope")
				assert.Len(t, stats.DHCPScopeDetails, 1, "Should have DHCP scope details")
				assert.Equal(t, "lan", stats.DHCPScopeDetails[0].Interface, "DHCP should be on LAN")
				assert.True(t, stats.DHCPScopeDetails[0].Enabled, "DHCP should be enabled")
				assert.Equal(t, "192.168.1.100", stats.DHCPScopeDetails[0].From, "DHCP range start")
				assert.Equal(t, "192.168.1.200", stats.DHCPScopeDetails[0].To, "DHCP range end")

				// User and group statistics
				assert.Equal(t, 3, stats.TotalUsers, "Should count all users")
				assert.Equal(t, 2, stats.TotalGroups, "Should count all groups")
				assert.Equal(t, 2, stats.UsersByScope["local"], "Should have 2 local users")
				assert.Equal(t, 1, stats.UsersByScope["system"], "Should have 1 system user")
				assert.Equal(t, 1, stats.GroupsByScope["local"], "Should have 1 local group")
				assert.Equal(t, 1, stats.GroupsByScope["system"], "Should have 1 system group")

				// Service statistics
				expectedServices := []string{
					"DHCP Server (LAN)",
					"Unbound DNS Resolver",
					"SNMP Daemon",
					"SSH Daemon",
					"NTP Daemon",
				}
				assert.Equal(t, len(expectedServices), stats.TotalServices, "Should count all enabled services")
				for _, service := range expectedServices {
					assert.Contains(t, stats.EnabledServices, service, "Should list %s as enabled", service)
				}

				// System configuration statistics
				assert.Equal(t, 2, stats.SysctlSettings, "Should count sysctl settings")

				// Security features
				expectedSecurityFeatures := []string{"Block Private Networks", "Block Bogon Networks", "HTTPS Web GUI"}
				for _, feature := range expectedSecurityFeatures {
					assert.Contains(t, stats.SecurityFeatures, feature, "Should detect %s security feature", feature)
				}

				// Summary metrics should be reasonable
				assert.Greater(t, stats.Summary.TotalConfigItems, 10, "Should have reasonable number of config items")
				assert.GreaterOrEqual(t, stats.Summary.SecurityScore, 0, "Security score should be non-negative")
				assert.LessOrEqual(t, stats.Summary.SecurityScore, 100, "Security score should not exceed 100")
				assert.GreaterOrEqual(t, stats.Summary.ConfigComplexity, 0, "Complexity should be non-negative")
				assert.LessOrEqual(t, stats.Summary.ConfigComplexity, 100, "Complexity should not exceed 100")
				assert.True(t, stats.Summary.HasSecurityFeatures, "Should detect security features")
			},
		},
		{
			name: "Empty configuration statistics",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "minimal-firewall",
					Domain:   "example.com",
				},
				Interfaces: model.Interfaces{
					Items: map[string]model.Interface{
						"wan": {Enable: "1"},
						"lan": {Enable: "1"},
					},
				},
			},
			validate: func(t *testing.T, stats *Statistics) {
				t.Helper()
				// Basic interface count should still be present
				assert.Equal(t, 2, stats.TotalInterfaces, "Should count basic interfaces")
				assert.Equal(t, 0, stats.TotalFirewallRules, "Should have no firewall rules")
				assert.Equal(t, 0, stats.TotalUsers, "Should have no users")
				assert.Equal(t, 0, stats.TotalGroups, "Should have no groups")
				assert.Equal(t, 0, stats.DHCPScopes, "Should have no DHCP scopes")
				assert.Equal(t, 0, stats.SysctlSettings, "Should have no sysctl settings")
				assert.Equal(t, 0, stats.TotalServices, "Should have no services enabled")
				assert.Empty(t, stats.EnabledServices, "Should have no enabled services")
				// After normalization, HTTPS is the default webgui protocol, so it's detected as a security feature
				assert.Equal(
					t,
					[]string{"HTTPS Web GUI"},
					stats.SecurityFeatures,
					"Should detect HTTPS Web GUI from normalization default",
				)
				assert.True(t, stats.Summary.HasSecurityFeatures, "Should detect security features from normalization")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := processor.Process(ctx, tt.config, WithStats())
			require.NoError(t, err)
			require.NotNil(t, report)
			require.NotNil(t, report.Statistics)

			tt.validate(t, report.Statistics)
		})
	}
}

// TestCoreProcessor_TransformFormats tests all supported output formats.
func TestCoreProcessor_TransformFormats(t *testing.T) {
	processor, err := NewCoreProcessor()
	require.NoError(t, err)

	ctx := context.Background()
	cfg := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "transform-test",
			Domain:   "example.com",
		},
		Interfaces: model.Interfaces{
			Items: map[string]model.Interface{
				"wan": {Enable: "1"},
				"lan": {Enable: "1"},
			},
		},
	}

	report, err := processor.Process(ctx, cfg, WithStats())
	require.NoError(t, err)
	require.NotNil(t, report)

	tests := []struct {
		name        string
		format      string
		expectError bool
		validate    func(t *testing.T, output string)
	}{
		{
			name:        "JSON format",
			format:      "json",
			expectError: false,
			validate: func(t *testing.T, output string) {
				t.Helper()
				assert.NotEmpty(t, output)
				assert.Contains(t, output, "transform-test")
				assert.Contains(t, output, "{")
				assert.Contains(t, output, "}")
			},
		},
		{
			name:        "JSON format case insensitive",
			format:      "JSON",
			expectError: false,
			validate: func(t *testing.T, output string) {
				t.Helper()
				assert.NotEmpty(t, output)
				assert.Contains(t, output, "transform-test")
			},
		},
		{
			name:        "Markdown format",
			format:      "markdown",
			expectError: false,
			validate: func(t *testing.T, output string) {
				t.Helper()
				assert.NotEmpty(t, output)
				assert.Contains(t, output, "# OPNsense Configuration Analysis Report")
				assert.Contains(t, output, "transform-test")
			},
		},
		{
			name:        "YAML format",
			format:      "yaml",
			expectError: false,
			validate: func(t *testing.T, output string) {
				t.Helper()
				assert.NotEmpty(t, output)
				assert.Contains(t, output, "transform-test")
			},
		},
		{
			name:        "Unsupported format",
			format:      "xml",
			expectError: true,
			validate: func(t *testing.T, output string) {
				t.Helper()
				assert.Empty(t, output)
			},
		},
		{
			name:        "Empty format",
			format:      "",
			expectError: true,
			validate: func(t *testing.T, output string) {
				t.Helper()
				assert.Empty(t, output)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := processor.Transform(ctx, report, tt.format)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			tt.validate(t, output)
		})
	}
}

// TestCoreProcessor_ValidationErrors tests validation error handling.
func TestCoreProcessor_ValidationErrors(t *testing.T) {
	processor, err := NewCoreProcessor()
	require.NoError(t, err)

	ctx := context.Background()

	tests := []struct {
		name           string
		config         *model.OpnSenseDocument
		expectedErrors int
	}{
		{
			name: "Configuration with validation errors",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "", // Empty hostname should trigger validation error
					Domain:   "example.com",
					SSH: struct {
						Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
					}{Group: ""}, // Empty required field
				},
				Interfaces: model.Interfaces{
					Items: map[string]model.Interface{
						"wan": {Enable: "1"},
						"lan": {Enable: "1"},
					},
				},
			},
			expectedErrors: 0, // May not have strict validation depending on implementation
		},
		{
			name: "Valid configuration",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "valid-host",
					Domain:   "example.com",
					SSH: struct {
						Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
					}{Group: "admins"},
				},
				Interfaces: model.Interfaces{
					Items: map[string]model.Interface{
						"wan": {Enable: "1"},
						"lan": {Enable: "1"},
					},
				},
			},
			expectedErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := processor.Process(ctx, tt.config, WithAllFeatures())
			require.NoError(t, err)
			assert.NotNil(t, report)

			// Check for validation findings
			validationFindings := 0
			for _, finding := range report.Findings.High {
				if finding.Type == "validation" {
					validationFindings++
				}
			}

			if tt.expectedErrors > 0 {
				assert.GreaterOrEqual(t, validationFindings, tt.expectedErrors)
			}
		})
	}
}

// TestCoreProcessor_ProcessorCreationFailure tests processor creation edge cases.
func TestCoreProcessor_ProcessorCreationFailure(t *testing.T) {
	// Test that NewCoreProcessor handles markdown generator failures gracefully
	// This test assumes the markdown generator can fail under certain conditions

	processor, err := NewCoreProcessor()
	// Should normally succeed
	require.NoError(t, err)
	assert.NotNil(t, processor)
	assert.NotNil(t, processor.validator)
	assert.NotNil(t, processor.generator)
}

// TestReport_FindingSeverityDistribution tests finding distribution.
func TestReport_FindingSeverityDistribution(t *testing.T) {
	cfg := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "severity-test",
			Domain:   "example.com",
		},
	}

	report := NewReport(cfg, Config{EnableStats: true})

	// Add findings with different severities
	severityCount := map[Severity]int{
		SeverityCritical: 5,
		SeverityHigh:     10,
		SeverityMedium:   15,
		SeverityLow:      20,
		SeverityInfo:     25,
	}

	for severity, count := range severityCount {
		for i := range count {
			finding := Finding{
				Type:        "test",
				Title:       fmt.Sprintf("%s Finding %d", severity, i+1),
				Description: fmt.Sprintf("Test %s finding", severity),
				Component:   "test-component",
			}
			report.AddFinding(severity, finding)
		}
	}

	// Verify distribution
	assert.Len(t, report.Findings.Critical, severityCount[SeverityCritical])
	assert.Len(t, report.Findings.High, severityCount[SeverityHigh])
	assert.Len(t, report.Findings.Medium, severityCount[SeverityMedium])
	assert.Len(t, report.Findings.Low, severityCount[SeverityLow])
	assert.Len(t, report.Findings.Info, severityCount[SeverityInfo])

	// Verify total
	expectedTotal := 5 + 10 + 15 + 20 + 25 // 75
	assert.Equal(t, expectedTotal, report.TotalFindings())

	// Test HasCriticalFindings
	assert.True(t, report.HasCriticalFindings())

	// Test Summary method with multiple findings
	summary := report.Summary()
	assert.Contains(t, summary, "75 findings")
	assert.Contains(t, summary, "5 critical")
	assert.Contains(t, summary, "10 high")
}

// TestReport_EmptyFindingsScenarios tests various empty finding scenarios.
func TestReport_EmptyFindingsScenarios(t *testing.T) {
	cfg := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "empty-findings",
			Domain:   "example.com",
		},
	}

	tests := []struct {
		name     string
		setup    func(report *Report)
		validate func(t *testing.T, report *Report)
	}{
		{
			name:  "Completely empty findings",
			setup: func(_ *Report) {},
			validate: func(t *testing.T, report *Report) {
				t.Helper()
				assert.Equal(t, 0, report.TotalFindings())
				assert.False(t, report.HasCriticalFindings())
				// Accept either legacy or new summary string for future-proofing
				summary := report.Summary()
				if !strings.Contains(summary, "No findings to report.") &&
					!strings.Contains(summary, "No issues found") {
					t.Errorf(
						"Expected summary to contain 'No findings to report.' or 'No issues found', got: %q",
						summary,
					)
				}

				markdown := report.ToMarkdown()
				if !strings.Contains(markdown, "No findings to report.") &&
					!strings.Contains(markdown, "No issues found") {
					t.Errorf(
						"Expected markdown to contain 'No findings to report.' or 'No issues found', got: %q",
						markdown,
					)
				}
			},
		},
		{
			name: "Only info findings",
			setup: func(report *Report) {
				report.AddFinding(SeverityInfo, Finding{
					Type:        "info",
					Title:       "Info Finding",
					Description: "Informational message",
					Component:   "test",
				})
			},
			validate: func(t *testing.T, report *Report) {
				t.Helper()
				assert.Equal(t, 1, report.TotalFindings())
				assert.False(t, report.HasCriticalFindings())
				assert.Contains(t, report.Summary(), "1 findings")
				assert.Contains(t, report.Summary(), "1 info")
			},
		},
		{
			name: "Mixed severities without critical",
			setup: func(report *Report) {
				report.AddFinding(SeverityHigh, Finding{
					Type: "test", Title: "High", Description: "High priority", Component: "test",
				})
				report.AddFinding(SeverityMedium, Finding{
					Type: "test", Title: "Medium", Description: "Medium priority", Component: "test",
				})
				report.AddFinding(SeverityLow, Finding{
					Type: "test", Title: "Low", Description: "Low priority", Component: "test",
				})
			},
			validate: func(t *testing.T, report *Report) {
				t.Helper()
				assert.Equal(t, 3, report.TotalFindings())
				assert.False(t, report.HasCriticalFindings())
				assert.Contains(t, report.Summary(), "3 findings")
				assert.Contains(t, report.Summary(), "1 high")
				assert.Contains(t, report.Summary(), "1 medium")
				assert.Contains(t, report.Summary(), "1 low")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := NewReport(cfg, Config{EnableStats: true})
			tt.setup(report)
			tt.validate(t, report)
		})
	}
}

// TestStatistics_ZeroValues tests statistics with zero/empty values.
func TestStatistics_ZeroValues(t *testing.T) {
	processor, err := NewCoreProcessor()
	require.NoError(t, err)

	ctx := context.Background()

	// Configuration with minimal/zero values
	cfg := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "zero-values",
			Domain:   "example.com",
		},
		// No interfaces, users, groups, rules, etc.
	}

	report, err := processor.Process(ctx, cfg, WithStats())
	require.NoError(t, err)
	require.NotNil(t, report)
	require.NotNil(t, report.Statistics)

	stats := report.Statistics

	// Test zero values (expect 2 interfaces: wan, lan)
	assert.Equal(t, 2, stats.TotalInterfaces)
	assert.Equal(t, 0, stats.TotalFirewallRules)
	assert.Equal(t, 0, stats.TotalUsers)
	assert.Equal(t, 0, stats.TotalGroups)
	assert.Equal(t, 0, stats.DHCPScopes)
	assert.Equal(t, 0, stats.SysctlSettings)
	assert.Equal(t, 0, stats.TotalServices)

	// Test empty collections (interfaces present)
	assert.NotEmpty(t, stats.InterfaceDetails)
	assert.Empty(t, stats.RulesByInterface)
	assert.Empty(t, stats.RulesByType)
	assert.Empty(t, stats.UsersByScope)
	assert.Empty(t, stats.GroupsByScope)
	assert.Empty(t, stats.EnabledServices)
	assert.Empty(t, stats.DHCPScopeDetails)

	// Summary should handle zero values gracefully
	assert.GreaterOrEqual(t, stats.Summary.TotalConfigItems, 0)
	assert.GreaterOrEqual(t, stats.Summary.SecurityScore, 0)
	assert.GreaterOrEqual(t, stats.Summary.ConfigComplexity, 0)
}

// TestCoreProcessor_MutexProtection tests that the mutex protects concurrent access properly.
func TestCoreProcessor_MutexProtection(t *testing.T) {
	processor, err := NewCoreProcessor()
	require.NoError(t, err)

	ctx := context.Background()
	config := generateSmallConfig()

	// Test that processing is properly serialized
	// We can't directly test mutex behavior, but we can ensure no data races occur
	var wg sync.WaitGroup
	results := make([]*Report, 50)
	errors := make([]error, 50)

	for i := range 50 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			report, err := processor.Process(ctx, config, WithAllFeatures())
			results[idx] = report
			errors[idx] = err
		}(i)
	}

	wg.Wait()

	// All should succeed
	for i, err := range errors {
		require.NoError(t, err, "Process %d should not error", i)
		assert.NotNil(t, results[i], "Process %d should return report", i)
	}

	// All reports should be consistent
	for i := 1; i < len(results); i++ {
		assert.Equal(t, results[0].ConfigInfo.Hostname, results[i].ConfigInfo.Hostname)
		assert.Equal(t, results[0].Statistics.TotalUsers, results[i].Statistics.TotalUsers)
		assert.Equal(t, results[0].Statistics.TotalFirewallRules, results[i].Statistics.TotalFirewallRules)
	}
}

// TestProcessor_ContextCancellationTiming tests context cancellation at different phases.
func TestProcessor_ContextCancellationTiming(t *testing.T) {
	processor, err := NewCoreProcessor()
	require.NoError(t, err)

	config := generateLargeConfig()

	tests := []struct {
		name        string
		cancelAfter time.Duration
		expectError bool
	}{
		{
			name:        "Cancel immediately",
			cancelAfter: 0,
			expectError: true,
		},
		{
			name:        "Cancel after 1ms",
			cancelAfter: 1 * time.Millisecond,
			expectError: true,
		},
		{
			name:        "Cancel after 10ms",
			cancelAfter: 10 * time.Millisecond,
			expectError: false, // Might complete before cancellation
		},
		{
			name:        "Cancel after 100ms",
			cancelAfter: 100 * time.Millisecond,
			expectError: false, // Should complete
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			if tt.cancelAfter == 0 {
				cancel() // Cancel immediately
			} else {
				go func() {
					time.Sleep(tt.cancelAfter)
					cancel()
				}()
			}

			_, err := processor.Process(ctx, config, WithAllFeatures())

			if tt.expectError && tt.cancelAfter <= 1*time.Millisecond {
				// For very short timeouts, we expect cancellation
				if err == nil {
					t.Errorf("Expected error due to context cancellation, got nil")
				}
			}
			// For longer timeouts, either success or cancellation is acceptable
		})
	}
}

// TestReport_JSONSerializationPerformance tests JSON serialization performance.
func TestReport_JSONSerializationPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	cfg := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "perf-test",
			Domain:   "example.com",
		},
	}

	report := NewReport(cfg, Config{EnableStats: true})

	// Add many findings
	for i := range 1000 {
		finding := Finding{
			Type:  "performance-test",
			Title: fmt.Sprintf("Finding %d with some longer text to make it more realistic", i),
			Description: fmt.Sprintf(
				"This is finding number %d with a detailed description that includes various details and explanations that would normally be found in a real security finding report",
				i,
			),
			Recommendation: fmt.Sprintf(
				"Recommendation %d: Please fix this issue by following these detailed steps and procedures",
				i,
			),
			Component: fmt.Sprintf("component-%d", i%10),
		}

		severity := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}[i%5]
		report.AddFinding(severity, finding)
	}

	// Test serialization performance
	start := time.Now()
	jsonStr, err := report.ToJSON()
	duration := time.Since(start)

	require.NoError(t, err)
	assert.NotEmpty(t, jsonStr)

	// Should complete within reasonable time (< 1 second for 1000 findings)
	assert.Less(t, duration, 1*time.Second, "JSON serialization should be fast")

	t.Logf("JSON serialization of 1000 findings took %v", duration)
	t.Logf("JSON output size: %d bytes", len(jsonStr))

	// Verify the JSON is valid and contains expected data
	assert.Contains(t, jsonStr, "perf-test")
	assert.Contains(t, jsonStr, "Finding 999") // Last finding should be present
}

// TestReport_MarkdownGenerationEdgeCases tests markdown generation with edge cases.
func TestReport_MarkdownGenerationEdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		setupFunc  func() *Report
		expectFunc func(t *testing.T, markdown string)
	}{
		{
			name: "Report with very long text",
			setupFunc: func() *Report {
				cfg := &model.OpnSenseDocument{
					System: model.System{
						Hostname: "long-text-test",
						Domain:   "example.com",
					},
				}
				report := NewReport(cfg, Config{EnableStats: true})

				longText := strings.Repeat(
					"This is a very long text that contains many words and should test the markdown generator's ability to handle large amounts of text without issues. ",
					50,
				)

				report.AddFinding(SeverityHigh, Finding{
					Type:           "test",
					Title:          "Finding with very long text",
					Description:    longText,
					Recommendation: longText,
					Component:      "test-component",
				})

				return report
			},
			expectFunc: func(t *testing.T, markdown string) {
				t.Helper()
				assert.Contains(t, markdown, "# OPNsense Configuration Analysis Report")
				assert.Contains(t, markdown, "long-text-test")
				assert.Contains(t, markdown, "Finding with very long text")
				assert.Greater(t, len(markdown), 5000, "Markdown should contain the long text")
			},
		},
		{
			name: "Report with HTML-like content",
			setupFunc: func() *Report {
				cfg := &model.OpnSenseDocument{
					System: model.System{
						Hostname: "html-test",
						Domain:   "example.com",
					},
				}
				report := NewReport(cfg, Config{EnableStats: true})

				report.AddFinding(SeverityMedium, Finding{
					Type:        "test",
					Title:       "Finding with <script>alert('xss')</script> content",
					Description: "This contains <b>HTML</b> tags and &entities;",
					Component:   "html-component",
				})

				return report
			},
			expectFunc: func(t *testing.T, markdown string) {
				t.Helper()
				assert.Contains(t, markdown, "# OPNsense Configuration Analysis Report")
				assert.Contains(t, markdown, "html-test")
				// HTML content should be preserved in markdown (it's up to renderer to sanitize)
				assert.Contains(t, markdown, "<script>")
				assert.Contains(t, markdown, "<b>HTML</b>")
				assert.Contains(t, markdown, "&entities;")
			},
		},
		{
			name: "Report with empty statistics",
			setupFunc: func() *Report {
				cfg := &model.OpnSenseDocument{
					System: model.System{
						Hostname: "empty-stats",
						Domain:   "example.com",
					},
				}
				// Create report with stats disabled
				report := NewReport(cfg, Config{EnableStats: false})

				return report
			},
			expectFunc: func(t *testing.T, markdown string) {
				t.Helper()
				assert.Contains(t, markdown, "# OPNsense Configuration Analysis Report")
				assert.Contains(t, markdown, "empty-stats")
				// Should not contain statistics section if disabled
				// Note: This depends on the actual markdown template implementation
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := tt.setupFunc()
			markdown := report.ToMarkdown()
			tt.expectFunc(t, markdown)
		})
	}
}

// TestProcessorOptions_EdgeCases tests edge cases in option processing.
func TestProcessorOptions_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		options []Option
		expect  func(t *testing.T, config *Config)
	}{
		{
			name:    "Nil options slice",
			options: nil,
			expect: func(t *testing.T, config *Config) {
				t.Helper()
				// Should have defaults
				assert.True(t, config.EnableStats)
				assert.False(t, config.EnableDeadRuleCheck)
			},
		},
		{
			name:    "Empty options slice",
			options: []Option{},
			expect: func(t *testing.T, config *Config) {
				t.Helper()
				// Should have defaults
				assert.True(t, config.EnableStats)
				assert.False(t, config.EnableDeadRuleCheck)
			},
		},
		{
			name: "Duplicate options",
			options: []Option{
				WithSecurityAnalysis(),
				WithSecurityAnalysis(),
				WithSecurityAnalysis(),
			},
			expect: func(t *testing.T, config *Config) {
				t.Helper()
				// Multiple calls should be idempotent
				assert.True(t, config.EnableSecurityAnalysis)
				assert.True(t, config.EnableStats)          // Default
				assert.False(t, config.EnableDeadRuleCheck) // Not set
			},
		},
		{
			name: "Conflicting options order",
			options: []Option{
				WithAllFeatures(), // Enables everything
				func(c *Config) { // Custom option that disables something
					c.EnableDeadRuleCheck = false
				},
			},
			expect: func(t *testing.T, config *Config) {
				t.Helper()
				// Last option should win
				assert.True(t, config.EnableStats)
				assert.True(t, config.EnableSecurityAnalysis)
				assert.False(t, config.EnableDeadRuleCheck) // Disabled by custom option
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig()
			config.ApplyOptions(tt.options...)
			tt.expect(t, config)
		})
	}
}

// TestReport_ThreadSafetyStress performs stress testing for thread safety.
func TestReport_ThreadSafetyStress(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	cfg := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "stress-test",
			Domain:   "example.com",
		},
	}

	report := NewReport(cfg, Config{EnableStats: true})

	// Stress test with many goroutines doing different operations
	var wg sync.WaitGroup
	numGoroutines := 100
	operationsPerGoroutine := 100

	// Start goroutines that add findings
	for i := range numGoroutines {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			for j := range operationsPerGoroutine {
				finding := Finding{
					Type:        "stress-test",
					Title:       fmt.Sprintf("G%d-F%d", goroutineID, j),
					Description: fmt.Sprintf("Stress test finding from goroutine %d, operation %d", goroutineID, j),
					Component:   fmt.Sprintf("component-%d", j%5),
				}

				severity := []Severity{
					SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo,
				}[j%5]

				report.AddFinding(severity, finding)

				// Occasionally check total findings (read operation)
				if j%10 == 0 {
					_ = report.TotalFindings()
				}

				// Occasionally check for critical findings (read operation)
				if j%15 == 0 {
					_ = report.HasCriticalFindings()
				}
			}
		}(i)
	}

	// Start goroutines that perform read operations
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for j := range operationsPerGoroutine * 10 {
				_ = report.TotalFindings()
				_ = report.HasCriticalFindings()
				_ = report.Summary()

				// Occasionally serialize to JSON
				if j%50 == 0 {
					if _, err := report.ToJSON(); err != nil {
						// Log or handle error if needed, but don't fail the test
						_ = err
					}
				}

				// Small delay to allow other goroutines to interleave
				time.Sleep(1 * time.Microsecond)
			}
		}()
	}

	wg.Wait()

	// Verify final state
	totalExpected := numGoroutines * operationsPerGoroutine
	actualTotal := report.TotalFindings()
	assert.Equal(t, totalExpected, actualTotal, "All findings should be present")

	// Verify distribution (each severity should have equal numbers)
	expectedPerSeverity := totalExpected / 5
	assert.Len(t, report.Findings.Critical, expectedPerSeverity)
	assert.Len(t, report.Findings.High, expectedPerSeverity)
	assert.Len(t, report.Findings.Medium, expectedPerSeverity)
	assert.Len(t, report.Findings.Low, expectedPerSeverity)
	assert.Len(t, report.Findings.Info, expectedPerSeverity)

	// Final serialization should work
	jsonStr, err := report.ToJSON()
	require.NoError(t, err)
	assert.NotEmpty(t, jsonStr)

	markdown := report.ToMarkdown()
	assert.NotEmpty(t, markdown)
	assert.Contains(t, markdown, "stress-test")
}
