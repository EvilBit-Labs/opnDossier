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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unclesp1d3r/opnFocus/internal/model"
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
	assert.Error(t, err)
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
			Webgui: model.Webgui{
				Protocol: "https",
			},
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
			Webgui: model.Webgui{
				Protocol: "http", // Insecure protocol
			},
			SSH: model.SSH{
				Group: "admins", // SSH enabled
			},
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
	assert.True(t, len(report.Findings.High) > 0, "Should have high severity findings")

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
	assert.Error(t, err)
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
	processor := NewCoreProcessor()

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
							Interface: "wan",
							Source:    model.Source{Network: "192.168.1.100"},
							Descr:     "Allow specific host",
						},
						{
							Type:      "block",
							Interface: "lan",
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
					assert.True(t, normalized1.System.User[i-1].Name <= normalized1.System.User[i].Name,
						"Users should remain sorted after multiple normalizations")
				}
			}

			if len(normalized1.System.Group) > 0 {
				// Groups should remain sorted
				for i := 1; i < len(normalized1.System.Group); i++ {
					assert.True(t, normalized1.System.Group[i-1].Name <= normalized1.System.Group[i].Name,
						"Groups should remain sorted after multiple normalizations")
				}
			}

			if len(normalized1.Sysctl) > 0 {
				// Sysctl items should remain sorted
				for i := 1; i < len(normalized1.Sysctl); i++ {
					assert.True(t, normalized1.Sysctl[i-1].Tunable <= normalized1.Sysctl[i].Tunable,
						"Sysctl items should remain sorted after multiple normalizations")
				}
			}

			// Check that defaults are consistently filled
			assert.Equal(t, "normal", normalized1.System.Optimization)
			assert.Equal(t, "https", normalized1.System.Webgui.Protocol)
			assert.Equal(t, "UTC", normalized1.System.Timezone)
			assert.Equal(t, "monthly", normalized1.System.Bogons.Interval)
			assert.Equal(t, "opnsense", normalized1.Theme)
		})
	}
}

// TestCoreProcessor_AnalysisFindings tests various analysis findings with table-driven tests.
func TestCoreProcessor_AnalysisFindings(t *testing.T) {
	processor := NewCoreProcessor()
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
					Webgui: model.Webgui{
						Protocol: "http", // Insecure
					},
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
							Interface: "wan",
							Source:    model.Source{Network: "any"},
							Descr:     "Block all",
						},
						{
							Type:      "pass",
							Interface: "wan",
							Source:    model.Source{Network: "192.168.1.0/24"},
							Descr:     "Allow LAN (unreachable)",
						},
						{
							Type:       "pass",
							Interface:  "lan",
							IPProtocol: "inet",
							Source:     model.Source{Network: "10.0.0.0/8"},
							Descr:      "Allow private",
						},
						{
							Type:       "pass",
							Interface:  "lan",
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
					DisableChecksumOffloading:     "1",
					DisableSegmentationOffloading: "1",
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
					Hostname: "combined-firewall",
					Domain:   "example.com",
					Webgui: model.Webgui{
						Protocol: "http",
					},
					DisableChecksumOffloading: "1",
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
							Interface: "wan",
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
	for i := 0; i < count; i++ {
		rules[i] = model.Rule{
			Type:      "pass",
			Interface: "lan",
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
			Webgui: model.Webgui{
				Protocol: "https",
			},
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
				{Type: "pass", Interface: "lan", Descr: "Allow LAN"},
				{Type: "block", Interface: "wan", Descr: "Block WAN"},
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
	for i := 0; i < 100; i++ {
		users[i] = model.User{
			Name:  fmt.Sprintf("user%d", i),
			UID:   strconv.Itoa(1000 + i),
			Scope: "local",
		}
	}

	// Create many groups
	groups := make([]model.Group, 50)
	for i := 0; i < 50; i++ {
		groups[i] = model.Group{
			Name:  fmt.Sprintf("group%d", i),
			Gid:   strconv.Itoa(2000 + i),
			Scope: "local",
		}
	}

	// Create many sysctl items
	sysctlItems := make([]model.SysctlItem, 200)
	for i := 0; i < 200; i++ {
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
			Webgui: model.Webgui{
				Protocol: "https",
			},
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
	processor := NewCoreProcessor()
	ctx := context.Background()
	smallConfig := generateSmallConfig()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
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
	processor := NewCoreProcessor()
	ctx := context.Background()
	largeConfig := generateLargeConfig()

	// Record baseline memory stats
	var memBefore, memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
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
	processor := NewCoreProcessor()
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
	processor := NewCoreProcessor()
	largeConfig := generateLargeConfig()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
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
	processor := NewCoreProcessor()
	ctx := context.Background()
	smallConfig := generateSmallConfig()
	largeConfig := generateLargeConfig()

	// Test concurrent processing of the same config
	t.Run("Concurrent Same Config", func(t *testing.T) {
		var wg sync.WaitGroup
		errorChan := make(chan error, 10)

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				report, err := processor.Process(ctx, smallConfig, WithAllFeatures())
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

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				var config *model.OpnSenseDocument
				var expectedHostname string
				if id%2 == 0 {
					config = smallConfig
					expectedHostname = "small-config"
				} else {
					config = largeConfig
					expectedHostname = "large-config"
				}

				report, err := processor.Process(ctx, config, WithAllFeatures())
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

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				localProcessor := NewCoreProcessor()
				if localProcessor == nil {
					errorChan <- NewTestError(id, "processor is nil")
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
	processor := NewCoreProcessor()
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
					Webgui: model.Webgui{
						Protocol: "https",
					},
					SSH: model.SSH{
						Group: "admins",
					},
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
						{Type: "pass", Interface: "lan", Descr: "Allow LAN to WAN"},
						{Type: "block", Interface: "wan", Descr: "Block external access"},
						{Type: "pass", Interface: "wan", Descr: "Allow specific service"},
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
				expectedServices := []string{"DHCP Server (LAN)", "Unbound DNS Resolver", "SNMP Daemon", "SSH Daemon", "NTP Daemon"}
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
				assert.Equal(t, []string{"HTTPS Web GUI"}, stats.SecurityFeatures, "Should detect HTTPS Web GUI from normalization default")
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
