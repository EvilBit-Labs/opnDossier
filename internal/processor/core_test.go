package processor

import (
	"context"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoreProcessor_Process(t *testing.T) {
	processor, err := NewCoreProcessor()
	require.NoError(t, err)

	ctx := context.Background()

	// Create a test configuration
	cfg := &common.CommonDevice{
		System: common.System{
			Hostname: "test-host",
			Domain:   "test.local",
			WebGUI:   common.WebGUI{Protocol: "http"}, // Insecure protocol for security finding
			Bogons:   common.Bogons{Interval: "monthly"},
		},
		Interfaces: []common.Interface{
			{
				Name:      "wan",
				Enabled:   true,
				IPAddress: "192.168.1.1",
				Subnet:    "24",
			},
			{
				Name:      "lan",
				Enabled:   true,
				IPAddress: "10.0.0.1",
				Subnet:    "24",
			},
		},
		FirewallRules: []common.FirewallRule{
			{
				Type:        "pass",
				Interfaces:  []string{"wan"},
				Source:      common.RuleEndpoint{Address: "any"},
				Description: "",
			},
		},
		SNMP: common.SNMPConfig{
			ROCommunity: "public", // This should trigger a security finding
		},
	}

	t.Run("Process with default options", func(t *testing.T) {
		report, err := processor.Process(ctx, cfg)
		require.NoError(t, err)
		assert.NotNil(t, report)
		assert.NotNil(t, report.NormalizedConfig)
		assert.NotNil(t, report.Statistics)
		assert.Equal(t, "test-host", report.ConfigInfo.Hostname)
		assert.Equal(t, "test.local", report.ConfigInfo.Domain)
	})

	t.Run("Process with security analysis enabled", func(t *testing.T) {
		report, err := processor.Process(ctx, cfg, WithSecurityAnalysis())
		require.NoError(t, err)
		assert.NotNil(t, report)

		// Should have security findings
		assert.True(t, len(report.Findings.Critical) > 0 || len(report.Findings.High) > 0)

		// Check for specific security findings
		hasHTTPFinding := false
		hasSNMPFinding := false

		allFindings := append([]Finding{}, report.Findings.Critical...)

		allFindings = append(allFindings, report.Findings.High...)
		for _, finding := range allFindings {
			if finding.Type == "security" {
				if finding.Component == "system.webgui.protocol" {
					hasHTTPFinding = true
				}

				if finding.Component == "snmpd.rocommunity" {
					hasSNMPFinding = true
				}
			}
		}

		assert.True(t, hasHTTPFinding, "Should have HTTP security finding")
		assert.True(t, hasSNMPFinding, "Should have SNMP security finding")
	})

	t.Run("Process with dead rule check enabled", func(t *testing.T) {
		report, err := processor.Process(ctx, cfg, WithDeadRuleCheck())
		require.NoError(t, err)
		assert.NotNil(t, report)

		// Should have findings about overly broad rules
		hasSecurityFinding := false

		for _, finding := range report.Findings.High {
			if finding.Type == "security" && finding.Title == "Overly Broad Pass Rule" {
				hasSecurityFinding = true
				break
			}
		}

		assert.True(t, hasSecurityFinding, "Should have overly broad rule finding")
	})

	t.Run("Process with all features enabled", func(t *testing.T) {
		report, err := processor.Process(ctx, cfg, WithAllFeatures())
		require.NoError(t, err)
		assert.NotNil(t, report)
		assert.True(t, report.ProcessorConfig.EnableStats)
		assert.True(t, report.ProcessorConfig.EnableDeadRuleCheck)
		assert.True(t, report.ProcessorConfig.EnableSecurityAnalysis)
		assert.True(t, report.ProcessorConfig.EnablePerformanceAnalysis)
		assert.True(t, report.ProcessorConfig.EnableComplianceCheck)
	})

	t.Run("Process with nil configuration", func(t *testing.T) {
		_, err := processor.Process(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "configuration cannot be nil")
	})
}

func TestCoreProcessor_Transform(t *testing.T) {
	processor, err := NewCoreProcessor()
	require.NoError(t, err)

	ctx := context.Background()

	// Create a simple test configuration and process it
	cfg := &common.CommonDevice{
		System: common.System{
			Hostname: "test-firewall",
			Domain:   "example.com",
		},
		Interfaces: []common.Interface{
			{Name: "wan", Enabled: true},
			{Name: "lan", Enabled: true},
		},
	}

	report, err := processor.Process(ctx, cfg)
	require.NoError(t, err)

	t.Run("Transform to JSON", func(t *testing.T) {
		result, err := processor.Transform(ctx, report, "json")
		require.NoError(t, err)
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "test-firewall")
		assert.Contains(t, result, "example.com")
	})

	t.Run("Transform to YAML", func(t *testing.T) {
		result, err := processor.Transform(ctx, report, "yaml")
		require.NoError(t, err)
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "test-firewall")
		assert.Contains(t, result, "example.com")
	})

	t.Run("Transform to Markdown", func(t *testing.T) {
		result, err := processor.Transform(ctx, report, "markdown")
		require.NoError(t, err)
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "test-firewall")
		assert.Contains(t, result, "example.com")
	})

	t.Run("Transform to unsupported format", func(t *testing.T) {
		_, err := processor.Transform(ctx, report, "xml")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported format")
	})
}

func TestCoreProcessor_Normalization(t *testing.T) {
	processor, err := NewCoreProcessor()
	require.NoError(t, err)

	t.Run("IP address canonicalization", func(t *testing.T) {
		cfg := &common.CommonDevice{
			System: common.System{
				Hostname: "test",
				Domain:   "example.com",
			},
			Interfaces: []common.Interface{
				{Name: "wan", IPAddress: "192.168.1.1", Subnet: "24"},
				{Name: "lan", IPAddress: "10.0.0.1", Subnet: "24"},
			},
			FirewallRules: []common.FirewallRule{
				{
					Source: common.RuleEndpoint{Address: "192.168.1.100"},
				},
			},
		}

		normalized := processor.normalize(cfg)

		// IP addresses should be in canonical form
		wan := findInterface(normalized.Interfaces, "wan")
		require.NotNil(t, wan, "wan interface should exist")
		assert.Equal(t, "192.168.1.1", wan.IPAddress)

		lan := findInterface(normalized.Interfaces, "lan")
		require.NotNil(t, lan, "lan interface should exist")
		assert.Equal(t, "10.0.0.1", lan.IPAddress)

		// Single IP should be converted to CIDR
		assert.Equal(t, "192.168.1.100/32", normalized.FirewallRules[0].Source.Address)
	})

	t.Run("Default values filling", func(t *testing.T) {
		cfg := &common.CommonDevice{
			System: common.System{
				Hostname: "test",
				Domain:   "example.com",
			},
			Interfaces: []common.Interface{
				{Name: "wan", Enabled: true},
				{Name: "lan", Enabled: true},
			},
		}

		normalized := processor.normalize(cfg)

		// Defaults should be filled
		assert.Equal(t, "normal", normalized.System.Optimization)
		assert.Equal(t, "https", normalized.System.WebGUI.Protocol)
		assert.Equal(t, "UTC", normalized.System.Timezone)
		assert.Equal(t, "monthly", normalized.System.Bogons.Interval)
		assert.Equal(t, "automatic", normalized.NAT.OutboundMode)
		assert.Equal(t, "opnsense", normalized.Theme)
	})

	t.Run("Slice sorting", func(t *testing.T) {
		cfg := &common.CommonDevice{
			System: common.System{
				Hostname: "test",
				Domain:   "example.com",
			},
			Interfaces: []common.Interface{
				{Name: "wan", Enabled: true},
				{Name: "lan", Enabled: true},
			},
			Users: []common.User{
				{Name: "charlie"},
				{Name: "alice"},
				{Name: "bob"},
			},
			Groups: []common.Group{
				{Name: "zebra"},
				{Name: "alpha"},
				{Name: "beta"},
			},
			Sysctl: []common.SysctlItem{
				{Tunable: "net.inet.tcp.mssdflt"},
				{Tunable: "kern.ipc.maxsockbuf"},
				{Tunable: "net.inet.ip.forwarding"},
			},
		}

		normalized := processor.normalize(cfg)

		// Users should be sorted by name
		assert.Equal(t, "alice", normalized.Users[0].Name)
		assert.Equal(t, "bob", normalized.Users[1].Name)
		assert.Equal(t, "charlie", normalized.Users[2].Name)

		// Groups should be sorted by name
		assert.Equal(t, "alpha", normalized.Groups[0].Name)
		assert.Equal(t, "beta", normalized.Groups[1].Name)
		assert.Equal(t, "zebra", normalized.Groups[2].Name)

		// Sysctl items should be sorted by tunable name
		assert.Equal(t, "kern.ipc.maxsockbuf", normalized.Sysctl[0].Tunable)
		assert.Equal(t, "net.inet.ip.forwarding", normalized.Sysctl[1].Tunable)
		assert.Equal(t, "net.inet.tcp.mssdflt", normalized.Sysctl[2].Tunable)
	})
}

func TestCoreProcessor_Analysis(t *testing.T) {
	processor, err := NewCoreProcessor()
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("Dead rule detection", func(t *testing.T) {
		cfg := &common.CommonDevice{
			System: common.System{
				Hostname: "test",
				Domain:   "example.com",
			},
			Interfaces: []common.Interface{
				{Name: "wan", Enabled: true},
				{Name: "lan", Enabled: true},
			},
			FirewallRules: []common.FirewallRule{
				{
					Type:        "block",
					Interfaces:  []string{"wan"},
					Source:      common.RuleEndpoint{Address: "any"},
					Destination: common.RuleEndpoint{Address: "any"},
					Description: "Block all traffic",
				},
				{
					Type:        "pass",
					Interfaces:  []string{"wan"},
					Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
					Description: "Allow LAN traffic",
				},
			},
		}

		report, err := processor.Process(ctx, cfg, WithDeadRuleCheck())
		require.NoError(t, err)

		// Should detect unreachable rule after block-all
		hasDeadRuleFinding := false

		for _, finding := range report.Findings.Medium {
			if finding.Type == "dead-rule" {
				hasDeadRuleFinding = true
				break
			}
		}

		assert.True(t, hasDeadRuleFinding, "Should detect dead rule after block-all")
	})

	t.Run("Duplicate rule detection", func(t *testing.T) {
		cfg := &common.CommonDevice{
			System: common.System{
				Hostname: "test",
				Domain:   "example.com",
			},
			Interfaces: []common.Interface{
				{Name: "wan", Enabled: true},
				{Name: "lan", Enabled: true},
			},
			FirewallRules: []common.FirewallRule{
				{
					Type:        "pass",
					Interfaces:  []string{"lan"},
					IPProtocol:  "inet",
					Source:      common.RuleEndpoint{Address: "any"},
					Description: "Allow traffic",
				},
				{
					Type:        "pass",
					Interfaces:  []string{"lan"},
					IPProtocol:  "inet",
					Source:      common.RuleEndpoint{Address: "any"},
					Description: "Duplicate rule",
				},
			},
		}

		report, err := processor.Process(ctx, cfg, WithDeadRuleCheck())
		require.NoError(t, err)

		// Should detect duplicate rules
		hasDuplicateFinding := false

		for _, finding := range report.Findings.Low {
			if finding.Type == "duplicate-rule" {
				hasDuplicateFinding = true
				break
			}
		}

		assert.True(t, hasDuplicateFinding, "Should detect duplicate rules")
	})

	t.Run("User-group consistency check", func(t *testing.T) {
		cfg := &common.CommonDevice{
			System: common.System{
				Hostname: "test",
				Domain:   "example.com",
			},
			Interfaces: []common.Interface{
				{Name: "wan", Enabled: true},
				{Name: "lan", Enabled: true},
			},
			Users: []common.User{
				{
					Name:      "testuser",
					GroupName: "nonexistent",
					UID:       "1001",
					Scope:     "local",
				},
			},
			Groups: []common.Group{
				{
					Name:  "admins",
					GID:   "1000",
					Scope: "local",
				},
			},
		}

		report, err := processor.Process(ctx, cfg, WithComplianceCheck())
		require.NoError(t, err)

		// Should detect user referencing non-existent group
		hasConsistencyFinding := false

		for _, finding := range report.Findings.Medium {
			if finding.Type == "consistency" && finding.Title == "User References Non-existent Group" {
				hasConsistencyFinding = true
				break
			}
		}

		assert.True(t, hasConsistencyFinding, "Should detect user referencing non-existent group")
	})
}
