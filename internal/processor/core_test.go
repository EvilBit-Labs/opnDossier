package processor

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unclesp1d3r/opnFocus/internal/model"
)

func TestCoreProcessor_Process(t *testing.T) {
	processor := NewCoreProcessor()
	ctx := context.Background()

	// Create a test configuration
	cfg := &model.Opnsense{
		System: model.System{
			Hostname: "test-firewall",
			Domain:   "example.com",
			Webgui: model.Webgui{
				Protocol: "http", // This should trigger a security finding
			},
		},
		Interfaces: model.Interfaces{
			Wan: model.Interface{
				Enable: "1",
				IPAddr: "192.168.1.1",
				Subnet: "24",
			},
			Lan: model.Interface{
				Enable: "1",
				IPAddr: "10.0.0.1",
				Subnet: "24",
			},
		},
		Filter: model.Filter{
			Rule: []model.Rule{
				{
					Type:      "pass",
					Interface: "wan",
					Source:    model.Source{Network: "any"},
					Descr:     "",
				},
			},
		},
		Snmpd: model.Snmpd{
			ROCommunity: "public", // This should trigger a security finding
		},
	}

	t.Run("Process with default options", func(t *testing.T) {
		report, err := processor.Process(ctx, cfg)
		require.NoError(t, err)
		assert.NotNil(t, report)
		assert.NotNil(t, report.NormalizedConfig)
		assert.NotNil(t, report.Statistics)
		assert.Equal(t, "test-firewall", report.ConfigInfo.Hostname)
		assert.Equal(t, "example.com", report.ConfigInfo.Domain)
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
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "configuration cannot be nil")
	})
}

func TestCoreProcessor_Transform(t *testing.T) {
	processor := NewCoreProcessor()
	ctx := context.Background()

	// Create a simple test configuration and process it
	cfg := &model.Opnsense{
		System: model.System{
			Hostname: "test-firewall",
			Domain:   "example.com",
		},
		Interfaces: model.Interfaces{
			Wan: model.Interface{Enable: "1"},
			Lan: model.Interface{Enable: "1"},
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
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported format")
	})
}

func TestCoreProcessor_Normalization(t *testing.T) {
	processor := NewCoreProcessor()

	t.Run("IP address canonicalization", func(t *testing.T) {
		cfg := &model.Opnsense{
			System: model.System{
				Hostname: "test",
				Domain:   "example.com",
			},
			Interfaces: model.Interfaces{
				Wan: model.Interface{
					IPAddr: "192.168.1.1",
					Subnet: "24",
				},
				Lan: model.Interface{
					IPAddr: "10.0.0.1",
					Subnet: "24",
				},
			},
			Filter: model.Filter{
				Rule: []model.Rule{
					{
						Source: model.Source{Network: "192.168.1.100"},
					},
				},
			},
		}

		normalized := processor.normalize(cfg)

		// IP addresses should be in canonical form
		assert.Equal(t, "192.168.1.1", normalized.Interfaces.Wan.IPAddr)
		assert.Equal(t, "10.0.0.1", normalized.Interfaces.Lan.IPAddr)

		// Single IP should be converted to CIDR
		assert.Equal(t, "192.168.1.100/32", normalized.Filter.Rule[0].Source.Network)
	})

	t.Run("Default values filling", func(t *testing.T) {
		cfg := &model.Opnsense{
			System: model.System{
				Hostname: "test",
				Domain:   "example.com",
			},
			Interfaces: model.Interfaces{
				Wan: model.Interface{Enable: "1"},
				Lan: model.Interface{Enable: "1"},
			},
		}

		normalized := processor.normalize(cfg)

		// Defaults should be filled
		assert.Equal(t, "normal", normalized.System.Optimization)
		assert.Equal(t, "https", normalized.System.Webgui.Protocol)
		assert.Equal(t, "UTC", normalized.System.Timezone)
		assert.Equal(t, "monthly", normalized.System.Bogons.Interval)
		assert.Equal(t, "1500", normalized.Interfaces.Wan.MTU)
		assert.Equal(t, "1500", normalized.Interfaces.Lan.MTU)
		assert.Equal(t, "automatic", normalized.Nat.Outbound.Mode)
		assert.Equal(t, "opnsense", normalized.Theme)
	})

	t.Run("Slice sorting", func(t *testing.T) {
		cfg := &model.Opnsense{
			System: model.System{
				Hostname: "test",
				Domain:   "example.com",
				User: []model.User{
					{Name: "charlie"},
					{Name: "alice"},
					{Name: "bob"},
				},
				Group: []model.Group{
					{Name: "zebra"},
					{Name: "alpha"},
					{Name: "beta"},
				},
			},
			Interfaces: model.Interfaces{
				Wan: model.Interface{Enable: "1"},
				Lan: model.Interface{Enable: "1"},
			},
			Sysctl: []model.SysctlItem{
				{Tunable: "net.inet.tcp.mssdflt"},
				{Tunable: "kern.ipc.maxsockbuf"},
				{Tunable: "net.inet.ip.forwarding"},
			},
		}

		normalized := processor.normalize(cfg)

		// Users should be sorted by name
		assert.Equal(t, "alice", normalized.System.User[0].Name)
		assert.Equal(t, "bob", normalized.System.User[1].Name)
		assert.Equal(t, "charlie", normalized.System.User[2].Name)

		// Groups should be sorted by name
		assert.Equal(t, "alpha", normalized.System.Group[0].Name)
		assert.Equal(t, "beta", normalized.System.Group[1].Name)
		assert.Equal(t, "zebra", normalized.System.Group[2].Name)

		// Sysctl items should be sorted by tunable name
		assert.Equal(t, "kern.ipc.maxsockbuf", normalized.Sysctl[0].Tunable)
		assert.Equal(t, "net.inet.ip.forwarding", normalized.Sysctl[1].Tunable)
		assert.Equal(t, "net.inet.tcp.mssdflt", normalized.Sysctl[2].Tunable)
	})
}

func TestCoreProcessor_Analysis(t *testing.T) {
	processor := NewCoreProcessor()
	ctx := context.Background()

	t.Run("Dead rule detection", func(t *testing.T) {
		cfg := &model.Opnsense{
			System: model.System{
				Hostname: "test",
				Domain:   "example.com",
			},
			Interfaces: model.Interfaces{
				Wan: model.Interface{Enable: "1"},
				Lan: model.Interface{Enable: "1"},
			},
			Filter: model.Filter{
				Rule: []model.Rule{
					{
						Type:      "block",
						Interface: "wan",
						Source:    model.Source{Network: "any"},
						Descr:     "Block all traffic",
					},
					{
						Type:      "pass",
						Interface: "wan",
						Source:    model.Source{Network: "192.168.1.0/24"},
						Descr:     "Allow LAN traffic",
					},
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
		cfg := &model.Opnsense{
			System: model.System{
				Hostname: "test",
				Domain:   "example.com",
			},
			Interfaces: model.Interfaces{
				Wan: model.Interface{Enable: "1"},
				Lan: model.Interface{Enable: "1"},
			},
			Filter: model.Filter{
				Rule: []model.Rule{
					{
						Type:       "pass",
						Interface:  "lan",
						IPProtocol: "inet",
						Source:     model.Source{Network: "any"},
						Descr:      "Allow traffic",
					},
					{
						Type:       "pass",
						Interface:  "lan",
						IPProtocol: "inet",
						Source:     model.Source{Network: "any"},
						Descr:      "Duplicate rule",
					},
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
		cfg := &model.Opnsense{
			System: model.System{
				Hostname: "test",
				Domain:   "example.com",
				User: []model.User{
					{
						Name:      "testuser",
						Groupname: "nonexistent",
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
				Wan: model.Interface{Enable: "1"},
				Lan: model.Interface{Enable: "1"},
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
