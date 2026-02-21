package stig

import (
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPlugin(t *testing.T) {
	t.Parallel()

	p := NewPlugin()
	assert.NotNil(t, p)
	assert.NotEmpty(t, p.controls)
	assert.Len(t, p.controls, 4) // Should have 4 STIG controls
}

func TestPluginMetadata(t *testing.T) {
	t.Parallel()

	p := NewPlugin()

	assert.Equal(t, "stig", p.Name())
	assert.Equal(t, "1.0.0", p.Version())
	assert.Contains(t, p.Description(), "STIG")
	assert.Contains(t, p.Description(), "compliance checks")
}

func TestGetControls(t *testing.T) {
	t.Parallel()

	p := NewPlugin()
	controls := p.GetControls()

	assert.Len(t, controls, 4)

	// Verify all expected control IDs are present
	expectedIDs := []string{"V-206694", "V-206674", "V-206690", "V-206682"}
	for _, expectedID := range expectedIDs {
		found := false
		for _, control := range controls {
			if control.ID == expectedID {
				found = true
				break
			}
		}
		assert.True(t, found, "Control %s should be present", expectedID)
	}
}

func TestGetControlByID(t *testing.T) {
	t.Parallel()

	p := NewPlugin()

	tests := []struct {
		name        string
		controlID   string
		expectError bool
	}{
		{"valid control V-206694", "V-206694", false},
		{"valid control V-206674", "V-206674", false},
		{"valid control V-206690", "V-206690", false},
		{"valid control V-206682", "V-206682", false},
		{"invalid control", "V-999999", true},
		{"empty control ID", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			control, err := p.GetControlByID(tt.controlID)

			if tt.expectError {
				require.Error(t, err)
				assert.Equal(t, compliance.ErrControlNotFound, err)
				assert.Nil(t, control)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, control)
				assert.Equal(t, tt.controlID, control.ID)
				assert.NotEmpty(t, control.Title)
				assert.NotEmpty(t, control.Description)
				assert.NotEmpty(t, control.Severity)
			}
		})
	}
}

func TestValidateConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		plugin      *Plugin
		expectError bool
	}{
		{
			"valid plugin with controls",
			NewPlugin(),
			false,
		},
		{
			"plugin with no controls",
			&Plugin{controls: []compliance.Control{}},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.plugin.ValidateConfiguration()

			if tt.expectError {
				require.Error(t, err)
				assert.Equal(t, compliance.ErrNoControlsDefined, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRunChecks(t *testing.T) {
	t.Parallel()

	p := NewPlugin()

	// Test with empty config (should pass some checks, fail others)
	emptyConfig := &common.CommonDevice{}
	findings := p.RunChecks(emptyConfig)

	// With empty config:
	// - Default deny policy check should pass (conservative approach)
	// - Overly permissive rules should pass (no rules to be permissive)
	// - Unnecessary services should pass (no services configured)
	// - Comprehensive logging should fail (no logging configured)
	assert.Len(t, findings, 1) // Only logging should fail

	// Verify the finding is for logging
	assert.Equal(t, "Insufficient Firewall Logging", findings[0].Title)
	assert.Equal(t, "STIG V-206682", findings[0].Reference)
}

func TestRunChecksWithProblematicConfig(t *testing.T) {
	t.Parallel()

	p := NewPlugin()

	// Create a config with multiple issues
	problematicConfig := &common.CommonDevice{
		// Any/any allow rule (violates default deny and is overly permissive)
		FirewallRules: []common.FirewallRule{
			{
				Type:        "pass",
				Source:      common.RuleEndpoint{Address: constants.NetworkAny},
				Destination: common.RuleEndpoint{Address: constants.NetworkAny},
			},
		},
		// SNMP enabled (unnecessary service)
		SNMP: common.SNMPConfig{
			ROCommunity: "public",
		},
		// No logging configured
	}

	findings := p.RunChecks(problematicConfig)

	// Should have multiple findings:
	// 1. Missing default deny policy
	// 2. Overly permissive rules
	// 3. Unnecessary services
	// 4. Insufficient logging
	assert.Len(t, findings, 4)

	// Verify all findings are present
	findingTitles := make([]string, len(findings))
	for i, finding := range findings {
		findingTitles[i] = finding.Title
		assert.Equal(t, "compliance", finding.Type)
		assert.Contains(t, finding.Tags, "stig")
	}

	expectedTitles := []string{
		"Missing Default Deny Policy",
		"Overly Permissive Firewall Rules",
		"Unnecessary Network Services Enabled",
		"Insufficient Firewall Logging",
	}

	for _, expected := range expectedTitles {
		assert.Contains(t, findingTitles, expected)
	}
}

func TestHasDefaultDenyPolicyEdgeCases(t *testing.T) {
	t.Parallel()

	p := NewPlugin()

	tests := []struct {
		name     string
		config   *common.CommonDevice
		expected bool
	}{
		{
			"config with reject rules",
			&common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        "reject",
						Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
						Destination: common.RuleEndpoint{Address: "10.0.0.0/24"},
					},
				},
			},
			true,
		},
		{
			"config with mixed allow and deny rules",
			&common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        "pass",
						Source:      common.RuleEndpoint{Address: "192.168.1.10"},
						Destination: common.RuleEndpoint{Address: "10.0.0.10", Port: "22"},
					},
					{
						Type:        "block",
						Source:      common.RuleEndpoint{Address: constants.NetworkAny},
						Destination: common.RuleEndpoint{Address: constants.NetworkAny},
					},
				},
			},
			true,
		},
		{
			"config with any source, specific destination",
			&common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        "pass",
						Source:      common.RuleEndpoint{Address: constants.NetworkAny},
						Destination: common.RuleEndpoint{Address: "10.0.0.10", Port: "80"},
					},
				},
			},
			false, // No explicit deny rules, so hasExplicitDeny is false, result is false
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := p.hasDefaultDenyPolicy(tt.config)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHasOverlyPermissiveRulesProtocols(t *testing.T) {
	t.Parallel()

	p := NewPlugin()

	tests := []struct {
		name     string
		config   *common.CommonDevice
		expected bool
	}{
		{
			"tcp/udp protocol without port but narrow src/dst (not flagged)",
			&common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        "pass",
						Protocol:    "tcp/udp",
						Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
						Destination: common.RuleEndpoint{Address: "10.0.0.0/24", Port: ""},
					},
				},
			},
			false,
		},
		{
			"non-TCP/UDP protocol is not flagged for missing port",
			&common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        "pass",
						Protocol:    "gre",
						Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
						Destination: common.RuleEndpoint{Address: "10.0.0.0/24", Port: ""},
					},
				},
			},
			false,
		},
		{
			"block rule is not checked for permissiveness",
			&common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        "block",
						Source:      common.RuleEndpoint{Address: constants.NetworkAny},
						Destination: common.RuleEndpoint{Address: constants.NetworkAny},
					},
				},
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := p.hasOverlyPermissiveRules(tt.config)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHasUnnecessaryServicesEdgeCases(t *testing.T) {
	t.Parallel()

	p := NewPlugin()

	tests := []struct {
		name     string
		config   *common.CommonDevice
		expected bool
	}{
		{
			"SNMP without community string is not flagged",
			&common.CommonDevice{
				SNMP: common.SNMPConfig{
					ROCommunity: "",
				},
			},
			false,
		},
		{
			"Unbound enabled without DNSSEC stripping is not flagged",
			&common.CommonDevice{
				DNS: common.DNSConfig{
					Unbound: common.UnboundConfig{
						Enabled:        true,
						DNSSECStripped: false,
					},
				},
			},
			false,
		},
		{
			"Unbound disabled is not flagged",
			&common.CommonDevice{
				DNS: common.DNSConfig{
					Unbound: common.UnboundConfig{
						Enabled:        false,
						DNSSECStripped: true,
					},
				},
			},
			false,
		},
		{
			"DHCP with exactly MaxDHCPInterfaces is not flagged",
			&common.CommonDevice{
				DHCP: []common.DHCPScope{
					{
						Interface: "lan",
						Enabled:   true,
						Range:     common.DHCPRange{From: "192.168.1.100", To: "192.168.1.200"},
					},
					{Interface: "opt1", Enabled: true, Range: common.DHCPRange{From: "10.0.1.100", To: "10.0.1.200"}},
				},
			},
			false,
		},
		{
			"DHCP with disabled interfaces is still counted",
			&common.CommonDevice{
				DHCP: []common.DHCPScope{
					{
						Interface: "lan",
						Enabled:   true,
						Range:     common.DHCPRange{From: "192.168.1.100", To: "192.168.1.200"},
					},
					{Interface: "opt1", Enabled: false, Range: common.DHCPRange{From: "10.0.1.100", To: "10.0.1.200"}},
					{
						Interface: "opt2",
						Enabled:   false,
						Range:     common.DHCPRange{From: "172.16.1.100", To: "172.16.1.200"},
					},
				},
			},
			true, // len(DHCP) > MaxDHCPInterfaces regardless of Enabled status
		},
		{
			"Load balancer with empty monitor type is not flagged",
			&common.CommonDevice{
				LoadBalancer: common.LoadBalancerConfig{
					MonitorTypes: []common.MonitorType{},
				},
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := p.hasUnnecessaryServices(tt.config)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLoggingStatusConstants(t *testing.T) {
	t.Parallel()

	// Test that the constants are defined correctly
	assert.Equal(t, LoggingStatusNotConfigured, LoggingStatus(0))
	assert.Equal(t, LoggingStatusComprehensive, LoggingStatus(1))
	assert.Equal(t, LoggingStatusPartial, LoggingStatus(2))
	assert.Equal(t, LoggingStatusUnableToDetermine, LoggingStatus(3))
}

func TestAnalyzeLoggingConfigurationEdgeCases(t *testing.T) {
	t.Parallel()

	p := NewPlugin()

	tests := []struct {
		name     string
		config   *common.CommonDevice
		expected LoggingStatus
	}{
		{
			"syslog enabled with only system logging",
			&common.CommonDevice{
				Syslog: common.SyslogConfig{
					Enabled:       true,
					SystemLogging: true,
					AuthLogging:   false,
				},
			},
			LoggingStatusPartial,
		},
		{
			"syslog enabled with only auth logging",
			&common.CommonDevice{
				Syslog: common.SyslogConfig{
					Enabled:       true,
					SystemLogging: false,
					AuthLogging:   true,
				},
			},
			LoggingStatusPartial,
		},
		{
			"syslog disabled",
			&common.CommonDevice{
				Syslog: common.SyslogConfig{
					Enabled:       false,
					SystemLogging: true,
					AuthLogging:   true,
				},
			},
			LoggingStatusNotConfigured,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := p.analyzeLoggingConfiguration(tt.config)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBroadNetworkRangesConstants(t *testing.T) {
	t.Parallel()

	// Test the constants used in the plugin
	assert.Equal(t, "any", constants.NetworkAny)
	assert.Equal(t, 2, MaxDHCPInterfaces)
}

func TestControlsStructure(t *testing.T) {
	t.Parallel()

	p := NewPlugin()
	controls := p.GetControls()

	// Verify each control has required fields
	for _, control := range controls {
		assert.NotEmpty(t, control.ID, "Control ID should not be empty")
		assert.NotEmpty(t, control.Title, "Control title should not be empty")
		assert.NotEmpty(t, control.Description, "Control description should not be empty")
		assert.NotEmpty(t, control.Category, "Control category should not be empty")
		assert.NotEmpty(t, control.Severity, "Control severity should not be empty")
		assert.NotEmpty(t, control.Rationale, "Control rationale should not be empty")
		assert.NotEmpty(t, control.Remediation, "Control remediation should not be empty")
		assert.NotEmpty(t, control.Tags, "Control tags should not be empty")

		// Verify severity is a valid value
		validSeverities := []string{"critical", "high", "medium", "low"}
		assert.Contains(t, validSeverities, control.Severity,
			"Control %s has invalid severity: %s", control.ID, control.Severity)

		// Verify ID starts with V-
		assert.True(t, strings.HasPrefix(control.ID, "V-"),
			"Control ID should start with 'V-': %s", control.ID)
	}
}

func TestPluginInterface(t *testing.T) {
	t.Parallel()

	// Verify that Plugin implements compliance.Plugin interface
	var _ compliance.Plugin = (*Plugin)(nil)

	p := NewPlugin()

	// Test interface methods
	assert.Implements(t, (*compliance.Plugin)(nil), p)
}

func TestModelIntegration(t *testing.T) {
	t.Parallel()

	// Test integration with CommonDevice types
	device := &common.CommonDevice{}

	p := NewPlugin()

	// Should not panic with empty device
	assert.NotPanics(t, func() {
		_ = p.RunChecks(device)
	})
}

func TestComplexScenarios(t *testing.T) {
	t.Parallel()

	p := NewPlugin()

	// Test realistic configuration with some good and some bad settings
	mixedConfig := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			// Good rule - specific source/destination/port
			{
				Type:        "pass",
				Protocol:    "tcp",
				Source:      common.RuleEndpoint{Address: "192.168.1.10"},
				Destination: common.RuleEndpoint{Address: "10.0.0.10", Port: "22"},
			},
			// Bad rule - any to any
			{
				Type:        "pass",
				Source:      common.RuleEndpoint{Address: constants.NetworkAny},
				Destination: common.RuleEndpoint{Address: constants.NetworkAny},
			},
			// Good rule - explicit deny
			{
				Type:        "block",
				Source:      common.RuleEndpoint{Address: constants.NetworkAny},
				Destination: common.RuleEndpoint{Address: constants.NetworkAny},
			},
		},
		// Good logging configuration
		Syslog: common.SyslogConfig{
			Enabled:       true,
			SystemLogging: true,
			AuthLogging:   true,
		},
		// No unnecessary services
	}

	findings := p.RunChecks(mixedConfig)

	// Should detect multiple issues:
	// 1. Missing default deny (any-to-any rule overrides the explicit deny)
	// 2. Overly permissive rules (any-to-any rule)
	assert.Len(t, findings, 2)

	// Check that both expected findings are present
	findingTitles := make([]string, len(findings))
	for i, finding := range findings {
		findingTitles[i] = finding.Title
	}

	assert.Contains(t, findingTitles, "Missing Default Deny Policy")
	assert.Contains(t, findingTitles, "Overly Permissive Firewall Rules")
}
