package sans_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/sans"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSANSPlugin_RunChecks(t *testing.T) {
	sansPlugin := sans.NewPlugin()

	tests := []struct {
		name               string
		config             *common.CommonDevice
		expectedFindingIDs []string
		description        string
	}{
		{
			name: "Default configuration - minimal device triggers multiple findings",
			config: &common.CommonDevice{
				System: common.System{
					Hostname: "OPNsense",
					Domain:   "localdomain",
				},
			},
			expectedFindingIDs: []string{
				"SANS-FW-003", // zone separation (0 enabled interfaces)
				"SANS-FW-004", // logging not enabled
				"SANS-FW-006", // no proxy packages
				"SANS-FW-008", // no firmware version
				"SANS-FW-009", // no DMZ interface
				"SANS-FW-015", // SSH not enabled
				"SANS-FW-019", // NAT not configured
				"SANS-FW-022", // no WAN-to-LAN deny rules
				"SANS-FW-025", // no HA config
			},
			description: "Default config with no interfaces/rules triggers expected findings",
		},
		{
			name: "Compliant configuration - no findings expected",
			config: &common.CommonDevice{
				System: common.System{
					Hostname: "fw01",
					SSH:      common.SSH{Enabled: true},
					Firmware: common.Firmware{Version: "24.7"},
				},
				Interfaces: []common.Interface{
					{Name: "wan", Enabled: true, BlockPrivate: true, BlockBogons: true},
					{Name: "lan", Enabled: true},
					{Name: "opt1", Enabled: true},
				},
				FirewallRules: []common.FirewallRule{
					{
						Type: common.RuleTypeBlock, Interfaces: []string{"wan"},
						Description: "Block RFC1918 on WAN",
					},
					{
						Type: common.RuleTypePass, Interfaces: []string{"lan"},
						Protocol: "tcp", StateType: "keep state",
						Description: "Allow LAN outbound",
						Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
						Destination: common.RuleEndpoint{Address: "any"},
						Direction:   common.DirectionOut,
					},
				},
				Syslog: common.SyslogConfig{
					Enabled:       true,
					FilterLogging: true,
				},
				Sysctl: []common.SysctlItem{
					{Tunable: "net.inet.ip.sourceroute", Value: "0"},
					{Tunable: "net.inet.ip.accept_sourceroute", Value: "0"},
				},
				NAT: common.NATConfig{
					OutboundMode: common.OutboundAutomatic,
				},
				Packages: []common.Package{
					{Name: "os-haproxy", Installed: true},
				},
				HighAvailability: common.HighAvailability{
					PfsyncPeerIP: "10.0.0.2",
				},
			},
			expectedFindingIDs: []string{},
			description:        "Fully compliant config should produce no findings",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run the checks
			findings, _, err := sansPlugin.RunChecks(tt.config)
			require.NoError(t, err)

			// Verify the expected number of findings
			assert.Len(t, findings, len(tt.expectedFindingIDs), "Expected %d findings, got %d: %v",
				len(tt.expectedFindingIDs), len(findings), getFindings(findings))

			// Verify each expected finding is present
			for _, expectedID := range tt.expectedFindingIDs {
				found := false
				for _, finding := range findings {
					if finding.Reference == expectedID {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected finding ID %s not found in results", expectedID)
			}

			// Verify each finding has required fields
			for _, finding := range findings {
				assert.NotEmpty(t, finding.Type, "Finding should have a type")
				assert.NotEmpty(t, finding.Title, "Finding should have a title")
				assert.NotEmpty(t, finding.Description, "Finding should have a description")
				assert.NotEmpty(t, finding.Recommendation, "Finding should have a recommendation")
				assert.NotEmpty(t, finding.Component, "Finding should have a component")
				assert.NotEmpty(t, finding.Reference, "Finding should have a reference")
				assert.NotEmpty(t, finding.References, "Finding should have references")
				assert.NotEmpty(t, finding.Tags, "Finding should have tags")
			}
		})
	}
}

func TestSANSPlugin_Metadata(t *testing.T) {
	tests := []struct {
		name     string
		plugin   *sans.Plugin
		expected string
	}{
		{
			name:     "Plugin name",
			plugin:   sans.NewPlugin(),
			expected: "sans",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.plugin.Name()
			assert.Equal(t, tt.expected, result)
		})
	}

	// Test version
	sansPlugin := sans.NewPlugin()
	assert.Equal(t, "1.0.0", sansPlugin.Version())
	assert.NotEmpty(t, sansPlugin.Description())
}

func TestSANSPlugin_Controls(t *testing.T) {
	sansPlugin := sans.NewPlugin()

	tests := []struct {
		name             string
		controlID        string
		expectFound      bool
		expectedSeverity string
		expectedCategory string
	}{
		{
			name:             "Default Deny Policy control",
			controlID:        "SANS-FW-001",
			expectFound:      true,
			expectedSeverity: "high",
			expectedCategory: "Access Control",
		},
		{
			name:             "Comprehensive Logging control",
			controlID:        "SANS-FW-004",
			expectFound:      true,
			expectedSeverity: "medium",
			expectedCategory: "Logging and Monitoring",
		},
		{
			name:        "Non-existent control",
			controlID:   "SANS-FW-999",
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			control, err := sansPlugin.GetControlByID(tt.controlID)

			if tt.expectFound {
				require.NoError(t, err)
				require.NotNil(t, control)
				assert.Equal(t, tt.controlID, control.ID)
				assert.Equal(t, tt.expectedSeverity, control.Severity)
				assert.Equal(t, tt.expectedCategory, control.Category)
				assert.NotEmpty(t, control.Title)
				assert.NotEmpty(t, control.Description)
				assert.NotEmpty(t, control.Rationale)
				assert.NotEmpty(t, control.Remediation)
				assert.NotEmpty(t, control.Tags)
			} else {
				require.Error(t, err)
				assert.Nil(t, control)
			}
		})
	}

	// Test GetControls returns all controls
	controls := sansPlugin.GetControls()
	assert.Len(t, controls, 25, "Expected 25 SANS controls")

	// Verify all control IDs are unique
	controlIDs := make(map[string]bool)
	for _, control := range controls {
		assert.False(t, controlIDs[control.ID], "Duplicate control ID: %s", control.ID)
		controlIDs[control.ID] = true
	}
}

func TestSANSPlugin_ValidateConfiguration(t *testing.T) {
	tests := []struct {
		name        string
		plugin      *sans.Plugin
		expectError bool
	}{
		{
			name:        "Valid plugin configuration",
			plugin:      sans.NewPlugin(),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.plugin.ValidateConfiguration()
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSANSPlugin_FindingSeverityMatchesControl(t *testing.T) {
	t.Parallel()

	sansPlugin := sans.NewPlugin()

	// The SANS helpers are currently placeholders that return compliant for all
	// checks, so no findings are emitted with a default device. This test
	// validates the structural invariant: for any device configuration, every
	// emitted finding's severity must match the severity of its referenced
	// control. When the helpers gain real logic and start emitting findings,
	// this test will automatically cover them.
	configs := []*common.CommonDevice{
		{},
		{System: common.System{Hostname: "test"}},
	}

	for _, device := range configs {
		findings, _, err := sansPlugin.RunChecks(device)
		require.NoError(t, err)
		for _, finding := range findings {
			control, err := sansPlugin.GetControlByID(finding.Reference)
			require.NoError(t, err, "finding references unknown control %s", finding.Reference)
			assert.Equal(t, control.Severity, finding.Severity,
				"finding %s severity %q does not match control severity %q",
				finding.Reference, finding.Severity, control.Severity)
		}
	}

	// Verify all controls have non-empty severity (prerequisite for the invariant).
	for _, control := range sansPlugin.GetControls() {
		assert.NotEmpty(t, control.Severity, "control %s has empty severity", control.ID)
	}
}

func getFindings(findings []compliance.Finding) []string {
	var ids []string
	for _, finding := range findings {
		ids = append(ids, finding.Reference)
	}
	return ids
}
