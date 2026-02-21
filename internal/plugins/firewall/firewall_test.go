package firewall_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/firewall"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFirewallPlugin_RunChecks(t *testing.T) {
	firewallPlugin := firewall.NewPlugin()

	tests := []struct {
		name               string
		config             *common.CommonDevice
		expectedFindings   int
		expectedFindingIDs []string
		description        string
	}{
		{
			name: "Default configuration - all findings expected",
			config: &common.CommonDevice{
				System: common.System{
					Hostname: "OPNsense", // Default hostname
					Domain:   "localdomain",
					WebGUI: common.WebGUI{
						Protocol: "http", // Insecure HTTP
					},
					IPv6Allow: true, // IPv6 enabled
				},
			},
			expectedFindings: 2,
			expectedFindingIDs: []string{
				"FIREWALL-006", "FIREWALL-007",
			},
			description: "Default OPNsense config should trigger all firewall compliance checks",
		},
		{
			name: "Custom secure configuration - minimal findings",
			config: &common.CommonDevice{
				System: common.System{
					Hostname:   "secure-firewall",
					Domain:     "company.local",
					WebGUI:     common.WebGUI{Protocol: "https"},
					IPv6Allow:  false, // IPv6 disabled
					DNSServers: []string{"8.8.8.8"},
				},
			},
			expectedFindings: 2,
			expectedFindingIDs: []string{
				"FIREWALL-006", "FIREWALL-007",
			},
			description: "Secure config with custom hostname, HTTPS, DNS, and disabled IPv6",
		},
		{
			name: "Empty configuration - all findings expected",
			config: &common.CommonDevice{
				System: common.System{},
			},
			expectedFindings: 2,
			expectedFindingIDs: []string{
				"FIREWALL-006", "FIREWALL-007",
			},
			description: "Empty system config should trigger all checks",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run the checks
			findings := firewallPlugin.RunChecks(tt.config)

			// Verify the expected number of findings
			assert.Len(t, findings, tt.expectedFindings, "Expected %d findings, got %d: %v",
				tt.expectedFindings, len(findings), getFindings(findings))

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

func TestFirewallPlugin_Metadata(t *testing.T) {
	tests := []struct {
		name     string
		plugin   *firewall.Plugin
		expected string
	}{
		{
			name:     "Plugin name",
			plugin:   firewall.NewPlugin(),
			expected: "firewall",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.plugin.Name()
			assert.Equal(t, tt.expected, result)
		})
	}

	// Test version
	firewallPlugin := firewall.NewPlugin()
	assert.Equal(t, "1.0.0", firewallPlugin.Version())
	assert.NotEmpty(t, firewallPlugin.Description())
}

func TestFirewallPlugin_Controls(t *testing.T) {
	firewallPlugin := firewall.NewPlugin()

	tests := []struct {
		name             string
		controlID        string
		expectFound      bool
		expectedSeverity string
		expectedCategory string
	}{
		{
			name:             "SSH Warning Banner control",
			controlID:        "FIREWALL-001",
			expectFound:      true,
			expectedSeverity: "medium",
			expectedCategory: "SSH Security",
		},
		{
			name:             "HTTPS Web Management control",
			controlID:        "FIREWALL-008",
			expectFound:      true,
			expectedSeverity: "high",
			expectedCategory: "Management Access",
		},
		{
			name:        "Non-existent control",
			controlID:   "FIREWALL-999",
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			control, err := firewallPlugin.GetControlByID(tt.controlID)

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
	controls := firewallPlugin.GetControls()
	assert.Len(t, controls, 8, "Expected 8 firewall controls")

	// Verify all control IDs are unique
	controlIDs := make(map[string]bool)
	for _, control := range controls {
		assert.False(t, controlIDs[control.ID], "Duplicate control ID: %s", control.ID)
		controlIDs[control.ID] = true
	}
}

func TestFirewallPlugin_ValidateConfiguration(t *testing.T) {
	tests := []struct {
		name        string
		plugin      *firewall.Plugin
		expectError bool
	}{
		{
			name:        "Valid plugin configuration",
			plugin:      firewall.NewPlugin(),
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

// Helper function to extract finding IDs for debugging.
func getFindings(findings []compliance.Finding) []string {
	var ids []string
	for _, finding := range findings {
		ids = append(ids, finding.Reference)
	}
	return ids
}
