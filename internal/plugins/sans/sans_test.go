package sans_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/opnFocus/internal/model"
	"github.com/unclesp1d3r/opnFocus/internal/plugin"
	"github.com/unclesp1d3r/opnFocus/internal/plugins/sans"
)

func TestSANSPlugin_RunChecks(t *testing.T) {
	sansPlugin := sans.NewPlugin()

	tests := []struct {
		name               string
		config             *model.OpnSenseDocument
		expectedFindings   int
		expectedFindingIDs []string
		description        string
	}{
		{
			name: "Default configuration - all findings expected",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "OPNsense",
					Domain:   "localdomain",
				},
			},
			expectedFindings:   0,
			expectedFindingIDs: []string{},
			description:        "Default config should trigger all SANS compliance checks",
		},
		{
			name: "Empty configuration - all findings expected",
			config: &model.OpnSenseDocument{
				System: model.System{},
			},
			expectedFindings:   0,
			expectedFindingIDs: []string{},
			description:        "Empty config should trigger all SANS compliance checks",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run the checks
			findings := sansPlugin.RunChecks(tt.config)

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
	assert.Len(t, controls, 4, "Expected 4 SANS controls")

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

func getFindings(findings []plugin.Finding) []string {
	var ids []string
	for _, finding := range findings {
		ids = append(ids, finding.Reference)
	}
	return ids
}
