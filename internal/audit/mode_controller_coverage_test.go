package audit

import (
	"context"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/firewall"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/sans"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/stig"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestModeController_GenerateBlueReport_WithPlugins tests blue report generation with plugin execution.
func TestModeController_GenerateBlueReport_WithPlugins(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()
	logger := newTestLogger(t)
	controller := NewModeController(registry, logger)

	// Register a mock plugin that succeeds
	mockPlugin := &mockCompliancePlugin{
		name:        "test-plugin",
		description: "Test plugin for blue report",
		version:     "1.0.0",
	}

	err := registry.RegisterPlugin(mockPlugin)
	if err != nil {
		t.Fatalf("Failed to register mock plugin: %v", err)
	}

	testConfig := &common.CommonDevice{
		System: common.System{
			Hostname: "test-host",
			Domain:   "test.local",
		},
	}

	tests := []struct {
		name            string
		selectedPlugins []string
		expectError     bool
	}{
		{
			name:            "with valid plugins",
			selectedPlugins: []string{"test-plugin"},
			expectError:     false,
		},
		{
			name:            "with invalid plugins",
			selectedPlugins: []string{"nonexistent-plugin"},
			expectError:     true, // Should error for non-existent plugin
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := &ModeConfig{
				Mode:            ModeBlue,
				SelectedPlugins: tt.selectedPlugins,
				Comprehensive:   true,
			}

			report, err := controller.GenerateReport(context.Background(), testConfig, config)
			if (err != nil) != tt.expectError {
				t.Errorf("GenerateReport() error = %v, expectError %v", err, tt.expectError)
				return
			}

			if !tt.expectError {
				if report == nil {
					t.Error("GenerateReport() returned nil report")
					return
				}

				// Verify metadata contains blue team specific fields
				if reportType, exists := report.Metadata["report_type"]; !exists || reportType != "blue_team" {
					t.Error("GenerateReport() missing or incorrect report_type in metadata")
				}

				// Check compliance check status
				if status, exists := report.Metadata["compliance_check_status"]; !exists {
					t.Error("GenerateReport() missing compliance_check_status in metadata")
				} else if status != complianceCheckStatusCompleted {
					t.Errorf(
						"GenerateReport() compliance_check_status = %v, want %q for valid plugin",
						status, complianceCheckStatusCompleted,
					)
				}

				// Verify per-plugin compliance results are keyed by plugin name
				if _, exists := report.Compliance["plugin_results"]; exists {
					t.Error("GenerateReport() should not store compliance under 'plugin_results' key")
				}

				pluginResult, exists := report.Compliance["test-plugin"]
				if !exists {
					t.Error("GenerateReport() should store compliance under 'test-plugin' key")
				} else {
					assert.NotNil(t, pluginResult.Summary,
						"GenerateReport() per-plugin compliance result should have non-nil Summary")
					assert.NotNil(t, pluginResult.Findings,
						"GenerateReport() per-plugin compliance result should have non-nil Findings")
				}
			}
		})
	}
}

// TestReport_TotalFindingsCount tests the aggregate finding count across
// direct security findings and per-plugin compliance findings.
func TestReport_TotalFindingsCount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		report    *Report
		wantCount int
	}{
		{
			name: "empty report",
			report: &Report{
				Findings:   []Finding{},
				Compliance: map[string]ComplianceResult{},
			},
			wantCount: 0,
		},
		{
			name: "direct findings only",
			report: &Report{
				Findings: []Finding{
					{Finding: analysis.Finding{Title: "f1"}},
					{Finding: analysis.Finding{Title: "f2"}},
					{Finding: analysis.Finding{Title: "f3"}},
				},
				Compliance: map[string]ComplianceResult{},
			},
			wantCount: 3,
		},
		{
			name: "compliance findings only",
			report: &Report{
				Findings: []Finding{},
				Compliance: map[string]ComplianceResult{
					"stig": {
						Summary: &ComplianceSummary{TotalFindings: 5},
					},
					"firewall": {
						Summary: &ComplianceSummary{TotalFindings: 3},
					},
				},
			},
			wantCount: 8,
		},
		{
			name: "mixed direct and compliance findings",
			report: &Report{
				Findings: []Finding{
					{Finding: analysis.Finding{Title: "f1"}},
				},
				Compliance: map[string]ComplianceResult{
					"stig": {
						Summary: &ComplianceSummary{TotalFindings: 4},
					},
				},
			},
			wantCount: 5,
		},
		{
			name: "nil Summary in compliance entry does not panic",
			report: &Report{
				Findings: []Finding{
					{Finding: analysis.Finding{Title: "f1"}},
				},
				Compliance: map[string]ComplianceResult{
					"good": {
						Summary: &ComplianceSummary{TotalFindings: 2},
					},
					"nil_summary": {
						Summary: nil,
					},
				},
			},
			wantCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.wantCount, tt.report.TotalFindingsCount())
		})
	}
}

// TestCountSeverities tests the severity tallying function with mixed-case input.
func TestCountSeverities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		findings []compliance.Finding
		want     severityCounts
	}{
		{
			name:     "empty findings",
			findings: []compliance.Finding{},
			want:     severityCounts{},
		},
		{
			name: "lowercase severities",
			findings: []compliance.Finding{
				{Severity: "critical"},
				{Severity: "high"},
				{Severity: "medium"},
				{Severity: "low"},
			},
			want: severityCounts{critical: 1, high: 1, medium: 1, low: 1},
		},
		{
			name: "uppercase severities",
			findings: []compliance.Finding{
				{Severity: "CRITICAL"},
				{Severity: "HIGH"},
				{Severity: "MEDIUM"},
				{Severity: "LOW"},
			},
			want: severityCounts{critical: 1, high: 1, medium: 1, low: 1},
		},
		{
			name: "mixed case severities",
			findings: []compliance.Finding{
				{Severity: "Critical"},
				{Severity: "HIGH"},
				{Severity: "medium"},
				{Severity: "Low"},
			},
			want: severityCounts{critical: 1, high: 1, medium: 1, low: 1},
		},
		{
			name: "unknown severities are ignored",
			findings: []compliance.Finding{
				{Severity: "critical"},
				{Severity: "unknown"},
				{Severity: "info"},
				{Severity: ""},
				{Severity: "high"},
			},
			want: severityCounts{critical: 1, high: 1},
		},
		{
			name: "multiple same severity",
			findings: []compliance.Finding{
				{Severity: "critical"},
				{Severity: "CRITICAL"},
				{Severity: "Critical"},
			},
			want: severityCounts{critical: 3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := countSeverities(tt.findings)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestComputePerPluginSummary tests per-plugin summary calculation.
func TestComputePerPluginSummary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		pluginName    string
		findings      []compliance.Finding
		complianceMap map[string]bool
		wantTotal     int
		wantCritical  int
		wantHigh      int
		wantMedium    int
		wantLow       int
		wantCompliant int
		wantNonCompl  int
	}{
		{
			name:          "empty findings and compliance",
			pluginName:    "test",
			findings:      []compliance.Finding{},
			complianceMap: map[string]bool{},
			wantTotal:     0,
		},
		{
			name:       "single severity findings",
			pluginName: "stig",
			findings: []compliance.Finding{
				{Severity: "critical", Title: "f1"},
				{Severity: "critical", Title: "f2"},
			},
			complianceMap: map[string]bool{
				"CTRL-001": false,
				"CTRL-002": false,
			},
			wantTotal:     2,
			wantCritical:  2,
			wantCompliant: 0,
			wantNonCompl:  2,
		},
		{
			name:       "all four severity levels",
			pluginName: "firewall",
			findings: []compliance.Finding{
				{Severity: "critical", Title: "f1"},
				{Severity: "high", Title: "f2"},
				{Severity: "medium", Title: "f3"},
				{Severity: "low", Title: "f4"},
			},
			complianceMap: map[string]bool{
				"CTRL-001": false,
				"CTRL-002": false,
				"CTRL-003": true,
				"CTRL-004": true,
			},
			wantTotal:     4,
			wantCritical:  1,
			wantHigh:      1,
			wantMedium:    1,
			wantLow:       1,
			wantCompliant: 2,
			wantNonCompl:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			summary := computePerPluginSummary(tt.pluginName, tt.findings, tt.complianceMap)
			require.NotNil(t, summary)
			assert.Equal(t, tt.wantTotal, summary.TotalFindings)
			assert.Equal(t, tt.wantCritical, summary.CriticalFindings)
			assert.Equal(t, tt.wantHigh, summary.HighFindings)
			assert.Equal(t, tt.wantMedium, summary.MediumFindings)
			assert.Equal(t, tt.wantLow, summary.LowFindings)
			assert.Equal(t, 1, summary.PluginCount)

			pc, exists := summary.Compliance[tt.pluginName]
			require.True(t, exists, "summary should contain compliance entry for plugin")
			assert.Equal(t, tt.wantCompliant, pc.Compliant)
			assert.Equal(t, tt.wantNonCompl, pc.NonCompliant)
		})
	}
}

// TestValidateModeConfig_CaseInsensitiveDuplicate verifies that ["stig", "STIG"]
// is detected as a duplicate and that normalization produces lowercase names.
func TestValidateModeConfig_CaseInsensitiveDuplicate(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()
	logger := newTestLogger(t)
	controller := NewModeController(registry, logger)

	require.NoError(t, registry.RegisterPlugin(stig.NewPlugin()))
	require.NoError(t, registry.RegisterPlugin(sans.NewPlugin()))
	require.NoError(t, registry.RegisterPlugin(firewall.NewPlugin()))

	t.Run("case insensitive duplicate rejected", func(t *testing.T) {
		t.Parallel()

		config := &ModeConfig{
			Mode:            ModeBlue,
			SelectedPlugins: []string{"stig", "STIG"},
		}
		err := controller.ValidateModeConfig(config)
		assert.ErrorIs(t, err, ErrDuplicatePlugin)
	})

	t.Run("normalization produces lowercase", func(t *testing.T) {
		t.Parallel()

		config := &ModeConfig{
			Mode:            ModeBlue,
			SelectedPlugins: []string{"STIG", "SANS"},
		}
		err := controller.ValidateModeConfig(config)
		require.NoError(t, err)
		assert.Equal(t, "stig", config.SelectedPlugins[0])
		assert.Equal(t, "sans", config.SelectedPlugins[1])
	})

	t.Run("does not mutate original slice", func(t *testing.T) {
		t.Parallel()

		original := []string{"STIG", "SANS"}
		// Keep a copy to verify no mutation
		originalCopy := make([]string, len(original))
		copy(originalCopy, original)

		config := &ModeConfig{
			Mode:            ModeBlue,
			SelectedPlugins: original,
		}
		err := controller.ValidateModeConfig(config)
		require.NoError(t, err)

		// The original slice should not have been mutated
		assert.Equal(t, originalCopy, original, "original slice should not be mutated")
		// config.SelectedPlugins should be a new normalized slice
		assert.Equal(t, []string{"stig", "sans"}, config.SelectedPlugins)
	})
}
