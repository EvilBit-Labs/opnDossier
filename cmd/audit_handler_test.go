package cmd

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/audit"
	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestValidAuditModes(t *testing.T) {
	t.Parallel()

	completions, directive := ValidAuditModes(nil, nil, "")

	assert.Len(t, completions, 2)
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)

	// Check that all modes are present
	completionStr := strings.Join(completions, " ")
	assert.Contains(t, completionStr, "blue")
	assert.Contains(t, completionStr, "red")
}

func TestValidAuditPlugins(t *testing.T) {
	t.Parallel()

	completions, directive := ValidAuditPlugins(nil, nil, "")

	assert.Len(t, completions, 3)
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)

	// Check that all plugins are present
	completionStr := strings.Join(completions, " ")
	assert.Contains(t, completionStr, "stig")
	assert.Contains(t, completionStr, "sans")
	assert.Contains(t, completionStr, "firewall")
}

// TestPluginDescriptionsSyncWithRegistry verifies that every built-in plugin
// registered in the audit registry has a corresponding entry in the
// pluginDescriptions map used for shell completion descriptions.
func TestPluginDescriptionsSyncWithRegistry(t *testing.T) {
	t.Parallel()

	registryNames := registryPluginNames()
	for _, name := range registryNames {
		_, ok := pluginDescriptions[name]
		assert.True(t, ok,
			"pluginDescriptions missing entry for registered plugin %q", name)
	}
}

// TestMapAuditReportToComplianceResults verifies the mapping function
// correctly converts audit.Report data into common.ComplianceResults.
func TestMapAuditReportToComplianceResults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		report *audit.Report
		verify func(t *testing.T, result *common.ComplianceResults)
	}{
		{
			name: "empty report sets mode",
			report: &audit.Report{
				Mode:       audit.ModeBlue,
				Findings:   []audit.Finding{},
				Compliance: make(map[string]audit.ComplianceResult),
				Metadata:   make(map[string]any),
			},
			verify: func(t *testing.T, result *common.ComplianceResults) {
				t.Helper()
				assert.Equal(t, "blue", result.Mode)
				assert.Empty(t, result.Findings)
				assert.Empty(t, result.PluginResults)
				require.NotNil(t, result.Summary)
				assert.Equal(t, 0, result.Summary.TotalFindings)
			},
		},
		{
			name: "report with findings maps correctly",
			report: &audit.Report{
				Mode: audit.ModeRed,
				Findings: []audit.Finding{
					{Finding: compliance.Finding{
						Type:           "security",
						Severity:       "high",
						Title:          "Weak Rule",
						Description:    "Rule allows all",
						Recommendation: "Restrict",
						Component:      "firewall",
						References:     []string{"REF-001"},
					}},
				},
				Compliance: make(map[string]audit.ComplianceResult),
				Metadata:   make(map[string]any),
			},
			verify: func(t *testing.T, result *common.ComplianceResults) {
				t.Helper()
				assert.Equal(t, "red", result.Mode)
				require.Len(t, result.Findings, 1)

				f := result.Findings[0]
				assert.Equal(t, "security", f.Type)
				assert.Equal(t, "high", f.Severity)
				assert.Equal(t, "Weak Rule", f.Title)
				assert.Equal(t, "Rule allows all", f.Description)
				assert.Equal(t, "Restrict", f.Recommendation)
				assert.Equal(t, "firewall", f.Component)
				assert.Equal(t, []string{"REF-001"}, f.References)

				require.NotNil(t, result.Summary)
				assert.Equal(t, 1, result.Summary.TotalFindings)
			},
		},
		{
			name: "report with compliance results maps per-plugin data",
			report: &audit.Report{
				Mode:     audit.ModeBlue,
				Findings: []audit.Finding{},
				Compliance: map[string]audit.ComplianceResult{
					"stig": {
						Findings: []compliance.Finding{
							{
								Type:        "compliance",
								Severity:    "high",
								Title:       "STIG Violation",
								Description: "SSH timeout not configured",
							},
						},
						Summary: &audit.ComplianceSummary{
							TotalFindings: 1,
							HighFindings:  1,
							PluginCount:   1,
							Compliance:    map[string]audit.PluginCompliance{},
						},
						PluginInfo: map[string]audit.PluginInfo{
							"stig": {
								Name:        "stig",
								Version:     "1.0.0",
								Description: "STIG compliance checks",
								Controls: []compliance.Control{
									{
										ID:       "STIG-V-000001",
										Title:    "SSH Timeout",
										Severity: "high",
										Category: "access",
									},
								},
							},
						},
						Compliance: map[string]map[string]bool{
							"stig": {"STIG-V-000001": false},
						},
					},
				},
				Metadata: map[string]any{"scan_time": "2024-01-15"},
			},
			verify: func(t *testing.T, result *common.ComplianceResults) {
				t.Helper()

				// Metadata
				assert.Equal(t, "2024-01-15", result.Metadata["scan_time"])

				// Plugin results
				require.Contains(t, result.PluginResults, "stig")
				pr := result.PluginResults["stig"]

				// Plugin info
				assert.Equal(t, "stig", pr.PluginInfo.Name)
				assert.Equal(t, "1.0.0", pr.PluginInfo.Version)
				assert.Equal(t, "STIG compliance checks", pr.PluginInfo.Description)

				// Controls
				require.Len(t, pr.Controls, 1)
				assert.Equal(t, "STIG-V-000001", pr.Controls[0].ID)
				assert.Equal(t, "high", pr.Controls[0].Severity)
				assert.Equal(t, common.ControlStatusFail, pr.Controls[0].Status)

				// Findings
				require.Len(t, pr.Findings, 1)
				assert.Equal(t, "STIG Violation", pr.Findings[0].Title)

				// Summary
				require.NotNil(t, pr.Summary)
				assert.Equal(t, 1, pr.Summary.TotalFindings)
				assert.Equal(t, 1, pr.Summary.HighFindings)

				// Compliance map
				require.Contains(t, pr.Compliance, "STIG-V-000001")
				assert.False(t, pr.Compliance["STIG-V-000001"])

				// Aggregate summary
				require.NotNil(t, result.Summary)
				assert.Equal(t, 1, result.Summary.TotalFindings)
				assert.Equal(t, 1, result.Summary.HighFindings)
				assert.Equal(t, 1, result.Summary.PluginCount)
			},
		},
		{
			name: "aggregate summary across multiple plugins",
			report: &audit.Report{
				Mode:     audit.ModeBlue,
				Findings: []audit.Finding{},
				Compliance: map[string]audit.ComplianceResult{
					"stig": {
						Findings: []compliance.Finding{},
						Summary: &audit.ComplianceSummary{
							TotalFindings:    3,
							CriticalFindings: 1,
							HighFindings:     2,
						},
						PluginInfo: map[string]audit.PluginInfo{},
						Compliance: map[string]map[string]bool{},
					},
					"firewall": {
						Findings: []compliance.Finding{},
						Summary: &audit.ComplianceSummary{
							TotalFindings:  2,
							MediumFindings: 1,
							LowFindings:    1,
						},
						PluginInfo: map[string]audit.PluginInfo{},
						Compliance: map[string]map[string]bool{},
					},
				},
				Metadata: make(map[string]any),
			},
			verify: func(t *testing.T, result *common.ComplianceResults) {
				t.Helper()
				require.NotNil(t, result.Summary)
				assert.Equal(t, 5, result.Summary.TotalFindings)
				assert.Equal(t, 1, result.Summary.CriticalFindings)
				assert.Equal(t, 2, result.Summary.HighFindings)
				assert.Equal(t, 1, result.Summary.MediumFindings)
				assert.Equal(t, 1, result.Summary.LowFindings)
				assert.Equal(t, 2, result.Summary.PluginCount)
			},
		},
		{
			name:   "nil report returns nil",
			report: nil,
			verify: func(t *testing.T, _ *common.ComplianceResults) {
				t.Helper()
				// nil is handled by the test loop below
			},
		},
		{
			name: "direct finding severity counts included in aggregate summary",
			report: &audit.Report{
				Mode: audit.ModeBlue,
				Findings: []audit.Finding{
					{Finding: compliance.Finding{Severity: "high", Title: "F1"}},
					{Finding: compliance.Finding{Severity: "critical", Title: "F2"}},
					{Finding: compliance.Finding{Severity: "info", Title: "F3"}},
				},
				Compliance: map[string]audit.ComplianceResult{
					"stig": {
						Findings: []compliance.Finding{},
						Summary: &audit.ComplianceSummary{
							TotalFindings:  1,
							MediumFindings: 1,
						},
						PluginInfo: map[string]audit.PluginInfo{},
						Compliance: map[string]map[string]bool{},
					},
				},
				Metadata: make(map[string]any),
			},
			verify: func(t *testing.T, result *common.ComplianceResults) {
				t.Helper()
				require.NotNil(t, result.Summary)
				// 3 direct + 1 plugin = 4 total
				assert.Equal(t, 4, result.Summary.TotalFindings)
				assert.Equal(t, 1, result.Summary.CriticalFindings)
				assert.Equal(t, 1, result.Summary.HighFindings)
				assert.Equal(t, 1, result.Summary.MediumFindings)
				assert.Equal(t, 1, result.Summary.InfoFindings)
			},
		},
		{
			name: "missing PluginInfo key produces zero-valued info",
			report: &audit.Report{
				Mode:     audit.ModeBlue,
				Findings: []audit.Finding{},
				Compliance: map[string]audit.ComplianceResult{
					"firewall": {
						Findings:   []compliance.Finding{},
						Summary:    &audit.ComplianceSummary{TotalFindings: 0},
						PluginInfo: map[string]audit.PluginInfo{},
						Compliance: map[string]map[string]bool{},
					},
				},
				Metadata: make(map[string]any),
			},
			verify: func(t *testing.T, result *common.ComplianceResults) {
				t.Helper()
				require.Contains(t, result.PluginResults, "firewall")
				pr := result.PluginResults["firewall"]
				assert.Empty(t, pr.PluginInfo.Name)
				assert.Empty(t, pr.PluginInfo.Version)
				assert.Empty(t, pr.Controls)
			},
		},
		{
			name: "audit-specific fields mapped from audit.Finding",
			report: &audit.Report{
				Mode: audit.ModeRed,
				Findings: []audit.Finding{
					{
						Finding: compliance.Finding{
							Severity:  "high",
							Title:     "Open Port",
							Reference: "CIS-1.1",
							Tags:      []string{"network", "exposure"},
							Metadata:  map[string]string{"port": "22"},
						},
						AttackSurface: &audit.AttackSurface{
							Type:            "network",
							Ports:           []int{22, 443},
							Services:        []string{"ssh", "https"},
							Vulnerabilities: []string{"CVE-2024-0001"},
						},
						ExploitNotes: "SSH brute force possible",
						Control:      "STIG-V-000001",
					},
				},
				Compliance: make(map[string]audit.ComplianceResult),
				Metadata:   make(map[string]any),
			},
			verify: func(t *testing.T, result *common.ComplianceResults) {
				t.Helper()
				require.Len(t, result.Findings, 1)
				f := result.Findings[0]

				// analysis.Finding fields
				assert.Equal(t, "CIS-1.1", f.Reference)
				assert.Equal(t, []string{"network", "exposure"}, f.Tags)
				assert.Equal(t, map[string]string{"port": "22"}, f.Metadata)

				// audit.Finding fields
				require.NotNil(t, f.AttackSurface)
				assert.Equal(t, "network", f.AttackSurface.Type)
				assert.Equal(t, []int{22, 443}, f.AttackSurface.Ports)
				assert.Equal(t, []string{"ssh", "https"}, f.AttackSurface.Services)
				assert.Equal(t, []string{"CVE-2024-0001"}, f.AttackSurface.Vulnerabilities)
				assert.Equal(t, "SSH brute force possible", f.ExploitNotes)
				assert.Equal(t, "STIG-V-000001", f.Control)
			},
		},
		{
			name: "controls with tags and metadata are deep-copied",
			report: &audit.Report{
				Mode:     audit.ModeBlue,
				Findings: []audit.Finding{},
				Compliance: map[string]audit.ComplianceResult{
					"stig": {
						Findings: []compliance.Finding{},
						Summary:  &audit.ComplianceSummary{TotalFindings: 0},
						PluginInfo: map[string]audit.PluginInfo{
							"stig": {
								Name:    "stig",
								Version: "1.0.0",
								Controls: []compliance.Control{
									{
										ID:          "STIG-V-000002",
										Title:       "Audit Logging",
										Severity:    "medium",
										Rationale:   "Required for accountability",
										Remediation: "Enable audit logging",
										References:  []string{"NIST-AU-2"},
										Tags:        []string{"logging", "audit"},
										Metadata:    map[string]string{"source": "DISA"},
									},
								},
							},
						},
						Compliance: map[string]map[string]bool{},
					},
				},
				Metadata: make(map[string]any),
			},
			verify: func(t *testing.T, result *common.ComplianceResults) {
				t.Helper()
				require.Contains(t, result.PluginResults, "stig")
				pr := result.PluginResults["stig"]
				require.Len(t, pr.Controls, 1)
				c := pr.Controls[0]
				assert.Equal(t, "STIG-V-000002", c.ID)
				assert.Equal(
					t,
					common.ControlStatusUnknown,
					c.Status,
					"control absent from compliance map defaults to UNKNOWN",
				)
				assert.Equal(t, "Required for accountability", c.Rationale)
				assert.Equal(t, "Enable audit logging", c.Remediation)
				assert.Equal(t, []string{"NIST-AU-2"}, c.References)
				assert.Equal(t, []string{"logging", "audit"}, c.Tags)
				assert.Equal(t, map[string]string{"source": "DISA"}, c.Metadata)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := mapAuditReportToComplianceResults(tt.report)
			if tt.report == nil {
				assert.Nil(t, result, "nil report should return nil result")
				return
			}
			require.NotNil(t, result)
			tt.verify(t, result)
		})
	}
}

func TestMapControls_StatusPopulation(t *testing.T) {
	t.Parallel()

	controls := []compliance.Control{
		{ID: "CTRL-001", Title: "Passes", Severity: "low"},
		{ID: "CTRL-002", Title: "Fails", Severity: "high"},
		{ID: "CTRL-003", Title: "Also Passes", Severity: "medium"},
	}

	tests := []struct {
		name             string
		controls         []compliance.Control
		complianceStatus map[string]bool
		wantStatuses     []string
	}{
		{
			name:     "mixed pass and fail",
			controls: controls,
			complianceStatus: map[string]bool{
				"CTRL-001": true,
				"CTRL-002": false,
				"CTRL-003": true,
			},
			wantStatuses: []string{
				common.ControlStatusPass,
				common.ControlStatusFail,
				common.ControlStatusPass,
			},
		},
		{
			name:     "all pass",
			controls: controls,
			complianceStatus: map[string]bool{
				"CTRL-001": true,
				"CTRL-002": true,
				"CTRL-003": true,
			},
			wantStatuses: []string{
				common.ControlStatusPass,
				common.ControlStatusPass,
				common.ControlStatusPass,
			},
		},
		{
			name:     "all fail",
			controls: controls,
			complianceStatus: map[string]bool{
				"CTRL-001": false,
				"CTRL-002": false,
				"CTRL-003": false,
			},
			wantStatuses: []string{
				common.ControlStatusFail,
				common.ControlStatusFail,
				common.ControlStatusFail,
			},
		},
		{
			name:             "nil compliance map defaults to UNKNOWN",
			controls:         controls,
			complianceStatus: nil,
			wantStatuses: []string{
				common.ControlStatusUnknown,
				common.ControlStatusUnknown,
				common.ControlStatusUnknown,
			},
		},
		{
			name:     "missing entry defaults to UNKNOWN",
			controls: controls,
			complianceStatus: map[string]bool{
				"CTRL-001": true,
				// CTRL-002 intentionally absent
				"CTRL-003": true,
			},
			wantStatuses: []string{
				common.ControlStatusPass,
				common.ControlStatusUnknown,
				common.ControlStatusPass,
			},
		},
		{
			name:             "empty controls returns nil",
			controls:         nil,
			complianceStatus: map[string]bool{"CTRL-001": true},
			wantStatuses:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := mapControls(tt.controls, tt.complianceStatus)

			if tt.wantStatuses == nil {
				assert.Nil(t, result)
				return
			}

			require.Len(t, result, len(tt.wantStatuses))
			for i, want := range tt.wantStatuses {
				assert.Equal(t, want, result[i].Status,
					"control %s status mismatch", result[i].ID)
			}
		})
	}
}

func TestMapControls_PreservesAllFields(t *testing.T) {
	t.Parallel()

	controls := []compliance.Control{
		{
			ID:          "CTRL-001",
			Title:       "Test Control",
			Description: "A test control",
			Category:    "security",
			Severity:    "high",
			Rationale:   "Because security",
			Remediation: "Fix it",
			References:  []string{"REF-1", "REF-2"},
			Tags:        []string{"tag-a"},
			Metadata:    map[string]string{"key": "value"},
		},
	}

	result := mapControls(controls, map[string]bool{"CTRL-001": true})

	require.Len(t, result, 1)
	c := result[0]
	assert.Equal(t, "CTRL-001", c.ID)
	assert.Equal(t, common.ControlStatusPass, c.Status)
	assert.Equal(t, "Test Control", c.Title)
	assert.Equal(t, "A test control", c.Description)
	assert.Equal(t, "security", c.Category)
	assert.Equal(t, "high", c.Severity)
	assert.Equal(t, "Because security", c.Rationale)
	assert.Equal(t, "Fix it", c.Remediation)
	assert.Equal(t, []string{"REF-1", "REF-2"}, c.References)
	assert.Equal(t, []string{"tag-a"}, c.Tags)
	assert.Equal(t, map[string]string{"key": "value"}, c.Metadata)
}

func TestMapControls_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	controls := []compliance.Control{
		{ID: "CTRL-001", Title: "Pass Control", Severity: "low"},
		{ID: "CTRL-002", Title: "Fail Control", Severity: "high"},
	}
	complianceMap := map[string]bool{
		"CTRL-001": true,
		"CTRL-002": false,
	}

	result := mapControls(controls, complianceMap)

	data, err := json.Marshal(result)
	require.NoError(t, err)

	jsonStr := string(data)
	assert.Contains(t, jsonStr, `"status":"PASS"`)
	assert.Contains(t, jsonStr, `"status":"FAIL"`)

	// Round-trip: unmarshal back and verify
	var unmarshaled []common.ComplianceControl
	require.NoError(t, json.Unmarshal(data, &unmarshaled))
	require.Len(t, unmarshaled, 2)
	assert.Equal(t, common.ControlStatusPass, unmarshaled[0].Status)
	assert.Equal(t, common.ControlStatusFail, unmarshaled[1].Status)
}

// TestHandleAuditMode_EndToEnd exercises the full audit pipeline: plugin
// initialization, compliance checks, and report generation via the shared
// generator pipeline. It asserts that the rendered output contains
// the audit section from the builder layer.
func TestHandleAuditMode_EndToEnd(t *testing.T) {
	t.Parallel()

	logger, err := logging.New(logging.Config{Level: "warn"})
	require.NoError(t, err)

	// A minimal device triggers at least one STIG finding (missing logging).
	device := &common.CommonDevice{
		System: common.System{
			Hostname: "test-fw",
			Domain:   "example.com",
		},
	}

	auditOpts := audit.Options{
		AuditMode:       "blue",
		SelectedPlugins: []string{"stig"},
	}

	opt := converter.Options{
		Format: converter.FormatMarkdown,
	}

	result, err := handleAuditMode(context.Background(), device, auditOpts, opt, logger)
	require.NoError(t, err)

	// The rendered markdown must contain the compliance audit results and summary
	// (rendered by the builder layer, not the old appendAuditFindings).
	assert.Contains(t, result, "## Compliance Audit Results")
	assert.Contains(t, result, "## Compliance Audit Summary")
	assert.Contains(t, result, "stig")

	// handleAuditMode must NOT mutate the input device (immutability rule)
	assert.Nil(t, device.ComplianceChecks, "input device should not be mutated")
}

// TestHandleAuditMode_BlueModeNoPluginsRunsAll verifies that bare blue mode
// (no --plugins) produces populated compliance results rather than silently
// skipping compliance. This is a regression test for the documented default
// where `opnDossier audit config.xml --mode blue` runs all available plugins.
func TestHandleAuditMode_BlueModeNoPluginsRunsAll(t *testing.T) {
	// Do NOT use t.Parallel() — exercises audit pipeline with package-level flag state.
	logger, err := logging.New(logging.Config{Level: "warn"})
	require.NoError(t, err)

	device := &common.CommonDevice{
		System: common.System{
			Hostname: "test-fw",
			Domain:   "example.com",
		},
	}

	// Bare blue mode: empty SelectedPlugins
	auditOpts := audit.Options{
		AuditMode:       "blue",
		SelectedPlugins: nil,
	}

	opt := converter.Options{
		Format: converter.FormatJSON,
	}

	result, err := handleAuditMode(context.Background(), device, auditOpts, opt, logger)
	require.NoError(t, err)

	// Parse JSON and verify complianceChecks is populated with plugin results
	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(result), &parsed))

	checks, ok := parsed["complianceChecks"].(map[string]any)
	require.True(t, ok, "complianceChecks should be an object")
	assert.Equal(t, "blue", checks["mode"])

	// pluginResults must contain all three built-in plugins
	pluginResults, ok := checks["pluginResults"].(map[string]any)
	require.True(t, ok, "pluginResults should be an object")

	for _, name := range []string{"stig", "sans", "firewall"} {
		assert.Contains(t, pluginResults, name,
			"bare blue mode should include plugin %q in results", name)
	}

	// Input device must not be mutated (immutability rule)
	assert.Nil(t, device.ComplianceChecks, "input device should not be mutated")
}

// TestHandleAuditMode_StructuredFormats verifies that audit data appears in JSON and YAML output.
func TestHandleAuditMode_StructuredFormats(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		format    converter.Format
		unmarshal func([]byte, any) error
	}{
		{"JSON", converter.FormatJSON, json.Unmarshal},
		{"YAML", converter.FormatYAML, yaml.Unmarshal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger, err := logging.New(logging.Config{Level: "warn"})
			require.NoError(t, err)

			device := &common.CommonDevice{
				System: common.System{
					Hostname: "test-fw",
					Domain:   "example.com",
				},
			}

			auditOpts := audit.Options{
				AuditMode:       "blue",
				SelectedPlugins: []string{"stig"},
			}

			opt := converter.Options{
				Format: tt.format,
			}

			result, err := handleAuditMode(context.Background(), device, auditOpts, opt, logger)
			require.NoError(t, err)

			// Verify it's valid structured output
			var parsed map[string]any
			require.NoError(t, tt.unmarshal([]byte(result), &parsed))

			// Verify complianceChecks key is present
			assert.Contains(t, parsed, "complianceChecks")

			// Verify compliance data has content
			checks, ok := parsed["complianceChecks"].(map[string]any)
			require.True(t, ok, "complianceChecks should be an object")
			assert.Equal(t, "blue", checks["mode"])
		})
	}
}

// TestHandleAuditMode_UnknownPluginRejectedPostInit verifies that handleAuditMode
// rejects an unknown plugin name after plugin initialization, because the registry
// does not contain the requested plugin. This tests the post-init validation phase
// (ValidateModeConfig via GenerateReport). PreRunE acceptance is tested separately
// in TestAuditCmdPreRunEDynamicPluginAccepted.
func TestHandleAuditMode_UnknownPluginRejectedPostInit(t *testing.T) {
	t.Parallel()

	logger, err := logging.New(logging.Config{Level: "warn"})
	require.NoError(t, err)

	device := &common.CommonDevice{
		System: common.System{
			Hostname: "test-fw",
			Domain:   "example.com",
		},
	}

	pluginDir := t.TempDir()

	auditOpts := audit.Options{
		AuditMode:         "blue",
		SelectedPlugins:   []string{"myplugin"},
		PluginDir:         pluginDir,
		ExplicitPluginDir: true,
	}

	opt := converter.Options{
		Format: converter.FormatMarkdown,
	}

	_, err = handleAuditMode(context.Background(), device, auditOpts, opt, logger)
	require.Error(t, err)
	require.ErrorIs(t, err, audit.ErrPluginNotFound,
		"expected ErrPluginNotFound in error chain, got: %v", err)
	assert.Contains(t, err.Error(), "myplugin")
}

// TestHandleAuditMode_FailuresOnlyPipeline verifies that FailuresOnly propagates
// through the full pipeline: audit.Options → converter.Options → builder → filtered output.
// Passing controls should be excluded from the rendered markdown when FailuresOnly is true.
func TestHandleAuditMode_FailuresOnlyPipeline(t *testing.T) {
	// Do NOT use t.Parallel() — exercises audit pipeline with package-level state.
	logger, err := logging.New(logging.Config{Level: "warn"})
	require.NoError(t, err)

	device := &common.CommonDevice{
		System: common.System{
			Hostname: "test-fw",
			Domain:   "example.com",
		},
	}

	auditOpts := audit.Options{
		AuditMode:       "blue",
		SelectedPlugins: []string{"stig"},
		FailuresOnly:    true,
	}

	opt := converter.Options{
		Format: converter.FormatMarkdown,
	}

	result, err := handleAuditMode(context.Background(), device, auditOpts, opt, logger)
	require.NoError(t, err)

	// Output should contain FAIL but not PASS — failuresOnly filters passing controls
	assert.Contains(t, result, "FAIL", "expected FAIL controls in filtered output")
	assert.NotContains(t, result, "| PASS", "expected PASS controls to be filtered out")
}
