package cmd

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/audit"
	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestValidateAuditModeValid(t *testing.T) {
	originalAuditMode := sharedAuditMode
	originalPlugins := sharedSelectedPlugins
	t.Cleanup(func() {
		sharedAuditMode = originalAuditMode
		sharedSelectedPlugins = originalPlugins
	})

	tests := []struct {
		name      string
		auditMode string
	}{
		{"standard mode", "standard"},
		{"blue mode", "blue"},
		{"red mode", "red"},
		{"uppercase standard", "STANDARD"},
		{"uppercase blue", "BLUE"},
		{"uppercase red", "RED"},
		{"mixed case", "Blue"},
		{"empty mode (disabled)", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sharedAuditMode = tt.auditMode
			sharedSelectedPlugins = nil
			sharedWrapWidth = -1
			sharedNoWrap = false

			// Set up minimal flags
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			flags.Bool("no-wrap", false, "")
			flags.Int("wrap", -1, "")

			err := validateConvertFlags(flags, nil)
			require.NoError(t, err, "audit mode %q should be valid", tt.auditMode)
		})
	}
}

func TestValidateAuditModeInvalid(t *testing.T) {
	originalAuditMode := sharedAuditMode
	originalPlugins := sharedSelectedPlugins
	originalFormat := format
	t.Cleanup(func() {
		sharedAuditMode = originalAuditMode
		sharedSelectedPlugins = originalPlugins
		format = originalFormat
	})

	tests := []struct {
		name          string
		auditMode     string
		wantErrSubstr string
	}{
		{"invalid mode", "invalid", "invalid audit mode"},
		{"typo mode", "stanard", "invalid audit mode"},
		{"numeric mode", "123", "invalid audit mode"},
		{"partial mode", "blu", "invalid audit mode"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sharedAuditMode = tt.auditMode
			sharedSelectedPlugins = nil
			sharedWrapWidth = -1
			sharedNoWrap = false
			format = string(converter.FormatMarkdown) // Set valid format to avoid format error

			// Set up minimal flags
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			flags.Bool("no-wrap", false, "")
			flags.Int("wrap", -1, "")

			err := validateConvertFlags(flags, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrSubstr)
		})
	}
}

func TestValidateAuditPluginsValid(t *testing.T) {
	originalAuditMode := sharedAuditMode
	originalPlugins := sharedSelectedPlugins
	originalFormat := format
	t.Cleanup(func() {
		sharedAuditMode = originalAuditMode
		sharedSelectedPlugins = originalPlugins
		format = originalFormat
	})

	tests := []struct {
		name    string
		plugins []string
	}{
		{"single stig", []string{"stig"}},
		{"single sans", []string{"sans"}},
		{"single firewall", []string{"firewall"}},
		{"all plugins", []string{"stig", "sans", "firewall"}},
		{"two plugins", []string{"stig", "sans"}},
		{"empty plugins", []string{}},
		{"uppercase plugin", []string{"STIG"}},
		{"mixed case", []string{"Stig", "SANS"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sharedAuditMode = ""
			sharedSelectedPlugins = tt.plugins
			sharedWrapWidth = -1
			sharedNoWrap = false
			format = string(converter.FormatMarkdown)

			// Set up minimal flags
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			flags.Bool("no-wrap", false, "")
			flags.Int("wrap", -1, "")

			err := validateConvertFlags(flags, nil)
			require.NoError(t, err, "plugins %v should be valid", tt.plugins)
		})
	}
}

func TestValidateAuditPluginsInvalid(t *testing.T) {
	originalAuditMode := sharedAuditMode
	originalPlugins := sharedSelectedPlugins
	originalFormat := format
	t.Cleanup(func() {
		sharedAuditMode = originalAuditMode
		sharedSelectedPlugins = originalPlugins
		format = originalFormat
	})

	tests := []struct {
		name          string
		plugins       []string
		wantErrSubstr string
	}{
		{"invalid plugin", []string{"invalid"}, "invalid audit plugin"},
		{"typo plugin", []string{"stigg"}, "invalid audit plugin"},
		{"valid and invalid mixed", []string{"stig", "invalid"}, "invalid audit plugin"},
		{"numeric plugin", []string{"123"}, "invalid audit plugin"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sharedAuditMode = ""
			sharedSelectedPlugins = tt.plugins
			sharedWrapWidth = -1
			sharedNoWrap = false
			format = string(converter.FormatMarkdown)

			// Set up minimal flags
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			flags.Bool("no-wrap", false, "")
			flags.Int("wrap", -1, "")

			err := validateConvertFlags(flags, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrSubstr)
		})
	}
}

func TestAddSharedAuditFlagsRegistersFlags(t *testing.T) {
	t.Parallel()

	// Create a fresh command for testing
	cmd := &cobra.Command{Use: "test"}
	addSharedAuditFlags(cmd)

	flags := cmd.Flags()

	// Verify audit-mode flag
	auditModeFlag := flags.Lookup("audit-mode")
	require.NotNil(t, auditModeFlag)
	assert.Empty(t, auditModeFlag.DefValue)

	// Verify audit-blackhat flag
	blackhatFlag := flags.Lookup("audit-blackhat")
	require.NotNil(t, blackhatFlag)
	assert.Equal(t, "false", blackhatFlag.DefValue)

	// Verify audit-plugins flag
	pluginsFlag := flags.Lookup("audit-plugins")
	require.NotNil(t, pluginsFlag)
	assert.Equal(t, "[]", pluginsFlag.DefValue)

	// Verify plugin-dir flag
	pluginDirFlag := flags.Lookup("plugin-dir")
	require.NotNil(t, pluginDirFlag)
	assert.Empty(t, pluginDirFlag.DefValue)
}

func TestValidAuditModes(t *testing.T) {
	t.Parallel()

	completions, directive := ValidAuditModes(nil, nil, "")

	assert.Len(t, completions, 3)
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)

	// Check that all modes are present
	completionStr := strings.Join(completions, " ")
	assert.Contains(t, completionStr, "standard")
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

// TestBuildAuditOptions tests that audit flags are properly set in audit options.
func TestBuildAuditOptions(t *testing.T) {
	originalAuditMode := sharedAuditMode
	originalBlackhat := sharedBlackhatMode
	originalPlugins := sharedSelectedPlugins
	originalPluginDir := sharedPluginDir
	t.Cleanup(func() {
		sharedAuditMode = originalAuditMode
		sharedBlackhatMode = originalBlackhat
		sharedSelectedPlugins = originalPlugins
		sharedPluginDir = originalPluginDir
	})

	tests := []struct {
		name            string
		auditMode       string
		blackhatMode    bool
		selectedPlugins []string
		pluginDir       string
		wantPluginDir   string
		wantExplicitDir bool
	}{
		{
			name:            "empty defaults",
			auditMode:       "",
			blackhatMode:    false,
			selectedPlugins: nil,
			pluginDir:       "",
			wantPluginDir:   "",
			wantExplicitDir: false,
		},
		{
			name:            "standard mode",
			auditMode:       "standard",
			blackhatMode:    false,
			selectedPlugins: nil,
			pluginDir:       "",
			wantPluginDir:   "",
			wantExplicitDir: false,
		},
		{
			name:            "blue mode with plugins",
			auditMode:       "blue",
			blackhatMode:    false,
			selectedPlugins: []string{"stig", "sans"},
			pluginDir:       "",
			wantPluginDir:   "",
			wantExplicitDir: false,
		},
		{
			name:            "red mode with blackhat",
			auditMode:       "red",
			blackhatMode:    true,
			selectedPlugins: nil,
			pluginDir:       "",
			wantPluginDir:   "",
			wantExplicitDir: false,
		},
		{
			name:            "with plugin dir",
			auditMode:       "blue",
			blackhatMode:    false,
			selectedPlugins: nil,
			pluginDir:       "/path/to/plugins",
			wantPluginDir:   "/path/to/plugins",
			wantExplicitDir: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sharedAuditMode = tt.auditMode
			sharedBlackhatMode = tt.blackhatMode
			sharedSelectedPlugins = tt.selectedPlugins
			sharedPluginDir = tt.pluginDir

			result := buildAuditOptions()

			assert.Equal(t, tt.auditMode, result.AuditMode)
			assert.Equal(t, tt.blackhatMode, result.BlackhatMode)
			assert.Equal(t, tt.selectedPlugins, result.SelectedPlugins)
			assert.Equal(t, tt.wantPluginDir, result.PluginDir)
			assert.Equal(t, tt.wantExplicitDir, result.ExplicitPluginDir)
		})
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
				Mode:     audit.ModeStandard,
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
				Mode:     audit.ModeStandard,
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

// TestHandleAuditMode_EndToEnd exercises the full audit pipeline: plugin
// initialization, compliance checks, and report generation via the standard
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

	// The rendered markdown must contain the compliance audit summary section
	// (rendered by the builder layer, not the old appendAuditFindings).
	assert.Contains(t, result, "## Compliance Audit Summary")
	assert.Contains(t, result, "Plugin Compliance Results")
	assert.Contains(t, result, "stig")

	// handleAuditMode must NOT mutate the input device (immutability rule)
	assert.Nil(t, device.ComplianceChecks, "input device should not be mutated")
}

// TestHandleAuditMode_BlueModeNoPluginsRunsAll verifies that bare blue mode
// (no --plugins) produces populated compliance results rather than silently
// skipping compliance. This is a regression test for the documented default
// where `opnDossier audit config.xml --mode blue` runs all available plugins.
func TestHandleAuditMode_BlueModeNoPluginsRunsAll(t *testing.T) {
	t.Parallel()

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

// TestEmitAuditResult_MultiFileAutoNaming verifies that multi-file audit runs
// derive unique per-input output paths instead of falling back to stdout or
// resolving to a shared config-driven output path.
func TestEmitAuditResult_MultiFileAutoNaming(t *testing.T) {
	// Do NOT use t.Parallel() — modifies package-level flag variables.
	originalOutputFile := outputFile
	originalFormat := format
	originalForce := force
	t.Cleanup(func() {
		outputFile = originalOutputFile
		format = originalFormat
		force = originalForce
	})

	outputFile = "" // No CLI --output
	format = "markdown"
	force = true

	// Two different input files with the same parent directory
	result1 := auditResult{inputFile: "/tmp/config1.xml"}
	result2 := auditResult{inputFile: "/tmp/config2.xml"}

	// Multi-file auto-naming derives unique per-input paths
	path1 := deriveAuditOutputPath(result1.inputFile, ".md")
	path2 := deriveAuditOutputPath(result2.inputFile, ".md")

	assert.Equal(t, "tmp-config1-audit.md", path1)
	assert.Equal(t, "tmp-config2-audit.md", path2)
	assert.NotEqual(t, path1, path2, "multi-file audit must produce distinct output paths")

	// Verify the derived paths pass through determineOutputPath correctly
	// (treated as explicit CLI outputFile, so config is ignored)
	resolvedPath1, err1 := determineOutputPath(result1.inputFile, path1, ".md", nil, force)
	resolvedPath2, err2 := determineOutputPath(result2.inputFile, path2, ".md", nil, force)
	require.NoError(t, err1)
	require.NoError(t, err2)

	assert.Equal(t, "tmp-config1-audit.md", resolvedPath1)
	assert.Equal(t, "tmp-config2-audit.md", resolvedPath2)
}

// TestEmitAuditResult_MultiFileConfigOutputFileIgnored verifies that when
// cmdConfig.OutputFile is set during a multi-file audit, the shared config
// destination is ignored in favor of per-input auto-named paths.
func TestEmitAuditResult_MultiFileConfigOutputFileIgnored(t *testing.T) {
	// Do NOT use t.Parallel() — modifies package-level flag variables.
	originalOutputFile := outputFile
	originalFormat := format
	originalForce := force
	t.Cleanup(func() {
		outputFile = originalOutputFile
		format = originalFormat
		force = originalForce
	})

	outputFile = "" // No CLI --output
	format = "markdown"
	force = true

	// Simulate multi-file run with config OutputFile set
	cfgWithOutput := &config.Config{OutputFile: "/tmp/shared-report.md"}

	// Without the fix, both inputs would resolve to the shared config path
	pathA, errA := determineOutputPath("/tmp/config1.xml", "", ".md", cfgWithOutput, true)
	pathB, errB := determineOutputPath("/tmp/config2.xml", "", ".md", cfgWithOutput, true)
	require.NoError(t, errA)
	require.NoError(t, errB)
	assert.Equal(t, pathA, pathB, "raw config OutputFile causes collision")

	// With the fix, deriveAuditOutputPath produces unique paths and nil config
	// is passed to determineOutputPath, preventing the config path from being used.
	derivedA := deriveAuditOutputPath("/tmp/config1.xml", ".md")
	derivedB := deriveAuditOutputPath("/tmp/config2.xml", ".md")

	resolvedA, errResolvedA := determineOutputPath("/tmp/config1.xml", derivedA, ".md", nil, true)
	resolvedB, errResolvedB := determineOutputPath("/tmp/config2.xml", derivedB, ".md", nil, true)
	require.NoError(t, errResolvedA)
	require.NoError(t, errResolvedB)

	assert.Equal(t, "tmp-config1-audit.md", resolvedA)
	assert.Equal(t, "tmp-config2-audit.md", resolvedB)
	assert.NotEqual(t, resolvedA, resolvedB, "multi-file audit must not resolve to same output path")
}

// TestDeriveAuditOutputPath verifies per-input filename derivation for multi-file audit.
func TestDeriveAuditOutputPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		inputFile string
		fileExt   string
		want      string
	}{
		{"markdown from xml", "/path/to/config.xml", ".md", "to-config-audit.md"},
		{"json from xml", "/path/to/config.xml", ".json", "to-config-audit.json"},
		{"yaml from xml", "/path/to/config.xml", ".yaml", "to-config-audit.yaml"},
		{"html from xml", "config.xml", ".html", "config-audit.html"},
		{"txt from xml", "config.xml", ".txt", "config-audit.txt"},
		{"nested path", "/a/b/c/firewall-prod.xml", ".md", "c-firewall-prod-audit.md"},
		{"no extension input", "/path/to/config", ".json", "to-config-audit.json"},
		{"relative path", "configs/backup.xml", ".md", "configs-backup-audit.md"},
		{"bare filename no dir", "config.xml", ".md", "config-audit.md"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := deriveAuditOutputPath(tt.inputFile, tt.fileExt)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestDeriveAuditOutputPath_BasenamCollision verifies that inputs with the same
// basename but different parent directories produce distinct output paths,
// preventing overwrite prompts or silent clobbering during multi-file audit.
func TestDeriveAuditOutputPath_BasenameCollision(t *testing.T) {
	t.Parallel()

	pathA := deriveAuditOutputPath("site-a/config.xml", ".md")
	pathB := deriveAuditOutputPath("site-b/config.xml", ".md")

	assert.Equal(t, "site-a-config-audit.md", pathA)
	assert.Equal(t, "site-b-config-audit.md", pathB)
	assert.NotEqual(t, pathA, pathB,
		"inputs with same basename but different directories must produce distinct output paths")
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
