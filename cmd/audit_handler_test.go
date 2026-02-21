package cmd

import (
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/audit"
	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/processor"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testBaseReport is a base report string used across multiple tests.
const testBaseReport = "# Report\n"

func TestAppendAuditFindings_EmptyReport(t *testing.T) {
	// Create a base report
	baseReport := "# Test Report\n\nSome content"

	// Create an audit report with no findings
	report := &audit.Report{
		Mode:          audit.ModeStandard,
		BlackhatMode:  false,
		Comprehensive: false,
		Findings:      []audit.Finding{},
		Compliance:    make(map[string]audit.ComplianceResult),
		Metadata:      make(map[string]any),
	}

	result := appendAuditFindings(baseReport, report)

	// Verify the base report is preserved
	assert.Contains(t, result, "# Test Report")
	assert.Contains(t, result, "Some content")

	// Verify the audit section was appended
	assert.Contains(t, result, "## Compliance Audit Summary")
	assert.Contains(t, result, "Report Mode")
	assert.Contains(t, result, "standard")
	assert.Contains(t, result, "Blackhat Mode")
	assert.Contains(t, result, "false")
	assert.Contains(t, result, "Total Findings")
	assert.Contains(t, result, "0")

	// Should not have findings section with no findings
	assert.NotContains(t, result, "### Security Findings")
}

func TestAppendAuditFindings_WithFindings(t *testing.T) {
	baseReport := "# Configuration Report\n"

	report := &audit.Report{
		Mode:          audit.ModeBlue,
		BlackhatMode:  false,
		Comprehensive: true,
		Findings: []audit.Finding{
			{
				Title:          "Weak Firewall Rule",
				Severity:       processor.SeverityHigh,
				Description:    "Rule allows all traffic from any source",
				Recommendation: "Restrict source addresses",
				Component:      "firewall",
			},
			{
				Title:          "Missing Authentication",
				Severity:       processor.SeverityCritical,
				Description:    "Admin portal lacks MFA",
				Recommendation: "Enable multi-factor authentication",
				Component:      "system",
			},
		},
		Compliance: make(map[string]audit.ComplianceResult),
		Metadata:   make(map[string]any),
	}

	result := appendAuditFindings(baseReport, report)

	// Verify summary table
	assert.Contains(t, result, "Report Mode")
	assert.Contains(t, result, "blue")
	assert.Contains(t, result, "Total Findings")
	assert.Contains(t, result, "2")

	// Verify findings section exists
	assert.Contains(t, result, "### Security Findings")
	assert.Contains(t, result, "Severity")
	assert.Contains(t, result, "Component")

	// Verify finding details are present
	assert.Contains(t, result, "Weak Firewall Rule")
	assert.Contains(t, result, "firewall")
	assert.Contains(t, result, "Missing Authentication")
	assert.Contains(t, result, "system")
}

func TestAppendAuditFindings_WithComplianceResults(t *testing.T) {
	baseReport := testBaseReport

	report := &audit.Report{
		Mode:         audit.ModeBlue,
		BlackhatMode: false,
		Findings:     []audit.Finding{},
		Compliance: map[string]audit.ComplianceResult{
			"stig": {
				Findings: []compliance.Finding{
					{
						Type:        "high",
						Title:       "STIG Violation",
						Description: "SSH timeout not configured",
					},
				},
				Summary: &audit.ComplianceSummary{
					TotalFindings:    1,
					CriticalFindings: 0,
					HighFindings:     1,
					MediumFindings:   0,
					LowFindings:      0,
				},
			},
		},
		Metadata: make(map[string]any),
	}

	result := appendAuditFindings(baseReport, report)

	// Verify plugin compliance results section
	assert.Contains(t, result, "### Plugin Compliance Results")
	assert.Contains(t, result, "#### stig")
	assert.Contains(t, result, "1 findings")
	assert.Contains(t, result, "High: 1")

	// Verify plugin findings section
	assert.Contains(t, result, "### stig Plugin Findings")
	assert.Contains(t, result, "STIG Violation")
	assert.Contains(t, result, "SSH timeout not configured")
}

func TestAppendAuditFindings_WithMetadata(t *testing.T) {
	baseReport := testBaseReport

	report := &audit.Report{
		Mode:       audit.ModeRed,
		Findings:   []audit.Finding{},
		Compliance: make(map[string]audit.ComplianceResult),
		Metadata: map[string]any{
			"scan_time":       "2024-01-15T10:30:00Z",
			"scanner_version": "1.0.0",
		},
	}

	result := appendAuditFindings(baseReport, report)

	// Verify metadata section
	assert.Contains(t, result, "### Audit Metadata")
	assert.Contains(t, result, "scan_time")
	assert.Contains(t, result, "scanner_version")
}

func TestAppendAuditFindings_RedTeamWithBlackhat(t *testing.T) {
	baseReport := testBaseReport

	report := &audit.Report{
		Mode:         audit.ModeRed,
		BlackhatMode: true,
		Findings:     []audit.Finding{},
		Compliance:   make(map[string]audit.ComplianceResult),
		Metadata:     make(map[string]any),
	}

	result := appendAuditFindings(baseReport, report)

	// Verify blackhat mode is shown
	assert.Contains(t, result, "Report Mode")
	assert.Contains(t, result, "red")
	assert.Contains(t, result, "Blackhat Mode")
	assert.Contains(t, result, "true")
}

func TestEscapePipeForMarkdown(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no pipes", "hello world", "hello world"},
		{"single pipe", "a|b", "a\\|b"},
		{"multiple pipes", "a|b|c", "a\\|b\\|c"},
		{"empty string", "", ""},
		{"pipe at start", "|hello", "\\|hello"},
		{"pipe at end", "hello|", "hello\\|"},
		{"only pipe", "|", "\\|"},
		{"adjacent pipes", "a||b", "a\\|\\|b"},
		{"pipes with spaces", "a | b | c", "a \\| b \\| c"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := escapePipeForMarkdown(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{"short string", "hello", 10, "hello"},
		{"exact length", "hello", 5, "hello"},
		{"needs truncation", "hello world", 8, "hello..."},
		{"empty string", "", 10, ""},
		{"very short max", "hello world", 4, "h..."},
		// Note: maxLen <= 3 causes issues with current implementation
		// Testing realistic scenarios where maxLen >= 4
		{"four char max", "hello", 4, "h..."},
		{"five char max", "hello world", 5, "he..."},
		{"long string", strings.Repeat("a", 100), 20, strings.Repeat("a", 17) + "..."},
		// Rune-aware truncation: multi-byte characters are not split
		{"unicode emoji", "Hello 🌍🌎🌏 World", 10, "Hello 🌍..."},
		{"japanese text", "こんにちは世界", 5, "こん..."},
		{"mixed unicode", "Test日本語Text", 8, "Test日..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateString(tt.input, tt.maxLen)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTruncateString_MaxDescriptionLength(t *testing.T) {
	// Test with the actual maxDescriptionLength constant
	longDescription := strings.Repeat("a", 100)
	result := truncateString(longDescription, maxDescriptionLength)

	assert.LessOrEqual(t, len(result), maxDescriptionLength)
	assert.True(t, strings.HasSuffix(result, "..."))
}

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
			format = FormatMarkdown // Set valid format to avoid format error

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
			format = FormatMarkdown

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
			format = FormatMarkdown

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

func TestAppendAuditFindings_ComplianceSeverityCounts(t *testing.T) {
	baseReport := testBaseReport

	report := &audit.Report{
		Mode:     audit.ModeBlue,
		Findings: []audit.Finding{},
		Compliance: map[string]audit.ComplianceResult{
			"comprehensive": {
				Findings: []compliance.Finding{},
				Summary: &audit.ComplianceSummary{
					TotalFindings:    10,
					CriticalFindings: 2,
					HighFindings:     3,
					MediumFindings:   4,
					LowFindings:      1,
				},
			},
		},
		Metadata: make(map[string]any),
	}

	result := appendAuditFindings(baseReport, report)

	// Verify all severity counts are shown
	assert.Contains(t, result, "Critical: 2")
	assert.Contains(t, result, "High: 3")
	assert.Contains(t, result, "Medium: 4")
	assert.Contains(t, result, "Low: 1")
}

func TestAppendAuditFindings_PluginFindingsTruncation(t *testing.T) {
	baseReport := testBaseReport

	// Create a very long description
	longDescription := strings.Repeat("This is a very long description. ", 10)

	report := &audit.Report{
		Mode:     audit.ModeBlue,
		Findings: []audit.Finding{},
		Compliance: map[string]audit.ComplianceResult{
			"test_plugin": {
				Findings: []compliance.Finding{
					{
						Type:        "high",
						Title:       "Test Finding",
						Description: longDescription,
					},
				},
				Summary: &audit.ComplianceSummary{
					TotalFindings: 1,
					HighFindings:  1,
				},
			},
		},
		Metadata: make(map[string]any),
	}

	result := appendAuditFindings(baseReport, report)

	// The description should be truncated
	assert.Contains(t, result, "Test Finding")
	// Truncated description should end with "..."
	assert.Contains(t, result, "...")
	// Full description should not be present (it exceeds maxDescriptionLength)
	assert.NotContains(t, result, longDescription)
}

func TestAppendAuditFindings_PipeEscapingInTables(t *testing.T) {
	baseReport := testBaseReport

	report := &audit.Report{
		Mode: audit.ModeBlue,
		Findings: []audit.Finding{
			{
				Title:          "Rule with | pipe",
				Severity:       processor.SeverityMedium,
				Description:    "Contains | multiple | pipes",
				Recommendation: "Fix the | issue",
				Component:      "firewall|nat",
			},
		},
		Compliance: make(map[string]audit.ComplianceResult),
		Metadata:   make(map[string]any),
	}

	result := appendAuditFindings(baseReport, report)

	// Pipes should be escaped in table cells
	assert.Contains(t, result, "Rule with \\| pipe")
	assert.Contains(t, result, "firewall\\|nat")
	assert.Contains(t, result, "Fix the \\| issue")
}

func TestAddSharedAuditFlagsRegistersFlags(t *testing.T) {
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
}

func TestValidAuditModes(t *testing.T) {
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
	t.Cleanup(func() {
		sharedAuditMode = originalAuditMode
		sharedBlackhatMode = originalBlackhat
		sharedSelectedPlugins = originalPlugins
	})

	tests := []struct {
		name            string
		auditMode       string
		blackhatMode    bool
		selectedPlugins []string
	}{
		{
			name:            "empty defaults",
			auditMode:       "",
			blackhatMode:    false,
			selectedPlugins: nil,
		},
		{
			name:            "standard mode",
			auditMode:       "standard",
			blackhatMode:    false,
			selectedPlugins: nil,
		},
		{
			name:            "blue mode with plugins",
			auditMode:       "blue",
			blackhatMode:    false,
			selectedPlugins: []string{"stig", "sans"},
		},
		{
			name:            "red mode with blackhat",
			auditMode:       "red",
			blackhatMode:    true,
			selectedPlugins: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sharedAuditMode = tt.auditMode
			sharedBlackhatMode = tt.blackhatMode
			sharedSelectedPlugins = tt.selectedPlugins

			result := buildAuditOptions()

			assert.Equal(t, tt.auditMode, result.AuditMode)
			assert.Equal(t, tt.blackhatMode, result.BlackhatMode)
			assert.Equal(t, tt.selectedPlugins, result.SelectedPlugins)
		})
	}
}
