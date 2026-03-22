package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// auditFlagSnapshot captures audit-specific and shared convert-level flag variables
// for test isolation. Use captureAuditFlags to save and restore via t.Cleanup to
// prevent test pollution when flags are modified during test execution.
type auditFlagSnapshot struct {
	mode       string
	plugins    []string
	pluginDir  string
	formatFlag string
	outputFile string
	forceFlag  bool
}

// captureAuditFlags saves the current state of audit-specific and shared
// convert-level flag variables for later restoration.
func captureAuditFlags() auditFlagSnapshot {
	return auditFlagSnapshot{
		mode:       auditMode,
		plugins:    auditPlugins,
		pluginDir:  auditPluginDir,
		formatFlag: format,
		outputFile: outputFile,
		forceFlag:  force,
	}
}

// restore resets the audit-specific and shared convert-level flag variables
// to their previously captured values.
func (s auditFlagSnapshot) restore() {
	auditMode = s.mode
	auditPlugins = s.plugins
	auditPluginDir = s.pluginDir
	format = s.formatFlag
	outputFile = s.outputFile
	force = s.forceFlag
}

// findAuditCommand locates the "audit" subcommand among the root command's children.
func findAuditCommand(root *cobra.Command) *cobra.Command {
	for _, cmd := range root.Commands() {
		if cmd.Name() == "audit" {
			return cmd
		}
	}

	return nil
}

// TestAuditCmdRegistration verifies that the audit command is registered as a child
// of rootCmd with the correct group and configuration.
func TestAuditCmdRegistration(t *testing.T) {
	rootCmd := GetRootCmd()
	cmd := findAuditCommand(rootCmd)

	require.NotNil(t, cmd, "audit command should be registered on rootCmd")
	assert.Equal(t, "audit", cmd.Name())
	assert.Equal(t, "audit", cmd.GroupID)
	assert.NotNil(t, cmd.Args, "audit command should have an Args validator")
	assert.NotNil(t, cmd.ValidArgsFunction, "audit command should have a ValidArgsFunction")
}

// TestAuditCmdFlagDefaults verifies that all audit command flags have correct default values.
func TestAuditCmdFlagDefaults(t *testing.T) {
	rootCmd := GetRootCmd()
	cmd := findAuditCommand(rootCmd)
	require.NotNil(t, cmd)

	flags := cmd.Flags()

	tests := []struct {
		name     string
		defValue string
	}{
		{"mode", "standard"},
		{"plugins", "[]"},
		{"plugin-dir", ""},
		{"format", "markdown"},
		{"output", ""},
		{"force", "false"},
		{"comprehensive", "false"},
		{"redact", "false"},
		{"wrap", "-1"},
		{"no-wrap", "false"},
	}

	for _, tt := range tests {
		f := flags.Lookup(tt.name)
		require.NotNil(t, f, "flag %q should be registered", tt.name)
		assert.Equal(t, tt.defValue, f.DefValue, "flag %q default", tt.name)
	}

	// Verify shorthands on format and output flags
	formatFlag := flags.Lookup("format")
	require.NotNil(t, formatFlag)
	assert.Equal(t, "f", formatFlag.Shorthand)

	outputFlag := flags.Lookup("output")
	require.NotNil(t, outputFlag)
	assert.Equal(t, "o", outputFlag.Shorthand)
}

// TestAuditCmdHelpOutput verifies that the audit command's help output contains
// expected content for modes, plugins, format, and output flags.
func TestAuditCmdHelpOutput(t *testing.T) {
	rootCmd := GetRootCmd()

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"audit", "--help"})

	err := rootCmd.Execute()
	require.NoError(t, err)

	output := buf.String()

	expectedSubstrings := []string{
		"audit",
		"--mode",
		"--plugins",
		"--format",
		"--output",
	}

	for _, sub := range expectedSubstrings {
		assert.Contains(t, output, sub, "help output should contain %q", sub)
	}

	// Verify the full audit mode description strings from auditCmd.Long
	modeDescriptions := []string{
		"standard  - Neutral, comprehensive documentation report (default)",
		"blue      - Defensive audit with security findings and recommendations",
		"red       - Attacker-focused recon report highlighting attack surfaces",
	}

	for _, desc := range modeDescriptions {
		assert.Contains(t, output, desc, "help output should contain mode description %q", desc)
	}
}

// TestAuditCmdPreRunEModeValidation exercises the PreRunE validation of the --mode flag
// with valid and invalid mode values. It drives flag values through Cobra/pflag binding
// to verify the real CLI wiring as well as the validation behavior.
func TestAuditCmdPreRunEModeValidation(t *testing.T) {
	tests := []struct {
		name      string
		mode      string
		wantErr   bool
		errSubstr string
	}{
		{"standard is accepted", "standard", false, ""},
		{"blue is accepted", "blue", false, ""},
		{"red is accepted", "red", false, ""},
		{"invalid is rejected", "invalid", true, "invalid audit mode"},
		{"empty is rejected", "", true, "invalid audit mode"},
		{"typo is rejected", "stanard", true, "invalid audit mode"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auditSnap := captureAuditFlags()
			sharedSnap := captureSharedFlags()
			t.Cleanup(func() {
				auditSnap.restore()
				sharedSnap.restore()
			})

			// Build a command with the same flag bindings as auditCmd to exercise
			// real Cobra/pflag parsing, not just direct global mutation.
			tempCmd := &cobra.Command{}
			tempCmd.Flags().StringVar(&auditMode, "mode", "standard", "")
			tempCmd.Flags().StringSliceVar(&auditPlugins, "plugins", []string{}, "")
			tempCmd.Flags().StringVar(&outputFile, "output", "", "")
			tempCmd.Flags().StringVar(&format, "format", "markdown", "")
			tempCmd.Flags().Bool("no-wrap", false, "")
			tempCmd.Flags().Int("wrap", -1, "")

			// Set flags through pflag to verify real CLI wiring
			require.NoError(t, tempCmd.Flags().Set("mode", tt.mode))

			err := auditCmd.PreRunE(tempCmd, []string{"dummy.xml"})
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestAuditCmdPreRunEPluginValidation exercises the PreRunE validation of the --plugins
// flag with valid and invalid plugin names in blue mode. It drives flag values through
// Cobra/pflag binding to verify the real CLI wiring as well as the validation behavior.
func TestAuditCmdPreRunEPluginValidation(t *testing.T) {
	tests := []struct {
		name      string
		plugins   string // comma-separated, as a user would pass on the CLI
		wantErr   bool
		errSubstr string
	}{
		{"stig accepted", "stig", false, ""},
		{"sans accepted", "sans", false, ""},
		{"firewall accepted", "firewall", false, ""},
		{"all accepted", "stig,sans,firewall", false, ""},
		{"invalid rejected", "invalid", true, "invalid audit plugin"},
		{"mixed valid+invalid", "stig,bad", true, "invalid audit plugin"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auditSnap := captureAuditFlags()
			sharedSnap := captureSharedFlags()
			t.Cleanup(func() {
				auditSnap.restore()
				sharedSnap.restore()
			})

			// Build a command with the same flag bindings as auditCmd to exercise
			// real Cobra/pflag parsing, not just direct global mutation.
			tempCmd := &cobra.Command{}
			tempCmd.Flags().StringVar(&auditMode, "mode", "standard", "")
			tempCmd.Flags().StringSliceVar(&auditPlugins, "plugins", []string{}, "")
			tempCmd.Flags().StringVar(&outputFile, "output", "", "")
			tempCmd.Flags().StringVar(&format, "format", "markdown", "")
			tempCmd.Flags().Bool("no-wrap", false, "")
			tempCmd.Flags().Int("wrap", -1, "")

			// Set flags through pflag to verify real CLI wiring
			require.NoError(t, tempCmd.Flags().Set("mode", "blue"))
			require.NoError(t, tempCmd.Flags().Set("plugins", tt.plugins))

			err := auditCmd.PreRunE(tempCmd, []string{"dummy.xml"})
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestAuditCmdPreRunEPluginsRequireBlueMode verifies that the --plugins flag is rejected
// when the audit mode is not blue. It drives flag values through Cobra/pflag binding
// to verify the real CLI wiring as well as the validation behavior.
func TestAuditCmdPreRunEPluginsRequireBlueMode(t *testing.T) {
	tests := []struct {
		name      string
		mode      string
		plugins   string // comma-separated, empty string means no --plugins flag set
		wantErr   bool
		errSubstr string
	}{
		{"plugins with standard", "standard", "stig", true, "--plugins is only supported with --mode blue"},
		{"plugins with red", "red", "stig", true, "--plugins is only supported with --mode blue"},
		{"plugins with blue accepted", "blue", "stig", false, ""},
		{"empty plugins with standard", "standard", "", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auditSnap := captureAuditFlags()
			sharedSnap := captureSharedFlags()
			t.Cleanup(func() {
				auditSnap.restore()
				sharedSnap.restore()
			})

			// Build a command with the same flag bindings as auditCmd to exercise
			// real Cobra/pflag parsing, not just direct global mutation.
			tempCmd := &cobra.Command{}
			tempCmd.Flags().StringVar(&auditMode, "mode", "standard", "")
			tempCmd.Flags().StringSliceVar(&auditPlugins, "plugins", []string{}, "")
			tempCmd.Flags().StringVar(&outputFile, "output", "", "")
			tempCmd.Flags().StringVar(&format, "format", "markdown", "")
			tempCmd.Flags().Bool("no-wrap", false, "")
			tempCmd.Flags().Int("wrap", -1, "")

			// Set flags through pflag to verify real CLI wiring
			require.NoError(t, tempCmd.Flags().Set("mode", tt.mode))
			if tt.plugins != "" {
				require.NoError(t, tempCmd.Flags().Set("plugins", tt.plugins))
			}

			err := auditCmd.PreRunE(tempCmd, []string{"dummy.xml"})
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestAuditCmdPreRunEMultiFileOutput verifies that --output is rejected when multiple
// input files are provided, and accepted with a single file. It drives flag values
// through Cobra/pflag binding to verify the real CLI wiring.
func TestAuditCmdPreRunEMultiFileOutput(t *testing.T) {
	auditSnap := captureAuditFlags()
	sharedSnap := captureSharedFlags()
	t.Cleanup(func() {
		auditSnap.restore()
		sharedSnap.restore()
	})

	// Build a command with the same flag bindings as auditCmd to exercise
	// real Cobra/pflag parsing, not just direct global mutation.
	tempCmd := &cobra.Command{}
	tempCmd.Flags().StringVar(&auditMode, "mode", "standard", "")
	tempCmd.Flags().StringSliceVar(&auditPlugins, "plugins", []string{}, "")
	tempCmd.Flags().StringVarP(&outputFile, "output", "o", "", "")
	tempCmd.Flags().StringVar(&format, "format", "markdown", "")
	tempCmd.Flags().Bool("no-wrap", false, "")
	tempCmd.Flags().Int("wrap", -1, "")

	// Set --output through pflag to verify real CLI wiring
	require.NoError(t, tempCmd.Flags().Set("output", "report.md"))

	// Multi-file with --output should fail
	err := auditCmd.PreRunE(tempCmd, []string{"file1.xml", "file2.xml"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--output cannot be used with multiple input files")

	// Single file with --output should succeed
	err = auditCmd.PreRunE(tempCmd, []string{"file1.xml"})
	assert.NoError(t, err)
}

// TestAuditCmdCompletions verifies that shell completion functions return the expected
// completions and directives for audit-related flags. This file intentionally avoids
// parallel execution per audit test requirements and AGENTS.md §7.7.
func TestAuditCmdCompletions(t *testing.T) {
	t.Run("audit modes", func(t *testing.T) {
		completions, directive := ValidAuditModes(nil, nil, "")
		assert.Len(t, completions, 3)
		assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)

		joined := strings.Join(completions, " ")
		assert.Contains(t, joined, "standard")
		assert.Contains(t, joined, "blue")
		assert.Contains(t, joined, "red")
	})

	t.Run("audit plugins", func(t *testing.T) {
		completions, directive := ValidAuditPlugins(nil, nil, "")
		assert.Len(t, completions, 3)
		assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)

		joined := strings.Join(completions, " ")
		assert.Contains(t, joined, "stig")
		assert.Contains(t, joined, "sans")
		assert.Contains(t, joined, "firewall")
	})

	t.Run("formats", func(t *testing.T) {
		completions, directive := ValidFormats(nil, nil, "")
		assert.Len(t, completions, 5)
		assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
	})
}
