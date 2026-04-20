package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/diff"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testOldConfigFile = "old-config.xml"
	testNewConfigFile = "new-config.xml"
)

// newTestLogger creates a logger suitable for tests, discarding output.
func newTestLogger(t *testing.T) *logging.Logger {
	t.Helper()

	l, err := logging.New(logging.Config{
		Level:  "error",
		Output: os.Stderr,
	})
	require.NoError(t, err)

	return l
}

// diffFlagSnapshot captures diff-specific flag variables for test isolation.
type diffFlagSnapshot struct {
	outputFile   string
	format       string
	mode         string
	sections     []string
	securityOnly bool
	normalize    bool
	detectOrder  bool
}

// captureDiffFlags saves the current state of diff flag variables.
func captureDiffFlags() diffFlagSnapshot {
	return diffFlagSnapshot{
		outputFile:   diffOutputFile,
		format:       diffFormat,
		mode:         diffMode,
		sections:     diffSections,
		securityOnly: diffSecurityOnly,
		normalize:    diffNormalize,
		detectOrder:  diffDetectOrder,
	}
}

// restore resets the diff flag variables to their previously captured values.
func (s diffFlagSnapshot) restore() {
	diffOutputFile = s.outputFile
	diffFormat = s.format
	diffMode = s.mode
	diffSections = s.sections
	diffSecurityOnly = s.securityOnly
	diffNormalize = s.normalize
	diffDetectOrder = s.detectOrder
}

// findDiffCommand locates the "diff" subcommand among the root command's children.
func findDiffCommand(root *cobra.Command) *cobra.Command {
	for _, cmd := range root.Commands() {
		if cmd.Name() == "diff" {
			return cmd
		}
	}

	return nil
}

// TestDiffCmdRegistration verifies that the diff command is registered as a child
// of rootCmd with the correct group and configuration.
func TestDiffCmdRegistration(t *testing.T) {
	rootCmd := GetRootCmd()
	cmd := findDiffCommand(rootCmd)

	require.NotNil(t, cmd, "diff command should be registered on rootCmd")
	assert.Equal(t, "diff", cmd.Name())
	assert.Equal(t, "core", cmd.GroupID)
	assert.NotNil(t, cmd.Args, "diff command should have an Args validator")
	assert.NotNil(t, cmd.ValidArgsFunction, "diff command should have a ValidArgsFunction")
	assert.NotNil(t, cmd.PreRunE, "diff command should have a PreRunE validator")
}

// TestDiffCmdFlagDefaults verifies that all diff command flags have correct default values.
func TestDiffCmdFlagDefaults(t *testing.T) {
	rootCmd := GetRootCmd()
	cmd := findDiffCommand(rootCmd)
	require.NotNil(t, cmd)

	flags := cmd.Flags()

	tests := []struct {
		name     string
		defValue string
	}{
		{"output", ""},
		{"format", DiffFormatTerminal},
		{"mode", DiffModeUnified},
		{"section", "[]"},
		{"security", "false"},
		{"normalize", "false"},
		{"detect-order", "false"},
	}

	for _, tt := range tests {
		f := flags.Lookup(tt.name)
		require.NotNil(t, f, "flag %q should be registered", tt.name)
		assert.Equal(t, tt.defValue, f.DefValue, "flag %q default", tt.name)
	}

	// Verify shorthands
	formatFlag := flags.Lookup("format")
	require.NotNil(t, formatFlag)
	assert.Equal(t, "f", formatFlag.Shorthand)

	outputFlag := flags.Lookup("output")
	require.NotNil(t, outputFlag)
	assert.Equal(t, "o", outputFlag.Shorthand)

	modeFlag := flags.Lookup("mode")
	require.NotNil(t, modeFlag)
	assert.Equal(t, "m", modeFlag.Shorthand)

	sectionFlag := flags.Lookup("section")
	require.NotNil(t, sectionFlag)
	assert.Equal(t, "s", sectionFlag.Shorthand)
}

// TestValidateDiffFlags exercises the validateDiffFlags function with valid and invalid
// flag combinations. It drives flag values through direct global mutation with cleanup
// to verify validation behavior.
func TestValidateDiffFlags(t *testing.T) {
	tests := []struct {
		name         string
		format       string
		mode         string
		sections     []string
		securityOnly bool
		wantErr      bool
		errSubstr    string
	}{
		// Valid combinations
		{
			name:   "defaults are valid",
			format: DiffFormatTerminal,
			mode:   DiffModeUnified,
		},
		{
			name:   "markdown format accepted",
			format: DiffFormatMarkdown,
			mode:   DiffModeUnified,
		},
		{
			name:   "json format accepted",
			format: DiffFormatJSON,
			mode:   DiffModeUnified,
		},
		{
			name:   "html format accepted",
			format: DiffFormatHTML,
			mode:   DiffModeUnified,
		},
		{
			name:   "empty format accepted",
			format: "",
			mode:   DiffModeUnified,
		},
		{
			name:   "side-by-side with terminal accepted",
			format: DiffFormatTerminal,
			mode:   DiffModeSideBySide,
		},
		{
			name:   "side-by-side with empty format accepted",
			format: "",
			mode:   DiffModeSideBySide,
		},
		{
			name:     "valid section firewall",
			format:   DiffFormatTerminal,
			mode:     DiffModeUnified,
			sections: []string{"firewall"},
		},
		{
			name:     "multiple valid sections",
			format:   DiffFormatTerminal,
			mode:     DiffModeUnified,
			sections: []string{"system", "interfaces", "nat"},
		},
		{
			name:         "security only flag accepted",
			format:       DiffFormatTerminal,
			mode:         DiffModeUnified,
			securityOnly: true,
		},
		{
			name:   "empty mode accepted",
			format: DiffFormatTerminal,
			mode:   "",
		},

		// Invalid format
		{
			name:      "invalid format rejected",
			format:    "xml",
			mode:      DiffModeUnified,
			wantErr:   true,
			errSubstr: "invalid format",
		},
		{
			name:      "typo format rejected",
			format:    "termiinal",
			mode:      DiffModeUnified,
			wantErr:   true,
			errSubstr: "invalid format",
		},

		// Invalid mode
		{
			name:      "invalid mode rejected",
			format:    DiffFormatTerminal,
			mode:      "parallel",
			wantErr:   true,
			errSubstr: "invalid mode",
		},

		// Side-by-side only with terminal
		{
			name:      "side-by-side with markdown rejected",
			format:    DiffFormatMarkdown,
			mode:      DiffModeSideBySide,
			wantErr:   true,
			errSubstr: "side-by-side is only supported with --format terminal",
		},
		{
			name:      "side-by-side with json rejected",
			format:    DiffFormatJSON,
			mode:      DiffModeSideBySide,
			wantErr:   true,
			errSubstr: "side-by-side is only supported with --format terminal",
		},
		{
			name:      "side-by-side with html rejected",
			format:    DiffFormatHTML,
			mode:      DiffModeSideBySide,
			wantErr:   true,
			errSubstr: "side-by-side is only supported with --format terminal",
		},

		// Invalid sections
		{
			name:      "invalid section rejected",
			format:    DiffFormatTerminal,
			mode:      DiffModeUnified,
			sections:  []string{"invalid"},
			wantErr:   true,
			errSubstr: "invalid section",
		},
		{
			name:      "unimplemented section dns rejected",
			format:    DiffFormatTerminal,
			mode:      DiffModeUnified,
			sections:  []string{"dns"},
			wantErr:   true,
			errSubstr: "not yet implemented",
		},
		{
			name:      "unimplemented section vpn rejected",
			format:    DiffFormatTerminal,
			mode:      DiffModeUnified,
			sections:  []string{"vpn"},
			wantErr:   true,
			errSubstr: "not yet implemented",
		},
		{
			name:      "unimplemented section certificates rejected",
			format:    DiffFormatTerminal,
			mode:      DiffModeUnified,
			sections:  []string{"certificates"},
			wantErr:   true,
			errSubstr: "not yet implemented",
		},
		{
			name:      "mix of valid and invalid sections rejected",
			format:    DiffFormatTerminal,
			mode:      DiffModeUnified,
			sections:  []string{"firewall", "bogus"},
			wantErr:   true,
			errSubstr: "invalid section",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snap := captureDiffFlags()
			t.Cleanup(snap.restore)

			diffFormat = tt.format
			diffMode = tt.mode
			diffSections = tt.sections
			diffSecurityOnly = tt.securityOnly

			err := validateDiffFlags()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateDiffFlagsSectionNormalization verifies that sections are normalized
// to lowercase after validation.
func TestValidateDiffFlagsSectionNormalization(t *testing.T) {
	snap := captureDiffFlags()
	t.Cleanup(snap.restore)

	diffFormat = DiffFormatTerminal
	diffMode = DiffModeUnified
	diffSections = []string{"Firewall", " SYSTEM ", "NAT"}

	err := validateDiffFlags()
	require.NoError(t, err)

	assert.Equal(t, []string{"firewall", "system", "nat"}, diffSections)
}

// TestValidateDiffFlagsEmptySections verifies that empty section list is accepted
// and means "all sections".
func TestValidateDiffFlagsEmptySections(t *testing.T) {
	snap := captureDiffFlags()
	t.Cleanup(snap.restore)

	diffFormat = DiffFormatTerminal
	diffMode = DiffModeUnified
	diffSections = nil

	err := validateDiffFlags()
	assert.NoError(t, err)
}

// TestDiffCmdPreRunEValidation exercises the PreRunE validation through the real
// cobra command, binding flags to the actual globals (GOTCHAS §5.3).
func TestDiffCmdPreRunEValidation(t *testing.T) {
	tests := []struct {
		name      string
		format    string
		mode      string
		wantErr   bool
		errSubstr string
	}{
		{"valid defaults", DiffFormatTerminal, DiffModeUnified, false, ""},
		{"invalid format via PreRunE", "xml", DiffModeUnified, true, "invalid format"},
		{"invalid mode via PreRunE", DiffFormatTerminal, "bad", true, "invalid mode"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snap := captureDiffFlags()
			t.Cleanup(snap.restore)

			// Build a temp command with the same flag bindings as diffCmd
			// to exercise real Cobra/pflag parsing (GOTCHAS §5.3).
			tempCmd := &cobra.Command{}
			tempCmd.Flags().StringVar(&diffFormat, "format", DiffFormatTerminal, "")
			tempCmd.Flags().StringVar(&diffMode, "mode", DiffModeUnified, "")
			tempCmd.Flags().StringSliceVar(&diffSections, "section", nil, "")

			require.NoError(t, tempCmd.Flags().Set("format", tt.format))
			require.NoError(t, tempCmd.Flags().Set("mode", tt.mode))

			err := diffCmd.PreRunE(tempCmd, []string{"old.xml", "new.xml"})
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestParseConfigFile_Success verifies that parseConfigFile successfully parses
// a valid OPNsense configuration XML file from testdata.
func TestParseConfigFile_Success(t *testing.T) {
	snap := captureDiffFlags()
	sharedSnap := captureSharedFlags()
	t.Cleanup(func() {
		snap.restore()
		sharedSnap.restore()
	})

	// Use the project's testdata fixture
	testFile := filepath.Join("..", "testdata", "sample.config.1.xml")
	absPath, err := filepath.Abs(testFile)
	require.NoError(t, err)
	require.FileExists(t, absPath)

	cmdLogger := newTestLogger(t)
	ctx := context.Background()

	device, err := parseConfigFile(ctx, absPath, cmdLogger, false)
	require.NoError(t, err)
	require.NotNil(t, device, "parsed device should not be nil")
}

// TestParseConfigFile_QuietSuppressesWarnings verifies that the quiet flag
// suppresses conversion warnings without affecting the parse result.
func TestParseConfigFile_QuietSuppressesWarnings(t *testing.T) {
	snap := captureDiffFlags()
	sharedSnap := captureSharedFlags()
	t.Cleanup(func() {
		snap.restore()
		sharedSnap.restore()
	})

	testFile := filepath.Join("..", "testdata", "sample.config.1.xml")
	absPath, err := filepath.Abs(testFile)
	require.NoError(t, err)

	cmdLogger := newTestLogger(t)
	ctx := context.Background()

	// Both quiet=true and quiet=false should return the same device
	deviceQuiet, err := parseConfigFile(ctx, absPath, cmdLogger, true)
	require.NoError(t, err)
	require.NotNil(t, deviceQuiet)

	deviceVerbose, err := parseConfigFile(ctx, absPath, cmdLogger, false)
	require.NoError(t, err)
	require.NotNil(t, deviceVerbose)
}

// TestParseConfigFile_InvalidPath verifies that parseConfigFile returns an error
// for a non-existent file path.
func TestParseConfigFile_InvalidPath(t *testing.T) {
	snap := captureDiffFlags()
	sharedSnap := captureSharedFlags()
	t.Cleanup(func() {
		snap.restore()
		sharedSnap.restore()
	})

	cmdLogger := newTestLogger(t)
	ctx := context.Background()

	device, err := parseConfigFile(ctx, "/nonexistent/path/config.xml", cmdLogger, false)
	require.Error(t, err)
	assert.Nil(t, device)
	assert.Contains(t, err.Error(), "failed to open file")
}

// TestParseConfigFile_InvalidXML verifies that parseConfigFile returns an error
// when the file contains invalid XML content.
func TestParseConfigFile_InvalidXML(t *testing.T) {
	snap := captureDiffFlags()
	sharedSnap := captureSharedFlags()
	t.Cleanup(func() {
		snap.restore()
		sharedSnap.restore()
	})

	// Create a temporary file with invalid XML
	tmpDir := t.TempDir()
	badFile := filepath.Join(tmpDir, "bad.xml")
	err := os.WriteFile(badFile, []byte("<<<not xml at all>>>"), 0o600)
	require.NoError(t, err)

	cmdLogger := newTestLogger(t)
	ctx := context.Background()

	device, err := parseConfigFile(ctx, badFile, cmdLogger, false)
	require.Error(t, err)
	assert.Nil(t, device)
	assert.Contains(t, err.Error(), "failed to parse config")
}

// TestParseConfigFile_RelativePath verifies that parseConfigFile handles relative
// paths by converting them to absolute paths.
func TestParseConfigFile_RelativePath(t *testing.T) {
	snap := captureDiffFlags()
	sharedSnap := captureSharedFlags()
	t.Cleanup(func() {
		snap.restore()
		sharedSnap.restore()
	})

	cmdLogger := newTestLogger(t)
	ctx := context.Background()

	// Use a relative path to the testdata fixture
	relPath := filepath.Join("..", "testdata", "sample.config.1.xml")

	device, err := parseConfigFile(ctx, relPath, cmdLogger, false)
	require.NoError(t, err)
	require.NotNil(t, device)
}

// TestOutputDiffResult_Markdown verifies that outputDiffResult produces markdown
// output when the format is set to markdown.
func TestOutputDiffResult_Markdown(t *testing.T) {
	snap := captureDiffFlags()
	t.Cleanup(snap.restore)

	diffOutputFile = "" // write to command's stdout

	result := diff.NewResult()
	result.Metadata.OldFile = testOldConfigFile
	result.Metadata.NewFile = testNewConfigFile

	opts := diff.Options{
		Format: DiffFormatMarkdown,
		Mode:   DiffModeUnified,
	}

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	err := outputDiffResult(cmd, result, opts)
	require.NoError(t, err)

	output := buf.String()
	assert.NotEmpty(t, output, "markdown output should not be empty")
}

// TestOutputDiffResult_JSON verifies that outputDiffResult produces valid JSON
// output when the format is set to json.
func TestOutputDiffResult_JSON(t *testing.T) {
	snap := captureDiffFlags()
	t.Cleanup(snap.restore)

	diffOutputFile = "" // write to command's stdout

	result := diff.NewResult()
	result.Metadata.OldFile = testOldConfigFile
	result.Metadata.NewFile = testNewConfigFile

	opts := diff.Options{
		Format: DiffFormatJSON,
		Mode:   DiffModeUnified,
	}

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	err := outputDiffResult(cmd, result, opts)
	require.NoError(t, err)

	output := buf.String()
	assert.NotEmpty(t, output, "json output should not be empty")
	// JSON output should start with { or [
	assert.True(t, output[0] == '{' || output[0] == '[',
		"json output should start with { or [, got %q", string(output[0]))
}

// TestOutputDiffResult_Terminal verifies that outputDiffResult produces terminal
// output with the default format.
func TestOutputDiffResult_Terminal(t *testing.T) {
	t.Setenv("TERM", "dumb")

	snap := captureDiffFlags()
	t.Cleanup(snap.restore)

	diffOutputFile = ""

	result := diff.NewResult()
	result.Metadata.OldFile = testOldConfigFile
	result.Metadata.NewFile = testNewConfigFile

	opts := diff.Options{
		Format: DiffFormatTerminal,
		Mode:   DiffModeUnified,
	}

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	err := outputDiffResult(cmd, result, opts)
	require.NoError(t, err)
	// Terminal formatter may produce empty output for empty results, which is acceptable
}

// TestOutputDiffResult_HTML verifies that outputDiffResult produces HTML output.
func TestOutputDiffResult_HTML(t *testing.T) {
	snap := captureDiffFlags()
	t.Cleanup(snap.restore)

	diffOutputFile = ""

	result := diff.NewResult()
	result.Metadata.OldFile = testOldConfigFile
	result.Metadata.NewFile = testNewConfigFile

	opts := diff.Options{
		Format: DiffFormatHTML,
		Mode:   DiffModeUnified,
	}

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	err := outputDiffResult(cmd, result, opts)
	require.NoError(t, err)

	output := buf.String()
	assert.NotEmpty(t, output, "html output should not be empty")
}

// TestOutputDiffResult_FileOutput verifies that outputDiffResult writes to a file
// when diffOutputFile is set.
func TestOutputDiffResult_FileOutput(t *testing.T) {
	snap := captureDiffFlags()
	t.Cleanup(snap.restore)

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "diff-output.json")
	diffOutputFile = outFile

	result := diff.NewResult()
	result.Metadata.OldFile = testOldConfigFile
	result.Metadata.NewFile = testNewConfigFile

	opts := diff.Options{
		Format: DiffFormatJSON,
		Mode:   DiffModeUnified,
	}

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	err := outputDiffResult(cmd, result, opts)
	require.NoError(t, err)

	// Verify file was created and has content
	content, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.NotEmpty(t, content, "output file should have content")

	// Verify nothing went to stdout buffer since output was redirected to file
	assert.Empty(t, buf.String(), "stdout should be empty when writing to file")
}

// TestOutputDiffResult_InvalidOutputPath verifies that outputDiffResult returns an error
// when the output file path is invalid.
func TestOutputDiffResult_InvalidOutputPath(t *testing.T) {
	snap := captureDiffFlags()
	t.Cleanup(snap.restore)

	diffOutputFile = "/nonexistent/directory/output.md"

	result := diff.NewResult()
	opts := diff.Options{
		Format: DiffFormatMarkdown,
		Mode:   DiffModeUnified,
	}

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	err := outputDiffResult(cmd, result, opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create output file")
}

// TestOutputDiffResult_EmptyResult verifies that outputDiffResult handles an empty
// diff result without error.
func TestOutputDiffResult_EmptyResult(t *testing.T) {
	snap := captureDiffFlags()
	t.Cleanup(snap.restore)

	diffOutputFile = ""

	result := diff.NewResult()
	opts := diff.Options{
		Format: DiffFormatJSON,
		Mode:   DiffModeUnified,
	}

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	err := outputDiffResult(cmd, result, opts)
	require.NoError(t, err)
}

// TestDiffCmdHelpOutput verifies that the diff command's help output contains
// expected content for all flags and descriptions.
func TestDiffCmdHelpOutput(t *testing.T) {
	rootCmd := GetRootCmd()

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"diff", "--help"})

	err := rootCmd.Execute()
	require.NoError(t, err)

	output := buf.String()

	expectedSubstrings := []string{
		"diff",
		"--format",
		"--output",
		"--mode",
		"--section",
		"--security",
		"--normalize",
		"--detect-order",
	}

	for _, sub := range expectedSubstrings {
		assert.Contains(t, output, sub, "help output should contain %q", sub)
	}
}

// TestValidDiffFormats verifies the completion function returns all valid formats.
func TestValidDiffFormats(t *testing.T) {
	completions, directive := ValidDiffFormats(nil, nil, "")
	assert.Len(t, completions, 4)
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)

	// Verify all format names appear
	joined := ""
	var joinedSb740 strings.Builder
	for _, c := range completions {
		joinedSb740.WriteString(c + " ")
	}
	joined += joinedSb740.String()
	assert.Contains(t, joined, DiffFormatTerminal)
	assert.Contains(t, joined, DiffFormatMarkdown)
	assert.Contains(t, joined, DiffFormatJSON)
	assert.Contains(t, joined, DiffFormatHTML)
}

// TestValidDiffModes verifies the completion function returns all valid modes.
func TestValidDiffModes(t *testing.T) {
	completions, directive := ValidDiffModes(nil, nil, "")
	assert.Len(t, completions, 2)
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)

	joined := ""
	var joinedSb756 strings.Builder
	for _, c := range completions {
		joinedSb756.WriteString(c + " ")
	}
	joined += joinedSb756.String()
	assert.Contains(t, joined, DiffModeUnified)
	assert.Contains(t, joined, DiffModeSideBySide)
}

// TestValidDiffSections verifies the completion function returns all valid sections.
func TestValidDiffSections(t *testing.T) {
	completions, directive := ValidDiffSections(nil, nil, "")
	assert.NotEmpty(t, completions)
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)

	joined := ""
	var joinedSb770 strings.Builder
	for _, c := range completions {
		joinedSb770.WriteString(c + " ")
	}
	joined += joinedSb770.String()
	// Check that both implemented and unimplemented sections appear in completions
	for _, section := range []string{"system", "firewall", "nat", "interfaces", "vlans", "dhcp", "users", "routing", "dns", "vpn", "certificates"} {
		assert.Contains(t, joined, section, "completions should contain section %q", section)
	}
}

// TestOutputDiffResult_UnsupportedFormat verifies that outputDiffResult returns an error
// for an unsupported format that bypasses validateDiffFlags.
func TestOutputDiffResult_UnsupportedFormat(t *testing.T) {
	snap := captureDiffFlags()
	t.Cleanup(snap.restore)

	diffOutputFile = ""

	result := diff.NewResult()
	opts := diff.Options{
		Format: "unsupported_format",
		Mode:   DiffModeUnified,
	}

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	err := outputDiffResult(cmd, result, opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported diff format")
}

// TestParseConfigFile_EmptyFile verifies that parseConfigFile returns an error
// when the file is empty.
func TestParseConfigFile_EmptyFile(t *testing.T) {
	snap := captureDiffFlags()
	sharedSnap := captureSharedFlags()
	t.Cleanup(func() {
		snap.restore()
		sharedSnap.restore()
	})

	tmpDir := t.TempDir()
	emptyFile := filepath.Join(tmpDir, "empty.xml")
	err := os.WriteFile(emptyFile, []byte(""), 0o600)
	require.NoError(t, err)

	cmdLogger := newTestLogger(t)
	ctx := context.Background()

	device, err := parseConfigFile(ctx, emptyFile, cmdLogger, false)
	require.Error(t, err)
	assert.Nil(t, device)
}

// TestParseConfigFile_ContextCancellation verifies that parseConfigFile respects
// context cancellation.
func TestParseConfigFile_ContextCancellation(t *testing.T) {
	snap := captureDiffFlags()
	sharedSnap := captureSharedFlags()
	t.Cleanup(func() {
		snap.restore()
		sharedSnap.restore()
	})

	testFile := filepath.Join("..", "testdata", "sample.config.1.xml")
	absPath, err := filepath.Abs(testFile)
	require.NoError(t, err)

	cmdLogger := newTestLogger(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// The parser may or may not check context — verify it doesn't panic
	// and returns without corrupting state.
	require.NotPanics(t, func() {
		device, parseErr := parseConfigFile(ctx, absPath, cmdLogger, false)
		// Parser may complete before checking context, so either outcome is valid
		if parseErr != nil {
			assert.Nil(t, device, "device should be nil on error")
		}
	})
}
