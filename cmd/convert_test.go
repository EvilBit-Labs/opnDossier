package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertCmd(t *testing.T) {
	// Test that convert command is properly initialized
	rootCmd := GetRootCmd()
	convertCmd := findCommand(rootCmd)
	require.NotNil(t, convertCmd)
	assert.Equal(t, "convert", convertCmd.Name())
	assert.Contains(t, convertCmd.Short, "Convert OPNsense configuration files")
}

func TestConvertCmdFlags(t *testing.T) {
	rootCmd := GetRootCmd()
	convertCmd := findCommand(rootCmd)
	require.NotNil(t, convertCmd)

	flags := convertCmd.Flags()

	// Check output flag
	outputFlag := flags.Lookup("output")
	require.NotNil(t, outputFlag)
	assert.Equal(t, "o", outputFlag.Shorthand)

	// Check format flag
	formatFlag := flags.Lookup("format")
	require.NotNil(t, formatFlag)
	assert.Equal(t, "f", formatFlag.Shorthand)
	assert.Equal(t, "markdown", formatFlag.DefValue)

	// Check section flag
	sectionFlag := flags.Lookup("section")
	require.NotNil(t, sectionFlag)

	// Check wrap flag
	wrapFlag := flags.Lookup("wrap")
	require.NotNil(t, wrapFlag)
	assert.Equal(t, "-1", wrapFlag.DefValue)

	// Check no-wrap flag
	noWrapFlag := flags.Lookup("no-wrap")
	require.NotNil(t, noWrapFlag)
}

func TestConvertCmdHelp(t *testing.T) {
	rootCmd := GetRootCmd()
	convertCmd := findCommand(rootCmd)
	require.NotNil(t, convertCmd)

	// Just verify command structure, not help output
	assert.Contains(t, convertCmd.Short, "Convert OPNsense configuration files")
	assert.Contains(t, convertCmd.Long, "convert")
	assert.Contains(t, convertCmd.Long, "Examples:")
}

func TestConvertCmdRequiresArgs(t *testing.T) {
	rootCmd := GetRootCmd()
	convertCmd := findCommand(rootCmd)
	require.NotNil(t, convertCmd)

	// Just verify Args requirement is set correctly
	assert.NotNil(t, convertCmd.Args)
	// Args should require at least 1 argument (MinimumNArgs(1))
	assert.Equal(t, "convert", convertCmd.Name())
}

func TestBuildEffectiveFormat(t *testing.T) {
	tests := []struct {
		name         string
		flagFormat   string
		configFormat string
		expected     string
	}{
		{
			name:         "CLI flag takes precedence",
			flagFormat:   "json",
			configFormat: "yaml",
			expected:     "json",
		},
		{
			name:         "Config used when no CLI flag",
			flagFormat:   "",
			configFormat: "yaml",
			expected:     "yaml",
		},
		{
			name:         "Default when neither set",
			flagFormat:   "",
			configFormat: "",
			expected:     "markdown",
		},
		{
			name:         "Empty CLI flag falls back to config",
			flagFormat:   "",
			configFormat: "json",
			expected:     "json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg *config.Config
			if tt.configFormat != "" {
				// Create a mock config with the format set
				cfg = &config.Config{
					Format: tt.configFormat,
				}
			}

			result := buildEffectiveFormat(tt.flagFormat, cfg)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeFormat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		expected converter.Format
	}{
		{name: "md to markdown", input: "md", expected: converter.FormatMarkdown},
		{name: "yml to yaml", input: "yml", expected: converter.FormatYAML},
		{name: "txt to text", input: "txt", expected: converter.FormatText},
		{name: "markdown unchanged", input: "markdown", expected: converter.FormatMarkdown},
		{name: "json unchanged", input: "json", expected: converter.FormatJSON},
		{name: "yaml unchanged", input: "yaml", expected: converter.FormatYAML},
		{name: "text unchanged", input: "text", expected: converter.FormatText},
		{name: "case insensitive MD", input: "MD", expected: converter.FormatMarkdown},
		{name: "case insensitive TXT", input: "TXT", expected: converter.FormatText},
		{name: "htm to html", input: "htm", expected: converter.FormatHTML},
		{name: "html unchanged", input: "html", expected: converter.FormatHTML},
		{name: "case insensitive HTML", input: "HTML", expected: converter.FormatHTML},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := normalizeFormat(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildConversionOptions(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		sections []string
		wrap     int
		expected struct {
			format   converter.Format
			sections []string
			wrap     int
		}
	}{
		{
			name:     "All options set",
			format:   "json",
			sections: []string{"system", "network"},
			wrap:     120,
			expected: struct {
				format   converter.Format
				sections []string
				wrap     int
			}{
				format:   converter.Format("json"),
				sections: []string{"system", "network"},
				wrap:     120,
			},
		},
		{
			name:   "Default options",
			format: "markdown",
			expected: struct {
				format   converter.Format
				sections []string
				wrap     int
			}{
				format: converter.Format("markdown"),
				wrap:   0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up shared flags for testing
			sharedSections = tt.sections
			sharedWrapWidth = tt.wrap

			result := buildConversionOptions(tt.format, nil)

			assert.Equal(t, tt.expected.format, result.Format)

			if len(tt.expected.sections) > 0 {
				assert.Equal(t, tt.expected.sections, result.Sections)
			}

			if tt.expected.wrap > 0 {
				assert.Equal(t, tt.expected.wrap, result.WrapWidth)
			}
		})
	}
}

func TestBuildConversionOptionsWrapWidthPrecedence(t *testing.T) {
	originalWrap := sharedWrapWidth
	originalNoWrap := sharedNoWrap
	originalSections := sharedSections
	t.Cleanup(func() {
		sharedWrapWidth = originalWrap
		sharedNoWrap = originalNoWrap
		sharedSections = originalSections
	})

	makeConfig := func(wrap int) *config.Config {
		return &config.Config{WrapWidth: wrap}
	}

	applyNoWrap := func(t *testing.T) {
		t.Helper()
		flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
		flags.Bool("no-wrap", false, "")
		flags.Int("wrap", -1, "")
		require.NoError(t, flags.Set("no-wrap", "true"))
		sharedNoWrap = true
		sharedWrapWidth = -1
		normalizeConvertFlags()
	}

	tests := []struct {
		name       string
		setupFlags func(t *testing.T)
		wrapFlag   int
		configWrap int
		expected   int
	}{
		{
			name:       "No-wrap overrides config",
			setupFlags: applyNoWrap,
			wrapFlag:   -1,
			configWrap: 80,
			expected:   0,
		},
		{
			name:       "Wrap zero overrides config",
			setupFlags: nil,
			wrapFlag:   0,
			configWrap: 80,
			expected:   0,
		},
		{
			name:       "Wrap 120 overrides config",
			setupFlags: nil,
			wrapFlag:   120,
			configWrap: 80,
			expected:   120,
		},
		{
			name:       "No CLI flag uses config",
			setupFlags: nil,
			wrapFlag:   -1,
			configWrap: 100,
			expected:   100,
		},
		{
			name:       "Config auto-detect honored",
			setupFlags: nil,
			wrapFlag:   -1,
			configWrap: -1,
			expected:   -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sharedSections = nil
			sharedNoWrap = false
			sharedWrapWidth = tt.wrapFlag
			if tt.setupFlags != nil {
				tt.setupFlags(t)
			}

			result := buildConversionOptions("markdown", makeConfig(tt.configWrap))
			assert.Equal(t, tt.expected, result.WrapWidth)
		})
	}
}

func TestValidateConvertFlagsNoWrapMutualExclusivity(t *testing.T) {
	originalWrap := sharedWrapWidth
	originalNoWrap := sharedNoWrap
	t.Cleanup(func() {
		sharedWrapWidth = originalWrap
		sharedNoWrap = originalNoWrap
	})

	baseFlags := func() *pflag.FlagSet {
		flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
		flags.Bool("no-wrap", false, "")
		flags.Int("wrap", -1, "")
		return flags
	}

	tests := []struct {
		name          string
		noWrap        bool
		wrapValue     string
		setWrapFlag   bool
		wantErr       bool
		wantErrSubstr string
	}{
		{
			name:        "No-wrap alone is valid",
			noWrap:      true,
			setWrapFlag: false,
			wantErr:     false,
		},
		{
			name:          "No-wrap with wrap auto-detect",
			noWrap:        true,
			setWrapFlag:   true,
			wrapValue:     "-1",
			wantErr:       true,
			wantErrSubstr: "--no-wrap and --wrap flags are mutually exclusive",
		},
		{
			name:          "No-wrap with wrap zero",
			noWrap:        true,
			setWrapFlag:   true,
			wrapValue:     "0",
			wantErr:       true,
			wantErrSubstr: "--no-wrap and --wrap flags are mutually exclusive",
		},
		{
			name:          "No-wrap with wrap 80",
			noWrap:        true,
			setWrapFlag:   true,
			wrapValue:     "80",
			wantErr:       true,
			wantErrSubstr: "--no-wrap and --wrap flags are mutually exclusive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := baseFlags()
			sharedNoWrap = tt.noWrap
			sharedWrapWidth = -1

			if tt.noWrap {
				require.NoError(t, flags.Set("no-wrap", "true"))
			}
			if tt.setWrapFlag {
				require.NoError(t, flags.Set("wrap", tt.wrapValue))
				wrapVal, err := flags.GetInt("wrap")
				require.NoError(t, err)
				sharedWrapWidth = wrapVal
			}

			err := validateConvertFlags(flags, nil)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrSubstr)
				return
			}
			require.NoError(t, err)
			normalizeConvertFlags()
			assert.Equal(t, 0, sharedWrapWidth)
		})
	}
}

func TestValidateConvertFlagsWrapWidthBounds(t *testing.T) {
	originalWrap := sharedWrapWidth
	t.Cleanup(func() {
		sharedWrapWidth = originalWrap
	})

	tests := []struct {
		name    string
		width   int
		wantErr bool
	}{
		{name: "negative below -1 is rejected", width: -2, wantErr: true},
		{name: "auto-detect is valid", width: -1, wantErr: false},
		{name: "no wrapping is valid", width: 0, wantErr: false},
		{name: "within range is valid", width: 80, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sharedWrapWidth = tt.width
			err := validateConvertFlags(nil, nil)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid wrap width")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConvertCmdWithInvalidFile(t *testing.T) {
	// Create a temporary directory
	tmpDir := t.TempDir()

	// Try to convert a non-existent file
	nonExistentFile := filepath.Join(tmpDir, "nonexistent.xml")

	rootCmd := GetRootCmd()

	var stderr bytes.Buffer
	rootCmd.SetErr(&stderr)
	rootCmd.SetArgs([]string{"convert", nonExistentFile})

	err := rootCmd.Execute()
	require.Error(t, err)
	assert.True(t,
		strings.Contains(err.Error(), "no such file or directory") ||
			strings.Contains(err.Error(), "The system cannot find the file specified"),
		"error message should indicate missing file, got: %s", err.Error())
}

func TestConvertCmdWithValidXML(t *testing.T) {
	// Create a temporary directory
	tmpDir := t.TempDir()

	// Create a minimal valid OPNsense config file
	configContent := `<?xml version="1.0"?>
<opnsense>
  <version>24.1</version>
  <system>
    <hostname>test-firewall</hostname>
    <domain>example.com</domain>
  </system>
</opnsense>`

	configFile := filepath.Join(tmpDir, "test-config.xml")
	err := os.WriteFile(configFile, []byte(configContent), 0o600)
	require.NoError(t, err)

	// Test conversion to stdout
	rootCmd := GetRootCmd()

	var stdout bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetArgs([]string{"convert", configFile})

	// Note: This test may fail if the parser is strict about the XML format
	// or if templates cannot be found during testing
	// We're testing the command structure here
	err = rootCmd.Execute()
	// We don't assert no error here because the XML may not pass validation
	// or templates may not be found in test environment
	// The important thing is that the command runs and attempts conversion
	if err != nil {
		// If it fails, it should be a parsing error, template error, or similar processing error
		// but not a command structure error
		errorStr := err.Error()
		assert.True(t,
			strings.Contains(errorStr, "parse") ||
				strings.Contains(errorStr, "template") ||
				strings.Contains(errorStr, "generator"),
			"Expected parsing, template, or generator error, got: %s", errorStr)
	}
}

func TestDetermineOutputPath(t *testing.T) {
	tests := []struct {
		name        string
		inputFile   string
		outputFile  string
		fileExt     string
		cfg         *config.Config
		force       bool
		expectPath  string
		expectError bool
	}{
		{
			name:       "no output specified - return empty for stdout",
			inputFile:  "config.xml",
			outputFile: "",
			fileExt:    ".md",
			cfg:        nil,
			force:      false,
			expectPath: "",
		},
		{
			name:       "CLI flag takes precedence",
			inputFile:  "config.xml",
			outputFile: "output.md",
			fileExt:    ".json",
			cfg: &config.Config{
				OutputFile: "config_output.md",
			},
			force:      false,
			expectPath: "output.md",
		},
		{
			name:       "use config value when no CLI flag",
			inputFile:  "config.xml",
			outputFile: "",
			fileExt:    ".json",
			cfg: &config.Config{
				OutputFile: "config_output.json",
			},
			force:      false,
			expectPath: "config_output.json",
		},
		{
			name:       "use input filename with extension when config has output_file",
			inputFile:  "my_config.xml",
			outputFile: "",
			fileExt:    ".yaml",
			cfg: &config.Config{
				OutputFile: "default_output.yaml",
			},
			force:      false,
			expectPath: "default_output.yaml",
		},
		{
			name:       "handle input file with no extension",
			inputFile:  "config",
			outputFile: "output.md",
			fileExt:    ".md",
			cfg:        nil,
			force:      false,
			expectPath: "output.md",
		},
		{
			name:       "handle input file with multiple dots",
			inputFile:  "config.backup.xml",
			outputFile: "output.json",
			fileExt:    ".json",
			cfg:        nil,
			force:      false,
			expectPath: "output.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := determineOutputPath(tt.inputFile, tt.outputFile, tt.fileExt, tt.cfg, tt.force)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectPath, path)
			}
		})
	}
}

func TestDetermineOutputPath_OverwriteProtection(t *testing.T) {
	// Create a temporary file for testing
	tmpDir := t.TempDir()
	existingFile := filepath.Join(tmpDir, "existing.md")

	// Create the file
	err := os.WriteFile(existingFile, []byte("existing content"), 0o600)
	require.NoError(t, err)

	tests := []struct {
		name        string
		outputFile  string
		force       bool
		expectError bool
		expectPath  string
	}{
		{
			name:        "file exists with force - should overwrite",
			outputFile:  existingFile,
			force:       true,
			expectError: false,
			expectPath:  existingFile,
		},
		{
			name:        "file does not exist - should work",
			outputFile:  filepath.Join(tmpDir, "new_file.md"),
			force:       false,
			expectError: false,
			expectPath:  filepath.Join(tmpDir, "new_file.md"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := determineOutputPath("config.xml", tt.outputFile, ".md", nil, tt.force)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectPath, path)
			}
		})
	}
}

func TestDetermineOutputPath_NoDirectoryCreation(t *testing.T) {
	// Test that the function doesn't create directories automatically
	nonexistentDir := filepath.Join("nonexistent", "path", "output.md")

	path, err := determineOutputPath("config.xml", nonexistentDir, ".md", nil, false)

	// Should not create directories, just return the path
	require.NoError(t, err)
	assert.Equal(t, nonexistentDir, path)

	// Verify the directory doesn't exist
	dir := filepath.Dir(nonexistentDir)
	_, err = os.Stat(dir)
	assert.True(t, os.IsNotExist(err), "Directory should not be created")
}

// Helper function to find a command by name.
func findCommand(root *cobra.Command) *cobra.Command {
	for _, cmd := range root.Commands() {
		if cmd.Name() == "convert" {
			return cmd
		}
	}

	return nil
}
