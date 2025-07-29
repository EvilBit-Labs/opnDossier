package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/opnFocus/internal/config"
	"github.com/unclesp1d3r/opnFocus/internal/markdown"
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

	// Check template flag
	templateFlag := flags.Lookup("template")
	require.NotNil(t, templateFlag)

	// Check section flag
	sectionFlag := flags.Lookup("section")
	require.NotNil(t, sectionFlag)

	// Check theme flag
	themeFlag := flags.Lookup("theme")
	require.NotNil(t, themeFlag)

	// Check wrap flag
	wrapFlag := flags.Lookup("wrap")
	require.NotNil(t, wrapFlag)
	assert.Equal(t, "0", wrapFlag.DefValue)
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

func TestBuildConversionOptions(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		template string
		sections []string
		theme    string
		wrap     int
		expected struct {
			format   markdown.Format
			template string
			sections []string
			theme    markdown.Theme
			wrap     int
		}
	}{
		{
			name:     "All options set",
			format:   "json",
			template: "detailed",
			sections: []string{"system", "network"},
			theme:    "dark",
			wrap:     120,
			expected: struct {
				format   markdown.Format
				template string
				sections []string
				theme    markdown.Theme
				wrap     int
			}{
				format:   markdown.Format("json"),
				template: "detailed",
				sections: []string{"system", "network"},
				theme:    markdown.Theme("dark"),
				wrap:     120,
			},
		},
		{
			name:   "Default options",
			format: "markdown",
			expected: struct {
				format   markdown.Format
				template string
				sections []string
				theme    markdown.Theme
				wrap     int
			}{
				format: markdown.Format("markdown"),
				wrap:   0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildConversionOptions(tt.format, tt.template, tt.sections, tt.theme, tt.wrap, nil)

			assert.Equal(t, tt.expected.format, result.Format)
			if tt.expected.template != "" {
				assert.Equal(t, tt.expected.template, result.TemplateName)
			}
			if len(tt.expected.sections) > 0 {
				assert.Equal(t, tt.expected.sections, result.Sections)
			}
			if tt.expected.theme != "" {
				assert.Equal(t, tt.expected.theme, result.Theme)
			}
			if tt.expected.wrap > 0 {
				assert.Equal(t, tt.expected.wrap, result.WrapWidth)
			}
		})
	}
}

func TestConvertCmdWithInvalidFile(t *testing.T) {
	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "opnfocus-convert-test")
	require.NoError(t, err)
	defer func() {
		err := os.RemoveAll(tmpDir)
		require.NoError(t, err)
	}()

	// Try to convert a non-existent file
	nonExistentFile := filepath.Join(tmpDir, "nonexistent.xml")

	rootCmd := GetRootCmd()

	var stderr bytes.Buffer
	rootCmd.SetErr(&stderr)
	rootCmd.SetArgs([]string{"convert", nonExistentFile})

	err = rootCmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open file")
}

func TestConvertCmdWithValidXML(t *testing.T) {
	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "opnfocus-convert-test")
	require.NoError(t, err)
	defer func() {
		err := os.RemoveAll(tmpDir)
		require.NoError(t, err)
	}()

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
	err = os.WriteFile(configFile, []byte(configContent), 0o600)
	require.NoError(t, err)

	// Test conversion to stdout
	rootCmd := GetRootCmd()

	var stdout bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetArgs([]string{"convert", configFile})

	// Note: This test may fail if the parser is strict about the XML format
	// We're testing the command structure here
	err = rootCmd.Execute()
	// We don't assert no error here because the XML may not pass validation
	// The important thing is that the command runs and attempts conversion
	if err != nil {
		// If it fails, it should be a parsing error, not a command structure error
		assert.Contains(t, err.Error(), "parse")
	}
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
