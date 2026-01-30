package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfigFromFile(t *testing.T) {
	// Clear environment variables for this test
	clearEnvironment(t)

	// Create a temporary config file
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.xml")
	cfgFilePath := filepath.Join(tmpDir, ".opnDossier.yaml")
	content := fmt.Sprintf(`
input_file: %s
output_file: %s
verbose: true
quiet: false
`, inputFile, filepath.Join(tmpDir, "output.md"))
	err := os.WriteFile(cfgFilePath, []byte(content), 0o600)
	require.NoError(t, err)

	// Create the input file to pass validation
	err = os.WriteFile(inputFile, []byte("<test/>"), 0o600)
	require.NoError(t, err)

	// Test loading from file
	cfg, err := LoadConfigWithViper(cfgFilePath, viper.New())
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, inputFile, cfg.InputFile)
	assert.Equal(t, filepath.Join(tmpDir, "output.md"), cfg.OutputFile)
	assert.True(t, cfg.Verbose)
	assert.False(t, cfg.Quiet)
}

func TestLoadConfigFromEnv(t *testing.T) {
	// Clear environment variables for this test
	clearEnvironment(t)

	// Create temporary directory and file for testing
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.xml")
	err := os.WriteFile(inputFile, []byte("<test/>"), 0o600)
	require.NoError(t, err)

	t.Setenv("OPNDOSSIER_INPUT_FILE", inputFile)
	t.Setenv("OPNDOSSIER_VERBOSE", "false")

	cfg, err := LoadConfigWithViper("", viper.New()) // Load without a specific file to pick up env vars
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, inputFile, cfg.InputFile)
	assert.Empty(t, cfg.OutputFile) // Should not be overridden by env var
	assert.False(t, cfg.Verbose)
}

func TestLoadConfigPrecedence(t *testing.T) {
	// Clear environment variables for this test
	clearEnvironment(t)

	// Create temporary files for testing
	tmpDir := t.TempDir()
	fileInputFile := filepath.Join(tmpDir, "file_input.xml")
	envInputFile := filepath.Join(tmpDir, "env_input.xml")

	err := os.WriteFile(fileInputFile, []byte("<test/>"), 0o600)
	require.NoError(t, err)
	err = os.WriteFile(envInputFile, []byte("<test/>"), 0o600)
	require.NoError(t, err)

	// Create a temporary config file with a valid output path
	outputFile := filepath.Join(tmpDir, "output.md")
	cfgFilePath := filepath.Join(tmpDir, ".opnDossier.yaml")
	content := fmt.Sprintf(`
input_file: %s
output_file: %s
verbose: true
`, fileInputFile, outputFile)
	err = os.WriteFile(cfgFilePath, []byte(content), 0o600)
	require.NoError(t, err)

	t.Setenv("OPNDOSSIER_INPUT_FILE", envInputFile)
	t.Setenv("OPNDOSSIER_VERBOSE", "false")

	// Environment variables should override config file values (standard precedence)
	cfg, err := LoadConfigWithViper(cfgFilePath, viper.New())
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, envInputFile, cfg.InputFile) // Environment variable should win
	assert.Equal(t, outputFile, cfg.OutputFile)  // Config file value (no env var set)
	assert.False(t, cfg.Verbose)                 // Environment variable should win
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid_config",
			config: Config{
				InputFile:  "",
				OutputFile: "",
				Verbose:    false,
				Quiet:      false,
			},
			wantErr: false,
		},
		{
			name: "mutually_exclusive_verbose_quiet",
			config: Config{
				Verbose: true,
				Quiet:   true,
			},
			wantErr: false, // Validation now handled by Cobra flag validation
		},
		{
			name: "nonexistent_input_file",
			config: Config{
				InputFile: "/nonexistent/file.xml",
			},
			wantErr: true,
			errMsg:  "input file does not exist",
		},
		{
			name: "nonexistent_output_directory",
			config: Config{
				OutputFile: "/nonexistent/dir/output.md",
			},
			wantErr: true,
			errMsg:  "output directory does not exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfig_HelperMethods(t *testing.T) {
	cfg := &Config{
		Verbose: true,
		Quiet:   false,
	}

	assert.True(t, cfg.IsVerbose())
	assert.False(t, cfg.IsQuiet())
}

func TestLoadConfigFromEnvWithNewFields(t *testing.T) {
	// Clear environment variables for this test
	clearEnvironment(t)

	// Set environment variables for new fields
	t.Setenv("OPNDOSSIER_QUIET", "true")

	cfg, err := LoadConfigWithViper("", viper.New())
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.True(t, cfg.Quiet)
}

func TestLoadConfigFromEnvWithAllFields(t *testing.T) {
	// Clear environment variables for this test
	clearEnvironment(t)

	// Create temporary directory and file for testing
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.xml")
	outputFile := filepath.Join(tmpDir, "output.md")
	err := os.WriteFile(inputFile, []byte("<test/>"), 0o600)
	require.NoError(t, err)

	// Set environment variables for all configuration fields
	t.Setenv("OPNDOSSIER_INPUT_FILE", inputFile)
	t.Setenv("OPNDOSSIER_OUTPUT_FILE", outputFile)
	t.Setenv("OPNDOSSIER_VERBOSE", "true")
	t.Setenv("OPNDOSSIER_QUIET", "false")
	t.Setenv("OPNDOSSIER_THEME", "dark")
	t.Setenv("OPNDOSSIER_FORMAT", "yaml")
	t.Setenv("OPNDOSSIER_TEMPLATE", "comprehensive")
	t.Setenv("OPNDOSSIER_SECTIONS", "system,network,firewall")
	t.Setenv("OPNDOSSIER_WRAP", "80")

	cfg, err := LoadConfigWithViper("", viper.New())
	require.NoError(t, err)
	assert.NotNil(t, cfg)

	// Verify all environment variables are properly loaded
	assert.Equal(t, inputFile, cfg.InputFile)
	assert.Equal(t, outputFile, cfg.OutputFile)
	assert.True(t, cfg.Verbose)
	assert.False(t, cfg.Quiet)
	assert.Equal(t, "dark", cfg.Theme)
	assert.Equal(t, "yaml", cfg.Format)
	assert.Equal(t, "comprehensive", cfg.Template)
	assert.Equal(t, []string{"system", "network", "firewall"}, cfg.Sections)
	assert.Equal(t, 80, cfg.WrapWidth)
}

func TestLoadConfigFromEnvWithBooleanValues(t *testing.T) {
	// Clear environment variables for this test
	clearEnvironment(t)

	// Test various boolean representations
	testCases := []struct {
		name     string
		value    string
		expected bool
	}{
		{"true_string", "true", true},
		{"false_string", "false", false},
		{"true_uppercase", "TRUE", true},
		{"false_uppercase", "FALSE", false},
		{"true_mixed", "True", true},
		{"false_mixed", "False", false},
		{"one", "1", true},
		{"zero", "0", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			clearEnvironment(t)
			t.Setenv("OPNDOSSIER_VERBOSE", tc.value)

			cfg, err := LoadConfigWithViper("", viper.New())
			require.NoError(t, err)
			assert.Equal(t, tc.expected, cfg.Verbose, "Failed for value: %s", tc.value)
		})
	}
}

func TestLoadConfigFromEnvWithIntegerValues(t *testing.T) {
	// Clear environment variables for this test
	clearEnvironment(t)

	// Test integer environment variable
	t.Setenv("OPNDOSSIER_WRAP", "120")

	cfg, err := LoadConfigWithViper("", viper.New())
	require.NoError(t, err)
	assert.Equal(t, 120, cfg.WrapWidth)
}

func TestLoadConfigFromEnvWithSliceValues(t *testing.T) {
	// Clear environment variables for this test
	clearEnvironment(t)

	// Test slice environment variable (comma-separated)
	t.Setenv("OPNDOSSIER_SECTIONS", "system,network,firewall,dhcp")

	cfg, err := LoadConfigWithViper("", viper.New())
	require.NoError(t, err)
	assert.Equal(t, []string{"system", "network", "firewall", "dhcp"}, cfg.Sections)
}

func TestLoadConfigFromEnvWithEmptySlice(t *testing.T) {
	// Clear environment variables for this test
	clearEnvironment(t)

	// Test empty slice environment variable
	t.Setenv("OPNDOSSIER_SECTIONS", "")

	cfg, err := LoadConfigWithViper("", viper.New())
	require.NoError(t, err)
	assert.Equal(t, []string{}, cfg.Sections) // Viper behavior for empty string
}

func TestValidationError_Error(t *testing.T) {
	err := ValidationError{
		Field:   "test_field",
		Message: "test message",
	}

	expected := "validation error for field 'test_field': test message"
	assert.Equal(t, expected, err.Error())
}

// clearEnvironment removes all OPNDOSSIER_ environment variables for testing.
func clearEnvironment(_ *testing.T) {
	envVars := []string{
		"OPNDOSSIER_INPUT_FILE",
		"OPNDOSSIER_OUTPUT_FILE",
		"OPNDOSSIER_VERBOSE",
		"OPNDOSSIER_QUIET",
		"OPNDOSSIER_THEME",
		"OPNDOSSIER_FORMAT",
		"OPNDOSSIER_TEMPLATE",
		"OPNDOSSIER_SECTIONS",
		"OPNDOSSIER_WRAP",
		// Nested config env vars
		"OPNDOSSIER_DISPLAY_WIDTH",
		"OPNDOSSIER_DISPLAY_PAGER",
		"OPNDOSSIER_DISPLAY_SYNTAX_HIGHLIGHTING",
		"OPNDOSSIER_EXPORT_FORMAT",
		"OPNDOSSIER_EXPORT_DIRECTORY",
		"OPNDOSSIER_EXPORT_TEMPLATE",
		"OPNDOSSIER_EXPORT_BACKUP",
		"OPNDOSSIER_LOGGING_LEVEL",
		"OPNDOSSIER_LOGGING_FORMAT",
		"OPNDOSSIER_VALIDATION_STRICT",
		"OPNDOSSIER_VALIDATION_SCHEMA_VALIDATION",
	}

	for _, env := range envVars {
		_ = os.Unsetenv(env)
	}
}

// TestNestedConfigFromYAML tests loading nested configuration from YAML file.
func TestNestedConfigFromYAML(t *testing.T) {
	clearEnvironment(t)

	tmpDir := t.TempDir()
	cfgFilePath := filepath.Join(tmpDir, ".opnDossier.yaml")
	content := `
display:
  width: 120
  pager: true
  syntax_highlighting: true
export:
  format: json
  directory: ./output
  template: comprehensive
  backup: true
logging:
  level: debug
  format: json
validation:
  strict: true
  schema_validation: true
`
	err := os.WriteFile(cfgFilePath, []byte(content), 0o600)
	require.NoError(t, err)

	cfg, err := LoadConfigWithViper(cfgFilePath, viper.New())
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify nested display config
	assert.Equal(t, 120, cfg.Display.Width)
	assert.True(t, cfg.Display.Pager)
	assert.True(t, cfg.Display.SyntaxHighlighting)

	// Verify nested export config
	assert.Equal(t, "json", cfg.Export.Format)
	assert.Equal(t, "./output", cfg.Export.Directory)
	assert.Equal(t, "comprehensive", cfg.Export.Template)
	assert.True(t, cfg.Export.Backup)

	// Verify nested logging config
	assert.Equal(t, "debug", cfg.Logging.Level)
	assert.Equal(t, "json", cfg.Logging.Format)

	// Verify nested validation config
	assert.True(t, cfg.Validation.Strict)
	assert.True(t, cfg.Validation.SchemaValidation)
}

// TestNestedConfigDefaults tests that nested config has proper defaults.
func TestNestedConfigDefaults(t *testing.T) {
	clearEnvironment(t)

	cfg, err := LoadConfigWithViper("", viper.New())
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify display defaults
	assert.Equal(t, -1, cfg.Display.Width) // -1 means auto-detect
	assert.False(t, cfg.Display.Pager)
	assert.True(t, cfg.Display.SyntaxHighlighting)

	// Verify export defaults
	assert.Equal(t, "markdown", cfg.Export.Format)
	assert.Empty(t, cfg.Export.Directory)
	assert.Empty(t, cfg.Export.Template)
	assert.False(t, cfg.Export.Backup)

	// Verify logging defaults
	assert.Equal(t, "info", cfg.Logging.Level)
	assert.Equal(t, "text", cfg.Logging.Format)

	// Verify validation defaults
	assert.False(t, cfg.Validation.Strict)
	assert.False(t, cfg.Validation.SchemaValidation)
}

// TestNestedConfigFromEnv tests loading nested configuration from environment variables.
func TestNestedConfigFromEnv(t *testing.T) {
	clearEnvironment(t)

	t.Setenv("OPNDOSSIER_DISPLAY_WIDTH", "100")
	t.Setenv("OPNDOSSIER_DISPLAY_PAGER", "true")
	t.Setenv("OPNDOSSIER_DISPLAY_SYNTAX_HIGHLIGHTING", "false")
	t.Setenv("OPNDOSSIER_EXPORT_FORMAT", "yaml")
	t.Setenv("OPNDOSSIER_EXPORT_DIRECTORY", "/tmp/export")
	t.Setenv("OPNDOSSIER_LOGGING_LEVEL", "warn")
	t.Setenv("OPNDOSSIER_VALIDATION_STRICT", "true")

	cfg, err := LoadConfigWithViper("", viper.New())
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify nested display config from env
	assert.Equal(t, 100, cfg.Display.Width)
	assert.True(t, cfg.Display.Pager)
	assert.False(t, cfg.Display.SyntaxHighlighting)

	// Verify nested export config from env
	assert.Equal(t, "yaml", cfg.Export.Format)
	assert.Equal(t, "/tmp/export", cfg.Export.Directory)

	// Verify nested logging config from env
	assert.Equal(t, "warn", cfg.Logging.Level)

	// Verify nested validation config from env
	assert.True(t, cfg.Validation.Strict)
}

// TestBackwardCompatibilityFlatConfig tests that flat config still works for backward compatibility.
func TestBackwardCompatibilityFlatConfig(t *testing.T) {
	clearEnvironment(t)

	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.xml")
	err := os.WriteFile(inputFile, []byte("<test/>"), 0o600)
	require.NoError(t, err)

	cfgFilePath := filepath.Join(tmpDir, ".opnDossier.yaml")
	// This is the OLD flat config format - should still work
	content := fmt.Sprintf(`
input_file: %s
output_file: %s
verbose: true
quiet: false
theme: dark
format: json
wrap: 80
`, inputFile, filepath.Join(tmpDir, "output.md"))
	err = os.WriteFile(cfgFilePath, []byte(content), 0o600)
	require.NoError(t, err)

	cfg, err := LoadConfigWithViper(cfgFilePath, viper.New())
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Flat config should still work
	assert.Equal(t, inputFile, cfg.InputFile)
	assert.Equal(t, filepath.Join(tmpDir, "output.md"), cfg.OutputFile)
	assert.True(t, cfg.Verbose)
	assert.False(t, cfg.Quiet)
	assert.Equal(t, "dark", cfg.Theme)
	assert.Equal(t, "json", cfg.Format)
	assert.Equal(t, 80, cfg.WrapWidth)
}

// TestNestedConfigGetters tests the getter methods for nested config.
func TestNestedConfigGetters(t *testing.T) {
	cfg := &Config{
		Display: DisplayConfig{
			Width:              100,
			Pager:              true,
			SyntaxHighlighting: true,
		},
		Export: ExportConfig{
			Format:    "yaml",
			Directory: "/output",
			Template:  "full",
			Backup:    true,
		},
		Logging: LoggingConfig{
			Level:  "debug",
			Format: "json",
		},
		Validation: ValidationConfig{
			Strict:           true,
			SchemaValidation: true,
		},
	}

	// Test Display getters
	assert.Equal(t, 100, cfg.GetDisplayWidth())
	assert.True(t, cfg.IsDisplayPager())
	assert.True(t, cfg.IsDisplaySyntaxHighlighting())

	// Test Export getters
	assert.Equal(t, "yaml", cfg.GetExportFormat())
	assert.Equal(t, "/output", cfg.GetExportDirectory())
	assert.Equal(t, "full", cfg.GetExportTemplate())
	assert.True(t, cfg.IsExportBackup())

	// Test Logging getters
	assert.Equal(t, "debug", cfg.GetLoggingLevel())
	assert.Equal(t, "json", cfg.GetLoggingFormat())

	// Test Validation getters
	assert.True(t, cfg.IsValidationStrict())
	assert.True(t, cfg.IsValidationSchemaValidation())
}

// TestMixedFlatAndNestedConfig tests that flat and nested configs can be mixed.
func TestMixedFlatAndNestedConfig(t *testing.T) {
	clearEnvironment(t)

	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.xml")
	err := os.WriteFile(inputFile, []byte("<test/>"), 0o600)
	require.NoError(t, err)

	cfgFilePath := filepath.Join(tmpDir, ".opnDossier.yaml")
	// Mix of flat and nested config
	content := fmt.Sprintf(`
input_file: %s
verbose: true
display:
  width: 120
logging:
  level: debug
`, inputFile)
	err = os.WriteFile(cfgFilePath, []byte(content), 0o600)
	require.NoError(t, err)

	cfg, err := LoadConfigWithViper(cfgFilePath, viper.New())
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Flat config
	assert.Equal(t, inputFile, cfg.InputFile)
	assert.True(t, cfg.Verbose)

	// Nested config
	assert.Equal(t, 120, cfg.Display.Width)
	assert.Equal(t, "debug", cfg.Logging.Level)

	// Defaults should still apply for unset nested fields
	assert.False(t, cfg.Display.Pager)
	assert.True(t, cfg.Display.SyntaxHighlighting)
}
