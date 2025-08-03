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
log_level: debug
log_format: json
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
	assert.Equal(t, "debug", cfg.LogLevel)
	assert.Equal(t, "json", cfg.LogFormat)
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
				LogLevel:   "info",
				LogFormat:  "text",
			},
			wantErr: false,
		},
		{
			name: "mutually_exclusive_verbose_quiet",
			config: Config{
				Verbose:   true,
				Quiet:     true,
				LogLevel:  "info",
				LogFormat: "text",
			},
			wantErr: false, // Validation now handled by Cobra flag validation
		},
		{
			name: "invalid_log_level",
			config: Config{
				LogLevel:  "invalid",
				LogFormat: "text",
			},
			wantErr: true,
			errMsg:  "invalid log level 'invalid'",
		},
		{
			name: "invalid_log_format",
			config: Config{
				LogLevel:  "info",
				LogFormat: "invalid",
			},
			wantErr: true,
			errMsg:  "invalid log format 'invalid'",
		},
		{
			name: "nonexistent_input_file",
			config: Config{
				InputFile: "/nonexistent/file.xml",
				LogLevel:  "info",
				LogFormat: "text",
			},
			wantErr: true,
			errMsg:  "input file does not exist",
		},
		{
			name: "nonexistent_output_directory",
			config: Config{
				OutputFile: "/nonexistent/dir/output.md",
				LogLevel:   "info",
				LogFormat:  "text",
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
		Verbose:   true,
		Quiet:     false,
		LogLevel:  "debug",
		LogFormat: "json",
	}

	assert.True(t, cfg.IsVerbose())
	assert.False(t, cfg.IsQuiet())
	assert.Equal(t, "debug", cfg.GetLogLevel())
	assert.Equal(t, "json", cfg.GetLogFormat())
}

func TestLoadConfigFromEnvWithNewFields(t *testing.T) {
	// Clear environment variables for this test
	clearEnvironment(t)

	// Set environment variables for new fields
	t.Setenv("OPNDOSSIER_QUIET", "true")
	t.Setenv("OPNDOSSIER_LOG_LEVEL", "warn")
	t.Setenv("OPNDOSSIER_LOG_FORMAT", "json")

	cfg, err := LoadConfigWithViper("", viper.New())
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.True(t, cfg.Quiet)
	assert.Equal(t, "warn", cfg.LogLevel)
	assert.Equal(t, "json", cfg.LogFormat)
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
	t.Setenv("OPNDOSSIER_LOG_LEVEL", "debug")
	t.Setenv("OPNDOSSIER_LOG_FORMAT", "json")
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
	assert.Equal(t, "debug", cfg.LogLevel)
	assert.Equal(t, "json", cfg.LogFormat)
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
		"OPNDOSSIER_LOG_LEVEL",
		"OPNDOSSIER_LOG_FORMAT",
		"OPNDOSSIER_THEME",
		"OPNDOSSIER_FORMAT",
		"OPNDOSSIER_TEMPLATE",
		"OPNDOSSIER_SECTIONS",
		"OPNDOSSIER_WRAP",
	}

	for _, env := range envVars {
		_ = os.Unsetenv(env)
	}
}
