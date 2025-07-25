package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestLoadConfigFromFile(t *testing.T) {
	// Clear environment variables for this test
	_ = os.Unsetenv("OPNFOCUS_INPUT_FILE")  //nolint:errcheck // Test cleanup
	_ = os.Unsetenv("OPNFOCUS_OUTPUT_FILE") //nolint:errcheck // Test cleanup
	_ = os.Unsetenv("OPNFOCUS_VERBOSE")     //nolint:errcheck // Test cleanup

	// Create a temporary config file
	tmpDir := t.TempDir()
	cfgFilePath := filepath.Join(tmpDir, ".opnFocus.yaml")
	content := `
input_file: /tmp/input.xml
output_file: /tmp/output.md
verbose: true
`
	err := os.WriteFile(cfgFilePath, []byte(content), 0o600)
	assert.NoError(t, err)

	// Test loading from file
	cfg, err := LoadConfigWithViper(cfgFilePath, viper.New())
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, "/tmp/input.xml", cfg.InputFile)
	assert.Equal(t, "/tmp/output.md", cfg.OutputFile)
	assert.True(t, cfg.Verbose)
}

func TestLoadConfigFromEnv(t *testing.T) {
	// Clear environment variables for this test
	_ = os.Unsetenv("OPNFOCUS_INPUT_FILE")  //nolint:errcheck // Test cleanup
	_ = os.Unsetenv("OPNFOCUS_OUTPUT_FILE") //nolint:errcheck // Test cleanup
	_ = os.Unsetenv("OPNFOCUS_VERBOSE")     //nolint:errcheck // Test cleanup

	t.Setenv("OPNFOCUS_INPUT_FILE", "/env/input.xml")
	t.Setenv("OPNFOCUS_VERBOSE", "false")

	cfg, err := LoadConfigWithViper("", viper.New()) // Load without a specific file to pick up env vars
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, "/env/input.xml", cfg.InputFile)
	assert.Equal(t, "", cfg.OutputFile) // Should not be overridden by env var
	assert.False(t, cfg.Verbose)
}

func TestLoadConfigPrecedence(t *testing.T) {
	// Clear environment variables for this test
	_ = os.Unsetenv("OPNFOCUS_INPUT_FILE")  //nolint:errcheck // Test cleanup
	_ = os.Unsetenv("OPNFOCUS_OUTPUT_FILE") //nolint:errcheck // Test cleanup
	_ = os.Unsetenv("OPNFOCUS_VERBOSE")     //nolint:errcheck // Test cleanup

	// Create a temporary config file
	tmpDir := t.TempDir()
	cfgFilePath := filepath.Join(tmpDir, ".opnFocus.yaml")
	content := `
input_file: /tmp/input.xml
output_file: /tmp/output.md
verbose: true
`
	err := os.WriteFile(cfgFilePath, []byte(content), 0o600)
	assert.NoError(t, err)

	t.Setenv("OPNFOCUS_INPUT_FILE", "/env/input.xml")
	t.Setenv("OPNFOCUS_VERBOSE", "false")

	// Environment variables should override config file values (standard precedence)
	cfg, err := LoadConfigWithViper(cfgFilePath, viper.New())
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, "/env/input.xml", cfg.InputFile)  // Environment variable should win
	assert.Equal(t, "/tmp/output.md", cfg.OutputFile) // Config file value (no env var set)
	assert.False(t, cfg.Verbose)                      // Environment variable should win
}
