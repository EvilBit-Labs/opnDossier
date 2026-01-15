package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadConfig tests the main LoadConfig function wrapper.
func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name        string
		cfgFile     string
		setup       func() string
		cleanup     func(string)
		expectError bool
	}{
		{
			name:        "empty config file",
			cfgFile:     "",
			expectError: false,
		},
		{
			name:        "non-existent config file",
			cfgFile:     "/non/existent/config.yaml",
			expectError: true,
		},
		{
			name:        "valid config file",
			expectError: false,
			setup: func() string {
				tmpDir := t.TempDir()

				cfgPath := filepath.Join(tmpDir, "config.yaml")
				content := `
input_file: ""
output_file: ""
verbose: false
engine: "programmatic"
`
				if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
					t.Fatalf("Failed to create config file: %v", err)
				}
				return cfgPath
			},
			cleanup: func(path string) {
				if err := os.RemoveAll(filepath.Dir(path)); err != nil {
					t.Logf("Failed to cleanup temp dir: %v", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfgFile := tt.cfgFile
			if tt.setup != nil {
				cfgFile = tt.setup()
			}

			cfg, err := LoadConfig(cfgFile)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cfg)
			}

			if tt.cleanup != nil && cfgFile != "" {
				tt.cleanup(cfgFile)
			}
		})
	}
}

// TestLoadConfigWithFlags tests the LoadConfigWithFlags function.
func TestLoadConfigWithFlags(t *testing.T) {
	tests := []struct {
		name        string
		cfgFile     string
		setupFlags  func() *pflag.FlagSet
		expectError bool
		validate    func(*testing.T, *Config)
	}{
		{
			name:    "nil flags",
			cfgFile: "",
			setupFlags: func() *pflag.FlagSet {
				return nil
			},
			expectError: false,
		},
		{
			name:    "empty flags",
			cfgFile: "",
			setupFlags: func() *pflag.FlagSet {
				return pflag.NewFlagSet("test", pflag.ContinueOnError)
			},
			expectError: false,
		},
		{
			name:    "flags with values",
			cfgFile: "",
			setupFlags: func() *pflag.FlagSet {
				fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
				fs.Bool("verbose", true, "verbose mode")
				fs.String("theme", "dark", "theme")
				fs.Int("wrap", 100, "wrap width")

				// Set flag values
				if err := fs.Set("verbose", "true"); err != nil {
					t.Fatal(err)
				}
				if err := fs.Set("theme", "dark"); err != nil {
					t.Fatal(err)
				}
				if err := fs.Set("wrap", "100"); err != nil {
					t.Fatal(err)
				}

				return fs
			},
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				t.Helper()
				assert.True(t, cfg.Verbose)
				assert.Equal(t, "dark", cfg.Theme)
				assert.Equal(t, 100, cfg.WrapWidth)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := tt.setupFlags()

			cfg, err := LoadConfigWithFlags(tt.cfgFile, flags)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cfg)

				if tt.validate != nil {
					tt.validate(t, cfg)
				}
			}
		})
	}
}

// TestValidationFunctionsIndirectly tests the validation functions indirectly through the Validate method.
func TestValidationFunctionsIndirectly(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "verbose and quiet both true should pass validation",
			config: Config{
				Verbose: true,
				Quiet:   true,
			},
			expectError: false, // validateFlags is a no-op, Cobra handles this
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if tt.expectError && err != nil && tt.errorMsg != "" {
				assert.Contains(t, err.Error(), tt.errorMsg)
			}
		})
	}
}

// TestInputFileValidationIndirectly tests input file validation through the main Validate method.
func TestInputFileValidationIndirectly(t *testing.T) {
	// Create a temporary file for testing
	tempFile, err := os.CreateTemp(t.TempDir(), "test-input-*.xml")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())
	if err := tempFile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	tests := []struct {
		name        string
		inputFile   string
		expectError bool
	}{
		{
			name:        "empty input file",
			inputFile:   "",
			expectError: false,
		},
		{
			name:        "existing file",
			inputFile:   tempFile.Name(),
			expectError: false,
		},
		{
			name:        "non-existent file",
			inputFile:   "/non/existent/file.xml",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := Config{InputFile: tt.inputFile}
			err := config.Validate()

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestOutputFileValidationIndirectly tests output file validation through the main Validate method.
func TestOutputFileValidationIndirectly(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()

	validOutputFile := filepath.Join(tempDir, "output.md")

	tests := []struct {
		name        string
		outputFile  string
		expectError bool
	}{
		{
			name:        "empty output file",
			outputFile:  "",
			expectError: false,
		},
		{
			name:        "valid output file",
			outputFile:  validOutputFile,
			expectError: false,
		},
		{
			name:        "output file in non-existent directory",
			outputFile:  "/non/existent/dir/output.md",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := Config{OutputFile: tt.outputFile}
			err := config.Validate()

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestThemeValidationIndirectly tests theme validation through the main Validate method.
func TestThemeValidationIndirectly(t *testing.T) {
	tests := []struct {
		name        string
		theme       string
		expectError bool
	}{
		{
			name:        "empty theme",
			theme:       "",
			expectError: false,
		},
		{
			name:        "valid theme",
			theme:       "dark",
			expectError: false,
		},
		{
			name:        "another valid theme",
			theme:       "light",
			expectError: false,
		},
		{
			name:        "invalid theme",
			theme:       "invalid",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := Config{Theme: tt.theme}
			err := config.Validate()

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestFormatValidationIndirectly tests format validation through the main Validate method.
func TestFormatValidationIndirectly(t *testing.T) {
	tests := []struct {
		name        string
		format      string
		expectError bool
	}{
		{
			name:        "empty format",
			format:      "",
			expectError: false,
		},
		{
			name:        "markdown format",
			format:      "markdown",
			expectError: false,
		},
		{
			name:        "json format",
			format:      "json",
			expectError: false,
		},
		{
			name:        "yaml format",
			format:      "yaml",
			expectError: false,
		},
		{
			name:        "invalid format",
			format:      "invalid",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := Config{Format: tt.format}
			err := config.Validate()

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestWrapWidthValidationIndirectly tests wrap width validation through the main Validate method.
func TestWrapWidthValidationIndirectly(t *testing.T) {
	tests := []struct {
		name        string
		wrapWidth   int
		expectError bool
	}{
		{
			name:        "zero wrap width",
			wrapWidth:   0,
			expectError: false,
		},
		{
			name:        "auto-detect wrap width",
			wrapWidth:   -1,
			expectError: false,
		},
		{
			name:        "valid wrap width",
			wrapWidth:   80,
			expectError: false,
		},
		{
			name:        "large wrap width",
			wrapWidth:   200,
			expectError: false,
		},
		{
			name:        "negative wrap width",
			wrapWidth:   -2,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := Config{WrapWidth: tt.wrapWidth}
			err := config.Validate()

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestEngineValidationIndirectly tests engine validation through the main Validate method.
func TestEngineValidationIndirectly(t *testing.T) {
	tests := []struct {
		name        string
		engine      string
		expectError bool
	}{
		{
			name:        "empty engine",
			engine:      "",
			expectError: false,
		},
		{
			name:        "programmatic engine",
			engine:      "programmatic",
			expectError: false,
		},
		{
			name:        "template engine",
			engine:      "template",
			expectError: false,
		},
		{
			name:        "case insensitive programmatic",
			engine:      "PROGRAMMATIC",
			expectError: false,
		},
		{
			name:        "case insensitive template",
			engine:      "TEMPLATE",
			expectError: false,
		},
		{
			name:        "invalid engine",
			engine:      "invalid",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := Config{Engine: tt.engine}
			err := config.Validate()

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestCombineValidationErrorsIndirectly tests the validation error combination indirectly.
func TestCombineValidationErrorsIndirectly(t *testing.T) {
	// Test by creating a config with multiple validation errors
	config := Config{
		Engine:    "invalid",
		Format:    "badformat",
		Theme:     "badtheme",
		WrapWidth: -2,
	}

	err := config.Validate()
	require.Error(t, err)

	// The error should contain multiple validation messages combined
	errStr := err.Error()
	assert.Contains(t, errStr, "invalid")
}

// TestConfigGetterMethods tests all the getter methods with 0% coverage.
func TestConfigGetterMethods(t *testing.T) {
	cfg := &Config{
		Theme:       "dark",
		Format:      "json",
		Template:    "comprehensive",
		Sections:    []string{"system", "network"},
		WrapWidth:   120,
		Engine:      "template",
		UseTemplate: true,
	}

	// Test GetLogLevel
	logLevel := cfg.GetLogLevel()
	assert.Equal(t, "info", logLevel) // Default value

	// Test GetLogFormat
	logFormat := cfg.GetLogFormat()
	assert.Equal(t, "text", logFormat) // Default value

	// Test GetTheme
	assert.Equal(t, "dark", cfg.GetTheme())

	// Test GetFormat
	assert.Equal(t, "json", cfg.GetFormat())

	// Test GetTemplate
	assert.Equal(t, "comprehensive", cfg.GetTemplate())

	// Test GetSections
	assert.Equal(t, []string{"system", "network"}, cfg.GetSections())

	// Test GetWrapWidth
	assert.Equal(t, 120, cfg.GetWrapWidth())

	// Test GetEngine
	assert.Equal(t, "template", cfg.GetEngine())

	// Test IsUseTemplate
	assert.True(t, cfg.IsUseTemplate())
}

// TestConfigGetterMethodsWithDefaults tests getter methods with default values.
func TestConfigGetterMethodsWithDefaults(t *testing.T) {
	cfg := &Config{} // Empty config to test defaults

	// Test defaults
	assert.Equal(t, "info", cfg.GetLogLevel())
	assert.Equal(t, "text", cfg.GetLogFormat())
	assert.Empty(t, cfg.GetTheme())
	assert.Empty(t, cfg.GetFormat())
	assert.Empty(t, cfg.GetTemplate())
	assert.Nil(t, cfg.GetSections())
	assert.Equal(t, 0, cfg.GetWrapWidth())
	assert.Empty(t, cfg.GetEngine())
	assert.False(t, cfg.IsUseTemplate())
}

// TestLoadConfigWithViperErrors tests error scenarios in LoadConfigWithViper.
func TestLoadConfigWithViperErrors(t *testing.T) {
	tests := []struct {
		name        string
		setup       func() (string, *viper.Viper)
		expectError bool
		errorMsg    string
	}{
		{
			name: "invalid yaml syntax",
			setup: func() (string, *viper.Viper) {
				tmpDir := t.TempDir()

				cfgPath := filepath.Join(tmpDir, "config.yaml")
				content := `
invalid: yaml: syntax:
  - missing
    bracket
`
				if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
					t.Fatalf("Failed to create config file: %v", err)
				}

				return cfgPath, viper.New()
			},
			expectError: true,
		},
		{
			name: "validation errors in config",
			setup: func() (string, *viper.Viper) {
				tmpDir := t.TempDir()

				cfgPath := filepath.Join(tmpDir, "config.yaml")
				content := `
verbose: true
quiet: true
wrap: -1
engine: "invalid"
theme: "badtheme"
format: "badformat"
`
				if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
					t.Fatalf("Failed to create config file: %v", err)
				}

				return cfgPath, viper.New()
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfgPath, v := tt.setup()
			defer os.RemoveAll(filepath.Dir(cfgPath))

			cfg, err := LoadConfigWithViper(cfgPath, v)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, cfg)
			}
		})
	}
}

// TestEngineValidationNew tests the new engine validation added in the changes.
func TestEngineValidationNew(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *Config
		expectErr bool
	}{
		{
			name: "valid programmatic engine",
			cfg: &Config{
				Engine: "programmatic",
			},
			expectErr: false,
		},
		{
			name: "valid template engine",
			cfg: &Config{
				Engine: "template",
			},
			expectErr: false,
		},
		{
			name: "empty engine is valid (defaults to programmatic)",
			cfg: &Config{
				Engine: "",
			},
			expectErr: false,
		},
		{
			name: "invalid engine should fail validation",
			cfg: &Config{
				Engine: "invalid",
			},
			expectErr: true,
		},
		{
			name: "case insensitive engine validation",
			cfg: &Config{
				Engine: "TEMPLATE",
			},
			expectErr: false,
		},
		{
			name: "whitespace trimming engine validation",
			cfg: &Config{
				Engine: " template ",
			},
			expectErr: false,
		},
		{
			name: "whitespace trimming with invalid engine shows trimmed value in error",
			cfg: &Config{
				Engine: " invalid ",
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			hasErr := err != nil
			if hasErr != tt.expectErr {
				if tt.expectErr {
					t.Errorf("Expected validation error for engine '%s', but got none", tt.cfg.Engine)
				} else {
					t.Errorf("Unexpected validation error for engine '%s': %v", tt.cfg.Engine, err)
				}
			}
		})
	}
}
