// Package config provides application configuration management.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// Config holds the configuration for the opnDossier application.
type Config struct {
	InputFile   string   `mapstructure:"input_file"`
	OutputFile  string   `mapstructure:"output_file"`
	Verbose     bool     `mapstructure:"verbose"`
	Quiet       bool     `mapstructure:"quiet"`
	Theme       string   `mapstructure:"theme"`
	Format      string   `mapstructure:"format"`
	Template    string   `mapstructure:"template"`
	Sections    []string `mapstructure:"sections"`
	WrapWidth   int      `mapstructure:"wrap"`
	Engine      string   `mapstructure:"engine"`       // Generation engine (programmatic, template)
	UseTemplate bool     `mapstructure:"use_template"` // Explicitly enable template mode
	JSONOutput  bool     `mapstructure:"json_output"`  // Output errors in JSON format
	Minimal     bool     `mapstructure:"minimal"`      // Minimal output mode
	NoProgress  bool     `mapstructure:"no_progress"`  // Disable progress indicators
}

// LoadConfig loads application configuration from the specified YAML file, environment variables, and defaults.
// If cfgFile is empty, it attempts to load from a default config file location.
// LoadConfig loads application configuration from a YAML file, environment variables, and defaults using a new Viper instance.
// Returns a populated Config struct or an error if loading or validation fails.
func LoadConfig(cfgFile string) (*Config, error) {
	return LoadConfigWithViper(cfgFile, viper.New())
}

// LoadConfigWithFlags loads configuration with CLI flag binding for proper precedence.
// LoadConfigWithFlags loads configuration using a config file and a set of CLI flags, ensuring that flag values take precedence over other sources.
// Returns the populated Config struct or an error if loading or validation fails.
func LoadConfigWithFlags(cfgFile string, flags *pflag.FlagSet) (*Config, error) {
	v := viper.New()

	// Bind flags to viper for proper precedence
	if flags != nil {
		if err := v.BindPFlags(flags); err != nil {
			return nil, fmt.Errorf("failed to bind flags: %w", err)
		}
	}

	return LoadConfigWithViper(cfgFile, v)
}

// LoadConfigWithViper loads the configuration using a provided Viper instance.
// LoadConfigWithViper loads application configuration using the provided Viper instance, applying defaults, config file values, and environment variables with standard precedence.
// LoadConfigWithViper loads application configuration using the provided Viper instance, merging values from a config file, environment variables with the "OPNDOSSIER" prefix, and defaults.
// If a config file path is specified, it is used; otherwise, a default YAML file in the user's home directory is attempted. If the config file is missing, environment variables and defaults are used.
// LoadConfigWithViper loads application configuration from a YAML file, environment variables, and defaults using the provided Viper instance.
// It returns a validated Config struct or an error if loading or validation fails.
// If the specified config file is missing, environment variables and defaults are used instead.
func LoadConfigWithViper(cfgFile string, v *viper.Viper) (*Config, error) {
	// Set defaults
	v.SetDefault("input_file", "")
	v.SetDefault("output_file", "")
	v.SetDefault("verbose", false)
	v.SetDefault("quiet", false)
	v.SetDefault("theme", "")
	v.SetDefault("format", "markdown")
	v.SetDefault("template", "")
	v.SetDefault("sections", []string{})
	v.SetDefault("wrap", -1)
	v.SetDefault("engine", "programmatic") // Default to programmatic mode
	v.SetDefault("use_template", false)
	v.SetDefault("json_output", false)
	v.SetDefault("minimal", false)
	v.SetDefault("no_progress", false)

	// Set up environment variable handling
	v.SetEnvPrefix("OPNDOSSIER")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	// Configure config file settings
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get user home directory: %w", err)
		}

		v.AddConfigPath(home)
		v.SetConfigType("yaml")
		v.SetConfigName(".opnDossier")
	}

	// Read config file if it exists
	if err := v.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if !errors.As(err, &configFileNotFoundError) {
			// Return error only for non-config-file-not-found errors
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// If config file not found, that's okay - we can still use env vars and defaults
	}

	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Normalize engine value after loading
	if cfg.Engine != "" {
		normalizedEngine := strings.ToLower(strings.TrimSpace(cfg.Engine))
		cfg.Engine = normalizedEngine
		// Update the viper instance to reflect the normalized value
		v.Set("engine", normalizedEngine)
	}

	// Validate the configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

// ValidationError represents a configuration validation error.
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s", e.Field, e.Message)
}

// Validate validates the configuration for consistency and correctness.
func (c *Config) Validate() error {
	// Normalize engine value before validation
	if c.Engine != "" {
		c.Engine = strings.ToLower(strings.TrimSpace(c.Engine))
	}

	var validationErrors []ValidationError

	validateFlags(c, &validationErrors)
	validateInputFile(c, &validationErrors)
	validateOutputFile(c, &validationErrors)
	validateTheme(c, &validationErrors)
	validateFormat(c, &validationErrors)
	validateWrapWidth(c, &validationErrors)
	validateEngine(c, &validationErrors)

	// Return combined validation errors
	if len(validationErrors) > 0 {
		return combineValidationErrors(validationErrors)
	}

	return nil
}

func validateFlags(_ *Config, _ *[]ValidationError) {
	// Validate flags
	// Note: Verbose/quiet mutual exclusivity is handled by Cobra flag validation
	// No additional validation needed here
}

func validateInputFile(c *Config, validationErrors *[]ValidationError) {
	// Validate input file exists if specified
	if c.InputFile != "" {
		if _, err := os.Stat(c.InputFile); os.IsNotExist(err) {
			*validationErrors = append(*validationErrors, ValidationError{
				Field:   "input_file",
				Message: "input file does not exist: " + c.InputFile,
			})
		} else if err != nil {
			*validationErrors = append(*validationErrors, ValidationError{
				Field:   "input_file",
				Message: fmt.Sprintf("failed to check input file: %v", err),
			})
		}
	}
}

func validateOutputFile(c *Config, validationErrors *[]ValidationError) {
	// Validate output file directory exists if specified
	if c.OutputFile != "" {
		dir := filepath.Dir(c.OutputFile)
		if dir != "." && dir != "" {
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				*validationErrors = append(*validationErrors, ValidationError{
					Field:   "output_file",
					Message: "output directory does not exist: " + dir,
				})
			} else if err != nil {
				*validationErrors = append(*validationErrors, ValidationError{
					Field:   "output_file",
					Message: fmt.Sprintf("failed to check output directory: %v", err),
				})
			}
		}
	}
}

func validateTheme(c *Config, validationErrors *[]ValidationError) {
	// Validate theme
	validThemes := map[string]bool{
		"":       true, // Empty means auto-detect
		"light":  true,
		"dark":   true,
		"custom": true,
		"auto":   true,
		"none":   true,
	}
	if !validThemes[c.Theme] {
		*validationErrors = append(*validationErrors, ValidationError{
			Field: "theme",
			Message: fmt.Sprintf(
				"invalid theme '%s', must be one of: light, dark, custom, auto, none (or empty for auto-detect)",
				c.Theme,
			),
		})
	}
}

func validateFormat(c *Config, validationErrors *[]ValidationError) {
	// Validate format
	validFormats := map[string]bool{
		"markdown": true,
		"md":       true,
		"json":     true,
		"yaml":     true,
		"yml":      true,
	}
	if c.Format != "" && !validFormats[c.Format] {
		*validationErrors = append(*validationErrors, ValidationError{
			Field:   "format",
			Message: fmt.Sprintf("invalid format '%s', must be one of: markdown, md, json, yaml, yml", c.Format),
		})
	}
}

func validateWrapWidth(c *Config, validationErrors *[]ValidationError) {
	// Validate wrap width (-1 means auto-detect)
	if c.WrapWidth < -1 {
		*validationErrors = append(*validationErrors, ValidationError{
			Field:   "wrap",
			Message: fmt.Sprintf("wrap width must be -1 (auto-detect), 0 (no wrapping), or positive: %d", c.WrapWidth),
		})
	}
}

func validateEngine(c *Config, validationErrors *[]ValidationError) {
	// Validate generation engine
	validEngines := map[string]bool{
		"":             true, // Empty means default (programmatic)
		"programmatic": true,
		"template":     true,
	}

	if c.Engine != "" && !validEngines[c.Engine] {
		*validationErrors = append(*validationErrors, ValidationError{
			Field: "engine",
			Message: fmt.Sprintf(
				"invalid engine '%s', must be one of: programmatic, template (or empty for default)",
				c.Engine,
			),
		})
	}
}

func combineValidationErrors(validationErrors []ValidationError) error {
	var sb strings.Builder
	for i, err := range validationErrors {
		if i > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(err.Error())
	}

	return &ValidationError{
		Field:   "config",
		Message: sb.String(),
	}
}

// IsVerbose returns true if verbose logging is enabled.
func (c *Config) IsVerbose() bool {
	return c.Verbose
}

// IsQuiet returns true if quiet mode is enabled.
func (c *Config) IsQuiet() bool {
	return c.Quiet
}

// GetTheme returns the configured theme.
func (c *Config) GetTheme() string {
	return c.Theme
}

// GetFormat returns the configured output format.
func (c *Config) GetFormat() string {
	return c.Format
}

// GetTemplate returns the configured template name.
func (c *Config) GetTemplate() string {
	return c.Template
}

// GetSections returns the configured sections to include.
func (c *Config) GetSections() []string {
	return c.Sections
}

// GetWrapWidth returns the configured wrap width.
func (c *Config) GetWrapWidth() int {
	return c.WrapWidth
}

// GetEngine returns the configured generation engine.
func (c *Config) GetEngine() string {
	return c.Engine
}

// IsUseTemplate returns true if template mode is explicitly enabled.
func (c *Config) IsUseTemplate() bool {
	return c.UseTemplate
}

// IsJSONOutput returns true if JSON output mode is enabled.
func (c *Config) IsJSONOutput() bool {
	return c.JSONOutput
}

// IsMinimal returns true if minimal output mode is enabled.
func (c *Config) IsMinimal() bool {
	return c.Minimal
}

// IsNoProgress returns true if progress indicators should be disabled.
func (c *Config) IsNoProgress() bool {
	return c.NoProgress
}
