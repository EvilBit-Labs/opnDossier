// Package config provides application configuration management.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// DisplayConfig holds display-related settings.
type DisplayConfig struct {
	Width              int  `mapstructure:"width"`               // Terminal width (-1 = auto-detect)
	Pager              bool `mapstructure:"pager"`               // Enable pager for output
	SyntaxHighlighting bool `mapstructure:"syntax_highlighting"` // Enable syntax highlighting
}

// ExportConfig holds export-related settings.
type ExportConfig struct {
	Format    string `mapstructure:"format"`    // Output format (markdown, json, yaml)
	Directory string `mapstructure:"directory"` // Output directory
	Template  string `mapstructure:"template"`  // Template name
	Backup    bool   `mapstructure:"backup"`    // Create backups before overwriting
}

// LoggingConfig holds logging-related settings.
type LoggingConfig struct {
	Level  string `mapstructure:"level"`  // Log level (debug, info, warn, error)
	Format string `mapstructure:"format"` // Log format (text, json)
}

// ValidationConfig holds validation-related settings.
type ValidationConfig struct {
	Strict           bool `mapstructure:"strict"`            // Enable strict validation
	SchemaValidation bool `mapstructure:"schema_validation"` // Enable XML schema validation
}

// Config holds the configuration for the opnDossier application.
type Config struct {
	// Flat fields (backward compatible)
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

	// Nested configuration sections
	Display    DisplayConfig    `mapstructure:"display"`
	Export     ExportConfig     `mapstructure:"export"`
	Logging    LoggingConfig    `mapstructure:"logging"`
	Validation ValidationConfig `mapstructure:"validation"`
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

// LoadConfigWithViper loads application configuration using the provided Viper instance.
// It merges values from a config file, environment variables with the "OPNDOSSIER" prefix, and defaults.
// Precedence order: CLI flags > environment variables > config file > defaults.
// If cfgFile is specified, that file is used; otherwise, .opnDossier.yaml in the home directory is attempted.
// If the config file is missing, environment variables and defaults are used instead.
// Returns a validated Config struct or an error if loading or validation fails.
func LoadConfigWithViper(cfgFile string, v *viper.Viper) (*Config, error) {
	// Set defaults for flat fields
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

	// Set defaults for nested display config
	v.SetDefault("display.width", -1) // -1 means auto-detect
	v.SetDefault("display.pager", false)
	v.SetDefault("display.syntax_highlighting", true)

	// Set defaults for nested export config
	v.SetDefault("export.format", "markdown")
	v.SetDefault("export.directory", "")
	v.SetDefault("export.template", "")
	v.SetDefault("export.backup", false)

	// Set defaults for nested logging config
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "text")

	// Set defaults for nested validation config
	v.SetDefault("validation.strict", false)
	v.SetDefault("validation.schema_validation", false)

	// Set up environment variable handling
	v.SetEnvPrefix("OPNDOSSIER")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	v.AutomaticEnv()

	// Bind environment variables for nested configuration keys.
	// Viper's AutomaticEnv() doesn't automatically resolve nested keys when using "_"
	// as separator in env vars, so we need to bind them explicitly.
	nestedEnvBindings := map[string]string{
		"display.width":                "DISPLAY_WIDTH",
		"display.pager":                "DISPLAY_PAGER",
		"display.syntax_highlighting":  "DISPLAY_SYNTAX_HIGHLIGHTING",
		"export.format":                "EXPORT_FORMAT",
		"export.directory":             "EXPORT_DIRECTORY",
		"export.template":              "EXPORT_TEMPLATE",
		"export.backup":                "EXPORT_BACKUP",
		"logging.level":                "LOGGING_LEVEL",
		"logging.format":               "LOGGING_FORMAT",
		"validation.strict":            "VALIDATION_STRICT",
		"validation.schema_validation": "VALIDATION_SCHEMA_VALIDATION",
	}
	for key, envSuffix := range nestedEnvBindings {
		if err := v.BindEnv(key, "OPNDOSSIER_"+envSuffix); err != nil {
			return nil, fmt.Errorf("failed to bind env var for %s: %w", key, err)
		}
	}

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

// Error returns a formatted string describing the validation error, including the field name and message.
func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s", e.Field, e.Message)
}

// Validate validates the configuration for consistency and correctness.
// It uses the comprehensive Validator for all validation checks including
// nested configuration sections.
func (c *Config) Validate() error {
	validator := NewValidator(c)
	if errs := validator.Validate(); errs != nil {
		// Convert to legacy format for backward compatibility
		return convertToLegacyError(errs)
	}
	return nil
}

// ValidateV2 validates the configuration and returns detailed MultiValidationError
// with suggestions and context for better error reporting.
func (c *Config) ValidateV2() *MultiValidationError {
	validator := NewValidator(c)
	return validator.Validate()
}

// convertToLegacyError converts MultiValidationError to a legacy ValidationError format.
func convertToLegacyError(errs *MultiValidationError) error {
	if errs == nil || !errs.HasErrors() {
		return nil
	}

	// Convert V2 errors to legacy format
	legacyErrors := make([]ValidationError, len(errs.Errors))
	for i, e := range errs.Errors {
		legacyErrors[i] = ValidationError{
			Field:   e.Field,
			Message: e.Message,
		}
	}

	return combineValidationErrors(legacyErrors)
}

// Legacy validation functions are now handled by the Validator in validation.go
// These are kept as no-ops for backward compatibility with any code that might reference them.

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

// GetDisplayWidth returns the configured display width.
func (c *Config) GetDisplayWidth() int {
	return c.Display.Width
}

// IsDisplayPager returns true if pager is enabled.
func (c *Config) IsDisplayPager() bool {
	return c.Display.Pager
}

// IsDisplaySyntaxHighlighting returns true if syntax highlighting is enabled.
func (c *Config) IsDisplaySyntaxHighlighting() bool {
	return c.Display.SyntaxHighlighting
}

// GetExportFormat returns the configured export format.
func (c *Config) GetExportFormat() string {
	return c.Export.Format
}

// GetExportDirectory returns the configured export directory.
func (c *Config) GetExportDirectory() string {
	return c.Export.Directory
}

// GetExportTemplate returns the configured export template.
func (c *Config) GetExportTemplate() string {
	return c.Export.Template
}

// IsExportBackup returns true if backup is enabled for exports.
func (c *Config) IsExportBackup() bool {
	return c.Export.Backup
}

// GetLoggingLevel returns the configured logging level.
func (c *Config) GetLoggingLevel() string {
	return c.Logging.Level
}

// GetLoggingFormat returns the configured logging format.
func (c *Config) GetLoggingFormat() string {
	return c.Logging.Format
}

// IsValidationStrict returns true if strict validation is enabled.
func (c *Config) IsValidationStrict() bool {
	return c.Validation.Strict
}

// IsValidationSchemaValidation returns true if schema validation is enabled.
func (c *Config) IsValidationSchemaValidation() bool {
	return c.Validation.SchemaValidation
}
