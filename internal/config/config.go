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

// Config holds the configuration for the opnFocus application.
type Config struct {
	InputFile  string `mapstructure:"input_file"`
	OutputFile string `mapstructure:"output_file"`
	Verbose    bool   `mapstructure:"verbose"`
	Quiet      bool   `mapstructure:"quiet"`
	LogLevel   string `mapstructure:"log_level"`
	LogFormat  string `mapstructure:"log_format"`
}

// LoadConfig loads application configuration from the specified YAML file, environment variables, and defaults.
// If cfgFile is empty, it attempts to load from a default config file location.
// Returns a populated Config struct or an error if loading fails.
func LoadConfig(cfgFile string) (*Config, error) {
	return LoadConfigWithViper(cfgFile, viper.New())
}

// LoadConfigWithFlags loads configuration with CLI flag binding for proper precedence.
// This function binds the provided flags to Viper for correct precedence handling.
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
// If a config file path is given, it is used; otherwise, the function attempts to load from a default YAML file in the user's home directory. Environment variables with the prefix "OPNFOCUS" are also read. If the config file is missing, environment variables and defaults are used instead. Returns a populated Config struct or an error if configuration loading fails.
func LoadConfigWithViper(cfgFile string, v *viper.Viper) (*Config, error) {
	// Set defaults
	v.SetDefault("input_file", "")
	v.SetDefault("output_file", "")
	v.SetDefault("verbose", false)
	v.SetDefault("quiet", false)
	v.SetDefault("log_level", "info")
	v.SetDefault("log_format", "text")

	// Set up environment variable handling
	v.SetEnvPrefix("OPNFOCUS")
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
		v.SetConfigName(".opnFocus")
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
	var validationErrors []ValidationError

	// Check for mutually exclusive verbose and quiet flags
	if c.Verbose && c.Quiet {
		validationErrors = append(validationErrors, ValidationError{
			Field:   "verbose/quiet",
			Message: "verbose and quiet options are mutually exclusive",
		})
	}

	// Validate input file exists if specified
	if c.InputFile != "" {
		if _, err := os.Stat(c.InputFile); os.IsNotExist(err) {
			validationErrors = append(validationErrors, ValidationError{
				Field:   "input_file",
				Message: "input file does not exist: " + c.InputFile,
			})
		} else if err != nil {
			validationErrors = append(validationErrors, ValidationError{
				Field:   "input_file",
				Message: fmt.Sprintf("failed to check input file: %v", err),
			})
		}
	}

	// Validate output file directory exists if specified
	if c.OutputFile != "" {
		dir := filepath.Dir(c.OutputFile)
		if dir != "." && dir != "" {
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				validationErrors = append(validationErrors, ValidationError{
					Field:   "output_file",
					Message: "output directory does not exist: " + dir,
				})
			} else if err != nil {
				validationErrors = append(validationErrors, ValidationError{
					Field:   "output_file",
					Message: fmt.Sprintf("failed to check output directory: %v", err),
				})
			}
		}
	}

	// Validate log level
	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if !validLogLevels[c.LogLevel] {
		validationErrors = append(validationErrors, ValidationError{
			Field:   "log_level",
			Message: fmt.Sprintf("invalid log level '%s', must be one of: debug, info, warn, error", c.LogLevel),
		})
	}

	// Validate log format
	validLogFormats := map[string]bool{
		"text": true,
		"json": true,
	}
	if !validLogFormats[c.LogFormat] {
		validationErrors = append(validationErrors, ValidationError{
			Field:   "log_format",
			Message: fmt.Sprintf("invalid log format '%s', must be one of: text, json", c.LogFormat),
		})
	}

	// Return combined validation errors
	if len(validationErrors) > 0 {
		var errMsg string
		for i, err := range validationErrors {
			if i > 0 {
				errMsg += "; "
			}
			errMsg += err.Error()
		}
		return errors.New(errMsg)
	}

	return nil
}

// GetLogLevel returns the configured log level.
func (c *Config) GetLogLevel() string {
	return c.LogLevel
}

// GetLogFormat returns the configured log format.
func (c *Config) GetLogFormat() string {
	return c.LogFormat
}

// IsVerbose returns true if verbose logging is enabled.
func (c *Config) IsVerbose() bool {
	return c.Verbose
}

// IsQuiet returns true if quiet mode is enabled.
func (c *Config) IsQuiet() bool {
	return c.Quiet
}
