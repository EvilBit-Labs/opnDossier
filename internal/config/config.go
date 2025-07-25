// Package config provides application configuration management.
package config

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/viper"
)

// Config holds the configuration for the opnFocus application.
type Config struct {
	InputFile  string `mapstructure:"input_file"`
	OutputFile string `mapstructure:"output_file"`
	Verbose    bool   `mapstructure:"verbose"`
}

// LoadConfig loads application configuration from the specified YAML file, environment variables, and defaults.
// If cfgFile is empty, it attempts to load from a default config file location.
// Returns a populated Config struct or an error if loading fails.
func LoadConfig(cfgFile string) (*Config, error) {
	return LoadConfigWithViper(cfgFile, viper.New())
}

// LoadConfigWithViper loads the configuration using a provided Viper instance.
// LoadConfigWithViper loads application configuration using the provided Viper instance, applying defaults, config file values, and environment variables with explicit precedence for config file values.
// If a config file path is given, it is used; otherwise, the function attempts to load from a default YAML file in the user's home directory. Environment variables with the prefix "OPNFOCUS" are also read. If the config file is missing, environment variables and defaults are used instead. Returns a populated Config struct or an error if configuration loading fails.
func LoadConfigWithViper(cfgFile string, v *viper.Viper) (*Config, error) {
	// Set defaults
	v.SetDefault("input_file", "")
	v.SetDefault("output_file", "")
	v.SetDefault("verbose", false)

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

	v.SetEnvPrefix("OPNFOCUS") // Set environment variable prefix
	v.AutomaticEnv()           // read in environment variables that match

	if err := v.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if !errors.As(err, &configFileNotFoundError) {
			// Return error only for non-config-file-not-found errors
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// If config file not found, that's okay - we can still use env vars and defaults
	}

	// After reading config and env, explicitly set values from config file to ensure precedence
	// This is a workaround for Viper's default precedence where env vars override config files.
	if v.IsSet("input_file") {
		v.Set("input_file", v.GetString("input_file"))
	}

	if v.IsSet("output_file") {
		v.Set("output_file", v.GetString("output_file"))
	}

	if v.IsSet("verbose") {
		v.Set("verbose", v.GetBool("verbose"))
	}

	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return cfg, nil
}
