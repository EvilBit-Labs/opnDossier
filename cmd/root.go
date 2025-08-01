package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/unclesp1d3r/opnFocus/internal/config"
	"github.com/unclesp1d3r/opnFocus/internal/log"
)

var (
	cfgFile string //nolint:gochecknoglobals // CLI config file path
	// Cfg holds the application's configuration, loaded from file, environment, or flags.
	Cfg    *config.Config //nolint:gochecknoglobals // Application configuration
	logger *log.Logger    //nolint:gochecknoglobals // Application logger
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra root command
	Use:   "opnFocus",
	Short: "opnFocus: A CLI tool for processing OPNsense configuration files.",
	Long: `opnFocus is a command-line interface (CLI) tool designed to process OPNsense firewall
configuration files (config.xml) and convert them into human-readable formats,
primarily Markdown. This tool is built to assist network administrators and
security professionals in documenting, auditing, and understanding their
OPNsense configurations more effectively.

CONFIGURATION:
  Configuration uses Viper for layered settings management with this precedence:
  1. Command-line flags (highest priority)
  2. Environment variables (OPNFOCUS_*)
  3. Configuration file (~/.opnFocus.yaml)
  4. Default values (lowest priority)

  The CLI is enhanced with Fang for improved user experience including
  styled help, automatic version/completion commands, and error formatting.

Examples:
  # Convert an OPNsense config.xml to markdown and print to console
  opnFocus convert config.xml

  # Convert an OPNsense config.xml to markdown and save to a file
  opnFocus convert config.xml -o output.md

  # Use verbose logging with JSON format
  opnFocus --verbose --log_format=json convert config.xml

  # Override config file settings with environment variables
  OPNFOCUS_LOG_LEVEL=debug opnFocus convert config.xml
`,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		var err error
		// Load configuration with flag binding for proper precedence
		// Note: Fang complements Cobra for CLI enhancement
		Cfg, err = config.LoadConfigWithFlags(cfgFile, cmd.Flags())
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Initialize logger after config load with proper verbose/quiet handling
		logLevel := Cfg.GetLogLevel()
		logFormat := Cfg.GetLogFormat()

		// Honor --verbose/--quiet overrides with proper precedence
		// CLI flags > env vars > config file > defaults
		if Cfg.IsQuiet() {
			logLevel = "error"
		} else if Cfg.IsVerbose() {
			logLevel = "debug"
		}

		// Create new logger with centralized configuration
		var loggerErr error
		logger, loggerErr = log.New(log.Config{
			Level:           logLevel,
			Format:          logFormat,
			Output:          os.Stderr,
			ReportCaller:    true,
			ReportTimestamp: true,
		})
		if loggerErr != nil {
			return fmt.Errorf("failed to create logger: %w", loggerErr)
		}

		return nil
	},
}

// init initializes the global logger with default settings and registers persistent CLI flags for configuration file path, verbosity, log level, log format, and display theme. Panics if logger initialization fails.
func init() {
	// Initialize logger with default configuration before config is loaded
	var loggerErr error

	logger, loggerErr = log.New(log.Config{
		Level:           "info",
		Format:          "text",
		Output:          os.Stderr,
		ReportCaller:    true,
		ReportTimestamp: true,
	})
	if loggerErr != nil {
		// In init function, we can't return an error, so we'll panic
		// This should never happen with valid default config
		panic(fmt.Sprintf("failed to create default logger: %v", loggerErr))
	}

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.opnFocus.yaml)")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output (debug logging)")
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "Suppress all output except errors")
	rootCmd.PersistentFlags().String("log_level", "info", "Set log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().String("log_format", "text", "Set log format (text, json)")
	rootCmd.PersistentFlags().String("theme", "", "Set display theme (light, dark, custom, or empty for auto-detect)")
}

// GetRootCmd returns the root Cobra command for the opnFocus CLI application.
// This provides access to the application's main command and its subcommands for integration or extension.
func GetRootCmd() *cobra.Command {
	return rootCmd
}

// GetLogger returns the current application logger instance.
// GetLogger returns the centrally configured logger instance for use by other packages.
func GetLogger() *log.Logger {
	return logger
}

// GetConfig returns the current application configuration instance.
// GetConfig returns the current application configuration instance for use by subcommands and other packages.
func GetConfig() *config.Config {
	return Cfg
}
