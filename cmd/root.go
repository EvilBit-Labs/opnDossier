package cmd

import (
	"fmt"
	"os"

	"github.com/unclesp1d3r/opnFocus/internal/config"
	"github.com/unclesp1d3r/opnFocus/internal/log"

	"github.com/spf13/cobra"
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
		logger = log.New(log.Config{
			Level:           logLevel,
			Format:          logFormat,
			Output:          os.Stderr,
			ReportCaller:    true,
			ReportTimestamp: true,
		})

		return nil
	},
}

// init initializes the global logger and sets up persistent CLI flags for configuration file, verbose output, and quiet mode.
func init() {
	// Initialize logger with default configuration before config is loaded
	logger = log.New(log.Config{
		Level:           "info",
		Format:          "text",
		Output:          os.Stderr,
		ReportCaller:    true,
		ReportTimestamp: true,
	})

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.opnFocus.yaml)")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output (debug logging)")
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "Suppress all output except errors")
	rootCmd.PersistentFlags().String("log_level", "info", "Set log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().String("log_format", "text", "Set log format (text, json)")
}

// GetRootCmd returns the root Cobra command for the opnFocus CLI application. Use this to access the application's main command and its subcommands.
func GetRootCmd() *cobra.Command {
	return rootCmd
}

// GetLogger returns the current application logger instance.
// This allows other packages to access the centrally configured logger.
func GetLogger() *log.Logger {
	return logger
}

// GetConfig returns the current application configuration instance.
// This allows sub-commands to access the configured Cfg via dependency injection.
func GetConfig() *config.Config {
	return Cfg
}
