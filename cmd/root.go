package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/unclesp1d3r/opnFocus/internal/config"
	"github.com/unclesp1d3r/opnFocus/internal/constants"
	"github.com/unclesp1d3r/opnFocus/internal/log"
)

var (
	cfgFile string //nolint:gochecknoglobals // CLI config file path
	// Cfg holds the application's configuration, loaded from file, environment, or flags.
	Cfg    *config.Config //nolint:gochecknoglobals // Application configuration
	logger *log.Logger    //nolint:gochecknoglobals // Application logger

	// Build information injected by GoReleaser via ldflags.
	buildDate = "unknown"
	gitCommit = "unknown"
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

WORKFLOW EXAMPLES:
  # Basic conversion workflow
  opnFocus convert config.xml -o documentation.md

  # Audit workflow with compliance checks
  opnFocus convert config.xml --mode blue --plugins stig,sans

  # Development workflow with verbose logging
  opnFocus --verbose convert config.xml --format json

  # Configuration management workflow
  OPNFOCUS_LOG_LEVEL=debug opnFocus convert config.xml --theme dark

  # Template customization workflow
  opnFocus convert config.xml --template-dir ~/.opnFocus/templates --template detailed

  # Compliance workflow
  opnFocus convert config.xml --mode blue --plugins stig,sans --comprehensive`,
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

	// Configuration flags
	rootCmd.PersistentFlags().
		StringVar(&cfgFile, "config", "", "Configuration file path (default: $HOME/.opnFocus.yaml)")
	setFlagAnnotation(rootCmd.PersistentFlags(), "config", []string{"configuration"})

	// Output control flags
	rootCmd.PersistentFlags().
		BoolP("verbose", "v", false, "Enable verbose output with debug-level logging for detailed troubleshooting")
	setFlagAnnotation(rootCmd.PersistentFlags(), "verbose", []string{"output"})
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "Suppress all output except errors and critical messages")
	setFlagAnnotation(rootCmd.PersistentFlags(), "quiet", []string{"output"})

	// Logging configuration flags
	rootCmd.PersistentFlags().
		String("log_level", "info", "Set logging level (debug, info, warn, error) for detailed output control")
	setFlagAnnotation(rootCmd.PersistentFlags(), "log_level", []string{"logging"})
	rootCmd.PersistentFlags().String("log_format", "text", "Set log output format (text, json) for structured logging")
	setFlagAnnotation(rootCmd.PersistentFlags(), "log_format", []string{"logging"})

	// Display configuration flags
	rootCmd.PersistentFlags().
		String("theme", "", "Set display theme (light, dark, auto, none) for terminal output styling")
	setFlagAnnotation(rootCmd.PersistentFlags(), "theme", []string{"display"})

	// Flag groups for better organization
	rootCmd.PersistentFlags().SortFlags = false

	// Mark mutually exclusive flags
	// Verbose and quiet are mutually exclusive
	rootCmd.MarkFlagsMutuallyExclusive("verbose", "quiet")

	// Add version command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Display version information",
		Long:  "Display the current version of opnFocus and build information.",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("opnFocus version %s\n", constants.Version)
			fmt.Printf("Build date: %s\n", getBuildDate())
			fmt.Printf("Git commit: %s\n", getGitCommit())
		},
	})

	// Add command groups for better organization
	rootCmd.AddGroup(&cobra.Group{
		ID:    "core",
		Title: "Core Commands",
	})
	rootCmd.AddGroup(&cobra.Group{
		ID:    "audit",
		Title: "Audit & Compliance",
	})
	rootCmd.AddGroup(&cobra.Group{
		ID:    "utility",
		Title: "Utility Commands",
	})
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

// GetFlagsByCategory returns flags grouped by their category annotation.
// This demonstrates how flag annotations can be used for programmatic flag management.
func GetFlagsByCategory(cmd *cobra.Command) map[string][]string {
	categories := make(map[string][]string)

	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if category, ok := flag.Annotations["category"]; ok && len(category) > 0 {
			cat := category[0]
			categories[cat] = append(categories[cat], flag.Name)
		}
	})

	return categories
}

// setFlagAnnotation safely sets a flag annotation and logs any errors.
func setFlagAnnotation(flags *pflag.FlagSet, flagName string, values []string) {
	if err := flags.SetAnnotation(flagName, "category", values); err != nil {
		// In init functions, we can't return errors, so we log them
		// This should never happen with valid flag names
		logger.Error("failed to set flag annotation", "flag", flagName, "error", err)
	}
}

// getBuildDate returns the build date from ldflags or a default value.
func getBuildDate() string {
	return buildDate
}

// getGitCommit returns the git commit from ldflags or a default value.
func getGitCommit() string {
	return gitCommit
}
