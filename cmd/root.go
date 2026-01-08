package cmd

import (
	"fmt"
	"os"

	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
	Use:   "opnDossier",
	Short: "opnDossier: A CLI tool for processing OPNsense configuration files.",
	Long: `opnDossier is a command-line interface (CLI) tool designed to process OPNsense firewall
configuration files (config.xml) and convert them into human-readable formats,
primarily Markdown. This tool is built to assist network administrators and
security professionals in documenting, auditing, and understanding their
OPNsense configurations more effectively.

WORKFLOW EXAMPLES:
  # Basic conversion workflow
  opnDossier convert config.xml -o documentation.md

  # Development workflow with verbose logging
  opnDossier --verbose convert config.xml --format json

  # Configuration management workflow
  opnDossier --verbose convert config.xml --theme dark

  # Template customization workflow
  opnDossier convert config.xml --custom-template /path/to/my-template.tmpl

  # Validation workflow
  opnDossier validate config.xml && opnDossier convert config.xml -o documentation.md`,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		var err error
		// Load configuration with flag binding for proper precedence
		// Note: Fang complements Cobra for CLI enhancement
		Cfg, err = config.LoadConfigWithFlags(cfgFile, cmd.Flags())
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Initialize logger after config load with proper verbose/quiet handling
		// Determine log level based on verbose/quiet flags
		logLevel := "info"
		if Cfg.IsQuiet() {
			logLevel = "error"
		} else if Cfg.IsVerbose() {
			logLevel = "debug"
		}

		// Create new logger with centralized configuration
		var loggerErr error
		logger, loggerErr = log.New(log.Config{
			Level:           logLevel,
			Format:          "text", // Log format is hardcoded to "text" for consistency
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
		StringVar(&cfgFile, "config", "", "Configuration file path (default: $HOME/.opnDossier.yaml)")
	setFlagAnnotation(rootCmd.PersistentFlags(), "config", []string{"configuration"})

	// Output control flags
	rootCmd.PersistentFlags().
		BoolP("verbose", "v", false, "Enable verbose output with debug-level logging for detailed troubleshooting")
	setFlagAnnotation(rootCmd.PersistentFlags(), "verbose", []string{"output"})
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "Suppress all output except errors and critical messages")
	setFlagAnnotation(rootCmd.PersistentFlags(), "quiet", []string{"output"})

	// Flag groups for better organization
	rootCmd.PersistentFlags().SortFlags = false

	// Mark mutually exclusive flags
	// Verbose and quiet are mutually exclusive
	rootCmd.MarkFlagsMutuallyExclusive("verbose", "quiet")

	// Add version command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Display version information",
		Long:  "Display the current version of opnDossier and build information.",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("opnDossier version %s\n", constants.Version)
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

// GetRootCmd returns the root Cobra command for the opnDossier CLI application.
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
