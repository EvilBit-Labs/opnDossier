package cmd

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	charmLog "github.com/charmbracelet/log"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	cfgFile string          //nolint:gochecknoglobals // CLI config file path
	cfg     *config.Config  //nolint:gochecknoglobals // Application configuration (internal)
	logger  *logging.Logger //nolint:gochecknoglobals // Application logger (internal)

	// Build information injected by GoReleaser via ldflags.
	buildDate = "unknown"
	gitCommit = "unknown"
)

// defaultLoggerConfig provides the initial logger configuration used during init.
// It is defined as a variable to allow fault injection in tests.
var defaultLoggerConfig = logging.Config{ //nolint:gochecknoglobals // test override hook
	Level:           "info",
	Format:          "text",
	Output:          os.Stderr,
	ReportCaller:    true,
	ReportTimestamp: true,
}

// lightweightCommands lists command names that don't need full initialization.
// These commands skip config file loading and heavy logger setup for faster startup.
var lightweightCommands = map[string]bool{ //nolint:gochecknoglobals // Static command list
	"version":    true,
	"help":       true,
	"completion": true,
}

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

  # Generate comprehensive report
  opnDossier convert config.xml --comprehensive

  # Validation workflow
  opnDossier validate config.xml && opnDossier convert config.xml -o documentation.md`,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		// Fast path: Skip heavy initialization for lightweight commands
		// This significantly improves startup time for --help, version, etc.
		if isLightweightCommand(cmd) {
			return setupLightweightContext(cmd)
		}

		return setupFullContext(cmd)
	},
}

// isLightweightCommand checks if the command or any of its parents is a lightweight command.
func isLightweightCommand(cmd *cobra.Command) bool {
	// Check if this command is lightweight
	if lightweightCommands[cmd.Name()] {
		return true
	}

	// Check if command has the lightweight annotation
	if cmd.Annotations != nil {
		if _, ok := cmd.Annotations["lightweight"]; ok {
			return true
		}
	}

	return false
}

// setupLightweightContext creates a minimal context for lightweight commands.
// This skips config file loading and uses minimal defaults for fast startup.
func setupLightweightContext(cmd *cobra.Command) error {
	// Use minimal default config - no file loading, no env var processing
	cfg = &config.Config{
		Format: "markdown",
		Engine: "programmatic",
	}

	// Create minimal command context with default logger
	cmdCtx := &CommandContext{
		Config: cfg,
		Logger: logger, // Use the default logger initialized in init()
	}

	if cmd.Context() == nil {
		cmd.SetContext(context.Background())
	}
	SetCommandContext(cmd, cmdCtx)

	return nil
}

// setupFullContext performs complete initialization for commands that need it.
func setupFullContext(cmd *cobra.Command) error {
	var err error
	// Load configuration with flag binding for proper precedence
	// Note: Fang complements Cobra for CLI enhancement
	cfg, err = config.LoadConfigWithFlags(cfgFile, cmd.Flags())
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize logger after config load with proper verbose/quiet handling
	// Determine log level based on verbose/quiet flags
	logLevel := "info"
	if cfg.IsQuiet() {
		logLevel = "error"
	} else if cfg.IsVerbose() {
		logLevel = "debug"
	}

	// Create new logger with centralized configuration
	var loggerErr error
	logger, loggerErr = logging.New(logging.Config{
		Level:           logLevel,
		Format:          "text", // Log format is hardcoded to "text" for consistency
		Output:          os.Stderr,
		ReportCaller:    true,
		ReportTimestamp: true,
	})
	if loggerErr != nil {
		return fmt.Errorf("failed to create logger: %w", loggerErr)
	}

	// Validate global flags after config is loaded
	if err := validateGlobalFlags(cmd.Flags()); err != nil {
		return fmt.Errorf("invalid flag configuration: %w", err)
	}

	// Set up CommandContext for explicit dependency injection
	// This makes config and logger available to all subcommands via context
	cmdCtx := &CommandContext{
		Config: cfg,
		Logger: logger,
	}

	// Ensure the command has a base context
	if cmd.Context() == nil {
		cmd.SetContext(context.Background())
	}
	SetCommandContext(cmd, cmdCtx)

	return nil
}

// init initializes the global logger with default settings and registers persistent CLI flags for configuration file path, verbosity, log level, log format, and display theme.
// If logger initialization fails, a stderr-based fallback logger is used to keep the CLI operational.
func init() {
	initializeDefaultLogger()

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

	// Logging control flags
	rootCmd.PersistentFlags().
		Bool("timestamps", false, "Include timestamps in log output")
	setFlagAnnotation(rootCmd.PersistentFlags(), "timestamps", []string{"logging"})

	// Progress and display control flags
	rootCmd.PersistentFlags().
		Bool("no-progress", false, "Disable progress indicators")
	setFlagAnnotation(rootCmd.PersistentFlags(), "no-progress", []string{"progress"})
	rootCmd.PersistentFlags().
		String("color", "auto", "Color output mode (auto, always, never)")
	setFlagAnnotation(rootCmd.PersistentFlags(), "color", []string{"display"})
	rootCmd.PersistentFlags().
		Bool("minimal", false, "Minimal output mode (suppresses progress and verbose messages)")
	setFlagAnnotation(rootCmd.PersistentFlags(), "minimal", []string{"output"})
	rootCmd.PersistentFlags().
		Bool("json-output", false, "Output errors in JSON format (for machine consumption)")
	setFlagAnnotation(rootCmd.PersistentFlags(), "json-output", []string{"output"})

	// Flag groups for better organization
	rootCmd.PersistentFlags().SortFlags = false

	// Mark mutually exclusive flags
	// Verbose and quiet are mutually exclusive
	rootCmd.MarkFlagsMutuallyExclusive("verbose", "quiet")

	// Add version command with lightweight annotation for fast startup
	versionCmd := &cobra.Command{
		Use:     "version",
		Short:   "Display version information",
		Long:    "Display the current version of opnDossier and build information.",
		GroupID: "utility",
		Annotations: map[string]string{
			"lightweight": "true", // Skip heavy initialization for fast startup
		},
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("opnDossier version %s\n", constants.Version)
			fmt.Printf("Build date: %s\n", getBuildDate())
			fmt.Printf("Git commit: %s\n", getGitCommit())
		},
	}
	rootCmd.AddCommand(versionCmd)

	// Add command aliases for common workflows
	// Note: Cobra doesn't directly support command aliases, but we can create wrapper commands
	convCmd := &cobra.Command{
		Use:               "conv [file ...]",
		Short:             "Alias for 'convert' command",
		Long:              "Alias for the 'convert' command. Converts OPNsense configuration files to structured formats.",
		GroupID:           "core",
		ValidArgsFunction: ValidXMLFiles,
		RunE:              convertCmd.RunE,
		Args:              convertCmd.Args,
		PreRunE:           convertCmd.PreRunE,
	}
	// Copy flags from convert command
	convCmd.Flags().AddFlagSet(convertCmd.Flags())
	rootCmd.AddCommand(convCmd)

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

	// Define flag groups for better help organization
	rootCmd.PersistentFlags().SetNormalizeFunc(func(_ *pflag.FlagSet, name string) pflag.NormalizedName {
		// Normalize kebab-case consistently
		return pflag.NormalizedName(strings.ReplaceAll(name, "_", "-"))
	})

	// Register global flag completion functions
	registerRootFlagCompletions(rootCmd)

	// Initialize enhanced help system with suggestions and custom templates
	InitHelp(rootCmd)
}

// registerRootFlagCompletions registers completion functions for root command persistent flags.
func registerRootFlagCompletions(cmd *cobra.Command) {
	// Color flag completion
	if err := cmd.RegisterFlagCompletionFunc("color", ValidColorModes); err != nil {
		// Log error but don't fail - completion is optional
		logger.Debug("failed to register color completion", "error", err)
	}
}

func initializeDefaultLogger() {
	// Initialize logger with default configuration before config is loaded.
	// If it fails, fall back to a minimal stderr logger to avoid breaking startup.
	var loggerErr error
	logger, loggerErr = logging.New(defaultLoggerConfig)
	if loggerErr != nil {
		logger = createFallbackLogger(loggerErr)
	}
}

// createFallbackLogger returns a minimal stderr-backed logger and reports the failure.
// This avoids panicking during init while still providing basic error visibility.
func createFallbackLogger(reason error) *logging.Logger {
	fmt.Fprintf(os.Stderr, "warning: unable to initialize logging (%v). Falling back to stderr output.\n", reason)

	fallback, err := logging.New(logging.Config{
		Level:           "error",
		Format:          "text",
		Output:          os.Stderr,
		ReportCaller:    false,
		ReportTimestamp: false,
	})
	if err == nil {
		return fallback
	}

	fmt.Fprintf(os.Stderr, "warning: unable to initialize fallback logger (%v). Using minimal stderr output.\n", err)
	return &logging.Logger{Logger: charmLog.NewWithOptions(os.Stderr, charmLog.Options{})}
}

// GetRootCmd returns the root Cobra command for the opnDossier CLI application.
// This provides access to the application's main command and its subcommands for integration or extension.
func GetRootCmd() *cobra.Command {
	return rootCmd
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

// validateGlobalFlags validates global flag combinations for consistency.
func validateGlobalFlags(flags *pflag.FlagSet) error {
	// Check color values
	if color, err := flags.GetString("color"); err == nil && color != "" {
		validColors := []string{"auto", "always", "never"}
		if !slices.Contains(validColors, color) {
			return fmt.Errorf("invalid color %q, must be one of: %s", color, strings.Join(validColors, ", "))
		}
	}

	return nil
}
