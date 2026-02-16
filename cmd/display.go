// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/EvilBit-Labs/opnDossier/internal/display"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// init registers the display command with the root command and sets up its CLI flags for XML validation control, theming, section filtering, and text wrapping.
func init() {
	rootCmd.AddCommand(displayCmd)

	// Add shared styling and content flags
	addSharedTemplateFlags(displayCmd)
	// Add display-specific flags
	addDisplayFlags(displayCmd)

	// Register flag completion functions for better tab completion
	registerDisplayFlagCompletions(displayCmd)

	// Flag groups for better organization
	displayCmd.Flags().SortFlags = false
}

// registerDisplayFlagCompletions registers completion functions for display command flags.
func registerDisplayFlagCompletions(cmd *cobra.Command) {
	// Theme flag completion
	if err := cmd.RegisterFlagCompletionFunc("theme", ValidThemes); err != nil {
		// Log error but don't fail - completion is optional
		logger.Debug("failed to register theme completion", "error", err)
	}

	// Section flag completion
	if err := cmd.RegisterFlagCompletionFunc("section", ValidSections); err != nil {
		logger.Debug("failed to register section completion", "error", err)
	}
}

var displayCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra command
	Use:               "display [file]",
	Short:             "Display OPNsense configuration in formatted markdown.",
	GroupID:           "core",
	ValidArgsFunction: ValidXMLFiles,
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		// Validate flag combinations specific to display command
		if err := validateDisplayFlags(cmd.Flags()); err != nil {
			return fmt.Errorf("display command validation failed: %w", err)
		}

		return nil
	},
	Long: `The 'display' command converts an OPNsense config.xml file to markdown
and displays it in the terminal with syntax highlighting and formatting.
This provides an immediate, readable view of your firewall configuration
without saving to a file.

The configuration is parsed without validation to ensure
it can be displayed even with configuration inconsistencies that are
common in production environments.

  OUTPUT FORMATS:
  The display command renders markdown with syntax highlighting and formatting.

  The output is always displayed in the terminal using glamour rendering.

The output includes:
- Syntax-highlighted markdown rendering
- Proper formatting with headers, lists, and code blocks
- Theme-aware colors (adapts to light/dark terminal themes)
- Structured presentation of configuration hierarchy
- Section filtering
- Configurable text wrapping

Examples:
  # Display configuration
  opnDossier display config.xml

  # Display with specific theme
  opnDossier display --theme dark config.xml
  opnDossier display --theme light config.xml

  # Display with sections
  opnDossier display --section system,network config.xml

  # Display with text wrapping
  opnDossier display --wrap 120 config.xml
  # When --wrap is not specified, terminal width is auto-detected (COLUMNS or default 120)
  # Recommended wrap range: 80-120 columns

  # Display with narrow terminal wrapping
  opnDossier display --wrap 80 config.xml

  # Display without text wrapping
  opnDossier display --no-wrap config.xml

  # Display without text wrapping (using --wrap 0)
  opnDossier display --wrap 0 config.xml

  # Display with verbose logging to see processing details
  opnDossier --verbose display config.xml

  # Display with quiet mode (suppress processing messages)
  opnDossier --quiet display config.xml`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}

		// Get configuration and logger from CommandContext
		cmdCtx := GetCommandContext(cmd)
		if cmdCtx == nil {
			return errors.New("command context not initialized")
		}
		cmdLogger := cmdCtx.Logger
		cmdConfig := cmdCtx.Config

		filePath := args[0]

		// Create context-aware logger with input file field
		ctxLogger := cmdLogger.WithContext(ctx).WithFields("input_file", filePath)

		// Sanitize the file path
		cleanPath := filepath.Clean(filePath)
		if !filepath.IsAbs(cleanPath) {
			// If not an absolute path, make it relative to the current working directory
			var err error
			cleanPath, err = filepath.Abs(cleanPath)
			if err != nil {
				return fmt.Errorf("failed to get absolute path for %s: %w", filePath, err)
			}
		}

		// Read the file
		file, err := os.Open(cleanPath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %w", filePath, err)
		}
		defer func() {
			if cerr := file.Close(); cerr != nil {
				ctxLogger.Error("failed to close file", "error", cerr)
			}
		}()

		// Parse the XML - display command only ensures XML can be unmarshalled
		// Full validation should be done with the 'validate' command
		p := cfgparser.NewXMLParser()
		opnsense, err := p.Parse(ctx, file)
		if err != nil {
			ctxLogger.Error("Failed to parse XML", "error", err)
			// Enhanced error handling for different error types
			if cfgparser.IsParseError(err) {
				if parseErr := cfgparser.GetParseError(err); parseErr != nil {
					ctxLogger.Error("XML syntax error detected", "line", parseErr.Line, "message", parseErr.Message)
				}
			}
			if cfgparser.IsValidationError(err) {
				ctxLogger.Error("Configuration validation failed")
			}
			return fmt.Errorf("failed to parse XML from %s: %w", filePath, err)
		}

		mdOpts := buildDisplayOptions(cmdConfig)
		g, err := converter.NewMarkdownGenerator(ctxLogger, mdOpts)
		if err != nil {
			ctxLogger.Error("Failed to create markdown generator", "error", err)
			return fmt.Errorf("failed to create markdown generator: %w", err)
		}

		// Standard markdown generation
		md, err := g.Generate(ctx, opnsense, mdOpts)
		if err != nil {
			ctxLogger.Error("Failed to convert to markdown", "error", err)
			return fmt.Errorf("failed to convert to markdown from %s: %w", filePath, err)
		}

		// Create terminal display with full markdown options
		displayer := display.NewTerminalDisplayWithMarkdownOptions(mdOpts)

		if err := displayer.Display(ctx, md); err != nil {
			ctxLogger.Error("Failed to display markdown", "error", err)
			return fmt.Errorf("failed to display markdown: %w", err)
		}
		return nil
	},
}

// buildDisplayOptions constructs converter.Options for the display command, applying CLI flag values with precedence over configuration settings and defaults.
//
// CLI-provided values for theme, sections, and wrap width override corresponding configuration values. If neither is set, defaults are used.
//
// buildDisplayOptions constructs converter.Options for markdown generation using
// default values, global CLI flags, and values from cfg when present.
//
// The precedence for each option is: CLI flag > cfg value > package default.
//   - SuppressWarnings is enabled when cfg.IsQuiet() is true.
//   - Theme and Sections are taken from CLI flags when set, otherwise from cfg.
//   - WrapWidth uses CLI flag if >= 0, otherwise cfg value if >= 0, otherwise -1
//     (auto-detect). A WrapWidth of 0 disables wrapping; positive values set a
//     specific column width.
//   - Comprehensive is taken from the corresponding CLI flag.
func buildDisplayOptions(cfg *config.Config) converter.Options {
	// Start with defaults
	opt := converter.DefaultOptions()

	// Propagate quiet flag to suppress warnings
	if cfg != nil && cfg.IsQuiet() {
		opt.SuppressWarnings = true
	}

	// Theme: CLI flag > config > default
	if sharedTheme != "" {
		opt.Theme = converter.Theme(sharedTheme)
	} else if cfg != nil && cfg.GetTheme() != "" {
		opt.Theme = converter.Theme(cfg.GetTheme())
	}

	// Sections: CLI flag > config > default
	if len(sharedSections) > 0 {
		opt.Sections = sharedSections
	} else if cfg != nil && len(cfg.GetSections()) > 0 {
		opt.Sections = cfg.GetSections()
	}

	// Wrap width: CLI flag > config > default
	// -1 means auto-detect (not provided), 0 means no wrapping, >0 means specific width
	switch {
	case sharedWrapWidth >= 0:
		opt.WrapWidth = sharedWrapWidth
	case cfg != nil && cfg.GetWrapWidth() >= 0:
		opt.WrapWidth = cfg.GetWrapWidth()
	default:
		opt.WrapWidth = -1
	}

	opt.Comprehensive = sharedComprehensive

	return opt
}

// validateDisplayFlags checks display command flag combinations and value constraints.
//
// It inspects the provided FlagSet to detect flags that were explicitly set and enforces:
// - Mutual exclusivity of `--no-wrap` and `--wrap` (returns an error if both were set).
// - Normalizes `sharedWrapWidth` to 0 when `sharedNoWrap` is true.
// - Validates that `sharedTheme`, if provided, is one of: "light", "dark", "auto", or "none" (returns an error otherwise).
// - Emits a warning to stderr when a positive `sharedWrapWidth` is outside the recommended [MinWrapWidth, MaxWrapWidth] range.
// - Returns an error if `sharedWrapWidth` is less than -1.
//
// Parameters:
//
//	flags: the command FlagSet used to determine whether `--no-wrap` or `--wrap` were explicitly changed.
//
// Returns an error when flag combinations or values are invalid; nil otherwise.
func validateDisplayFlags(flags *pflag.FlagSet) error {
	// Validate mutual exclusivity for wrap flags before other checks
	if flags != nil {
		noWrapFlag := flags.Lookup("no-wrap")
		wrapFlag := flags.Lookup("wrap")
		if noWrapFlag != nil && wrapFlag != nil && noWrapFlag.Changed && wrapFlag.Changed {
			return errors.New("--no-wrap and --wrap flags are mutually exclusive")
		}
	}

	if sharedNoWrap {
		sharedWrapWidth = 0
	}

	// Validate theme values
	if sharedTheme != "" {
		validThemes := []string{"light", "dark", "auto", "none"}
		if !slices.Contains(validThemes, strings.ToLower(sharedTheme)) {
			return fmt.Errorf("invalid theme %q, must be one of: %s", sharedTheme, strings.Join(validThemes, ", "))
		}
	}

	// Validate wrap width if specified
	if sharedWrapWidth > 0 && (sharedWrapWidth < MinWrapWidth || sharedWrapWidth > MaxWrapWidth) {
		fmt.Fprintf(os.Stderr, "Warning: wrap width %d is outside recommended range [%d, %d]\n",
			sharedWrapWidth, MinWrapWidth, MaxWrapWidth)
	}
	if sharedWrapWidth < -1 {
		return fmt.Errorf("invalid wrap width %d: must be -1 (auto-detect), 0 (no wrapping), or positive",
			sharedWrapWidth)
	}

	return nil
}
