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

	// TODO: Audit mode functionality is not yet complete - disabled for now
	// "github.com/EvilBit-Labs/opnDossier/internal/audit".
	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/display"
	"github.com/EvilBit-Labs/opnDossier/internal/markdown"
	"github.com/EvilBit-Labs/opnDossier/internal/parser"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// init registers the display command with the root command and sets up its CLI flags for XML validation control, theming, template selection, section filtering, text wrapping, and custom template directories.
func init() {
	rootCmd.AddCommand(displayCmd)

	// Add shared template flags
	addSharedTemplateFlags(displayCmd)
	// Add display-specific flags
	addDisplayFlags(displayCmd)
	// Add audit flags (same as convert command)
	addSharedAuditFlags(displayCmd)

	// Flag groups for better organization
	displayCmd.Flags().SortFlags = false
}

var displayCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra command
	Use:     "display [file]",
	Short:   "Display OPNsense configuration in formatted markdown.",
	GroupID: "core",
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
- Customizable templates and section filtering
- Configurable text wrapping

Examples:
  # Display configuration
  opnDossier display config.xml

  # Display with specific theme
  opnDossier display --theme dark config.xml
  opnDossier display --theme light config.xml

  # Display with sections
  opnDossier display --section system,network config.xml

  # Display with custom template file
  opnDossier display --custom-template /path/to/my-template.tmpl config.xml

  # Display with text wrapping
  opnDossier display --wrap 120 config.xml

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

		filePath := args[0]

		// Create context-aware logger with input file field
		ctxLogger := logger.WithContext(ctx).WithFields("input_file", filePath)

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
		p := parser.NewXMLParser()
		opnsense, err := p.Parse(ctx, file)
		if err != nil {
			ctxLogger.Error("Failed to parse XML", "error", err)
			// Enhanced error handling for different error types
			if parser.IsParseError(err) {
				if parseErr := parser.GetParseError(err); parseErr != nil {
					ctxLogger.Error("XML syntax error detected", "line", parseErr.Line, "message", parseErr.Message)
				}
			}
			if parser.IsValidationError(err) {
				ctxLogger.Error("Configuration validation failed")
			}
			return fmt.Errorf("failed to parse XML from %s: %w", filePath, err)
		}

		templateDir := getSharedTemplateDir()
		mdOpts := buildDisplayOptions(Cfg)
		g, err := markdown.NewMarkdownGeneratorWithTemplates(ctxLogger, templateDir, mdOpts)
		if err != nil {
			ctxLogger.Error("Failed to create markdown generator", "error", err)
			return fmt.Errorf("failed to create markdown generator: %w", err)
		}

		// TODO: Audit mode functionality is not yet complete - disabled for now
		// Handle audit mode if specified
		// var md string
		// if mdOpts.AuditMode != "" {
		// 	// Create plugin registry for audit mode
		// 	registry := audit.NewPluginRegistry()
		// 	md, err = handleAuditMode(ctx, opnsense, mdOpts, ctxLogger, registry)
		// 	if err != nil {
		// 		ctxLogger.Error("Failed to generate audit report", "error", err)
		// 		return fmt.Errorf("failed to generate audit report from %s: %w", filePath, err)
		// 	}
		// } else {
		// Standard markdown generation
		md, err := g.Generate(ctx, opnsense, mdOpts)
		// }
		if err != nil {
			ctxLogger.Error("Failed to convert to markdown", "error", err)
			return fmt.Errorf("failed to convert to markdown from %s: %w", filePath, err)
		}

		// Create terminal display with theme support
		var displayer *display.TerminalDisplay
		if sharedTheme != "" {
			// Use explicit theme
			theme := display.DetectTheme(sharedTheme)
			opts := display.DefaultOptions()
			opts.Theme = theme
			displayer = display.NewTerminalDisplayWithOptions(opts)
		} else {
			// Use auto-detection
			displayer = display.NewTerminalDisplay()
		}

		if err := displayer.Display(ctx, md); err != nil {
			ctxLogger.Error("Failed to display markdown", "error", err)
			return fmt.Errorf("failed to display markdown: %w", err)
		}
		return nil
	},
}

// buildDisplayOptions constructs markdown.Options for the display command, applying CLI flag values with precedence over configuration settings and defaults.
//
// CLI-provided values for theme, template, sections, wrap width, and template directory override corresponding configuration values. If neither is set, defaults are used.
//
// Returns the resulting markdown.Options struct for use in markdown generation.
func buildDisplayOptions(cfg *config.Config) markdown.Options {
	// Start with defaults
	opt := markdown.DefaultOptions()

	// Propagate quiet flag to suppress deprecation warnings
	if cfg != nil && cfg.IsQuiet() {
		opt.SuppressWarnings = true
	}

	// Theme: CLI flag > config > default
	if sharedTheme != "" {
		opt.Theme = markdown.Theme(sharedTheme)
	} else if cfg != nil && cfg.GetTheme() != "" {
		opt.Theme = markdown.Theme(cfg.GetTheme())
	}

	// Template: config > default (no CLI flag for template)
	if cfg != nil && cfg.GetTemplate() != "" {
		opt.TemplateName = cfg.GetTemplate()
	}

	// Sections: CLI flag > config > default
	if len(sharedSections) > 0 {
		opt.Sections = sharedSections
	} else if cfg != nil && len(cfg.GetSections()) > 0 {
		opt.Sections = cfg.GetSections()
	}

	// Wrap width: CLI flag > config > default
	if sharedWrapWidth > 0 {
		opt.WrapWidth = sharedWrapWidth
	} else if cfg != nil && cfg.GetWrapWidth() > 0 {
		opt.WrapWidth = cfg.GetWrapWidth()
	}

	// Template directory: CLI flag only
	templateDir := getSharedTemplateDir()
	if templateDir != "" {
		opt.TemplateDir = templateDir
	}

	// TODO: Audit mode functionality is not yet complete - disabled for now
	// Audit mode flags: CLI flag only
	// if sharedAuditMode != "" {
	// 	opt.AuditMode = markdown.AuditMode(sharedAuditMode)
	// }
	// opt.BlackhatMode = sharedBlackhatMode
	opt.Comprehensive = sharedComprehensive
	// Selected plugins are disabled until audit functionality is complete

	return opt
}

// validateDisplayFlags validates flag combinations specific to the display command.
func validateDisplayFlags(_ *pflag.FlagSet) error {
	// Validate theme values
	if sharedTheme != "" {
		validThemes := []string{"light", "dark", "auto", "none"}
		if !slices.Contains(validThemes, strings.ToLower(sharedTheme)) {
			return fmt.Errorf("invalid theme %q, must be one of: %s", sharedTheme, strings.Join(validThemes, ", "))
		}
	}

	// Validate engine flag combinations
	if sharedEngine != "" {
		if sharedUseTemplate {
			return errors.New("--use-template and --engine flags are mutually exclusive")
		}
		if sharedLegacy {
			return errors.New("--legacy and --engine flags are mutually exclusive")
		}
		if sharedCustomTemplate != "" {
			return errors.New(
				"--custom-template and --engine flags are mutually exclusive when engine is explicitly set",
			)
		}
	}

	// Validate template-related flags
	if sharedCustomTemplate != "" && sharedUseTemplate {
		return errors.New("--custom-template automatically enables template mode, --use-template is redundant")
	}

	// Validate wrap width if specified
	if sharedWrapWidth > 0 && (sharedWrapWidth < MinWrapWidth || sharedWrapWidth > MaxWrapWidth) {
		fmt.Fprintf(os.Stderr, "Warning: wrap width %d is outside recommended range [%d, %d]\n",
			sharedWrapWidth, MinWrapWidth, MaxWrapWidth)
	}

	// Validate template cache size if specified
	if sharedTemplateCacheSize > MaxTemplateCacheSize {
		return fmt.Errorf("template cache size %d exceeds maximum recommended size %d",
			sharedTemplateCacheSize, MaxTemplateCacheSize)
	}

	return nil
}
