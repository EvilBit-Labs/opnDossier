// Package cmd provides the command-line interface for opnFocus.
package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/unclesp1d3r/opnFocus/internal/config"
	"github.com/unclesp1d3r/opnFocus/internal/display"
	"github.com/unclesp1d3r/opnFocus/internal/markdown"
	"github.com/unclesp1d3r/opnFocus/internal/model"
	"github.com/unclesp1d3r/opnFocus/internal/parser"
)

var (
	noValidation       bool     //nolint:gochecknoglobals // Cobra flag variable
	displayTheme       string   //nolint:gochecknoglobals // Theme for display
	displayTemplate    string   //nolint:gochecknoglobals // Template name to use
	displaySections    []string //nolint:gochecknoglobals // Sections to include
	displayWrapWidth   int      //nolint:gochecknoglobals // Text wrap width
	displayTemplateDir string   //nolint:gochecknoglobals // Custom template directory
)

const (
	progressChannelBufferSize = 10
	parsingCompletePercent    = 0.1
	markdownCompletePercent   = 0.3
	preparingDisplayPercent   = 0.7
	renderingPercent          = 0.9
)

// init registers the display command with the root command and configures its CLI flags for validation, theming, template selection, section filtering, and text wrapping.
func init() {
	rootCmd.AddCommand(displayCmd)

	// Validation flags
	displayCmd.Flags().
		BoolVar(&noValidation, "no-validate", false, "Skip validation and display potentially malformed configurations (use with caution)")
	setFlagAnnotation(displayCmd.Flags(), "no-validate", []string{"validation"})

	// Template and styling flags
	displayCmd.Flags().StringVar(&displayTheme, "theme", "", "Theme for terminal display (light, dark, auto, none)")
	setFlagAnnotation(displayCmd.Flags(), "theme", []string{"template"})
	displayCmd.Flags().
		StringVar(&displayTemplate, "template", "", "Template name to use for markdown rendering (default: auto-selected). Available: standard, comprehensive, json, yaml, blue, red, blue-enhanced")
	setFlagAnnotation(displayCmd.Flags(), "template", []string{"template"})
	displayCmd.Flags().
		StringSliceVar(&displaySections, "section", []string{}, "Specific sections to include in display (comma-separated, e.g., system,network,firewall)")
	setFlagAnnotation(displayCmd.Flags(), "section", []string{"template"})
	displayCmd.Flags().
		IntVar(&displayWrapWidth, "wrap", 0, "Text wrap width in characters (0 = no wrapping, recommended: 80-120)")
	setFlagAnnotation(displayCmd.Flags(), "wrap", []string{"template"})
	displayCmd.Flags().
		StringVar(&displayTemplateDir, "template-dir", "", "Custom template directory for user-defined templates (overrides built-in templates)")
	setFlagAnnotation(displayCmd.Flags(), "template-dir", []string{"template"})

	// Flag groups for better organization
	displayCmd.Flags().SortFlags = false

	// Mark mutually exclusive flags
	// Template and template-dir are mutually exclusive (template-dir overrides built-in templates)
	displayCmd.MarkFlagsMutuallyExclusive("template", "template-dir")
}

var displayCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra command
	Use:     "display [file]",
	Short:   "Display OPNsense configuration in formatted markdown.",
	GroupID: "core",
	Long: `The 'display' command converts an OPNsense config.xml file to markdown
and displays it in the terminal with syntax highlighting and formatting.
This provides an immediate, readable view of your firewall configuration
without saving to a file.

By default, the configuration is validated before display to ensure
data integrity. Use --no-validate to skip validation if you need to
display potentially malformed configurations.

TEMPLATES:
  Main templates:
    standard                    - Standard report (default)
    comprehensive               - Comprehensive report
    json                        - JSON format output
    yaml                        - YAML format output

  Audit mode templates:
    blue                        - Blue team audit report
    red                         - Red team audit report
    blue-enhanced               - Enhanced blue team audit report

The output includes:
- Syntax-highlighted markdown rendering
- Proper formatting with headers, lists, and code blocks
- Theme-aware colors (adapts to light/dark terminal themes)
- Structured presentation of configuration hierarchy
- Customizable templates and section filtering
- Configurable text wrapping

Examples:
  # Display configuration with validation (default behavior)
  opnFocus display config.xml

  # Display configuration without validation
  opnFocus display --no-validate config.xml

  # Display with specific theme
  opnFocus display --theme dark config.xml
  opnFocus display --theme light config.xml

  # Display with custom template and sections
  opnFocus display --template detailed --section system,network config.xml

  # Display with custom template directory
  opnFocus display --template-dir ~/.opnFocus/templates config.xml

  # Display with text wrapping
  opnFocus display --wrap 120 config.xml

  # Display with verbose logging to see processing details
  opnFocus --verbose display config.xml

  # Display with quiet mode (suppress processing messages)
  opnFocus --quiet display config.xml`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}

		filePath := args[0]

		// Create context-aware logger with input file field
		ctxLogger := logger.WithContext(ctx).WithFields("input_file", filePath)
		ctxLogger.Info("Starting display process")

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

		// Parse the XML with or without validation based on flag
		ctxLogger.Debug("Parsing XML file")
		p := parser.NewXMLParser()
		var opnsense *model.OpnSenseDocument
		if noValidation {
			// Use Parse when validation is explicitly disabled
			opnsense, err = p.Parse(ctx, file)
			ctxLogger.Debug("Parsing without validation")
		} else {
			// Use ParseAndValidate for default behavior (with validation)
			opnsense, err = p.ParseAndValidate(ctx, file)
			ctxLogger.Debug("Parsing with validation")
		}

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
		ctxLogger.Debug("XML parsing completed successfully")

		// Convert to markdown
		ctxLogger.Debug("Converting to markdown")

		g, err := markdown.NewMarkdownGeneratorWithTemplates(ctxLogger.Logger, displayTemplateDir)
		if err != nil {
			ctxLogger.Error("Failed to create markdown generator", "error", err)
			return fmt.Errorf("failed to create markdown generator: %w", err)
		}

		// Create markdown options with comprehensive support
		mdOpts := buildDisplayOptions(
			displayTheme,
			displayTemplate,
			displaySections,
			displayWrapWidth,
			displayTemplateDir,
			Cfg,
		)

		md, err := g.Generate(ctx, opnsense, mdOpts)
		if err != nil {
			ctxLogger.Error("Failed to convert to markdown", "error", err)
			return fmt.Errorf("failed to convert to markdown from %s: %w", filePath, err)
		}
		ctxLogger.Debug("Markdown conversion completed successfully")

		// Display the markdown in terminal with progress indication
		ctxLogger.Debug("Displaying markdown in terminal")

		// Create terminal display with theme support
		var displayer *display.TerminalDisplay
		if displayTheme != "" {
			// Use explicit theme
			theme := display.DetectTheme(displayTheme)
			opts := display.DefaultOptions()
			opts.Theme = theme
			displayer = display.NewTerminalDisplayWithOptions(opts)
		} else {
			// Use auto-detection
			displayer = display.NewTerminalDisplay()
		}

		// Create a progress channel to stream progress events
		progressCh := make(chan display.ProgressEvent, progressChannelBufferSize)

		// Start displaying with progress in a goroutine
		go func() {
			defer close(progressCh)
			progressCh <- display.ProgressEvent{Percent: parsingCompletePercent, Message: "Parsing complete"}
			progressCh <- display.ProgressEvent{Percent: markdownCompletePercent, Message: "Markdown conversion complete"}
			progressCh <- display.ProgressEvent{Percent: preparingDisplayPercent, Message: "Preparing display..."}
			progressCh <- display.ProgressEvent{Percent: renderingPercent, Message: "Rendering..."}
		}()

		if err := displayer.DisplayWithProgress(ctx, md, progressCh); err != nil {
			ctxLogger.Error("Failed to display markdown", "error", err)
			return fmt.Errorf("failed to display markdown: %w", err)
		}

		ctxLogger.Info("Display process completed successfully")
		return nil
	},
}

// buildDisplayOptions constructs markdown.Options for the display command, applying CLI flag values with precedence over configuration settings and defaults.
//
// CLI-provided values for theme, template, sections, wrap width, and template directory override corresponding configuration values. If neither is set, defaults are used.
//
// Returns the resulting markdown.Options struct for use in markdown generation.
func buildDisplayOptions(
	theme, template string,
	sections []string,
	wrap int,
	templateDir string,
	cfg *config.Config,
) markdown.Options {
	// Start with defaults
	opt := markdown.DefaultOptions()

	// Theme: CLI flag > config > default
	if theme != "" {
		opt.Theme = markdown.Theme(theme)
	} else if cfg != nil && cfg.GetTheme() != "" {
		opt.Theme = markdown.Theme(cfg.GetTheme())
	}

	// Template: CLI flag > config > default
	if template != "" {
		opt.TemplateName = template
	} else if cfg != nil && cfg.GetTemplate() != "" {
		opt.TemplateName = cfg.GetTemplate()
	}

	// Sections: CLI flag > config > default
	if len(sections) > 0 {
		opt.Sections = sections
	} else if cfg != nil && len(cfg.GetSections()) > 0 {
		opt.Sections = cfg.GetSections()
	}

	// Wrap width: CLI flag > config > default
	if wrap > 0 {
		opt.WrapWidth = wrap
	} else if cfg != nil && cfg.GetWrapWidth() > 0 {
		opt.WrapWidth = cfg.GetWrapWidth()
	}

	// Template directory: CLI flag only
	if templateDir != "" {
		opt.TemplateDir = templateDir
	}

	return opt
}
