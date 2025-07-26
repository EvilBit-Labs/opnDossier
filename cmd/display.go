// Package cmd provides the command-line interface for opnFocus.
package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/unclesp1d3r/opnFocus/internal/converter"
	"github.com/unclesp1d3r/opnFocus/internal/display"
	"github.com/unclesp1d3r/opnFocus/internal/model"
	"github.com/unclesp1d3r/opnFocus/internal/parser"

	"github.com/spf13/cobra"
)

var noValidation bool //nolint:gochecknoglobals // Cobra flag variable

func init() {
	rootCmd.AddCommand(displayCmd)
	displayCmd.Flags().BoolVar(&noValidation, "no-validate", false, "Skip validation and display potentially malformed configurations")
}

var displayCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra command
	Use:   "display [file]",
	Short: "Display OPNsense configuration as formatted markdown in terminal",
	Long: `The 'display' command converts an OPNsense config.xml file to markdown
and displays it in the terminal with syntax highlighting and formatting.
This provides an immediate, readable view of your firewall configuration
without saving to a file.

By default, the configuration is validated before display to ensure
data integrity. Use --no-validate to skip validation if you need to
display potentially malformed configurations.

The output includes:
- Syntax-highlighted markdown rendering
- Proper formatting with headers, lists, and code blocks
- Theme-aware colors (adapts to light/dark terminal themes)
- Structured presentation of configuration hierarchy

CONFIGURATION:
  This command respects the global configuration precedence:
  CLI flags > environment variables (OPNFOCUS_*) > config file > defaults

Examples:
  # Display configuration with validation (default behavior)
  opnFocus display config.xml

  # Display configuration without validation
  opnFocus display --no-validate config.xml

  # Display with verbose logging to see processing details
  opnFocus --verbose display config.xml

  # Display with quiet mode (suppress processing messages)
  opnFocus --quiet display config.xml
`,
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
		var opnsense *model.Opnsense
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
		c := converter.NewMarkdownConverter()
		md, err := c.ToMarkdown(ctx, opnsense)
		if err != nil {
			ctxLogger.Error("Failed to convert to markdown", "error", err)
			return fmt.Errorf("failed to convert to markdown from %s: %w", filePath, err)
		}
		ctxLogger.Debug("Markdown conversion completed successfully")

		// Display the markdown in terminal
		ctxLogger.Debug("Displaying markdown in terminal")
		displayer := display.NewTerminalDisplay()
		if err := displayer.Display(ctx, md); err != nil {
			ctxLogger.Error("Failed to display markdown", "error", err)
			return fmt.Errorf("failed to display markdown: %w", err)
		}

		ctxLogger.Info("Display process completed successfully")
		return nil
	},
}
