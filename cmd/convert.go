// Package cmd provides the command-line interface for opnFocus.
package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/unclesp1d3r/opnFocus/internal/converter"
	"github.com/unclesp1d3r/opnFocus/internal/export"
	"github.com/unclesp1d3r/opnFocus/internal/log"
	"github.com/unclesp1d3r/opnFocus/internal/parser"

	"github.com/spf13/cobra"
)

var (
	outputFile string //nolint:gochecknoglobals // Cobra flag variable
	format     string //nolint:gochecknoglobals // Output format (markdown, json, yaml)
)

func init() {
	rootCmd.AddCommand(convertCmd)
	convertCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")
	convertCmd.Flags().StringVarP(&format, "format", "f", "markdown", "Output format (markdown, json, yaml)")
}

var convertCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra command
	Use:   "convert [file ...]",
	Short: "Convert OPNsense configuration files to various formats",
	Long: `The 'convert' command processes one or more OPNsense config.xml files and transforms
its content into structured formats. Supported output formats include Markdown (default),
JSON, and YAML. This allows for easier readability, documentation, programmatic access,
and auditing of your firewall configuration.

The convert command focuses on conversion only and does not perform validation.
To validate your configuration files before conversion, use the 'validate' command.

You can either print the generated output directly to the console or save it to a
specified output file using the '--output' or '-o' flag. Use the '--format' or '-f'
flag to specify the output format (markdown, json, or yaml).

When processing multiple files, the --output flag will be ignored, and each output
file will be named based on its input file with the appropriate extension
(e.g., config.xml -> config.md, config.json, or config.yaml).

CONFIGURATION:
  This command respects the global configuration precedence:
  CLI flags > environment variables (OPNFOCUS_*) > config file > defaults

  Output file can be set via:
    --output flag (highest priority)
    OPNFOCUS_OUTPUT_FILE environment variable
    output_file in ~/.opnFocus.yaml

Examples:
  # Convert 'my_config.xml' and print markdown to console
  opnFocus convert my_config.xml

  # Convert 'my_config.xml' to JSON format
  opnFocus convert my_config.xml --format json

  # Convert 'my_config.xml' to YAML and save to file
  opnFocus convert my_config.xml -f yaml -o documentation.yaml

  # Convert multiple files to JSON format
  opnFocus convert config1.xml config2.xml --format json

  # Convert 'backup_config.xml' with verbose logging
  opnFocus --verbose convert backup_config.xml -f json

  # Use environment variable to set default output location
  OPNFOCUS_OUTPUT_FILE=./docs/network.md opnFocus convert config.xml

  # Validate before converting (recommended workflow)
  opnFocus validate config.xml && opnFocus convert config.xml -f json -o output.json
`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}

		var wg sync.WaitGroup
		errs := make(chan error, len(args))

		for _, filePath := range args {
			wg.Add(1)
			go func(fp string) {
				defer wg.Done()

				// Create context-aware logger for this goroutine with input file field
				ctxLogger := logger.WithContext(ctx).WithFields("input_file", fp)
				ctxLogger.Info("Starting conversion process")

				// Sanitize the file path
				cleanPath := filepath.Clean(fp)
				if !filepath.IsAbs(cleanPath) {
					// If not an absolute path, make it relative to the current working directory
					var err error
					cleanPath, err = filepath.Abs(cleanPath)
					if err != nil {
						errs <- fmt.Errorf("failed to get absolute path for %s: %w", fp, err)
						return
					}
				}

				// Read the file
				file, err := os.Open(cleanPath)
				if err != nil {
					errs <- fmt.Errorf("failed to open file %s: %w", fp, err)
					return
				}
				defer func() {
					if cerr := file.Close(); cerr != nil {
						ctxLogger.Error("failed to close file", "error", cerr)
					}
				}()

				// Parse the XML without validation (use 'validate' command for validation)
				ctxLogger.Debug("Parsing XML file")
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
					errs <- fmt.Errorf("failed to parse XML from %s: %w", fp, err)
					return
				}
				ctxLogger.Debug("XML parsing completed successfully")

				// Convert based on format
				var output string
				var fileExt string

				switch strings.ToLower(format) {
				case "markdown", "md":
					ctxLogger.Debug("Converting to markdown")
					c := converter.NewMarkdownConverter()
					output, err = c.ToMarkdown(ctx, opnsense)
					if err != nil {
						ctxLogger.Error("Failed to convert to markdown", "error", err)
						errs <- fmt.Errorf("failed to convert to markdown from %s: %w", fp, err)
						return
					}
					fileExt = ".md"
					ctxLogger.Debug("Markdown conversion completed successfully")

				case "json":
					ctxLogger.Debug("Converting to JSON")
					c := converter.NewJSONConverter()
					output, err = c.ToJSON(ctx, opnsense)
					if err != nil {
						ctxLogger.Error("Failed to convert to JSON", "error", err)
						errs <- fmt.Errorf("failed to convert to JSON from %s: %w", fp, err)
						return
					}
					fileExt = ".json"
					ctxLogger.Debug("JSON conversion completed successfully")

				case "yaml", "yml":
					ctxLogger.Debug("Converting to YAML")
					c := converter.NewYAMLConverter()
					output, err = c.ToYAML(ctx, opnsense)
					if err != nil {
						ctxLogger.Error("Failed to convert to YAML", "error", err)
						errs <- fmt.Errorf("failed to convert to YAML from %s: %w", fp, err)
						return
					}
					fileExt = ".yaml"
					ctxLogger.Debug("YAML conversion completed successfully")

				default:
					ctxLogger.Error("Unsupported format", "format", format)
					errs <- fmt.Errorf("%w: got '%s'", converter.ErrUnsupportedFormat, format)
					return
				}

				// Determine output path
				actualOutputFile := outputFile
				if len(args) > 1 || (actualOutputFile == "" && Cfg.OutputFile != "") {
					// If multiple files, or single file with no -o but config has output_file
					// use input filename with appropriate extension
					base := filepath.Base(fp)
					ext := filepath.Ext(base)
					actualOutputFile = strings.TrimSuffix(base, ext) + fileExt
				}

				// Create enhanced logger with output file information
				var enhancedLogger *log.Logger
				if actualOutputFile != "" {
					enhancedLogger = ctxLogger.WithFields("output_file", actualOutputFile)
				} else {
					enhancedLogger = ctxLogger.WithFields("output_mode", "stdout")
				}

				// Export or print the output
				if actualOutputFile != "" {
					enhancedLogger.Debug("Exporting to file")
					e := export.NewFileExporter()
					if err := e.Export(ctx, output, actualOutputFile); err != nil {
						enhancedLogger.Error("Failed to export output", "error", err)
						errs <- fmt.Errorf("failed to export output to %s: %w", actualOutputFile, err)
						return
					}
					enhancedLogger.Info("Output exported successfully")
				} else {
					enhancedLogger.Debug("Outputting to stdout")
					fmt.Print(output)
				}

				ctxLogger.Info("Conversion process completed successfully")
			}(filePath)
		}

		wg.Wait()
		close(errs)

		var allErrors error
		for err := range errs {
			if allErrors == nil {
				allErrors = err
			} else {
				allErrors = fmt.Errorf("%w; %w", allErrors, err)
			}
		}

		return allErrors
	},
}
