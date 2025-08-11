// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/template"

	// TODO: Audit mode functionality is not yet complete - disabled for now
	// "github.com/EvilBit-Labs/opnDossier/internal/audit".
	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/EvilBit-Labs/opnDossier/internal/export"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/EvilBit-Labs/opnDossier/internal/markdown"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/EvilBit-Labs/opnDossier/internal/parser"
	"github.com/spf13/cobra"
)

var (
	outputFile string //nolint:gochecknoglobals // Cobra flag variable
	format     string //nolint:gochecknoglobals // Output format (markdown, json, yaml)
	force      bool   //nolint:gochecknoglobals // Force overwrite without prompt
)

// ErrOperationCancelled is returned when the user cancels an operation.
var ErrOperationCancelled = errors.New("operation cancelled by user")

// Static errors for better error handling.
var (
	ErrUnsupportedAuditMode = errors.New("unsupported audit mode")
	ErrFailedToEnrichConfig = errors.New("failed to enrich configuration")
)

// init registers the convert command and its flags with the root command.
//
// This function sets up command-line flags for output file path, format, template, sections, theme, and text wrap width, enabling users to customize the conversion of OPNsense configuration files.
func init() {
	rootCmd.AddCommand(convertCmd)

	// Output and format flags
	convertCmd.Flags().
		StringVarP(&outputFile, "output", "o", "", "Output file path for saving converted configuration (default: print to console)")
	setFlagAnnotation(convertCmd.Flags(), "output", []string{"output"})
	convertCmd.Flags().
		StringVarP(&format, "format", "f", "markdown", "Output format for conversion (markdown, json, yaml)")
	setFlagAnnotation(convertCmd.Flags(), "format", []string{"output"})
	convertCmd.Flags().
		BoolVar(&force, "force", false, "Force overwrite existing files without prompting for confirmation")
	setFlagAnnotation(convertCmd.Flags(), "force", []string{"output"})

	// Add shared template flags
	addSharedTemplateFlags(convertCmd)
	addSharedAuditFlags(convertCmd)

	// Flag groups for better organization
	convertCmd.Flags().SortFlags = false
}

var convertCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra command
	Use:     "convert [file ...]",
	Short:   "Convert OPNsense configuration files to structured formats.",
	GroupID: "core",
	Long: `The 'convert' command processes one or more OPNsense config.xml files and transforms
its content into structured formats. Supported output formats include Markdown (default),
JSON, and YAML. This allows for easier readability, documentation, programmatic access,
and auditing of your firewall configuration.

  The convert command focuses on format transformation without validation.
  TODO: Audit mode functionality is not yet complete and has been disabled.
  --comprehensive: Generate detailed, comprehensive reports
  --custom-template: Use custom template file for report generation

  OUTPUT FORMATS:
  The convert command supports multiple output formats:

  Basic formats (use --format flag):
    markdown                    - Standard markdown report (default)
    json                        - JSON format output
    yaml                        - YAML format output

  TODO: Audit mode functionality is not yet complete and has been disabled.
  Use --format for basic output formats (markdown, json, yaml).

The convert command focuses on conversion only and does not perform validation.
To validate your configuration files before conversion, use the 'validate' command.

You can either print the generated output directly to the console or save it to a
specified output file using the '--output' or '-o' flag. Use the '--format' or '-f'
flag to specify the output format (markdown, json, or yaml).

When processing multiple files, the --output flag will be ignored, and each output
file will be named based on its input file with the appropriate extension
(e.g., config.xml -> config.md, config.json, or config.yaml).

Examples:
  # Convert 'my_config.xml' and print markdown to console
  opnDossier convert my_config.xml

  # Convert 'my_config.xml' to JSON format
  opnDossier convert my_config.xml --format json

  # Convert 'my_config.xml' to YAML and save to file
  opnDossier convert my_config.xml -f yaml -o documentation.yaml

  # Generate comprehensive report
  opnDossier convert my_config.xml --comprehensive

  # TODO: Audit mode functionality is not yet complete and has been disabled
  # # Generate blue team audit report
  # opnDossier convert my_config.xml --mode blue --comprehensive

  # # Generate red team recon report with blackhat mode
  # opnDossier convert my_config.xml --mode red --blackhat-mode

  # # Run compliance checks with specific plugins
  # opnDossier convert my_config.xml --mode blue --plugins stig,sans

  # Convert with specific sections
  opnDossier convert my_config.xml --section system,network

  # Convert with format and text wrapping
  opnDossier convert my_config.xml --format json --wrap 120

  # Convert with custom template file
  opnDossier convert my_config.xml --custom-template /path/to/my-template.tmpl

  # Convert multiple files to JSON format
  opnDossier convert config1.xml config2.xml --format json

  # Convert 'backup_config.xml' with verbose logging
  opnDossier --verbose convert backup_config.xml -f json

  # Use environment variable to set default output location
  OPNDOSSIER_OUTPUT_FILE=./docs/network.md opnDossier convert config.xml

  # Force overwrite existing file without prompt
  opnDossier convert config.xml -o output.md --force

  # Include all system tunables (including defaults) in the report
  opnDossier convert config.xml --include-tunables

  # Validate before converting (recommended workflow)
  opnDossier validate config.xml && opnDossier convert config.xml -f json -o output.json`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}

		var wg sync.WaitGroup
		errs := make(chan error, len(args))

		// Create a timeout context for file processing
		timeoutCtx, cancel := context.WithTimeout(ctx, constants.DefaultProcessingTimeout)
		defer cancel()

		for _, filePath := range args {
			wg.Add(1)
			go func(fp string) {
				defer wg.Done()

				// Create context-aware logger for this goroutine with input file field
				ctxLogger := logger.WithContext(timeoutCtx).WithFields("input_file", fp)

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
				opnsense, err := p.Parse(timeoutCtx, file)
				if err != nil {
					ctxLogger.Error("Failed to parse XML", "error", err)
					// Enhanced error handling for different error types
					if parser.IsParseError(err) {
						if parseErr := parser.GetParseError(err); parseErr != nil {
							ctxLogger.Error(
								"XML syntax error detected",
								"line",
								parseErr.Line,
								"message",
								parseErr.Message,
							)
						}
					}
					if parser.IsValidationError(err) {
						ctxLogger.Error("Configuration validation failed")
					}
					errs <- fmt.Errorf("failed to parse XML from %s: %w", fp, err)
					return
				}
				ctxLogger.Debug("XML parsing completed successfully")

				// Build options for conversion with precedence: CLI flags > env vars > config > defaults
				eff := buildEffectiveFormat(format, Cfg)
				opt := buildConversionOptions(eff, Cfg)

				// Convert using the new markdown generator
				var output string
				var fileExt string

				ctxLogger.Debug(
					"Converting with options",
					"format",
					opt.Format,
					"theme",
					opt.Theme,
					"sections",
					opt.Sections,
				)

				// TODO: Audit mode functionality is not yet complete - disabled for now
				// Handle audit mode if specified
				// if opt.AuditMode != "" {
				// 	// Create plugin registry for audit mode
				// 	registry := audit.NewPluginRegistry()
				// 	output, err = handleAuditMode(timeoutCtx, opnsense, opt, ctxLogger, registry)
				// 	if err != nil {
				// 		ctxLogger.Error("Failed to generate audit report", "error", err)
				// 		errs <- fmt.Errorf("failed to generate audit report from %s: %w", fp, err)
				// 		return
				// 	}
				// } else {
				// Use hybrid generator for progressive migration
				output, err = generateWithHybridGenerator(timeoutCtx, opnsense, opt, ctxLogger)
				if err != nil {
					ctxLogger.Error("Failed to convert", "error", err)
					errs <- fmt.Errorf("failed to convert from %s: %w", fp, err)
					return
				}
				// }

				// Determine file extension based on format
				switch strings.ToLower(string(opt.Format)) {
				case "markdown", "md":
					fileExt = ".md"
				case "json":
					fileExt = ".json"
				case "yaml", "yml":
					fileExt = ".yaml"
				default:
					fileExt = ".md" // Default to markdown
				}

				ctxLogger.Debug("Conversion completed successfully")

				// Determine output path with smart naming and overwrite protection
				actualOutputFile, err := determineOutputPath(fp, outputFile, fileExt, Cfg, force)
				if err != nil {
					ctxLogger.Error("Failed to determine output path", "error", err)
					errs <- fmt.Errorf("failed to determine output path for %s: %w", fp, err)
					return
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
					if err := e.Export(timeoutCtx, output, actualOutputFile); err != nil {
						enhancedLogger.Error("Failed to export output", "error", err)
						errs <- fmt.Errorf("failed to export output to %s: %w", actualOutputFile, err)
						return
					}
					// Output exported successfully (no logging to avoid corrupting output)
				} else {
					enhancedLogger.Debug("Outputting to stdout")
					fmt.Print(output)
				}

				// Conversion process completed successfully (no logging to avoid corrupting output)
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

// buildEffectiveFormat returns the output format to use, giving precedence to the CLI flag, then the configuration file, and defaulting to "markdown" if neither is set.
func buildEffectiveFormat(flagFormat string, cfg *config.Config) string {
	// CLI flag takes precedence
	if flagFormat != "" {
		return flagFormat
	}

	// Use config value if CLI flag not specified
	if cfg != nil && cfg.GetFormat() != "" {
		return cfg.GetFormat()
	}

	// Default
	return "markdown"
}

// buildConversionOptions constructs a markdown.Options struct by merging CLI arguments and configuration values with defined precedence.
// CLI arguments take priority over configuration file values, which in turn override defaults. The resulting options control output format, template, section filtering, theme, and text wrapping for the conversion process.
func buildConversionOptions(
	format string,
	cfg *config.Config,
) markdown.Options {
	// Start with defaults
	opt := markdown.DefaultOptions()

	// Set format
	opt.Format = markdown.Format(format)

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

	// Theme: config > default (no CLI flag for theme in convert command)
	if cfg != nil && cfg.GetTheme() != "" {
		opt.Theme = markdown.Theme(cfg.GetTheme())
	}

	// Wrap width: CLI flag > config > default
	if sharedWrapWidth > 0 {
		opt.WrapWidth = sharedWrapWidth
	} else if cfg != nil && cfg.GetWrapWidth() > 0 {
		opt.WrapWidth = cfg.GetWrapWidth()
	}

	// TODO: Audit mode functionality is not yet complete - disabled for now
	// Audit mode: CLI flag > config > default
	// if sharedAuditMode != "" {
	// 	opt.AuditMode = markdown.AuditMode(sharedAuditMode)
	// }

	// TODO: Audit mode functionality is not yet complete - disabled for now
	// Blackhat mode: CLI flag only
	// opt.BlackhatMode = sharedBlackhatMode

	// Comprehensive: CLI flag only
	opt.Comprehensive = sharedComprehensive

	// TODO: Audit mode functionality is not yet complete - disabled for now
	// Selected plugins: CLI flag only
	// if len(sharedSelectedPlugins) > 0 {
	// 	opt.SelectedPlugins = sharedSelectedPlugins
	// }

	// Template directory: CLI flag only
	templateDir := getSharedTemplateDir()
	if templateDir != "" {
		opt.TemplateDir = templateDir
	}

	// Include tunables: CLI flag only
	opt.CustomFields["IncludeTunables"] = sharedIncludeTunables

	return opt
}

// determineOutputPath determines the output file path with smart naming and overwrite protection.
// It handles the following scenarios:
// 1. If outputFile is specified, use it (with overwrite protection)
// 2. If multiple files are being processed, use input filename with appropriate extension
// 3. If config has output_file but no CLI flag, use input filename with appropriate extension
// 4. If no output specified, return empty string (stdout)
//
// The function ensures no automatic directory creation and provides overwrite prompts
// unless the force flag is set.
func determineOutputPath(inputFile, outputFile, fileExt string, cfg *config.Config, force bool) (string, error) {
	// If no output file specified, return empty string for stdout
	if outputFile == "" && (cfg == nil || cfg.OutputFile == "") {
		return "", nil
	}

	var actualOutputFile string

	// Determine the output file path using switch statement
	switch {
	case outputFile != "":
		// CLI flag takes precedence
		actualOutputFile = outputFile
	case cfg != nil && cfg.OutputFile != "":
		// Use config value if CLI flag not specified
		actualOutputFile = cfg.OutputFile
	default:
		// Use input filename with appropriate extension as default
		base := filepath.Base(inputFile)
		ext := filepath.Ext(base)
		actualOutputFile = strings.TrimSuffix(base, ext) + fileExt
	}

	// Check if file already exists and handle overwrite protection
	if _, err := os.Stat(actualOutputFile); err == nil {
		// File exists, check if we should overwrite
		if !force {
			// Prompt user for confirmation (using stderr to avoid interfering with piped output)
			fmt.Fprintf(os.Stderr, "File '%s' already exists. Overwrite? (y/N): ", actualOutputFile)

			// Use bufio.NewReader to correctly capture entire input line including spaces
			reader := bufio.NewReader(os.Stdin)

			response, err := reader.ReadString('\n')
			if err != nil {
				return "", fmt.Errorf("failed to read user input: %w", err)
			}

			// Trim whitespace and newline characters
			response = strings.TrimSpace(response)

			// Empty input defaults to "N" (no)
			if response == "" {
				response = "N"
			}

			// Only proceed if user explicitly confirms with 'y' or 'Y'
			if response != "y" && response != "Y" {
				return "", ErrOperationCancelled
			}
		}
	}

	return actualOutputFile, nil
}

// generateWithHybridGenerator creates a hybrid generator and generates output using either
// programmatic generation (default) or template generation based on options.
func generateWithHybridGenerator(
	ctx context.Context,
	opnsense *model.OpnSenseDocument,
	opt markdown.Options,
	logger *log.Logger,
) (string, error) {
	// Create the programmatic builder
	builder := converter.NewMarkdownBuilder()

	// Create hybrid generator
	hybridGen := markdown.NewHybridGenerator(builder, logger)

	// If a custom template is specified, load it and set it on the hybrid generator
	if sharedCustomTemplate != "" {
		// Load the custom template file
		tmpl, err := loadCustomTemplate(sharedCustomTemplate)
		if err != nil {
			return "", fmt.Errorf("failed to load custom template: %w", err)
		}
		hybridGen.SetTemplate(tmpl)
	}

	// Generate the output
	return hybridGen.Generate(ctx, opnsense, opt)
}

// loadCustomTemplate loads a custom template from a file.
func loadCustomTemplate(templatePath string) (*template.Template, error) {
	// Read the template file
	content, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read template file: %w", err)
	}

	// Parse the template
	tmpl, err := template.New("custom").Parse(string(content))
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	return tmpl, nil
}
