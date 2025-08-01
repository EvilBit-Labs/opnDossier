// Package cmd provides the command-line interface for opnFocus.
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

	"github.com/spf13/cobra"
	"github.com/unclesp1d3r/opnFocus/internal/audit"
	"github.com/unclesp1d3r/opnFocus/internal/config"
	"github.com/unclesp1d3r/opnFocus/internal/constants"
	"github.com/unclesp1d3r/opnFocus/internal/export"
	"github.com/unclesp1d3r/opnFocus/internal/log"
	"github.com/unclesp1d3r/opnFocus/internal/markdown"
	"github.com/unclesp1d3r/opnFocus/internal/model"
	"github.com/unclesp1d3r/opnFocus/internal/parser"
)

var (
	outputFile      string   //nolint:gochecknoglobals // Cobra flag variable
	format          string   //nolint:gochecknoglobals // Output format (markdown, json, yaml)
	templateName    string   //nolint:gochecknoglobals // Template name to use
	sections        []string //nolint:gochecknoglobals // Sections to include
	themeName       string   //nolint:gochecknoglobals // Theme for rendering
	wrapWidth       int      //nolint:gochecknoglobals // Text wrap width
	force           bool     //nolint:gochecknoglobals // Force overwrite without prompt
	auditMode       string   //nolint:gochecknoglobals // Audit mode (standard, blue, red)
	blackhatMode    bool     //nolint:gochecknoglobals // Enable blackhat mode for red team reports
	comprehensive   bool     //nolint:gochecknoglobals // Generate comprehensive report
	selectedPlugins []string //nolint:gochecknoglobals // Selected compliance plugins
	templateDir     string   //nolint:gochecknoglobals // Custom template directory
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

	// Template and styling flags
	convertCmd.Flags().
		StringVar(&templateName, "template", "", "Template name to use for markdown generation (default: auto-selected). Available: standard, comprehensive, json, yaml, blue, red, blue-enhanced")
	setFlagAnnotation(convertCmd.Flags(), "template", []string{"template"})
	convertCmd.Flags().
		StringSliceVar(&sections, "section", []string{}, "Specific sections to include in output (comma-separated, e.g., system,network,firewall)")
	setFlagAnnotation(convertCmd.Flags(), "section", []string{"template"})
	convertCmd.Flags().StringVar(&themeName, "theme", "", "Theme for rendering output (light, dark, auto, none)")
	setFlagAnnotation(convertCmd.Flags(), "theme", []string{"template"})
	convertCmd.Flags().
		IntVar(&wrapWidth, "wrap", 0, "Text wrap width in characters (0 = no wrapping, recommended: 80-120)")
	setFlagAnnotation(convertCmd.Flags(), "wrap", []string{"template"})

	// Audit mode flags
	convertCmd.Flags().
		StringVar(&auditMode, "mode", "", "Audit mode for security-focused reporting (standard, blue, red)")
	setFlagAnnotation(convertCmd.Flags(), "mode", []string{"audit"})
	convertCmd.Flags().
		BoolVar(&blackhatMode, "blackhat-mode", false, "Enable blackhat commentary mode for red team reports (adds snarky commentary)")
	setFlagAnnotation(convertCmd.Flags(), "blackhat-mode", []string{"audit"})
	convertCmd.Flags().
		BoolVar(&comprehensive, "comprehensive", false, "Generate comprehensive detailed reports with full configuration analysis")
	setFlagAnnotation(convertCmd.Flags(), "comprehensive", []string{"audit"})
	convertCmd.Flags().
		StringSliceVar(&selectedPlugins, "plugins", []string{}, "Compliance plugins to run (comma-separated, e.g., stig,sans)")
	setFlagAnnotation(convertCmd.Flags(), "plugins", []string{"audit"})
	convertCmd.Flags().
		StringVar(&templateDir, "template-dir", "", "Custom template directory for user-defined templates (overrides built-in templates)")
	setFlagAnnotation(convertCmd.Flags(), "template-dir", []string{"template"})

	// Flag groups for better organization
	convertCmd.Flags().SortFlags = false

	// Mark mutually exclusive flags
	// Template and template-dir are mutually exclusive (template-dir overrides built-in templates)
	convertCmd.MarkFlagsMutuallyExclusive("template", "template-dir")

	// Mark flags that require audit mode
	convertCmd.MarkFlagsRequiredTogether("blackhat-mode", "mode")
	convertCmd.MarkFlagsRequiredTogether("plugins", "mode")

	// Note: mode and template can be used together, so no mutual exclusivity needed
}

var convertCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra command
	Use:     "convert [file ...]",
	Short:   "Convert OPNsense configuration files to structured formats.",
	GroupID: "core",
	Long: `The 'convert' command processes one or more OPNsense config.xml files and transforms
its content into structured formats. Supported output formats include Markdown (default),
JSON, and YAML. This allows for easier readability, documentation, programmatic access,
and auditing of your firewall configuration.

The convert command supports both basic conversion and audit report generation.
For basic conversion, it focuses on format transformation without validation.
For audit reports, use the --mode flag to generate security-focused reports.

AUDIT MODES:
  --mode standard: Generate neutral, comprehensive documentation (default)
  --mode blue: Generate defensive audit report with security findings and recommendations
  --mode red: Generate attacker-focused recon report highlighting attack surfaces

  Additional audit options:
    --blackhat-mode: Enable snarky commentary for red team reports
    --comprehensive: Generate detailed, comprehensive reports
    --plugins: Specify compliance plugins to run (e.g., stig,sans)
    --template-dir: Use custom templates for report generation

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
  opnFocus convert my_config.xml

  # Convert 'my_config.xml' to JSON format
  opnFocus convert my_config.xml --format json

  # Convert 'my_config.xml' to YAML and save to file
  opnFocus convert my_config.xml -f yaml -o documentation.yaml

  # Generate blue team audit report
  opnFocus convert my_config.xml --mode blue --comprehensive

  # Generate red team recon report with blackhat mode
  opnFocus convert my_config.xml --mode red --blackhat-mode

  # Run compliance checks with specific plugins
  opnFocus convert my_config.xml --mode blue --plugins stig,sans

  # Convert with specific theme and sections
  opnFocus convert my_config.xml --theme dark --section system,network

  # Convert with custom template and text wrapping
  opnFocus convert my_config.xml --template detailed --wrap 120

  # Convert multiple files to JSON format
  opnFocus convert config1.xml config2.xml --format json

  # Convert 'backup_config.xml' with verbose logging
  opnFocus --verbose convert backup_config.xml -f json

  # Use environment variable to set default output location
  OPNFOCUS_OUTPUT_FILE=./docs/network.md opnFocus convert config.xml

  # Force overwrite existing file without prompt
  opnFocus convert config.xml -o output.md --force

  # Validate before converting (recommended workflow)
  opnFocus validate config.xml && opnFocus convert config.xml -f json -o output.json`,
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
				opt := buildConversionOptions(eff, templateName, sections, themeName, wrapWidth, Cfg)

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

				// Handle audit mode if specified
				if opt.AuditMode != "" {
					// Create plugin registry for audit mode
					registry := audit.NewPluginRegistry()
					output, err = handleAuditMode(timeoutCtx, opnsense, opt, ctxLogger, registry)
					if err != nil {
						ctxLogger.Error("Failed to generate audit report", "error", err)
						errs <- fmt.Errorf("failed to generate audit report from %s: %w", fp, err)
						return
					}
				} else {
					// Standard markdown generation
					g, err := markdown.NewMarkdownGeneratorWithTemplates(ctxLogger.Logger, opt.TemplateDir)
					if err != nil {
						ctxLogger.Error("Failed to create markdown generator", "error", err)
						errs <- fmt.Errorf("failed to create markdown generator: %w", err)
						return
					}
					output, err = g.Generate(timeoutCtx, opnsense, opt)
					if err != nil {
						ctxLogger.Error("Failed to convert", "error", err)
						errs <- fmt.Errorf("failed to convert from %s: %w", fp, err)
						return
					}
				}

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
	format, template string,
	sections []string,
	theme string,
	wrap int,
	cfg *config.Config,
) markdown.Options {
	// Start with defaults
	opt := markdown.DefaultOptions()

	// Set format
	opt.Format = markdown.Format(format)

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

	// Theme: CLI flag > config > default
	if theme != "" {
		opt.Theme = markdown.Theme(theme)
	} else if cfg != nil && cfg.GetTheme() != "" {
		opt.Theme = markdown.Theme(cfg.GetTheme())
	}

	// Wrap width: CLI flag > config > default
	if wrap > 0 {
		opt.WrapWidth = wrap
	} else if cfg != nil && cfg.GetWrapWidth() > 0 {
		opt.WrapWidth = cfg.GetWrapWidth()
	}

	// Audit mode: CLI flag > config > default
	if auditMode != "" {
		opt.AuditMode = markdown.AuditMode(auditMode)
	}

	// Blackhat mode: CLI flag only
	opt.BlackhatMode = blackhatMode

	// Comprehensive: CLI flag only
	opt.Comprehensive = comprehensive

	// Selected plugins: CLI flag only
	if len(selectedPlugins) > 0 {
		opt.SelectedPlugins = selectedPlugins
	}

	// Template directory: CLI flag only
	if templateDir != "" {
		opt.TemplateDir = templateDir
	}

	return opt
}

// handleAuditMode generates an audit report using the audit mode controller and markdown generator.
func handleAuditMode(
	ctx context.Context,
	cfg *model.OpnSenseDocument,
	opts markdown.Options,
	logger *log.Logger,
	registry *audit.PluginRegistry,
) (string, error) {
	// Create audit mode controller with plugin registry
	controller := audit.NewModeController(registry, logger.Logger)

	// Convert audit mode and create config
	reportMode, err := convertAuditModeToReportMode(opts.AuditMode)
	if err != nil {
		return "", err
	}

	modeConfig := createModeConfig(reportMode, opts)

	// Generate audit report
	auditReport, err := controller.GenerateReport(ctx, cfg, modeConfig)
	if err != nil {
		return "", fmt.Errorf("failed to generate audit report: %w", err)
	}

	// Enrich the configuration for template rendering
	enrichedCfg := model.EnrichDocument(cfg)
	if enrichedCfg == nil {
		return "", ErrFailedToEnrichConfig
	}

	// Generate the base report
	result, err := generateBaseAuditReport(ctx, cfg, opts, logger)
	if err != nil {
		return "", err
	}

	// Append audit findings
	result = appendAuditFindings(result, auditReport)

	return result, nil
}

// convertAuditModeToReportMode converts markdown audit mode to audit report mode.
func convertAuditModeToReportMode(auditMode markdown.AuditMode) (audit.ReportMode, error) {
	switch auditMode {
	case markdown.AuditModeStandard:
		return audit.ModeStandard, nil
	case markdown.AuditModeBlue:
		return audit.ModeBlue, nil
	case markdown.AuditModeRed:
		return audit.ModeRed, nil
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedAuditMode, auditMode)
	}
}

// createModeConfig creates an audit mode configuration from options.
func createModeConfig(reportMode audit.ReportMode, opts markdown.Options) *audit.ModeConfig {
	return &audit.ModeConfig{
		Mode:            reportMode,
		BlackhatMode:    opts.BlackhatMode,
		Comprehensive:   opts.Comprehensive,
		SelectedPlugins: opts.SelectedPlugins,
		TemplateDir:     opts.TemplateDir,
	}
}

// generateBaseAuditReport generates the base audit report using template rendering.
func generateBaseAuditReport(
	ctx context.Context,
	cfg *model.OpnSenseDocument,
	opts markdown.Options,
	logger *log.Logger,
) (string, error) {
	// Create markdown generator for template rendering
	generator, err := markdown.NewMarkdownGeneratorWithTemplates(logger.Logger, opts.TemplateDir)
	if err != nil {
		return "", fmt.Errorf("failed to create markdown generator: %w", err)
	}

	// Build markdown options for audit mode
	markdownOpts := createAuditMarkdownOptions(opts)

	// Generate the audit report using template rendering
	result, err := generator.Generate(ctx, cfg, markdownOpts)
	if err != nil {
		return "", fmt.Errorf("failed to generate audit report: %w", err)
	}

	return result, nil
}

// createAuditMarkdownOptions creates markdown options specifically for audit mode.
func createAuditMarkdownOptions(opts markdown.Options) markdown.Options {
	return markdown.Options{
		Format:          markdown.FormatMarkdown,
		Comprehensive:   opts.Comprehensive,
		Template:        nil,
		TemplateName:    "",
		Sections:        nil,
		Theme:           markdown.ThemeAuto,
		WrapWidth:       0,
		EnableTables:    true,
		EnableColors:    true,
		EnableEmojis:    true,
		Compact:         false,
		IncludeMetadata: true,
		CustomFields:    make(map[string]any),
		AuditMode:       opts.AuditMode,
		BlackhatMode:    false,
		SelectedPlugins: nil,
		TemplateDir:     "",
	}
}

// appendAuditFindings appends audit findings summary to the report.
func appendAuditFindings(result string, auditReport *audit.Report) string {
	if len(auditReport.Findings) == 0 {
		return result
	}

	result += fmt.Sprintf("\n\n## Audit Findings Summary\n\nTotal Findings: %d\n\n", len(auditReport.Findings))
	for i, finding := range auditReport.Findings {
		result += fmt.Sprintf("### %d. %s\n\n**Severity:** %s\n**Component:** %s\n**Description:** %s\n\n",
			i+1, finding.Title, finding.Severity, finding.Component, finding.Description)
		if finding.Recommendation != "" {
			result += fmt.Sprintf("**Recommendation:** %s\n\n", finding.Recommendation)
		}
	}

	return result
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
