// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	"github.com/EvilBit-Labs/opnDossier/internal/export"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/EvilBit-Labs/opnDossier/internal/parser"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
	ErrFailedToEnrichConfig    = errors.New("failed to enrich configuration")
	ErrUnsupportedOutputFormat = errors.New("unsupported output format")
)

// Format constants for output formats.
const (
	FormatMarkdown = "markdown"
	FormatJSON     = "json"
	FormatYAML     = "yaml"
)

// init registers the convert command and its flags with the root command.
//
// init registers the `convert` command with the root command and configures its command-line flags.
//
// It defines the primary flags used to control conversion output:
//   - `--output, -o` : file path to write the converted output (omitted to print to stdout).
//   - `--format, -f` : output format to produce; supported values are `markdown`, `json`, and `yaml` (default: `markdown`).
//   - `--force`      : overwrite existing output files without prompting.
//
// It also adds shared styling and content flags (sections, theme, wrap width, etc.) via addSharedTemplateFlags and
// disables automatic flag sorting to preserve logical flag grouping in help output.
//
// Examples:
//
//	opndossier convert input.xml                # prints markdown to stdout
//	opndossier convert -o out.md input.xml      # write markdown to out.md
//	opndossier convert -f json --force in.xml   # write JSON, overwriting any existing file
//
// Note: flag validation and conversion behavior are implemented separately; this function only wires up flags and help text.
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

	// Add shared styling and content flags
	addSharedTemplateFlags(convertCmd)

	// Add shared audit flags
	addSharedAuditFlags(convertCmd)

	// Register flag completion functions for better tab completion
	registerConvertFlagCompletions(convertCmd)

	// Flag groups for better organization
	convertCmd.Flags().SortFlags = false
}

// registerConvertFlagCompletions registers completion functions for convert command flags.
func registerConvertFlagCompletions(cmd *cobra.Command) {
	// Format flag completion
	if err := cmd.RegisterFlagCompletionFunc("format", ValidFormats); err != nil {
		// Log error but don't fail - completion is optional
		logger.Debug("failed to register format completion", "error", err)
	}

	// Section flag completion
	if err := cmd.RegisterFlagCompletionFunc("section", ValidSections); err != nil {
		logger.Debug("failed to register section completion", "error", err)
	}
}

var convertCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra command
	Use:               "convert [file ...]",
	Short:             "Convert OPNsense configuration files to structured formats.",
	GroupID:           "core",
	ValidArgsFunction: ValidXMLFiles,
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		// Get logger from CommandContext for validation warnings
		cmdCtx := GetCommandContext(cmd)
		var cmdLogger *log.Logger
		if cmdCtx != nil {
			cmdLogger = cmdCtx.Logger
		}

		// Validate flag combinations specific to convert command
		if err := validateConvertFlags(cmd.Flags(), cmdLogger); err != nil {
			return fmt.Errorf("convert command validation failed: %w", err)
		}

		return nil
	},
	Long: `The 'convert' command processes one or more OPNsense config.xml files and transforms
its content into structured formats. Supported output formats include Markdown (default),
JSON, and YAML. This allows for easier readability, documentation, and programmatic access
to your firewall configuration.

  OUTPUT FORMATS:
  The convert command supports multiple output formats:

  Basic formats (use --format flag):
    markdown                    - Standard markdown report (default)
    json                        - JSON format output
    yaml                        - YAML format output

  Additional options:
    --comprehensive             - Generate detailed, comprehensive reports

The convert command focuses on conversion only and does not perform validation.
To validate your configuration files before conversion, use the 'validate' command.

You can either print the generated output directly to the console or save it to a
specified output file using the '--output' or '-o' flag. Use the '--format' or '-f'
flag to specify the output format (markdown, json, or yaml).

When processing multiple files, the --output flag will be ignored, and each output
file will be named based on its input file with the appropriate extension
(e.g., config.xml -> config.md, config.json, or config.yaml).

Examples:
  # Convert configuration to markdown (default)
  opnDossier convert my_config.xml

  # Convert 'my_config.xml' to JSON format
  opnDossier convert my_config.xml --format json

  # Convert 'my_config.xml' to YAML and save to file
  opnDossier convert my_config.xml -f yaml -o documentation.yaml

  # Generate comprehensive report
  opnDossier convert my_config.xml --comprehensive

  # Convert with specific sections
  opnDossier convert my_config.xml --section system,network

  # Convert with format and text wrapping
  opnDossier convert my_config.xml --format json --wrap 120

  # Convert without text wrapping
  opnDossier convert my_config.xml --no-wrap

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

		// Get configuration and logger from CommandContext
		cmdCtx := GetCommandContext(cmd)
		if cmdCtx == nil {
			return errors.New("command context not initialized")
		}
		cmdLogger := cmdCtx.Logger
		cmdConfig := cmdCtx.Config

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
				ctxLogger := cmdLogger.WithContext(timeoutCtx).WithFields("input_file", fp)

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
				eff := buildEffectiveFormat(format, cmdConfig)
				opt := buildConversionOptions(eff, cmdConfig)

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

				// Generate output based on format
				output, err = generateOutputByFormat(timeoutCtx, opnsense, opt, ctxLogger)
				if err != nil {
					ctxLogger.Error("Failed to convert", "error", err)
					errs <- fmt.Errorf("failed to convert from %s: %w", fp, err)
					return
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
				actualOutputFile, err := determineOutputPath(fp, outputFile, fileExt, cmdConfig, force)
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
					e := export.NewFileExporter(ctxLogger)
					if err := e.Export(timeoutCtx, output, actualOutputFile); err != nil {
						enhancedLogger.Error("Failed to export output", "error", err)
						errs <- fmt.Errorf("failed to export output to %s: %w", actualOutputFile, err)
						return
					}
					// Output exported successfully (no logging to avoid corrupting output)
				} else {
					enhancedLogger.Debug("Outputting to stdout")

					fmt.Fprint(cmd.OutOrStdout(), output)
				}

				// Conversion process completed successfully (no logging to avoid corrupting output)
			}(filePath)
		}

		wg.Wait()
		close(errs)

		// Collect all errors and join them using errors.Join for proper unwrapping
		var allErrors []error
		for err := range errs {
			allErrors = append(allErrors, err)
		}

		return errors.Join(allErrors...)
	},
}

// buildEffectiveFormat determines the output format to use, giving precedence to the CLI flag, then the configuration file, and defaulting to "markdown" if neither is set.
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

// buildConversionOptions constructs a converter.Options struct by merging CLI arguments and configuration values with defined precedence.
// buildConversionOptions constructs a converter.Options value for the given output
// format by combining CLI-provided flags, the provided configuration, and defaults.
// CLI flags take precedence over configuration values, which in turn override defaults.
//
// The resulting options set:
//   - Format: based on the provided format argument.
//   - SuppressWarnings: enabled if cfg indicates quiet mode.
//   - Sections: uses CLI-provided sections if present, otherwise uses cfg sections.
//   - Theme: uses the theme from cfg when set.
//   - WrapWidth: CLI wrap width if specified (>=0), otherwise cfg wrap width if >=0,
//     otherwise -1 to indicate automatic behavior; 0 disables wrapping.
//   - Comprehensive: controlled by the CLI-only comprehensive flag.
//   - CustomFields["IncludeTunables"]: set from the CLI-only include-tunables flag.
//
// The function returns a fully populated converter.Options ready for use by the
// programmatic generator.
func buildConversionOptions(
	format string,
	cfg *config.Config,
) converter.Options {
	// Start with defaults
	opt := converter.DefaultOptions()

	// Set format
	opt.Format = converter.Format(format)

	// Propagate quiet flag to suppress warnings
	if cfg != nil && cfg.IsQuiet() {
		opt.SuppressWarnings = true
	}

	// Sections: CLI flag > config > default
	if len(sharedSections) > 0 {
		opt.Sections = sharedSections
	} else if cfg != nil && len(cfg.GetSections()) > 0 {
		opt.Sections = cfg.GetSections()
	}

	// Theme: config > default (no CLI flag for theme in convert command)
	if cfg != nil && cfg.GetTheme() != "" {
		opt.Theme = converter.Theme(cfg.GetTheme())
	}

	// Wrap width: CLI flag > config > default
	// -1 means auto-detect (not provided), 0 means no wrapping, >0 means specific width
	// Config values of -1 are treated as "not set" and fall through to default
	switch {
	case sharedWrapWidth >= 0:
		opt.WrapWidth = sharedWrapWidth
	case cfg != nil && cfg.GetWrapWidth() >= 0:
		opt.WrapWidth = cfg.GetWrapWidth()
	default:
		opt.WrapWidth = -1
	}

	// Comprehensive: CLI flag only
	opt.Comprehensive = sharedComprehensive

	// Include tunables: CLI flag only
	opt.CustomFields["IncludeTunables"] = sharedIncludeTunables

	// Audit mode options
	if sharedAuditMode != "" {
		opt.AuditMode = sharedAuditMode
	}
	opt.BlackhatMode = sharedBlackhatMode
	if len(sharedSelectedPlugins) > 0 {
		opt.SelectedPlugins = sharedSelectedPlugins
	}

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

// generateOutputByFormat generates the document output in the requested format using the programmatic generator.
// Supported formats are "markdown" (or "md"), "json", and "yaml" (or "yml").
// It returns the rendered output string, or an error if the format is unsupported or generation fails.
func generateOutputByFormat(
	ctx context.Context,
	opnsense *model.OpnSenseDocument,
	opt converter.Options,
	logger *log.Logger,
) (string, error) {
	// Determine the format to use
	format := strings.ToLower(string(opt.Format))

	switch format {
	case FormatMarkdown, "md", FormatJSON, FormatYAML, "yml":
		// Use programmatic generator for all formats
		// The HybridGenerator handles markdown (via builder), JSON, and YAML natively
		return generateWithProgrammaticGenerator(ctx, opnsense, opt, logger)
	default:
		return "", fmt.Errorf("%w: %q (supported: markdown, md, json, yaml, yml)", ErrUnsupportedOutputFormat, format)
	}
}

// generateWithProgrammaticGenerator creates and uses a generator that produces output using the programmatic Markdown builder.
// It returns the generated document content according to the provided conversion options, or an error if generation fails.
//
// Use this function when you need the output as a string for further processing
// (e.g., converting markdown to HTML). For direct file/stdout output, consider
// using generateToWriter for better memory efficiency.
func generateWithProgrammaticGenerator(
	ctx context.Context,
	opnsense *model.OpnSenseDocument,
	opt converter.Options,
	logger *log.Logger,
) (string, error) {
	// Create the programmatic builder
	reportBuilder := builder.NewMarkdownBuilder()

	// Create hybrid generator (configured for programmatic mode)
	hybridGen, err := converter.NewHybridGenerator(reportBuilder, logger)
	if err != nil {
		return "", fmt.Errorf("failed to create hybrid generator: %w", err)
	}

	// Generate the output
	return hybridGen.Generate(ctx, opnsense, opt)
}

// generateToWriter writes output directly to the provided io.Writer.
// This is more memory-efficient than generateWithProgrammaticGenerator as it
// streams markdown output section-by-section without accumulating the entire
// output in memory first.
//
// This function is currently unused but provides infrastructure for future
// streaming output support (e.g., direct file streaming, pipe support).
//
//nolint:unused // Infrastructure for future streaming output support
func generateToWriter(
	ctx context.Context,
	w io.Writer,
	opnsense *model.OpnSenseDocument,
	opt converter.Options,
	logger *log.Logger,
) error {
	// Create the programmatic builder
	reportBuilder := builder.NewMarkdownBuilder()

	// Create hybrid generator (configured for programmatic mode)
	hybridGen, err := converter.NewHybridGenerator(reportBuilder, logger)
	if err != nil {
		return fmt.Errorf("failed to create hybrid generator: %w", err)
	}

	// Generate directly to writer
	return hybridGen.GenerateToWriter(ctx, w, opnsense, opt)
}

// validateConvertFlags validates flag combinations and CLI options for the convert command.
// It ensures mutually exclusive wrap flags are not both set, checks that the chosen output
// format is one of markdown/md/json/yaml/yml, warns when section filtering is used with
// JSON or YAML (sections will be ignored), and enforces that an explicit wrap width falls
// within the supported range. Returns an error when flag combinations or values are invalid.
//
// The cmdLogger parameter is used for warnings; if nil, warnings are skipped.
func validateConvertFlags(flags *pflag.FlagSet, cmdLogger *log.Logger) error {
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

	// Validate format values
	if format != "" {
		validFormats := []string{"markdown", "md", "json", "yaml", "yml"}
		if !slices.Contains(validFormats, strings.ToLower(format)) {
			return fmt.Errorf("invalid format %q, must be one of: %s", format, strings.Join(validFormats, ", "))
		}
	}

	// Validate output format compatibility (warn if logger available)
	if cmdLogger != nil {
		if strings.EqualFold(format, "json") && len(sharedSections) > 0 {
			cmdLogger.Warn("section filtering not supported with JSON format, sections will be ignored")
		}
		if strings.EqualFold(format, "yaml") && len(sharedSections) > 0 {
			cmdLogger.Warn("section filtering not supported with YAML format, sections will be ignored")
		}
	}

	// Validate wrap width if specified
	if sharedWrapWidth > 0 && (sharedWrapWidth < MinWrapWidth || sharedWrapWidth > MaxWrapWidth) {
		return fmt.Errorf("wrap width %d out of recommended range [%d, %d]",
			sharedWrapWidth, MinWrapWidth, MaxWrapWidth)
	}

	// Validate audit mode if provided
	if sharedAuditMode != "" {
		validModes := []string{"standard", "blue", "red"}
		if !slices.Contains(validModes, strings.ToLower(sharedAuditMode)) {
			return fmt.Errorf("invalid audit mode %q, must be one of: %s",
				sharedAuditMode, strings.Join(validModes, ", "))
		}
	}

	// Validate audit plugins if provided
	if len(sharedSelectedPlugins) > 0 {
		validPlugins := []string{"stig", "sans", "firewall"}
		for _, p := range sharedSelectedPlugins {
			if !slices.Contains(validPlugins, strings.ToLower(p)) {
				return fmt.Errorf("invalid audit plugin %q, must be one of: %s",
					p, strings.Join(validPlugins, ", "))
			}
		}
	}

	return nil
}
