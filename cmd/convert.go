// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	"github.com/EvilBit-Labs/opnDossier/internal/export"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Package-level flag variables for the convert command, required by cobra's flag binding mechanism.
var (
	outputFile string //nolint:gochecknoglobals // Cobra flag variable
	format     string //nolint:gochecknoglobals // Output format (markdown, json, yaml, text, html)
	force      bool   //nolint:gochecknoglobals // Force overwrite without prompt
)

// ErrOperationCancelled is returned when the user cancels an operation.
var ErrOperationCancelled = errors.New("operation cancelled by user")

// Static errors for better error handling.
var (
	// ErrFailedToEnrichConfig is returned when configuration enrichment fails.
	ErrFailedToEnrichConfig = errors.New("failed to enrich configuration")
	// ErrUnsupportedOutputFormat is returned when an unsupported output format is specified.
	ErrUnsupportedOutputFormat = errors.New("unsupported output format")
)

// init registers the `convert` command with the root command and configures its command-line flags.
//
// It defines the primary flags used to control conversion output:
//   - `--output, -o` : file path to write the converted output (omitted to print to stdout).
//   - `--format, -f` : output format to produce; supported values are `markdown`, `json`, and `yaml` (default: `markdown`).
//   - `--force`      : overwrite existing output files without prompting.
//
// It also adds shared styling and content flags (sections, theme, wrap width, etc.) via addSharedContentFlags and
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
		StringVarP(&format, "format", "f", "markdown", "Output format for conversion (markdown, json, yaml, text, html)")
	setFlagAnnotation(convertCmd.Flags(), "format", []string{"output"})
	convertCmd.Flags().
		BoolVar(&force, "force", false, "Force overwrite existing files without prompting for confirmation")
	setFlagAnnotation(convertCmd.Flags(), "force", []string{"output"})

	// Add shared styling and content flags
	addSharedContentFlags(convertCmd)

	// Add shared redact flag
	addSharedRedactFlag(convertCmd)

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

// convertCmd is the cobra.Command for the convert subcommand.
var convertCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra command
	Use:               "convert [file ...]",
	Short:             "Convert OPNsense configuration files to structured formats.",
	GroupID:           "core",
	ValidArgsFunction: ValidXMLFiles,
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		// Get logger from CommandContext for validation warnings
		cmdCtx := GetCommandContext(cmd)
		var cmdLogger *logging.Logger
		if cmdCtx != nil {
			cmdLogger = cmdCtx.Logger
		}

		// Normalize flags (apply side-effects like --no-wrap → wrap=0)
		normalizeConvertFlags()

		// Validate flag combinations specific to convert command
		if err := validateConvertFlags(cmd.Flags(), cmdLogger); err != nil {
			return fmt.Errorf("convert command validation failed: %w", err)
		}

		return nil
	},
	Long: `The 'convert' command processes one or more OPNsense config.xml files and
transforms them into structured documentation and export formats. Use convert
when you need a human-readable report or a machine-readable export — not when
you need compliance analysis or structural validation.

OUTPUT FORMATS:
  Select the output encoding with --format:

    markdown  - Rendered markdown report (default)
    json      - JSON export for programmatic access
    yaml      - YAML export for configuration management
    text      - Plain text (markdown without ANSI formatting)
    html      - Self-contained HTML report

CONTENT OPTIONS:
  --comprehensive    - Emit every section, including rarely used ones
  --include-tunables - Include all system tunables (default suppresses defaults)
  --section          - Restrict output to specific sections (e.g. system,firewall)
  --wrap / --no-wrap - Control text wrapping for terminal rendering
  --redact           - Redact passwords, SNMP community strings, private keys

OUTPUT DESTINATION:
  By default, output is printed to stdout. Use --output/-o to save to a file.
  When processing multiple input files, --output is ignored and each output
  file is auto-named after the input (config.xml -> config.md, config.json, ...).
  Use --force to overwrite existing files without prompting.

RELATED:
  audit      - Convert plus compliance checks (STIG/SANS/firewall)
  display    - Convert then render to the terminal in one step
  validate   - Validate config.xml before conversion
  sanitize   - Redact a config.xml before distribution`,
	Example: `  # Convert configuration to markdown (default)
  opnDossier convert my_config.xml

  # Convert to JSON format
  opnDossier convert my_config.xml --format json

  # Convert to YAML and save to a file
  opnDossier convert my_config.xml -f yaml -o documentation.yaml

  # Convert to self-contained HTML
  opnDossier convert my_config.xml --format html -o report.html

  # Generate a comprehensive report
  opnDossier convert my_config.xml --comprehensive

  # Convert only specific sections
  opnDossier convert my_config.xml --section system,network

  # Convert multiple files to JSON (each output auto-named)
  opnDossier convert config1.xml config2.xml --format json

  # Redact sensitive fields (passwords, SNMP community strings, private keys)
  opnDossier convert config.xml --format json --redact

  # Validate then convert (recommended workflow)
  opnDossier validate config.xml && opnDossier convert config.xml -f json -o output.json`,
	Args: cobra.MinimumNArgs(1),
	RunE: runConvert,
}

// convertResult pairs a per-file outcome with its error slot so a single slice
// entry can represent either success or failure. Preserves input ordering for
// deterministic error aggregation after wg.Wait().
type convertResult struct {
	err error
}

// runConvert processes one or more configuration files through the convert
// pipeline. It parses each file concurrently and exports the rendered output
// to the configured destination (file or stdout). Per-file work is extracted
// into processConvertFile; results are buffered in an indexed slice and errors
// are joined via errors.Join after wg.Wait() (no channel — mirrors the
// cmd/audit.go:runAudit + processAuditFile pattern).
func runConvert(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// Validate device type flag early before any file processing
	if err := validateDeviceType(); err != nil {
		return err
	}

	// Get configuration and logger from CommandContext
	cmdCtx := GetCommandContext(cmd)
	if cmdCtx == nil {
		return errors.New("command context not initialized")
	}
	cmdLogger := cmdCtx.Logger
	cmdConfig := cmdCtx.Config

	// Create a timeout context for file processing
	timeoutCtx, cancel := context.WithTimeout(ctx, constants.DefaultProcessingTimeout)
	defer cancel()

	// Use a semaphore to limit concurrent file operations.
	// This prevents resource exhaustion when processing many files.
	maxConcurrent := max(runtime.NumCPU(), 1)
	sem := make(chan struct{}, maxConcurrent)

	// Buffer per-file outcomes indexed by input position. Replaces the former
	// sized errs channel: each goroutine writes exactly one entry, and the
	// parent goroutine aggregates after wg.Wait(). The indexed slice removes
	// the latent deadlock that would occur if the body ever emitted more than
	// one error per goroutine (see todo #112).
	results := make([]convertResult, len(args))

	var wg sync.WaitGroup

	for i, filePath := range args {
		wg.Add(1)

		go func(idx int, fp string) {
			defer wg.Done()

			results[idx] = processConvertFile(timeoutCtx, fp, sem, cmd, cmdLogger, cmdConfig)
		}(i, filePath)
	}

	wg.Wait()

	// Aggregate errors in input order via errors.Join for proper Unwrap() support.
	var allErrors []error

	for _, r := range results {
		if r.err != nil {
			allErrors = append(allErrors, r.err)
		}
	}

	return errors.Join(allErrors...)
}

// processConvertFile runs the full convert pipeline for a single input file
// under the shared concurrency semaphore. It parses the XML, generates the
// requested output format, resolves the output path, and exports to file or
// stdout — preserving the pre-refactor behavior where emission happens
// inside the worker (unlike audit, which defers emission to the parent).
//
// A context timeout or cancellation before the semaphore is acquired returns
// the ctx error immediately. All subsequent failures are wrapped with the
// input file path so aggregated errors identify the offending file.
func processConvertFile(
	ctx context.Context,
	fp string,
	sem chan struct{},
	cmd *cobra.Command,
	cmdLogger *logging.Logger,
	cmdConfig *config.Config,
) convertResult {
	// Acquire semaphore slot with context awareness
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	case <-ctx.Done():
		return convertResult{err: ctx.Err()}
	}

	// Create logger for this goroutine with input file field
	ctxLogger := cmdLogger.WithFields("input_file", fp)

	// Sanitize the file path
	cleanPath := filepath.Clean(fp)
	if !filepath.IsAbs(cleanPath) {
		// If not an absolute path, make it relative to the current working directory
		var err error

		cleanPath, err = filepath.Abs(cleanPath)
		if err != nil {
			return convertResult{err: fmt.Errorf("failed to get absolute path for %s: %w", fp, err)}
		}
	}

	// Read the file
	file, err := os.Open(cleanPath)
	if err != nil {
		return convertResult{err: fmt.Errorf("failed to open file %s: %w", fp, err)}
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			ctxLogger.Error("failed to close file", "error", cerr)
		}
	}()

	// Parse the XML and convert to platform-agnostic device model
	ctxLogger.Debug("Parsing configuration file")

	device, warnings, err := parser.NewFactory(cfgparser.NewXMLParser()).
		CreateDevice(ctx, file, resolveDeviceType(), false)
	if err != nil {
		ctxLogger.Error("Failed to parse configuration", "error", err)
		// Enhanced error handling for different error types
		if cfgparser.IsParseError(err) {
			if parseErr := cfgparser.GetParseError(err); parseErr != nil {
				ctxLogger.Error(
					"XML syntax error detected",
					"line",
					parseErr.Line,
					"message",
					parseErr.Message,
				)
			}
		}

		if cfgparser.IsValidationError(err) {
			ctxLogger.Error("Configuration validation failed")
		}

		return convertResult{err: fmt.Errorf("failed to parse configuration from %s: %w", fp, err)}
	}

	ctxLogger.Debug("Configuration parsed successfully")

	if cmdConfig == nil || !cmdConfig.IsQuiet() {
		for _, w := range warnings {
			ctxLogger.Warn("conversion warning",
				"field", w.Field,
				"message", w.Message,
				"severity", w.Severity,
			)
		}
	}

	// Build options for conversion with precedence: CLI flags > env vars > config > defaults
	eff := buildEffectiveFormat(format, cmdConfig)
	opt := buildConversionOptions(eff, cmdConfig)

	// Convert using the new markdown generator
	ctxLogger.Debug(
		"Converting with options",
		"format",
		opt.Format,
		"theme",
		opt.Theme,
		"sections",
		opt.Sections,
	)

	// Generate output based on format. The resolved FormatHandler is reused below
	// for the file extension — a second registry lookup would be redundant.
	output, handler, err := generateOutputByFormat(ctx, device, opt, ctxLogger)
	if err != nil {
		ctxLogger.Error("Failed to convert", "error", err)

		return convertResult{err: fmt.Errorf("failed to convert from %s: %w", fp, err)}
	}

	fileExt := handler.FileExtension()

	ctxLogger.Debug("Conversion completed successfully")

	// Determine output path with smart naming and overwrite protection
	actualOutputFile, err := determineOutputPath(fp, outputFile, fileExt, cmdConfig, force)
	if err != nil {
		ctxLogger.Error("Failed to determine output path", "error", err)

		return convertResult{err: fmt.Errorf("failed to determine output path for %s: %w", fp, err)}
	}

	// Create enhanced logger with output file information
	var enhancedLogger *logging.Logger
	if actualOutputFile != "" {
		enhancedLogger = ctxLogger.WithFields("output_file", actualOutputFile)
	} else {
		enhancedLogger = ctxLogger.WithFields("output_mode", "stdout")
	}

	// Export or print the output
	if actualOutputFile != "" {
		enhancedLogger.Debug("Exporting to file")
		e := export.NewFileExporter(ctxLogger)

		if err := e.Export(ctx, output, actualOutputFile); err != nil {
			enhancedLogger.Error("Failed to export output", "error", err)

			return convertResult{err: fmt.Errorf("failed to export output to %s: %w", actualOutputFile, err)}
		}
		// Output exported successfully (no logging to avoid corrupting output)
	} else {
		enhancedLogger.Debug("Outputting to stdout")

		if _, err := fmt.Fprint(cmd.OutOrStdout(), output); err != nil {
			enhancedLogger.Error("Failed to write output to stdout", "error", err)

			return convertResult{err: fmt.Errorf("failed to write output to stdout: %w", err)}
		}
	}

	// Conversion process completed successfully (no logging to avoid corrupting output)
	return convertResult{}
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
	return string(converter.FormatMarkdown)
}

// normalizeFormat maps format aliases to their canonical converter.Format values
// using the converter.DefaultRegistry as the single source of truth.
// Unrecognized formats are passed through as-is for downstream validation.
func normalizeFormat(format string) converter.Format {
	canonical, _ := converter.DefaultRegistry.Canonical(format)

	return converter.Format(canonical)
}

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
//   - IncludeTunables: set from the CLI-only include-tunables flag.
//
// The function returns a fully populated converter.Options ready for use by the
// programmatic generator.
func buildConversionOptions(
	format string,
	cfg *config.Config,
) converter.Options {
	// Start with defaults
	opt := converter.DefaultOptions()

	// Set format, normalizing aliases to canonical values
	opt.Format = normalizeFormat(format)

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
	opt.IncludeTunables = sharedIncludeTunables

	// Redact: CLI flag only
	opt.Redact = sharedRedact

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
// Supported formats are "markdown" (or "md"), "json", "yaml" (or "yml"), "text" (or "txt"), and "html" (or "htm").
// It returns the rendered output, the resolved FormatHandler (for file-extension lookups), or an error
// if the format is unsupported or generation fails.
//
// The handler is resolved via a single DefaultRegistry.Get call — callers should NOT perform their own
// lookup, as that would duplicate work and invent an impossible-by-construction error branch.
func generateOutputByFormat(
	ctx context.Context,
	device *common.CommonDevice,
	opt converter.Options,
	logger *logging.Logger,
) (string, converter.FormatHandler, error) {
	// Validate format via registry once and reuse the resolved handler.
	handler, err := converter.DefaultRegistry.Get(string(opt.Format))
	if err != nil {
		return "", nil, fmt.Errorf(
			"%w: %q (supported: %s)",
			ErrUnsupportedOutputFormat,
			opt.Format,
			strings.Join(converter.DefaultRegistry.ValidFormatsWithAliases(), ", "),
		)
	}

	// Use programmatic generator for all formats.
	// The HybridGenerator handles markdown (via builder), JSON, YAML, text, and HTML natively.
	output, err := generateWithProgrammaticGenerator(ctx, device, opt, logger)
	if err != nil {
		return "", nil, err
	}
	return output, handler, nil
}

// generateWithProgrammaticGenerator creates and uses a generator that produces output using the programmatic Markdown builder.
// It returns the generated document content according to the provided conversion options, or an error if generation fails.
//
// Use this function when you need the output as a string for further processing
// (e.g., converting markdown to HTML). For direct file/stdout output, consider
// using generateToWriter for better memory efficiency.
func generateWithProgrammaticGenerator(
	ctx context.Context,
	device *common.CommonDevice,
	opt converter.Options,
	logger *logging.Logger,
) (string, error) {
	// Create the programmatic builder
	reportBuilder := builder.NewMarkdownBuilder()

	// Create hybrid generator (configured for programmatic mode)
	hybridGen, err := converter.NewHybridGenerator(reportBuilder, logger)
	if err != nil {
		return "", fmt.Errorf("failed to create hybrid generator: %w", err)
	}

	// Generate the output
	return hybridGen.Generate(ctx, device, opt)
}

// normalizeConvertFlags applies side-effects to shared flag variables before validation.
// When --no-wrap is set, it forces the wrap width to zero.
func normalizeConvertFlags() {
	if sharedNoWrap {
		sharedWrapWidth = 0
	}
}

// validateConvertFlags validates flag combinations and CLI options for the convert command.
// It delegates format, wrap, and section validation to validateOutputFlags.
// The cmdLogger parameter is used for structured warnings; if nil, warnings fall back to stderr.
func validateConvertFlags(flags *pflag.FlagSet, cmdLogger *logging.Logger) error {
	return validateOutputFlags(flags, cmdLogger)
}
