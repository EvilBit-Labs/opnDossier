// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
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
	setFlagAnnotation(convertCmd.Flags(), "output", []flagCategory{categoryOutput})
	convertCmd.Flags().
		StringVarP(&format, "format", "f", "markdown", "Output format for conversion (markdown, json, yaml, text, html)")
	setFlagAnnotation(convertCmd.Flags(), "format", []flagCategory{categoryOutput})
	convertCmd.Flags().
		BoolVar(&force, "force", false, "Force overwrite existing files without prompting for confirmation")
	setFlagAnnotation(convertCmd.Flags(), "force", []flagCategory{categoryOutput})

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
	GroupID:           groupCore,
	ValidArgsFunction: ValidXMLFiles,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// Get logger from CommandContext for validation warnings
		cmdCtx := GetCommandContext(cmd)
		var cmdLogger *logging.Logger
		if cmdCtx != nil {
			cmdLogger = cmdCtx.Logger
		}

		// Normalize flags (apply side-effects like --no-wrap → wrap=0)
		normalizeConvertFlags()

		// Reject a single --output shared across several inputs. Each worker
		// would write the same path and the last one would silently win.
		if err := validateMultiFileOutput(
			outputFile, len(args),
			"omit --output so each report is written to its own auto-named file, or convert one file at a time",
		); err != nil {
			return err
		}

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
  --output is rejected when several input files are given, because one
  destination cannot hold several reports. Multi-file runs instead write each
  report to its own file, auto-named after the input
  (config.xml -> config.md, config.json, ...), the same way audit does.
  Use --force to overwrite existing files without prompting. The prompt is
  answered on stdin, so when stdin is not a terminal it cannot be answered and
  --force is required instead.

RELATED:
  audit      - Convert plus compliance checks (STIG/SANS/firewall)
  display    - Convert then render to the terminal in one step
  validate   - Validate config.xml before conversion
  sanitize   - Redact a config.xml before distribution`,
	Example: `  # Convert configuration to markdown (default)
  opndossier convert my_config.xml

  # Convert to JSON format
  opndossier convert my_config.xml --format json

  # Convert to YAML and save to a file
  opndossier convert my_config.xml -f yaml -o documentation.yaml

  # Convert to self-contained HTML
  opndossier convert my_config.xml --format html -o report.html

  # Generate a comprehensive report
  opndossier convert my_config.xml --comprehensive

  # Convert only specific sections
  opndossier convert my_config.xml --section system,network

  # Convert multiple files to JSON (each output auto-named)
  opndossier convert config1.xml config2.xml --format json

  # Redact sensitive fields (passwords, SNMP community strings, private keys)
  opndossier convert config.xml --format json --redact

  # Validate then convert (recommended workflow)
  opndossier validate config.xml && opndossier convert config.xml -f json -o output.json`,
	Args: cobra.MinimumNArgs(1),
	RunE: runConvert,
}

// convertResult pairs a per-file outcome with its error slot so a single slice
// entry can represent either success or failure. Preserves input ordering for
// deterministic error aggregation and emission after wg.Wait().
type convertResult struct {
	output string
	err    error
}

// runConvert processes one or more configuration files through the convert
// pipeline. It parses and renders each file concurrently, then emits the
// results serially in input order (GOTCHAS §8.3: concurrent generation, serial
// emission — the same shape cmd/audit.go:runAudit uses).
//
// The output destination is resolved once, before any worker starts. Resolving
// it per file inside the workers meant several of them could target one path,
// and meant the overwrite prompt ran concurrently on stdin.
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

	// Resolve format once: it is a single flag for the whole run, and the
	// handler supplies the file extension the destination needs.
	eff := buildEffectiveFormat(format, cmdConfig)
	opt := buildConversionOptions(eff, cmdConfig)

	// Validate the format once up front rather than per file. The registry
	// lookup is the only thing that can reject it, and every file in the run
	// shares the same --format value. The handler also supplies the extension a
	// derived per-input destination needs.
	handler, err := converter.DefaultRegistry.Get(string(opt.Format))
	if err != nil {
		return fmt.Errorf(
			"%w: %q (supported: %s)",
			ErrUnsupportedOutputFormat,
			opt.Format,
			strings.Join(converter.DefaultRegistry.ValidFormatsWithAliases(), ", "),
		)
	}

	fileExt := handler.FileExtension()

	multiFile := len(args) > 1

	// A decline is returned rather than swallowed, so the command exits
	// non-zero. Reporting success for a run that wrote nothing leaves a caller
	// such as `convert config.xml && publish` unable to tell the two apart, and
	// audit already treats a decline as an error.
	destination, err := resolveConvertDestination(cmd, cmdConfig, cmdLogger, multiFile)
	if err != nil {
		return err
	}

	// Create a timeout context for file processing
	timeoutCtx, cancel := context.WithTimeout(ctx, constants.DefaultProcessingTimeout)
	defer cancel()

	// Use a semaphore to limit concurrent file operations.
	// This prevents resource exhaustion when processing many files.
	maxConcurrent := max(runtime.NumCPU(), 1)
	sem := make(chan struct{}, maxConcurrent)

	// Buffer per-file outcomes indexed by input position so both errors and
	// emission stay in input order regardless of completion order.
	results := make([]convertResult, len(args))

	var wg sync.WaitGroup

	for i, filePath := range args {
		wg.Add(1)

		go func(idx int, fp string) {
			defer wg.Done()

			results[idx] = processConvertFile(timeoutCtx, fp, sem, opt, cmdLogger, cmdConfig)
		}(i, filePath)
	}

	wg.Wait()

	// Emit serially in input order. Concurrent writes to a single destination
	// lose reports, and concurrent writes to stdout interleave once a report
	// exceeds the pipe buffer.
	var allErrors []error

	for i := range args {
		r := results[i]
		if r.err != nil {
			allErrors = append(allErrors, r.err)

			continue
		}

		// Every error here is collected, a decline included. A run that wrote
		// fewer reports than it was given inputs must not exit 0; that is the
		// same silent-incompleteness this branch set out to fix, reached a
		// different way.
		perInput, err := convertDestinationFor(cmd, cmdLogger, args[i], destination, multiFile, fileExt)
		if err != nil {
			allErrors = append(allErrors, fmt.Errorf("%s: %w", args[i], err))

			continue
		}

		if err := emitConvertOutput(ctx, cmd, cmdLogger, r.output, perInput); err != nil {
			allErrors = append(allErrors, err)
		}
	}

	return errors.Join(allErrors...)
}

// convertDestinationFor resolves where one report goes.
//
// Single-file runs use the destination already settled by
// resolveConvertDestination. Multi-file runs derive a per-input path instead, so
// each report lands in its own file. Concatenating them on stdout is not a
// usable alternative: markdown and text merge readably, but a second JSON
// document produces "}{" and fails to parse, two HTML documents give two
// doctypes, and two YAML documents without separators parse as one mapping in
// which the later keys silently replace the earlier ones.
//
// Overwrite protection runs here, in the serialized emission loop, rather than
// up front, matching cmd/audit_output.go. Prompting is safe here because
// emission runs on the parent goroutine; calling it from a worker would race
// the other workers for stdin.
func convertDestinationFor(
	cmd *cobra.Command,
	ctxLogger *logging.Logger,
	inputFile, destination string,
	multiFile bool,
	fileExt string,
) (string, error) {
	if !multiFile {
		return destination, nil
	}

	derived := derivePerInputOutputPath(inputFile, "", fileExt)

	if err := confirmOverwrite(os.Stdin, cmd.ErrOrStderr(), derived, force); err != nil {
		return "", err
	}

	ctxLogger.Debug("Derived per-input output path", "input_file", inputFile, "output_file", derived)

	return derived, nil
}

// resolveConvertDestination determines the single output path for the run and
// settles overwrite protection before any work happens.
//
// An empty return means stdout, which is the single-file default. Multi-file
// runs do not use this destination at all: --output is rejected in PreRunE and a
// configured output_file is ignored here, because one destination cannot hold
// several reports. Each of those reports gets its own path from
// convertDestinationFor instead.
func resolveConvertDestination(
	cmd *cobra.Command,
	cfg *config.Config,
	logger *logging.Logger,
	multiFile bool,
) (string, error) {
	if multiFile {
		if cfg != nil && cfg.OutputFile != "" {
			logger.Info(
				"Configured output_file ignored for multi-file convert; each report is written to its own auto-named file",
				"configured_output",
				cfg.OutputFile,
			)
		}

		return "", nil
	}

	destination := determineOutputPath(outputFile, cfg)
	if err := confirmOverwrite(os.Stdin, cmd.ErrOrStderr(), destination, force); err != nil {
		return "", err
	}

	return destination, nil
}

// processConvertFile runs the convert pipeline for a single input file under
// the shared concurrency semaphore and returns the rendered report. It performs
// no I/O emission, so it is safe to call from a goroutine; the parent writes
// the buffered results in input order (GOTCHAS §8.3).
//
// A context timeout or cancellation before the semaphore is acquired returns
// the ctx error wrapped with the input file path. All subsequent failures are
// wrapped with the input file path so aggregated errors identify the offending
// file.
func processConvertFile(
	ctx context.Context,
	fp string,
	sem chan struct{},
	opt converter.Options,
	cmdLogger *logging.Logger,
	cmdConfig *config.Config,
) convertResult {
	// Acquire semaphore slot with context awareness
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	case <-ctx.Done():
		return convertResult{err: fmt.Errorf("%s: %w", fp, ctx.Err())}
	}

	ctxLogger := cmdLogger.WithFields("input_file", fp)

	device, err := parseConvertInput(ctx, fp, ctxLogger, cmdConfig)
	if err != nil {
		return convertResult{err: err}
	}

	ctxLogger.Debug("Converting with options", "format", opt.Format, "theme", opt.Theme, "sections", opt.Sections)

	output, err := generateWithProgrammaticGenerator(ctx, device, opt, ctxLogger)
	if err != nil {
		ctxLogger.Error("Failed to convert", "error", err)

		return convertResult{err: fmt.Errorf("failed to convert from %s: %w", fp, err)}
	}

	ctxLogger.Debug("Conversion completed successfully")

	return convertResult{output: output}
}

// parseConvertInput cleans fp, opens the file, and parses it into a CommonDevice.
// All parse-side logging (Debug success, Warn per conversion warning, Error
// with detailed parse/validation context) stays here so processConvertFile
// remains a straightforward orchestrator. Distinct from diff.go's
// parseConfigFile which has different logging/warning semantics.
func parseConvertInput(
	ctx context.Context,
	fp string,
	ctxLogger *logging.Logger,
	cmdConfig *config.Config,
) (*common.CommonDevice, error) {
	cleanPath := filepath.Clean(fp)
	if !filepath.IsAbs(cleanPath) {
		abs, err := filepath.Abs(cleanPath)
		if err != nil {
			return nil, fmt.Errorf("failed to get absolute path for %s: %w", fp, err)
		}
		cleanPath = abs
	}

	file, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", fp, err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			ctxLogger.Error("failed to close file", "error", cerr)
		}
	}()

	ctxLogger.Debug("Parsing configuration file")
	device, warnings, err := parser.NewFactory(cfgparser.NewXMLParser()).
		CreateDevice(ctx, file, resolveDeviceType(), false)
	if err != nil {
		ctxLogger.Error("Failed to parse configuration", "error", err)
		if cfgparser.IsParseError(err) {
			if parseErr := cfgparser.GetParseError(err); parseErr != nil {
				ctxLogger.Error("XML syntax error detected",
					"line", parseErr.Line, "message", parseErr.Message)
			}
		}
		if cfgparser.IsValidationError(err) {
			ctxLogger.Error("Configuration validation failed")
		}
		return nil, fmt.Errorf("failed to parse configuration from %s: %w", fp, err)
	}

	ctxLogger.Debug("Configuration parsed successfully")
	if cmdConfig == nil || !cmdConfig.IsQuiet() {
		for _, w := range warnings {
			ctxLogger.Warn("conversion warning",
				"field", w.Field, "message", w.Message, "severity", w.Severity)
		}
	}
	return device, nil
}

// emitConvertOutput writes the converted report to actualOutputFile when
// non-empty, otherwise to cmd's stdout. The enhanced logger tags every log
// line with either output_file or output_mode=stdout so CLI logs stay
// attributable when multiple inputs run concurrently.
func emitConvertOutput(
	ctx context.Context,
	cmd *cobra.Command,
	ctxLogger *logging.Logger,
	output, actualOutputFile string,
) error {
	if actualOutputFile != "" {
		enhancedLogger := ctxLogger.WithFields("output_file", actualOutputFile)
		enhancedLogger.Debug("Exporting to file")
		e := export.NewFileExporter(ctxLogger)
		if err := e.Export(ctx, output, actualOutputFile); err != nil {
			enhancedLogger.Error("Failed to export output", "error", err)
			return fmt.Errorf("failed to export output to %s: %w", actualOutputFile, err)
		}
		return nil
	}

	enhancedLogger := ctxLogger.WithFields("output_mode", "stdout")
	enhancedLogger.Debug("Outputting to stdout")
	if _, err := fmt.Fprint(cmd.OutOrStdout(), output); err != nil {
		enhancedLogger.Error("Failed to write output to stdout", "error", err)
		return fmt.Errorf("failed to write output to stdout: %w", err)
	}
	return nil
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

// determineOutputPath resolves the output destination. An empty return means
// stdout. Precedence is --output, then a configured output_file.
//
// Overwrite protection is deliberately not applied here. Callers invoke
// confirmOverwrite themselves, so convert can settle it once before starting
// concurrent work rather than from inside a worker.
//
// This previously accepted the input filename and extension to auto-name the
// destination, but that branch was unreachable: a run with neither --output nor
// a configured output_file returns early for stdout, so the switch never hit its
// default. Callers wanting a derived per-input path build it themselves, as
// derivePerInputOutputPath does.
func determineOutputPath(outputFile string, cfg *config.Config) string {
	switch {
	case outputFile != "":
		return outputFile
	case cfg != nil && cfg.OutputFile != "":
		return cfg.OutputFile
	default:
		return ""
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
