// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"

	"github.com/EvilBit-Labs/opnDossier/internal/audit"
	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/spf13/cobra"
)

// Package-level flag variables for the audit command, required by cobra's flag binding mechanism.
var (
	auditMode         string   //nolint:gochecknoglobals // Cobra flag variable — audit reporting mode
	auditPlugins      []string //nolint:gochecknoglobals // Cobra flag variable — selected compliance plugins
	auditPluginDir    string   //nolint:gochecknoglobals // Cobra flag variable — dynamic plugin directory
	auditFailuresOnly bool     //nolint:gochecknoglobals // Cobra flag variable — show only failing controls
)

// init registers the audit command with the root command and configures its command-line flags.
func init() {
	rootCmd.AddCommand(auditCmd)

	// Audit-specific flags (shorter names since this is the dedicated audit command)
	auditCmd.Flags().
		StringVar(&auditMode, "mode", "blue", "Audit mode (blue|red)")
	setFlagAnnotation(auditCmd.Flags(), "mode", []string{"audit"})

	auditCmd.Flags().
		StringSliceVar(&auditPlugins, "plugins", []string{}, "Compliance plugins to run (stig,sans,firewall)")
	setFlagAnnotation(auditCmd.Flags(), "plugins", []string{"audit"})

	auditCmd.Flags().
		StringVar(&auditPluginDir, "plugin-dir", "", "Directory containing dynamic .so compliance plugins")
	setFlagAnnotation(auditCmd.Flags(), "plugin-dir", []string{"audit"})

	auditCmd.Flags().
		BoolVar(&auditFailuresOnly, "failures-only", false, "Show only failing controls in blue mode plugin results tables")
	setFlagAnnotation(auditCmd.Flags(), "failures-only", []string{"audit"})

	// Output and format flags (reuse existing package-level variables)
	auditCmd.Flags().
		StringVarP(&format, "format", "f", "markdown", "Output format for audit report (markdown, json, yaml, text, html)")
	setFlagAnnotation(auditCmd.Flags(), "format", []string{"output"})

	auditCmd.Flags().
		StringVarP(&outputFile, "output", "o", "", "Output file path for saving audit report (default: print to console)")
	setFlagAnnotation(auditCmd.Flags(), "output", []string{"output"})

	auditCmd.Flags().
		BoolVar(&force, "force", false, "Force overwrite existing files without prompting for confirmation")
	setFlagAnnotation(auditCmd.Flags(), "force", []string{"output"})

	// Add shared styling and content flags
	addSharedTemplateFlags(auditCmd)

	// Add shared redact flag
	addSharedRedactFlag(auditCmd)

	// Register flag completion functions for better tab completion
	registerAuditFlagCompletions(auditCmd)

	// Preserve logical flag grouping in help output
	auditCmd.Flags().SortFlags = false
}

// registerAuditFlagCompletions registers completion functions for audit command flags.
func registerAuditFlagCompletions(cmd *cobra.Command) {
	if err := cmd.RegisterFlagCompletionFunc("mode", ValidAuditModes); err != nil {
		logger.Debug("failed to register mode completion", "error", err)
	}

	if err := cmd.RegisterFlagCompletionFunc("plugins", ValidAuditPlugins); err != nil {
		logger.Debug("failed to register plugins completion", "error", err)
	}

	if err := cmd.RegisterFlagCompletionFunc("format", ValidFormats); err != nil {
		logger.Debug("failed to register format completion", "error", err)
	}

	if err := cmd.RegisterFlagCompletionFunc("section", ValidSections); err != nil {
		logger.Debug("failed to register section completion", "error", err)
	}
}

// auditCmd is the cobra.Command for the audit subcommand.
//
//nolint:gochecknoglobals // Cobra command
var auditCmd = &cobra.Command{
	Use:               "audit [file ...]",
	Short:             "Run security audit and compliance checks on OPNsense configurations.",
	GroupID:           "audit",
	ValidArgsFunction: ValidXMLFiles,
	Args:              cobra.MinimumNArgs(1),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// Get logger from CommandContext for validation warnings
		cmdCtx := GetCommandContext(cmd)
		var cmdLogger *logging.Logger
		if cmdCtx != nil {
			cmdLogger = cmdCtx.Logger
		}

		// Normalize flags (apply side-effects like --no-wrap -> wrap=0)
		normalizeConvertFlags()

		// Validate audit mode
		validModes := []string{"blue", "red"}
		if !slices.Contains(validModes, strings.ToLower(auditMode)) {
			return fmt.Errorf("invalid audit mode %q, must be one of: %s",
				auditMode, strings.Join(validModes, ", "))
		}

		// Reject --plugins when the selected mode does not execute compliance checks.
		// Only blue mode runs RunComplianceChecks; red mode ignores plugins.
		if len(auditPlugins) > 0 && !strings.EqualFold(auditMode, "blue") {
			return fmt.Errorf("--plugins is only supported with --mode blue; %q mode does not run compliance checks",
				auditMode)
		}

		// Reject --failures-only when the selected mode does not execute compliance checks.
		if auditFailuresOnly && !strings.EqualFold(auditMode, "blue") {
			return fmt.Errorf(
				"--failures-only is only supported with --mode blue; %q mode does not run compliance checks",
				auditMode,
			)
		}

		// Reject --output with multiple input files to prevent output clobbering.
		// Each file produces a separate report auto-named as <input>-audit.<ext>.
		if outputFile != "" && len(args) > 1 {
			return errors.New(
				"--output cannot be used with multiple input files; omit --output to auto-name each report as <input>-audit.<ext>",
			)
		}

		// Validate format/wrap flag combinations (shared output flags only,
		// not convert-specific audit globals)
		if err := validateOutputFlags(cmd.Flags(), cmdLogger); err != nil {
			return fmt.Errorf("audit command validation failed: %w", err)
		}

		return nil
	},
	Long: `The 'audit' command runs security audit and compliance checks on one or more
OPNsense config.xml files. It produces a report with compliance findings,
security recommendations, and risk assessments based on the selected audit
mode and compliance plugins.

  AUDIT MODES:
  Select the audit perspective using the --mode flag:

    blue      - Defensive audit with security findings and recommendations (default)
    red       - Attacker-focused recon report highlighting attack surfaces

  COMPLIANCE PLUGINS (blue mode only):
  Select compliance checks to run with the --plugins flag (requires --mode blue):

    stig      - Security Technical Implementation Guide
    sans      - SANS Firewall Baseline
    firewall  - Firewall Configuration Analysis

  When no plugins are specified in blue mode, all available plugins are run.
  The --plugins flag is not accepted with red mode.

  CONTROL FILTERING (blue mode only):
  Use --failures-only to show only non-compliant controls in plugin results tables.
  When omitted, all controls (PASS and FAIL) are shown.

  OUTPUT FORMATS:
  The audit report can be exported in multiple formats using the --format flag:

    markdown  - Standard markdown report (default)
    json      - JSON format for programmatic access
    yaml      - YAML format for configuration management
    text      - Plain text output (markdown without formatting)
    html      - Self-contained HTML report for web viewing

Examples:
  # Run a blue team audit with all compliance plugins (default)
  opnDossier audit config.xml

  # Blue team defensive audit with specific plugins
  opnDossier audit config.xml --plugins stig,sans

  # Red team attack surface analysis
  opnDossier audit config.xml --mode red

  # Export audit report as JSON
  opnDossier audit config.xml --format json -o audit-report.json

  # Run audit on multiple files (each report is auto-named: config1-audit.md, config2-audit.md)
  opnDossier audit config1.xml config2.xml --mode blue

  # Comprehensive blue team audit with all compliance checks
  opnDossier audit config.xml --mode blue --comprehensive --plugins stig,sans,firewall

  # Show only failing controls in blue mode
  opnDossier audit config.xml --mode blue --failures-only

  # Redact sensitive fields from audit output
  opnDossier audit config.xml --redact

  # Quiet mode (errors only)
  opnDossier --quiet audit config.xml --mode blue

  # Verbose audit diagnostics
  opnDossier --verbose audit config.xml --mode blue --plugins stig,sans`,
	RunE: runAudit,
}

// runAudit processes one or more configuration files through the audit pipeline.
// It parses each file concurrently, runs compliance checks with the selected audit
// mode and plugins, buffers the results, and then serializes the final output
// writes to avoid interleaved or overwritten reports.
func runAudit(cmd *cobra.Command, args []string) error {
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

	// For multi-file runs, reject any shared output destination — whether from
	// the CLI flag (already validated in PreRunE) or from configuration defaults
	// (e.g., config file output_file or OPNDOSSIER_OUTPUT_FILE). Each file must
	// produce a uniquely named report to prevent later reports overwriting earlier ones.
	multiFile := len(args) > 1
	if multiFile && cmdConfig != nil && cmdConfig.OutputFile != "" {
		cmdLogger.Info(
			"Configured output_file ignored for multi-file audit; each report will be auto-named from input filename",
			"configured_output",
			cmdConfig.OutputFile,
		)
	}

	// Create a timeout context for file processing
	timeoutCtx, cancel := context.WithTimeout(ctx, constants.DefaultProcessingTimeout)
	defer cancel()

	// Use a semaphore to limit concurrent file operations
	maxConcurrent := max(runtime.NumCPU(), 1)
	sem := make(chan struct{}, maxConcurrent)

	// Buffer results: each goroutine produces an auditResult or an error.
	// Results are collected here and emitted serially after all processing completes.
	type resultOrError struct {
		result auditResult
		err    error
	}

	results := make([]resultOrError, len(args))

	var wg sync.WaitGroup

	for i, filePath := range args {
		wg.Add(1)

		go func(idx int, fp string) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					cmdLogger.WithContext(timeoutCtx).Error(
						"goroutine panicked during audit processing",
						"input_file", fp,
						"panic", r,
						"stack", string(debug.Stack()),
					)
					results[idx] = resultOrError{
						err: fmt.Errorf("panic processing %s: %v", fp, r),
					}
				}
			}()

			// Acquire semaphore slot with context awareness
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-timeoutCtx.Done():
				results[idx] = resultOrError{err: timeoutCtx.Err()}

				return
			}

			output, err := generateAuditOutput(timeoutCtx, fp, cmdLogger, cmdConfig)
			if err != nil {
				results[idx] = resultOrError{err: err}
			} else {
				results[idx] = resultOrError{result: auditResult{inputFile: fp, output: output}}
			}
		}(i, filePath)
	}

	wg.Wait()

	// Serialize emission: write results in input order after all processing completes.
	// This prevents interleaved stdout writes and file clobbering.
	var allErrors []error

	for _, r := range results {
		if r.err != nil {
			allErrors = append(allErrors, r.err)

			continue
		}

		if err := emitAuditResult(ctx, cmd, r.result, cmdLogger, cmdConfig, multiFile); err != nil {
			allErrors = append(allErrors, err)
		}
	}

	return errors.Join(allErrors...)
}

// generateAuditOutput handles parsing and audit generation for a single configuration
// file, returning the rendered report string. It does NOT perform any I/O emission
// (stdout or file writes) so that it is safe to call concurrently.
func generateAuditOutput(
	ctx context.Context,
	fp string,
	cmdLogger *logging.Logger,
	cmdConfig *config.Config,
) (string, error) {
	// Create context-aware logger for this goroutine with input file field
	ctxLogger := cmdLogger.WithContext(ctx).WithFields("input_file", fp)

	// Sanitize the file path
	cleanPath := filepath.Clean(fp)
	if !filepath.IsAbs(cleanPath) {
		var err error

		cleanPath, err = filepath.Abs(cleanPath)
		if err != nil {
			return "", fmt.Errorf("failed to get absolute path for %s: %w", fp, err)
		}
	}

	// Read the file
	file, err := os.Open(cleanPath)
	if err != nil {
		return "", fmt.Errorf("failed to open file %s: %w", fp, err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			ctxLogger.Warn("failed to close file", "error", cerr)
		}
	}()

	// Parse the XML and convert to platform-agnostic device model
	ctxLogger.Debug("Parsing configuration file")

	device, warnings, parseErr := parser.NewFactory(cfgparser.NewXMLParser()).
		CreateDevice(ctx, file, resolveDeviceType(), false)
	if parseErr != nil {
		ctxLogger.Error("Failed to parse configuration", "error", parseErr)

		if cfgparser.IsParseError(parseErr) {
			if pe := cfgparser.GetParseError(parseErr); pe != nil {
				ctxLogger.Error("XML syntax error detected", "line", pe.Line, "message", pe.Message)
			}
		}

		if cfgparser.IsValidationError(parseErr) {
			ctxLogger.Error("Configuration validation failed")
		}

		return "", fmt.Errorf("failed to parse configuration from %s: %w", fp, parseErr)
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

	// Build conversion options with precedence: CLI flags > env vars > config > defaults
	eff := buildEffectiveFormat(format, cmdConfig)
	opt := buildConversionOptions(eff, cmdConfig)

	// Build audit options from audit-specific flag variables (not shared globals)
	auditOpts := audit.Options{
		AuditMode:       auditMode,
		SelectedPlugins: auditPlugins,
		FailuresOnly:    auditFailuresOnly,
	}

	if auditPluginDir != "" {
		auditOpts.PluginDir = auditPluginDir
		auditOpts.ExplicitPluginDir = true
	}

	// Always route through audit mode — this is the dedicated audit command
	ctxLogger.Debug("Running audit",
		"mode", auditOpts.AuditMode,
		"plugins", auditOpts.SelectedPlugins,
	)

	output, err := handleAuditMode(ctx, device, auditOpts, opt, ctxLogger)
	if err != nil {
		ctxLogger.Error("Failed to generate audit report", "error", err)

		return "", fmt.Errorf("failed to generate audit report for %s: %w", fp, err)
	}

	return output, nil
}
