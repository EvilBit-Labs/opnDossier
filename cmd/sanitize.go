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

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/sanitizer"
	"github.com/spf13/cobra"
)

// Sanitize command flag variables.
var (
	sanitizeMode        string //nolint:gochecknoglobals // Cobra flag variable
	sanitizeOutputFile  string //nolint:gochecknoglobals // Output file path
	sanitizeMappingFile string //nolint:gochecknoglobals // Mapping file output path
	sanitizeForce       bool   //nolint:gochecknoglobals // Force overwrite without prompt
)

// Sanitize mode constants matching the sanitizer package.
const (
	// SanitizeModeAggressive redacts all sensitive data for public sharing.
	SanitizeModeAggressive = "aggressive"
	// SanitizeModeModerate redacts most data but preserves some network structure.
	SanitizeModeModerate = "moderate"
	// SanitizeModeMinimal redacts only the most sensitive data (passwords, keys).
	SanitizeModeMinimal = "minimal"
)

// Static errors for sanitize command.
var (
	// ErrInvalidSanitizeMode is returned when an invalid sanitization mode is specified.
	ErrInvalidSanitizeMode = errors.New("invalid sanitize mode")
)

// opndossier sanitize config.xml --mode aggressive --output sanitized.xml --mapping map.json --force.
func init() {
	rootCmd.AddCommand(sanitizeCmd)

	// Mode flag
	sanitizeCmd.Flags().
		StringVarP(&sanitizeMode, "mode", "m", SanitizeModeModerate,
			"Sanitization mode: aggressive (public sharing), moderate (internal sharing), minimal (credentials only)")
	setFlagAnnotation(sanitizeCmd.Flags(), "mode", []string{"sanitize"})

	// Output flag
	sanitizeCmd.Flags().
		StringVarP(&sanitizeOutputFile, "output", "o", "",
			"Output file path for sanitized configuration (default: print to console)")
	setFlagAnnotation(sanitizeCmd.Flags(), "output", []string{"output"})

	// Mapping file flag
	sanitizeCmd.Flags().
		StringVar(&sanitizeMappingFile, "mapping", "",
			"Output path for mapping file (JSON) that documents original→redacted mappings")
	setFlagAnnotation(sanitizeCmd.Flags(), "mapping", []string{"output"})

	// Force flag
	sanitizeCmd.Flags().
		BoolVar(&sanitizeForce, "force", false,
			"Force overwrite existing files without prompting for confirmation")
	setFlagAnnotation(sanitizeCmd.Flags(), "force", []string{"output"})

	// Register flag completion functions
	registerSanitizeFlagCompletions(sanitizeCmd)

	// Flag groups for better organization
	sanitizeCmd.Flags().SortFlags = false
}

// registerSanitizeFlagCompletions registers shell completion handlers for the sanitize command's flags.
// It attaches a completer for the `--mode` flag that suggests valid sanitize modes (aggressive, moderate, minimal).
//
// cmd is the Cobra command representing the sanitize subcommand.
func registerSanitizeFlagCompletions(cmd *cobra.Command) {
	// Mode flag completion
	if err := cmd.RegisterFlagCompletionFunc("mode", ValidSanitizeModes); err != nil {
		logger.Debug("failed to register mode completion", "error", err)
	}
}

// ValidSanitizeModes provides tab-completion candidates for the sanitize command's --mode flag.
// It returns the three valid modes with brief descriptions and a shell directive that disables file completion.
func ValidSanitizeModes(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	return []string{
		SanitizeModeAggressive + "\tRedact all sensitive data for public sharing",
		SanitizeModeModerate + "\tRedact most sensitive data, preserve network structure",
		SanitizeModeMinimal + "\tRedact only credentials (passwords, keys, secrets)",
	}, cobra.ShellCompDirectiveNoFileComp
}

var sanitizeCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra command
	Use:               "sanitize [file]",
	Short:             "Redact sensitive data from OPNsense configuration files.",
	GroupID:           "utility",
	ValidArgsFunction: ValidXMLFiles,
	PreRunE: func(_ *cobra.Command, _ []string) error {
		// Validate sanitize mode
		if !sanitizer.IsValidMode(sanitizeMode) {
			validModes := []string{SanitizeModeAggressive, SanitizeModeModerate, SanitizeModeMinimal}
			return fmt.Errorf("%w: %q, must be one of: %s",
				ErrInvalidSanitizeMode, sanitizeMode, strings.Join(validModes, ", "))
		}
		return nil
	},
	Long: `The 'sanitize' command redacts sensitive information from OPNsense configuration
files, making them safe to share for troubleshooting, documentation, or public
reporting without exposing credentials, IP addresses, or other sensitive data.

  SANITIZATION MODES:
  Choose the appropriate mode based on your sharing context:

    aggressive   - Maximum redaction for public sharing (forums, GitHub issues)
                   Redacts: passwords, keys, certificates, all IPs, MACs, emails,
                   hostnames, usernames, domains

    moderate     - Balanced redaction for internal sharing (default)
                   Redacts: passwords, keys, public IPs, MACs, emails
                   Preserves: private IPs, hostnames (for network topology analysis)

    minimal      - Credential-only redaction for trusted environments
                   Redacts: passwords, secrets, API keys, PSKs, certificates
                   Preserves: all network information

  REFERENTIAL INTEGRITY:
  The sanitizer maintains consistent mappings throughout the document:
  - Same original value → same redacted value
  - Network relationships remain visible (e.g., 192.168.1.1 → 10.0.0.1)
  - Use --mapping flag to save the mapping file for reverse lookup

  OUTPUT:
  By default, sanitized output is printed to stdout. Use -o to save to a file.
  The --mapping flag generates a JSON file documenting all original→redacted mappings.

Examples:
  # Sanitize for public sharing (maximum redaction)
  opnDossier sanitize config.xml --mode aggressive -o config-sanitized.xml

  # Sanitize for internal sharing (default mode)
  opnDossier sanitize config.xml -o sanitized.xml

  # Sanitize with mapping file for reverse lookup
  opnDossier sanitize config.xml -o sanitized.xml --mapping mappings.json

  # Minimal redaction (credentials only)
  opnDossier sanitize config.xml --mode minimal

  # Force overwrite existing files
  opnDossier sanitize config.xml -o output.xml --force

  # Pipe to another command
  opnDossier sanitize config.xml | less`,
	Args: cobra.ExactArgs(1),
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

		inputFile := args[0]

		// Create context-aware logger with input file field
		ctxLogger := cmdLogger.WithContext(ctx).WithFields("input_file", inputFile)

		// Create a timeout context for processing
		timeoutCtx, cancel := context.WithTimeout(ctx, constants.DefaultProcessingTimeout)
		defer cancel()

		// Sanitize the file path
		cleanPath := filepath.Clean(inputFile)
		if !filepath.IsAbs(cleanPath) {
			var err error
			cleanPath, err = filepath.Abs(cleanPath)
			if err != nil {
				return fmt.Errorf("failed to get absolute path for %s: %w", inputFile, err)
			}
		}

		// Open input file
		file, err := os.Open(cleanPath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %w", inputFile, err)
		}
		defer func() {
			if cerr := file.Close(); cerr != nil {
				ctxLogger.Error("failed to close input file", "error", cerr)
			}
		}()

		// Create sanitizer with specified mode
		ctxLogger.Debug("Creating sanitizer", "mode", sanitizeMode)
		s := sanitizer.NewSanitizer(sanitizer.Mode(sanitizeMode))

		// Determine output destination
		var outputWriter *os.File
		actualOutputFile := ""

		if sanitizeOutputFile != "" {
			// Handle overwrite protection
			actualOutputFile, err = determineSanitizeOutputPath(sanitizeOutputFile, sanitizeForce)
			if err != nil {
				if errors.Is(err, ErrOperationCancelled) {
					ctxLogger.Info("Operation cancelled by user")
					return nil
				}
				return err
			}

			outputWriter, err = os.Create(actualOutputFile)
			if err != nil {
				return fmt.Errorf("failed to create output file %s: %w", actualOutputFile, err)
			}
			defer func() {
				if cerr := outputWriter.Close(); cerr != nil {
					ctxLogger.Warn("failed to close output file", "error", cerr)
				}
			}()
			ctxLogger = ctxLogger.WithFields("output_file", actualOutputFile)
		} else {
			outputWriter = os.Stdout
		}

		// Perform sanitization
		ctxLogger.Debug("Sanitizing configuration")

		// Check for context cancellation
		select {
		case <-timeoutCtx.Done():
			return fmt.Errorf("operation timed out: %w", timeoutCtx.Err())
		default:
		}

		if err := s.SanitizeXML(file, outputWriter); err != nil {
			return fmt.Errorf("failed to sanitize configuration: %w", err)
		}

		// Sync output file if writing to disk
		if actualOutputFile != "" {
			if err := outputWriter.Sync(); err != nil {
				return fmt.Errorf("failed to sync output file: %w", err)
			}
		}

		// Log statistics
		stats := s.GetStats()
		ctxLogger.Debug("Sanitization complete",
			"total_fields", stats.TotalFields,
			"redacted_fields", stats.RedactedFields,
			"skipped_fields", stats.SkippedFields,
		)

		// Write mapping file if requested
		if sanitizeMappingFile != "" {
			mappingPath, err := determineSanitizeOutputPath(sanitizeMappingFile, sanitizeForce)
			if err != nil {
				if errors.Is(err, ErrOperationCancelled) {
					ctxLogger.Info("Mapping file creation cancelled by user")
					// Still consider the main operation successful
					return nil
				}
				return err
			}

			mappingJSON, err := s.GetMapper().ToJSON(sanitizeMode)
			if err != nil {
				return fmt.Errorf("failed to generate mapping JSON: %w", err)
			}

			mappingWriter, err := os.Create(mappingPath)
			if err != nil {
				return fmt.Errorf("failed to create mapping file %s: %w", mappingPath, err)
			}
			defer func() {
				if cerr := mappingWriter.Close(); cerr != nil {
					ctxLogger.Warn("failed to close mapping file", "error", cerr)
				}
			}()

			if _, err := mappingWriter.Write(mappingJSON); err != nil {
				return fmt.Errorf("failed to write mapping file: %w", err)
			}

			if err := mappingWriter.Sync(); err != nil {
				return fmt.Errorf("failed to sync mapping file: %w", err)
			}

			ctxLogger.Debug("Mapping file written", "mapping_file", mappingPath)
		}

		// Output summary to stderr if writing to file (so it doesn't corrupt stdout)
		if actualOutputFile != "" {
			fmt.Fprintf(os.Stderr, "Sanitized %s → %s (%d fields redacted)\n",
				inputFile, actualOutputFile, stats.RedactedFields)
			if sanitizeMappingFile != "" {
				fmt.Fprintf(os.Stderr, "Mapping file: %s\n", sanitizeMappingFile)
			}
		}

		return nil
	},
}

// determineSanitizeOutputPath determines whether the provided outputPath may be used.
// If the file already exists and force is false, it prompts the user on stderr to
// confirm overwriting; an empty response is treated as "No" and only `y` or `Y`
// are accepted to proceed. It returns the original outputPath on approval.
// Returns ErrOperationCancelled when the user declines, or a wrapped error if
// reading user input fails.
func determineSanitizeOutputPath(outputPath string, force bool) (string, error) {
	// Check if file already exists
	if _, err := os.Stat(outputPath); err == nil {
		// File exists, check if we should overwrite
		if !force {
			fmt.Fprintf(os.Stderr, "File '%s' already exists. Overwrite? (y/N): ", outputPath)

			reader := bufio.NewReader(os.Stdin)
			response, err := reader.ReadString('\n')
			if err != nil {
				return "", fmt.Errorf("failed to read user input: %w", err)
			}

			response = strings.TrimSpace(response)
			if response == "" {
				response = "N"
			}

			if response != "y" && response != "Y" {
				return "", ErrOperationCancelled
			}
		}
	}

	return outputPath, nil
}
