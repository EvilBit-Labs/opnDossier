// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/EvilBit-Labs/opnDossier/internal/parser"
	"github.com/spf13/cobra"
)

// init registers the validate command with the root command for the CLI.
func init() {
	rootCmd.AddCommand(validateCmd)
}

var validateCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra command
	Use:     "validate [file ...]",
	Short:   "Validate OPNsense configuration files",
	GroupID: "utility",
	Long: `The 'validate' command checks one or more OPNsense config.xml files for
structural and semantic correctness without performing any conversion.
This is useful for verifying configuration integrity before processing
or for automated quality checks in CI/CD pipelines.

The validation includes:
- XML syntax validation
- OPNsense schema validation
- Required field validation
- Cross-field consistency checks
- Enum value validation

Examples:
  # Validate a single configuration file
  opnDossier validate config.xml

  # Validate multiple configuration files
  opnDossier validate config1.xml config2.xml config3.xml

  # Validate with verbose output to see detailed validation results
  opnDossier --verbose validate config.xml

  # Validate with quiet mode (only show errors)
  opnDossier --quiet validate config.xml
`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}

		// Get logger from CommandContext
		cmdCtx := GetCommandContext(cmd)
		if cmdCtx == nil {
			return errors.New("command context not initialized")
		}
		cmdLogger := cmdCtx.Logger

		var wg sync.WaitGroup
		errs := make(chan error, len(args))
		validationFailed := false

		for _, filePath := range args {
			wg.Add(1)
			go func(fp string) {
				defer wg.Done()

				// Create context-aware logger for this goroutine with input file field
				ctxLogger := cmdLogger.WithContext(ctx).WithFields("input_file", fp)
				ctxLogger.Info("Starting validation process")

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

				// Parse and validate the XML
				ctxLogger.Debug("Parsing and validating XML file")
				p := parser.NewXMLParser()
				_, err = p.ParseAndValidate(ctx, file)
				if err != nil {
					validationFailed = true
					ctxLogger.Error("Validation failed", "error", err)

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
						// For parse errors, report and continue to next file
						fmt.Fprintf(os.Stderr, "❌ %s: %v\n", fp, err)
						return
					}

					// Handle validation errors - display all validation issues
					if parser.IsValidationError(err) {
						ctxLogger.Error("Configuration validation failed")
						fmt.Fprintf(os.Stderr, "❌ %s:\n%s\n", fp, err)
					} else {
						// For other errors, still report but continue
						fmt.Fprintf(os.Stderr, "❌ %s: %v\n", fp, err)
					}
					return
				}

				ctxLogger.Info("Validation completed successfully")
				fmt.Printf("✅ %s: Valid\n", fp)
			}(filePath)
		}

		wg.Wait()
		close(errs)

		// Collect any execution errors (not validation errors)
		var allErrors error
		for err := range errs {
			if allErrors == nil {
				allErrors = err
			} else {
				allErrors = fmt.Errorf("%w; %w", allErrors, err)
			}
		}

		// Return execution errors if any
		if allErrors != nil {
			return allErrors
		}

		// Exit with code 1 if validation failed for any files
		if validationFailed {
			os.Exit(1)
		}

		return nil
	},
}
