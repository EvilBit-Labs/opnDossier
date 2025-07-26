// Package cmd provides the command-line interface for opnFocus.
package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/unclesp1d3r/opnFocus/internal/parser"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(validateCmd)
}

var validateCmd = &cobra.Command{
	Use:   "validate [file ...]",
	Short: "Validate OPNsense configuration files",
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

Exit codes:
  0 - All files are valid
  1 - One or more files have validation errors
  2 - Command execution error (file not found, permissions, etc.)

CONFIGURATION:
  This command respects the global configuration precedence:
  CLI flags > environment variables (OPNFOCUS_*) > config file > defaults

Examples:
  # Validate a single configuration file
  opnFocus validate config.xml

  # Validate multiple configuration files
  opnFocus validate config1.xml config2.xml config3.xml

  # Validate with verbose output to see detailed validation results
  opnFocus --verbose validate config.xml

  # Validate with quiet mode (only show errors)
  opnFocus --quiet validate config.xml
`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}

		var wg sync.WaitGroup
		errs := make(chan error, len(args))
		validationFailed := false

		for _, filePath := range args {
			wg.Add(1)
			go func(fp string) {
				defer wg.Done()

				// Create context-aware logger for this goroutine with input file field
				ctxLogger := logger.WithContext(ctx).WithFields("input_file", fp)
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
							ctxLogger.Error("XML syntax error detected", "line", parseErr.Line, "message", parseErr.Message)
						}
					}
					if parser.IsValidationError(err) {
						ctxLogger.Error("Configuration validation failed")
						// Log validation error details without failing the command
						fmt.Fprintf(os.Stderr, "❌ %s: %v\n", fp, err)
					} else {
						// For parse errors, still report but continue
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
