// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/EvilBit-Labs/opnDossier/internal/parser"
)

// Exit codes for structured error handling in CI/CD pipelines.
// These codes allow automation to distinguish between different error types.
const (
	// ExitSuccess indicates successful execution.
	ExitSuccess = 0

	// ExitGeneralError indicates a general/unknown error.
	ExitGeneralError = 1

	// ExitParseError indicates an XML parsing error.
	ExitParseError = 2

	// ExitValidationError indicates a configuration validation error.
	ExitValidationError = 3

	// ExitFileError indicates a file I/O error (file not found, permission denied, etc.).
	ExitFileError = 4
)

// JSONError represents a machine-readable error output.
type JSONError struct {
	Error   string         `json:"error"`
	Code    int            `json:"code"`
	Type    string         `json:"type"`
	File    string         `json:"file,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

// OutputJSONError outputs an error in JSON format to stderr.
// This is used when --json-output flag is enabled for machine consumption.
func OutputJSONError(err error, file string, exitCode int) {
	jsonErr := JSONError{
		Error: err.Error(),
		Code:  exitCode,
		Type:  getErrorType(exitCode),
		File:  file,
	}

	// Add additional details based on error type
	if parser.IsParseError(err) {
		if parseErr := parser.GetParseError(err); parseErr != nil {
			jsonErr.Details = map[string]any{
				"line":    parseErr.Line,
				"message": parseErr.Message,
			}
		}
	}

	output, marshalErr := json.Marshal(jsonErr)
	if marshalErr != nil {
		// Fallback to plain error if JSON marshaling fails
		fmt.Fprintf(os.Stderr, `{"error": "failed to marshal error", "code": %d}`, exitCode)
		fmt.Fprintln(os.Stderr)
		return
	}

	fmt.Fprintln(os.Stderr, string(output))
}

// getErrorType returns a human-readable error type string for the exit code.
func getErrorType(code int) string {
	switch code {
	case ExitSuccess:
		return "success"
	case ExitGeneralError:
		return "general_error"
	case ExitParseError:
		return "parse_error"
	case ExitValidationError:
		return "validation_error"
	case ExitFileError:
		return "file_error"
	default:
		return "unknown_error"
	}
}

// DetermineExitCode returns the appropriate exit code based on the error type.
func DetermineExitCode(err error) int {
	if err == nil {
		return ExitSuccess
	}

	if parser.IsParseError(err) {
		return ExitParseError
	}

	if parser.IsValidationError(err) {
		return ExitValidationError
	}

	if os.IsNotExist(err) || os.IsPermission(err) {
		return ExitFileError
	}

	return ExitGeneralError
}

// ExitWithCode exits the program with the specified exit code.
// This function should be used instead of os.Exit to ensure proper cleanup.
func ExitWithCode(code int) {
	os.Exit(code)
}

// JSONSuccess outputs a success message in JSON format to stdout.
// This is used when --json-output flag is enabled for machine consumption.
func JSONSuccess(message, file string) {
	output := map[string]any{
		"success": true,
		"message": message,
		"file":    file,
		"code":    ExitSuccess,
	}

	jsonOutput, err := json.Marshal(output)
	if err != nil {
		fmt.Printf(`{"success": true, "file": "%s"}`, file)
		fmt.Println()
		return
	}

	fmt.Println(string(jsonOutput))
}
