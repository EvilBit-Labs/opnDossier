package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetErrorType verifies that getErrorType returns the correct
// human-readable string for each known exit code and the fallback
// for unknown codes.
func TestGetErrorType(t *testing.T) {
	tests := []struct {
		name string
		code int
		want string
	}{
		{"success", ExitSuccess, "success"},
		{"general error", ExitGeneralError, "general_error"},
		{"parse error", ExitParseError, "parse_error"},
		{"validation error", ExitValidationError, "validation_error"},
		{"file error", ExitFileError, "file_error"},
		{"unknown code 99", 99, "unknown_error"},
		{"unknown negative", -1, "unknown_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getErrorType(tt.code)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestDetermineExitCode verifies that DetermineExitCode maps error types
// to the correct exit codes.
func TestDetermineExitCode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode int
	}{
		{"nil error returns success", nil, ExitSuccess},
		{
			"parse error returns ExitParseError",
			cfgparser.NewParseError(1, 1, "bad xml"),
			ExitParseError,
		},
		{
			"validation error returns ExitValidationError",
			cfgparser.NewValidationError("system.hostname", "missing"),
			ExitValidationError,
		},
		{
			"file not found returns ExitFileError",
			&os.PathError{Op: "open", Path: "/nonexistent", Err: os.ErrNotExist},
			ExitFileError,
		},
		{
			"permission denied returns ExitFileError",
			&os.PathError{Op: "open", Path: "/secret", Err: os.ErrPermission},
			ExitFileError,
		},
		{
			"generic error returns ExitGeneralError",
			errors.New("something went wrong"),
			ExitGeneralError,
		},
		{
			"wrapped parse error returns ExitParseError",
			fmt.Errorf("parse failed: %w", cfgparser.NewParseError(5, 3, "unexpected token")),
			ExitParseError,
		},
		{
			"wrapped validation error returns ExitValidationError",
			fmt.Errorf("validation failed: %w", cfgparser.NewValidationError("dns", "invalid")),
			ExitValidationError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetermineExitCode(tt.err)
			assert.Equal(t, tt.wantCode, got)
		})
	}
}

// TestOutputJSONError verifies that OutputJSONError writes valid JSON
// to stderr with the correct structure and error type mapping.
func TestOutputJSONError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		file     string
		exitCode int
		wantType string
		wantFile string
	}{
		{
			name:     "general error",
			err:      errors.New("something broke"),
			file:     "config.xml",
			exitCode: ExitGeneralError,
			wantType: "general_error",
			wantFile: "config.xml",
		},
		{
			name:     "parse error with details",
			err:      cfgparser.NewParseError(10, 5, "unexpected EOF"),
			file:     "bad.xml",
			exitCode: ExitParseError,
			wantType: "parse_error",
			wantFile: "bad.xml",
		},
		{
			name:     "empty file path",
			err:      errors.New("no file"),
			file:     "",
			exitCode: ExitFileError,
			wantType: "file_error",
			wantFile: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stderr output
			origStderr := os.Stderr
			r, w, err := os.Pipe()
			require.NoError(t, err)

			os.Stderr = w
			t.Cleanup(func() { os.Stderr = origStderr })

			OutputJSONError(tt.err, tt.file, tt.exitCode)

			require.NoError(t, w.Close())

			buf := make([]byte, 4096)
			n, readErr := r.Read(buf)
			require.NoError(t, readErr)
			output := string(buf[:n])

			// Parse the JSON output
			var jsonErr JSONError
			require.NoError(t, json.Unmarshal([]byte(output), &jsonErr),
				"output should be valid JSON: %s", output)

			assert.Equal(t, tt.err.Error(), jsonErr.Error)
			assert.Equal(t, tt.exitCode, jsonErr.Code)
			assert.Equal(t, tt.wantType, jsonErr.Type)

			// File is omitted when empty due to omitempty tag
			if tt.wantFile != "" {
				assert.Equal(t, tt.wantFile, jsonErr.File)
			}

			// Parse errors should include line details
			if cfgparser.IsParseError(tt.err) {
				require.NotNil(t, jsonErr.Details)
				assert.Contains(t, jsonErr.Details, "line")
				assert.Contains(t, jsonErr.Details, "message")
			}
		})
	}
}

// TestJSONSuccess verifies that JSONSuccess writes valid JSON
// to stdout with the correct success structure.
func TestJSONSuccess(t *testing.T) {
	// Capture stdout output
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)

	os.Stdout = w
	t.Cleanup(func() { os.Stdout = origStdout })

	JSONSuccess("operation completed", "output.md")

	require.NoError(t, w.Close())

	buf := make([]byte, 4096)
	n, readErr := r.Read(buf)
	require.NoError(t, readErr)
	output := string(buf[:n])

	var result map[string]any
	require.NoError(t, json.Unmarshal([]byte(output), &result),
		"output should be valid JSON: %s", output)

	assert.Equal(t, true, result["success"])
	assert.Equal(t, "operation completed", result["message"])
	assert.Equal(t, "output.md", result["file"])
	assert.InDelta(t, float64(ExitSuccess), result["code"], 0.001)
}
