package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDisplayCommandParserErrors tests error handling for malformed XML files.
func TestDisplayCommandParserErrors(t *testing.T) {
	tests := []struct {
		name           string
		xmlContent     string
		expectParseErr bool
		expectInLog    string
	}{
		{
			name: "Malformed XML - unclosed tag",
			xmlContent: `<?xml version="1.0"?>
<opnsense>
	<system>
		<hostname>test</hostname>
	</system>
`,
			expectParseErr: true,
			expectInLog:    "Failed to parse XML",
		},
		{
			name: "Malformed XML - invalid syntax",
			xmlContent: `<?xml version="1.0"?>
<opnsense>
	<system>
		<hostname>test<
	</system>
</opnsense>`,
			expectParseErr: true,
			expectInLog:    "Failed to parse XML",
		},
		{
			name:           "Empty file",
			xmlContent:     "",
			expectParseErr: true,
			expectInLog:    "Failed to parse XML",
		},
		{
			name: "Invalid root element",
			xmlContent: `<?xml version="1.0"?>
<invalid>
	<system>
		<hostname>test</hostname>
	</system>
</invalid>`,
			expectParseErr: true,
			expectInLog:    "Failed to parse XML",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary XML file
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "test-config.xml")
			err := os.WriteFile(tmpFile, []byte(tt.xmlContent), 0o600)
			require.NoError(t, err)

			// Execute display command via root command
			rootCmd := GetRootCmd()
			rootCmd.SetArgs([]string{"display", tmpFile})

			// Capture stderr to check logging
			// Note: We can't easily capture slog output in tests without setting up a test logger
			// This test verifies that the error is returned correctly
			err = rootCmd.Execute()

			if tt.expectParseErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to parse XML")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestDisplayCommandValidationErrors tests error handling for invalid configurations.
func TestDisplayCommandValidationErrors(t *testing.T) {
	tests := []struct {
		name        string
		xmlContent  string
		expectError bool
		expectInLog string
	}{
		{
			name: "Missing required fields",
			xmlContent: `<?xml version="1.0"?>
<opnsense>
	<system>
	</system>
</opnsense>`,
			expectError: true,
			expectInLog: "validation failed",
		},
		{
			name: "Valid minimal config",
			xmlContent: `<?xml version="1.0"?>
<opnsense>
	<system>
		<hostname>test</hostname>
		<domain>example.com</domain>
	</system>
	<interfaces>
		<wan>
			<enable>1</enable>
			<if>em0</if>
		</wan>
	</interfaces>
</opnsense>`,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary XML file
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "test-config.xml")
			err := os.WriteFile(tmpFile, []byte(tt.xmlContent), 0o600)
			require.NoError(t, err)

			// Execute display command via root command
			rootCmd := GetRootCmd()
			rootCmd.SetArgs([]string{"display", tmpFile})

			// Execute command
			err = rootCmd.Execute()

			if tt.expectError {
				assert.Error(t, err)
			} else if err != nil {
				// For valid configs, we expect either success or a different error
				// (not a validation error)
				assert.NotContains(t, err.Error(), "validation failed")
			}
		})
	}
}

// TestDisplayCommandEnhancedErrorMessages tests that error messages are clear and helpful.
func TestDisplayCommandEnhancedErrorMessages(t *testing.T) {
	tests := []struct {
		name           string
		xmlContent     string
		expectedErrMsg string
	}{
		{
			name:           "File does not exist",
			xmlContent:     "", // Will use non-existent file path
			expectedErrMsg: "no such file or directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use a non-existent file path
			nonExistentFile := filepath.Join(t.TempDir(), "does-not-exist.xml")

			// Execute display command via root command
			rootCmd := GetRootCmd()
			rootCmd.SetArgs([]string{"display", nonExistentFile})

			// Execute command
			err := rootCmd.Execute()

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErrMsg)
		})
	}
}
