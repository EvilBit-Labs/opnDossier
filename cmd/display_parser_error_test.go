package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestXMLFile creates a temporary XML file for testing and returns its path.
func createTestXMLFile(t *testing.T, content string) string {
	t.Helper()
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test-config.xml")
	err := os.WriteFile(tmpFile, []byte(content), 0o600)
	require.NoError(t, err)
	return tmpFile
}

// runDisplayCommand executes the display command with the given file path.
func runDisplayCommand(t *testing.T, filePath string) error {
	t.Helper()
	rootCmd := GetRootCmd()
	rootCmd.SetArgs([]string{"display", filePath})
	return rootCmd.Execute()
}

// TestDisplayCommandParserErrors tests error handling for malformed XML files.
func TestDisplayCommandParserErrors(t *testing.T) {
	tests := []struct {
		name       string
		xmlContent string
	}{
		{
			name: "Malformed XML - unclosed tag",
			xmlContent: `<?xml version="1.0"?>
<opnsense>
	<system>
		<hostname>test</hostname>
	</system>
`,
		},
		{
			name: "Malformed XML - invalid syntax",
			xmlContent: `<?xml version="1.0"?>
<opnsense>
	<system>
		<hostname>test<
	</system>
</opnsense>`,
		},
		{
			name:       "Empty file",
			xmlContent: "",
		},
		{
			name: "Invalid root element",
			xmlContent: `<?xml version="1.0"?>
<invalid>
	<system>
		<hostname>test</hostname>
	</system>
</invalid>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile := createTestXMLFile(t, tt.xmlContent)
			err := runDisplayCommand(t, tmpFile)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "failed to parse XML")
		})
	}
}

// TestDisplayCommandValidationErrors tests error handling for invalid configurations.
func TestDisplayCommandValidationErrors(t *testing.T) {
	t.Run("Missing required fields", func(t *testing.T) {
		// Note: Missing required fields is handled gracefully by the programmatic generator.
		// It generates output with empty values rather than failing.
		xmlContent := `<?xml version="1.0"?>
<opnsense>
	<system>
	</system>
</opnsense>`
		tmpFile := createTestXMLFile(t, xmlContent)
		err := runDisplayCommand(t, tmpFile)
		// Programmatic generation handles empty configs gracefully - no error expected
		assert.NoError(t, err)
	})

	t.Run("Valid minimal config", func(t *testing.T) {
		xmlContent := `<?xml version="1.0"?>
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
</opnsense>`
		tmpFile := createTestXMLFile(t, xmlContent)
		err := runDisplayCommand(t, tmpFile)
		if err != nil {
			assert.NotContains(t, err.Error(), "validation failed")
		}
	})
}

// TestDisplayCommandEnhancedErrorMessages tests that error messages are clear and helpful.
func TestDisplayCommandEnhancedErrorMessages(t *testing.T) {
	t.Run("File does not exist", func(t *testing.T) {
		nonExistentFile := filepath.Join(t.TempDir(), "does-not-exist.xml")
		err := runDisplayCommand(t, nonExistentFile)

		require.Error(t, err)
		// Check for filename in error message (works across platforms)
		assert.Contains(t, err.Error(), "does-not-exist.xml")
	})
}
