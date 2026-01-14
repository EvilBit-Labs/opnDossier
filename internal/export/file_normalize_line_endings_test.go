package export

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/stretchr/testify/assert"
)

const (
	testLineContent = "line1\nline2\nline3\n"
)

// TestNormalizeLineEndings tests the normalizeLineEndings function comprehensively.
func TestNormalizeLineEndings(t *testing.T) {
	// Create a logger for tests that need it
	logger, err := log.New(log.Config{Level: "warn", Output: os.Stderr})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		envVar   string
		expected string
	}{
		{
			name:     "disabled by default - returns input unchanged",
			input:    "line1\nline2\r\nline3\r",
			envVar:   "",
			expected: "line1\nline2\r\nline3\r",
		},
		{
			name:     "env var set to 0 - returns input unchanged",
			input:    "line1\nline2\r\n",
			envVar:   "0",
			expected: "line1\nline2\r\n",
		},
		{
			name:   "enabled - normalizes mixed line endings",
			input:  "line1\r\nline2\rline3\n",
			envVar: "1",
			expected: func() string {
				if runtime.GOOS == "windows" {
					return "line1\r\nline2\r\nline3\r\n"
				}
				return "line1\nline2\nline3\n"
			}(),
		},
		{
			name:   "enabled - converts all to platform-specific",
			input:  "line1\nline2\rline3\r\n",
			envVar: "1",
			expected: func() string {
				if runtime.GOOS == "windows" {
					return "line1\r\nline2\r\nline3\r\n"
				}
				return "line1\nline2\nline3\n"
			}(),
		},
		{
			name:     "enabled - empty string",
			input:    "",
			envVar:   "1",
			expected: "",
		},
		{
			name:     "enabled - no line endings",
			input:    "single line",
			envVar:   "1",
			expected: "single line",
		},
		{
			name:   "enabled - only line endings",
			input:  "\n\r\n\r",
			envVar: "1",
			expected: func() string {
				if runtime.GOOS == "windows" {
					return "\r\n\r\n\r\n"
				}
				return "\n\n\n"
			}(),
		},
		{
			name:     "invalid env value 'true' - returns input unchanged",
			input:    "line1\nline2\r\n",
			envVar:   "true",
			expected: "line1\nline2\r\n",
		},
		{
			name:     "invalid env value 'yes' - returns input unchanged",
			input:    "line1\nline2\r\n",
			envVar:   "yes",
			expected: "line1\nline2\r\n",
		},
		{
			name:     "invalid env value with spaces - returns input unchanged",
			input:    "line1\nline2\r\n",
			envVar:   " 1 ",
			expected: "line1\nline2\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup environment using t.Setenv for automatic cleanup
			if tt.envVar != "" {
				t.Setenv("OPNDOSSIER_PLATFORM_LINE_ENDINGS", tt.envVar)
			}

			result := normalizeLineEndings(logger, tt.input)
			assert.Equal(t, tt.expected, result, "Line ending normalization mismatch")
		})
	}
}

// TestNormalizeLineEndings_Idempotent tests that normalizing already-normalized content is safe.
func TestNormalizeLineEndings_Idempotent(t *testing.T) {
	logger, err := log.New(log.Config{Level: "warn", Output: os.Stderr})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	t.Setenv("OPNDOSSIER_PLATFORM_LINE_ENDINGS", "1")

	first := normalizeLineEndings(logger, testLineContent)
	second := normalizeLineEndings(logger, first)

	assert.Equal(t, first, second, "Function should be idempotent")
}

// TestNormalizeLineEndings_Performance tests performance with large files.
func TestNormalizeLineEndings_Performance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	logger, err := log.New(log.Config{Level: "warn", Output: os.Stderr})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	// Test with large content (10MB of text)
	var largeContentSb strings.Builder
	for range 100000 {
		largeContentSb.WriteString("line content\nmore content\r\neven more\r")
	}
	largeContent := largeContentSb.String()

	t.Setenv("OPNDOSSIER_PLATFORM_LINE_ENDINGS", "1")

	result := normalizeLineEndings(logger, largeContent)

	assert.NotEmpty(t, result, "Large content should be normalized")
}

// TestNormalizeLineEndings_WithNilLogger tests that function works gracefully with nil logger.
func TestNormalizeLineEndings_WithNilLogger(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		envVar   string
		expected string
	}{
		{
			name:     "nil logger with invalid env - should not panic",
			input:    "line1\nline2\n",
			envVar:   "invalid",
			expected: "line1\nline2\n",
		},
		{
			name:   "nil logger with valid env - should work",
			input:  "line1\nline2\n",
			envVar: "1",
			expected: func() string {
				if runtime.GOOS == "windows" {
					return "line1\r\nline2\r\n"
				}
				return "line1\nline2\n"
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envVar != "" {
				t.Setenv("OPNDOSSIER_PLATFORM_LINE_ENDINGS", tt.envVar)
			}

			// Pass nil logger - should not panic
			result := normalizeLineEndings(nil, tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestNormalizeLineEndings_ContentPreservation tests that logical line breaks are preserved.
func TestNormalizeLineEndings_ContentPreservation(t *testing.T) {
	logger, err := log.New(log.Config{Level: "warn", Output: os.Stderr})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	input := "line1\r\nline2\nline3\rline4\nline5"

	t.Setenv("OPNDOSSIER_PLATFORM_LINE_ENDINGS", "1")

	result := normalizeLineEndings(logger, input)

	// Count logical lines by normalizing all line endings to \n and counting
	normalizedForCount := result
	if runtime.GOOS == "windows" {
		// On Windows, remove \r to count only \n
		normalizedForCount = ""
		var normalizedForCountSb261 strings.Builder
		for _, r := range result {
			if r != '\r' {
				normalizedForCountSb261.WriteString(string(r))
			}
		}
		normalizedForCount += normalizedForCountSb261.String()
	}

	// Count lines (number of \n plus 1 for the last line)
	lineCount := 1 // Start with 1 for the first line
	for _, r := range normalizedForCount {
		if r == '\n' {
			lineCount++
		}
	}

	assert.Equal(t, 5, lineCount, "Line count should be preserved after normalization")
}
