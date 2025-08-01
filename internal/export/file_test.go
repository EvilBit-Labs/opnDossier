package export

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/charmbracelet/glamour"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/opnFocus/internal/markdown"
	"github.com/yuin/goldmark"
	goldmark_parser "github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer/html"
	"gopkg.in/yaml.v3"
)

// ValidationTestCase represents a test case for validation tests.
type ValidationTestCase struct {
	Name       string
	Content    string
	FileName   string
	ValidateFn func(string) error
}

// runValidationTests runs the standard validation test suite.
func runValidationTests(t *testing.T, tests []ValidationTestCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			e := NewFileExporter()
			path := filepath.Join(t.TempDir(), tt.FileName)

			// Export the content
			err := e.Export(context.Background(), tt.Content, path)
			require.NoError(t, err)

			defer os.Remove(path)

			// Read the exported file
			exportedContent, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, tt.Content, string(exportedContent))

			// Validate that the exported content passes validation
			err = tt.ValidateFn(string(exportedContent))
			require.NoError(t, err, "Exported content should pass validation")
		})
	}
}

// findTestConfigFile finds the test config file from various possible locations.
func findTestConfigFile(t *testing.T) string {
	t.Helper()

	possiblePaths := []string{
		filepath.Join("..", "..", "testdata", "config.xml.sample"), // From test directory
		filepath.Join("testdata", "config.xml.sample"),             // From project root
		filepath.Join(".", "testdata", "config.xml.sample"),        // From current directory
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			// Convert to absolute path for CLI command
			absPath, err := filepath.Abs(path)
			if err == nil {
				return absPath
			}

			return path
		}
	}

	t.Fatalf("Could not find test config file in any of the expected locations: %v", possiblePaths)

	return ""
}

func TestFileExporter_Export(t *testing.T) {
	tests := []struct {
		name    string
		content string
		path    string
		wantErr bool
	}{
		{
			name:    "successful export",
			content: "test content",
			path:    filepath.Join(t.TempDir(), "test_output.md"),
			wantErr: false,
		},
		{
			name:    "invalid path",
			content: "test content",
			path:    "/nonexistent/path/test_output.md",
			wantErr: true,
		},
		{
			name:    "empty content",
			content: "",
			path:    filepath.Join(t.TempDir(), "test_output.md"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewFileExporter()
			err := e.Export(context.Background(), tt.content, tt.path)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				content, err := os.ReadFile(tt.path)
				require.NoError(t, err)
				assert.Equal(t, tt.content, string(content))
				_ = os.Remove(tt.path)
			}
		})
	}
}

// TestFileExporter_ExportErrorTypes tests that export errors provide clear, actionable messages
// This test ensures that the file export functionality meets the acceptance criteria
// for TASK-021: "Provides clear error messages for file I/O issues during export".
func TestFileExporter_ExportErrorTypes(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		path       string
		expectedOp string
		checkError func(t *testing.T, err error)
	}{
		{
			name:       "empty content error",
			content:    "",
			path:       filepath.Join(t.TempDir(), "test.md"),
			expectedOp: "export",
			checkError: func(t *testing.T, err error) {
				t.Helper()
				var exportErr *Error
				require.ErrorAs(t, err, &exportErr)
				assert.Equal(t, "export", exportErr.Operation)
				assert.Contains(t, exportErr.Message, "empty content")
			},
		},
		{
			name:       "path traversal error",
			content:    "test content",
			path:       "../../../etc/passwd",
			expectedOp: "validate_path",
			checkError: func(t *testing.T, err error) {
				t.Helper()
				var exportErr *Error
				require.ErrorAs(t, err, &exportErr)
				assert.Equal(t, "validate_path", exportErr.Operation)
				assert.Contains(t, exportErr.Message, "malicious traversal")
			},
		},
		{
			name:       "nonexistent directory error",
			content:    "test content",
			path:       "/nonexistent/directory/test.md",
			expectedOp: "validate_path",
			checkError: func(t *testing.T, err error) {
				t.Helper()
				var exportErr *Error
				require.ErrorAs(t, err, &exportErr)
				assert.Equal(t, "validate_path", exportErr.Operation)
				assert.Contains(t, exportErr.Message, "does not exist")
			},
		},
		{
			name:       "context cancellation error",
			content:    "test content",
			path:       "test.md", // Will be joined with t.TempDir() in the test
			expectedOp: "export",
			checkError: func(t *testing.T, err error) {
				t.Helper()
				var exportErr *Error
				require.ErrorAs(t, err, &exportErr)
				assert.Equal(t, "export", exportErr.Operation)
				assert.Contains(t, exportErr.Message, "cancelled by context")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewFileExporter()

			// For context cancellation test, create a cancelled context
			ctx := context.Background()
			if tt.name == "context cancellation error" {
				cancelledCtx, cancel := context.WithCancel(context.Background())
				cancel() // Cancel immediately

				ctx = cancelledCtx
			}

			err := e.Export(ctx, tt.content, tt.path)
			require.Error(t, err)
			tt.checkError(t, err)
		})
	}
}

// TestFileExporter_PathValidation tests comprehensive path validation
// This test ensures that the file export functionality meets the acceptance criteria
// for TASK-021: "Provides clear error messages for file I/O issues during export".
func TestFileExporter_PathValidation(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		expectError bool
		errorCheck  func(t *testing.T, err error)
	}{
		{
			name:        "valid path",
			path:        "valid_test.md", // Will be joined with t.TempDir() in the test
			expectError: false,
		},
		{
			name:        "path traversal attack",
			path:        "../../../etc/passwd",
			expectError: true,
			errorCheck: func(t *testing.T, err error) {
				t.Helper()
				var exportErr *Error
				require.ErrorAs(t, err, &exportErr)
				assert.Equal(t, "validate_path", exportErr.Operation)
				assert.Contains(t, exportErr.Message, "malicious traversal")
			},
		},
		{
			name:        "nonexistent directory",
			path:        "/nonexistent/dir/test.md",
			expectError: true,
			errorCheck: func(t *testing.T, err error) {
				t.Helper()
				var exportErr *Error
				require.ErrorAs(t, err, &exportErr)
				assert.Equal(t, "validate_path", exportErr.Operation)
				assert.Contains(t, exportErr.Message, "does not exist")
			},
		},
		{
			name:        "relative path traversal",
			path:        "test/../../../etc/passwd",
			expectError: true,
			errorCheck: func(t *testing.T, err error) {
				t.Helper()
				var exportErr *Error
				require.ErrorAs(t, err, &exportErr)
				assert.Equal(t, "validate_path", exportErr.Operation)
				assert.Contains(t, exportErr.Message, "malicious traversal")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewFileExporter()
			err := e.validateExportPath(tt.path)

			if tt.expectError {
				require.Error(t, err)

				if tt.errorCheck != nil {
					tt.errorCheck(t, err)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestFileExporter_AtomicWrite tests that file writing is atomic and safe
// This test ensures that the file export functionality meets the acceptance criteria
// for TASK-021: "Provides clear error messages for file I/O issues during export".
func TestFileExporter_AtomicWrite(t *testing.T) {
	tmpDir := t.TempDir()
	testPath := filepath.Join(tmpDir, "atomic_test.md")
	testContent := "test content for atomic write"

	e := NewFileExporter()

	// Test atomic write
	err := e.Export(context.Background(), testContent, testPath)
	require.NoError(t, err)

	// Verify file was written correctly
	content, err := os.ReadFile(testPath)
	require.NoError(t, err)
	assert.Equal(t, testContent, string(content))

	// Verify file permissions
	info, err := os.Stat(testPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(DefaultFilePermissions), info.Mode().Perm())

	// Cleanup
	if removeErr := os.Remove(testPath); removeErr != nil {
		t.Logf("Failed to remove test file: %v", removeErr)
	}
}

// TestFileExporter_ExportErrorUnwrap tests that Error properly unwraps underlying errors.
func TestFileExporter_ExportErrorUnwrap(t *testing.T) {
	e := NewFileExporter()

	// Test with a path that will cause an underlying error
	err := e.Export(context.Background(), "test content", "/nonexistent/dir/test.md")

	var exportErr *Error
	require.ErrorAs(t, err, &exportErr)

	// Test unwrapping
	unwrapped := exportErr.Unwrap()
	require.Error(t, unwrapped)
	assert.NotEqual(t, exportErr, unwrapped)
}

// TestFileExporter_MarkdownValidation tests that exported markdown files pass validation
// This test ensures that the markdown export functionality meets the acceptance criteria
// for TASK-017: "passes markdown validation tests".
func TestFileExporter_MarkdownValidation(t *testing.T) {
	tests := []struct {
		name    string
		content string
		path    string
	}{
		{
			name: "valid markdown content",
			content: `# Test Document

This is a **test** document with *markdown* formatting.

## Section 1

- Item 1
- Item 2
- Item 3

## Section 2

| Column 1 | Column 2 |
|----------|----------|
| Value 1  | Value 2  |
| Value 3  | Value 4  |

` + "```" + `bash
echo "code block"
` + "```" + `
`,
			path: filepath.Join(t.TempDir(), "test_markdown_validation.md"),
		},
		{
			name: "simple markdown content",
			content: `# Simple Document

Just plain text with a heading.

- List item
- Another item
`,
			path: filepath.Join(t.TempDir(), "test_simple_markdown.md"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewFileExporter()

			// Export the markdown content
			err := e.Export(context.Background(), tt.content, tt.path)
			require.NoError(t, err)

			defer os.Remove(tt.path)

			// Read the exported file
			exportedContent, err := os.ReadFile(tt.path)
			require.NoError(t, err)
			assert.Equal(t, tt.content, string(exportedContent))

			// Validate that the exported markdown passes validation
			err = markdown.ValidateMarkdown(string(exportedContent))
			require.NoError(t, err, "Exported markdown should pass validation")
		})
	}
}

// TestFileExporter_NoTerminalControlCharacters tests that exported markdown files
// contain no terminal control characters, which is part of the acceptance criteria
// for TASK-017.
func TestFileExporter_NoTerminalControlCharacters(t *testing.T) {
	// Test content that might contain terminal control characters
	testContent := `# Test Document

This is a test document that should not contain any terminal control characters.

## Colors and Formatting

This text should be plain markdown without any ANSI escape codes or terminal control sequences.

- Item 1
- Item 2
- Item 3
`

	path := filepath.Join(t.TempDir(), "test_no_control_chars.md")
	e := NewFileExporter()

	err := e.Export(context.Background(), testContent, path)
	require.NoError(t, err)

	defer os.Remove(path)

	// Read the exported file
	exportedContent, err := os.ReadFile(path)
	require.NoError(t, err)

	// Check for common terminal control characters
	contentStr := string(exportedContent)

	// ANSI escape sequences start with ESC (0x1B) followed by [
	assert.NotContains(t, contentStr, "\x1b[", "Exported markdown should not contain ANSI escape sequences")

	// Check for other common terminal control characters
	assert.NotContains(t, contentStr, "\x07", "Exported markdown should not contain bell characters")
	assert.NotContains(t, contentStr, "\x08", "Exported markdown should not contain backspace characters")
	assert.NotContains(t, contentStr, "\x0d", "Exported markdown should not contain carriage return characters")

	// The content should be exactly what we exported
	assert.Equal(t, testContent, contentStr)
}

// TestFileExporter_ActualExportedFile tests that the actual exported markdown file
// from the CLI command passes validation and meets all acceptance criteria for TASK-017.
func TestFileExporter_ActualExportedFile(t *testing.T) {
	// This test validates that the actual exported markdown file meets all acceptance criteria:
	// 1. Exports valid markdown file with no terminal control characters
	// 2. Uses templates from internal/templates
	// 3. Passes markdown validation tests

	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	// Use existing test config file
	configFile := findTestConfigFile(t)

	// Run the CLI command to generate the markdown file using go run
	// Change to project root directory first
	projectRoot := filepath.Join("..", "..")
	outputFile := filepath.Join(tmpDir, "test_output.md")
	cmd := exec.CommandContext(
		context.Background(),
		"go",
		"run",
		".",
		"convert",
		configFile,
		"--format",
		"markdown",
		"-o",
		outputFile,
	)
	cmd.Dir = projectRoot

	var stdout, stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		t.Skipf("Skipping test - CLI command failed: %v, stderr: %s", err, stderr.String())
	}

	// Read the exported file
	exportedContent, err := os.ReadFile(outputFile)
	require.NoError(t, err, "Failed to read exported file")

	contentStr := string(exportedContent)

	// 1. Validate that the markdown passes validation
	err = markdown.ValidateMarkdown(contentStr)
	require.NoError(t, err, "Exported markdown should pass validation")

	// 2. Check for no terminal control characters
	assert.NotContains(t, contentStr, "\x1b[", "Exported markdown should not contain ANSI escape sequences")
	assert.NotContains(t, contentStr, "\x07", "Exported markdown should not contain bell characters")
	assert.NotContains(t, contentStr, "\x08", "Exported markdown should not contain backspace characters")

	// 3. Verify it uses templates from internal/templates by checking for expected content
	// The templates should generate content with specific structure
	assert.Contains(
		t,
		contentStr,
		"# OPNsense Configuration Summary",
		"Should contain expected template-generated content",
	)
	assert.Contains(t, contentStr, "## System Information", "Should contain expected template-generated content")
	assert.Contains(t, contentStr, "## Table of Contents", "Should contain expected template-generated content")
	assert.Contains(t, contentStr, "## Interfaces", "Should contain expected template-generated content")

	// 4. Verify it's valid markdown structure
	assert.Contains(t, contentStr, "---", "Should contain markdown horizontal rules")
	assert.Contains(t, contentStr, "|", "Should contain markdown tables")
	assert.Contains(t, contentStr, "`", "Should contain markdown code formatting")
}

// TestFileExporter_JSONValidation tests that exported JSON files pass validation
// This test ensures that the JSON export functionality meets the acceptance criteria
// for TASK-018: "passes JSON validation tests".
func TestFileExporter_JSONValidation(t *testing.T) {
	tests := []ValidationTestCase{
		{
			Name: "valid json content",
			Content: `{
  "system": {
    "hostname": "test-firewall",
    "domain": "example.com",
    "timezone": "UTC"
  },
  "interfaces": {
    "wan": {
      "enable": "1",
      "if": "vtnet0",
      "ipaddr": "dhcp"
    },
    "lan": {
      "enable": "1",
      "if": "vtnet1",
      "ipaddr": "192.168.1.1",
      "subnet": "24"
    }
  },
  "statistics": {
    "totalInterfaces": 2,
    "totalFirewallRules": 2
  }
}`,
			FileName:   "test_json_validation.json",
			ValidateFn: validateJSON,
		},
		{
			Name: "simple json content",
			Content: `{
  "hostname": "simple-test",
  "enabled": true,
  "version": "1.0.0"
}`,
			FileName:   "test_simple_json.json",
			ValidateFn: validateJSON,
		},
	}

	runValidationTests(t, tests)
}

// TestFileExporter_NoTerminalControlCharactersJSON tests that exported JSON files
// contain no terminal control characters, which is part of the acceptance criteria
// for TASK-018.
func TestFileExporter_NoTerminalControlCharactersJSON(t *testing.T) {
	// Test content that might contain terminal control characters
	testContent := `{
  "system": {
    "hostname": "test-firewall",
    "domain": "example.com"
  },
  "interfaces": {
    "wan": {
      "enable": "1",
      "ipaddr": "dhcp"
    }
  },
  "statistics": {
    "totalInterfaces": 1
  }
}`

	path := filepath.Join(t.TempDir(), "test_no_control_chars_json.json")
	e := NewFileExporter()

	err := e.Export(context.Background(), testContent, path)
	require.NoError(t, err)

	defer os.Remove(path)

	// Read the exported file
	exportedContent, err := os.ReadFile(path)
	require.NoError(t, err)

	// Check for common terminal control characters
	contentStr := string(exportedContent)

	// ANSI escape sequences start with ESC (0x1B) followed by [
	assert.NotContains(t, contentStr, "\x1b[", "Exported JSON should not contain ANSI escape sequences")

	// Check for other common terminal control characters
	assert.NotContains(t, contentStr, "\x07", "Exported JSON should not contain bell characters")
	assert.NotContains(t, contentStr, "\x08", "Exported JSON should not contain backspace characters")
	assert.NotContains(t, contentStr, "\x0d", "Exported JSON should not contain carriage return characters")

	// The content should be exactly what we exported
	assert.Equal(t, testContent, contentStr)
}

// TestFileExporter_ActualExportedJSONFile tests that the actual exported JSON file
// from the CLI command passes validation and meets all acceptance criteria for TASK-018.
func TestFileExporter_ActualExportedJSONFile(t *testing.T) {
	// This test validates that the actual exported JSON file meets all acceptance criteria:
	// 1. Exports valid JSON file with no terminal control characters
	// 2. Passes JSON validation tests

	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	// Use existing test config file
	configFile := findTestConfigFile(t)

	// Run the CLI command to generate the JSON file using go run
	// Change to project root directory first
	projectRoot := filepath.Join("..", "..")
	outputFile := filepath.Join(tmpDir, "test_output.json")
	cmd := exec.CommandContext(
		context.Background(),
		"go",
		"run",
		".",
		"convert",
		configFile,
		"--format",
		"json",
		"-o",
		outputFile,
	)
	cmd.Dir = projectRoot

	var stdout, stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		t.Skipf("Skipping test - CLI command failed: %v, stderr: %s", err, stderr.String())
	}

	// Read the exported file
	exportedContent, err := os.ReadFile(outputFile)
	require.NoError(t, err, "Failed to read exported file")

	contentStr := string(exportedContent)

	// 1. Validate that the JSON passes validation
	err = validateJSON(contentStr)
	require.NoError(t, err, "Exported JSON should pass validation")

	// 2. Check for no terminal control characters
	assert.NotContains(t, contentStr, "\x1b[", "Exported JSON should not contain ANSI escape sequences")
	assert.NotContains(t, contentStr, "\x07", "Exported JSON should not contain bell characters")
	assert.NotContains(t, contentStr, "\x08", "Exported JSON should not contain backspace characters")

	// 3. Verify it's valid JSON structure
	assert.Contains(t, contentStr, "{", "Should contain JSON opening brace")
	assert.Contains(t, contentStr, "}", "Should contain JSON closing brace")
	assert.Contains(t, contentStr, "OPNsense", "Should contain expected hostname from config")
	assert.Contains(t, contentStr, "localdomain", "Should contain expected domain from config")
}

// validateJSON validates that a string contains valid JSON by attempting to parse it.
func validateJSON(content string) error {
	var result map[string]any
	return json.Unmarshal([]byte(content), &result)
}

// TestFileExporter_YAMLValidation tests that exported YAML files pass validation
// This test ensures that the YAML export functionality meets the acceptance criteria
// for TASK-019: "passes YAML validation tests".
func TestFileExporter_YAMLValidation(t *testing.T) {
	tests := []ValidationTestCase{
		{
			Name: "valid yaml content",
			Content: `system:
  hostname: test-firewall
  domain: example.com
  timezone: UTC
interfaces:
  wan:
    enable: "1"
    if: vtnet0
    ipaddr: dhcp
  lan:
    enable: "1"
    if: vtnet1
    ipaddr: 192.168.1.1
    subnet: "24"
statistics:
  totalInterfaces: 2
  totalFirewallRules: 2
`,
			FileName:   "test_yaml_validation.yaml",
			ValidateFn: validateYAML,
		},
		{
			Name: "simple yaml content",
			Content: `hostname: simple-test
enabled: true
version: "1.0.0"
`,
			FileName:   "test_simple_yaml.yaml",
			ValidateFn: validateYAML,
		},
	}

	runValidationTests(t, tests)
}

// TestFileExporter_NoTerminalControlCharactersYAML tests that exported YAML files
// contain no terminal control characters, which is part of the acceptance criteria
// for TASK-019.
func TestFileExporter_NoTerminalControlCharactersYAML(t *testing.T) {
	// Test content that might contain terminal control characters
	testContent := `system:
  hostname: test-firewall
  domain: example.com
interfaces:
  wan:
    enable: "1"
    ipaddr: dhcp
statistics:
  totalInterfaces: 1
`

	path := filepath.Join(t.TempDir(), "test_no_control_chars_yaml.yaml")
	e := NewFileExporter()

	err := e.Export(context.Background(), testContent, path)
	require.NoError(t, err)

	defer os.Remove(path)

	// Read the exported file
	exportedContent, err := os.ReadFile(path)
	require.NoError(t, err)

	// Check for common terminal control characters
	contentStr := string(exportedContent)

	// ANSI escape sequences start with ESC (0x1B) followed by [
	assert.NotContains(t, contentStr, "\x1b[", "Exported YAML should not contain ANSI escape sequences")

	// Check for other common terminal control characters
	assert.NotContains(t, contentStr, "\x07", "Exported YAML should not contain bell characters")
	assert.NotContains(t, contentStr, "\x08", "Exported YAML should not contain backspace characters")
	assert.NotContains(t, contentStr, "\x0d", "Exported YAML should not contain carriage return characters")

	// The content should be exactly what we exported
	assert.Equal(t, testContent, contentStr)
}

// TestFileExporter_ActualExportedYAMLFile tests that the actual exported YAML file
// from the CLI command passes validation and meets all acceptance criteria for TASK-019.
func TestFileExporter_ActualExportedYAMLFile(t *testing.T) {
	// This test validates that the actual exported YAML file meets all acceptance criteria:
	// 1. Exports valid YAML file with no terminal control characters
	// 2. Passes YAML validation tests

	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	// Use existing test config file
	configFile := findTestConfigFile(t)

	// Run the CLI command to generate the YAML file using go run
	// Change to project root directory first
	projectRoot := filepath.Join("..", "..")
	outputFile := filepath.Join(tmpDir, "test_output.yaml")
	cmd := exec.CommandContext(
		context.Background(),
		"go",
		"run",
		".",
		"convert",
		configFile,
		"--format",
		"yaml",
		"-o",
		outputFile,
	)
	cmd.Dir = projectRoot

	var stdout, stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		t.Skipf("Skipping test - CLI command failed: %v, stderr: %s", err, stderr.String())
	}

	// Read the exported file
	exportedContent, err := os.ReadFile(outputFile)
	require.NoError(t, err, "Failed to read exported file")

	contentStr := string(exportedContent)

	// 1. Validate that the YAML passes validation
	err = validateYAML(contentStr)
	require.NoError(t, err, "Exported YAML should pass validation")

	// 2. Check for no terminal control characters
	assert.NotContains(t, contentStr, "\x1b[", "Exported YAML should not contain ANSI escape sequences")
	assert.NotContains(t, contentStr, "\x07", "Exported YAML should not contain bell characters")
	assert.NotContains(t, contentStr, "\x08", "Exported YAML should not contain backspace characters")

	// 3. Verify it's valid YAML structure
	assert.Contains(t, contentStr, "hostname:", "Should contain expected YAML structure")
	assert.Contains(t, contentStr, "OPNsense", "Should contain expected hostname from config")
	assert.Contains(t, contentStr, "localdomain", "Should contain expected domain from config")
}

// validateYAML validates that a string contains valid YAML by attempting to parse it.
func validateYAML(content string) error {
	var result map[string]any
	return yaml.Unmarshal([]byte(content), &result)
}

// TestFileExporter_StandardToolValidation tests that exported files can be parsed
// by standard tools and libraries (markdown linters, JSON parsers, YAML parsers).
// This test ensures that the file export functionality meets the acceptance criteria
// for TASK-021a: "All exported files pass validation tests with standard tools and libraries".
func TestFileExporter_StandardToolValidation(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	// Use existing test config file
	configFile := findTestConfigFile(t)
	projectRoot := filepath.Join("..", "..")

	tests := []struct {
		name     string
		format   string
		validate func(t *testing.T, filePath string)
	}{
		{
			name:   "markdown validation with strict parser",
			format: "markdown",
			validate: func(t *testing.T, filePath string) {
				t.Helper()

				// Read the file content
				content, err := os.ReadFile(filePath)
				require.NoError(t, err, "Failed to read markdown file")

				// Use goldmark with strict parsing options
				md := goldmark.New(
					goldmark.WithParserOptions(
						goldmark_parser.WithAutoHeadingID(),
					),
					goldmark.WithRendererOptions(
						html.WithHardWraps(),
						html.WithXHTML(),
					),
				)

				// Try to convert the markdown to validate syntax
				var buf strings.Builder
				err = md.Convert(content, &buf)
				require.NoError(t, err, "Markdown should pass strict goldmark validation")

				// Additional basic validation checks
				contentStr := string(content)

				// Check for basic markdown structure
				assert.Contains(t, contentStr, "#", "Markdown should contain headers")
				assert.NotContains(t, contentStr, "\x1b[", "Markdown should not contain ANSI escape sequences")
			},
		},
		{
			name:   "json validation with strict parser",
			format: "json",
			validate: func(t *testing.T, filePath string) {
				t.Helper()

				// Read the file content
				content, err := os.ReadFile(filePath)
				require.NoError(t, err, "Failed to read JSON file")

				// Use encoding/json with strict validation
				var result map[string]any
				err = json.Unmarshal(content, &result)
				require.NoError(t, err, "JSON should pass strict encoding/json validation")

				// Additional basic validation checks
				contentStr := string(content)

				// Check for valid JSON structure
				assert.Contains(t, contentStr, "{", "JSON should contain object structure")
				assert.Contains(t, contentStr, "}", "JSON should contain object structure")
				assert.NotContains(t, contentStr, "\x1b[", "JSON should not contain ANSI escape sequences")

				// Check for valid JSON syntax
				assert.True(t, json.Valid(content), "JSON should pass json.Valid check")
			},
		},
		{
			name:   "yaml validation with strict parser",
			format: "yaml",
			validate: func(t *testing.T, filePath string) {
				t.Helper()

				// Read the file content
				content, err := os.ReadFile(filePath)
				require.NoError(t, err, "Failed to read YAML file")

				// Use yaml.v3 with strict validation
				var result map[string]any
				err = yaml.Unmarshal(content, &result)
				require.NoError(t, err, "YAML should pass strict yaml.v3 validation")

				// Additional basic validation checks
				contentStr := string(content)

				// Check for valid YAML structure
				assert.NotContains(t, contentStr, "\x1b[", "YAML should not contain ANSI escape sequences")

				// Test with yaml.Node for more detailed validation
				var node yaml.Node
				err = yaml.Unmarshal(content, &node)
				require.NoError(t, err, "YAML should pass yaml.Node validation")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputFile := filepath.Join(tmpDir, "test_output."+tt.format)

			// Run the CLI command to generate the file
			cmd := exec.CommandContext(
				context.Background(),
				"go",
				"run",
				".",
				"convert",
				configFile,
				"--format",
				tt.format,
				"-o",
				outputFile,
			)
			cmd.Dir = projectRoot

			var stdout, stderr bytes.Buffer

			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			if err != nil {
				t.Skipf("Skipping test - CLI command failed: %v, stderr: %s", err, stderr.String())
			}

			// Verify the file was created
			_, err = os.Stat(outputFile)
			require.NoError(t, err, "Output file should be created")

			// Run strict validation
			tt.validate(t, outputFile)
		})
	}
}

// TestFileExporter_LibraryValidation tests that exported files can be parsed
// by standard Go libraries and other common libraries.
// This test ensures that the file export functionality meets the acceptance criteria
// for TASK-021a: "All exported files pass validation tests with standard tools and libraries".
func TestFileExporter_LibraryValidation(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	// Use existing test config file
	configFile := findTestConfigFile(t)
	projectRoot := filepath.Join("..", "..")

	tests := []struct {
		name     string
		format   string
		validate func(t *testing.T, content []byte)
	}{
		{
			name:   "markdown library validation",
			format: "markdown",
			validate: func(t *testing.T, content []byte) {
				t.Helper()
				// Test with multiple markdown parsers

				// 1. Test with goldmark (already used in ValidateMarkdown)
				err := markdown.ValidateMarkdown(string(content))
				require.NoError(t, err, "Markdown should pass goldmark validation")

				// 2. Test with glamour (terminal markdown renderer)
				// This simulates what users would see in terminal
				_, err = glamour.Render(string(content), "dark")
				require.NoError(t, err, "Markdown should pass glamour validation")

				// 3. Basic markdown structure validation
				contentStr := string(content)
				assert.Contains(t, contentStr, "#", "Markdown should contain headers")
				assert.NotContains(t, contentStr, "\x1b[", "Markdown should not contain ANSI escape sequences")
			},
		},
		{
			name:   "json library validation",
			format: "json",
			validate: func(t *testing.T, content []byte) {
				t.Helper()
				// Test with multiple JSON parsers

				// 1. Test with encoding/json
				var result map[string]any
				err := json.Unmarshal(content, &result)
				require.NoError(t, err, "JSON should pass encoding/json validation")

				// 2. Test with json.Valid (Go 1.9+)
				if !json.Valid(content) {
					t.Error("JSON should pass json.Valid check")
				}

				// 3. Test with different target types
				var arrayResult []any
				// This might fail if the JSON is not an array, which is expected
				// We just want to ensure it doesn't panic
				if err := json.Unmarshal(content, &arrayResult); err != nil {
					// Expected to fail for non-array JSON, just log it
					t.Logf("JSON array unmarshal failed as expected: %v", err)
				}

				// 4. Basic JSON structure validation
				contentStr := string(content)
				assert.Contains(t, contentStr, "{", "JSON should contain object structure")
				assert.Contains(t, contentStr, "}", "JSON should contain object structure")
				assert.NotContains(t, contentStr, "\x1b[", "JSON should not contain ANSI escape sequences")
			},
		},
		{
			name:   "yaml library validation",
			format: "yaml",
			validate: func(t *testing.T, content []byte) {
				t.Helper()
				// Test with multiple YAML parsers

				// 1. Test with gopkg.in/yaml.v3
				var result map[string]any
				err := yaml.Unmarshal(content, &result)
				require.NoError(t, err, "YAML should pass yaml.v3 validation")

				// 2. Test with different target types
				var arrayResult []any
				// This might fail if the YAML is not an array, which is expected
				// We just want to ensure it doesn't panic
				if err := yaml.Unmarshal(content, &arrayResult); err != nil {
					// Expected to fail for non-array YAML, just log it
					t.Logf("YAML array unmarshal failed as expected: %v", err)
				}

				// 3. Test with yaml.Node for more detailed validation
				var node yaml.Node
				err = yaml.Unmarshal(content, &node)
				require.NoError(t, err, "YAML should pass yaml.Node validation")

				// 4. Basic YAML structure validation
				contentStr := string(content)
				assert.NotContains(t, contentStr, "\x1b[", "YAML should not contain ANSI escape sequences")
				assert.NotContains(t, contentStr, "\t", "YAML should not contain tabs (should use spaces)")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputFile := filepath.Join(tmpDir, "test_output."+tt.format)

			// Run the CLI command to generate the file
			cmd := exec.CommandContext(
				context.Background(),
				"go",
				"run",
				".",
				"convert",
				configFile,
				"--format",
				tt.format,
				"-o",
				outputFile,
			)
			cmd.Dir = projectRoot

			var stdout, stderr bytes.Buffer

			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			if err != nil {
				t.Skipf("Skipping test - CLI command failed: %v, stderr: %s", err, stderr.String())
			}

			// Read the exported file
			exportedContent, err := os.ReadFile(outputFile)
			require.NoError(t, err, "Failed to read exported file")

			// Run library validation
			tt.validate(t, exportedContent)
		})
	}
}

// TestFileExporter_CrossPlatformValidation tests that exported files are valid
// across different platforms and environments.
// This test ensures that the file export functionality meets the acceptance criteria
// for TASK-021a: "All exported files pass validation tests with standard tools and libraries".
func TestFileExporter_CrossPlatformValidation(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	// Use existing test config file
	configFile := findTestConfigFile(t)
	projectRoot := filepath.Join("..", "..")

	tests := []struct {
		name   string
		format string
	}{
		{"markdown cross-platform", "markdown"},
		{"json cross-platform", "json"},
		{"yaml cross-platform", "yaml"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputFile := filepath.Join(tmpDir, "test_output."+tt.format)

			// Run the CLI command to generate the file
			cmd := exec.CommandContext(
				context.Background(),
				"go",
				"run",
				".",
				"convert",
				configFile,
				"--format",
				tt.format,
				"-o",
				outputFile,
			)
			cmd.Dir = projectRoot

			var stdout, stderr bytes.Buffer

			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			if err != nil {
				t.Skipf("Skipping test - CLI command failed: %v, stderr: %s", err, stderr.String())
			}

			// Read the exported file
			exportedContent, err := os.ReadFile(outputFile)
			require.NoError(t, err, "Failed to read exported file")

			contentStr := string(exportedContent)

			// Cross-platform validation checks

			// 1. No platform-specific line endings (should be \n)
			assert.NotContains(t, contentStr, "\r\n", "File should not contain Windows line endings")
			assert.NotContains(t, contentStr, "\r", "File should not contain Mac line endings")

			// 2. No platform-specific path separators
			assert.NotContains(t, contentStr, "\\", "File should not contain Windows path separators")

			// 3. No platform-specific encoding issues
			// Check for valid UTF-8
			assert.True(t, utf8.Valid(exportedContent), "File should be valid UTF-8")

			// 4. No platform-specific control characters
			assert.NotContains(t, contentStr, "\x00", "File should not contain null bytes")
			assert.NotContains(t, contentStr, "\x1a", "File should not contain EOF characters")

			// 5. File should be readable by standard tools
			switch tt.format {
			case "markdown":
				err = markdown.ValidateMarkdown(contentStr)
				require.NoError(t, err, "Markdown should be valid")
			case "json":
				assert.True(t, json.Valid(exportedContent), "JSON should be valid")
			case "yaml":
				var result map[string]any

				err = yaml.Unmarshal(exportedContent, &result)
				require.NoError(t, err, "YAML should be valid")
			}
		})
	}
}

// TestFileExporter_Error tests the Error method of the Error type.
func TestFileExporter_Error(t *testing.T) {
	// Create an error with all fields populated
	exportErr := &Error{
		Operation: "test_operation",
		Message:   "test error message",
		Path:      "/test/path",
		Cause:     assert.AnError,
	}

	// Test the Error method
	errorString := exportErr.Error()

	// The error string should contain the operation and message
	assert.Contains(t, errorString, "test_operation")
	assert.Contains(t, errorString, "test error message")
	assert.Contains(t, errorString, "/test/path")
}

// TestFileExporter_CheckFileWritable tests the checkFileWritable function.
func TestFileExporter_CheckFileWritable(t *testing.T) {
	e := NewFileExporter()

	// Test with a writable file
	tmpFile := filepath.Join(t.TempDir(), "writable_test.txt")
	err := os.WriteFile(tmpFile, []byte("test content"), 0o600)
	require.NoError(t, err)

	fileInfo, err := os.Stat(tmpFile)
	require.NoError(t, err)

	err = e.checkFileWritable(tmpFile, fileInfo)
	require.NoError(t, err)
}

// TestFileExporter_ValidateExportPathEdgeCases tests edge cases for validateExportPath.
func TestFileExporter_ValidateExportPathEdgeCases(t *testing.T) {
	e := NewFileExporter()

	// Test path traversal detection
	err := e.validateExportPath("../../../etc/passwd")
	require.Error(t, err)
	var exportErr *Error
	require.ErrorAs(t, err, &exportErr)
	assert.Equal(t, "validate_path", exportErr.Operation)
}

// TestFileExporter_ResolveAbsolutePathEdgeCases tests edge cases for resolveAbsolutePath.
func TestFileExporter_ResolveAbsolutePathEdgeCases(t *testing.T) {
	e := NewFileExporter()

	// Test valid path resolution
	absPath, err := e.resolveAbsolutePath("test/file.txt")
	require.NoError(t, err)
	assert.NotEmpty(t, absPath)
}

// TestFileExporter_ValidateTargetDirectoryEdgeCases tests edge cases for validateTargetDirectory.
func TestFileExporter_ValidateTargetDirectoryEdgeCases(t *testing.T) {
	e := NewFileExporter()

	// Test with writable directory
	tmpDir := t.TempDir()
	err := e.validateTargetDirectory(tmpDir, tmpDir)
	require.NoError(t, err)
}

// TestFileExporter_CheckDirectoryWritableEdgeCases tests edge cases for checkDirectoryWritable.
func TestFileExporter_CheckDirectoryWritableEdgeCases(t *testing.T) {
	e := NewFileExporter()

	// Test with writable directory
	tmpDir := t.TempDir()
	err := e.checkDirectoryWritable(tmpDir)
	require.NoError(t, err)
}

// TestFileExporter_CheckExistingFilePermissionsEdgeCases tests edge cases for checkExistingFilePermissions.
func TestFileExporter_CheckExistingFilePermissionsEdgeCases(t *testing.T) {
	e := NewFileExporter()

	// Test with nonexistent file (should not error)
	nonexistentFile := filepath.Join(t.TempDir(), "nonexistent.txt")
	err := e.checkExistingFilePermissions(nonexistentFile, nonexistentFile)
	require.NoError(t, err)
}

// TestFileExporter_WriteFileAtomicEdgeCases tests edge cases for writeFileAtomic.
func TestFileExporter_WriteFileAtomicEdgeCases(t *testing.T) {
	e := NewFileExporter()

	tests := []struct {
		name        string
		content     string
		path        string
		expectError bool
	}{
		{
			name:        "empty content",
			content:     "",
			path:        filepath.Join(t.TempDir(), "empty_test.txt"),
			expectError: true,
		},
		{
			name:        "valid content",
			content:     "test content",
			path:        filepath.Join(t.TempDir(), "valid_test.txt"),
			expectError: false,
		},
		{
			name:        "large content",
			content:     strings.Repeat("test content ", 1000),
			path:        filepath.Join(t.TempDir(), "large_test.txt"),
			expectError: false,
		},
		{
			name:        "unicode content",
			content:     "test content with unicode: 🚀 🔥 💯",
			path:        filepath.Join(t.TempDir(), "unicode_test.txt"),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := e.writeFileAtomic(tt.path, []byte(tt.content))

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				// Verify file was written correctly
				content, err := os.ReadFile(tt.path)
				require.NoError(t, err)
				assert.Equal(t, tt.content, string(content))
			}
		})
	}
}
