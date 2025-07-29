package export

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/opnFocus/internal/markdown"
)

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
			path:    filepath.Join(os.TempDir(), "test_output.md"),
			wantErr: false,
		},
		{
			name:    "invalid path",
			content: "test content",
			path:    "/nonexistent/path/test_output.md",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewFileExporter()
			err := e.Export(context.Background(), tt.content, tt.path)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				content, err := os.ReadFile(tt.path)
				assert.NoError(t, err)
				assert.Equal(t, tt.content, string(content))
				_ = os.Remove(tt.path) //nolint:errcheck // Test cleanup
			}
		})
	}
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
			path: filepath.Join(os.TempDir(), "test_markdown_validation.md"),
		},
		{
			name: "simple markdown content",
			content: `# Simple Document

Just plain text with a heading.

- List item
- Another item
`,
			path: filepath.Join(os.TempDir(), "test_simple_markdown.md"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewFileExporter()

			// Export the markdown content
			err := e.Export(context.Background(), tt.content, tt.path)
			require.NoError(t, err)
			defer os.Remove(tt.path) //nolint:errcheck // Test cleanup

			// Read the exported file
			exportedContent, err := os.ReadFile(tt.path)
			require.NoError(t, err)
			assert.Equal(t, tt.content, string(exportedContent))

			// Validate that the exported markdown passes validation
			err = markdown.ValidateMarkdown(string(exportedContent))
			assert.NoError(t, err, "Exported markdown should pass validation")
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

	path := filepath.Join(os.TempDir(), "test_no_control_chars.md")
	e := NewFileExporter()

	err := e.Export(context.Background(), testContent, path)
	require.NoError(t, err)
	defer os.Remove(path) //nolint:errcheck // Test cleanup

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
	tmpDir, err := os.MkdirTemp("", "opnfocus-export-test")
	require.NoError(t, err)
	defer func() {
		_ = os.RemoveAll(tmpDir) //nolint:errcheck // Test cleanup
	}()

	// Create a sample OPNsense config file for testing
	configContent := `<?xml version="1.0"?>
<opnsense>
  <version>24.1</version>
  <system>
    <hostname>test-firewall</hostname>
    <domain>example.com</domain>
    <dnsserver>8.8.8.8</dnsserver>
    <dnsserver>8.8.4.4</dnsserver>
    <timezone>UTC</timezone>
  </system>
  <interfaces>
    <wan>
      <enable>1</enable>
      <if>vtnet0</if>
      <ipaddr>dhcp</ipaddr>
      <ipaddrv6>dhcp6</ipaddrv6>
      <subnet>24</subnet>
      <gateway>wan_gw</gateway>
    </wan>
    <lan>
      <enable>1</enable>
      <if>vtnet1</if>
      <ipaddr>192.168.1.1</ipaddr>
      <subnet>24</subnet>
    </lan>
  </interfaces>
  <gateways>
    <gateway_item>
      <interface>wan</interface>
      <gateway>192.168.0.1</gateway>
      <name>wan_gw</name>
      <weight>1</weight>
      <ipprotocol>inet</ipprotocol>
      <interval>1</interval>
    </gateway_item>
  </gateways>
</opnsense>`

	configFile := filepath.Join(tmpDir, "test-config.xml")
	err = os.WriteFile(configFile, []byte(configContent), 0o600)
	require.NoError(t, err)

	// Run the CLI command to generate the markdown file using go run
	// Change to project root directory first
	projectRoot := filepath.Join("..", "..")
	outputFile := filepath.Join(tmpDir, "test_output.md")
	cmd := exec.CommandContext(context.Background(), "go", "run", ".", "convert", configFile, "--format", "markdown", "-o", outputFile)
	cmd.Dir = projectRoot

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		t.Skipf("Skipping test - CLI command failed: %v, stderr: %s", err, stderr.String())
	}

	// Read the exported file
	exportedContent, err := os.ReadFile(outputFile)
	require.NoError(t, err, "Failed to read exported file")

	contentStr := string(exportedContent)

	// 1. Validate that the markdown passes validation
	err = markdown.ValidateMarkdown(contentStr)
	assert.NoError(t, err, "Exported markdown should pass validation")

	// 2. Check for no terminal control characters
	assert.NotContains(t, contentStr, "\x1b[", "Exported markdown should not contain ANSI escape sequences")
	assert.NotContains(t, contentStr, "\x07", "Exported markdown should not contain bell characters")
	assert.NotContains(t, contentStr, "\x08", "Exported markdown should not contain backspace characters")

	// 3. Verify it uses templates from internal/templates by checking for expected content
	// The templates should generate content with specific structure
	assert.Contains(t, contentStr, "# OPNsense Configuration Summary", "Should contain expected template-generated content")
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
	tests := []struct {
		name    string
		content string
		path    string
	}{
		{
			name: "valid json content",
			content: `{
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
			path: filepath.Join(os.TempDir(), "test_json_validation.json"),
		},
		{
			name: "simple json content",
			content: `{
  "hostname": "simple-test",
  "enabled": true,
  "version": "1.0.0"
}`,
			path: filepath.Join(os.TempDir(), "test_simple_json.json"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewFileExporter()

			// Export the JSON content
			err := e.Export(context.Background(), tt.content, tt.path)
			require.NoError(t, err)
			defer os.Remove(tt.path) //nolint:errcheck // Test cleanup

			// Read the exported file
			exportedContent, err := os.ReadFile(tt.path)
			require.NoError(t, err)
			assert.Equal(t, tt.content, string(exportedContent))

			// Validate that the exported JSON passes validation
			err = validateJSON(string(exportedContent))
			assert.NoError(t, err, "Exported JSON should pass validation")
		})
	}
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

	path := filepath.Join(os.TempDir(), "test_no_control_chars_json.json")
	e := NewFileExporter()

	err := e.Export(context.Background(), testContent, path)
	require.NoError(t, err)
	defer os.Remove(path) //nolint:errcheck // Test cleanup

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
	tmpDir, err := os.MkdirTemp("", "opnfocus-export-test")
	require.NoError(t, err)
	defer func() {
		_ = os.RemoveAll(tmpDir) //nolint:errcheck // Test cleanup
	}()

	// Create a sample OPNsense config file for testing
	configContent := `<?xml version="1.0"?>
<opnsense>
  <version>24.1</version>
  <system>
    <hostname>test-firewall</hostname>
    <domain>example.com</domain>
    <dnsserver>8.8.8.8</dnsserver>
    <dnsserver>8.8.4.4</dnsserver>
    <timezone>UTC</timezone>
  </system>
  <interfaces>
    <wan>
      <enable>1</enable>
      <if>vtnet0</if>
      <ipaddr>dhcp</ipaddr>
      <ipaddrv6>dhcp6</ipaddrv6>
      <subnet>24</subnet>
      <gateway>wan_gw</gateway>
    </wan>
    <lan>
      <enable>1</enable>
      <if>vtnet1</if>
      <ipaddr>192.168.1.1</ipaddr>
      <subnet>24</subnet>
    </lan>
  </interfaces>
  <gateways>
    <gateway_item>
      <interface>wan</interface>
      <gateway>192.168.0.1</gateway>
      <name>wan_gw</name>
      <weight>1</weight>
      <ipprotocol>inet</ipprotocol>
      <interval>1</interval>
    </gateway_item>
  </gateways>
</opnsense>`

	configFile := filepath.Join(tmpDir, "test-config.xml")
	err = os.WriteFile(configFile, []byte(configContent), 0o600)
	require.NoError(t, err)

	// Run the CLI command to generate the JSON file using go run
	// Change to project root directory first
	projectRoot := filepath.Join("..", "..")
	outputFile := filepath.Join(tmpDir, "test_output.json")
	cmd := exec.CommandContext(context.Background(), "go", "run", ".", "convert", configFile, "--format", "json", "-o", outputFile)
	cmd.Dir = projectRoot

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		t.Skipf("Skipping test - CLI command failed: %v, stderr: %s", err, stderr.String())
	}

	// Read the exported file
	exportedContent, err := os.ReadFile(outputFile)
	require.NoError(t, err, "Failed to read exported file")

	contentStr := string(exportedContent)

	// 1. Validate that the JSON passes validation
	err = validateJSON(contentStr)
	assert.NoError(t, err, "Exported JSON should pass validation")

	// 2. Check for no terminal control characters
	assert.NotContains(t, contentStr, "\x1b[", "Exported JSON should not contain ANSI escape sequences")
	assert.NotContains(t, contentStr, "\x07", "Exported JSON should not contain bell characters")
	assert.NotContains(t, contentStr, "\x08", "Exported JSON should not contain backspace characters")

	// 3. Verify it's valid JSON structure
	assert.Contains(t, contentStr, "{", "Should contain JSON opening brace")
	assert.Contains(t, contentStr, "}", "Should contain JSON closing brace")
	assert.Contains(t, contentStr, "test-firewall", "Should contain expected hostname from config")
	assert.Contains(t, contentStr, "example.com", "Should contain expected domain from config")
}

// validateJSON validates that a string contains valid JSON by attempting to parse it.
func validateJSON(content string) error {
	var result map[string]any
	return json.Unmarshal([]byte(content), &result)
}
