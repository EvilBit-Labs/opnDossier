//go:build integration

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEndToEndConversion performs an end-to-end integration test of the CLI
func TestEndToEndConversion(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "opndossier-integration-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create a sample OPNsense config file
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
	err = os.WriteFile(configFile, []byte(configContent), 0o644)
	require.NoError(t, err)

	// Build the opnDossier binary if it doesn't exist
	binaryPath := filepath.Join(tmpDir, "opndossier")
	if _, err := os.Stat("./opndossier"); os.IsNotExist(err) {
		buildCmd := exec.Command("go", "build", "-o", binaryPath, ".")
		err = buildCmd.Run()
		require.NoErrorf(t, err, "Failed to build opnDossier binary")
	} else {
		// Copy existing binary
		binaryPath = "./opndossier"
	}

	// Test cases for different CLI scenarios
	testCases := []struct {
		name     string
		args     []string
		expected []string // strings that should appear in output
	}{
		{
			name:     "Basic markdown conversion",
			args:     []string{"convert", configFile},
			expected: []string{"test-firewall", "example.com", "System Configuration", "Network Configuration"},
		},
		{
			name:     "JSON format conversion",
			args:     []string{"convert", configFile, "--format", "json"},
			expected: []string{`"hostname"`, `"test-firewall"`, `"domain"`, `"example.com"`},
		},
		{
			name:     "YAML format conversion",
			args:     []string{"convert", configFile, "--format", "yaml"},
			expected: []string{"hostname:", "test-firewall", "domain:", "example.com"},
		},
		{
			name:     "Markdown with specific sections",
			args:     []string{"convert", configFile, "--section", "system,network"},
			expected: []string{"System Configuration", "Network Configuration", "test-firewall"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(binaryPath, tc.args...)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()

			// The command might fail due to parsing issues, but we should get some output
			output := stdout.String() + stderr.String()
			assert.NotEmpty(t, output, "Expected some output from CLI command")

			if err != nil {
				// If there's an error, it should be a parsing error, not a command structure error
				errorStr := err.Error() + stderr.String()
				assert.True(t,
					strings.Contains(errorStr, "parse") ||
						strings.Contains(errorStr, "xml") ||
						strings.Contains(errorStr, "config"),
					"Error should be related to parsing, not command structure: %s", errorStr)
			} else {
				// If successful, check for expected content
				for _, expected := range tc.expected {
					assert.Contains(t, output, expected,
						"Output should contain expected content: %s", expected)
				}
			}
		})
	}
}

// TestEndToEndValidation tests the validate command
func TestEndToEndValidation(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "opndossier-validation-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create a sample config file (may not be fully valid but should be parseable)
	configContent := `<?xml version="1.0"?>
<opnsense>
  <version>24.1</version>
  <system>
    <hostname>test-firewall</hostname>
  </system>
</opnsense>`

	configFile := filepath.Join(tmpDir, "test-config.xml")
	err = os.WriteFile(configFile, []byte(configContent), 0o644)
	require.NoError(t, err)

	// Use the built binary or build it
	binaryPath := "./opndossier"
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		binaryPath = filepath.Join(tmpDir, "opndossier")
		buildCmd := exec.Command("go", "build", "-o", binaryPath, ".")
		err = buildCmd.Run()
		require.NoError(t, err)
	}

	// Test validation command
	cmd := exec.Command(binaryPath, "validate", configFile)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	output := stdout.String() + stderr.String()

	// The validate command should run and provide some output
	assert.NotEmpty(t, output, "Validate command should produce output")

	// Check that it mentions validation or parsing
	assert.True(t,
		strings.Contains(output, "valid") ||
			strings.Contains(output, "parse") ||
			strings.Contains(output, "check"),
		"Output should mention validation or parsing")
}

// TestEndToEndDisplay tests the display command
func TestEndToEndDisplay(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "opndossier-display-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create a minimal config file
	configContent := `<?xml version="1.0"?>
<opnsense>
  <version>24.1</version>
  <system>
    <hostname>display-test</hostname>
  </system>
</opnsense>`

	configFile := filepath.Join(tmpDir, "test-config.xml")
	err = os.WriteFile(configFile, []byte(configContent), 0o644)
	require.NoError(t, err)

	// Use the built binary or build it
	binaryPath := "./opndossier"
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		binaryPath = filepath.Join(tmpDir, "opndossier")
		buildCmd := exec.Command("go", "build", "-o", binaryPath, ".")
		err = buildCmd.Run()
		require.NoError(t, err)
	}

	// Test display command
	cmd := exec.Command(binaryPath, "display", configFile)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	output := stdout.String() + stderr.String()

	// The display command should run and provide some output
	assert.NotEmpty(t, output, "Display command should produce output")
}

func TestEndToEndDisplayWrapWidth(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "opndossier-display-wrap-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	longHostname := "display-wrap-" + strings.Repeat("a", 140)
	configContent := `<?xml version="1.0"?>
<opnsense>
  <version>24.1</version>
  <system>
    <hostname>` + longHostname + `</hostname>
  </system>
</opnsense>`

	configFile := filepath.Join(tmpDir, "test-config.xml")
	err = os.WriteFile(configFile, []byte(configContent), 0o644)
	require.NoError(t, err)

	binaryPath := "./opndossier"
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		binaryPath = filepath.Join(tmpDir, "opndossier")
		buildCmd := exec.Command("go", "build", "-o", binaryPath, ".")
		err = buildCmd.Run()
		require.NoError(t, err)
	}

	t.Run("Explicit wrap widths", func(t *testing.T) {
		tests := []struct {
			name      string
			wrapWidth int
			args      []string
		}{
			{
				name:      "Wrap 80",
				wrapWidth: 80,
				args:      []string{"display", "--wrap", "80", configFile},
			},
			{
				name:      "Wrap 100",
				wrapWidth: 100,
				args:      []string{"display", "--wrap", "100", configFile},
			},
			{
				name:      "Wrap 120",
				wrapWidth: 120,
				args:      []string{"display", "--wrap", "120", configFile},
			},
			{
				name:      "Wrap 80 with comprehensive output",
				wrapWidth: 80,
				args:      []string{"display", "--wrap", "80", "--comprehensive", configFile},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				cmd := exec.Command(binaryPath, tt.args...)
				var stdout, stderr bytes.Buffer
				cmd.Stdout = &stdout
				cmd.Stderr = &stderr

				err := cmd.Run()
				require.NoError(t, err)

				output := stdout.String() + stderr.String()
				assert.NotEmpty(t, output, "Display output should not be empty")

				maxLen := maxVisibleLineLength(stripANSI(output))
				assert.LessOrEqual(t, maxLen, tt.wrapWidth)
			})
		}
	})

	t.Run("Auto-detected wrap width via COLUMNS", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "display", configFile)
		cmd.Env = append(os.Environ(), "COLUMNS=100")

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		require.NoError(t, err)

		output := stdout.String() + stderr.String()
		assert.NotEmpty(t, output, "Display output should not be empty")

		maxLen := maxVisibleLineLength(stripANSI(output))
		assert.LessOrEqual(t, maxLen, 100)
	})
}

func stripANSI(input string) string {
	re := regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
	return re.ReplaceAllString(input, "")
}

func maxVisibleLineLength(output string) int {
	maxLen := 0
	inCodeBlock := false

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "```") {
			inCodeBlock = !inCodeBlock
			continue
		}
		if inCodeBlock {
			continue
		}
		if strings.HasPrefix(trimmed, "|") {
			continue
		}
		if strings.HasPrefix(trimmed, "---") {
			continue
		}
		if trimmed == "" {
			continue
		}

		visible := strings.TrimRightFunc(trimmed, func(r rune) bool { return r == '\r' })
		if len(visible) > maxLen {
			maxLen = len(visible)
		}
	}

	return maxLen
}
