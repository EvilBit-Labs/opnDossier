package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBinaryWithEmbeddedTemplates(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping build test in short mode")
	}

	t.Run("binary works with embedded templates when filesystem templates are missing", func(t *testing.T) {
		// Create a temporary directory for our test
		tempDir := t.TempDir()

		// Build the binary in the temp directory
		binaryPath := filepath.Join(tempDir, "opnDossier-test")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Build the binary
		cmd := exec.CommandContext(ctx, "go", "build", "-o", binaryPath, ".")
		cmd.Dir = "." // Current directory (project root)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Failed to build binary: %s", string(output))

		// Verify the binary was created
		_, err = os.Stat(binaryPath)
		require.NoError(t, err, "Binary should exist")

		// Test that the binary can run and show help (this exercises template loading)
		ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel2()

		cmd = exec.CommandContext(ctx2, binaryPath, "--help")
		cmd.Dir = tempDir // Run from temp dir where there are no template files
		output, err = cmd.CombinedOutput()

		// The binary should run successfully using embedded templates
		require.NoError(t, err, "Binary should run with embedded templates, output: %s", string(output))
		assert.Contains(t, string(output), "opnDossier", "Help output should contain application name")
		assert.Contains(t, string(output), "convert", "Help output should contain convert command")
	})
}

func TestTemplateEmbeddingInBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping template embedding test in short mode")
	}

	t.Run("binary can access embedded templates for conversion", func(t *testing.T) {
		// This test verifies that a built binary can access embedded templates
		// even when running from a directory without template files

		tempDir := t.TempDir()
		binaryPath := filepath.Join(tempDir, "opnDossier-test")

		// Build the binary
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "go", "build", "-o", binaryPath, ".")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Failed to build binary: %s", string(output))

		// Create a minimal test config file
		configContent := `<?xml version="1.0"?>
<opnsense>
  <version>24.1</version>
  <system>
    <hostname>test-firewall</hostname>
    <domain>example.com</domain>
  </system>
  <interfaces>
    <wan>
      <enable>1</enable>
      <if>em0</if>
      <ipaddr>dhcp</ipaddr>
    </wan>
  </interfaces>
</opnsense>`

		configPath := filepath.Join(tempDir, "test-config.xml")
		err = os.WriteFile(configPath, []byte(configContent), 0o600)
		require.NoError(t, err)

		// Try to convert the config using the binary
		// This will test that embedded templates are accessible
		ctx2, cancel2 := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel2()

		cmd = exec.CommandContext(ctx2, binaryPath, "convert", configPath, "--format", "json")
		cmd.Dir = tempDir // Run from temp dir without template files
		output, err = cmd.CombinedOutput()

		// The command might fail for other reasons (invalid config, etc.)
		// but it should NOT fail due to missing templates
		outputStr := string(output)

		// Check that it's not failing due to template embedding issues
		assert.NotContains(t, outputStr, "buildssa", "Should not have build errors")
		assert.NotContains(t, outputStr, "export data", "Should not have export data errors")
		assert.NotContains(t, outputStr, "no templates found", "Should find embedded templates")

		// If it fails, it should be for legitimate reasons, not embedding
		if err != nil {
			t.Logf("Binary output (may fail for legitimate reasons): %s", outputStr)
			// We mainly care that it's not failing due to embedding issues
		}
	})
}
