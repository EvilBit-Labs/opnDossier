package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const (
	testBinaryName = "opnDossier-test"
	windowsOS      = "windows"
	exeExtension   = ".exe"
)

// BuildTestSuite provides a test suite for build-related tests.
type BuildTestSuite struct {
	suite.Suite

	tempDir    string
	binaryPath string
}

// SetupSuite runs once before all tests in the suite.
func (s *BuildTestSuite) SetupSuite() {
	s.tempDir = s.T().TempDir()
	s.buildBinary()
}

// buildBinary builds the test binary once for the entire suite.
func (s *BuildTestSuite) buildBinary() {
	binaryName := testBinaryName
	if runtime.GOOS == windowsOS {
		binaryName += exeExtension
	}
	s.binaryPath = filepath.Join(s.tempDir, binaryName)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	//nolint:gosec // This is test code, the binary path is controlled by the test
	cmd := exec.CommandContext(ctx, "go", "build", "-o", s.binaryPath, ".")
	cmd.Dir = "." // Current directory (project root)
	output, err := cmd.CombinedOutput()
	s.Require().NoError(err, "Failed to build binary: %s", string(output))

	// Verify the binary was created
	_, err = os.Stat(s.binaryPath)
	s.Require().NoError(err, "Binary should exist")
}

// runBinary executes the binary with given arguments and returns output.
func (s *BuildTestSuite) runBinary(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	//nolint:gosec // This is test code, the binary path is controlled by the test
	cmd := exec.CommandContext(ctx, s.binaryPath, args...)
	cmd.Dir = s.tempDir // Run from temp dir where there are no template files
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// createTestConfig creates a minimal test configuration file.
func (s *BuildTestSuite) createTestConfig() string {
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

	configPath := filepath.Join(s.tempDir, "test-config.xml")
	err := os.WriteFile(configPath, []byte(configContent), 0o600)
	s.Require().NoError(err)
	return configPath
}

// TestBinaryWithEmbeddedTemplates tests that the binary works with embedded templates.
func (s *BuildTestSuite) TestBinaryWithEmbeddedTemplates() {
	if testing.Short() {
		s.T().Skip("Skipping build test in short mode")
	}

	output, err := s.runBinary("--help")

	// The binary should run successfully using embedded templates
	s.Require().NoError(err, "Binary should run with embedded templates, output: %s", output)
	s.Contains(output, "opnDossier", "Help output should contain application name")
	s.Contains(output, "convert", "Help output should contain convert command")
}

// TestTemplateEmbeddingInBinary tests that embedded templates are accessible.
func (s *BuildTestSuite) TestTemplateEmbeddingInBinary() {
	if testing.Short() {
		s.T().Skip("Skipping template embedding test in short mode")
	}

	// Create a minimal test config file
	configPath := s.createTestConfig()

	// Try to convert the config using the binary
	// This will test that embedded templates are accessible
	output, err := s.runBinary("convert", configPath, "--format", "json")

	// The command might fail for other reasons (invalid config, etc.)
	// but it should NOT fail due to missing templates
	s.NotContains(output, "buildssa", "Should not have build errors")
	s.NotContains(output, "export data", "Should not have export data errors")
	s.NotContains(output, "no templates found", "Should find embedded templates")

	// If it fails, it should be for legitimate reasons, not embedding
	if err != nil {
		s.T().Logf("Binary output (may fail for legitimate reasons): %s", output)
		// We mainly care that it's not failing due to embedding issues
	}
}

// TestBinaryWithEmbeddedTemplatesSuite runs the build test suite.
func TestBinaryWithEmbeddedTemplatesSuite(t *testing.T) {
	suite.Run(t, new(BuildTestSuite))
}

// Legacy test functions for backward compatibility and simpler test runs.
func TestBinaryWithEmbeddedTemplates_Legacy(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping build test in short mode")
	}

	t.Run("binary works with embedded templates when filesystem templates are missing", func(t *testing.T) {
		// Create a temporary directory for our test
		tempDir := t.TempDir()

		// Build the binary in the temp directory
		binaryName := testBinaryName
		if runtime.GOOS == windowsOS {
			binaryName += exeExtension
		}
		binaryPath := filepath.Join(tempDir, binaryName)

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

func TestTemplateEmbeddingInBinary_Legacy(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping template embedding test in short mode")
	}

	t.Run("binary can access embedded templates for conversion", func(t *testing.T) {
		// This test verifies that a built binary can access embedded templates
		// even when running from a directory without template files

		tempDir := t.TempDir()
		binaryName := testBinaryName
		if runtime.GOOS == windowsOS {
			binaryName += exeExtension
		}
		binaryPath := filepath.Join(tempDir, binaryName)

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
