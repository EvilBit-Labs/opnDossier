package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigInitCmd(t *testing.T) {
	testLogger, err := logging.New(logging.Config{Level: "info"})
	require.NoError(t, err)

	t.Run("Creates config file in specified path", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, ".opnDossier.yaml")

		// Store and restore global flag
		origOutputPath := configInitOutputPath
		origForce := configInitForce
		t.Cleanup(func() {
			configInitOutputPath = origOutputPath
			configInitForce = origForce
		})

		configInitOutputPath = outputPath
		configInitForce = false

		cmd := &cobra.Command{Use: "test"}
		cmd.SetContext(context.Background())
		SetCommandContext(cmd, &CommandContext{
			Config: &config.Config{},
			Logger: testLogger,
		})

		// Capture output to avoid noise in tests
		_ = captureStdout(t, func() {
			err := runConfigInit(cmd, nil)
			require.NoError(t, err)
		})

		// Verify file was created
		_, statErr := os.Stat(outputPath)
		require.NoError(t, statErr, "Config file should be created")

		// Verify content
		content, readErr := os.ReadFile(outputPath)
		require.NoError(t, readErr)
		assert.Contains(t, string(content), "opnDossier Configuration File")
		assert.Contains(t, string(content), "verbose:")
		assert.Contains(t, string(content), "format:")
	})

	t.Run("Fails when file exists without force", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, ".opnDossier.yaml")

		// Create existing file
		//nolint:gosec // Test file permissions are fine for testing
		err := os.WriteFile(outputPath, []byte("existing content"), 0o644)
		require.NoError(t, err)

		// Store and restore global flag
		origOutputPath := configInitOutputPath
		origForce := configInitForce
		t.Cleanup(func() {
			configInitOutputPath = origOutputPath
			configInitForce = origForce
		})

		configInitOutputPath = outputPath
		configInitForce = false

		cmd := &cobra.Command{Use: "test"}
		cmd.SetContext(context.Background())
		SetCommandContext(cmd, &CommandContext{
			Config: &config.Config{},
			Logger: testLogger,
		})

		err = runConfigInit(cmd, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
		assert.Contains(t, err.Error(), "--force")
	})

	t.Run("Overwrites file with force flag", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, ".opnDossier.yaml")

		// Create existing file with different content
		//nolint:gosec // Test file permissions are fine for testing
		err := os.WriteFile(outputPath, []byte("old content"), 0o644)
		require.NoError(t, err)

		// Store and restore global flag
		origOutputPath := configInitOutputPath
		origForce := configInitForce
		t.Cleanup(func() {
			configInitOutputPath = origOutputPath
			configInitForce = origForce
		})

		configInitOutputPath = outputPath
		configInitForce = true

		cmd := &cobra.Command{Use: "test"}
		cmd.SetContext(context.Background())
		SetCommandContext(cmd, &CommandContext{
			Config: &config.Config{},
			Logger: testLogger,
		})

		_ = captureStdout(t, func() {
			err := runConfigInit(cmd, nil)
			require.NoError(t, err)
		})

		// Verify file was overwritten
		content, readErr := os.ReadFile(outputPath)
		require.NoError(t, readErr)
		assert.Contains(t, string(content), "opnDossier Configuration File")
		assert.NotContains(t, string(content), "old content")
	})

	t.Run("Fails when directory does not exist", func(t *testing.T) {
		nonExistentDir := filepath.Join(t.TempDir(), "does-not-exist")
		outputPath := filepath.Join(nonExistentDir, ".opnDossier.yaml")

		// Store and restore global flag
		origOutputPath := configInitOutputPath
		origForce := configInitForce
		t.Cleanup(func() {
			configInitOutputPath = origOutputPath
			configInitForce = origForce
		})

		configInitOutputPath = outputPath
		configInitForce = false

		cmd := &cobra.Command{Use: "test"}
		cmd.SetContext(context.Background())
		SetCommandContext(cmd, &CommandContext{
			Config: &config.Config{},
			Logger: testLogger,
		})

		err := runConfigInit(cmd, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "directory does not exist")
	})

	t.Run("Fails with nil context", func(t *testing.T) {
		cmd := &cobra.Command{Use: "test"}
		// Don't set context

		err := runConfigInit(cmd, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "command context not initialized")
	})
}

func TestConfigTemplateContent(t *testing.T) {
	// Verify the template contains expected sections
	assert.Contains(t, configTemplate, "# opnDossier Configuration File")
	assert.Contains(t, configTemplate, "# Basic Settings")
	assert.Contains(t, configTemplate, "# Display Settings")
	assert.Contains(t, configTemplate, "# Export Settings")
	assert.Contains(t, configTemplate, "# Logging Settings")
	assert.Contains(t, configTemplate, "# Validation Settings")
	assert.Contains(t, configTemplate, "# Environment Variables")

	// Verify expected configuration options are present (commented out)
	assert.Contains(t, configTemplate, "# verbose:")
	assert.Contains(t, configTemplate, "# format:")
	assert.Contains(t, configTemplate, "# theme:")
	assert.Contains(t, configTemplate, "# wrap:")
	assert.Contains(t, configTemplate, "# display:")
	assert.Contains(t, configTemplate, "# logging:")
	assert.Contains(t, configTemplate, "# validation:")
}
