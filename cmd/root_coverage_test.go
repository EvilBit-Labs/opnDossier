package cmd

import (
	"context"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetBuildDate verifies that getBuildDate returns the current buildDate value.
func TestGetBuildDate(t *testing.T) {
	origBuildDate := buildDate
	t.Cleanup(func() { buildDate = origBuildDate })

	buildDate = "2024-01-01"
	assert.Equal(t, "2024-01-01", getBuildDate())

	buildDate = "dev"
	assert.Equal(t, "dev", getBuildDate())
}

// TestGetGitCommit verifies that getGitCommit returns the current gitCommit value.
func TestGetGitCommit(t *testing.T) {
	origGitCommit := gitCommit
	t.Cleanup(func() { gitCommit = origGitCommit })

	gitCommit = "abc123"
	assert.Equal(t, "abc123", getGitCommit())

	gitCommit = "none"
	assert.Equal(t, "none", getGitCommit())
}

// TestSetupLightweightContext verifies that setupLightweightContext creates
// a minimal command context with default config and logger.
func TestSetupLightweightContext(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}

	err := setupLightweightContext(cmd)
	require.NoError(t, err)

	cmdCtx := GetCommandContext(cmd)
	require.NotNil(t, cmdCtx, "CommandContext should be set")
	require.NotNil(t, cmdCtx.Config, "Config should be set")
	require.NotNil(t, cmdCtx.Logger, "Logger should be set")

	assert.Equal(t, "markdown", cmdCtx.Config.Format)
	assert.Equal(t, "programmatic", cmdCtx.Config.Engine)
	assert.NotNil(t, cmd.Context())
}

// TestSetupLightweightContextPreservesExistingContext verifies that
// setupLightweightContext does not overwrite an existing go context.
func TestSetupLightweightContextPreservesExistingContext(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.SetContext(context.Background())

	err := setupLightweightContext(cmd)
	require.NoError(t, err)

	assert.NotNil(t, cmd.Context())
	cmdCtx := GetCommandContext(cmd)
	require.NotNil(t, cmdCtx)
	assert.NotNil(t, cmdCtx.Config)
}
