package cmd

import (
	"context"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCommandContext_ValidContext(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.SetContext(context.Background())

	expectedCfg := &config.Config{Verbose: true}
	expectedLogger, err := logging.New(logging.Config{Level: "info"})
	require.NoError(t, err)

	cmdCtx := &CommandContext{
		Config: expectedCfg,
		Logger: expectedLogger,
	}

	SetCommandContext(cmd, cmdCtx)

	result := GetCommandContext(cmd)
	require.NotNil(t, result)
	assert.Equal(t, expectedCfg, result.Config)
	assert.Equal(t, expectedLogger, result.Logger)
}

func TestGetCommandContext_NilCommand(t *testing.T) {
	result := GetCommandContext(nil)
	assert.Nil(t, result)
}

func TestGetCommandContext_NilContext(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	// Don't set context

	result := GetCommandContext(cmd)
	assert.Nil(t, result)
}

func TestGetCommandContext_MissingKey(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.SetContext(context.Background())
	// Don't set CommandContext

	result := GetCommandContext(cmd)
	assert.Nil(t, result)
}

func TestGetCommandContext_WrongType(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	// Set a different type with the same key
	ctx := context.WithValue(context.Background(), cmdContextKey, "not a CommandContext")
	cmd.SetContext(ctx)

	result := GetCommandContext(cmd)
	assert.Nil(t, result)
}

func TestSetCommandContext_NilCommand(t *testing.T) {
	cmdCtx := &CommandContext{}

	// Should not panic
	require.NotPanics(t, func() {
		SetCommandContext(nil, cmdCtx)
	})
}

func TestSetCommandContext_NilContext(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	// Don't set context on command

	cmdCtx := &CommandContext{
		Config: &config.Config{},
	}

	SetCommandContext(cmd, cmdCtx)

	// Should have created a new context and stored the value
	result := GetCommandContext(cmd)
	require.NotNil(t, result)
	assert.Equal(t, cmdCtx.Config, result.Config)
}

// testContextKey is a typed key for testing context preservation.
type testContextKey string

func TestSetCommandContext_ExistingContext(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	const otherKey testContextKey = "other-key"
	existingCtx := context.WithValue(context.Background(), otherKey, "other-value")
	cmd.SetContext(existingCtx)

	cmdCtx := &CommandContext{
		Config: &config.Config{Verbose: true},
	}

	SetCommandContext(cmd, cmdCtx)

	// Should preserve existing context values
	assert.Equal(t, "other-value", cmd.Context().Value(otherKey))

	// And also have the CommandContext
	result := GetCommandContext(cmd)
	require.NotNil(t, result)
	assert.True(t, result.Config.Verbose)
}

func TestMustGetCommandContext_ValidContext(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.SetContext(context.Background())

	cmdCtx := &CommandContext{
		Config: &config.Config{},
	}
	SetCommandContext(cmd, cmdCtx)

	require.NotPanics(t, func() {
		result := MustGetCommandContext(cmd)
		assert.NotNil(t, result)
	})
}

func TestMustGetCommandContext_NilContext_Panics(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	// Don't set context

	assert.Panics(t, func() {
		MustGetCommandContext(cmd)
	})
}

func TestMustGetCommandContext_MissingKey_Panics(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.SetContext(context.Background())
	// Don't set CommandContext

	assert.Panics(t, func() {
		MustGetCommandContext(cmd)
	})
}

func TestCommandContext_FieldAccess(t *testing.T) {
	cfg := &config.Config{
		Verbose:    true,
		Quiet:      false,
		OutputFile: "test.md",
	}
	logger, err := logging.New(logging.Config{Level: "debug"})
	require.NoError(t, err)

	cmdCtx := &CommandContext{
		Config: cfg,
		Logger: logger,
	}

	assert.True(t, cmdCtx.Config.Verbose)
	assert.False(t, cmdCtx.Config.Quiet)
	assert.Equal(t, "test.md", cmdCtx.Config.OutputFile)
	assert.NotNil(t, cmdCtx.Logger)
}
