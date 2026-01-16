package cmd

import (
	"bytes"
	"errors"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddSharedTemplateFlagsRegistersFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	addSharedTemplateFlags(cmd)

	flags := cmd.Flags()
	require.NotNil(t, flags.Lookup("legacy"))
	require.NotNil(t, flags.Lookup("custom-template"))
	require.NotNil(t, flags.Lookup("template-cache-size"))
}

func TestAddSharedTemplateFlags_DeprecationFailureLogsWarning(t *testing.T) {
	originalMarkDeprecated := markDeprecated
	t.Cleanup(func() {
		markDeprecated = originalMarkDeprecated
	})
	markDeprecated = func(_ *pflag.FlagSet, _, _ string) error {
		return errors.New("deprecation failure")
	}

	var logOutput bytes.Buffer
	testLogger, err := log.New(log.Config{
		Level:  "warn",
		Format: "text",
		Output: &logOutput,
	})
	require.NoError(t, err)

	originalLogger := logger
	logger = testLogger
	t.Cleanup(func() {
		logger = originalLogger
	})

	cmd := &cobra.Command{Use: "test"}
	addSharedTemplateFlags(cmd)

	output := logOutput.String()
	assert.Contains(t, output, "Could not mark --legacy as deprecated")
	assert.Contains(t, output, "deprecation warning will not be shown")
	assert.NotNil(t, cmd.Flags().Lookup("legacy"))
}
