package cmd

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigCmdHelp(t *testing.T) {
	rootCmd := GetRootCmd()
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"config", "--help"})

	err := rootCmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "config")
	assert.Contains(t, output, "show")
	assert.Contains(t, output, "init")
	assert.Contains(t, output, "validate")
}

func TestConfigCmdSubcommands(t *testing.T) {
	// Find the config command
	var configCmd *cobra.Command
	for _, cmd := range GetRootCmd().Commands() {
		if cmd.Name() == "config" {
			configCmd = cmd
			break
		}
	}
	require.NotNil(t, configCmd, "config command should exist")

	// Get subcommand names
	subcommandNames := make([]string, 0)
	for _, cmd := range configCmd.Commands() {
		subcommandNames = append(subcommandNames, cmd.Name())
	}

	// Verify expected subcommands exist
	assert.Contains(t, subcommandNames, "show")
	assert.Contains(t, subcommandNames, "init")
	assert.Contains(t, subcommandNames, "validate")
}

func TestConfigCmdGroupID(t *testing.T) {
	// Find the config command
	var configCmd *cobra.Command
	for _, cmd := range GetRootCmd().Commands() {
		if cmd.Name() == "config" {
			configCmd = cmd
			break
		}
	}
	require.NotNil(t, configCmd, "config command should exist")
	assert.Equal(t, "utility", configCmd.GroupID)
}
