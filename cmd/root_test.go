package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const rootTestConfigContent = `verbose: false
quiet: false
`

func TestGetRootCmd(t *testing.T) {
	rootCmd := GetRootCmd()
	require.NotNil(t, rootCmd)
	assert.Equal(t, "opnDossier", rootCmd.Use)
	assert.Contains(t, rootCmd.Short, "CLI tool for processing OPNsense configuration files")
}

func TestRootCmdFlags(t *testing.T) {
	rootCmd := GetRootCmd()

	// Test that persistent flags are defined
	flags := rootCmd.PersistentFlags()

	// Check config flag
	configFlag := flags.Lookup("config")
	require.NotNil(t, configFlag)
	assert.Empty(t, configFlag.DefValue)

	// Check verbose flag
	verboseFlag := flags.Lookup("verbose")
	require.NotNil(t, verboseFlag)
	assert.Equal(t, "false", verboseFlag.DefValue)

	// Check quiet flag
	quietFlag := flags.Lookup("quiet")
	require.NotNil(t, quietFlag)
	assert.Equal(t, "false", quietFlag.DefValue)
}

func TestRootCmdHelp(t *testing.T) {
	rootCmd := GetRootCmd()
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"--help"})
	err := rootCmd.Execute()
	require.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "opnDossier")
	assert.Contains(t, output, "OPNsense configuration files")
	assert.Contains(t, output, "EXAMPLES:")
	assert.Contains(t, output, "--verbose")
	assert.Contains(t, output, "--quiet")
	assert.Contains(t, output, "--config")
}

func TestGetFlagsByCategory(t *testing.T) {
	rootCmd := GetRootCmd()
	categories := GetFlagsByCategory(rootCmd)

	// Test that categories exist
	assert.Contains(t, categories, "configuration")
	assert.Contains(t, categories, "output")

	// Test specific flags in categories
	assert.Contains(t, categories["configuration"], "config")
	assert.Contains(t, categories["output"], "verbose")
	assert.Contains(t, categories["output"], "quiet")
}

func TestRootCmdSubcommands(t *testing.T) {
	rootCmd := GetRootCmd()

	// Get all subcommands
	subcommands := rootCmd.Commands()

	// Verify we have the expected subcommands
	commandNames := make([]string, 0, len(subcommands))
	for _, subcmd := range subcommands {
		commandNames = append(commandNames, subcmd.Name())
	}

	// Should have convert, display, validate commands
	assert.Contains(t, commandNames, "convert")
	assert.Contains(t, commandNames, "display")
	assert.Contains(t, commandNames, "validate")
}

func TestGetLogger(t *testing.T) {
	// Test that GetLogger returns a logger instance
	logger := GetLogger()
	require.NotNil(t, logger)
}

func TestGetConfig(_ *testing.T) {
	// Initially, config should be nil until initialized
	config := GetConfig()
	// Config is initialized during PersistentPreRunE, so it may be nil initially
	// This is expected behavior
	_ = config // Just verify the function doesn't panic
}

func TestRootCmdPersistentPreRunE(t *testing.T) {
	// Create a temporary config file for testing
	tmpFile, err := os.CreateTemp(t.TempDir(), "opndossier-test-*.yaml")
	require.NoError(t, err)

	defer func() {
		err := os.Remove(tmpFile.Name())
		require.NoError(t, err)
	}()

	// Write a minimal config
	_, err = tmpFile.WriteString(rootTestConfigContent)
	require.NoError(t, err)
	err = tmpFile.Close()
	require.NoError(t, err)

	// Create a fresh command for testing
	testCmd := &cobra.Command{
		Use: "test",
		RunE: func(_ *cobra.Command, _ []string) error {
			return nil
		},
	}

	// Copy flags from root command
	rootCmd := GetRootCmd()
	testCmd.PersistentFlags().AddFlagSet(rootCmd.PersistentFlags())

	// Set the config file flag
	require.NoError(t, testCmd.PersistentFlags().Set("config", tmpFile.Name()))

	// Test PersistentPreRunE
	err = rootCmd.PersistentPreRunE(testCmd, []string{})
	require.NoError(t, err)

	// Verify config and logger are initialized
	assert.NotNil(t, GetConfig())
	assert.NotNil(t, GetLogger())
}

func TestRootCmdInvalidConfig(t *testing.T) {
	// Create a temporary invalid config file
	tmpFile, err := os.CreateTemp(t.TempDir(), "opndossier-invalid-*.yaml")
	require.NoError(t, err)

	defer func() {
		err := os.Remove(tmpFile.Name())
		require.NoError(t, err)
	}()

	// Write invalid YAML
	_, err = tmpFile.WriteString("invalid: yaml: content: [")
	require.NoError(t, err)
	err = tmpFile.Close()
	require.NoError(t, err)

	// Create a fresh command for testing
	testCmd := &cobra.Command{
		Use: "test",
	}

	// Copy flags from root command
	rootCmd := GetRootCmd()
	testCmd.PersistentFlags().AddFlagSet(rootCmd.PersistentFlags())

	// Set the invalid config file flag
	require.NoError(t, testCmd.PersistentFlags().Set("config", tmpFile.Name()))

	// Test PersistentPreRunE should return an error
	err = rootCmd.PersistentPreRunE(testCmd, []string{})
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "config")
}

func TestRootCmdVerboseQuietFlags(t *testing.T) {
	// Create a temporary config file for testing
	tmpFile, err := os.CreateTemp(t.TempDir(), "opndossier-test-*.yaml")
	require.NoError(t, err)

	defer func() {
		err := os.Remove(tmpFile.Name())
		require.NoError(t, err)
	}()

	// Write a minimal config
	_, err = tmpFile.WriteString(rootTestConfigContent)
	require.NoError(t, err)
	err = tmpFile.Close()
	require.NoError(t, err)

	// Test verbose flag functionality
	testCmd := &cobra.Command{Use: "test"}
	rootCmd := GetRootCmd()
	testCmd.PersistentFlags().AddFlagSet(rootCmd.PersistentFlags())

	// Set the config file and verbose flag
	require.NoError(t, testCmd.PersistentFlags().Set("config", tmpFile.Name()))
	require.NoError(t, testCmd.PersistentFlags().Set("verbose", "true"))
	err = rootCmd.PersistentPreRunE(testCmd, []string{})
	require.NoError(t, err)

	// Create a new command for quiet test
	testCmd2 := &cobra.Command{Use: "test2"}
	testCmd2.PersistentFlags().AddFlagSet(rootCmd.PersistentFlags())

	// Set the config file and quiet flag
	require.NoError(t, testCmd2.PersistentFlags().Set("config", tmpFile.Name()))
	require.NoError(t, testCmd2.PersistentFlags().Set("quiet", "true"))
	err = rootCmd.PersistentPreRunE(testCmd2, []string{})
	require.NoError(t, err)
}

func TestInitializeDefaultLogger_NoPanicOnInvalidConfig(t *testing.T) {
	originalConfig := defaultLoggerConfig
	t.Cleanup(func() {
		defaultLoggerConfig = originalConfig
		initializeDefaultLogger()
	})

	defaultLoggerConfig = log.Config{
		Level:  "invalid",
		Format: "text",
		Output: os.Stderr,
	}

	require.NotPanics(t, func() {
		initializeDefaultLogger()
	})
}

func TestInitializeDefaultLoggerFallbackWritesToStderr(t *testing.T) {
	originalConfig := defaultLoggerConfig
	t.Cleanup(func() {
		defaultLoggerConfig = originalConfig
		initializeDefaultLogger()
	})

	defaultLoggerConfig = log.Config{
		Level:  "invalid",
		Format: "text",
		Output: os.Stderr,
	}

	output := captureStderr(t, func() {
		initializeDefaultLogger()
	})

	assert.Contains(t, output, "unable to initialize logging")
	assert.NotNil(t, GetLogger())
}

func TestRootCmdPersistentPreRunERecoversFromFallback(t *testing.T) {
	originalConfig := defaultLoggerConfig
	t.Cleanup(func() {
		defaultLoggerConfig = originalConfig
		initializeDefaultLogger()
	})

	defaultLoggerConfig = log.Config{
		Level:  "invalid",
		Format: "text",
		Output: os.Stderr,
	}
	initializeDefaultLogger()

	// Create a temporary config file for testing
	tmpFile, err := os.CreateTemp(t.TempDir(), "opndossier-test-*.yaml")
	require.NoError(t, err)

	defer func() {
		err := os.Remove(tmpFile.Name())
		require.NoError(t, err)
	}()

	// Write a minimal config
	_, err = tmpFile.WriteString(rootTestConfigContent)
	require.NoError(t, err)
	err = tmpFile.Close()
	require.NoError(t, err)

	// Create a fresh command for testing
	testCmd := &cobra.Command{
		Use: "test",
	}

	// Copy flags from root command
	rootCmd := GetRootCmd()
	testCmd.PersistentFlags().AddFlagSet(rootCmd.PersistentFlags())

	// Set the config file flag
	require.NoError(t, testCmd.PersistentFlags().Set("config", tmpFile.Name()))

	// Test PersistentPreRunE should succeed and reinitialize logger
	err = rootCmd.PersistentPreRunE(testCmd, []string{})
	require.NoError(t, err)
	assert.NotNil(t, GetLogger())
}
