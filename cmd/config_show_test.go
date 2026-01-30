package cmd

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectSource(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		defaultVal string
		expected   string
	}{
		{
			name:       "Value equals default",
			value:      "markdown",
			defaultVal: "markdown",
			expected:   sourceDefault,
		},
		{
			name:       "Value differs from default",
			value:      "json",
			defaultVal: "markdown",
			expected:   sourceConfigured,
		},
		{
			name:       "Empty value with empty default",
			value:      "",
			defaultVal: "",
			expected:   sourceDefault,
		},
		{
			name:       "Non-empty value with empty default",
			value:      "custom",
			defaultVal: "",
			expected:   sourceConfigured,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectSource(tt.value, tt.defaultVal)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDetectSourceBool(t *testing.T) {
	tests := []struct {
		name       string
		value      bool
		defaultVal bool
		expected   string
	}{
		{
			name:       "Both false",
			value:      false,
			defaultVal: false,
			expected:   sourceDefault,
		},
		{
			name:       "Both true",
			value:      true,
			defaultVal: true,
			expected:   sourceDefault,
		},
		{
			name:       "Value true default false",
			value:      true,
			defaultVal: false,
			expected:   sourceConfigured,
		},
		{
			name:       "Value false default true",
			value:      false,
			defaultVal: true,
			expected:   sourceConfigured,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectSourceBool(tt.value, tt.defaultVal)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDetectSourceInt(t *testing.T) {
	tests := []struct {
		name       string
		value      int
		defaultVal int
		expected   string
	}{
		{
			name:       "Both same value",
			value:      -1,
			defaultVal: -1,
			expected:   sourceDefault,
		},
		{
			name:       "Different values",
			value:      80,
			defaultVal: -1,
			expected:   sourceConfigured,
		},
		{
			name:       "Zero is different from default",
			value:      0,
			defaultVal: -1,
			expected:   sourceConfigured,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectSourceInt(tt.value, tt.defaultVal)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDetectSourceSlice(t *testing.T) {
	tests := []struct {
		name     string
		value    []string
		expected string
	}{
		{
			name:     "Empty slice",
			value:    []string{},
			expected: sourceDefault,
		},
		{
			name:     "Nil slice",
			value:    nil,
			expected: sourceDefault,
		},
		{
			name:     "Non-empty slice",
			value:    []string{"system", "network"},
			expected: sourceConfigured,
		},
		{
			name:     "Single element",
			value:    []string{"firewall"},
			expected: sourceConfigured,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectSourceSlice(tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatValueForDisplay(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		expected string
	}{
		{
			name:     "Empty string",
			value:    "",
			expected: "(empty)",
		},
		{
			name:     "Non-empty string",
			value:    "markdown",
			expected: "markdown",
		},
		{
			name:     "True bool",
			value:    true,
			expected: "true",
		},
		{
			name:     "False bool",
			value:    false,
			expected: "false",
		},
		{
			name:     "Positive int",
			value:    80,
			expected: "80",
		},
		{
			name:     "Negative int",
			value:    -1,
			expected: "-1",
		},
		{
			name:     "Zero int",
			value:    0,
			expected: "0",
		},
		{
			name:     "Empty slice",
			value:    []string{},
			expected: "(empty)",
		},
		{
			name:     "Single element slice",
			value:    []string{"system"},
			expected: "system",
		},
		{
			name:     "Multi element slice",
			value:    []string{"system", "network", "firewall"},
			expected: "system, network, firewall",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatValueForDisplay(tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildConfigValues(t *testing.T) {
	cfg := &config.Config{
		Verbose:    true,
		Format:     "json",
		WrapWidth:  80,
		JSONOutput: true,
	}

	values := buildConfigValues(cfg)

	// Verify we have expected number of values
	assert.NotEmpty(t, values)

	// Check specific values
	var verboseValue, formatValue, wrapValue ConfigValue
	for _, v := range values {
		switch v.Key {
		case "verbose":
			verboseValue = v
		case "format":
			formatValue = v
		case "wrap":
			wrapValue = v
		}
	}

	assert.Equal(t, true, verboseValue.Value)
	assert.Equal(t, sourceConfigured, verboseValue.Source)

	assert.Equal(t, "json", formatValue.Value)
	assert.Equal(t, sourceConfigured, formatValue.Source)

	assert.Equal(t, 80, wrapValue.Value)
	assert.Equal(t, sourceConfigured, wrapValue.Source)
}

func TestConfigShowCmdJSONOutput(t *testing.T) {
	// Create a test command context
	testLogger, err := log.New(log.Config{Level: "info"})
	require.NoError(t, err)

	cfg := &config.Config{
		Format:    "markdown",
		WrapWidth: -1,
	}

	cmd := &cobra.Command{Use: "test"}
	cmd.SetContext(context.Background())
	SetCommandContext(cmd, &CommandContext{
		Config: cfg,
		Logger: testLogger,
	})

	// Capture stdout
	output := captureStdout(t, func() {
		configShowJSONOutput = true
		t.Cleanup(func() { configShowJSONOutput = false })

		err := runConfigShow(cmd, nil)
		require.NoError(t, err)
	})

	// Parse JSON output
	var result ConfigShowOutput
	err = json.Unmarshal([]byte(output), &result)
	require.NoError(t, err, "Output should be valid JSON")

	assert.NotEmpty(t, result.Values, "Should have configuration values")

	// Check a specific value
	var formatValue ConfigValue
	for _, v := range result.Values {
		if v.Key == "format" {
			formatValue = v
			break
		}
	}
	assert.Equal(t, "format", formatValue.Key)
	assert.Equal(t, "markdown", formatValue.Value)
	assert.Equal(t, sourceDefault, formatValue.Source)
}

func TestConfigShowCmdStyledOutput(t *testing.T) {
	// Create a test command context
	testLogger, err := log.New(log.Config{Level: "info"})
	require.NoError(t, err)

	cfg := &config.Config{
		Format:  "json",
		Verbose: true,
	}

	cmd := &cobra.Command{Use: "test"}
	cmd.SetContext(context.Background())
	SetCommandContext(cmd, &CommandContext{
		Config: cfg,
		Logger: testLogger,
	})

	// Capture stdout
	output := captureStdout(t, func() {
		configShowJSONOutput = false

		err := runConfigShow(cmd, nil)
		require.NoError(t, err)
	})

	// Check styled output contains expected content
	assert.Contains(t, output, "opnDossier Effective Configuration")
	assert.Contains(t, output, "format")
	assert.Contains(t, output, "verbose")
}

func TestConfigShowCmdNilContext(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	// Don't set context

	err := runConfigShow(cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "command context not initialized")
}

func TestConfigShowCmdNilConfig(t *testing.T) {
	testLogger, err := log.New(log.Config{Level: "info"})
	require.NoError(t, err)

	cmd := &cobra.Command{Use: "test"}
	cmd.SetContext(context.Background())
	SetCommandContext(cmd, &CommandContext{
		Config: nil,
		Logger: testLogger,
	})

	err = runConfigShow(cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "configuration not loaded")
}

// captureStdout captures stdout output during function execution.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	originalStdout := os.Stdout
	reader, writer, err := os.Pipe()
	require.NoError(t, err)

	os.Stdout = writer

	var (
		output string
		once   sync.Once
	)
	cleanup := func() {
		once.Do(func() {
			os.Stdout = originalStdout
			require.NoError(t, writer.Close())

			captured, readErr := io.ReadAll(reader)
			require.NoError(t, readErr)
			output = string(captured)

			require.NoError(t, reader.Close())
		})
	}
	defer cleanup()

	fn()
	cleanup()

	return output
}
