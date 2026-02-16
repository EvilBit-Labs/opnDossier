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

func TestConfigValidateCmd(t *testing.T) {
	testLogger, err := logging.New(logging.Config{Level: "info"})
	require.NoError(t, err)

	t.Run("Validates valid config file", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, ".opnDossier.yaml")

		// Create a valid config file
		validConfig := `verbose: false
format: markdown
wrap: -1
`
		//nolint:gosec // Test file permissions are fine for testing
		err := os.WriteFile(configPath, []byte(validConfig), 0o644)
		require.NoError(t, err)

		cmd := &cobra.Command{Use: "test"}
		cmd.SetContext(context.Background())
		SetCommandContext(cmd, &CommandContext{
			Config: &config.Config{},
			Logger: testLogger,
		})

		output := captureStdout(t, func() {
			err := runConfigValidate(cmd, []string{configPath})
			require.NoError(t, err)
		})

		assert.Contains(t, output, "Valid")
		assert.Contains(t, output, configPath)
	})

	t.Run("Reports file not found", func(t *testing.T) {
		nonExistentPath := filepath.Join(t.TempDir(), "does-not-exist.yaml")

		cmd := &cobra.Command{Use: "test"}
		cmd.SetContext(context.Background())
		SetCommandContext(cmd, &CommandContext{
			Config: &config.Config{},
			Logger: testLogger,
		})

		err := runConfigValidate(cmd, []string{nonExistentPath})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("Fails with nil context", func(t *testing.T) {
		cmd := &cobra.Command{Use: "test"}
		// Don't set context

		err := runConfigValidate(cmd, []string{"/some/path"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "command context not initialized")
	})
}

func TestExtractYAMLLineNumber(t *testing.T) {
	tests := []struct {
		name     string
		errStr   string
		expected int
	}{
		{
			name:     "Standard yaml.v3 error format",
			errStr:   "yaml: line 5: could not find expected ':'",
			expected: 5,
		},
		{
			name:     "Error with line number in middle",
			errStr:   "yaml: line 123: mapping values are not allowed",
			expected: 123,
		},
		{
			name:     "No line number",
			errStr:   "yaml: unmarshal error",
			expected: 0,
		},
		{
			name:     "Line 1",
			errStr:   "yaml: line 1: did not find expected node content",
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &testError{msg: tt.errStr}
			result := extractYAMLLineNumber(err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// testError is a simple error type for testing.
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func TestFindUnknownKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]any
		expected []string
	}{
		{
			name: "All known keys",
			input: map[string]any{
				"verbose": true,
				"format":  "markdown",
			},
			expected: nil,
		},
		{
			name: "One unknown key",
			input: map[string]any{
				"verbose":     true,
				"unknown_key": "value",
			},
			expected: []string{"unknown_key"},
		},
		{
			name: "Multiple unknown keys",
			input: map[string]any{
				"foo": "bar",
				"baz": 123,
			},
			expected: []string{"foo", "baz"},
		},
		{
			name: "Known nested section with unknown nested key",
			input: map[string]any{
				"display": map[string]any{
					"width":       100,
					"unknown_key": "value",
				},
			},
			expected: []string{"display.unknown_key"},
		},
		{
			name: "All valid nested keys",
			input: map[string]any{
				"display": map[string]any{
					"width": 100,
					"pager": true,
				},
				"logging": map[string]any{
					"level":  "debug",
					"format": "text",
				},
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findUnknownKeys(tt.input)
			if tt.expected == nil {
				assert.Empty(t, result)
			} else {
				// Check that all expected keys are present (order may vary)
				for _, key := range tt.expected {
					assert.Contains(t, result, key)
				}
				assert.Len(t, result, len(tt.expected))
			}
		})
	}
}

func TestShowLineContext(t *testing.T) {
	content := []byte(`line 1
line 2
line 3
line 4 with error
line 5
line 6
line 7`)

	// Capture stderr output
	output := captureStderr(t, func() {
		showLineContext(content, 4)
	})

	// Verify context lines are shown
	assert.Contains(t, output, "line 2")
	assert.Contains(t, output, "line 3")
	assert.Contains(t, output, "line 4 with error")
	assert.Contains(t, output, "line 5")
	assert.Contains(t, output, "line 6")

	// Verify error marker is present
	assert.Contains(t, output, ">>>")
}

func TestExitConfigValidationErrorConstant(t *testing.T) {
	// Ensure the exit code constant is defined correctly
	assert.Equal(t, 5, ExitConfigValidationError)
}
