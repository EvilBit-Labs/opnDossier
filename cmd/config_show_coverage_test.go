package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOutputConfigPlain verifies that outputConfigPlain writes plain-text
// configuration output without lipgloss styling, grouped by section.
func TestOutputConfigPlain(t *testing.T) {
	values := []ConfigValue{
		{Key: "format", Value: "markdown", Source: sourceDefault},
		{Key: "verbose", Value: false, Source: sourceDefault},
		{Key: "display.theme", Value: "default", Source: sourceConfigured},
		{Key: "display.wrap", Value: 80, Source: sourceConfigured},
		{Key: "export.output_file", Value: "report.md", Source: sourceConfigured},
	}

	output := captureStdout(t, func() {
		err := outputConfigPlain(values)
		require.NoError(t, err)
	})

	// Verify header
	assert.Contains(t, output, "opnDossier Effective Configuration")

	// Verify section headers appear
	assert.Contains(t, output, "[display]")
	assert.Contains(t, output, "[export]")

	// Verify values appear with source annotations
	assert.Contains(t, output, "format:")
	assert.Contains(t, output, "markdown")
	assert.Contains(t, output, sourceDefault)
	assert.Contains(t, output, "display.theme:")
	assert.Contains(t, output, sourceConfigured)
}

// TestOutputConfigPlainEmptyValues verifies that outputConfigPlain handles
// an empty values slice without errors.
func TestOutputConfigPlainEmptyValues(t *testing.T) {
	output := captureStdout(t, func() {
		err := outputConfigPlain([]ConfigValue{})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "opnDossier Effective Configuration")
}
