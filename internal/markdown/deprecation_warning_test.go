package markdown

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"testing"
	"text/template"

	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO(v3.0): Remove this entire file when template mode is removed

func TestShouldShowTemplateDeprecationWarning(t *testing.T) {
	t.Parallel()
	t.Run("suppressed when SuppressWarnings is true", func(t *testing.T) {
		t.Parallel()
		opts := DefaultOptions()
		opts.SuppressWarnings = true
		assert.False(t, shouldShowTemplateDeprecationWarning(opts))
	})

	t.Run("suppressed for non-markdown formats", func(t *testing.T) {
		t.Parallel()
		opts := DefaultOptions()
		opts.Format = FormatJSON
		assert.False(t, shouldShowTemplateDeprecationWarning(opts))
	})

	// Template mode detection tests
	t.Run("shows warning when UseTemplateEngine is true", func(t *testing.T) {
		t.Parallel()
		opts := DefaultOptions()
		opts.UseTemplateEngine = true
		assert.True(t, shouldShowTemplateDeprecationWarning(opts))
	})

	t.Run("shows warning when custom Template is provided", func(t *testing.T) {
		t.Parallel()
		opts := DefaultOptions()
		opts.Template = template.New("custom")
		assert.True(t, shouldShowTemplateDeprecationWarning(opts))
	})

	t.Run("shows warning when TemplateName is specified", func(t *testing.T) {
		t.Parallel()
		opts := DefaultOptions()
		opts.TemplateName = "comprehensive"
		assert.True(t, shouldShowTemplateDeprecationWarning(opts))
	})

	t.Run("shows warning when TemplateDir is specified", func(t *testing.T) {
		t.Parallel()
		opts := DefaultOptions()
		opts.TemplateDir = "/custom/templates"
		assert.True(t, shouldShowTemplateDeprecationWarning(opts))
	})

	t.Run("does not show warning for programmatic mode (default)", func(t *testing.T) {
		t.Parallel()
		opts := DefaultOptions()
		// All template mode signals are false/empty
		assert.False(t, shouldShowTemplateDeprecationWarning(opts))
	})

	t.Run("empty format is treated as markdown for warning purposes", func(t *testing.T) {
		t.Parallel()
		opts := DefaultOptions()
		opts.Format = "" // Empty format
		opts.UseTemplateEngine = true
		assert.True(t, shouldShowTemplateDeprecationWarning(opts))
	})
}

func TestFormatTemplateDeprecationWarningBox(t *testing.T) {
	t.Run("box has correct structure and content", func(t *testing.T) {
		box := formatTemplateDeprecationWarningBox()
		lines := strings.Split(box, "\n")

		// Verify box structure
		assert.True(t, strings.HasPrefix(lines[0], "╔"), "Box should start with top border")
		assert.True(t, strings.HasPrefix(lines[len(lines)-1], "╚"), "Box should end with bottom border")

		// Verify all required content is present
		fullBox := strings.Join(lines, " ")
		assert.Contains(t, fullBox, "DEPRECATION WARNING")
		assert.Contains(t, fullBox, "Template-based generation is deprecated")
		assert.Contains(t, fullBox, "v3.0")
		assert.Contains(t, fullBox, "74% faster report generation")
		assert.Contains(t, fullBox, "78% less memory usage")
		assert.Contains(t, fullBox, "github.com/EvilBit-Labs/opnDossier")
		assert.Contains(t, fullBox, "--quiet flag")

		// Verify all lines have box borders
		for i, line := range lines {
			switch {
			case i == 0:
				assert.True(t, strings.HasPrefix(line, "╔"), "First line should start with ╔")
			case i == len(lines)-1:
				assert.True(t, strings.HasPrefix(line, "╚"), "Last line should start with ╚")
			case line != "":
				assert.True(t, strings.HasPrefix(line, "║"), "Content line %d should start with ║", i)
			}
		}
	})
}

func TestShowTemplateDeprecationWarning(t *testing.T) {
	t.Run("handles nil logger gracefully", func(t *testing.T) {
		// Reset the sync.Once for this test
		templateDeprecationWarningOnce = sync.Once{}
		defer func() { templateDeprecationWarningOnce = sync.Once{} }()

		opts := DefaultOptions()
		opts.UseTemplateEngine = true

		// Capture stderr
		oldStderr := os.Stderr
		r, w, err := os.Pipe()
		require.NoError(t, err, "Failed to create pipe")
		os.Stderr = w

		// Should not panic
		assert.NotPanics(t, func() {
			showTemplateDeprecationWarning(nil, opts)
		})

		// Restore stderr and check output
		require.NoError(t, w.Close(), "Failed to close pipe writer")
		os.Stderr = oldStderr
		var buf bytes.Buffer
		_, err = buf.ReadFrom(r)
		require.NoError(t, err, "Failed to read from pipe")

		// Should either create a fallback logger or write to stderr
		output := buf.String()
		// Either we see the warning box, or we see an error about logger creation
		assert.True(t, strings.Contains(output, "DEPRECATION WARNING") ||
			strings.Contains(output, "Failed to create logger"),
			"Should show warning or logger error")
	})

	t.Run("warning shown only once across multiple calls", func(t *testing.T) {
		// Reset the sync.Once for this test
		templateDeprecationWarningOnce = sync.Once{}
		defer func() { templateDeprecationWarningOnce = sync.Once{} }()

		// Create a buffer to capture log output
		var logOutput bytes.Buffer
		logger, err := log.New(log.Config{
			Level:  "warn",
			Format: "text",
			Output: &logOutput,
		})
		require.NoError(t, err)

		opts := DefaultOptions()
		opts.UseTemplateEngine = true

		// Call multiple times
		showTemplateDeprecationWarning(logger, opts)
		showTemplateDeprecationWarning(logger, opts)
		showTemplateDeprecationWarning(logger, opts)

		// Count occurrences of the warning header
		output := logOutput.String()
		count := strings.Count(output, "DEPRECATION WARNING")
		assert.Equal(t, 1, count, "Warning should be shown exactly once")
	})
}
