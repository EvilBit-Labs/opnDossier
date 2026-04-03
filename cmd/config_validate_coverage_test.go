package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestShowLineContextPlain verifies that showLineContextPlain outputs
// context lines around an error line without any styling.
func TestShowLineContextPlain(t *testing.T) {
	content := []byte("line 1\nline 2\nline 3\nline 4 with error\nline 5\nline 6\nline 7")

	output := captureStderr(t, func() {
		showLineContextPlain(content, 4)
	})

	// Verify context lines are shown (2 lines before and after)
	assert.Contains(t, output, "line 2")
	assert.Contains(t, output, "line 3")
	assert.Contains(t, output, "line 4 with error")
	assert.Contains(t, output, "line 5")
	assert.Contains(t, output, "line 6")

	// Verify error marker is present on the error line
	assert.Contains(t, output, ">>>")
}

// TestShowLineContextPlainAtStart verifies context display when the
// error line is near the beginning of the file.
func TestShowLineContextPlainAtStart(t *testing.T) {
	content := []byte("error line\nline 2\nline 3")

	output := captureStderr(t, func() {
		showLineContextPlain(content, 1)
	})

	assert.Contains(t, output, ">>>")
	assert.Contains(t, output, "error line")
	assert.Contains(t, output, "line 2")
	assert.Contains(t, output, "line 3")
}

// TestReportUnknownKeys verifies that reportUnknownKeys writes unknown
// key warnings to stderr with appropriate content.
func TestReportUnknownKeys(t *testing.T) {
	t.Run("plain output without styles", func(t *testing.T) {
		t.Setenv("TERM", "dumb")
		t.Setenv("NO_COLOR", "1")

		keys := []string{"unknown_key1", "display.bad_key"}

		output := captureStderr(t, func() {
			reportUnknownKeys("/path/to/config.yaml", keys)
		})

		assert.Contains(t, output, "Unknown configuration keys")
		assert.Contains(t, output, "/path/to/config.yaml")
		assert.Contains(t, output, "unknown_key1")
		assert.Contains(t, output, "display.bad_key")
	})
}
