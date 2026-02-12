package formatters

import (
	"bytes"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/diff"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSideBySideFormatter(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewSideBySideFormatter(&buf)
	assert.NotNil(t, formatter)
	assert.Positive(t, formatter.width)
}

func TestSideBySideFormatter_Format_NoChanges(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewSideBySideFormatter(&buf)
	formatter.useStyles = false
	formatter.width = defaultTerminalWidth

	result := diff.NewResult()
	err := formatter.Format(result)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "No changes detected")
}

func TestSideBySideFormatter_Format_WithChanges(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewSideBySideFormatter(&buf)
	formatter.useStyles = false
	formatter.width = defaultTerminalWidth

	result := diff.NewResult()
	result.AddChange(diff.Change{
		Type:        diff.ChangeModified,
		Section:     diff.SectionSystem,
		Path:        "system.hostname",
		Description: "Hostname changed",
		OldValue:    "old-host",
		NewValue:    "new-host",
	})

	err := formatter.Format(result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "OLD")
	assert.Contains(t, output, "NEW")
	assert.Contains(t, output, "Hostname changed")
	assert.Contains(t, output, "old-host")
	assert.Contains(t, output, "new-host")
}

func TestSideBySideFormatter_Format_NarrowTerminalFallback(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewSideBySideFormatter(&buf)
	formatter.useStyles = false
	formatter.width = 40 // Too narrow for side-by-side

	result := diff.NewResult()
	result.AddChange(diff.Change{
		Type:        diff.ChangeAdded,
		Section:     diff.SectionFirewall,
		Path:        "test",
		Description: "Test change",
	})

	err := formatter.Format(result)
	require.NoError(t, err)

	// Should fall back to unified format (no column separator)
	output := buf.String()
	assert.Contains(t, output, "Test change")
}

func TestSideBySideFormatter_Format_SecurityBadges(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewSideBySideFormatter(&buf)
	formatter.useStyles = false
	formatter.width = defaultTerminalWidth

	result := diff.NewResult()
	result.AddChange(diff.Change{
		Type:           diff.ChangeAdded,
		Section:        diff.SectionFirewall,
		Path:           "test",
		Description:    "Permissive rule",
		SecurityImpact: "high",
	})

	err := formatter.Format(result)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "[HIGH]")
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{"no truncation needed", "hello", 10, "hello"},
		{"exact length", "hello", 5, "hello"},
		{"truncated with ellipsis", "hello world", 8, "hello..."},
		{"very short max", "hello", 2, "he"},
		{"empty string", "", 10, ""},
		{"zero max", "hello", 0, "hello"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, truncate(tt.input, tt.maxLen))
		})
	}
}

func TestSideBySideFormatter_InterfaceCompliance(_ *testing.T) {
	var buf bytes.Buffer
	var _ Formatter = NewSideBySideFormatter(&buf)
}
