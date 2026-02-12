package formatters

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_SupportedFormats(t *testing.T) {
	tests := []struct {
		name   string
		format string
	}{
		{"terminal", FormatTerminal},
		{"markdown", FormatMarkdown},
		{"json", FormatJSON},
		{"html", FormatHTML},
		{"empty defaults to terminal", ""},
		{"case insensitive", "TERMINAL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			f, err := New(tt.format, &buf)
			require.NoError(t, err)
			assert.NotNil(t, f)
		})
	}
}

func TestNewWithMode_SideBySide(t *testing.T) {
	var buf bytes.Buffer
	f, err := NewWithMode(FormatTerminal, ModeSideBySide, &buf)
	require.NoError(t, err)
	assert.NotNil(t, f)
	// Should be a SideBySideFormatter
	_, ok := f.(*SideBySideFormatter)
	assert.True(t, ok, "expected SideBySideFormatter for terminal side-by-side")
}

func TestNewWithMode_UnifiedDefault(t *testing.T) {
	var buf bytes.Buffer
	f, err := NewWithMode(FormatTerminal, ModeUnified, &buf)
	require.NoError(t, err)
	assert.NotNil(t, f)
	_, ok := f.(*TerminalFormatter)
	assert.True(t, ok, "expected TerminalFormatter for terminal unified")
}

func TestNew_UnsupportedFormat(t *testing.T) {
	var buf bytes.Buffer
	f, err := New("xml", &buf)
	assert.Nil(t, f)
	require.ErrorContains(t, err, "unsupported format")
}

func TestInterfaceCompliance(_ *testing.T) {
	var buf bytes.Buffer

	// Verify all formatters implement the Formatter interface at compile time.
	var _ Formatter = NewTerminalFormatter(&buf)
	var _ Formatter = NewMarkdownFormatter(&buf)
	var _ Formatter = NewJSONFormatter(&buf)
	var _ Formatter = NewHTMLFormatter(&buf)
	var _ Formatter = NewSideBySideFormatter(&buf)
}
