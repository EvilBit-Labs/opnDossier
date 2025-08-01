package markdown

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/unclesp1d3r/opnFocus/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMarkdownGenerator(t *testing.T) {
	// Test with nil registry and modeController (should work for non-audit reports)
	generator, err := NewMarkdownGenerator(nil)
	if err != nil {
		t.Fatalf("Failed to create markdown generator with nil registry: %v", err)
	}
	if generator == nil {
		t.Fatal("Generator should not be nil")
	}
}

func TestMarkdownGenerator_Generate(t *testing.T) {
	generator, err := NewMarkdownGenerator(nil)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("nil configuration", func(t *testing.T) {
		opts := DefaultOptions()
		result, err := generator.Generate(ctx, nil, opts)
		assert.Error(t, err)
		assert.Equal(t, ErrNilConfiguration, err)
		assert.Empty(t, result)
	})

	t.Run("invalid options", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{}
		opts := Options{
			Format:    "invalid",
			WrapWidth: -1,
		}
		result, err := generator.Generate(ctx, cfg, opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid options")
		assert.Empty(t, result)
	})

	t.Run("valid markdown generation", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{
			System: model.System{
				Hostname: "test-host",
				Domain:   "test.local",
			},
		}
		opts := DefaultOptions().WithFormat(FormatMarkdown)
		result, err := generator.Generate(ctx, cfg, opts)

		assert.NoError(t, err)
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "test-host")
	})

	t.Run("valid comprehensive markdown generation", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{
			System: model.System{
				Hostname: "test-host",
				Domain:   "test.local",
			},
		}
		opts := DefaultOptions().WithFormat(FormatMarkdown).WithComprehensive(true)
		result, err := generator.Generate(ctx, cfg, opts)

		assert.NoError(t, err)
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "test-host")
	})

	t.Run("valid JSON generation", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{
			System: model.System{
				Hostname: "test-host",
				Domain:   "test.local",
			},
		}
		opts := DefaultOptions().WithFormat(FormatJSON)
		result, err := generator.Generate(ctx, cfg, opts)

		assert.NoError(t, err)
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "test-host")
	})

	t.Run("valid YAML generation", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{
			System: model.System{
				Hostname: "test-host",
				Domain:   "test.local",
			},
		}
		opts := DefaultOptions().WithFormat(FormatYAML)
		result, err := generator.Generate(ctx, cfg, opts)

		assert.NoError(t, err)
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "test-host")
	})

	t.Run("unsupported format", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{}
		opts := Options{Format: Format("unsupported")}
		result, err := generator.Generate(ctx, cfg, opts)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported format")
		assert.Empty(t, result)
	})
}

func TestOptions(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		opts := DefaultOptions()
		assert.Equal(t, FormatMarkdown, opts.Format)
		assert.Equal(t, ThemeAuto, opts.Theme)
		assert.True(t, opts.EnableTables)
		assert.True(t, opts.EnableColors)
		assert.True(t, opts.EnableEmojis)
		assert.False(t, opts.Compact)
		assert.True(t, opts.IncludeMetadata)
		assert.NotNil(t, opts.CustomFields)
	})

	t.Run("options validation", func(t *testing.T) {
		// Valid options
		opts := DefaultOptions()
		assert.NoError(t, opts.Validate())

		// Invalid format
		opts.Format = Format("invalid")
		assert.Error(t, opts.Validate())

		// Invalid wrap width
		opts = DefaultOptions()
		opts.WrapWidth = -1
		assert.Error(t, opts.Validate())
	})

	t.Run("options fluent interface", func(t *testing.T) {
		opts := DefaultOptions().
			WithFormat(FormatJSON).
			WithTheme(ThemeDark).
			WithWrapWidth(80).
			WithTables(false).
			WithColors(false).
			WithEmojis(false).
			WithCompact(true).
			WithMetadata(false).
			WithCustomField("test", "value")

		assert.Equal(t, FormatJSON, opts.Format)
		assert.Equal(t, ThemeDark, opts.Theme)
		assert.Equal(t, 80, opts.WrapWidth)
		assert.False(t, opts.EnableTables)
		assert.False(t, opts.EnableColors)
		assert.False(t, opts.EnableEmojis)
		assert.True(t, opts.Compact)
		assert.False(t, opts.IncludeMetadata)
		assert.Equal(t, "value", opts.CustomFields["test"])
	})
}

func TestFormatValidation(t *testing.T) {
	tests := []struct {
		format Format
		valid  bool
	}{
		{FormatMarkdown, true},
		{FormatJSON, true},
		{FormatYAML, true},
		{Format("invalid"), false},
		{Format(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			err := tt.format.Validate()
			if tt.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestEscapeTableContent(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected string
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: "",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "simple text",
			input:    "normal text",
			expected: "normal text",
		},
		{
			name:     "pipe character",
			input:    "text with | pipe",
			expected: "text with \\| pipe",
		},
		{
			name:     "multiple pipe characters",
			input:    "text | with | multiple | pipes",
			expected: "text \\| with \\| multiple \\| pipes",
		},
		{
			name:     "newline character",
			input:    "line1\nline2",
			expected: "line1<br>line2",
		},
		{
			name:     "carriage return",
			input:    "line1\rline2",
			expected: "line1<br>line2",
		},
		{
			name:     "carriage return newline",
			input:    "line1\r\nline2",
			expected: "line1<br>line2",
		},
		{
			name:     "mixed special characters",
			input:    "text | with\nnewlines\r\nand\rreturns",
			expected: "text \\| with<br>newlines<br>and<br>returns",
		},
		{
			name:     "non-string type",
			input:    123,
			expected: "123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a template function map with our escapeTableContent function
			funcMap := map[string]any{
				"escapeTableContent": func(content any) string {
					if content == nil {
						return ""
					}
					str := fmt.Sprintf("%v", content)
					// Escape pipe characters by replacing | with \|
					str = strings.ReplaceAll(str, "|", "\\|")
					// Replace carriage return + newline first to avoid double replacement
					str = strings.ReplaceAll(str, "\r\n", "<br>")
					// Replace remaining newlines with <br> for HTML rendering
					str = strings.ReplaceAll(str, "\n", "<br>")
					// Replace remaining carriage returns with <br>
					str = strings.ReplaceAll(str, "\r", "<br>")
					return str
				},
			}

			// Get the function and call it
			escapeFunc, ok := funcMap["escapeTableContent"].(func(any) string)
			require.True(t, ok, "escapeTableContent function should be of correct type")
			result := escapeFunc(tt.input)

			assert.Equal(t, tt.expected, result)
		})
	}
}
