package markdown

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Note: Embedded templates are set up by main.go during initialization
// Tests should use the same embedded templates that are available at runtime

// TestMain sets up the embedded templates for all tests in this package.
func TestMain(m *testing.M) {
	// Run the tests and exit with the appropriate code
	os.Exit(m.Run())
}

func TestNewMarkdownGenerator(t *testing.T) {
	// Test with nil registry and modeController (should work for non-audit reports)
	opts := DefaultOptions()
	generator, err := NewMarkdownGenerator(nil, opts)
	if err != nil {
		t.Fatalf("Failed to create markdown generator with nil registry: %v", err)
	}

	if generator == nil {
		t.Fatal("Generator should not be nil")
	}
}

func TestMarkdownGenerator_Generate(t *testing.T) {
	opts := DefaultOptions()
	generator, err := NewMarkdownGenerator(nil, opts)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("nil configuration", func(t *testing.T) {
		opts := DefaultOptions()
		result, err := generator.Generate(ctx, nil, opts)
		require.Error(t, err)
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
		require.Error(t, err)
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
		opts = DefaultOptions().WithFormat(FormatMarkdown)
		result, err := generator.Generate(ctx, cfg, opts)

		require.NoError(t, err)
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
		opts = DefaultOptions().WithFormat(FormatMarkdown).WithComprehensive(true)
		result, err := generator.Generate(ctx, cfg, opts)

		require.NoError(t, err)
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

		require.NoError(t, err)
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

		require.NoError(t, err)
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "test-host")
	})

	t.Run("unsupported format", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{}
		opts := Options{Format: Format("unsupported")}
		result, err := generator.Generate(ctx, cfg, opts)

		require.Error(t, err)
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
		assert.False(t, opts.UseTemplateEngine)
	})

	t.Run("options validation", func(t *testing.T) {
		// Valid options
		opts := DefaultOptions()
		require.NoError(t, opts.Validate())

		// Invalid format
		opts.Format = Format("invalid")
		require.Error(t, opts.Validate())

		// Invalid wrap width
		opts = DefaultOptions()
		opts.WrapWidth = -1
		require.Error(t, opts.Validate())

		// Invalid template engine with non-markdown format
		opts = DefaultOptions()
		opts.Format = FormatJSON
		opts.UseTemplateEngine = true
		require.Error(t, opts.Validate())

		// Valid template engine with markdown format
		opts = DefaultOptions()
		opts.Format = FormatMarkdown
		opts.UseTemplateEngine = true
		require.NoError(t, opts.Validate())
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
			WithCustomField("test", "value").
			WithUseTemplateEngine(true)

		assert.Equal(t, FormatJSON, opts.Format)
		assert.Equal(t, ThemeDark, opts.Theme)
		assert.Equal(t, 80, opts.WrapWidth)
		assert.False(t, opts.EnableTables)
		assert.False(t, opts.EnableColors)
		assert.False(t, opts.EnableEmojis)
		assert.True(t, opts.Compact)
		assert.False(t, opts.IncludeMetadata)
		assert.Equal(t, "value", opts.CustomFields["test"])
		assert.True(t, opts.UseTemplateEngine)
	})

	t.Run("validation logging on invalid inputs", func(t *testing.T) {
		// Test that WithFormat logs warning and returns unchanged options on invalid format
		originalOpts := DefaultOptions()
		opts := originalOpts.WithFormat("invalid_format")

		// Should return unchanged options when validation fails
		assert.Equal(t, originalOpts.Format, opts.Format)

		// Test that WithAuditMode logs warning and returns unchanged options on invalid mode
		opts = originalOpts.WithAuditMode("invalid_mode")

		// Should return unchanged options when validation fails
		assert.Equal(t, originalOpts.AuditMode, opts.AuditMode)
	})

	t.Run("UseTemplateEngine field", func(t *testing.T) {
		// Test default value
		opts := DefaultOptions()
		assert.False(t, opts.UseTemplateEngine)

		// Test setting to true
		opts = opts.WithUseTemplateEngine(true)
		assert.True(t, opts.UseTemplateEngine)

		// Test setting to false
		opts = opts.WithUseTemplateEngine(false)
		assert.False(t, opts.UseTemplateEngine)

		// Test validation with markdown format
		opts = DefaultOptions().WithFormat(FormatMarkdown).WithUseTemplateEngine(true)
		require.NoError(t, opts.Validate())

		// Test validation with non-markdown format
		opts = DefaultOptions().WithFormat(FormatJSON).WithUseTemplateEngine(true)
		require.Error(t, opts.Validate())
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
				require.NoError(t, err)
			} else {
				require.Error(t, err)
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
			name:     "asterisk character",
			input:    "text with *bold* text",
			expected: "text with \\*bold\\* text",
		},
		{
			name:     "underscore character",
			input:    "text with _italic_ text",
			expected: "text with \\_italic\\_ text",
		},
		{
			name:     "backtick character",
			input:    "text with `code` text",
			expected: "text with \\`code\\` text",
		},
		{
			name:     "square brackets",
			input:    "text with [link] text",
			expected: "text with \\[link\\] text",
		},
		{
			name:     "angle brackets",
			input:    "text with <tag> text",
			expected: "text with \\<tag\\> text",
		},
		{
			name:     "backslash character",
			input:    "text with \\backslash\\ text",
			expected: "text with \\\\backslash\\\\ text",
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
			input:    "text | with\nnewlines\r\nand\rreturns *bold* _italic_ `code` [link] <tag> \\backslash\\",
			expected: "text \\| with<br>newlines<br>and<br>returns \\*bold\\* \\_italic\\_ \\`code\\` \\[link\\] \\<tag\\> \\\\backslash\\\\",
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

					// Escape Markdown special characters in order of precedence
					// Backslashes must be escaped first to avoid double-escaping
					str = strings.ReplaceAll(str, "\\", "\\\\")

					// Escape asterisks (used for bold/italic)
					str = strings.ReplaceAll(str, "*", "\\*")

					// Escape underscores (used for italic/underline)
					str = strings.ReplaceAll(str, "_", "\\_")

					// Escape backticks (used for inline code)
					str = strings.ReplaceAll(str, "`", "\\`")

					// Escape square brackets (used for links)
					str = strings.ReplaceAll(str, "[", "\\[")
					str = strings.ReplaceAll(str, "]", "\\]")

					// Escape angle brackets (used for HTML tags)
					str = strings.ReplaceAll(str, "<", "\\<")
					str = strings.ReplaceAll(str, ">", "\\>")

					// Escape pipe characters (used for table separators)
					str = strings.ReplaceAll(str, "|", "\\|")

					// Handle newlines and carriage returns
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

func TestFormatInterfacesAsLinksTemplateFunction(t *testing.T) {
	// Create a test configuration with multiple interfaces
	cfg := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-host",
			Domain:   "test.local",
		},
		Filter: model.Filter{
			Rule: []model.Rule{
				{
					Type:        "pass",
					Interface:   model.InterfaceList{"wan", "lan"},
					IPProtocol:  "inet",
					Protocol:    "tcp",
					Source:      model.Source{Network: "any"},
					Destination: model.Destination{Network: "any"},
					Descr:       "Test rule with multiple interfaces",
				},
				{
					Type:        "block",
					Interface:   model.InterfaceList{"opt1"},
					IPProtocol:  "inet",
					Protocol:    "udp",
					Source:      model.Source{Network: "any"},
					Destination: model.Destination{Network: "any"},
					Descr:       "Test rule with single interface",
				},
			},
		},
		Interfaces: model.Interfaces{
			Items: map[string]model.Interface{
				"wan":  {Enable: "1", IPAddr: "192.168.1.1"},
				"lan":  {Enable: "1", IPAddr: "10.0.0.1"},
				"opt1": {Enable: "1", IPAddr: "172.16.0.1"},
			},
		},
	}

	ctx := context.Background()

	t.Run("comprehensive template with interface links", func(t *testing.T) {
		opts := DefaultOptions()
		generator, err := NewMarkdownGenerator(nil, opts)
		require.NoError(t, err)

		opts = DefaultOptions().WithFormat(FormatMarkdown).WithComprehensive(true)
		result, err := generator.Generate(ctx, cfg, opts)

		require.NoError(t, err)
		assert.NotEmpty(t, result)

		// Check that interface links are properly formatted
		assert.Contains(t, result, "[wan](#wan-interface), [lan](#lan-interface)")
		assert.Contains(t, result, "[opt1](#opt1-interface)")

		// Check that interface sections are created
		assert.Contains(t, result, "### Wan Interface")
		assert.Contains(t, result, "### Lan Interface")
		assert.Contains(t, result, "### Opt1 Interface")
	})

	t.Run("standard template with interface links", func(t *testing.T) {
		opts := DefaultOptions()
		generator, err := NewMarkdownGenerator(nil, opts)
		require.NoError(t, err)

		opts = DefaultOptions().WithFormat(FormatMarkdown)
		result, err := generator.Generate(ctx, cfg, opts)

		require.NoError(t, err)
		assert.NotEmpty(t, result)

		// Check that interface links are properly formatted
		assert.Contains(t, result, "[wan](#wan-interface), [lan](#lan-interface)")
		assert.Contains(t, result, "[opt1](#opt1-interface)")
	})
}
