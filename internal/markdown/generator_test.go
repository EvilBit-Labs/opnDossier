package markdown

import (
	"context"
	"testing"

	"github.com/unclesp1d3r/opnFocus/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMarkdownGenerator(t *testing.T) {
	generator, err := NewMarkdownGenerator()
	require.NoError(t, err)
	assert.NotNil(t, generator)
	assert.Implements(t, (*Generator)(nil), generator)
}

func TestMarkdownGenerator_Generate(t *testing.T) {
	generator, err := NewMarkdownGenerator()
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
