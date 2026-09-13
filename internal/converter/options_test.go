package converter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormat_String(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		format Format
		want   string
	}{
		{
			name:   "markdown format",
			format: FormatMarkdown,
			want:   "markdown",
		},
		{
			name:   "json format",
			format: FormatJSON,
			want:   "json",
		},
		{
			name:   "yaml format",
			format: FormatYAML,
			want:   "yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.format.String())
		})
	}
}

func TestFormat_Validate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		format  Format
		wantErr bool
	}{
		{
			name:    "valid markdown",
			format:  FormatMarkdown,
			wantErr: false,
		},
		{
			name:    "valid json",
			format:  FormatJSON,
			wantErr: false,
		},
		{
			name:    "valid yaml",
			format:  FormatYAML,
			wantErr: false,
		},
		{
			name:    "invalid format",
			format:  Format("invalid"),
			wantErr: true,
		},
		{
			name:    "empty format",
			format:  Format(""),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.format.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrUnsupportedFormat)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestTheme_String(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		theme Theme
		want  string
	}{
		{
			name:  "auto theme",
			theme: ThemeAuto,
			want:  "auto",
		},
		{
			name:  "dark theme",
			theme: ThemeDark,
			want:  "dark",
		},
		{
			name:  "light theme",
			theme: ThemeLight,
			want:  "light",
		},
		{
			name:  "none theme",
			theme: ThemeNone,
			want:  "none",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.theme.String())
		})
	}
}

func TestDefaultOptions(t *testing.T) {
	t.Parallel()
	opts := DefaultOptions()

	assert.Equal(t, FormatMarkdown, opts.Format)
	assert.False(t, opts.Comprehensive)
	assert.Nil(t, opts.Sections)
	assert.Equal(t, ThemeAuto, opts.Theme)
	assert.Equal(t, 0, opts.WrapWidth)
	assert.True(t, opts.EnableTables)
	assert.True(t, opts.EnableColors)
	assert.True(t, opts.EnableEmojis)
	assert.False(t, opts.Compact)
	assert.True(t, opts.IncludeMetadata)
	assert.False(t, opts.SuppressWarnings)
	assert.False(t, opts.Redact)
	assert.False(t, opts.IncludeTunables)
}

func TestOptions_Validate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		options Options
		wantErr bool
	}{
		{
			name:    "valid options",
			options: DefaultOptions(),
			wantErr: false,
		},
		{
			name: "invalid format",
			options: Options{
				Format:    Format("invalid"),
				WrapWidth: 0,
			},
			wantErr: true,
		},
		{
			name: "invalid wrap width negative",
			options: Options{
				Format:    FormatMarkdown,
				WrapWidth: -2,
			},
			wantErr: true,
		},
		{
			name: "valid wrap width -1 (auto-detect)",
			options: Options{
				Format:    FormatMarkdown,
				WrapWidth: -1,
			},
			wantErr: false,
		},
		{
			name: "valid wrap width 0 (no wrapping)",
			options: Options{
				Format:    FormatMarkdown,
				WrapWidth: 0,
			},
			wantErr: false,
		},
		{
			name: "valid wrap width positive",
			options: Options{
				Format:    FormatMarkdown,
				WrapWidth: 80,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.options.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestOptions_FieldAssignment verifies that every Options field can be set
// directly via struct literal / field assignment, replacing the removed
// With* builder methods (which had no production callers — every real
// caller already builds Options as a struct literal).
func TestOptions_FieldAssignment(t *testing.T) {
	t.Parallel()

	opts := Options{
		Format:           FormatJSON,
		Sections:         []string{"system", "interfaces"},
		Theme:            ThemeDark,
		WrapWidth:        100,
		EnableTables:     false,
		EnableColors:     false,
		EnableEmojis:     false,
		Compact:          true,
		IncludeMetadata:  false,
		Comprehensive:    true,
		SuppressWarnings: true,
		Redact:           true,
		IncludeTunables:  true,
		FailuresOnly:     true,
	}

	assert.Equal(t, FormatJSON, opts.Format)
	assert.Equal(t, []string{"system", "interfaces"}, opts.Sections)
	assert.Equal(t, ThemeDark, opts.Theme)
	assert.Equal(t, 100, opts.WrapWidth)
	assert.False(t, opts.EnableTables)
	assert.False(t, opts.EnableColors)
	assert.False(t, opts.EnableEmojis)
	assert.True(t, opts.Compact)
	assert.False(t, opts.IncludeMetadata)
	assert.True(t, opts.Comprehensive)
	assert.True(t, opts.SuppressWarnings)
	assert.True(t, opts.Redact)
	assert.True(t, opts.IncludeTunables)
	assert.True(t, opts.FailuresOnly)
}
