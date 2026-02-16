package converter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOptions_WithAuditMode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		mode     string
		expected string
	}{
		{
			name:     "standard mode",
			mode:     "standard",
			expected: "standard",
		},
		{
			name:     "blue mode",
			mode:     "blue",
			expected: "blue",
		},
		{
			name:     "red mode",
			mode:     "red",
			expected: "red",
		},
		{
			name:     "empty mode",
			mode:     "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := DefaultOptions().WithAuditMode(tt.mode)
			assert.Equal(t, tt.expected, opts.AuditMode)
		})
	}
}

func TestOptions_WithBlackhatMode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		enabled  bool
		expected bool
	}{
		{
			name:     "enabled",
			enabled:  true,
			expected: true,
		},
		{
			name:     "disabled",
			enabled:  false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := DefaultOptions().WithBlackhatMode(tt.enabled)
			assert.Equal(t, tt.expected, opts.BlackhatMode)
		})
	}
}

func TestOptions_WithSelectedPlugins(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		plugins  []string
		expected []string
	}{
		{
			name:     "single plugin",
			plugins:  []string{"stig"},
			expected: []string{"stig"},
		},
		{
			name:     "multiple plugins",
			plugins:  []string{"stig", "sans", "firewall"},
			expected: []string{"stig", "sans", "firewall"},
		},
		{
			name:     "empty plugins",
			plugins:  []string{},
			expected: []string{},
		},
		{
			name:     "nil plugins",
			plugins:  nil,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := DefaultOptions().WithSelectedPlugins(tt.plugins...)
			assert.Equal(t, tt.expected, opts.SelectedPlugins)
		})
	}
}

func TestOptions_AuditFieldsChaining(t *testing.T) {
	t.Parallel()
	// Test that audit fields can be chained with other options
	opts := DefaultOptions().
		WithAuditMode("red").
		WithBlackhatMode(true).
		WithSelectedPlugins("stig", "sans").
		WithFormat(FormatJSON)

	require.Equal(t, "red", opts.AuditMode)
	require.True(t, opts.BlackhatMode)
	require.Equal(t, []string{"stig", "sans"}, opts.SelectedPlugins)
	require.Equal(t, FormatJSON, opts.Format)
}

func TestDefaultOptions_AuditFieldsInitialized(t *testing.T) {
	t.Parallel()
	// Verify default values for audit fields
	opts := DefaultOptions()

	assert.Empty(t, opts.AuditMode, "AuditMode should be empty by default")
	assert.False(t, opts.BlackhatMode, "BlackhatMode should be false by default")
	assert.Nil(t, opts.SelectedPlugins, "SelectedPlugins should be nil by default")
}

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
	assert.NotNil(t, opts.CustomFields)
	assert.Equal(t, false, opts.CustomFields["IncludeTunables"])
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

func TestOptions_WithFormat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		format   Format
		expected Format
	}{
		{
			name:     "valid markdown",
			format:   FormatMarkdown,
			expected: FormatMarkdown,
		},
		{
			name:     "valid json",
			format:   FormatJSON,
			expected: FormatJSON,
		},
		{
			name:     "valid yaml",
			format:   FormatYAML,
			expected: FormatYAML,
		},
		{
			name:     "invalid format returns original",
			format:   Format("invalid"),
			expected: FormatMarkdown, // DefaultOptions has markdown
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := DefaultOptions().WithFormat(tt.format)
			assert.Equal(t, tt.expected, opts.Format)
		})
	}
}

func TestOptions_WithSections(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		sections []string
		expected []string
	}{
		{
			name:     "single section",
			sections: []string{"system"},
			expected: []string{"system"},
		},
		{
			name:     "multiple sections",
			sections: []string{"system", "interfaces", "firewall"},
			expected: []string{"system", "interfaces", "firewall"},
		},
		{
			name:     "empty sections",
			sections: []string{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := DefaultOptions().WithSections(tt.sections...)
			assert.Equal(t, tt.expected, opts.Sections)
		})
	}
}

func TestOptions_WithTheme(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		theme    Theme
		expected Theme
	}{
		{
			name:     "auto theme",
			theme:    ThemeAuto,
			expected: ThemeAuto,
		},
		{
			name:     "dark theme",
			theme:    ThemeDark,
			expected: ThemeDark,
		},
		{
			name:     "light theme",
			theme:    ThemeLight,
			expected: ThemeLight,
		},
		{
			name:     "none theme",
			theme:    ThemeNone,
			expected: ThemeNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := DefaultOptions().WithTheme(tt.theme)
			assert.Equal(t, tt.expected, opts.Theme)
		})
	}
}

func TestOptions_WithWrapWidth(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		width    int
		expected int
	}{
		{
			name:     "auto-detect width",
			width:    -1,
			expected: -1,
		},
		{
			name:     "no wrapping",
			width:    0,
			expected: 0,
		},
		{
			name:     "positive width",
			width:    80,
			expected: 80,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := DefaultOptions().WithWrapWidth(tt.width)
			assert.Equal(t, tt.expected, opts.WrapWidth)
		})
	}
}

func TestOptions_WithTables(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		enabled  bool
		expected bool
	}{
		{
			name:     "enable tables",
			enabled:  true,
			expected: true,
		},
		{
			name:     "disable tables",
			enabled:  false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := DefaultOptions().WithTables(tt.enabled)
			assert.Equal(t, tt.expected, opts.EnableTables)
		})
	}
}

func TestOptions_WithColors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		enabled  bool
		expected bool
	}{
		{
			name:     "enable colors",
			enabled:  true,
			expected: true,
		},
		{
			name:     "disable colors",
			enabled:  false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := DefaultOptions().WithColors(tt.enabled)
			assert.Equal(t, tt.expected, opts.EnableColors)
		})
	}
}

func TestOptions_WithEmojis(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		enabled  bool
		expected bool
	}{
		{
			name:     "enable emojis",
			enabled:  true,
			expected: true,
		},
		{
			name:     "disable emojis",
			enabled:  false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := DefaultOptions().WithEmojis(tt.enabled)
			assert.Equal(t, tt.expected, opts.EnableEmojis)
		})
	}
}

func TestOptions_WithCompact(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		compact  bool
		expected bool
	}{
		{
			name:     "enable compact",
			compact:  true,
			expected: true,
		},
		{
			name:     "disable compact",
			compact:  false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := DefaultOptions().WithCompact(tt.compact)
			assert.Equal(t, tt.expected, opts.Compact)
		})
	}
}

func TestOptions_WithMetadata(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		enabled  bool
		expected bool
	}{
		{
			name:     "enable metadata",
			enabled:  true,
			expected: true,
		},
		{
			name:     "disable metadata",
			enabled:  false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := DefaultOptions().WithMetadata(tt.enabled)
			assert.Equal(t, tt.expected, opts.IncludeMetadata)
		})
	}
}

func TestOptions_WithCustomField(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		key      string
		value    any
		expected any
	}{
		{
			name:     "string value",
			key:      "TestKey",
			value:    "TestValue",
			expected: "TestValue",
		},
		{
			name:     "boolean value",
			key:      "BoolKey",
			value:    true,
			expected: true,
		},
		{
			name:     "int value",
			key:      "IntKey",
			value:    42,
			expected: 42,
		},
		{
			name:     "nil value",
			key:      "NilKey",
			value:    nil,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := DefaultOptions().WithCustomField(tt.key, tt.value)
			assert.Equal(t, tt.expected, opts.CustomFields[tt.key])
		})
	}
}

func TestOptions_WithCustomField_NilMap(t *testing.T) {
	t.Parallel()
	// Test that WithCustomField creates a map if it's nil
	opts := Options{} // Empty options with nil CustomFields
	opts = opts.WithCustomField("TestKey", "TestValue")
	assert.NotNil(t, opts.CustomFields)
	assert.Equal(t, "TestValue", opts.CustomFields["TestKey"])
}

func TestOptions_WithComprehensive(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		enabled  bool
		expected bool
	}{
		{
			name:     "enable comprehensive",
			enabled:  true,
			expected: true,
		},
		{
			name:     "disable comprehensive",
			enabled:  false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := DefaultOptions().WithComprehensive(tt.enabled)
			assert.Equal(t, tt.expected, opts.Comprehensive)
		})
	}
}

func TestOptions_WithSuppressWarnings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		suppress bool
		expected bool
	}{
		{
			name:     "suppress warnings",
			suppress: true,
			expected: true,
		},
		{
			name:     "allow warnings",
			suppress: false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := DefaultOptions().WithSuppressWarnings(tt.suppress)
			assert.Equal(t, tt.expected, opts.SuppressWarnings)
		})
	}
}

func TestOptions_MethodChaining(t *testing.T) {
	t.Parallel()
	// Test that all With methods can be chained together
	opts := DefaultOptions().
		WithFormat(FormatJSON).
		WithSections("system", "interfaces").
		WithTheme(ThemeDark).
		WithWrapWidth(100).
		WithTables(false).
		WithColors(false).
		WithEmojis(false).
		WithCompact(true).
		WithMetadata(false).
		WithCustomField("TestKey", "TestValue").
		WithComprehensive(true).
		WithSuppressWarnings(true).
		WithAuditMode("blue").
		WithBlackhatMode(true).
		WithSelectedPlugins("stig", "sans")

	assert.Equal(t, FormatJSON, opts.Format)
	assert.Equal(t, []string{"system", "interfaces"}, opts.Sections)
	assert.Equal(t, ThemeDark, opts.Theme)
	assert.Equal(t, 100, opts.WrapWidth)
	assert.False(t, opts.EnableTables)
	assert.False(t, opts.EnableColors)
	assert.False(t, opts.EnableEmojis)
	assert.True(t, opts.Compact)
	assert.False(t, opts.IncludeMetadata)
	assert.Equal(t, "TestValue", opts.CustomFields["TestKey"])
	assert.True(t, opts.Comprehensive)
	assert.True(t, opts.SuppressWarnings)
	assert.Equal(t, "blue", opts.AuditMode)
	assert.True(t, opts.BlackhatMode)
	assert.Equal(t, []string{"stig", "sans"}, opts.SelectedPlugins)
}
