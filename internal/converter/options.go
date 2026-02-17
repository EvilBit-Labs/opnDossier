package converter

import (
	"errors"
	"fmt"
)

// Format represents the output format type.
type Format string

const (
	// FormatMarkdown represents markdown output format.
	FormatMarkdown Format = "markdown"
	// FormatJSON represents JSON output format.
	FormatJSON Format = "json"
	// FormatYAML represents YAML output format.
	FormatYAML Format = "yaml"
	// FormatText represents plain text output format (markdown with formatting stripped).
	FormatText Format = "text"
	// FormatHTML represents self-contained HTML output format.
	FormatHTML Format = "html"
)

// String returns the string representation of the format.
func (f Format) String() string {
	return string(f)
}

// Validate checks if the format is supported.
func (f Format) Validate() error {
	switch f {
	case FormatMarkdown, FormatJSON, FormatYAML, FormatText, FormatHTML:
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedFormat, f)
	}
}

// Theme represents the rendering theme for terminal output.
type Theme string

const (
	// ThemeAuto automatically detects the appropriate theme.
	ThemeAuto Theme = "auto"
	// ThemeDark uses a dark terminal theme.
	ThemeDark Theme = "dark"
	// ThemeLight uses a light terminal theme.
	ThemeLight Theme = "light"
	// ThemeNone disables styling for plain text output.
	ThemeNone Theme = "none"
)

// String returns the string representation of the theme.
func (t Theme) String() string {
	return string(t)
}

// Options contains configuration options for report generation.
type Options struct {
	// Format specifies the output format (markdown, json, yaml, text, html).
	Format Format

	// Comprehensive specifies whether to generate a comprehensive report.
	Comprehensive bool

	// Sections specifies which configuration sections to include.
	Sections []string

	// Theme specifies the terminal rendering theme for markdown output.
	Theme Theme

	// WrapWidth specifies the column width for text wrapping.
	WrapWidth int

	// EnableTables controls whether to render data as tables.
	EnableTables bool

	// EnableColors controls whether to use colored output.
	EnableColors bool

	// EnableEmojis controls whether to include emoji icons in output.
	EnableEmojis bool

	// Compact controls whether to use a more compact output format.
	Compact bool

	// IncludeMetadata controls whether to include generation metadata.
	IncludeMetadata bool

	// CustomFields allows for additional custom fields to be passed to generation.
	CustomFields map[string]any

	// SuppressWarnings suppresses non-critical warnings.
	SuppressWarnings bool

	// AuditMode specifies the audit reporting mode (standard, blue, red).
	AuditMode string

	// BlackhatMode enables red team blackhat commentary.
	BlackhatMode bool

	// SelectedPlugins specifies which compliance plugins to run.
	SelectedPlugins []string
}

// DefaultOptions returns an Options initialized with the package's default settings for report generation.
// Defaults: Format=markdown, Theme=auto, WrapWidth=0, EnableTables=true, EnableColors=true, EnableEmojis=true,
// IncludeMetadata=true, CustomFields["IncludeTunables"]=false, Comprehensive and Compact set to false, and
// SuppressWarnings set to false.
func DefaultOptions() Options {
	return Options{
		Format:          FormatMarkdown,
		Comprehensive:   false,
		Sections:        nil,
		Theme:           ThemeAuto,
		WrapWidth:       0,
		EnableTables:    true,
		EnableColors:    true,
		EnableEmojis:    true,
		Compact:         false,
		IncludeMetadata: true,
		CustomFields: map[string]any{
			"IncludeTunables": false,
		},
		SuppressWarnings: false,
	}
}

// ErrInvalidWrapWidth indicates that the wrap width setting is invalid.
var ErrInvalidWrapWidth = errors.New("wrap width must be -1 (auto-detect), 0 (no wrapping), or positive")

// Validate checks if the options are valid.
func (o Options) Validate() error {
	if err := o.Format.Validate(); err != nil {
		return fmt.Errorf("invalid format: %w", err)
	}

	if o.WrapWidth < -1 {
		return fmt.Errorf("%w: %d", ErrInvalidWrapWidth, o.WrapWidth)
	}

	return nil
}

// WithFormat sets the output format. Format validity is checked by Options.Validate().
func (o Options) WithFormat(format Format) Options {
	o.Format = format
	return o
}

// WithSections sets the sections to include in output.
func (o Options) WithSections(sections ...string) Options {
	o.Sections = sections
	return o
}

// WithTheme sets the terminal rendering theme.
func (o Options) WithTheme(theme Theme) Options {
	o.Theme = theme
	return o
}

// WithWrapWidth sets the text wrapping width.
func (o Options) WithWrapWidth(width int) Options {
	o.WrapWidth = width
	return o
}

// WithTables enables or disables table rendering.
func (o Options) WithTables(enabled bool) Options {
	o.EnableTables = enabled
	return o
}

// WithColors enables or disables colored output.
func (o Options) WithColors(enabled bool) Options {
	o.EnableColors = enabled
	return o
}

// WithEmojis enables or disables emoji icons.
func (o Options) WithEmojis(enabled bool) Options {
	o.EnableEmojis = enabled
	return o
}

// WithCompact enables or disables compact output format.
func (o Options) WithCompact(compact bool) Options {
	o.Compact = compact
	return o
}

// WithMetadata enables or disables generation metadata.
func (o Options) WithMetadata(enabled bool) Options {
	o.IncludeMetadata = enabled
	return o
}

// WithCustomField adds a custom field for template rendering.
func (o Options) WithCustomField(key string, value any) Options {
	if o.CustomFields == nil {
		o.CustomFields = make(map[string]any)
	}

	o.CustomFields[key] = value

	return o
}

// WithComprehensive enables or disables comprehensive report generation.
func (o Options) WithComprehensive(enabled bool) Options {
	o.Comprehensive = enabled
	return o
}

// WithSuppressWarnings enables or disables warning suppression.
func (o Options) WithSuppressWarnings(suppress bool) Options {
	o.SuppressWarnings = suppress
	return o
}

// WithAuditMode sets the audit reporting mode.
func (o Options) WithAuditMode(mode string) Options {
	o.AuditMode = mode
	return o
}

// WithBlackhatMode enables or disables blackhat mode for red team reports.
func (o Options) WithBlackhatMode(enabled bool) Options {
	o.BlackhatMode = enabled
	return o
}

// WithSelectedPlugins sets the compliance plugins to run.
func (o Options) WithSelectedPlugins(plugins ...string) Options {
	o.SelectedPlugins = plugins
	return o
}
