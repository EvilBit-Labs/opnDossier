package converter

import (
	"errors"
	"fmt"
)

// Format represents the output format type.
type Format string

// Supported output format constants for report generation.
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

// Validate checks if the format is supported by looking it up in the DefaultRegistry.
func (f Format) Validate() error {
	_, err := DefaultRegistry.Get(string(f))

	return err
}

// Theme represents the rendering theme for terminal output.
type Theme string

// Supported rendering theme constants for terminal output styling.
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

	// SuppressWarnings suppresses non-critical warnings.
	SuppressWarnings bool

	// IncludeTunables controls whether all system tunables are included in the output.
	// When false (default), only security-related tunables are shown in markdown, text, and HTML output.
	// JSON and YAML exports always include all tunables regardless of this setting.
	IncludeTunables bool

	// FailuresOnly filters the plugin control results table to show only non-compliant controls.
	// Only meaningful in blue mode audit reports where compliance checks are executed.
	FailuresOnly bool

	// Redact controls whether sensitive fields (passwords, private keys, community strings, etc.)
	// are replaced with [REDACTED] in the output. Defaults to false.
	Redact bool
}

// DefaultOptions returns an Options initialized with the package's default settings for report generation.
// Defaults: Format=markdown, Theme=auto, WrapWidth=0, EnableTables=true, EnableColors=true, EnableEmojis=true,
// IncludeMetadata=true, IncludeTunables=false, Comprehensive and Compact set to false, and
// SuppressWarnings set to false.
func DefaultOptions() Options {
	return Options{
		Format:           FormatMarkdown,
		Comprehensive:    false,
		Sections:         nil,
		Theme:            ThemeAuto,
		WrapWidth:        0,
		EnableTables:     true,
		EnableColors:     true,
		EnableEmojis:     true,
		Compact:          false,
		IncludeMetadata:  true,
		SuppressWarnings: false,
		IncludeTunables:  false,
		Redact:           false,
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
