// Package markdown provides an extended API for generating markdown documentation
// from OPNsense configurations with configurable options.
package markdown

import "github.com/EvilBit-Labs/opnDossier/internal/converter"

// Format represents the output format type.
type Format = converter.Format

const (
	// FormatMarkdown represents markdown output format.
	FormatMarkdown = converter.FormatMarkdown
	// FormatJSON represents JSON output format.
	FormatJSON = converter.FormatJSON
	// FormatYAML represents YAML output format.
	FormatYAML = converter.FormatYAML
)

// Theme represents the rendering theme for terminal output.
type Theme = converter.Theme

const (
	// ThemeAuto automatically detects the appropriate theme.
	ThemeAuto = converter.ThemeAuto
	// ThemeDark uses a dark terminal theme.
	ThemeDark = converter.ThemeDark
	// ThemeLight uses a light terminal theme.
	ThemeLight = converter.ThemeLight
	// ThemeNone disables styling for plain text output.
	ThemeNone = converter.ThemeNone
)

// Options contains configuration options for markdown generation.
type Options = converter.Options

// DefaultOptions returns an Options struct initialized with default settings for markdown generation.
func DefaultOptions() Options {
	return converter.DefaultOptions()
}

// ErrInvalidWrapWidth indicates that the wrap width setting is invalid.
var ErrInvalidWrapWidth = converter.ErrInvalidWrapWidth
