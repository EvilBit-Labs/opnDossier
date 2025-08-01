// Package markdown provides an extended API for generating markdown documentation
// from OPNsense configurations with configurable options and pluggable templates.
package markdown

import (
	"errors"
	"fmt"
	"text/template"

	"github.com/unclesp1d3r/opnFocus/internal/log"
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
)

// String returns the string representation of the format.
func (f Format) String() string {
	return string(f)
}

// Validate checks if the format is supported.
func (f Format) Validate() error {
	switch f {
	case FormatMarkdown, FormatJSON, FormatYAML:
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

// AuditMode represents the type of audit report to generate.
type AuditMode string

const (
	// AuditModeStandard represents a neutral, comprehensive documentation report.
	AuditModeStandard AuditMode = "standard"
	// AuditModeBlue represents a defensive audit report with security findings and recommendations.
	AuditModeBlue AuditMode = "blue"
	// AuditModeRed represents an attacker-focused recon report highlighting attack surfaces.
	AuditModeRed AuditMode = "red"
)

// String returns the string representation of the audit mode.
func (a AuditMode) String() string {
	return string(a)
}

// Validate checks if the audit mode is supported.
func (a AuditMode) Validate() error {
	switch a {
	case AuditModeStandard, AuditModeBlue, AuditModeRed, "":
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedAuditMode, a)
	}
}

// Options contains configuration options for markdown generation.
// Options contains configuration options for markdown generation.
type Options struct {
	// Format specifies the output format (markdown, json, yaml).
	Format Format

	// Comprehensive specifies whether to generate a comprehensive report.
	Comprehensive bool

	// Template specifies a custom Go text/template to use for rendering.
	// If nil, the default template for the specified format will be used.
	Template *template.Template

	// TemplateName specifies the name of a built-in template to use.
	// This is ignored if Template is specified.
	TemplateName string

	// Sections specifies which configuration sections to include.
	// If empty, all sections are included.
	Sections []string

	// Theme specifies the terminal rendering theme for markdown output.
	Theme Theme

	// WrapWidth specifies the column width for text wrapping.
	// A value of 0 means no wrapping.
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

	// CustomFields allows for additional custom fields to be passed to templates.
	CustomFields map[string]any

	// AuditMode specifies the type of audit report to generate (standard, blue, red).
	AuditMode AuditMode

	// BlackhatMode enables snarky or attacker-focused commentary for red team reports.
	BlackhatMode bool

	// SelectedPlugins specifies which compliance plugins to run for blue team reports.
	SelectedPlugins []string

	// TemplateDir specifies a custom directory for user template overrides.
	TemplateDir string
}

// DefaultOptions returns an Options struct initialized with default settings for markdown generation.
func DefaultOptions() Options {
	return Options{
		Format:          FormatMarkdown,
		Comprehensive:   false,
		Template:        nil,
		TemplateName:    "",
		Sections:        nil, // Include all sections
		Theme:           ThemeAuto,
		WrapWidth:       0, // No wrapping
		EnableTables:    true,
		EnableColors:    true,
		EnableEmojis:    true,
		Compact:         false,
		IncludeMetadata: true,
		CustomFields:    make(map[string]any),
		AuditMode:       "", // No audit mode by default
		BlackhatMode:    false,
		SelectedPlugins: nil,
		TemplateDir:     "",
	}
}

// ErrInvalidWrapWidth indicates that the wrap width setting is invalid.
var (
	ErrInvalidWrapWidth     = errors.New("wrap width cannot be negative")
	ErrUnsupportedAuditMode = errors.New("unsupported audit mode")
)

// Validate checks if the options are valid.
func (o Options) Validate() error {
	if err := o.Format.Validate(); err != nil {
		return fmt.Errorf("invalid format: %w", err)
	}

	if err := o.AuditMode.Validate(); err != nil {
		return fmt.Errorf("invalid audit mode: %w", err)
	}

	if o.WrapWidth < 0 {
		return fmt.Errorf("%w: %d", ErrInvalidWrapWidth, o.WrapWidth)
	}

	return nil
}

// WithFormat sets the output format.
func (o Options) WithFormat(format Format) Options {
	if err := format.Validate(); err != nil {
		// Log warning about validation failure instead of silently ignoring
		if logger, loggerErr := log.New(log.Config{Level: "warn"}); loggerErr == nil {
			logger.Warn("format validation failed, returning unchanged options", "format", format, "error", err)
		}

		return o
	}

	o.Format = format

	return o
}

// WithTemplate sets a custom template.
func (o Options) WithTemplate(tmpl *template.Template) Options {
	o.Template = tmpl
	return o
}

// WithTemplateName sets the name of a built-in template to use.
func (o Options) WithTemplateName(name string) Options {
	o.TemplateName = name
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

// WithAuditMode sets the audit report mode.
func (o Options) WithAuditMode(mode AuditMode) Options {
	if err := mode.Validate(); err != nil {
		// Log warning about validation failure instead of silently ignoring
		if logger, loggerErr := log.New(log.Config{Level: "warn"}); loggerErr == nil {
			logger.Warn("audit mode validation failed, returning unchanged options", "mode", mode, "error", err)
		}

		return o
	}

	o.AuditMode = mode

	return o
}

// WithBlackhatMode enables or disables blackhat mode for red team reports.
func (o Options) WithBlackhatMode(enabled bool) Options {
	o.BlackhatMode = enabled
	return o
}

// WithSelectedPlugins sets the compliance plugins to run for blue team reports.
func (o Options) WithSelectedPlugins(plugins []string) Options {
	o.SelectedPlugins = plugins
	return o
}

// WithTemplateDir sets the custom template directory for user overrides.
func (o Options) WithTemplateDir(dir string) Options {
	o.TemplateDir = dir
	return o
}
