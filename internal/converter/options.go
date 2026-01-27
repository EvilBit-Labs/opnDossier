package converter

import (
	"errors"
	"fmt"
	"text/template"

	"github.com/EvilBit-Labs/opnDossier/internal/log"
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

// Options contains configuration options for markdown generation.
type Options struct {
	// Format specifies the output format (markdown, json, yaml).
	Format Format

	// Comprehensive specifies whether to generate a comprehensive report.
	Comprehensive bool

	// Template specifies a custom Go text/template to use for rendering.
	Template *template.Template

	// TemplateName specifies the name of a built-in template to use.
	TemplateName string

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

	// CustomFields allows for additional custom fields to be passed to templates.
	CustomFields map[string]any

	// TemplateDir specifies a custom directory for user template overrides.
	TemplateDir string

	// UseTemplateEngine specifies whether to use template-based generation instead of programmatic generation.
	UseTemplateEngine bool

	// SuppressWarnings suppresses deprecation and other non-critical warnings.
	SuppressWarnings bool
}

// DefaultOptions returns an Options struct initialized with default settings for markdown generation.
func DefaultOptions() Options {
	return Options{
		Format:          FormatMarkdown,
		Comprehensive:   false,
		Template:        nil,
		TemplateName:    "",
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
		TemplateDir:       "",
		UseTemplateEngine: false,
		SuppressWarnings:  false,
	}
}

var (
	// ErrInvalidWrapWidth indicates that the wrap width setting is invalid.
	ErrInvalidWrapWidth = errors.New("wrap width must be -1 (auto-detect), 0 (no wrapping), or positive")
	// ErrAuditTemplateDeferred indicates that an audit-related template was requested but audit mode is not available.
	ErrAuditTemplateDeferred = errors.New("audit templates (blue, red, blue-enhanced) are deferred to v2.1")
)

var deferredAuditTemplates = map[string]bool{
	"blue":          true,
	"red":           true,
	"blue-enhanced": true,
}

// Validate checks if the options are valid.
func (o Options) Validate() error {
	if err := o.Format.Validate(); err != nil {
		return fmt.Errorf("invalid format: %w", err)
	}

	if o.WrapWidth < -1 {
		return fmt.Errorf("%w: %d", ErrInvalidWrapWidth, o.WrapWidth)
	}

	if o.TemplateName != "" {
		if deferredAuditTemplates[o.TemplateName] {
			return fmt.Errorf(
				"%w: template %q requires audit mode which is not yet available",
				ErrAuditTemplateDeferred,
				o.TemplateName,
			)
		}
	}

	if o.UseTemplateEngine && o.Format != FormatMarkdown {
		return fmt.Errorf("template engine can only be used with markdown format, got: %s", o.Format)
	}

	return nil
}

// WithFormat sets the output format.
func (o Options) WithFormat(format Format) Options {
	if err := format.Validate(); err != nil {
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

// WithTemplateDir sets the custom template directory for user overrides.
func (o Options) WithTemplateDir(dir string) Options {
	o.TemplateDir = dir
	return o
}

// WithUseTemplateEngine sets whether to use template-based generation.
func (o Options) WithUseTemplateEngine(useTemplate bool) Options {
	o.UseTemplateEngine = useTemplate
	return o
}

// WithSuppressWarnings enables or disables warning suppression.
func (o Options) WithSuppressWarnings(suppress bool) Options {
	o.SuppressWarnings = suppress
	return o
}
