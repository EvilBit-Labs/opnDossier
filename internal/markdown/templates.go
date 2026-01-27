package markdown

import (
	"embed"
	"text/template"

	"github.com/EvilBit-Labs/opnDossier/internal/converter"
)

// TemplateManager manages built-in and custom templates.
type TemplateManager = converter.TemplateManager

// ErrTemplateNotImplemented indicates that embedded template loading is not yet implemented.
var ErrTemplateNotImplemented = converter.ErrTemplateNotImplemented

// SetEmbeddedTemplates allows external packages to set the embedded templates filesystem.
//
// Deprecated: use converter.SetEmbeddedTemplates instead.
func SetEmbeddedTemplates(fs embed.FS) {
	converter.SetEmbeddedTemplates(fs)
}

// NewTemplateManager returns a new TemplateManager with an initialized empty template map.
//
// Deprecated: use converter.NewTemplateManager instead.
func NewTemplateManager() *TemplateManager {
	return converter.NewTemplateManager()
}

// GetDefaultTemplateManager creates and returns a new default TemplateManager instance.
//
// Deprecated: use converter.GetDefaultTemplateManager instead.
func GetDefaultTemplateManager() *TemplateManager {
	return converter.GetDefaultTemplateManager()
}

// LoadBuiltinTemplate retrieves a built-in template by name using the default template manager.
//
// Deprecated: use converter.LoadBuiltinTemplate instead.
func LoadBuiltinTemplate(name string) (*template.Template, error) {
	return converter.LoadBuiltinTemplate(name)
}

// RegisterCustomTemplate registers a custom template with the default template manager, making it available globally by name.
//
// Deprecated: use converter.RegisterCustomTemplate instead.
func RegisterCustomTemplate(name string, tmpl *template.Template) {
	converter.RegisterCustomTemplate(name, tmpl)
}
