package converter

import (
	"embed"
	"errors"
	"fmt"
	"path/filepath"
	"text/template"
)

// embeddedTemplates will be set to reference the main package's embedded templates.
var embeddedTemplates embed.FS

// SetEmbeddedTemplates allows external packages to set the embedded templates filesystem.
func SetEmbeddedTemplates(fs embed.FS) {
	embeddedTemplates = fs
}

// TemplateManager manages built-in and custom templates.
type TemplateManager struct {
	templates map[string]*template.Template
}

// NewTemplateManager returns a new TemplateManager with an initialized empty template map.
func NewTemplateManager() *TemplateManager {
	return &TemplateManager{templates: make(map[string]*template.Template)}
}

// LoadTemplate loads a template by name from the built-in templates.
func (tm *TemplateManager) LoadTemplate(name string) (*template.Template, error) {
	if tmpl, exists := tm.templates[name]; exists {
		return tmpl, nil
	}

	templatePath := filepath.Join("templates", name)

	tmpl, err := tm.loadFromEmbedded(templatePath)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotFound, name)
	}

	tm.templates[name] = tmpl

	return tmpl, nil
}

// RegisterTemplate registers a custom template with the given name.
func (tm *TemplateManager) RegisterTemplate(name string, tmpl *template.Template) {
	tm.templates[name] = tmpl
}

// GetTemplate retrieves a template by name.
func (tm *TemplateManager) GetTemplate(name string) (*template.Template, bool) {
	tmpl, exists := tm.templates[name]
	return tmpl, exists
}

// ErrTemplateNotImplemented indicates that embedded template loading is not yet implemented.
var ErrTemplateNotImplemented = errors.New("embedded template loading not yet implemented")

// loadFromEmbedded loads a template from the embedded filesystem.
func (tm *TemplateManager) loadFromEmbedded(templatePath string) (*template.Template, error) {
	content, err := embeddedTemplates.ReadFile(templatePath)
	if err != nil {
		return nil, fmt.Errorf("template not found in embedded filesystem: %w", err)
	}

	tmpl, err := template.New(filepath.Base(templatePath)).Parse(string(content))
	if err != nil {
		return nil, fmt.Errorf("failed to parse embedded template: %w", err)
	}

	return tmpl, nil
}

// GetDefaultTemplateManager creates and returns a new default TemplateManager instance.
func GetDefaultTemplateManager() *TemplateManager {
	return NewTemplateManager()
}

// LoadBuiltinTemplate retrieves a built-in template by name using the default template manager.
func LoadBuiltinTemplate(name string) (*template.Template, error) {
	return GetDefaultTemplateManager().LoadTemplate(name)
}

// RegisterCustomTemplate registers a custom template with the default template manager, making it available globally by name.
func RegisterCustomTemplate(name string, tmpl *template.Template) {
	GetDefaultTemplateManager().RegisterTemplate(name, tmpl)
}
