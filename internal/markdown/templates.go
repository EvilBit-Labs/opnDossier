package markdown

import (
	"fmt"
	"path/filepath"
	"text/template"
)

// TemplateManager manages built-in and custom templates.
type TemplateManager struct {
	templates map[string]*template.Template
}

// NewTemplateManager creates a new template manager.
func NewTemplateManager() *TemplateManager {
	return &TemplateManager{
		templates: make(map[string]*template.Template),
	}
}

// LoadTemplate loads a template by name from the built-in templates.
func (tm *TemplateManager) LoadTemplate(name string) (*template.Template, error) {
	if tmpl, exists := tm.templates[name]; exists {
		return tmpl, nil
	}

	// Try to load from embedded templates directory
	templatePath := filepath.Join("templates", name)
	tmpl, err := tm.loadFromEmbedded(templatePath)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotFound, name)
	}

	// Cache the template
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

// loadFromEmbedded loads a template from the embedded filesystem.
// This is a placeholder for now - we'll implement the actual embedded loading
// when we move the templates.
func (tm *TemplateManager) loadFromEmbedded(path string) (*template.Template, error) {
	// For now, return an error - this will be implemented when we integrate
	// with the existing templates in internal/templates/
	return nil, fmt.Errorf("embedded template loading not yet implemented: %s", path)
}

// Default template manager instance.
var defaultTemplateManager = NewTemplateManager()

// LoadBuiltinTemplate loads a built-in template by name.
func LoadBuiltinTemplate(name string) (*template.Template, error) {
	return defaultTemplateManager.LoadTemplate(name)
}

// RegisterCustomTemplate registers a custom template globally.
func RegisterCustomTemplate(name string, tmpl *template.Template) {
	defaultTemplateManager.RegisterTemplate(name, tmpl)
}
