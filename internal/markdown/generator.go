package markdown

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	"github.com/unclesp1d3r/opnFocus/internal/model"

	"github.com/charmbracelet/glamour"
	"gopkg.in/yaml.v3"
)

// Generator represents the interface for generating documentation from OPNsense configurations.
type Generator interface {
	// Generate creates documentation in a specified format from the provided OPNsense configuration.
	Generate(ctx context.Context, cfg *model.OpnSenseDocument, opts Options) (string, error)
}

// markdownGenerator is the default implementation that wraps the old Markdown logic.
type markdownGenerator struct {
	templates *template.Template
}

// NewMarkdownGenerator returns an instance of the default markdownGenerator implementation.
func NewMarkdownGenerator() (Generator, error) {
	// Create template with sprig functions
	funcMap := sprig.FuncMap()

	// Add custom functions that aren't provided by sprig
	funcMap["isLast"] = func(index, slice interface{}) bool {
		switch s := slice.(type) {
		case map[string]interface{}:
			// For maps, we can't determine order, so always return false for now
			return false
		case []interface{}:
			if i, ok := index.(int); ok {
				return i == len(s)-1
			}
		}
		return false
	}

	// Try multiple possible paths for templates
	possiblePaths := []string{
		"internal/templates/*.tmpl",       // When running from project root
		"../../internal/templates/*.tmpl", // When running from test directory
		"../templates/*.tmpl",             // Alternative relative path
	}

	var templates *template.Template
	var err error
	for _, path := range possiblePaths {
		templates = template.New("opnfocus").Funcs(funcMap)
		templates, err = templates.ParseGlob(path)
		if err == nil && templates != nil && len(templates.Templates()) > 1 {
			break
		}
	}
	if err != nil || templates == nil || len(templates.Templates()) <= 1 {
		return nil, fmt.Errorf("failed to parse templates from any path: %w", err)
	}
	return &markdownGenerator{templates: templates}, nil
}

// Generate converts an OPNsense configuration to the specified format using the Options provided.
func (g *markdownGenerator) Generate(ctx context.Context, cfg *model.OpnSenseDocument, opts Options) (string, error) {
	if cfg == nil {
		return "", ErrNilConfiguration
	}

	if err := opts.Validate(); err != nil {
		return "", fmt.Errorf("invalid options: %w", err)
	}

	// Add metadata for template rendering
	metadata := struct {
		*model.OpnSenseDocument
		Generated   string
		ToolVersion string
	}{
		OpnSenseDocument: cfg,
		Generated:        time.Now().Format(time.RFC3339),
		ToolVersion:      "1.0.0", // Example version number, replace with actual
	}

	switch opts.Format {
	case FormatMarkdown:
		return g.generateMarkdown(ctx, metadata, opts)

	case FormatJSON:
		return g.generateJSON(ctx, cfg, opts)

	case FormatYAML:
		return g.generateYAML(ctx, cfg, opts)

	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedFormat, opts.Format)
	}
}

// generateMarkdown generates markdown output using templates.
func (g *markdownGenerator) generateMarkdown(_ context.Context, data interface{}, opts Options) (string, error) {
	// Determine which template to use based on comprehensive flag
	templateName := "opnsense_report.md.tmpl"
	if opts.Comprehensive {
		templateName = "opnsense_report_comprehensive.md.tmpl"
	}

	// Check if the template exists
	tmpl := g.templates.Lookup(templateName)
	if tmpl == nil {
		return "", fmt.Errorf("%w: %s", ErrTemplateNotFound, templateName)
	}

	// Render the template with the data
	var buf bytes.Buffer
	err := tmpl.Execute(&buf, data)
	if err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	rawMarkdown := buf.String()

	// Use glamour for terminal rendering with theme compatibility
	theme := g.getTheme(opts)
	r, err := glamour.Render(rawMarkdown, theme)
	if err != nil {
		return "", fmt.Errorf("failed to render markdown: %w", err)
	}

	return r, nil
}

// generateJSON generates JSON output.
func (g *markdownGenerator) generateJSON(_ context.Context, cfg *model.OpnSenseDocument, _ Options) (string, error) {
	// Marshal the OpnSenseDocument struct to JSON with indentation
	jsonBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal to JSON: %w", err)
	}

	return string(jsonBytes), nil
}

// generateYAML generates YAML output.
func (g *markdownGenerator) generateYAML(_ context.Context, cfg *model.OpnSenseDocument, _ Options) (string, error) {
	// Marshal the OpnSenseDocument struct to YAML
	yamlBytes, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("failed to marshal to YAML: %w", err)
	}

	return string(yamlBytes), nil
}

// getTheme determines the appropriate theme based on the options provided.
func (g *markdownGenerator) getTheme(opts Options) string {
	// Check for explicit theme preference in options
	if opts.Theme != "" {
		return opts.Theme.String()
	}

	// Default to auto which will detect based on terminal
	return "auto"
}
