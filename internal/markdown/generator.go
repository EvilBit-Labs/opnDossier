package markdown

import (
	"bytes"
	"context"
	"fmt"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	"github.com/unclesp1d3r/opnFocus/internal/model"
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

// NewMarkdownGenerator creates a new Generator that produces documentation in Markdown, JSON, or YAML formats using predefined templates.
// It attempts to load and parse templates from multiple possible filesystem paths and returns an error if none are found or parsing fails.
func NewMarkdownGenerator() (Generator, error) {
	// Create template with sprig functions
	funcMap := sprig.FuncMap()

	// Add custom functions that aren't provided by sprig
	funcMap["isLast"] = func(index, slice any) bool {
		switch s := slice.(type) {
		case map[string]any:
			// For maps, we can't determine order, so always return false for now
			return false
		case []any:
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
		if err == nil && templates != nil && len(templates.Templates()) > 0 {
			break
		}
	}
	if err != nil || templates == nil || len(templates.Templates()) == 0 {
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

	// Enrich the model with calculated fields and analysis data
	enrichedCfg := model.EnrichDocument(cfg)
	if enrichedCfg == nil {
		return "", ErrNilConfiguration
	}

	// Add metadata for template rendering
	metadata := struct {
		*model.EnrichedOpnSenseDocument
		Generated   string
		ToolVersion string
	}{
		EnrichedOpnSenseDocument: enrichedCfg,
		Generated:                time.Now().Format(time.RFC3339),
		ToolVersion:              "1.0.0", // Example version number, replace with actual
	}

	switch opts.Format {
	case FormatMarkdown:
		return g.generateMarkdown(ctx, metadata, opts)

	case FormatJSON:
		return g.generateJSON(ctx, enrichedCfg, opts)

	case FormatYAML:
		return g.generateYAML(ctx, enrichedCfg, opts)

	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedFormat, opts.Format)
	}
}

// generateMarkdown generates markdown output using templates.
func (g *markdownGenerator) generateMarkdown(_ context.Context, data any, opts Options) (string, error) {
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

	// Return raw markdown - let the display package handle theme-aware rendering
	return buf.String(), nil
}

// generateJSON generates JSON output using the JSON template.
func (g *markdownGenerator) generateJSON(_ context.Context, cfg *model.EnrichedOpnSenseDocument, _ Options) (string, error) {
	// Create template data with base document and generated timestamp
	templateData := struct {
		*model.OpnSenseDocument
		GeneratedAt string
	}{
		OpnSenseDocument: cfg.OpnSenseDocument,
		GeneratedAt:      time.Now().Format(time.RFC3339),
	}

	// Execute the JSON template
	tmpl := g.templates.Lookup("json_output.tmpl")
	if tmpl == nil {
		return "", fmt.Errorf("%w: %s", ErrTemplateNotFound, "json_output.tmpl")
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, templateData); err != nil {
		return "", fmt.Errorf("failed to execute JSON template: %w", err)
	}

	return buf.String(), nil
}

// generateYAML generates YAML output using the YAML template.
func (g *markdownGenerator) generateYAML(_ context.Context, cfg *model.EnrichedOpnSenseDocument, _ Options) (string, error) {
	// Create template data with base document and generated timestamp
	templateData := struct {
		*model.OpnSenseDocument
		GeneratedAt string
	}{
		OpnSenseDocument: cfg.OpnSenseDocument,
		GeneratedAt:      time.Now().Format(time.RFC3339),
	}

	// Execute the YAML template
	tmpl := g.templates.Lookup("yaml_output.tmpl")
	if tmpl == nil {
		return "", fmt.Errorf("%w: %s", ErrTemplateNotFound, "yaml_output.tmpl")
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, templateData); err != nil {
		return "", fmt.Errorf("failed to execute YAML template: %w", err)
	}

	return buf.String(), nil
}
