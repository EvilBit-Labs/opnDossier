// Package markdown provides an extended API for generating markdown documentation
// from OPNsense configurations with configurable options and pluggable templates.
package markdown

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"text/template"

	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

// HybridGenerator provides dual-mode support for markdown generation,
// allowing progressive migration from templates to programmatic generation
// while maintaining backwards compatibility.
type HybridGenerator struct {
	builder  converter.ReportBuilder
	template *template.Template // Optional override
	logger   *log.Logger
}

// NewHybridGenerator creates a new HybridGenerator with the specified builder and optional template.
func NewHybridGenerator(builder converter.ReportBuilder, logger *log.Logger) (*HybridGenerator, error) {
	if logger == nil {
		var err error
		logger, err = log.New(log.Config{})
		if err != nil {
			return nil, fmt.Errorf("failed to create default logger: %w", err)
		}
	}
	return &HybridGenerator{
		builder: builder,
		logger:  logger,
	}, nil
}

// NewHybridGeneratorWithTemplate creates a new HybridGenerator with a custom template override.
func NewHybridGeneratorWithTemplate(
	builder converter.ReportBuilder,
	tmpl *template.Template,
	logger *log.Logger,
) (*HybridGenerator, error) {
	if logger == nil {
		var err error
		logger, err = log.New(log.Config{})
		if err != nil {
			return nil, fmt.Errorf("failed to create default logger: %w", err)
		}
	}
	return &HybridGenerator{
		builder:  builder,
		template: tmpl,
		logger:   logger,
	}, nil
}

// getStringFromMap safely extracts a string value from a map with a default fallback.
func getStringFromMap(m map[string]any, key, defaultValue string) string {
	if m == nil {
		return defaultValue
	}
	if value, exists := m[key]; exists && value != nil {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return defaultValue
}

// Generate creates documentation using either programmatic generation (default) or template override.
// If a custom template is provided, it uses template generation; otherwise, it uses programmatic generation.
func (g *HybridGenerator) Generate(ctx context.Context, data *model.OpnSenseDocument, opts Options) (string, error) {
	if data == nil {
		return "", converter.ErrNilOpnSenseDocument
	}

	// Check if we should use template generation
	if g.shouldUseTemplate(opts) {
		return g.generateFromTemplate(ctx, data, opts)
	}

	// Use programmatic generation (default)
	return g.generateFromBuilder(ctx, data, opts)
}

// shouldUseTemplate determines whether to use template generation based on options and available templates.
// Template generation is only used for markdown format; other formats use programmatic generation.
//
// Updated for Phase 3.7: Now defaults to programmatic generation unless explicitly enabled.
func (g *HybridGenerator) shouldUseTemplate(opts Options) bool {
	// Format-aware routing: only use templates for markdown format
	// Empty format defaults to markdown (as per DefaultOptions())
	if opts.Format != "" && !strings.EqualFold(string(opts.Format), string(FormatMarkdown)) {
		return false
	}

	// Check for explicit CLI-based engine selection first
	if useTemplateFromCLI, exists := opts.CustomFields["UseTemplateEngine"]; exists {
		if useTemplate, ok := useTemplateFromCLI.(bool); ok && useTemplate {
			return true
		}
	}

	// If a custom template is explicitly provided via SetTemplate(), use it
	if g.template != nil {
		return true
	}

	// If template name is specified and we have a template generator, use it
	if opts.TemplateName != "" {
		return true
	}

	// If custom template directory is specified, use template generation
	if opts.TemplateDir != "" {
		return true
	}

	// Default to programmatic generation (new behavior for Phase 3.7)
	return false
}

// generateFromTemplate generates output using template-based generation.
func (g *HybridGenerator) generateFromTemplate(
	ctx context.Context,
	data *model.OpnSenseDocument,
	opts Options,
) (string, error) {
	g.logger.Debug("Using template-based generation")

	// If we have a custom template, use the custom generator
	if g.template != nil {
		// Create a custom template generator with our template
		customGen := g.createCustomTemplateGenerator(opts)
		return customGen.Generate(ctx, data, opts)
	}

	// Create a template generator for standard template-based generation
	templateGen, err := NewMarkdownGeneratorWithTemplates(g.logger.Logger, opts.TemplateDir)
	if err != nil {
		return "", fmt.Errorf("failed to create template generator: %w", err)
	}

	// Use the standard template generator
	return templateGen.Generate(ctx, data, opts)
}

// generateFromBuilder generates output using programmatic generation.
func (g *HybridGenerator) generateFromBuilder(
	_ context.Context,
	data *model.OpnSenseDocument,
	opts Options,
) (string, error) {
	g.logger.Debug("Using programmatic generation")

	// Validate that we have a builder
	if g.builder == nil {
		return "", errors.New("no report builder available for programmatic generation")
	}

	// Determine which report type to generate
	switch {
	case opts.Comprehensive:
		return g.builder.BuildComprehensiveReport(data)
	default:
		return g.builder.BuildStandardReport(data)
	}
}

// createCustomTemplateGenerator creates a custom template generator with the provided template.
func (g *HybridGenerator) createCustomTemplateGenerator(_ Options) Generator {
	// Create a custom markdown generator that uses our template
	customGen := &customTemplateGenerator{
		template: g.template,
		logger:   g.logger,
	}

	return customGen
}

// customTemplateGenerator is a simple generator that uses a custom template.
type customTemplateGenerator struct {
	template *template.Template
	logger   *log.Logger
}

// Generate implements the Generator interface for custom templates.
func (c *customTemplateGenerator) Generate(
	_ context.Context,
	cfg *model.OpnSenseDocument,
	opts Options,
) (string, error) {
	if cfg == nil {
		return "", converter.ErrNilOpnSenseDocument
	}

	if c.template == nil {
		return "", errors.New("no template provided for custom template generator")
	}

	// Enrich the model with calculated fields and analysis data
	enrichedCfg := model.EnrichDocument(cfg)
	if enrichedCfg == nil {
		return "", converter.ErrNilOpnSenseDocument
	}

	// Add metadata for template rendering
	metadata := struct {
		*model.EnrichedOpnSenseDocument

		Generated    string
		ToolVersion  string
		CustomFields map[string]any
	}{
		EnrichedOpnSenseDocument: enrichedCfg,
		Generated:                getStringFromMap(opts.CustomFields, "Generated", "2024-01-01T00:00:00Z"),
		ToolVersion:              getStringFromMap(opts.CustomFields, "ToolVersion", "1.0.0"),
		CustomFields:             opts.CustomFields,
	}

	// Render the template with the data
	var buf bytes.Buffer
	err := c.template.Execute(&buf, metadata)
	if err != nil {
		return "", fmt.Errorf("failed to execute custom template: %w", err)
	}

	return buf.String(), nil
}

// SetTemplate sets a custom template for the hybrid generator.
func (g *HybridGenerator) SetTemplate(tmpl *template.Template) {
	g.template = tmpl
}

// GetTemplate returns the current custom template, if any.
func (g *HybridGenerator) GetTemplate() *template.Template {
	return g.template
}

// SetBuilder sets the report builder for programmatic generation.
func (g *HybridGenerator) SetBuilder(builder converter.ReportBuilder) {
	g.builder = builder
}

// GetBuilder returns the current report builder.
func (g *HybridGenerator) GetBuilder() converter.ReportBuilder {
	return g.builder
}
