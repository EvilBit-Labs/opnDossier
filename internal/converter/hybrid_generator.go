package converter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"text/template"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

// HybridGenerator provides dual-mode support for markdown generation.
type HybridGenerator struct {
	builder  builder.ReportBuilder
	template *template.Template
	logger   *log.Logger
}

// NewHybridGenerator creates a new HybridGenerator with the specified builder and optional template.
func NewHybridGenerator(reportBuilder builder.ReportBuilder, logger *log.Logger) (*HybridGenerator, error) {
	if logger == nil {
		var err error
		logger, err = log.New(log.Config{})
		if err != nil {
			return nil, fmt.Errorf("failed to create default logger: %w", err)
		}
	}
	return &HybridGenerator{
		builder: reportBuilder,
		logger:  logger,
	}, nil
}

// NewHybridGeneratorWithTemplate creates a new HybridGenerator with a custom template override.
func NewHybridGeneratorWithTemplate(
	reportBuilder builder.ReportBuilder,
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
		builder:  reportBuilder,
		template: tmpl,
		logger:   logger,
	}, nil
}

// Generate creates documentation using either programmatic generation (default) or template override.
func (g *HybridGenerator) Generate(ctx context.Context, data *model.OpnSenseDocument, opts Options) (string, error) {
	if data == nil {
		return "", ErrNilOpnSenseDocument
	}

	if g.shouldUseTemplate(opts) {
		return g.generateFromTemplate(ctx, data, opts)
	}

	return g.generateFromBuilder(ctx, data, opts)
}

func (g *HybridGenerator) shouldUseTemplate(opts Options) bool {
	if opts.Format != "" && !strings.EqualFold(string(opts.Format), string(FormatMarkdown)) {
		return false
	}

	if opts.UseTemplateEngine {
		g.logger.Debug("Template mode selected (opts.UseTemplateEngine=true)")
		return true
	}

	if g.template != nil {
		g.logger.Debug("Template mode selected (custom template override)")
		return true
	}

	if opts.TemplateName != "" {
		g.logger.Debug("Template mode selected (opts.TemplateName set)", "template_name", opts.TemplateName)
		return true
	}

	if opts.TemplateDir != "" {
		g.logger.Debug("Template mode selected (opts.TemplateDir set)", "template_dir", opts.TemplateDir)
		return true
	}

	return false
}

func (g *HybridGenerator) generateFromTemplate(
	ctx context.Context,
	data *model.OpnSenseDocument,
	opts Options,
) (string, error) {
	showTemplateDeprecationWarning(g.logger, opts)

	if g.template != nil {
		customGen := g.createCustomTemplateGenerator()
		return customGen.Generate(ctx, data, opts)
	}

	templateGen, err := NewMarkdownGeneratorWithTemplates(g.logger, opts.TemplateDir, opts)
	if err != nil {
		return "", fmt.Errorf("failed to create template generator: %w", err)
	}

	return templateGen.Generate(ctx, data, opts)
}

func (g *HybridGenerator) generateFromBuilder(
	_ context.Context,
	data *model.OpnSenseDocument,
	opts Options,
) (string, error) {
	g.logger.Debug("Using programmatic generation")

	if g.builder == nil {
		return "", errors.New("no report builder available for programmatic generation")
	}

	switch {
	case opts.Comprehensive:
		return g.builder.BuildComprehensiveReport(data)
	default:
		return g.builder.BuildStandardReport(data)
	}
}

func (g *HybridGenerator) createCustomTemplateGenerator() Generator {
	return &customTemplateGenerator{
		template: g.template,
		logger:   g.logger,
	}
}

type customTemplateGenerator struct {
	template *template.Template
	logger   *log.Logger
}

func (c *customTemplateGenerator) Generate(
	_ context.Context,
	cfg *model.OpnSenseDocument,
	opts Options,
) (string, error) {
	if cfg == nil {
		return "", ErrNilOpnSenseDocument
	}

	if c.template == nil {
		return "", errors.New("no template provided for custom template generator")
	}

	enrichedCfg := model.EnrichDocument(cfg)
	if enrichedCfg == nil {
		return "", ErrNilOpnSenseDocument
	}

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

	var buf bytes.Buffer
	if err := c.template.Execute(&buf, metadata); err != nil {
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
func (g *HybridGenerator) SetBuilder(reportBuilder builder.ReportBuilder) {
	g.builder = reportBuilder
}

// GetBuilder returns the current report builder.
func (g *HybridGenerator) GetBuilder() builder.ReportBuilder {
	return g.builder
}

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
