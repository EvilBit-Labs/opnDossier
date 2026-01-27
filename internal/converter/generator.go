package converter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/template"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/converter/templates"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"gopkg.in/yaml.v3"
)

// Generator interface for creating documentation in various formats.
type Generator interface {
	// Generate creates documentation in a specified format from the provided OPNsense configuration.
	Generate(ctx context.Context, cfg *model.OpnSenseDocument, opts Options) (string, error)
}

// markdownGenerator is the default implementation that wraps the old Markdown logic.
type markdownGenerator struct {
	templates *template.Template
	logger    *log.Logger
}

// ensureLogger creates a default logger if the provided logger is nil.
// Returns the provided logger if non-nil, or creates a new logger with stderr output.
func ensureLogger(logger *log.Logger) (*log.Logger, error) {
	if logger == nil {
		var err error
		logger, err = log.New(log.Config{Output: os.Stderr})
		if err != nil {
			return nil, fmt.Errorf("failed to create default logger: %w", err)
		}
	}
	return logger, nil
}

// NewMarkdownGenerator creates a new Generator that produces documentation in Markdown, JSON, or YAML formats using predefined templates.
// It attempts to load and parse templates from multiple possible filesystem paths and returns an error if none are found or parsing fails.
//
// NOTE: This generator is specifically for template-based generation. The deprecation warning is shown
// only when template mode signals are present (UseTemplateEngine, TemplateName, TemplateDir, or Template).
// For programmatic generation (the default since v2.0), use HybridGenerator instead.
func NewMarkdownGenerator(logger *log.Logger, opts Options) (Generator, error) {
	var err error
	logger, err = ensureLogger(logger)
	if err != nil {
		return nil, err
	}

	// Show deprecation warning if template mode is being used.
	showTemplateDeprecationWarning(logger, opts)

	return NewMarkdownGeneratorWithTemplates(logger, "", opts)
}

// NewMarkdownGeneratorWithTemplates creates a new Generator with custom template directory support.
// If templateDir is provided, it will be used first for template overrides, falling back to built-in templates.
//
// NOTE: This generator is specifically for template-based generation. The deprecation warning is shown
// only when template mode signals are present, indicating explicit template usage.
func NewMarkdownGeneratorWithTemplates(logger *log.Logger, templateDir string, opts Options) (Generator, error) {
	var err error
	logger, err = ensureLogger(logger)
	if err != nil {
		return nil, err
	}

	// If templateDir is specified via parameter, set it in opts for consistent warning detection.
	if templateDir != "" && opts.TemplateDir == "" {
		opts.TemplateDir = templateDir
	}

	// Show deprecation warning if template mode is being used.
	showTemplateDeprecationWarning(logger, opts)

	funcMap := templates.CreateTemplateFuncMap()
	possiblePaths := templates.BuildTemplatePaths(templateDir)

	templateSet, err := templates.ParseTemplatesWithEmbeddedFallback(possiblePaths, funcMap, embeddedTemplates)
	if err != nil {
		return nil, err
	}

	return &markdownGenerator{
		templates: templateSet,
		logger:    logger,
	}, nil
}

// Generate converts an OPNsense configuration to the specified format using the Options provided.
func (g *markdownGenerator) Generate(ctx context.Context, cfg *model.OpnSenseDocument, opts Options) (string, error) {
	if cfg == nil {
		return "", ErrNilConfiguration
	}

	if err := opts.Validate(); err != nil {
		return "", fmt.Errorf("invalid options: %w", err)
	}

	// Enrich the model with calculated fields and analysis data.
	enrichedCfg := model.EnrichDocument(cfg)
	if enrichedCfg == nil {
		return "", ErrNilConfiguration
	}

	// Add metadata for template rendering.
	metadata := struct {
		*model.EnrichedOpnSenseDocument

		Generated    string
		ToolVersion  string
		CustomFields map[string]any
	}{
		EnrichedOpnSenseDocument: enrichedCfg,
		Generated:                time.Now().Format(time.RFC3339),
		ToolVersion:              constants.Version,
		CustomFields:             opts.CustomFields,
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
	templateName := g.selectTemplate(opts)

	// Check if the template exists.
	tmpl := g.templates.Lookup(templateName)
	if tmpl == nil {
		return "", fmt.Errorf("%w: %s", ErrTemplateNotFound, templateName)
	}

	// Render the template with the data.
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	// Return raw markdown - let the display package handle theme-aware rendering.
	return buf.String(), nil
}

// mapTemplateName converts logical template names to actual filenames.
// NOTE: Templates "blue", "red", and "blue-enhanced" are deferred to v2.1 (audit mode required).
// These are blocked at validation time in Options.Validate() to provide a clear user-facing error.
func mapTemplateName(logicalName string) string {
	switch logicalName {
	case "standard":
		return "opnsense_report.md.tmpl"
	case "comprehensive":
		return "opnsense_report_comprehensive.md.tmpl"
	case "blue":
		return "blue.md.tmpl"
	case "red":
		return "red.md.tmpl"
	case "blue-enhanced":
		return "blue_enhanced.md.tmpl"
	default:
		// If it's not a known logical name, assume it's already a filename.
		return logicalName
	}
}

// selectTemplate determines which template to use based on the options provided.
func (g *markdownGenerator) selectTemplate(opts Options) string {
	// If a custom template name is specified, use it.
	if opts.TemplateName != "" {
		return mapTemplateName(opts.TemplateName)
	}

	// Fall back to comprehensive or standard templates.
	if opts.Comprehensive {
		return "opnsense_report_comprehensive.md.tmpl"
	}
	return "opnsense_report.md.tmpl"
}

// generateJSON generates JSON output using direct marshaling.
func (g *markdownGenerator) generateJSON(
	_ context.Context,
	cfg *model.EnrichedOpnSenseDocument,
	_ Options,
) (string, error) {
	data, err := json.MarshalIndent(cfg, "", "  ") //nolint:musttag // EnrichedOpnSenseDocument has proper json tags
	if err != nil {
		return "", fmt.Errorf("failed to marshal to JSON: %w", err)
	}
	return string(data), nil
}

// generateYAML generates YAML output using direct marshaling.
func (g *markdownGenerator) generateYAML(
	_ context.Context,
	cfg *model.EnrichedOpnSenseDocument,
	_ Options,
) (string, error) {
	data, err := yaml.Marshal(cfg) //nolint:musttag // EnrichedOpnSenseDocument has proper yaml tags
	if err != nil {
		return "", fmt.Errorf("failed to marshal to YAML: %w", err)
	}
	return string(data), nil
}
