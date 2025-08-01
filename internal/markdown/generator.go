package markdown

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	"github.com/charmbracelet/log"
	"github.com/unclesp1d3r/opnFocus/internal/constants"
	"github.com/unclesp1d3r/opnFocus/internal/model"
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

// NewMarkdownGenerator creates a new Generator that produces documentation in Markdown, JSON, or YAML formats using predefined templates.
// It attempts to load and parse templates from multiple possible filesystem paths and returns an error if none are found or parsing fails.
func NewMarkdownGenerator(logger *log.Logger) (Generator, error) {
	if logger == nil {
		logger = log.NewWithOptions(os.Stderr, log.Options{})
	}
	return NewMarkdownGeneratorWithTemplates(logger, "")
}

// NewMarkdownGeneratorWithTemplates creates a new Generator with custom template directory support.
// If templateDir is provided, it will be used first for template overrides, falling back to built-in templates.
func NewMarkdownGeneratorWithTemplates(logger *log.Logger, templateDir string) (Generator, error) {
	if logger == nil {
		logger = log.NewWithOptions(os.Stderr, log.Options{})
	}

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

	// Escape markdown table cell content to prevent breaking table structure
	funcMap["escapeTableContent"] = func(content any) string {
		if content == nil {
			return ""
		}
		str := fmt.Sprintf("%v", content)
		// Escape pipe characters by replacing | with \|
		str = strings.ReplaceAll(str, "|", "\\|")
		// Replace carriage return + newline first to avoid double replacement
		str = strings.ReplaceAll(str, "\r\n", "<br>")
		// Replace remaining newlines with <br> for HTML rendering
		str = strings.ReplaceAll(str, "\n", "<br>")
		// Replace remaining carriage returns with <br>
		str = strings.ReplaceAll(str, "\r", "<br>")
		return str
	}

	// Build list of template paths
	var possiblePaths []string

	// Add custom template directory paths first if specified
	if templateDir != "" {
		possiblePaths = append(possiblePaths,
			filepath.Join(templateDir, "*.tmpl"),
			filepath.Join(templateDir, "reports", "*.tmpl"),
		)
	}

	// Add default template paths
	possiblePaths = append(possiblePaths,
		"internal/templates/*.tmpl",               // When running from project root
		"internal/templates/reports/*.tmpl",       // Audit mode templates
		"../../internal/templates/*.tmpl",         // When running from test directory
		"../../internal/templates/reports/*.tmpl", // Audit mode templates from test
		"../templates/*.tmpl",                     // Alternative relative path
		"../templates/reports/*.tmpl",             // Audit mode templates alternative path
	)

	templates := template.New("opnfocus").Funcs(funcMap)
	var lastErr error
	var foundAny bool

	for _, path := range possiblePaths {
		parsedTemplates, err := templates.ParseGlob(path)
		if err == nil && parsedTemplates != nil {
			templates = parsedTemplates
			foundAny = true
		} else if err != nil {
			lastErr = fmt.Errorf("failed to parse templates from %s: %w", path, err)
		}
	}

	if !foundAny {
		if lastErr != nil {
			return nil, fmt.Errorf("failed to parse templates from any path: %w", lastErr)
		}
		return nil, ErrTemplateNotFound
	}

	return &markdownGenerator{
		templates: templates,
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
		ToolVersion:              constants.Version,
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

// selectTemplate determines which template to use based on the options provided.
func (g *markdownGenerator) selectTemplate(opts Options) string {
	// If audit mode is specified, use audit mode templates
	if opts.AuditMode != "" {
		switch opts.AuditMode {
		case AuditModeStandard:
			return "standard.md.tmpl"
		case AuditModeBlue:
			return "blue.md.tmpl"
		case AuditModeRed:
			return "red.md.tmpl"
		}
	}

	// Fall back to comprehensive or standard templates
	if opts.Comprehensive {
		return "opnsense_report_comprehensive.md.tmpl"
	}
	return "opnsense_report.md.tmpl"
}

// generateJSON generates JSON output.
func (g *markdownGenerator) generateJSON(
	_ context.Context,
	cfg *model.EnrichedOpnSenseDocument,
	_ Options,
) (string, error) {
	return g.generateDataOutput("json_output.tmpl", cfg)
}

// generateYAML generates YAML output.
func (g *markdownGenerator) generateYAML(
	_ context.Context,
	cfg *model.EnrichedOpnSenseDocument,
	_ Options,
) (string, error) {
	return g.generateDataOutput("yaml_output.tmpl", cfg)
}

// generateDataOutput is a helper function that generates output for JSON/YAML using templates.
func (g *markdownGenerator) generateDataOutput(
	templateName string,
	cfg *model.EnrichedOpnSenseDocument,
) (string, error) {
	// Use template data with GeneratedAt for template
	metadata := struct {
		*model.EnrichedOpnSenseDocument

		GeneratedAt string
		ToolVersion string
	}{
		EnrichedOpnSenseDocument: cfg,
		GeneratedAt:              time.Now().Format(time.RFC3339),
		ToolVersion:              constants.Version,
	}

	// Use the specified template
	tmpl := g.templates.Lookup(templateName)
	if tmpl == nil {
		// Fallback to simple JSON/YAML if template not found
		configJSON, err := json.Marshal(cfg)
		if err != nil {
			return "", fmt.Errorf("failed to marshal configuration to JSON: %w", err)
		}

		// Determine fallback format based on template name
		if strings.Contains(templateName, "json") {
			return fmt.Sprintf(`{
			"generated": "%s",
			"tool_version": "%s",
			"configuration": %s
		}`, time.Now().Format(time.RFC3339), constants.Version, string(configJSON)), nil
		}
		return fmt.Sprintf(`generated: %s
tool_version: "%s"
configuration: %s
`, time.Now().Format(time.RFC3339), constants.Version, string(configJSON)), nil
	}

	var buf bytes.Buffer
	err := tmpl.Execute(&buf, metadata)
	if err != nil {
		return "", fmt.Errorf("failed to execute %s template: %w", templateName, err)
	}

	return buf.String(), nil
}
