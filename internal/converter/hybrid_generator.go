package converter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"gopkg.in/yaml.v3"
)

// Generator interface for creating documentation in various formats.
type Generator interface {
	// Generate creates documentation in a specified format from the provided OPNsense configuration.
	Generate(ctx context.Context, cfg *model.OpnSenseDocument, opts Options) (string, error)
}

// HybridGenerator provides programmatic markdown, JSON, and YAML generation.
// It uses the builder pattern for markdown output and direct serialization for JSON/YAML.
type HybridGenerator struct {
	builder builder.ReportBuilder
	logger  *log.Logger
}

// NewHybridGenerator creates a HybridGenerator that uses the provided ReportBuilder and logger.
// If logger is nil, NewHybridGenerator creates a default logger and returns an error if logger creation fails.
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

// ensureLogger creates a default logger if the provided logger is nil.
// ensureLogger returns the provided logger if non-nil; otherwise it creates and returns a new logger configured to write to stderr. It returns an error only if creating the default logger fails.
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

// NewMarkdownGenerator creates a new Generator that produces documentation in Markdown, JSON, or YAML formats.
// NewMarkdownGenerator creates a Generator that produces Markdown output using the programmatic report builder.
// It ensures a usable logger (creating a default logger if nil) and constructs a Markdown report builder.
// The provided Options parameter is ignored and exists only for backward compatibility.
// Returns a Generator configured for Markdown or an error if logger creation fails.
func NewMarkdownGenerator(logger *log.Logger, _ Options) (Generator, error) {
	var err error
	logger, err = ensureLogger(logger)
	if err != nil {
		return nil, err
	}

	reportBuilder := builder.NewMarkdownBuilder()
	return NewHybridGenerator(reportBuilder, logger)
}

// Generate creates documentation in the specified format from the provided OPNsense configuration.
// Supported formats: markdown (default), json, yaml.
func (g *HybridGenerator) Generate(_ context.Context, data *model.OpnSenseDocument, opts Options) (string, error) {
	if data == nil {
		return "", ErrNilConfiguration
	}

	if err := opts.Validate(); err != nil {
		return "", fmt.Errorf("invalid options: %w", err)
	}

	// Determine format and generate accordingly
	format := strings.ToLower(string(opts.Format))
	if format == "" {
		format = string(FormatMarkdown)
	}

	switch format {
	case string(FormatMarkdown), "md":
		return g.generateMarkdown(data, opts)
	case string(FormatJSON):
		return g.generateJSON(data)
	case string(FormatYAML), "yml":
		return g.generateYAML(data)
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedFormat, opts.Format)
	}
}

// generateMarkdown generates markdown output using the programmatic builder.
func (g *HybridGenerator) generateMarkdown(data *model.OpnSenseDocument, opts Options) (string, error) {
	g.logger.Debug("Using programmatic markdown generation")

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

// generateJSON generates JSON output by serializing the enriched model.
func (g *HybridGenerator) generateJSON(data *model.OpnSenseDocument) (string, error) {
	g.logger.Debug("Generating JSON output")

	// Enrich the model with calculated fields and analysis data
	enrichedCfg := model.EnrichDocument(data)
	if enrichedCfg == nil {
		return "", ErrNilConfiguration
	}

	//nolint:musttag // EnrichedOpnSenseDocument has proper json tags
	jsonBytes, err := json.MarshalIndent(
		enrichedCfg,
		"",
		"  ",
	)
	if err != nil {
		return "", fmt.Errorf("failed to marshal to JSON: %w", err)
	}
	return string(jsonBytes), nil
}

// generateYAML generates YAML output by serializing the enriched model.
func (g *HybridGenerator) generateYAML(data *model.OpnSenseDocument) (string, error) {
	g.logger.Debug("Generating YAML output")

	// Enrich the model with calculated fields and analysis data
	enrichedCfg := model.EnrichDocument(data)
	if enrichedCfg == nil {
		return "", ErrNilConfiguration
	}

	yamlData, err := yaml.Marshal(enrichedCfg) //nolint:musttag // EnrichedOpnSenseDocument has proper yaml tags
	if err != nil {
		return "", fmt.Errorf("failed to marshal to YAML: %w", err)
	}
	return string(yamlData), nil
}

// SetBuilder sets the report builder for programmatic generation.
func (g *HybridGenerator) SetBuilder(reportBuilder builder.ReportBuilder) {
	g.builder = reportBuilder
}

// GetBuilder returns the current report builder.
func (g *HybridGenerator) GetBuilder() builder.ReportBuilder {
	return g.builder
}