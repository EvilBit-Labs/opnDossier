package converter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"gopkg.in/yaml.v3"
)

// Generator interface for creating documentation in various formats.
type Generator interface {
	// Generate creates documentation in a specified format from the provided device configuration.
	// This method returns the complete output as a string, which is useful when the output
	// needs further processing (e.g., HTML conversion).
	Generate(ctx context.Context, cfg *common.CommonDevice, opts Options) (string, error)
}

// StreamingGenerator extends Generator with io.Writer-based output support.
// This interface enables memory-efficient generation by writing directly to
// the destination without accumulating the entire output in memory first.
type StreamingGenerator interface {
	Generator

	// GenerateToWriter writes documentation directly to the provided io.Writer.
	// This is more memory-efficient than Generate() for large configurations
	// as it streams output section-by-section.
	GenerateToWriter(ctx context.Context, w io.Writer, cfg *common.CommonDevice, opts Options) error
}

// HybridGenerator provides programmatic markdown, JSON, and YAML generation.
// It uses the builder pattern for markdown output and direct serialization for JSON/YAML.
//
// HybridGenerator implements both Generator (string-based) and StreamingGenerator
// (io.Writer-based) interfaces. Use GenerateToWriter for memory-efficient streaming
// output, or Generate when you need the output as a string for further processing.
type HybridGenerator struct {
	builder builder.ReportBuilder
	logger  *logging.Logger
}

// Ensure HybridGenerator implements StreamingGenerator.
var _ StreamingGenerator = (*HybridGenerator)(nil)

// NewHybridGenerator creates a HybridGenerator that uses the provided ReportBuilder and logger.
// If logger is nil, NewHybridGenerator creates a default logger and returns an error if logger creation fails.
func NewHybridGenerator(reportBuilder builder.ReportBuilder, logger *logging.Logger) (*HybridGenerator, error) {
	if logger == nil {
		var err error
		logger, err = logging.New(logging.Config{})
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
func ensureLogger(logger *logging.Logger) (*logging.Logger, error) {
	if logger == nil {
		var err error
		logger, err = logging.New(logging.Config{Output: os.Stderr})
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
func NewMarkdownGenerator(logger *logging.Logger, _ Options) (Generator, error) {
	var err error
	logger, err = ensureLogger(logger)
	if err != nil {
		return nil, err
	}

	reportBuilder := builder.NewMarkdownBuilder()
	return NewHybridGenerator(reportBuilder, logger)
}

// Generate creates documentation in the specified format from the provided OPNsense configuration.
// Supported formats: markdown (default), json, yaml, text, and html.
//
// For memory-efficient streaming output, use GenerateToWriter instead.
// Generate is preferred when you need the output as a string for further processing.
func (g *HybridGenerator) Generate(_ context.Context, data *common.CommonDevice, opts Options) (string, error) {
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
	case string(FormatText), "txt":
		return g.generatePlainText(data, opts)
	case string(FormatHTML), "htm":
		return g.generateHTML(data, opts)
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedFormat, opts.Format)
	}
}

// GenerateToWriter writes documentation directly to the provided io.Writer.
// This is more memory-efficient than Generate() as it streams output section-by-section
// without accumulating the entire output in memory first.
//
// Supported formats: markdown (default), json, yaml, text, and html.
// For markdown format, sections are written incrementally as they are generated.
// For JSON, YAML, text, and HTML formats, the full output is generated then written
// (these formats require complete document serialization or post-processing).
//
// Use Generate() instead when you need the output as a string for further processing.
func (g *HybridGenerator) GenerateToWriter(
	_ context.Context,
	w io.Writer,
	data *common.CommonDevice,
	opts Options,
) error {
	if data == nil {
		return ErrNilConfiguration
	}

	if err := opts.Validate(); err != nil {
		return fmt.Errorf("invalid options: %w", err)
	}

	// Determine format and generate accordingly
	format := strings.ToLower(string(opts.Format))
	if format == "" {
		format = string(FormatMarkdown)
	}

	switch format {
	case string(FormatMarkdown), "md":
		return g.generateMarkdownToWriter(w, data, opts)
	case string(FormatJSON):
		return g.generateJSONToWriter(w, data)
	case string(FormatYAML), "yml":
		return g.generateYAMLToWriter(w, data)
	case string(FormatText), "txt":
		return g.generatePlainTextToWriter(w, data, opts)
	case string(FormatHTML), "htm":
		return g.generateHTMLToWriter(w, data, opts)
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedFormat, opts.Format)
	}
}

// generateMarkdown generates markdown output using the programmatic builder.
func (g *HybridGenerator) generateMarkdown(data *common.CommonDevice, opts Options) (string, error) {
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

// generateMarkdownToWriter writes markdown output directly to the writer.
func (g *HybridGenerator) generateMarkdownToWriter(
	w io.Writer,
	data *common.CommonDevice,
	opts Options,
) error {
	g.logger.Debug("Using streaming markdown generation")

	if g.builder == nil {
		return errors.New("no report builder available for programmatic generation")
	}

	// Check if builder supports SectionWriter interface for streaming
	sectionWriter, ok := g.builder.(builder.SectionWriter)
	if !ok {
		// Fallback to string-based generation if builder doesn't support streaming
		g.logger.Debug("Builder does not support SectionWriter, falling back to string generation")
		output, err := g.generateMarkdown(data, opts)
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, output)
		return err
	}

	// Use streaming writer
	switch {
	case opts.Comprehensive:
		return sectionWriter.WriteComprehensiveReport(w, data)
	default:
		return sectionWriter.WriteStandardReport(w, data)
	}
}

// generateJSON generates JSON output by serializing the model.
func (g *HybridGenerator) generateJSON(data *common.CommonDevice) (string, error) {
	g.logger.Debug("Generating JSON output")

	target := prepareForExport(data)

	jsonBytes, err := json.MarshalIndent(
		target,
		"",
		"  ",
	)
	if err != nil {
		return "", fmt.Errorf("failed to marshal to JSON: %w", err)
	}
	return string(jsonBytes), nil
}

// generateJSONToWriter writes JSON output directly to the writer.
// Note: JSON marshaling requires the full document, so this doesn't provide
// the same streaming benefits as markdown generation.
func (g *HybridGenerator) generateJSONToWriter(w io.Writer, data *common.CommonDevice) error {
	g.logger.Debug("Generating JSON output to writer")

	target := prepareForExport(data)

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(target); err != nil {
		return fmt.Errorf("failed to encode JSON to writer: %w", err)
	}
	return nil
}

// generateYAML generates YAML output by serializing the model.
func (g *HybridGenerator) generateYAML(data *common.CommonDevice) (string, error) {
	g.logger.Debug("Generating YAML output")

	target := prepareForExport(data)

	yamlData, err := yaml.Marshal(target)
	if err != nil {
		return "", fmt.Errorf("failed to marshal to YAML: %w", err)
	}
	return string(yamlData), nil
}

// generateYAMLToWriter writes YAML output directly to the writer.
// Note: YAML marshaling requires the full document, so this doesn't provide
// the same streaming benefits as markdown generation.
func (g *HybridGenerator) generateYAMLToWriter(w io.Writer, data *common.CommonDevice) error {
	g.logger.Debug("Generating YAML output to writer")

	target := prepareForExport(data)

	encoder := yaml.NewEncoder(w)
	encoder.SetIndent(2) //nolint:mnd // Standard YAML indentation
	if err := encoder.Encode(target); err != nil {
		return fmt.Errorf("failed to encode YAML to writer: %w", err)
	}
	return encoder.Close()
}

// generatePlainText generates plain text output by rendering markdown first, then stripping formatting.
func (g *HybridGenerator) generatePlainText(data *common.CommonDevice, opts Options) (string, error) {
	g.logger.Debug("Generating plain text output")

	markdown, err := g.generateMarkdown(data, opts)
	if err != nil {
		return "", fmt.Errorf("failed to generate markdown for plain text conversion: %w", err)
	}

	return stripMarkdownFormatting(markdown), nil
}

// generatePlainTextToWriter writes plain text output directly to the writer.
func (g *HybridGenerator) generatePlainTextToWriter(
	w io.Writer,
	data *common.CommonDevice,
	opts Options,
) error {
	g.logger.Debug("Generating plain text output to writer")

	output, err := g.generatePlainText(data, opts)
	if err != nil {
		return err
	}

	_, err = io.WriteString(w, output)
	return err
}

// generateHTML generates HTML output by rendering markdown first, then converting via goldmark.
func (g *HybridGenerator) generateHTML(data *common.CommonDevice, opts Options) (string, error) {
	g.logger.Debug("Generating HTML output")

	markdown, err := g.generateMarkdown(data, opts)
	if err != nil {
		return "", fmt.Errorf("failed to generate markdown for HTML conversion: %w", err)
	}

	return renderMarkdownToHTML(markdown)
}

// generateHTMLToWriter writes HTML output directly to the writer.
func (g *HybridGenerator) generateHTMLToWriter(
	w io.Writer,
	data *common.CommonDevice,
	opts Options,
) error {
	g.logger.Debug("Generating HTML output to writer")

	output, err := g.generateHTML(data, opts)
	if err != nil {
		return err
	}

	_, err = io.WriteString(w, output)
	return err
}

// SetBuilder sets the report builder for programmatic generation.
func (g *HybridGenerator) SetBuilder(reportBuilder builder.ReportBuilder) {
	g.builder = reportBuilder
}

// GetBuilder returns the current report builder.
func (g *HybridGenerator) GetBuilder() builder.ReportBuilder {
	return g.builder
}
