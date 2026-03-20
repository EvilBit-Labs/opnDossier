package converter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
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

// reportGenerator is the narrowest interface HybridGenerator requires from its
// builder. It lists only the four methods HybridGenerator directly calls:
// report composition (BuildStandardReport, BuildComprehensiveReport),
// audit section rendering (BuildAuditSection), and a tunables toggle
// (SetIncludeTunables). The remaining SectionBuilder and TableWriter methods
// are deliberately excluded — HybridGenerator delegates full-report assembly
// to the builder and only renders the audit section individually.
//
// Note: HybridGenerator also type-asserts the builder to builder.SectionWriter
// for streaming support — see generateMarkdownToWriter.
type reportGenerator interface {
	// SetIncludeTunables configures whether all system tunables are included in the report.
	SetIncludeTunables(v bool)
	// BuildAuditSection builds the compliance audit section from the device's ComplianceChecks.
	BuildAuditSection(data *common.CommonDevice) string
	// BuildStandardReport generates a standard configuration report.
	BuildStandardReport(data *common.CommonDevice) (string, error)
	// BuildComprehensiveReport generates a comprehensive configuration report.
	BuildComprehensiveReport(data *common.CommonDevice) (string, error)
}

// HybridGenerator provides programmatic markdown, JSON, and YAML generation.
// It uses the builder pattern for markdown output and direct serialization for JSON/YAML.
//
// HybridGenerator implements both Generator (string-based) and StreamingGenerator
// (io.Writer-based) interfaces. Use GenerateToWriter for memory-efficient streaming
// output, or Generate when you need the output as a string for further processing.
type HybridGenerator struct {
	builder reportGenerator
	logger  *logging.Logger
}

// Compile-time assertions.
var (
	_ StreamingGenerator = (*HybridGenerator)(nil)
	_ reportGenerator    = (*builder.MarkdownBuilder)(nil)
)

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

// NewMarkdownGenerator creates a HybridGenerator configured with a MarkdownBuilder and the provided logger.
// Despite its name, the returned Generator supports all output formats (Markdown, JSON, YAML, Text, HTML)
// via the Options passed to Generate(). The opts parameter is ignored and exists for backward compatibility.
// Returns an error only if the provided logger is nil and creating a default logger fails.
func NewMarkdownGenerator(logger *logging.Logger, _ Options) (Generator, error) {
	var err error
	logger, err = ensureLogger(logger)
	if err != nil {
		return nil, err
	}

	reportBuilder := builder.NewMarkdownBuilder()
	return NewHybridGenerator(reportBuilder, logger)
}

// handlerForFormat resolves the format string to a FormatHandler via the DefaultRegistry,
// defaulting to markdown when the format is empty. Returns ErrUnsupportedFormat for unknown formats.
func handlerForFormat(format string) (FormatHandler, error) {
	if format == "" {
		format = string(FormatMarkdown)
	}

	return DefaultRegistry.Get(format)
}

// Generate creates documentation in the specified format from the provided OPNsense configuration.
// Supported formats: markdown (default), json, yaml, text, and html.
//
// For memory-efficient streaming output, use GenerateToWriter instead.
// Generate is preferred when you need the output as a string for further processing.
func (g *HybridGenerator) Generate(_ context.Context, data *common.CommonDevice, opts Options) (string, error) {
	if data == nil {
		return "", ErrNilDevice
	}

	if err := opts.Validate(); err != nil {
		return "", fmt.Errorf("invalid options: %w", err)
	}

	handler, err := handlerForFormat(string(opts.Format))
	if err != nil {
		return "", err
	}

	return handler.Generate(g, data, opts)
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
		return ErrNilDevice
	}

	if err := opts.Validate(); err != nil {
		return fmt.Errorf("invalid options: %w", err)
	}

	handler, err := handlerForFormat(string(opts.Format))
	if err != nil {
		return err
	}

	return handler.GenerateToWriter(g, w, data, opts)
}

// generateMarkdown generates markdown output using the programmatic builder.
// Not safe for concurrent use — MarkdownBuilder is per-instance, not shared.
func (g *HybridGenerator) generateMarkdown(data *common.CommonDevice, opts Options) (string, error) {
	g.logger.Debug("Using programmatic markdown generation")

	if g.builder == nil {
		return "", errors.New("no report builder available for programmatic generation")
	}

	g.builder.SetIncludeTunables(opts.IncludeTunables)
	target := prepareForExport(data, opts.Redact)

	var report string
	var err error

	switch {
	case opts.Comprehensive:
		report, err = g.builder.BuildComprehensiveReport(target)
	default:
		report, err = g.builder.BuildStandardReport(target)
	}

	if err != nil {
		return "", err
	}

	// Append audit section when compliance data is present
	if target.ComplianceChecks != nil {
		auditSection := g.builder.BuildAuditSection(target)
		if auditSection != "" {
			report += "\n\n" + auditSection
		}
	}

	return report, nil
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

	g.builder.SetIncludeTunables(opts.IncludeTunables)
	target := prepareForExport(data, opts.Redact)

	// Check if builder supports SectionWriter interface for streaming
	sectionWriter, ok := g.builder.(builder.SectionWriter)
	if !ok {
		// Fallback to string-based generation using the already-prepared target
		g.logger.Debug("Builder does not support SectionWriter, falling back to string generation")

		var output string
		var err error

		switch {
		case opts.Comprehensive:
			output, err = g.builder.BuildComprehensiveReport(target)
		default:
			output, err = g.builder.BuildStandardReport(target)
		}

		if err != nil {
			return err
		}

		// Append audit section when compliance data is present
		if target.ComplianceChecks != nil {
			auditSection := g.builder.BuildAuditSection(target)
			if auditSection != "" {
				output += "\n\n" + auditSection
			}
		}

		_, err = io.WriteString(w, output)

		return err
	}

	// Use streaming writer
	var err error

	switch {
	case opts.Comprehensive:
		err = sectionWriter.WriteComprehensiveReport(w, target)
	default:
		err = sectionWriter.WriteStandardReport(w, target)
	}

	if err != nil {
		return err
	}

	// Append audit section when compliance data is present
	if target.ComplianceChecks != nil {
		auditSection := g.builder.BuildAuditSection(target)
		if auditSection != "" {
			if _, writeErr := io.WriteString(w, "\n\n"+auditSection); writeErr != nil {
				return fmt.Errorf("failed to write audit section: %w", writeErr)
			}
		}
	}

	return nil
}

// generateJSON generates JSON output by serializing the model.
func (g *HybridGenerator) generateJSON(data *common.CommonDevice, opts Options) (string, error) {
	g.logger.Debug("Generating JSON output")

	target := prepareForExport(data, opts.Redact)

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
func (g *HybridGenerator) generateJSONToWriter(w io.Writer, data *common.CommonDevice, opts Options) error {
	g.logger.Debug("Generating JSON output to writer")

	target := prepareForExport(data, opts.Redact)

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(target); err != nil {
		return fmt.Errorf("failed to encode JSON to writer: %w", err)
	}
	return nil
}

// generateYAML generates YAML output by serializing the model.
func (g *HybridGenerator) generateYAML(data *common.CommonDevice, opts Options) (string, error) {
	g.logger.Debug("Generating YAML output")

	target := prepareForExport(data, opts.Redact)

	yamlData, err := yaml.Marshal(target)
	if err != nil {
		return "", fmt.Errorf("failed to marshal to YAML: %w", err)
	}
	return string(yamlData), nil
}

// generateYAMLToWriter writes YAML output directly to the writer.
// Note: YAML marshaling requires the full document, so this doesn't provide
// the same streaming benefits as markdown generation.
func (g *HybridGenerator) generateYAMLToWriter(w io.Writer, data *common.CommonDevice, opts Options) error {
	g.logger.Debug("Generating YAML output to writer")

	target := prepareForExport(data, opts.Redact)

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

	return StripMarkdownFormatting(markdown)
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

	return RenderMarkdownToHTML(markdown)
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

// GetBuilder returns the current report builder as a ReportBuilder.
// The underlying value is typically a ReportBuilder (e.g., *MarkdownBuilder)
// because SetBuilder and NewHybridGenerator accept ReportBuilder.
// Returns nil if the builder is nil or does not satisfy the full ReportBuilder interface.
func (g *HybridGenerator) GetBuilder() builder.ReportBuilder {
	if g.builder == nil {
		return nil
	}

	rb, ok := g.builder.(builder.ReportBuilder)
	if !ok {
		g.logger.Debug("builder does not satisfy full ReportBuilder interface",
			"type", fmt.Sprintf("%T", g.builder))

		return nil
	}

	return rb
}
