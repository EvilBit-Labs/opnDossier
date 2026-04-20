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
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"gopkg.in/yaml.v3"
)

// auditSectionSeparator is written between the base report body and the
// appended audit section when compliance data is present.
const auditSectionSeparator = "\n\n"

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
// builder. It lists only the methods HybridGenerator directly calls:
// report composition (BuildStandardReport, BuildComprehensiveReport),
// audit section rendering (BuildAuditSection), and rendering toggles
// (SetIncludeTunables, SetFailuresOnly). The remaining SectionBuilder and
// TableWriter methods are deliberately excluded — HybridGenerator delegates
// full-report assembly to the builder and only renders the audit section individually.
//
// Note: HybridGenerator also type-asserts the builder to builder.SectionWriter
// for streaming support — see generateMarkdownToWriter.
type reportGenerator interface {
	// SetIncludeTunables configures whether all system tunables are included in the report.
	SetIncludeTunables(v bool)
	// SetFailuresOnly configures whether only non-compliant controls are shown in audit reports.
	SetFailuresOnly(v bool)
	// BuildAuditSection builds the compliance audit section from the device's ComplianceResults.
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

// handlerForFormat resolves the format string to a FormatHandler via the DefaultRegistry.
// Returns ErrUnsupportedFormat for unknown formats.
//
// Note: Generate/GenerateToWriter call opts.Validate() before reaching this function,
// so empty and invalid formats are rejected upstream. This function does not add its own
// empty-format default to avoid masking validation gaps.
func handlerForFormat(format string) (FormatHandler, error) {
	return DefaultRegistry.Get(format)
}

// Generate creates documentation in the specified format from the provided OPNsense configuration.
// Supported formats: markdown (default), json, yaml, text, and html.
//
// Memory tradeoff (JSON/YAML): Generate pays roughly 2x peak memory for JSON and
// YAML output because the marshaled byte slice and its string(...) conversion both
// live on the heap simultaneously. For markdown, text, and HTML the builder
// already accumulates a string, so there is no additional penalty versus
// GenerateToWriter. Prefer GenerateToWriter once output approaches ~5MB.
//
// Use Generate when:
//   - You need the result as an in-memory string (to embed in another structure,
//     pass to a templating system, return from an API handler, or display in a TUI).
//   - The caller does not have an io.Writer to hand off (no file handle, no
//     http.ResponseWriter, no buffer already in scope).
//   - Output is small and the ergonomics of a return value matter more than peak memory.
//
// For streaming output, writing directly to a file/socket/HTTP response, or
// composing with io.Copy / io.MultiWriter, see GenerateToWriter.
func (g *HybridGenerator) Generate(ctx context.Context, data *common.CommonDevice, opts Options) (string, error) {
	// Honor ctx at entry so a pre-canceled ctx aborts before any work is done.
	// Per-subsystem boundary checks are applied inside the format-specific
	// generators (e.g., between report body and audit section in markdown).
	// Full ctx propagation through the builder layer is deferred to v1.6.
	if err := ctx.Err(); err != nil {
		return "", err
	}

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

	// Post-validation boundary: cancellation between validation and dispatch.
	if err := ctx.Err(); err != nil {
		return "", err
	}

	return handler.Generate(ctx, g, data, opts)
}

// GenerateToWriter writes documentation directly to the provided io.Writer.
//
// Supported formats: markdown (default), json, yaml, text, and html.
// For markdown, sections are written incrementally as they are generated.
// For JSON and YAML, an encoder writes directly to w — this avoids the 2x
// peak-memory hit that Generate incurs (marshaled bytes plus their string(...)
// conversion both resident at once). For text and HTML, the full output is
// produced then written because those formats require complete document
// serialization or post-processing.
//
// Use GenerateToWriter when:
//   - You are writing directly to a file, socket, or HTTP response.
//   - Output may be large (>5MB for JSON/YAML) and peak memory matters.
//   - You want partial-output-on-error semantics: bytes already flushed to w
//     remain visible if encoding fails partway through.
//   - You are composing with io.Copy, io.MultiWriter, or other writer patterns.
//
// For an in-memory string — for example to embed in another structure, feed a
// templating system, or return from an API handler — see Generate.
func (g *HybridGenerator) GenerateToWriter(
	ctx context.Context,
	w io.Writer,
	data *common.CommonDevice,
	opts Options,
) error {
	// Honor ctx at entry so a pre-canceled ctx aborts before any work is done.
	// Per-subsystem boundary checks are applied inside the format-specific
	// generators (e.g., between report body and audit section in markdown).
	// Full ctx propagation through the builder layer is deferred to v1.6.
	if err := ctx.Err(); err != nil {
		return err
	}

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

	// Post-validation boundary: cancellation between validation and dispatch.
	if err := ctx.Err(); err != nil {
		return err
	}

	return handler.GenerateToWriter(ctx, g, w, data, opts)
}

// generateMarkdown generates markdown output using the programmatic builder.
// Not safe for concurrent use — MarkdownBuilder is per-instance, not shared.
//
// ctx is checked at the per-subsystem boundary between report body composition
// and the compliance audit section append. The builder itself does not yet
// receive ctx — full propagation is deferred to v1.6.
func (g *HybridGenerator) generateMarkdown(
	ctx context.Context,
	data *common.CommonDevice,
	opts Options,
) (string, error) {
	g.logger.Debug("Using programmatic markdown generation")

	if g.builder == nil {
		return "", errors.New("no report builder available for programmatic generation")
	}

	g.builder.SetIncludeTunables(opts.IncludeTunables)
	g.builder.SetFailuresOnly(opts.FailuresOnly)
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

	// Per-subsystem boundary: between report body and audit section.
	if err := ctx.Err(); err != nil {
		return "", err
	}

	// Append audit section when compliance data is present. Use strings.Builder
	// with Grow() pre-sizing instead of += concatenation so we do not copy the
	// (potentially 2MB+) report body once per append (PERF-M7).
	if target.ComplianceResults != nil {
		auditSection := g.builder.BuildAuditSection(target)
		if auditSection != "" {
			var b strings.Builder
			b.Grow(len(report) + len(auditSectionSeparator) + len(auditSection))
			b.WriteString(report)
			b.WriteString(auditSectionSeparator)
			b.WriteString(auditSection)
			return b.String(), nil
		}
	}

	return report, nil
}

// generateMarkdownToWriter writes markdown output directly to the writer.
//
// ctx is checked at the per-subsystem boundary between report body composition
// and the compliance audit section append (in both the streaming and
// non-streaming fallback paths). The builder itself does not yet receive ctx —
// full propagation is deferred to v1.6.
func (g *HybridGenerator) generateMarkdownToWriter(
	ctx context.Context,
	w io.Writer,
	data *common.CommonDevice,
	opts Options,
) error {
	g.logger.Debug("Using streaming markdown generation")

	if g.builder == nil {
		return errors.New("no report builder available for programmatic generation")
	}

	g.builder.SetIncludeTunables(opts.IncludeTunables)
	g.builder.SetFailuresOnly(opts.FailuresOnly)
	target := prepareForExport(data, opts.Redact)

	// Check if builder supports SectionWriter interface for streaming
	sectionWriter, ok := g.builder.(builder.SectionWriter)
	if !ok {
		return g.generateMarkdownFallback(ctx, w, target, opts)
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

	// Per-subsystem boundary: between report body and audit section (streaming path).
	if err := ctx.Err(); err != nil {
		return err
	}

	// Append audit section when compliance data is present. Write the
	// separator and the audit body as two direct writes to w rather than
	// concatenating a new string first (PERF-M7).
	if target.ComplianceResults != nil {
		auditSection := g.builder.BuildAuditSection(target)
		if auditSection != "" {
			if _, writeErr := io.WriteString(w, auditSectionSeparator); writeErr != nil {
				return fmt.Errorf("failed to write audit section: %w", writeErr)
			}
			if _, writeErr := io.WriteString(w, auditSection); writeErr != nil {
				return fmt.Errorf("failed to write audit section: %w", writeErr)
			}
		}
	}

	return nil
}

// generateMarkdownFallback is the string-based (non-streaming) markdown path,
// taken when the configured builder does not implement SectionWriter. It
// composes the report body into a string via the builder and then streams the
// body + optional audit section to w to avoid += copies (PERF-M7). Extracted
// from generateMarkdownToWriter to keep the branching there shallow.
func (g *HybridGenerator) generateMarkdownFallback(
	ctx context.Context,
	w io.Writer,
	target *common.CommonDevice,
	opts Options,
) error {
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

	// Per-subsystem boundary: between report body and audit section (fallback path).
	if err := ctx.Err(); err != nil {
		return err
	}

	// Append audit section when compliance data is present.
	if target.ComplianceResults != nil {
		auditSection := g.builder.BuildAuditSection(target)
		if auditSection != "" {
			if _, writeErr := io.WriteString(w, output); writeErr != nil {
				return fmt.Errorf("failed to write report body: %w", writeErr)
			}
			if _, writeErr := io.WriteString(w, auditSectionSeparator); writeErr != nil {
				return fmt.Errorf("failed to write audit section separator: %w", writeErr)
			}
			if _, writeErr := io.WriteString(w, auditSection); writeErr != nil {
				return fmt.Errorf("failed to write audit section: %w", writeErr)
			}
			return nil
		}
	}

	if _, writeErr := io.WriteString(w, output); writeErr != nil {
		return fmt.Errorf("failed to write report body: %w", writeErr)
	}
	return nil
}

// generateJSON generates JSON output by serializing the model.
//
// ctx is checked between export preparation and marshaling — the
// per-subsystem boundary for JSON is coarse because marshaling is a
// single opaque encoding step.
func (g *HybridGenerator) generateJSON(ctx context.Context, data *common.CommonDevice, opts Options) (string, error) {
	g.logger.Debug("Generating JSON output")

	target := prepareForExport(data, opts.Redact)

	// Per-subsystem boundary: between export preparation and marshaling.
	if err := ctx.Err(); err != nil {
		return "", err
	}

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
func (g *HybridGenerator) generateJSONToWriter(
	ctx context.Context,
	w io.Writer,
	data *common.CommonDevice,
	opts Options,
) error {
	g.logger.Debug("Generating JSON output to writer")

	target := prepareForExport(data, opts.Redact)

	// Per-subsystem boundary: between export preparation and encoding.
	if err := ctx.Err(); err != nil {
		return err
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(target); err != nil {
		return fmt.Errorf("failed to encode JSON to writer: %w", err)
	}
	return nil
}

// generateYAML generates YAML output by serializing the model.
//
// ctx is checked between export preparation and marshaling.
func (g *HybridGenerator) generateYAML(ctx context.Context, data *common.CommonDevice, opts Options) (string, error) {
	g.logger.Debug("Generating YAML output")

	target := prepareForExport(data, opts.Redact)

	// Per-subsystem boundary: between export preparation and marshaling.
	if err := ctx.Err(); err != nil {
		return "", err
	}

	yamlData, err := yaml.Marshal(target)
	if err != nil {
		return "", fmt.Errorf("failed to marshal to YAML: %w", err)
	}
	return string(yamlData), nil
}

// generateYAMLToWriter writes YAML output directly to the writer.
// Note: YAML marshaling requires the full document, so this doesn't provide
// the same streaming benefits as markdown generation.
func (g *HybridGenerator) generateYAMLToWriter(
	ctx context.Context,
	w io.Writer,
	data *common.CommonDevice,
	opts Options,
) error {
	g.logger.Debug("Generating YAML output to writer")

	target := prepareForExport(data, opts.Redact)

	// Per-subsystem boundary: between export preparation and encoding.
	if err := ctx.Err(); err != nil {
		return err
	}

	encoder := yaml.NewEncoder(w)
	encoder.SetIndent(2) //nolint:mnd // Standard YAML indentation
	if err := encoder.Encode(target); err != nil {
		return fmt.Errorf("failed to encode YAML to writer: %w", err)
	}
	return encoder.Close()
}

// generatePlainText generates plain text output by rendering markdown first, then stripping formatting.
//
// ctx is threaded through generateMarkdown; an additional boundary is checked
// between markdown rendering and formatting stripping.
func (g *HybridGenerator) generatePlainText(
	ctx context.Context,
	data *common.CommonDevice,
	opts Options,
) (string, error) {
	g.logger.Debug("Generating plain text output")

	markdown, err := g.generateMarkdown(ctx, data, opts)
	if err != nil {
		return "", fmt.Errorf("failed to generate markdown for plain text conversion: %w", err)
	}

	// Per-subsystem boundary: between markdown rendering and strip-formatting.
	if err := ctx.Err(); err != nil {
		return "", err
	}

	return StripMarkdownFormatting(markdown)
}

// generatePlainTextToWriter writes plain text output directly to the writer.
func (g *HybridGenerator) generatePlainTextToWriter(
	ctx context.Context,
	w io.Writer,
	data *common.CommonDevice,
	opts Options,
) error {
	g.logger.Debug("Generating plain text output to writer")

	output, err := g.generatePlainText(ctx, data, opts)
	if err != nil {
		return err
	}

	_, err = io.WriteString(w, output)
	return err
}

// generateHTML generates HTML output by rendering markdown first, then converting via goldmark.
//
// ctx is threaded through generateMarkdown; an additional boundary is checked
// between markdown rendering and HTML conversion.
func (g *HybridGenerator) generateHTML(ctx context.Context, data *common.CommonDevice, opts Options) (string, error) {
	g.logger.Debug("Generating HTML output")

	markdown, err := g.generateMarkdown(ctx, data, opts)
	if err != nil {
		return "", fmt.Errorf("failed to generate markdown for HTML conversion: %w", err)
	}

	// Per-subsystem boundary: between markdown rendering and HTML conversion.
	if err := ctx.Err(); err != nil {
		return "", err
	}

	return RenderMarkdownToHTML(markdown)
}

// generateHTMLToWriter writes HTML output directly to the writer.
func (g *HybridGenerator) generateHTMLToWriter(
	ctx context.Context,
	w io.Writer,
	data *common.CommonDevice,
	opts Options,
) error {
	g.logger.Debug("Generating HTML output to writer")

	output, err := g.generateHTML(ctx, data, opts)
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
