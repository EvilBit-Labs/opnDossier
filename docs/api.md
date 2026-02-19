# Markdown Builder API Reference

## Overview

The MarkdownBuilder provides a programmatic interface for generating reports from OPNsense configurations. All methods are designed for offline usage.

For the full internal Go API reference including parser, config, and export packages, see the [Developer Guide API Reference](dev-guide/api.md).

## Core Interfaces

### ReportBuilder

Defined in `internal/converter/builder/builder.go` (key methods shown; see source for full interface):

```go
type ReportBuilder interface {
    BuildStandardReport(data *model.OpnSenseDocument) (string, error)
    BuildComprehensiveReport(data *model.OpnSenseDocument) (string, error)
    BuildSystemSection(data *model.OpnSenseDocument) string
    BuildNetworkSection(data *model.OpnSenseDocument) string
    BuildSecuritySection(data *model.OpnSenseDocument) string
    BuildServicesSection(data *model.OpnSenseDocument) string
    // Plus ~15 Write*Table methods for individual components
}
```

### Generator and StreamingGenerator

Defined in `internal/converter/hybrid_generator.go`:

```go
type Generator interface {
    Generate(ctx context.Context, cfg *model.OpnSenseDocument, opts Options) (string, error)
}

type StreamingGenerator interface {
    Generator
    GenerateToWriter(ctx context.Context, w io.Writer, cfg *model.OpnSenseDocument, opts Options) error
}
```

## Security Assessment Functions

Standalone functions in `internal/converter/formatters/`:

```go
// Calculate an overall security score (0-100)
formatters.CalculateSecurityScore(doc *model.OpnSenseDocument) int

// Convert severity strings to risk level labels
formatters.AssessRiskLevel(severity string) string

// Evaluate security risk for a service
formatters.AssessServiceRisk(service model.Service) string

// Filter tunables (true = include all, false = security-relevant only)
formatters.FilterSystemTunables(tunables []model.SysctlItem, includeTunables bool) []model.SysctlItem

// Group services by running/stopped status
formatters.GroupServicesByStatus(services []model.Service) map[string][]model.Service
```

## Parser API

The XML parser is in `internal/cfgparser/`:

```go
// Create a new parser
parser := cfgparser.NewXMLParser()

// Parse from an io.Reader
doc, err := parser.Parse(ctx, reader)

// Validate the parsed document
err := parser.Validate(doc)
```

The parser supports UTF-8, US-ASCII, ISO-8859-1, and Windows-1252 encodings. Input is limited to 10MB by default (`DefaultMaxInputSize`).

## Converter API

The converter in `internal/converter/` provides format-specific converters:

```go
// Markdown conversion
converter := converter.NewMarkdownConverter()
markdown, err := converter.ToMarkdown(ctx, doc)

// JSON conversion
jsonConverter := converter.NewJSONConverter()
jsonStr, err := jsonConverter.ToJSON(ctx, doc)

// YAML conversion
yamlConverter := converter.NewYAMLConverter()
yamlStr, err := yamlConverter.ToYAML(ctx, doc)
```

## Error Handling

The codebase uses sentinel errors for expected conditions:

```go
// cfgparser package
var ErrMissingOpnSenseDocumentRoot = errors.New("invalid XML: missing opnsense root element")

// converter package
var ErrNilOpnSenseDocument = errors.New("input OpnSenseDocument struct is nil")
```

All errors are wrapped with context using `fmt.Errorf("context: %w", err)`.

## Performance

Performance benchmarks are available in `internal/converter/markdown_bench_test.go`. Run them with:

```bash
just bench-perf
```

## Thread Safety

The `MarkdownBuilder` is safe for concurrent use in read-only operations. See AGENTS.md section 5.6 for thread safety patterns used in the codebase.

## Related Documentation

- [Developer Guide API Reference](dev-guide/api.md) - Full internal API documentation
- [Data Model & Integration](templates/index.md) - JSON/YAML export examples
- [Architecture](development/architecture.md) - System architecture
