# Markdown Builder API Reference

## Overview

The MarkdownBuilder provides a programmatic interface for generating reports from OPNsense configurations. All methods are designed for offline usage.

For the full internal Go API reference including parser, config, and export packages, see the [Developer Guide API Reference](development/api.md).

## Core Interfaces

### ReportBuilder

Defined in `internal/converter/builder/builder.go` (key methods shown; see source for full interface):

```go
type ReportBuilder interface {
    BuildStandardReport(data *common.CommonDevice) (string, error)
    BuildComprehensiveReport(data *common.CommonDevice) (string, error)
    BuildSystemSection(data *common.CommonDevice) string
    BuildNetworkSection(data *common.CommonDevice) string
    BuildSecuritySection(data *common.CommonDevice) string
    BuildServicesSection(data *common.CommonDevice) string
    // Plus ~15 Write*Table methods for individual components
}
```

### Generator and StreamingGenerator

Defined in `internal/converter/hybrid_generator.go`:

```go
type Generator interface {
    Generate(ctx context.Context, cfg *common.CommonDevice, opts Options) (string, error)
}

type StreamingGenerator interface {
    Generator
    GenerateToWriter(ctx context.Context, w io.Writer, cfg *common.CommonDevice, opts Options) error
}
```

## Security Assessment Functions

Standalone functions in `internal/converter/formatters/`:

```go
// Calculate an overall security score (0-100)
formatters.CalculateSecurityScore(data *common.CommonDevice) int

// Convert severity strings to risk level labels
formatters.AssessRiskLevel(severity string) string

// Evaluate security risk for a named service
formatters.AssessServiceRisk(serviceName string) string

// Filter tunables (true = include all, false = security-relevant only)
formatters.FilterSystemTunables(tunables []common.SysctlItem, includeTunables bool) []common.SysctlItem
```

## Parser API

The preferred entry point is `ParserFactory` in `internal/model/factory.go`, which auto-detects the device type and returns a `common.CommonDevice`:

```go
factory := model.NewParserFactory()

// Auto-detect device type and parse
device, err := factory.CreateDevice(ctx, reader, "", false)

// With validation
device, err := factory.CreateDevice(ctx, reader, "", true)
```

The underlying XML parser (`internal/cfgparser/XMLParser`) supports UTF-8, US-ASCII, ISO-8859-1, and Windows-1252 encodings. Input is limited to 10MB by default (`DefaultMaxInputSize`).

## Converter API

The converter in `internal/converter/` provides format-specific converters:

```go
// Markdown conversion
converter := converter.NewMarkdownConverter()
markdown, err := converter.ToMarkdown(ctx, device)

// JSON conversion (redact=true replaces sensitive fields with [REDACTED])
jsonConverter := converter.NewJSONConverter()
jsonStr, err := jsonConverter.ToJSON(ctx, device, false)

// YAML conversion (redact=true replaces sensitive fields with [REDACTED])
yamlConverter := converter.NewYAMLConverter()
yamlStr, err := yamlConverter.ToYAML(ctx, device, false)
```

## Error Handling

The codebase uses sentinel errors for expected conditions:

```go
// cfgparser package
var ErrMissingOpnSenseDocumentRoot = errors.New("invalid XML: missing opnsense root element")

// converter package
var ErrNilDevice = errors.New("device configuration is nil")
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

- [Developer Guide API Reference](development/api.md) - Full internal API documentation
- [Data Model & Integration](templates/index.md) - JSON/YAML export examples
- [Architecture](development/architecture.md) - System architecture
