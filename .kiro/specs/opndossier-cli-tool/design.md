# Design Document

## Overview

opnDossier v2.0 is architected as a high-performance, security-focused CLI tool that transforms OPNsense XML configurations into actionable reports for cybersecurity professionals. The system employs a modern programmatic generation architecture with plugin-based compliance checking, multi-mode reporting capabilities, and complete offline operation.

## Architecture

### High-Level System Architecture

The v2.0 system follows a layered architecture pattern with programmatic generation at its core:

```
┌─────────────────────────────────────────────────────────────┐
│                    CLI Interface Layer                      │
│  (Cobra Framework + Fang Enhancement + Configuration)      │
├─────────────────────────────────────────────────────────────┤
│                  Business Logic Layer                      │
│  ┌─────────────┬─────────────┬─────────────┬─────────────┐  │
│  │   Parser    │  Processor  │   Audit     │ Programmatic│  │
│  │   Engine    │   Engine    │   Engine    │  Generator  │  │
│  └─────────────┴─────────────┴─────────────┴─────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                   Data Model Layer                         │
│  (Structured Go Types + Enrichment + Validation)          │
├─────────────────────────────────────────────────────────────┤
│                  Infrastructure Layer                      │
│  (File I/O + Display + Export + Logging + Metrics)        │
└─────────────────────────────────────────────────────────────┘
```

### Core Design Principles

1. **Programmatic-First**: Go-based generation for performance and type safety
2. **Offline-First**: Complete functionality without external dependencies
3. **Security-First**: Input validation, secure defaults, no telemetry
4. **Performance-First**: Optimized memory usage and concurrent processing
5. **Operator-Focused**: Intuitive workflows for security professionals

### Data Flow Pipeline

```
XML Input → Validation → Parsing → Enrichment → Processing → Audit Analysis → Programmatic Generation → Output
```

## Components and Interfaces

### 1. CLI Interface Layer

**Primary Components:**

- **Command Router** (`cmd/`): Cobra-based command structure with convert, display, and audit commands
- **Configuration Manager** (`internal/config/`): Viper-based configuration with precedence handling
- **CLI Enhancement** (`charmbracelet/fang`): Styled help, errors, and automatic features

**Key Interfaces:**

```go
type CommandHandler interface {
    Execute(ctx context.Context, args []string) error
    Validate(args []string) error
    GetHelp() string
}

type ConfigurationManager interface {
    LoadConfig() (*Config, error)
    GetPrecedence() []string // CLI flags > env vars > config file > defaults
    ValidateConfig(*Config) error
}
```

### 2. Parser Engine

**Primary Components:**

- **XML Parser** (`internal/parser/`): Streaming XML processing with validation
- **Schema Validator** (`internal/validator/`): OPNsense schema compliance checking
- **Error Handler**: Contextual error reporting with line/column information

**Key Interfaces:**

```go
type XMLParser interface {
    Parse(reader io.Reader) (*model.OpnSenseDocument, error)
    ValidateSchema(data []byte) error
    GetParsingErrors() []ParseError
}

type SchemaValidator interface {
    Validate(doc *model.OpnSenseDocument) []ValidationError
    GetSupportedVersions() []string
}
```

### 3. Data Model Layer

**Primary Components:**

- **Core Models** (`internal/model/`): Structured Go types with XML/JSON tags
- **Enrichment Engine** (`internal/model/enrichment.go`): Calculated fields and derived data
- **Completeness Analyzer** (`internal/model/completeness.go`): Configuration coverage analysis

**Key Data Structures:**

```go
type OpnSenseDocument struct {
    System      SystemConfig      `xml:"system" json:"system"`
    Interfaces  InterfaceConfig   `xml:"interfaces" json:"interfaces"`
    Firewall    FirewallConfig    `xml:"filter" json:"firewall"`
    NAT         NATConfig         `xml:"nat" json:"nat"`
    Services    ServicesConfig    `xml:"services" json:"services"`
    // Enriched fields
    Statistics  ConfigStatistics  `json:"statistics,omitempty"`
    Analysis    SecurityAnalysis  `json:"analysis,omitempty"`
}
```

### 4. Processing Engine

**Primary Components:**

- **Core Processor** (`internal/processor/`): Main processing orchestration
- **Data Transformer**: Configuration normalization and transformation
- **Analysis Engine**: Security and performance analysis

**Key Interfaces:**

```go
type Processor interface {
    Process(doc *model.OpnSenseDocument) (*ProcessedConfig, error)
    Analyze(config *ProcessedConfig) (*AnalysisResult, error)
    Transform(data interface{}) (interface{}, error)
}
```

### 5. Audit Engine

**Primary Components:**

- **Plugin Manager** (`internal/audit/plugin_manager.go`): Plugin lifecycle management
- **Mode Controller** (`internal/audit/mode_controller.go`): Multi-mode report coordination
- **Compliance Plugins** (`internal/plugins/`): STIG, SANS, security benchmark implementations

**Key Interfaces:**

```go
type CompliancePlugin interface {
    Name() string
    Version() string
    Check(config *model.OpnSenseDocument) []Finding
    GetMetadata() PluginMetadata
    Configure(options map[string]interface{}) error
}

type AuditEngine interface {
    RegisterPlugin(plugin CompliancePlugin) error
    RunAudit(config *model.OpnSenseDocument, mode AuditMode) (*AuditReport, error)
    GetAvailablePlugins() []PluginInfo
}
```

### 6. Programmatic Generation Engine (v2.0 Core Architecture)

**Primary Components:**

- **MarkdownBuilder** (`internal/markdown/generator.go`): High-performance Go-based generation
- **Security Assessor**: Built-in security analysis and scoring
- **Data Transformer**: Optimized data transformation utilities
- **String Formatter**: Type-safe string formatting and escaping

**Key Interfaces:**

```go
type ReportGenerator interface {
    GenerateReport(data *model.OpnSenseDocument, options GenerationOptions) (string, error)
    GetSupportedFormats() []string
    BuildSection(sectionType SectionType, data interface{}) (string, error)
}

type MarkdownBuilder interface {
    BuildStandardReport(data *model.OpnSenseDocument) (string, error)
    BuildAuditReport(data *model.OpnSenseDocument, findings []Finding, mode AuditMode) (string, error)
    BuildSystemSection(data *model.OpnSenseDocument) (string, error)
    BuildNetworkSection(data *model.OpnSenseDocument) (string, error)
    BuildSecuritySection(data *model.OpnSenseDocument) (string, error)
}
```

**Performance Characteristics:**

- **Generation Speed**: 74% faster than template-based approach
- **Memory Usage**: 78% reduction in memory consumption
- **Throughput**: 3.8x increase (643 vs 170 reports/sec)
- **Type Safety**: Compile-time validation of all generation logic

### 7. Output System

**Primary Components:**

- **Display Engine** (`internal/display/`): Terminal rendering with Charm Glamour
- **Export Engine** (`internal/export/`): Multi-format file export
- **Theme Manager** (`internal/display/theme.go`): Light/dark theme support

**Key Interfaces:**

```go
type DisplayRenderer interface {
    RenderToTerminal(content string, options DisplayOptions) error
    DetectTheme() Theme
    SupportsPaging() bool
}

type FileExporter interface {
    ExportMarkdown(content string, path string) error
    ExportJSON(data interface{}, path string) error
    ExportYAML(data interface{}, path string) error
    ValidateOutput(path string, format OutputFormat) error
}
```

## Data Models

### Core Configuration Model

The system uses a hierarchical data model that mirrors OPNsense's XML structure while adding enrichment capabilities:

```go
type OpnSenseDocument struct {
    // Core configuration sections
    System      SystemConfig      `xml:"system" json:"system"`
    Interfaces  InterfaceConfig   `xml:"interfaces" json:"interfaces"`
    Firewall    FirewallConfig    `xml:"filter" json:"firewall"`
    NAT         NATConfig         `xml:"nat" json:"nat"`
    Services    ServicesConfig    `xml:"services" json:"services"`
    Certificates CertConfig       `xml:"cert" json:"certificates"`
    VPN         VPNConfig         `xml:"openvpn,ipsec" json:"vpn"`

    // Enriched analysis data
    Statistics  ConfigStatistics  `json:"statistics,omitempty"`
    Analysis    SecurityAnalysis  `json:"analysis,omitempty"`
    Completeness CompletionStatus `json:"completeness,omitempty"`
}
```

### Audit Finding Model

Consistent structure across all audit modes:

```go
type Finding struct {
    ID           string            `json:"id"`
    Title        string            `json:"title"`
    Severity     SeverityLevel     `json:"severity"`
    Description  string            `json:"description"`
    Recommendation string          `json:"recommendation"`
    Tags         []string          `json:"tags"`

    // Red team specific fields
    AttackSurface  *AttackSurface  `json:"attack_surface,omitempty"`
    ExploitNotes   *ExploitNotes   `json:"exploit_notes,omitempty"`

    // Blue team specific fields
    ComplianceRefs []ComplianceRef `json:"compliance_refs,omitempty"`
    Remediation    *Remediation    `json:"remediation,omitempty"`
}
```

### Plugin Architecture Model

```go
type PluginMetadata struct {
    Name         string            `json:"name"`
    Version      string            `json:"version"`
    Description  string            `json:"description"`
    Author       string            `json:"author"`
    Framework    string            `json:"framework"` // STIG, SANS, security benchmarks, etc.
    Dependencies []string          `json:"dependencies"`
    Configuration map[string]interface{} `json:"configuration"`
}
```

## Error Handling

### Structured Error System

The system implements comprehensive error handling with context preservation:

```go
type OpnDossierError struct {
    Code      ErrorCode     `json:"code"`
    Message   string        `json:"message"`
    Context   ErrorContext  `json:"context"`
    Cause     error         `json:"cause,omitempty"`
    Timestamp time.Time     `json:"timestamp"`
}

type ErrorContext struct {
    Component string                 `json:"component"`
    Operation string                 `json:"operation"`
    File      string                 `json:"file,omitempty"`
    Line      int                    `json:"line,omitempty"`
    Data      map[string]interface{} `json:"data,omitempty"`
}
```

### Error Categories

1. **Validation Errors**: Input validation failures with specific field information
2. **Parsing Errors**: XML parsing issues with line/column details
3. **Processing Errors**: Business logic failures with context
4. **Plugin Errors**: Plugin-specific failures with plugin information
5. **Export Errors**: File I/O and format-specific errors

## Testing Strategy

### Multi-Layer Testing Approach

1. **Unit Tests**: Individual component testing with >80% coverage target
2. **Integration Tests**: End-to-end workflow validation
3. **Performance Tests**: Benchmarking critical paths with regression detection
4. **Security Tests**: Input validation and security boundary testing
5. **Compatibility Tests**: Cross-platform and OPNsense version testing

### Test Organization

```text
tests/
├── unit/           # Component-level tests
├── integration/    # End-to-end workflow tests
├── performance/    # Benchmark and performance tests
├── security/       # Security boundary tests
├── fixtures/       # Test data and configurations
└── helpers/        # Test utilities and mocks
```

### Quality Gates

- All tests must pass before merge
- Coverage must exceed 80% for new code
- Performance benchmarks must not regress
- Security tests must validate all input boundaries
- Cross-platform compatibility must be verified

### Programmatic Generation Testing

The v2.0 architecture enables superior testing capabilities:

```go
func TestMarkdownBuilder_BuildSystemSection(t *testing.T) {
    builder := NewMarkdownBuilder()

    // Type-safe test data
    testData := &model.OpnSenseDocument{
        System: model.SystemConfig{
            Hostname: "test-firewall",
            Domain:   "example.com",
        },
    }

    // Direct method testing
    result, err := builder.BuildSystemSection(testData)

    // Compile-time validated assertions
    assert.NoError(t, err)
    assert.Contains(t, result, "# System Configuration")
    assert.Contains(t, result, "test-firewall.example.com")
}
```

## Security Considerations

### Threat Model

**Primary Threats Addressed:**

- Malicious XML input files
- Path traversal attacks
- Resource exhaustion attacks
- Information disclosure through error messages

**Security Controls:**

1. **Input Validation**:

   - XML schema validation
   - File path sanitization
   - Size and complexity limits
   - Character encoding validation

2. **Processing Security**:

   - Memory safety through Go runtime
   - Type safety throughout pipeline
   - Structured error handling
   - Resource usage monitoring

3. **Output Security**:

   - Path validation for exports
   - Content sanitization
   - Permission checks
   - Sensitive data filtering

### Programmatic Generation Security Benefits

The v2.0 architecture provides enhanced security:

- **No Template Injection**: Eliminates template-based attack vectors
- **Type Safety**: Compile-time validation prevents runtime vulnerabilities
- **Memory Safety**: Optimized memory management reduces DoS risks
- **Error Isolation**: Structured error handling prevents information leakage

## Performance Optimization

### Programmatic Generation Performance

The v2.0 architecture delivers significant performance improvements:

```go
// Optimized MarkdownBuilder with pre-allocated buffers
type MarkdownBuilder struct {
    buffer    strings.Builder
    config    *model.OpnSenseDocument
    options   BuildOptions
    allocPool sync.Pool // Pre-allocated buffers for reuse
}

// High-performance section building
func (b *MarkdownBuilder) BuildSystemSection(data *model.OpnSenseDocument) (string, error) {
    // Direct method calls - no template parsing overhead
    b.buffer.Reset()
    b.writeSystemHeader(data.System)
    b.writeSystemDetails(data.System)
    b.writeSystemStatistics(data.Statistics)
    return b.buffer.String(), nil
}
```

**Performance Metrics:**

- **Generation Speed**: 74% faster than template-based approach
- **Memory Usage**: 78% reduction (1.97MB vs 8.80MB)
- **Throughput**: 3.8x increase (643 vs 170 reports/sec)
- **Allocations**: 58% fewer allocations (39,585 vs 93,984)

### Memory Management

```go
// Streaming XML processing for large files
func (p *XMLParser) ParseStream(reader io.Reader) (*model.OpnSenseDocument, error) {
    decoder := xml.NewDecoder(reader)
    decoder.CharsetReader = charset.NewReaderLabel

    // Process in chunks to minimize memory usage
    for {
        token, err := decoder.Token()
        if err == io.EOF {
            break
        }
        // Process token without loading entire document
    }
}
```

### Concurrent Processing

- **I/O Operations**: Goroutines for file operations
- **Plugin Execution**: Concurrent compliance checking
- **Report Generation**: Parallel section building
- **Export Operations**: Concurrent multi-format export

## Deployment Architecture

### Single Binary Distribution

- **Build**: Cross-compiled Go binary with embedded assets
- **Size**: Optimized footprint (~15-25MB)
- **Dependencies**: None (all embedded)
- **Installation**: Drop-in deployment, no setup required

### Multi-Platform Support

- **Operating Systems**: Linux, macOS, Windows
- **Architectures**: amd64, arm64, 386
- **Special Features**: macOS universal binaries, Windows code signing
- **Package Formats**: Native packages for each platform

### Configuration Management

- **Precedence**: CLI flags > Environment variables > Config file > Defaults
- **Environment Variables**: `OPNDOSSIER_*` prefix for all settings
- **Config Files**: YAML format with comprehensive validation
- **Override Support**: Runtime configuration changes via CLI flags

This v2.0 design provides a robust, secure, and high-performance foundation for the opnDossier CLI tool, leveraging programmatic generation for superior performance, maintainability, and type safety while maintaining the flexibility needed for diverse cybersecurity workflows.
