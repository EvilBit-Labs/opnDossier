# Processor Package

The `processor` package provides interfaces and types for processing OPNsense configurations. It enables flexible analysis of OPNsense configurations through an options pattern, allowing features like statistics generation, dead-rule detection, and other analyses to be enabled independently.

## Overview

The package defines a `Processor` interface that implementations can provide to analyze OPNsense configurations and generate comprehensive reports. The design follows Go best practices with:

- **Interface-based design**: The `Processor` interface allows for multiple implementations
- **Options pattern**: Flexible configuration using functional options
- **Context support**: Proper context handling for cancellation and timeouts
- **Multi-format output**: Reports can be exported as JSON, YAML, Markdown, or plain text summaries

## Core Processor Implementation

The `CoreProcessor` implements a comprehensive four-phase processing pipeline:

1. **Normalize**: Fill defaults, canonicalize IP/CIDR, sort slices for determinism
2. **Validate**: Use go-playground/validator and custom checks leveraging struct tags
3. **Analyze**: Dead rule detection, unused interfaces, consistency checks
4. **Transform**: Delegate to converter for markdown; marshal to JSON/YAML for other formats

### Normalization Features

- **Fill Defaults**: Populates missing values (system optimization: "normal", web GUI: "https", timezone: "UTC")
- **Canonicalize Addresses**: Standardizes IP addresses and converts single IPs to CIDR notation
- **Sort Slices**: Ensures deterministic output by sorting users, groups, rules, and sysctl items

### Analysis Capabilities

- **Dead Rule Detection**: Identifies unreachable rules after "block all" rules and duplicate rules
- **Unused Interface Analysis**: Finds enabled interfaces not used in rules or services
- **Consistency Checks**: Validates gateway configurations, DHCP settings, and user-group relationships
- **Security Analysis**: Detects insecure protocols, default SNMP community strings, overly permissive rules
- **Performance Analysis**: Identifies disabled hardware offloading and excessive rule counts

## Core Interface

```go
type Processor interface {
    Process(ctx context.Context, cfg *model.Opnsense, opts ...Option) (*Report, error)
}
```

The `Process` method analyzes an OPNsense configuration and returns a comprehensive report containing:

- Normalized configuration data
- Analysis findings categorized by severity
- Configuration statistics
- Multi-format output capabilities

## Features

The processor supports various analysis features that can be enabled through options:

- **Statistics Generation** (`WithStats()`): Generates configuration statistics
- **Dead Rule Detection** (`WithDeadRuleCheck()`): Analyzes for unused/dead firewall rules
- **Security Analysis** (`WithSecurityAnalysis()`): Performs security-related analysis
- **Performance Analysis** (`WithPerformanceAnalysis()`): Analyzes performance aspects
- **Compliance Checking** (`WithComplianceCheck()`): Checks compliance with best practices

## Usage Examples

### Basic Usage

```go
processor := NewExampleProcessor()
ctx := context.Background()

// Basic processing with default options (statistics enabled)
report, err := processor.Process(ctx, opnsenseConfig)
if err != nil {
    log.Fatal(err)
}

fmt.Println(report.Summary())
```

### Advanced Usage with Options

```go
processor := NewExampleProcessor()
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

// Enable specific analysis features
report, err := processor.Process(ctx, opnsenseConfig,
    WithStats(),
    WithSecurityAnalysis(),
    WithDeadRuleCheck(),
)
if err != nil {
    log.Fatal(err)
}

// Export as Markdown
markdown := report.ToMarkdown()
ioutil.WriteFile("report.md", []byte(markdown), 0644)

// Export as JSON
jsonStr, err := report.ToJSON()
if err != nil {
    log.Fatal(err)
}
ioutil.WriteFile("report.json", []byte(jsonStr), 0644)
```

### Enable All Features

```go
// Enable all available analysis features
report, err := processor.Process(ctx, opnsenseConfig, WithAllFeatures())
```

## Report Structure

The `Report` struct contains:

```go
type Report struct {
    GeneratedAt      time.Time       // When the report was generated
    ConfigInfo       ConfigInfo      // Basic configuration information
    NormalizedConfig *model.Opnsense // The processed configuration
    Statistics       *Statistics     // Configuration statistics (if enabled)
    Findings         Findings        // Analysis findings by severity
    ProcessorConfig  ProcessorConfig // Configuration used during processing
}
```

### Findings

Findings are categorized by severity:

- **Critical**: Issues requiring immediate attention
- **High**: High severity issues
- **Medium**: Medium severity issues
- **Low**: Low severity issues
- **Info**: Informational findings

Each finding contains:

- **Type**: Category (e.g., "security", "performance", "compliance")
- **Title**: Brief description
- **Description**: Detailed information
- **Recommendation**: Suggested remediation
- **Component**: Affected configuration component
- **Reference**: Additional documentation links

## Processor Workflow

The processor implements a comprehensive four-phase pipeline for analyzing OPNsense configurations:

```text
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Phase 1:      │    │   Phase 2:      │    │   Phase 3:      │    │   Phase 4:      │
│   NORMALIZE     │───▶│   VALIDATE      │───▶│   ANALYZE       │───▶│   TRANSFORM     │
│                 │    │                 │    │                 │    │                 │
│ • Fill defaults │    │ • Struct tags   │    │ • Dead rules    │    │ • Markdown      │
│ • Canonicalize  │    │ • Custom checks │    │ • Unused ifaces │    │ • JSON/YAML     │
│ • Sort for      │    │ • Cross-field   │    │ • Security scan │    │ • Plain text    │
│   determinism   │    │   validation    │    │ • Performance   │    │ • Export        │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Phase 1: Normalization

- **Fill Defaults**: Populates missing values (system optimization: "normal", web GUI: "https", timezone: "UTC")
- **Canonicalize Addresses**: Standardizes IP addresses and converts single IPs to CIDR notation
- **Sort Slices**: Ensures deterministic output by sorting users, groups, rules, and sysctl items

### Phase 2: Validation

- **Struct Tag Validation**: Uses go-playground/validator for field-level validation
- **Custom Business Logic**: Domain-specific validation rules
- **Cross-field Validation**: Validates relationships between configuration elements

### Phase 3: Analysis

- **Dead Rule Detection**: Identifies unreachable rules after "block all" rules and duplicate rules
- **Unused Interface Analysis**: Finds enabled interfaces not used in rules or services
- **Security Analysis**: Detects insecure protocols, default SNMP community strings, overly permissive rules
- **Performance Analysis**: Identifies disabled hardware offloading and excessive rule counts
- **Compliance Checking**: Validates against security and operational best practices

### Phase 4: Transform

- **Multi-format Output**: Generates Markdown, JSON, YAML, or plain text summaries
- **Structured Reports**: Organizes findings by severity (Critical, High, Medium, Low, Info)
- **Export Capabilities**: Saves to files or streams to stdout

## Configurable Analysis Options

The processor supports flexible configuration through functional options:

```go
// Enable specific analysis features
report, err := processor.Process(ctx, opnsenseConfig,
    WithStats(),
    WithSecurityAnalysis(),
    WithDeadRuleCheck(),
    WithPerformanceAnalysis(),
    WithComplianceCheck(),
)

// Or enable all features
report, err := processor.Process(ctx, opnsenseConfig, WithAllFeatures())
```

## Output Formats

Reports support multiple output formats:

### JSON Output

```go
jsonStr, err := report.ToJSON()
```

### Markdown Output

```go
markdown := report.ToMarkdown()
```

### Plain Text Summary

```go
summary := report.Summary()
```

## Implementation

The package includes an `ExampleProcessor` that provides a reference implementation with basic analysis capabilities:

- Basic configuration validation
- Security analysis (SSH, SNMP, web GUI protocol)
- Dead rule detection (rules without descriptions)
- Performance analysis (system optimization, hardware offloading)
- Compliance checking (administrative users, time synchronization)

## Extending the Processor

To create a custom processor implementation:

1. Implement the `Processor` interface
2. Handle the provided options in your implementation
3. Use the `Report` struct to structure your findings
4. Leverage the severity levels to categorize findings appropriately

```go
type CustomProcessor struct {
    // Your custom fields
}

func (p *CustomProcessor) Process(ctx context.Context, cfg *model.Opnsense, opts ...Option) (*Report, error) {
    // Apply options
    config := DefaultConfig()
    config.ApplyOptions(opts...)

    // Create report
    report := NewReport(cfg, *config)

    // Perform your custom analysis
    // ...

    return report, nil
}
```

## Testing

The package includes comprehensive tests demonstrating:

- Interface compliance
- Option handling
- Context cancellation
- Report generation and formatting
- Finding management

Run tests with:

```bash
go test -v ./internal/processor
```
