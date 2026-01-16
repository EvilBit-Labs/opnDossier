# opnDossier System Architecture

## Overview

opnDossier is a **CLI-based OPNsense configuration processor** designed with an **offline-first, operator-focused architecture**. The system transforms complex XML configuration files into human-readable markdown documentation, following security-first principles and air-gap compatibility.

![System Architecture](../dev-guide/opnDossier_System_Architecture.png)

## High-Level Architecture

### Core Design Principles

1. **Offline-First**: Zero external dependencies, complete air-gap compatibility
2. **Operator-Focused**: Built for network administrators and operators
3. **Framework-First**: Leverages established Go libraries (Cobra, Charm ecosystem)
4. **Structured Data**: Maintains configuration hierarchy and relationships
5. **Security-First**: No telemetry, input validation, secure processing

### Architecture Pattern

- **Monolithic CLI Application** with clear separation of concerns
- **Single Binary Distribution** for easy deployment
- **Local Processing Only** - no external network calls
- **Streaming Data Pipeline** from XML input to various output formats

### Technology Stack

Built with modern Go practices and established libraries:

| Component          | Technology                                                  |
| ------------------ | ----------------------------------------------------------- |
| CLI Framework      | [Cobra](https://github.com/spf13/cobra)                     |
| Configuration      | [Viper](https://github.com/spf13/viper)                     |
| CLI Enhancement    | [Charm Fang](https://github.com/charmbracelet/fang)         |
| Terminal Styling   | [Charm Lipgloss](https://github.com/charmbracelet/lipgloss) |
| Markdown Rendering | [Charm Glamour](https://github.com/charmbracelet/glamour)   |
| XML Processing     | Go's built-in `encoding/xml`                                |
| Structured Logging | [Charm Log](https://github.com/charmbracelet/log)           |

The CLI uses a layered architecture: **Cobra** provides command structure and argument parsing, **Viper** handles layered configuration management (files, env, flags), and **Fang** adds enhanced UX features like styled help, automatic version flags, and shell completion.

## Services and Components

### 1. CLI Interface Layer

- **Framework**: Cobra CLI
- **Responsibility**: Command parsing, user interaction, error handling
- **Key Files**: `cmd/root.go`, `cmd/opnsense.go`

### 2. Configuration Management

- **Framework**: spf13/viper
- **Sources**: CLI flags > Environment variables > Config file > Defaults
- **Format**: YAML configuration files
- **Precedence**: Standard order where environment variables override config files for deployment flexibility

### 3. Data Processing Engine

#### XML Parser Component

- **Technology**: Go's built-in `encoding/xml`
- **Input**: OPNsense config.xml files
- **Output**: Structured Go data types
- **Features**: Schema validation, error reporting

#### Data Converter Component

- **Input**: Parsed XML structures
- **Output**: Markdown content
- **Features**: Hierarchy preservation, metadata injection

#### Output Renderer Component

- **Formats**: Terminal display, Markdown files, JSON (planned)
- **Technologies**: Charm Lipgloss (styling) + Charm Glamour (rendering)

### 4. Output Systems

- **Terminal Display**: Syntax-highlighted, styled terminal output
- **File Export**: Markdown file generation with metadata
- **Future**: HTML, JSON, and other structured formats

## Data Model Architecture

opnDossier uses a hierarchical model structure that mirrors the OPNsense XML configuration while organizing functionality into logical domains:

```mermaid
graph TB
    subgraph "Root Configuration"
        ROOT[Opnsense Root]
        META[Metadata & Global Settings]
    end

    subgraph "System Domain"
        SYS[System Configuration]
        USERS[User Management]
        GROUPS[Group Management]
        SYSCFG[System Services Config]
    end

    subgraph "Network Domain"
        NET[Network Configuration]
        IFACES[Interface Management]
        ROUTING[Routing & Gateways]
        VLAN[VLAN Configuration]
    end

    subgraph "Security Domain"
        SEC[Security Configuration]
        FIREWALL[Firewall Rules]
        NAT[NAT Configuration]
        VPN[VPN Services]
        CERTS[Certificate Management]
    end

    subgraph "Services Domain"
        SVC[Services Configuration]
        DNS[DNS Services]
        DHCP[DHCP Services]
        MONITOR[Monitoring Services]
        WEB[Web Services]
    end

    ROOT --> META
    ROOT --> SYS
    ROOT --> NET
    ROOT --> SEC
    ROOT --> SVC

    SYS --> USERS
    SYS --> GROUPS
    SYS --> SYSCFG

    NET --> IFACES
    NET --> ROUTING
    NET --> VLAN

    SEC --> FIREWALL
    SEC --> NAT
    SEC --> VPN
    SEC --> CERTS

    SVC --> DNS
    SVC --> DHCP
    SVC --> MONITOR
    SVC --> WEB
```

This hierarchical structure provides:

- **Logical Organization**: Related configuration grouped by functional domain
- **Maintainability**: Easier to locate and modify specific configuration types
- **Extensibility**: New features can be added to appropriate domains
- **Validation**: Domain-specific validation rules improve data integrity
- **API Evolution**: JSON tags enable better REST API integration

## Data Flow Architecture

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant ConfigMgr as Config Manager
    participant Parser as XML Parser
    participant Converter
    participant Renderer
    participant Output

    User->>CLI: opndossier convert config.xml
    CLI->>ConfigMgr: Load configuration
    ConfigMgr-->>CLI: Configuration object
    CLI->>Parser: Parse XML file

    alt Valid XML
        Parser->>Parser: Validate structure
        Parser-->>CLI: Structured data
        CLI->>Converter: Transform data
        Converter-->>CLI: Markdown content
        CLI->>Renderer: Format output

        alt Terminal display
            Renderer->>Output: Styled terminal
            Output-->>User: Visual output
        else File export
            Renderer->>Output: Write file
            Output-->>User: Confirmation
        end
    else Invalid XML
        Parser-->>CLI: Error details
        CLI-->>User: Error message
    end
```

## Programmatic Generation Architecture (v2.0+)

### Evolution from Template-Based to Programmatic Generation

opnDossier v2.0 introduces a major architectural shift from template-based markdown generation to programmatic generation, delivering significant performance improvements and enhanced developer experience.

#### Previous Architecture (v1.x)

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant Parser as XML Parser
    participant TmplEngine as Template Engine
    participant TmplFiles as Template Files
    participant Renderer
    participant Output

    User->>CLI: opndossier convert config.xml
    CLI->>Parser: Parse XML file
    Parser-->>CLI: Structured data
    CLI->>TmplEngine: Load templates
    TmplEngine->>TmplFiles: Read template files
    TmplFiles-->>TmplEngine: Template content
    TmplEngine->>TmplEngine: Parse templates
    TmplEngine->>TmplEngine: Execute with data
    TmplEngine-->>CLI: Rendered content
    CLI->>Renderer: Format output
    Renderer->>Output: Final markdown
    Output-->>User: Generated report
```

#### New Architecture (v2.0+)

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant Parser as XML Parser
    participant Builder as MarkdownBuilder
    participant Methods as Go Methods
    participant Renderer
    participant Output

    User->>CLI: opndossier convert config.xml
    CLI->>Parser: Parse XML file
    Parser-->>CLI: Structured data
    CLI->>Builder: Create builder instance
    Builder->>Methods: Direct method calls
    Methods->>Methods: Type-safe operations
    Methods-->>Builder: Structured content
    Builder->>Renderer: Optimized string building
    Renderer->>Output: Final markdown
    Output-->>User: Generated report
```

### Key Architectural Improvements

#### 1. Elimination of Template Overhead

- **Before**: Parse templates → String interpolation → Variable resolution → Output generation
- **After**: Direct method calls → Structured building → Optimized output

#### 2. Performance Optimizations

The programmatic approach is designed for significant performance improvements:

- **Memory Usage**: Reduced allocations through direct string building
- **Generation Speed**: Faster generation via method-based approach
- **Throughput**: Increased reports per second
- **Scalability**: Consistent performance across all dataset sizes

Actual performance can be measured using comparative benchmarks in `internal/converter/markdown_bench_test.go`.

#### 3. Enhanced Type Safety

```mermaid
graph TB
    subgraph "Template Mode (v1.x)"
        T1[Template String] --> T2[Runtime Parsing]
        T2 --> T3[Variable Resolution]
        T3 --> T4[Silent Failures]
        T4 --> T5[Runtime Errors]
    end

    subgraph "Programmatic Mode (v2.0+)"
        P1[Go Methods] --> P2[Compile-time Validation]
        P2 --> P3[Type-safe Operations]
        P3 --> P4[Explicit Error Handling]
        P4 --> P5[Structured Results]
    end

    style T4 fill:#ff9999
    style T5 fill:#ff9999
    style P2 fill:#99ff99
    style P3 fill:#99ff99
    style P4 fill:#99ff99
```

#### 4. Security Enhancements (Red Team Focus)

- **Output Obfuscation**: Built-in capabilities for sensitive data handling
- **Complete Offline Support**: No external template dependencies
- **Memory Safety**: Improved handling of large configurations
- **Error Isolation**: Structured error handling prevents information leakage

### MarkdownBuilder Component Architecture

```mermaid
classDiagram
    class ReportBuilder {
        <<interface>>
        +BuildStandardReport(data) string
        +BuildCustomReport(data, options) string
        +BuildSystemSection(data) string
        +BuildNetworkSection(data) string
        +BuildSecuritySection(data) string
        +BuildServicesSection(data) string
    }

    class MarkdownBuilder {
        -config *OpnSenseDocument
        -options BuildOptions
        -logger *Logger
        +CalculateSecurityScore(data) int
        +AssessRiskLevel(severity) string
        +FilterSystemTunables(tunables, filter) []SysctlItem
        +GroupServicesByStatus(services) map[string][]Service
        +FormatInterfaceLinks(interfaces) string
        +EscapeMarkdownSpecialChars(input) string
    }

    class SecurityAssessor {
        +CalculateSecurityScore(data) int
        +AssessRiskLevel(severity) string
        +AssessServiceRisk(service) string
        +DetermineSecurityZone(interface) string
    }

    class DataTransformer {
        +FilterSystemTunables(tunables, filter) []SysctlItem
        +GroupServicesByStatus(services) map[string][]Service
        +FormatSystemStats(data) map[string]interface{}
    }

    class StringFormatter {
        +EscapeMarkdownSpecialChars(input) string
        +FormatTimestamp(timestamp) string
        +TruncateDescription(text, length) string
        +FormatBoolean(value) string
    }

    ReportBuilder <|.. MarkdownBuilder
    MarkdownBuilder o-- SecurityAssessor
    MarkdownBuilder o-- DataTransformer
    MarkdownBuilder o-- StringFormatter
```

### Data Flow Pipeline (Programmatic Mode)

```mermaid
graph TD
    subgraph "Input Processing"
        XML[OPNsense XML] --> Parser[Enhanced Parser]
        Parser --> Model[Structured Model]
    end

    subgraph "Programmatic Generation Engine"
        Model --> Builder[MarkdownBuilder]
        Builder --> Security[SecurityAssessor]
        Builder --> Transform[DataTransformer]
        Builder --> Format[StringFormatter]

        Security --> Methods[Method-Based Generation]
        Transform --> Methods
        Format --> Methods
    end

    subgraph "Output Optimization"
        Methods --> StringBuild[Optimized String Building]
        StringBuild --> Render[Direct Rendering]
        Render --> Output[Markdown Output]
    end

    subgraph "Performance Characteristics"
        Metrics[Performance Metrics<br/>• Faster generation<br/>• Reduced memory<br/>• Increased throughput<br/>• Type-safe operations]
    end

    Output -.-> Metrics

    style Builder fill:#99ff99,stroke:#333,stroke-width:4px
    style Methods fill:#99ff99,stroke:#333,stroke-width:2px
    style StringBuild fill:#99ff99,stroke:#333,stroke-width:2px
```

### Hybrid Architecture Support

To ensure smooth migration, v2.0 supports both template and programmatic modes:

```mermaid
graph TB
    subgraph "Hybrid Architecture"
        Input[User Input] --> Decision{Generation Mode?}

        Decision -->|--use-template| TemplatePath[Template Mode]
        Decision -->|Default| ProgPath[Programmatic Mode]

        TemplatePath --> TemplateEngine[Template Engine]
        ProgPath --> MarkdownBuilder[MarkdownBuilder]

        TemplateEngine --> Output[Markdown Output]
        MarkdownBuilder --> Output
    end

    subgraph "Migration Support"
        Compare[Output Comparison]
        Validate[Validation Engine]
        Fallback[Fallback Mechanism]
    end

    Output --> Compare
    Compare --> Validate
    Validate --> Fallback

    style ProgPath fill:#99ff99,stroke:#333,stroke-width:2px
    style MarkdownBuilder fill:#99ff99,stroke:#333,stroke-width:2px
```

### Method Categories and Performance

#### Security Assessment Methods

- **CalculateSecurityScore**: 1.59M operations/sec
- **AssessRiskLevel**: 92M operations/sec
- **AssessServiceRisk**: High-frequency assessment capability

#### Data Transformation Methods

- **FilterSystemTunables**: 797K operations/sec
- **GroupServicesByStatus**: 1.01M operations/sec
- **FormatSystemStats**: Optimized for large datasets

#### String Utility Methods

- **EscapeMarkdownSpecialChars**: Ultra-fast character processing
- **FormatTimestamp**: Efficient time formatting
- **TruncateDescription**: Word-boundary aware truncation

#### Section Builders

- **BuildSystemSection**: 1.7K operations/sec (comprehensive sections)
- **BuildNetworkSection**: 6.7K operations/sec
- **BuildSecuritySection**: 5.1K operations/sec
- **BuildServicesSection**: 13K operations/sec

### Memory Management Architecture

```mermaid
graph LR
    subgraph "Template Mode (v1.x)"
        T1[Template Files] --> T2[Template Parsing]
        T2 --> T3[Variable Context]
        T3 --> T4[String Interpolation]
        T4 --> T5[8.80MB Memory]
        T5 --> T6[93,984 Allocations]
    end

    subgraph "Programmatic Mode (v2.0+)"
        P1[Direct Methods] --> P2[Structured Building]
        P2 --> P3[Pre-allocated Buffers]
        P3 --> P4[Optimized Strings]
        P4 --> P5[1.97MB Memory]
        P5 --> P6[39,585 Allocations]
    end

    style T5 fill:#ff9999
    style T6 fill:#ff9999
    style P5 fill:#99ff99
    style P6 fill:#99ff99
```

### Error Handling Architecture

#### Template Mode Error Handling

- Silent failures with default values
- Runtime template parsing errors
- Difficult debugging and troubleshooting
- Generic error messages

#### Programmatic Mode Error Handling

```go
// Structured error types
type ValidationError struct {
    Field   string
    Value   any
    Message string
}

type GenerationError struct {
    Component string
    Operation string
    Cause     error
}

// Context-aware error handling
func (b *MarkdownBuilder) BuildSection(data *model.OpnSenseDocument) (string, error) {
    if err := b.validateInput(data); err != nil {
        return "", &ValidationError{
            Field:   "input_data",
            Value:   data,
            Message: fmt.Sprintf("invalid input: %v", err),
        }
    }

    result, err := b.generateContent(data)
    if err != nil {
        return "", &GenerationError{
            Component: "section_builder",
            Operation: "content_generation",
            Cause:     err,
        }
    }

    return result, nil
}
```

## Data Storage Strategy

### Local File System

- **Configuration**: `~/.opnDossier.yaml` (user preferences)
- **Input**: OPNsense XML files (any location)
- **Output**: Markdown files (user-specified or current directory)

### Memory Management

- **Structured Data**: Go structs with XML/JSON tags
- **Large Files**: Streaming processing for memory efficiency
- **Type Safety**: Strong typing throughout the pipeline

### No Persistent Storage

- **Stateless Operation**: Each run is independent
- **No Database**: All data flows through memory
- **Temporary Files**: Cleaned up automatically

## External Integrations

### Documentation System

- **Technology**: MkDocs with Material theme
- **Purpose**: Static documentation generation
- **Deployment**: Local development server, no runtime dependencies

### Package Distribution

- **Build System**: GoReleaser for multi-platform builds
- **Platforms**: Linux, macOS, Windows (amd64, arm64)
- **Distribution**: GitHub Releases, package managers, direct download
- **Formats**: Binary archives, system packages (deb, rpm, apk)

### Development Integration

- **CI/CD**: GitHub Actions
- **Quality**: golangci-lint, pre-commit hooks
- **Testing**: Go's built-in testing framework
- **Task Runner**: Just for development workflows

## Air-Gap/Offline Considerations

### Design for Isolation

```mermaid
graph LR
    subgraph "Air-Gapped Environment"
        subgraph "Secure Network"
            FW[OPNsense Firewall]
            OPS[Operator Workstation]
            DOCS[Documentation Server]
        end

        subgraph "opnDossier Application"
            BIN[Single Binary]
            CFG[Local Config]
            TEMP[Templates]
        end
    end

    FW -->|config.xml| OPS
    OPS -->|Executes| BIN
    BIN -->|Uses| CFG
    BIN -->|Uses| TEMP
    BIN -->|Generates| DOCS
```

### Offline Capabilities

1. **Zero External Dependencies**: All libraries embedded in binary
2. **No Network Calls**: Completely self-contained operation
3. **Portable Deployment**: Single binary, no installation required
4. **Data Exchange**: File-based import/export only

### Data Exchange Patterns

- **Import**: Local files, USB drives, network shares
- **Export**: Markdown, JSON, plain text
- **Transfer**: Standard file transfer protocols (SCP, SFTP, etc.)

## Versioned Data Strategy

### Configuration Versioning

- **Backward Compatibility**: Support for older OPNsense versions
- **Forward Compatibility**: Graceful handling of newer configurations
- **Version Detection**: Automatic OPNsense version identification
- **Migration Support**: Utilities for format changes

### Non-Destructive Processing

- **Original Preservation**: Input files never modified
- **Timestamped Outputs**: Version metadata in all outputs
- **Audit Trail**: Change tracking and diff generation
- **Rollback Support**: Easy reversion to previous states

### Schema Evolution

```mermaid
graph TB
    subgraph "Version Management"
        V1[OPNsense v1.x<br/>Basic features]
        V2[OPNsense v2.x<br/>Enhanced features]
        V3[OPNsense v3.x<br/>Latest features]
    end

    subgraph "Compatibility Layer"
        COMPAT[Version Handler]
        MIGRATE[Migration Engine]
        VALIDATE[Schema Validator]
    end

    subgraph "Processing Pipeline"
        PARSER[XML Parser]
        CONVERTER[Data Converter]
        RENDERER[Output Renderer]
    end

    V1 --> COMPAT
    V2 --> COMPAT
    V3 --> COMPAT

    COMPAT --> VALIDATE
    COMPAT --> MIGRATE
    MIGRATE --> PARSER
    VALIDATE --> PARSER

    PARSER --> CONVERTER
    CONVERTER --> RENDERER
```

## Security Architecture

### Threat Model

- **Primary Threats**: Malicious XML files, path traversal, resource exhaustion
- **Not Addressed**: Network attacks (offline operation), privilege escalation (user-level tool)

### Security Controls

- **Input Validation**: XML schema validation, path sanitization, size limits
- **Processing Security**: Memory safety (Go runtime), type safety, error handling
- **Output Security**: Path validation, permission checks, content sanitization

### Air-Gap Security Benefits

- **No Network Attack Surface**: Offline operation eliminates network-based threats
- **No Data Exfiltration**: Local processing only
- **No Unauthorized Updates**: Manual deployment only
- **Audit-Friendly**: All operations are local and traceable

## Deployment Patterns

### Single Binary Distribution

- **Build**: Cross-compiled Go binary
- **Size**: Minimal footprint (~10-20MB)
- **Dependencies**: None (all embedded)
- **Installation**: Drop-in replacement, no setup required

### Multi-Platform Support

- **Operating Systems**: Linux, macOS, Windows
- **Architectures**: amd64, arm64
- **Special**: macOS universal binaries
- **Packages**: Native package formats for each platform

### Enterprise Deployment

- **Package Management**: APT, RPM, Homebrew integration
- **Code Signing**: Verified binaries for security
- **Bulk Deployment**: Network share or USB distribution
- **Configuration Management**: YAML-based configuration

---

## Quick Start Architecture Summary

1. **User provides** OPNsense config.xml file
2. **CLI parses** command-line arguments and loads configuration
3. **XML Parser** validates and structures the input data
4. **Data Converter** transforms XML to markdown with metadata
5. **Output Renderer** formats for terminal display or file export
6. **User receives** human-readable documentation

**Key Benefits**: Offline operation, security-first design, operator-focused workflows, cross-platform compatibility, and comprehensive documentation generation from complex network configurations.

For detailed architecture information, see the [complete architecture documentation](docs/dev-guide/architecture.md).
