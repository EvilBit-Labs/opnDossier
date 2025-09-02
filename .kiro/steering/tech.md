# Technical Architecture and Standards

## Technology Stack

### Core Technologies

- **Language**: Go 1.21+ for performance, cross-platform support, and strong typing
- **CLI Framework**: Cobra v1.8.0 for command organization and user experience
- **Configuration**: Viper for configuration management with Fang for styled help
- **XML Processing**: Native `encoding/xml` for OPNsense configuration parsing
- **Output Styling**: Charm libraries (lipgloss, glamour, log) for terminal experience

### Key Dependencies

```go
// Core CLI and Configuration
github.com/spf13/cobra v1.8.0
github.com/spf13/viper
github.com/charmbracelet/fang

// Terminal and Output
github.com/charmbracelet/lipgloss
github.com/charmbracelet/glamour
github.com/charmbracelet/log

// Programmatic Markdown Generation
github.com/nao1215/markdown v0.8.0  // Compile-time checked markdown generation

// Data Processing
encoding/xml (standard library)
encoding/json (standard library)
gopkg.in/yaml.v3
```

## Architectural Patterns

### Command Pattern

- Clean separation between CLI commands and business logic
- Each command focuses on a single responsibility
- Consistent error handling and user feedback across commands

### Plugin Architecture

- Extensible compliance checking through plugin system
- Interface-based design for easy testing and extension
- Registry pattern for plugin discovery and management

### Data Processing Pipeline

```text
XML Config → Parser → Data Model → Processor → Audit Engine → Report Generator → Output
```

### Layered Architecture

```text
├── CLI Layer (cmd/)           # User interface and command handling
├── Business Logic (internal/) # Core application logic
│   ├── audit/                # Compliance checking and plugin management
│   ├── converter/            # Data transformation
│   ├── parser/               # XML parsing and validation
│   └── model/                # Data structures and types
└── Infrastructure            # External concerns (file I/O, logging)
```

## Data Models

### Core Structures

- **OpnSenseDocument**: Root configuration representation
- **Finding**: Audit result with severity and recommendations
- **Target**: Network entity for security analysis
- **Exposure**: Potential security risk or vulnerability

### Design Principles

- **Immutable Data**: Prefer immutable structures where possible
- **Type Safety**: Leverage Go's type system for compile-time guarantees
- **JSON/XML Tags**: Consistent serialization across formats
- **Validation**: Built-in validation methods for data integrity

## Markdown Generation

Uses `github.com/nao1215/markdown` for **programmatic markdown generation** with compile-time safety instead of templates. This ensures markdown structure is validated at compile time, provides type safety, and eliminates runtime template errors.

## Performance Requirements

### Scalability Targets

- Handle configuration files up to 100MB
- Process complex rulesets (10,000+ rules) in \<30 seconds
- Memory usage \<500MB for typical configurations
- Startup time \<1 second for CLI responsiveness

### Optimization Strategies

- Streaming XML parsing for large files
- Concurrent processing where safe
- Memory-efficient data structures
- Lazy loading of optional components

## Security Considerations

### Data Protection

- No network communication (offline-first)
- Secure file handling with proper permissions
- Input validation and sanitization
- No secrets in configuration or logs

### Code Security

- Static analysis with golangci-lint
- Dependency scanning and vulnerability assessment
- Secure coding practices and error handling
- Regular security updates for dependencies

## Testing Strategy

### Test Types

- **Unit Tests**: Individual component testing with >80% coverage
- **Integration Tests**: End-to-end workflow validation
- **Table-Driven Tests**: Comprehensive scenario coverage
- **Performance Tests**: Benchmarking critical paths

### Test Organization

```text
├── *_test.go              # Unit tests alongside source
├── testdata/              # Test fixtures and sample data
└── integration_test.go    # Integration test suite
```

### Quality Gates

- All tests must pass before merge
- Race condition detection with `go test -race`
- Coverage reporting and trend analysis
- Performance regression detection

## Build and Deployment

### Build System

- **Task Runner**: Just for development workflow automation
- **Cross-Platform**: Support for macOS, Windows, Linux
- **Release Management**: GoReleaser v2 for automated releases
- **Dependency Management**: Go modules with version pinning

### CI/CD Pipeline

```bash
# Development workflow
just format    # Code formatting
just lint      # Static analysis
just test      # Test execution
just ci-check  # Comprehensive validation
```

### Distribution

- Single binary distribution
- No external runtime dependencies
- Semantic versioning with conventional commits
- Automated release notes and changelog generation

## Code Quality Standards

### Go Conventions

- Standard Go formatting with `gofmt`
- Effective Go guidelines compliance
- Idiomatic Go patterns and practices
- Comprehensive error handling with context

### Documentation Requirements

- Godoc comments for all public APIs
- README with clear usage examples
- Architecture documentation maintenance
- Inline comments for complex logic

### Linting and Analysis

- golangci-lint with comprehensive rule set
- Custom linting rules for project-specific patterns
- Dependency vulnerability scanning
- Code complexity analysis

## Extensibility Design

### Plugin Interface

```go
type CompliancePlugin interface {
    Name() string
    Check(config *model.OpnSenseDocument) []Finding
    Metadata() PluginMetadata
}
```

### Configuration Extension

- YAML-based plugin configuration
- Runtime plugin discovery and loading
- Configurable severity levels and rules
- Custom report templates and formats

## Monitoring and Observability

### Logging Strategy

- Structured logging with charmbracelet/log
- Configurable log levels (debug, info, warn, error)
- Context-aware logging with operation tracing
- No sensitive data in logs

### Error Handling

- Comprehensive error context preservation
- User-friendly error messages
- Graceful degradation for non-critical failures
- Detailed error reporting for debugging

## Future Technical Considerations

### Scalability Enhancements

- Distributed processing for large-scale audits
- Caching layer for repeated operations
- Database backend for audit history
- API layer for integration with other tools

### Technology Evolution

- Go version compatibility strategy
- Dependency update and security patching
- Performance optimization opportunities
- New output format support
