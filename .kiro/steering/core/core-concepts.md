---
inclusion: always
---

# opnDossier Core Development Guidelines

**Project**: OPNsense configuration auditing tool for cybersecurity professionals
**Repository**: <https://github.com/EvilBit-Labs/opnDossier>
**Mission**: Transform OPNsense config.xml files into structured, actionable reports for blue/red team operations

## Critical Quality Gates

**MANDATORY before task completion:**

- `just ci-check` must pass completely
- `just test` must pass with >80% coverage
- All Go code formatted with `gofmt`
- No linting errors from `golangci-lint`

## Architecture Principles

### Core Philosophy

- **Operator-Focused**: Intuitive workflows for security professionals
- **Offline-First**: No external dependencies, works in airgapped environments
- **Structured Data**: Auditable, portable, versioned configuration data
- **Framework-First**: Use well-maintained third-party libraries and frameworks over custom implementations (e.g., use `lipgloss` for terminal styling, `glamour` for markdown rendering, `cobra` for CLI)

### Data Flow Pipeline

```text
XML Config → Parser → OpnSenseDocument → Processor → Audit Engine → Report Generator → Output
```

### Package Structure

- `cmd/`: CLI commands using Cobra framework
- `internal/model/`: Core data structures with strict XML tag mapping
- `internal/parser/`: XML parsing with `encoding/xml`
- `internal/audit/`: Plugin management and compliance checking
- `internal/plugins/`: Framework-specific compliance implementations

## Technology Stack

### Required Dependencies

- **CLI**: `cobra` v1.8.0 for command organization
- **Config**: `charmbracelet/fang` + `spf13/viper` for configuration
- **Terminal**: `charmbracelet/lipgloss` for styling, `charmbracelet/glamour` for markdown
- **XML**: `encoding/xml` (standard library) for OPNsense parsing
- **Logging**: `charmbracelet/log` for structured logging
- **Markdown**: `github.com/nao1215/markdown` for programmatic generation

### Forbidden Patterns

- No `fmt.Printf` for logging (use `charmbracelet/log`)
- No hardcoded secrets or credentials
- No external network dependencies
- No custom XML parsing (use `encoding/xml`)

## Code Standards

### Go Conventions

- Use `gofmt` with tabs for indentation
- Follow Go naming: `camelCase` variables, `PascalCase` types
- Always handle errors with context: `fmt.Errorf("context: %w", err)`
- Use structured logging: `log.Info("message", "key", value)`
- Write table-driven tests with `t.Parallel()` when safe

### Data Models

- **OpnSenseDocument**: Root configuration struct with strict XML tags
- **Finding**: Audit result with severity and recommendations
- **Target**: Network entity for security analysis
- **Exposure**: Potential security risk or vulnerability

## Report Generation

### Audience-Specific Output

- **Blue Team**: Compliance focus, clear grouping, actionable recommendations
- **Red Team**: Target prioritization, attack surface discovery, pivot points
- **Operations**: Technical details, configuration overview, system status

### Output Formats

- **Markdown**: Primary human-readable format using programmatic generation
- **JSON/YAML**: Machine-readable exports for integration
- **Terminal**: Styled output with `lipgloss` for interactive use

## Development Workflow

### Essential Commands

```bash
just format    # Format code and docs
just lint      # Static analysis
just test      # Run test suite
just ci-check  # Comprehensive validation (REQUIRED)
```

### Commit Standards

Follow conventional commits: `<type>(<scope>): <description>`

- **Types**: feat, fix, docs, style, refactor, test, chore
- **Scopes**: parser, converter, audit, cli, model, plugin
- **Description**: Imperative mood, lowercase, no period

### File Organization

- Review existing files before creating new ones
- Match established patterns and conventions
- Reuse utilities; avoid unnecessary dependencies
- Keep functions focused and testable

## Security Requirements

- **Input Validation**: Sanitize all user inputs
- **File Permissions**: Use restrictive permissions (0600 for configs)
- **Error Handling**: Don't expose sensitive data in error messages
- **Secure Defaults**: Default to secure configurations

## Plugin Architecture

### Compliance Plugins

- Implement `CompliancePlugin` interface
- Support STIG, SANS, CIS frameworks
- Return structured `Finding` objects
- Include severity levels and remediation guidance

### Extensibility

- Use interfaces for testability
- Registry pattern for plugin discovery
- Configuration-driven plugin selection
- Clear plugin metadata and versioning

## Performance Targets

- Handle 100MB configuration files
- Process 10,000+ rules in \<30 seconds
- Memory usage \<500MB for typical configs
- Startup time \<1 second

## Testing Strategy

- **Unit Tests**: >80% coverage with table-driven tests
- **Integration Tests**: End-to-end workflow validation
- **Performance Tests**: Benchmark critical paths
- **Race Detection**: Use `go test -race` for concurrency safety

## Documentation Requirements

- Godoc comments for all public APIs
- README with clear usage examples
- Architecture documentation maintenance
- Inline comments for complex business logic
