---
inclusion: always
---

# opnDossier AI Development Guidelines

## Critical Requirements

### Quality Gates (MANDATORY)

- **ALWAYS run `just ci-check`** before reporting task completion
- **Never commit without passing tests**: `just test` must pass
- **Follow Go conventions**: Use `gofmt`, proper error handling, structured logging
- **Validate markdown**: Use `mdformat` and `markdownlint-cli2` for all generated docs

### Code Standards

- **Error Handling**: Always use `fmt.Errorf` or `errors.Wrap` with context
- **Logging**: Use `charmbracelet/log` for structured logging, never `fmt.Printf`
- **Testing**: Write table-driven tests, aim for >80% coverage
- **Documentation**: Follow Go doc conventions for all public APIs

## Architecture Patterns

### Data Flow

```text
XML Config → Parser → Data Model → Processor → Audit Engine → Report Generator → Output
```

### Key Components

- **OpnSenseDocument**: Core configuration model with strict XML tag mapping
- **Plugin System**: Extensible compliance checking via interfaces
- **Report Generation**: Audience-specific formatting (ops/blue/red team)
- **Offline-First**: No external dependencies or network calls

### Package Organization

- `cmd/`: CLI commands using Cobra framework
- `internal/model/`: Core data structures with JSON/XML/YAML tags
- `internal/parser/`: XML parsing with `encoding/xml`
- `internal/audit/`: Plugin management and compliance checking
- `internal/plugins/`: Framework-specific compliance implementations

## Development Workflow

### Essential Commands

```bash
just format    # Format code and docs
just lint      # Static analysis
just test      # Run test suite
just ci-check  # Comprehensive validation (REQUIRED)
```

### Code Generation Rules

- **Minimal Dependencies**: Reuse existing utilities, avoid new dependencies
- **Type Safety**: Leverage Go's type system for compile-time guarantees
- **Immutable Data**: Prefer immutable structures where possible
- **Plugin Architecture**: Use interfaces for extensibility

## Report Generation Guidelines

### Audience-Specific Output

- **Blue Team**: Clarity, grouping, actionability, compliance focus
- **Red Team**: Target prioritization, pivot points, attack surface discovery
- **Operations**: Standard configuration overview with technical details

### Data Presentation

- **Structured Over Flat**: Prefer config data + audit overlays vs summary tables
- **Multiple Formats**: Support markdown, JSON, YAML export
- **Programmatic Markdown**: Use `github.com/nao1215/markdown` for type-safe generation

## Project Context

### Core Mission

OPNsense configuration auditing tool for cybersecurity professionals, supporting both defensive (blue team) and offensive (red team) security operations.

### Technology Stack

- **CLI**: Cobra v1.8.0 with Charm libraries for styling
- **Config**: Viper + Fang for configuration management
- **XML**: Native `encoding/xml` for OPNsense parsing
- **Output**: Lipgloss for terminal, Glamour for markdown rendering

### Compliance Frameworks

- Built-in support for STIG, SANS, CIS frameworks
- Extensible plugin system for custom compliance rules
- Framework-first approach leveraging established standards

## Implementation Checklist

Before submitting code:

- [ ] Code follows Go formatting standards (`gofmt`)
- [ ] All linting issues resolved (`golangci-lint`)
- [ ] Tests pass and coverage >80%
- [ ] Error handling includes proper context
- [ ] Structured logging for important operations
- [ ] No hardcoded secrets or credentials
- [ ] Input validation implemented
- [ ] Documentation updated for new features
- [ ] Dependencies properly managed (`go mod tidy`)
- [ ] Architecture patterns followed
- [ ] **`just ci-check` passes completely**

## Key Reference Documents

- **[requirements.md](project_spec/requirements.md)** - Complete functional requirements
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System design and data flow
- **[DEVELOPMENT_STANDARDS.md](DEVELOPMENT_STANDARDS.md)** - Go coding standards
