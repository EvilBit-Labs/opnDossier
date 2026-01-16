# GitHub Copilot Instructions for opnDossier

This file provides guidance to GitHub Copilot when working with code in this repository.

**AGENTS.md is the single source of truth** for AI assistant behavior, development workflows, and architecture. This file provides Copilot-specific guidance derived from AGENTS.md.

## Rule Precedence (CRITICAL)

**Rules are applied in the following order of precedence:**

1. **Project-specific rules** (from AGENTS.md or .cursor/rules/)
2. **General development standards**
3. **Language-specific style guides** (Go conventions, etc.)

When rules conflict, always follow the rule with higher precedence.

## Project Overview

opnDossier is a tool for auditing and reporting on OPNsense configurations, with the primary goal of generating markdown views derived from OPNsense config.xml files. This project follows EvilBit Labs standards and is built for operators, by operators.

### Core Philosophy

- **Operator-Focused**: Build intuitive, efficient tools for end users
- **Offline-First**: Must operate in fully offline or airgapped environments with no external dependencies
- **Structured Data**: Data should be structured, versioned, and portable for auditable, actionable systems
- **Framework-First**: Leverage built-in functionality of established frameworks; avoid custom solutions

### EvilBit Labs Brand Principles

- **Trust the Operator**: Full control, no black boxes
- **Polish Over Scale**: Quality over feature-bloat
- **Offline First**: Built for where the internet isn't
- **Sane Defaults**: Clean outputs, CLI help that's actually helpful
- **Ethical Constraints**: No dark patterns, spyware, or telemetry

## Project Architecture & Data Flow

- **Monolithic Go CLI**: Converts OPNsense `config.xml` to Markdown, JSON, or YAML. No external network calls - offline-first.

- **Major Components**:

  - `cmd/`: CLI entrypoints (`convert`, `display`, `validate`). See `cmd/root.go` for command registration.
  - `internal/parser/`: XML parsing to Go structs (`OpnSenseDocument` in `internal/model/opnsense.go`).
  - `internal/model/`: Strict data models mirroring OPNsense config structure.
  - `internal/processor/`: Normalization, validation, analysis, and transformation pipeline.
  - `internal/converter/`, `internal/markdown/`: Multi-format export (Markdown, JSON, YAML) using templates and options.
  - `internal/audit/`, `internal/plugin/`, `internal/plugins/`: Compliance audit engine and plugin system (STIG, SANS, firewall).
  - `internal/display/`, `internal/log/`: Terminal output and structured logging.

- **Data Flow**: `parser` → `model` → `processor` → `converter`/`markdown` → `export`

- **Audit overlays**: `processor` → `audit` → `plugins`

## Technology Stack

| Layer             | Technology                                     |
| ----------------- | ---------------------------------------------- |
| **CLI Framework** | `cobra` v1.8.0 for command organization        |
| **Configuration** | `charmbracelet/fang` + `spf13/viper`           |
| **Styling**       | `charmbracelet/lipgloss` for terminal output   |
| **Markdown**      | `charmbracelet/glamour` for rendering          |
| **XML Parsing**   | `encoding/xml` for OPNsense config files       |
| **Logging**       | `charmbracelet/log` for structured logging     |
| **Data Formats**  | Support for XML, JSON, and YAML export formats |
| **Go Version**    | Minimum 1.21.6+, Recommended 1.24.5+           |

## Critical Workflows

- **All development tasks use `just`** (see `justfile`):
  - `just install` - install dependencies
  - `just build` - build binary
  - `just test` - run all tests
  - `just lint` - run golangci-lint
  - `just ci-check` - run full CI-equivalent checks (must pass before reporting success)
  - `just format` - format code and documentation
  - `just dev` - run in development mode
- **No external dependencies**: All code must run fully offline.
- **Never commit code without explicit user permission.**

## Go Coding Standards

### Code Style and Formatting

- **Tools**: `gofmt` (with tabs), `golangci-lint`, `go vet`, `go test -race`
- **Naming Conventions**:
  - **Packages**: `snake_case` or single word, lowercase
  - **Variables/functions**: `camelCase` for private, `PascalCase` for exported
  - **Constants**: `camelCase` for private, `PascalCase` for exported (avoid `ALL_CAPS`)
  - **Types**: `PascalCase`
  - **Interfaces**: `PascalCase` ending with `-er` when appropriate
  - **Receivers**: Use consistent single-letter names (e.g., `c *Config`)

### Error Handling

- Always check errors and provide meaningful context using `fmt.Errorf` with `%w` for error wrapping
- Create domain-specific error types (ValidationError, ProcessingError)
- Use `errors.Is()` and `errors.As()` for error type checking
- Handle errors gracefully in CLI commands with user-friendly messages

**Example Pattern**:

```go
// Always wrap errors with context
if err != nil {
    return fmt.Errorf("failed to parse config: %w", err)
}

// Use domain-specific error types
type ValidationError struct {
    Field string
    Value interface{}
    Err   error
}
```

### Testing Standards

- **Framework**: Go's built-in `testing` package
- **Test Organization**: Place tests in `*_test.go` files in same package
- **Test Names**: `TestFunctionName_Scenario_ExpectedResult`
- **Coverage Target**: >80% for critical business logic
- **Types**: Unit tests, integration tests (with `//go:build integration` tag), table-driven tests
- **Performance**: Keep tests fast (\<100ms), use `t.Parallel()` when safe
- **Helpers**: Use `t.Helper()` in helper functions
- Use table-driven tests for multiple scenarios
- Test both success and error conditions

### Structured Logging

**Pattern**: Use `charmbracelet/log` for structured logging with appropriate levels

```go
// Use charmbracelet/log with context
logger.Info("parsing configuration", "filename", filename, "size", size)
logger.Error("parse failed", "error", err, "filename", filename)
```

**Guidelines**:

- Include context in log messages (filename, operation, duration, counts)
- Use debug level for troubleshooting, info for operations, warn for issues, error for failures
- Avoid logging sensitive information from configuration
- For CI / `TERM=dumb` environments, keep logs readable and avoid over-styled output

### Configuration Management

**Note for AI Assistants**: `viper` is used for managing the opnDossier application's own configuration (CLI settings, display preferences, etc.), not for parsing OPNsense config.xml files. The OPNsense configuration parsing is handled separately by the XML parser in `internal/parser/`.

**Pattern**: Use `spf13/viper` for configuration with precedence: CLI flags > Environment variables > Config file > Defaults

## Data Model Standards

### Core Data Models

- **OpnSenseDocument**: Core model representing entire OPNsense configuration
- **XML Tags**: Must strictly follow OPNsense configuration file structure
- **JSON/YAML Tags**: Follow recommended best practices for each format
- **Audit-Oriented Modeling**: Create internal structs (`Finding`, `Target`, `Exposure`) separately from config structs

### Multi-Format Export

- **Purpose**: Export OPNsense configurations to markdown, JSON, or YAML formats
- **Usage**: `opndossier convert config.xml --format [markdown|json|yaml]`
- **File Quality**: Exported files must be valid and parseable by standard tools
- **Output Control**: Smart file naming with overwrite protection and `-f` force option

### Report Generation

- **Presentation-Aware Output**: Format and prioritize data based on audience (ops/blue/red)
- Blue team reports: favor clarity, grouping, and actionability
- Red team reports: favor target prioritization and pivot surface discovery
- Always prefer structured config data + audit overlays over flat summary tables

## Security Requirements

### Code Security

- **No Secrets in Code**: Never hardcode API keys, passwords, or sensitive data
- **Environment Variables**: Use environment variables or secure vaults for secrets
- **Input Validation**: Always validate and sanitize user inputs and file paths
- **Secure Defaults**: Default to secure configurations
- **File Permissions**: Use restrictive permissions (0600 for config files)
- **Error Messages**: Avoid exposing sensitive information in error messages

### Operational Security

- **Offline-First**: Systems must function without internet connectivity
- **No Telemetry**: No tracking, no phoning home, no external data collection
- **Portable Data**: Support import/export of data bundles
- **Airgap Compatible**: Full functionality in isolated environments

## Project-Specific Conventions

- **Rule Precedence**: See [AGENTS.md](../AGENTS.md) for canonical rule precedence and always defer to the project root for authoritative standards
- **Config Management**: Use `internal/config` and `spf13/viper` for CLI/app config (NOT for OPNsense XML parsing)
- **Validation System**: Automatically applied during parsing, can be explicitly initiated via CLI
- **Commit Messages**: Must follow Conventional Commits (`<type>(<scope>): <description>`)

## CI/CD Integration Standards

### Conventional Commits

All commit messages must follow the [Conventional Commits](https://www.conventionalcommits.org) specification:

- **Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`
- **Scopes**: `(parser)`, `(converter)`, `(audit)`, `(cli)`, `(model)`, `(plugin)`, `(templates)`, etc.
- **Format**: `<type>(<scope>): <description>`
- **Breaking Changes**: Indicated with `!` in the header (e.g., `feat(api)!: redesign plugin interface`)
- **Examples**:
  - `feat(parser): add support for OPNsense 24.1 config format`
  - `fix(converter): handle empty VLAN configurations gracefully`
  - `docs(readme): update installation instructions`

### Quality Gates

- **Branch Protection**: Strict linting, testing, and security gates
- **Pre-commit Hooks**: Automated formatting, linting, and basic validation
- **CI Pipeline**: Comprehensive testing across multiple Go versions and platforms
- **Security Scanning**: Regular dependency auditing and vulnerability assessment

## Integration & Plugin Patterns

- **Audit Plugins**: Implement `CompliancePlugin` interface (`internal/plugin/interfaces.go`). Register in `internal/audit/plugin_manager.go`.
- **Plugin Structure**: Place in `internal/plugins/{standard}/`. Use generic `Finding` struct - no compliance-specific fields.
- **Multi-Format Export**: Add new formats in `internal/converter/` and templates in `internal/templates/`.

## Project Structure

```text
opndossier/
├── cmd/              # Command entry points (convert, display, validate, root)
├── internal/         # Private application logic
│   ├── parser/       # XML parsing logic
│   ├── model/        # Data models and structures
│   ├── processor/    # Data processing and analysis
│   ├── converter/    # Data conversion utilities
│   ├── markdown/     # Markdown generation
│   ├── display/      # Terminal display formatting
│   ├── export/       # File export functionality
│   ├── audit/        # Audit engine and compliance checking
│   └── validator/    # Configuration validation
├── project_spec/     # Requirements, tasks, user stories
└── docs/             # Documentation
```

## Key Files & References

- `AGENTS.md`, `docs/development/standards.md`, `docs/development/architecture.md`, `project_spec/requirements.md`
- `cmd/convert.go`, `internal/model/opnsense.go`, `internal/parser/xml.go`, `internal/processor/README.md`

## Example Patterns

**CLI Command**:

```go
var convertCmd = &cobra.Command{
    Use:   "convert [file]",
    Short: "Convert OPNsense config to multiple formats",
    RunE:  runConvert,
}
```

**Plugin Interface**:

```go
type CompliancePlugin interface {
    Name() string
    RunChecks(config *model.OpnSenseDocument) []Finding
    // ...
}
```

## AI Assistant Guidelines

### Development Rules of Engagement

- **TERM=dumb Support**: Ensure terminal output respects `TERM="dumb"` environment variable for CI/automation
- **CodeRabbit.ai Integration**: Prefer coderabbit.ai for code review over GitHub Copilot auto-reviews
- **Single Maintainer Workflow**: Configure for single maintainer (UncleSp1d3r) with no second reviewer requirement
- **No Auto-commits**: Never commit code on behalf of maintainer without explicit permission

### Assistant Behavior Rules

- **Clarity and Precision**: Be direct, professional, and context-aware in all interactions
- **Adherence to Standards**: Strictly follow the defined rules for code style and project structure
- **Tool Usage**: Use `just` for task execution, `go` commands for Go development
- **Focus on Value**: Enhance the project's unique value proposition as an OPNsense configuration auditing tool
- **Respect Documentation**: Always consult and follow project documentation before making changes

### Code Generation Requirements

- Generated code must conform to all established patterns
- Include comprehensive error handling with context preservation
- Follow architectural patterns (Command, Strategy, Builder where appropriate)
- Include appropriate documentation and testing
- Use proper type safety through Go's type system

## Common Commands and Workflows

### Development Commands

```bash
# Primary development workflow
just dev                 # Run in development mode
just install            # Install dependencies and setup environment
just build              # Complete build with all checks

# Code quality
just format             # Format code and documentation
just lint               # Run linting and static analysis
just check              # Run pre-commit hooks and comprehensive checks
just ci-check           # Run CI-equivalent checks locally

# Testing
just test               # Run the full test suite
go test ./...           # Run tests directly
go test -race ./...     # Run tests with race detection
go test -cover ./...    # Run tests with coverage

# Maintenance
go mod tidy             # Clean up dependencies
go mod verify           # Verify dependencies
just docs               # Serve documentation locally (if available)
```

### Usage Examples

```bash
# Primary use cases - Convert OPNsense configurations
./opndossier convert config.xml --format markdown
./opndossier convert config.xml --format json -o output.json
./opndossier convert config.xml --format yaml --force

# Display configuration information
./opndossier display config.xml

# Validate configuration
./opndossier validate config.xml

# Run with audit plugins
./opndossier convert config.xml --audit stig,sans
```

## AI Agent Mandatory Practices

When AI agents contribute to this project, they **MUST**:

01. **Always run tests** after making changes: `just test`
02. **Run linting** before committing: `just lint`
03. **Follow the established patterns** shown in existing code
04. **Use the preferred tooling commands** (see justfile)
05. **Write comprehensive tests** for new functionality
06. **Include proper error handling** with context
07. **Add structured logging** for important operations
08. **Validate all inputs** and handle edge cases
09. **Document new functions and types** following Go conventions
10. **Never commit secrets** or hardcoded credentials
11. **Consult project documentation** - requirements.md, docs/development/architecture.md, and docs/development/standards.md for guidance
12. When rendering reports, always prefer structured config data + audit overlays over flat summary tables
13. Blue team output should favor clarity, grouping, and actionability. Red team output should favor target prioritization and pivot surface discovery
14. Validate all generated markdown for formatting correctness using mdformat for formatting and markdownlint-cli2 for validation
15. **CRITICAL: Tasks are NOT considered complete until `just ci-check` passes**

## AI Agent Code Review Checklist

Before suggesting code completion or marking a task complete, AI agents **MUST** verify:

- [ ] Code follows Go formatting standards (`gofmt`, `goimports`)
- [ ] All linting issues resolved (`golangci-lint`)
- [ ] Tests pass (`go test ./...` or `just test`)
- [ ] Error handling includes proper context with `%w` wrapping
- [ ] Logging uses structured format with `charmbracelet/log` and appropriate levels
- [ ] No hardcoded secrets or credentials
- [ ] Input validation implemented where needed (especially file paths and XML input)
- [ ] Documentation updated for new features or changed behavior
- [ ] Dependencies properly managed (`go mod tidy`, `go mod verify`)
- [ ] Code follows established patterns and interfaces (parser/model/processor/audit/converter layering)
- [ ] Requirements compliance verified against `project_spec/requirements.md`
- [ ] Architecture patterns followed per `docs/development/architecture.md` and related docs
- [ ] Development standards adhered to per `docs/development/standards.md`
- [ ] Use `just` for all dev tasks
- [ ] Run `just ci-check` before reporting success (CRITICAL)
- [ ] Follow established code/data patterns
- [ ] Never add external dependencies
- [ ] Tests included for new functionality

## Development Process

### Pre-Development

1. **Review Requirements**: Understand specific requirements being implemented
2. **Check Existing Code**: Review similar implementations for patterns
3. **Verify Architecture**: Ensure changes follow docs/development/architecture.md patterns

### Implementation

1. **Implement Changes**: Follow established patterns and conventions
2. **Write Tests**: Create comprehensive test coverage
3. **Update Documentation**: Update relevant documentation files

### Quality Assurance

```bash
# Format and lint
just format
just lint

# Run tests
just test

# Comprehensive validation
just ci-check
```

## Issue Resolution

When encountering problems:

- Identify the specific issue clearly
- Explain the problem in ≤ 5 lines
- Propose a concrete path forward
- Don't proceed without resolving blockers

## Key Documentation References

AI agents **MUST** familiarize themselves with:

- **[requirements.md](project_spec/requirements.md)** - Complete functional and technical requirements
- **[docs/development/architecture.md](docs/development/architecture.md)** - System design, data flow, and component architecture
- **[docs/development/standards.md](docs/development/standards.md)** - Go-specific coding standards and project structure
- **[AGENTS.md](../AGENTS.md)** - Complete AI agent development guidelines (single source of truth)

**Remember**: When in doubt, refer to AGENTS.md for the complete authoritative guidance. This file provides Copilot-specific quick reference derived from that source.
