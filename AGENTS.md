# AI Agent Coding Standards and Project Structure

This document outlines the preferred coding standards, architectural principles, and development workflows for the opnDossier project.

## 📚 Related Documentation

For comprehensive project information, refer to these key documents:

- **[Requirements Document](project_spec/requirements.md)** - Complete project requirements, functional specifications, and technical constraints
- **[System Architecture](ARCHITECTURE.md)** - Detailed system design, component interactions, and deployment patterns
- **[Development Standards](DEVELOPMENT_STANDARDS.md)** - Go-specific coding standards, project structure, and development workflow

These documents provide the foundation for all development decisions and should be consulted when implementing new features or making architectural changes.

## New Features: Multi-Format Export and Validation

The latest version introduces comprehensive multi-format export and validation features:

### Multi-Format Export

- **Purpose**: Export OPNsense configurations to markdown, JSON, or YAML formats
- **Usage**: `opndossier convert config.xml --format [markdown|json|yaml]`
- **File Quality**: Exported files are valid and parseable by standard tools and libraries
- **Output Control**: Smart file naming with overwrite protection and `-f` force option

### Validation System

- **Purpose**: Enhances configuration integrity by validating against rules and constraints
- **Usage**: Automatically applied during parsing, or can be explicitly initiated via CLI
- **Typical Output**: See README for detailed examples
- **Limitations**: Handles large configurations using streamlined memory-efficient approaches

## Rule Precedence

**CRITICAL - Rules are applied in the following order of precedence:**

1. **Project-specific rules** (from project root instruction files like AGENTS.md or .cursor/rules/)
2. **General development standards** (outlined in this document)
3. **Language-specific style guides** (Go conventions, etc.)

When rules conflict, always follow the rule with higher precedence.

## 1. Core Philosophy

- **Operator-Focused:** Build tools for operators, by operators. Workflows should be intuitive and efficient for the end-user.
- **Offline-First:** Systems should be designed to operate in fully offline or airgapped environments. This means no external dependencies, no telemetry, and support for data exchange via portable bundles.
- **Structured Data:** Data should be structured, versioned, and portable. This enables auditable, actionable, and reliable systems.
- **Framework-First:** Leverage the built-in functionality of established frameworks and libraries. Avoid custom solutions when a well-established, predictable one already exists.

### 1.1. EvilBit Labs Brand Principles

- **Trust the Operator:** Full control, no black boxes
- **Polish Over Scale:** Quality over feature-bloat
- **Offline First:** Built for where the internet isn't
- **Sane Defaults:** Clean outputs, CLI help that's actually helpful
- **Ethical Constraints:** No dark patterns, spyware, or telemetry

## 2. Shared Development Standards

### 2.1. Security Principles

- **No Secrets in Code:** Never hardcode API keys, passwords, or sensitive data in source code
- **Environment Variables:** Use environment variables or secure vaults for configuration secrets
- **Input Validation:** Always validate and sanitize user inputs
- **Secure Defaults:** Default to secure configurations

### 2.2. Offline-First Architecture

- **No External Dependencies:** Systems must function without internet connectivity
- **Portable Data Exchange:** Support import/export of data bundles
- **Local Processing:** All operations should work locally
- **Airgap Compatible:** Full functionality in isolated environments

### 2.3. CI/CD Integration Standards

#### Conventional Commits

All commit messages must follow the [Conventional Commits](https://www.conventionalcommits.org) specification:

- **Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`
- **Scopes:** `(parser)`, `(converter)`, `(audit)`, `(cli)`, `(model)`, `(plugin)`, `(templates)`, etc.
- **Format:** `<type>(<scope>): <description>`
- **Breaking Changes:** Indicated with `!` in the header (e.g., `feat(api)!: redesign plugin interface`)
- **Examples:**
  - `feat(parser): add support for OPNsense 24.1 config format`
  - `fix(converter): handle empty VLAN configurations gracefully`
  - `docs(readme): update installation instructions`

#### Quality Gates

- **Branch Protection:** Strict linting, testing, and security gates
- **Pre-commit Hooks:** Automated formatting, linting, and basic validation
- **CI Pipeline:** Comprehensive testing across multiple Go versions and platforms
- **Security Scanning:** Regular dependency auditing and vulnerability assessment

### 2.4. Data Processing

- **Data Model:** The data model OpnSenseDocument is the core data model representing the entire OPNsense configuration and requires the xml tags to strictly follow the OPNsense configuration file structure. JSON and YAML tags should follow recommended best practices for each format.
- **Audit-Oriented Modeling:** Create internal structs (`Finding`, `Target`, `Exposure`) that represent red/blue audit concepts separately from core config structs.
- **Presentation-Aware Output:** Each report mode must format and prioritize data differently based on audience: ops (standard), defense (blue), adversary (red).
- **Data Processing:** The data processing pipeline is responsible for transforming the data model into the different report formats.

## 3. Go Language Standards

### 3.1. Technology Stack

| Layer      | Technology                                                                  |
| ---------- | --------------------------------------------------------------------------- |
| CLI Tool   | `cobra` v1.8.0 + `charmbracelet/fang` for styled help, errors, and features |
| Config     | `spf13/viper` for configuration parsing                                     |
| Display    | `charmbracelet/glamour` for markdown rendering                              |
| Data Model | Go structs with `encoding/xml`, `encoding/json`, and `gopkg.in/yaml.v3`     |
| Logging    | `charmbracelet/log` for structured logging                                  |
| Testing    | Go's built-in `testing` package                                             |

### 3.2. Go Version Requirements

- **Minimum Go Version:** 1.21.6+
- **Recommended Go Version:** 1.24.5+
- **Module Support:** Required (Go modules only)

### 3.3. CLI Architecture

- **Command Structure:** Use `cobra` for CLI command organization with consistent verb patterns (`create`, `list`, `get`, `update`, `delete`)
- **Configuration:** Use `spf13/viper` for configuration management with support for environment variables, config files, and command-line flags
- **CLI Enhancement:** Use `charmbracelet/fang` for enhanced CLI experience with styled help, errors, automatic version/completion, and manpage generation
- **Output Formatting:** Use `charmbracelet/lipgloss` for styled terminal output and `charmbracelet/glamour` for markdown rendering
- **Error Handling:** Use Go's error handling patterns with `fmt.Errorf` and `errors.Wrap` for context preservation

### 3.4. Data Processing

- **XML Parsing:** Use Go's `encoding/xml` package for parsing XML configuration files
- **Data Models:** Define clear struct types with appropriate tags for XML/JSON/YAML serialization
- **Validation:** Implement validation using struct tags and custom validation functions
- **Transformation:** Use functional programming patterns for data transformation pipelines

### 3.5. Code Style and Conventions

- **Tools:**
  - **`gofmt`:** For code formatting (run automatically on save).
  - **`golangci-lint`:** For comprehensive linting.
  - **`go vet`:** For static analysis.
  - **`go test`:** For testing.
  - **`go test -race`:** For race detection.
  - **`gosec`:** For security scanning (via golangci-lint).
- **Formatting:**
  - Use `gofmt` with default settings.
  - Line length: Follow Go conventions (typically 80-120 characters).
  - Indentation: Use tabs (Go standard).
- **Naming Conventions:**
  - **Packages:** `snake_case` or single word, lowercase.
  - **Variables/functions:** `camelCase` for private, `PascalCase` for exported.
  - **Constants:** `camelCase` for private, `PascalCase` for exported (avoid `ALL_CAPS`).
  - **Types:** `PascalCase`.
  - **Interfaces:** `PascalCase` ending with `-er` when appropriate.
  - **Receivers:** Use consistent single-letter names (e.g., `c *Config`, not `config *Config`).
- **Error Handling:** Always check errors and provide meaningful context using `fmt.Errorf` with `%w` for error wrapping.
- **Logging:** Use structured logging with `charmbracelet/log` instead of `fmt.Printf`.
- **Comments:** Start comments with the name of the thing being described. Use complete sentences.

### 3.6. Project Structure

```text
opndossier/
├── cmd/
│   ├── convert.go                         # Convert command entry point
│   ├── display.go                         # Display command entry point
│   ├── validate.go                        # Validate command entry point
│   └── root.go                            # Root command and main entry point
├── internal/
│   ├── config/                            # Configuration handling
│   ├── parser/                            # XML parsing logic
│   ├── markdown/                          # Markdown generation and templates
│   ├── display/                           # Terminal display formatting
│   ├── export/                            # File export functionality
│   ├── processor/                         # Data processing and analysis
│   ├── model/                             # Data models and structures
│   ├── validator/                         # Configuration validation
│   ├── templates/                         # Output templates
│   └── log/                               # Structured logging
├── pkg/                                   # Public packages (if any)
├── docs/                                  # Documentation
├── go.mod                                 # Go module file
├── go.sum                                 # Go module checksum file
├── README.md                              # Project README
├── project_spec/requirements.md           # Project requirements
├── ARCHITECTURE.md                        # System architecture documentation
├── DEVELOPMENT_STANDARDS.md               # Development standards
└── justfile                               # Build and development tasks
```

> **Note:** For detailed project structure and development guidelines, see [DEVELOPMENT_STANDARDS.md](DEVELOPMENT_STANDARDS.md). For system architecture details, see [ARCHITECTURE.md](ARCHITECTURE.md).

### 3.7. Testing and Quality

- **Framework:** Use Go's built-in `testing` package.
- **Test Organization:**
  - Place tests in `*_test.go` files in the same package.
  - Use descriptive test names: `TestFunctionName_Scenario_ExpectedResult`.
  - Group related tests using `t.Run()` for subtests.
- **Test Types:**
  - **Unit Tests:** Verify individual functions and methods.
  - **Integration Tests:** Use `//go:build integration` build tags.
  - **Table-Driven Tests:** Use for testing multiple input scenarios.
  - **Benchmarks:** Use `go test -bench` for performance-critical code.
- **Test Coverage:** Use `go test -cover` to measure code coverage. Aim for >80% coverage.
- **Test Helpers:** Use `t.Helper()` in helper functions, create realistic test fixtures.
- **Error Testing:** Always test error conditions and verify error messages.
- **Performance:** Keep tests fast (\<100ms per test), use `t.Parallel()` when safe.
- **Pre-commit Hooks:** Use `pre-commit` to run `gofmt`, `golangci-lint`, and tests automatically.

### 3.8. Development Workflow

- **Task Runner:** Use `justfile` for running common development tasks. Key commands include:
  - `just install`: Install dependencies and tools.
  - `just format`: Format code with `gofmt`.
  - `just lint`: Run linting with `golangci-lint`.
  - `just test`: Run the test suite.
  - `just build`: Build the application.
  - `just check`: Run pre-commit checks
  - `just ci-check`: Run checks, format, lint, and tests
- **Dependency Management:** Use Go modules (`go.mod`) for dependency management.
- **Release Management:** Use GoReleaser v2 for cross-platform builds and releases.

### 3.9. Key Implementation Patterns

> [!NOTE]
> The user prefers to use well maintained 3rd party libraries and frameworks over custom solutions.

#### Configuration Management

**Note for AI Assistants**: `viper` is used for managing the opnDossier application's own configuration (CLI settings, display preferences, etc.), not for parsing OPNsense config.xml files. The OPNsense configuration parsing is handled separately by the XML parser in `internal/parser/`.

**Pattern**: Use `spf13/viper` for configuration with precedence: CLI flags > Environment variables > Config file > Defaults

#### Error Handling

**Pattern**: Always wrap errors with context using `fmt.Errorf` with `%w` verb
**Pattern**: Create domain-specific error types for better error handling
**Pattern**: Use `errors.Is()` and `errors.As()` for error type checking

#### Structured Logging

**Pattern**: Use `charmbracelet/log` for structured logging with appropriate levels
**Pattern**: Include context in log messages (filename, operation, duration)
**Pattern**: Use debug level for troubleshooting, info for operations, warn for issues, error for failures

#### Testing

**Pattern**: Use table-driven tests for multiple scenarios
**Pattern**: Test both success and error conditions
**Pattern**: Use `t.Helper()` in test helper functions
**Pattern**: Aim for >80% test coverage

#### Security

**Pattern**: Never hardcode secrets - use environment variables
**Pattern**: Validate all user inputs and sanitize file paths
**Pattern**: Use restrictive file permissions (0600 for config files)
**Pattern**: Avoid exposing sensitive information in error messages

### 3.10. CLI Implementation Guidelines

#### Command Structure

- Use `cobra` for command organization
- Use `charmbracelet/fang` for enhanced CLI experience
- Follow consistent verb patterns: `convert`, `display`, `validate`
- Provide comprehensive help documentation

#### Configuration

- Use `spf13/viper` for configuration management
- Support YAML config files, environment variables, and CLI flags
- Implement proper precedence order
- Handle missing config files gracefully

#### Output Formatting

- Use `charmbracelet/lipgloss` for styled terminal output
- Use `charmbracelet/glamour` for markdown rendering
- Support theme detection (light/dark)
- Provide progress indicators for long operations

## 4. Implementation Guidelines

### 4.1. Preferred Tooling Commands

#### Primary Task Runner: `just`

All development tasks should be executed through the justfile to ensure consistency:

```bash
# Development workflow
just dev                 # Run the application in development mode
just install            # Install dependencies and setup environment
just build              # Complete build with all checks

# Code quality
just lint               # Run linting and formatting
just check              # Run pre-commit hooks and comprehensive checks
just ci-check           # Run CI-equivalent checks locally

# Testing
just test               # Run the full test suite

# Maintenance
just update-deps        # Update and verify dependencies
just docs               # Serve documentation locally
```

### 4.2. Testing Tiers

The project implements a three-tier testing strategy:

#### Tier 1: Unit Tests

- **Purpose:** Test individual functions and methods in isolation
- **Location:** `*_test.go` files alongside source code
- **Command:** `go test ./...` or `just test`
- **Coverage Target:** >80% for critical business logic
- **Speed:** \<100ms per test

#### Tier 2: Integration Tests

- **Purpose:** Test interactions between components
- **Location:** `*_test.go` files with `//go:build integration` tag
- **Command:** `go test -tags=integration ./...`
- **Focus:** File I/O, configuration parsing, command execution

### 4.3. Dependency Injection Patterns

- Use interface-based design for testability
- Define interfaces for dependencies (ConfigReader, FileWriter, etc.)
- Use dependency injection in main components
- Create test doubles (mocks) for testing

### 4.4. Error Handling Patterns

- Create domain-specific error types (ValidationError, ProcessingError)
- Always wrap errors with context using `fmt.Errorf` with `%w`
- Use `errors.Is()` and `errors.As()` for error type checking
- Handle errors gracefully in CLI commands with user-friendly messages

### 4.5. Logging Guidelines

- Use `charmbracelet/log` for structured logging
- Initialize logger with appropriate level (debug, info, warn, error)
- Add context to logger for request/operation tracking
- Use appropriate log levels for different types of messages

### 4.6. Security Practices

- **Secret Management:** Use environment variables, never hardcode secrets
- **Input Validation:** Validate all user inputs and sanitize file paths
- **File Operations:** Use secure file permissions and validate file sizes
- **Configuration Security:** Separate sensitive and non-sensitive configuration

### 4.7. AI Assistant Guidelines

#### Development Rules of Engagement

- **TERM=dumb Support**: Ensure terminal output respects `TERM="dumb"` environment variable for CI/automation
- **CodeRabbit.ai Integration**: Prefer coderabbit.ai for code review over GitHub Copilot auto-reviews
- **Single Maintainer Workflow**: Configure for single maintainer (UncleSp1d3r) with no second reviewer requirement
- **No Auto-commits**: Never commit code on behalf of maintainer without explicit permission

#### Assistant Behavior Rules

- **Clarity and Precision**: Be direct, professional, and context-aware in all interactions
- **Adherence to Standards**: Strictly follow the defined rules for code style and project structure
- **Tool Usage**: Use `just` for task execution, `go` commands for Go development
- **Focus on Value**: Enhance the project's unique value proposition as an OPNsense configuration auditing tool
- **Respect Documentation**: Always consult and follow project documentation before making changes

#### Code Generation Requirements

- Generated code must conform to all established patterns
- Include comprehensive error handling with context preservation
- Follow architectural patterns (Command, Strategy, Builder where appropriate)
- Include appropriate documentation and testing
- Use proper type safety through Go's type system

### 4.8. Common Commands and Workflows

#### Development Commands

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

#### Usage Examples

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

### 4.9. AI Agent Mandatory Practices

When AI agents contribute to this project, they **MUST**:

01. **Always run tests** after making changes: `just test`
02. **Run linting** before committing: `just lint`
03. **Follow the established patterns** shown in existing code
04. **Use the preferred tooling commands** listed above
05. **Write comprehensive tests** for new functionality
06. **Include proper error handling** with context
07. **Add structured logging** for important operations
08. **Validate all inputs** and handle edge cases
09. **Document new functions and types** following Go conventions
10. **Never commit secrets** or hardcoded credentials
11. **Consult project documentation** - [requirements.md](project_spec/requirements.md), [ARCHITECTURE.md](ARCHITECTURE.md), and [DEVELOPMENT_STANDARDS.md](DEVELOPMENT_STANDARDS.md) for guidance
12. When rendering reports, always prefer structured config data + audit overlays over flat summary tables
13. Blue team output should favor clarity, grouping, and actionability. Red team output should favor target prioritization and pivot surface discovery
14. Validate all generated markdown for formatting correctness using mdformat for formatting and markdownlint-cli2 for validation
15. **CRITICAL: Tasks are NOT considered completed until `just ci-check` is run and fully passes**

#### AI Agent Code Review Checklist

Before submitting code, AI agents should verify:

- [ ] Code follows Go formatting standards (`gofmt`)
- [ ] All linting issues resolved (`golangci-lint`)
- [ ] Tests pass (`go test ./...`)
- [ ] Error handling includes proper context
- [ ] Logging uses structured format with appropriate levels
- [ ] No hardcoded secrets or credentials
- [ ] Input validation implemented where needed
- [ ] Documentation updated for new features
- [ ] Dependencies properly managed (`go mod tidy`)
- [ ] Code follows established patterns and interfaces
- [ ] Requirements compliance verified against [requirements.md](project_spec/requirements.md)
- [ ] Architecture patterns followed per [ARCHITECTURE.md](ARCHITECTURE.md)
- [ ] Development standards adhered to per [DEVELOPMENT_STANDARDS.md](DEVELOPMENT_STANDARDS.md)

These implementation guidelines ensure that all contributors, whether human or AI, can work effectively within the established project standards and produce high-quality, maintainable code.

---

## Additional Resources

For comprehensive project understanding, AI agents should familiarize themselves with:

- **[requirements.md](project_spec/requirements.md)** - Complete functional and technical requirements
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System design, data flow, and component architecture
- **[DEVELOPMENT_STANDARDS.md](DEVELOPMENT_STANDARDS.md)** - Go-specific coding standards and project structure

These documents provide the complete context needed for effective development and decision-making within the opnDossier project.
