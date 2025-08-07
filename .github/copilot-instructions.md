---
applyTo: '**'
---

# GitHub Copilot Instructions for opnDossier

## AI Assistant Guidelines

**CRITICAL**: When contributing to this project, always:

1. **Follow the established patterns** in existing code
2. **Use `just` commands** for all development tasks
3. **Run `just ci-check`** before reporting success
4. **Reference key documents**: `AGENTS.md`, `DEVELOPMENT_STANDARDS.md`, `ARCHITECTURE.md`, and `project_spec/requirements.md`
5. **Maintain offline-first architecture** (no external dependencies)
6. **Never commit code** without explicit permission from the user
7. **Apply rule precedence**: Project-specific rules > General development standards > Language-specific style guides

## Project Overview

opnDossier is a Go-based CLI tool for processing OPNsense firewall configurations. It converts XML config files to Markdown/JSON/YAML with comprehensive audit capabilities and multi-format export features. Built for operators with strict offline-first design principles.

### Core Philosophy

- **Operator-Focused**: Build tools for operators, by operators - workflows must be intuitive and efficient
- **Offline-First**: Systems must operate in fully offline or airgapped environments with no external dependencies
- **Structured Data**: Data should be structured, versioned, and portable for auditable, actionable systems
- **Framework-First**: Leverage built-in functionality of established frameworks, avoid custom solutions

### New Features

- **Multi-Format Export**: Export to markdown, JSON, or YAML (`opndossier convert config.xml --format [markdown|json|yaml]`)
- **Validation System**: Enhanced configuration integrity with automatic validation during parsing
- **Compliance Audit Engine**: Comprehensive STIG, SANS, and firewall security compliance checking

## Technology Stack

| Layer          | Technology                                         | Notes                                   |
| -------------- | -------------------------------------------------- | --------------------------------------- |
| **CLI Tool**   | `cobra` v1.8.0 + `charmbracelet/fang`              | Styled help, errors, and features       |
| **Config**     | `spf13/viper`                                      | Configuration parsing with precedence   |
| **Display**    | `charmbracelet/glamour` + `charmbracelet/lipgloss` | Markdown rendering and styled output    |
| **Data Model** | Go structs with XML/JSON/YAML tags                 | Strict OPNsense configuration structure |
| **Logging**    | `charmbracelet/log`                                | Structured logging                      |
| **Testing**    | Go's built-in `testing` package                    | Table-driven tests, >80% coverage       |

## Go Version Requirements

- **Minimum Go Version**: 1.21.6+
- **Recommended Go Version**: 1.24.5+
- **Module Support**: Required (Go modules only)

## Code Organization Patterns

### Directory Structure

```text
cmd/                    # CLI entry points (convert, display, validate)
internal/
├── audit/             # Compliance checking and audit engine
├── config/            # Configuration management with env vars
├── converter/         # Multi-format conversion (MD/JSON/YAML)
├── display/           # Terminal output with themes
├── export/            # File export with overwrite protection
├── log/               # Structured logging
├── markdown/          # Markdown generation with templates
├── model/             # OPNsense data models
├── parser/            # XML parsing and validation
├── plugin/            # Plugin interfaces
├── plugins/           # Compliance plugins (stig, sans, firewall)
├── processor/         # Data processing and analysis
├── templates/         # Markdown templates
├── validator/         # Configuration validation
└── walker.go          # File system utilities
```

### Key Patterns to Follow

**Error Handling**: Always use `fmt.Errorf` with context

```go
return fmt.Errorf("failed to parse config: %w", err)
```

**Logging**: Use `charmbracelet/log` for structured logging

```go
logger := log.New(os.Stderr, "", log.LstdFlags)
logger.Info("processing config file", "filename", filename)
```

**Configuration**: Use `internal/config` for all settings

```go
cfg := config.GetConfig()
```

**Data Models**: Use `internal/model` structs for OPNsense data

```go
doc := &model.OpnSenseDocument{}
```

## Project Structure

```text
opndossier/
├── cmd/
│   ├── convert.go           # Convert command entry point
│   ├── display.go           # Display command entry point
│   ├── validate.go          # Validate command entry point
│   └── root.go              # Root command and main entry point
├── internal/
│   ├── audit/               # Audit engine and compliance checking
│   │   ├── plugin.go        # Plugin registry and compliance logic
│   │   └── plugin_manager.go # Plugin lifecycle management
│   ├── config/              # Configuration handling
│   ├── converter/           # Multi-format conversion (MD/JSON/YAML)
│   ├── display/             # Terminal display formatting
│   ├── export/              # File export functionality
│   ├── log/                 # Structured logging
│   ├── markdown/            # Markdown generation and templates
│   ├── model/               # Data models and structures
│   ├── parser/              # XML parsing logic
│   ├── plugin/              # Plugin interfaces and data structures
│   ├── plugins/             # Compliance plugins
│   │   ├── firewall/        # Firewall compliance plugin
│   │   ├── sans/            # SANS compliance plugin
│   │   └── stig/            # STIG compliance plugin
│   ├── processor/           # Data processing and analysis
│   ├── templates/           # Output templates
│   └── validator/           # Configuration validation
├── pkg/                     # Public packages (if any)
├── docs/                    # Documentation
├── project_spec/            # Project requirements and specifications
├── testdata/                # Test data and fixtures
├── go.mod                   # Go module file
├── go.sum                   # Go module checksum file
├── justfile                 # Build and development tasks
├── AGENTS.md                # AI agent development guidelines
├── ARCHITECTURE.md          # System architecture documentation
└── DEVELOPMENT_STANDARDS.md # Development standards
```

## Development Commands

**ALWAYS use these `just` commands:**

```bash
# Development workflow
just dev                 # Run in development mode
just install            # Install dependencies and setup environment
just build              # Complete build with all checks

# Code quality
just format             # Format code and documentation
just lint               # Run linting checks
just check              # Run pre-commit hooks and comprehensive checks
just ci-check           # Run CI-equivalent checks locally

# Testing
just test               # Run the full test suite

# Maintenance
just update-deps        # Update and verify dependencies
just docs               # Serve documentation locally
```

## Code Standards and Patterns

### Naming Conventions

- **Packages**: `snake_case` or single word, lowercase
- **Variables/Functions**: `camelCase` for private, `PascalCase` for exported
- **Constants**: `camelCase` for private, `PascalCase` for exported (avoid `ALL_CAPS`)
- **Types**: `PascalCase`
- **Interfaces**: `PascalCase` ending with `-er` when appropriate
- **Receivers**: Consistent single-letter names (e.g., `c *Config`)

### Error Handling Patterns

**Always use context-preserving error handling:**

```go
// Error wrapping with context
if err := parseConfig(data); err != nil {
    return fmt.Errorf("failed to parse configuration: %w", err)
}

// Custom error types for domain-specific errors
type ParseError struct {
    Message string
    Line    int
    Column  int
}

func (e *ParseError) Error() string {
    return fmt.Sprintf("parse error at line %d, column %d: %s", e.Line, e.Column, e.Message)
}

// Error checking with errors.Is() and errors.As()
if errors.Is(err, ErrConfigNotFound) {
    // Handle specific error type
}
```

### Logging Patterns

**Use structured logging with `charmbracelet/log`:**

```go
import "github.com/charmbracelet/log"

func processConfig(filename string) error {
    logger := log.With("filename", filename, "operation", "process")
    logger.Info("starting configuration processing")

    if err := validateConfig(filename); err != nil {
        logger.Error("validation failed", "error", err)
        return fmt.Errorf("validation failed: %w", err)
    }

    logger.Info("configuration processed successfully")
    return nil
}
```

### Configuration Management

**Important**: `viper` is used for managing opnDossier's application configuration (CLI settings, display preferences, etc.), NOT for parsing OPNsense config.xml files. OPNsense configuration parsing is handled separately by the XML parser in `internal/parser/`.

```go
// Use viper for application configuration
cfg := viper.New()
cfg.SetConfigName("config")
cfg.SetConfigType("yaml")
cfg.AddConfigPath(".")

// Handle precedence: CLI flags > Environment variables > Config file > Defaults
```

### Data Processing Patterns

**Core data model standards:**

- **OpnSenseDocument**: Core data model representing entire OPNsense configuration
- **XML Tags**: Must strictly follow OPNsense configuration file structure
- **JSON/YAML Tags**: Follow recommended best practices for each format
- **Audit-Oriented Modeling**: Create internal structs (`Finding`, `Target`, `Exposure`) for red/blue audit concepts

```go
// Data model example
type OpnSenseDocument struct {
    System     SystemConfig     `xml:"system" json:"system" yaml:"system"`
    Interfaces InterfaceConfig  `xml:"interfaces" json:"interfaces" yaml:"interfaces"`
    Filter     FilterConfig     `xml:"filter" json:"filter" yaml:"filter"`
}

// Multi-format export validation
func validateExportedFile(filename string, format string) error {
    switch format {
    case "json":
        return validateJSONFile(filename)
    case "yaml":
        return validateYAMLFile(filename)
    case "markdown":
        return validateMarkdownFile(filename)
    }
    return fmt.Errorf("unsupported format: %s", format)
}
```

## CLI Command Patterns

### Command Structure

```go
var convertCmd = &cobra.Command{
    Use:   "convert [file]",
    Short: "Convert OPNsense config to multiple formats",
    Long: `Convert an OPNsense configuration file to markdown, JSON, or YAML format.

The convert command reads an XML configuration file and generates
a structured output with all configuration details.

Examples:
  opndossier convert config.xml
  opndossier convert config.xml --format json
  opndossier convert config.xml --output output.md --format markdown`,
    Args:  cobra.ExactArgs(1),
    RunE:  runConvert,
}
```

### Flag Patterns

```go
// Multi-format export flags
convertCmd.Flags().StringVarP(&format, "format", "f", "markdown", "Output format (markdown|json|yaml)")
convertCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")
convertCmd.Flags().BoolVarP(&forceOverwrite, "force", "F", false, "Force overwrite existing files")

// Audit and validation flags
convertCmd.Flags().StringVar(&auditMode, "mode", "", "Audit mode (standard|blue|red)")
convertCmd.Flags().StringSliceVar(&selectedPlugins, "plugins", []string{}, "Compliance plugins to run")

// Display flags
convertCmd.Flags().BoolVarP(&display, "display", "d", false, "Display result in terminal")
```

## Data Processing Patterns

### XML Parsing Flow

1. Use `internal/parser` for XML parsing
2. Convert to `internal/model` structs
3. Process with `internal/processor`
4. Convert to output format with `internal/converter`

### Template Usage

```go
// Use internal/templates for markdown generation
opts := markdown.Options{
    Template: templateName,
    Theme:    themeName,
    Wrap:     wrapWidth,
}
```

### Audit Integration

```go
// Use internal/audit for compliance checking
registry := audit.NewPluginRegistry()
report := registry.RunAudit(ctx, config, mode)
```

## Audit Engine and Plugin Architecture

### Plugin Interface

All compliance plugins must implement the `CompliancePlugin` interface:

```go
type CompliancePlugin interface {
    Name() string
    Version() string
    Description() string
    RunChecks(config *model.OpnSenseDocument) []Finding
    GetControls() []Control
    GetControlByID(id string) (*Control, error)
    ValidateConfiguration() error
}
```

### Plugin Development Standards

- **Generic Data Structures**: Use generic `Finding` struct with `References`, `Tags`, and `Metadata` fields
- **No Compliance-Specific Fields**: Avoid compliance-specific reference fields in findings
- **Plugin Organization**: Place plugins in `internal/plugins/` directory by compliance standard
- **Plugin Registration**: Use `PluginManager` for lifecycle management
- **Control Naming**: Use consistent control ID naming: `STIG-V-XXXXXX`, `SANS-XXX`, `FIREWALL-XXX`

### Audit Modes

- **Standard Mode**: General operational reporting
- **Blue Team Mode**: Defense-oriented reporting with clarity, grouping, and actionability
- **Red Team Mode**: Adversary-oriented reporting with target prioritization and pivot surface discovery

## Multi-Format Export and Validation

### Export Standards

- **Supported Formats**: Markdown, JSON, YAML
- **File Quality**: Exported files must be valid and parseable by standard tools
- **Output Control**: Smart file naming with overwrite protection
- **Force Option**: Use `-f` flag for force overwrite operations
- **Usage Pattern**: `opndossier convert config.xml --format [markdown|json|yaml]`

### Validation Integration

- **Automatic Validation**: Applied during parsing by default
- **Explicit Validation**: Available via CLI commands
- **Performance**: Use memory-efficient approaches for large configurations
- **Error Reporting**: Provide clear, actionable error messages

## Testing Patterns

### Test Structure

**ALWAYS write comprehensive tests:**

```go
func TestParseConfig_ValidXML_ReturnsConfig(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected *Config
        wantErr  bool
    }{
        {
            name:     "valid xml config",
            input:    `<opnsense><system><hostname>test</hostname></system></opnsense>`,
            expected: &Config{System: SystemConfig{Hostname: "test"}},
            wantErr:  false,
        },
        {
            name:     "invalid xml",
            input:    "<invalid>",
            expected: nil,
            wantErr:  true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := ParseConfig(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("ParseConfig() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if !reflect.DeepEqual(result, tt.expected) {
                t.Errorf("ParseConfig() = %v, want %v", result, tt.expected)
            }
        })
    }
}
```

### Testing Requirements

- **Coverage**: Aim for >80% test coverage
- **Test Types**: Unit tests, integration tests (with build tags), benchmarks
- **Performance**: Keep tests fast (\<100ms per test), use `t.Parallel()` when safe
- **Helpers**: Use `t.Helper()` in helper functions
- **Fixtures**: Use `testdata/` directory for test files

## Error Patterns

**Use these error types from internal packages:**

```go
import "github.com/EvilBit-Labs/opnDossier/internal/parser"
import "github.com/EvilBit-Labs/opnDossier/internal/plugin"

// Common error patterns
if err != nil {
    return fmt.Errorf("operation failed: %w", err)
}
```

## Security Requirements

**NEVER do these:**

- Hardcode secrets or API keys
- Use external HTTP calls
- Store sensitive data in code
- Skip input validation

**ALWAYS do these:**

- Use environment variables with `OPNDOSSIER_` prefix for config
- Validate and sanitize XML input files
- Use secure defaults
- Handle errors gracefully with context
- Include context in log messages (filename, operation, duration)
- Use appropriate log levels (debug, info, warn, error)

## Integration Points

### Component Communication

```text
parser → model → processor → converter → export
                ↓
            audit → plugins
                ↓
            templates → markdown
```

### Key Interfaces

- `internal/plugin.Plugin` for compliance plugins
- `internal/model.OpnSenseDocument` for data
- `internal/config.Config` for settings
- `charmbracelet/log.Logger` for logging

## Common Tasks

### Adding New Command

1. Create file in `cmd/`
2. Follow existing command patterns
3. Add to `root.go` init()
4. Write comprehensive tests
5. Update documentation

### Adding New Format

1. Add converter in `internal/converter/`
2. Add template in `internal/templates/`
3. Update command flags
4. Add tests
5. Update documentation

### Adding New Plugin

1. Implement `internal/plugin.Plugin` interface
2. Add to `internal/plugins/`
3. Register in `internal/audit/`
4. Add tests
5. Update documentation

## Quality Checklist

**Before submitting code:**

- [ ] Code follows Go formatting (`gofmt`)
- [ ] All linting issues resolved (`golangci-lint`)
- [ ] Tests pass (`go test ./...`)
- [ ] Test coverage >80%
- [ ] Error handling includes context with `fmt.Errorf`
- [ ] Logging uses `charmbracelet/log` with structured fields
- [ ] No hardcoded secrets
- [ ] Input validation implemented
- [ ] Documentation updated
- [ ] Dependencies managed (`go mod tidy`)

## Key Files to Reference

- `AGENTS.md` - Detailed development standards
- `DEVELOPMENT_STANDARDS.md` - Go-specific conventions
- `ARCHITECTURE.md` - System design
- `project_spec/requirements.md` - Complete requirements
- `project_spec/tasks.md` - Implementation tasks
- `internal/model/opnsense.go` - Core data models
- `cmd/convert.go` - Main command implementation
- `internal/parser/xml.go` - XML parsing logic

## Documentation Standards

### Function Documentation

```go
// ParseConfig reads and parses an OPNsense configuration file.
// The filename parameter specifies the path to the XML configuration file.
// It returns a structured representation of the configuration
// or an error if the file cannot be read or parsed.
// The returned Config struct contains all configuration sections
// including system settings, interfaces, and firewall rules.
func ParseConfig(filename string) (*Config, error) {
    // implementation
}
```

### Package Documentation

```go
// Package parser provides functionality for parsing OPNsense configuration files.
// It supports XML parsing and conversion to structured data formats.
// The package includes utilities for validation and transformation of configuration data.
package parser
```

## AI Agent Mandatory Practices

**When AI agents contribute to this project, they must:**

01. **Always run tests** after making changes: `just test`
02. **Run linting** before committing: `just lint`
03. **Follow established patterns** shown in existing code
04. **Use preferred tooling commands** listed above
05. **Write comprehensive tests** for new functionality
06. **Include proper error handling** with context
07. **Add structured logging** for important operations
08. **Validate all inputs** and handle edge cases
09. **Document new functions and types** following Go conventions
10. **Never commit secrets** or hardcoded credentials
11. **Consult project documentation** for guidance
12. **Prefer structured config data + audit overlays** over flat summary tables
13. **Validate generated markdown** for formatting correctness

## AI Agent Code Review Checklist

**Before submitting code, verify:**

- [ ] Code follows Go formatting standards (`gofmt`)
- [ ] All linting issues resolved (`golangci-lint`)
- [ ] Tests pass (`go test ./...`)
- [ ] Test coverage >80% for new functionality
- [ ] Error handling includes proper context with `fmt.Errorf` and `%w`
- [ ] Logging uses `charmbracelet/log` with structured fields
- [ ] No hardcoded secrets or credentials
- [ ] Input validation implemented where needed
- [ ] Documentation updated for new features
- [ ] Dependencies properly managed (`go mod tidy`)
- [ ] Code follows established patterns and interfaces
- [ ] Requirements compliance verified against requirements.md
- [ ] Architecture patterns followed per ARCHITECTURE.md
- [ ] Development standards adhered to per DEVELOPMENT_STANDARDS.md

## Commit Message Standards

Follow [Conventional Commits](https://www.conventionalcommits.org) specification:

- **Format**: `<type>(<scope>): <description>`
- **Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `build`, `ci`, `chore`, `perf`
- **Scope**: Required for all commits (e.g., `(cli)`, `(audit)`, `(parser)`)
- **Description**: Imperative mood, ≤72 characters, no period at end
- **Breaking Changes**: Use `!` after type/scope or `BREAKING CHANGE:` in footer

**Examples:**

- `feat(cli): add multi-format export support`
- `fix(parser): handle malformed XML gracefully`
- `docs(audit): update plugin development guide`

## Key Documentation References

**Before making changes, consult:**

- **[AGENTS.md](AGENTS.md)** - Comprehensive AI agent development guidelines and project standards
- **[DEVELOPMENT_STANDARDS.md](DEVELOPMENT_STANDARDS.md)** - Go-specific coding standards and project structure
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System design, data flow, and component architecture
- **[project_spec/requirements.md](project_spec/requirements.md)** - Complete functional and technical requirements
- **[project_spec/tasks.md](project_spec/tasks.md)** - Implementation tasks and progress tracking
- **[project_spec/user_stories.md](project_spec/user_stories.md)** - User stories and use cases

## Integration Points

### Component Communication Flow

```text
parser → model → processor → converter → export
                ↓
            audit → plugins
                ↓
            templates → markdown
```

### Key Interfaces

- `internal/plugin.CompliancePlugin` for compliance plugins
- `internal/model.OpnSenseDocument` for configuration data
- `internal/config.Config` for application settings
- `charmbracelet/log.Logger` for structured logging

---

**Remember**: This project prioritizes offline operation, structured data, operator-focused workflows, and comprehensive audit capabilities. Always maintain these core principles in your contributions. When in doubt, refer to AGENTS.md for detailed guidance and established patterns.
