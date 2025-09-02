# Project Structure and Organization

## Repository Structure

```text
opnDossier/
├── .github/                    # GitHub workflows and templates
├── .kiro/                      # Kiro IDE configuration and steering
│   ├── settings/               # IDE settings and MCP configuration
│   └── steering/               # Development guidance and standards
├── cmd/                        # CLI command implementations
├── docs/                       # Comprehensive project documentation
├── internal/                   # Private application packages
├── project_spec/               # Project requirements and specifications
├── testdata/                   # Test fixtures and sample configurations
├── main.go                     # Application entry point
├── go.mod                      # Go module definition
├── go.sum                      # Dependency checksums
└── justfile                    # Development task automation
```

## Source Code Organization

### Command Layer (`cmd/`)

```text
cmd/
├── root.go                     # Root command and global flags
├── convert.go                  # Configuration conversion command
├── display.go                  # Configuration display command
├── validate.go                 # Configuration validation command
├── completion.go               # Shell completion generation
├── man.go                      # Manual page generation
└── shared_flags.go             # Common command flags and utilities
```

**Responsibilities:**

- CLI interface definition and user interaction
- Command-line argument parsing and validation
- User feedback and error reporting
- Integration with business logic layer

### Business Logic (`internal/`)

```text
internal/
├── audit/                      # Compliance checking and audit engine
│   ├── plugin.go               # Plugin interface and registry
│   └── plugin_manager.go       # Plugin lifecycle management
├── config/                     # Configuration management
├── converter/                  # Data format conversion utilities
├── display/                    # Terminal output formatting
├── export/                     # File export functionality
├── log/                        # Logging configuration and utilities
├── markdown/                   # Markdown generation and templating
├── model/                      # Core data structures and types
├── parser/                     # XML parsing and validation
├── plugin/                     # Plugin interfaces and base types
├── plugins/                    # Compliance plugin implementations
│   ├── firewall/               # Firewall-specific compliance rules
│   ├── sans/                   # SANS framework compliance
│   └── stig/                   # STIG compliance checking
├── processor/                  # Data processing and analysis
├── templates/                  # Output template management
├── validator/                  # Data validation utilities
├── constants/                  # Application constants and enums
└── walker.go                   # File system utilities
```

**Key Principles:**

- **Single Responsibility**: Each package has a clear, focused purpose
- **Dependency Direction**: Dependencies flow inward (no circular dependencies)
- **Interface Segregation**: Small, focused interfaces for testability
- **Encapsulation**: Internal packages hide implementation details

## Package Responsibilities

### Core Packages

#### `model/`

- Data structures representing OPNsense configuration
- Audit findings and security analysis results
- Serialization tags for JSON, XML, and YAML
- Validation methods and business rules

#### `parser/`

- XML configuration file parsing
- Schema validation and error handling
- Data transformation from XML to internal models
- Support for different OPNsense versions

#### `audit/`

- Plugin management and orchestration
- Compliance rule execution
- Finding aggregation and reporting
- Severity assessment and prioritization

#### `converter/`

- Format conversion between XML, JSON, YAML, Markdown
- Template-based output generation
- Data filtering and transformation
- Export functionality

### Plugin Architecture

#### `plugin/`

- Base interfaces for compliance plugins
- Common plugin utilities and helpers
- Error types and handling patterns
- Plugin metadata and registration

#### `plugins/`

- Concrete implementations of compliance frameworks
- Framework-specific rule definitions
- Custom finding types and severity mappings
- Configuration validation for each framework

### Utility Packages

#### `display/`

- Terminal output formatting with lipgloss
- Progress indicators and user feedback
- Color schemes and styling consistency
- Interactive elements and prompts

#### `templates/`

- Output template management
- Markdown, JSON, and YAML templates
- Template inheritance and composition
- Custom template function registration

## Documentation Structure

### Primary Documentation (`docs/`)

```text
docs/
├── index.md                    # Project overview and introduction
├── api.md                      # API reference and usage
├── examples.md                 # Usage examples and tutorials
├── migration.md                # Version migration guides
├── user-guide/                 # End-user documentation
├── dev-guide/                  # Developer documentation
└── examples/                   # Sample configurations and outputs
```

### Project Specifications (`project_spec/`)

```text
project_spec/
├── requirements.md             # Detailed requirements specification
├── tasks.md                    # Implementation task checklist
├── user_stories.md             # User stories and acceptance criteria
└── ROADMAP_V2.0.md            # Future development roadmap
```

## Configuration and Build

### Development Configuration

```text
├── .editorconfig               # Editor configuration consistency
├── .gitignore                  # Git ignore patterns
├── .golangci.yml              # Linting configuration
├── .goreleaser.yaml           # Release automation configuration
├── .pre-commit-config.yaml    # Pre-commit hook configuration
├── justfile                   # Development task definitions
└── mkdocs.yml                 # Documentation site configuration
```

### Quality Assurance

```text
├── .coderabbit.yaml           # Code review automation
├── .fossa.yml                 # License and security scanning
├── .markdownlint-cli2.jsonc   # Markdown linting rules
├── .mdformat.toml             # Markdown formatting configuration
└── commitlint.config.js       # Commit message validation
```

## File Naming Conventions

### Go Source Files

- **Commands**: `{command}.go` (e.g., `convert.go`, `validate.go`)
- **Interfaces**: `{domain}.go` (e.g., `plugin.go`, `parser.go`)
- **Implementations**: `{domain}_{impl}.go` (e.g., `plugin_manager.go`)
- **Tests**: `{source}_test.go` for unit tests
- **Integration Tests**: `integration_test.go` for end-to-end tests

### Documentation Files

- **Uppercase**: Core project files (`README.md`, `CHANGELOG.md`)
- **Lowercase**: Documentation content (`api.md`, `examples.md`)
- **Descriptive**: Clear purpose indication (`migration.md`, `user-guide/`)

### Configuration Files

- **Dotfiles**: Tool-specific configuration (`.golangci.yml`, `.gitignore`)
- **Descriptive**: Purpose-clear naming (`justfile`, `mkdocs.yml`)

## Import Organization

### Import Groups (in order)

1. **Standard Library**: Go standard library packages
2. **Third-Party**: External dependencies
3. **Internal**: Project internal packages

### Example Import Block

```go
import (
    // Standard library
    "encoding/json"
    "fmt"
    "os"

    // Third-party dependencies
    "github.com/spf13/cobra"
    "github.com/charmbracelet/lipgloss"

    // Internal packages
    "github.com/EvilBit-Labs/opnDossier/internal/model"
    "github.com/EvilBit-Labs/opnDossier/internal/parser"
)
```

## Testing Structure

### Test Organization

- **Unit Tests**: Alongside source files (`*_test.go`)
- **Integration Tests**: Root level (`integration_test.go`)
- **Test Data**: Centralized in `testdata/` directory
- **Benchmarks**: Performance tests with `Benchmark*` functions

### Test Data Management

```text
testdata/
├── config.xml.sample          # Sample OPNsense configuration
├── sample.config.*.xml        # Various configuration scenarios
├── opnsense-config.dtd        # OPNsense DTD for validation
├── opnsense-config.xsd        # OPNsense XSD schema
└── README.md                  # Test data documentation
```

## Development Workflow Structure

### Task Automation (`justfile`)

- **Development**: `just dev`, `just install`, `just build`
- **Quality**: `just format`, `just lint`, `just test`
- **Validation**: `just check`, `just ci-check`
- **Documentation**: `just docs`, `just serve-docs`

### Git Workflow

- **Feature Branches**: `feature/{description}` or `fix/{description}`
- **Conventional Commits**: Structured commit messages
- **Protected Main**: All changes via pull requests
- **Automated Checks**: CI validation before merge

## Maintenance and Evolution

### Code Organization Principles

- **Cohesion**: Related functionality grouped together
- **Coupling**: Minimal dependencies between packages
- **Clarity**: Clear naming and organization
- **Consistency**: Uniform patterns across the codebase

### Refactoring Guidelines

- Maintain backward compatibility in public APIs
- Update documentation with structural changes
- Preserve test coverage during reorganization
- Follow established patterns for new components

### Growth Accommodation

- Plugin system for extensibility
- Clear interfaces for new implementations
- Modular design for feature additions
- Scalable testing and documentation structure
