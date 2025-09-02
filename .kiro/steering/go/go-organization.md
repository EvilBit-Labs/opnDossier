---
inclusion: fileMatch
fileMatchPattern:
  - "**/*.go"
  - "**/go.mod"
  - "**/go.sum"
---

# Go Project Organization for opnDossier

## Package Structure (REQUIRED)

```text
opnDossier/
├── cmd/                        # CLI commands (Cobra)
│   ├── root.go                 # Root command and global flags
│   ├── convert.go              # Configuration conversion command
│   ├── display.go              # Configuration display command
│   └── validate.go             # Configuration validation command
├── internal/                   # Private application logic
│   ├── model/                  # Core data structures with XML tags
│   ├── parser/                 # XML parsing (encoding/xml)
│   ├── audit/                  # Plugin management & compliance
│   ├── plugins/                # Compliance implementations
│   │   ├── firewall/           # Firewall-specific compliance rules
│   │   ├── sans/               # SANS framework compliance
│   │   └── stig/               # STIG compliance checking
│   ├── converter/              # Format conversion utilities
│   ├── display/                # Terminal output (lipgloss)
│   ├── export/                 # File export functionality
│   ├── templates/              # Output templates
│   └── validator/              # Data validation utilities
├── testdata/                   # Test fixtures and sample configs
├── docs/                       # Project documentation
├── go.mod                      # Dependencies
└── main.go                     # Entry point
```

## File Organization Standards

### Naming Conventions

- Use descriptive file names that indicate functionality
- Group related functionality in the same package
- Use `snake_case` for file names (Go convention)
- Separate concerns into focused packages

### Package Responsibilities

#### `cmd/` - CLI Interface

- Command definitions using Cobra framework
- User interaction and input validation
- Command-line argument parsing
- Integration with business logic layer

#### `internal/model/` - Data Structures

- Core data types with XML/JSON/YAML tags
- Validation methods and business rules
- Serialization support for multiple formats

#### `internal/parser/` - Configuration Parsing

- XML parsing with `encoding/xml`
- Schema validation and error handling
- Data transformation from XML to internal models

#### `internal/audit/` - Compliance Engine

- Plugin management and orchestration
- Compliance rule execution
- Finding aggregation and reporting

#### `internal/plugins/` - Compliance Implementations

- Framework-specific compliance rules (STIG, SANS, CIS)
- Custom finding types and severity mappings
- Configuration validation for each framework

#### `internal/converter/` - Format Conversion

- Multi-format export (markdown, JSON, YAML)
- Template-based output generation
- Data filtering and transformation

#### `internal/display/` - Terminal Output

- Styled terminal output with lipgloss
- Progress indicators and user feedback
- Interactive elements and prompts

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

## Dependency Management

### Module Structure

- Use Go modules for dependency management
- Pin dependency versions for stability
- Regularly update dependencies for security
- Minimize external dependencies

### Dependency Categories

- **CLI Framework**: Cobra for command structure
- **Terminal UI**: Charm libraries for styling
- **Configuration**: Viper for app configuration
- **Standard Library**: Prefer standard library when possible

## Code Organization Principles

### Single Responsibility

- Each package has a clear, focused purpose
- Functions and types serve a single responsibility
- Avoid mixing concerns within packages

### Dependency Direction

- Dependencies flow inward (no circular dependencies)
- Higher-level packages depend on lower-level ones
- Business logic doesn't depend on UI concerns

### Interface Segregation

- Small, focused interfaces for testability
- Separate interfaces for different concerns
- Use interfaces to define contracts between packages

## File Structure Within Packages

### Standard Files

- `doc.go` - Package documentation
- `types.go` - Type definitions
- `errors.go` - Error definitions
- `interface.go` - Interface definitions
- `*_test.go` - Test files

### Naming Patterns

- Group related functionality in appropriately named files
- Use descriptive names that indicate the file's purpose
- Keep files focused and reasonably sized (<500 lines)

## Plugin Architecture Organization

### Plugin Discovery

- Registry pattern for plugin management
- Interface-based design for extensibility
- Clear separation between plugin interface and implementations

### Plugin Structure

```text
internal/plugins/
├── plugin.go              # Plugin interface definition
├── registry.go            # Plugin registry and management
├── firewall/
│   ├── firewall.go         # Firewall compliance plugin
│   └── rules.go            # Firewall-specific rules
├── sans/
│   ├── sans.go             # SANS compliance plugin
│   └── framework.go        # SANS framework implementation
└── stig/
    ├── stig.go             # STIG compliance plugin
    └── controls.go         # STIG control implementations
```
