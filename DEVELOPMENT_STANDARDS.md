# Development Standards for opnFocus

This document enumerates coding standards, commit message conventions, directory structure expectations, and lint/format rules specifically for the opnFocus CLI tool, based on established requirements and project-specific needs.

## Table of Contents

1. [Core Philosophy & General Principles](#core-philosophy--general-principles)
2. [Commit Message Conventions](#commit-message-conventions)
3. [Go Standards](#go-standards)
4. [Project Structure](#project-structure)
5. [Development Workflow](#development-workflow)
6. [Security Standards](#security-standards)

## Core Philosophy & General Principles

### 1. Framework-First Principle

- Always prefer built-in functionality from Go standard library and established frameworks
- Trust framework serialization, validation, and dependency injection mechanisms
- Examples: `encoding/xml`, `encoding/json`, `cobra`, `charmbracelet` libraries

### 2. Operator-Centric Design

- Build for security operators, by security operators
- Prioritize efficient, auditable, and functional workflows
- Support contested or airgapped environments
- Focus on CLI efficiency and clear output

### 3. Structured and Versioned Data

- All data models should be structured, versioned, and non-destructive
- Updates create new versions rather than overwriting existing data
- Support portable data exchange via structured bundles

### 4. Offline-First Architecture

- Systems must function without internet connectivity
- No external dependencies during runtime
- Full functionality in isolated/airgapped environments
- Zero telemetry or external communication

## Commit Message Conventions

### Conventional Commits Specification

All commit messages **MUST** follow the [Conventional Commits](https://www.conventionalcommits.org) specification:

**Format:** `<type>(<scope>): <description>`

**Types:**

- `feat` - New features
- `fix` - Bug fixes
- `docs` - Documentation changes
- `style` - Code style changes (formatting, etc.)
- `refactor` - Code refactoring
- `perf` - Performance improvements
- `test` - Adding or updating tests
- `build` - Build system changes
- `ci` - CI/CD changes
- `chore` - Maintenance tasks

**Scopes:** `(cli)`, `(parser)`, `(converter)`, `(display)`, `(config)`, `(docs)`, etc.

**Breaking Changes:**

- Use `!` in the header: `feat(cli)!: change command structure`
- Or add `BREAKING CHANGE:` footer

**Examples:**

```text
feat(cli): add support for custom config path
fix(parser): handle malformed XML gracefully
docs: update README with install instructions
perf(converter): optimize markdown generation
test(parser): add integration tests for XML parsing
```

## Go Standards

### Technology Stack

| Layer | Technology | Notes |
|-------|------------|-------|
| **CLI Framework** | `cobra` | Command organization and help system |
| **Configuration** | `charmbracelet/fang` | Configuration management |
| **Terminal Styling** | `charmbracelet/lipgloss` | Colored output and styling |
| **Markdown Rendering** | `charmbracelet/glamour` | Terminal markdown display |
| **Logging** | `charmbracelet/log` | Structured logging |
| **Data Processing** | `encoding/xml`, `encoding/json` | Standard library XML/JSON handling |
| **Testing** | Go's built-in `testing` package | Table-driven tests with >80% coverage |

### Code Style and Formatting

**Tools:**

- **`gofmt`** - Code formatting (automatic)
- **`gofumpt`** - Enhanced formatting
- **`golangci-lint`** - Comprehensive linting
- **`go vet`** - Static analysis
- **`goimports`** - Import organization
- **`gosec`** - Security scanning (via golangci-lint)

**Conventions:**

- **Formatting:** Use `gofmt` with default settings
- **Line Length:** 80-120 characters (Go conventions)
- **Indentation:** Use tabs (Go standard)
- **Naming:**
  - Packages: `snake_case` or single word, lowercase
  - Variables/functions: `camelCase` for private, `PascalCase` for exported
  - Constants: `camelCase` for private, `PascalCase` for exported (avoid `ALL_CAPS`)
  - Types: `PascalCase`
  - Interfaces: `PascalCase`, ending with `-er` when appropriate
  - Receivers: Single-letter names (e.g., `c *Config`)

### Directory Structure

```text
opnFocus/
├── cmd/
│   ├── opnsense.go          # Main CLI entry point
│   └── root.go              # Root command definition
├── internal/
│   ├── config/              # Configuration handling
│   ├── parser/              # XML parsing logic
│   ├── converter/           # XML to Markdown conversion
│   └── display/             # Terminal output formatting
├── pkg/                     # Public packages (if any)
├── docs/                    # Documentation
├── go.mod
├── go.sum
├── justfile                 # Task runner
├── README.md
└── requirements.md          # Project requirements
```

### Development Commands

```bash
# Code quality
gofmt -w .                    # Format code
gofumpt -w .                  # Enhanced formatting
golangci-lint run            # Run linting
go vet ./...                 # Static analysis
goimports -w .               # Organize imports

# Testing
go test ./...                # Run tests
go test -race ./...          # Run tests with race detection
go test -cover ./...         # Run tests with coverage
go test -bench ./...         # Run benchmarks

# Build and run
go build                     # Build application
go run cmd/opnsense.go      # Run application
go mod tidy                 # Clean up dependencies
```

### Error Handling Patterns

```go
// Always check errors and provide context
func parseXMLConfig(filename string) (*Config, error) {
    data, err := os.ReadFile(filename)
    if err != nil {
        return nil, fmt.Errorf("failed to read config file %s: %w", filename, err)
    }

    var config Config
    if err := xml.Unmarshal(data, &config); err != nil {
        return nil, fmt.Errorf("failed to parse XML config: %w", err)
    }

    return &config, nil
}

// Use structured logging
logger := log.New(os.Stderr, "", log.LstdFlags)
logger.Info("processing config file", "filename", filename)
```

### Testing Standards

**Requirements:**

- **Coverage Target:** >80% test coverage
- **Test Organization:** Table-driven tests with `t.Run()` subtests
- **Performance:** Individual tests <100ms
- **Integration Tests:** Use build tags (`//go:build integration`)

**Example Test Structure:**

```go
func TestParseXMLConfig(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected *Config
        wantErr  bool
    }{
        {
            name:     "valid config",
            input:    `<config><system><hostname>test</hostname></system></config>`,
            expected: &Config{System: System{Hostname: "test"}},
            wantErr:  false,
        },
        {
            name:     "invalid XML",
            input:    `<config><unclosed>`,
            expected: nil,
            wantErr:  true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := parseXMLConfig(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("parseXMLConfig() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if !reflect.DeepEqual(result, tt.expected) {
                t.Errorf("parseXMLConfig() = %v, want %v", result, tt.expected)
            }
        })
    }
}
```

## Project Structure

### Module Organization

**cmd/ - Command Definitions:**

- `opnsense.go`: Main application entry point
- `root.go`: Root command and global flags

**internal/ - Private Application Logic:**

- `config/`: Configuration management using `charmbracelet/fang`
- `parser/`: XML parsing using `encoding/xml`
- `converter/`: XML to Markdown conversion logic
- `display/`: Terminal output using `charmbracelet/lipgloss` and `charmbracelet/glamour`

**pkg/ - Public Packages:**

- Only include if packages are intended for external use
- Follow Go module conventions for public APIs

### Configuration Management

```go
// Using charmbracelet/fang for configuration
type Config struct {
    InputFile  string `flag:"input" desc:"Input XML file path"`
    OutputFile string `flag:"output" desc:"Output markdown file path"`
    Verbose    bool   `flag:"verbose" desc:"Enable verbose output"`
}

// Configuration precedence: CLI flags > environment variables > config file > defaults
```

## Development Workflow

### Task Runner (Justfile)

All development tasks should use `just` for automation:

```makefile
# Common tasks
default:
    @just --list

# Development
dev:
    go run cmd/opnsense.go

install:
    go mod download
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Code Quality
format:
    gofmt -w .
    gofumpt -w .
    goimports -w .

lint:
    golangci-lint run

check:
    just format
    just lint
    go vet ./...

# Testing
test:
    go test ./...

test-coverage:
    go test -cover ./...

test-race:
    go test -race ./...

test-bench:
    go test -bench ./...

# Build
build:
    go build -o bin/opnFocus cmd/opnsense.go

build-cross:
    GOOS=linux GOARCH=amd64 go build -o bin/opnFocus-linux-amd64 cmd/opnsense.go
    GOOS=darwin GOARCH=amd64 go build -o bin/opnFocus-darwin-amd64 cmd/opnsense.go
    GOOS=windows GOARCH=amd64 go build -o bin/opnFocus-windows-amd64.exe cmd/opnsense.go

clean:
    rm -rf bin/

# CI/CD
ci-check:
    just check
    just test-coverage
    just build
```

### Pre-commit Checks

**Required Quality Checks:**

```bash
gofmt -d .                   # Format check
gofumpt -d .                 # Enhanced format check
golangci-lint run           # Linting
go vet ./...                # Static analysis
go test ./...               # Tests
go test -race ./...         # Race detection
```

### Performance Requirements

- **Startup Time:** CLI should start quickly for operator efficiency
- **Memory Efficiency:** Streaming XML processing for large files
- **Concurrent Processing:** Use goroutines and channels for I/O operations
- **Test Performance:** Individual tests <100ms

## Security Standards

### General Security Principles

1. **No Secrets in Code:** Never hardcode API keys, passwords, or sensitive data
2. **Environment Variables:** Use environment variables with `OPNFOCUS_` prefix for configuration
3. **Input Validation:** Always validate and sanitize XML input files
4. **Secure Defaults:** Default to secure configurations
5. **Error Messages:** Avoid exposing sensitive information in error messages

### Go-Specific Security

**Input Validation:**

```go
// Validate XML input before processing
func validateXMLInput(data []byte) error {
    if len(data) == 0 {
        return errors.New("empty XML input")
    }

    // Check for basic XML structure
    if !bytes.Contains(data, []byte("<?xml")) && !bytes.Contains(data, []byte("<opnsense")) {
        return errors.New("invalid XML format: missing XML declaration or opnsense root")
    }

    return nil
}
```

**Error Handling:**

```go
// Safe error messages without sensitive information
func processConfig(filename string) error {
    data, err := os.ReadFile(filename)
    if err != nil {
        // Don't expose full file paths in error messages
        return fmt.Errorf("failed to read configuration file: %w", err)
    }

    // Process data...
    return nil
}
```

**Secure Random Generation:**

```go
import "crypto/rand"

// Use crypto/rand for secure random generation
func generateSecureID() (string, error) {
    bytes := make([]byte, 16)
    if _, err := rand.Read(bytes); err != nil {
        return "", fmt.Errorf("failed to generate secure ID: %w", err)
    }
    return hex.EncodeToString(bytes), nil
}
```

### Operational Security

- **Airgap Compatibility:** Full functionality in isolated environments
- **No Telemetry:** No external data transmission
- **Portable Data Exchange:** Secure data bundle import/export
- **Error Message Safety:** No sensitive information exposure

### Dependency Security

- **Minimal Dependencies:** Reduced attack surface
- **Dependency Scanning:** Automated vulnerability detection via `gosec`
- **Supply Chain Security:** Go module checksums and verification
- **SBOM Generation:** Dependency transparency for security compliance

---

This document serves as the comprehensive development standards guide for the opnFocus CLI tool. All team members and AI assistants should refer to and follow these standards when working on the project. The standards align with the specific requirements outlined in `requirements.md` and should be updated as new patterns emerge or requirements change.
