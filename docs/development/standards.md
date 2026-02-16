# Development Standards for opnDossier

This document provides coding standards, development workflows, and technical guidelines for contributors to the opnDossier CLI tool. It focuses on practical development tasks, code quality, and maintainability. It complements the AI agent guidelines in [AGENTS.md](https://github.com/EvilBit-Labs/opnDossier/blob/main/AGENTS.md).

## Table of Contents

1. [Development Environment Setup](#development-environment-setup)
2. [Code Quality Standards](#code-quality-standards)
3. [Testing Requirements](#testing-requirements)
4. [Development Workflow](#development-workflow)
5. [Architecture Guidelines](#architecture-guidelines)
6. [Security Standards](#security-standards)

## Development Environment Setup

### Prerequisites

- **Go 1.21.6+** (recommended: 1.24.5+)
- **Git** with conventional commit support
- **Just** task runner (`just --version` to verify)
- **Python 3.11+** (for documentation)

### Initial Setup

```bash
# Clone and setup
git clone https://github.com/EvilBit-Labs/opnDossier.git
cd opnDossier

# Install dependencies and tools
just install

# Verify setup
just test
just lint
```

### IDE Configuration

**VS Code Extensions:**

- Go extension (official)
- Pre-commit hooks
- YAML support
- Markdown preview

**GoLand/IntelliJ:**

- Enable `gofmt` on save
- Configure `golangci-lint` integration
- Set up run configurations for `just` commands

### Environment Variables

```bash
# Development environment
export OPNDOSSIER_VERBOSE=true

# For testing
export OPNDOSSIER_TEST_MODE=true
```

## Code Quality Standards

### Technology Stack

| Component              | Technology                      | Purpose                               |
| ---------------------- | ------------------------------- | ------------------------------------- |
| **CLI Framework**      | `cobra`                         | Command organization and help system  |
| **Configuration**      | `spf13/viper`                   | Configuration management              |
| **CLI Enhancement**    | `charmbracelet/fang`            | Enhanced CLI experience               |
| **Terminal Styling**   | `charmbracelet/lipgloss`        | Colored output and styling            |
| **Markdown Rendering** | `charmbracelet/glamour`         | Terminal markdown display             |
| **Logging**            | `charmbracelet/log`             | Structured logging                    |
| **Data Processing**    | `encoding/xml`, `encoding/json` | Standard library XML/JSON handling    |
| **Testing**            | Go's built-in `testing` package | Table-driven tests with >80% coverage |

### Code Style and Formatting

**Required Tools:**

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

### Commit Message Conventions

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

**Examples:**

```text
feat(cli): add support for custom config path
fix(parser): handle malformed XML gracefully
docs: update README with install instructions
perf(converter): optimize markdown generation
test(parser): add integration tests for XML parsing
```

## Testing Requirements

### Test Standards

**Requirements:**

- **Coverage Target:** >80% test coverage
- **Test Organization:** Table-driven tests with `t.Run()` subtests
- **Performance:** Individual tests \<100ms
- **Integration Tests:** Use build tags (`//go:build integration`)

### Test Structure

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

### Testing Commands

```bash
# Run all tests
just test

# Run with coverage
just coverage

# Run benchmarks
just bench

# Run memory benchmarks
just bench-memory

# Run race detection
go test -race ./...
```

## Development Workflow

### Daily Development Tasks

```bash
# Start development session
just dev --help                    # Test CLI functionality
just test                         # Run tests before making changes
just lint                         # Check code quality

# Make changes, then:
just format                       # Format code
just check                        # Run pre-commit checks
just test                         # Verify tests still pass
```

### Adding New Features

1. **Create feature branch:**

   ```bash
   git checkout -b feat/your-feature-name
   ```

2. **Implement feature:**

   - Follow existing patterns in similar code
   - Add tests for new functionality
   - Update documentation if needed

3. **Quality checks:**

   ```bash
   just ci-check                   # Run all checks locally
   ```

4. **Commit changes:**

   ```bash
   git add .
   git commit -m "feat(scope): description"
   ```

### Debugging

**Common debugging scenarios:**

```bash
# Debug CLI commands
just dev --verbose convert testdata/config.xml

# Debug with specific log level
OPNDOSSIER_VERBOSE=true just dev convert testdata/config.xml

# Profile performance
go test -bench=. -cpuprofile=cpu.prof ./internal/cfgparser
go tool pprof cpu.prof

# Memory profiling
go test -bench=. -memprofile=mem.prof ./internal/cfgparser
go tool pprof mem.prof
```

**Debugging tips:**

- Use `log.Debug()` for temporary debugging output
- Check `internal/logging/` for structured logging patterns
- Use `go test -v` for verbose test output
- Use `golangci-lint run --verbose` for detailed linting info

### Performance Optimization

**Benchmarking:**

```bash
# Run benchmarks
just bench

# Compare benchmarks
go test -bench=. -benchmem ./internal/cfgparser > old.txt
# Make changes
go test -bench=. -benchmem ./internal/cfgparser > new.txt
benchcmp old.txt new.txt
```

**Profiling:**

```bash
# CPU profiling
go test -cpuprofile=cpu.prof -bench=. ./internal/cfgparser
go tool pprof cpu.prof

# Memory profiling
go test -memprofile=mem.prof -bench=. ./internal/cfgparser
go tool pprof mem.prof
```

## Architecture Guidelines

### Project Structure

```text
opnDossier/
├── main.go                           # Application entry point
├── cmd/                              # CLI commands
│   ├── root.go                       # Root command and CLI setup
│   ├── convert.go                    # Convert command implementation
│   ├── display.go                    # Display command implementation
│   ├── validate.go                   # Validate command implementation
│   └── *_test.go                     # Command tests
├── internal/                         # Private application logic
│   ├── config/                       # Configuration handling
│   ├── parser/                       # XML parsing logic
│   ├── converter/                    # Data conversion logic
│   ├── display/                      # Output formatting
│   ├── export/                       # File export logic
│   ├── processor/                    # Configuration processing pipeline
│   ├── markdown/                     # Markdown generation
│   ├── model/                        # Data models
│   ├── validator/                    # Validation logic
│   ├── log/                          # Structured logging
│   ├── metrics/                      # Performance metrics
│   ├── walker.go                     # XML walker utilities
│   └── *_test.go                     # Package tests
├── docs/                             # Documentation
├── project_spec/                     # Project requirements
├── testdata/                         # Test data files
└── justfile                          # Task runner
```

### Key Design Principles

1. **Framework-First:** Use established libraries (cobra, viper, charmbracelet)
2. **Operator-Centric:** Build for security operators' workflows
3. **Offline-First:** No external dependencies or telemetry
4. **Structured Data:** Versioned, portable data models

### Configuration Management

```go
// Using spf13/viper for configuration
type Config struct {
    InputFile  string `flag:"input" desc:"Input XML file path"`
    OutputFile string `flag:"output" desc:"Output markdown file path"`
    Verbose    bool   `flag:"verbose" desc:"Enable verbose output"`
}

// Configuration precedence: CLI flags > environment variables > config file > defaults
```

### Error Handling

- Always wrap errors with context using `fmt.Errorf` with `%w`
- Create domain-specific error types for better error handling
- Use `errors.Is()` and `errors.As()` for error type checking
- Provide actionable error messages for users

### Logging

- Use `charmbracelet/log` for structured logging
- Include context in log messages (filename, operation, duration)
- Use appropriate log levels (debug, info, warn, error)
- Avoid logging sensitive information

### XML Schema Evolution

The config.xml data model is enhanced in phases to ensure backward compatibility and thorough testing at each stage.

**Completed Phases:**

| Phase | Scope                        | Fields Added | Key Changes                                                                                                                        |
| ----- | ---------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| 1     | Source/Destination gaps      | 3            | Address, Port (Source), Not — added directly to structs                                                                            |
| 2     | High-priority Rule fields    | 8            | Log, Disabled/Quick→BoolFlag, Floating, Gateway, Direction, Tracker, StateType                                                     |
| 3     | Rate-limiting and advanced   | 14           | max-src-\*, TCP/ICMP flags, state timeout, advanced BoolFlags                                                                      |
| 4     | NAT rule enhancements        | 9            | NATRule: StaticNatPort, NoNat, NatPort, PoolOptsSrcHashKey; InboundRule: NATReflection, AssociatedRuleID, NoRDR, NoSync, LocalPort |
| 5     | Documentation and validation | —            | Research doc updates, field reference, validator enhancements                                                                      |

**BoolFlag vs String Pattern:**

OPNsense uses two boolean patterns. Choosing the wrong type silently breaks semantics:

- **Presence-based** (`isset()` in PHP): Use `BoolFlag`. Examples: `<disabled/>`, `<log/>`, `<not/>`, `<quick/>`
- **Value-based** (`== "1"` in PHP): Use `string`. Examples: `<enable>1</enable>`, `<blockpriv>1</blockpriv>`

`BoolFlag.UnmarshalXML` treats any present element as true — so `<enabled>0</enabled>` becomes `true`, breaking value-based semantics. See `docs/development/xml-structure-research.md` §1 for the complete field inventory.

**Adding New XML Fields:**

1. Check upstream OPNsense/pfSense source for field semantics (presence-based vs value-based)
2. Add the field to the appropriate struct in `internal/schema/`
3. Add XML round-trip tests in the corresponding `*_test.go`
4. Update the validator in `internal/validator/opnsense.go` if the field has constraints
5. Update `docs/development/xml-structure-research.md` with the field details

## Security Standards

### General Security Principles

1. **No Secrets in Code:** Never hardcode API keys, passwords, or sensitive data
2. **Environment Variables:** Use environment variables with `OPNDOSSIER_` prefix for configuration
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

### Operational Security

- **Airgap Compatibility:** Full functionality in isolated environments
- **No Telemetry:** No external data transmission
- **Portable Data Exchange:** Secure data bundle import/export
- **Error Message Safety:** No sensitive information exposure

### Dependency Security

- **Minimal Dependencies:** Reduced attack surface, except for cryptography dependencies - never write your own crypto code
- **Dependency Scanning:** Automated vulnerability detection via `gosec`
- **Supply Chain Security:** Go module checksums and verification
- **SBOM Generation:** Dependency transparency for security compliance

---

This document serves as the development standards guide for the opnDossier CLI tool. All contributors should follow these standards to ensure code quality, maintainability, and security.
