---
inclusion: fileMatch
fileMatchPattern:
  - '**/*.go'
  - '**/go.mod'
  - '**/go.sum'
---

# Go Standards for opnDossier

## Critical Quality Gates (MANDATORY)

- **ALWAYS run `just ci-check`** before completing any task
- **All tests must pass**: `just test` with >80% coverage
- **Code formatting**: Use `gofmt` and `goimports` (automated via `just format`)
- **No linting errors**: `golangci-lint` must pass clean

## Technology Stack (REQUIRED)

### Core Dependencies (DO NOT DEVIATE)

```go
// CLI Framework
github.com/spf13/cobra v1.8.0
github.com/spf13/viper
github.com/charmbracelet/fang

// Terminal Output
github.com/charmbracelet/lipgloss
github.com/charmbracelet/glamour
github.com/charmbracelet/log

// Programmatic Markdown (NOT templates)
github.com/nao1215/markdown v0.8.0

// Standard Library (preferred)
encoding/xml
encoding/json
gopkg.in/yaml.v3
```

### Go Version Requirements

- **Minimum**: Go 1.21.6+
- **Recommended**: Go 1.24.5+
- **Module Support**: Required (Go modules only)

## Code Standards (ENFORCED)

### Error Handling Pattern

```go
// REQUIRED: Always provide context
if err != nil {
    return fmt.Errorf("parsing OPNsense config: %w", err)
}

// FORBIDDEN: Generic error handling
if err != nil {
    return err
}
```

### Logging Pattern

```go
// REQUIRED: Structured logging with charmbracelet/log
log.Info("parsing configuration", "file", filename, "size", fileSize)

// FORBIDDEN: Printf-style logging
fmt.Printf("Parsing %s\n", filename)
```

### Naming Conventions

- Use `camelCase` for variables and functions
- Use `PascalCase` for exported types and functions
- Use descriptive names that clearly indicate purpose
- Avoid abbreviations unless widely understood

## XML Processing Standards

### OPNsense Configuration Parsing

- Use `encoding/xml` standard library ONLY
- Strict tag mapping to OPNsense schema
- Handle large files (100MB+) with streaming
- Validate against OPNsense DTD/XSD when available

### Performance Requirements

- Handle 100MB configuration files
- Process 10,000+ rules in \<30 seconds
- Memory usage \<500MB for typical configs
- Startup time \<1 second

## Multi-Format Export Standards

### Output Formats

- **Markdown**: Use `github.com/nao1215/markdown` for programmatic generation (NOT templates)
- **JSON/YAML**: Standard library with proper struct tags
- **File handling**: Smart naming with overwrite protection (`-f` flag)

### Plugin Interface Standards

- Use interfaces for extensibility and testability
- Keep interfaces small and focused
- Document interface contracts clearly
- Use registry pattern for plugin discovery

## Security Standards (CRITICAL)

### Input Validation

```go
// REQUIRED: Validate file paths and sizes
func validateConfigFile(path string) error {
    info, err := os.Stat(path)
    if err != nil {
        return fmt.Errorf("config file not accessible: %w", err)
    }

    if info.Size() > maxConfigSize {
        return fmt.Errorf("config file too large: %d bytes", info.Size())
    }

    return nil
}
```

### Offline-First Architecture

- No external network dependencies
- No external API dependencies
- All processing happens locally
- No hardcoded secrets or credentials

## Forbidden Patterns

- **NO** `fmt.Printf` for logging (use `charmbracelet/log`)
- **NO** custom XML parsers (use `encoding/xml`)
- **NO** template-based markdown (use `github.com/nao1215/markdown`)
- **NO** hardcoded secrets or credentials
- **NO** external network dependencies
- **NO** `log.Fatal` in library code

## Development Workflow

```bash
# REQUIRED before any commit
just format    # Format code and docs
just lint      # Static analysis
just test      # Run test suite with race detection
just ci-check  # Comprehensive validation (MANDATORY)
```
