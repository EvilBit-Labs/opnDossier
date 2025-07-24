# AI Agent Coding Standards and Project Structure

This document outlines the preferred coding standards, architectural principles, and development workflows for projects.

## Rule Precedence

**CRITICAL - Rules are applied in the following order of precedence:**
1. **Project-specific rules** (from project root instruction files like AGENTS.md, GEMINI.md, or .cursor/rules/)
2. **General development standards** (outlined in this document)
3. **Language-specific style guides** (Go conventions, etc.)

When rules conflict, always follow the rule with higher precedence.

## 1. Core Philosophy

- **Operator-Focused:** Build tools for operators, by operators. Workflows should be intuitive and efficient for the end-user.
- **Offline-First:** Systems should be designed to operate in fully offline or airgapped environments. This means no external dependencies, no telemetry, and support for data exchange via portable bundles.
- **Structured Data:** Data should be structured, versioned, and portable. This enables auditable, actionable, and reliable systems.
- **Framework-First:** Leverage the built-in functionality of established frameworks and libraries. Avoid custom solutions when a well-established, predictable one already exists.

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

### 2.3. Commit Message Standards

Follow the [Conventional Commits](https://www.conventionalcommits.org) specification:

- **Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `build`, `ci`, `chore`, `perf`
- **Format:** `type(scope): description`
- **Breaking Changes:** Use `!` in the type/scope (e.g., `feat(cli)!:`) or a `BREAKING CHANGE:` footer
- **Examples:**
  - `feat(auth): add OAuth2 support`
  - `fix(parser): handle malformed XML gracefully`
  - `docs: update API documentation`

## 3. Go Language Standards

### 3.1. Technology Stack

| Layer      | Technology                                               |
| ---------- | -------------------------------------------------------- |
| CLI Tool   | `cobra` + `charmbracelet/fang` + `charmbracelet/lipgloss` |
| Config     | `charmbracelet/fang` for configuration parsing           |
| Display    | `charmbracelet/glamour` for markdown rendering           |
| Data Model | Go structs with `encoding/xml` and `encoding/json`      |
| Testing    | Go's built-in `testing` package                          |

### 3.2. CLI Architecture

- **Command Structure:** Use `cobra` for CLI command organization with consistent verb patterns (`create`, `list`, `get`, `update`, `delete`)
- **Configuration:** Use `charmbracelet/fang` for configuration management with support for environment variables, config files, and command-line flags
- **Output Formatting:** Use `charmbracelet/lipgloss` for styled terminal output and `charmbracelet/glamour` for markdown rendering
- **Error Handling:** Use Go's error handling patterns with `fmt.Errorf` and `errors.Wrap` for context preservation

### 3.3. Data Processing

- **XML Parsing:** Use Go's `encoding/xml` package for parsing XML configuration files
- **Data Models:** Define clear struct types with appropriate tags for XML/JSON serialization
- **Validation:** Implement validation using struct tags and custom validation functions
- **Transformation:** Use functional programming patterns for data transformation pipelines

### 3.4. Code Style and Conventions

- **Tools:**
    - **`gofmt`:** For code formatting (run automatically on save).
    - **`golangci-lint`:** For comprehensive linting.
    - **`go vet`:** For static analysis.
    - **`go test`:** For testing.
    - **`go test -race`:** For race detection.
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
- **Logging:** Use structured logging with `log/slog` instead of `fmt.Printf`.
- **Comments:** Start comments with the name of the thing being described. Use complete sentences.

### 3.5. Project Structure

```
opnfocus/
├── cmd/
│   └── main.go              # Application entry point
├── internal/
│   ├── config/              # Configuration handling
│   ├── parser/              # XML parsing logic
│   ├── converter/           # Data conversion logic
│   └── display/             # Output formatting
├── pkg/                     # Public packages (if any)
├── go.mod
├── go.sum
├── README.md
└── Justfile                 # Build and development tasks
```

### 3.6. Testing and Quality

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
- **Performance:** Keep tests fast (<100ms per test), use `t.Parallel()` when safe.
- **Pre-commit Hooks:** Use `pre-commit` to run `gofmt`, `golangci-lint`, and tests automatically.

### 3.7. Development Workflow

- **Task Runner:** Use `Justfile` for running common development tasks. Key commands include:
    - `just install`: Install dependencies and tools.
    - `just format`: Format code with `gofmt`.
    - `just lint`: Run linting with `golangci-lint`.
    - `just test`: Run the test suite.
    - `just build`: Build the application.
    - `just check`: Run pre-commit checks
    - `just ci-check`: Run checks, format, lint, and tests
- **Dependency Management:** Use Go modules (`go.mod`) for dependency management.

### 3.8. CLI Tool Implementation Examples

#### Command Structure
```go
// Use cobra for command organization
var rootCmd = &cobra.Command{
    Use:   "opnFocus",
    Short: "OPNsense configuration processor",
    Long:  `A CLI tool for processing OPNsense config.xml files and converting them to markdown.`,
}

var convertCmd = &cobra.Command{
    Use:   "convert [file]",
    Short: "Convert OPNsense config to markdown",
    Args:  cobra.ExactArgs(1),
    RunE:  runConvert,
}
```

#### Configuration with Fang
```go
// Use fang for configuration management
type Config struct {
    InputFile  string `env:"INPUT_FILE" flag:"input" short:"i" desc:"Input XML file"`
    OutputFile string `env:"OUTPUT_FILE" flag:"output" short:"o" desc:"Output markdown file"`
    Display    bool   `env:"DISPLAY" flag:"display" short:"d" desc:"Display in terminal"`
}
```

#### Styled Output with Lipgloss
```go
// Use lipgloss for styled terminal output
var (
    titleStyle = lipgloss.NewStyle().
        Bold(true).
        Foreground(lipgloss.Color("#FAFAFA")).
        Background(lipgloss.Color("#7D56F4")).
        Padding(0, 1)

    errorStyle = lipgloss.NewStyle().
        Bold(true).
        Foreground(lipgloss.Color("#FF0000"))
)
```

#### Markdown Rendering with Glamour
```go
// Use glamour for markdown rendering
func renderMarkdown(content string) (string, error) {
    return glamour.Render(content, "dark")
}
```

### 3.9. Error Handling Patterns

```go
// Always check errors and provide context
func parseConfig(filename string) (*Opnsense, error) {
    data, err := os.ReadFile(filename)
    if err != nil {
        return nil, fmt.Errorf("failed to read config file %s: %w", filename, err)
    }

    var config Opnsense
    if err := xml.Unmarshal(data, &config); err != nil {
        return nil, fmt.Errorf("failed to parse XML config: %w", err)
    }

    return &config, nil
}
```

### 3.10. Documentation Standards

- **Package Documentation:**
    - Every package should have a package comment starting with "Package packagename".
    - Use complete sentences and proper grammar.
    - Place package comment before package declaration.
- **Function Documentation:**
    - Document all exported functions and types.
    - Start with the function name and use complete sentences.
    - Describe parameters, return values, and error conditions.
    - Include usage examples for complex functions.
- **Type Documentation:**
    - Document all exported types and interfaces.
    - Include field descriptions for structs.
    - Document any constraints or requirements.
- **Code Comments:**
    - Use comments to explain "why" not "what".
    - Use TODO, FIXME, and NOTE comments appropriately.
    - Keep comments up to date with code changes.

### 3.11. Testing Patterns

```go
// Use table-driven tests for multiple scenarios
func TestConvertConfig(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected string
        wantErr  bool
    }{
        {
            name:     "valid config",
            input:    "<opnsense>...</opnsense>",
            expected: "# OPNsense Configuration\n",
            wantErr:  false,
        },
        // Add more test cases
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := ConvertConfig(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("ConvertConfig() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if result != tt.expected {
                t.Errorf("ConvertConfig() = %v, want %v", result, tt.expected)
            }
        })
    }
}

// Test helpers should use t.Helper()
func setupTestConfig(t *testing.T) *Config {
    t.Helper()
    return &Config{
        InputFile:  "testdata/config.xml",
        OutputFile: "testdata/output.md",
    }
}
```

### 3.12. Error Handling Best Practices

- **Custom Error Types:** Create domain-specific error types when appropriate:
```go
type ParseError struct {
    Message string
    Line    int
    Column  int
}

func (e *ParseError) Error() string {
    return fmt.Sprintf("parse error at line %d, column %d: %s", e.Line, e.Column, e.Message)
}
```
- **Error Wrapping:** Use `fmt.Errorf` with `%w` for error context:
```go
if err := xml.Unmarshal(data, &config); err != nil {
    return nil, fmt.Errorf("failed to unmarshal config: %w", err)
}
```
- **Error Checking:** Use `errors.Is()` and `errors.As()` for error type checking.

### 3.13. Performance Considerations

- **Memory Efficiency:** Use streaming for large XML files when possible.
- **Concurrency:** Use goroutines and channels for I/O-bound operations.
- **Profiling:** Use `go tool pprof` for performance analysis.
- **Benchmarks:** Write benchmarks for performance-critical code paths.
- **Zero-Value Friendliness:** Design structs that work correctly when initialized with zero values.

### 3.14. Security Best Practices

- **Input Validation:** Validate all input data and sanitize user inputs.
- **No Secrets in Code:** Use environment variables or secure vaults for secrets.
- **Error Messages:** Avoid exposing sensitive information in error messages.
- **Command Injection:** Avoid command injection vulnerabilities in CLI tools.

This document provides a comprehensive framework with shared development standards that apply across all projects, with specific Go language implementations that follow consistent patterns while respecting the established rule precedence.
