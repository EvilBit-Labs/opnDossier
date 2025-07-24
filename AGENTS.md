# AI Agent Coding Standards and Project Structure

This document outlines the preferred coding standards, architectural principles, and development workflows for Go projects.

## 1. Core Philosophy

- **Operator-Focused:** Build tools for operators, by operators. Workflows should be intuitive and efficient for the end-user.
- **Offline-First:** Systems should be designed to operate in fully offline or airgapped environments. This means no external dependencies, no telemetry, and support for data exchange via portable bundles.
- **Structured Data:** Data should be structured, versioned, and portable. This enables auditable, actionable, and reliable systems.
- **Framework-First:** Leverage the built-in functionality of Go and established libraries. Avoid custom solutions when a well-established, predictable one already exists.

## 2. Architecture and Technology Stack

### 2.1. Technology Stack

| Layer      | Technology                                               |
| ---------- | -------------------------------------------------------- |
| CLI Tool   | `cobra` + `viper` + `charmbracelet/lipgloss`            |
| Config     | `charmbracelet/fang` for configuration parsing           |
| Display    | `charmbracelet/glamour` for markdown rendering           |
| Data Model | Go structs with `encoding/xml` and `encoding/json`      |
| Testing    | Go's built-in `testing` package                          |

### 2.2. CLI Architecture

- **Command Structure:** Use `cobra` for CLI command organization with consistent verb patterns (`create`, `list`, `get`, `update`, `delete`).
- **Configuration:** Use `charmbracelet/fang` for configuration management with support for environment variables, config files, and command-line flags.
- **Output Formatting:** Use `charmbracelet/lipgloss` for styled terminal output and `charmbracelet/glamour` for markdown rendering.
- **Error Handling:** Use Go's error handling patterns with `fmt.Errorf` and `errors.Wrap` for context preservation.
- **Offline Operation:** The CLI must be fully functional in an offline environment, with support for importing and exporting data bundles.

### 2.3. Data Processing

- **XML Parsing:** Use Go's `encoding/xml` package for parsing XML configuration files.
- **Data Models:** Define clear struct types with appropriate tags for XML/JSON serialization.
- **Validation:** Implement validation using struct tags and custom validation functions.
- **Transformation:** Use functional programming patterns for data transformation pipelines.

## 3. Go Code Style

- **Tools:**
    - **`gofmt`:** For code formatting (run automatically on save).
    - **`golangci-lint`:** For comprehensive linting.
    - **`go vet`:** For static analysis.
    - **`go test`:** For testing.
- **Formatting:**
    - Use `gofmt` with default settings.
    - Line length: Follow Go conventions (typically 80-120 characters).
    - Indentation: Use tabs (Go standard).
- **Naming Conventions:**
    - Packages: `snake_case` or single word.
    - Variables/functions: `camelCase`.
    - Constants: `camelCase` or `ALL_CAPS` for exported constants.
    - Types: `PascalCase`.
    - Interfaces: `PascalCase` ending with `-er` when appropriate.
- **Error Handling:** Always check errors and provide meaningful context using `fmt.Errorf` or `errors.Wrap`.
- **Logging:** Use structured logging with `log/slog` or `logrus` instead of `fmt.Printf`.

## 4. Project Structure

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

## 5. Testing and Quality

- **Framework:** Use Go's built-in `testing` package.
- **Test Types:**
    - **Unit Tests:** Verify individual functions and methods.
    - **Integration Tests:** Verify interactions between components.
    - **Table-Driven Tests:** Use for testing multiple input scenarios.
- **Test Coverage:** Use `go test -cover` to measure code coverage. Aim for >80% coverage.
- **Benchmarks:** Use `go test -bench` for performance-critical code.
- **Pre-commit Hooks:** Use `pre-commit` to run `gofmt`, `golangci-lint`, and tests automatically.

## 6. Development Workflow

- **Task Runner:** Use `Justfile` for running common development tasks. Key commands include:
    - `just install`: Install dependencies and tools.
    - `just format`: Format code with `gofmt`.
    - `just lint`: Run linting with `golangci-lint`.
    - `just test`: Run the test suite.
    - `just build`: Build the application.
    - `just check`: Run pre-commit checks
    - `just ci-check`: Run checks, format, lint, and tests
- **Dependency Management:** Use Go modules (`go.mod`) for dependency management.
- **Commit Conventions:** Follow the [Conventional Commits](https://www.conventionalcommits.org) specification.
    - **Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `build`, `ci`, `chore`, `perf`.
    - **Breaking Changes:** Use `!` in the type/scope (e.g., `feat(cli)!:`) or a `BREAKING CHANGE:` footer.

## 7. CLI Tool Specific Guidelines

### 7.1. Command Structure
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

### 7.2. Configuration with Fang
```go
// Use fang for configuration management
type Config struct {
    InputFile  string `env:"INPUT_FILE" flag:"input" short:"i" desc:"Input XML file"`
    OutputFile string `env:"OUTPUT_FILE" flag:"output" short:"o" desc:"Output markdown file"`
    Display    bool   `env:"DISPLAY" flag:"display" short:"d" desc:"Display in terminal"`
}
```

### 7.3. Styled Output with Lipgloss
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

### 7.4. Markdown Rendering with Glamour
```go
// Use glamour for markdown rendering
func renderMarkdown(content string) (string, error) {
    return glamour.Render(content, "dark")
}
```

## 8. Error Handling Patterns

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

## 9. Testing Patterns

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
```

## 10. Performance Considerations

- **Memory Efficiency:** Use streaming for large XML files when possible.
- **Concurrency:** Use goroutines and channels for I/O-bound operations.
- **Profiling:** Use `go tool pprof` for performance analysis.
- **Benchmarks:** Write benchmarks for performance-critical code paths.

This revised standard maintains the core philosophy while adapting to Go's conventions and the specific requirements of your OPNsense configuration processing tool.
