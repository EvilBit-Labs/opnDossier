# AI Agent Coding Standards and Project Structure

This document outlines the preferred coding standards, architectural principles, and development workflows for the opnFocus project.

## 📚 Related Documentation

For comprehensive project information, refer to these key documents:

- **[Requirements Document](project_spec/requirements.md)** - Complete project requirements, functional specifications, and technical constraints
- **[System Architecture](ARCHITECTURE.md)** - Detailed system design, component interactions, and deployment patterns
- **[Development Standards](DEVELOPMENT_STANDARDS.md)** - Go-specific coding standards, project structure, and development workflow

These documents provide the foundation for all development decisions and should be consulted when implementing new features or making architectural changes.

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

| Layer      | Technology                                                       |
| ---------- | ---------------------------------------------------------------- |
| CLI Tool   | `cobra` v1.8.0 + `charmbracelet/fang` + `charmbracelet/lipgloss` |
| Config     | `charmbracelet/fang` for configuration parsing                   |
| Display    | `charmbracelet/glamour` for markdown rendering                   |
| Data Model | Go structs with `encoding/xml` and `encoding/json`               |
| Logging    | `charmbracelet/log` for structured logging                       |
| Testing    | Go's built-in `testing` package                                  |

### 3.2. Go Version Requirements

- **Minimum Go Version:** 1.21.6+
- **Recommended Go Version:** 1.24.5+
- **Module Support:** Required (Go modules only)

### 3.3. CLI Architecture

- **Command Structure:** Use `cobra` for CLI command organization with consistent verb patterns (`create`, `list`, `get`, `update`, `delete`)
- **Configuration:** Use `charmbracelet/fang` for configuration management with support for environment variables, config files, and command-line flags
- **Output Formatting:** Use `charmbracelet/lipgloss` for styled terminal output and `charmbracelet/glamour` for markdown rendering
- **Error Handling:** Use Go's error handling patterns with `fmt.Errorf` and `errors.Wrap` for context preservation

### 3.4. Data Processing

- **XML Parsing:** Use Go's `encoding/xml` package for parsing XML configuration files
- **Data Models:** Define clear struct types with appropriate tags for XML/JSON serialization
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
opnfocus/
├── cmd/
│   ├── opnsense.go                        # OPNsense command entry point
│   └── root.go                            # Root command and main entry point
├── internal/
│   ├── config/                            # Configuration handling
│   ├── parser/                            # XML parsing logic
│   ├── converter/                         # Data conversion logic
│   └── display/                           # Output formatting
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

### 3.9. CLI Tool Implementation Examples

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

### 3.10. Error Handling Patterns

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

### 3.11. Documentation Standards

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

### 3.12. Testing Patterns

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

### 3.13. Error Handling Best Practices

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

### 3.14. Performance Considerations

- **Memory Efficiency:** Use streaming for large XML files when possible.
- **Concurrency:** Use goroutines and channels for I/O-bound operations.
- **Profiling:** Use `go tool pprof` for performance analysis.
- **Benchmarks:** Write benchmarks for performance-critical code paths.
- **Zero-Value Friendliness:** Design structs that work correctly when initialized with zero values.

### 3.15. Security Best Practices

- **Input Validation:** Validate all input data and sanitize user inputs.
- **No Secrets in Code:** Use environment variables or secure vaults for secrets.
- **Error Messages:** Avoid exposing sensitive information in error messages.
- **Command Injection:** Avoid command injection vulnerabilities in CLI tools.
- **Security Scanning:** Use `gosec` via golangci-lint for automated security analysis.

This document provides a comprehensive framework with shared development standards that apply across all projects, with specific Go language implementations that follow consistent patterns while respecting the established rule precedence.

## 4. Implementation Guidelines

This section provides actionable guidance for contributors and AI agents working on this project. These guidelines ensure consistency, reliability, and maintainability across all contributions.

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

#### Go Toolchain Commands

When working directly with Go (when just commands are not available):

```bash
# Dependency management
go mod tidy             # Clean up dependencies
go mod download         # Download dependencies
go mod verify           # Verify dependency checksums

# Code quality
golangci-lint run       # Run comprehensive linting
go vet ./...            # Static analysis
go fmt ./...            # Format code

# Testing
go test ./...           # Run all tests
go test -race ./...     # Run tests with race detection
go test -cover ./...    # Run tests with coverage

# Building
go build                # Build the application
go install             # Build and install
```

### 4.2. Testing Tiers

The project implements a three-tier testing strategy:

#### Tier 1: Unit Tests

- **Purpose:** Test individual functions and methods in isolation
- **Location:** `*_test.go` files alongside source code
- **Command:** `go test ./...` or `just test`
- **Coverage Target:** >80% for critical business logic
- **Speed:** \<100ms per test

```go
// Example unit test structure
func TestParseConfig_ValidXML_ReturnsConfig(t *testing.T) {
    t.Parallel()

    input := `<opnsense><version>24.1</version></opnsense>`

    config, err := ParseConfig(strings.NewReader(input))

    assert.NoError(t, err)
    assert.Equal(t, "24.1", config.Version)
}
```

#### Tier 2: Integration Tests

- **Purpose:** Test interactions between components
- **Location:** `*_test.go` files with `//go:build integration` tag
- **Command:** `go test -tags=integration ./...`
- **Focus:** File I/O, configuration parsing, command execution

```go
//go:build integration

func TestConvertCommand_RealFile_GeneratesMarkdown(t *testing.T) {
    tmpDir := t.TempDir()
    inputFile := filepath.Join(tmpDir, "config.xml")
    outputFile := filepath.Join(tmpDir, "output.md")

    // Create test XML file
    err := os.WriteFile(inputFile, testXMLData, 0644)
    require.NoError(t, err)

    // Run conversion command
    cmd := exec.Command("./opnFocus", "convert", inputFile, "-o", outputFile)
    err = cmd.Run()

    require.NoError(t, err)
    assert.FileExists(t, outputFile)
}
```

#### Tier 3: End-to-End Tests

- **Purpose:** Test complete user workflows
- **Location:** `e2e/` directory
- **Command:** `go test ./e2e/...`
- **Focus:** Full CLI interactions, file processing workflows

### 4.3. Dependency Injection Patterns

Use dependency injection to improve testability and maintainability:

#### Interface-Based Design

```go
// Define interfaces for dependencies
type ConfigReader interface {
    ReadConfig(filename string) (*Config, error)
}

type MarkdownWriter interface {
    WriteMarkdown(content string, filename string) error
}

// Implement concrete types
type XMLConfigReader struct{}

func (r *XMLConfigReader) ReadConfig(filename string) (*Config, error) {
    // Implementation
}

// Use dependency injection in main components
type Converter struct {
    reader ConfigReader
    writer MarkdownWriter
}

func NewConverter(reader ConfigReader, writer MarkdownWriter) *Converter {
    return &Converter{
        reader: reader,
        writer: writer,
    }
}
```

#### Testing with Mocks

```go
// Create test doubles for dependencies
type mockConfigReader struct {
    config *Config
    err    error
}

func (m *mockConfigReader) ReadConfig(filename string) (*Config, error) {
    return m.config, m.err
}

// Use in tests
func TestConverter_Convert_CallsDependencies(t *testing.T) {
    mockReader := &mockConfigReader{config: &Config{Version: "24.1"}}
    mockWriter := &mockMarkdownWriter{}

    converter := NewConverter(mockReader, mockWriter)

    err := converter.Convert("input.xml", "output.md")

    assert.NoError(t, err)
    assert.True(t, mockWriter.writeCalled)
}
```

### 4.4. Error Handling Patterns

#### Structured Error Types

Create domain-specific error types for better error handling:

```go
// Define error types
type ValidationError struct {
    Field   string
    Value   interface{}
    Message string
}

func (e *ValidationError) Error() string {
    return fmt.Sprintf("validation failed for field '%s' with value '%v': %s",
        e.Field, e.Value, e.Message)
}

type ProcessingError struct {
    Step    string
    Cause   error
    Context map[string]interface{}
}

func (e *ProcessingError) Error() string {
    return fmt.Sprintf("processing failed at step '%s': %v", e.Step, e.Cause)
}

func (e *ProcessingError) Unwrap() error {
    return e.Cause
}
```

#### Error Wrapping and Context

```go
// Always provide context when wrapping errors
func parseConfigFile(filename string) (*Config, error) {
    data, err := os.ReadFile(filename)
    if err != nil {
        return nil, fmt.Errorf("failed to read config file '%s': %w", filename, err)
    }

    var config Config
    if err := xml.Unmarshal(data, &config); err != nil {
        return nil, &ProcessingError{
            Step:  "xml_parsing",
            Cause: err,
            Context: map[string]interface{}{
                "filename": filename,
                "filesize": len(data),
            },
        }
    }

    if err := validateConfig(&config); err != nil {
        return nil, fmt.Errorf("config validation failed for '%s': %w", filename, err)
    }

    return &config, nil
}
```

#### Error Handling in CLI Commands

```go
// Handle errors gracefully in CLI commands
func runConvertCommand(cmd *cobra.Command, args []string) error {
    filename := args[0]

    config, err := parseConfigFile(filename)
    if err != nil {
        // Check for specific error types
        var validationErr *ValidationError
        if errors.As(err, &validationErr) {
            return fmt.Errorf("configuration validation failed: %s\nPlease check your config file and try again", validationErr.Message)
        }

        var processingErr *ProcessingError
        if errors.As(err, &processingErr) {
            return fmt.Errorf("failed to process config at step '%s': %s\nContext: %+v",
                processingErr.Step, processingErr.Cause, processingErr.Context)
        }

        // Generic error handling
        return fmt.Errorf("failed to process config file '%s': %w", filename, err)
    }

    // Continue with processing...
    return nil
}
```

### 4.5. Logging Guidelines

#### Structured Logging with charmbracelet/log

```go
import (
    "github.com/charmbracelet/log"
    "os"
)

// Initialize logger with appropriate level
func initLogger(debug bool) *log.Logger {
    level := log.InfoLevel
    if debug {
        level = log.DebugLevel
    }

    return log.NewWithOptions(os.Stdout, log.Options{
        Level: level,
    })
}

// Use structured logging throughout the application
func processConfig(logger *log.Logger, filename string) error {
    logger.Info("Starting config processing",
        "filename", filename,
        "timestamp", time.Now())

    config, err := parseConfigFile(filename)
    if err != nil {
        logger.Error("Failed to parse config file",
            "filename", filename,
            "error", err,
            "step", "parsing")
        return err
    }

    logger.Debug("Config parsed successfully",
        "filename", filename,
        "version", config.Version,
        "sections", len(config.Sections))

    // Continue processing...
    logger.Info("Config processing completed",
        "filename", filename,
        "duration", time.Since(start))

    return nil
}
```

#### Log Levels and Usage

- **Debug:** Detailed information for troubleshooting (enabled with `--debug` flag)
- **Info:** General operational messages (default level)
- **Warn:** Recoverable issues that should be noted
- **Error:** Error conditions that prevent operation completion

#### Context-Aware Logging

```go
// Add context to logger for request/operation tracking
func handleConversion(logger *log.Logger, req ConversionRequest) error {
    // Create logger with operation context
    opLogger := logger.With(
        "operation", "conversion",
        "request_id", req.ID,
        "input_file", req.InputFile,
    )

    opLogger.Info("Starting conversion")

    // Use contextual logger throughout the operation
    if err := validateRequest(opLogger, req); err != nil {
        opLogger.Error("Request validation failed", "error", err)
        return err
    }

    // Continue with contextual logging...
    return nil
}
```

### 4.6. Security Practices

#### Secret Management

**NEVER hardcode secrets in source code.** Follow these patterns:

```go
// ✅ Good: Use environment variables
func getAPIKey() (string, error) {
    key := os.Getenv("API_KEY")
    if key == "" {
        return "", fmt.Errorf("API_KEY environment variable is required")
    }
    return key, nil
}

// ✅ Good: Use configuration files with environment variable substitution
type Config struct {
    APIKey    string `env:"API_KEY" flag:"api-key" desc:"API key for external service"`
    Database  string `env:"DATABASE_URL" flag:"db-url" desc:"Database connection string"`
}

// ❌ Bad: Hardcoded secrets
const APIKey = "sk-1234567890abcdef"  // Never do this!
```

#### Input Validation and Sanitization

```go
// Validate all user inputs
func validateFilename(filename string) error {
    // Check for path traversal attempts
    if strings.Contains(filename, "..") {
        return fmt.Errorf("invalid filename: path traversal not allowed")
    }

    // Check file extension
    if !strings.HasSuffix(filename, ".xml") {
        return fmt.Errorf("invalid file type: only .xml files are supported")
    }

    // Check filename length
    if len(filename) > 255 {
        return fmt.Errorf("filename too long: maximum 255 characters")
    }

    return nil
}

// Sanitize file paths
func sanitizeFilePath(path string) (string, error) {
    // Clean the path
    cleanPath := filepath.Clean(path)

    // Ensure it's not an absolute path if not expected
    if filepath.IsAbs(cleanPath) && !allowAbsolutePaths {
        return "", fmt.Errorf("absolute paths not allowed")
    }

    return cleanPath, nil
}
```

#### Secure File Operations

```go
// Create files with appropriate permissions
func writeConfigFile(filename string, data []byte) error {
    // Use restrictive permissions (owner read/write only)
    return os.WriteFile(filename, data, 0600)
}

// Safely create temporary files
func createTempFile(pattern string) (*os.File, error) {
    // Create in secure temporary directory
    return os.CreateTemp("", pattern)
}

// Validate file size before processing
func validateFileSize(filename string, maxSize int64) error {
    info, err := os.Stat(filename)
    if err != nil {
        return fmt.Errorf("failed to stat file: %w", err)
    }

    if info.Size() > maxSize {
        return fmt.Errorf("file size (%d bytes) exceeds maximum allowed size (%d bytes)",
            info.Size(), maxSize)
    }

    return nil
}
```

#### Configuration Security

```go
// Secure configuration loading
type SecureConfig struct {
    // Non-sensitive configuration
    LogLevel    string `json:"log_level"`
    OutputPath  string `json:"output_path"`

    // Sensitive configuration (loaded from environment)
    APIKey      string `json:"-"` // Don't serialize
    DatabaseURL string `json:"-"` // Don't serialize
}

func LoadConfig(configFile string) (*SecureConfig, error) {
    config := &SecureConfig{}

    // Load non-sensitive config from file
    if configFile != "" {
        data, err := os.ReadFile(configFile)
        if err != nil {
            return nil, fmt.Errorf("failed to read config file: %w", err)
        }

        if err := json.Unmarshal(data, config); err != nil {
            return nil, fmt.Errorf("failed to parse config file: %w", err)
        }
    }

    // Load sensitive config from environment
    config.APIKey = os.Getenv("API_KEY")
    config.DatabaseURL = os.Getenv("DATABASE_URL")

    return config, nil
}
```

### 4.7. AI Agent Guidelines

When AI agents contribute to this project, they should:

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

## 📖 Additional Resources

For comprehensive project understanding, AI agents should familiarize themselves with:

- **[requirements.md](project_spec/requirements.md)** - Complete functional and technical requirements
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System design, data flow, and component architecture
- **[DEVELOPMENT_STANDARDS.md](DEVELOPMENT_STANDARDS.md)** - Go-specific coding standards and project structure

These documents provide the complete context needed for effective development and decision-making within the opnFocus project.
