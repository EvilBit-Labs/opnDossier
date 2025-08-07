---
applyTo: '**/*.go,**/go.mod,**/go.sum'
---

# Go Project Organization Best Practices (Google Standards)

## Package Structure

- Use clear, descriptive package names
- Keep packages focused on a single responsibility
- Use `internal/` for private packages
- Use `pkg/` for public packages that can be imported by others
- Follow standard Go project layout

```text
opndossier/
├── cmd/
│   └── opndossier/
│       └── main.go
├── internal/
│   ├── config/
│   ├── parser/
│   ├── converter/
│   └── display/
├── pkg/
│   └── types/
├── testdata/
├── go.mod
├── go.sum
├── README.md
├── CONTRIBUTING.md
└── LICENSE
```

## File Organization

- Group related functionality in the same file
- Keep files under 500 lines when possible
- Use descriptive file names
- Place tests in `*_test.go` files
- Use consistent file naming conventions

## Naming Conventions

- Use `camelCase` for variables and functions
- Use `PascalCase` for exported types and functions
- Use `snake_case` for package names
- Use `ALL_CAPS` for constants
- Use descriptive, self-documenting names
- Avoid abbreviations unless widely understood

```go
// Good naming examples
var configFile string
var maxRetries = 3
const DefaultTimeout = 30 * time.Second

type ConfigParser struct {
    // fields
}

func ParseConfigFile(filename string) (*Config, error) {
    // implementation
}

// Avoid abbreviations
var cfg *Config  // Bad
var config *Config  // Good

var num int  // Bad
var count int  // Good
```

## Package Dependencies

- Minimize package dependencies
- Use interfaces for loose coupling
- Avoid circular dependencies
- Use dependency injection when appropriate
- Keep dependencies up to date

```go
// Use interfaces for testability and loose coupling
type ConfigParser interface {
    Parse(data []byte) (*Config, error)
    Validate(config *Config) error
}

type XMLParser struct {
    // implementation
}

func (x *XMLParser) Parse(data []byte) (*Config, error) {
    // implementation
}

func (x *XMLParser) Validate(config *Config) error {
    // implementation
}
```

## Error Handling

- Return errors from functions that can fail
- Use `fmt.Errorf` with `%w` for error wrapping
- Create custom error types for domain-specific errors
- Handle errors at the appropriate level
- Use `errors.Is()` and `errors.As()` for error checking

```go
// Custom error types
type ParseError struct {
    Message string
    Line    int
    Column  int
}

func (e *ParseError) Error() string {
    return fmt.Sprintf("parse error at line %d, column %d: %s", e.Line, e.Column, e.Message)
}

func (e *ParseError) Unwrap() error {
    return nil
}

// Error wrapping
func parseConfig(data []byte) (*Config, error) {
    var config Config
    if err := xml.Unmarshal(data, &config); err != nil {
        return nil, fmt.Errorf("failed to unmarshal config: %w", err)
    }

    if err := validateConfig(&config); err != nil {
        return nil, fmt.Errorf("config validation failed: %w", err)
    }

    return &config, nil
}

// Error checking
func processConfig(filename string) error {
    config, err := parseConfigFile(filename)
    if err != nil {
        var parseErr *ParseError
        if errors.As(err, &parseErr) {
            // Handle parse-specific error
            return fmt.Errorf("configuration file has syntax errors: %w", err)
        }
        return fmt.Errorf("failed to process configuration: %w", err)
    }
    return nil
}
```

## Configuration Management

- Use environment variables for configuration
- Provide sensible defaults
- Validate configuration on startup
- Use configuration structs with tags
- Use `charmbracelet/fang` for configuration parsing

```go
type Config struct {
    InputFile  string `env:"INPUT_FILE" flag:"input" short:"i" desc:"Input XML file path"`
    OutputFile string `env:"OUTPUT_FILE" flag:"output" short:"o" desc:"Output markdown file path"`
    Verbose    bool   `env:"VERBOSE" flag:"verbose" short:"v" desc:"Enable verbose output"`
    Display    bool   `env:"DISPLAY" flag:"display" short:"d" desc:"Display result in terminal"`
}

func LoadConfig() (*Config, error) {
    var config Config
    if err := fang.Parse(&config); err != nil {
        return nil, fmt.Errorf("failed to parse configuration: %w", err)
    }

    if err := validateConfig(&config); err != nil {
        return nil, fmt.Errorf("configuration validation failed: %w", err)
    }

    return &config, nil
}

func validateConfig(config *Config) error {
    if config.InputFile == "" {
        return errors.New("input file path is required")
    }
    return nil
}
```

## Logging and Observability

- Use structured logging with `log/slog`
- Include context in log messages
- Use appropriate log levels
- Avoid logging sensitive information
- Use consistent logging patterns

```go
import "log/slog"

func processConfig(config *Config) error {
    logger := slog.With(
        "input_file", config.InputFile,
        "output_file", config.OutputFile,
    )
    logger.Info("starting configuration processing")

    if err := validateConfig(config); err != nil {
        logger.Error("config validation failed", "error", err)
        return err
    }

    if err := parseConfig(config); err != nil {
        logger.Error("config parsing failed", "error", err)
        return err
    }

    logger.Info("configuration processed successfully")
    return nil
}
```

## CLI Structure

- Use `cobra` for command organization
- Group related commands logically
- Provide helpful usage information
- Use consistent flag naming
- Follow CLI design best practices

```go
var rootCmd = &cobra.Command{
    Use:   "opndossier",
    Short: "OPNsense configuration processor",
    Long:  `A CLI tool for processing OPNsense config.xml files and converting them to markdown.`,
    PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
        return setupLogging()
    },
}

var convertCmd = &cobra.Command{
    Use:   "convert [file]",
    Short: "Convert config to markdown",
    Long:  `Convert an OPNsense configuration file to markdown format.`,
    Args:  cobra.ExactArgs(1),
    RunE:  runConvert,
}

func init() {
    rootCmd.AddCommand(convertCmd)

    // Global flags
    rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output")

    // Command-specific flags
    convertCmd.Flags().StringP("output", "o", "", "Output file path")
    convertCmd.Flags().BoolP("display", "d", false, "Display result in terminal")
}

func runConvert(cmd *cobra.Command, args []string) error {
    inputFile := args[0]
    outputFile, _ := cmd.Flags().GetString("output")
    display, _ := cmd.Flags().GetBool("display")

    config := &Config{
        InputFile:  inputFile,
        OutputFile: outputFile,
        Display:    display,
    }

    return processConfig(config)
}
```

## Testing Organization

- Place tests in the same package as the code
- Use table-driven tests for multiple scenarios
- Create test helpers for common setup
- Use test fixtures for complex data
- Use `testdata/` directory for test files

```go
// test_helpers.go
func setupTestConfig(t *testing.T) *Config {
    t.Helper()
    return &Config{
        InputFile:  "testdata/config.xml",
        OutputFile: "testdata/output.md",
    }
}

func createTempFile(t *testing.T, content string) string {
    t.Helper()
    tmpfile, err := os.CreateTemp("", "test-*.xml")
    if err != nil {
        t.Fatal(err)
    }
    t.Cleanup(func() { os.Remove(tmpfile.Name()) })

    if _, err := tmpfile.Write([]byte(content)); err != nil {
        t.Fatal(err)
    }
    if err := tmpfile.Close(); err != nil {
        t.Fatal(err)
    }
    return tmpfile.Name()
}

// main_test.go
func TestConvertConfig(t *testing.T) {
    tests := []struct {
        name     string
        config   *Config
        wantErr  bool
    }{
        {
            name:     "valid config",
            config:   setupTestConfig(t),
            wantErr:  false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := ConvertConfig(tt.config)
            if (err != nil) != tt.wantErr {
                t.Errorf("ConvertConfig() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

## Build and Deployment

- Use `go.mod` for dependency management
- Create build scripts for different platforms
- Use build tags for conditional compilation
- Create Docker images when appropriate
- Use semantic versioning

```go
// +build integration

package main

func TestIntegration(t *testing.T) {
    // integration tests
}

// +build !integration

package main

func TestUnit(t *testing.T) {
    // unit tests
}
```

## Code Review Guidelines

- Review for readability and maintainability
- Check for proper error handling
- Verify test coverage
- Ensure consistent formatting with `gofmt`
- Look for security vulnerabilities
- Check for performance issues

## Performance Considerations

- Profile code for bottlenecks
- Use benchmarks to measure performance
- Optimize critical paths
- Consider memory usage and garbage collection
- Use appropriate data structures
- Use `sync.Pool` for frequently allocated objects

## Security Best Practices

- Validate all input data
- Use secure random number generation
- Avoid command injection vulnerabilities
- Handle sensitive data appropriately
- Use HTTPS for network communication
- Sanitize user inputs
