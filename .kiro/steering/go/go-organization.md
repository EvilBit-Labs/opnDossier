---
inclusion: fileMatch
fileMatchPattern:
  - "**/*.go"
  - "**/go.mod"
  - "**/go.sum"
---

# Go Development Standards for opnDossier

## Critical Quality Gates

**MANDATORY before task completion:**

- Run `just ci-check` and ensure it passes completely
- All Go code formatted with `gofmt`
- No linting errors from `golangci-lint`
- Tests pass with >80% coverage

## Project Architecture

### Package Structure (REQUIRED)

```text
opnDossier/
├── cmd/                        # CLI commands (Cobra)
├── internal/                   # Private application logic
│   ├── model/                  # Core data structures with XML tags
│   ├── parser/                 # XML parsing (encoding/xml)
│   ├── audit/                  # Plugin management & compliance
│   ├── plugins/                # Compliance implementations
│   ├── converter/              # Format conversion utilities
│   ├── display/                # Terminal output (lipgloss)
│   └── templates/              # Output templates
├── testdata/                   # Test fixtures and sample configs
├── go.mod                      # Dependencies
└── main.go                     # Entry point
```

### Technology Stack (REQUIRED)

- **CLI**: `cobra` v1.8.0 for commands
- **Config**: `charmbracelet/fang` + `viper` for configuration
- **Terminal**: `charmbracelet/lipgloss` for styling, `charmbracelet/log` for logging
- **XML**: `encoding/xml` (standard library) for OPNsense parsing
- **Markdown**: `github.com/nao1215/markdown` for programmatic generation

## Code Standards

### Error Handling (MANDATORY)

```go
// Always wrap errors with context
func parseConfig(data []byte) (*Config, error) {
    var config Config
    if err := xml.Unmarshal(data, &config); err != nil {
        return nil, fmt.Errorf("failed to unmarshal config: %w", err)
    }
    return &config, nil
}

// Custom error types for domain-specific errors
type ParseError struct {
    File    string
    Line    int
    Element string
    Cause   error
}

func (e *ParseError) Error() string {
    return fmt.Sprintf("parse error in %s at line %d, element <%s>: %v",
        e.File, e.Line, e.Element, e.Cause)
}
```

### Logging (MANDATORY)

```go
// Use charmbracelet/log for structured logging
import "github.com/charmbracelet/log"

func processConfig(config *Config) error {
    log.Info("processing configuration",
        "input_file", config.InputFile,
        "output_file", config.OutputFile)

    if err := validateConfig(config); err != nil {
        log.Error("validation failed", "error", err)
        return fmt.Errorf("config validation failed: %w", err)
    }

    log.Info("configuration processed successfully")
    return nil
}
```

### Data Models (REQUIRED Pattern)

```go
// Core data structures with strict XML tag mapping
type OpnSenseDocument struct {
    System     SystemConfig    `xml:"system" json:"system" yaml:"system"`
    Interfaces InterfaceConfig `xml:"interfaces" json:"interfaces" yaml:"interfaces"`
    Filter     FilterConfig    `xml:"filter" json:"filter" yaml:"filter"`
}

// Audit findings with severity levels
type Finding struct {
    ID          string `json:"id"`
    Severity    string `json:"severity"`    // CRITICAL, HIGH, MEDIUM, LOW
    Title       string `json:"title"`
    Description string `json:"description"`
    Element     string `json:"element"`
    Remediation string `json:"remediation"`
}
```

### CLI Commands (REQUIRED Pattern)

```go
var convertCmd = &cobra.Command{
    Use:   "convert [config.xml]",
    Short: "Convert OPNsense configuration to structured formats",
    Long: `Convert an OPNsense XML configuration file to markdown, JSON, or YAML.

Examples:
  opndossier convert config.xml
  opndossier convert config.xml --output report.md --audit`,
    Args: cobra.ExactArgs(1),
    RunE: runConvert,
}

func runConvert(cmd *cobra.Command, args []string) error {
    // Implementation with proper error handling
    return processConfig(args[0])
}
```

## Testing Standards

### Table-Driven Tests (REQUIRED)

```go
func TestParseConfig(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    *Config
        wantErr bool
    }{
        {
            name:    "valid config",
            input:   "testdata/valid.xml",
            want:    &Config{System: SystemConfig{Hostname: "test"}},
            wantErr: false,
        },
        {
            name:    "invalid xml",
            input:   "testdata/invalid.xml",
            want:    nil,
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel()
            got, err := ParseConfig(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("ParseConfig() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if !reflect.DeepEqual(got, tt.want) {
                t.Errorf("ParseConfig() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### Test Helpers (REQUIRED)

```go
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
    require.NoError(t, err)
    t.Cleanup(func() { os.Remove(tmpfile.Name()) })

    _, err = tmpfile.WriteString(content)
    require.NoError(t, err)
    require.NoError(t, tmpfile.Close())

    return tmpfile.Name()
}
```

## Plugin Architecture (REQUIRED)

### Plugin Interface

```go
// CompliancePlugin defines the interface for security compliance plugins
type CompliancePlugin interface {
    Name() string
    Check(config *model.OpnSenseDocument) []Finding
    Metadata() PluginMetadata
}

// Plugin implementation example
type STIGPlugin struct{}

func (p *STIGPlugin) Name() string {
    return "stig"
}

func (p *STIGPlugin) Check(config *model.OpnSenseDocument) []Finding {
    var findings []Finding
    // Implementation with specific STIG compliance checks
    return findings
}
```

## Performance Requirements

- Handle configuration files up to 100MB
- Process 10,000+ rules in <30 seconds
- Memory usage <500MB for typical configs
- Startup time <1 second

## Security Requirements

- Validate all input data
- Use restrictive file permissions (0600 for configs)
- No hardcoded secrets or credentials
- Sanitize user inputs and file paths
- Handle sensitive data appropriately

## Forbidden Patterns

- No `fmt.Printf` for logging (use `charmbracelet/log`)
- No external network dependencies
- No custom XML parsing (use `encoding/xml`)
- No hardcoded file paths or credentials

## Development Workflow

```bash
# Essential commands (run before committing)
just format    # Format code and docs
just lint      # Static analysis
just test      # Run test suite
just ci-check  # Comprehensive validation (MANDATORY)
```
