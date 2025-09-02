# Design Document

## Overview

This design document outlines the implementation of snapshot testing for opnDossier using the go-snaps library. The design focuses on replacing existing string-based tests with comprehensive snapshot validation, providing better test reliability and maintainability while ensuring consistent CLI output and generated report content.

## Architecture

### Core Components

```text
Snapshot Testing Architecture
├── Test Infrastructure
│   ├── go-snaps Integration
│   ├── Test Helpers and Utilities
│   └── Snapshot Organization
├── CLI Output Capture
│   ├── Command Execution Wrapper
│   ├── Output Normalization
│   └── Cross-Platform Handling
├── Report Content Validation
│   ├── Markdown Snapshot Testing
│   ├── JSON/YAML Validation
│   └── Plugin Output Capture
└── Test Data Management
    ├── Sample Configuration Files
    ├── Expected Output Organization
    └── Snapshot File Management
```

### Integration Points

The snapshot testing system integrates with existing opnDossier components:

- **CLI Commands**: Capture output from `convert`, `display`, and `validate` commands
- **Report Generation**: Validate markdown, JSON, and YAML output formats
- **Plugin System**: Test compliance plugin findings and recommendations
- **Parser**: Validate XML parsing and data model conversion
- **Template System**: Ensure template rendering consistency

## Components and Interfaces

### Snapshot Test Helper Interface

```go
// SnapshotTestHelper provides utilities for snapshot testing
type SnapshotTestHelper interface {
    // CaptureCommandOutput executes a CLI command and captures output
    CaptureCommandOutput(cmd string, args []string, input io.Reader) (*CommandOutput, error)

    // NormalizeOutput normalizes platform-specific differences
    NormalizeOutput(output string) string

    // CreateSnapshot creates or updates a snapshot for the given test
    CreateSnapshot(t *testing.T, name string, content interface{})

    // ValidateSnapshot compares content against stored snapshot
    ValidateSnapshot(t *testing.T, name string, content interface{})
}

// CommandOutput represents captured CLI command output
type CommandOutput struct {
    Stdout   string
    Stderr   string
    ExitCode int
    Duration time.Duration
}
```

### Snapshot Organization Structure

```go
// SnapshotConfig defines snapshot test configuration
type SnapshotConfig struct {
    // TestDataDir is the directory containing sample configurations
    TestDataDir string

    // SnapshotDir is the directory for storing snapshot files
    SnapshotDir string

    // NormalizePaths indicates whether to normalize file paths
    NormalizePaths bool

    // NormalizeTimestamps indicates whether to normalize timestamps
    NormalizeTimestamps bool

    // Platform-specific settings
    PlatformSpecific bool
}

// SnapshotTest represents a single snapshot test case
type SnapshotTest struct {
    Name        string
    Description string
    Command     string
    Args        []string
    InputFile   string
    Config      SnapshotConfig
}
```

### Test Categories and Organization

#### CLI Command Tests

```go
// CLISnapshotTests contains snapshot tests for CLI commands
type CLISnapshotTests struct {
    ConvertTests  []SnapshotTest
    DisplayTests  []SnapshotTest
    ValidateTests []SnapshotTest
    AuditTests    []SnapshotTest
}
```

#### Report Generation Tests

```go
// ReportSnapshotTests contains snapshot tests for report generation
type ReportSnapshotTests struct {
    MarkdownTests []SnapshotTest
    JSONTests     []SnapshotTest
    YAMLTests     []SnapshotTest
    TemplateTests []SnapshotTest
}
```

#### Plugin Output Tests

```go
// PluginSnapshotTests contains snapshot tests for plugin outputs
type PluginSnapshotTests struct {
    STIGTests     []SnapshotTest
    SANSTests     []SnapshotTest
    FirewallTests []SnapshotTest
    CustomTests   []SnapshotTest
}
```

## Data Models

### Snapshot File Organization

```text
testdata/
├── snapshots/
│   ├── cli/
│   │   ├── convert/
│   │   │   ├── basic_conversion.snap
│   │   │   ├── markdown_output.snap
│   │   │   └── json_output.snap
│   │   ├── display/
│   │   │   ├── terminal_output.snap
│   │   │   └── themed_output.snap
│   │   └── validate/
│   │       ├── valid_config.snap
│   │       └── invalid_config.snap
│   ├── reports/
│   │   ├── markdown/
│   │   │   ├── standard_report.snap
│   │   │   ├── blue_team_report.snap
│   │   │   └── red_team_report.snap
│   │   ├── json/
│   │   │   ├── config_export.snap
│   │   │   └── audit_results.snap
│   │   └── yaml/
│   │       ├── config_export.snap
│   │       └── findings_export.snap
│   └── plugins/
│       ├── stig/
│       │   ├── firewall_findings.snap
│       │   └── compliance_report.snap
│       ├── sans/
│       │   ├── network_analysis.snap
│       │   └── security_findings.snap
│       └── firewall/
│           ├── rule_analysis.snap
│           └── security_assessment.snap
└── configs/
    ├── sample.config.1.xml
    ├── sample.config.2.xml
    └── test_scenarios/
        ├── basic_firewall.xml
        ├── complex_rules.xml
        └── ha_configuration.xml
```

### Snapshot Metadata

```go
// SnapshotMetadata contains information about snapshot files
type SnapshotMetadata struct {
    Version     string    `json:"version"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
    TestName    string    `json:"test_name"`
    Description string    `json:"description"`
    Platform    string    `json:"platform,omitempty"`
    ConfigFile  string    `json:"config_file"`
    Command     string    `json:"command"`
    Args        []string  `json:"args"`
}
```

## Error Handling

### Snapshot Comparison Errors

```go
// SnapshotError represents snapshot testing errors
type SnapshotError struct {
    Type        ErrorType
    TestName    string
    Expected    string
    Actual      string
    Diff        string
    Suggestions []string
}

type ErrorType int

const (
    SnapshotMissing ErrorType = iota
    ContentMismatch
    FormatError
    PlatformMismatch
    ValidationError
)

// Error implements the error interface
func (e *SnapshotError) Error() string {
    switch e.Type {
    case SnapshotMissing:
        return fmt.Sprintf("snapshot missing for test '%s': run with -update to create", e.TestName)
    case ContentMismatch:
        return fmt.Sprintf("snapshot mismatch for test '%s':\n%s", e.TestName, e.Diff)
    case FormatError:
        return fmt.Sprintf("snapshot format error for test '%s': %s", e.TestName, e.Actual)
    default:
        return fmt.Sprintf("snapshot error for test '%s'", e.TestName)
    }
}
```

### Error Recovery and Suggestions

```go
// SnapshotErrorHandler provides error handling and recovery suggestions
type SnapshotErrorHandler struct {
    logger *log.Logger
}

func (h *SnapshotErrorHandler) HandleError(err *SnapshotError) {
    switch err.Type {
    case SnapshotMissing:
        h.logger.Info("Creating new snapshot", "test", err.TestName)
        h.suggestSnapshotCreation(err)
    case ContentMismatch:
        h.logger.Warn("Snapshot content mismatch", "test", err.TestName)
        h.suggestContentReview(err)
    case PlatformMismatch:
        h.logger.Warn("Platform-specific differences detected", "test", err.TestName)
        h.suggestPlatformNormalization(err)
    }
}
```

## Testing Strategy

### Test Organization Patterns

#### Table-Driven Snapshot Tests

```go
func TestCLICommandSnapshots(t *testing.T) {
    tests := []struct {
        name       string
        command    string
        args       []string
        inputFile  string
        normalize  bool
    }{
        {
            name:      "convert_basic_markdown",
            command:   "convert",
            args:      []string{"--format", "markdown", "--input"},
            inputFile: "sample.config.1.xml",
            normalize: true,
        },
        {
            name:      "convert_json_output",
            command:   "convert",
            args:      []string{"--format", "json", "--input"},
            inputFile: "sample.config.1.xml",
            normalize: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel()

            helper := NewSnapshotTestHelper(t)
            output, err := helper.CaptureCommandOutput(tt.command, tt.args, tt.inputFile)
            require.NoError(t, err)

            content := output.Stdout
            if tt.normalize {
                content = helper.NormalizeOutput(content)
            }

            snaps.MatchSnapshot(t, content)
        })
    }
}
```

#### Plugin Output Validation

```go
func TestPluginOutputSnapshots(t *testing.T) {
    plugins := []struct {
        name     string
        plugin   audit.CompliancePlugin
        config   string
    }{
        {"stig_basic", stig.NewPlugin(), "sample.config.1.xml"},
        {"sans_network", sans.NewPlugin(), "sample.config.2.xml"},
        {"firewall_rules", firewall.NewPlugin(), "complex_rules.xml"},
    }

    for _, p := range plugins {
        t.Run(p.name, func(t *testing.T) {
            t.Parallel()

            doc := loadTestConfig(t, p.config)
            findings := p.plugin.Check(doc)

            // Normalize timestamps and dynamic content
            normalizedFindings := normalizeFindings(findings)

            snaps.MatchSnapshot(t, normalizedFindings)
        })
    }
}
```

### Cross-Platform Testing Strategy

#### Platform Normalization

```go
// PlatformNormalizer handles platform-specific differences
type PlatformNormalizer struct {
    normalizePaths      bool
    normalizeLineEndings bool
    normalizeTimestamps  bool
}

func (n *PlatformNormalizer) Normalize(content string) string {
    if n.normalizeLineEndings {
        content = strings.ReplaceAll(content, "\r\n", "\n")
    }

    if n.normalizePaths {
        content = n.normalizePaths(content)
    }

    if n.normalizeTimestamps {
        content = n.normalizeTimestamps(content)
    }

    return content
}

func (n *PlatformNormalizer) normalizePaths(content string) string {
    // Convert Windows paths to Unix-style for consistent snapshots
    re := regexp.MustCompile(`[A-Za-z]:\\[^\\s]*`)
    return re.ReplaceAllStringFunc(content, func(path string) string {
        return strings.ReplaceAll(path, "\\", "/")
    })
}
```

### Performance Considerations

#### Efficient Snapshot Storage

```go
// SnapshotCompressor handles large snapshot compression
type SnapshotCompressor struct {
    threshold int // Size threshold for compression
}

func (c *SnapshotCompressor) CompressIfNeeded(content []byte) []byte {
    if len(content) > c.threshold {
        return c.compress(content)
    }
    return content
}

// Parallel Test Execution
func TestSnapshotsParallel(t *testing.T) {
    // Use t.Parallel() for independent snapshot tests
    // Avoid parallel execution for tests that modify shared state
    testCases := getSnapshotTestCases()

    for _, tc := range testCases {
        tc := tc // Capture loop variable
        t.Run(tc.name, func(t *testing.T) {
            if tc.canRunParallel {
                t.Parallel()
            }

            runSnapshotTest(t, tc)
        })
    }
}
```

## Implementation Phases

### Phase 1: Core Infrastructure

1. **go-snaps Integration**

   - Add go-snaps dependency to go.mod
   - Create basic snapshot test helper utilities
   - Implement command output capture mechanism
   - Set up snapshot file organization structure

2. **Platform Normalization**

   - Implement path normalization for cross-platform consistency
   - Add line ending normalization
   - Create timestamp normalization utilities
   - Test cross-platform snapshot consistency

### Phase 2: CLI Command Testing

1. **Convert Command Snapshots**

   - Replace existing string-based tests in `cmd/convert_test.go`
   - Create snapshots for markdown, JSON, and YAML outputs
   - Add test cases for different configuration scenarios
   - Validate output format consistency

2. **Display Command Snapshots**

   - Replace string parsing tests in display command tests
   - Create snapshots for terminal output with different themes
   - Add test cases for various display options
   - Validate styling and formatting consistency

3. **Validate Command Snapshots**

   - Create snapshots for validation success and error cases
   - Replace existing error message string comparisons
   - Add comprehensive validation scenario coverage
   - Ensure consistent error reporting format

### Phase 3: Report Generation Testing

1. **Markdown Report Snapshots**

   - Replace template-based string tests with snapshot validation
   - Create snapshots for standard, blue team, and red team reports
   - Add test cases for different audit modes
   - Validate report structure and content consistency

2. **JSON/YAML Export Snapshots**

   - Create snapshots for structured data exports
   - Replace JSON parsing and validation tests
   - Add comprehensive export format coverage
   - Ensure data integrity across format conversions

### Phase 4: Plugin Output Validation

1. **Compliance Plugin Snapshots**

   - Create snapshots for STIG, SANS, and Firewall plugin outputs
   - Replace finding validation string tests
   - Add comprehensive plugin scenario coverage
   - Validate finding structure and content consistency

2. **Audit Result Integration**

   - Create snapshots for combined audit results
   - Test plugin interaction and finding aggregation
   - Validate audit report generation with plugin findings
   - Ensure consistent audit output formatting

## Migration Strategy

### Identifying Tests to Replace

1. **String Parsing Tests**

   - Tests using `strings.Contains()` for output validation
   - Tests using regular expressions for content matching
   - Tests parsing JSON/YAML output manually
   - Tests validating specific output formatting

2. **Fragile Assertion Tests**

   - Tests sensitive to whitespace changes
   - Tests dependent on exact string matching
   - Tests validating complex output structures
   - Tests checking multiple output elements

### Migration Process

1. **Assessment Phase**

   - Identify all string-based tests in the codebase
   - Categorize tests by complexity and migration priority
   - Document current test coverage and expected behavior
   - Plan migration timeline and dependencies

2. **Conversion Phase**

   - Convert high-priority tests first (CLI commands, report generation)
   - Maintain existing test behavior during conversion
   - Add snapshot tests alongside existing tests initially
   - Validate snapshot test coverage matches original tests

3. **Cleanup Phase**

   - Remove original string-based tests after snapshot validation
   - Update test documentation and examples
   - Optimize snapshot organization and structure
   - Add comprehensive snapshot test coverage reporting

## Quality Assurance

### Snapshot Validation

- **Content Integrity**: Ensure snapshots capture complete output
- **Format Consistency**: Validate snapshot format across different test types
- **Platform Compatibility**: Test snapshot consistency across operating systems
- **Version Control**: Ensure snapshots are reviewable and maintainable in Git

### Performance Monitoring

- **Test Execution Time**: Monitor snapshot test performance vs. string tests
- **Snapshot File Size**: Track snapshot storage requirements
- **Memory Usage**: Validate memory efficiency during snapshot comparison
- **CI/CD Integration**: Ensure snapshot tests don't slow down build pipeline

### Maintenance Guidelines

- **Snapshot Updates**: Clear process for updating snapshots when output changes
- **Review Process**: Guidelines for reviewing snapshot changes in pull requests
- **Documentation**: Comprehensive documentation for snapshot test maintenance
- **Tooling**: Utilities for snapshot management and cleanup
