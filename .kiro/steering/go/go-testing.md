---
inclusion: fileMatch
fileMatchPattern:
  - '**/*_test.go'
  - '**/testdata/**'
---

# Go Testing Standards for opnDossier

## Test Coverage Requirements

- **>80% test coverage** required for all packages
- **Race detection**: All tests must pass with `go test -race`
- **Table-driven tests**: Use for comprehensive scenario coverage
- **Parallel execution**: Use `t.Parallel()` when safe for performance

## Test Structure and Naming

Use descriptive test names following `TestFunction_Scenario_Expected` pattern:

```go
func TestParseOPNsenseConfig_ValidXML_ReturnsDocument(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected *model.OpnSenseDocument
        wantErr  bool
    }{
        {
            name:     "valid opnsense config",
            input:    "<opnsense><system><hostname>firewall</hostname></system></opnsense>",
            expected: &model.OpnSenseDocument{System: model.SystemConfig{Hostname: "firewall"}},
            wantErr:  false,
        },
        {
            name:     "malformed xml",
            input:    "<opnsense><system>",
            expected: nil,
            wantErr:  true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel() // Use when safe for performance

            result, err := parser.ParseConfig([]byte(tt.input))
            if (err != nil) != tt.wantErr {
                t.Errorf("ParseConfig() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if !reflect.DeepEqual(result, tt.expected) {
                t.Errorf("ParseConfig() = %v, want %v", result, tt.expected)
            }
        })
    }
}
```

## opnDossier-Specific Test Patterns

### XML Configuration Testing

```go
func TestParseFirewallRules_LargeConfig_HandlesPerformance(t *testing.T) {
    // Use realistic OPNsense test data from testdata/
    configData := loadTestConfig(t, "testdata/sample.config.1.xml")

    start := time.Now()
    doc, err := parser.ParseConfig(configData)
    duration := time.Since(start)

    if err != nil {
        t.Fatalf("ParseConfig() failed: %v", err)
    }

    // Performance requirement: <30 seconds for 10,000+ rules
    if duration > 30*time.Second {
        t.Errorf("ParseConfig() took %v, expected <30s", duration)
    }

    if len(doc.Filter.Rules) == 0 {
        t.Error("Expected firewall rules, got none")
    }
}
```

### Plugin Testing Pattern

```go
func TestSTIGPlugin_Check_ReturnsFindings(t *testing.T) {
    plugin := plugins.NewSTIGPlugin()
    doc := &model.OpnSenseDocument{
        Filter: model.FilterConfig{
            Rules: []model.FirewallRule{
                {Source: "any", Destination: model.Target{Port: "22"}}, // SSH from any
            },
        },
    }

    findings := plugin.Check(doc)

    if len(findings) == 0 {
        t.Error("Expected STIG findings for SSH from any, got none")
    }

    // Verify finding structure
    for _, finding := range findings {
        if finding.Severity == "" {
            t.Error("Finding missing severity level")
        }
        if finding.Message == "" {
            t.Error("Finding missing message")
        }
    }
}
```

## Test Helpers and Utilities

```go
func loadTestConfig(t *testing.T, filename string) []byte {
    t.Helper()
    data, err := os.ReadFile(filename)
    if err != nil {
        t.Fatalf("Failed to load test config %s: %v", filename, err)
    }
    return data
}

func createTempConfigFile(t *testing.T, content string) string {
    t.Helper()
    tmpfile, err := os.CreateTemp("", "opnsense-test-*.xml")
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
```

## Error Testing Requirements

Always test error conditions with proper context:

```go
func TestParseConfig_InvalidXML_ReturnsWrappedError(t *testing.T) {
    _, err := parser.ParseConfig([]byte("<invalid>"))
    if err == nil {
        t.Fatal("expected error for invalid XML, got nil")
    }

    // Verify error wrapping and context
    if !strings.Contains(err.Error(), "parsing OPNsense config") {
        t.Errorf("error should contain context, got: %s", err.Error())
    }

    var parseErr *parser.ParseError
    if !errors.As(err, &parseErr) {
        t.Errorf("expected ParseError, got %T", err)
    }
}
```

## Integration Tests

Use build tags for integration tests:

```go
//go:build integration

package cmd

func TestConvertCommand_EndToEnd_GeneratesReport(t *testing.T) {
    // Test complete workflow: XML → Parse → Audit → Report
    inputFile := "testdata/sample.config.1.xml"
    outputFile := filepath.Join(t.TempDir(), "report.md")

    cmd := &cobra.Command{}
    cmd.SetArgs([]string{"convert", inputFile, "--output", outputFile, "--audit"})

    err := cmd.Execute()
    if err != nil {
        t.Fatalf("Convert command failed: %v", err)
    }

    // Verify output file exists and contains expected content
    content, err := os.ReadFile(outputFile)
    if err != nil {
        t.Fatalf("Failed to read output file: %v", err)
    }

    if !strings.Contains(string(content), "# OPNsense Configuration Report") {
        t.Error("Output missing expected report header")
    }
}
```

## Performance Testing

```go
func BenchmarkParseConfig_LargeFile(b *testing.B) {
    configData := loadTestConfig(b, "testdata/sample.config.7.xml") // Large config

    b.ResetTimer()
    b.ReportAllocs()

    for i := 0; i < b.N; i++ {
        _, err := parser.ParseConfig(configData)
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

## Test Execution Patterns

```bash
# Core test commands (quality gates handled by go-standards.md)
go test ./...                    # All tests
go test -cover ./...             # With coverage reporting
go test -race ./...              # Race condition detection
go test -short ./...             # Skip slow/integration tests
go test -tags=integration ./...  # Integration tests only
go test -bench=. ./...           # Performance benchmarks
```

## Test Data Management

- Use `testdata/` directory for OPNsense configuration samples
- Create realistic test scenarios based on actual OPNsense configs
- Test edge cases: empty configs, malformed XML, large files
- Use constants for common test values and expected results
