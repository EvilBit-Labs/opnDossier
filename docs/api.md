# Markdown Builder API Reference

## Overview

The MarkdownBuilder provides a programmatic interface for generating security audit reports from OPNsense configurations. All methods are designed with red team operations in mind, supporting offline usage and output obfuscation.

The programmatic API is designed to deliver significantly faster generation with reduced memory usage compared to template-based generation, while providing full compile-time type safety. Performance characteristics can be measured using the comparative benchmarks in `internal/converter/markdown_bench_test.go`.

## Core Interface

```go
// ReportBuilder interface defines the contract for programmatic report generation.
type ReportBuilder interface {
    // Core section builders
    BuildSystemSection(data *model.OpnSenseDocument) string
    BuildNetworkSection(data *model.OpnSenseDocument) string
    BuildSecuritySection(data *model.OpnSenseDocument) string
    BuildServicesSection(data *model.OpnSenseDocument) string

    // Component builders
    BuildFirewallRulesTable(rules []model.Rule) *markdown.TableSet
    BuildInterfaceTable(interfaces model.Interfaces) *markdown.TableSet
    BuildUserTable(users []model.User) *markdown.TableSet
    BuildGroupTable(groups []model.Group) *markdown.TableSet
    BuildSysctlTable(sysctl []model.SysctlItem) *markdown.TableSet

    // Report generation
    BuildStandardReport(data *model.OpnSenseDocument) (string, error)
    BuildCustomReport(data *model.OpnSenseDocument, options BuildOptions) (string, error)
}
```

## Method Categories

### Security Assessment Methods

These methods provide security analysis and risk assessment capabilities.

```go
// CalculateSecurityScore computes an overall security score (0-100) based on configuration analysis
func (b *MarkdownBuilder) CalculateSecurityScore(data *model.OpnSenseDocument) int

// AssessRiskLevel converts severity strings to human-readable risk levels with emoji indicators
func (b *MarkdownBuilder) AssessRiskLevel(severity string) string // Returns: "🔴 Critical", "🟡 Medium", etc.

// AssessServiceRisk evaluates security risk for individual services
func (b *MarkdownBuilder) AssessServiceRisk(service model.Service) string

// DetermineSecurityZone classifies network interfaces by security zone
func (b *MarkdownBuilder) DetermineSecurityZone(interfaceName string) string
```

### Data Transformation Methods

These methods handle data filtering, grouping, and formatting operations.

```go
// FilterSystemTunables filters system tunables based on security relevance
func (b *MarkdownBuilder) FilterSystemTunables(tunables []model.SysctlItem, securityOnly bool) []model.SysctlItem

// GroupServicesByStatus groups services by their operational status
func (b *MarkdownBuilder) GroupServicesByStatus(services []model.Service) map[string][]model.Service

// FormatInterfaceLinks creates markdown anchor links for interface navigation
func (b *MarkdownBuilder) FormatInterfaceLinks(interfaces model.InterfaceList) string

// FormatSystemStats formats system statistics for report inclusion
func (b *MarkdownBuilder) FormatSystemStats(data *model.OpnSenseDocument) map[string]interface{}
```

### String Utility Methods

These methods provide string manipulation and formatting capabilities.

```go
// EscapeMarkdownSpecialChars escapes special markdown characters to prevent formatting issues
func (b *MarkdownBuilder) EscapeMarkdownSpecialChars(input string) string

// FormatTimestamp converts timestamps to human-readable format
func (b *MarkdownBuilder) FormatTimestamp(timestamp time.Time) string

// TruncateDescription truncates long descriptions while preserving word boundaries
func (b *MarkdownBuilder) TruncateDescription(description string, maxLength int) string

// FormatBoolean converts boolean values to checkmark/X-mark symbols
func (b *MarkdownBuilder) FormatBoolean(value any) string // Returns: "✓" or "✗"
```

## Usage Examples

### Basic Security Report Generation

```go
package main

import (
    "log"
    "github.com/EvilBit-Labs/opnDossier/internal/converter"
    "github.com/EvilBit-Labs/opnDossier/internal/parser"
)

func main() {
    // Parse OPNsense configuration
    parser := parser.NewXMLParser()
    config, err := parser.ParseFile("config.xml")
    if err != nil {
        log.Fatal(err)
    }

    // Create markdown builder
    builder := converter.NewMarkdownBuilder()

    // Generate standard report
    report, err := builder.BuildStandardReport(config)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(report)
}
```

### Custom Security Assessment

```go
func generateCustomSecurityReport(config *model.OpnSenseDocument) string {
    builder := converter.NewMarkdownBuilder()

    // Calculate security metrics
    score := builder.CalculateSecurityScore(config)
    riskLevel := builder.AssessRiskLevel("high")

    // Build custom report sections
    var report strings.Builder

    report.WriteString("# Security Assessment Report\n\n")
    report.WriteString(fmt.Sprintf("**Overall Security Score:** %d/100 (%s)\n\n", score, riskLevel))

    // Add filtered security tunables
    if config.Sysctl != nil {
        securityTunables := builder.FilterSystemTunables(config.Sysctl.Item, true)
        if len(securityTunables) > 0 {
            report.WriteString("## Critical Security Tunables\n\n")
            // Add table generation logic here
        }
    }

    // Add grouped services analysis
    if len(config.Installedpackages.Services) > 0 {
        serviceGroups := builder.GroupServicesByStatus(config.Installedpackages.Services)

        report.WriteString("## Service Status Analysis\n\n")
        report.WriteString(fmt.Sprintf("- **Running Services:** %d\n", len(serviceGroups["running"])))
        report.WriteString(fmt.Sprintf("- **Stopped Services:** %d\n", len(serviceGroups["stopped"])))
    }

    return report.String()
}
```

### Advanced Table Generation

```go
func generateFirewallAudit(config *model.OpnSenseDocument) string {
    builder := converter.NewMarkdownBuilder()

    // Extract firewall rules
    var allRules []model.Rule
    if config.Filter != nil {
        allRules = append(allRules, config.Filter.Rule...)
    }

    // Build firewall rules table
    rulesTable := builder.BuildFirewallRulesTable(allRules)

    // Build interface table
    interfaceTable := builder.BuildInterfaceTable(config.Interfaces)

    // Combine into comprehensive report
    var report strings.Builder
    report.WriteString("# Firewall Configuration Audit\n\n")
    report.WriteString("## Firewall Rules\n\n")
    report.WriteString(rulesTable.String())
    report.WriteString("\n## Network Interfaces\n\n")
    report.WriteString(interfaceTable.String())

    return report.String()
}
```

## Error Handling Patterns

### Standard Error Handling

```go
func processConfigSafely(filename string) error {
    builder := converter.NewMarkdownBuilder()

    // Parse configuration
    parser := parser.NewXMLParser()
    config, err := parser.ParseFile(filename)
    if err != nil {
        return fmt.Errorf("failed to parse config: %w", err)
    }

    // Generate report with error handling
    report, err := builder.BuildStandardReport(config)
    if err != nil {
        switch {
        case errors.Is(err, converter.ErrInvalidData):
            log.Printf("Invalid OPNsense data: %v", err)
            return fmt.Errorf("configuration validation failed: %w", err)
        case errors.Is(err, converter.ErrGenerationFailed):
            log.Printf("Report generation failed: %v", err)
            return fmt.Errorf("markdown generation error: %w", err)
        default:
            log.Printf("Unexpected error: %v", err)
            return fmt.Errorf("unexpected generation error: %w", err)
        }
    }

    // Process successful report
    fmt.Println(report)
    return nil
}
```

### Defensive Programming

```go
func safeSecurityAssessment(config *model.OpnSenseDocument) map[string]interface{} {
    builder := converter.NewMarkdownBuilder()

    results := make(map[string]interface{})

    // Safe security score calculation
    if config != nil {
        results["security_score"] = builder.CalculateSecurityScore(config)
    } else {
        results["security_score"] = 0
        results["error"] = "Invalid configuration"
    }

    // Safe tunable filtering
    if config != nil && config.Sysctl != nil {
        securityTunables := builder.FilterSystemTunables(config.Sysctl.Item, true)
        results["security_tunables_count"] = len(securityTunables)
    } else {
        results["security_tunables_count"] = 0
    }

    // Safe service grouping
    if config != nil && len(config.Installedpackages.Services) > 0 {
        serviceGroups := builder.GroupServicesByStatus(config.Installedpackages.Services)
        results["running_services"] = len(serviceGroups["running"])
        results["stopped_services"] = len(serviceGroups["stopped"])
    } else {
        results["running_services"] = 0
        results["stopped_services"] = 0
    }

    return results
}
```

## Performance Considerations

### Optimization Guidelines

1. **Pre-allocate Slices**: Use capacity hints for better performance

   ```go
   // Good: Pre-allocate with estimated capacity
   results := make([]model.Rule, 0, len(allRules)/3)

   // Avoid: Frequent reallocations
   var results []model.Rule
   ```

2. **Reuse Builders**: Create builders once and reuse for multiple reports

   ```go
   // Good: Reuse builder instance
   builder := converter.NewMarkdownBuilder()
   for _, config := range configs {
       report, _ := builder.BuildStandardReport(config)
       // Process report
   }
   ```

3. **Batch Operations**: Group similar operations together

   ```go
   // Good: Batch multiple assessments
   scores := make([]int, len(configs))
   for i, config := range configs {
       scores[i] = builder.CalculateSecurityScore(config)
   }
   ```

### Memory Management

```go
func efficientReportGeneration(configs []*model.OpnSenseDocument) []string {
    builder := converter.NewMarkdownBuilder()

    // Pre-allocate results slice
    reports := make([]string, 0, len(configs))

    // Process in batches to manage memory
    batchSize := 10
    for i := 0; i < len(configs); i += batchSize {
        end := i + batchSize
        if end > len(configs) {
            end = len(configs)
        }

        // Process batch
        for j := i; j < end; j++ {
            if report, err := builder.BuildStandardReport(configs[j]); err == nil {
                reports = append(reports, report)
            }
        }

        // Optional: Force garbage collection between batches for large datasets
        // runtime.GC()
    }

    return reports
}
```

## Thread Safety

The MarkdownBuilder is **thread-safe** for read operations but requires synchronization for concurrent modifications:

```go
func concurrentReportGeneration(configs []*model.OpnSenseDocument) []string {
    builder := converter.NewMarkdownBuilder()

    var wg sync.WaitGroup
    results := make([]string, len(configs))

    // Process configurations concurrently
    for i, config := range configs {
        wg.Add(1)
        go func(index int, cfg *model.OpnSenseDocument) {
            defer wg.Done()

            if report, err := builder.BuildStandardReport(cfg); err == nil {
                results[index] = report
            }
        }(i, config)
    }

    wg.Wait()
    return results
}
```

## Migration from Template Mode

### Key Differences

| Template Mode                  | Programmatic Mode                        |
| ------------------------------ | ---------------------------------------- |
| `{{ getRiskLevel .Severity }}` | `builder.AssessRiskLevel(item.Severity)` |
| `{{ .Value \| upper }}`        | `strings.ToUpper(item.Value)`            |
| `{{ if .IsSecure }}`           | `if item.IsSecure {`                     |
| Silent failures                | Explicit error handling                  |
| Runtime template parsing       | Compile-time validation                  |

### Migration Strategy

1. **Replace template calls** with method calls
2. **Add explicit error handling** for all operations
3. **Use type-safe parameters** instead of template variables
4. **Implement defensive programming** for edge cases

See the [complete migration guide](migration.md) for detailed step-by-step instructions.

## Best Practices

1. **Always handle errors** explicitly - don't ignore return values
2. **Use defensive programming** - check for nil pointers and empty slices
3. **Pre-allocate slices** when size is known or estimable
4. **Reuse builder instances** for multiple reports
5. **Use structured logging** for debugging and monitoring
6. **Profile performance** for large datasets or high-frequency usage
7. **Follow Go naming conventions** in custom extensions

## Related Documentation

- [Migration Guide](migration.md) - Step-by-step migration from template mode
- [Examples](examples.md) - Real-world usage scenarios and patterns
- [Architecture](../ARCHITECTURE.md) - System architecture and design decisions
- [Contributing](../CONTRIBUTING.md) - Development guidelines for API extensions
