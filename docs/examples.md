# opnDossier Examples

## Overview

This document provides real-world usage examples and patterns for opnDossier's programmatic markdown generation. These examples demonstrate the transition from template-based to programmatic generation, showcasing improved performance and type safety.

## Basic Usage Examples

### Simple Configuration Report

**Before (Template Mode v1.x):**

```bash
# Template-based generation (slower, less memory efficient)
opnDossier convert config.xml --use-template -o report.md
```

**After (Programmatic Mode v2.0+):**

```bash
# Programmatic generation (designed for better performance and memory efficiency)
opnDossier convert config.xml -o report.md
```

### Security-Focused Analysis

```bash
# Generate comprehensive security report
opnDossier convert config.xml -o security-audit.md --include-tunables

# High-security focus with detailed analysis
opnDossier convert config.xml -o detailed-audit.md --security-focus high

# Export for further analysis
opnDossier convert config.xml -f json -o config-data.json
```

## Programming Examples

### Basic Go Integration

```go
package main

import (
    "fmt"
    "log"

    "github.com/EvilBit-Labs/opnDossier/internal/converter"
    "github.com/EvilBit-Labs/opnDossier/internal/parser"
)

func main() {
    // Parse OPNsense configuration
    xmlParser := parser.NewXMLParser()
    config, err := xmlParser.ParseFile("config.xml")
    if err != nil {
        log.Fatalf("Failed to parse config: %v", err)
    }

    // Create markdown builder
    builder := converter.NewMarkdownBuilder()

    // Generate standard report
    report, err := builder.BuildStandardReport(config)
    if err != nil {
        log.Fatalf("Failed to generate report: %v", err)
    }

    fmt.Println("=== OPNsense Configuration Report ===")
    fmt.Println(report)
}
```

### Custom Security Assessment

```go
package main

import (
    "fmt"
    "strings"

    "github.com/EvilBit-Labs/opnDossier/internal/converter"
    "github.com/EvilBit-Labs/opnDossier/internal/model"
)

func generateSecurityAudit(config *model.OpnSenseDocument) string {
    builder := converter.NewMarkdownBuilder()

    var report strings.Builder

    // Header with security score
    score := builder.CalculateSecurityScore(config)
    riskLevel := builder.AssessRiskLevel(determineRiskFromScore(score))

    report.WriteString("# Security Audit Report\n\n")
    report.WriteString(fmt.Sprintf("**Security Score:** %d/100 %s\n\n", score, riskLevel))

    // System tunables analysis
    if config.Sysctl != nil {
        securityTunables := builder.FilterSystemTunables(config.Sysctl.Item, true)
        report.WriteString("## Security-Related System Tunables\n\n")

        if len(securityTunables) > 0 {
            report.WriteString("| Tunable | Value | Description |\n")
            report.WriteString("|---------|-------|-------------|\n")

            for _, tunable := range securityTunables {
                escapedDesc := builder.EscapeMarkdownSpecialChars(tunable.Descr)
                report.WriteString(fmt.Sprintf("| `%s` | `%s` | %s |\n",
                    tunable.Tunable, tunable.Value, escapedDesc))
            }
        } else {
            report.WriteString("*No security-related tunables found.*\n")
        }
        report.WriteString("\n")
    }

    // Service status analysis
    if len(config.Installedpackages.Services) > 0 {
        serviceGroups := builder.GroupServicesByStatus(config.Installedpackages.Services)

        report.WriteString("## Service Status Summary\n\n")
        report.WriteString(fmt.Sprintf("- **Running Services:** %d\n", len(serviceGroups["running"])))
        report.WriteString(fmt.Sprintf("- **Stopped Services:** %d\n", len(serviceGroups["stopped"])))
        report.WriteString("\n")

        // Risk assessment for running services
        if len(serviceGroups["running"]) > 0 {
            report.WriteString("### Running Services Risk Assessment\n\n")
            for _, service := range serviceGroups["running"] {
                risk := builder.AssessServiceRisk(service)
                report.WriteString(fmt.Sprintf("- **%s**: %s\n", service.Name, risk))
            }
            report.WriteString("\n")
        }
    }

    return report.String()
}

func determineRiskFromScore(score int) string {
    switch {
    case score >= 80:
        return "low"
    case score >= 60:
        return "medium"
    case score >= 40:
        return "high"
    default:
        return "critical"
    }
}
```

### Firewall Rules Analysis

```go
func analyzeFirewallRules(config *model.OpnSenseDocument) string {
    builder := converter.NewMarkdownBuilder()

    var report strings.Builder
    report.WriteString("# Firewall Rules Analysis\n\n")

    // Extract all firewall rules
    var allRules []model.Rule
    if config.Filter != nil {
        allRules = config.Filter.Rule
    }

    if len(allRules) == 0 {
        report.WriteString("*No firewall rules configured.*\n")
        return report.String()
    }

    // Generate rules table
    rulesTable := builder.BuildFirewallRulesTable(allRules)
    report.WriteString(rulesTable.String())
    report.WriteString("\n")

    // Rules statistics
    report.WriteString("## Rules Statistics\n\n")

    allowRules := 0
    blockRules := 0
    for _, rule := range allRules {
        if rule.Type == "pass" {
            allowRules++
        } else if rule.Type == "block" {
            blockRules++
        }
    }

    report.WriteString(fmt.Sprintf("- **Total Rules:** %d\n", len(allRules)))
    report.WriteString(fmt.Sprintf("- **Allow Rules:** %d\n", allowRules))
    report.WriteString(fmt.Sprintf("- **Block Rules:** %d\n", blockRules))

    // Security recommendations
    report.WriteString("\n## Security Recommendations\n\n")

    if blockRules == 0 {
        report.WriteString("⚠️ **Warning:** No explicit block rules found. Consider adding deny rules for defense in depth.\n")
    }

    if float64(allowRules)/float64(len(allRules)) > 0.8 {
        report.WriteString("⚠️ **Warning:** High ratio of allow rules. Review for overly permissive access.\n")
    }

    return report.String()
}
```

## Advanced Integration Examples

### CI/CD Pipeline Integration

```yaml
# .github/workflows/security-audit.yml
name: OPNsense Security Audit

on:
  pull_request:
    paths:
      - configs/*.xml

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      - name: Install opnDossier
        run: go install github.com/EvilBit-Labs/opnDossier@latest

      - name: Generate Security Reports
        run: |
          mkdir -p reports
          for config in configs/*.xml; do
            filename=$(basename "$config" .xml)
            opnDossier convert "$config" -o "reports/${filename}-audit.md" --include-tunables
          done

      - name: Upload Reports
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: reports/
```

### Batch Processing Script

```bash
#!/bin/bash
# batch-audit.sh - Process multiple OPNsense configurations

set -euo pipefail

CONFIG_DIR="./configs"
OUTPUT_DIR="./reports"
OPNDOSSIER_BIN="./opnDossier"

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "Starting batch security audit..."

# Process each configuration file
for config_file in "$CONFIG_DIR"/*.xml; do
    if [[ -f "$config_file" ]]; then
        filename=$(basename "$config_file" .xml)
        output_file="$OUTPUT_DIR/${filename}-security-audit.md"

        echo "Processing: $config_file"

        # Generate comprehensive security report
        if "$OPNDOSSIER_BIN" convert "$config_file" \
            -o "$output_file" \
            --include-tunables \
            --security-focus high; then
            echo "✓ Generated: $output_file"
        else
            echo "✗ Failed to process: $config_file"
        fi
    fi
done

echo "Batch audit complete. Reports saved to: $OUTPUT_DIR"

# Generate summary report
echo "Generating summary report..."
cat > "$OUTPUT_DIR/audit-summary.md" << EOF
# Security Audit Summary

Generated: $(date)

## Processed Configurations

$(find "$OUTPUT_DIR" -name "*-security-audit.md" -exec basename {} .md \; | sed 's/^/- /')

## Quick Access

$(find "$OUTPUT_DIR" -name "*-security-audit.md" -exec bash -c 'echo "- [$(basename "{}" -security-audit.md)](./$(basename "{}"))"' \;)
EOF

echo "✓ Summary report: $OUTPUT_DIR/audit-summary.md"
```

### Custom Report Templates (Go)

```go
package main

import (
    "fmt"
    "os"
    "text/template"

    "github.com/EvilBit-Labs/opnDossier/internal/converter"
    "github.com/EvilBit-Labs/opnDossier/internal/model"
)

// ReportData aggregates all analysis results
type ReportData struct {
    Config         *model.OpnSenseDocument
    SecurityScore  int
    RiskLevel      string
    ServiceGroups  map[string][]model.Service
    SecurityTunables []model.SysctlItem
    Timestamp      string
}

func generateCustomReport(config *model.OpnSenseDocument) error {
    builder := converter.NewMarkdownBuilder()

    // Gather all analysis data
    data := ReportData{
        Config:           config,
        SecurityScore:    builder.CalculateSecurityScore(config),
        ServiceGroups:    builder.GroupServicesByStatus(config.Installedpackages.Services),
        Timestamp:        builder.FormatTimestamp(time.Now()),
    }

    data.RiskLevel = builder.AssessRiskLevel(determineRiskFromScore(data.SecurityScore))

    if config.Sysctl != nil {
        data.SecurityTunables = builder.FilterSystemTunables(config.Sysctl.Item, true)
    }

    // Define custom report template
    reportTemplate := `# {{ .Config.System.Hostname }} Security Assessment

**Generated:** {{ .Timestamp }}
**Security Score:** {{ .SecurityScore }}/100 {{ .RiskLevel }}

## Executive Summary

This report provides a comprehensive security assessment of the OPNsense configuration for {{ .Config.System.Hostname }}.{{ .Config.System.Domain }}.

### Key Findings

- **System Security Score:** {{ .SecurityScore }}/100
- **Risk Classification:** {{ .RiskLevel }}
- **Running Services:** {{ len (index .ServiceGroups "running") }}
- **Security Tunables:** {{ len .SecurityTunables }}

{{ if lt .SecurityScore 70 }}
⚠️ **ATTENTION:** This configuration has a security score below 70/100. Immediate review recommended.
{{ end }}

## Detailed Analysis

### Service Status
{{ range $status, $services := .ServiceGroups }}
#### {{ title $status }} Services ({{ len $services }})
{{ range $services }}
- {{ .Name }}{{ if .Description }} - {{ .Description }}{{ end }}
{{ end }}
{{ end }}

### Security Configuration
{{ if .SecurityTunables }}
The following security-related system tunables are configured:

| Tunable | Value |
|---------|-------|
{{ range .SecurityTunables }}| ` + "`{{ .Tunable }}`" + ` | ` + "`{{ .Value }}`" + ` |
{{ end }}
{{ else }}
*No security-related tunables configured.*
{{ end }}

---
*Report generated by opnDossier v2.0 - Programmatic Generation Mode*
`

    // Parse and execute template
    tmpl, err := template.New("security-report").Parse(reportTemplate)
    if err != nil {
        return fmt.Errorf("failed to parse template: %w", err)
    }

    // Generate report
    output, err := os.Create(fmt.Sprintf("%s-security-report.md", data.Config.System.Hostname))
    if err != nil {
        return fmt.Errorf("failed to create output file: %w", err)
    }
    defer output.Close()

    if err := tmpl.Execute(output, data); err != nil {
        return fmt.Errorf("failed to execute template: %w", err)
    }

    fmt.Printf("Custom security report generated: %s-security-report.md\n", data.Config.System.Hostname)
    return nil
}
```

## Performance Optimization Examples

### Efficient Bulk Processing

```go
func processMultipleConfigs(configFiles []string) error {
    // Create reusable components
    parser := parser.NewXMLParser()
    builder := converter.NewMarkdownBuilder()

    // Pre-allocate results
    results := make([]string, 0, len(configFiles))

    // Process in optimized batches
    batchSize := 10
    for i := 0; i < len(configFiles); i += batchSize {
        end := i + batchSize
        if end > len(configFiles) {
            end = len(configFiles)
        }

        // Process batch
        for j := i; j < end; j++ {
            config, err := parser.ParseFile(configFiles[j])
            if err != nil {
                log.Printf("Failed to parse %s: %v", configFiles[j], err)
                continue
            }

            report, err := builder.BuildStandardReport(config)
            if err != nil {
                log.Printf("Failed to generate report for %s: %v", configFiles[j], err)
                continue
            }

            results = append(results, report)
        }

        // Optional: Memory cleanup between batches
        // runtime.GC()
    }

    log.Printf("Successfully processed %d/%d configurations", len(results), len(configFiles))
    return nil
}
```

### Concurrent Report Generation

```go
func concurrentReportGeneration(configs []*model.OpnSenseDocument) []string {
    builder := converter.NewMarkdownBuilder()

    type result struct {
        index  int
        report string
        err    error
    }

    // Create worker pool
    workers := runtime.NumCPU()
    jobs := make(chan int, len(configs))
    results := make(chan result, len(configs))

    // Start workers
    for w := 0; w < workers; w++ {
        go func() {
            for index := range jobs {
                report, err := builder.BuildStandardReport(configs[index])
                results <- result{index: index, report: report, err: err}
            }
        }()
    }

    // Send jobs
    for i := range configs {
        jobs <- i
    }
    close(jobs)

    // Collect results
    reports := make([]string, len(configs))
    for i := 0; i < len(configs); i++ {
        result := <-results
        if result.err == nil {
            reports[result.index] = result.report
        } else {
            log.Printf("Failed to generate report for config %d: %v", result.index, result.err)
        }
    }

    return reports
}
```

## Migration Examples

### Template to Programmatic Conversion

**Before (Template Mode):**

```go
// Old template-based approach
func generateReportOld(config *model.OpnSenseDocument) (string, error) {
    tmpl := `
    {{/* Template logic */}}
    {{ if .System.Hostname }}
    # {{ .System.Hostname }} Configuration
    {{ end }}

    ## Security Score: {{ getRiskLevel .SecurityLevel }}

    {{ range .Services }}
    - {{ .Name }}: {{ .Status | upper }}
    {{ end }}
    `

    // Parse and execute template (slower, less type-safe)
    t, err := template.New("report").Parse(tmpl)
    if err != nil {
        return "", err
    }

    var buf bytes.Buffer
    if err := t.Execute(&buf, config); err != nil {
        return "", err
    }

    return buf.String(), nil
}
```

**After (Programmatic Mode):**

```go
// New programmatic approach
func generateReportNew(config *model.OpnSenseDocument) (string, error) {
    builder := converter.NewMarkdownBuilder()

    var report strings.Builder

    // Type-safe, compile-time checked operations
    if config.System.Hostname != "" {
        report.WriteString(fmt.Sprintf("# %s Configuration\n\n",
            builder.EscapeMarkdownSpecialChars(config.System.Hostname)))
    }

    // Direct method calls with proper error handling
    score := builder.CalculateSecurityScore(config)
    riskLevel := builder.AssessRiskLevel(determineRiskFromScore(score))
    report.WriteString(fmt.Sprintf("## Security Score: %s\n\n", riskLevel))

    // Efficient service processing
    serviceGroups := builder.GroupServicesByStatus(config.Installedpackages.Services)
    for status, services := range serviceGroups {
        for _, service := range services {
            report.WriteString(fmt.Sprintf("- %s: %s\n",
                service.Name, strings.ToUpper(status)))
        }
    }

    return report.String(), nil
}
```

## Troubleshooting Examples

### Common Error Handling

```go
func robustReportGeneration(configFile string) error {
    // Parse configuration with error handling
    parser := parser.NewXMLParser()
    config, err := parser.ParseFile(configFile)
    if err != nil {
        switch {
        case os.IsNotExist(err):
            return fmt.Errorf("configuration file not found: %s", configFile)
        case strings.Contains(err.Error(), "invalid XML"):
            return fmt.Errorf("malformed XML in configuration file: %w", err)
        default:
            return fmt.Errorf("failed to parse configuration: %w", err)
        }
    }

    // Generate report with comprehensive error handling
    builder := converter.NewMarkdownBuilder()
    report, err := builder.BuildStandardReport(config)
    if err != nil {
        switch {
        case errors.Is(err, converter.ErrInvalidData):
            // Handle data validation errors
            log.Printf("Configuration data validation failed: %v", err)
            return fmt.Errorf("invalid configuration data: %w", err)
        case errors.Is(err, converter.ErrGenerationFailed):
            // Handle generation-specific errors
            log.Printf("Report generation failed: %v", err)
            return fmt.Errorf("failed to generate markdown: %w", err)
        default:
            // Handle unexpected errors
            log.Printf("Unexpected error during report generation: %v", err)
            return fmt.Errorf("unexpected error: %w", err)
        }
    }

    // Save report
    outputFile := strings.TrimSuffix(configFile, ".xml") + "-report.md"
    if err := os.WriteFile(outputFile, []byte(report), 0644); err != nil {
        return fmt.Errorf("failed to write report to %s: %w", outputFile, err)
    }

    log.Printf("Successfully generated report: %s", outputFile)
    return nil
}
```

### Performance Debugging

```go
func benchmarkReportGeneration(config *model.OpnSenseDocument) {
    builder := converter.NewMarkdownBuilder()

    // Measure total generation time
    start := time.Now()
    report, err := builder.BuildStandardReport(config)
    totalTime := time.Since(start)

    if err != nil {
        log.Printf("Generation failed: %v", err)
        return
    }

    // Performance metrics
    log.Printf("Report generation completed:")
    log.Printf("  - Total time: %v", totalTime)
    log.Printf("  - Report size: %d characters", len(report))
    log.Printf("  - Generation rate: %.2f chars/ms", float64(len(report))/float64(totalTime.Milliseconds()))

    // Memory usage (requires runtime profiling)
    var m runtime.MemStats
    runtime.ReadMemStats(&m)
    log.Printf("  - Memory allocated: %d KB", m.Alloc/1024)
    log.Printf("  - Total allocations: %d", m.TotalAlloc/1024)
}
```

## Best Practices Summary

1. **Always handle errors explicitly** - The programmatic API provides detailed error information
2. **Reuse builder instances** - Create once, use multiple times for better performance
3. **Use defensive programming** - Check for nil pointers and empty collections
4. **Pre-allocate slices** when size is predictable
5. **Profile performance** for large datasets or high-frequency operations
6. **Leverage type safety** - Compile-time checks prevent runtime template errors
7. **Follow Go conventions** - Use standard Go patterns and idioms

For more examples and detailed migration guidance, see:

- [API Documentation](api.md)
- [Migration Guide](migration.md)
- [Architecture Overview](../ARCHITECTURE.md)
