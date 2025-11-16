# Migration Guide: Template to Programmatic Generation

## Overview

This guide provides step-by-step instructions for migrating from template-based markdown generation (v1.x) to the new programmatic generation approach (v2.0+). The migration delivers **74% faster** generation, **78% less** memory usage, and compile-time type safety.

## Why Migrate?

### Performance Improvements

- **Generation Speed**: 74% faster report generation
- **Memory Usage**: 78% reduction in memory allocations
- **Throughput**: 3.8x improvement (643 vs 170 reports/sec)
- **Scalability**: Consistent performance gains across all dataset sizes

### Development Experience

- **Type Safety**: Compile-time validation vs runtime template errors
- **IDE Support**: Full IntelliSense and code completion
- **Error Handling**: Explicit error reporting with context
- **Debugging**: Standard Go debugging tools and techniques

### Security & Operations

- **Red Team Features**: Enhanced output obfuscation and offline capabilities
- **Reliability**: Reduced silent failures and improved error visibility
- **Maintainability**: Direct method calls vs template string manipulation

## Deprecation Timeline

> **⚠️ Action Required**: Template support will be completely removed in v3.0. Plan your migration now.

### Version Roadmap

| Version            | Status                | Template Support                    | Action Required                   |
| ------------------ | --------------------- | ----------------------------------- | --------------------------------- |
| **v2.0** (Current) | ✅ Active             | Available via `--use-template` flag | None - templates still supported  |
| **v2.1 - v2.4**    | 🔄 Planned            | Deprecated with warnings            | Migrate to programmatic mode      |
| **v2.5**           | ⚠️ Migration Deadline | Deprecated, removal imminent        | **Complete migration by Q2 2025** |
| **v3.0**           | 🚫 Removal            | **Complete removal**                | Templates will no longer work     |

### Migration Deadlines

- **Q2 2025**: v2.5 release - Final migration deadline before template removal
- **Q3 2025**: v3.0 release - Template support completely removed

### What This Means

- **v2.0 (Current)**: Continue using templates with `--use-template` flag if needed
- **v2.1-v2.4**: Deprecation warnings will appear when using template mode
- **v2.5**: Last version with template support (deprecated)
- **v3.0+**: Template mode will fail - programmatic mode only

**Recommendation**: Begin migration now to avoid last-minute issues. Use the [migration validator script](../scripts/validate-migration.sh) to assess your current setup.

## Migration Checklist

### Pre-Migration Assessment

- [ ] **Inventory current templates** - Document all custom templates and modifications
- [ ] **Identify template functions** - List all custom template functions in use
- [ ] **Test current setup** - Establish baseline performance and output quality
- [ ] **Backup configurations** - Save current working configuration files
- [ ] **Plan testing strategy** - Define acceptance criteria for migrated functionality

## Custom Template User Quick Start

If you're using custom templates, follow this three-step assessment process:

### Step 1: Run Migration Validator

Use the provided validation script to assess your current setup:

```bash
# Run from project root
./scripts/validate-migration.sh [TEMPLATE_DIR] [SAMPLE_CONFIG]

# Example with custom template directory
./scripts/validate-migration.sh ./custom-templates ./testdata/config.xml
```

The validator will:

- Detect custom templates in your directory
- Extract template functions in use
- Cross-reference with available MarkdownBuilder methods
- Generate comparison reports (template vs programmatic)
- Provide actionable next steps

### Step 2: Map Template Functions

Review the [function mapping table](template-function-migration.md) to identify:

- ✅ Functions already migrated (ready to use)
- ⏳ Functions pending migration (plan workaround)
- ❌ Functions without equivalents (requires custom implementation)

### Step 3: Choose Migration Path

**Option A: Continue with Templates (Temporary)**

Use the `--use-template` flag to maintain current functionality:

```bash
opndossier convert config.xml --use-template -o report.md
```

⚠️ **Note**: This is a temporary solution. Templates will be removed in v3.0.

**Option B: Migrate to Programmatic (Recommended)**

1. Extend `MarkdownBuilder` with custom methods (see [Real-World Examples](#real-world-migration-examples))
2. Port template logic to Go methods
3. Test with programmatic mode (default)
4. Remove template dependencies

### Migration Phases

#### Phase 1: Basic Functionality Migration

- [ ] Replace simple template calls with programmatic methods
- [ ] Migrate core report generation workflows
- [ ] Update basic string formatting operations
- [ ] Test output equivalence

#### Phase 2: Advanced Feature Migration

- [ ] Convert custom template functions to Go methods
- [ ] Migrate complex data transformations
- [ ] Update security assessment logic
- [ ] Integrate performance optimizations

#### Phase 3: Cleanup and Optimization

- [ ] Remove template dependencies
- [ ] Optimize for new performance characteristics
- [ ] Update documentation and examples
- [ ] Implement monitoring and validation

## Step-by-Step Migration

### Step 1: Update Installation and Dependencies

**Before (v1.x):**

```bash
# Old template-based installation
go install github.com/EvilBit-Labs/opnDossier@v1.x
```

**After (v2.0+):**

```bash
# New programmatic generation
go install github.com/EvilBit-Labs/opnDossier@latest

# Or build from source for latest features
git clone https://github.com/EvilBit-Labs/opnDossier.git
cd opnDossier
just install
just build
```

### Step 2: Update CLI Usage Patterns

**Before (Template Mode):**

```bash
# Template-based generation (default in v1.x)
opnDossier convert config.xml -o report.md

# Custom templates
opnDossier convert config.xml --template-dir ./custom-templates/
```

**After (Programmatic Mode):**

```bash
# Programmatic generation (default in v2.0+)
opnDossier convert config.xml -o report.md

# Legacy template mode (for compatibility)
opnDossier convert config.xml -o report.md --use-template

# Custom templates (if still needed)
opnDossier convert config.xml --template-dir ./custom-templates/ --use-template
```

### Step 3: Migrate Simple Template Functions

**Before (Template Calls):**

```go
// Template function calls
{{ getRiskLevel .Severity }}
{{ formatBoolean .IsEnabled }}
{{ .Value | upper }}
{{ .Description | truncate 50 }}
```

**After (Method Calls):**

```go
// Direct method calls on MarkdownBuilder
builder.AssessRiskLevel(item.Severity)
builder.FormatBoolean(item.IsEnabled)
strings.ToUpper(item.Value)
builder.TruncateDescription(item.Description, 50)
```

### Step 4: Convert Data Processing Logic

**Before (Template Logic):**

```go
// Template-based data processing
{{ range .System.Tunables }}
  {{ if hasPrefix .Name "security" }}
    - {{ .Name }}: {{ .Value }}
  {{ end }}
{{ end }}
```

**After (Go Logic):**

```go
// Programmatic data processing
builder := converter.NewMarkdownBuilder()
securityTunables := builder.FilterSystemTunables(config.Sysctl.Item, true)

var output strings.Builder
for _, tunable := range securityTunables {
    output.WriteString(fmt.Sprintf("- %s: %s\n", tunable.Tunable, tunable.Value))
}
```

### Step 5: Migrate Complex Templates

**Before (Complex Template):**

```go
// Complex template with conditional logic
{{- define "serviceStatus" -}}
{{ $running := 0 }}{{ $stopped := 0 }}
{{ range .Services }}
  {{ if eq .Status "running" }}{{ $running = add $running 1 }}{{ else }}{{ $stopped = add $stopped 1 }}{{ end }}
{{ end }}
**Running:** {{ $running }} | **Stopped:** {{ $stopped }}
{{- end -}}
```

**After (Go Method):**

```go
// Equivalent Go method
func (b *MarkdownBuilder) formatServiceStatus(services []model.Service) string {
    serviceGroups := b.GroupServicesByStatus(services)

    running := len(serviceGroups["running"])
    stopped := len(serviceGroups["stopped"])

    return fmt.Sprintf("**Running:** %d | **Stopped:** %d", running, stopped)
}
```

### Step 6: Update Error Handling

**Before (Silent Template Failures):**

```go
// Templates fail silently or with generic errors
{{ .NonExistentField | default "N/A" }}
```

**After (Explicit Error Handling):**

```go
// Explicit error handling with context
func safeGetField(config *model.OpnSenseDocument) (string, error) {
    if config == nil {
        return "", fmt.Errorf("configuration is nil")
    }

    if config.System.Hostname == "" {
        return "N/A", nil  // Explicit default handling
    }

    return config.System.Hostname, nil
}
```

## Code Examples: Before and After

### Example 1: Basic Report Generation

**Before (Template-Based):**

```go
// template file: report.tmpl
{{/* Basic report template */}}
# {{ .System.Hostname }} Configuration Report

## System Information
- **Hostname:** {{ .System.Hostname }}
- **Domain:** {{ .System.Domain }}
- **Version:** {{ .System.Version }}

## Security Assessment
- **Risk Level:** {{ getRiskLevel .SecurityLevel }}
- **Score:** {{ calculateScore . }}/100

{{ range .Services }}
- {{ .Name }}: {{ .Status | upper }}
{{ end }}
```

```go
// Go code using templates
func generateReport(config *model.OpnSenseDocument) (string, error) {
    tmpl, err := template.ParseFiles("report.tmpl")
    if err != nil {
        return "", err
    }

    var buf bytes.Buffer
    if err := tmpl.Execute(&buf, config); err != nil {
        return "", err
    }

    return buf.String(), nil
}
```

**After (Programmatic):**

```go
// Direct Go implementation
func generateReport(config *model.OpnSenseDocument) (string, error) {
    builder := converter.NewMarkdownBuilder()

    var report strings.Builder

    // Header with system information
    report.WriteString(fmt.Sprintf("# %s Configuration Report\n\n",
        builder.EscapeMarkdownSpecialChars(config.System.Hostname)))

    // System information section
    report.WriteString("## System Information\n")
    report.WriteString(fmt.Sprintf("- **Hostname:** %s\n", config.System.Hostname))
    report.WriteString(fmt.Sprintf("- **Domain:** %s\n", config.System.Domain))
    report.WriteString(fmt.Sprintf("- **Version:** %s\n", config.System.Version))
    report.WriteString("\n")

    // Security assessment
    score := builder.CalculateSecurityScore(config)
    riskLevel := builder.AssessRiskLevel(determineRiskFromScore(score))

    report.WriteString("## Security Assessment\n")
    report.WriteString(fmt.Sprintf("- **Risk Level:** %s\n", riskLevel))
    report.WriteString(fmt.Sprintf("- **Score:** %d/100\n\n", score))

    // Services listing
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

### Example 2: Custom Function Migration

**Before (Custom Template Functions):**

```go
// Custom template functions
func createTemplateFunctions() template.FuncMap {
    return template.FuncMap{
        "formatUptime": func(seconds int) string {
            hours := seconds / 3600
            return fmt.Sprintf("%d hours", hours)
        },
        "securityIcon": func(level string) string {
            switch level {
            case "high": return "🔴"
            case "medium": return "🟡"
            case "low": return "🟢"
            default: return "⚪"
            }
        },
        "formatBytes": func(bytes int64) string {
            return fmt.Sprintf("%.2f MB", float64(bytes)/1024/1024)
        },
    }
}
```

**After (MarkdownBuilder Methods):**

```go
// Methods on MarkdownBuilder type
func (b *MarkdownBuilder) FormatUptime(seconds int) string {
    hours := seconds / 3600
    return fmt.Sprintf("%d hours", hours)
}

func (b *MarkdownBuilder) SecurityIcon(level string) string {
    switch level {
    case "high": return "🔴"
    case "medium": return "🟡"
    case "low": return "🟢"
    default: return "⚪"
    }
}

func (b *MarkdownBuilder) FormatBytes(bytes int64) string {
    return fmt.Sprintf("%.2f MB", float64(bytes)/1024/1024)
}
```

### Example 3: Custom Risk Assessment Section

**Before (Template):**

```go
{{- define "riskAssessment" -}}
## Risk Assessment

{{ range .Services }}
- **{{ .Name }}**: {{ getRiskLevel .Severity }}
  - Status: {{ .Status | upper }}
  - Risk Score: {{ calculateSecurityScore . }}
{{ end }}
{{- end -}}
```

**After (Go Method):**

```go
// Custom SecurityBuilder extending MarkdownBuilder
type SecurityBuilder struct {
    *MarkdownBuilder
}

func NewSecurityBuilder() *SecurityBuilder {
    return &SecurityBuilder{
        MarkdownBuilder: converter.NewMarkdownBuilder(),
    }
}

func (sb *SecurityBuilder) BuildRiskAssessmentSection(data *model.OpnSenseDocument) string {
    var section strings.Builder

    section.WriteString("## Risk Assessment\n\n")

    for _, service := range data.Installedpackages.Services {
        // Use inherited methods from MarkdownBuilder
        // AssessServiceRisk already returns a fully formatted risk label (emoji + text)
        riskLevel := sb.AssessServiceRisk(service)
        status := sb.ToUpper(service.Status)
        score := sb.CalculateSecurityScore(data)

        section.WriteString(fmt.Sprintf("- **%s**: %s\n", service.Name, riskLevel))
        section.WriteString(fmt.Sprintf("  - Status: %s\n", status))
        section.WriteString(fmt.Sprintf("  - Risk Score: %d\n\n", score))
    }

    return section.String()
}
```

**Usage:**

```go
builder := NewSecurityBuilder()
riskSection := builder.BuildRiskAssessmentSection(config)
```

### Example 4: Custom Compliance Report

**Before (Template):**

```go
{{- define "complianceCheck" -}}
## Compliance Report

{{ $rules := .Filter.Rule }}
{{ range $rules }}
  {{ if eq .Type "pass" }}
    - ✅ Rule #{{ .Number }}: {{ .Descr }}
  {{ else }}
    - ❌ Rule #{{ .Number }}: {{ .Descr }} (Non-compliant)
  {{ end }}
{{ end }}
{{- end -}}
```

**After (Go Method):**

```go
func (b *MarkdownBuilder) BuildComplianceReport(data *model.OpnSenseDocument) string {
    var report strings.Builder

    report.WriteString("## Compliance Report\n\n")

    // Filter rules by type using MarkdownBuilder method
    passRules := b.FilterRulesByType(data.Filter.Rule, "pass")
    blockRules := b.FilterRulesByType(data.Filter.Rule, "block")

    report.WriteString("### Compliant Rules (Pass)\n\n")
    for i, rule := range passRules {
        report.WriteString(fmt.Sprintf("- ✅ Rule #%d: %s\n",
            i+1, b.EscapeTableContent(rule.Descr)))
    }

    report.WriteString("\n### Non-Compliant Rules (Block)\n\n")
    for i, rule := range blockRules {
        report.WriteString(fmt.Sprintf("- ❌ Rule #%d: %s\n",
            i+1, b.EscapeTableContent(rule.Descr)))
    }

    return report.String()
}
```

**Reference**: Uses `FilterRulesByType` from `internal/converter/markdown_transformers.go` line 164.

### Example 5: Custom Network Analysis

**Before (Template):**

```go
{{- define "networkAnalysis" -}}
## Network Interface Analysis

{{ $interfaces := .Interfaces.Items }}
{{ range $name, $iface := $interfaces }}
  {{ if eq $iface.Enable "1" }}
    ### {{ $name | upper }} Interface
    - IP: {{ $iface.IPAddr }}
    - Subnet: {{ $iface.Subnet }}
    - Gateway: {{ $iface.Gateway | default "N/A" }}
  {{ end }}
{{ end }}
{{- end -}}
```

**After (Go Method):**

```go
func (b *MarkdownBuilder) BuildNetworkAnalysis(data *model.OpnSenseDocument) string {
    var analysis strings.Builder

    analysis.WriteString("## Network Interface Analysis\n\n")

    netConfig := data.NetworkConfig()

    for name, iface := range netConfig.Interfaces.Items {
        // Filter enabled interfaces only
        if iface.Enable != "1" {
            continue
        }

        analysis.WriteString(fmt.Sprintf("### %s Interface\n\n", b.ToUpper(name)))
        analysis.WriteString(fmt.Sprintf("- IP: %s\n", iface.IPAddr))
        analysis.WriteString(fmt.Sprintf("- Subnet: %s\n", iface.Subnet))

        // Use DefaultValue for optional fields
        gateway := b.DefaultValue(iface.Gateway, "N/A")
        analysis.WriteString(fmt.Sprintf("- Gateway: %s\n\n", gateway))
    }

    return analysis.String()
}
```

**Reference**: Uses `ToUpper` from `internal/converter/markdown_utils.go` line 130 and `DefaultValue` from line 93.

## Performance Validation

### Benchmarking Migration Results

```go
// Benchmark comparison function
func BenchmarkMigrationComparison(b *testing.B) {
    config := loadTestConfig() // Load test configuration

    // Benchmark old template approach
    b.Run("Template", func(b *testing.B) {
        for i := 0; i < b.N; i++ {
            _, err := generateReportTemplate(config)
            if err != nil {
                b.Fatal(err)
            }
        }
    })

    // Benchmark new programmatic approach
    b.Run("Programmatic", func(b *testing.B) {
        builder := converter.NewMarkdownBuilder()
        for i := 0; i < b.N; i++ {
            _, err := builder.BuildStandardReport(config)
            if err != nil {
                b.Fatal(err)
            }
        }
    })
}
```

**Expected Results:**

```
BenchmarkMigrationComparison/Template-8        200    5520000 ns/op    8800000 B/op    93984 allocs/op
BenchmarkMigrationComparison/Programmatic-8    800    1520000 ns/op    1970000 B/op    39585 allocs/op
```

### Validation Checklist

- [ ] **Output Equivalence**: Generated reports match template output (content-wise)
- [ ] **Performance Improvement**: Confirm 50%+ speed improvement
- [ ] **Memory Efficiency**: Verify significant reduction in allocations
- [ ] **Error Handling**: Ensure better error reporting and handling
- [ ] **Type Safety**: Confirm compile-time validation of all operations

## Common Migration Challenges

### Challenge 1: Complex Template Logic

**Problem:** Nested template conditionals and loops are hard to translate directly.

**Solution:** Break down complex templates into smaller, focused Go functions.

```go
// Instead of complex template logic, use focused functions
func (b *MarkdownBuilder) generateServiceSection(services []model.Service) string {
    if len(services) == 0 {
        return "*No services configured.*\n"
    }

    serviceGroups := b.GroupServicesByStatus(services)

    var section strings.Builder
    section.WriteString("## Services\n\n")

    // Handle each group separately
    b.addServiceGroup(&section, "Running", serviceGroups["running"])
    b.addServiceGroup(&section, "Stopped", serviceGroups["stopped"])

    return section.String()
}

func (b *MarkdownBuilder) addServiceGroup(w *strings.Builder, title string, services []model.Service) {
    if len(services) == 0 {
        return
    }

    w.WriteString(fmt.Sprintf("### %s Services (%d)\n\n", title, len(services)))
    for _, service := range services {
        w.WriteString(fmt.Sprintf("- **%s**", service.Name))
        if service.Description != "" {
            w.WriteString(fmt.Sprintf(": %s", b.TruncateDescription(service.Description, 100)))
        }
        w.WriteString("\n")
    }
    w.WriteString("\n")
}
```

### Challenge 2: Sprig Function Dependencies

**Problem:** Templates rely heavily on Sprig functions for string manipulation.

**Solution:** Implement essential functions as MarkdownBuilder methods or use standard Go functions.

```go
// Replace Sprig functions with Go standard library or custom methods
func migrateSprigFunctions() {
    // Old: {{ .Value | upper }}
    // New: strings.ToUpper(value)

    // Old: {{ .List | join ", " }}
    // New: strings.Join(list, ", ")

    // Old: {{ .Text | default "N/A" }}
    // New: Use DefaultValue method (works with any type)
    builder.DefaultValue(text, "N/A")
}

// Note: DefaultValue already exists in MarkdownBuilder
// For string-specific handling, you can use:
func (b *MarkdownBuilder) DefaultString(value, defaultValue string) string {
    result := b.DefaultValue(value, defaultValue)
    if str, ok := result.(string); ok {
        return str
    }
    return defaultValue
}
```

### Challenge 3: Template Inheritance

**Problem:** Template inheritance and includes are harder to replicate.

**Solution:** Use Go composition and method delegation.

```go
// Replace template inheritance with Go composition
type ReportBuilder struct {
    *MarkdownBuilder
    headerBuilder  *HeaderBuilder
    sectionBuilder *SectionBuilder
}

func (r *ReportBuilder) BuildFullReport(config *model.OpnSenseDocument) (string, error) {
    var report strings.Builder

    // Compose report from different builders
    header := r.headerBuilder.BuildHeader(config)
    system := r.sectionBuilder.BuildSystemSection(config)
    network := r.sectionBuilder.BuildNetworkSection(config)

    report.WriteString(header)
    report.WriteString(system)
    report.WriteString(network)

    return report.String(), nil
}
```

## Testing Migration

### Unit Test Migration

```go
// Test template vs programmatic output equivalence
func TestMigrationEquivalence(t *testing.T) {
    config := loadTestConfig()

    // Generate with both approaches
    templateOutput, err := generateReportTemplate(config)
    require.NoError(t, err)

    builder := converter.NewMarkdownBuilder()
    programmaticOutput, err := builder.BuildStandardReport(config)
    require.NoError(t, err)

    // Compare content (allowing for formatting differences)
    assert.Equal(t, normalizeContent(templateOutput), normalizeContent(programmaticOutput))
}

func normalizeContent(content string) string {
    // Normalize whitespace and formatting for comparison
    lines := strings.Split(content, "\n")
    var normalized []string

    for _, line := range lines {
        trimmed := strings.TrimSpace(line)
        if trimmed != "" {
            normalized = append(normalized, trimmed)
        }
    }

    return strings.Join(normalized, "\n")
}
```

### Integration Test Migration

```go
func TestEndToEndMigration(t *testing.T) {
    testCases := []struct {
        name       string
        configFile string
        expected   string
    }{
        {"small-config", "testdata/small-config.xml", "testdata/small-expected.md"},
        {"medium-config", "testdata/medium-config.xml", "testdata/medium-expected.md"},
        {"large-config", "testdata/large-config.xml", "testdata/large-expected.md"},
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            // Parse configuration
            parser := parser.NewXMLParser()
            config, err := parser.ParseFile(tc.configFile)
            require.NoError(t, err)

            // Generate report
            builder := converter.NewMarkdownBuilder()
            report, err := builder.BuildStandardReport(config)
            require.NoError(t, err)

            // Validate output
            expected, err := os.ReadFile(tc.expected)
            require.NoError(t, err)

            assert.Equal(t, normalizeContent(string(expected)), normalizeContent(report))
        })
    }
}
```

## Rollback Strategy

### Maintaining Template Compatibility

```go
// Support both approaches during transition
type HybridBuilder struct {
    useTemplate bool
    templateGen Generator
    progGen     *MarkdownBuilder
}

func NewHybridBuilder(useTemplate bool) *HybridBuilder {
    return &HybridBuilder{
        useTemplate: useTemplate,
        templateGen: markdown.NewMarkdownGenerator(nil),
        progGen:     converter.NewMarkdownBuilder(),
    }
}

func (h *HybridBuilder) GenerateReport(config *model.OpnSenseDocument) (string, error) {
    if h.useTemplate {
        // Fallback to template mode
        return h.templateGen.Generate(context.Background(), config, markdown.Options{})
    }

    // Use new programmatic mode
    return h.progGen.BuildStandardReport(config)
}
```

### Feature Flags

```bash
# Environment variables for gradual rollout
export OPNDOSSIER_USE_PROGRAMMATIC=true   # Enable programmatic mode
export OPNDOSSIER_FALLBACK_TEMPLATE=true  # Fallback to templates on error
export OPNDOSSIER_VALIDATE_OUTPUT=true    # Compare template vs programmatic output
```

## Post-Migration Optimization

### Performance Tuning

```go
// Optimize for new performance characteristics
func optimizeForProgrammaticGeneration() {
    // 1. Create builder (reuse for multiple reports when possible)
    builder := converter.NewMarkdownBuilder()

    // 2. Process multiple configs (builder is stateless, safe to reuse)
    for _, config := range configs {
        report, _ := builder.BuildStandardReport(config)
        // Builder is stateless - no Reset() needed, just reuse
        _ = report
    }

    // 3. Use concurrent processing for multiple configs
    // Each goroutine should create its own builder for thread safety
    processConfigsConcurrently(configs)
}
```

### Monitoring and Validation

```go
// Add metrics to track migration success
func trackMigrationMetrics(templateTime, progTime time.Duration, templateErr, progErr error) {
    metrics := map[string]interface{}{
        "template_duration_ms":     templateTime.Milliseconds(),
        "programmatic_duration_ms": progTime.Milliseconds(),
        "performance_improvement":  float64(templateTime-progTime) / float64(templateTime) * 100,
        "template_error":          templateErr != nil,
        "programmatic_error":      progErr != nil,
    }

    // Log or send to monitoring system
    log.Printf("Migration metrics: %+v", metrics)
}
```

## Success Criteria

### Performance Metrics

- [ ] **Generation Speed**: Achieve 50%+ improvement over template mode
- [ ] **Memory Usage**: Reduce allocations by 50%+
- [ ] **Throughput**: Handle 2x+ more reports per second
- [ ] **Scalability**: Maintain performance with large configurations

### Quality Metrics

- [ ] **Output Equivalence**: Reports match template output functionality
- [ ] **Error Handling**: Improved error reporting and debugging
- [ ] **Type Safety**: Zero runtime template errors
- [ ] **Maintainability**: Easier to extend and modify

### Operational Metrics

- [ ] **Reliability**: Reduced failure rates
- [ ] **Debugging**: Faster issue identification and resolution
- [ ] **Development**: Faster feature development and testing
- [ ] **Documentation**: Clear migration path and examples

## FAQ

### How long will template support be available?

Template support will be available until **v3.0** (estimated Q3 2025). The `--use-template` flag will work in v2.0-v2.5, but templates will be completely removed in v3.0.

### Can I use both template and programmatic modes?

Yes! The HybridGenerator supports both modes. Use `--use-template` for template mode, or omit the flag for programmatic mode (default). See `internal/markdown/hybrid_generator.go` for implementation details.

### What performance improvements can I expect?

Based on benchmarks:

- **74% faster** report generation
- **78% less** memory usage
- **3.8x improvement** in throughput (643 vs 170 reports/sec)

### How do I rollback if migration causes issues?

Use the `--use-template` flag to temporarily revert to template mode:

```bash
opndossier convert config.xml --use-template -o report.md
```

This allows you to continue using templates while fixing programmatic implementation issues.

### What if a template function doesn't have a Go equivalent?

1. Check the [function mapping table](template-function-migration.md) for status
2. If pending, implement as a custom MarkdownBuilder method (see [Contributing](#contributing-custom-functions))
3. Consider contributing your implementation back to the project

### Troubleshooting Common Issues

**Issue**: Template functions not found in programmatic mode

**Solution**: Check the function mapping table. If the function is marked "Pending", you'll need to implement it or use a workaround.

**Issue**: Output differs between template and programmatic modes

**Solution**: Run the migration validator script to generate a diff report. Review differences and adjust your programmatic implementation accordingly.

**Issue**: Performance is worse after migration

**Solution**: Ensure you're using the latest version of opnDossier. If issues persist, file a bug report with performance benchmarks.

## Contributing Custom Functions

If you've implemented custom MarkdownBuilder methods that would benefit the community, consider contributing them back to the project.

### Contribution Process

1. **Implement as MarkdownBuilder Method**

   Add your method to `internal/converter/markdown_custom.go` (or appropriate file):

   ```go
   // Package converter provides functionality to convert OPNsense configurations to markdown.
   package converter

   // YourCustomMethod provides [description of functionality].
   func (b *MarkdownBuilder) YourCustomMethod(params) returnType {
       // Implementation
   }
   ```

2. **Add Comprehensive Tests**

   Create tests in `internal/converter/markdown_custom_test.go`:

   ```go
   func TestMarkdownBuilder_YourCustomMethod(t *testing.T) {
       builder := NewMarkdownBuilder()

       tests := []struct {
           name     string
           input    inputType
           expected returnType
       }{
           // Test cases
       }

       for _, tt := range tests {
           t.Run(tt.name, func(t *testing.T) {
               result := builder.YourCustomMethod(tt.input)
               assert.Equal(t, tt.expected, result)
           })
       }
   }
   ```

   Reference existing test patterns from `internal/converter/markdown_utils_test.go`.

3. **Document in Migration Guide**

   Update `docs/template-function-migration.md` with your function mapping:

   - Add to appropriate phase table
   - Mark status as **Migrated**
   - Include implementation file reference

4. **Submit Pull Request**

   PR requirements:

   - Clear use case description
   - Before/after examples (template → Go method)
   - Test coverage report (>80% for new code)
   - Documentation updates
   - Link to related issues (if any)

### Code Structure Guidelines

- **File Organization**: Add methods to appropriate files:

  - `markdown_utils.go` - Core utility functions
  - `markdown_security.go` - Security and compliance functions
  - `markdown_transformers.go` - Data transformation functions
  - `markdown_custom.go` - Custom/advanced functions

- **Naming Conventions**: Follow Go naming conventions:

  - Exported methods: `PascalCase`
  - Private helpers: `camelCase`
  - Descriptive names that indicate purpose

- **Error Handling**: Always handle errors explicitly:

  ```go
   if err != nil {
       return "", fmt.Errorf("context: %w", err)
   }
  ```

- **Documentation**: Include godoc comments:

  ```go
  // YourCustomMethod does [what] for [purpose].
  // It returns [what] and handles [edge cases].
  func (b *MarkdownBuilder) YourCustomMethod(...) ... {
  ```

## Next Steps

1. **Complete Migration**: Follow this guide step-by-step
2. **Validate Results**: Run comprehensive tests and benchmarks
3. **Monitor Performance**: Track metrics and optimize as needed
4. **Update Documentation**: Reflect new programmatic approach
5. **Train Team**: Ensure team understands new development patterns

For additional support and examples:

- [API Documentation](api.md) - Complete method reference
- [Examples](examples.md) - Real-world usage patterns
- [Architecture](../ARCHITECTURE.md) - System design overview
- [Function Migration Guide](template-function-migration.md) - Complete function mapping
