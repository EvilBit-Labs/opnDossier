# Migration Guide: Templates to Programmatic Generation

## Overview

opnDossier v2.0 introduces a new programmatic markdown generation approach that offers better performance, type safety, and maintainability. This guide helps you migrate from custom templates.

## Quick Migration

### Option 1: Continue Using Templates (Temporary)

Your existing templates will continue to work with the `--use-template` flag:

```bash
# Old way (still works but deprecated)
opndossier convert -i config.xml -o report.md

# New way to use templates
opndossier convert -i config.xml -o report.md --use-template --custom-template ./templates/
```

### Option 2: Migrate to Programmatic (Recommended)

## Custom Template Function Mapping

| Template Function                        | Programmatic Method                            | Notes                                     |
| ---------------------------------------- | ---------------------------------------------- | ----------------------------------------- |
| `{{ getRiskLevel .severity }}`           | `builder.AssessRiskLevel(severity)`            | Returns emoji + text                      |
| `{{ filterTunables .tunables true }}`    | `builder.FilterSystemTunables(tunables, true)` | Same filtering logic                      |
| `{{ .data \| formatInterfacesAsLinks }}` | `formatInterfacesAsLinks(data)`                | Internal function, use in custom builders |
| `{{ default .value "N/A" }}`             | `builder.DefaultValue(value, "N/A")`           | Sprig replacement                         |
| `{{ truncate 50 .text }}`                | `builder.TruncateDescription(text, 50)`        | Sprig replacement                         |
| `{{ .value \| upper }}`                  | `builder.ToUpper(value)`                       | String case conversion                    |
| `{{ .value \| lower }}`                  | `builder.ToLower(value)`                       | String case conversion                    |
| `{{ escapeTableContent .content }}`      | `builder.EscapeTableContent(content)`          | Safe table content                        |
| `{{ formatBoolean .value }}`             | `markdown.FormatBoolean(value)`                | Boolean formatting                        |
| `{{ formatUnixTimestamp .timestamp }}`   | `markdown.FormatUnixTimestamp(timestamp)`      | Time formatting                           |

## Creating Custom Reports

### Before (Template)

```go-template
{{ define "custom-section" }}
## Custom Analysis
Risk Level: {{ getRiskLevel .severity }}
Interfaces: {{ .interfaces | formatInterfacesAsLinks }}
{{ end }}
```

### After (Programmatic)

```go
func (b *CustomBuilder) WriteCustomSection(data *model.OpnSenseDocument) {
    var section strings.Builder
    section.WriteString("## Custom Analysis\n")

    // Risk assessment using MarkdownBuilder method
    risk := b.AssessRiskLevel("high")
    section.WriteString(fmt.Sprintf("Risk Level: %s\n", risk))

    // Interface links using internal function
    if !data.Interfaces.IsEmpty() {
        interfaceLinks := formatInterfacesAsLinks(data.Interfaces.Wan) // Use internal function
        section.WriteString(fmt.Sprintf("Interfaces: %s\n", interfaceLinks))
    }

    return section.String()
}
```

## Extending the Builder

### Creating a Custom Builder

```go
package custom

import "github.com/EvilBit-Labs/opnDossier/internal/converter"

type MyCustomBuilder struct {
    *converter.MarkdownBuilder
}

func NewCustomBuilder() *MyCustomBuilder {
    return &MyCustomBuilder{
        MarkdownBuilder: converter.NewMarkdownBuilder(),
    }
}

func (b *MyCustomBuilder) AddCustomSection(data *model.OpnSenseDocument) {
    // Your custom logic here
    b.WriteHeader(2, "My Custom Section")
    // Use inherited methods
    risk := b.AssessRiskLevel("high")
    b.WriteParagraph("Risk: " + risk)
}
```

## Common Migration Patterns

### Pattern 1: Conditional Sections

**Template:**

```go-template
{{ if .showDetails }}
  {{ template "details" . }}
{{ end }}
```

**Programmatic:**

```go
if showDetails {
    b.WriteDetailsSection(data)
}
```

### Pattern 2: Loops and Formatting

**Template:**

```go-template
{{ range .interfaces }}
- {{ .name }}: {{ .ip }}
{{ end }}
```

**Programmatic:**

```go
for _, iface := range interfaces {
    b.WriteListItem(fmt.Sprintf("%s: %s", iface.Name, iface.IP))
}
```

### Pattern 3: Complex Data Transformation

**Template:**

```go-template
{{ $securityRules := 0 }}
{{ range .firewall.rules }}
  {{ if hasPrefix .description "security" }}
    {{ $securityRules = add $securityRules 1 }}
  {{ end }}
{{ end }}
Security Rules: {{ $securityRules }}
```

**Programmatic:**

```go
securityRules := 0
for _, rule := range data.Filter.Rule {
    if strings.HasPrefix(strings.ToLower(rule.Description), "security") {
        securityRules++
    }
}
section.WriteString(fmt.Sprintf("Security Rules: %d\n", securityRules))
```

## Advanced Migration Techniques

### Migrating Template Functions to Methods

**Step 1: Identify Template Functions**

Review your custom templates for functions like:

- `{{ myCustomFunction .data }}`
- `{{ .value | customFilter }}`
- `{{ calculateSomething .input1 .input2 }}`

#### Step 2: Convert to MarkdownBuilder Methods

```go
// Add to your custom builder
func (b *MyCustomBuilder) MyCustomFunction(data interface{}) string {
    // Implement your logic here
    return fmt.Sprintf("processed: %v", data)
}

func (b *MyCustomBuilder) CustomFilter(value string) string {
    // Implement your filter logic
    return strings.TrimSpace(strings.ToUpper(value))
}

func (b *MyCustomBuilder) CalculateSomething(input1, input2 string) int {
    // Implement your calculation
    return len(input1) + len(input2)
}
```

### Creating Reusable Components

**Template Components:**

```go-template
{{ define "statusBadge" }}
  {{ if eq .status "active" }}🟢{{ else }}🔴{{ end }} {{ .status }}
{{ end }}
```

**Programmatic Components:**

```go
func (b *MyCustomBuilder) StatusBadge(status string) string {
    icon := "🔴" // default
    if status == "active" {
        icon = "🟢"
    }
    return fmt.Sprintf("%s %s", icon, status)
}

// Usage in reports
badge := b.StatusBadge(service.Status)
section.WriteString(fmt.Sprintf("Service Status: %s\n", badge))
```

## Performance Optimization

### Memory-Efficient Building

```go
func (b *MyCustomBuilder) BuildLargeReport(data *model.OpnSenseDocument) string {
    // Pre-allocate with estimated capacity
    var section strings.Builder
    section.Grow(8192) // Pre-allocate 8KB

    // Build content efficiently
    b.writeSystemInfo(&section, data)
    b.writeNetworkInfo(&section, data)
    b.writeSecurityInfo(&section, data)

    return section.String()
}
```

### Caching Expensive Operations

```go
type CustomBuilder struct {
    *converter.MarkdownBuilder
    securityScoreCache map[string]int
}

func (b *CustomBuilder) GetCachedSecurityScore(key string, data *model.OpnSenseDocument) int {
    if score, exists := b.securityScoreCache[key]; exists {
        return score
    }

    score := b.CalculateSecurityScore(data)
    b.securityScoreCache[key] = score
    return score
}
```

## Testing Your Migration

### Unit Testing Programmatic Functions

```go
func TestCustomBuilder_StatusBadge(t *testing.T) {
    builder := NewCustomBuilder()

    tests := []struct {
        name     string
        status   string
        expected string
    }{
        {"active status", "active", "🟢 active"},
        {"inactive status", "inactive", "🔴 inactive"},
        {"unknown status", "unknown", "🔴 unknown"},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := builder.StatusBadge(tt.status)
            assert.Equal(t, tt.expected, result)
        })
    }
}
```

### Integration Testing

```go
func TestMigrationCompatibility(t *testing.T) {
    // Load test configuration
    config := loadTestConfig(t)

    // Generate with programmatic approach
    builder := NewCustomBuilder()
    programmaticcOutput := builder.BuildReport(config)

    // Verify key content is present
    assert.Contains(t, programmaticcOutput, "System Information")
    assert.Contains(t, programmaticcOutput, "Security Assessment")
}
```

## Troubleshooting Migration Issues

### Common Problems and Solutions

#### Problem 1: Missing Template Functions

```text
Error: template function "myCustomFunc" not found
```

**Solution:** Implement the function as a MarkdownBuilder method:

```go
func (b *MyCustomBuilder) MyCustomFunc(input string) string {
    // Implement the logic that was in your template function
    return processInput(input)
}
```

#### Problem 2: Different Output Format

```text
Expected: "Value: 123"
Got: "Value: value=123"
```

**Solution:** Check string formatting and ensure consistent output:

```go
// Template might have: {{ printf "Value: %s" .value }}
// Programmatic should be: fmt.Sprintf("Value: %s", value)
```

#### Problem 3: Type Conversion Issues

```text
Error: cannot convert interface{} to string
```

**Solution:** Add explicit type checking and conversion:

```go
func (b *MyCustomBuilder) SafeStringConvert(value interface{}) string {
    if value == nil {
        return ""
    }
    return fmt.Sprintf("%v", value)
}
```

## Migration Timeline and Deprecation

### Current Support Status

- **v2.0+**: Programmatic generation is default, templates available via `--use-template`
- **v2.x**: Both modes fully supported
- **v3.0**: Legacy template mode will be deprecated (warnings shown)
- **v4.0**: Template mode may become optional or removed

### Preparing for Future Versions

1. **Immediate (v2.x)**: Migrate custom templates to programmatic approach
2. **Before v3.0**: Test all custom functionality with programmatic generation
3. **Before v4.0**: Complete migration and remove template dependencies

## FAQ

**Q: Will my custom templates stop working?** A: No, they'll continue to work with the `--use-template` flag through v2.x and v3.x, but template mode may be removed in v4.0. We recommend migrating to programmatic generation for better performance and maintainability.

**Q: Can I mix programmatic and template approaches?** A: Yes, during migration you can use hybrid approaches, but it's not recommended for production. Choose one approach for consistency.

**Q: How do I contribute my custom functions?** A: Submit a PR adding your functions to the MarkdownBuilder. We welcome contributions! Follow the existing patterns in `internal/converter/markdown_*.go` files.

**Q: Is the programmatic approach faster?** A: Yes, programmatic generation is significantly faster than template processing. You'll see 40-70% performance improvements for most reports.

**Q: Can I still customize the output format?** A: Yes, programmatic generation gives you more control over output formatting. You can create custom builders that extend the base MarkdownBuilder.

**Q: What if I need template-like conditional logic?** A: Use standard Go conditional statements (if/else, switch) and loops (for, range). This provides better type safety and IDE support.

**Q: How do I handle errors in programmatic generation?** A: Programmatic generation provides explicit error handling. Methods can return errors that you handle appropriately:

```go
report, err := builder.BuildReport(config)
if err != nil {
    return fmt.Errorf("failed to build report: %w", err)
}
```

**Q: Can I reuse my existing template data processing logic?** A: Yes, convert your template logic to Go functions. Many template patterns translate directly to Go code with better performance.

**Q: Where can I find examples of programmatic generation?** A: Check the `internal/converter/markdown*.go` files for extensive examples of programmatic report generation.

**Q: How do I validate that my migration is correct?** A: Use the migration validation script (`scripts/validate-migration.sh`) to compare template and programmatic outputs. Write unit tests for your custom functions.

## Contributing Custom Functions

We encourage users to contribute useful custom functions back to the project. Here's how:

### 1. Add to MarkdownBuilder

Place new methods in the appropriate file:

- `internal/converter/markdown_utils.go` - Utility functions
- `internal/converter/markdown_transformers.go` - Data transformation
- `internal/converter/markdown_security.go` - Security assessment

### 2. Follow Existing Patterns

```go
// Good: Clear naming, proper error handling, documentation
func (b *MarkdownBuilder) FormatNetworkPort(port string) string {
    if port == "" {
        return "any"
    }
    if port == "22" {
        return "22 (SSH)"
    }
    return port
}
```

### 3. Add Tests

```go
func TestMarkdownBuilder_FormatNetworkPort(t *testing.T) {
    builder := NewMarkdownBuilder()

    tests := []struct {
        name     string
        port     string
        expected string
    }{
        {"empty port", "", "any"},
        {"ssh port", "22", "22 (SSH)"},
        {"custom port", "8080", "8080"},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := builder.FormatNetworkPort(tt.port)
            assert.Equal(t, tt.expected, result)
        })
    }
}
```

### 4. Update Documentation

Add your functions to the template migration mapping table in this guide.

## Getting Help

If you need assistance with migration:

1. **Documentation**: Review this guide and the API documentation
2. **Examples**: Check `internal/converter/` for working examples
3. **Issues**: Open a GitHub issue with the `migration` label
4. **Testing**: Use `scripts/validate-migration.sh` to verify your migration
5. **Community**: Ask questions in GitHub Discussions
