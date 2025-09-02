---
inclusion: fileMatch
fileMatchPattern:
  - '**/*.go'
  - '**/*.md'
  - '**/README*'
---

# Go Documentation Standards for opnDossier

## Critical Documentation Requirements

### Package Documentation (MANDATORY)

Every package MUST have a package comment following this exact pattern:

```go
// Package parser provides functionality for parsing OPNsense configuration files.
// It supports XML parsing and conversion to structured data formats.
package parser
```

**Rules:**

- Start with `Package packagename` followed by description
- Use complete sentences with proper grammar
- Keep concise but informative (1-3 lines maximum)
- Place directly before package declaration

### Function Documentation (MANDATORY for Exported Functions)

All exported functions MUST be documented using this pattern:

```go
// ParseConfig reads and parses an OPNsense configuration file.
// It returns a structured OpnSenseDocument or an error if parsing fails.
// The filename parameter specifies the path to the XML configuration file.
func ParseConfig(filename string) (*model.OpnSenseDocument, error) {
    // implementation
}
```

**Rules:**

- First sentence starts with function name and describes what it does
- Document parameters, return values, and error conditions
- Use present tense ("reads", "returns", "validates")
- Include usage examples for complex functions

### Type Documentation (MANDATORY for Exported Types)

All exported types MUST include comprehensive documentation:

```go
// OpnSenseDocument represents the complete OPNsense configuration structure.
// It contains all firewall settings, network interfaces, and security policies.
// The struct supports XML, JSON, and YAML serialization for multiple output formats.
type OpnSenseDocument struct {
    // System contains hostname, domain, timezone, and administrative settings.
    System SystemConfig `xml:"system" json:"system" yaml:"system"`

    // Interfaces contains WAN, LAN, and VLAN network interface configurations.
    Interfaces InterfaceConfig `xml:"interfaces" json:"interfaces" yaml:"interfaces"`

    // Filter contains firewall rules, NAT policies, and traffic filtering rules.
    Filter FilterConfig `xml:"filter" json:"filter" yaml:"filter"`
}
```

**Rules:**

- Explain purpose and usage of each type
- Document struct fields with inline comments
- Include serialization format information
- Document any constraints or validation rules

## opnDossier-Specific Documentation Patterns

### CLI Command Documentation

Use this exact pattern for Cobra commands:

```go
var convertCmd = &cobra.Command{
    Use:   "convert [config.xml]",
    Short: "Convert OPNsense configuration to structured formats",
    Long: `Convert an OPNsense XML configuration file to markdown, JSON, or YAML.

The convert command parses OPNsense config.xml files and generates structured
reports suitable for security auditing, compliance checking, and documentation.

Supported output formats:
- Markdown: Human-readable reports with security analysis
- JSON: Machine-readable data for integration with other tools
- YAML: Configuration data in YAML format

Examples:
  opndossier convert config.xml
  opndossier convert config.xml --output report.md
  opndossier convert config.xml --format json --audit`,
    Args: cobra.ExactArgs(1),
    RunE: runConvert,
}
```

### Error Documentation Pattern

Document errors with context and resolution guidance:

```go
// ErrInvalidXML indicates the configuration file contains malformed XML.
// This error occurs when the XML structure doesn't match OPNsense schema.
// Resolution: Validate the XML file against OPNsense DTD/XSD schema.
var ErrInvalidXML = errors.New("invalid XML configuration format")

// ParseError represents configuration parsing failures with detailed context.
type ParseError struct {
    File    string // Configuration file path
    Line    int    // Line number where error occurred
    Element string // XML element that caused the error
    Cause   error  // Underlying error cause
}

// Error returns a formatted error message with parsing context.
func (e *ParseError) Error() string {
    return fmt.Sprintf("parse error in %s at line %d, element <%s>: %v",
        e.File, e.Line, e.Element, e.Cause)
}
```

### Plugin Interface Documentation

Document plugin interfaces with implementation guidance:

```go
// CompliancePlugin defines the interface for security compliance checking plugins.
// Plugins implement specific compliance frameworks (STIG, SANS, CIS) and return
// structured findings with severity levels and remediation guidance.
//
// Example implementation:
//   type STIGPlugin struct{}
//   func (p *STIGPlugin) Check(doc *OpnSenseDocument) []Finding { ... }
type CompliancePlugin interface {
    // Name returns the plugin identifier (e.g., "stig", "sans", "cis").
    Name() string

    // Check analyzes the configuration and returns compliance findings.
    // Returns empty slice if no issues found.
    Check(config *model.OpnSenseDocument) []Finding

    // Metadata returns plugin information including version and description.
    Metadata() PluginMetadata
}
```

## Code Comment Standards

### Inline Comments (Use Sparingly)

Focus on "why" not "what":

```go
// Parse interface configurations first to establish network topology
// before processing firewall rules that reference these interfaces
interfaces, err := parseInterfaces(xmlData.Interfaces)

// TODO(v2.0): Add IPv6 configuration parsing support
// FIXME: Handle edge case where VLAN ID conflicts with interface name
// NOTE: This validation is expensive - consider caching for large configs
```

### Business Logic Comments

Document complex algorithms and security-related logic:

```go
// validateFirewallRule checks rule consistency and security implications.
// Rules allowing traffic from ANY source to critical services (SSH, HTTPS admin)
// are flagged as high-severity findings for security review.
func validateFirewallRule(rule FirewallRule) []Finding {
    var findings []Finding

    // Check for overly permissive source rules (security concern)
    if rule.Source == "any" && isCriticalService(rule.Destination.Port) {
        findings = append(findings, Finding{
            Severity: "HIGH",
            Message:  "Firewall rule allows unrestricted access to critical service",
            Element:  rule.ID,
        })
    }

    return findings
}
```

## Documentation Validation

### Required Checks Before Commit

```bash
# Format all Go code and documentation
just format

# Validate documentation completeness
go doc -all ./... | grep -c "^func\|^type\|^var"

# Check for undocumented exports
golangci-lint run --enable=missing-docs

# Comprehensive validation
just ci-check
```

### Documentation Quality Gates

- All exported functions, types, and variables MUST have documentation
- Package documentation MUST exist for all packages
- CLI commands MUST include usage examples
- Error types MUST include resolution guidance
- Complex business logic MUST have explanatory comments

## Project-Specific Requirements

### Security Documentation

Document security implications and compliance considerations:

```go
// AuditFindings represents security compliance analysis results.
// Findings are categorized by severity (CRITICAL, HIGH, MEDIUM, LOW)
// and include remediation guidance for security teams.
type AuditFindings struct {
    // Critical findings require immediate attention (exposed admin interfaces)
    Critical []Finding `json:"critical"`

    // High findings should be addressed promptly (weak firewall rules)
    High []Finding `json:"high"`

    // Medium findings are recommended improvements (missing logging)
    Medium []Finding `json:"medium"`

    // Low findings are best practice suggestions (naming conventions)
    Low []Finding `json:"low"`
}
```

### Performance Documentation

Document performance characteristics for large configurations:

```go
// ParseLargeConfig handles OPNsense configurations up to 100MB.
// Uses streaming XML parsing to minimize memory usage.
// Typical performance: ~30 seconds for 10,000+ firewall rules.
// Memory usage: <500MB for configurations with complex rule sets.
func ParseLargeConfig(filename string) (*OpnSenseDocument, error) {
    // implementation with performance optimizations
}
```
