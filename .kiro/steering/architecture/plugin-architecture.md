---
inclusion: fileMatch
fileMatchPattern:
  - internal/plugins/**/*
  - internal/plugin/**/*
  - internal/audit/**/*
---

# Plugin Architecture Guidelines

## Core Architecture

The plugin system enables extensible compliance checking through a standardized interface. Key components:

- **CompliancePlugin Interface**: Standard contract for all compliance plugins
- **PluginRegistry**: Manages plugin registration and lifecycle
- **PluginManager**: High-level plugin operations and audit coordination
- **Control/Finding Structs**: Standardized data structures for compliance results

## Plugin Interface Requirements

All plugins MUST implement `CompliancePlugin` interface:

```go
type CompliancePlugin interface {
    Name() string                                           // Unique identifier (e.g., "stig", "sans")
    Version() string                                        // Semantic version (e.g., "1.0.0")
    Description() string                                    // Human-readable description
    RunChecks(config *model.OpnSenseDocument) []Finding    // Execute compliance checks
    GetControls() []Control                                 // Return all available controls
    GetControlByID(id string) (*Control, error)           // Get specific control by ID
    ValidateConfiguration() error                           // Validate plugin configuration
}
```

## Data Structure Standards

### Finding Structure

Use the generic `Finding` struct with standardized fields:

```go
type Finding struct {
    Type           string            // "compliance", "security", "configuration"
    Title          string            // Clear, descriptive title
    Description    string            // Detailed description of the issue
    Recommendation string            // Actionable remediation steps
    Component      string            // Affected component (e.g., "firewall-rules")
    Severity       string            // "Critical", "High", "Medium", "Low", "Info"
    References     []string          // All applicable control IDs
    Evidence       []string          // Artifact paths, URLs, or evidence details
    Tags           []string          // Categorization tags
    Metadata       map[string]string // Optional additional data
}
```

### Control Structure

Define controls with complete metadata:

```go
type Control struct {
    ID              string            // Unique control ID (e.g., "V-206694")
    Title           string            // Control title
    Description     string            // Detailed description
    Category        string            // Control category
    Framework       string            // Framework name (e.g., "STIG", "SANS", "CIS")
    FrameworkVersion string           // Framework version (e.g., "V2R1", "2023.1")
    Severity        SeverityLevel     // Typed severity level
    Rationale       string            // Why this control is important
    Remediation     string            // How to fix compliance issues
    References      []string          // External references (optional)
    Tags            []string          // Categorization tags (optional)
    Metadata        map[string]string // Additional metadata (optional)
}

type SeverityLevel string

const (
    SeverityCritical SeverityLevel = "Critical"
    SeverityHigh     SeverityLevel = "High"
    SeverityMedium   SeverityLevel = "Medium"
    SeverityLow      SeverityLevel = "Low"
    SeverityInfo     SeverityLevel = "Info"
)

func (s SeverityLevel) IsValid() bool {
    switch s {
    case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
        return true
    default:
        return false
    }
}
```

## Plugin Development Patterns

### Static Plugin Structure

Create plugins in `internal/plugins/{name}/` with this pattern:

```go
package pluginname

type Plugin struct {
    controls []Control
}

func NewPlugin() CompliancePlugin {
    return &Plugin{
        controls: []Control{
            // Define controls here
        },
    }
}

// Implement all CompliancePlugin methods
```

### Control ID Conventions

- Use framework-specific prefixes: `V-` for STIG, `SANS-` for SANS, etc.
- Include numeric identifiers: `V-206694`, `SANS-001`
- Maintain consistency within each plugin
- Reference official control IDs when available

### Compliance Check Implementation

- Focus on OPNsense configuration analysis
- Use helper methods for complex logic
- Return specific, actionable findings
- Include all relevant control references
- Use appropriate severity levels

## Plugin Registration

### Static Registration

Register in `PluginManager.InitializePlugins()`:

```go
func (pm *PluginManager) InitializePlugins(ctx context.Context) error {
    // Create and validate your plugin
    yourPlugin := yourplugin.NewPlugin()

    // Validate plugin configuration
    if err := yourPlugin.ValidateConfiguration(); err != nil {
        return fmt.Errorf("validation failed for %s plugin: %w", yourPlugin.Name(), err)
    }

    // Check for duplicate registration
    existingPlugin, exists := pm.registry.GetPlugin(yourPlugin.Name(), yourPlugin.Version())
    if exists {
        return fmt.Errorf("duplicate plugin: %s version %s already registered", yourPlugin.Name(), yourPlugin.Version())
    }

    // Register the plugin
    if err := pm.registry.RegisterPlugin(yourPlugin); err != nil {
        return fmt.Errorf("failed to register %s plugin: %w", yourPlugin.Name(), err)
    }

    return nil
}
```

### Dynamic Plugin Support

**Important Constraints and Limitations:**

- **Build Mode Support**: `go build -buildmode=plugin` is only supported on specific OS/architecture combinations:
  - Linux: amd64, arm64, 386, arm
  - FreeBSD: amd64, arm64
  - macOS: amd64, arm64
  - Windows: amd64, 386
- **Toolchain Requirements**: The plugin must be built with the exact same Go version, GOOS, GOARCH, and build flags as the host binary
- **Runtime Limitations**: Go cannot unload plugins once loaded - they remain in memory for the lifetime of the process
- **Version Compatibility**: Plugin and host must use identical Go toolchain versions

**Recommended Pattern:**

```go
// Use build tags to produce plugin vs static builds
//go:build plugin
// +build plugin

package main

import "github.com/yourorg/opndossier/internal/plugin"

// Plugin variable must be exported for dynamic loading
var Plugin plugin.CompliancePlugin = &YourPlugin{}

//go:build !plugin
// +build !plugin

package main

import "github.com/yourorg/opndossier/internal/plugin"

// Static registration fallback
func init() {
    // Register plugin statically when dynamic loading unavailable
}
```

**Toolchain Version Matching:**

```bash
# Ensure plugin and host use identical Go version
go version  # Both must match exactly

# Build plugin with same flags as host
go build -buildmode=plugin -ldflags="-s -w" -o plugin.so ./plugin

# Verify compatibility
file plugin.so  # Check architecture
strings plugin.so | grep "go1."  # Check Go version
```

## Testing Standards

### Required Test Coverage

- Plugin metadata validation
- Control structure validation
- Compliance check logic
- Error handling scenarios
- Edge cases and boundary conditions

### Test Structure

```go
func TestPluginName_RunChecks(t *testing.T) {
    tests := []struct {
        name     string
        config   *model.OpnSenseDocument
        expected []plugin.Finding
    }{
        // Test cases
    }

    plugin := NewPlugin()
    for _, tt := range tests {
        tt := tt // Capture loop variable for safe parallelization
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel() // Enable safe concurrent execution

            findings := plugin.RunChecks(tt.config)

            // Use cmp.Diff for stable, readable comparison
            if diff := cmp.Diff(tt.expected, findings); diff != "" {
                t.Errorf("RunChecks() mismatch (-expected +got):\n%s", diff)
            }
        })
    }
}
```

## Implementation Guidelines

### Code Quality

- Follow Go conventions and formatting
- Use structured logging with context
- Implement proper error handling
- Include comprehensive documentation
- Maintain >80% test coverage

### Performance Considerations

- Optimize for large configuration files
- Use efficient data structures
- Avoid unnecessary allocations
- Consider concurrent processing where safe

### Security Practices

- Validate all inputs
- Handle malformed configurations gracefully
- Avoid exposing sensitive information
- Use secure coding practices

## Reference Files

- #[[file:internal/plugin/interfaces.go]] - Core interfaces and structs
- #[[file:internal/audit/plugin.go]] - Plugin registry and management
- #[[file:internal/audit/plugin_manager.go]] - High-level plugin operations
- #[[file:internal/plugins/stig/stig.go]] - Example static plugin implementation
- #[[file:docs/dev-guide/plugin-development.md]] - Detailed development guide
