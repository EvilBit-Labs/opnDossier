---
inclusion: fileMatch
fileMatchPattern:
  - 'internal/plugins/**/*'
  - 'internal/plugin/**/*'
  - 'internal/audit/**/*'
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
    Reference      string            // Primary reference (e.g., "STIG V-206694")
    References     []string          // All applicable control IDs
    Tags           []string          // Categorization tags
    Metadata       map[string]string // Optional additional data
}
```

### Control Structure

Define controls with complete metadata:

```go
type Control struct {
    ID          string            // Unique control ID (e.g., "V-206694")
    Title       string            // Control title
    Description string            // Detailed description
    Category    string            // Control category
    Severity    string            // "critical", "high", "medium", "low"
    Rationale   string            // Why this control is important
    Remediation string            // How to fix compliance issues
    References  []string          // External references (optional)
    Tags        []string          // Categorization tags (optional)
    Metadata    map[string]string // Additional metadata (optional)
}
```

## Plugin Development Patterns

### Static Plugin Structure

Create plugins in `internal/plugins/{name}/` with this pattern:

```go
package pluginname

type Plugin struct {
    controls []plugin.Control
}

func NewPlugin() *Plugin {
    return &Plugin{
        controls: []plugin.Control{
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
    // Register your plugin
    yourPlugin := yourplugin.NewPlugin()
    if err := pm.registry.RegisterPlugin(yourPlugin); err != nil {
        return fmt.Errorf("failed to register your plugin: %w", err)
    }
    return nil
}
```

### Dynamic Plugin Support

- Build with `go build -buildmode=plugin`
- Export `var Plugin plugin.CompliancePlugin`
- Place `.so` files in plugin directory
- Ensure Go version compatibility

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
        t.Run(tt.name, func(t *testing.T) {
            findings := plugin.RunChecks(tt.config)
            // Assertions
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
