---
applyTo: internal/audit/**/*.go,internal/plugin/**/*.go
---

# Audit Engine Guidelines

## Core Audit Components

The audit engine is defined in the following files:

- `internal/audit/plugin.go` - Plugin registry and compliance checking logic
- `internal/audit/plugin_manager.go` - Plugin lifecycle management
- `internal/plugin/interfaces.go` - Plugin interfaces and data structures

## Audit Engine Standards

### Data Structures

- Use the generic `Finding` struct for all audit findings (with `References`, `Tags`, and `Metadata` fields)
- Use `ComplianceResult` struct for audit results
- Use `ComplianceSummary` struct for audit summaries
- Use `PluginInfo` struct for plugin metadata
- Do not use compliance-specific reference fields in findings

### Compliance Checking

- Implement compliance checks in separate functions within plugin packages
- Use descriptive function names that indicate what is being checked
- Return meaningful findings with actionable recommendations
- Include proper severity levels and categorization
- Use the `RunChecks` method in plugins to perform compliance validation

### Plugin Architecture

- All compliance plugins must implement the `CompliancePlugin` interface
- Plugins are organized in `internal/plugins/` directory by compliance standard
- Each plugin should have its own package (e.g., `firewall`, `sans`, `stig`)
- Use `Plugin` as the main type name to avoid stuttering
- Implement `NewPlugin()` constructor function

### Error Handling

- Use structured error handling with context
- Provide clear error messages for configuration issues
- Handle edge cases gracefully
- Log errors appropriately for debugging
- Use context-aware logging methods (`InfoContext`, `ErrorContext`)

### Performance Considerations

- Optimize compliance checks for large configurations
- Use efficient data structures and algorithms
- Minimize memory allocations during processing
- Consider concurrent processing for multiple checks
- Pre-allocate slices where possible

## Integration with Plugins

- The audit engine supports both static (baked-in) and dynamic (runtime-loaded) plugins
- Use the plugin registry for dynamic compliance checking
- Support multiple compliance standards simultaneously
- Maintain backward compatibility with existing functionality
- Plugins are loosely coupled and only depend on the OpnSenseDocument model and the generic plugin interface
- Use `PluginManager` for plugin lifecycle management

## Plugin Development

### Required Methods

All plugins must implement:

- `Name()` - Returns unique plugin identifier
- `Version()` - Returns plugin version
- `Description()` - Returns plugin description
- `RunChecks(config *model.OpnSenseDocument) []plugin.Finding` - Performs compliance checks
- `GetControls()` - Returns all controls
- `GetControlByID(id string)` - Returns specific control
- `ValidateConfiguration()` - Validates plugin configuration

### Plugin Structure

```go
type Plugin struct {
    controls []plugin.Control
}

func NewPlugin() *Plugin {
    // Initialize plugin with controls
}

func (p *Plugin) RunChecks(config *model.OpnSenseDocument) []plugin.Finding {
    // Implement compliance checks
}
```

## Testing Requirements

- Create comprehensive tests for all compliance checks
- Use table-driven tests for multiple scenarios
- Test with various configuration types and sizes
- Ensure proper error handling and edge cases
- Test plugin registration and lifecycle management
- Validate plugin interface compliance
- Ensure proper error handling and edge cases
