---
inclusion: fileMatch
fileMatchPattern:
  - internal/audit/**/*.go
  - internal/plugin/**/*.go
  - internal/plugins/**/*.go
---

# Audit Engine Architecture Guidelines

## Core Components

The audit engine consists of three key components:

- #[[file:internal/audit/plugin.go]] - Plugin registry and compliance checking
- #[[file:internal/audit/plugin_manager.go]] - Plugin lifecycle management
- #[[file:internal/plugin/interfaces.go]] - Plugin interfaces and data structures

## Data Structure Standards

### Required Structs

- **`Finding`**: Generic audit finding with `References`, `Tags`, `Metadata` fields
- **`ComplianceResult`**: Complete audit results with findings and summary
- **`ComplianceSummary`**: Statistical summary of compliance status
- **`PluginInfo`**: Plugin metadata and control information
- **`Control`**: Individual compliance control definition

### Finding Structure Rules

- Use generic `Finding` struct for all audit results
- Include actionable recommendations in `Recommendation` field
- Populate `References` array with control IDs
- Use `Tags` for categorization and filtering
- Store additional context in `Metadata` map
- Never create compliance-specific finding types

## Plugin Development Standards

### Interface Implementation

All plugins MUST implement `CompliancePlugin` interface:

```go
type Plugin struct {
    controls []plugin.Control
}

func NewPlugin() *Plugin {
    return &Plugin{controls: initializeControls()}
}

func (p *Plugin) RunChecks(config *model.OpnSenseDocument) []plugin.Finding {
    // Implement compliance validation logic
}
```

### Required Methods

- `Name()` - Unique plugin identifier (e.g., "STIG", "SANS")
- `Version()` - Plugin version string
- `Description()` - Brief plugin description
- `RunChecks()` - Core compliance checking logic
- `GetControls()` - Return all available controls
- `GetControlByID()` - Retrieve specific control by ID
- `ValidateConfiguration()` - Validate plugin setup

### Plugin Organization

- Place plugins in `internal/plugins/{standard}/` directories
- Use lowercase package names (`firewall`, `sans`, `stig`)
- Name main type `Plugin` to avoid stuttering
- Implement `NewPlugin()` constructor function
- Register plugins in `PluginManager.InitializePlugins()`

## Compliance Checking Patterns

### Check Implementation

- Create separate functions for each compliance check
- Use descriptive names: `checkPasswordComplexity()`, `validateFirewallRules()`
- Return `[]plugin.Finding` with specific violations
- Include severity levels: `critical`, `high`, `medium`, `low`
- Provide actionable remediation guidance

### Error Handling

- Use structured logging with `charmbracelet/log`
- Log with context: `logger.InfoContext(ctx, "message", "key", value)`
- Handle configuration parsing errors gracefully
- Return meaningful error messages for debugging
- Never panic in plugin code

### Performance Guidelines

- Pre-allocate slices with known capacity
- Minimize memory allocations in hot paths
- Use efficient data structures for lookups
- Consider concurrent processing for independent checks
- Optimize for large configuration files (>100MB)

## Plugin Registry Usage

### Registration Process

```go
// In PluginManager.InitializePlugins()
stigPlugin := stig.NewPlugin()
if err := pm.registry.RegisterPlugin(stigPlugin); err != nil {
    return fmt.Errorf("failed to register STIG plugin: %w", err)
}
```

### Dynamic Plugin Support

- Load `.so` files from plugin directory
- Validate plugin interface compliance
- Handle loading failures gracefully
- Log plugin registration status
- Support hot-reloading of plugins

## Testing Requirements

### Test Coverage

- Unit tests for all compliance checks
- Table-driven tests for multiple scenarios
- Integration tests with sample configurations
- Error handling and edge case validation
- Plugin registration and lifecycle testing

### Test Structure

```go
func TestPlugin_RunChecks(t *testing.T) {
    tests := []struct {
        name     string
        config   *model.OpnSenseDocument
        expected []plugin.Finding
    }{
        // Test cases
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

## Integration Guidelines

### Audit Engine Usage

- Use `PluginManager` for all plugin operations
- Initialize plugins during application startup
- Support multiple compliance standards simultaneously
- Maintain plugin isolation and error boundaries
- Log audit operations with structured logging

### Configuration Validation

- Validate plugin configuration on registration
- Check for required dependencies and resources
- Provide clear error messages for misconfigurations
- Support plugin-specific configuration options
- Validate control definitions and metadata
