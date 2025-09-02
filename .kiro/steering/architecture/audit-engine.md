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

> **Note for Contributors**: The canonical struct definitions live in `internal/plugin/interfaces.go`.
> Modify types only in that file and update this documentation when changes are made.

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
    &Plugin{controls: initializeControls()}
}

func (p *Plugin) RunChecks(ctx context.Context, config *model.OpnSenseDocument) ([]plugin.Finding, error) {
    // Implement compliance validation logic
    // Check ctx.Done() for cancellation
    // Return errors from underlying checks
}
```

### Required Methods

- `Name()` - Unique plugin identifier (e.g., "STIG", "SANS") - returns string
- `Version()` - Plugin version string - returns string
- `Description()` - Brief plugin description - returns string
- `RunChecks(ctx context.Context, config *model.OpnSenseDocument) ([]plugin.Finding, error)` - Core compliance checking logic
- `GetControls(ctx context.Context) ([]plugin.Control, error)` - Return all available controls
- `GetControlByID(ctx context.Context, id string) (*plugin.Control, error)` - Retrieve specific control by ID
- `ValidateConfiguration(ctx context.Context) error` - Validate plugin setup

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
- Log with context: `log.Info("message", "key", value)`
- Handle configuration parsing errors gracefully
- Return meaningful error messages for debugging
- Never panic in plugin code

### Performance Guidelines

- Use `xml.Decoder.Token()` for streaming large XML configs to avoid loading entire file into memory
- Pre-allocate findings/collections using known control counts (`len`/`cap`) before parsing to reduce allocations
- Use pre-sized maps or slices for lookups and buffering results
- Consider bounded worker queues for concurrent independent checks to avoid unbounded memory growth on >100MB files
- Minimize memory allocations in hot paths
- Use efficient data structures for lookups

## Plugin Registry Usage

### Registration Process

```go
// In PluginManager.InitializePlugins()
stigPlugin := stig.NewPlugin()

// Validate plugin configuration before registration
if err := stigPlugin.ValidateConfiguration(ctx); err != nil {
    return fmt.Errorf("STIG plugin configuration validation failed: %w", err)
}

// Check for duplicate registrations
if existing := pm.registry.GetPlugin(stigPlugin.Name(), stigPlugin.Version()); existing != nil {
    return fmt.Errorf("plugin %s version %s already registered", stigPlugin.Name(), stigPlugin.Version())
}

// Register plugin after validation and duplicate checks
if err := pm.registry.RegisterPlugin(stigPlugin); err != nil {
    return fmt.Errorf("failed to register STIG plugin: %w", err)
}
```

### Dynamic Plugin Support

- Load `.so` files from plugin directory
- Validate plugin interface compliance
- Handle loading failures gracefully
- Log plugin registration status
- Support discovering and loading new plugins on change; restart required to unload/replace

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
        goldenFile string
    }{
        // Test cases with golden file references
    }

    for _, tt := range tests {
        tt := tt // capture range variable
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel() // Run subtests in parallel

            plugin := NewPlugin()
            findings, err := plugin.RunChecks(context.Background(), tt.config)
            if err != nil {
                t.Fatalf("RunChecks failed: %v", err)
            }

            // Normalize ordering/IDs for deterministic comparison
            normalizedFindings := normalizeFindings(findings)

            // Load golden file and compare
            goldenData := loadGoldenFile(t, tt.goldenFile)
            if diff := cmp.Diff(goldenData, normalizedFindings); diff != "" {
                if *updateGoldens {
                    writeGoldenFile(t, tt.goldenFile, normalizedFindings)
                    t.Logf("Updated golden file: %s", tt.goldenFile)
                } else {
                    t.Errorf("Findings mismatch (-want +got):\n%s", diff)
                }
            }
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
