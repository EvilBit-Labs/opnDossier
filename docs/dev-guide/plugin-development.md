# Plugin Development Guide

## Overview

opnFocus uses a plugin-based architecture for compliance standards, allowing developers to create custom compliance plugins that integrate seamlessly with the core audit engine. Plugins can be either statically registered (baked into the binary) or dynamically loaded at runtime as Go plugins (`.so` files). This guide explains how to create, implement, and integrate new compliance plugins.

## Plugin Architecture

### Core Components

- **`CompliancePlugin` Interface**: Defines the contract that all plugins must implement
- **`PluginRegistry`**: Manages plugin registration, dynamic loading, and lifecycle
- **`PluginManager`**: Coordinates plugin operations and provides high-level APIs
- **`Control` Struct**: Represents individual compliance controls within a standard

### Plugin Interface

All plugins must implement the `CompliancePlugin` interface:

```go
import "github.com/unclesp1d3r/opnFocus/internal/plugin"

type CompliancePlugin interface {
    Name() string                    // Unique plugin identifier
    Version() string                 // Plugin version
    Description() string             // Human-readable description
    RunChecks(config *model.OpnSenseDocument) []plugin.Finding // Execute compliance checks
    GetControls() []plugin.Control   // Return all controls
    GetControlByID(id string) (*plugin.Control, error) // Get specific control
    ValidateConfiguration() error    // Validate plugin config
}
```

The `Finding` struct is generic and uses `References`, `Tags`, and `Metadata` fields:

```go
// plugin.Finding
Type        string              // e.g. "compliance"
Title       string
Description string
Recommendation string
Component   string
Reference   string
References  []string            // Control IDs or external references
Tags        []string            // Arbitrary tags for filtering/categorization
Metadata    map[string]string   // Optional extra data
```

## Creating a New Plugin

### Step 1: Plugin Structure

For static plugins, create a new directory in `internal/plugins/`:

```text
internal/plugins/
├── stig/
│   └── stig.go
├── sans/
│   └── sans.go
├── firewall/
│   └── firewall.go
└── your_plugin/
    └── your_plugin.go
```

For dynamic plugins, create a new Go module or directory with a `main` package.

### Step 2: Plugin Implementation

#### Static Plugin Example

```go
package plugins

import (
    "fmt"
    "github.com/unclesp1d3r/opnFocus/internal/plugin"
    "github.com/unclesp1d3r/opnFocus/internal/model"
)

type CustomPlugin struct {
    controls []plugin.Control
}

func NewCustomPlugin() *CustomPlugin {
    return &CustomPlugin{
        controls: []plugin.Control{
            {
                ID:          "CUSTOM-001",
                Title:       "Custom Security Control",
                Description: "Description of the custom security control",
                Category:    "Security",
                Severity:    "high",
                Rationale:   "Why this control is important",
                Remediation: "How to fix compliance issues",
                Tags:        []string{"custom", "security", "compliance"},
            },
        },
    }
}

func (cp *CustomPlugin) Name() string        { return "custom" }
func (cp *CustomPlugin) Version() string     { return "1.0.0" }
func (cp *CustomPlugin) Description() string { return "Custom compliance checks for specific security requirements" }
func (cp *CustomPlugin) GetControls() []plugin.Control { return cp.controls }
func (cp *CustomPlugin) GetControlByID(id string) (*plugin.Control, error) {
    for _, control := range cp.controls {
        if control.ID == id {
            return &control, nil
        }
    }
    return nil, fmt.Errorf("control '%s' not found", id)
}
func (cp *CustomPlugin) ValidateConfiguration() error {
    if len(cp.controls) == 0 {
        return fmt.Errorf("no controls defined")
    }
    return nil
}
func (cp *CustomPlugin) RunChecks(config *model.OpnSenseDocument) []plugin.Finding {
    var findings []plugin.Finding
    // Implement your compliance checks here
    // Example:
    findings = append(findings, plugin.Finding{
        Type:           "compliance",
        Title:          "Missing Custom Security Feature",
        Description:    "The configuration is missing required custom security feature",
        Recommendation: "Enable the custom security feature in the configuration",
        Component:      "security",
        Reference:      "CUSTOM-001",
        References:     []string{"CUSTOM-001"},
        Tags:           []string{"custom", "security", "compliance"},
    })
    return findings
}
```

#### Dynamic Plugin Example

```go
package main

import (
    "github.com/unclesp1d3r/opnFocus/internal/plugin"
    "github.com/unclesp1d3r/opnFocus/internal/model"
)

type MyDynamicPlugin struct{}

// Implement CompliancePlugin methods...

var Plugin plugin.CompliancePlugin = &MyDynamicPlugin{}
```

Build with:

```sh
go build -buildmode=plugin -o myplugin.so main.go
```

### Step 3: Plugin Registration

- **Static plugins**: Register in the plugin manager as before.
- **Dynamic plugins**: Drop `.so` files into the plugin directory (default: `./plugins`). They will be loaded automatically at startup.

## Dynamic Plugin Loading

- The audit engine will scan a configurable directory for `.so` files and load any plugin that exports `var Plugin plugin.CompliancePlugin`.
- Dynamic plugins must be built with the same Go version and dependencies as the main binary.
- Both static and dynamic plugins are supported and can coexist.

## Plugin Development Best Practices

- Use unique, descriptive control IDs and titles.
- Provide actionable remediation and clear rationale.
- Use the `References` and `Tags` fields for all findings.
- Write comprehensive tests for your plugin.
- Document your controls and plugin usage.

## Troubleshooting

- **Plugin not loaded?** Ensure it is built as a Go plugin (`-buildmode=plugin`), exports `var Plugin`, and is in the correct directory.
- **Go version mismatch?** All plugins and the main binary must be built with the exact same Go version and dependencies.
- **Platform support:** Go plugins are supported on Linux and macOS, not Windows.

## Examples

- See `internal/plugins/` for static plugin examples.
- See the above dynamic plugin example for external plugins.

## Conclusion

The opnFocus plugin system is flexible: you can extend compliance coverage by adding new plugins statically or dynamically, with a simple, generic interface and robust integration with the audit engine.
