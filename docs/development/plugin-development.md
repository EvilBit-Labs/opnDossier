# Plugin Development Guide

## Overview

opnDossier uses a plugin-based architecture for compliance standards, allowing developers to create custom compliance plugins that integrate seamlessly with the core audit engine. Plugins can be either statically registered (baked into the binary) or dynamically loaded at runtime as Go plugins (`.so` files). This guide explains how to create, implement, and integrate new compliance plugins.

## Plugin Architecture

### Core Components

- **`compliance.Plugin` Interface**: Defines the contract that all plugins must implement
- **`PluginRegistry`**: Manages plugin registration, dynamic loading, and lifecycle
- **`PluginManager`**: Coordinates plugin operations and provides high-level APIs
- **`Control` Struct**: Represents individual compliance controls within a standard

### Plugin Interface

All plugins must implement the `compliance.Plugin` interface:

```go
import (
    "github.com/EvilBit-Labs/opnDossier/internal/compliance"
    common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

type Plugin interface {
    Name() string                    // Unique plugin identifier
    Version() string                 // Plugin version
    Description() string             // Human-readable description
    RunChecks(device *common.CommonDevice) []compliance.Finding // Execute compliance checks
    GetControls() []compliance.Control   // Return all controls
    GetControlByID(id string) (*compliance.Control, error) // Get specific control
    ValidateConfiguration() error    // Validate plugin config
}
```

The `Finding` struct is generic and uses `Severity`, `References`, `Tags`, and `Metadata` fields:

```go
// compliance.Finding
Type        string              // e.g. "compliance"
Severity    string              // e.g. "high" — copied from control's severity
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
    "github.com/EvilBit-Labs/opnDossier/internal/compliance"
    common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

type CustomPlugin struct {
    controls []compliance.Control
}

func NewCustomPlugin() *CustomPlugin {
    return &CustomPlugin{
        controls: []compliance.Control{
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
func (cp *CustomPlugin) GetControls() []compliance.Control { return cp.controls }
func (cp *CustomPlugin) GetControlByID(id string) (*compliance.Control, error) {
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
func (cp *CustomPlugin) RunChecks(device *common.CommonDevice) []compliance.Finding {
    var findings []compliance.Finding
    // Implement your compliance checks here
    // Example:
    findings = append(findings, compliance.Finding{
        Type:           "compliance",
        Severity:       "high",
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
    "github.com/EvilBit-Labs/opnDossier/internal/compliance"
    common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

type MyDynamicPlugin struct{}

// Implement compliance.Plugin methods...
// RunChecks(device *common.CommonDevice) []compliance.Finding

var Plugin compliance.Plugin = &MyDynamicPlugin{}
```

Build with:

```sh
go build -buildmode=plugin -o myplugin.so main.go
```

### Step 3: Plugin Registration

- **Static plugins**: Register in the plugin manager as before.
- **Dynamic plugins**: Drop `.so` files into the plugin directory (default: `./plugins`). They will be loaded automatically at startup.

## Dynamic Plugin Loading

- The audit engine will scan a configurable directory for `.so` files and load any plugin that exports `var Plugin compliance.Plugin`.
- Dynamic plugins must be built with the same Go version and dependencies as the main binary.
- Both static and dynamic plugins are supported and can coexist.

## Migrating to the CommonDevice Plugin API

**Breaking change (internal API — semver stays v1.x):** The `RunChecks` method signature changed from `*model.OpnSenseDocument` to `*common.CommonDevice`.

| Item      | v1.x                      | Current                |
| --------- | ------------------------- | ---------------------- |
| Import    | `internal/model`          | `pkg/model`            |
| Parameter | `*model.OpnSenseDocument` | `*common.CommonDevice` |

**Migration steps:**

1. Replace `"github.com/EvilBit-Labs/opnDossier/internal/model"` import with `common "github.com/EvilBit-Labs/opnDossier/pkg/model"`
2. Change `RunChecks(config *model.OpnSenseDocument)` to `RunChecks(device *common.CommonDevice)`
3. Update field access — `CommonDevice` mirrors the full OPNsense surface area; field names follow Go domain conventions rather than XML tag names. Refer to `pkg/model/` for the full type definitions.

## Plugin Development Best Practices

- Use unique, descriptive control IDs and titles.
- Provide actionable remediation and clear rationale.
- Always set `Finding.Severity` to match the control's `Severity` for correct severity breakdown in audit reports.
- Use the `References` and `Tags` fields for all findings.
- Write comprehensive tests for your plugin.
- Document your controls and plugin usage.

## Device Parser Development

opnDossier supports adding new device types (e.g., pfSense, Fortinet, MikroTik) through a compile-time parser registry. This is separate from compliance plugins -- device parsers transform vendor-specific configuration files into the platform-agnostic `CommonDevice` model.

### Architecture

The `DeviceParserRegistry` in `pkg/parser/registry.go` follows the `database/sql` driver registration pattern:

- Parsers self-register via `init()` functions
- The `Factory` auto-detects device type from the XML root element
- External parsers link at compile time via blank imports

### Creating a Device Parser

1. **Create a Go package** that implements the `parser.DeviceParser` interface:

   ```go
   package pfsense

   import (
       "context"
       "io"

       common "github.com/EvilBit-Labs/opnDossier/pkg/model"
       "github.com/EvilBit-Labs/opnDossier/pkg/parser"
   )

   type PfSenseParser struct{}

   func (p *PfSenseParser) Parse(
       ctx context.Context, r io.Reader,
   ) (*common.CommonDevice, []common.ConversionWarning, error) {
       // Parse pfSense XML and convert to CommonDevice
   }

   func (p *PfSenseParser) ParseAndValidate(
       ctx context.Context, r io.Reader,
   ) (*common.CommonDevice, []common.ConversionWarning, error) {
       // Parse + validate
   }
   ```

2. **Register via `init()`**:

   ```go
   func init() {
       parser.Register("pfsense", func(dec parser.XMLDecoder) parser.DeviceParser {
           return &PfSenseParser{}
       })
   }
   ```

   The first argument (`"pfsense"`) must match the XML root element name of the config file.

3. **Link via blank import** in your consumer binary:

   ```go
   package main

   import (
       "github.com/EvilBit-Labs/opnDossier/cmd"
       _ "github.com/example/pfsense-parser" // self-registers at init()
   )

   func main() { cmd.Execute() }
   ```

### Key Types

| Type                     | Description                                                                                           |
| ------------------------ | ----------------------------------------------------------------------------------------------------- |
| `parser.DeviceParser`    | Interface: `Parse()` and `ParseAndValidate()` returning `(*CommonDevice, []ConversionWarning, error)` |
| `parser.ConstructorFunc` | Factory signature: `func(XMLDecoder) DeviceParser`                                                    |
| `parser.XMLDecoder`      | XML parsing backend injected by the Factory; external parsers that handle their own XML may ignore it |

### Registration Rules

- Device type names are normalized to lowercase with whitespace trimmed
- Duplicate registrations panic at startup (fail-fast)
- Nil factories and empty names panic at startup
- `parser.DefaultRegistry().List()` returns all registered types (sorted)

### Testing

Use `parser.NewFactoryWithRegistry()` with `parser.NewDeviceParserRegistry()` for isolated tests that don't pollute the global registry:

```go
reg := parser.NewDeviceParserRegistry()
reg.Register("testdevice", myFactory)
factory := parser.NewFactoryWithRegistry(decoder, reg)
device, warnings, err := factory.CreateDevice(ctx, reader, "", false)
```

### Common Pitfalls

**Empty registry (missing blank import):** The most common mistake is forgetting the blank import. Without it, your parser's `init()` never runs and the registry stays empty. The symptom is an error like:

```text
unsupported device type: root element <pfsense> is not recognized; supported: (none registered -- ensure parser packages are imported)
```

Fix: add `_ "your/parser/package"` to the binary's import list.

**Root element mismatch:** The string passed to `parser.Register()` must exactly match the XML root element name (lowercase). If a pfSense config uses `<pfsense>` as the root element, register as `"pfsense"`, not `"pfSense"` or `"PfSense"` (the registry normalizes to lowercase, but the XML root element detection also lowercases).

**Duplicate registration:** If two packages register the same root element name, the binary will panic at startup. This is intentional -- it surfaces conflicts immediately rather than silently picking one.

### Source Files

- `pkg/parser/registry.go` -- Registry implementation
- `pkg/parser/factory.go` -- Factory with auto-detection and error handling
- `pkg/parser/opnsense/parser.go` -- Built-in OPNsense parser (reference implementation)

## Troubleshooting

### Compliance Plugins

- **Plugin not loaded?** Ensure it is built as a Go plugin (`-buildmode=plugin`), exports `var Plugin`, and is in the correct directory.
- **Go version mismatch?** All plugins and the main binary must be built with the exact same Go version and dependencies.
- **Platform support:** Go plugins are supported on Linux and macOS, not Windows.

### Device Parsers

- **Device type not recognized?** Ensure the parser package is imported via blank import (`_ "pkg/path"`) in the binary so `init()` runs. See "Common Pitfalls" above.
- **Panic on startup?** Two packages registered the same root element name. Check for duplicate `parser.Register()` calls.
- **Auto-detection picks wrong parser?** Use `--device-type` to force a specific parser and bypass root element detection.

## Examples

- `internal/plugins/` contains static compliance plugin examples.
- `pkg/parser/opnsense/parser.go` provides a reference device parser implementation.
- The dynamic plugin example above demonstrates external compliance plugins.

## Conclusion

The opnDossier plugin system is flexible: you can extend compliance coverage by adding new compliance plugins, and add new device types by registering device parsers via the `DeviceParserRegistry`. Both systems use self-registration patterns for zero-change extensibility.
