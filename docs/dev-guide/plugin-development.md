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
    RunChecks(device *common.CommonDevice) []compliance.Finding // Execute compliance checks (panic-safe)
    GetControls() []compliance.Control   // Return all controls
    GetControlByID(id string) (*compliance.Control, error) // Get specific control
    ValidateConfiguration() error    // Validate plugin config
}
```

**Note:** The audit engine wraps `RunChecks()` calls in panic recovery, so a panicking plugin will not crash the audit process. However, plugins should still handle errors properly and return findings or empty slices rather than panicking, as panic recovery is a safety mechanism, not a substitute for good error handling.

The `Finding` struct is generic and uses `References`, `Tags`, and `Metadata` fields:

```go
// compliance.Finding
Type           string            // Category (e.g., "compliance")
Severity       common.Severity   // Severity level: use constants like common.SeverityCritical, common.SeverityHigh, etc.
Title          string
Description    string
Recommendation string
Component      string
Reference      string            // Single control ID reference
References     []string          // Multiple control ID references
Tags           []string
Metadata       map[string]string
```

**Note:** `compliance.Finding` is a type alias for the canonical `analysis.Finding` type defined in `internal/analysis/finding.go`. This architectural change unifies finding representations across the audit, compliance, and processor modules, ensuring consistency throughout the codebase. Plugins should continue to import `github.com/EvilBit-Labs/opnDossier/internal/compliance` and use `compliance.Finding`, which remains fully compatible.

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
                Severity:    string(common.SeverityHigh),
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
func (cp *CustomPlugin) GetControls() []compliance.Control { return compliance.CloneControls(cp.controls) }
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

// controlSeverity returns the severity for a control ID from the control
// definitions. This ensures findings derive severity from the single source
// of truth (the control metadata) rather than hard-coding literals.
func (cp *CustomPlugin) controlSeverity(id string) common.Severity {
    for _, c := range cp.controls {
        if c.ID == id {
            return common.Severity(c.Severity)
        }
    }
    return ""
}
func (cp *CustomPlugin) RunChecks(device *common.CommonDevice) []compliance.Finding {
    var findings []compliance.Finding
    // Implement your compliance checks here
    // Example:
    findings = append(findings, compliance.Finding{
        Type:           "compliance",
        Severity:       cp.controlSeverity("CUSTOM-001"),
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
- **Dynamic plugins**: Drop `.so` files into the plugin directory. They will be loaded automatically at startup.

## Dynamic Plugin Loading

The audit engine scans a configurable directory for `.so` files and loads any plugin that exports `var Plugin compliance.Plugin`.

### Configuration

Use the `--plugin-dir` CLI flag to specify a custom directory containing `.so` plugins:

```sh
opndossier convert --audit-mode standard --plugin-dir /path/to/plugins config.xml
```

**Default behavior:** If `--plugin-dir` is not specified, the engine does not attempt to load dynamic plugins. There is no hardcoded default plugin directory.

**Explicit vs. optional paths:**

- **Explicit directory** (user-provided via `--plugin-dir`): If the directory does not exist, the audit fails fast with an error.
- **Optional/default paths**: If implemented by calling code, missing directories are silently skipped (Debug log).

### Load Result and Error Handling

`LoadDynamicPlugins` returns `(LoadResult, error)`:

- **`LoadResult`** tracks both successful (`Loaded int`) and failed (`Failed() int`) plugin counts
- **Per-plugin failures** are collected in `LoadResult.Failures` (slice of `PluginLoadError`)
- **Aggregate errors** are returned via `errors.Join` when one or more plugins fail to load
- **Individual plugin load failures are non-fatal** — other plugins continue loading

**CLI behavior:** The audit command surfaces load failures to users via `Warn` logs listing failed plugin filenames. The audit continues with any successfully loaded plugins.

**Programmatic usage:** If using `PluginManager` programmatically:

1. Call `SetPluginDir(dir, explicit)` before `InitializePlugins()`
2. Check `GetLoadResult()` after initialization to detect any plugin load failures
3. `LoadResult.Failures` contains individual `PluginLoadError` entries with filename and error

**PluginLoadError type:** Each failure captures the `.so` filename and the underlying error. It implements the `error` interface for use with `errors.Join`.

### Requirements

- Dynamic plugins must be built with the same Go version and dependencies as the main binary.
- Both static and dynamic plugins are supported and can coexist.
- The plugin directory is scanned once during `InitializePlugins()`, not on every audit.

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

- **Control ID patterns**: Use stable, predictable identifiers. The built-in plugins use `V-XXXXXX` for STIG (matching real DISA STIG vulnerability IDs), `SANS-FW-XXX` for SANS, and `FIREWALL-XXX` for the firewall plugin. New plugins should follow a similar `PLUGIN-XXX` pattern with a prefix that identifies the standard.
- Provide actionable remediation and clear rationale.
- Use the `References` and `Tags` fields for all findings.
- **Set Finding Severity**: Plugins must populate `Finding.Severity` for accurate severity breakdown in reports. Use typed constants like `common.SeverityHigh`, `common.SeverityCritical`, etc., from `pkg/model`. Use a helper function like `controlSeverity(id string) common.Severity` to look up severity from control definitions rather than hard-coding literals.
- **Deep Copy Controls**: Implement `GetControls()` to return `compliance.CloneControls(cp.controls)` to prevent callers from mutating the plugin's internal state.
- Write comprehensive tests for your plugin.
- Document your controls and plugin usage.

### Testing Dynamic Plugin Loading

For testing code that loads dynamic plugins without requiring real `.so` files, use the `pluginLoaderFunc` injection mechanism:

- Tests can create a `PluginRegistry` with `newPluginRegistryWithLoader(fakeLoader)`
- The fake loader can return mock plugins or simulate load failures deterministically
- This enables testing of load error handling, partial failures, and `LoadResult` aggregation without filesystem dependencies

See `internal/audit/plugin_global_test.go` for examples of injecting test loaders.

### Error Handling and Panic Recovery

The audit engine wraps each `RunChecks()` call in panic recovery to protect the audit process from misbehaving plugins. If a plugin panics during execution:

- The panic is caught and logged via the structured logger with the plugin name and panic details
- The plugin remains in the audit results with zero findings (it is not skipped or removed)
- Other plugins continue to execute without interruption
- The overall audit process completes successfully

**Best practices:**

- Plugins should handle errors gracefully by returning appropriate findings rather than panicking
- Use proper error checking and validation in your compliance checks
- Return empty findings slices (`[]compliance.Finding`) for plugins that find no issues, rather than panicking
- The panic recovery is a safety net for unexpected failures, not a substitute for proper error handling
- For better diagnostics, log errors within your plugin and return descriptive findings instead of relying on panic recovery

### Dynamic Plugin Load Failures

Dynamic plugin load failures (from `.so` files) are distinct from runtime panics:

- Load failures occur during `InitializePlugins()` when the registry scans the plugin directory
- Failed plugins do not appear in the audit results at all (they are never registered)
- The CLI surfaces load failures via `Warn` logs with failed plugin filenames
- Programmatic callers should check `PluginManager.GetLoadResult()` after initialization
- Common load failure causes: Go version mismatch, missing dependencies, malformed `.so` files, duplicate plugin names

### Setting Finding Severity

The audit engine requires the `Finding.Severity` field to generate accurate severity breakdowns in reports. Plugins should:

1. **Use typed severity constants from `pkg/model`**:

   Available severity constants:

   - `common.SeverityCritical` — for critical security issues
   - `common.SeverityHigh` — for high-priority findings
   - `common.SeverityMedium` — for medium-priority findings
   - `common.SeverityLow` — for low-priority findings

2. **Derive severity from control metadata** using a helper function that looks up the control's severity:

   ```go
   // controlSeverity returns the severity for a control ID from the control
   // definitions. This ensures findings derive severity from the single source
   // of truth (the control metadata) rather than hard-coding literals.
   func (p *Plugin) controlSeverity(id string) common.Severity {
       for _, c := range p.controls {
           if c.ID == id {
               return common.Severity(c.Severity)
           }
       }
       return ""
   }
   ```

3. **Set Severity on every Finding**:

   ```go
   findings = append(findings, compliance.Finding{
       Type:           "compliance",
       Severity:       p.controlSeverity("MY-PLUGIN-001"),
       Title:          "Example Finding",
       Description:    "Description of the issue",
       Recommendation: "How to fix it",
       Reference:      "MY-PLUGIN-001",
   })
   ```

4. **Benefits of typed constants**: Using typed constants from `pkg/model` provides compile-time validation, prevents typos, enables IDE autocomplete, and makes refactoring safer. The compiler will catch invalid severity values before runtime.

5. **Fallback behavior**: The audit engine will attempt to derive severity from referenced controls if not provided, but plugins should not rely on this behavior. Always set `Finding.Severity` explicitly.

### Working with Model Enums

opnDossier uses typed string enums in `pkg/model` for firewall rules, NAT configuration, network types, and other model fields. These enums provide compile-time type safety and prevent typos.

**Common enum types:**

- **`RuleType`** (firewall rule actions):

  - `common.RuleTypePass` — allow matching traffic
  - `common.RuleTypeBlock` — silently drop matching traffic
  - `common.RuleTypeReject` — drop and send rejection response

- **`Direction`** (firewall rule direction):

  - `common.DirectionIn` — inbound traffic
  - `common.DirectionOut` — outbound traffic
  - `common.DirectionAny` — bidirectional

- **`IPProtocol`** (IP address family):

  - `common.IPProtocolInet` — IPv4
  - `common.IPProtocolInet6` — IPv6

- **`NATOutboundMode`** (NAT configuration):

  - `common.OutboundAutomatic` — automatic outbound NAT
  - `common.OutboundHybrid` — combined automatic and manual rules
  - `common.OutboundAdvanced` — manual rules only
  - `common.OutboundDisabled` — NAT disabled

**Example usage in plugin checks:**

```go
// Check for permissive firewall rules
for _, rule := range device.FirewallRules {
    if rule.Type == common.RuleTypePass && 
       rule.Source.Address == "any" && 
       rule.Direction == common.DirectionIn {
        // Found a permissive inbound allow rule
    }
}

// Check NAT configuration
if device.NAT.OutboundMode == common.OutboundAutomatic {
    // NAT is in automatic mode
}

// Check IP protocol for IPv6 support
for _, rule := range device.FirewallRules {
    if rule.IPProtocol == common.IPProtocolInet6 {
        // Found an IPv6 rule
    }
}
```

**Benefits:**

- Compile-time validation — invalid enum values cause build failures
- IDE autocomplete for available values
- Refactoring support — renaming a constant updates all uses
- Eliminates string literal typos like `"pas"` instead of `"pass"`

## Device Parser Development

opnDossier ships with built-in parsers for **OPNsense** and **pfSense** devices. Additional device types (e.g., Fortinet, MikroTik, Cisco ASA) can be added through a compile-time parser registry. Device parsers are separate from compliance plugins -- they transform vendor-specific configuration files into the platform-agnostic `CommonDevice` model.

### Architecture

The `DeviceParserRegistry` in `pkg/parser/registry.go` follows the `database/sql` driver registration pattern:

- Parsers self-register via `init()` functions
- The `Factory` auto-detects device type from the XML root element
- External parsers link at compile time via blank imports

### Creating a Device Parser

1. **Create a Go package** that implements the `parser.DeviceParser` interface:

   ```go
   package fortinet

   import (
       "context"
       "io"

       common "github.com/EvilBit-Labs/opnDossier/pkg/model"
       "github.com/EvilBit-Labs/opnDossier/pkg/parser"
   )

   type FortinetParser struct{}

   func (p *FortinetParser) Parse(
       ctx context.Context, r io.Reader,
   ) (*common.CommonDevice, []common.ConversionWarning, error) {
       // Parse Fortinet config and convert to CommonDevice
   }

   func (p *FortinetParser) ParseAndValidate(
       ctx context.Context, r io.Reader,
   ) (*common.CommonDevice, []common.ConversionWarning, error) {
       // Parse + validate
   }
   ```

2. **Register via `init()`**:

   ```go
   func init() {
       parser.Register("fortinet", func(dec parser.XMLDecoder) parser.DeviceParser {
           return &FortinetParser{}
       })
   }
   ```

   The first argument (`"fortinet"`) must match the XML root element name of the config file.

3. **Link via blank import** in your consumer binary:

   ```go
   package main

   import (
       "github.com/EvilBit-Labs/opnDossier/cmd"
       _ "github.com/example/fortinet-parser" // self-registers at init()
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
unsupported device type: root element <fortinet> is not recognized; supported: (none registered -- ensure parser packages are imported)
```

Fix: add `_ "your/parser/package"` to the binary's import list.

**Root element mismatch:** The string passed to `parser.Register()` must exactly match the XML root element name (lowercase). For example, if a Fortinet config uses `<fortinet>` as the root element, register as `"fortinet"`, not `"Fortinet"` or `"FortiNet"` (the registry normalizes to lowercase, but the XML root element detection also lowercases).

**Duplicate registration:** If two packages register the same root element name, the binary will panic at startup. This is intentional -- it surfaces conflicts immediately rather than silently picking one.

### Source Files

- `pkg/parser/registry.go` -- Registry implementation
- `pkg/parser/factory.go` -- Factory with auto-detection and error handling
- `pkg/parser/opnsense/parser.go` -- Built-in OPNsense parser (reference implementation)
- `pkg/parser/pfsense/parser.go` -- Built-in pfSense parser

## Troubleshooting

### Compliance Plugins

- **Plugin not loaded?** Ensure it is built as a Go plugin (`-buildmode=plugin`), exports `var Plugin`, and is in the correct directory. Check `GetLoadResult()` or CLI warnings for load failures.
- **Go version mismatch?** All plugins and the main binary must be built with the exact same Go version and dependencies. This is the most common cause of dynamic plugin load failures.
- **Platform support:** Go plugins are supported on Linux and macOS, not Windows.
- **Plugin appears with zero findings?** The plugin may have panicked during execution. Check the audit logs for panic details. Panicked plugins are retained in results but produce no findings. Review the plugin's error handling and ensure it returns findings properly rather than panicking.
- **Dynamic plugin directory not found?** If you specified `--plugin-dir`, ensure the directory exists. Explicit directories fail fast if missing. Without the flag, no dynamic plugins are loaded.
- **Duplicate plugin name?** If a dynamic plugin has the same name as a static plugin or another dynamic plugin, registration will fail. Check the load failures in `GetLoadResult()` or CLI warning logs.

### Device Parsers

- **Device type not recognized?** Ensure the parser package is imported via blank import (`_ "pkg/path"`) in the binary so `init()` runs. See "Common Pitfalls" above.
- **Panic on startup?** Two packages registered the same root element name. Check for duplicate `parser.Register()` calls.
- **Auto-detection picks wrong parser?** Use `--device-type` to force a specific parser and bypass root element detection.

## Examples

- `internal/plugins/` contains static compliance plugin examples.
- `pkg/parser/opnsense/parser.go` and `pkg/parser/pfsense/parser.go` provide reference device parser implementations.
- The dynamic plugin example above demonstrates external compliance plugins.

## Conclusion

The opnDossier plugin system is flexible: you can extend compliance coverage by adding new compliance plugins, and add new device types by registering device parsers via the `DeviceParserRegistry`. Both systems use self-registration patterns for zero-change extensibility.
