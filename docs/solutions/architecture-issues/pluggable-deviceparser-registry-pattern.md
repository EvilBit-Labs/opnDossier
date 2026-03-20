---
title: Pluggable DeviceParser Registry Pattern
module: parser
problem_type: best_practice
component: parser, factory
symptoms:
  - Hardcoded device type switches in Factory methods
  - Difficulty adding new device parser implementations
  - No central registry of available parsers
  - Error messages listing available types require code changes
root_cause: Monolithic factory implementation with switch statements instead of registry pattern
tags:
  - registry
  - plugin
  - factory
  - extensibility
  - thread-safety
severity: medium
---

## Problem

The original Factory implementation used hardcoded `switch` statements to create device parsers based on device type. This approach:

- Requires modifying `pkg/parser/factory.go` when adding new device parser implementations
- Provides no runtime discovery of available parsers
- Makes it difficult for downstream code (CLI completions, error messages) to dynamically list supported device types
- Couples the factory directly to specific parser implementations
- Limits extensibility without modifying core factory code

## Solution: Registry Pattern with Self-Registration

Implement a thread-safe `DeviceParserRegistry` singleton that uses **self-registration** via `init()` functions in parser packages. This enables:

- **Decoupled registration**: Each parser package registers itself independently
- **Dynamic discovery**: Parsers are enumerable at runtime via `registry.List()`
- **Extensibility without core changes**: New parsers register via `init()` with zero changes to factory code
- **Thread-safe concurrent access**: All registry operations protected by `sync.RWMutex`
- **Fail-fast semantics**: Duplicate registrations and invalid inputs panic immediately during initialization

## Implementation Details

### Registry Structure

The registry is a thread-safe map of normalized device type names to parser factories:

```go
// pkg/parser/registry.go

type parserEntry struct {
    factory     DeviceParserFactory
    displayName string
}

type DeviceParserRegistry struct {
    mu      sync.RWMutex
    parsers map[string]*parserEntry
}

var globalRegistry *DeviceParserRegistry

// GetGlobalRegistry returns the singleton registry instance.
// Lazy-initialized with sync.OnceFunc for thread-safe access.
func GetGlobalRegistry() *DeviceParserRegistry {
    return globalRegistry
}
```

### Registry Methods

**`Register(deviceType string, factory DeviceParserFactory, displayName string) error`**

- Registers a parser with case-insensitive device type matching
- Normalizes device type via `strings.ToLower(strings.TrimSpace(deviceType))`
- Returns error on nil factory or empty device type
- Panics on duplicate registration (including case-insensitive duplicates)
- Called during init() by parser packages

**`Get(deviceType string) (DeviceParserFactory, error)`**

- Retrieves a registered parser factory
- Normalizes device type via case-insensitive matching
- Returns error if device type not found; error includes available types

**`GetFactory(deviceType string) DeviceParserFactory`**

- Returns factory or nil if not found (no error return)
- Used by createWithAutoDetect() for XML root element detection

**`List() []string`**

- Returns sorted list of all registered device types
- Used by error messages, CLI completions, and dynamic UI generation
- Returns empty slice if no parsers registered

**`RegisterGlobalDeviceParser(deviceType string, factory DeviceParserFactory, displayName string)`**

- Convenience wrapper calling GetGlobalRegistry().Register()
- Used by parser packages in init() functions

### Self-Registration Pattern

Each parser package registers itself during initialization:

```go
// pkg/parser/opnsense/init.go (example)

func init() {
    parser.RegisterGlobalDeviceParser(
        "opnsense",
        NewOpnSenseParserFactory,
        "OPNsense Firewall",
    )
}

// NewOpnSenseParserFactory is the factory function
func NewOpnSenseParserFactory(decoder parser.XMLDecoder) parser.DeviceParser {
    return &OpnSenseParser{decoder: decoder}
}
```

This approach:

- Moves all registration logic into the parser package itself
- Eliminates central factory switch statements
- Allows new parsers to be added without modifying factory.go
- Guarantees registration happens before factory methods are called (init() ordering)

### Factory Integration

The Factory uses dynamic registry lookups instead of hardcoded switches:

**`createWithOverride(deviceType string) (*CommonDevice, []ConversionWarning, error)`**

```go
factory, err := registry.Get(deviceType)
if err != nil {
    return nil, nil, fmt.Errorf("create with override: %w", err)
}
return factory(f.decoder).ToCommonDevice(f.doc)
```

**`createWithAutoDetect() (*CommonDevice, []ConversionWarning, error)`**

```go
rootElem := strings.ToLower(f.doc.XMLName.Local)
if factory := registry.GetFactory(rootElem); factory != nil {
    return factory(f.decoder).ToCommonDevice(f.doc)
}

// Dynamic error message using registry.List()
available := strings.Join(registry.List(), ", ")
return nil, nil, fmt.Errorf(
    "unsupported device type: root element <%s> is not recognized; supported: %s",
    rootElem, available,
)
```

### Thread Safety

All registry operations are protected by `sync.RWMutex`:

- **Read operations** (`Get`, `GetFactory`, `List`): Use `RLock()`
- **Write operations** (`Register`): Use `Lock()`
- **Concurrent initialization**: Multiple goroutines can safely call registry methods during parallel test execution
- **Singleton access**: `GetGlobalRegistry()` uses `sync.OnceFunc` for atomic initialization

## Testing Strategy

Comprehensive test coverage validates:

1. **Singleton Pattern**: Multiple calls to GetGlobalRegistry return identical instance
2. **Registration**: Successful registration with normalization (case-insensitive, whitespace trimming)
3. **Panic Conditions**:
   - Nil factory registration
   - Empty device type registration
   - Duplicate registration (case-sensitive and case-insensitive)
4. **Retrieval**: Get/GetFactory with various device types and error cases
5. **Listing**: All registered types returned in sorted order
6. **Thread Safety**: Concurrent registration and retrieval from multiple goroutines
7. **Factory Integration**: Registry lookups work correctly with Factory.CreateDevice()
8. **Dynamic Errors**: Error messages include available device types from registry.List()

Test file: `pkg/parser/registry_test.go` (380 lines)

## Code Examples

### Adding a New Device Parser

To add support for a new device type (e.g., "fortios"):

1. **Create parser package** with DeviceParser implementation

2. **Export factory function**:

   ```go
   func NewFortIOSParserFactory(decoder parser.XMLDecoder) parser.DeviceParser {
       return &FortIOSParser{decoder: decoder}
   }
   ```

3. **Register in init()**:

   ```go
   func init() {
       parser.RegisterGlobalDeviceParser(
           "fortios",
           NewFortIOSParserFactory,
           "Fortinet FortiOS",
       )
   }
   ```

4. **No changes to factory.go required** — registration happens automatically

### Using Registry in Downstream Code

**CLI Completions**:

```go
// cmd/convert.go
func validDeviceTypes() []string {
    return parser.GetGlobalRegistry().List()
}
```

**Error Messages**:

```go
// Factory dynamic error
available := strings.Join(registry.List(), ", ")
return fmt.Errorf("unsupported device type: %s; supported: %s", dt, available)
```

**Device Type Validation**:

```go
// Validate --device-type flag
if _, err := parser.GetGlobalRegistry().Get(deviceType); err != nil {
    return fmt.Errorf("invalid device type: %w", err)
}
```

## Benefits

1. **Zero-Cost Extensibility**: New parsers require no factory changes
2. **Runtime Discovery**: Registry.List() enables dynamic UI/completions
3. **Better Errors**: Error messages automatically include available types
4. **Clean Architecture**: Parser implementations own their registration
5. **Thread-Safe**: Safe for concurrent test execution and goroutines
6. **Fail-Fast**: Duplicate registrations caught immediately at init time
7. **Type-Safe**: DeviceParserFactory interface ensures correct signatures

## Implementation Status

- **Registry**: `pkg/parser/registry.go` ✓
- **Factory Integration**: `pkg/parser/factory.go` refactored ✓
- **Tests**: `pkg/parser/registry_test.go` ✓
- **Parser Self-Registration**: `pkg/parser/opnsense/parser.go` init() ✓
- **CLI Integration**: `cmd/shared_flags.go` ValidDeviceTypes + validateDeviceType ✓
- **Shell Completions**: Dynamic from registry via DefaultRegistry().List() ✓
- **Blank Imports**: `cmd/root.go` + all test files using parser.NewFactory ✓

## Related Files

- `pkg/parser/registry.go` — DeviceParserRegistry, ConstructorFunc, DefaultRegistry(), Register()
- `pkg/parser/factory.go` — Factory with registry field, NewFactoryWithRegistry()
- `pkg/parser/opnsense/parser.go` — OPNsense parser self-registration via init()
- `pkg/parser/registry_test.go` — Comprehensive unit tests
- `cmd/shared_flags.go` — ValidDeviceTypes, validateDeviceType using registry
- `cmd/root.go` — Blank import triggering OPNsense init()
- AGENTS.md §8 — Plugin Architecture documentation
