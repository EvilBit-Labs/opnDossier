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
related_issues:
  - '#302'
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

The registry is a flat map of normalized device type names to constructor functions:

```go
// pkg/parser/registry.go

// ConstructorFunc is the factory function signature for creating DeviceParser instances.
type ConstructorFunc = func(XMLDecoder) DeviceParser

type DeviceParserRegistry struct {
    mu      sync.RWMutex
    parsers map[string]ConstructorFunc
}

func NewDeviceParserRegistry() *DeviceParserRegistry {
    return &DeviceParserRegistry{parsers: make(map[string]ConstructorFunc)}
}

func DefaultRegistry() *DeviceParserRegistry {
    defaultRegistryOnce.Do(func() {
        defaultRegistry = NewDeviceParserRegistry()
    })
    return defaultRegistry
}
```

### Registry Methods

**`Register(deviceType string, fn ConstructorFunc)`**

- Registers a parser with case-insensitive device type matching
- Normalizes device type via `strings.ToLower(strings.TrimSpace(deviceType))`
- Panics on nil factory, empty device type, or duplicate registration
- Called during `init()` by parser packages

**`Get(deviceType string) (ConstructorFunc, bool)`**

- Retrieves a registered parser constructor
- Normalizes device type via case-insensitive matching
- Returns `(nil, false)` if device type not found (Go map semantics)

**`List() []string`**

- Returns sorted list of all registered device types
- Used by error messages, CLI completions, and dynamic UI generation
- Returns empty slice if no parsers registered

**`Register(deviceType string, fn ConstructorFunc)` (package-level)**

- Convenience wrapper calling `DefaultRegistry().Register()`
- Follows `database/sql.Register()` pattern for use in `init()` functions

### Self-Registration Pattern

Each parser package registers itself during initialization:

```go
// pkg/parser/opnsense/parser.go

// NewParserFactory returns a new DeviceParser configured for OPNsense devices.
func NewParserFactory(decoder parser.XMLDecoder) parser.DeviceParser {
    return NewParser(decoder)
}

func init() {
    parser.Register("opnsense", NewParserFactory)
}
```

This approach:

- Moves all registration logic into the parser package itself
- Eliminates central factory switch statements
- Allows new parsers to be added without modifying factory.go
- Guarantees registration happens before factory methods are called (init() ordering)
- **Requires blank imports** in any file using `parser.NewFactory()` (see Gotchas below)

### Factory Integration

The Factory consults the registry via `(fn, ok)` lookups:

```go
type Factory struct {
    xmlDecoder XMLDecoder
    registry   *DeviceParserRegistry
}

func NewFactory(decoder XMLDecoder) *Factory {
    return &Factory{xmlDecoder: decoder, registry: DefaultRegistry()}
}

func NewFactoryWithRegistry(decoder XMLDecoder, reg *DeviceParserRegistry) *Factory {
    return &Factory{xmlDecoder: decoder, registry: reg}
}

func (f *Factory) createWithOverride(...) {
    fn, ok := f.registry.Get(override)
    if !ok {
        return nil, nil, fmt.Errorf(
            "unsupported device type override: %s; supported: %s",
            override, strings.Join(f.registry.List(), ", "),
        )
    }
    return parseDevice(ctx, fn(f.xmlDecoder), r, validateMode)
}

func (f *Factory) createWithAutoDetect(...) {
    rootElem, fullReader, err := peekRootElementBounded(ctx, r)
    // ...
    fn, ok := f.registry.Get(rootElem)
    if !ok {
        return nil, nil, fmt.Errorf(
            "unsupported device type: root element <%s> is not recognized; supported: %s",
            rootElem, strings.Join(f.registry.List(), ", "),
        )
    }
    return parseDevice(ctx, fn(f.xmlDecoder), fullReader, validateMode)
}
```

### Thread Safety

All registry operations are protected by `sync.RWMutex`:

- **Read operations** (`Get`, `List`): Use `RLock()`
- **Write operations** (`Register`): Use `Lock()`
- **Concurrent initialization**: Multiple goroutines can safely call registry methods during parallel test execution
- **Singleton access**: `DefaultRegistry()` uses `sync.Once` for atomic initialization

## Gotchas

### Blank Import Requirement

`factory.go` no longer imports `pkg/parser/opnsense` directly. The OPNsense parser only registers when its `init()` runs, which requires a blank import:

```go
_ "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"
```

- **Symptom:** `"unsupported device type: root element <opnsense> is not recognized; supported: "` -- empty supported list
- **Cause:** Missing blank import means `init()` never ran, registry is empty
- **Fix:** Add the blank import to any file using `parser.NewFactory()`
- **Canonical location:** `cmd/root.go` has the production blank import; test files must add their own

## Testing Strategy

Comprehensive test coverage validates:

1. **Singleton Pattern**: Multiple calls to `DefaultRegistry()` return identical instance
2. **Registration**: Successful registration with normalization (case-insensitive, whitespace trimming)
3. **Panic Conditions**:
   - Nil factory registration
   - Empty device type registration
   - Whitespace-only device type registration
   - Duplicate registration (exact and case-insensitive)
4. **Retrieval**: `Get()` with found/not-found, case-insensitive, whitespace-trimmed lookups
5. **Listing**: All registered types returned in sorted order, empty registry returns empty slice
6. **Thread Safety**: Concurrent `Get` and `List` calls from multiple goroutines
7. **Factory Integration**: `NewFactoryWithRegistry()` with isolated registry, override and auto-detect paths
8. **Dynamic Errors**: Error messages include available device types from `registry.List()`
9. **Package-level Register**: `Register()` convenience delegates to `DefaultRegistry()`

Test file: `pkg/parser/registry_test.go` (9 test functions, ~445 lines)

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
       parser.Register("fortios", NewFortIOSParserFactory)
   }
   ```

4. **Add blank import** in `cmd/root.go` (or wherever the binary is built):

   ```go
   _ "github.com/example/fortios-parser"
   ```

5. **No changes to factory.go required** -- registration happens automatically

### Using Registry in Downstream Code

**CLI Completions**:

```go
// cmd/shared_flags.go
func ValidDeviceTypes(...) ([]string, cobra.ShellCompDirective) {
    devices := parser.DefaultRegistry().List()
    // build completion strings from devices...
}
```

**Device Type Validation**:

```go
// cmd/shared_flags.go
func validateDeviceType() error {
    if _, ok := parser.DefaultRegistry().Get(sharedDeviceType); ok {
        return nil
    }
    return fmt.Errorf("unsupported device type: %q; supported: %s",
        sharedDeviceType, strings.Join(parser.DefaultRegistry().List(), ", "))
}
```

## Benefits

1. **Zero-Cost Extensibility**: New parsers require no factory changes
2. **Runtime Discovery**: `Registry.List()` enables dynamic UI/completions
3. **Better Errors**: Error messages automatically include available types
4. **Clean Architecture**: Parser implementations own their registration
5. **Thread-Safe**: Safe for concurrent test execution and goroutines
6. **Fail-Fast**: Duplicate registrations caught immediately at init time
7. **Type-Safe**: `ConstructorFunc` type alias ensures correct signatures
8. **Test Isolation**: `NewFactoryWithRegistry()` + `NewDeviceParserRegistry()` prevent global pollution

## Implementation Status

- **Registry**: `pkg/parser/registry.go` -- `DeviceParserRegistry`, `ConstructorFunc`, `DefaultRegistry()`, `Register()`, `Get()`, `List()` ✓
- **Factory Integration**: `pkg/parser/factory.go` -- `Factory` with `registry` field, `NewFactoryWithRegistry()`, nil guards ✓
- **Tests**: `pkg/parser/registry_test.go` -- 9 test functions covering all acceptance criteria ✓
- **Parser Self-Registration**: `pkg/parser/opnsense/parser.go` -- `NewParserFactory` + `init()` ✓
- **CLI Integration**: `cmd/shared_flags.go` -- `ValidDeviceTypes` + `validateDeviceType` using registry ✓
- **Shell Completions**: Dynamic from registry via `DefaultRegistry().List()` ✓
- **Blank Imports**: `cmd/root.go` + all test files using `parser.NewFactory` ✓

## Related Files

- `pkg/parser/registry.go` -- `DeviceParserRegistry`, `ConstructorFunc`, `DefaultRegistry()`, `Register()`
- `pkg/parser/factory.go` -- `Factory` with registry field, `NewFactoryWithRegistry()`
- `pkg/parser/opnsense/parser.go` -- OPNsense parser self-registration via `init()`
- `pkg/parser/registry_test.go` -- Comprehensive unit tests (9 functions)
- `pkg/parser/factory_test.go` -- Factory tests with blank import
- `cmd/shared_flags.go` -- `ValidDeviceTypes`, `validateDeviceType` using registry
- `cmd/root.go` -- Blank import triggering OPNsense `init()`
- AGENTS.md section 5.25a -- DeviceParser Registry Pattern documentation
- GOTCHAS.md section 7.1 -- Blank import requirement
