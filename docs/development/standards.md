# Development Standards for opnDossier

This document is the authoritative reference for Go development patterns, implementation details, and technical guidelines for the opnDossier CLI tool. It covers coding standards, architecture patterns, data processing, and testing practices.

## Table of Contents

1. [Development Environment Setup](#development-environment-setup)
2. [Code Quality Standards](#code-quality-standards)
3. [Testing Requirements](#testing-requirements)
4. [Development Workflow](#development-workflow)
5. [Architecture Guidelines](#architecture-guidelines)
6. [Go Implementation Patterns](#go-implementation-patterns)
7. [Data Processing Standards](#data-processing-standards)
8. [Security Standards](#security-standards)

## Development Environment Setup

### Prerequisites

- **Go 1.26+**
- **Git** with GPG signing configured
- **[Just](https://just.systems/)** task runner
- **[pre-commit](https://pre-commit.com/)** - Git hook framework
- **[golangci-lint](https://golangci-lint.run/)** - Go linter

### Initial Setup

```bash
# Clone and setup
git clone https://github.com/EvilBit-Labs/opnDossier.git
cd opnDossier

# Install dependencies and tools
just install

# Verify setup
just test
just lint
```

### IDE Configuration

**VS Code Extensions:**

- Go extension (official)
- Pre-commit hooks
- YAML support
- Markdown preview

**GoLand/IntelliJ:**

- Enable `gofmt` on save
- Configure `golangci-lint` integration
- Set up run configurations for `just` commands

### Environment Variables

```bash
# Development environment
export OPNDOSSIER_VERBOSE=true
```

## Code Quality Standards

### Technology Stack

| Component               | Technology                      | Purpose                               |
| ----------------------- | ------------------------------- | ------------------------------------- |
| **CLI Framework**       | `cobra`                         | Command organization and help system  |
| **Configuration**       | `spf13/viper`                   | Configuration management              |
| **CLI Enhancement**     | `charmbracelet/fang`            | Enhanced CLI experience               |
| **Terminal Styling**    | `charmbracelet/lipgloss`        | Colored output and styling            |
| **Markdown Rendering**  | `charmbracelet/glamour`         | Terminal markdown display             |
| **Logging**             | `charmbracelet/log`             | Structured logging                    |
| **Markdown Generation** | `nao1215/markdown`              | Programmatic markdown builder         |
| **Data Processing**     | `encoding/xml`, `encoding/json` | Standard library XML/JSON handling    |
| **Testing**             | Go's built-in `testing` package | Table-driven tests with >80% coverage |

### Code Style and Formatting

**Required Tools:**

- **`gofmt`** - Code formatting (automatic)
- **`gofumpt`** - Enhanced formatting
- **`golangci-lint`** - Comprehensive linting
- **`go vet`** - Static analysis
- **`goimports`** - Import organization
- **`gosec`** - Security scanning (via golangci-lint)

**Conventions:**

- **Formatting:** Use `gofmt` with default settings
- **Line Length:** 80-120 characters (Go conventions)
- **Indentation:** Use tabs (Go standard)
- **Naming:**
  - Packages: lowercase, single word preferred
  - Variables/functions: `camelCase` for private, `PascalCase` for exported
  - Constants: `camelCase` for private, `PascalCase` for exported (avoid `ALL_CAPS`)
  - Types: `PascalCase`
  - Interfaces: `PascalCase`, ending with `-er` when appropriate
  - Receivers: Single-letter names (e.g., `c *Config`)

### Error Handling Patterns

```go
// Always check errors and provide context
func parseXMLConfig(filename string) (*Config, error) {
    data, err := os.ReadFile(filename)
    if err != nil {
        return nil, fmt.Errorf("failed to read config file %s: %w", filename, err)
    }

    var config Config
    if err := xml.Unmarshal(data, &config); err != nil {
        return nil, fmt.Errorf("failed to parse XML config: %w", err)
    }

    return &config, nil
}

// Use charmbracelet/log for structured logging
logger := log.With("input_file", filename)
logger.Info("processing config file")
```

### Commit Message Conventions

All commit messages **MUST** follow the [Conventional Commits](https://www.conventionalcommits.org) specification:

**Format:** `<type>(<scope>): <description>`

**Types:**

- `feat` - New features
- `fix` - Bug fixes
- `docs` - Documentation changes
- `style` - Code style changes (formatting, etc.)
- `refactor` - Code refactoring
- `perf` - Performance improvements
- `test` - Adding or updating tests
- `build` - Build system changes
- `ci` - CI/CD changes
- `chore` - Maintenance tasks

**Scopes:** `(cli)`, `(parser)`, `(converter)`, `(display)`, `(config)`, `(docs)`, etc.

**Examples:**

```text
feat(cli): add support for custom config path
fix(parser): handle malformed XML gracefully
docs: update README with install instructions
perf(converter): optimize markdown generation
test(parser): add integration tests for XML parsing
```

### Linter Guidance

Treat `just lint` as authoritative; IDE diagnostics are suggestions, not the final word. Common patterns and fixes:

| Linter                     | Issue                                  | Fix                                                                                                                                                                                |
| -------------------------- | -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `gocritic emptyStringTest` | `len(s) == 0`                          | Use `s == ""`                                                                                                                                                                      |
| `gosec G115`               | Integer overflow on int→int32          | Add `//nolint:gosec` with bounded value comment                                                                                                                                    |
| `mnd`                      | Magic numbers                          | Create named constants                                                                                                                                                             |
| `minmax`                   | Manual min/max comparisons             | Use `min()`/`max()` builtins                                                                                                                                                       |
| `goconst`                  | Repeated string literals               | Extract to package-level constants                                                                                                                                                 |
| `tparallel`                | Subtests use `t.Parallel()`            | Parent test must also call `t.Parallel()`                                                                                                                                          |
| `tparallel`                | Subtests share mutable state           | Add `//nolint:tparallel` above func when subtests cannot be parallel due to shared mutable state                                                                                   |
| `nonamedreturns`           | Named return values                    | Use a struct return type instead of named returns                                                                                                                                  |
| `funcorder`                | Method placed between constructors     | All constructors (`New*`) must be grouped before any methods on the struct                                                                                                         |
| `copylocks`                | Copying `sync.Once`                    | In tests resetting globals, suppress with `//nolint:govet` and comment explaining intentional reset                                                                                |
| `revive redefines-builtin` | Package name shadows stdlib            | Rename package (e.g., `log` → `logging`)                                                                                                                                           |
| `revive stutters`          | `pkg.PkgThing` repeats name            | Drop prefix: `compliance.Plugin` not `compliance.CompliancePlugin`                                                                                                                 |
| `modernize`                | `omitempty` on struct fields           | Remove `omitempty` from JSON tags on struct-typed fields (no effect in `encoding/json`); YAML `omitempty` is fine                                                                  |
| `staticcheck SA1019`       | Deprecated type alias usage            | Migrate ALL references (including test files) when deprecating a type alias — `Deprecated:` doc comment triggers SA1019 on every reference                                         |
| `modernize`                | Legacy `sort.Strings`/`sort.Slice`     | Use `slices.Sort()` / `slices.SortFunc()` with `strings.Compare`                                                                                                                   |
| `gofumpt` vs `//nolint`    | Directive between doc comment and func | `gofumpt` inserts a blank line that detaches the directive from the func — embed the suppression rationale in the doc comment instead of using `//nolint`                          |
| `dupl`                     | Cross-type validator similarity        | Both sides of the duplicate pair need `//nolint:dupl` — see [GOTCHAS.md](https://github.com/EvilBit-Labs/opnDossier/blob/main/GOTCHAS.md#91-cross-type-validator-duplication) §9.1 |

## Testing Requirements

### Test Standards

**Requirements:**

- **Coverage Target:** >80% test coverage
- **Test Organization:** Table-driven tests with `t.Run()` subtests
- **Performance:** Individual tests \<100ms
- **Integration Tests:** Use build tags (`//go:build integration`)

### Test Structure

```go
func TestParseXMLConfig(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected *Config
        wantErr  bool
    }{
        {
            name:     "valid config",
            input:    `<config><system><hostname>test</hostname></system></config>`,
            expected: &Config{System: System{Hostname: "test"}},
            wantErr:  false,
        },
        {
            name:     "invalid XML",
            input:    `<config><unclosed>`,
            expected: nil,
            wantErr:  true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := parseXMLConfig(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("parseXMLConfig() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if !reflect.DeepEqual(result, tt.expected) {
                t.Errorf("parseXMLConfig() = %v, want %v", result, tt.expected)
            }
        })
    }
}
```

### Testing Commands

```bash
# Run all tests
just test

# Run with coverage
just coverage

# Run benchmarks
just bench

# Run memory benchmarks
just bench-memory

# Run race detection
go test -race ./...
```

### Test Helpers

Use `t.Helper()` in all test helpers and `t.Cleanup()` for teardown. Place shared helpers in `test_helpers.go` (not `_test.go` — `revive` var-naming applies).

### Map Iteration in Tests

Map iteration is non-deterministic — test for presence (`strings.Contains()`) not exact equality. Production code must sort before rendering (see [GOTCHAS.md](https://github.com/EvilBit-Labs/opnDossier/blob/main/GOTCHAS.md#31-map-iteration-order) §3.1).

### Pointer Identity in Tests

Use `assert.Same(t, expected, actual)` (not `assert.Equal`) when verifying that two interface values point to the same object (e.g., alias and canonical registry lookups return the same handler instance).

### Test Assertion Specificity

When testing formatted output (Markdown links, tables), verify the actual format, not just content presence:

```go
// Bad - only verifies content exists
assert.Contains(t, row[2], "wan")

// Good - verifies link format
assert.Contains(t, interfaceCell, "[wan]")
assert.Contains(t, interfaceCell, "#wan-interface")
assert.Contains(t, interfaceCell, ", ") // Multi-value separator
```

### Golden File Testing

Use `sebdah/goldie/v2` for snapshot testing. Key patterns:

- Golden files contain **actual** values (timestamps, versions), not placeholders
- Use a `normalizeGoldenOutput` function to normalize dynamic content before comparison
- Update golden files: `go test ./path -run TestGolden -update`
- Use `time.RFC3339` for timestamps
- Clean trailing whitespace: `sed -i '' 's/[[:space:]]*$//' *.golden.md`
- Ensure golden files end with a trailing newline — goldie uses strict byte comparison
- When making a report section conditional, update tests that assert its presence in ToC

### Testing Global Flag Variables

When testing CLI commands with package-level flag variables (required by Cobra), save originals and use `t.Cleanup()` to restore them. Do NOT use `t.Parallel()` — see [GOTCHAS.md](https://github.com/EvilBit-Labs/opnDossier/blob/main/GOTCHAS.md#11-tparallel-and-global-state) §1.1.

When adding new shared flags (`cmd/shared_flags.go`), update `sharedFlagSnapshot` in `cmd/display_test.go`. When adding audit-specific flags, update `auditFlagSnapshot` in `cmd/audit_test.go`.

### Testing Cobra PreRunE Validators

To unit-test `PreRunE` without requiring a full `CommandContext`, construct a temporary `cobra.Command` with flags bound to the same global variables, set values via `cmd.Flags().Set("name", "value")`, then invoke `auditCmd.PreRunE(tempCmd, args)` directly. See `cmd/audit_test.go` for the canonical pattern and [GOTCHAS.md](https://github.com/EvilBit-Labs/opnDossier/blob/main/GOTCHAS.md#53-prerune-test-commands-must-bind-to-real-globals) §5.3 for the binding pitfall.

## Development Workflow

### Daily Development Tasks

```bash
# Start development session
just dev --help                    # Test CLI functionality
just test                         # Run tests before making changes
just lint                         # Check code quality

# Make changes, then:
just format                       # Format code
just check                        # Run pre-commit checks
just test                         # Verify tests still pass
```

### Adding New Features

1. **Create feature branch:**

   ```bash
   git checkout -b feat/your-feature-name
   ```

2. **Implement feature:**

   - Follow existing patterns in similar code
   - Add tests for new functionality
   - Update documentation if needed

3. **Quality checks:**

   ```bash
   just ci-check                   # Run all checks locally
   ```

4. **Commit changes:**

   ```bash
   git add .
   git commit -m "feat(scope): description"
   ```

### Debugging

**Common debugging scenarios:**

```bash
# Debug CLI commands
just dev --verbose convert testdata/config.xml

# Debug with specific log level
OPNDOSSIER_VERBOSE=true just dev convert testdata/config.xml

# Profile performance
go test -bench=. -cpuprofile=cpu.prof ./internal/cfgparser
go tool pprof cpu.prof

# Memory profiling
go test -bench=. -memprofile=mem.prof ./internal/cfgparser
go tool pprof mem.prof
```

**Debugging tips:**

- Use `log.Debug()` for temporary debugging output
- Check `internal/logging/` for structured logging patterns
- Use `go test -v` for verbose test output
- Use `golangci-lint run --verbose` for detailed linting info

### Performance Optimization

**Benchmarking:**

```bash
# Run benchmarks
just bench

# Save benchmark baseline, then compare after changes
just bench-save
# Make changes
just bench-compare
```

**Profiling:**

```bash
# CPU profiling
go test -cpuprofile=cpu.prof -bench=. ./internal/cfgparser
go tool pprof cpu.prof

# Memory profiling
go test -memprofile=mem.prof -bench=. ./internal/cfgparser
go tool pprof mem.prof
```

## Architecture Guidelines

### Project Structure

```text
opnDossier/
├── main.go                           # Application entry point
├── cmd/                              # CLI commands
│   ├── root.go                       # Root command and CLI setup
│   ├── convert.go                    # Convert command implementation
│   ├── display.go                    # Display command implementation
│   ├── validate.go                   # Validate command implementation
│   └── *_test.go                     # Command tests
├── internal/                         # Private application logic
│   ├── audit/                        # Audit engine and plugin management
│   ├── cfgparser/                    # XML parsing and validation
│   ├── compliance/                   # Plugin interfaces
│   ├── config/                       # Configuration management
│   ├── converter/                    # Data conversion and report generation
│   │   ├── builder/                  # Programmatic markdown builder
│   │   └── formatters/              # Security scoring, transformers
│   ├── display/                      # Terminal display formatting
│   ├── export/                       # File export functionality
│   ├── logging/                      # Structured logging (charmbracelet/log)
│   ├── plugins/                      # Compliance plugins (firewall/SANS/STIG)
│   ├── processor/                    # Data processing and report generation
│   ├── progress/                     # CLI progress indicators
│   ├── validator/                    # Configuration validation
│   └── walker.go                     # XML walker utilities
├── pkg/                              # Public API packages
│   ├── model/                        # Platform-agnostic CommonDevice domain model
│   ├── parser/                       # Factory + DeviceParser interface + shared xmlutil.go
│   │   ├── opnsense/                 # OPNsense parser + schema→CommonDevice converter
│   │   └── pfsense/                  # pfSense parser + schema→CommonDevice converter
│   └── schema/
│       ├── opnsense/                 # Canonical OPNsense XML data model structs
│       └── pfsense/                  # pfSense XML data model (copy-on-write from opnsense)
├── docs/                             # Documentation
├── project_spec/                     # Project requirements
├── testdata/                         # Test data files
└── justfile                          # Task runner
```

### Key Design Principles

1. **Framework-First:** Use established libraries (cobra, viper, charmbracelet)
2. **Operator-Centric:** Build for security operators' workflows
3. **Offline-First:** No external dependencies or telemetry
4. **Structured Data:** Versioned, portable data models

### Configuration Management

```go
// Using spf13/viper for configuration
type Config struct {
    InputFile  string `flag:"input" desc:"Input XML file path"`
    OutputFile string `flag:"output" desc:"Output markdown file path"`
    Verbose    bool   `flag:"verbose" desc:"Enable verbose output"`
}

// Configuration precedence: CLI flags > environment variables > config file > defaults
```

> [!NOTE]
> `viper` manages opnDossier's own configuration such as CLI settings and display preferences. OPNsense `config.xml` parsing is a separate concern handled by `internal/cfgparser/`.

### Error Handling

- Always wrap errors with context using `fmt.Errorf` with `%w`
- Create domain-specific error types for better error handling
- Use `errors.Is()` and `errors.As()` for error type checking
- Provide actionable error messages for users
- Use `errors.New` instead of `fmt.Errorf` for static error strings

### Logging

- Use `charmbracelet/log` for structured logging
- Include context in log messages (filename, operation, duration)
- Use appropriate log levels (debug, info, warn, error)
- Avoid logging sensitive information

### Thread Safety with `sync.RWMutex`

When a struct uses `sync.RWMutex`, all read methods need `RLock()` — not just write paths. Go's `RWMutex` is not reentrant; internal call chains should use lock-free `*Unsafe()` helpers. Getter methods should return value copies, not pointers into protected state. See `internal/processor/report.go` for the canonical pattern.

### XML Handling

`string` fields cannot distinguish between absent elements and self-closing elements like `<any/>`; both decode to `""`. Use `*string` when presence matters, and add helpers like `IsAny()` or `Equal()` instead of comparing raw `*string` fields. See `pkg/schema/opnsense/security.go` for the pattern.

Always use `xml.EscapeText` from the standard library; never hand-roll XML escaping.

### Streaming Interfaces

When adding `io.Writer` support alongside string-returning APIs, split responsibilities. Create dedicated writer-oriented interfaces like `SectionWriter`, expose `Streaming*` wrapper interfaces for streaming consumers, and keep string methods for post-processing flows. `MarkdownBuilder` is not concurrency-safe; create a new instance per goroutine. See `internal/converter/builder/writer.go`.

### FormatRegistry Pattern

`converter.DefaultRegistry` in `internal/converter/registry.go` is the single source of truth for output formats. Register `FormatHandler` in `newDefaultRegistry()` for validation, shell completion, file extensions, and dispatch. Don't reintroduce format constants or switch statements; use `converter.FormatMarkdown`, `converter.FormatJSON`, etc.

### DeviceParser Registry Pattern

Parser registration follows the `database/sql` model: parsers call `parser.Register(name, factory)` from `init()`. **Critical:** any file using `parser.NewFactory()` must blank-import the parser packages (e.g., `_ ".../pkg/parser/opnsense"` and `_ ".../pkg/parser/pfsense"`). Without it, the registry is empty. See **[GOTCHAS.md](https://github.com/EvilBit-Labs/opnDossier/blob/main/GOTCHAS.md#71-blank-import-requirement)** for symptoms and fixes.

Both parsers share XML security hardening via `parser.NewSecureXMLDecoder()` in `pkg/parser/xmlutil.go` (LimitReader, XXE protection, charset handling). The pfSense parser manages its own XML decoding because `XMLDecoder` returns `*schema.OpnSenseDocument`; validation is injected via `pfsense.ValidateFunc` (set in `cmd/root.go`).

### File Write Safety

Always call `file.Sync()` before `Close()` when writing files that matter. Handle close failures in deferred functions with `logger.Warn`; never silently discard them.

### Public Package Purity

Packages under `pkg/` must never import `internal/`. Before committing `pkg/` changes, run `grep -rn 'internal/' --include='*.go' pkg/ | grep -v _test.go`. When `pkg/` needs `internal/` functionality, define an interface in `pkg/` and inject the implementation from `cmd/`.

### XML Schema Evolution

The config.xml data model is enhanced in phases to ensure backward compatibility and thorough testing at each stage.

**Completed Phases:**

| Phase | Scope                        | Fields Added | Key Changes                                                                                                                        |
| ----- | ---------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| 1     | Source/Destination gaps      | 3            | Address, Port (Source), Not — added directly to structs                                                                            |
| 2     | High-priority Rule fields    | 8            | Log, Disabled/Quick→BoolFlag, Floating, Gateway, Direction, Tracker, StateType                                                     |
| 3     | Rate-limiting and advanced   | 14           | max-src-\*, TCP/ICMP flags, state timeout, advanced BoolFlags                                                                      |
| 4     | NAT rule enhancements        | 9            | NATRule: StaticNatPort, NoNat, NatPort, PoolOptsSrcHashKey; InboundRule: NATReflection, AssociatedRuleID, NoRDR, NoSync, LocalPort |
| 5     | Documentation and validation | —            | Research doc updates, field reference, validator enhancements                                                                      |

**BoolFlag vs String Pattern:**

OPNsense and pfSense use two boolean patterns. Choosing the wrong type silently breaks semantics:

- **Presence-based** (`isset()` in PHP): Use `BoolFlag`. Examples: `<disabled/>`, `<log/>`, `<not/>`, `<quick/>`
- **Value-based** (`== "1"` in PHP): Use `string`. Examples: `<enable>1</enable>`, `<blockpriv>1</blockpriv>`

`BoolFlag.UnmarshalXML` treats any present element as true — so `<enabled>0</enabled>` becomes `true`, breaking value-based semantics. See `docs/development/xml-structure-research.md` §1 for the complete field inventory.

**Adding New XML Fields:**

1. Check upstream OPNsense/pfSense source for field semantics (presence-based vs value-based)
2. Add the field to the appropriate struct in `pkg/schema/opnsense/` or `pkg/schema/pfsense/` (copy-on-write: reuse opnsense types where XML is identical, fork locally at divergence)
3. Add XML round-trip tests in the corresponding `*_test.go`
4. Update the validator in `internal/validator/opnsense.go` or `internal/validator/pfsense.go` if the field has constraints
5. Update `docs/development/xml-structure-research.md` with the field details
6. If the field is a credential, add its XML element name to the sanitizer patterns in `internal/sanitizer/rules.go` and `internal/sanitizer/patterns.go`

## Go Implementation Patterns

These patterns document project-specific conventions that go beyond standard Go practices.

### Struct Copy, Comparison, and Slice Patterns

- **Shallow copy with slices:** `normalized := *cfg` copies the struct but slices share backing arrays — deep-copy any slice you intend to mutate with `make` + `copy`
- **Comparison functions:** Handle nil inputs first (both-nil → nil, one-nil → added/removed). Use `slices.Equal()` for slice fields. Map-like `Get()` methods often return `(value, bool)` not `(value, error)`
- **Slice pre-allocation:** Use `make([]T, 0)` without capacity hints for small, variable-length slices. Only add capacity hints when performance-critical
- **String comparisons:** Use `strings.EqualFold(a, b)` for case-insensitive comparison (no `strings.ToLower()` needed). For enum validation, iterate with `EqualFold` directly

### Value-Type Presence Detection

For value-type structs (not pointers), add a `HasData() bool` method on the struct itself to check for meaningful data. `CommonDevice` convenience methods (e.g., `HasNATConfig()`) delegate to the inner struct's `HasData()`. The diff engine calls `HasData()` directly on the value rather than using package-level helpers.

See `NATConfig.HasData()` and `CompareNAT` in `internal/diff/analyzer.go` for the canonical pattern.

### CommandContext Pattern (CLI Dependency Injection)

The `cmd` package uses `CommandContext` (see `cmd/context.go`) to inject dependencies into subcommands:

- `PersistentPreRunE` in `root.go` creates and sets the context after config loading
- Flag variables remain package-level (required by Cobra's binding mechanism)
- Config and logger are unexported (`cfg`, `logger`) — accessed only via `CommandContext`
- Use `GetCommandContext()` for safe access and handle the nil case explicitly

### Context Key Types

Always use typed context keys (`type contextKey string`) to avoid `revive` linter `context-keys-type` warnings. Never use raw strings as context keys.

### Consumer-Local Interface Narrowing

When a struct depends on a broad interface but only calls a subset of its methods, define an unexported consumer-local interface listing only the methods actually called. Do NOT embed a broader sub-interface if it brings unused methods — instead, list the exact method signatures directly. Embedding a sub-interface is acceptable when every method in that sub-interface is called by the consumer.

- Name the interface descriptively (e.g., `reportGenerator`)
- Keep public constructor/setter signatures accepting the broad interface for backward compatibility
- Use a two-value type assertion in getter methods to recover the broad interface when needed
- See `reportGenerator` in `internal/converter/hybrid_generator.go`

### Terminal Output Styling

When using Lipgloss/charmbracelet styling in CLI commands:

- Create a shared `useStylesCheck()` helper that checks `TERM != "dumb"` and `NO_COLOR == ""`
- Define terminal constants (`termEnvVar`, `noColorEnvVar`, `termDumb`) to avoid goconst issues
- Provide plain text fallback functions (e.g., `outputConfigPlain()`) for CI/automation
- **All lists must be sorted for deterministic output** — use `slices.Sort()`, `slices.SortFunc()`, or `slices.Sorted(maps.Keys())` on any slice derived from maps, config iteration, or aggregation before rendering, comparing, or serializing. Non-deterministic order causes flaky tests, unstable golden files, and inconsistent CLI output

### Standalone Tools Pattern

Place standalone development tools in `tools/<name>/main.go` with `//go:build ignore`:

- Tools are independent from main build (won't break if dependencies differ)
- Some code duplication is acceptable for tool independence
- Run via `go run tools/<name>/main.go` or justfile targets
- Example: `tools/docgen/main.go` generates model documentation

### Markdown Generation (`nao1215/markdown`)

Use `nao1215/markdown` for programmatic markdown generation in `internal/converter/builder/`. Always prefer library methods over manual string construction:

- Use fluent builder pattern: chain `.H1().PlainText().Table().Build()`
- Use `BulletList()` with `markdown.Link()` — not manual `"- [text](url)"`
- Use semantic alerts: `Warning()`, `Note()`, `Tip()`, `Caution()`, `Important()` — not manual `> [!WARNING]`
- Chain tables with headers: `md.H4("Title").Table(tableSet)` — not separate calls

### Unused Code Guidance

- **Remove unused code** rather than suppressing with `//nolint:unused` — rely on version control history if needed later
- **Type aliases and re-exported constants**: Before removing, grep the entire codebase for external references (e.g., `grep -r 'pkg.AliasName'`) — `cmd/` frequently references aliases from internal packages

### XML Element Presence Detection

Go's `encoding/xml` produces `""` for both self-closing tags (`<any/>`) and absent elements when using `string` fields. Use `*string` to distinguish presence from absence: self-closing → `*string` pointing to `""` (non-nil); absent → `nil`. See [GOTCHAS.md](https://github.com/EvilBit-Labs/opnDossier/blob/main/GOTCHAS.md#32-xml-presence-vs-absence) §3.2 for the pitfall.

**Creating `*string` values:** Use `new(expr)` (Go 1.26+), e.g., `Source{Any: new(""), Network: new("lan")}`.

Add `IsAny()` / `Equal()` methods rather than comparing `*string` fields directly. See `pkg/schema/opnsense/security.go` for the canonical pattern.

**Address resolution:** `Source.EffectiveAddress()` / `Destination.EffectiveAddress()` resolves with priority: `Network` > `Address` > `Any` > `""`. Use this instead of manual `IsAny() || Network == NetworkAny` checks.

**Type selection for boolean-like XML elements:**

- **Presence-based** (`isset()` in PHP): `<disabled/>`, `<log/>`, `<not/>` → use `BoolFlag`
- **Value-based** (`== "1"` in PHP): `<enable>1</enable>`, `<blockpriv>1</blockpriv>` → use `string`
- **Presence with value access needed**: `<any/>` in Source/Destination → use `*string`

See `docs/development/xml-structure-research.md` for the complete field inventory with upstream source citations.

**BoolFlag in forked structs:** When a copy-on-write struct changes a field from `string` to `BoolFlag`, add a private type alias and a pointer-receiver `MarshalXML` that delegates via `e.EncodeElement((*alias)(ptr), start)`. See `pkg/schema/pfsense/interfaces.go` and [GOTCHAS.md](https://github.com/EvilBit-Labs/opnDossier/blob/main/GOTCHAS.md#151-pointer-receiver-marshalxml-and-value-marshaling) §15.1.

**Repeated XML elements:** Use `[]string` for elements that can appear multiple times — see [GOTCHAS.md](https://github.com/EvilBit-Labs/opnDossier/blob/main/GOTCHAS.md#33-repeated-xml-elements-and-string-fields) §3.3 for the silent data loss pitfall.

### Context-Aware Semaphore

When acquiring semaphores in goroutines, use `select` with `ctx.Done()` to respect cancellation (don't block unconditionally on `sem <- struct{}{}`).

### Goroutine Stop/Write Safety

When a goroutine writes to an `io.Writer` and a stop method also writes after signaling shutdown, the goroutine must fully exit before the caller writes. Use a `stopped` channel: goroutine defers `close(stopped)`, stop method does `close(done)` then `<-stopped`.

### Dual Validator Synchronization

`internal/processor/validate.go` maintains lightweight validation whitelists (powerd modes, optimization values, etc.) that must stay in sync with the authoritative `internal/validator/opnsense.go`. When updating allowed values in either package, grep for the same whitelist in the other and update both.

### Duplicate Code Detection in Tests

The `dupl` linter flags structurally similar test files (e.g., `json_test.go` and `yaml_test.go`). When JSON and YAML tests share device construction and assertions, extract shared logic into `test_helpers.go` (e.g., `newFieldsTestDevice()`, `assertNewFieldsPresent()`) and use a single `Test*` function with subtests for each format. If the files remain structurally similar despite extraction, add `//nolint:dupl` on the package line.

### Statistics Struct Synchronization

When adding fields to `common.Statistics`, update two places:

1. The struct definition in `pkg/model/enrichment.go`
2. Population logic in `ComputeStatistics()` in `internal/analysis/statistics.go`

The processor's `translateCommonStats()` in `internal/processor/report_statistics.go` must also be updated if new fields are added to `processor.Statistics`.

When changing a `Statistics` field from `string` to a typed enum (e.g., `NATMode string` → `NATMode NATOutboundMode`), add a `string()` cast in `translateCommonStats()` and update test struct field types. Separate check logic from stats updates — never increment stats inside a function that may be called multiple times for fallback logic.

### Public Package Import Aliases

`pkg/schema/opnsense/` (package `opnsense`) and `pkg/model/` (package `model`) are public API packages. Consumer files use import aliases to preserve historical qualifiers:

```go
schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"  // use schema.OpnSenseDocument
common "github.com/EvilBit-Labs/opnDossier/pkg/model"             // use common.CommonDevice
```

Files in `pkg/parser/opnsense/` (package `opnsense`) **must** alias the schema import as `schema` to avoid collision. `cmd/` files that use the parser factory import `"github.com/EvilBit-Labs/opnDossier/pkg/parser"` (no alias needed).

`parser.NewFactory(decoder)` requires an `XMLDecoder` argument — wire with `parser.NewFactory(cfgparser.NewXMLParser())` at the call site. The `XMLDecoder` interface is defined in `pkg/parser/factory.go`.

**pfSense parser independence:** The pfSense parser in `pkg/parser/pfsense/` manages its own XML decoding because `XMLDecoder.Parse()` returns `*schema.OpnSenseDocument`, which is incompatible with `pfsense.Document`. Security hardening is shared via `parser.NewSecureXMLDecoder()` in `pkg/parser/xmlutil.go`.

### Report Serialization Redaction

`Report.ToJSON()` and `Report.ToYAML()` serialize a redacted copy via `redactedCopyUnsafe()` to prevent sensitive fields from leaking. Currently redacted: `SNMP.ROCommunity`, `Certificate.PrivateKey`, and `CertificateAuthority.PrivateKey`. When adding new sensitive fields to `CommonDevice`, extend `redactedCopyUnsafe()` in `internal/processor/report.go`. Certificate/CA slices are deep-copied via `make` + `copy` before mutation. Only entries with non-empty sensitive values are redacted. The copy is constructed field-by-field (not `cp := *r`) to avoid `copylocks` on `sync.RWMutex`.

### Sanitizer Field Pattern Maintenance

The `sanitize` command operates on raw XML element names via pattern matching in `internal/sanitizer/rules.go` (`FieldPatterns`) and `internal/sanitizer/patterns.go` (`passwordKeywords`). When adding a new device type, audit its XML element names for credential fields that differ from OPNsense and add them to both files.

**Verification:** `opndossier sanitize <config.xml> | grep -i 'hash\|secret\|key\|pass\|community'` — check for unredacted sensitive values.

### Schema-Level Secret Exclusion

Secret fields in `pkg/schema/` structs must carry `json:"-" yaml:"-"` tags to prevent accidental serialization. This is defense-in-depth alongside `redactedCopyUnsafe()`. Do NOT map these fields to the common model — the sanitizer handles them at the XML level.

### File-Split Refactoring Pattern

When splitting a large file into domain-specific files within the same package:

- All functions remain in the same package — tests find them regardless of file
- Pre-commit hooks may rearrange where helpers land — re-verify file contents after hooks run
- Changing an unexported function's signature breaks same-package test files — grep for all call sites in `*_test.go` before changing signatures
- Shared helpers used across domain files stay in the orchestrator file; domain-specific helpers move with their domain
- Naming convention: `<base>_<domain>.go` (e.g., `validate_system.go`, `report_statistics.go`)

---

## Data Processing Standards

### Data Models

- **OpnSenseDocument**: Core data model representing entire OPNsense configuration
- **XML Tags**: Must strictly follow OPNsense configuration file structure
- **JSON/YAML Tags**: Follow recommended best practices for each format
- **Audit Models**: Create separate structs (`Finding`, `Target`, `Exposure`) for audit concepts

**Architecture notes:**

- `pkg/schema/opnsense/` is the canonical OPNsense XML data model
- `RuleLocation` in `common.go` has complete source/destination fields but is NOT used by `Source`/`Destination` in `security.go` — tracked in issue #255
- Known schema gaps: ~40+ type mismatches and missing fields — see `docs/development/xml-structure-research.md` §4-5
- **Schema reuse (copy-on-write):** Reuse struct definitions from another schema when truly identical. Treat reused structs as copy-on-write: do not alter the original in place. Fork locally at first divergence

**pfSense type divergences from OPNsense:**

- `pfsense.Group` has `Priv []string` (not `string`) — converter uses `strings.Join(g.Priv, ", ")`
- `pfsense.System.DNSServers` is `[]string` (not space-separated `string`) — no `strings.Fields()` needed
- `pfsense.InboundRule` has `Target` field — converter uses `Target` with fallback to `InternalIP`
- pfSense and OPNsense value-based booleans use "1", "on", "yes", "true", "enable", or "enabled" (case-insensitive) — use `shared.IsValueTrue()` from `pkg/schema/shared`, or type the field as `FlexBool` when the element is always emitted, rather than `== "1"`. Use `BoolFlag` **only** for presence-based toggles where element absence means false (e.g., `<enable/>`); using it for value-based booleans can drop explicit false values on marshal since `BoolFlag` marshals false as an absent element
- `pfsense.Interface` has `Enable opnsense.BoolFlag` (not `string`) — use `iface.Enable.Bool()`
- `pfsense.Group.Member` is `[]string` (listtag) — converter uses `strings.Join(g.Member, ", ")`

See [`pkg/schema/pfsense/README.md`](https://github.com/EvilBit-Labs/opnDossier/blob/main/pkg/schema/pfsense/README.md) for the complete pfSense structural reference.

**Platform-agnostic model layer:**

- `pkg/model/` contains device-agnostic types. `revive` var-naming exclusion configured in `.golangci.yml`
- `docs/data-model/` documents the **CommonDevice** export model, NOT the XML schema — paths, types, and nesting differ significantly
- JSON struct tags on nested struct fields must NOT use `omitempty` (Go 1.26+ modernize check)

**Converter enrichment pipeline:**

- `prepareForExport()` in `internal/converter/enrichment.go` is the single gate for all JSON/YAML exports
- It populates `Statistics`, `Analysis`, `SecurityAssessment`, and `PerformanceMetrics` on a shallow copy
- Delegates to `internal/analysis/` for `ComputeStatistics` and `ComputeAnalysis` (shared, not mirrored)
- New `CommonDevice` enrichment fields must be wired here to appear in JSON/YAML output
- `computeStatistics` receives *unredacted* data; sensitive values in `ServiceDetails` must be post-processed by `redactStatisticsServiceDetails()` when `redact=true`

**Compliance results model:**

- `CommonDevice.ComplianceChecks` uses `*ComplianceResults`. Types mirror `audit`/`analysis`/`compliance` shapes but live in `common` to avoid circular deps
- Populated by `mapAuditReportToComplianceResults()` in `cmd/audit_handler.go`, not by `prepareForExport()` (pass-through only)

**Audit report rendering:**

- `handleAuditMode()` in `cmd/audit_handler.go` maps `audit.Report` → `device.ComplianceChecks`, creates a shallow copy (immutability), then delegates to `generateWithProgrammaticGenerator()`
- `ComplianceResultSummary` int fields use `json:"field"` (no `omitempty`) — zero values must serialize
- Plugin names and metadata keys iterated in sorted order (`slices.Sorted(maps.Keys(...))`)

**Port field disambiguation:**

- `Source.Port` → `<source><port>...</port></source>` (nested, preferred)
- `Rule.SourcePort` → `<sourceport>...</sourceport>` (top-level, legacy)
- Prefer `Source.Port` with fallback to `Rule.SourcePort` for backward compatibility

**Conversion warnings:**

- `common.ConversionWarning` in `pkg/model/warning.go` — platform-agnostic
- `ToCommonDevice` returns `(*CommonDevice, []ConversionWarning, error)` — propagated through all CLI commands
- Warning `Field` uses dot-path with array indices: `"FirewallRules[0].Type"`
- Warning `Severity` uses `pkg/model.Severity` (not `internal/analysis.Severity`) — public API boundary

**`DeviceType` serialization:**

- `CommonDevice.DeviceType` uses `json:"device_type"` (no `omitempty`) — always serializes
- `DeviceType.DisplayName()` returns properly-cased names (`"OPNsense"`, `"pfSense"`, `"Device"` for unknown). All report titles use this method — never hardcode platform names in rendered output

### Multi-Format Export

```bash
opndossier convert config.xml --format [markdown|json|yaml|text|html]
opndossier convert config.xml --format json -o output.json
opndossier convert config.xml --format yaml --force
```

- Exported files must be valid and parseable by standard tools
- Smart file naming with overwrite protection (`-f` to force)

### Report Generation Modes

| Mode            | Audience  | Focus                                 |
| --------------- | --------- | ------------------------------------- |
| Blue (defense)  | Blue Team | Clarity, grouping, actionability      |
| Red (adversary) | Red Team  | Target prioritization, pivot surfaces |

All report generation uses programmatic Go code via `builder.MarkdownBuilder` (no template system).

### cfgparser/Schema Synchronization

`internal/cfgparser/xml.go` switch cases reference `OpnSenseDocument` fields by name. When renaming fields or changing types (e.g., singular → slice), update the cfgparser cases too. For slice fields, `decodeSection` can't decode a single XML element into a slice — decode into a temp variable and `append` to the slice field.

---

## Security Standards

### General Security Principles

1. **No Secrets in Code:** Never hardcode API keys, passwords, or sensitive data
2. **Environment Variables:** Use environment variables with `OPNDOSSIER_` prefix for configuration
3. **Input Validation:** Always validate and sanitize XML input files
4. **Secure Defaults:** Default to secure configurations
5. **Error Messages:** Avoid exposing sensitive information in error messages

### Go-Specific Security

**Input Validation:**

```go
// Validate XML input before processing
func validateXMLInput(data []byte) error {
    if len(data) == 0 {
        return errors.New("empty XML input")
    }

    // Check for basic XML structure
    if !bytes.Contains(data, []byte("<?xml")) && !bytes.Contains(data, []byte("<opnsense")) {
        return errors.New("invalid XML format: missing XML declaration or opnsense root")
    }

    return nil
}
```

**Error Handling:**

```go
// Safe error messages without sensitive information
func processConfig(filename string) error {
    data, err := os.ReadFile(filename)
    if err != nil {
        // Don't expose full file paths in error messages
        return fmt.Errorf("failed to read configuration file: %w", err)
    }

    // Process data...
    return nil
}
```

### Operational Security

- **Airgap Compatibility:** Full functionality in isolated environments
- **No Telemetry:** No external data transmission
- **Portable Data Exchange:** Secure data bundle import/export
- **Error Message Safety:** No sensitive information exposure
- **File Permissions:** Write sensitive files with `0600` permissions
- **Input Validation:** Validate all inputs at system boundaries (CLI args, config files, XML)
- **Secret Management:** Never commit secrets; use environment variables or secure secret storage

For detailed secure coding principles, vulnerability reporting, and threat model, see **[CONTRIBUTING.md](https://github.com/EvilBit-Labs/opnDossier/blob/main/CONTRIBUTING.md)** and `SECURITY.md`.

### Dependency Security

- **Minimal Dependencies:** Reduced attack surface, except for cryptography dependencies - never write your own crypto code
- **Dependency Scanning:** Automated vulnerability detection via `gosec`
- **Supply Chain Security:** Go module checksums and verification
- **SBOM Generation:** Dependency transparency for security compliance

---

This document serves as the development standards guide for the opnDossier CLI tool. All contributors should follow these standards to ensure code quality, maintainability, and security.
