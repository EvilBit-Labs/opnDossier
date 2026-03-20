# AI Agent Coding Standards and Project Structure

This document consolidates all development standards, architectural principles, and workflows for the opnDossier project.

@GOTCHAS.md

## Related Documentation

- **[Requirements](project_spec/requirements.md)** - Complete project requirements and specifications (WHAT)
- **[Architecture](docs/development/architecture.md)** - System design, component interactions, and deployment patterns
- **[Development Standards](docs/development/standards.md)** - Go-specific coding standards and project structure
- **[Gotchas](GOTCHAS.md)** - Common pitfalls and non-obvious behaviors
- **[Tasks](project_spec/tasks.md)** - Implementation tasks (HOW)
- **[User Stories](project_spec/user_stories.md)** - User stories (WHY)
- **[Solutions](docs/solutions/)** - Documented problem solutions for searchable future reference

---

## Code Quality Policy

- **Zero tolerance for tech debt.** Never dismiss warnings, lint failures, or CI errors as "pre-existing" or "not from our changes." If CI fails, investigate and fix it — regardless of when the issue was introduced. Every session should leave the codebase better than it found it.

---

## 1. Rule Precedence

**CRITICAL - Rules are applied in the following order:**

1. **Project-specific rules** (this document, .cursor/rules/)
2. **General development standards** (docs/development/standards.md)
3. **Language-specific style guides** (Go conventions)

When rules conflict, follow the higher precedence rule.

---

## 2. Core Philosophy

| Principle               | Description                                                                         |
| ----------------------- | ----------------------------------------------------------------------------------- |
| **Operator-Focused**    | Build tools for operators, by operators. Full control, no black boxes               |
| **Offline-First**       | Operate in fully offline/airgapped environments. No external dependencies           |
| **Structured Data**     | Data should be structured, versioned, and portable for auditable systems            |
| **Framework-First**     | Leverage established frameworks. Avoid custom solutions when established ones exist |
| **Polish Over Scale**   | Quality over feature-bloat. Sane defaults, CLI help that's actually helpful         |
| **Ethical Constraints** | No dark patterns, spyware, telemetry, or emojis in code/output/docs                 |

**Repository Roles:** Maintainer: `unclesp1d3r` (sole maintainer, enqueues PRs via Mergify `/queue`). Trusted bots: `dependabot[bot]`, `dosubot[bot]` (auto-approved by Mergify).

---

## 3. Technology Stack

| Layer               | Technology                                             |
| ------------------- | ------------------------------------------------------ |
| CLI Framework       | `cobra` v1.8.0                                         |
| CLI Enhancement     | `charmbracelet/fang` for styled help, errors, features |
| Configuration       | `spf13/viper` for config parsing                       |
| Terminal Styling    | `charmbracelet/lipgloss`                               |
| Markdown Rendering  | `charmbracelet/glamour`                                |
| Markdown Generation | `nao1215/markdown` for programmatic report building    |
| Logging             | `charmbracelet/log`                                    |
| Data Formats        | `encoding/xml`, `encoding/json`, `gopkg.in/yaml.v3`    |
| Testing             | Go's built-in `testing` package                        |

**Go Version:** 1.26+

> [!NOTE]
> `viper` manages opnDossier's own configuration (CLI settings, display preferences), not OPNsense config.xml parsing. XML parsing is handled by `internal/cfgparser/`.

---

## 4. Project Structure

```text
opndossier/
├── cmd/                    # CLI command entry points (root, audit, convert, diff, display, etc.)
├── internal/               # Private application logic
│   ├── analysis/           # Canonical Finding and Severity types (shared across audit, compliance, processor)
│   ├── audit/              # Audit engine, plugin registry, plugin manager
│   ├── cfgparser/          # XML parsing and validation
│   ├── compliance/         # Plugin interfaces (Plugin, Control, Finding)
│   ├── config/             # Configuration management
│   ├── constants/          # Shared constants (validation whitelists, etc.)
│   ├── converter/          # Data conversion, enrichment, markdown builder
│   ├── diff/               # Configuration diff engine
│   ├── display/            # Terminal display formatting
│   ├── export/             # File export functionality
│   ├── logging/            # Logging utilities
│   ├── markdown/           # Markdown generation and validation
│   ├── plugins/            # Compliance plugins (firewall/, sans/, stig/)
│   ├── pool/               # Worker pool for concurrent processing
│   ├── processor/          # Data processing and report generation
│   ├── progress/           # CLI progress indicators (spinner, bar)
│   ├── sanitizer/          # Data sanitization utilities
│   ├── testing/            # Shared test helpers
│   └── validator/          # Data validation
├── pkg/                    # Public API packages (importable by external consumers)
│   ├── model/              # Platform-agnostic CommonDevice domain model
│   ├── parser/             # Factory + DeviceParser interface
│   │   └── opnsense/       # OPNsense parser + schema→CommonDevice converter
│   └── schema/
│       └── opnsense/       # Canonical OPNsense data model — XML structs
├── tools/docgen/           # Standalone model documentation generator (//go:build ignore)
├── testdata/               # Test data and fixtures
├── docs/                   # Documentation
├── project_spec/           # Requirements, tasks, user stories
├── go.mod / go.sum         # Go modules
├── justfile                # Task runner
└── main.go                 # Entry point
```

---

## 5. Go Development Standards

### 5.1 Naming Conventions

| Element             | Convention                                 | Example                     |
| ------------------- | ------------------------------------------ | --------------------------- |
| Packages            | lowercase, single word                     | `parser`, `config`          |
| Variables/functions | camelCase (private), PascalCase (exported) | `configFile`, `ParseConfig` |
| Types               | PascalCase                                 | `ConfigParser`              |
| Constants           | PascalCase (avoid ALL_CAPS)                | `DefaultTimeout`            |
| Receivers           | single letter                              | `func (c *Config)`          |
| Interfaces          | PascalCase, `-er` suffix when appropriate  | `ConfigReader`              |

### 5.2 Error Handling

- Always wrap errors with context using `fmt.Errorf("...: %w", err)`
- Use `errors.Is()` and `errors.As()` for checking (not type assertions)
- Create domain-specific error types for structured error handling

### 5.3 Logging

Use `charmbracelet/log` with structured key-value pairs: `logger.Info("msg", "key", val)`. Log levels: `debug` (troubleshooting), `info` (operations), `warn` (issues), `error` (failures).

**Context-aware logging:** When a method receives `context.Context`, use `pm.logger.WithContext(ctx)` to create a scoped logger — never drop `ctx` from logging calls.

### 5.4 Documentation

- Start comments with the name of the thing being described
- Use complete sentences
- Include examples for complex functionality

### 5.5 Import Organization

Group imports: standard library → third-party → internal, separated by blank lines.

### 5.6 Thread Safety

When using `sync.RWMutex` to protect struct fields:

- ALL read methods need `RLock()`, not just write methods
- Go's `sync.RWMutex` is NOT reentrant — create internal `*Unsafe()` helpers for lock-free internal calls
- Getter methods should return value copies, not pointers to internal state
- See `internal/processor/report.go` for the canonical pattern

### 5.6a Struct Copy, Comparison, and Slice Patterns

- **Shallow copy with slices:** `normalized := *cfg` copies the struct but slices share backing arrays — deep-copy any slice you intend to mutate with `make` + `copy`
- **Comparison functions:** Handle nil inputs first (both-nil → nil, one-nil → added/removed). Use `slices.Equal()` for slice fields. Map-like `Get()` methods often return `(value, bool)` not `(value, error)`
- **Slice pre-allocation:** Use `make([]T, 0)` without capacity hints for small, variable-length slices. Only add capacity hints when performance-critical
- **String comparisons:** Use `strings.EqualFold(a, b)` for case-insensitive comparison (no `strings.ToLower()` needed). For enum validation, iterate with `EqualFold` directly

### 5.6b Value-Type Presence Detection

For value-type structs (not pointers), add a `HasData() bool` method on the struct itself to check for meaningful data. `CommonDevice` convenience methods (e.g., `HasNATConfig()`) delegate to the inner struct's `HasData()`. The diff engine calls `HasData()` directly on the value rather than using package-level helpers.

See `NATConfig.HasData()` and `CompareNAT` in `internal/diff/analyzer.go` for the canonical pattern.

### 5.7 CommandContext Pattern (CLI Dependency Injection)

The `cmd` package uses `CommandContext` (see `cmd/context.go`) to inject dependencies into subcommands:

- `PersistentPreRunE` in `root.go` creates and sets the context after config loading
- Flag variables remain package-level (required by Cobra's binding mechanism)
- Config and logger are unexported (`cfg`, `logger`) — accessed only via `CommandContext`
- Use `GetCommandContext()` for safe access and handle the nil case explicitly

### 5.8 Context Key Types

Always use typed context keys (`type contextKey string`) to avoid `revive` linter `context-keys-type` warnings. Never use raw strings as context keys.

### 5.9 Streaming Interface Pattern

When adding `io.Writer` support alongside string-based APIs:

- Create a separate interface (e.g., `SectionWriter`) that the builder implements
- Add a `Streaming*` interface that embeds the base interface (e.g., `StreamingGenerator` embeds `Generator`)
- Keep string-based methods for cases needing further processing (HTML conversion)
- See `internal/converter/builder/writer.go` and `internal/converter/hybrid_generator.go`

> **Thread safety:** `MarkdownBuilder` is not safe for concurrent use. Create a new instance per goroutine. `SetIncludeTunables` and similar setters mutate builder state and must be called in the same synchronous call chain as `Build*Report`.

### 5.9a Consumer-Local Interface Narrowing

When a struct depends on a broad interface but only calls a subset of its methods, define an unexported consumer-local interface listing only the methods actually called. Do NOT embed a broader sub-interface if it brings unused methods — instead, list the exact method signatures directly. Embedding a sub-interface is acceptable when every method in that sub-interface is called by the consumer.

- Name the interface descriptively (e.g., `reportGenerator`)
- Keep public constructor/setter signatures accepting the broad interface for backward compatibility
- Use a two-value type assertion in getter methods to recover the broad interface when needed
- See `reportGenerator` in `internal/converter/hybrid_generator.go`

### 5.10 Common Linter Patterns

Frequently encountered linter issues and fixes:

| Linter                     | Issue                              | Fix                                                                                                               |
| -------------------------- | ---------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `gocritic emptyStringTest` | `len(s) == 0`                      | Use `s == ""`                                                                                                     |
| `gosec G115`               | Integer overflow on int→int32      | Add `//nolint:gosec` with bounded value comment                                                                   |
| `mnd`                      | Magic numbers                      | Create named constants                                                                                            |
| `minmax`                   | Manual min/max comparisons         | Use `min()`/`max()` builtins                                                                                      |
| `goconst`                  | Repeated string literals           | Extract to package-level constants                                                                                |
| `tparallel`                | Subtests use `t.Parallel()`        | Parent test must also call `t.Parallel()`                                                                         |
| `tparallel`                | Subtests share mutable state       | Add `//nolint:tparallel` above func when subtests cannot be parallel due to shared mutable state                  |
| `nonamedreturns`           | Named return values                | Use a struct return type instead of named returns                                                                 |
| `funcorder`                | Method placed between constructors | All constructors (`New*`) must be grouped before any methods on the struct                                        |
| `copylocks`                | Copying `sync.Once`                | In tests resetting globals, suppress with `//nolint:govet` and comment explaining intentional reset               |
| `revive redefines-builtin` | Package name shadows stdlib        | Rename package (e.g., `log` → `logging`)                                                                          |
| `revive stutters`          | `pkg.PkgThing` repeats name        | Drop prefix: `compliance.Plugin` not `compliance.CompliancePlugin`                                                |
| `modernize`                | `omitempty` on struct fields       | Remove `omitempty` from JSON tags on struct-typed fields (no effect in `encoding/json`); YAML `omitempty` is fine |
| `modernize`                | Legacy `sort.Strings`/`sort.Slice` | Use `slices.Sort()` / `slices.SortFunc()` with `strings.Compare`                                                  |

> [!NOTE]
> IDE diagnostics (marked with ★ in some editors) are suggestions, not errors. The authoritative source is `just lint` - if it reports "0 issues", the code is correct regardless of IDE warnings.

### 5.11 Terminal Output Styling

When using Lipgloss/charmbracelet styling in CLI commands:

- Create a shared `useStylesCheck()` helper that checks `TERM != "dumb"` and `NO_COLOR == ""`
- Define terminal constants (`termEnvVar`, `noColorEnvVar`, `termDumb`) to avoid goconst issues
- Provide plain text fallback functions (e.g., `outputConfigPlain()`) for CI/automation
- **All lists must be sorted for deterministic output** — use `slices.Sort()`, `slices.SortFunc()`, or `slices.Sorted(maps.Keys())` on any slice derived from maps, config iteration, or aggregation before rendering, comparing, or serializing. Non-deterministic order causes flaky tests, unstable golden files, and inconsistent CLI output

### 5.12 Standalone Tools Pattern

Place standalone development tools in `tools/<name>/main.go` with `//go:build ignore`:

- Tools are independent from main build (won't break if dependencies differ)
- Some code duplication is acceptable for tool independence
- Run via `go run tools/<name>/main.go` or justfile targets
- Example: `tools/docgen/main.go` generates model documentation

### 5.13 Markdown Generation (`nao1215/markdown`)

Use `nao1215/markdown` for programmatic markdown generation in `internal/converter/builder/`. Always prefer library methods over manual string construction:

- Use fluent builder pattern: chain `.H1().PlainText().Table().Build()`
- Use `BulletList()` with `markdown.Link()` — not manual `"- [text](url)"`
- Use semantic alerts: `Warning()`, `Note()`, `Tip()`, `Caution()`, `Important()` — not manual `> [!WARNING]`
- Use helper functions: `markdown.Bold()`, `markdown.Italic()`, `markdown.Code()`, `markdown.Link()`
- Chain tables with headers: `md.H4("Title").Table(tableSet)` — not separate calls

### 5.14 Unused Code Guidance

- **Remove unused code** rather than suppressing with `//nolint:unused` — rely on version control history if needed later
- **Type aliases and re-exported constants**: Before removing, grep the entire codebase for external references (e.g., `grep -r 'pkg.AliasName'`) — `cmd/` frequently references aliases from internal packages

### 5.15 File Write Safety

Call `file.Sync()` before `Close()` to ensure data is flushed to disk. Handle close errors in a deferred func with `logger.Warn`, not silent discard.

### 5.16 XML Escaping

Use `xml.EscapeText` from stdlib instead of hand-rolled escaping. Note: stdlib uses numeric refs (`&#34;`) not named entities (`&quot;`) — both are valid XML.

### 5.17 XML Element Presence Detection

Go's `encoding/xml` produces `""` for both self-closing tags (`<any/>`) and absent elements when using `string` fields. Use `*string` to distinguish presence from absence: self-closing → `*string` pointing to `""` (non-nil); absent → `nil`.

**Creating `*string` values:** Use `new(expr)` (Go 1.26+), e.g., `Source{Any: new(""), Network: new("lan")}`. Legacy `StringPtr` helper still available in model package.

Add `IsAny()` / `Equal()` methods rather than comparing `*string` fields directly. See `pkg/schema/opnsense/security.go` for the canonical pattern.

**Address resolution:** `Source.EffectiveAddress()` / `Destination.EffectiveAddress()` resolves with priority: `Network` > `Address` > `Any` > `""`. Use this instead of manual `IsAny() || Network == NetworkAny` checks.

**Type selection for boolean-like XML elements:**

- **Presence-based** (`isset()` in PHP): `<disabled/>`, `<log/>`, `<not/>` → use `BoolFlag`
- **Value-based** (`== "1"` in PHP): `<enable>1</enable>`, `<blockpriv>1</blockpriv>` → use `string`
- **Presence with value access needed**: `<any/>` in Source/Destination → use `*string`

See `docs/development/xml-structure-research.md` for the complete field inventory with upstream source citations.

**`DeviceType` serialization:** `CommonDevice.DeviceType` uses `json:"device_type"` (no `omitempty`) — always serializes, even when empty. The `prepareForExport` pipeline defaults it to `DeviceTypeOPNsense`.

### 5.18 Context-Aware Semaphore

When acquiring semaphores in goroutines, use `select` with `ctx.Done()` to respect cancellation (don't block unconditionally on `sem <- struct{}{}`).

### 5.19 Goroutine Stop/Write Safety

When a goroutine writes to an `io.Writer` and a stop method also writes after signaling shutdown, the goroutine must fully exit before the caller writes. Use a `stopped` channel: goroutine defers `close(stopped)`, stop method does `close(done)` then `<-stopped`.

### 5.20 Dual Validator Synchronization

`internal/processor/validate.go` maintains lightweight validation whitelists (powerd modes, optimization values, etc.) that must stay in sync with the authoritative `internal/validator/opnsense.go`. When updating allowed values in either package, grep for the same whitelist in the other and update both.

### 5.21 Duplicate Code Detection in Tests

The `dupl` linter flags structurally similar test files (e.g., `json_test.go` and `yaml_test.go`). When JSON and YAML tests share device construction and assertions, extract shared logic into `test_helpers.go` (e.g., `newFieldsTestDevice()`, `assertNewFieldsPresent()`) and use a single `Test*` function with subtests for each format. If the files remain structurally similar despite extraction, add `//nolint:dupl` on the package line.

### 5.22 Statistics Struct Synchronization

When adding fields to `common.Statistics`, update two places:

1. The struct definition in `pkg/model/enrichment.go`
2. Population logic in `ComputeStatistics()` in `internal/analysis/statistics.go`

The processor's `translateCommonStats()` in `internal/processor/report_statistics.go` must also be updated if new fields are added to `processor.Statistics`.

Separate check logic from stats updates. Never increment stats inside a function that may be called multiple times for fallback logic — check all candidates first, then update stats once based on the outcome.

### 5.23 Public Package Import Aliases

`pkg/schema/opnsense/` (package `opnsense`) and `pkg/model/` (package `model`) are public API packages. Consumer files use import aliases to preserve historical qualifiers:

```go
schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"  // use schema.OpnSenseDocument
common "github.com/EvilBit-Labs/opnDossier/pkg/model"             // use common.CommonDevice
```

Files in `pkg/parser/opnsense/` (package `opnsense`) **must** alias the schema import as `schema` to avoid collision. `cmd/` files that use the parser factory import `"github.com/EvilBit-Labs/opnDossier/pkg/parser"` (no alias needed -- package name `parser` is unambiguous).

`parser.NewFactory(decoder)` requires an `XMLDecoder` argument -- wire with `parser.NewFactory(cfgparser.NewXMLParser())` at the call site. The `XMLDecoder` interface is defined in `pkg/parser/factory.go`.

### 5.24 Public Package Purity

`pkg/` packages must NEVER import `internal/` packages. Any type exposed through a `pkg/` struct field must itself live in `pkg/` or stdlib. When moving types from `internal/` to `pkg/`, audit all struct fields for leaked internal types and define public equivalents in `pkg/` (e.g., `pkg/model.Severity` replaces `internal/analysis.Severity` in `ConversionWarning`).

**Boundary verification:** `grep -rn 'internal/' --include='*.go' pkg/ | grep -v _test.go` -- run before committing `pkg/` changes.

**Interface injection pattern:** When `pkg/` needs `internal/` functionality, define an interface in `pkg/` and inject the concrete implementation at the `cmd/` layer. See `pkg/parser.XMLDecoder` for the canonical example. Go's structural typing allows `pkg/` sub-packages to define their own unexported interface that `internal/` types satisfy without importing them.

**Unexporting types:** When making a type unexported (e.g., `Converter` -> `converter`), add a convenience function (e.g., `ConvertDocument()`) for external test packages that cannot access unexported constructors.

### 5.25 Processor Report Serialization Redaction

`Report.ToJSON()` and `Report.ToYAML()` serialize a redacted copy via `redactedCopyUnsafe()` to prevent `NormalizedConfig.SNMP.ROCommunity` from leaking. When adding new sensitive fields to `CommonDevice`, extend `redactedCopyUnsafe()` in `internal/processor/report.go`. The copy is constructed field-by-field (not `cp := *r`) to avoid `copylocks` on `sync.RWMutex`. Statistics redaction (`redactServiceDetails`) is separate and handles the statistics-layer SNMP community.

### 5.26 File-Split Refactoring Pattern

When splitting a large file into domain-specific files within the same package:

- All functions remain in the same package — tests find them regardless of file
- Pre-commit hooks (gofumpt, linters) may rearrange where helpers land — re-verify file contents after hooks run
- Changing an unexported function's signature breaks same-package test files that call it directly — grep for all call sites in `*_test.go` before changing signatures
- Shared helpers used across domain files stay in the orchestrator file; domain-specific helpers move with their domain
- Naming convention: `<base>_<domain>.go` (e.g., `validate_system.go`, `report_statistics.go`)
- Precedent: PR #415 (`report.go` split), PR #417 (`opnsense.go` split), `pkg/parser/opnsense/` (`converter_*.go`)

---

## 6. Data Processing Standards

### 6.1 Data Models

- **OpnSenseDocument**: Core data model representing entire OPNsense configuration
- **XML Tags**: Must strictly follow OPNsense configuration file structure
- **JSON/YAML Tags**: Follow recommended best practices for each format
- **Audit Models**: Create separate structs (`Finding`, `Target`, `Exposure`) for audit concepts

**Architecture notes:**

- `pkg/schema/opnsense/` is the canonical OPNsense XML data model. Boolean patterns: see §5.17
- `RuleLocation` in `common.go` has complete source/destination fields but is NOT used by `Source`/`Destination` in `security.go` — tracked in issue #255
- Known schema gaps: ~40+ type mismatches and missing fields — see `docs/development/xml-structure-research.md` §4-5

**Platform-agnostic model layer:**

- `pkg/model/` contains device-agnostic types (firewall rules, VPN, system, network, etc.). `revive` var-naming exclusion configured in `.golangci.yml`
- `docs/data-model/` documents the **CommonDevice** export model (`pkg/model/`), NOT the `OpnSenseDocument` XML schema -- paths, types, and nesting differ significantly (e.g., flat `[]Interface` vs map-keyed, `bool` vs `BoolFlag`, top-level `users[]` vs nested `system.user[]`)
- JSON struct tags on nested struct fields must NOT use `omitempty` (Go 1.26+ modernize check)

**Converter enrichment pipeline:**

- `prepareForExport()` in `internal/converter/enrichment.go` is the single gate for all JSON/YAML exports
- It populates `Statistics`, `Analysis`, `SecurityAssessment`, and `PerformanceMetrics` on a shallow copy
- Delegates to `internal/analysis/` for `ComputeStatistics` and `ComputeAnalysis` (shared, not mirrored)
- `internal/processor/` also delegates to `internal/analysis/` via `translateCommonStats` for type translation
- New `CommonDevice` enrichment fields must be wired here to appear in JSON/YAML output
- `computeStatistics` receives *unredacted* data (for accurate presence checks); sensitive values copied into `ServiceDetails` must be post-processed by `redactStatisticsServiceDetails()` when `redact=true`

**Compliance results model:**

- `CommonDevice.ComplianceChecks` uses `*ComplianceResults`. Types (`ComplianceResults`, `ComplianceFinding`, `PluginComplianceResult`, `ComplianceControl`, `ComplianceResultSummary`) mirror `audit`/`analysis`/`compliance` shapes but live in `common` to avoid circular deps. `compliance.Finding` is a type alias for `analysis.Finding`
- `ComplianceFinding` includes `AttackSurface`, `ExploitNotes`, `Control` (from `audit.Finding`) plus all `analysis.Finding` fields. `ComplianceControl` includes `References`, `Tags`, `Metadata` matching `compliance.Control`
- Populated by `mapAuditReportToComplianceResults()` in `cmd/audit_handler.go`, not by `prepareForExport()` (pass-through only)

**Audit report rendering:**

- `handleAuditMode()` in `cmd/audit_handler.go`: maps `audit.Report` → `device.ComplianceChecks` via `mapAuditReportToComplianceResults()`, creates a shallow copy (immutability), then delegates to `generateWithProgrammaticGenerator()` — no format-specific code in handler
- `ComplianceResultSummary` int fields use `json:"field"` (no `omitempty`) — zero values must serialize to distinguish "zero findings" from "not computed"; YAML `omitempty` is fine
- Markdown: `HybridGenerator` appends `BuildAuditSection()` / `WriteAuditSection()` when `ComplianceChecks` is present. Both are safe to call unconditionally (nil → empty string / nil return). JSON/YAML serialize `ComplianceChecks` automatically via struct tags
- `audit.ComplianceResult` has nested maps (`PluginInfo map[string]PluginInfo`, `Compliance map[string]map[string]bool`) — require plugin-name keyed lookups during mapping
- `converter.Format` is the type name for output format (not `OutputFormat`)
- `EscapePipeForMarkdown()` (pipe-only) and `TruncateString()` (rune-aware, exact position) are distinct from `formatters.EscapeTableContent()` (all special chars) and `formatters.TruncateDescription()` (word boundary)
- Plugin names and metadata keys iterated in sorted order (`slices.Sorted(maps.Keys(...))`)

**Port field disambiguation:**

- `Source.Port` → `<source><port>...</port></source>` (nested, preferred)
- `Rule.SourcePort` → `<sourceport>...</sourceport>` (top-level, legacy)
- Prefer `Source.Port` with fallback to `Rule.SourcePort` for backward compatibility

**Conversion warnings:**

- `common.ConversionWarning` in `pkg/model/warning.go` — platform-agnostic. `Converter.addWarning(field, value, message, severity)` accumulates non-fatal warnings
- `ToCommonDevice` returns `(*CommonDevice, []ConversionWarning, error)` — propagated through `DeviceParser`, `Factory.CreateDevice`, and all CLI commands (logged via `ctxLogger.Warn`)
- `diff.go`'s `parseConfigFile` accepts a `*logging.Logger` parameter for warning logging
- Warning `Field` uses dot-path with array indices: `"FirewallRules[0].Type"`, `"NAT.InboundRules[0].Interface"`
- Warning `Severity` uses `pkg/model.Severity` (not `internal/analysis.Severity`) — public API boundary

### 6.2 Multi-Format Export

```bash
opndossier convert config.xml --format [markdown|json|yaml]
opndossier convert config.xml --format json -o output.json
opndossier convert config.xml --format yaml --force
```

- Exported files must be valid and parseable by standard tools
- Smart file naming with overwrite protection (`-f` to force)

### 6.3 Report Generation

| Mode            | Audience   | Focus                                 |
| --------------- | ---------- | ------------------------------------- |
| Standard (ops)  | Operations | General configuration overview        |
| Blue (defense)  | Blue Team  | Clarity, grouping, actionability      |
| Red (adversary) | Red Team   | Target prioritization, pivot surfaces |

All report generation uses programmatic Go code via `builder.MarkdownBuilder` (no template system).

### 6.4 Modular Report Generator Architecture

Each report generator is a **self-contained module** with all generation, calculation, and transformation logic. Shared: `model.OpnSenseDocument`, common interfaces (`ReportBuilder`, `Generator`), and helpers. Pro-level generators use `//go:build pro` tags. See [Architecture Documentation](docs/development/architecture.md#modular-report-generator-architecture) for detailed design.

### 6.5 cfgparser/Schema Synchronization

`internal/cfgparser/xml.go` switch cases reference `OpnSenseDocument` fields by name. When renaming fields or changing types (e.g., singular → slice), update the cfgparser cases too. For slice fields, `decodeSection` can't decode a single XML element into a slice — decode into a temp variable and `append` to the slice field.

---

## 7. Testing Standards

### 7.1 Test Organization

Use table-driven tests with subtests (`t.Run`). Always call `t.Parallel()` on both parent test and subtests.

### 7.2 Test Requirements

| Requirement       | Target                       |
| ----------------- | ---------------------------- |
| Coverage          | >80%                         |
| Speed             | \<100ms per test             |
| Race detection    | `go test -race`              |
| Integration tests | `//go:build integration` tag |

### 7.3 Test Helpers

Use `t.Helper()` in all test helpers and `t.Cleanup()` for teardown. Place shared helpers in `test_helpers.go` (not `_test.go` — `revive` var-naming applies).

### 7.4 Map Iteration in Tests

Map iteration is non-deterministic — test for presence (`strings.Contains()`) not exact equality. Production code must sort before rendering (see §5.11).

### 7.5 Test Assertion Specificity

When testing formatted output (Markdown links, tables), verify the actual format, not just content presence:

```go
// Bad - only verifies content exists
assert.Contains(t, row[2], "wan")

// Good - verifies link format
assert.Contains(t, interfaceCell, "[wan]")
assert.Contains(t, interfaceCell, "#wan-interface")
assert.Contains(t, interfaceCell, ", ") // Multi-value separator
```

### 7.6 Golden File Testing

Use `sebdah/goldie/v2` for snapshot testing. Key patterns:

- Golden files contain **actual** values (timestamps, versions), not placeholders
- Use a `normalizeGoldenOutput` function to normalize dynamic content before comparison
- Update golden files: `go test ./path -run TestGolden -update`
- Use `time.RFC3339` for timestamps (standard format, consistent across codebase)
- Clean trailing whitespace: `sed -i '' 's/[[:space:]]*$//' *.golden.md`
- Ensure golden files end with a trailing newline — goldie uses strict byte comparison and `md.String()` output includes one
- Markdown validation: `internal/markdown.ValidateMarkdown()` uses goldmark for round-trip validation
- When making a report section conditional, update tests that assert its presence in ToC — tests with no matching data must use `NotContains`
- Changing shared rendering functions (e.g., goldmark config in `internal/markdown/`) requires regenerating golden files across ALL formatters that depend on them

### 7.7 Testing Global Flag Variables

When testing CLI commands with package-level flag variables (required by Cobra), save originals and use `t.Cleanup()` to restore them. Do NOT use `t.Parallel()` — see GOTCHAS.md §1.1.

When adding new shared flags (`cmd/shared_flags.go`), update `sharedFlagSnapshot` in `cmd/display_test.go` — add the field to the struct, `captureSharedFlags()`, and `restore()`. Missing fields leak state between tests.

---

## 8. Plugin Architecture

### 8.1 Core Components

| File                                | Purpose                                                         |
| ----------------------------------- | --------------------------------------------------------------- |
| `internal/analysis/finding.go`      | Canonical `Finding` struct, `Severity` type, validation helpers |
| `internal/compliance/interfaces.go` | `Plugin` interface, `Control`, `Finding` structs                |
| `internal/audit/plugin.go`          | `PluginRegistry`, dynamic plugin loader                         |
| `internal/audit/plugin_manager.go`  | `PluginManager` for lifecycle operations                        |
| `internal/plugins/`                 | Built-in plugin implementations                                 |

**Important:** `PluginManager`'s registry is independent of the global singleton — see GOTCHAS.md §2.1 for details.

### 8.2 Plugin Development

All plugins implement `compliance.Plugin` (see `internal/compliance/interfaces.go`). Import `common "github.com/EvilBit-Labs/opnDossier/pkg/model"` for CommonDevice types.

- Control naming: `PLUGIN-001`, `PLUGIN-002`. Severity levels: `critical`, `high`, `medium`, `low`
- `Finding.Type` = category (e.g., `"compliance"`); `Finding.Severity` = severity level from the control definition via `controlSeverity(id)` helper — never hard-code severity literals in `RunChecks()`
- Dynamic plugins: export `var Plugin compliance.Plugin`. Must set `Severity` or provide resolvable `References` — `RunComplianceChecks` normalizes empty severity via `GetControlByID()` or returns error
- `compliance.CloneControls()` deep-copies `[]Control` including nested types (Tags, Metadata) — use in `GetControls()` and when storing controls in result structs
- Plugin name matching is case-insensitive (`deduplicatePluginNames`, `ValidateModeConfig` normalize to lowercase)

### 8.3 Compliance Standards

| Standard | Control Pattern | Location                     |
| -------- | --------------- | ---------------------------- |
| STIG     | `STIG-V-XXXXXX` | `internal/plugins/stig/`     |
| SANS     | `SANS-XXX`      | `internal/plugins/sans/`     |
| Firewall | `FIREWALL-XXX`  | `internal/plugins/firewall/` |

---

## 9. Commit Style

Format: `<type>(<scope>): <description>` — imperative mood, no period, ≤72 chars, capitalized. **Scope is required.**

**Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore` **Scopes:** `(parser)`, `(converter)`, `(audit)`, `(cli)`, `(model)`, `(plugin)`, `(builder)` **Breaking changes:** add `!` after scope or use `BREAKING CHANGE:` in footer

Examples:

```text
feat(parser): add support for OPNsense 24.1 config format
fix(converter): handle empty VLAN configurations gracefully
feat(api)!: redesign plugin interface
```

---

## 10. Development Workflow

### 10.1 Command Reference

```bash
# Development
just dev              # Run in development mode
just build            # Build with all checks
just rebuild          # Clean and rebuild
just install          # Install dependencies

# Quality
just format           # Format code and apply fixes
just lint             # Run linter
just test             # Run all tests
just check            # Run pre-commit checks on all files
just ci-check         # Run full CI checks (pre-commit, format, lint, test)
just ci-smoke         # Run smoke tests (fast, minimal validation)
just modernize        # Apply Go modernization fixes (remove //go:fix inline directives afterward)
just modernize-check  # Check for modernization opportunities (dry-run)

# Testing
just test-race        # Run tests with race detector
just test-stress      # Run stress tests (build tag)
just test-integration # Run integration tests (build tag)
just coverage         # Run tests and open coverage in browser
just cover            # Generate coverage artifact
just completeness-check # Run model completeness check

# Benchmarks
just bench            # Run benchmarks
just bench-compare    # Compare current benchmarks against baseline
just bench-save       # Save benchmark baseline for comparison

# Security
just scan             # Run gosec security scanner
just sbom             # Generate SBOM with cyclonedx-gomod
just security-all     # Run all security checks (SBOM + scan)
```

### 10.2 Secure Build

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o opnDossier ./main.go
```

Static, portable builds: no CGO, stripped debug info, no local paths in binary.

### 10.3 CI Debugging Commands

| Command                                            | Purpose                                                           |
| -------------------------------------------------- | ----------------------------------------------------------------- |
| `gh pr checks <PR#>`                               | List all CI check statuses for a PR                               |
| `gh run view <run-id> --json jobs \| jq '.jobs[]'` | Get detailed job/step status                                      |
| `just test-race`                                   | Run race detection locally (not in CI - can have false positives) |
| `just test-stress`                                 | Run stress tests (build tag `stress`)                             |

**CI Gotchas:**

- Race detection can fail on async test infrastructure (spinners/progress bars) - not production bugs
- Benchmarks with large files can hang for hours; use `timeout-minutes` and `continue-on-error: true`
- The `Performance Benchmarks` job is non-blocking (continue-on-error) to prevent PR merge delays

**Mergify merge queues:**

- `.mergify.yml` defines 4 queues: `dosubot` (lint-only), `dependabot-workflows` (lint-only), `dependabot` (full CI), `default` (full CI, manually enqueued)
- Bot queues use `autoqueue: true` — PRs are enqueued automatically when `queue_conditions` match
- Human PRs use the `default` queue — maintainers manually enqueue via Mergify `/queue` command; repo permissions restrict who can send the command
- CI check names in Mergify must match the `name:` field in workflow jobs (e.g., `Lint`, `Build`, `Test (ubuntu-latest)`), NOT the job ID (`lint`, `build`, `test`)
- DCO sign-off is enforced by a GitHub App, not a CI workflow — there is no `DCO` check name
- Bot PRs (dosubot, dependabot workflow-only) require only `Lint`; all others require full CI

---

## 11. Security Standards

| Principle              | Implementation                                  |
| ---------------------- | ----------------------------------------------- |
| No secrets in code     | Use environment variables or secure vaults      |
| Input validation       | Validate and sanitize all user inputs           |
| Secure defaults        | Default to secure configurations                |
| File permissions       | Use 0600 for config files                       |
| Error messages         | Avoid exposing sensitive information            |
| Network unavailability | Cache reference data locally, handle gracefully |

---

## 12. AI Agent Guidelines

### 12.1 Mandatory Practices

All standards in §§5-11 apply. Additionally:

1. **CRITICAL: Tasks are NOT complete until `just ci-check` passes**
2. **Always run tests** after changes (`just test`) and **linting** before committing (`just lint`)
3. **Consult project documentation** before making changes
4. Prefer structured config data + audit overlays over flat summary tables
5. Validate markdown with `mdformat` and `markdownlint-cli2`
6. Place `//nolint:` directives on SEPARATE LINE above call (inline gets stripped by gofumpt)

### 12.2 Code Review Checklist

- [ ] Formatting, linting, and tests pass (`just ci-check`)
- [ ] Error handling includes context
- [ ] No hardcoded secrets
- [ ] Input validation at boundaries
- [ ] Documentation updated
- [ ] Follows established patterns and architecture

### 12.3 Rules of Engagement

- **TERM=dumb Support**: Ensure terminal output respects `TERM="dumb"` for CI/automation
- **No Auto-commits**: Never commit without explicit permission
- **Focus on Value**: Enhance the project's unique value as an OPNsense auditing tool
- **No Destructive Actions**: No major refactors without explicit permission
- **Stay Focused**: Avoid scope creep

### 12.4 Issue Resolution

When encountering problems:

1. Identify the specific issue clearly
2. Explain the problem in ≤5 lines
3. Propose a concrete path forward
4. Don't proceed without resolving blockers

---

## 13. Open-Source Quality Standards (OSSF Best Practices)

This project has the OSSF Best Practices passing badge. Maintain these standards:

### 13.1 Every PR Must

- Sign off commits with `git commit -s` (DCO enforced by GitHub App)
- Pass CI (golangci-lint, gofumpt, tests, CodeQL, Grype) before merge
- Include tests for new functionality -- this is policy, not optional
- Be reviewed (human or CodeRabbit) for correctness, safety, and style
- Not introduce `panic()` in library code, unchecked errors, or unvalidated input

### 13.2 Every Release Must

- Have human-readable release notes via git-cliff (not raw git log)
- Use unique SemVer identifiers (`vX.Y.Z` tags)
- Be built reproducibly (pinned toolchain, committed `go.sum`, GoReleaser)

### 13.3 Security

- Vulnerabilities go through private reporting (GitHub advisories or <support@evilbitlabs.io>), never public issues
- Grype and Snyk run in CI -- fix findings promptly
- Medium+ severity vulnerabilities: we aim to release a fix within 90 days of confirmation (see SECURITY.md for canonical policy)
- `docs/security/vulnerability-scanning.md` documents scanning thresholds and remediation process
- `docs/security/security-assurance.md` must be updated when new attack surface is introduced

### 13.4 Documentation

- Exported APIs require godoc comments with examples where appropriate
- CONTRIBUTING.md documents code review criteria, test policy, DCO, and governance
- SECURITY.md documents vulnerability reporting with scope, safe harbor, and PGP key
- AGENTS.md must accurately reflect implemented features (not aspirational)
- `docs/security/security-assurance.md` documents threat model, design principles, and CWE countermeasures

## Agent Rules <!-- tessl-managed -->

@.tessl/RULES.md follow the [instructions](.tessl/RULES.md)
