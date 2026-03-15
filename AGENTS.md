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

| Principle            | Description                                                                         |
| -------------------- | ----------------------------------------------------------------------------------- |
| **Operator-Focused** | Build tools for operators, by operators. Intuitive and efficient workflows          |
| **Offline-First**    | Operate in fully offline/airgapped environments. No external dependencies           |
| **Structured Data**  | Data should be structured, versioned, and portable for auditable systems            |
| **Framework-First**  | Leverage established frameworks. Avoid custom solutions when established ones exist |

### EvilBit Labs Brand Principles

- **Trust the Operator:** Full control, no black boxes
- **Polish Over Scale:** Quality over feature-bloat
- **Offline First:** Built for where the internet isn't
- **Sane Defaults:** Clean outputs, CLI help that's actually helpful
- **Ethical Constraints:** No dark patterns, spyware, or telemetry
- **No Emojis:** Do not use emojis in code, CLI output, comments, or documentation unless the code specifically processes emoji data

### Repository Roles

- **Maintainer:** `unclesp1d3r` (sole maintainer — `lgtm` label self-merge pattern in Mergify)
- **Trusted bots:** `dependabot[bot]`, `dosubot[bot]` (auto-approved by Mergify)

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
│   ├── model/              # Data models and re-export seam
│   │   ├── common/         # Platform-agnostic CommonDevice domain model
│   │   ├── opnsense/       # OPNsense parser + schema→CommonDevice converter
│   │   └── factory.go      # ParserFactory + DeviceParser interface
│   ├── plugins/            # Compliance plugins (firewall/, sans/, stig/)
│   ├── pool/               # Worker pool for concurrent processing
│   ├── processor/          # Data processing and report generation
│   ├── progress/           # CLI progress indicators (spinner, bar)
│   ├── sanitizer/          # Data sanitization utilities
│   ├── schema/             # Canonical OPNsense data model (XML structs)
│   ├── testing/            # Shared test helpers
│   └── validator/          # Data validation
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

Use `charmbracelet/log` for structured logging:

```go
logger := log.With("input_file", config.InputFile)
logger.Info("starting processing")
logger.Error("validation failed", "error", err)
```

Log levels: `debug` (troubleshooting), `info` (operations), `warn` (issues), `error` (failures)

**Context-aware logging — use `WithContext()` pattern:**

When a method receives `context.Context`, create a local context-scoped logger instead of dropping `ctx`:

```go
func (pm *PluginManager) DoWork(ctx context.Context) error {
    logger := pm.logger.WithContext(ctx)
    logger.Info("starting work")
    // ...
}
```

This replaces `slog.InfoContext(ctx, ...)` — never simply drop `ctx` from logging calls.

### 5.4 Documentation

- Start comments with the name of the thing being described
- Use complete sentences
- Include examples for complex functionality

### 5.5 Import Organization

Group imports: standard library → third-party → internal, separated by blank lines.

### 5.6 Thread Safety

When using `sync.RWMutex` to protect struct fields:

- ALL read methods need `RLock()`, not just write methods
- Go's `sync.RWMutex` is NOT reentrant - create internal `*Unsafe()` helpers
- Getter methods should return value copies, not pointers to internal state
- Example pattern from `internal/processor/report.go`:

```go
func (r *Report) TotalFindings() int {
    r.mu.RLock()
    defer r.mu.RUnlock()
    return r.totalFindingsUnsafe()  // Internal helper, no lock
}
```

### 5.6a Struct Copy, Comparison, and Slice Patterns

**Shallow copy with slices:** `normalized := *cfg` copies the struct but slices share backing arrays. Deep-copy any slice you intend to mutate:

```go
normalized := *cfg
if cfg.Filter.Rule != nil {
    normalized.Filter.Rule = make([]model.Rule, len(cfg.Filter.Rule))
    copy(normalized.Filter.Rule, cfg.Filter.Rule)
}
```

**Comparison functions:** Always handle nil inputs first (both-nil → nil, one-nil → added/removed). Use `slices.Equal()` for slice fields. For map-like types with `Get()` methods, check return signature: many return `(value, bool)` not `(value, error)`.

**Slice pre-allocation:** Use `make([]T, 0)` without capacity hints for small, variable-length slices. Only add capacity hints when the value is reused elsewhere or performance-critical. Avoid creating constants solely for capacity hints.

**String comparisons:** Use `strings.EqualFold(a, b)` for case-insensitive comparison (no need for `strings.ToLower()` first). For case-insensitive enum validation, iterate with `EqualFold` directly on original value.

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

When code becomes unused during refactoring:

- **Remove it** rather than suppressing linter warnings with `//nolint:unused`
- Unused code adds maintenance burden and confuses future readers
- If the code might be needed later, rely on version control history
- This includes helper functions, test utilities, and constants
- **Type aliases and re-exported constants**: Before removing, grep the entire codebase for external references (e.g., `grep -r 'pkg.AliasName'`). The `internal/model/` re-export layer and `cmd/` package frequently reference aliases from internal packages.

### 5.15 File Write Safety

Call `file.Sync()` before `Close()` to ensure data is flushed to disk. Handle close errors for write operations:

```go
defer func() {
    if cerr := outputFile.Close(); cerr != nil {
        logger.Warn("failed to close output file", "error", cerr)
    }
}()
// ... write operations ...
if err := outputFile.Sync(); err != nil {
    return fmt.Errorf("failed to sync output file: %w", err)
}
```

### 5.16 XML Escaping

Use `xml.EscapeText` from stdlib instead of hand-rolled escaping:

```go
func escapeXMLText(s string) string {
    var buf bytes.Buffer
    if err := xml.EscapeText(&buf, []byte(s)); err != nil {
        return s
    }
    return buf.String()
}
```

Note: stdlib uses numeric refs (`&#34;`) not named entities (`&quot;`) - both are valid XML.

### 5.17 XML Element Presence Detection

Go's `encoding/xml` produces `""` for both self-closing tags (`<any/>`) and absent elements when using `string` fields. Use `*string` to distinguish presence from absence:

- `<any/>` (self-closing) → `*string` pointing to `""` (non-nil)
- `<any>1</any>` → `*string` pointing to `"1"` (non-nil)
- absent element → `nil`

**Creating `*string` values — use `new(expr)` (Go 1.26+):**

```go
// Good — Go 1.26+ new(expr) syntax
src := Source{Any: new(""), Network: new("lan")}

// Legacy — StringPtr helper (still available in model package)
src := Source{Any: model.StringPtr(""), Network: model.StringPtr("lan")}
```

Add `IsAny()` / `Equal()` methods rather than comparing `*string` fields directly. See `internal/schema/security.go` for the canonical pattern.

**Address resolution — use `EffectiveAddress()`:**

`Source.EffectiveAddress()` / `Destination.EffectiveAddress()` resolves the effective address with priority: `Network` > `Address` > `Any` > `""`. Use this instead of manual `IsAny() || Network == NetworkAny` checks:

```go
// Good — single canonical method
srcAny := rule.Source.EffectiveAddress() == NetworkAny

// Bad — manual multi-field check (replaced in PR #258)
srcAny := rule.Source.Network == NetworkAny || rule.Source.IsAny()
```

**Type selection for boolean-like XML elements:**

- **Presence-based** (`isset()` in PHP): `<disabled/>`, `<log/>`, `<not/>` → use `BoolFlag`
- **Value-based** (`== "1"` in PHP): `<enable>1</enable>`, `<blockpriv>1</blockpriv>` → use `string`
- **Presence with value access needed**: `<any/>` in Source/Destination → use `*string`

See `docs/development/xml-structure-research.md` for the complete field inventory with upstream source citations.

**`DeviceType` serialization:**

`CommonDevice.DeviceType` uses `json:"device_type"` (no `omitempty`) — it always serializes, even when empty, to ensure JSON/YAML consumers can detect the field. The `prepareForExport` pipeline defaults it to `DeviceTypeOPNsense`.

### 5.18 Context-Aware Semaphore

When acquiring semaphores in goroutines, use select with context to respect cancellation:

```go
select {
case sem <- struct{}{}:
    defer func() { <-sem }()
case <-ctx.Done():
    return ctx.Err()
}
```

### 5.19 Goroutine Stop/Write Safety

When a goroutine writes to an `io.Writer` and a stop method also writes after signaling shutdown, the goroutine must fully exit before the caller writes. Use a `stopped` channel:

```go
func (s *Spinner) spin() {
    defer close(s.stopped)  // signal goroutine exit
    // ... write loop ...
}

func (s *Spinner) stop() {
    close(s.done)       // signal shutdown
    <-s.stopped         // wait for goroutine to finish writing
}
```

### 5.20 Dual Validator Synchronization

`internal/processor/validate.go` maintains lightweight validation whitelists (powerd modes, optimization values, etc.) that must stay in sync with the authoritative `internal/validator/opnsense.go`. When updating allowed values in either package, grep for the same whitelist in the other and update both.

### 5.21 Duplicate Code Detection in Tests

The `dupl` linter flags structurally similar test files (e.g., `json_test.go` and `yaml_test.go`). When JSON and YAML tests share device construction and assertions, extract shared logic into `test_helpers.go` (e.g., `newFieldsTestDevice()`, `assertNewFieldsPresent()`) and use a single `Test*` function with subtests for each format. If the files remain structurally similar despite extraction, add `//nolint:dupl` on the package line.

### 5.22 Statistics Struct Synchronization

When adding fields to `common.Statistics`, update three places:

1. The struct definition in `internal/model/common/enrichment.go`
2. Population logic in `computeStatistics()` in `internal/converter/enrichment.go`
3. The sum in `computeTotalConfigItems()` in the same file

Separate check logic from stats updates. Never increment stats inside a function that may be called multiple times for fallback logic — check all candidates first, then update stats once based on the outcome.

---

## 6. Data Processing Standards

### 6.1 Data Models

- **OpnSenseDocument**: Core data model representing entire OPNsense configuration
- **XML Tags**: Must strictly follow OPNsense configuration file structure
- **JSON/YAML Tags**: Follow recommended best practices for each format
- **Audit Models**: Create separate structs (`Finding`, `Target`, `Exposure`) for audit concepts

**Architecture notes:**

- `internal/schema/` is the canonical data model; `internal/model/` is a re-export layer (type aliases + constructor wrappers)
- OPNsense XML uses two boolean patterns: **presence-based** (`<disabled/>` → `BoolFlag`) and **value-based** (`<enable>1</enable>` → `string`). See §5.17 and `docs/development/xml-structure-research.md`
- `RuleLocation` in `common.go` has complete source/destination fields but is NOT used by `Source`/`Destination` in `security.go` — tracked in issue #255
- Known schema gaps: ~40+ type mismatches and missing fields — see `docs/development/xml-structure-research.md` §4-5

**Platform-agnostic model layer:**

- `internal/model/common/` contains device-agnostic types (firewall rules, VPN, system, network, etc.)
- `docs/data-model/` documents the **CommonDevice** export model (`internal/model/common/`), NOT the `OpnSenseDocument` XML schema -- field paths, types, and nesting differ significantly between the two (e.g., flat `[]Interface` array vs map-keyed, `bool` vs `BoolFlag`, top-level `users[]` vs nested `system.user[]`)
- `revive` var-naming exclusion for this path is configured in `.golangci.yml`
- JSON struct tags on nested struct fields must NOT use `omitempty` (Go 1.26+ modernize check)

**Converter enrichment pipeline:**

- `prepareForExport()` in `internal/converter/enrichment.go` is the single gate for all JSON/YAML exports
- It populates `Statistics`, `Analysis`, `SecurityAssessment`, and `PerformanceMetrics` on a shallow copy
- Cannot import `internal/processor` (circular dependency) — analysis/statistics logic is mirrored, not shared
- New `CommonDevice` enrichment fields must be wired here to appear in JSON/YAML output
- `computeStatistics` receives *unredacted* data (for accurate presence checks); sensitive values copied into `ServiceDetails` must be post-processed by `redactStatisticsServiceDetails()` when `redact=true`

**Compliance results model:**

- `CommonDevice.ComplianceChecks` uses `*ComplianceResults` (not the old stub `ComplianceChecks` struct)
- `common.ComplianceResults` / `ComplianceFinding` / `PluginComplianceResult` / `ComplianceControl` / `ComplianceResultSummary` mirror `audit.Report` / `analysis.Finding` / `audit.ComplianceResult` / `compliance.Control` / `audit.ComplianceSummary` shapes but live in `common` (no `audit` import — avoids circular deps). `ComplianceFinding` includes `AttackSurface`, `ExploitNotes`, and `Control` from `audit.Finding` in addition to all `analysis.Finding` fields
- `ComplianceChecks` is populated by `mapAuditReportToComplianceResults()` in `cmd/audit_handler.go`, not by `prepareForExport()` — pass-through only
- `ComplianceControl` includes `References`, `Tags`, `Metadata` fields matching `compliance.Control`
- `compliance.Finding` is a type alias for `analysis.Finding` — they are the same struct

**Audit report rendering:**

- `handleAuditMode()` in `cmd/audit_handler.go` maps `audit.Report` → `device.ComplianceChecks` via `mapAuditReportToComplianceResults()`, then delegates to `generateWithProgrammaticGenerator()` — no format-specific code in the handler
- `handleAuditMode()` creates a shallow copy of `*CommonDevice` before setting `ComplianceChecks` — does NOT mutate the input (immutability rule)
- `ComplianceFinding` includes `AttackSurface *ComplianceAttackSurface`, `ExploitNotes`, `Control` from `audit.Finding`, plus `Reference`, `Tags`, `Metadata` from `analysis.Finding` — no silent field drops during mapping
- `ComplianceResultSummary` int fields use `json:"field"` (no `omitempty`) — zero values must serialize to distinguish "zero findings" from "not computed"; YAML `omitempty` is fine
- `HybridGenerator.generateMarkdown()` / `generateMarkdownToWriter()` appends `BuildAuditSection()` / `WriteAuditSection()` when `ComplianceChecks` is present
- JSON/YAML formats serialize `ComplianceChecks` automatically via struct tags — no special handling needed
- `BuildAuditSection(data)` / `WriteAuditSection(w, data)` in `internal/converter/builder/` renders compliance audit results from `CommonDevice.ComplianceChecks`
- `BuildAuditSection` returns empty string when `ComplianceChecks` is nil; `WriteAuditSection` writes nothing and returns nil — both safe to call unconditionally
- `audit.ComplianceResult` has nested maps: `PluginInfo map[string]PluginInfo`, `Compliance map[string]map[string]bool` — require plugin-name keyed lookups during mapping
- `converter.Format` is the type name for output format (not `OutputFormat`)
- Uses `EscapePipeForMarkdown()` (pipe-only escaping) and `TruncateString()` (rune-aware, exact position) — distinct from `formatters.EscapeTableContent()` (all special chars) and `formatters.TruncateDescription()` (word boundary)
- Plugin names and metadata keys are iterated in sorted order (`slices.Sorted(maps.Keys(...))`)

**Port field disambiguation:**

- `Source.Port` → `<source><port>...</port></source>` (nested, preferred)
- `Rule.SourcePort` → `<sourceport>...</sourceport>` (top-level, legacy)
- Prefer `Source.Port` with fallback to `Rule.SourcePort` for backward compatibility

**Conversion warnings:**

- `common.ConversionWarning` lives in `internal/model/common/warning.go` — platform-agnostic, not in `opnsense` package
- `Converter.addWarning(field, value, message, severity)` accumulates warnings during conversion
- `ToCommonDevice` returns `(*CommonDevice, []ConversionWarning, error)` — warnings are non-fatal
- `DeviceParser` interface, `ParserFactory.CreateDevice`, and all CLI commands propagate the 3-value return
- CLI commands log warnings via `ctxLogger.Warn("conversion warning", "field", w.Field, ...)`
- `diff.go`'s `parseConfigFile` accepts a `*logging.Logger` parameter for warning logging
- Warning `Field` uses dot-path notation with array indices: `"FirewallRules[0].Type"`, `"NAT.InboundRules[0].Interface"`

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

`internal/cfgparser/xml.go` switch cases reference `OpnSenseDocument` fields by name. When renaming fields or changing types (e.g., singular → slice), update the cfgparser cases too. For slice fields, `decodeSection` can't decode a single XML element into a slice — use the temp-variable-and-append pattern:

```go
case "ca":
    var ca schema.CertificateAuthority
    if err := decodeSection(dec, &ca, se); err != nil {
        return err
    }
    doc.CAs = append(doc.CAs, ca)
    return nil
```

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

When testing output that involves map iteration:

- **Don't** compare exact string equality (map iteration order is non-deterministic)
- **Do** test for presence of expected content using `strings.Contains()`
- **Do** use `slices.Sorted(maps.Keys())` in production code for deterministic output

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
- Markdown validation: `internal/markdown.ValidateMarkdown()` uses goldmark for round-trip validation
- Changing shared rendering functions (e.g., goldmark config in `internal/markdown/`) requires regenerating golden files across ALL formatters that depend on them

### 7.7 Testing Global Flag Variables

When testing CLI commands with package-level flag variables (required by Cobra), use `t.Cleanup()` to restore original values:

```go
func TestValidateFlags(t *testing.T) {
    // Save original values
    origMode := sharedAuditMode
    origPlugins := sharedSelectedPlugins

    // Restore after test
    t.Cleanup(func() {
        sharedAuditMode = origMode
        sharedSelectedPlugins = origPlugins
    })

    // Test with modified values
    sharedAuditMode = "invalid"
    err := validateConvertFlags()
    require.Error(t, err)
}
```

This pattern ensures test isolation when multiple tests modify the same global state.

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

**Important:** `PluginManager` allocates and populates its own `PluginRegistry` instance via `InitializePlugins()`. This is independent of the global singleton returned by `GetGlobalRegistry()`. Plugins registered through `PluginManager` are not automatically available in the global registry — callers needing the global registry must use `RegisterGlobalPlugin()` separately.

### 8.2 Plugin Development

All plugins implement `compliance.Plugin` (see `internal/compliance/interfaces.go`).

- Import `internal/model/common`, not `internal/model`
- Use consistent control naming: `PLUGIN-001`, `PLUGIN-002`
- Severity levels: `critical`, `high`, `medium`, `low`
- `Finding.Type` = category (e.g., `"compliance"`); `Finding.Severity` = severity level matching the control's severity
- Derive `Finding.Severity` from the control definition via a `controlSeverity(id string) string` helper — never hard-code severity literals in `RunChecks()`
- Dynamic plugins: export `var Plugin compliance.Plugin`
- `RunComplianceChecks` normalizes findings: if `Finding.Severity` is empty, it derives severity from the referenced control via `GetControlByID()`; if no control matches, it returns an error — dynamic plugins must set `Severity` or provide resolvable `References`
- `compliance.CloneControls()` deep-copies a `[]Control` slice including nested reference types (Tags, Metadata) — use in `GetControls()` implementations and when storing controls in result structs
- Plugin name matching is case-insensitive — `deduplicatePluginNames` and `ValidateModeConfig` normalize to lowercase

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
just modernize        # Apply Go modernization fixes
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

# Modernization (Go 1.26+)
just modernize        # Applies modernize -fix; remove //go:fix inline directives afterward
```

### 10.2 Secure Build

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o opnDossier ./main.go
```

- `-trimpath`: Remove local paths from binaries
- `-ldflags="-s -w"`: Strip debug info
- `CGO_ENABLED=0`: Static, portable builds

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

- `.mergify.yml` defines 5 author-specific queues: `dosubot`, `dependabot-workflows`, `dependabot`, `maintainer`, `external`
- CI check names in Mergify must match the `name:` field in workflow jobs (e.g., `Lint`, `Build`, `Test (ubuntu-latest)`), NOT the job ID (`lint`, `build`, `test`)
- DCO sign-off is enforced by a GitHub App, not a CI workflow — there is no `DCO` check name
- Bot PRs (dosubot, dependabot workflow-only) require only `Lint`; all others require full CI
- `autoqueue: true` on all queues — PRs are enqueued automatically when `queue_conditions` match, no `pull_request_rules` queue action needed

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
7. **Fix pre-existing issues** encountered during work — do not dismiss as "not our problem"

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

# Agent Rules <!-- tessl-managed -->

@.tessl/RULES.md follow the [instructions](.tessl/RULES.md)
