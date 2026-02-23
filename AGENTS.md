# AI Agent Coding Standards and Project Structure

This document consolidates all development standards, architectural principles, and workflows for the opnDossier project.

## Related Documentation

- **[Requirements](../project_spec/requirements.md)** - Complete project requirements and specifications
- **[Architecture](docs/development/architecture.md)** - System design, component interactions, and deployment patterns
- **[Development Standards](docs/development/standards.md)** - Go-specific coding standards and project structure

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
├── cmd/                              # CLI command entry points
│   ├── root.go                       # Root command and PersistentPreRunE setup
│   ├── audit_handler.go              # Audit command handler
│   ├── completion.go                 # Shell completion support
│   ├── config.go                     # Config parent command
│   ├── config_init.go                # Config init subcommand
│   ├── config_show.go                # Config show subcommand
│   ├── config_validate.go            # Config validate subcommand
│   ├── context.go                    # CommandContext for dependency injection
│   ├── convert.go                    # Convert command
│   ├── diff.go                       # Diff command
│   ├── display.go                    # Display command
│   ├── exitcodes.go                  # Structured exit codes and JSON errors
│   ├── help.go                       # Custom help templates and suggestions
│   ├── man.go                        # Man page generation
│   ├── sanitize.go                   # Sanitize command
│   ├── shared_flags.go               # Shared flag definitions across commands
│   └── validate.go                   # Validate command
├── internal/                         # Private application logic
│   ├── walker.go                     # Tree-walking utilities
│   ├── audit/                        # Audit engine and compliance checking
│   │   ├── plugin.go                 # Plugin registry
│   │   └── plugin_manager.go         # Plugin lifecycle
│   ├── cfgparser/                    # XML parsing and validation
│   ├── compliance/                   # Plugin interfaces
│   ├── config/                       # Configuration management
│   ├── constants/                    # Shared constants (validation whitelists, etc.)
│   ├── converter/                    # Data conversion utilities
│   │   └── builder/                  # Markdown builder and writer
│   ├── diff/                         # Configuration diff engine
│   ├── display/                      # Terminal display formatting
│   ├── docgen/                       # Model documentation generation
│   ├── export/                       # File export functionality
│   ├── logging/                      # Logging utilities
│   ├── markdown/                     # Markdown generation and validation
│   ├── model/                        # Data models and re-export seam
│   │   ├── common/                   # Platform-agnostic CommonDevice domain model
│   │   ├── opnsense/                 # OPNsense parser + schema→CommonDevice converter
│   │   └── factory.go                # ParserFactory + DeviceParser interface
│   ├── plugins/                      # Compliance plugins
│   │   ├── firewall/                 # Firewall compliance
│   │   ├── sans/                     # SANS compliance
│   │   └── stig/                     # STIG compliance
│   ├── pool/                         # Worker pool for concurrent processing
│   ├── processor/                    # Data processing and report generation
│   ├── progress/                     # CLI progress indicators (spinner, bar)
│   ├── sanitizer/                    # Data sanitization utilities
│   ├── schema/                       # Canonical OPNsense data model (XML structs)
│   ├── testing/                      # Shared test helpers
│   └── validator/                    # Data validation
├── tools/                            # Standalone development tools
│   └── docgen/                       # Model documentation generator
├── testdata/                         # Test data and fixtures
├── docs/                             # Documentation
├── project_spec/                     # Project specifications
│   ├── requirements.md               # Requirements specification
│   ├── tasks.md                      # Implementation tasks
│   └── user_stories.md               # User stories
├── go.mod / go.sum                   # Go modules
├── justfile                          # Task runner
└── main.go                           # Entry point
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

```go
// Always wrap errors with context using %w
if err := validateConfig(config); err != nil {
return nil, fmt.Errorf("config validation failed: %w", err)
}

// Use errors.Is() and errors.As() for checking
var parseErr *ParseError
if errors.As(err, &parseErr) {
// Handle parse-specific error
}

// Create domain-specific error types
type ParseError struct {
Message string
Line    int
}

func (e *ParseError) Error() string {
return fmt.Sprintf("parse error at line %d: %s", e.Line, e.Message)
}
```

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

```go
// Package parser provides functionality for parsing OPNsense configuration files.
package parser

// ParseConfig reads and parses an OPNsense configuration file.
// It returns a structured representation or an error if parsing fails.
func ParseConfig(filename string) (*Config, error) {
  // implementation
}
```

- Start comments with the name of the thing being described
- Use complete sentences
- Include examples for complex functionality

### 5.5 Import Organization

```go
import (
// Standard library
"fmt"
"os"

// Third-party
"github.com/spf13/cobra"

// Internal
"github.com/project/internal/cfgparser"
)
```

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

### 5.6a Struct Shallow Copy with Slices

`normalized := *cfg` copies the struct but slices share backing arrays. Deep-copy any slice you intend to mutate:

```go
normalized := *cfg
if cfg.Filter.Rule != nil {
    normalized.Filter.Rule = make([]model.Rule, len(cfg.Filter.Rule))
    copy(normalized.Filter.Rule, cfg.Filter.Rule)
}
```

### 5.7 CommandContext Pattern (CLI Dependency Injection)

The `cmd` package uses `CommandContext` to inject dependencies into subcommands:

```go
// cmd/context.go - CommandContext encapsulates command dependencies
type CommandContext struct {
    Config *config.Config
    Logger *log.Logger
}

// Access in subcommands via:
cmdCtx := GetCommandContext(cmd)
if cmdCtx == nil {
    return errors.New("command context not initialized")
}
logger := cmdCtx.Logger
config := cmdCtx.Config
```

**Key points:**

- `PersistentPreRunE` in `root.go` creates and sets the context after config loading
- Flag variables remain package-level (required by Cobra's binding mechanism)
- Config and logger are unexported (`cfg`, `logger`) - accessed only via `CommandContext`
- Use `GetCommandContext()` for safe access and handle the nil case explicitly

**Pattern benefits:**

- Explicit dependency injection (not hidden global state)
- Testable: create mock `CommandContext` in tests
- Type-safe context key avoids collisions

### 5.8 Context Key Types

Always use typed context keys to avoid `revive` linter `context-keys-type` warnings:

```go
// Good - typed key
type contextKey string
const myKey contextKey = "myValue"
ctx = context.WithValue(ctx, myKey, value)

// Bad - raw string (linter warning)
ctx = context.WithValue(ctx, "myKey", value)
```

### 5.9 Streaming Interface Pattern

When adding `io.Writer` support alongside string-based APIs:

- Create a separate interface (e.g., `SectionWriter`) that the builder implements
- Add a `Streaming*` interface that embeds the base interface (e.g., `StreamingGenerator` embeds `Generator`)
- Keep string-based methods for cases needing further processing (HTML conversion)
- See `internal/converter/builder/writer.go` and `internal/converter/hybrid_generator.go`

### 5.10 Common Linter Patterns

Frequently encountered linter issues and fixes:

| Linter                     | Issue                         | Fix                                                                                                               |
| -------------------------- | ----------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `gocritic emptyStringTest` | `len(s) == 0`                 | Use `s == ""`                                                                                                     |
| `gosec G115`               | Integer overflow on int→int32 | Add `//nolint:gosec` with bounded value comment                                                                   |
| `mnd`                      | Magic numbers                 | Create named constants                                                                                            |
| `minmax`                   | Manual min/max comparisons    | Use `min()`/`max()` builtins                                                                                      |
| `goconst`                  | Repeated string literals      | Extract to package-level constants                                                                                |
| `tparallel`                | Subtests use `t.Parallel()`   | Parent test must also call `t.Parallel()`                                                                         |
| `revive redefines-builtin` | Package name shadows stdlib   | Rename package (e.g., `log` → `logging`)                                                                          |
| `revive stutters`          | `pkg.PkgThing` repeats name   | Drop prefix: `compliance.Plugin` not `compliance.CompliancePlugin`                                                |
| `modernize`                | `omitempty` on struct fields  | Remove `omitempty` from JSON tags on struct-typed fields (no effect in `encoding/json`); YAML `omitempty` is fine |

> [!NOTE]
> IDE diagnostics (marked with ★ in some editors) are suggestions, not errors. The authoritative source is `just lint` - if it reports "0 issues", the code is correct regardless of IDE warnings.

### 5.11 Terminal Output Styling

When using Lipgloss/charmbracelet styling in CLI commands:

- Create a shared `useStylesCheck()` helper that checks `TERM != "dumb"` and `NO_COLOR == ""`
- Define terminal constants (`termEnvVar`, `noColorEnvVar`, `termDumb`) to avoid goconst issues
- Provide plain text fallback functions (e.g., `outputConfigPlain()`) for CI/automation
- **All lists must be sorted for deterministic output** — use `slices.Sort()`, `slices.Sorted(maps.Keys())`, or `sort.Strings()` on any slice derived from maps, config iteration, or aggregation before rendering, comparing, or serializing. Non-deterministic order causes flaky tests, unstable golden files, and inconsistent CLI output

Example pattern:

```go
const (
    termEnvVar    = "TERM"
    noColorEnvVar = "NO_COLOR"
    termDumb      = "dumb"
)

func useStylesCheck() bool {
    return os.Getenv(termEnvVar) != termDumb && os.Getenv(noColorEnvVar) == ""
}
```

### 5.12 String Comparison Patterns

- `strings.EqualFold(a, b)` - Case-insensitive comparison, no need to call `strings.ToLower()` first
- For case-insensitive enum validation, iterate with `EqualFold` directly on original value

### 5.13 Standalone Tools Pattern

Place standalone development tools in `tools/<name>/main.go` with `//go:build ignore`:

- Tools are independent from main build (won't break if dependencies differ)
- Some code duplication is acceptable for tool independence
- Run via `go run tools/<name>/main.go` or justfile targets
- Example: `tools/docgen/main.go` generates model documentation

### 5.14 Markdown Generation (`nao1215/markdown`)

Use `nao1215/markdown` for programmatic markdown generation in `internal/converter/builder/`. Prefer library methods over manual string construction.

**Method chaining - Use fluent builder pattern:**

```go
// Idiomatic - chain methods and terminate with Build()
md.NewMarkdown(os.Stdout).
    H1("Report Title").
    PlainText("Introduction paragraph").
    H2("Section").
    BulletList("Item 1", "Item 2").
    Table(tableSet).
    Build()

// Alternative - use String() when capturing output
var buf bytes.Buffer
md := markdown.NewMarkdown(&buf)
md.H1("Title").
    PlainText(markdown.Italic("subtitle")).
    Table(data)
return md.String()
```

**Lists - Use `BulletList()` with `Link()` helper:**

```go
// Good - idiomatic
md.BulletList(
    markdown.Link("System Configuration", "#system-configuration"),
    markdown.Link("Interfaces", "#interfaces"),
)

// Bad - manual construction
md.PlainText("- [System Configuration](#system-configuration)")
md.PlainText("- [Interfaces](#interfaces)")
```

**Alerts - Use semantic alert methods:**

```go
// Good - renders as GitHub-flavored markdown alert
md.Warning("NAT reflection is enabled, which may expose internal services.")
md.Note("Phase 1/Phase 2 tunnels require additional configuration.")
md.Tip("Consider enabling hardware offloading for better performance.")
md.Caution("This action cannot be undone.")

// Bad - manual formatting
md.PlainText("**⚠️ Warning**: NAT reflection is enabled...")
md.PlainText("*Note: Phase 1/Phase 2 tunnels require...*")
```

**Text formatting - Use helper functions:**

```go
// Good
md.PlainText(markdown.Italic("No VLANs configured"))
md.PlainTextf("Status: %s", markdown.Bold("Active"))
linkText := markdown.Link("documentation", "https://example.com")

// Bad
md.PlainText("*No VLANs configured*")
md.PlainText("Status: **Active**")
```

**Available methods reference:**

| Method                     | Purpose         | Output           |
| -------------------------- | --------------- | ---------------- |
| `BulletList(items...)`     | Unordered list  | `- item`         |
| `OrderedList(items...)`    | Numbered list   | `1. item`        |
| `Warning(text)`            | Warning alert   | `> [!WARNING]`   |
| `Note(text)`               | Note alert      | `> [!NOTE]`      |
| `Tip(text)`                | Tip alert       | `> [!TIP]`       |
| `Caution(text)`            | Caution alert   | `> [!CAUTION]`   |
| `Important(text)`          | Important alert | `> [!IMPORTANT]` |
| `Details(summary, text)`   | Collapsible     | `<details>`      |
| `HorizontalRule()`         | Separator       | `---`            |
| `markdown.Link(text, url)` | Hyperlink       | `[text](url)`    |
| `markdown.Bold(text)`      | Bold text       | `**text**`       |
| `markdown.Italic(text)`    | Italic text     | `*text*`         |
| `markdown.Code(text)`      | Inline code     | `` `text` ``     |

**Inline tables - Chain with headers:**

```go
// Good - chain table with header
md.H4("Section Title").
    Table(markdown.TableSet{
        Header: []string{"Col1", "Col2"},
        Rows:   rows,
    })

// Bad - separate calls break the chain
md.H4("Section Title")
md.Table(markdown.TableSet{...})
```

### 5.15 Slice Pre-allocation

- Use `make([]T, 0)` without capacity hints for small, variable-length slices
- Only add capacity hints when the capacity value is reused elsewhere or performance-critical
- Avoid creating constants solely for capacity hints (adds maintenance burden)

### 5.16 Unused Code Guidance

When code becomes unused during refactoring:

- **Remove it** rather than suppressing linter warnings with `//nolint:unused`
- Unused code adds maintenance burden and confuses future readers
- If the code might be needed later, rely on version control history
- This includes helper functions, test utilities, and constants
- **Type aliases and re-exported constants**: Before removing, grep the entire codebase for external references (e.g., `grep -r 'pkg.AliasName'`). The `internal/model/` re-export layer and `cmd/` package frequently reference aliases from internal packages.

### 5.17 File Write Safety

When writing to output files:

- Call `file.Sync()` before `Close()` to ensure data is flushed to disk
- Handle close errors for write operations (data could be lost)
- Pattern:

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

### 5.18 Comparison Function Patterns

When writing functions that compare two structs:

- Always handle nil inputs at the start of comparison functions
- Use `slices.Equal()` for comparing slice fields (not manual iteration)
- Pattern for nil-safe comparisons:

```go
func CompareItems(old, new *Item) []Change {
    if old == nil && new == nil {
        return nil
    }
    if old == nil {
        return []Change{{Type: ChangeAdded, Description: "Item added"}}
    }
    if new == nil {
        return []Change{{Type: ChangeRemoved, Description: "Item removed"}}
    }
    // Compare fields...
}
```

- For map-like types with `Get()` methods, check return signature: many return `(value, bool)` not `(value, error)`

### 5.19 Stats Tracking Pattern

When a helper function updates stats and may be called multiple times for fallback logic:

```go
// Bad - stats incremented twice if first call skips
result := s.process(pathA, value)  // increments stats
if result == value {
    result = s.process(pathB, value)  // increments stats again
}

// Good - check first, update stats once
should, rule := s.shouldProcess(pathA, value)
if !should {
    should, rule = s.shouldProcess(pathB, value)
}
if should {
    stats.Processed++
    result = s.doProcess(value, rule)
} else {
    stats.Skipped++
}
```

### 5.20 XML Escaping

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

### 5.21 XML Element Presence Detection

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

### 5.22 Context-Aware Semaphore

When acquiring semaphores in goroutines, use select with context:

```go
// Bad - blocks indefinitely on context cancel
sem <- struct{}{}
defer func() { <-sem }()

// Good - respects context cancellation
select {
case sem <- struct{}{}:
    defer func() { <-sem }()
case <-ctx.Done():
    return ctx.Err()
}
```

### 5.23 Goroutine Stop/Write Safety

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

### 5.24 Dual Validator Synchronization

`internal/processor/validate.go` maintains lightweight validation whitelists (powerd modes, optimization values, etc.) that must stay in sync with the authoritative `internal/validator/opnsense.go`. When updating allowed values in either package, grep for the same whitelist in the other and update both.

---

## 6. Data Processing Standards

### 6.1 Data Models

- **OpnSenseDocument**: Core data model representing entire OPNsense configuration
- **XML Tags**: Must strictly follow OPNsense configuration file structure
- **JSON/YAML Tags**: Follow recommended best practices for each format
- **Audit Models**: Create separate structs (`Finding`, `Target`, `Exposure`) for audit concepts

**Architecture notes:**

- `internal/schema/` is the canonical data model; `internal/model/` is a re-export layer (type aliases + constructor wrappers)
- OPNsense XML uses two boolean patterns: **presence-based** (`<disabled/>` → `BoolFlag`) and **value-based** (`<enable>1</enable>` → `string`). See §5.21 and `docs/development/xml-structure-research.md`
- `RuleLocation` in `common.go` has complete source/destination fields but is NOT used by `Source`/`Destination` in `security.go` — tracked in issue #255
- Known schema gaps: ~40+ type mismatches and missing fields — see `docs/development/xml-structure-research.md` §4-5

**Platform-agnostic model layer:**

- `internal/model/common/` contains device-agnostic types (firewall rules, VPN, system, network, etc.)
- `revive` var-naming exclusion for this path is configured in `.golangci.yml`
- JSON struct tags on nested struct fields must NOT use `omitempty` (Go 1.26+ modernize check)

**Converter enrichment pipeline:**

- `prepareForExport()` in `internal/converter/enrichment.go` is the single gate for all JSON/YAML exports
- It populates `Statistics`, `Analysis`, `SecurityAssessment`, and `PerformanceMetrics` on a shallow copy
- Cannot import `internal/processor` (circular dependency) — analysis/statistics logic is mirrored, not shared
- New `CommonDevice` enrichment fields must be wired here to appear in JSON/YAML output

**Port field disambiguation:**

- `Source.Port` → `<source><port>...</port></source>` (nested, preferred)
- `Rule.SourcePort` → `<sourceport>...</sourceport>` (top-level, legacy)
- Prefer `Source.Port` with fallback to `Rule.SourcePort` for backward compatibility

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

Each report generator should be a **self-contained Go module** that can be included or excluded via build flags. This architecture enables Pro-level features and independent development of report types.

**What Each Report Module Should Contain:**

- All generation logic (markdown construction, section building)
- All calculation logic (security scoring, risk assessment, statistics)
- All data transformations specific to that report type
- Report-specific constants and mappings

**What Should Remain Shared:**

- `model.OpnSenseDocument` - The parsed configuration model
- Shared helpers (string formatting, markdown escaping, table building)
- Common interfaces (`ReportBuilder`, `Generator`)

**Build Flag Integration:**

```go
//go:build pro

package reports

// Pro-level report generators included only with -tags=pro
```

**Implementation Pattern:**

```go
// Each report module is self-contained
type BlueTeamGenerator struct {
    // All state for blue team reports
}

func (g *BlueTeamGenerator) Generate(doc *model.OpnSenseDocument) (string, error) {
    // Uses only model and shared helpers
    // All calculations are internal to this module
    score := g.calculateSecurityScore(doc)  // Internal method
    findings := g.analyzeCompliance(doc)    // Internal method
    return g.buildReport(doc, score, findings)
}
```

See [Architecture Documentation](docs/development/architecture.md#modular-report-generator-architecture) for detailed design.

---

## 7. Testing Standards

### 7.1 Test Organization

```go
func TestParseConfig_ValidXML_ReturnsConfig(t *testing.T) {
tests := []struct {
name    string
input   string
want    *Config
wantErr bool
}{
{
name:    "valid config",
input:   "<opnsense>...</opnsense>",
want:    &Config{},
wantErr: false,
},
}

for _, tt := range tests {
t.Run(tt.name, func (t *testing.T) {
got, err := ParseConfig(tt.input)
if (err != nil) != tt.wantErr {
t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
}
})
}
}
```

### 7.2 Test Requirements

| Requirement       | Target                       |
| ----------------- | ---------------------------- |
| Coverage          | >80%                         |
| Speed             | \<100ms per test             |
| Race detection    | `go test -race`              |
| Integration tests | `//go:build integration` tag |

### 7.3 Test Helpers

```go
func setupTestConfig(t *testing.T) *Config {
t.Helper()
return &Config{InputFile: "testdata/config.xml"}
}

func createTempFile(t *testing.T, content string) string {
t.Helper()
// implementation with t.Cleanup()
}
```

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

| File                                | Purpose                                          |
| ----------------------------------- | ------------------------------------------------ |
| `internal/compliance/interfaces.go` | `Plugin` interface, `Control`, `Finding` structs |
| `internal/audit/plugin.go`          | `PluginRegistry`, dynamic plugin loader          |
| `internal/audit/plugin_manager.go`  | `PluginManager` for lifecycle operations         |
| `internal/plugins/`                 | Built-in plugin implementations                  |

### 8.2 Plugin Interface

All plugins must implement `compliance.Plugin`:

```go
type Plugin interface {
Name() string
Version() string
Description() string
RunChecks(device *common.CommonDevice) []Finding
GetControls() []Control
GetControlByID(id string) (*Control, error)
ValidateConfiguration() error
}
```

### 8.3 Plugin Development

```go
import (
    "github.com/EvilBit-Labs/opnDossier/internal/compliance"
    "github.com/EvilBit-Labs/opnDossier/internal/model/common"
)

type Plugin struct {
controls []compliance.Control
}

func NewPlugin() *Plugin {
return &Plugin{controls: initControls()}
}

func (p *Plugin) RunChecks(device *common.CommonDevice) []compliance.Finding {
// Implement compliance checks
}
```

- Import `internal/model/common`, not `internal/model`
- Use consistent control naming: `PLUGIN-001`, `PLUGIN-002`
- Severity levels: `critical`, `high`, `medium`, `low`
- Dynamic plugins: export `var Plugin compliance.Plugin`

### 8.4 Compliance Standards

| Standard | Control Pattern | Location                     |
| -------- | --------------- | ---------------------------- |
| STIG     | `STIG-V-XXXXXX` | `internal/plugins/stig/`     |
| SANS     | `SANS-XXX`      | `internal/plugins/sans/`     |
| Firewall | `FIREWALL-XXX`  | `internal/plugins/firewall/` |

---

## 9. Commit Style

### 9.1 Conventional Commits

```text
<type>(<scope>): <description>
```

**Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`

**Scopes:** `(parser)`, `(converter)`, `(audit)`, `(cli)`, `(model)`, `(plugin)`, `(builder)`

### 9.2 Examples

```text
feat(parser): add support for OPNsense 24.1 config format
fix(converter): handle empty VLAN configurations gracefully
docs(readme): update installation instructions
feat(api)!: redesign plugin interface  # Breaking change
```

### 9.3 Rules

- Imperative mood ("add", not "added")
- No period at the end
- ≤72 characters, capitalized
- **Scope is required**
- Breaking changes: add `!` or use `BREAKING CHANGE:` in footer

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

# Go commands
go test ./...         # Run tests
go test -race ./...   # Race detection
go test -cover ./...  # Coverage
go mod tidy           # Clean dependencies
go mod verify         # Verify dependencies

# Modernization (Go 1.26+)
go run golang.org/x/tools/go/analysis/passes/modernize/cmd/modernize@latest -test -fix ./...
# Note: remove //go:fix inline directives afterward (conflicts with gocheckcompilerdirectives)
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

01. **Always run tests** after changes: `just test`
02. **Run linting** before committing: `just lint`
03. **Follow established patterns** in existing code
04. **Write comprehensive tests** for new functionality
05. **Include proper error handling** with context
06. **Add structured logging** for important operations
07. **Validate all inputs** and handle edge cases
08. **Document new functions and types** following Go conventions
09. **Never commit secrets** or hardcoded credentials
10. **Consult project documentation** before making changes
11. Prefer structured config data + audit overlays over flat summary tables
12. Validate markdown with `mdformat` and `markdownlint-cli2`
13. **CRITICAL: Tasks are NOT complete until `just ci-check` passes**
14. Place `//nolint:` directives on SEPARATE LINE above call (inline gets stripped by gofumpt)
15. **Fix pre-existing issues** encountered during work (race conditions, bugs, etc.) — do not dismiss them as "not our problem"

### 12.2 Code Review Checklist

- [ ] Code follows Go formatting (`gofmt`)
- [ ] Linting issues resolved (`golangci-lint`)
- [ ] Tests pass (`go test ./...`)
- [ ] Error handling includes context
- [ ] Structured logging used appropriately
- [ ] No hardcoded secrets
- [ ] Input validation implemented
- [ ] Documentation updated
- [ ] Dependencies managed (`go mod tidy`)
- [ ] Follows established patterns
- [ ] Requirements compliance verified
- [ ] Architecture patterns followed

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

## 13. Documentation Standards

### 13.1 Writing Style

- **Concise**: Prefer clear explanations over verbose descriptions
- **Consistent**: Maintain consistent style across all files
- **Clear**: Use direct language that avoids ambiguity

### 13.2 Formatting

- Standard markdown formatting
- Consistent heading hierarchy (H1 → H2 → H3)
- Proper syntax highlighting for code blocks
- Descriptive link text

### 13.3 Validation

```bash
just format                     # Format markdown
markdownlint **/*.md           # Validate syntax
just ci-check                  # Comprehensive checks
```

---

## 14. Requirements Management

### 14.1 Document Relationships

| Document          | Purpose                          |
| ----------------- | -------------------------------- |
| `requirements.md` | WHAT the system must do          |
| `tasks.md`        | HOW to implement requirements    |
| `user_stories.md` | WHY requirements matter to users |

### 14.2 Task Structure

```markdown
- [ ] **TASK-###**: Task Title
  - **Context**: Why this task is needed
  - **Requirement**: F###
  - **User Story**: US-###
  - **Action**: Implementation steps
  - **Acceptance**: Completion criteria
```

### 14.3 Task States

| Symbol | State       |
| ------ | ----------- |
| `[ ]`  | Not started |
| `[-]`  | In progress |
| `[x]`  | Completed   |

---

## 15. CLI Usage Examples

```bash
# Convert configurations
./opndossier convert config.xml --format markdown
./opndossier convert config.xml --format json -o output.json
./opndossier convert config.xml --format yaml --force

# Display configuration
./opndossier display config.xml

# Validate configuration
./opndossier validate config.xml
```

## 16. Open-Source Quality Standards (OSSF Best Practices)

This project has the OSSF Best Practices passing badge. Maintain these standards:

### 16.1 Every PR Must

- Sign off commits with `git commit -s` (DCO enforced by GitHub App)
- Pass CI (golangci-lint, gofumpt, tests, CodeQL, Grype) before merge
- Include tests for new functionality -- this is policy, not optional
- Be reviewed (human or CodeRabbit) for correctness, safety, and style
- Not introduce `panic()` in library code, unchecked errors, or unvalidated input

### 16.2 Every Release Must

- Have human-readable release notes via git-cliff (not raw git log)
- Use unique SemVer identifiers (`vX.Y.Z` tags)
- Be built reproducibly (pinned toolchain, committed `go.sum`, GoReleaser)

### 16.3 Security

- Vulnerabilities go through private reporting (GitHub advisories or <support@evilbitlabs.io>), never public issues
- Grype and Snyk run in CI -- fix findings promptly
- Medium+ severity vulnerabilities: we aim to release a fix within 90 days of confirmation (see SECURITY.md for canonical policy)
- `docs/security/vulnerability-scanning.md` documents scanning thresholds and remediation process
- `docs/security/security-assurance.md` must be updated when new attack surface is introduced

### 16.4 Documentation

- Exported APIs require godoc comments with examples where appropriate
- CONTRIBUTING.md documents code review criteria, test policy, DCO, and governance
- SECURITY.md documents vulnerability reporting with scope, safe harbor, and PGP key
- AGENTS.md must accurately reflect implemented features (not aspirational)
- `docs/security/security-assurance.md` documents threat model, design principles, and CWE countermeasures
