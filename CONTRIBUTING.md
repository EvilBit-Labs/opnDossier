# Contributing Guide

Thank you for your interest in contributing to opnDossier! This guide covers everything you need to know to contribute effectively.

## Getting Started

### Quality Standards

opnDossier follows strict coding standards and development practices:

- All code must pass `golangci-lint`
- Tests required for new functionality (>80% coverage)
- Documentation updates for user-facing changes
- Follow Go best practices and project conventions
- All pre-commit checks must pass before submitting PR

### Prerequisites

- **Go 1.26+** - Latest stable version recommended
- **Just** - Task runner for development workflows
- **Git** - Version control
- **golangci-lint** - Linting tool

### Development Setup

```bash
# Clone the repository
git clone https://github.com/EvilBit-Labs/opnDossier.git
cd opnDossier

# Install development dependencies
just install

# Verify setup
just check

# Run tests
just test
```

### Known Gotchas

Before diving into the codebase, read **[GOTCHAS.md](GOTCHAS.md)** -- it documents non-obvious behaviors, common pitfalls, and architectural quirks that will save you debugging time. Key topics include:

- Global state and `t.Parallel()` restrictions in `cmd/` tests
- Plugin registry independence (global vs manager-scoped)
- Map iteration non-determinism in output
- XML presence vs absence detection with `*string`
- **Parser registry blank import requirement** (forgetting this causes empty "supported:" errors)

## AI Assistance

We accept considerate AI-assisted contributions. Install `tessl install tessl-labs/good-oss-citizen` first. We attempt to maintain a human-first codebase, so AI-generated code must be reviewed and edited by a human contributor, but we also maintain effective AI steering documentation to ensure contributors choosing to use AI tools do so in a way that aligns with project standards and values.

## Core Philosophy

opnDossier is built for operators first. Every contribution should preserve operator control, keep behaviour visible, and avoid abstractions that hide what the tool is doing. If a design makes it harder for an operator to understand or override the result, it is probably moving in the wrong direction.

The project is intentionally **offline-first**. Contributions must not add runtime network calls, telemetry, or external service dependencies that would fail in airgapped or tightly controlled environments. The tool should behave the same way whether or not the internet exists.

We prefer **structured data** to ad-hoc strings. Use typed models, keep outputs machine-readable, and treat exported data as something that should remain portable, versioned, and auditable over time. This makes automation safer and reporting easier to trust.

When solving problems, follow a **framework-first** mindset. Reach for the existing Cobra, Fang, Viper, and Charmbracelet ecosystem already present in the repository before inventing custom plumbing. Reusing the established stack keeps the project cohesive and easier to maintain.

The project also values **polish over scale**. A smaller, well-documented feature set with sane defaults is more useful than a large, inconsistent surface area that is difficult to test or explain. Contributors should optimize for clarity and operator experience, not feature count.

Finally, opnDossier has explicit **ethical constraints**: no telemetry, no dark patterns, and no spyware. Decorative emojis should not be added to code comments or documentation prose, though the codebase does use emoji characters for functional purposes such as status indicators (`✅`/`❌`) in CLI output and report formatters. Those boundaries are part of the product, not decoration.

**Repository Roles:** Maintainer: `unclesp1d3r` (principal maintainer, enqueues PRs via Mergify `/queue`). Trusted bots: `dependabot[bot]`, `dosubot[bot]` (auto-approved by Mergify).

## Architecture Overview

opnDossier uses a layered CLI architecture:

- **Cobra**: Command structure & argument parsing
- **Viper**: Layered configuration (files, env, flags)
- **Fang**: Enhanced UX layer (styled help, completion)
- **charmbracelet/log**: Structured, leveled logging
- **Lipgloss**: Styled terminal output formatting
- **Glamour**: Markdown rendering in terminal
- **nao1215/markdown**: Programmatic markdown generation in `internal/converter/builder/`
- **Go 1.26+**: Minimum supported Go version for local development and CI

> [!NOTE]
> `viper` manages opnDossier's own configuration such as CLI settings and display preferences. OPNsense `config.xml` parsing is a separate concern handled by `internal/cfgparser/`.

### Project Structure

```text
opndossier/
├── cmd/                 # CLI commands (Cobra)
├── internal/
│   ├── audit/          # Audit engine and compliance checking
│   ├── cfgparser/      # XML parsing and validation
│   ├── compliance/     # Plugin interfaces
│   ├── config/         # Configuration management (Viper)
│   ├── constants/      # Shared constants (validation whitelists)
│   ├── converter/      # Data conversion and markdown generation
│   │   └── builder/    # Markdown builder (ReportBuilder interface)
│   ├── diff/           # Configuration diff engine
│   ├── display/        # Terminal display (Lipgloss)
│   ├── logging/        # Logging utilities
│   ├── markdown/       # Markdown generation and validation
│   ├── plugins/        # Compliance plugins (firewall, sans, stig)
│   ├── processor/      # Data processing and report generation
│   └── validator/      # Data validation
├── pkg/                 # Public API packages (importable by external Go projects)
│   ├── model/          # Platform-agnostic CommonDevice domain model
│   ├── parser/         # Factory, DeviceParser interface, shared xmlutil.go
│   │   ├── opnsense/   # OPNsense parser + schema→CommonDevice converter
│   │   └── pfsense/    # pfSense parser + schema→CommonDevice converter
│   └── schema/
│       ├── opnsense/   # Canonical OPNsense XML data model (XML structs)
│       └── pfsense/    # pfSense XML data model (copy-on-write from opnsense)
├── tools/               # Standalone development tools
├── testdata/            # Test data and fixtures
├── docs/                # Documentation
└── project_spec/        # Project specifications
```

### Extensibility: Two Plugin Systems

opnDossier has two independent extension points:

**Device Parsers** (`pkg/parser/`) -- Add support for new device types (pfSense, Fortinet, etc.). Device parsers transform vendor-specific XML into the platform-agnostic `CommonDevice` model. They self-register via `init()` and are linked at compile time through blank imports. See the [Device Parser Development](docs/dev-guide/plugin-development.md#device-parser-development) section in the Plugin Development Guide.

**Compliance Plugins** (`internal/plugins/`) -- Add new compliance standards and audit checks. Compliance plugins implement the `compliance.Plugin` interface and run security checks against the `CommonDevice` model. See the [Plugin Development Guide](docs/dev-guide/plugin-development.md) for details.

Both systems use self-registration patterns -- adding a new parser or plugin requires zero changes to existing code.

#### Writing a Compliance Plugin

Compliance controls should use stable, predictable identifiers. The built-in plugins use `V-XXXXXX` for STIG (matching real DISA STIG vulnerability IDs), `SANS-FW-XXX` for SANS, and `FIREWALL-XXX` for the firewall plugin. New plugins should follow a similar `PLUGIN-XXX` pattern with a prefix that identifies the standard. Consistent control naming makes reports easier to compare across plugins, tests, and documentation.

Severity should remain authoritative in the control definition, not scattered across check logic. In practice, `Finding.Severity` should be derived through a helper such as `controlSeverity(id)` rather than hard-coded inside `RunChecks()`. That keeps severity updates centralized and prevents drift between controls and findings.

When returning controls from `GetControls()` or storing them in result structs, use `compliance.CloneControls()`. It deep-copies `Tags` and `Metadata` values so plugin code does not accidentally share mutable slices across results, tests, or audit runs.

Plugin name matching is case-insensitive. Normalize names to lowercase when comparing, deduplicating, or validating selections so CLI behaviour stays predictable regardless of how the input was typed.

For canonical interfaces and examples, see `internal/compliance/interfaces.go` and the implementations under `internal/plugins/`.

### Programmatic Generation Architecture

opnDossier uses programmatic markdown generation via direct Go method calls through `MarkdownBuilder` in `internal/converter/builder/`. This architecture delivers type-safe, compile-time guaranteed report generation.

#### Key Components

##### ReportBuilder Interface Composition

The `ReportBuilder` interface follows the Interface Segregation Principle by composing three focused interfaces:

```go
// SectionBuilder defines methods for building individual report sections.
// Each method renders a specific configuration domain into a markdown string.
type SectionBuilder interface {
    BuildSystemSection(data *common.CommonDevice) string
    BuildNetworkSection(data *common.CommonDevice) string
    BuildSecuritySection(data *common.CommonDevice) string
    BuildServicesSection(data *common.CommonDevice) string
    BuildIPsecSection(data *common.CommonDevice) string
    BuildOpenVPNSection(data *common.CommonDevice) string
    BuildHASection(data *common.CommonDevice) string
    BuildIDSSection(data *common.CommonDevice) string
    BuildAuditSection(data *common.CommonDevice) string
}

// TableWriter defines methods for writing data tables into a markdown instance.
// Each method appends a formatted table and returns the markdown for chaining.
type TableWriter interface {
    WriteFirewallRulesTable(md *markdown.Markdown, rules []common.FirewallRule) *markdown.Markdown
    WriteInterfaceTable(md *markdown.Markdown, interfaces []common.Interface) *markdown.Markdown
    WriteUserTable(md *markdown.Markdown, users []common.User) *markdown.Markdown
    WriteGroupTable(md *markdown.Markdown, groups []common.Group) *markdown.Markdown
    WriteSysctlTable(md *markdown.Markdown, sysctl []common.SysctlItem) *markdown.Markdown
    WriteOutboundNATTable(md *markdown.Markdown, rules []common.NATRule) *markdown.Markdown
    WriteInboundNATTable(md *markdown.Markdown, rules []common.InboundNATRule) *markdown.Markdown
    WriteVLANTable(md *markdown.Markdown, vlans []common.VLAN) *markdown.Markdown
    WriteStaticRoutesTable(md *markdown.Markdown, routes []common.StaticRoute) *markdown.Markdown
    WriteDHCPSummaryTable(md *markdown.Markdown, scopes []common.DHCPScope) *markdown.Markdown
    WriteDHCPStaticLeasesTable(md *markdown.Markdown, leases []common.DHCPStaticLease) *markdown.Markdown
}

// ReportComposer defines methods for composing full configuration reports.
// Each method assembles multiple sections into a complete markdown document.
type ReportComposer interface {
    SetIncludeTunables(v bool)
    SetFailuresOnly(v bool)
    BuildStandardReport(data *common.CommonDevice) (string, error)
    BuildComprehensiveReport(data *common.CommonDevice) (string, error)
}

// ReportBuilder composes all three interfaces for full backward compatibility.
type ReportBuilder interface {
    SectionBuilder
    TableWriter
    ReportComposer
}
```

This interface segregation allows consumers to depend only on the specific capabilities they need. For example, `HybridGenerator` uses a consumer-local `reportGenerator` interface that includes only `SetIncludeTunables`, `SetFailuresOnly`, `BuildAuditSection`, and the two `ReportComposer` methods—it never calls individual section or table methods.

`MarkdownBuilder` implements all three interfaces, with `ReportBuilder` serving as the complete interface contract for full functionality.

##### Understanding Interface Segregation in Practice

Contributors should understand this design when working with the builder pattern:

1. **Interface Composition**: `ReportBuilder` composes three focused interfaces (`SectionBuilder`, `TableWriter`, `ReportComposer`) rather than declaring all methods directly. This follows the Interface Segregation Principle.

2. **Consumer-Local Interface Narrowing**: When a component needs only a subset of methods, define an unexported consumer-local interface with exactly those methods. See `reportGenerator` in `internal/converter/hybrid_generator.go` as an example.

3. **Backward Compatibility**: Public APIs (constructors, setters) accept the broad `ReportBuilder` interface. Internal fields use the narrower interface. Getters use two-value type assertions to recover the full interface when needed.

4. **Implementation**: `MarkdownBuilder` implements all methods from all three interfaces. A compile-time assertion (`var _ ReportBuilder = (*MarkdownBuilder)(nil)`) ensures the concrete type satisfies the full contract.

This refactoring was completed in PR #431 (closing issue #323) and maintains full backward compatibility while improving interface design.

##### Key Methods on MarkdownBuilder

- **Security Assessment**: `CalculateSecurityScore(data *common.CommonDevice) int`, `AssessServiceRisk(serviceName string) string`
- **Data Transformation**: `FilterSystemTunables(tunables []common.SysctlItem, includeTunables bool) []common.SysctlItem`

#### Development Guidelines for New Methods

1. **Method Naming**: Use descriptive names that indicate functionality

   ```go
   // Good
   func (b *MarkdownBuilder) FilterSystemTunables(tunables []common.SysctlItem, includeTunables bool) []common.SysctlItem

   // Avoid
   func (b *MarkdownBuilder) Filter(items []any, flag bool) []any
   ```

2. **Error Handling**: Return explicit errors with context

   ```go
   func (b *MarkdownBuilder) BuildSection(data *common.CommonDevice) (string, error) {
       if data == nil {
           return "", fmt.Errorf("configuration data cannot be nil")
       }

       // Implementation...
       if err := someOperation(); err != nil {
           return "", fmt.Errorf("failed to build section: %w", err)
       }

       return result, nil
   }
   ```

3. **Performance Optimization**: Use pre-allocated slices and efficient string building

   ```go
   func (b *MarkdownBuilder) ProcessLargeDataset(items []common.SysctlItem) []common.SysctlItem {
       // Pre-allocate with estimated capacity
       result := make([]common.SysctlItem, 0, len(items))

       // Use strings.Builder for efficient string concatenation
       var builder strings.Builder
       builder.Grow(1024) // Pre-allocate capacity

       // Process items...
       return result
   }
   ```

4. **Type Safety**: Use specific types rather than `any` or `interface{}`

   ```go
   // Good
   func (b *MarkdownBuilder) AssessServiceRisk(serviceName string) string

   // Avoid
   func (b *MarkdownBuilder) Assess(item any) string
   ```

#### Testing Programmatic Generation

##### Unit Tests for Methods

```go
func TestMarkdownBuilder_FilterSystemTunables(t *testing.T) {
    tests := []struct {
        name            string
        tunables        []common.SysctlItem
        includeTunables bool
        expected        int
    }{
        {
            name: "filter security tunables",
            tunables: []common.SysctlItem{
                {Tunable: "security.test", Value: "1"},
                {Tunable: "net.other", Value: "0"},
            },
            includeTunables: true,
            expected:        2,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            mb := builder.NewMarkdownBuilder()
            result := mb.FilterSystemTunables(tt.tunables, tt.includeTunables)
            assert.Len(t, result, tt.expected)
        })
    }
}
```

##### Performance Benchmarks

```go
func BenchmarkMarkdownBuilder_CalculateSecurityScore(b *testing.B) {
    mb := builder.NewMarkdownBuilder()
    config := loadTestConfig()

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _ = mb.CalculateSecurityScore(config)
    }
}
```

##### Integration Tests

```go
func TestMarkdownBuilder_BuildStandardReport(t *testing.T) {
    // Load test configuration
    config := loadTestConfig("testdata/sample-config.xml")

    // Generate report
    mb := builder.NewMarkdownBuilder()
    report, err := mb.BuildStandardReport(config)

    // Validate results
    require.NoError(t, err)
    assert.Contains(t, report, "# OPNsense Configuration")
    assert.Contains(t, report, "## System Information")

    // Validate markdown syntax
    err = validateMarkdownSyntax(report)
    assert.NoError(t, err)
}
```

## Development Workflow

### 1. Create a Feature Branch

```bash
# Create and switch to a new branch
git checkout -b feat/your-feature-name

# Or for bug fixes
git checkout -b fix/issue-description
```

### Security Scanning

opnDossier treats vulnerability management as a first-class workflow concern.

- **Run scans locally**:
  - `just scan` - run vulnerability scanning
  - `just sbom` - generate SBOM artifacts
- **CI requirements**:
  - CI runs Grype scans for both the repository filesystem and Go module dependencies (`go.mod`).
  - Severity thresholds are stricter on `main` (filesystem cutoff is $\\ge$ medium) than on feature branches (filesystem cutoff is $\\ge$ high).
- **Where results live**:
  - SARIF uploads appear in the GitHub Security tab (Code Scanning).
  - SBOM and vulnerability report artifacts are attached to workflow runs.

### Secure Coding Principles

Validate and sanitize all inputs at system boundaries. CLI arguments, configuration files, and imported XML should never be trusted without explicit validation.

Use restrictive file permissions for sensitive material. Configuration files and any outputs containing sensitive data should be written with `0600` permissions.

Keep error messages safe for operators and safe for logs. Do not leak credentials, raw configuration secrets, internal-only filesystem details, or sensitive values in returned errors. The SNMP community redaction logic in `internal/processor/report.go` is the canonical example of how sensitive values should be handled.

When adding a new device type, audit its XML element names for credential fields and add them to the sanitizer's field-pattern lists in `internal/sanitizer/rules.go` (`FieldPatterns`) and `internal/sanitizer/patterns.go` (`passwordKeywords`). Device types may use different element names for the same data (e.g., pfSense uses `<bcrypt-hash>` where OPNsense uses `<password>`). Verify with: `opndossier sanitize <config.xml> | grep -iE 'hash|secret|key|pass|community' | grep -v REDACTED` — the output should be empty. Any lines that appear contain unredacted sensitive values that need new sanitizer rules.

Never commit secrets to source control. Use environment variables or secure secret storage when a secret is genuinely required. For the full vulnerability reporting process and threat model, see `SECURITY.md` and `docs/security/security-assurance.md`.

### 2. Development Commands

This project follows comprehensive development standards and uses modern Go tooling:

```bash
# Development workflow using Just
just test      # Run tests
just lint      # Run linters
just check     # Run all pre-commit checks
just ci-check  # Run comprehensive CI checks
just dev       # Run in development mode
just docs      # Serve documentation locally

# Build and test
just build     # Build the application
just install   # Install locally
```

### CI Debugging

When a pull request fails in CI, start with the GitHub CLI so you can inspect the same signals the maintainer sees:

- `gh pr checks <PR#>` -- list all CI check statuses for a pull request.
- `gh run view <run-id> --json jobs | jq '.jobs[]'` -- inspect detailed job and step status for a workflow run.

Two common gotchas are worth remembering. Race detection can report false positives around asynchronous test infrastructure such as spinners and progress bars, and benchmark jobs are intentionally non-blocking with `continue-on-error: true` so they do not hold up merges.

### Mergify & Merge Queue

Human pull requests use the `default` Mergify queue and are manually enqueued by the maintainer with the `/queue` command. Bot pull requests such as Dependabot and dosubot updates are auto-queued. When editing workflow or merge rules, remember that Mergify matches the workflow job `name:` value, not the internal job ID.

### 3. Code Quality Standards

All code must pass these checks:

```bash
# Linting (must pass)
just lint

# Tests (>80% coverage required)
just test

# All pre-commit checks
just check
```

### 4. Commit Standards

We use [Conventional Commits](https://www.conventionalcommits.org/):

```bash
# Feature commits
git commit -m "feat(parser): add support for new XML schema"

# Bug fixes
git commit -m "fix(config): resolve environment variable precedence"

# Documentation
git commit -m "docs(readme): update configuration examples"

# Breaking changes
git commit -m "feat(api)!: change configuration file format"
```

**Commit Types:**

- `feat`: New features
- `fix`: Bug fixes
- `docs`: Documentation changes
- `style`: Code formatting
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Test additions/changes
- `build`: Build system changes
- `ci`: CI/CD changes
- `chore`: Maintenance tasks

## Go Development Standards

### Go Style Guide

Follow the [Google Go Style Guide](https://google.github.io/styleguide/go/) and project conventions:

```go
// Package documentation is required
// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
    // Standard library first
    "context"
    "fmt"

    // Third-party packages
    "github.com/spf13/cobra"

    // Internal packages
    "github.com/EvilBit-Labs/opnDossier/internal/config"
    
    // Public API packages
    common "github.com/EvilBit-Labs/opnDossier/pkg/model"
    "github.com/EvilBit-Labs/opnDossier/pkg/parser"
)

// Function documentation required for exported functions
// LoadConfig loads application configuration from multiple sources
// with proper precedence handling.
func LoadConfig(cfgFile string) (*Config, error) {
    // Implementation
}
```

### Error Handling

Use proper error wrapping and context:

```go
// Good: Wrap errors with context
func processFile(path string) error {
    file, err := os.Open(path)
    if err != nil {
        return fmt.Errorf("failed to open file %s: %w", path, err)
    }
    defer file.Close()

    // Process file...
    if err := someOperation(); err != nil {
        return fmt.Errorf("failed to process file %s: %w", path, err)
    }

    return nil
}

// Bad: Don't use log.Fatal or panic in library code
func badExample() {
    log.Fatal("This terminates the program") // Never do this
}
```

### Logging Standards

Use structured logging with charmbracelet/log:

```go
// Good: Structured logging with context
logger := log.New()

logger.Info("Starting conversion", "input_file", inputPath)
logger.Debug("Processing section", "section", sectionName, "count", itemCount)

// With fields for additional context
ctxLogger := logger.With("operation", "convert")
ctxLogger.Error("Conversion failed", "error", err)
```

### Thread Safety with `sync.RWMutex`

When a struct uses `sync.RWMutex`, all read methods need `RLock()` -- not just write paths. Go's `RWMutex` is also not reentrant, so internal call chains should use lock-free `*Unsafe()` helpers instead of trying to acquire the same lock twice. Getter methods should return value copies rather than pointers into protected internal state. The canonical pattern lives in `internal/processor/report.go`. See the [Development Standards](docs/development/standards.md#thread-safety-with-syncrwmutex) for the full thread safety guide.

### XML Handling

When working with `encoding/xml`, remember that `string` fields cannot distinguish between an absent element and a self-closing element such as `<any/>`; both decode to `""`. Use `*string` when presence itself matters, and add helpers such as `IsAny()` or `Equal()` instead of comparing raw `*string` fields throughout the codebase. See `pkg/schema/opnsense/security.go` for the established pattern.

For escaping, use `xml.EscapeText` from the standard library. Do not hand-roll XML escaping logic. See the [Development Standards](docs/development/standards.md#xml-handling) for additional XML patterns.

### Streaming Interfaces

When adding `io.Writer` support alongside string-returning APIs, split the responsibilities. Create a dedicated writer-oriented interface such as `SectionWriter`, then expose a `Streaming*` wrapper interface for consumers that need streaming behaviour. Keep string-based methods for flows that still need post-processing such as HTML conversion. Also note that `MarkdownBuilder` is not safe for concurrent use; create a new instance per goroutine. See `internal/converter/builder/writer.go` for the canonical pattern and [Development Standards](docs/development/standards.md#streaming-interfaces) for details.

### FormatRegistry Pattern

`converter.DefaultRegistry` in `internal/converter/registry.go` is the single source of truth for supported output formats. To add a new format, register a `FormatHandler` in `newDefaultRegistry()` and let validation, shell completion, file extensions, and dispatch pick it up automatically. Do not reintroduce format constants or switch statements in `cmd/convert.go`; use `converter.FormatMarkdown`, `converter.FormatJSON`, and the other registry-backed constants instead. See the [Development Standards](docs/development/standards.md#formatregistry-pattern) for the full registry specification.

### DeviceParser Registry Pattern

Device parser registration follows the `database/sql` model: parsers call `parser.Register(name, factory)` from their `init()` function. The critical footgun is the blank import requirement -- any file using `parser.NewFactory()` must also blank-import the parser package, for example `_ "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"`, so the `init()` registration actually runs. Without that import the registry is empty and supported type lookups fail. `GOTCHAS.md` already documents the symptom and fix.

### File Write Safety

Always call `file.Sync()` before `Close()` when writing files that matter. Handle close failures in a deferred function with `logger.Warn`; never silently discard them. See the [Development Standards](docs/development/standards.md#file-write-safety).

### Public Package Purity

Packages under `pkg/` must never import `internal/` packages. Before committing `pkg/` changes, run `grep -rn 'internal/' --include='*.go' pkg/ | grep -v _test.go` to confirm the public boundary remains clean. When `pkg/` needs functionality implemented in `internal/`, define an interface in `pkg/` and inject the concrete implementation from the `cmd/` layer. See the [Development Standards](docs/development/standards.md#public-package-purity) for the full boundary rules.

### Linter Guidance

Treat `just lint` as the authoritative linter reference; IDE diagnostics are helpful suggestions, not the final word. For common patterns such as replacing magic numbers with named constants, preferring `s == ""` over `len(s) == 0`, or using `slices.*` instead of legacy `sort.*`, see the [Development Standards](docs/development/standards.md#linter-guidance) and `.golangci.yml`.

### Testing Standards

Write comprehensive tests with >80% coverage:

```go
func TestConfigLoad(t *testing.T) {
    tests := []struct {
        name        string
        configFile  string
        envVars     map[string]string
        want        *Config
        wantErr     bool
    }{
        {
            name:       "default config",
            configFile: "",
            envVars:    nil,
            want:       &Config{LogLevel: "info"},
            wantErr:    false,
        },
        {
            name:       "env var override",
            configFile: "",
            envVars:    map[string]string{"OPNDOSSIER_VERBOSE": "true"},
            want:       &Config{Verbose: true},
            wantErr:    false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Set up environment
            for k, v := range tt.envVars {
                t.Setenv(k, v)
            }

            got, err := LoadConfig(tt.configFile)
            if (err != nil) != tt.wantErr {
                t.Errorf("LoadConfig() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if !reflect.DeepEqual(got, tt.want) {
                t.Errorf("LoadConfig() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

## Data Processing Pipeline

The pipeline starts with ingestion. The parser factory (`pkg/parser/factory.go`) auto-detects the device type from the XML root element (`<opnsense>` or `<pfsense>`) and delegates to the appropriate registered parser. OPNsense configs are parsed via `internal/cfgparser/` into `pkg/schema/opnsense.OpnSenseDocument`; pfSense configs are parsed directly into `pkg/schema/pfsense.Document`. Both parsers share XML security hardening via `pkg/parser/xmlutil.go`.

The next stage is conversion. `pkg/parser/opnsense/` and `pkg/parser/pfsense/` each transform their schema types into `pkg/model.CommonDevice`, the platform-agnostic domain model used by audit, diff, display, and export flows. Conversion warnings (`common.ConversionWarning`) are non-fatal and must be propagated to the caller rather than silently discarded.

From there, export enrichment happens through a single gate: `prepareForExport()` in `internal/converter/enrichment.go`. This function is the shared path for JSON and YAML export preparation and populates statistics, analysis, security assessment data, and performance metrics in one place.

Export itself is registry-driven. The project supports five output formats -- markdown, json, yaml, text, and html -- through the FormatRegistry pattern, including smart file naming and overwrite protection.

Report generation is audience-aware. Blue Team reports favour clarity and grouping, and Red Team reports favour target prioritisation and pivot surface discovery. Neutral configuration documentation is handled by the `convert` command. Markdown, text, and HTML reports are built through `builder.MarkdownBuilder` (text and HTML are derived from the markdown output). JSON and YAML exports serialize the enriched `CommonDevice` struct directly via struct tags -- they do not flow through `MarkdownBuilder`.

Finally, remember that `cfgparser` and schema definitions evolve together. If you rename or reshape fields on `OpnSenseDocument`, update the switch cases in `internal/cfgparser/xml.go` at the same time so decoding behaviour stays correct. For the full architectural walkthrough, see `docs/development/architecture.md`.

## Configuration Management

### Understanding the Stack

The configuration system uses **Viper** for layered configuration management:

1. **CLI flags** (highest priority) - Cobra integration
2. **Environment variables** (`OPNDOSSIER_*`) - Viper handling
3. **Configuration file** (`~/.opnDossier.yaml`) - Viper loading
4. **Default values** (lowest priority) - Viper defaults

### Adding New Configuration Options

1. **Add to Config struct:**

```go
// internal/config/config.go
type Config struct {
    // Existing fields...
    NewOption string `mapstructure:"new_option"`
}
```

2. **Set default value:**

```go
func LoadConfigWithViper(cfgFile string, v *viper.Viper) (*Config, error) {
    // Existing defaults...
    v.SetDefault("new_option", "default_value")
    // ...
}
```

3. **Add CLI flag:**

```go
// cmd/root.go
func init() {
    // Existing flags...
    rootCmd.PersistentFlags().String("new_option", "default_value", "Description of new option")
}
```

4. **Add validation:**

```go
func (c *Config) Validate() error {
    // Existing validation...
    if c.NewOption == "" {
        validationErrors = append(validationErrors, ValidationError{
            Field:   "new_option",
            Message: "new_option cannot be empty",
        })
    }
    // ...
}
```

5. **Update documentation:**

- Add to README examples
- Update `docs/user-guide/configuration.md`
- Add to CLI help text

## CLI Enhancement with Fang

### Understanding Fang's Role

**Fang** provides enhanced UX features on top of Cobra:

- Styled help and error messages
- Automatic `--version` flag
- Shell completion commands
- Improved terminal formatting

### Adding New Commands

```go
// cmd/newcommand.go
var newCmd = &cobra.Command{
    Use:   "new [args]",
    Short: "Brief description",
    Long: `Detailed description with configuration info:

CONFIGURATION:
  This command respects the global configuration precedence:
  CLI flags > environment variables (OPNDOSSIER_*) > config file > defaults`,

    RunE: func(cmd *cobra.Command, args []string) error {
        // Get dependencies via CommandContext (set by PersistentPreRunE in root.go)
        cmdCtx := GetCommandContext(cmd)
        if cmdCtx == nil {
            return errors.New("command context not initialized")
        }
        logger := cmdCtx.Logger
        cfg := cmdCtx.Config

        // Implementation...
        return nil
    },
}

func init() {
    rootCmd.AddCommand(newCmd)
    newCmd.Flags().String("option", "default", "Option description")
}
```

## Testing Standards

### Test Categories

1. **Unit Tests** - Test individual functions
2. **Integration Tests** - Test component interactions
3. **CLI Tests** - Test command-line interface

### Running Tests

```bash
# All tests
just test

# Specific package
go test ./internal/config

# With coverage
go test -cover ./...

# Race detection
go test -race ./...

# Verbose output
go test -v ./...
```

### Test File Organization

```text
internal/config/
├── config.go
├── config_test.go          # Unit tests
└── testdata/
    ├── valid-config.yaml
    └── invalid-config.yaml

cmd/
├── convert.go
├── convert_test.go         # CLI tests
└── testdata/
    └── sample-config.xml
```

### Map Iteration in Tests

Go map iteration is non-deterministic. When output is assembled from maps, tests should usually assert presence with helpers such as `strings.Contains()` instead of comparing full string output byte-for-byte. Production code is responsible for sorting before rendering. See the [Development Standards](docs/development/standards.md#map-iteration-in-tests).

### Golden File Testing

The project uses `sebdah/goldie/v2` for snapshot-style testing. Golden files should contain real expected values, not placeholders, and tests should normalize dynamic content with helpers such as `normalizeGoldenOutput` before comparison. Update snapshots with `go test ./path -run TestGolden -update`, and make sure every golden file ends with a trailing newline. For the full pattern, see the [Development Standards](docs/development/standards.md#golden-file-testing).

### Pointer Identity Assertions

When verifying that two interface values refer to the same underlying object, use `assert.Same(t, expected, actual)` rather than `assert.Equal`. This is especially important for registry tests that confirm aliases resolve to the canonical handler instance. See the [Development Standards](docs/development/standards.md#pointer-identity-in-tests).

### Global Flag Testing in `cmd/`

Tests in `cmd/` must account for Cobra's package-level flag bindings. Do not use `t.Parallel()` in those tests; instead, save original global values and restore them with `t.Cleanup()`. `GOTCHAS.md` documents this in detail.

### Duplicate Code Detection

The `dupl` linter will flag structurally similar test files, especially paired JSON and YAML coverage. When two test files mostly differ by format, extract the shared setup and assertions into `test_helpers.go` and use subtests to cover each format cleanly. See the [Development Standards](docs/development/standards.md#duplicate-code-detection-in-tests).

## Documentation

### Documentation Standards

1. **Code Documentation** - GoDoc comments for all exported functions
2. **User Documentation** - Markdown files in `docs/`
3. **CLI Help** - Detailed help text in commands
4. **Examples** - Working examples in documentation

### Updating Documentation

When adding features:

1. Update relevant `docs/` files
2. Update CLI help text
3. Add examples to README
4. Update configuration documentation

## Open-Source Quality Standards (OSSF Best Practices)

This project maintains the OSSF Best Practices passing badge. All contributions must uphold these standards:

### Every PR Must

- Sign off commits with `git commit -s` (DCO enforced by GitHub App)
- Pass CI (golangci-lint, gofumpt, tests, CodeQL, Grype) before merge
- Include tests for new functionality — this is policy, not optional
- Be reviewed (human or CodeRabbit) for correctness, safety, and style
- Not introduce `panic()` in library code, unchecked errors, or unvalidated input

### Every Release Must

- Have human-readable release notes via git-cliff (not raw git log)
- Use unique SemVer identifiers (`vX.Y.Z` tags)
- Be built reproducibly (pinned toolchain, committed `go.sum`, GoReleaser)

### Documentation Requirements

- Exported APIs require godoc comments with examples where appropriate
- CONTRIBUTING.md documents code review criteria, test policy, DCO, and governance
- SECURITY.md documents vulnerability reporting with scope, safe harbor, and PGP key
- `docs/security/security-assurance.md` must be updated when new attack surface is introduced

## Pull Request Process

### Before Submitting

1. **Run all checks:**

   ```bash
   just check  # Must pass all checks
   ```

2. **Ensure commits are signed off (DCO):**

   All commits must include a DCO sign-off (`git commit -s`). See [Developer Certificate of Origin](#developer-certificate-of-origin-dco) for details.

3. **Update documentation:**

   - Code comments
   - User guides if needed
   - CLI help text

4. **Add tests:**

   - Unit tests for new functions
   - Integration tests for new features
   - CLI tests for new commands

### Pull Request Template

```markdown
## Description

Brief description of changes

## Type of Change

- [ ] Bug fix (non-breaking change)
- [ ] New feature (non-breaking change)
- [ ] Breaking change (fix or feature that would cause existing functionality to
      change)
- [ ] Documentation update

## Testing

- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Configuration Changes

- [ ] New configuration options documented
- [ ] CLI help updated
- [ ] Examples provided

## Checklist

- [ ] Code follows project standards
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
```

### Review Process

1. **Automated Checks** - All CI checks must pass
2. **Code Review** - At least one maintainer review
3. **Testing** - Ensure comprehensive test coverage
4. **Documentation** - Verify docs are updated

## Release Process

### Versioning

We use [Semantic Versioning](https://semver.org/):

- `MAJOR.MINOR.PATCH`
- Breaking changes increment MAJOR
- New features increment MINOR
- Bug fixes increment PATCH

### Release Checklist

1. Update version in relevant files
2. Update CHANGELOG.md
3. Create release PR
4. Tag release after merge
5. GoReleaser handles the rest

Releases should always ship with human-readable notes generated through `git-cliff` rather than a raw git log dump. Tags must use unique semantic version identifiers in the form `vX.Y.Z`, and release artifacts should be reproducible through the pinned toolchain, committed `go.sum`, and GoReleaser workflow. See `RELEASING.md` for the full release process.

### Reporting Vulnerabilities

Do not open public GitHub issues for security vulnerabilities. Use [GitHub Private Vulnerability Reporting](https://github.com/EvilBit-Labs/opnDossier/security/advisories/new) or email `support@evilbitlabs.io` instead. The project aims to release fixes for confirmed vulnerabilities within 90 days. `SECURITY.md` documents scope, safe harbor, and the project's PGP details.

## Getting Help

### Communication Channels

- **GitHub Issues** - Bug reports and feature requests
- **GitHub Discussions** - Questions and general discussion
- **Code Reviews** - Technical discussions

### Issue Templates

Use appropriate issue templates:

- Bug Report
- Feature Request
- Documentation Issue
- Question

### Development Questions

For development questions:

1. Check existing documentation
2. Search existing issues
3. Ask in GitHub Discussions
4. Create an issue if needed

## Developer Certificate of Origin (DCO)

This project requires all contributors to sign off on their commits, certifying that they have the right to submit the code under the project's license. This is enforced by the [DCO GitHub App](https://github.com/apps/dco).

To sign off, add `-s` to your commit command:

```bash
git commit -s -m "feat(parser): add new feature"
```

This adds a `Signed-off-by` line to your commit message:

```text
Signed-off-by: Your Name <your.email@example.com>
```

By signing off, you agree to the [Developer Certificate of Origin](https://developercertificate.org/).

## Project Governance

### Decision-Making

opnDossier uses a **maintainer-driven** governance model. Decisions are made by the project maintainers through consensus on GitHub issues and pull requests. Community input is welcomed and encouraged on all significant changes.

### Roles

| Role                 | Responsibilities                                                                          | Current                                        |
| -------------------- | ----------------------------------------------------------------------------------------- | ---------------------------------------------- |
| **Maintainer**       | Merge PRs, manage releases, set project direction, review security reports, triage issues | [@UncleSp1d3r](https://github.com/UncleSp1d3r) |
| **Security Contact** | Triage vulnerability reports, coordinate fixes, publish advisories                        | <support@evilbitlabs.io>                       |
| **Contributor**      | Submit issues, PRs, and participate in discussions                                        | Anyone following this guide                    |

### How Decisions Are Made

- **Bug fixes and minor changes**: Any maintainer can review and merge
- **New features**: Discussed in a GitHub issue before implementation; maintainer approval required
- **Architecture changes**: Require maintainer approval with rationale documented in the PR description
- **Breaking changes**: Discussed in a GitHub issue with community input; maintainer approval required
- **Releases**: Prepared by any maintainer following the [release process](#release-process); GoReleaser handles automation

### Becoming a Maintainer

As the project grows, active contributors who demonstrate sustained, high-quality contributions and alignment with project goals may be invited to become maintainers. Criteria include:

- Consistent, high-quality PRs over a sustained period
- Understanding of the project's architecture and security model
- Alignment with the project's core philosophy (operator-focused, offline-first, structured data)

### Continuity Plan

To ensure the project can continue operating if any key person becomes unavailable:

- The GitHub organization (EvilBit-Labs) has multiple administrators
- CI/CD pipelines (GoReleaser, GitHub Actions) are fully automated and documented
- All development standards, architecture decisions, and processes are documented in AGENTS.md, CONTRIBUTING.md, and docs/
- Security response procedures are documented in SECURITY.md with alternative contact methods
- Release signing uses Sigstore keyless signatures (no personal keys required)

---

Thank you for contributing to opnDossier! Your contributions help make network configuration management better for everyone.
