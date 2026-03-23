# Contributing Guide

Thank you for your interest in contributing to opnDossier! This guide will help you get started with development and understand our contribution process.

## Core Philosophy

opnDossier is built for operators first. Every contribution should preserve operator control, keep behaviour visible, and avoid abstractions that hide what the tool is doing. If a design makes it harder for an operator to understand or override the result, it is probably moving in the wrong direction.

The project is intentionally **offline-first**. Contributions must not add runtime network calls, telemetry, or external service dependencies that would fail in airgapped or tightly controlled environments. The tool should behave the same way whether or not the internet exists.

We prefer **structured data** to ad-hoc strings. Use typed models, keep outputs machine-readable, and treat exported data as something that should remain portable, versioned, and auditable over time. This makes automation safer and reporting easier to trust.

When solving problems, follow a **framework-first** mindset. Reach for the existing Cobra, Fang, Viper, and Charmbracelet ecosystem already present in the repository before inventing custom plumbing. Reusing the established stack keeps the project cohesive and easier to maintain.

The project also values **polish over scale**. A smaller, well-documented feature set with sane defaults is more useful than a large, inconsistent surface area that is difficult to test or explain. Contributors should optimize for clarity and operator experience, not feature count.

Finally, opnDossier has explicit **ethical constraints**: no telemetry, no dark patterns, and no spyware. Decorative emojis should not be added to code comments or documentation prose, though the codebase does use emoji characters for functional purposes such as status indicators (`✅`/`❌`) in CLI output and report formatters. Those boundaries are part of the product, not decoration. For the canonical summary of these principles, see **[AGENTS.md](https://github.com/EvilBit-Labs/opnDossier/blob/main/AGENTS.md)** §2.

## Development Environment Setup

### Prerequisites

- **Go 1.26+**
- **Git** with GPG signing configured
- **[Just](https://just.systems/)** - Task runner (required for CI-equivalent checks)
- **[golangci-lint](https://golangci-lint.run/usage/install/)** - Go linter (latest version recommended)
- **[pre-commit](https://pre-commit.com/)** - Git hook framework

### Getting Started

1. Fork the repository on GitHub

2. Clone your fork locally:

   ```bash
   git clone https://github.com/yourusername/opnDossier.git
   cd opnDossier
   ```

3. Install dependencies and set up pre-commit hooks:

   ```bash
   just install
   ```

4. Run tests to ensure everything works:

   ```bash
   just test
   ```

5. Run all quality checks (CI-equivalent):

   ```bash
   just ci-check
   ```

## Development Workflow

### Architecture Overview

opnDossier uses a layered CLI architecture:

- **Cobra**: Command structure and flag parsing
- **Fang**: Configuration file path resolution (XDG-compliant)
- **Viper**: Configuration management
- **charmbracelet/log**: Structured, leveled logging
- **Lipgloss**: Styled terminal output formatting
- **Glamour**: Markdown rendering in terminal
- **nao1215/markdown**: Programmatic markdown generation in `internal/converter/builder/`
- **Go 1.26+**: Minimum supported Go version for local development and CI

> [!NOTE]
> `viper` manages opnDossier's own configuration such as CLI settings and display preferences. OPNsense `config.xml` parsing is a separate concern handled by `internal/cfgparser/`.

### Code Organization

The project follows standard Go conventions:

- `cmd/` - CLI commands (Cobra framework)
- `internal/` - Internal packages
  - `cfgparser/` - XML parsing and validation
  - `config/` - Configuration management (Viper)
  - `converter/` - Data conversion and report generation
  - `compliance/` - Plugin interfaces
  - `plugins/` - Compliance plugin implementations (stig, sans, firewall)
  - `audit/` - Audit engine and plugin management
  - `display/` - Terminal display formatting
  - `export/` - File export functionality
  - `logging/` - Structured logging (wraps `charmbracelet/log`)
  - `progress/` - CLI progress indicators
  - `validator/` - Configuration validation
- `pkg/` - Public API packages
  - `model/` - Platform-agnostic CommonDevice domain model (public API)
  - `parser/` - Parser factory and interfaces (public API)
    - `opnsense/` - OPNsense-specific parser implementation
  - `schema/opnsense/` - OPNsense XML schema definitions (public API)
- `docs/` - Documentation (MkDocs format)
- `testdata/` - Test fixtures and sample configuration files

### Extension Points

opnDossier has two independent extension points:

1. **Device Parsers** (`pkg/parser/`): Add support for new firewall platforms (currently supports OPNsense)
2. **Compliance Plugins** (`internal/plugins/`): Add new compliance frameworks (currently includes STIG, SANS, Firewall)

Both systems use self-registration patterns -- adding a new parser or plugin requires zero changes to existing code.

#### Writing a Compliance Plugin

Compliance controls should use stable, predictable identifiers. The built-in plugins use `V-XXXXXX` for STIG (matching real DISA STIG vulnerability IDs), `SANS-FW-XXX` for SANS, and `FIREWALL-XXX` for the firewall plugin. New plugins should follow a similar `PLUGIN-XXX` pattern with a prefix that identifies the standard. Consistent control naming makes reports easier to compare across plugins, tests, and documentation.

Severity should remain authoritative in the control definition, not scattered across check logic. In practice, `Finding.Severity` should be derived through a helper such as `controlSeverity(id)` rather than hard-coded inside `RunChecks()`. That keeps severity updates centralized and prevents drift between controls and findings.

When returning controls from `GetControls()` or storing them in result structs, use `compliance.CloneControls()`. It deep-copies `Tags` and `Metadata` values so plugin code does not accidentally share mutable slices across results, tests, or audit runs.

Plugin name matching is case-insensitive. Normalize names to lowercase when comparing, deduplicating, or validating selections so CLI behaviour stays predictable regardless of how the input was typed.

##### Panic Recovery and Error Handling

The audit engine wraps all `RunChecks()` calls in panic recovery. If a plugin panics, it will be logged via `*logging.Logger` (from `internal/logging`) and retained in results with zero findings rather than skipped. This safety net prevents a misbehaving plugin from crashing the entire audit process, which is especially important for dynamically-loaded plugins.

**Plugin authors do not need to implement panic recovery at the top level of `RunChecks()`.** The engine handles this automatically. However, panic recovery is not a replacement for proper error handling:

- **Handle expected failure cases explicitly**: `RunChecks()` returns `[]Finding`, not an error. Convert expected issues (invalid configuration, missing data, unsupported features) into descriptive findings with appropriate severity. Use `ValidateConfiguration() error` for pre-execution validation.
- **Handle edge cases gracefully**: Validate inputs, check for nil pointers, and guard against out-of-bounds access before they cause panics.
- **Reserve panics for truly unexpected situations**: Panics should only occur when the plugin encounters an unrecoverable programmer error or corrupt internal state.

When testing your plugin, include test cases that exercise edge conditions such as empty configurations, malformed data, and resource exhaustion scenarios. While panic recovery exists as a safety mechanism, plugins that handle errors gracefully provide a better operator experience through clear diagnostics and meaningful remediation guidance.

For canonical interfaces and examples, see `internal/compliance/interfaces.go` and the implementations under `internal/plugins/`.

### Making Changes

1. Create a feature branch:

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following our [development standards](../development/standards.md) and the coding standards in [AGENTS.md](https://github.com/EvilBit-Labs/opnDossier/blob/main/AGENTS.md)

3. Add tests for new functionality:

   ```bash
   just test
   ```

4. Run benchmarks if modifying parser performance:

   ```bash
   go test -run=^$ -bench=. ./internal/cfgparser/
   ```

5. Run linting:

   ```bash
   just lint
   ```

6. Run all CI-equivalent checks before committing:

   ```bash
   just ci-check
   ```

### Parser Development

When modifying XML parsing logic:

- The low-level XML parser lives in `internal/cfgparser/`
- Data models are defined in `pkg/schema/opnsense/` and parsed into the platform-agnostic `pkg/model/` structures
- Parser factory and interfaces are in `pkg/parser/` (public API)
- Test with sample files in `testdata/`
- Add benchmarks for performance-critical changes
- Preserve backward compatibility in the `Parser` interface

**Note:** The packages `pkg/model/`, `pkg/parser/`, and `pkg/schema/opnsense/` are public APIs that external Go projects can import.

## Data Processing Pipeline

The pipeline starts with ingestion. `internal/cfgparser/` parses OPNsense `config.xml` input into `pkg/schema/opnsense.OpnSenseDocument`, which serves as the canonical XML data transfer model for the rest of the system.

The next stage is conversion. `pkg/parser/opnsense/` transforms `OpnSenseDocument` into `pkg/model.CommonDevice`, the platform-agnostic domain model used by audit, diff, display, and export flows. Conversion warnings (`common.ConversionWarning`) are non-fatal and must be propagated to the caller rather than silently discarded.

From there, export enrichment happens through a single gate: `prepareForExport()` in `internal/converter/enrichment.go`. This function is the shared path for JSON and YAML export preparation and populates statistics, analysis, security assessment data, and performance metrics in one place.

Export itself is registry-driven. The project supports five output formats -- markdown, json, yaml, text, and html -- through the FormatRegistry pattern, including smart file naming and overwrite protection.

Report generation is audience-aware. Blue Team reports favour clarity and grouping, and Red Team reports favour target prioritisation and pivot surface discovery. Neutral configuration documentation is handled by the `convert` command. All audit reports are built through `builder.MarkdownBuilder`; there is no template system to keep in sync.

Finally, remember that `cfgparser` and schema definitions evolve together. If you rename or reshape fields on `OpnSenseDocument`, update the switch cases in `internal/cfgparser/xml.go` at the same time so decoding behaviour stays correct. For the full architectural walkthrough, see `docs/development/architecture.md`.

### Secure Coding Principles

Validate and sanitize all inputs at system boundaries. CLI arguments, configuration files, and imported XML should never be trusted without explicit validation.

Use restrictive file permissions for sensitive material. Configuration files and any outputs containing sensitive data should be written with `0600` permissions.

Keep error messages safe for operators and safe for logs. Do not leak credentials, raw configuration secrets, internal-only filesystem details, or sensitive values in returned errors. The SNMP community redaction logic in `internal/processor/report.go` is the canonical example of how sensitive values should be handled.

Never commit secrets to source control. Use environment variables or secure secret storage when a secret is genuinely required. For the full vulnerability reporting process and threat model, see `SECURITY.md` and `docs/security/security-assurance.md`.

### Testing

We maintain several types of tests:

- **Unit tests**: Test individual functions and methods
- **Integration tests**: Test complete workflows end-to-end
- **Golden file tests**: Snapshot tests using `sebdah/goldie/v2`
- **Performance tests**: Benchmarks for parser memory and speed
- **Error handling tests**: Verify proper error reporting

Run specific test suites:

```bash
# All tests
just test

# Specific package
go test ./internal/cfgparser/

# Benchmarks only
go test -run=^$ -bench=. ./internal/cfgparser/

# With coverage
go test -cover ./...

# Race detection
just test-race
```

### CI Debugging

When a pull request fails in CI, start with the GitHub CLI so you can inspect the same signals the maintainer sees:

- `gh pr checks <PR#>` -- list all CI check statuses for a pull request.
- `gh run view <run-id> --json jobs | jq '.jobs[]'` -- inspect detailed job and step status for a workflow run.

Two common gotchas are worth remembering. Race detection can report false positives around asynchronous test infrastructure such as spinners and progress bars, and benchmark jobs are intentionally non-blocking with `continue-on-error: true` so they do not hold up merges.

### Mergify & Merge Queue

Human pull requests use the `default` Mergify queue and are manually enqueued by the maintainer with the `/queue` command. Bot pull requests such as Dependabot and dosubot updates are auto-queued. When editing workflow or merge rules, remember that Mergify matches the workflow job `name:` value, not the internal job ID.

## Commit Standards

### Commit Message Format

```text
<type>(<scope>): <description>
```

**Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`

**Scopes:** `(parser)`, `(converter)`, `(audit)`, `(cli)`, `(model)`, `(plugin)`, `(builder)`, `(schema)`

### DCO Sign-off

All commits must include a DCO sign-off:

```bash
git commit -s -m "feat(parser): add support for new XML element"
```

## Pull Request Process

1. **Before submitting**:

   - Ensure `just ci-check` passes (pre-commit hooks + lint + tests)
   - Update documentation if needed
   - Include tests for new functionality
   - Verify typed enum constants are used instead of string literals for domain values

2. **PR Description**:

   - Clearly describe what changes were made
   - Reference any related issues
   - Include examples of new functionality
   - Note any breaking changes

3. **Review process**:

   - All PRs require at least one review (human or CodeRabbit)
   - CI must pass (golangci-lint, gofumpt, tests, CodeQL, Grype)
   - Documentation updates may be requested

## Go Development Standards

Please follow the coding standards documented in [AGENTS.md](https://github.com/EvilBit-Labs/opnDossier/blob/main/AGENTS.md), which covers:

- Go coding conventions and naming
- Error handling patterns
- Logging with `charmbracelet/log`
- Thread safety patterns
- XML element presence detection
- Testing standards
- No emojis in code, CLI output, comments, or documentation (unless processing emoji data)

### Thread Safety with `sync.RWMutex`

When a struct uses `sync.RWMutex`, all read methods need `RLock()` -- not just write paths. Go's `RWMutex` is also not reentrant, so internal call chains should use lock-free `*Unsafe()` helpers instead of trying to acquire the same lock twice. Getter methods should return value copies rather than pointers into protected internal state. The canonical pattern lives in `internal/processor/report.go`.

### XML Handling

When working with `encoding/xml`, remember that `string` fields cannot distinguish between an absent element and a self-closing element such as `<any/>`; both decode to `""`. Use `*string` when presence itself matters, and add helpers such as `IsAny()` or `Equal()` instead of comparing raw `*string` fields throughout the codebase. See `pkg/schema/opnsense/security.go` for the established pattern.

For escaping, use `xml.EscapeText` from the standard library. Do not hand-roll XML escaping logic.

### Streaming Interfaces

When adding `io.Writer` support alongside string-returning APIs, split the responsibilities. Create a dedicated writer-oriented interface such as `SectionWriter`, then expose a `Streaming*` wrapper interface for consumers that need streaming behaviour. Keep string-based methods for flows that still need post-processing such as HTML conversion. Also note that `MarkdownBuilder` is not safe for concurrent use; create a new instance per goroutine. See `internal/converter/builder/writer.go` for the canonical pattern.

### FormatRegistry Pattern

`converter.DefaultRegistry` in `internal/converter/registry.go` is the single source of truth for supported output formats. To add a new format, register a `FormatHandler` in `newDefaultRegistry()` and let validation, shell completion, file extensions, and dispatch pick it up automatically. Do not reintroduce format constants or switch statements in `cmd/convert.go`; use `converter.FormatMarkdown`, `converter.FormatJSON`, and the other registry-backed constants instead.

### DeviceParser Registry Pattern

Device parser registration follows the `database/sql` model: parsers call `parser.Register(name, factory)` from their `init()` function. The critical footgun is the blank import requirement -- any file using `parser.NewFactory()` must also blank-import the parser package, for example `_ "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"`, so the `init()` registration actually runs. Without that import the registry is empty and supported type lookups fail. `GOTCHAS.md` already documents the symptom and fix.

### File Write Safety

Always call `file.Sync()` before `Close()` when writing files that matter. Handle close failures in a deferred function with `logger.Warn`; never silently discard them.

### Public Package Purity

Packages under `pkg/` must never import `internal/` packages. Before committing `pkg/` changes, run `grep -rn 'internal/' --include='*.go' pkg/ | grep -v _test.go` to confirm the public boundary remains clean. When `pkg/` needs functionality implemented in `internal/`, define an interface in `pkg/` and inject the concrete implementation from the `cmd/` layer.

### Linter Guidance

Treat `just lint` as the authoritative linter reference; IDE diagnostics are helpful suggestions, not the final word. For common patterns such as replacing magic numbers with named constants, preferring `s == ""` over `len(s) == 0`, or using `slices.*` instead of legacy `sort.*`, see **[AGENTS.md](https://github.com/EvilBit-Labs/opnDossier/blob/main/AGENTS.md)** §5.10 and `.golangci.yml`.

### Use Typed Enums for Domain Constants

The project enforces compile-time type safety for domain values through typed string enums defined in `pkg/model/`. Firewall rule types, NAT configurations, DHCP settings, and other domain values use typed constants instead of magic strings.

**Rationale:**

- **Type safety**: Typed enums catch typos and invalid values at compile time
- **IDE support**: Autocompletion shows available values; refactoring updates all references
- **Intent clarity**: `rule.Type = common.RuleTypePass` is self-documenting; `rule.Type = "pass"` is not

**Pattern:**

```go
// ❌ Don't use magic strings
rule.Type = "pass"
natConfig.OutboundMode = "hybrid"
vip.Mode = "carp"

// ✅ Do use typed constants
rule.Type = common.RuleTypePass
natConfig.OutboundMode = common.OutboundHybrid
vip.Mode = common.VIPModeCarp
```

**Main enum types:**

- `FirewallRuleType`: `RuleTypePass`, `RuleTypeBlock`, `RuleTypeReject`
- `FirewallDirection`: `DirectionIn`, `DirectionOut`, `DirectionAny`
- `IPProtocol`: `IPProtocolInet`, `IPProtocolInet6`
- `NATOutboundMode`: `OutboundAutomatic`, `OutboundHybrid`, `OutboundAdvanced`, `OutboundDisabled`
- `VIPMode`: `VIPModeCarp`, `VIPModeIPAlias`, `VIPModeProxyARP`
- `LAGGProtocol`: `LAGGProtocolLACP`, `LAGGProtocolFailover`, `LAGGProtocolLoadBalance`, `LAGGProtocolRoundRobin`
- `DeviceType`: `DeviceTypeOPNsense`, `DeviceTypePfSense`, `DeviceTypeUnknown`

When adding new domain values to `pkg/model/`, define them as typed constants with godoc comments. Avoid string literals at compile boundaries; use the typed enums in analysis, diff, plugin, converter, and test code.

## Performance Considerations

This project processes potentially large XML files, so performance matters:

- Add benchmarks for significant algorithmic changes
- Consider memory allocation patterns
- Test with sample files of varying sizes in `testdata/`
- The parser limits input to 10MB by default (`DefaultMaxInputSize`)

## Testing Standards

### Map Iteration in Tests

Go map iteration is non-deterministic. When output is assembled from maps, tests should usually assert presence with helpers such as `strings.Contains()` instead of comparing full string output byte-for-byte. Production code is responsible for sorting before rendering.

### Golden File Testing

The project uses `sebdah/goldie/v2` for snapshot-style testing. Golden files should contain real expected values, not placeholders, and tests should normalize dynamic content with helpers such as `normalizeGoldenOutput` before comparison. Update snapshots with `go test ./path -run TestGolden -update`, and make sure every golden file ends with a trailing newline. For the full pattern, see **[AGENTS.md](https://github.com/EvilBit-Labs/opnDossier/blob/main/AGENTS.md)** §7.6.

### Pointer Identity Assertions

When verifying that two interface values refer to the same underlying object, use `assert.Same(t, expected, actual)` rather than `assert.Equal`. This is especially important for registry tests that confirm aliases resolve to the canonical handler instance.

### Global Flag Testing in `cmd/`

Tests in `cmd/` must account for Cobra's package-level flag bindings. Do not use `t.Parallel()` in those tests; instead, save original global values and restore them with `t.Cleanup()`. `GOTCHAS.md` documents this in detail.

### Duplicate Code Detection

The `dupl` linter will flag structurally similar test files, especially paired JSON and YAML coverage. When two test files mostly differ by format, extract the shared setup and assertions into `test_helpers.go` and use subtests to cover each format cleanly.

## Getting Help

- Check existing issues and documentation first
- Open an issue for bugs or feature requests
- Review AGENTS.md for detailed development standards
- Review the architecture documentation in `docs/development/`

## Release Process

Releases should always ship with human-readable notes generated through `git-cliff` rather than a raw git log dump. Tags must use unique semantic version identifiers in the form `vX.Y.Z`, and release artifacts should be reproducible through the pinned toolchain, committed `go.sum`, and GoReleaser workflow. See `RELEASING.md` for the full release process.

## Reporting Vulnerabilities

Do not open public GitHub issues for security vulnerabilities. Use [GitHub Private Vulnerability Reporting](https://github.com/EvilBit-Labs/opnDossier/security/advisories/new) or email `support@evilbitlabs.io` instead. The project aims to release fixes for confirmed vulnerabilities within 90 days. `SECURITY.md` documents scope, safe harbor, and the project's PGP details.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](https://github.com/EvilBit-Labs/opnDossier/blob/main/LICENSE).

Thank you for contributing to opnDossier!
