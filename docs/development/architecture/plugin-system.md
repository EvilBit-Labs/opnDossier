# Plugin System

This document covers the compliance plugin architecture: the `audit` command that hosts plugins, the plugin registry and its trust model, the dynamic loader, and the panic-recovery contract that keeps one misbehaving plugin from corrupting an audit run. For high-level system context see [overview.md](overview.md); for how audit reports flow through the render pipeline see [pipelines.md](pipelines.md#audit-to-export-mapping).

> **Authoritative references.** The canonical documentation for plugin implementation and the hardest-won operational gotchas lives in two places and should be read alongside this page:
>
> - [Plugin Development Guide](../plugin-development.md) — compliance plugin and device parser development (APIs, lifecycle, examples).
> - [GOTCHAS.md §2 Plugin Architecture](https://github.com/EvilBit-Labs/opnDossier/blob/main/GOTCHAS.md#2-plugin-architecture) — registry independence, panic recovery, `SetPluginDir` ordering, info-severity semantics, dynamic-plugin trust model.

## Audit Command Architecture

### Overview

The `opndossier audit` command provides the dedicated, first-class entry point for security audit and compliance checks. It uses the underlying audit/compliance engine through a CLI surface optimized for audit-specific workflows.

### Command Structure and Execution Flow

1. **Command Definition** (`cmd/audit.go`):

   - Declares audit-specific flags: `--mode` (blue/red), `--plugins` (compliance checks), `--plugin-dir` (dynamic plugin loading)
   - Reuses shared output flags: `--format`, `--output`, `--wrap`, `--section`, `--comprehensive`, `--redact`
   - `PreRunE` validation enforces:
     - Valid audit mode (blue, red)
     - `--plugins` flag only accepted with `--mode blue` (compliance checks only run in blue mode)
     - `--output` flag rejected when auditing multiple files (prevents output clobbering)
   - Plugin name validation deferred to post-initialization (`ValidateModeConfig` in `internal/audit/mode_controller.go`) to support dynamic plugins loaded from `--plugin-dir`
   - Shell completions for `--plugins` flag use registry-backed `registryPluginNames()` function, mirroring the `ValidDeviceTypes` pattern for dynamic discovery of available plugins

2. **Execution Flow** (`runAudit`):

   - Validates device type flag before any file processing
   - Processes multiple input files concurrently with configurable semaphore (defaults to `runtime.NumCPU()`)
   - Buffers all results before emission to prevent interleaved stdout writes or file overwrites
   - Each file processed via `generateAuditOutput` (parsing + audit generation, no I/O)
   - Results emitted serially via `emitAuditResult` after all processing completes

3. **Output Emission** (`cmd/audit_output.go`):

   - `emitAuditResult` handles file vs stdout emission with format-specific rendering
   - Markdown output to stdout uses glamour for styled terminal rendering
   - Non-markdown formats (JSON, YAML, text, HTML) written raw
   - File output uses standard file export without terminal styling

### Related Documentation

For complete implementation details of the two-phase validation pattern (CLI parsing vs. post-initialization validation), see:

- **[docs/solutions/logic-errors/cli-prerun-validation-timing-dynamic-plugins.md](../../solutions/logic-errors/cli-prerun-validation-timing-dynamic-plugins.md)** — Deferred plugin validation pattern for dynamic plugin support

### Architectural Patterns

#### Shared Validation Extraction

The `validateOutputFlags()` helper (in `cmd/shared_flags.go`) was extracted from `validateConvertFlags()` to share format, wrap, and section validation logic between audit and convert commands:

- **Validates**: Format against `converter.DefaultRegistry`, wrap width range, mutual exclusivity of `--wrap` and `--no-wrap`
- **Warns**: When section filtering used with JSON/YAML (sections ignored in structured formats)
- **Reused by**: Both `convert` and `audit` commands call `validateOutputFlags()` in their `PreRunE` hooks
- **Command-specific validation**: Each command performs its own audit-mode/plugin validation on command-specific flag variables

#### Multi-File Output Naming

When auditing multiple files, each report is auto-named to prevent filename collisions:

- **Pattern**: `<escaped-path>_<basename>-audit.<ext>`
- **Escaping**: Lossless tilde-based escaping via `escapePathSegment()`:
  - Tildes become `~~` (escape character doubling)
  - Underscores become `~u` (freeing underscore as segment separator)
  - Prevents boundary ambiguity: `"a_/b"` → `"a~u_b"`, `"a/_b"` → `"a_~ub"` (unambiguous)
- **Absolute paths**: Marked with `~a` prefix segment
- **Examples**:
  - `config.xml` → `config-audit.md`
  - `prod/site-a/config.xml` → `prod_site-a_config-audit.md`
  - `~/configs/edge.xml` → `~a_home_user_configs_edge-audit.md`

#### Plugin Mode Coupling

- `--plugins` flag only accepted with `--mode blue` (enforced in `PreRunE`)
- Red mode does not execute compliance checks
- When no plugins specified in blue mode, all available plugins run (resolved in `internal/audit/mode_controller.go`)

## Plugin Registry

`audit.PluginManager` maintains its own `PluginRegistry` instance that is **independent** of the global singleton returned by `audit.GetGlobalRegistry()`. This split exists so that CLI invocations and programmatic callers can operate with isolated plugin sets, but it introduces a sharp edge:

- `pm.InitializePlugins()` populates the manager's registry **only** — not the global one.
- Plugins that must be visible to simple CLI helpers must be registered explicitly via `audit.RegisterGlobalPlugin()`.
- Registry methods (`ListPlugins`, `GetPlugin`) are protected by `sync.RWMutex` and are safe for concurrent access. After `InitializePlugins` returns, the registry is effectively read-only.

See [GOTCHAS.md §2.1](https://github.com/EvilBit-Labs/opnDossier/blob/main/GOTCHAS.md#21-registry-independence) for the full invariant and the CLI call sites that depend on it.

### Plugin Selection and the `--plugins` Flag

- The `--plugins` CLI flag is only valid with `--mode blue`; `PreRunE` rejects it otherwise.
- Plugin-name validation is **deferred** to `ValidateModeConfig` (post-init) so that dynamically loaded plugins from `--plugin-dir` are visible to the check.
- When `--plugins` is omitted, all available plugins run (the "all available" default is resolved against the live registry after dynamic loading completes).
- Shell completions for `--plugins` are backed by `registryPluginNames()`, mirroring the `ValidDeviceTypes` pattern so new plugins become discoverable automatically.

## Dynamic Plugin Loader

`PluginRegistry.LoadDynamicPlugins` uses Go's `plugin.Open()` to load `.so` files from a directory at runtime. Two ordering and trust invariants must be preserved:

1. **`SetPluginDir` must precede `InitializePlugins`.** `PluginManager.SetPluginDir(dir, explicit)` mutates a field that `InitializePlugins` reads only during its execution. Setting the directory afterward has no observable effect. See [GOTCHAS.md §2.3](https://github.com/EvilBit-Labs/opnDossier/blob/main/GOTCHAS.md#23-setplugindir-must-precede-initializeplugins).
2. **Loading is opt-in.** Dynamic plugin loading runs only when the plugin directory is explicitly configured — currently via the `--plugin-dir` CLI flag (or the equivalent shared option for `convert`). If no directory is configured, `InitializePlugins` skips `LoadDynamicPlugins` entirely; there is no implicit `./plugins` auto-discovery. Plugins are never fetched from the network.

### Trust Model

Dynamic plugins execute with the **full privileges of the opnDossier process**. There is no signature verification, no checksum validation, and no sandboxing.

- Any `.so` in the plugin directory is loaded and executed.
- A malicious or compromised plugin has the same filesystem, environment, and network access as opnDossier itself.
- **Mitigations (opt-in, operator-owned):**
  - Restrict filesystem permissions on the plugin directory.
  - Only load plugins built from reviewed source code.
  - Avoid pointing `--plugin-dir` at world-writable directories in shared or CI environments.

The trust model is intentionally minimal — opnDossier does not try to be a plugin sandbox. Operators who need stronger isolation should run opnDossier under OS-level sandboxing (e.g., seccomp, AppArmor, containers) rather than relying on the loader. See [GOTCHAS.md §2.5](https://github.com/EvilBit-Labs/opnDossier/blob/main/GOTCHAS.md#25-dynamic-plugin-trust-model) for the canonical trust statement.

## Panic Recovery Contract

`RunComplianceChecks` wraps every plugin's `RunChecks()` call in `defer recover()`. The invariant is simple and must be preserved: **every selected plugin appears in the result maps, even if it panicked.**

When a plugin panics:

- The recovery path populates `PluginFindings`, `PluginInfo`, and `Compliance` with safe defaults using the `pluginName` string already in scope.
- The recovery path **does not call methods** on the panicked plugin (`Name()`, `Version()`, `Description()`, `GetControls()`) — post-panic internal state may be corrupt, so further method calls are unsafe.
- The `Version` field is set to `"unknown (panicked)"` and the compliance map is emitted empty.
- Execution falls through a `continue` to the next plugin; no other plugins are skipped as a side effect.

See [GOTCHAS.md §2.2](https://github.com/EvilBit-Labs/opnDossier/blob/main/GOTCHAS.md#22-panic-recovery-retains-plugins) for the full rationale and the tests that enforce this invariant.

## Severity, Compliance, and Inventory Semantics

The audit engine draws a clean line between **severity** (triage priority) and **compliance status** (pass/fail). Several subtle rules follow from that separation:

- **Info severity does not bypass compliance.** A finding with `Severity == "info"` that references a control still flips that control to non-compliant. Severity only affects presentation ordering and summary counts.
- **Inventory controls are excluded from the compliance map.** Controls with `Type: "inventory"` are omitted from `EvaluatedControlIDs` entirely and surface only in the "Configuration Notes" section of the report.
- **Unrecognized severity strings** are counted in a private `unknown` bucket by `countSeverities`. Callers that have access to a logger should emit a warning when `counts.unknown > 0`.

See [GOTCHAS.md §2.4](https://github.com/EvilBit-Labs/opnDossier/blob/main/GOTCHAS.md#24-info-severity-does-not-bypass-compliance) for the canonical statement of these rules.

## How Compliance Results Flow to Output

Audit compliance results flow from the plugin registry into the standard multi-format export pipeline:

1. `cmd/audit_handler.go` calls `mapAuditReportToComplianceResults()` to convert `audit.Report` into `common.ComplianceResults`.
2. `handleAuditMode()` creates a shallow copy of `CommonDevice` and sets its `ComplianceChecks` field to the mapped results.
3. The enriched device is passed to `generateWithProgrammaticGenerator()`, which dispatches to the `FormatHandler` from `DefaultRegistry` (markdown, JSON, YAML, text, or HTML).
4. For markdown, `BuildAuditSection()` in `internal/converter/builder/` renders per-plugin sections, findings tables, and summary. For structured formats, `ComplianceChecks` is serialized directly.

This is the same pipeline described in detail in [pipelines.md — Audit-to-Export Mapping](pipelines.md#audit-to-export-mapping); the plugin system simply populates the `ComplianceChecks` field before that pipeline runs.

## Further Reading

- [Plugin Development Guide](../plugin-development.md) — step-by-step authoring guide for new compliance plugins and device parsers.
- [GOTCHAS.md §2 Plugin Architecture](https://github.com/EvilBit-Labs/opnDossier/blob/main/GOTCHAS.md#2-plugin-architecture) — authoritative list of plugin-system gotchas.
- [GOTCHAS.md §8 Audit Command](https://github.com/EvilBit-Labs/opnDossier/blob/main/GOTCHAS.md#8-audit-command) — mode/plugin coupling, concurrent generation, multi-file output.
- [docs/solutions/logic-errors/cli-prerun-validation-timing-dynamic-plugins.md](../../solutions/logic-errors/cli-prerun-validation-timing-dynamic-plugins.md) — deferred validation pattern used by `--plugins`.
