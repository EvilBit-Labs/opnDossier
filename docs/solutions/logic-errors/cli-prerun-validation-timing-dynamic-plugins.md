---
title: Deferred audit plugin name validation to support dynamic plugins
category: logic-errors
date: 2026-03-23
tags:
  - plugin-validation
  - dynamic-plugins
  - prerunE
  - validation-ordering
  - shell-completion
  - audit-command
  - plugin-registry
  - cobra
components:
  - cmd/audit.go
  - cmd/shared_flags.go
  - internal/audit/mode_controller.go
severity: medium
resolution_time: 1-2 hours
related_issues: ['#448']
---

# Deferred Audit Plugin Name Validation to Support Dynamic Plugins

## Problem

The `audit` command's `PreRunE` function hardcoded valid plugin names as `[]string{"stig", "sans", "firewall"}`. This validation ran at `PreRunE` time, **before** `InitializePlugins` loaded dynamic `.so` plugins in the `RunE` phase. Users passing `--plugins my-custom-plugin` with a valid `--plugin-dir` received a confusing "invalid audit plugin" error even though the plugin was loadable.

**Symptom:** `--plugins my-custom-plugin --plugin-dir /path/to/plugins/` rejected at CLI parse time with "invalid audit plugin" despite a valid `.so` file existing.

## Root Cause

Validation timing mismatch in a two-phase CLI lifecycle. Plugin names were validated against a static list in `PreRunE`, but dynamic plugins are not available until `handleAuditMode` calls `pm.InitializePlugins()` during `RunE`. The hardcoded validation could never know about dynamically-loaded plugins because the registry had not yet been populated when `PreRunE` executed.

## Solution

### 1. Remove hardcoded plugin validation from PreRunE

Deleted the 9-line block from `cmd/audit.go` that validated plugin names against a static list:

```go
// REMOVED from PreRunE:
validPlugins := []string{"stig", "sans", "firewall"}
for _, p := range auditPlugins {
    if !slices.Contains(validPlugins, strings.ToLower(p)) {
        return fmt.Errorf("invalid audit plugin %q, must be one of: %s",
            p, strings.Join(validPlugins, ", "))
    }
}
```

`PreRunE` still validates audit mode, `--plugins`/`--mode` coupling, multi-file output conflicts, and shared output flags. Only the plugin name membership check was removed.

### 2. Rely on existing post-init validation

`ValidateModeConfig()` in `internal/audit/mode_controller.go` already validates `SelectedPlugins` against `mc.registry.ListPlugins()` after `InitializePlugins` populates the registry. It returns `ErrPluginNotFound` for unrecognized names. This method is called by `GenerateReport()`, invoked from `handleAuditMode()` in the `RunE` phase. No changes were needed here.

> **Thread safety:** `PluginRegistry` methods (`ListPlugins`, `GetPlugin`) are protected by `sync.RWMutex` and are safe for concurrent access. After `InitializePlugins` completes, the registry is effectively read-only. See [architecture docs](../../../docs/development/architecture.md) and AGENTS.md 5.6 for the canonical thread-safety pattern.

### 3. Add registry-backed shell completion

Added `registryPluginNames()` in `cmd/shared_flags.go` that creates a temporary `PluginManager`, initializes built-in plugins, and returns names from the registry. `ValidAuditPlugins()` now uses this instead of a hardcoded list, mirroring the `ValidDeviceTypes` registry-driven pattern. A `pluginDescriptions` map provides fallback descriptions for shell completions.

### 4. Update and add tests

- `TestAuditCmdPreRunEPluginValidation` -- updated to verify `PreRunE` accepts unknown plugin names without error.
- `TestAuditCmdPreRunEDynamicPluginAccepted` -- new test verifying `--plugin-dir` + unknown name passes `PreRunE`.
- `TestHandleAuditMode_UnknownPluginRejectedPostInit` -- new test confirming post-init rejection via `ErrPluginNotFound`.
- `TestAuditCmdCompletions` -- updated to assert against registry-backed plugin names.

## Verification

Verified at three layers:

1. **Unit (PreRunE):** Tests confirm `PreRunE` no longer rejects unknown plugin names.
2. **Integration (post-init):** `TestHandleAuditMode_UnknownPluginRejectedPostInit` confirms truly invalid names are still caught after `InitializePlugins`.
3. **Shell completions:** `TestAuditCmdCompletions` verifies completions derive from the live registry.
4. **CI:** `just ci-check` passes (lint, format, tests).

## Prevention Strategies

### 1. Static vs. Dynamic Validation Split

`PreRunE` is for validation answerable at flag-parse time: format strings, numeric ranges, enum membership against compile-time sets, mutually exclusive flags. `RunE` (or post-initialization) is for validation requiring runtime state: loaded plugins, parsed configs, populated registries.

**Rule:** If answering "is this value valid?" requires calling an initialization function or consulting a runtime-populated registry, the validation belongs after initialization, not in `PreRunE`.

### 2. Extensible Registry Membership Is Never a Compile-Time Constant

When a registry can be extended at runtime (dynamic plugins, external drivers), its membership set is not knowable at compile time. Any validation encoding membership as a hardcoded slice is a latent premature-rejection bug. If valid values are "whatever is in the registry at runtime," validation is a runtime concern.

### 3. Detection Heuristics

- Flag value accepted in one context, rejected in another with no code change
- "Invalid value" error before any I/O occurs
- Validation allowlist is a hardcoded constant for an extensible registry
- Zero golden file or test changes when a new flag is wired (per GOTCHAS.md 5.1)

### 4. Test Pattern: Two-Phase Validation

Write paired tests:

- `TestPreRunE_AcceptsUnknownExtensibleName`: set unknown name, call `PreRunE`, assert no error.
- `TestRunE_RejectsUnknownNameAfterInit`: run full pipeline with unknown name, assert error from `RunE`/post-init.

The two tests pin both sides of the invariant.

## Related Documentation

- [cli-flag-wiring-silent-ignore.md](cli-flag-wiring-silent-ignore.md) -- inverse pattern (flag accepted but silently ignored vs. flag rejected prematurely)
- [GOTCHAS.md 5.1](../../../GOTCHAS.md) -- Silent Flag Ignores
- [GOTCHAS.md 8.1](../../../GOTCHAS.md) -- Mode/Plugin Coupling
- [GOTCHAS.md 2.1](../../../GOTCHAS.md) -- Registry Independence
- [GOTCHAS.md 2.3](../../../GOTCHAS.md) -- SetPluginDir Must Precede InitializePlugins
- `docs/solutions/runtime-errors/plugin-panic-recovery-audit-runchecks.md` -- plugin fault isolation
- `docs/solutions/architecture-issues/pluggable-deviceparser-registry-pattern.md` -- registry pattern precedent
