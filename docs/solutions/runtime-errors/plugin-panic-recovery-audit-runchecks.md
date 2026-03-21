---
title: Panic recovery around plugin RunChecks() calls
category: runtime-errors
date: '2026-03-21'
tags:
  - panic-recovery
  - plugin-architecture
  - audit
  - fault-isolation
  - dynamic-plugins
severity: high
components:
  - internal/audit/plugin.go
  - internal/audit/plugin_manager.go
  - internal/audit/mode_controller.go
related_issues:
  - 309
---

# Panic Recovery Around Plugin RunChecks() Calls

## Problem

`PluginRegistry.RunComplianceChecks` in `internal/audit/plugin.go` called `p.RunChecks(device)` without any panic protection. The `compliance.Plugin` interface allows arbitrary implementations, including dynamically-loaded `.so` plugins. Any panic in `RunChecks()` propagated uncaught through the audit pipeline, killing the process and losing all other plugins' results.

**Symptoms:** If any compliance plugin panicked during `RunChecks()`, the entire audit crashed. Other healthy plugins' results were lost. No structured error reporting for the failure.

## Root Cause

The compliance plugin interface (`compliance.Plugin`) is an extension point designed for both built-in and dynamically-loaded plugins. Dynamic plugins loaded via Go's `plugin` package can contain arbitrary code. A bare `p.RunChecks(device)` call provides no isolation boundary, so any panic in plugin code propagates up the call stack and terminates the audit.

## Solution

Wrap the `p.RunChecks(device)` call in an immediately-invoked function with `defer recover()`. Add a `*slog.Logger` parameter to `RunComplianceChecks` for structured panic logging.

### Code Example

```go
// Before: bare call, panic propagates and kills the process
findings := p.RunChecks(device)

// After: panic recovery with structured logging
var findings []compliance.Finding

func() {
    defer func() {
        if r := recover(); r != nil {
            logger.Error("plugin panicked during RunChecks",
                "plugin", pluginName,
                "panic", r,
            )
        }
    }()
    findings = p.RunChecks(device)
}()
```

The immediately-invoked function literal creates a deferred recovery scope isolated to the single plugin call. If `RunChecks` panics, the deferred function catches it, logs the plugin name and panic value, and execution continues with `findings` at its zero value (nil slice). The surrounding loop proceeds to process remaining plugins unaffected.

### Key Design Decisions

1. **Logger parameter uses `*slog.Logger`** -- matches the existing `LoadDynamicPlugins` signature pattern in the same file, maintaining API consistency.
2. **Panicked plugins retained in results with zero findings** -- not skipped via `continue`. Downstream consumers (summary tables, compliance reports) can see the plugin was requested and evaluated, rather than silently disappearing from output. See GOTCHAS.md SS2.2.
3. **`slog.Default()` at call sites** -- bridging `charmbracelet/log` to `slog` would add complexity disproportionate to an exceptional-path-only log message. Both `PluginManager.RunComplianceAudit` and `ModeController.generateBlueReport` pass `slog.Default()`.
4. **Nil findings are inherently safe in Go** -- `range nil` is a no-op and `append(slice, nil...)` is a no-op, so the rest of the loop body (PluginInfo population, Compliance tracking) executes safely on the zero-value `findings` slice without additional nil guards.

### Files Changed

- `internal/audit/plugin.go` -- core panic recovery wrapper
- `internal/audit/plugin_manager.go` -- call site updated with `slog.Default()`
- `internal/audit/mode_controller.go` -- call site updated with `slog.Default()`
- `internal/audit/plugin_global_test.go` -- `mockPanickingPlugin` and isolation tests added
- `internal/audit/mode_controller_test.go` -- call sites updated

## Prevention

### Pattern

When calling any method on an interface implementation that may originate from external or dynamic sources (plugin `.so` files, user-provided implementations), wrap the call in a deferred `recover()` that captures the panic value and logs it. The recovery boundary should be as narrow as possible -- one per plugin invocation, not one global recovery around the entire audit loop.

### Where Else This Might Apply

| Call site                            | Method                                   | Status                                                       |
| ------------------------------------ | ---------------------------------------- | ------------------------------------------------------------ |
| `RunComplianceChecks`                | `plugin.RunChecks()`                     | Protected (this fix)                                         |
| `InitializePlugins`                  | `plugin.Name()`, `plugin.Version()`      | Review needed -- dynamic plugin metadata accessors can panic |
| `LoadDynamicPlugins`                 | `plugin.Lookup("Plugin")` result casting | Review needed -- type assertion on `plugin.Symbol` can panic |
| `GetControls()` / `GetControlByID()` | Called in `deriveSeverityFromControl`    | Review needed -- called during severity derivation           |

### Testing Strategy

Use the `mockPanickingPlugin` pattern:

1. Embed `mockCompliancePlugin`, override `RunChecks` to panic
2. Table-driven tests with both panicking and healthy plugins
3. Assert: healthy findings preserved, panicked plugin present with zero findings, no error returned
4. Run `just test-race` to confirm no data races in recovery closures

### Review Checklist

- [ ] Plugin interface method calls on dynamic/external plugins are wrapped in `defer recover()`
- [ ] Recovery boundary is per-plugin, not per-audit-run
- [ ] Panicked plugins retained in results (not skipped) per GOTCHAS.md SS2.2
- [ ] Tests include `mockPanickingPlugin` scenarios alongside healthy plugins
- [ ] `just test-race` passes

## Related Documentation

- [GOTCHAS.md SS2.1](../../../GOTCHAS.md) -- Registry Independence
- [GOTCHAS.md SS2.2](../../../GOTCHAS.md) -- Panic Recovery Retains Plugins (invariant)
- [AGENTS.md SS8.2](../../../AGENTS.md) -- Plugin Development standards
- [Plugin Development Guide](../../development/plugin-development.md)
- [Architecture Issues: Pluggable DeviceParser Registry](../architecture-issues/pluggable-deviceparser-registry-pattern.md) -- parallel registry pattern
- GitHub Issue #309 -- original tracking issue
- GitHub Issue #311 -- dynamic plugin load failures (related, still open)
