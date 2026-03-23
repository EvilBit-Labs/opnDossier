# Development Gotchas & Pitfalls

This document tracks non-obvious behaviors, common pitfalls, and architectural "gotchas" in the opnDossier codebase to assist future maintainers and contributors.

## 1. Testing & Concurrency

### 1.1 `t.Parallel()` and Global State

The `cmd/` package uses package-level global variables for CLI flags (required by `spf13/cobra` for flag binding). **Never use `t.Parallel()` in any test that modifies or relies on these global variables.**

- **Problem:** Concurrent tests modifying `sharedDeviceType`, `sharedAuditMode`, or the `rootCmd` flag set will cause non-deterministic data races.
- **Symptom:** `just test-race` fails with "DATA RACE" reports in the `cmd` package.
- **Solution:** Remove `t.Parallel()` from the parent test and all subtests that interact with global flags. Use `t.Cleanup()` to restore original global values after the test.

### 1.2 Race Detector Collateral

When a data race occurs in a test touching global state, the Go race detector may report collateral races in unrelated, stateless functions (e.g., `truncateString` or `escapePipeForMarkdown`) that happen to be running in other parallel tests.

- **Rule of Thumb:** If a stateless utility function is reporting a race, check if a concurrent test is modifying a global variable.

## 2. Plugin Architecture

### 2.1 Registry Independence

`audit.PluginManager` maintains its own internal `PluginRegistry` instance. This is **independent** of the global singleton returned by `audit.GetGlobalRegistry()`.

- **Gotcha:** Calling `pm.InitializePlugins()` does **not** populate the global registry.
- **Requirement:** If a plugin must be available globally (e.g., for simple CLI helpers), it must be explicitly registered via `audit.RegisterGlobalPlugin()`.

### 2.2 Panic Recovery Retains Plugins

`RunComplianceChecks` wraps each plugin's `RunChecks()` in `defer recover()`. On panic, a dedicated recovery path populates `PluginFindings`, `PluginInfo`, and `Compliance` with safe defaults, then uses `continue` to skip further method calls on the potentially corrupt plugin.

- **Gotcha:** The recovery path must NOT call methods on the panicked plugin (`Name()`, `Version()`, `Description()`, `GetControls()`) — the plugin's internal state may be corrupt after the panic. Instead, it uses the `pluginName` string already in scope and sets `Version: "unknown (panicked)"` with an empty compliance map.
- **Invariant:** Every selected plugin must appear in all result maps, even if it panicked.

### 2.3 SetPluginDir Must Precede InitializePlugins

`PluginManager.SetPluginDir(dir, explicit)` configures the directory for dynamic `.so` loading. It must be called **before** `InitializePlugins(ctx)` because `InitializePlugins` reads `pm.pluginDir` only during its execution. Calling `SetPluginDir` after `InitializePlugins` mutates the field but has no observable effect on plugin loading because `InitializePlugins` has already completed.

## 3. Data Processing

### 3.1 Map Iteration Order

Go map iteration is non-deterministic.

- **Gotcha:** Any CLI output or file export derived from a map (e.g., `report.Compliance`, `report.Metadata`) must be sorted before rendering.
- **Solution:** Use `slices.Sorted(maps.Keys(m))` or `slices.SortFunc()` to ensure deterministic, testable output.

### 3.2 XML Presence vs. Absence

The `encoding/xml` package treats self-closing tags (e.g., `<disabled/>`) and missing tags identically for `string` fields.

- **Gotcha:** Use `*string` (pointer to string) when you need to distinguish between "element present but empty" (`""`) and "element absent" (`nil`).

### 3.3 Repeated XML Elements and `string` Fields

When an XML element appears multiple times (e.g., `<priv>a</priv><priv>b</priv>`), a `string` field only captures the last occurrence — all others are silently dropped. Use `[]string` for elements that can repeat.

- **Symptom:** Only the last value is retained; no error is raised.
- **Detection:** Compare parsed struct against raw XML — earlier occurrences are silently overwritten by later ones.
- **Fix:** Change the field type from `string` to `[]string` with the same `xml` tag.

## 4. Diff Engine

### 4.1 Section-Level Added/Removed Guards

Most `Compare*` methods in `internal/diff/analyzer.go` have early-return guards that emit a single `ChangeAdded` or `ChangeRemoved` when one side has data and the other does not. For pointer types (`*common.System`), this uses nil checks. For value types (`NATConfig`, slices), this uses `HasData()` or `len() == 0`. New `Compare*` methods must follow this pattern.

- **Exceptions:** `CompareFirewallRules` and `CompareUsers` intentionally omit section-level guards because per-item granularity is more useful for security-sensitive resources (individual rule additions/removals are reported separately).

## 5. CLI Flag Wiring

### 5.1 Silent Flag Ignores

A CLI flag can be accepted by Cobra, stored in a package-level variable, and silently ignored if the command handler never transfers it to `Options` or stores it in an untyped map no consumer reads.

- **Symptom:** Flag accepted without error but output identical with/without it.
- **Detection:** A new flag that breaks zero golden files or tests is likely broken.
- **Prevention:** Typed `Options` fields (not `CustomFields`), regression tests per command, diff output with/without flag.
- **Reference:** `docs/solutions/logic-errors/cli-flag-wiring-silent-ignore.md`

### 5.2 Enum Type Casts from XML

When converting XML schema `string` fields to typed enums (e.g., `common.FirewallRuleType(rule.Type)`), always validate with `IsValid()` after the cast and emit a conversion warning for unrecognized values via `c.addWarning()`. The `DeviceType` enum with `ParseDeviceType()` + `IsValid()` is the canonical pattern. Bare casts silently pass invalid values through the entire pipeline.

- **Symptom:** Invalid enum values (e.g., `FirewallRuleType("match")`) pass through the pipeline without error, failing silently in downstream `switch` statements.
- **Prevention:** Call `IsValid()` after every XML-to-enum cast. For `NATOutboundMode`, `LAGGProtocol`, and `VIPMode` there is no downstream validation — the converter cast is the only defense.

### 5.3 PreRunE Test Commands Must Bind to Real Globals

When testing `PreRunE` with a temporary `cobra.Command`, bind its flags to the **same** package-level variables the real command uses (e.g., `tempCmd.Flags().StringVar(&auditMode, ...)`). If you bind to local variables instead, `PreRunE` reads stale globals and tests pass vacuously. Always set values via `cmd.Flags().Set()` (not direct assignment) to exercise real pflag parsing.

## 6. Validator

### 6.1 GID/UID Zero is Valid

Unix GID 0 (wheel/root group) and UID 0 (root user) are valid. The validator check is `gid < 0` / `uid < 0`, correctly allowing zero. Error messages must say "non-negative integer", not "positive integer".

## 7. Parser Registry

### 7.1 Blank Import Requirement

`pkg/parser/factory.go` dispatches through the registry, not via direct imports. The OPNsense parser only registers itself when its package `init()` runs, which requires a blank import: `_ "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"`.

- **Symptom:** `"unsupported device type: root element <opnsense> is not recognized; supported: (none registered -- ensure parser packages are imported)"` -- empty registry with hint
- **Cause:** Missing blank import means `init()` never ran, registry is empty
- **Fix:** Add the blank import to the test file or production file using `parser.NewFactory()`
- **Detection:** Any new test file using `parser.NewFactory()` that sees an empty registry is missing the blank import

## 8. Audit Command

### 8.1 Mode/Plugin Coupling

Only `blue` mode runs `RunComplianceChecks`. The `standard` and `red` modes ignore `SelectedPlugins` entirely. The `--plugins` flag is rejected in `PreRunE` unless `--mode blue` is set.

- **Gotcha:** Adding plugin support to `standard` or `red` mode requires wiring `RunComplianceChecks` into `generateStandardReport`/`generateRedReport` in `mode_controller.go` AND removing the `PreRunE` guard in `cmd/audit.go`.
- **Gotcha:** `--plugins` only accepts built-in names (`stig`, `sans`, `firewall`). Dynamic plugins loaded via `--plugin-dir` are included automatically when `--plugins` is omitted (the "all available" default). To run *only* a dynamic plugin, the current design does not support it — this is intentional to avoid unvalidated plugin name strings.

### 8.2 Concurrent Generation, Serial Emission

`runAudit` in `cmd/audit.go` processes files concurrently via `generateAuditOutput` (returns string, no I/O), then writes results serially via `emitAuditResult` in the parent goroutine.

- **Gotcha:** Never add stdout writes or file exports inside `generateAuditOutput` — all emission must go through `emitAuditResult` to prevent interleaved output.
- **Gotcha:** `--output` is rejected with multiple input files in `PreRunE` to prevent file clobbering.

### 8.3 Multi-File Output Path Uniqueness

`deriveAuditOutputPath` uses lossless tilde-based escaping: tildes in path segments become `~~` and underscores become `~u`, freeing the literal underscore to serve as an unambiguous directory separator. This prevents distinct paths from collapsing to the same filename, including boundary cases where one segment ends with `_` and the next begins with `_` (e.g., `a_/b/config.xml` → `a~u_b_config-audit.md` versus `a/_b/config.xml` → `a_~ub_config-audit.md`).

- **Gotcha:** Simple character replacement (e.g., `/` → `-`) is NOT sufficient — paths like `a-b/c/config.xml` and `a/b-c/config.xml` would collide. The escaping must be lossless (invertible). The earlier double-underscore scheme (`_` → `__`, separator → `_`) was also insufficient — it collapsed at segment boundaries where trailing/leading underscores were indistinguishable from the separator.
- **Gotcha:** Expected output filenames are asserted in 5+ test functions (`TestDeriveAuditOutputPath`, `TestEmitAuditResult_MultiFileAutoNaming`, `TestEmitAuditResult_MultiFileConfigOutputFileIgnored`, `TestDeriveAuditOutputPath_BasenameCollision`, `TestDeriveAuditOutputPath_BoundaryUnderscoreCollision`, etc.). When changing the encoding scheme, grep for all assertion sites — missing one causes CI failure.

## 9. Dupl Linter Bidirectional Firing

### 9.1 Cross-Type Validator Duplication

When adding device-specific validators that are structurally similar to existing validators (e.g., `validatePfSenseSystem` vs `validateSystem`), the `dupl` linter fires on BOTH files — not just the new one.

- **Gotcha:** Adding `//nolint:dupl` only to the new function is insufficient. The existing function also needs `//nolint:dupl` because `dupl` reports pairs.
- **Pattern:** Both sides of the duplicate pair must carry the suppression directive.

## 10. Converter Testing

### 10.1 ToMarkdown Outputs ANSI-Rendered Text

`MarkdownConverter.ToMarkdown()` passes output through `glamour.Render()`, which inserts ANSI escape codes. Tests asserting on the output must set `t.Setenv("TERM", "dumb")` for clean text. Since `t.Setenv` is incompatible with `t.Parallel()`, remove `t.Parallel()` and add `//nolint:tparallel` to the function.

- **Symptom:** `assert.Contains(t, md, "System Configuration")` fails despite the text being present.
- **Fix:** Add `t.Setenv("TERM", "dumb")` at the start of the test (no `t.Parallel()`).
- **Precedent:** `internal/converter/markdown_test.go` uses this pattern throughout.

### 10.2 NAT Rule Field Name Disambiguation

`OutboundNATRule.Target` is the NAT target address. `InboundNATRule.InternalIP` is the port-forward destination — there is no `Target` field on `InboundNATRule`. `FirewallRule` has no `Tag`/`Tagged` fields — those exist only on `OutboundNATRule`.

## 11. Sanitizer

### 11.1 pfSense `bcrypt-hash` Field Name

pfSense stores user passwords in `<bcrypt-hash>` elements, not `<password>` or `<passwd>` like OPNsense. The sanitizer's field-pattern matching must explicitly include `bcrypt-hash` and `sha512-hash` — the generic `"pass"` substring match does not cover these.

- **Symptom:** `sanitize` command outputs bcrypt hashes in cleartext.
- **Fix:** Add `"bcrypt-hash"`, `"sha512-hash"` to the `password` rule's `FieldPatterns` in `internal/sanitizer/rules.go` and to `passwordKeywords` in `internal/sanitizer/patterns.go`.
- **Precedent:** The SNMP community string (`rocommunity`) required a dedicated field pattern for the same reason.

### 11.2 New Device Type Field Names

When adding a new device type (e.g., pfSense), audit the XML element names for credential fields that differ from OPNsense. The sanitizer operates on raw XML element names, not CommonDevice field names. Any device-specific naming for secrets must be added to the sanitizer's pattern lists.

- **Detection:** `sanitize <config.xml> | grep -i 'hash\|secret\|key\|pass'` — check for unredacted sensitive values.
- **Prevention:** When adding a new device schema, grep for credential-like fields and verify each is matched by a sanitizer rule.
