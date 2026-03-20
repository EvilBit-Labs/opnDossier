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

## 3. Data Processing

### 3.1 Map Iteration Order

Go map iteration is non-deterministic.

- **Gotcha:** Any CLI output or file export derived from a map (e.g., `report.Compliance`, `report.Metadata`) must be sorted before rendering.
- **Solution:** Use `slices.Sorted(maps.Keys(m))` or `slices.SortFunc()` to ensure deterministic, testable output.

### 3.2 XML Presence vs. Absence

The `encoding/xml` package treats self-closing tags (e.g., `<disabled/>`) and missing tags identically for `string` fields.

- **Gotcha:** Use `*string` (pointer to string) when you need to distinguish between "element present but empty" (`""`) and "element absent" (`nil`).

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

## 6. Validator

### 6.1 GID/UID Zero is Valid

Unix GID 0 (wheel/root group) and UID 0 (root user) are valid. The validator check is `gid < 0` / `uid < 0`, correctly allowing zero. Error messages must say "non-negative integer", not "positive integer".

## 7. Parser Registry

### 7.1 Blank Import Requirement

`pkg/parser/factory.go` dispatches through the registry, not via direct imports. The OPNsense parser only registers itself when its package `init()` runs, which requires a blank import: `_ "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"`.

- **Symptom:** `"unsupported device type: root element <opnsense> is not recognized; supported: "` -- empty supported list
- **Cause:** Missing blank import means `init()` never ran, registry is empty
- **Fix:** Add the blank import to the test file or production file using `parser.NewFactory()`
- **Detection:** Any new test file using `parser.NewFactory()` that sees an empty registry is missing the blank import
