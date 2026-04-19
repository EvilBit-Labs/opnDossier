# Development Gotchas & Pitfalls

This document tracks non-obvious behaviors, common pitfalls, and architectural "gotchas" in the opnDossier codebase to assist future maintainers and contributors.

## 1. Testing & Concurrency

### 1.1 `t.Parallel()` and Global State

The `cmd/` package uses package-level global variables for CLI flags (required by `spf13/cobra` for flag binding). **Never use `t.Parallel()` in any test that modifies or relies on these global variables.**

- **Problem:** Concurrent tests modifying `sharedDeviceType`, `sharedAuditMode`, or the `rootCmd` flag set will cause non-deterministic data races.
- **Symptom:** `just test-race` fails with "DATA RACE" reports in the `cmd` package.
- **Solution:** Remove `t.Parallel()` from the parent test and all subtests that interact with global flags. Use `t.Cleanup()` to restore original global values after the test.
- **Enforcement:** The `.golangci.yml` `forbidigo` rule forbids `t.Parallel()` anywhere in `cmd/` — catches the regression at lint time. The race detector itself runs only locally via `just test-race` (or `just ci-check`); CI cannot host it reliably, and a prior pre-push `just ci-check` hook broke non-interactive push clients. See [CONTRIBUTING.md § Git Hooks](CONTRIBUTING.md#git-hooks) for the current setup.

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

### 2.4 Info Severity Does Not Bypass Compliance

Reclassified info-severity controls (e.g., FIREWALL-003 "Message of the Day") participate in the compliance map normally — they can PASS or FAIL. Severity only affects presentation priority (summary counts, sort order), NOT compliance status. The compliance flip in `RunComplianceChecks` is never skipped based on severity.

- **Gotcha:** A finding with `Severity == "info"` that references a control still flips that control to non-compliant. This is intentional — severity is triage priority, not compliance gating.
- **Gotcha:** Inventory controls (`Type: "inventory"`) are excluded from `EvaluatedControlIDs` entirely and do not appear in the compliance map. They only appear in "Configuration Notes."
- **Gotcha:** `countSeverities` tracks unrecognized severity strings in a private `unknown` counter. Callers with loggers should warn when `counts.unknown > 0`.

### 2.5 Dynamic Plugin Trust Model

`PluginRegistry.LoadDynamicPlugins` uses `plugin.Open()` to load `.so` files from a directory. Loaded plugins execute with full process privileges — there is no signature verification, checksum validation, or sandboxing.

- **Gotcha:** Any `.so` file in the plugin directory will be loaded and executed. A malicious or compromised plugin has the same access as the opnDossier process itself.
- **Mitigation:** Loading is opt-in: it requires an explicit `--plugin-dir` flag (or the equivalent config key). There is no `./plugins` auto-discovery fallback — `PluginManager.InitializePlugins` only calls `LoadDynamicPlugins` when `pluginDir != ""`. Plugins are never fetched remotely.
- **Prevention:** Restrict filesystem permissions on the plugin directory. Only load plugins built from reviewed source code. In shared or CI environments, avoid pointing `--plugin-dir` at world-writable directories.

**See also:** [docs/solutions/runtime-errors/plugin-panic-recovery-audit-runchecks.md](docs/solutions/runtime-errors/plugin-panic-recovery-audit-runchecks.md) — fault-isolation pattern that contains panics from the untrusted plugins described here.

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
- **Regression tests:** `TestConverter_EnumCast_EmitsWarning` in `pkg/parser/opnsense/converter_enum_cast_test.go` and `pkg/parser/pfsense/converter_enum_cast_test.go` cover every known callsite. When adding a new enum cast, add a row to the table-driven test in the same PR — otherwise the §5.2 defense is invisible.
- **History:** The NATS-145 audit (2026-04-18) discovered two unguarded `IPProtocol` casts in OPNsense `convertOutboundNATRules` and `convertInboundNATRules` that had been silently passing invalid values through for months. Both were fixed in the same audit with the canonical `if field != "" && !cast.IsValid() { addWarning }` pattern.

**See also:** [docs/solutions/logic-errors/opnsense-nat-ipprotocol-enum-cast-missing-guard.md](docs/solutions/logic-errors/opnsense-nat-ipprotocol-enum-cast-missing-guard.md) — full postmortem of the NATS-145 bare-cast audit, including regression-test patterns for new enum callsites.

### 5.3 PreRunE Test Commands Must Bind to Real Globals

When testing `PreRunE` with a temporary `cobra.Command`, bind its flags to the **same** package-level variables the real command uses (e.g., `tempCmd.Flags().StringVar(&auditMode, ...)`). If you bind to local variables instead, `PreRunE` reads stale globals and tests pass vacuously. Always set values via `cmd.Flags().Set()` (not direct assignment) to exercise real pflag parsing.

## 6. Validator

### 6.1 GID/UID Zero is Valid

Unix GID 0 (wheel/root group) and UID 0 (root user) are valid. The validator check is `gid < 0` / `uid < 0`, correctly allowing zero. Error messages must say "non-negative integer", not "positive integer".

**See also:** [docs/solutions/architecture-issues/file-split-refactor-gotchas.md](docs/solutions/architecture-issues/file-split-refactor-gotchas.md) — the validator file-split refactor where this "non-negative integer" fix was applied alongside pre-existing helper issues.

## 7. Parser Registry

### 7.1 Blank Import Requirement

`pkg/parser/factory.go` dispatches through the registry, not via direct imports. The OPNsense parser only registers itself when its package `init()` runs, which requires a blank import: `_ "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"`.

- **Symptom:** `"unsupported device type: root element <opnsense> is not recognized; supported: (none registered -- ensure parser packages are imported)"` -- empty registry with hint
- **Cause:** Missing blank import means `init()` never ran, registry is empty
- **Fix:** Add the blank import to the test file or production file using `parser.NewFactory()`
- **Detection:** Any new test file using `parser.NewFactory()` that sees an empty registry is missing the blank import

**See also:** [docs/solutions/architecture-issues/pluggable-deviceparser-registry-pattern.md](docs/solutions/architecture-issues/pluggable-deviceparser-registry-pattern.md) — the registry pattern whose init-time self-registration is what the blank import activates.

## 8. Audit Command

### 8.1 Mode/Plugin Coupling

Only `blue` mode runs `RunComplianceChecks`. Red mode ignores `SelectedPlugins` entirely. The `--plugins` flag is rejected in `PreRunE` unless `--mode blue` is set.

- **Gotcha:** Adding plugin support to red mode requires wiring `RunComplianceChecks` into `generateRedReport` in `mode_controller.go` AND removing the `--plugins`+non-blue-mode rejection guard in `cmd/audit.go` `PreRunE`.
- **Gotcha:** `--plugins` accepts any name at the CLI level — validation is deferred to `ValidateModeConfig` post-init, which checks against the live `PluginRegistry`. Dynamic plugins loaded via `--plugin-dir` are included automatically when `--plugins` is omitted (the "all available" default).

**See also:** [docs/solutions/logic-errors/cli-prerun-validation-timing-dynamic-plugins.md](docs/solutions/logic-errors/cli-prerun-validation-timing-dynamic-plugins.md) — why plugin-name validation moved from `PreRunE` to post-init and how dynamic `.so` plugins now pass the CLI parse gate.

### 8.2 Concurrent Generation, Serial Emission

`runAudit` in `cmd/audit.go` processes files concurrently via `generateAuditOutput` (returns string, no I/O), then writes results serially via `emitAuditResult` in the parent goroutine.

- **Gotcha:** Never add stdout writes or file exports inside `generateAuditOutput` — all emission must go through `emitAuditResult` to prevent interleaved output.
- **Gotcha:** `--output` is rejected with multiple input files in `PreRunE` to prevent file clobbering.

### 8.3 Multi-File Output Path Uniqueness

`deriveAuditOutputPath` uses lossless tilde-based escaping: tildes in path segments become `~~` and underscores become `~u`, freeing the literal underscore to serve as an unambiguous directory separator. This prevents distinct paths from collapsing to the same filename, including boundary cases where one segment ends with `_` and the next begins with `_` (e.g., `a_/b/config.xml` → `a~u_b_config-audit.md` versus `a/_b/config.xml` → `a_~ub_config-audit.md`).

- **Gotcha:** Simple character replacement (e.g., `/` → `-`) is NOT sufficient — paths like `a-b/c/config.xml` and `a/b-c/config.xml` would collide. The escaping must be lossless (invertible). The earlier double-underscore scheme (`_` → `__`, separator → `_`) was also insufficient — it collapsed at segment boundaries where trailing/leading underscores were indistinguishable from the separator.
- **Gotcha:** Expected output filenames are asserted in 5+ test functions (`TestDeriveAuditOutputPath`, `TestEmitAuditResult_MultiFileAutoNaming`, `TestEmitAuditResult_MultiFileConfigOutputFileIgnored`, `TestDeriveAuditOutputPath_BasenameCollision`, `TestDeriveAuditOutputPath_BoundaryUnderscoreCollision`, etc.). When changing the encoding scheme, grep for all assertion sites — missing one causes CI failure.

### 8.4 Red Mode Stub Implementations

`generateRedReport` in `mode_controller.go` calls five analysis methods (`addWANExposedServices`, `addWeakNATRules`, `addAdminPortals`, `addAttackSurfaces`, `addEnumerationData`) that are all placeholder stubs. Each method writes fabricated metadata (e.g., `"exposed_services_count": 0`, `"admin_portals_found": 1`) without inspecting the actual `CommonDevice` configuration. A CLI warning is emitted in `cmd/audit.go` `PreRunE` when `--mode red` is selected.

- **Gotcha:** Red mode reports look structurally complete (all metadata keys present, no errors) but contain no real analysis. Do not use red mode output for actual security assessments.
- **Gotcha:** When implementing real red mode analysis, each stub method must be replaced individually. The fabricated metadata keys (e.g., `"wan_exposure_scan_completed"`) are not covered by tests asserting specific values, so changing them will not break CI — but consumers relying on the metadata schema should be updated simultaneously.
- **Prevention:** The `PreRunE` warning in `cmd/audit.go` alerts users at invocation time. Remove the warning once the red mode pipeline is fully implemented.

## 9. Dupl Linter Bidirectional Firing

### 9.1 Cross-Type Validator Duplication

When adding device-specific validators that are structurally similar to existing validators (e.g., `validatePfSenseSystem` vs `validateSystem`), the `dupl` linter fires on BOTH files — not just the new one.

- **Gotcha:** Adding `//nolint:dupl` only to the new function is insufficient. The existing function also needs `//nolint:dupl` because `dupl` reports pairs.
- **Pattern:** Both sides of the duplicate pair must carry the suppression directive.

### 9.2 Validator Cascade on Document Field Type Forks

When changing a `Document` field type from an opnsense type to a local pfSense fork (e.g., `opnsense.Dhcpd` → `pfsense.Dhcpd`), the pfSense-specific validator function that accepts a pointer to that type will fail to compile. The shared field-level validator (e.g., `validateDhcpdInterface`) still expects `opnsense.DhcpdInterface`, so the pfSense wrapper must construct a temporary adapter value.

- **Symptom:** `cannot use &doc.Dhcpd (value of type *pfsense.Dhcpd) as *opnsense.Dhcpd`
- **Fix:** Update the pfSense validator signature to accept `*pfsense.Dhcpd` and adapt each item to `opnsense.DhcpdInterface` inside the loop before calling the shared validator.
- **Also update:** Test files (`pfsense_test.go`, `parser_test.go`) that construct `opnsense.Dhcpd{Items: map[string]opnsense.DhcpdInterface{...}}` — change to `pfsense.Dhcpd`/`pfsense.DhcpdInterface`.

## 10. Converter Testing

### 10.1 ToMarkdown Outputs ANSI-Rendered Text

`MarkdownConverter.ToMarkdown()` passes output through `glamour.Render()`, which inserts ANSI escape codes. Tests asserting on the output must set `t.Setenv("TERM", "dumb")` for clean text. Since `t.Setenv` is incompatible with `t.Parallel()`, remove `t.Parallel()` and add `//nolint:tparallel` to the function.

- **Symptom:** `assert.Contains(t, md, "System Configuration")` fails despite the text being present.
- **Fix:** Add `t.Setenv("TERM", "dumb")` at the start of the test (no `t.Parallel()`).
- **Precedent:** `internal/converter/markdown_test.go` uses this pattern throughout.

### 10.2 builder_test.go Uses Raw testing Package

`internal/converter/builder/builder_test.go` does not import `testify/assert`. Use `strings.Contains` + `t.Errorf` for assertions, not `assert.Contains`.

- **Symptom:** `undefined: assert` compilation error in builder tests.
- **Detection:** Check imports at top of test file before adding new test functions.

### 10.3 NAT Rule Field Name Disambiguation

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

## 12. Git Tagging

### 12.1 Tag the Squash-Merge Commit on Main

When tagging a release after a squash-merge PR, always tag the resulting commit **on `main`**, not the PR branch head. Squash-merge creates a new commit on `main` that is not an ancestor of the branch commits. If you tag the branch head instead, the tag points to an orphaned commit that `git log main` and `git describe` will never reach.

- **Symptom:** `git tag --merged main` does not list the release tag; `git describe` on `main` skips the version.
- **Fix:** `git checkout main && git pull && git tag vX.Y.Z && git push origin vX.Y.Z`
- **Prevention:** Always switch to `main` and pull before tagging. Never tag from the feature branch after merge.

## 13. Serialization Testing

### 13.1 Multiline Secret Assertions Against Serialized Output

`assert.NotContains(t, jsonStr, rawPEMKey)` is ineffective for multiline secrets: `encoding/json` escapes embedded newlines as `\n`, and `yaml.v3` may emit block scalars with indentation. The raw PEM substring will often not appear even when the secret is fully present in the output.

- **Symptom:** Test passes even when redaction is broken — the raw multiline string never matches the encoded form.
- **Fix:** Unmarshal JSON/YAML output back into a typed struct and assert on the parsed `PrivateKey` field values directly.
- **Precedent:** `certRedactionReport` in `internal/processor/report_ids_test.go`.

## 14. Sanitizer Rule Engine

### 14.1 `ShouldRedactField` Scans ALL Rules Globally

`ShouldRedactField` checks field names against `FieldPatterns` from **every** rule, not just the rule being tested. Adding a `FieldPattern` to any rule can break "should not match" test assertions for other rules.

- **Symptom:** A new field pattern causes unrelated sanitizer tests to fail.
- **Fix:** Check all rules' `FieldPatterns` when adding new patterns. Test assertions must account for global matching.

### 14.2 Value Detector Ordering

`ShouldRedactValue` checks field-name rules first (`ShouldRedactField`), then value-detector rules. Rules with both `FieldPatterns` and `ValueDetector`: a field match triggers redaction immediately; the value detector only runs on the value-only matching path.

### 14.3 Deterministic Mapper in Tests

A fresh `NewRuleEngine` creates a fresh `NewMapper()` — mappings are deterministic (e.g., first private IP maps to `10.0.0.1`, first hostname to `host-001.example.com`). Always assert exact expected values, not just inequality.

## 15. Liberal Boolean and Integer Parsing

### 15.0 `BoolFlag` vs `FlexBool` vs `FlexInt` vs strict `int`/`bool`

Four boolean/int handling styles coexist in the schema layer — pick the right one.

| Type                  | Where defined                    | XML input semantics                                                                       | Use when                                                                                              |
| --------------------- | -------------------------------- | ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `opnsense.BoolFlag`   | `pkg/schema/opnsense/common.go`  | absent → `false`; `<tag/>` → `true`; `<tag>body</tag>` → `shared.IsValueTrue(body)`       | Field is a boolean toggle in OPNsense/pfSense XML. Absence of the element is meaningful (= disabled). |
| `shared.FlexBool`     | `pkg/schema/shared/flex_bool.go` | body → `shared.IsValueTrue(body)`; no presence semantics                                  | Field is a boolean but the element is always emitted and presence carries no signal.                  |
| `shared.FlexInt`      | `pkg/schema/shared/flex_int.go`  | numeric → that value; `on`/`yes` → 1; `off`/`no` → 0; unknown non-numeric → wrapped error | Field must stay int-typed (may carry a count or a liberal toggle).                                    |
| strict `int` / `bool` | built-in                         | only decimal digits (for `int`); `true`/`false` only (for `bool`)                         | Field is genuinely numeric (UID, GID, PID, MTU) and non-numeric input is a real error.                |

Both OPNsense and pfSense emit the same liberal truthy vocabulary (`1|on|yes|true|enable|enabled`, case-insensitive). Always go through `shared.IsValueTrue` / `shared.IsValueFalse` — never hand-roll a truthy parser at the call site.

`BoolFlag.UnmarshalXML` was upgraded to delegate non-empty bodies through `shared.IsValueTrue` (previously it treated any element presence — even `<tag>0</tag>` — as `true`, silently dropping the body). Any code or test that relied on the old "presence = true regardless of body" behavior needs to be updated. See issue #558 and the plan at `docs/plans/2026-04-18-002-fix-issue-558-parser-on-value.md`.

### 15.1 Pointer-Receiver MarshalXML and Value Marshaling

`opnsense.BoolFlag` implements `MarshalXML` on a pointer receiver (`*BoolFlag`). When a struct containing a `BoolFlag` field is marshaled by value (not pointer), `encoding/xml` cannot find the pointer-receiver method and falls back to default `bool` serialization — producing `<enable>true</enable>` instead of `<enable/>`.

- **Symptom:** `BoolFlag` fields serialize as `true`/`false` text instead of presence-based empty elements.
- **Fix:** Add a private type alias (e.g., `type interfaceAlias Interface`) and a pointer-receiver `MarshalXML` on the parent struct that delegates via `e.EncodeElement((*alias)(ptr), start)`. Also pass `&value` (not `value`) when encoding the struct within map-based containers like `Interfaces.MarshalXML`.
- **Precedent:** `pkg/schema/pfsense/interfaces.go` — `interfaceAlias` and `(*Interface).MarshalXML`.
- **Rule:** Any pfSense struct forked from opnsense that changes a field to `BoolFlag` needs this pattern.
- **Scope:** The same pointer-receiver caveat applies to `shared.FlexBool` and `shared.FlexInt` — their `MarshalXML` methods are also pointer-receiver. Any struct embedding one of these types that is subsequently marshaled by value (not pointer) will silently fall back to Go's default `bool`/`int` serialization, producing `<tag>true</tag>` or `<tag>42</tag>` instead of the canonical form. Use the same alias + pointer-receiver `MarshalXML` workaround on the parent struct.

**See also:** [docs/solutions/runtime-errors/liberal-boolean-xml-parsing-opnsense-pfsense.md](docs/solutions/runtime-errors/liberal-boolean-xml-parsing-opnsense-pfsense.md) — full rollout of `BoolFlag`/`FlexBool`/`FlexInt` across OPNsense + pfSense schema, including the issue #558 `<tag>0</tag>` fix.

## 16. pfSense IPsec Enabled Flag

### 16.1 Phase 1 Is the Gate

`convertIPsec()` in `pkg/parser/pfsense/converter_services.go` sets `common.IPsecConfig.Enabled = true` **only when `len(ipsec.Phase1) > 0`**. Phase 2 tunnels and the mobile client configuration hang off Phase 1 in pfSense — without a Phase 1 entry they are functionally inactive, so the converter treats them as orphans: `Enabled` stays `false` and a medium-severity `ConversionWarning` is emitted for each orphan kind (`IPsec.Phase2`, `IPsec.Client`).

Downstream consumers (e.g., `builder_vpn.go`) short-circuit to "No IPsec configuration present" when `Enabled` is false — this is the correct behavior for orphan-only data, but breaks silently if the Phase 1 gate is ever weakened.

- **Symptom:** Valid Phase 1 tunnels show as "No IPsec configuration present" in reports (gate broken, `Enabled` stuck at `false`).
- **Detection:** `TestConverter_IPsecEnabled_Gotchas16` in `pkg/parser/pfsense/converter_ipsec_test.go` is the canonical regression. If that test fails, the gate has drifted.
- **Fix:** Keep the Phase 1 guard in `convertIPsec` intact. Phase 2 or mobile client without Phase 1 must stay orphan-warned, not implicitly promoted to `Enabled`.

## 17. HybridGenerator Interface Coupling

### 17.1 reportGenerator Must Stay Subset of ReportComposer

`hybrid_generator.go` defines `reportGenerator` — a narrow interface that `HybridGenerator` uses internally. `NewHybridGenerator` accepts `builder.ReportBuilder`, which embeds `ReportComposer`. The constructor stores the `ReportBuilder` value into a field typed as `reportGenerator`. If a method is added to `reportGenerator` without also adding it to `ReportComposer`, the `ReportBuilder` interface no longer satisfies `reportGenerator`, and the assignment in `NewHybridGenerator` fails at compile time. Note: there is no standalone `var _ reportGenerator = ...` assertion — the compile-time check occurs at the assignment site in the constructor.

- **Symptom:** `cannot use reportBuilder (variable of interface type builder.ReportBuilder) as reportGenerator value`
- **Fix:** Add the method to both `reportGenerator` (in `hybrid_generator.go`) and `ReportComposer` (in `builder/builder.go`).
- **Precedent:** `SetIncludeTunables` established this pattern; `SetFailuresOnly` was added following the same approach.

### 17.2 narrowOnlyBuilder Test Mock

`hybrid_generator_test.go` defines `narrowOnlyBuilder` — a minimal mock satisfying `reportGenerator` but NOT `ReportBuilder`. Adding a method to `reportGenerator` requires updating this mock.

- **Symptom:** `*narrowOnlyBuilder does not implement reportGenerator (missing method X)`
- **Fix:** Add a no-op method to `narrowOnlyBuilder` in `hybrid_generator_test.go`.

**See also:** [docs/solutions/logic-errors/documentation-code-drift-interface-refactoring.md](docs/solutions/logic-errors/documentation-code-drift-interface-refactoring.md) — the `ReportBuilder` → `SectionBuilder`/`TableWriter`/`ReportComposer` split that produced this coupling and its documentation-drift aftermath.

## 18. Kea DHCP4 Schema Version Pinning

### 18.1 Element Names Tied to MVC Model Version

The `KeaDhcp4` schema types in `pkg/schema/opnsense/kea.go` parse child elements named `subnet4` (under `<subnets>`) and `reservation` (under `<reservations>`), matching the OPNsense MVC model `KeaDhcpv4.xml` v1.0.4. If a future OPNsense release renames these elements, the Go XML decoder will silently produce empty slices — no error, no warning, just missing data.

- **Symptom:** Kea DHCP configured in OPNsense but opnDossier reports "no Kea subnets."
- **Detection:** Compare `KeaDhcp4.Version` attribute against known versions. If it differs from `1.0.4`, investigate element name changes.
- **Prevention:** When adding support for newer Kea MVC model versions, verify element names match by testing against a real config.xml from that version.

### 18.2 Pools Are Newline-Separated Inline Strings

Kea's `<pools>` element on each `<subnet4>` stores newline-separated (`\n`) IP range or CIDR strings via `KeaPoolsField` — NOT comma-separated UUIDs referencing a separate container. There is no `<pools>` container at the dhcp4 level.

- **Gotcha:** Only the first pool entry is represented in `DHCPScope.Range`. A conversion warning is emitted when multiple pools exist.
- **Source:** Confirmed via `KeaPoolsField.php` in OPNsense core.

### 18.3 Reservations Reference Subnets, Not Vice Versa

`KeaReservation.Subnet` contains the UUID of the parent subnet. The converter groups reservations by this field to attach them as static leases. Orphaned reservations (referencing nonexistent subnet UUIDs) emit a conversion warning.

- **Gotcha:** This is the inverse of what the OPNsense MVC model XML might suggest at first glance. The `<reservations>` container is a flat sibling of `<subnets>`, not nested inside each subnet.

## 19. Sanitizer Rule Ordering

### 19.1 `authserver_config` Must Precede `password` in `builtinRules()`

`ShouldRedactField` iterates the rule slice and returns on the first match. Both `authserver_config` and `password` match LDAP bind password fields — `authserver_config` via the exact pattern `authserver.ldap_bindpw`, and `password` via the `pass` substring. The `authserver_config` rule pseudonymizes the value through `MapAuthServerValue`; the `password` rule flat-redacts to `[REDACTED-PASSWORD]`.

- **Problem:** If `password` is moved above `authserver_config` in the `builtinRules()` slice, `ldap_bindpw` values silently switch from pseudonymized to flat-redacted. No error or warning is emitted.
- **Symptom:** Sanitized output shows `[REDACTED-PASSWORD]` for LDAP bind passwords instead of a pseudonymized value like `ldap-bindpw-001`.
- **Fix:** Ensure `authserver_config` remains the first rule in `builtinRules()`. The same first-match precedence applies to `email` vs `hostname` (email must precede hostname).
