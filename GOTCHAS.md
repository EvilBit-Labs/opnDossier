# Development Gotchas & Pitfalls

This document tracks non-obvious behaviors, common pitfalls, and architectural "gotchas" in the opnDossier codebase to assist future maintainers and contributors.

## 1. Testing & Concurrency

### 1.1 `t.Parallel()` and Global State

The `cmd/` package uses package-level global variables for CLI flags (required by `spf13/cobra` for flag binding). **Never use `t.Parallel()` in any test that modifies or relies on these global variables.**

- **Problem:** Concurrent tests modifying `sharedDeviceType`, `sharedAuditMode`, or the `rootCmd` flag set will cause non-deterministic data races.
- **Symptom:** `just test-race` fails with "DATA RACE" reports in the `cmd` package.
- **Solution:** Remove `t.Parallel()` from the parent test and all subtests that interact with global flags. Use `t.Cleanup()` to restore original global values after the test.
- **Enforcement:** The `.golangci.yml` `forbidigo` rule forbids `t.Parallel()` anywhere in `cmd/` — catches the regression at lint time, which is the only automated gate for this class. The race detector is **local-only**, via `just test-race` (or `just ci-check`); it is deliberately not a CI job — see § 1.7. A prior pre-push `just ci-check` hook broke non-interactive push clients, so the full gate is still not wired to a git hook. See [CONTRIBUTING.md § Git Hooks](CONTRIBUTING.md#git-hooks) for the current setup.

### 1.2 Race Detector Collateral

When a data race occurs in a test touching global state, the Go race detector may report collateral races in unrelated, stateless functions (e.g., `truncateString` or `escapePipeForMarkdown`) that happen to be running in other parallel tests.

- **Rule of Thumb:** If a stateless utility function is reporting a race, check if a concurrent test is modifying a global variable.

### 1.3 `require.*` Inside Goroutine Bodies Fails `testifylint go-require`

`require.NoError` / `require.NotNil` and other `require.*` calls invoke `t.FailNow`, which is only valid on the test's main goroutine. The `testifylint` linter (`go-require` rule) flags any `require.*` inside a goroutine body — `golangci-lint run` will fail at commit time even when the test passes at runtime.

- **Pattern:** collect per-goroutine outcomes into shared slices, then assert with `require.*` from the main test goroutine after `wg.Wait()`.
- **Live example of the safe side:** the concurrent `prepareForExport` test in `internal/converter/enrichment_test.go` runs eight goroutines that report failures with `t.Errorf` rather than `require.*`, so the linter is satisfied and no goroutine calls `FailNow`. When you need a halt-the-test assertion, collect each goroutine's outcome into a shared slice and run the `require.*` loop after `wg.Wait()` on the main goroutine.
- **`assert.*` is fine inside goroutines** — it doesn't call `FailNow`. Use `assert` for soft checks during the goroutine, `require` for halt-the-test checks after the join.

### 1.4 `goconst` Trips on Fixture-Derived String Duplication

The `goconst` linter flags string literals appearing 3+ times in the same package. Tests that hand-write a hostname or other fixture-derived string already present in `generateSmallConfig`/`generateLargeConfig` add a fourth occurrence and fail lint.

- **Wrong:** `expected := "small-config"` in a new test.
- **Right:** `expected := smallConfig.System.Hostname` — sources from the fixture and stays in sync if the fixture changes.
- **Avoid extracting a package-level constant** unless you're going to refactor the fixture builders to use it too — partial extraction keeps the lint warning and adds drift surface.

### 1.5 `gocognit` Threshold Is 40, Not the Default

The `.golangci.yml` `gocognit` linter is configured to fail at cognitive complexity > 40 (the default is 30). Table-driven benchmark functions that fan out 4+ sub-benchmarks via `b.Run` routinely trip it — `BenchmarkMultiFormatExport` (NATS-37) was the canonical case.

- **Fix pattern:** extract per-variant closures into helper functions returning `func(*testing.B)` (e.g., `runMultiFormatGenerate(ctx, gen, device, formats, preEnrich) func(*testing.B)`). Each helper drops the cognitive count of the enclosing function below the threshold without changing the test surface.
- **Don't:** add `//nolint:gocognit` to mask it. The threshold catches a real readability drift; helper extraction fixes both the lint and the readability.
- **Recurrence vector:** any test/benchmark orchestration function that grows from 2 to 4+ dispatch arms inside a `for _, tc := range cases` loop.

### 1.6 Wall-Clock Assertions and `-race`

Race instrumentation multiplies execution cost, so a latency assertion calibrated without it measures the instrumentation. On a loaded machine `TestPerformanceBaselines` failed 10 of 10 runs under `-race` and passed 10 of 10 without it — one of the reasons the detector is local-only (§ 1.7).

- **Rule:** never add a wall-clock upper bound to a test without deciding what it does under `-race`.
- **Pattern:** `internal/testing/racedetect.Enabled` is a build-tagged constant. Skip the assertion when the test is a latency baseline (`TestPerformanceBaselines`), or scale the bound when the bound is a coarse guard rather than a measurement (`cancelAbortBudget` in `internal/converter`, which only needs to tell "aborted" apart from "generated the whole document").
- **Subprocess builds:** a test that shells out to `go build` gets no benefit from a `-race` run (the child is not instrumented) and pays for it twice: the build cache holds only race-flavored artifacts, so the child compiles cold, and a deadline calibrated against a warm cache kills it. `build_test.go` skips under `racedetect.Enabled` for exactly this reason.
- **Do not** reach for `-short` to dodge this. It also skips the stress and thread-safety tests, which are the ones most worth running under the detector.

### 1.7 The Race Detector Is Local-Only, Deliberately

`just test-race` runs the detector locally and is part of `just ci-check`. It is **not** a CI job, and adding one back is a regression, not an improvement.

GitHub's shared runners cannot host it reliably. The instrumented suite is slow and contended enough that the job fails without producing a usable signal — the last attempt exited non-zero after every one of the ~40 packages reported `ok`, with no data race, no failing test, and no error text anywhere in the log, then passed on a retry with no code change. A gate that red-lights a clean tree and greens a rerun teaches contributors to re-run it rather than to read it, which is worse than not having it.

- **Where the protection actually comes from:** the `forbidigo` rule in `.golangci.yml` forbids `t.Parallel()` in `cmd/` at lint time (§ 1.1), and `just ci-check` runs the detector before you push.
- **If you re-add the job, you must also re-add its Mergify gates.** `.mergify.yml` lists `check-success` conditions in three places (the dependabot queue, the `default` queue, and the `Full CI must pass` rule). Removing a job without removing its gates deadlocks every PR on a check that never reports; adding a job without adding its gates means nothing enforces it.
- **The `-race` accommodations in the test suite stay.** `internal/testing/racedetect.Enabled` and the skips it drives (§ 1.6) exist for the local run and are still load-bearing.
- **The PR that removes a gated check cannot pass its own gate.** Mergify evaluates `.mergify.yml` from the **base** branch, so a PR deleting a job is still judged against `main`'s copy, which still requires it — `Full CI must pass` sits at "Waiting checks: `<job>`" indefinitely. This is not a misconfiguration and cannot be fixed from inside the PR; a maintainer merges it manually, and every PR afterwards uses the new config. The repo already routes workflow changes this way: the `Auto-queue` protection excludes any PR touching `.github/workflows/`.

## 2. Plugin Architecture

### 2.1 Registry Independence

`audit.PluginManager` owns its own `PluginRegistry` instance — there is no package-level global registry to opt into (the deprecated `GetGlobalRegistry`/`RegisterGlobalPlugin`/`GetGlobalPlugin`/`ListGlobalPlugins` singleton was removed; it had no production caller).

- **Gotcha:** Two `PluginManager` instances constructed with `NewPluginManager(logger, nil)` each allocate a private registry and do **not** see each other's registrations. Pass the same `*PluginRegistry` to `NewPluginManager` when multiple managers or subsystems must observe the same plugin set.
- **Requirement:** A dynamically loaded `.so` plugin is registered by the loader through its exported `Plugin` symbol into whichever `*PluginRegistry` the caller supplied to `NewPluginManager` — there is no separate "global" registration step.

### 2.2 Panic Recovery Retains Plugins

`RunComplianceChecks` wraps each plugin's `RunChecks()` in `defer recover()`. On panic, a dedicated recovery path populates `PluginFindings`, `PluginInfo`, and `Compliance` with safe defaults, then uses `continue` to skip further method calls on the potentially corrupt plugin.

- **Gotcha:** The recovery path must NOT call methods on the panicked plugin (`Name()`, `Version()`, `Description()`, `GetControls()`) — the plugin's internal state may be corrupt after the panic. Instead, it uses the `pluginName` string already in scope and sets `Version: "unknown (panicked)"` with an empty compliance map.
- **Invariant:** Every selected plugin must appear in all result maps, even if it panicked.

### 2.3 SetPluginDir Must Precede InitializePlugins

`PluginManager.SetPluginDir(dir, explicit)` configures the directory for dynamic `.so` loading. It must be called **before** `InitializePlugins(ctx)` because `InitializePlugins` reads `pm.pluginDir` only during its execution. Calling `SetPluginDir` after `InitializePlugins` mutates the field but has no observable effect on plugin loading because `InitializePlugins` has already completed.

### 2.4 Info Severity Does Not Bypass Compliance

Reclassified info-severity controls (e.g., FIREWALL-003 "Message of the Day") participate in the compliance map normally — they can PASS or FAIL. Severity only affects presentation priority (summary counts, sort order), NOT compliance status. The compliance flip in `RunComplianceChecks` is never skipped based on severity.

- **Gotcha:** A finding with `Severity == "info"` that references a control still flips that control to non-compliant. This is intentional — severity is triage priority, not compliance gating.
- **Gotcha:** Inventory controls (`Type: constants.FindingTypeInventory`) are excluded from the `evaluated` slice `RunChecks` returns, so they never enter the compliance map. They only appear in "Configuration Notes." (This slice was historically called `EvaluatedControlIDs`; that field no longer exists.)
- **Gotcha:** `applyFindingsToCompliance` skips inventory findings on an exact `Type` match, and `Finding.Type` is an unvalidated string supplied by the plugin. A finding mislabeled as inventory would exempt itself from the compliance flip, so the skip warns when an inventory-typed finding carries `high`/`critical` severity, and warns again on any `Type` that `constants.IsValidFindingType` does not recognize. The exemption still applies — a plugin must not be able to change gate behavior — but it is no longer silent.
- **Gotcha:** `countSeverities` tracks unrecognized severity strings in a private `unknown` counter. Callers with loggers should warn when `counts.unknown > 0`.

### 2.5 Dynamic Plugin Trust Model

`PluginRegistry.LoadDynamicPlugins` uses `plugin.Open()` to load `.so` files from a directory. Loaded plugins execute with full process privileges — there is no signature verification, checksum validation, or sandboxing.

- **Gotcha:** Any `.so` file in the plugin directory will be loaded and executed. A malicious or compromised plugin has the same access as the opnDossier process itself.
- **Mitigation:** Loading is opt-in: it requires an explicit `--plugin-dir` flag (or the equivalent config key). There is no `./plugins` auto-discovery fallback — `PluginManager.InitializePlugins` only calls `LoadDynamicPlugins` when `pluginDir != ""`. Plugins are never fetched remotely.
- **Prevention:** Restrict filesystem permissions on the plugin directory. Only load plugins built from reviewed source code. In shared or CI environments, avoid pointing `--plugin-dir` at world-writable directories.

**Phase A hardening (v1.5).** Before `plugin.Open` is invoked, `runPluginPreflight` in `internal/audit/plugin_preflight.go` rejects the following footguns and emits a structured audit log per attempt:

- **Symlinks rejected** via `os.Lstat` + `os.ModeSymlink` check. `plugin.Open` follows links, so an attacker with write access to the plugin directory could otherwise point a `.so` at anything on the filesystem.
- **Non-regular files rejected** via `info.Mode().IsRegular()` (cross-platform). A FIFO, socket, or device node named `*.so` would otherwise block `hashFileSizeCapped` indefinitely on `os.Open` or `io.CopyN` before `plugin.Open` is ever reached — a DoS primitive trivially reachable on POSIX.
- **Group/world-writable plugin files rejected** when `info.Mode().Perm()&0o022 != 0` (POSIX only). Closes CWE-732 where another local account could swap the file between audits.
- **Group/world-writable container directory rejected** via a second `os.Stat` on `filepath.Dir(path)` (POSIX only). The file bits alone are not enough — a writable parent lets an attacker unlink and replace the plugin.
- **Absolute plugin file paths required at preflight** via `filepath.IsAbs` (cross-platform, defense-in-depth). Relative `--plugin-dir` inputs from the operator are accepted and normalized via `filepath.Abs` before the preflight runs, so `--plugin-dir ./plugins` is a supported invocation; the absolute-path check then fires if any caller ever bypasses `LoadDynamicPlugins` and hands a relative path directly to `runPluginPreflight`.
- **Structured audit log per load attempt**: INFO for accepted loads, WARN for rejections, with fields `plugin`, `path`, `sha256`, `mode`, `owner_uid`, `mtime`, `size_bytes`, `verdict`, `reason`. The logged `path` is the normalized absolute plugin artifact path, and the SHA-256 is computed with a 64 MiB read cap so a pathological `.so` bounds preflight I/O and CPU time (the hasher streams rather than buffers, so this is a time/throughput cap, not a memory-allocation cap).

Rejections are reported as `PluginLoadError` entries in the returned `LoadResult`, so callers see identical wiring for preflight and `plugin.Open` failures.

**Phase B follow-ups (post-v1.5, tracked in todo #146):** owner-UID check (refuse `.so` whose UID does not match the process UID or a configured allowlist), hard configurable size cap (`--plugin-max-size-mb`), path denylist (`/tmp`, `/var/tmp`, `/dev/shm`, `$HOME` when EUID==0), filename allowlist (no NUL / shell metachars / path separators), optional `plugins.sha256` manifest enforcement, documented seccomp/landlock sandboxing recipe, and — aspirationally — out-of-process plugin isolation à la HashiCorp go-plugin.

**Windows behaviour.** POSIX permission bits are meaningless on NTFS, so the writable-mode and writable-dir rejections are skipped at runtime when `runtime.GOOS == "windows"`. The symlink and absolute-path checks still run. The `owner_uid` audit field is emitted as `unavailable` on Windows; Phase B will introduce a SID-aware ownership check if needed.

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
- **Detection:** Compare parsed struct against raw XML — earlier occurrences are silently overwritten by later ones. A quick sweep: walk each fixture in `testdata/` and report every `(parent, child)` pair where `child` appears more than once under one parent instance, then check that the matching schema field is a slice.
- **Fix:** Change the field type from `string` to `[]string` with the same `xml` tag.
- **Known instance (fixed):** `<dnsserver>` repeats once per resolver in both `<system>` and each `<dhcpd><interface>` scope. `pfsense.System.DNSServers` was already `[]string`, but `DHCPInterface.Dnsserver` was a scalar on both vendors, so every DHCP scope silently reported only its last resolver — including in `testdata/pfsense/config-pfSense.xml`, which configures two on `lan`, `opt1` and `opt5`. This reached the JSON/YAML export. `common.DHCPScope` gained `DNSServers` (`dhcp[].dnsServers`, an array); the old scalar `DNSServer` is retained and deprecated per the public-API deprecation policy, and `SetDNSServers` keeps it mirroring the first entry so the two cannot drift. `TestParser_ConfigPfSense_DHCPScopesKeepEveryDNSServer` guards the parse, `TestDHCPScope_SetDNSServers` the invariant.
- **The two schemas drift apart, and the pfSense side is usually right.** `pkg/schema/pfsense` modelled `Group.Member`, `Group.Priv` and `User.Priv` as `[]string` while `pkg/schema/opnsense` had the first two as `string` and omitted the third entirely, so the same three-member group read as one member on OPNsense and three on pfSense. When you touch a repeated element in one schema, diff it against its sibling: an asymmetry is either a real vendor difference or a bug, and it is nearly always a bug.
- **A slice is not automatically safe — check what element it is bound to.** `Sysctl []SysctlItem` with `xml:"sysctl"` tells `encoding/xml` that `<sysctl>` itself repeats. The vendor instead writes one `<sysctl>` container holding repeated `<item>` children, so every tunable in the file collapsed into a single entry with empty `Tunable` and `Value` — 287 tunables across the shipped fixtures reduced to one blank row per file, and a config with no tunables decoded identically to a config with two hundred. Either bind through the container (`xml:"sysctl>item"`) or give the slice its own `UnmarshalXML`, as `SysctlItems` does, when both the container and a legacy flat shape must decode. Watch for a scalar field that exists only to absorb the mis-parse: it is a sign the binding is wrong, not that the vendor writes a scalar there. `SysctlItem.Item` was exactly that, and was deleted once the binding was corrected — nothing could populate it any more, and leaving it would have kept the evidence of the bug in the public shape.
- **Writing an `UnmarshalXML`? Check whether its siblings pair one.** Every other custom container in `pkg/schema/opnsense` — `Dhcpd`, `Interfaces`, `InterfaceList` — defines `MarshalXML` alongside. `SysctlItems` shipped without one, so the encoder fell back to the default and emitted one `<sysctl>` element per tunable in the legacy flat shape instead of one container of `<item>` children. Nothing failed: the values round-tripped, because the unmarshaler accepts both shapes. The document simply stopped being what the vendor writes, and `pkg/parser/opnsense/roundtrip_test.go` does not touch sysctl, so nothing noticed. A one-directional custom codec is worth a second look on its own — but the cheaper signal is the neighbours, since an unpaired type in a package where every sibling pairs is a stronger smell than the asymmetry read cold.
- **The value parsed correctly and still never appeared?** That is a different failure with its own entry — see §3.6. Dumping the schema struct tells the two apart: a value missing from the dump was lost here, one present in the dump but absent from the export was lost at the converter. Reach for the sweep in §3.6 only after this one comes back clean, since a wrong binding hides a converter gap behind it.

### 3.4 Empty Placeholder Elements Become Phantom Entries

OPNsense and pfSense write a self-closing placeholder inside a container when nothing of that type is configured — `<staticroutes><route/></staticroutes>`, `<bridges><bridged/></bridges>`, `<ppps><ppp/></ppps>`. The shipped DTD declares `<!ELEMENT bridged EMPTY>` for exactly this reason. Each placeholder unmarshals into a one-element slice holding a struct whose configuration fields are all zero — `XMLName` is populated, which is the whole reason the predicates below compare named fields rather than the zero value — so a converter that appends unconditionally produces a phantom entry in `CommonDevice`.

- **Symptom:** A firewall with none of the resource configured reports one. `opndossier convert testdata/sample.config.5.xml --format json | jq -c '{ppps, routes: .routing.staticRoutes}'` returned `{"ppps":[{}],"routes":[{}]}` before the guards landed.
- **Impact is not just counting.** Two consumers break in user-visible ways. `CommonDevice.HasRoutes` is a has-data predicate that decides whether a report renders a routing section at all, so a phantom renders a routing section for a firewall that has no routing configuration. `internal/diff/analyzer_routing.go` compares `len(StaticRoutes)` for both its section-added guard and its `"%d routes"` count, so a phantom on one side alone reports a spurious route-count change. A third consumer, `internal/analysis/unused.go`, iterates the slice but is unharmed: it only calls `addRef(route.NetworkRef)`, and `NamedObjects.Ref("")` returns nil for a phantom's empty network, so no bogus reachability root is added.
- **`reflect.DeepEqual` against the zero value cannot detect it.** Every schema element type carries `XMLName xml.Name`, which `encoding/xml` populates on unmarshal, so a decoded `<ppp/>` is never equal to `PPP{}`. A reflect-based guard silently never matches and becomes dead code.
- **Fix:** guard at the converter boundary with a field-explicit predicate. Each guarded type carries an `IsPlaceholder()` method in `pkg/schema/opnsense`; both parsers consume those same types, so one predicate serves every call site. Keep it conservative — drop an entry only when every *configuration* field is zero (`XMLName` is excluded, since the decoder always sets it), so one carrying a description alone survives. Under-reporting configured resources is the more dangerous direction for an auditing tool.
- **Also drop the preallocation.** A guarded loop may skip an append, so `make([]T, 0, len(src))` violates the preallocation rule in `AGENTS.md` § Mandatory Practices item 7. Use `var result []T` — which also makes a placeholder-only container return nil rather than an empty slice.
- **Regression tests:** the `*_IsPlaceholder_DecodedEmptyElement_ReportsPlaceholder` tests in `pkg/schema/opnsense` fail loudly if the `XMLName` premise ever stops holding. The `*_EndToEnd_PlaceholderNotCounted` tests in both parser packages drive XML through parse and convert, which the struct-building converter tests never did — that gap is why this shipped undetected.
- **Adding a field to a guarded struct?** `TestIsPlaceholder_EveryFieldDefeatsPlaceholder_NoFieldIsSilentlyUncovered` (`pkg/schema/opnsense/placeholder_test.go`) sets each non-`XMLName` field in isolation and asserts the entry survives, so a field missing from a predicate fails there instead of silently dropping real config. It has no allowlist to drift, and a field type it cannot populate fails loudly rather than being skipped — extend the test and the predicate together.
- **Eight element types are guarded**, matching every `EMPTY` declaration `testdata/opnsense-config.dtd` makes for a repeated element: `route`, `bridged`, `ppp`, `gif`, `gre`, `lagg`, `vip`, and `vlan`. When adding a repeated-element container, grep that DTD for `<!ELEMENT <name> EMPTY>` — a hit means the vendor emits a placeholder and the converter needs a guard. Do not assume a container is clean because no phantom has been reported: the second five were found only because the first three were fixed and someone re-checked the DTD against the fixture.

### 3.5 "any" Has Four Spellings in the Common Model

An endpoint that matches every host reaches `common.RuleEndpoint.Address` as any of four values, and a check comparing against one of them misses the rest:

- `"any"` -- what the converters normalize `<any/>`, `<any>1</any>` and `<network>any</network>` to
- any casing of it -- the vendor XML is not case-normalized
- `""` -- an omitted or empty `<source>`/`<destination>` element; a rule with no source matches every source, and `testdata/gateway_groups_test.xml` contains such a `<rule>`
- `0.0.0.0/0` and `::/0` -- what automation and hand-edited configs write

**Use `analysis.IsAnyEndpoint` / `analysis.IsAnyPort` / `analysis.IsAnyProtocol` / `analysis.IsWideOpenPassRule`**, never a bare `== constants.NetworkAny`. Reach for `IsAnyEndpoint` rather than `IsAnyAddress` whenever you hold a `common.RuleEndpoint`: the endpoint also carries `Negated`, and a negated wildcard matches nothing rather than everything. Sixteen sites across `internal/plugins/{firewall,sans,stig}` and `internal/analysis/{detect,engine}` had the bare comparison, so a WAN pass rule matching all traffic reported compliant on FIREWALL-022 and FIREWALL-023.

- **Detection:** build the same rule five ways (`any`, `ANY`, `""`, `0.0.0.0/0`, `::/0`) and assert the check fires on all five. `TestFirewallPlugin_AnyAnyPassRule_AllAnySpellings` is the pattern.
- **Deliberately not converted:** `isBlockAllRule` and `isTerminalDenyRule` in `detect.go` identify *default-deny* rules, so widening them widens an exemption rather than a detection, and `isBlockAllRule` carries a byte-for-byte legacy output contract. `isAnyAddressSet` in `overlap.go` also stays as-is: the overlap engine does real CIDR containment, where treating `0.0.0.0/0` as an unconditional wildcard would make it cover IPv6 targets it cannot match.
- **Test fixtures:** hand-built `common.FirewallRule` values that leave `Source` unset now read as "any source". Pin an explicit address when a test is about something else, or it will trip the permissive-rule detectors.

### 3.6 Values Parsed But Never Converted

The schema and `CommonDevice` are separate models, and a value can be decoded correctly into the first yet never reach the second. Nothing errors, and the tests that exercise converters by building structs by hand never notice, because they only assert on the fields the converter already sets.

- **Symptom:** the value is present in `config.xml` and in the parsed schema struct, absent from every output format. `filter.rule.tag` decoded fine on pfSense and was simply never assigned; `model.FirewallRule` had no `Tag` field at all while `model.NATRule` had one, so the mark-then-match pairs that implement egress policy read as unconditional rules.
- **Detection:** extract every non-empty XML leaf value from a fixture, run `convert --format json`, and report values that appear in the file but in no output. Separate the two layers by also comparing against a raw `xml.Unmarshal` into the schema type — a value missing from the schema dump is a parse bug (§3.3), one present there but missing from the export is this. Expect false positives wherever the converter deliberately reshapes: aliases are split from `10.0.0.1 10.0.0.2` into a `members` list, `system.timeservers` likewise, and secrets are excluded on purpose.
- **Fix:** add the field to `pkg/model` if it is missing, then map it in *both* converters. The two are edited independently and drift, so fix the pair together.
- **Declared gaps are not this.** `pfsense.KnownGaps()` lists the `CommonDevice` subsystems the pfSense converter knowingly leaves empty, and each emits a conversion warning. Check that list before treating an empty subsystem as a bug.
- **A value can also be dropped before it ever reaches the schema struct, one layer earlier than the usual case above.** `internal/cfgparser/xml.go`'s `handleStartElement` dispatches each top-level `<opnsense>` child through a hand-maintained `switch` that mirrors the `xml:` tags on `schema.OpnSenseDocument`. It had no case for `aliases`, so a config using the legacy top-level `<aliases>` block (predating the MVC Firewall/Alias subsystem — see `schema.OpnSenseDocument.Aliases`) decoded to `namedObjects: null` even though the field existed on the schema struct and the converter (`convertNamedObjects` in `pkg/parser/opnsense/converter_aliases.go`) already read it correctly. No shipped fixture used that shape, so nothing failed until `testdata/opnsense-legacy-aliases.xml` was added.
  - **Guard:** `TestHandleStartElement_DispatchCoversEverySchemaField` in `internal/cfgparser/dispatch_coverage_test.go` parses `xml.go` via `go/ast`, extracts every case label in `handleStartElement`'s switch *together with the `doc.<Field>` it decodes into*, and reflects over `schema.OpnSenseDocument`'s `xml:` tags to assert a 1:1 pairing. It fails on a missing case (a new top-level element added to the schema with nothing dispatching it) and — checking the target, not just the label — on a case that decodes into the wrong field (a copy-paste swap between adjacent, structurally identical elements like `gifs`/`gres`/`laggs`, which a label-only check would miss).
  - **When adding a new top-level `<opnsense>` child element to the schema, add its dispatch case in the same change.** The coverage test will fail the build if you forget; it will not tell you if you *misroute* one unless the swap changes which field is referenced in the case body.

## 4. Diff Engine

### 4.1 Section-Level Added/Removed Guards

Most `Compare*` methods in `internal/diff/analyzer.go` have early-return guards that emit a single `ChangeAdded` or `ChangeRemoved` when one side has data and the other does not. For pointer types (`*common.System`), this uses nil checks. For value types (`NATConfig`, slices), this uses `HasData()` or `len() == 0`. New `Compare*` methods must follow this pattern.

- **Exceptions:** `CompareFirewallRules` and `CompareUsers` intentionally omit section-level guards because per-item granularity is more useful for security-sensitive resources (individual rule additions/removals are reported separately).

### 4.2 Rule and User Equality Helpers Must Cover Every Model Field

`rulesEqual` and `usersEqual` in `internal/diff` decide whether a paired item is reported as modified. A field missing from either helper does not produce a weaker diff entry -- it produces **no entry at all**, silently.

Both had drifted badly: `rulesEqual` compared 7 of `common.FirewallRule`'s 33 fields and `usersEqual` 5 of `common.User`'s 7 (the denominators are now 35 and 8, after `Tag`/`Tagged` and `Privileges` landed; the guards forced the equality helpers to cover them, which is the point). A diff stayed silent on a rule's direction being reversed, a rule becoming floating or quick, its gateway being redirected, its state type weakened, its logging turned off, and on a user's UID changing or an API credential being added, rotated or removed.

- **When you add a field to `common.FirewallRule` or `common.User`, add it to the equality helper.** `TestRulesEqual_ComparesEveryFirewallRuleField` and `TestUsersEqual_ComparesEveryUserField` walk the struct reflectively and fail until you do.
- **Only identity fields belong on the ignore list.** `UUID` and `Tracker` are excluded because `CompareFirewallRules` pairs on them; comparing them would mark every paired rule modified.

### 4.3 Most Configs Have No Rule UUIDs

`CompareFirewallRules` pairs rules by `UUID`, but **pfSense never writes one**, and neither do older OPNsense configs -- 10 of the 13 fixtures in `testdata/` have zero. The fallback used to compare only the rule *count*, so any content change that left the count intact was invisible: on `testdata/pfsense/config-2.6.x.xml`, flipping a rule from `pass` to `block` reported "No changes detected".

`compareRulesWithoutUUID` now pairs in three passes -- by pfSense's `<tracker>`, then by exact content (which anchors the unchanged rules), then by remaining position. Whatever is left unpaired is a genuine addition or removal.

- **Do not "simplify" this back to positional pairing.** The content-anchoring pass is what stops a rule inserted at the top from cascading into every rule below it reading as modified. `TestCompareFirewallRules_NoUUID_InsertionDoesNotCascade` guards it.
- **Test new comparison logic against a UUID-less fixture.** A test built on `sample.config.6.xml` (which has UUIDs) exercises a different code path than one built on any pfSense fixture.
- **Two known limits, pinned by `TestCompareFirewallRules_KnownLimits`.** Neither is a regression -- the count-only fallback reported nothing for either -- but both are sharp enough that a future change should decide about them rather than discover them:
  - **A pure reorder produces no entry from content comparison.** That is by design -- order changes are the order detector's job, reached via `--detect-order`. Note that detector had the *same* UUID dependency: `extractRuleUUIDs` dropped every rule without a `<uuid>`, so `--detect-order` was a documented flag that silently found nothing on pfSense. It now keys on `ruleIdentity` (UUID, else `<tracker>`), and rules with neither stay out because a rule indistinguishable from its peers cannot be said to have moved.
  - **Leftovers pair by similarity, not position.** Once the tracker and content passes have anchored what they can, the rest are scored against each other (`ruleSimilarity`) and matched best-first. Blind positional pairing misattributed edits: with `a, b, c(pass)` becoming `a, c(block)` it handed the surviving `c` to `b` and reported "b modified into c" plus "c removed". Weights are description 4, interface list 2, and one each for type, protocol, source, destination and port; `simMinScore` is 4, reachable by a matching description alone or by a matching interface list plus two other fields. Above `simMaxPairs` leftovers on either side the scoring is skipped and pairing falls back to positional, so a config where nothing anchors stays bounded.

### 4.4 NAT Rules Were Compared By Count Only

`CompareNAT` compared `len(old.OutboundRules) != len(newCfg.OutboundRules)` and the same for `InboundRules`, and nothing else. Every content change that left the counts intact was invisible: an outbound rule retargeted or moved to another interface, and -- worse -- a **port forward redirected to a different internal host**, which is about the most consequential NAT change there is.

No NAT rule in any shipped fixture carries a `<uuid>`, not even in the OPNsense MVC configs that populate them on firewall rules, so this is the path every real config takes.

- **Rules now pair via `itemPairer`** (`internal/diff/pairing.go`): identity, then exact content, then similarity, with a positional fallback. the same pairer the firewall rules use.
- **`natRulesEqual` and `inboundNATRulesEqual` must cover every model field.** A field missing from either produces no diff entry at all, not a less detailed one. `TestNATRulesEqual_ComparesEveryField` and `TestInboundNATRulesEqual_ComparesEveryField` walk the structs reflectively and fail until you add it.
- **Paths are `nat.inbound.rules[N]` and `nat.outbound.rules[N]`.** The `nat.inbound` prefix is load-bearing: the security scorer's `port-forward-change` pattern matches on it, so renaming the path silently drops the impact rating from every port-forward entry.

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

`derivePerInputOutputPath` uses lossless tilde-based escaping: tildes in path segments become `~~` and underscores become `~u`, freeing the literal underscore to serve as an unambiguous directory separator. This prevents distinct paths from collapsing to the same filename, including boundary cases where one segment ends with `_` and the next begins with `_` (e.g., `a_/b/config.xml` → `a~u_b_config-audit.md` versus `a/_b/config.xml` → `a_~ub_config-audit.md`).

- **Gotcha:** Simple character replacement (e.g., `/` → `-`) is NOT sufficient — paths like `a-b/c/config.xml` and `a/b-c/config.xml` would collide. The escaping must be lossless (invertible). The earlier double-underscore scheme (`_` → `__`, separator → `_`) was also insufficient — it collapsed at segment boundaries where trailing/leading underscores were indistinguishable from the separator.
- **Gotcha:** Both `audit` and `convert` derive per-input paths from this one helper, and the `suffix` argument is what keeps them apart. `audit` passes `auditOutputSuffix` (`-audit`), `convert` passes `""`. Dropping the suffix would make an audit and a convert of the same input write to the same filename.
- **Gotcha:** Neither command may fall back to stdout for a multi-file run. Markdown and text concatenate readably, but two JSON documents produce `}{` and fail to parse, two HTML documents give two doctypes, and two YAML documents without separators parse as one mapping where the later keys silently replace the earlier ones.
- **Gotcha:** Expected output filenames are asserted in 5+ test functions (`TestDeriveAuditOutputPath`, `TestEmitAuditResult_MultiFileAutoNaming`, `TestEmitAuditResult_MultiFileConfigOutputFileIgnored`, `TestDeriveAuditOutputPath_BasenameCollision`, `TestDeriveAuditOutputPath_BoundaryUnderscoreCollision`, etc.). When changing the encoding scheme, grep for all assertion sites — missing one causes CI failure.

### 8.4 Red Mode Analysis (formerly Stub Implementations)

`generateRedReport` in `mode_controller.go` runs `analysis.ScanObservations` once, then its five analysis methods — `addWANExposedServices`, `addWeakNATRules`, `addAdminPortals`, `addAttackSurfaces`, `addEnumerationData` (implemented in `internal/audit/red_analysis.go`) — perform real, reachability-filtered analysis of the `CommonDevice`. The former placeholder-stub behavior and the `cmd/audit.go` `PreRunE` "experimental / not yet implemented" warning were removed in the red-lens slice (epic #281, slice 2).

- **Findings vs. metadata split:** Only three of the five methods append to `report.Findings`. `addWANExposedServices` (the primary producer: one Finding + `AttackSurface` per WAN-reachable WebGUI/SSH/SNMP service), `addWeakNATRules` (WAN-reachable inbound NAT port-forwards), and `addAttackSurfaces` (WAN-reachable shared-engine hygiene observations reframed as exposure, de-duped by `Component`). `addAdminPortals` and `addEnumerationData` emit **structured metadata only** (portal inventory tagged by reachability; recon counts) — deliberately NOT Findings, to avoid double-counting an exposure already surfaced by a Finding-producing method. Every WAN exposure still lands in Findings, but via the method that owns that exposure class: firewall-local management-service exposure (WebGUI/SSH/SNMP) via `addWANExposedServices`, and inbound NAT port-forward exposure independently via `addWeakNATRules`. The metadata-only methods never introduce an exposure that one of those two does not already surface as a Finding.
- **WAN-exposed = correlation, not enabled-alone:** a firewall-local management service (WebGUI/SSH/SNMP) is WAN-reachable only when enabled AND a WAN-reachable firewall pass rule permits its port (`wanRulePermitsPort` / `rulePortPermits`). Port matching biases to over-report (empty/`any`/ranges/lists match by containment; an unresolvable port *alias* is treated as permitting — never under-report a possible exposure).
- **NAT rules never correlate against firewall-local services:** `wanRulePermitsPort` (used only by `serviceReachability` for WebGUI/SSH/SNMP) deliberately does NOT consult `device.NAT.InboundRules`. An inbound NAT rule forwards WAN traffic to `InboundNATRule.InternalIP` — a different host than the firewall itself — so a NAT rule sharing an external port with a management service is never evidence that the firewall's OWN service is exposed. An earlier version correlated NAT rules here too, producing a false positive: a NAT rule forwarding WAN port 22 to an unrelated internal host's SSH would flag the firewall's own SSH daemon (also on port 22) as WAN-exposed even with no pass rule ever targeting the firewall directly. NAT-forward exposure is reported separately and correctly by `addWeakNATRules`. See `TestRedMode_NATForward_DoesNotExposeFirewallLocalService`.
- **Web GUI port comes from the unified model, not a hardcode:** `common.WebGUI.Port` carries the configured web-configurator port. Both the OPNsense and pfSense parsers populate it from `<system><webgui><port>` when the element is present in `config.xml`; the 443/80 protocol default applies only when the configured port is absent (either vendor). Red analysis reads `device.System.WebGUI.Port` via `parsePort` rather than assuming 443/80, so a box on a custom GUI port is analyzed correctly regardless of vendor. New device parsers should populate this field when the platform exposes a GUI port.
- **ExploitNotes safety:** red `ExploitNotes` carry impact/context only (never weaponized/step-by-step guidance). Enforced by `FindInstructionalContent` (`exploit_notes_safety.go`) run over the actual generated notes plus a golden-file gate — not authoring discipline. `--audit-blackhat` selects the sharper-tone variant (red mode only; rejected in `PreRunE` for blue mode) and adjusts tone only — the denylist safety invariant holds for both tone variants.
- **NAT correlation is an intentional over-report:** an inbound NAT rule is treated as WAN-reachable when any enabled WAN pass rule exists (not one correlated by port to that specific forward). This is a deliberate safe-direction choice — precise per-rule correlation would risk under-reporting a real exposure, the wrong failure mode for a security audit.

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

`NATRule.Target` is the NAT translation target address. `InboundNATRule.InternalIP` is the port-forward destination — there is no `Target` field on `InboundNATRule`. The outbound type is named `NATRule`, not `OutboundNATRule`; only `NATRule` and `InboundNATRule` exist, so an earlier version of this entry named a type that never did.

`Tag` and `Tagged` are on **both** `FirewallRule` and `NATRule`. This entry previously said `FirewallRule` had neither, which was a description of the bug rather than of the model: the fields were missing until the converters stopped dropping them (§3.6).

### 10.4 Never Return `md.String()` or `buf.String()` Raw

`github.com/nao1215/markdown` emits the host's line ending — its `internal.LineFeed` returns `"\r\n"` on Windows and `"\n"` everywhere else. Any function that returns `md.String()`, or the `bytes.Buffer`/`strings.Builder` a `markdown.Markdown` was built into, therefore produces CRLF on a Windows checkout. That breaks every LF golden fixture and contradicts the LF guarantee in `internal/export`.

- **Rule:** in `internal/converter/builder`, return `renderMarkdown(md)`. Anywhere else, wrap the exit in `formatters.NormalizeToLF`. Any new code path that constructs markdown independently of the builder needs the same treatment — the builder's helper does not protect an exit it does not own.
- **`glamour.Render` is not affected** — it re-renders and emits LF, so `MarkdownConverter.ToMarkdown` was already clean. Do not add a redundant normalization there.
- **Detection:** `TestReportOutputIsLF` (builder) asserts the invariant across the public output surface, but it can only fail on Windows. The Windows CI job runs the full suite for this reason.
- **CRLF on disk is still available** via `OPNDOSSIER_PLATFORM_LINE_ENDINGS=1`, handled in `internal/export` at write time.

## 11. Sanitizer

### 11.1 pfSense `bcrypt-hash` Field Name

pfSense stores user passwords in `<bcrypt-hash>` elements, not `<password>` or `<passwd>` like OPNsense. The sanitizer's field-pattern matching must explicitly include `bcrypt-hash` and `sha512-hash` — the generic `"pass"` substring match does not cover these.

- **Symptom:** `sanitize` command outputs bcrypt hashes in cleartext.
- **Fix:** Add `"bcrypt-hash"`, `"sha512-hash"` to the `password` rule's `FieldPatterns` in `internal/sanitizer/rules.go`.
- **Precedent:** The SNMP community string (`rocommunity`) required a dedicated field pattern for the same reason.

### 11.2 New Device Type Field Names

When adding a new device type (e.g., pfSense), audit the XML element names for credential fields that differ from OPNsense. The sanitizer operates on raw XML element names, not CommonDevice field names. Any device-specific naming for secrets must be added to the sanitizer's pattern lists.

- **Detection:** `sanitize <config.xml> | grep -i 'hash\|secret\|key\|pass'` — check for unredacted sensitive values.
- **Prevention:** When adding a new device schema, grep for credential-like fields and verify each is matched by a sanitizer rule.

### 11.3 OpenVPN TLS and StaticKeys Are Credentials, Not Labels

OpenVPN's `<tls>` element (under `<openvpn-server>` / `<openvpn-client>`) holds the `--tls-auth` / `--tls-crypt` HMAC key, and the MVC `<OpenVPN><StaticKeys>` element holds static-key material. Both arrive in a PEM-shaped envelope with the literal label `-----BEGIN OpenVPN Static key V1-----` — which the stock `IsPrivateKey` detector misses because the label is not `PRIVATE KEY`. The sanitizer's `private_key` rule uses path-anchored `FieldPatterns` (`openvpn.tls`, `openvpn-server.tls`, `openvpn-client.tls`, `openvpn.statickeys`, `statickeys`, `tls_crypt`, `tls_auth`) plus the `IsOpenVPNStaticKey` envelope detector to catch both the field-name and value-based paths.

- **Gotcha:** The substring `tls` ALONE is not safe as a pattern. It would false-positive on:

  - The Suricata IDS wrapper `opnsense.OPNsense.IDS.general.eveLog.tls.*` (a struct of enable/extended/sessionResumption/custom booleans — `pkg/schema/opnsense/security.go` L383).
  - The IPsec strongSwan daemon log-level enum `opnsense.OPNsense.IPsec.charon.syslog.daemon.tls` (an integer 0–5 — `pkg/schema/opnsense/security.go` L443).

  Always anchor OpenVPN TLS patterns to their parent element path (e.g., `openvpn-server.tls`) and verify new unambiguous OpenVPN field names (like `tls_crypt` / `tls_auth`) never collide with other device schemas before adding them bare.

- **Detection:** `TestSanitizeXML_OpenVPNStaticKey` + `TestSanitizeXML_OpenVPN_TLS_NoFalsePositives` in `internal/sanitizer/sanitizer_test.go`. `TestIsOpenVPNStaticKey` in `patterns_test.go` covers the envelope detector.

- **Rule-ordering impact:** None. The `private_key` rule is distinct from `authserver_config` / `password` / `email` / `hostname` and does not participate in the §19.1 ordering invariants.

- **History:** SEC-H1 from the 2026-04-19 comprehensive review. Prior to the fix, `opndossier sanitize` silently leaked raw HMAC keys sufficient to forge OpenVPN handshakes — the headline promise of the subcommand.

### 11.4 NetBird `setupKey` Is a Credential

The OPNsense `os-netbird` plugin persists the NetBird enrollment/setup key as `<setupKey>` under `<OPNsense><netbird><authentication>` (MVC model mounted at `//OPNsense/netbird/authentication`). The value is a UUID-format registration token. Because the sanitizer's bare `"key"` FieldPattern is exact-match only (see `exactMatchPatterns` — same trap as SNMPv3 `<enckey>`), compound names like `setupKey` leaked through `sanitize` in cleartext.

- **Symptom:** `sanitize` leaves NetBird setup keys readable in output. The key remains in `config.xml` when NetBird is disabled and often survives plugin removal as orphaned MVC XML, so disabled/removed plugins still leak.
- **Fix:** Add `"setupkey"`, `"setup_key"`, `"setup-key"` to the **`secret`** rule's `FieldPatterns` in `internal/sanitizer/rules.go` (enrollment token, not private-key material — unlike SNMPv3 `enckey` which lives on `private_key`).
- **Detection:** `TestSanitizeXML_NetBirdSetupKey_RedactsSecret` + `TestSanitizeXML_NetBirdSetupKey_NoFalsePositives` in `internal/sanitizer/sanitizer_test.go`; `TestRedact_NetBirdSetupKey_RedactsSecret` in `rules_fieldpattern_test.go`.
- **Rule-ordering impact:** None. The `secret` rule already precedes `private_key` and does not participate in the §19.1 ordering invariants.
- **Upstream:** <https://github.com/opnsense/plugins> (`security/netbird`); field declared in `Authentication.xml` as `UpdateOnlyTextField` with UUID mask.
- **History:** Reported as a cleartext leak through `sanitize` when NetBird is disabled or the plugin XML remains after removal; fixed in #728.

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
- **Precedent:** `TestPrepareForExport_RedactsSensitiveFields_JSON` in `internal/converter/enrichment_test.go` demonstrates the assertion *shape* — it checks the typed `exported.Certificates[0].PrivateKey` field rather than substring-matching the marshalled JSON, then separately confirms the output still parses. Note its fixture is a single-line placeholder, so it does not itself exercise the newline-escaping trap; when you add coverage for a genuinely multiline secret, use a real PEM block so the encoded form differs from the raw one.

## 14. Sanitizer Rule Engine

### 14.1 `ShouldRedactField` Scans ALL Rules Globally

`ShouldRedactField` checks field names against `FieldPatterns` from **every** rule, not just the rule being tested. Adding a `FieldPattern` to any rule can break "should not match" test assertions for other rules.

- **Symptom:** A new field pattern causes unrelated sanitizer tests to fail.
- **Fix:** Check all rules' `FieldPatterns` when adding new patterns. Test assertions must account for global matching.

### 14.2 Value Detector Ordering

`ShouldRedactValue` checks field-name rules first (`ShouldRedactField`), then value-detector rules. Rules with both `FieldPatterns` and `ValueDetector`: a field match triggers redaction immediately; the value detector only runs on the value-only matching path.

### 14.3 Deterministic Mapper in Tests

A fresh `NewRuleEngine` creates a fresh `NewMapper()` — mappings are deterministic (e.g., first private IP maps to `[REDACTED-PRIVATE-IP-1]`, first hostname to `host-001.example.com`). Always assert exact expected values, not just inequality.

### 14.4 `SanitizeStruct` Skips Struct/Pointer-Valued Maps

`sanitizeReflect` in `internal/sanitizer/sanitizer.go` cannot recurse into `map[K]struct{...}` or `map[K]*struct{...}` values. Map values are not addressable in Go, so `reflect.Value.SetMapIndex` is the only way to write back — and that requires a fully reconstructed element, which the current walker does not perform. The guard at the top of the `reflect.Map` case detects this and logs a warning via the optional logger injected through `Sanitizer.SetLogger`. When no logger is set, the gap is silent.

- **Current scope:** This gap is reachable ONLY through `SanitizeStruct`, which is an opt-in consumer flow. The default `opndossier sanitize` CLI uses `SanitizeXML` (raw element walk) and is not affected — element names like `<password>` and `<bcrypt-hash>` are still redacted regardless of the Go model shape.
- **Known current paths:** OPNsense `KeaDhcp4` already uses map-style subnet containers, but those maps hold config metadata, not credentials. No currently-shipped schema path puts a secret behind a struct-valued map.
- **Why warn instead of fix:** Supporting struct-valued maps via reflection requires reconstructing each element in place (read → recurse into a copy → `SetMapIndex` with the mutated copy). That work is scheduled under todo #151 (tag-based redaction) which will subsume this gap by annotating sensitive fields directly and driving redaction from tags instead of field-name heuristics. The warning is the bridge until #151 lands.
- **Regression tests:** `TestSanitizeStruct_MapStructValues_WarnsAndSkips` and `TestSanitizeStruct_MapStructValues_NilLoggerNoPanic` in `internal/sanitizer/sanitizer_reflect_test.go` pin both the warning path and the nil-logger nil-safety invariant. If a future enhancement starts handling struct-valued maps, those tests must be updated (or replaced) to reflect the new behavior — do not delete them blind.

### 14.5 The Sanitizer Builds Its Own Decoder

`sanitizeXMLContent` constructs an `xml.Decoder` directly rather than going through `parser.NewSecureXMLDecoder`, because it needs `Strict = false` and token-level access the parsers do not. That means **every hardening the parsers get has to be repeated here by hand**, and one was missing: with no `CharsetReader`, `encoding/xml` refuses any declaration other than UTF-8 with `encoding %q declared but Decoder.CharsetReader is nil`.

Real OPNsense writes `<?xml version='1.0' encoding='us-ascii'?>`, so `opndossier sanitize` failed outright on its most common input, and on `testdata/sample.config.2.xml` and `sample.config.4.xml`. The failure was easy to miss because the verification loop in CONTRIBUTING pipes stderr to `/dev/null`, so a crashed run and a clean run both show zero unredacted lines.

- **When you add hardening to `pkg/parser/xmlutil.go`, check whether `sanitizeXMLContent` needs it too.** The two decoders are independent.
- **The output is always UTF-8.** `CharsetReader` decodes the input, so `writeXMLDeclaration` rewrites a non-UTF-8 declaration to `encoding="UTF-8"`; copying the original would label the file with an encoding it is not in. A UTF-8 or bare declaration is copied byte for byte so existing output does not shift.
- **Check exit codes, not just output, when testing the CLI.** `sanitize ... 2>/dev/null | grep` hides a total failure as an empty result.

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

`ShouldRedactField` iterates the rule slice and returns on the first match, so when two rules match the same field name the earlier one wins and the later one never runs. `authserver_config` pseudonymizes through `MapAuthServerValue`; the `password` rule flat-redacts to `[REDACTED-PASSWORD]`.

- **Problem:** If `password` is moved above `authserver_config` in the `builtinRules()` slice, any field both rules match silently switches from pseudonymized to flat-redacted. No error or warning is emitted.
- **Symptom:** Sanitized output shows `[REDACTED-PASSWORD]` where a pseudonymized value is expected — `MapAuthServerValue` renders `ldap_bindpw` as `BindPw-001-NotReal!` (`internal/sanitizer/mapper.go`).
- **Fix:** Ensure `authserver_config` remains the first rule in `builtinRules()`. This pair genuinely competes: `authserver.ldap_bindpw` matches `authserver_config` on its exact path pattern *and* `password` on the `bindpw` substring, so the order decides whether the value is pseudonymized or flat-redacted. Verified — `system.authserver.ldap_bindpw` resolves to `authserver_config` and yields `BindPw-001-NotReal!`, while a bare `ldap_bindpw` falls through to `password` and yields `[REDACTED-PASSWORD]`.
- **The `email`-before-`hostname` ordering is a different case.** It is the same first-match property but nothing currently depends on it: `email` matches the field pattern `email`, `hostname` matches `hostname`/`domain`/`althostnames`/`hostnames`, the two sets are disjoint, and the `hostname` rule's `ValueDetector` returns early on `IsEmail` so it declines an email-looking value regardless of order. Keep it as insurance against a future overlapping pattern, but do not cite it as a live guard.

**`password` does not reach `ldap_bindpw` through the `pass` substring.** An earlier version of this entry said it did. It does not: `ldap_bindpw` contains none of the `password` rule's patterns — `password`, `passwd`, `pass`, `pwd`, `bcrypt-hash`, `bcrypt_hash`, `sha512-hash`. If the `password` rule matches `ldap_bindpw` at all, it is because an explicit `bindpw` pattern was added to its `FieldPatterns`, never through the generic `pass` substring. Two consequences worth keeping straight:

- The `bindpw` pattern is what makes the ordering above load-bearing. Before it existed, every `authserver_config` pattern was an `authserver.*` / `system.authserver.*` path containing no `password`-rule substring, so the two rules never competed and the ordering guidance was real but vacuous. Adding `bindpw` to the `password` rule is what gave the pair a field they both match.
- A bare `<ldap_bindpw>` outside an `authserver.*` path matched no credential rule on field name alone until `bindpw` was added; it was emitted verbatim in every mode. That was the leak the pattern closes.

The general lesson: a documented fallback is not a verified one. Check the actual `FieldPatterns` slice before relying on a rule to catch a field — a plausible-sounding substring claim is exactly the kind of thing that hides a leak.

### 19.2 A Rule That Declines Inside Its Redactor Consumes the Match

First-match precedence has a second edge. A rule can match on field name and then decide, inside its `Redactor`, that it does not want the value after all — `ip_address_field` and `subnet_field` both did this, returning the value unchanged when it was not an IP or not a CIDR. That reads like declining, but the match was already consumed: `ShouldRedactField` had returned, so no later rule and no value-detector pass ever saw the value.

- **Symptom:** aggressive mode leaks values moderate redacts. Both offending rules are aggressive-only, so in moderate they are inactive and the value falls through to the detectors normally. An email in `<subnet>` or `<from>` was pseudonymized in moderate and emitted verbatim in aggressive — the higher-privacy mode being the leaky one.
- **Not caught by the fixtures.** No shipped config puts an email address in a `<subnet>` or `<from>` element, so a fixture sweep passes against the broken code. `TestModes_AggressiveRedactsEverythingModerateDoes_Synthetic` carries the invariant on probes built to trigger it; the fixture sweep beside it is the regression net for real-world shapes and is expected to be quiet.
- **Fix:** declare the qualification on the rule as `FieldGuard func(value string) bool` rather than implementing it in the `Redactor`. A rejected guard skips the rule and scanning continues. `ShouldRedactFieldValue` applies it wherever the value is in hand; `ShouldRedactField` remains name-only for callers that genuinely have no value.
- **Why not fall through whenever a `Redactor` returns its input unchanged?** That would mean invoking redactors speculatively, and redactors allocate pseudonyms in the `Mapper` that surface in the mapping report. Today's redactors happen to return before touching the mapper, but that is the same unenforced discipline whose absence caused this. A `FieldGuard` cannot allocate.
- **One declining redactor is left on purpose.** The `username` rule still returns its input for system accounts via `isSystemUser`, so it consumes the match the same way. It is not a leak today: the values it declines (`root`, `nobody`, `www`) are ones moderate does not redact either, so monotonicity holds — verified by probe, not assumed. It becomes one the moment a value `isSystemUser` accepts is also something a moderate-mode rule would redact. Prefer a `FieldGuard` if you touch it.
- **Adding a rule with generic patterns?** Patterns like `from`, `to`, or `subnet` match fields that have nothing to do with the rule. Give it a `FieldGuard`; do not test the value inside the `Redactor`.

### 19.3 A Generic Field Pattern Sometimes Needs `FieldExclusions`, Not a `FieldGuard`

§19.2 says to give a rule with generic patterns a `FieldGuard`. That advice has a limit: a `FieldGuard` only ever receives the **value**. When the value cannot distinguish the fields, only the field name can, and a guard is the wrong tool.

The `hostname` rule lists `domain` as a `FieldPattern`, matched as a substring, so it claimed three DHCP dynamic-DNS TSIG metadata fields — `ddnsdomainkeyname`, `ddnsdomainkeyalgorithm`, and `ddnsdomainalgorithm`. A field-name match redacts unconditionally (§14.2), so in aggressive mode the literal `hmac-md5` the audit engine reads became `host-001.example.com`. The rule is `aggressiveOnly`, so moderate and minimal were correct and aggressive — the mode operators pick when sharing most widely — was the broken one.

- **The obvious fix is wrong, and quietly so.** `FieldGuard: IsHostname` looks right and would have leaked every firewall hostname in the repo. `IsHostname` requires at least one dot (`TestIsHostname` pins `{"localhost", false}`), and **every** `<hostname>` value in `testdata/` is a single label: `firewall`, `OPNsense`, `pfSense`, `printer`, `fw-test`. The guard would decline on all of them, no later rule or detector would claim them, and aggressive mode would emit real hostnames verbatim.
- **No value predicate can work here.** `hmac-md5` and `fw1` are both valid single DNS labels. The discriminating information is the field name, not the value shape.
- **Fix:** `FieldExclusions []string` on `Rule`, honored in `ruleMatchesFieldName` — the shared chokepoint `ShouldRedactField` and `ShouldRedactFieldValue` both call, so the two lookups cannot drift. It skips the rule without consuming the match, exactly like `FieldGuard`. Matching is case-insensitive and anchored on the terminal path segment, so `dhcpd.lan.ddnsdomainkeyalgorithm` is excluded but `ddnsdomain` is not.
- **The exclusion does not release hostnames.** It suppresses only the unconditional name-based claim; `ShouldRedactValue` still runs its value-detector pass, and the `hostname` rule's `ValueDetector` is in it. A hostname-shaped value stored in an excluded field is still redacted. `TestAggressiveMode_ExcludedTSIGFieldStillRedactsHostname` pins this.
- **`ddnsdomainalgorithm` is the one you will miss.** It does not contain `ddnsdomainkey`, so the exact-match pattern that protects the other siblings from `private_key` does not cover it — and it is the most common of the three, appearing 71 times across the fixtures versus 4 for `ddnsdomainkeyalgorithm`. Grep the fixtures rather than trusting a bug report's field list.
- **A fixture diff will look far bigger than the change.** `Mapper` numbers pseudonyms in encounter order, so releasing 71 values renumbers every later `host-NNN`. Mask the indices (`s/host-[0-9]+/host-N/`) before diffing, or you will be reading hundreds of lines of renumbering looking for the four that matter.
- **Regression tests:** `TestRuleMatchesFieldName_FieldExclusions` (mechanism), `TestShouldRedactField_DDNSDomainKeySiblings` (all three fields, all three modes), `TestAggressiveMode_HostnameCoverageUnchanged` (the redaction this must not narrow).
- **Do not "simplify" the exclusions into a `FieldGuard`.** The single-label hostname case above is why they are keyed on the field name.

## 20. pfSense Validator Injection

### 20.1 `SetValidator` Is Guarded by `sync.Once`

`pkg/parser/pfsense.SetValidator` installs the semantic validator used by `Parser.ParseAndValidate`. The slot is unexported (`validateFuncHolder atomic.Pointer[...]`) and is written exactly once per process — the first `SetValidator` call wins, every subsequent call is silently dropped. The `atomic.Pointer` pairs with `sync.Once` so the writer side synchronizes cleanly with the concurrent reader side in `ParseAndValidate`.

The one-shot lock is the enforcement point against a dynamically loaded compliance plugin's `init()` reassigning the validator after CLI setup. Because `plugin.Open` fires the loaded `.so`'s `init()` at load time — later than Go's own `init()` ordering for in-tree packages — `cmd/root.go:init` calls `SetValidator` first, commits the sync.Once, and any subsequent plugin `init()` is effectively locked out. See the comprehensive-review ticket SEC-H2 / todos #105 and #128 for the original finding.

- **Gotcha:** Do NOT reintroduce a public mutable `ValidateFunc` variable. Any value that is directly assignable from plugin code re-opens the stomp hazard. The injection point MUST go through `SetValidator`.
- **Gotcha:** Test code that needs to swap validators across subtests uses the `ResetValidatorForTesting` / `ValidatorForTesting` helpers defined in `pkg/parser/pfsense/export_test.go`. These live in `_test.go` and therefore are NOT part of the public API — never promote them to a plain `.go` file.
- **Gotcha:** The exported `SetValidator` is safe to call from any goroutine; concurrent writers race to win the `sync.Once`, but only one does. Readers never see a torn value because the holder is `atomic.Pointer[...]` — verified by `TestPfSense_SetValidator_Race` under `-race`.
- **Regression tests:** `TestPfSense_SetValidator_CannotBeOverwritten` pins the stomp-protection invariant; `TestPfSense_SetValidator_Race` pins the concurrent-writer safety. Both live in `pkg/parser/pfsense/parser_test.go`. If either fails, the §20 defense has regressed.

## 22. Documentation Tooling

### 22.1 mdformat Collapses Consecutive `**Label**:` Lines

With `wrap = "no"` in `.mdformat.toml`, mdformat joins consecutive `**Label**:` lines onto a SINGLE line. ADR frontmatter written as three lines —

```markdown
**Date**: YYYY-MM-DD
**Status**: accepted
**Deciders**: ...
```

— renders after the pre-commit hook as one line: `**Date**: YYYY-MM-DD **Status**: accepted **Deciders**: ...`. That collapsed form is canonical.

- **Gotcha:** Do not "fix" these back onto separate lines — the `mdformat` pre-commit hook re-collapses them and the edit will not survive a commit. Both `docs/adr/template.md` and the ADRs are kept in the collapsed form, so they are already mutually consistent.
- **Gotcha:** Reviewers (e.g. CodeRabbit) sometimes flag the collapsed frontmatter as a layout defect and suggest splitting the lines. That suggestion is a false positive against this repo's formatter — decline it.

### 22.3 Cobra `Use:` Drives Generated Filenames — and macOS Hides the Fallout

The root command's `Use:` string (`cmd/root.go`) is not just help text. Cobra derives from it:

- the page **filenames** under `docs/cli/` (`opndossier_audit.md`, …) and the cross-reference links inside them,
- the man-page filenames emitted by `opndossier man` (`opndossier.1`),
- every rendered `Usage:` line.

Changing `Use:` therefore renames 19 committed doc files and one packaging artifact.

- **The macOS trap:** on a case-insensitive filesystem, regenerating writes `opndossier_audit.md` *over* `opnDossier_audit.md` and the directory entry keeps the **old** casing. `git status` shows a modification, the build passes, and everything looks fine. On Linux CI the same regeneration produces a **second, duplicate set** of pages while `mkdocs.yml` still points at the stale set.
- **Release coupling:** `.goreleaser.yaml` references `./packaging/opndossier.1` by exact path in two places (archive `contents:` and nfpm `contents:`). `just ci-check` never runs goreleaser, so a `Use:` change that breaks these paths is invisible until a `git tag` fails the release workflow.
- **After any `Use:` change:** run `go run . docs docs/cli/`, confirm `git ls-files docs/cli | grep -c '<old-casing>'` returns `0`, run `<binary> man <dir>` and check the emitted `.1` name against both `.goreleaser.yaml` paths, then update `mkdocs.yml`, `docs/for-agents.md`, and `docs/llms.txt`.
- **Regression test:** `TestGetRootCmd` (`cmd/root_test.go`) pins `Use` to the lowercase shipped binary name and carries a comment explaining why. The name must match goreleaser's `binary:` (`opndossier`), Homebrew, and `justfile`'s `binary_name`. `opnDossier` is the product name in prose, never the command.
- **`go install` is the permanent exception.** Go derives the installed binary name from the module path (`github.com/EvilBit-Labs/opnDossier`), so `go install` produces `opnDossier` regardless of `Use:`. This cannot be fixed without changing the import path; it is documented as a rename step in `docs/user-guide/getting-started.md` and `installation.md` instead.

### 22.4 `foo.md` and `foo/index.md` Silently Collide

MkDocs maps both `docs/foo.md` and `docs/foo/index.md` to the same output path, `site/foo/index.html`. One silently wins; the other is never served. **`--strict` does not catch this** — there is no broken link, just a page that renders someone else's content.

- **Live example:** `docs/examples.md` and `docs/examples/index.md` both built to `site/examples/index.html`. `examples/index.md` won, so the "All Examples" nav entry pointed at a URL rendering the Overview page. The condition survived undetected because every link still resolved.
- **Detection:** `for f in docs/*.md; do [ -d "docs/$(basename "$f" .md)" ] && echo "COLLISION: $f"; done`
- **Rule:** when splitting a page into a directory, delete the original. Do not leave both.
- **Corollary for `mkdocs-redirects`:** never add a `redirect_map` entry whose *source* collides with a real page's output path. `examples.md: examples/index.md` writes a redirect stub over `site/examples/index.html` — the very page it points at — replacing the Overview content with a self-redirect. `--strict` reports nothing. A colliding source needs no redirect anyway: the URL never changed meaning, only which file backed it.

### 22.2 mdformat Excludes Live in `.pre-commit-config.yaml`, Not `.mdformat.toml`

File exclusions for the `mdformat` hook are the pre-commit hook's native `exclude:` regex in `.pre-commit-config.yaml` (currently `*.golden.md`, `docs/cli/`, `CHANGELOG.md`, `*.tpl.md`). Do NOT reintroduce an `exclude = [...]` list in `.mdformat.toml`: that feature requires the hook to run under Python 3.13+, but pre-commit builds the hook venv with its own interpreter (3.11 today), so it fails on every markdown file with `'exclude' patterns are only available on Python 3.13+`.

## 23. Unused-Object Detection

### 23.1 Reachability Edge-Building Must NOT Mirror `resolveNode`

`DetectUnusedObjects` (`internal/analysis/unused.go`) frames unused-alias detection as graph reachability from policy roots. The obvious implementation — reuse `NamedObjects.resolveNode`'s member walk — is a **bug**. `resolveNode` (`pkg/model/named_objects.go`) early-returns for any `isDynamic()` type, and `staticNamedObjectTypes` is only `{host, network, port}`. Converters store the raw vendor type string verbatim (`common.NamedObjectType(a.Type)`), so a vendor `networkgroup` group alias is classified **dynamic** even though its members *are* alias names.

- **Symptom:** an alias referenced only via a rule → `networkgroup` group → alias chain is falsely reported unused, breaking the nested-group case the feature centers on.
- **Rule:** reachability uses its own predicate — for every object, for every member, add an edge if the member keys into `NamedObjects`, with **no** `isDynamic` gate. It only asks "does this member name another object?", never "do the members expand into literal addresses?" It stays correct for opaque types (`url`/`geoip`/`external`) because their members (URLs, country codes) do not key into the registry and so contribute no edges without needing a type check.
- **Regression test:** `TestDetectUnusedObjects` case "does not flag alias nested under a used networkgroup-typed group" (`internal/analysis/unused_test.go`). If it fails, someone reintroduced the `isDynamic` gate.

### 23.2 Disabled Rules Are Roots; Remediation Hedges

Root collection in `collectRoots` deliberately does **not** skip disabled rules. A disabled rule referencing an alias means the alias is *staged*, not dead — deleting it breaks the rule on re-enable. This is easy to "optimize" away by adding a `!rule.Disabled` guard; don't.

Relatedly, the finding's `Recommendation` intentionally hedges ("confirm before removing") rather than instructing deletion. The detector cannot see a config-invisible staging signal — an alias created before its referencing rule exists leaves no trace, and creation timestamps are not in `config.xml`. A flat "safe to delete" would be an outage recommendation for that case. Both invariants are pinned by `TestDetectUnusedObjects` ("does not flag alias referenced only by disabled rule") and `TestDetectUnusedObjects_FindingShape`.

### 23.3 R6 Completeness Is a Manual Surface Audit, Not Automatic

The "no false positive" guarantee holds exactly as far as the typed-`ObjectRef` root sites in `collectRoots` cover every `CommonDevice` field on which a pf-family alias can appear. When a new device parser or a new `CommonDevice` address/port field lands, it must be audited: an alias-capable field needs both an `*ObjectRef` model field (populated by the converter) and a `collectRoots` entry. Traffic-shaper and captive-portal config are modeled as opaque identifier strings (not addresses) and are correctly excluded; DNS/NTP/monitor/LB fields are literal IPs, not firewall aliases. A silently-untracked alias-capable field reintroduces the false-positive class.

## 24. GitHub Action

### 24.1 The Action Must Run As the Workspace Owner

The published image sets `USER 65532:65532`, which is the correct default for a bare `docker run`. A runner workspace is owned by the runner user (uid 1001 on GitHub-hosted runners), so without `--user "$(id -u):$(id -g)"` on the `docker run` line the container **cannot write into the bind mount**. Every invocation using the documented `output` input failed with `permission denied`; stdout-only runs were unaffected.

- **Test the Action with an output file, not just stdout.** The breakage is invisible to any check that only asserts the command exits 0 while printing to stdout, which is why it shipped.

- **Reproduce it locally** by chowning a scratch workspace to a uid the image does not run as:

  ```bash
  docker run --rm -v "$WS:/data" -w /data <image> convert config.xml --format json --output report.json
  ```

  Without `--user` that fails; with `--user 1001:1001` it writes `report.json` owned by 1001 at mode 600 (`export.DefaultFilePermissions`).

- **Do not "fix" this by dropping `USER` from the Dockerfile.** The non-root default protects direct `docker run` users; the Action overrides it only because it has a bind mount to match.

## 25. Lint Gate Self-Satisfaction

### 25.1 `fix: true` Makes `golangci-lint run` Unable to Fail

`.golangci.yml` set `fix: true` under `issues:`, which applies to every fixable finding, and that includes every formatter in the `formatters:` block. `run` repaired each one in place and then reported `0 issues` with exit 0. CI's Lint job invokes a bare `golangci-lint run`, so the repair landed in the runner's own checkout and was thrown away with it. Formatting drift could not turn the job red, and `just lint` behaved the same way on a developer machine.

Reproduce on any revision carrying the key by adding stray indentation to a `.go` file:

```console
$ golangci-lint run
0 issues.           # exit 0

$ git diff --stat   # empty: the indentation was repaired, never reported
```

- **Rule:** rewriting is opt-in at the call site, never in config. `just format` and the pre-commit hook pass `--fix` explicitly, and `golangci-lint fmt` rewrites by design. Nothing else may mutate the tree.
- CI's step also passes `args: --fix=false`, which overrides a `fix:` key if one is ever restored. Verified against a config with `fix: true` present.
- **Same trap, second location, and mind the caveat.** `just format-check` ran `golangci-lint fmt ./...`, which rewrites rather than checks, so that recipe could never fail on its own. `just ci-check` did still catch drift, but at the earlier `check` step, where pre-commit fails any hook that modified files, and the tree was silently reformatted on the way past. `format-check` now passes `--diff` so it gates where its own description says it does. Treat `lint` as the authoritative formatter gate regardless, since `fmt` and `run` can disagree about the same file (section 25.2).
- **Verify a change to this gate locally, not with a probe commit.** `act -j lint -P ubuntu-latest=catthehacker/ubuntu:act-latest` runs the real Lint job. Check both directions, green on a clean tree and red with a misformat planted, because a one-sided pass proves nothing. Without `-P`, and with no `~/.config/act/actrc` on the machine, act prompts for an image size and exits `level=fatal msg=EOF`, which looks like a failing gate and is not one.

### 25.2 A Construct Can Have No Formatting That Passes

`golines` and `gofumpt` both run in the `formatters:` pipeline and disagreed permanently on a multi-value `return` of two composite literals. `golangci-lint fmt` produced a shallow form that `run` rejected as `gofumpt`; `gofmt -w` produced a deeper form that `run` rejected as `gci`. No file content satisfied both, and `fix: true` hid the standoff by rewriting on every run and reporting nothing.

- **Symptom:** a formatter finding that successive PRs each report as pre-existing and each defer. Three did before this was traced.
- **Change the code, not the pipeline.** Building each literal into a local and returning the locals removes the disputed construct entirely. Reordering or dropping a formatter was the more disruptive option and proved unnecessary.
- The config change and the code change are load-bearing together. Closing the gate on a tree that still contains the standoff turns `main` red immediately.
