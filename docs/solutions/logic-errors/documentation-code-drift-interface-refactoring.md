---
title: Documentation-code drift in mechanical claims about Go source
category: logic-errors
date: '2026-03-19'
last_updated: '2026-05-03'
tags:
  - interface-split
  - documentation-drift
  - fabricated-methods
  - mermaid-diagram
  - test-coverage
  - compile-time-assertions
  - code-review
  - concurrency-invariants
  - prose-verification
  - automated-review-gap
  - second-opinion
component: converter/builder, processor
severity: medium
symptoms:
  - Documentation lists method names that do not exist in code
  - Method assigned to wrong interface in documentation
  - Mermaid diagram references nonexistent methods
  - Documentation references nonexistent sub-interface name
  - GetBuilder() returns nil without logging on type-assertion failure
  - No test coverage for GetBuilder() nil and narrow-builder code paths
  - 33% patch coverage on new code
  - Struct doc claims a field is "read-only after init" while in-package tests mutate it
  - GOTCHAS section claims a lock protects "concurrent appends from sub-goroutines" in a sequential function
  - Doc claims "clones only X" while the function clones additional defensive categories
  - Generic multi-persona automated review returns 0 findings on prose that contradicts the source
related_issues:
  - '#323'
  - '#431'
  - '#598'
related_docs:
  - docs/solutions/architecture-issues/file-split-refactor-gotchas.md
  - docs/solutions/logic-errors/cli-flag-wiring-silent-ignore.md
  - docs/solutions/architecture-issues/pkg-internal-import-boundary.md
  - docs/solutions/logic-errors/opnsense-nat-ipprotocol-enum-cast-missing-guard.md
---

# Documentation-Code Drift After Interface Refactoring

## Problem

After splitting the monolithic `ReportBuilder` interface (20 methods) into three focused interfaces (`SectionBuilder`, `TableWriter`, `ReportComposer`) in PR #431, documentation updates in `CONTRIBUTING.md` and `docs/development/architecture.md` contained fabricated method names, wrong interface assignments, and references to a nonexistent sub-interface. Additionally, the `GetBuilder()` method had untested code paths with silent nil returns.

### Symptoms

- `CONTRIBUTING.md` and architecture Mermaid diagram listed 6 `TableWriter` methods that do not exist in code (`WriteAliasTable`, `WriteNATRulesTable`, `WriteOpenVPNInstanceTable`, `WriteIPsecTunnelTable`, `WriteCARPInterfaceTable`, `WriteStaticRouteTable`)
- 5 real methods were missing from docs (`WriteUserTable`, `WriteGroupTable`, `WriteSysctlTable`, `WriteOutboundNATTable`, `WriteInboundNATTable`)
- `SetIncludeTunables` documented in `SectionBuilder` but actually belongs to `ReportComposer`
- Both docs referenced a nonexistent `auditBuilder` sub-interface
- `GetBuilder()` returned nil without logging when the type assertion failed
- Codecov reported 33% patch coverage -- nil and narrow-builder paths untested

## Root Cause

Documentation was drafted from the **proposed design** (issue #323) rather than verified against the **implemented code**. AI-generated documentation hallucinated plausible-sounding method names that matched the domain vocabulary. The same unverified content propagated into prose docs and the Mermaid class diagram.

Secondary issue: `GetBuilder()` was refactored to use a two-value type assertion but the failure path was left without logging or test coverage.

## Investigation Steps

1. Ran a 4-agent parallel code review (code-reviewer, type-design-analyzer, comment-analyzer, silent-failure-hunter) against the PR diff
2. Cross-referenced every documented method name against `builder.go` lines 49-72
3. Confirmed `SetIncludeTunables` placement via grep against the actual interfaces
4. Searched the entire codebase for `auditBuilder` -- zero results
5. Traced all `GetBuilder()` callers to assess nil-return impact
6. Checked Codecov patch coverage report

## Solution

### 1. Replace fabricated method names with actual methods

Updated `CONTRIBUTING.md` and the Mermaid diagram in `architecture.md` to list the actual 11 `TableWriter` methods from `builder.go`:

```go
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
```

### 2. Move SetIncludeTunables to correct interface in all docs

Moved from `SectionBuilder` to `ReportComposer` in CONTRIBUTING.md, architecture prose, and Mermaid diagram. Updated method counts (SectionBuilder: 9, ReportComposer: 3).

### 3. Remove phantom auditBuilder references

Deleted all references to `auditBuilder` from CONTRIBUTING.md and architecture.md. The `reportGenerator` interface lists its 4 methods directly without embedding.

### 4. Add debug logging in GetBuilder() failure path

```go
rb, ok := g.builder.(builder.ReportBuilder)
if !ok {
    g.logger.Debug("builder does not satisfy full ReportBuilder interface",
        "type", fmt.Sprintf("%T", g.builder))
    return nil
}
```

### 5. Add compile-time assertion for reportGenerator

```go
var _ reportGenerator = (*builder.MarkdownBuilder)(nil)
```

### 6. Add tests for uncovered paths

Created a `narrowOnlyBuilder` mock satisfying `reportGenerator` but not `ReportBuilder`, then added two tests:

- `TestHybridGenerator_GetBuilder_NilBuilder` -- covers nil branch
- `TestHybridGenerator_GetBuilder_NarrowBuilder` -- covers `!ok` branch

Result: `GetBuilder()` at 100% coverage.

## Prevention Strategies

### Write docs from `go doc` output, not from memory

Run `go doc -all ./internal/converter/builder` and copy-paste the interface definition. Then write prose around it. Never type method names from recall.

### Verify every identifier in Mermaid diagrams

After editing any Mermaid diagram, extract every identifier (class name, method name) and `grep -r` for each in Go source. Any identifier returning zero hits is fabricated.

### Compile-time assertions for every interface-implementor pair

Make `var _ Interface = (*Struct)(nil)` mandatory for every interface a struct implements. The project already does this in `builder.go` -- extend to all consumer-local interfaces.

### Treat docs like code: method counts must be verifiable

When stating "SectionBuilder has 9 methods", include a verification note in the PR description: `Verified: go doc ./internal/converter/builder SectionBuilder | grep -c '^\t'`.

### Update docs in the same commit as the interface change

Do not defer doc updates to a follow-up PR. The split commit knows the exact method assignments; a later doc commit relies on memory.

### Verify concurrency-invariant prose against the source

Concurrency-invariant claims are mechanically verifiable — every assertion ("X is read-only after init", "Y has sub-goroutines", "Z clones only these slices", "lock M protects N") points at code that can be grepped or read. Drift here is silent: the prose reads correct, plausibility-driven reviewers accept it, and the wrong claim ships. Run a per-claim grep before writing or accepting any of these prose categories. Each recipe distinguishes "verified" from "plausible":

**"Set once / read-only after init":**

```bash
grep -rn '\.<fieldName>\s*=' ./internal/<package>/
```

If assignments exist only in `_test.go`, the claim is true for production but not the in-package test surface. Write both: "Not reassigned by any production code path; in-package tests inject test doubles via the unexported field (see `<package>_test.go`)."

**"Sub-goroutines / concurrent X":**

```bash
grep -rn 'go func\|sync\.WaitGroup\|errgroup' ./internal/<package>/
```

If this returns nothing in the file being described, the function does not spawn sub-goroutines. A mutex protecting state across goroutines does not require sub-goroutines to exist *in the method being described* — it may exist for callers who share the resource. Name the actual threat model rather than inventing fan-out.

**"X protects Y against Z":**

```bash
grep -n 'mu\.Lock\|mu\.RLock\|mu\.Unlock\|mu\.RUnlock' ./internal/<package>/<file>.go
```

List the actual writer and reader methods. The protection statement must name them, not a hypothetical producer/consumer.

**"Clones only X" / "shares Y backing arrays":**

```bash
grep -n 'slices\.Clone\|make(\[\|copy(' ./internal/<package>/normalize.go
```

Read the cloning code line-by-line and enumerate every target by name. Group by reason (mutated-by-this-function vs. defensively-cloned). Listing only one category and using "only" understates the safety surface.

### Tell automated reviewers to verify, not just plausibility-check

Generic prompts like "check documentation accuracy" optimize for plausibility — reviewers read the prose, find it sensible, and report no issue. The 6-persona automated review on PR #598 missed three concurrency-prose drifts because none of the personas had been instructed to grep the cited claims. The 3-agent second-opinion review caught all three because the comment-analyzer's prompt specifically said "verify each cited claim against the actual source code; grep for the assignments / goroutine launches / lock callsites named in the prose."

When you write a reviewer prompt that touches concurrency-invariant docs, include the literal sentence:

> *"For each mechanical claim in the prose — field assignments, goroutine launches, mutex callsites, clone targets — run a grep or read the relevant lines before accepting the claim."*

Without that instruction, the reviewer's bar for "accuracy" defaults to "sounds right."

## Verification Checklist

Before merging PRs that touch docs, AGENTS.md, GOTCHAS.md, or Mermaid diagrams:

- [ ] Every interface named in docs exists in source
- [ ] Every method attributed to an interface appears in that interface definition
- [ ] Method counts match `grep -c` of method signatures
- [ ] Every struct claimed to implement an interface has a compile-time assertion
- [ ] Every Mermaid identifier resolves to a real symbol in source
- [ ] Every "set once / read-only" claim has been grepped for assignments package-wide
- [ ] Every "sub-goroutines" or "concurrent X" claim has been grepped for `go func`/`WaitGroup`/`errgroup` in the cited files
- [ ] Every "X protects Y against Z" claim names the actual `Lock`/`RLock` callsites
- [ ] Every "clones only X" claim enumerates all clone targets by reason
- [ ] Reviewer prompts that touch concurrency docs include explicit "grep/read each cited claim" instruction
- [ ] `just ci-check` passes
- [ ] Code paths described in docs have corresponding test cases

## Recurrence: Concurrency-Invariant Prose (2026-05-03)

The same drift pattern recurred on a different surface — concurrency invariants rather than interface methods — in [PR #598](https://github.com/EvilBit-Labs/opnDossier/pull/598) (`perf(processor): remove CoreProcessor mutex serialization`, squash-merged as commit `433bad6`). The mutex removal was correct and benchmarked clean (~2.24-2.57x throughput improvement). The follow-up doc commit on that PR (collapsed into `433bad6` by the squash-merge, so no longer addressable as a standalone SHA) contained three factual errors that a multi-persona automated review (correctness, testing, maintainability, project-standards, performance, reliability) passed without challenge:

1. **`validateFn` "read-only thereafter"** — `internal/processor/validate_test.go:351` writes `processor.validateFn = func(...) { panic(...) }` to inject panicking validators for the recovery test. The struct doc's "read-only thereafter" was true for production but false for the in-package test surface.

2. **`Report.mu` protects "concurrent appends from analyze's sub-goroutines"** — `internal/processor/analyze.go` is fully sequential (zero `go func`, zero `sync.WaitGroup`, zero `errgroup`). The mutex's actual role is serializing `AddFinding` (Lock) against `ToJSON`/`ToYAML`/`TotalFindings` (RLock) when a single `*Report` is shared across goroutines, plus forward-looking insurance for future fan-out analyzers.

3. **`normalize()` "clones only the slices it sorts"** — `internal/processor/normalize.go:18-37` clones two distinct categories: (a) slices mutated by sort/canonicalize phases (`FirewallRules`, `Users`, `Groups`, `Sysctl`, `LoadBalancer.MonitorTypes`); (b) defensively-cloned credential-bearing slices (`Certificates`, `DHCP` with deep `AdvancedV4`/`V6` pointer copies, `VPN.WireGuard.Clients`). The "only" understated the safety surface and mis-scoped the caller-aliasing contract.

A targeted second-opinion review with the explicit instruction to verify each cited claim against source caught all three because that prompt was scoped to grep for assignments, goroutine launches, and read the cloning code rather than evaluate the prose for plausibility. The corrections shipped in follow-up commits on the same PR, all collapsed into `433bad6` by the squash-merge. The session also produced separate guardrail-style GOTCHAS additions for `testifylint go-require` and `goconst` (now §1.3 / §1.4 of `GOTCHAS.md`); those landed in the next merge cycle.

The lesson is the same as the interface-refactor instance: prose drift is silent, generic review prompts measure plausibility, and the only reliable defense is explicit per-claim verification at write time and at review time. The grep recipes above (Prevention Strategies > Verify concurrency-invariant prose) are the operational form.
