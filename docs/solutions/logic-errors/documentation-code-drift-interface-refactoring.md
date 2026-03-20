---
title: Documentation-code drift after interface refactoring
category: logic-errors
date: '2026-03-19'
tags:
  - interface-split
  - documentation-drift
  - fabricated-methods
  - mermaid-diagram
  - test-coverage
  - compile-time-assertions
  - code-review
component: converter/builder
severity: medium
symptoms:
  - Documentation lists method names that do not exist in code
  - Method assigned to wrong interface in documentation
  - Mermaid diagram references nonexistent methods
  - Documentation references nonexistent sub-interface name
  - GetBuilder() returns nil without logging on type-assertion failure
  - No test coverage for GetBuilder() nil and narrow-builder code paths
  - 33% patch coverage on new code
related_issues:
  - '#323'
  - '#431'
related_docs:
  - docs/solutions/architecture-issues/file-split-refactor-gotchas.md
  - docs/solutions/logic-errors/cli-flag-wiring-silent-ignore.md
  - docs/solutions/architecture-issues/pkg-internal-import-boundary.md
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

When stating "SectionBuilder has 9 methods", include a verification note in the PR description: `Verified: grep -c 'func.*SectionBuilder' builder.go`.

### Update docs in the same commit as the interface change

Do not defer doc updates to a follow-up PR. The split commit knows the exact method assignments; a later doc commit relies on memory.

## Verification Checklist

Before merging PRs that touch docs, AGENTS.md, or Mermaid diagrams:

- [ ] Every interface named in docs exists in source
- [ ] Every method attributed to an interface appears in that interface definition
- [ ] Method counts match `grep -c` of method signatures
- [ ] Every struct claimed to implement an interface has a compile-time assertion
- [ ] Every Mermaid identifier resolves to a real symbol in source
- [ ] `just ci-check` passes
- [ ] Code paths described in docs have corresponding test cases
