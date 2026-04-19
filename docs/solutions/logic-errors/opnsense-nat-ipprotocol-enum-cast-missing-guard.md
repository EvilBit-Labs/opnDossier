---
title: OPNsense NAT rule IPProtocol bare enum casts silently passed invalid values
category: logic-errors
date: 2026-04-18
tags: [enum-validation, xml-to-go, converters, nat, asymmetry-drift, gotchas, audit, regression-tests]
component: pkg/parser/opnsense, pkg/parser/pfsense, pkg/model
module: pkg/parser/opnsense
problem_type: logic_error
severity: high
symptoms:
  - Invalid IPProtocol values from OPNsense NAT XML passed silently through the conversion pipeline
  - No ConversionWarning emitted for unrecognized IPProtocol strings in outbound or inbound NAT rules
  - Downstream consumers (builders, audit plugins) received invalid enum values without any signal
root_cause: missing_validation
resolution_type: code_fix
issue: NATS-145
pr: 580
related_docs:
  - docs/solutions/logic-errors/cli-flag-wiring-silent-ignore.md
  - docs/solutions/runtime-errors/liberal-boolean-xml-parsing-opnsense-pfsense.md
---

# OPNsense NAT rule `IPProtocol` bare enum casts silently passed invalid values

## Problem

`convertOutboundNATRules` and `convertInboundNATRules` in `pkg/parser/opnsense/converter.go` performed bare `common.IPProtocol(r.IPProtocol)` casts without the mandatory `IsValid()` guard, silently propagating unrecognized IP protocol family strings through the entire conversion pipeline into the `CommonDevice` model. The pattern this violates was already documented in `GOTCHAS.md §5.2` ("Enum Type Casts from XML") — the pfSense equivalents had the guard — but these two OPNsense callsites were never enumerated in the gotcha text and had no regression test, so the gap persisted undetected for months.

## Symptoms

- An OPNsense `config.xml` containing an unrecognized `<ipprotocol>` value on an outbound or inbound NAT rule (future OPNsense extension, hand-edited config, malformed import) produced no warning and no error.
- The invalid `common.IPProtocol` value propagated silently into `CommonDevice.NAT.OutboundRules[*].IPProtocol` and `.InboundRules[*].IPProtocol`.
- Downstream `switch` statements on `IPProtocol` fell through to their default branch, producing wrong output with no diagnostic.
- `ConvertDocument` returned a `nil` error, giving callers no signal that the data was semantically invalid.

## What Didn't Work

**Prose-only GOTCHAS documentation was not a sufficient tripwire.** `GOTCHAS.md §5.2` correctly described the required `IsValid()` pattern since before NATS-145 (the pfSense converter had adopted it; the `DeviceType` enum had adopted it). It explicitly named `NATOutboundMode`, `LAGGProtocol`, and `VIPMode` as callsites requiring the guard. But it did not enumerate the NAT rule `IPProtocol` paths, and there was no regression test that would fail when a new cast site was added without a guard. The documentation told contributors the rule; it did not enforce it.

**NATS-144's parser audit (PR #575) did not look inside converter rule-loops.** The NATS-144 pass was scoped to the registry, factory, and per-device parser entry points — godoc completeness, `internal/` import boundary, coverage thresholds. It stopped at the top-level `ConvertDocument` signature and did not descend into the inner `convertOutboundNATRules` / `convertInboundNATRules` loops where the bare casts lived. (session history)

**NATS-145's initial planning phase declared the problem solved prematurely.** Planning research checked the six most visible enum-cast sites in the OPNsense converter and reported "all 6 casts already have `IsValid()` guards" — accurate for the sites it checked, but the search targeted top-level switch/convert patterns, not inner per-rule mapping loops. The two NAT rule paths at lines 373 and 429 were missed. The PR was scoped as "audit-only: godoc completeness" on that basis. (session history)

## Solution

Added the canonical `IsValid()` + warning guard at both OPNsense NAT rule callsites, mirroring the pfSense implementation that was already correct.

### Before (pre-NATS-145, commit `0225387`)

In `convertOutboundNATRules`:

```go
result = append(result, common.NATRule{
    ...
    IPProtocol: common.IPProtocol(r.IPProtocol), // bare cast, no guard
    ...
})
```

In `convertInboundNATRules`:

```go
result = append(result, common.InboundNATRule{
    ...
    IPProtocol: common.IPProtocol(r.IPProtocol), // bare cast, no guard
    ...
})
```

### After (PR #580, commit `a6dc558`)

In `convertOutboundNATRules`:

```go
ipProto := common.IPProtocol(r.IPProtocol)
if r.IPProtocol != "" && !ipProto.IsValid() {
    c.addWarning(
        fmt.Sprintf("NAT.OutboundRules[%d].IPProtocol", i),
        r.IPProtocol,
        "unrecognized IP protocol family",
        common.SeverityLow,
    )
}
```

In `convertInboundNATRules`:

```go
ipProto := common.IPProtocol(r.IPProtocol)
if r.IPProtocol != "" && !ipProto.IsValid() {
    c.addWarning(
        fmt.Sprintf("NAT.InboundRules[%d].IPProtocol", i),
        r.IPProtocol,
        "unrecognized IP protocol family",
        common.SeverityLow,
    )
}
```

The canonical pfSense reference is `pkg/parser/pfsense/converter_security.go` (firewall rule `IPProtocol` at line 72, outbound NAT rule `IPProtocol` at line 165, inbound NAT rule `IPProtocol` at line 237) — all three had the guard before NATS-145 opened.

## Why This Works

The two-step pattern provides two invariants simultaneously:

- The `r.IPProtocol != ""` check exempts legitimately absent XML elements. When the schema omits the `<ipprotocol>` element entirely, the decoder produces an empty string — a valid "unspecified" state that must not generate noise.
- The `!ipProto.IsValid()` check catches every string that is non-empty but does not match any enum member. This makes the converter the last line of defense before invalid data enters `CommonDevice`.

`addWarning` accumulates into the `ConversionWarning` slice that `ConvertDocument` returns as its second return value, giving callers actionable diagnostics without forcing a hard error that would abort report generation. Consumers can filter by severity, log, or surface in UI at their discretion.

## Prevention

**Regression test as tripwire.** `TestConverter_EnumCast_EmitsWarning` in `pkg/parser/opnsense/converter_enum_cast_test.go` is a table-driven test with one row per guarded enum callsite. The two new rows — `"nat outbound rule ip protocol"` and `"nat inbound rule ip protocol"` — exercise the fixed code directly. Any future bare cast added to the OPNsense converter that omits the guard has no corresponding row, making the omission visible at PR review time. `TestConverter_EnumCast_EmptyStringDoesNotWarn` protects the empty-string exemption from accidental removal. Equivalent tests exist in the pfSense package.

**Audit technique: asymmetry detection between parallel implementations.** The correctness reviewer at 0.88 confidence found this bug by comparing guard coverage across the OPNsense and pfSense converters. Both converters implement the same contract (XML schema → `CommonDevice`) and expose the same `CommonDevice.NAT.*` fields. When one side has a guard and the other does not, that asymmetry is a red flag. When reviewing any new converter code, enumerate every `T(xmlString)` cast and verify its partner in the sibling converter has equivalent coverage. (session history)

**Scope decision: fix in-audit rather than defer.** The audit was nominally "audit-only," but the `AGENTS.md` zero-tolerance-for-tech-debt rule — "Fix all issues encountered, including pre-existing ones — never dismiss as 'not our problem'" — applied. Filing a follow-up todo would have left the bug in production while documentation accumulated; fixing in-scope closed the gap immediately. The fix landed in the same PR that surfaced it. (auto memory [claude])

**`GOTCHAS.md §5.2` updated with regression-test cross-references and the NATS-145 discovery history.** Future contributors who add a new enum cast are now instructed to add a corresponding row to the table-driven test in the same PR. The history note prevents the institutional-knowledge loss that caused the original gap.

## Related Issues

- [NATS-145 Jira ticket](https://evilbitlabs.atlassian.net/browse/NATS-145) — converter audit epic
- PR #575 (NATS-144) — sibling audit that established the methodology but did not check inner converter loops
- PR #577 — liberal boolean parsing; touched `pkg/parser/opnsense/converter.go` on a parallel track, did not surface this bug
- [`docs/solutions/logic-errors/cli-flag-wiring-silent-ignore.md`](cli-flag-wiring-silent-ignore.md) — same class of silent-ignore defect in a different layer (CLI flag wiring)
- [`docs/solutions/runtime-errors/liberal-boolean-xml-parsing-opnsense-pfsense.md`](../runtime-errors/liberal-boolean-xml-parsing-opnsense-pfsense.md) — sibling XML-to-Go correctness work on the same converter file
- `GOTCHAS.md §5.2` — canonical pattern documentation (updated in PR #580 to cross-reference the regression tests)
