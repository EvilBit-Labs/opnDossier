# ADR-0004: Unified firewall shadow-detection engine with a deadRules compatibility view

**Date**: 2026-07-19 **Status**: proposed **Deciders**: unclesp1d3r

> **Pending implementation.** This ADR records a forward-looking decision made while planning firewall rule shadowing detection (issue #202). The unified shadow engine and the `analysis.shadowedRules` output are not yet built; the `deadRules` compatibility view describes how the existing export is preserved once they are. Status moves to `accepted` once the engine lands.

## Context

`internal/analysis` currently has two narrow, separate firewall-rule detectors: block-all unreachability and byte-for-byte duplicates, both produced by `DetectDeadRules` and surfaced as `analysis.deadRules` in the JSON/YAML export that AI/agent consumers depend on (see `docs/for-agents.md`). Issue #202 adds broader shadow detection — full and partial shadows keyed to pf precedence, classified by operator impact. Planning had to decide whether to bolt the new detector alongside the existing one or consolidate, and how to treat the stable `analysis.deadRules` export.

## Decision

Consolidate all "a rule, or a subset of its traffic, never takes effect" detection into a single shadow engine, retiring the internal `DeadRuleKind` path. Preserve `analysis.deadRules` as a derived compatibility view — the unreachable-plus-duplicate subset of shadow findings — deprecated in the output documentation and slated for removal in a future major version. Add a richer `analysis.shadowedRules` collection alongside it.

## Alternatives Considered

### Alternative 1: Keep both detectors, cross-reference findings

- **Pros**: smallest change to existing output; no consolidation risk.
- **Cons**: two vocabularies for one concept; per-rule bookkeeping to avoid double-reporting the same rule; the two result sets drift over time.
- **Why not**: users would see the same rule flagged twice under different names, and the model never actually unifies.

### Alternative 2: Clean break — remove `deadRules`, replace with `shadowedRules`

- **Pros**: a single output vocabulary immediately; no dual-surface maintenance.
- **Cons**: breaks a stable machine-readable interface agent consumers depend on; forces an immediate major-version bump and a golden-file rewrite.
- **Why not**: opnDossier promises stable output for agent consumers; breaking it for an internal cleanup is the wrong trade.

## Consequences

### Positive

- One concept and one code path for rule-effectiveness analysis.
- No consumer breakage — `deadRules` stays populated.
- `shadowedRules` carries richer impact classification (security / troubleshooting / hygiene) and partial-shadow detail.

### Negative

- Dual output surface (`deadRules` and `shadowedRules`) until the compatibility view is removed.
- The derived view must stay in sync with the shadow findings it summarizes.

### Risks

- Compatibility-view drift — mitigate with a test asserting `deadRules` equals the unreachable-plus-duplicate subset derived from `shadowedRules`.
- Indefinite shim — mitigate with the stated removal-at-next-major criterion recorded in the output documentation.
