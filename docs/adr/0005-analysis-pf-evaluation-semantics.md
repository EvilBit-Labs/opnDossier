# ADR-0005: Firewall analysis models pf rule-evaluation semantics directly

**Date**: 2026-07-19 **Status**: proposed **Deciders**: unclesp1d3r

> **Pending implementation.** This ADR records a forward-looking decision made while planning firewall rule shadowing detection (issue #202). The precedence logic described here is not yet implemented; it defines the contract the shadow engine and future rule analyzers follow. Status moves to `accepted` once the engine lands.

## Context

Shadow detection (issue #202) must decide whether a rule is overridden by a higher-precedence rule. A first framing assumed "the earlier rule in list order wins" (quick-first-match). But pf (OPNsense/pfSense) is not uniformly first-match: non-quick rules are last-match — a later matching rule wins — floating rules default to non-quick and evaluate device-wide before interface rules, and direction (in/out/any) scopes which rules interact. `FirewallRule` already models `Quick`, `Floating`, and `Direction`, and `RulesEquivalent` already compares `Quick`. Treating raw list order as precedence would manufacture false-positive findings — the worst failure mode for a security tool — on exactly the traffic-control rules (VPN, HA sync, anti-lockout) that matter most.

## Decision

The analysis engine derives rule precedence from pf evaluation semantics, not raw list order: quick rules are first-match, non-quick rules are last-match, unscoped floating rules evaluate device-wide before interface rules, and coverage is scoped by (interface, direction). Precedence is computed from the modeled `Quick`, `Floating`, and `Direction` fields.

## Alternatives Considered

### Alternative 1: Quick-first-match approximation (list order equals precedence)

- **Pros**: simplest to implement; correct for the common all-quick ruleset.
- **Cons**: wrong for non-quick and floating rules; produces false-positive Security findings on VPN, HA-sync, and anti-lockout rules.
- **Why not**: false positives on protective traffic are the worst failure for a security audit tool, and the fields needed to do it correctly are already modeled — the approximation buys nothing.

### Alternative 2: Scope v1 to quick rules only, document non-quick as a gap

- **Pros**: avoids the false positives; less evaluation logic.
- **Cons**: silently ignores floating rules (common for anti-lockout, VPN client egress, and HA/pfsync), under-reporting real shadows in mainstream configurations.
- **Why not**: the floating and non-quick cases are mainstream, not edge cases; the gap would omit high-value findings.

## Consequences

### Positive

- Correct precedence for real-world OPNsense/pfSense rulesets, including floating and non-quick rules.
- No false-positive Security findings from list-order misreads.
- Establishes the evaluation-semantics contract every future rule analyzer must honor.

### Negative

- More evaluation logic than a list-order scan (last-match resolution, floating placement, direction scoping).

### Risks

- Subtle pf-semantics mismatches — mitigate with acceptance examples per rule kind (quick, non-quick last-match, floating, direction-scoped) and grounding against a real `config.xml` during planning.
