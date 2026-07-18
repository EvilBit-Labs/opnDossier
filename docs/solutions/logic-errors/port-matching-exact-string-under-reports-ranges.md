---
title: Exact-string port matching under-reports WAN exposure for ranges and aliases
category: logic-errors
date: 2026-07-18
tags: [security, port-matching, false-negative, red-mode, audit, wan-exposure, over-report, regression-tests]
component: internal/audit
module: internal/audit
problem_type: logic_error
severity: high
symptoms:
  - A WAN firewall/NAT rule that permits a service via a port range ("20-25") or comma list ("80,22,443") did not mark the service WAN-exposed
  - Red-mode audit reported a genuinely internet-reachable SSH/WebGUI/SNMP service as safely LAN-only
  - The doc comment claimed an "over-report (safe) direction" while the code actually under-reported
root_cause: incorrect_comparison
resolution_type: code_fix
issue: 281
pr: 695
related_docs:
  - docs/solutions/logic-errors/opnsense-nat-ipprotocol-enum-cast-missing-guard.md
  - docs/solutions/logic-errors/cli-flag-wiring-silent-ignore.md
---

## Problem

The red-mode WAN-exposure detector correlated a management service (WebGUI, SSH, SNMP) against firewall/NAT rules by comparing the rule's port to the service's port with **string equality**. OPNsense/pfSense rule port fields legitimately hold port **ranges** (`"20-25"`) and **comma lists** (`"80,22,443"`) as well as named **aliases**, so a rule permitting SSH via `Destination.Port = "20-25"` compared `"20-25" != "22"` and the service was classified `LANOnly`. For a security-audit tool this is a **false negative** — the worst failure direction, because a real internet-facing exposure is reported as safe.

## Symptoms

- A config with a WAN pass rule whose destination port is `"20-25"` (covering SSH/22) produced **zero** WAN-exposed-service findings.
- The same under-report applied to inbound NAT `ExternalPort` ranges.
- The `wanRulePermitsPort` doc comment asserted an over-report/safe bias, but the exact-match implementation silently biased the other way.

## What Didn't Work

- **Trusting the "safe direction" comment.** The code was documented as biasing toward over-report (matching the slice-1 NAT reachability choice), so the gap was invisible on a prose read. Three independent review lenses (correctness + security + adversarial) each flagged it from the code, not the comment — cross-corroboration is what promoted it to a confirmed P1.

## Solution

Parse the rule port grammar instead of comparing strings. Split on `,`; match each token as an exact numeric port or an `N-M` numeric range by containment; treat an empty/`any` port as permitting everything; and treat an **unresolvable non-numeric token** (a port alias we cannot expand without the alias table) as permitting the port — the deliberate over-report direction.

Before (`internal/audit/red_analysis.go`):

```go
func rulePortPermits(rulePort, servicePort string) bool {
    if rulePort == "" || rulePort == constants.NetworkAny {
        return true
    }
    return rulePort == servicePort // misses ranges, lists, aliases
}
```

After (`internal/audit/red_analysis.go`):

```go
func rulePortPermits(rulePort string, servicePort int) bool {
    if rulePort == "" || rulePort == constants.NetworkAny {
        return true
    }
    for token := range strings.SplitSeq(rulePort, ",") {
        token = strings.TrimSpace(token)
        if token == "" {
            continue
        }
        if lo, hi, ok := parsePortRange(token); ok {
            if servicePort >= lo && servicePort <= hi {
                return true
            }
            continue
        }
        if p, err := strconv.Atoi(token); err == nil {
            if p == servicePort {
                return true
            }
            continue
        }
        // Non-numeric, non-range token (a port alias): unresolvable here, so
        // over-report rather than emit a false negative.
        return true
    }
    return false
}
```

The repo already had a numeric-range parse precedent to mirror — `portMatchesDangerous` in `internal/plugins/sans/checks.go` splits `N-M` the same way.

## Why This Works

The exposure signal is now computed over the *actual* port grammar the vendor config uses, not a lexical string. Crucially, every ambiguous case resolves toward **over-report**: empty/`any` matches, ranges/lists match by containment, and an unresolvable alias is assumed to permit the port. A security audit that must not miss a real exposure should prefer a false positive (a LAN-only service flagged) over a false negative (an internet-facing service hidden). The prior string-equality biased the wrong way while claiming the right one.

## Prevention

- **Never string-compare a port (or protocol, or address) field in a security-analysis path.** These fields carry a small grammar — ranges, lists, aliases — and exact matching silently drops every non-literal form. Parse the grammar; where you cannot fully resolve it, bias to over-report.
- **State the failure direction and test it.** A comment claiming "safe direction" is not a test. Regression cases in `internal/audit/mode_controller_red_test.go` now pin the range hit (`"20-25"` → SSH exposed), the range miss (`"8000-9000"` → not exposed), the comma list (`"80,22,443"` → exposed), and the alias over-report (`"MgmtPorts"` → exposed).
- **Cross-lens review catches "plausible but wrong."** This bug survived a prose read because the comment was reassuring; it was caught only when independent correctness, security, and adversarial reviewers each read the implementation. When a claim about safety direction matters, verify it against the code, not the comment.
