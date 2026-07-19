---
title: Red-mode WAN-exposure detector wrongly correlates NAT port-forwards with the firewall's own management services
category: logic-errors
date: 2026-07-18
tags: [security, false-positive, red-mode, audit, wan-exposure, nat, webgui, ssh, snmp, regression-tests]
component: internal/audit
module: internal/audit
problem_type: logic_error
severity: high
symptoms:
  - A WAN inbound NAT port-forward to an unrelated internal host on the same external port as WebGUI/SSH/SNMP caused the firewall's own management service to be reported WAN-reachable
  - Red-mode audit flagged a firewall's own SSH/WebGUI/SNMP as internet-exposed with no pass rule ever targeting the firewall directly, purely because a port-forward shared the same external port number
  - False positive inflated exposed-service findings and could mask the real, separately-reportable NAT exposure by conflating it with a fabricated firewall-local exposure
root_cause: logic_error
resolution_type: code_fix
issue: 281
pr: 695
related_docs:
  - docs/solutions/logic-errors/port-matching-exact-string-under-reports-ranges.md
---

## Problem

`wanRulePermitsPort` in `internal/audit/red_analysis.go` correlated a firewall-local management service's port (WebGUI/SSH/SNMP) against `device.NAT.InboundRules` as well as firewall pass rules, so a WAN-reachable inbound NAT port-forward to a *different* internal host was mistaken for evidence that the firewall's own service on that port was WAN-exposed.

## Symptoms

- Red-mode audit reports a `WAN-Exposed Service: SSH` (or WebGUI/SNMP) finding for the firewall itself whenever any WAN-reachable inbound NAT rule happens to forward the same external port number to an unrelated internal host — even when no firewall pass rule ever targets the firewall directly on that port.
- Concretely: a NAT rule forwarding WAN port 22 to `192.0.2.50` (an internal host's SSH) caused the tool to flag the firewall's *own* SSH daemon (also listening on 22) as WAN-exposed, with zero pass rules permitting traffic to the firewall itself.
- `wan_exposed_services_count` metadata is inflated, and the emitted finding attributes an exposure to the wrong host — the firewall — while the real exposure (the port-forwarded internal host) is separately, correctly reported by `addWeakNATRules` as a "WAN-Reachable Port Forward" finding. So the same underlying NAT rule produced two findings pointing at two different hosts, one of them wrong.

## What Didn't Work / Why It Was Missed

`wanRulePermitsPort`'s doc comment (and sibling `rulePortPermits`) establishes a deliberate "over-report exposure" philosophy elsewhere in this file: an empty/`any` rule port, a range/comma-list containment match, and an unresolvable port alias are all *intentionally* treated as permitting the port, because a false negative in a security audit is worse than a false positive. Looping over `device.NAT.InboundRules` in addition to firewall pass rules looked like a natural extension of that same philosophy — "when in doubt, count it as exposed."

That reasoning doesn't transfer to NAT rules, and the difference was missed: the port-only correlation was structurally plausible (same port number, same WAN reachability check via `analysis.InboundNATRuleReachability`), but a NAT inbound rule's `InternalIP` is by construction a different host than the firewall. Over-reporting a real host's exposure onto the *wrong* host isn't the safe "err on the side of caution" direction the rest of the file relies on — it's simply incorrect and misleading, not merely noisy. The existing NAT-forward exposure path (`addWeakNATRules` via `analysis.InboundNATRuleReachability`) was always correct on its own terms and needed no change; the bug was solely in re-using that NAT data inside the firewall-local-service correlation.

Caught by CodeRabbit on PR #695.

## Solution

Before, `wanRulePermitsPort` iterated both `device.FirewallRules` and `device.NAT.InboundRules`:

```go
// (removed) second loop previously in wanRulePermitsPort:
for _, nat := range device.NAT.InboundRules {
    if analysis.InboundNATRuleReachability(nat, device.Interfaces, device.FirewallRules) != analysis.WANReachable {
        continue
    }

    if rulePortPermits(nat.ExternalPort, port) {
        return true
    }
}
```

After, the NAT loop is removed entirely, and `wanRulePermitsPort` only ever consults firewall pass rules:

```go
// wanRulePermitsPort reports whether any WAN-reachable enabled firewall pass
// rule permits the given port. Port matching biases toward over-reporting
// exposure (the safe direction for a security tool): an empty or "any" rule
// port permits every port, a numeric range or comma-list is matched by
// containment, and an unresolvable port alias is treated as permitting the
// port rather than silently classifying the service as safely LAN-only. Only
// a concrete numeric port that does not contain the service port is treated
// as non-permitting. See rulePortPermits.
func wanRulePermitsPort(device *common.CommonDevice, port int) bool {
	for _, rule := range device.FirewallRules {
		if rule.Disabled || rule.Type != common.RuleTypePass {
			continue
		}

		if analysis.RuleReachability(rule, device.Interfaces) != analysis.WANReachable {
			continue
		}

		if rulePortPermits(rule.Destination.Port, port) {
			return true
		}
	}

	return false
}
```

The caller, `serviceReachability` (`internal/audit/red_analysis.go` ~line 147), now carries an explanatory comment documenting *why* NAT rules are deliberately excluded:

```go
// serviceReachability classifies a firewall-local management service (WebGUI,
// SSH, SNMP) by port: WAN-reachable when a WAN-reachable firewall pass rule
// permits that port, otherwise LAN-only. A configured management service is
// never Local.
//
// Deliberately does NOT consult device.NAT.InboundRules: an inbound NAT rule
// forwards WAN traffic to InboundNATRule.InternalIP — by construction a
// different host than the firewall itself — so a NAT rule sharing the same
// external port as a management service is never evidence that the
// firewall's OWN service is WAN-reachable. Correlating NAT rules against
// firewall-local ports produced a false positive: a NAT rule forwarding WAN
// port 22 to an unrelated internal host's SSH would flag the firewall's own
// SSH daemon (also on port 22) as exposed even with no pass rule ever
// targeting the firewall directly. NAT rules are correlated separately, on
// their own terms, by addWeakNATRules/InboundNATRuleReachability.
func serviceReachability(device *common.CommonDevice, port int) analysis.Reachability {
	if wanRulePermitsPort(device, port) {
		return analysis.WANReachable
	}

	return analysis.LANOnly
}
```

`addWeakNATRules` (~line 347, unchanged) continues to report NAT port-forward exposure correctly and independently, by checking `analysis.InboundNATRuleReachability(nat, device.Interfaces, device.FirewallRules)` directly against each `InboundNATRule` and emitting a distinct "WAN-Reachable Port Forward" finding scoped to `nat.inbound[i]`, not to any management-service component.

Regression test: `TestRedMode_NATForward_DoesNotExposeFirewallLocalService` in `internal/audit/mode_controller_red_test.go` (~line 671). It builds a device with SSH enabled on port 22, a firewall pass rule that only permits WAN port 80, and an inbound NAT rule forwarding WAN port 22 to `192.0.2.50:22`. It asserts:

- `weak_nat_rules_count == 1` (the port forward is still correctly reported as its own, distinct exposure), and
- `wan_exposed_services_count == 0` and no `"WAN-Exposed Service: SSH"` finding exists (the firewall's own SSH is not falsely flagged).

Fixed on PR #695 while resolving review threads.

## Why This Works

The correct model is: a given host's own service is exposed only by rules whose traffic actually terminates *at that host*. For the firewall's own management services, that means firewall pass rules matched by `analysis.RuleReachability` — rules that govern traffic reaching the firewall's own interfaces. An inbound NAT/port-forward rule's traffic terminates at `InboundNATRule.InternalIP`, a separate internal host; it is that *other* host's exposure, not the firewall's, regardless of whether the external port number happens to numerically coincide with a service the firewall itself also runs on that port.

By removing the NAT loop from `wanRulePermitsPort`, the two exposure classes stay on their own dedicated analysis paths: `addWANExposedServices`/`serviceReachability` for firewall-local management-plane exposure (SSH, SNMP, WebGUI), and `addWeakNATRules`/`analysis.InboundNATRuleReachability` for port-forward exposure of internal hosts. Each finding's `Component`/`AttackSurface` now correctly attributes the exposure to the host it actually applies to, instead of a shared port number silently merging two unrelated hosts' exposure into one (wrong) finding.

## Prevention

- **General rule for host/service exposure correlation:** when determining whether a specific host's or service's port is exposed to the WAN, only count firewall rules whose *destination is that host*. A port-forward (NAT) rule's destination is always the different, internal host named in the NAT rule — never the firewall itself, and never any other host's own listening service — even when the external port number matches.
- **Keep NAT exposure on its own path.** NAT/port-forward exposure is a distinct, already-correct concept (`addWeakNATRules` + `analysis.InboundNATRuleReachability`). Don't fold it into firewall-local service correlation as an "extra layer of over-reporting" — the file's legitimate "bias toward over-reporting" principle (empty/`any` ports, ranges, unresolvable aliases) only applies *within* a single, correctly-scoped correlation; it does not license conflating two different hosts' exposure.
- **The regression test is the pin.** `TestRedMode_NATForward_DoesNotExposeFirewallLocalService` (`internal/audit/mode_controller_red_test.go`) asserts both that the NAT forward is still reported (`weak_nat_rules_count == 1`) and that it does NOT bleed into the firewall-local service finding (`wan_exposed_services_count == 0`, no `WAN-Exposed Service: SSH`). Any future change that reintroduces NAT correlation into `wanRulePermitsPort`/`serviceReachability` should be caught by this test — if it's ever weakened or removed, the false-positive class in this bug can silently return.

## Related

- [Exact-string port matching under-reports WAN exposure for ranges and aliases](port-matching-exact-string-under-reports-ranges.md) — sibling bug in the **same** `wanRulePermitsPort` function on the same PR, but the **opposite** failure direction: that one is a false *negative* (exact-string port comparison missed ranges/lists/aliases, under-reporting real exposure), this one is a false *positive* (NAT port-forwards for a different host over-reported the firewall's own exposure). Both are now pinned by regression tests in `mode_controller_red_test.go`.
