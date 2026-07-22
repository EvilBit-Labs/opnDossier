package analysis

import (
	"fmt"
	"slices"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// DetectShadowedRules reports firewall rules — or subsets of their traffic —
// that never take effect because a higher-precedence rule under pf
// evaluation semantics (quick first-match, non-quick last-match, floating
// device-wide) already covers them (R5-R7, R9, R12-R15).
//
// DetectShadowedRules is a pure function of cfg: no shared state, mirroring
// every other Detect* in this package. Returns nil for a nil cfg or fewer
// than two firewall rules.
func DetectShadowedRules(cfg *common.CommonDevice) []common.ShadowedRuleFinding {
	if cfg == nil || len(cfg.FirewallRules) < 2 {
		return nil
	}

	pairs := ResolvePrecedence(cfg)
	pairs = append(pairs, detectAliasBlockedSecurityAdvisories(cfg.FirewallRules, cfg.Interfaces, cfg.NamedObjects)...)

	var findings []common.ShadowedRuleFinding

	for _, pair := range pairs {
		if isTerminalDefaultDeny(pair, cfg.FirewallRules) {
			continue
		}

		if finding, ok := buildShadowFinding(pair, cfg.Interfaces); ok {
			findings = append(findings, finding)
		}
	}

	sortShadowFindings(findings)

	return findings
}

// buildShadowFinding classifies pair and produces its ShadowedRuleFinding.
// The second return is false when pair.AliasBlocked is true and the pair's
// impact class is not Security — R8's "stay silent for Hygiene/
// Troubleshooting aliasBlocked pairs" carve-out.
func buildShadowFinding(pair PrecedencePair, ifaces []common.Interface) (common.ShadowedRuleFinding, bool) {
	impactClass := impactClassFor(pair.Winner.Rule.Type, pair.Loser.Rule.Type)

	if pair.AliasBlocked && impactClass != common.ImpactClassSecurity {
		return common.ShadowedRuleFinding{}, false
	}

	kind := shadowKindFor(pair.Extent)
	sev := severityFor(impactClass, RuleReachability(pair.Loser.Rule, ifaces), pair.AliasBlocked)

	return common.ShadowedRuleFinding{
		Kind:            kind,
		ImpactClass:     impactClass,
		Severity:        sev.severity,
		Confidence:      sev.confidence,
		RuleIndex:       pair.Loser.Index,
		ShadowedByIndex: pair.Winner.Index,
		Interface:       pair.Interface,
		Direction:       pair.Direction,
		Port:            eclipsedPort(pair, kind),
		Description:     buildShadowDescription(pair, kind, pair.AliasBlocked),
		Recommendation:  recommendationFor(impactClass, pair.AliasBlocked),
	}, true
}

// impactClassFor derives R12's impact class from the winner→loser action
// relationship (not earlier/later — non-quick pf semantics flips which rule
// is the loser, so the classification must key off which rule actually won
// the overlap): same action ⇒ Hygiene; winner pass over a differently-typed
// (block/reject) loser ⇒ Security; any other combination — a block/reject
// winner over a pass loser, or two differently-typed explicit rules — ⇒
// Troubleshooting.
func impactClassFor(winnerType, loserType common.FirewallRuleType) common.ImpactClass {
	if winnerType == loserType {
		return common.ImpactClassHygiene
	}

	if winnerType == common.RuleTypePass {
		return common.ImpactClassSecurity
	}

	return common.ImpactClassTroubleshooting
}

// shadowKindFor maps a PrecedencePair's coverage Extent to the KTD-8
// full/partial Kind. Extent is never CoverNone or CoverIndeterminate for a
// pair reaching this point (ResolvePrecedence guarantees Full/Partial; the
// R8 advisory scan's CoverNone pairs are given an explicit conservative
// Extent by resolveAliasBlockedAdvisoryPair).
func shadowKindFor(extent Coverage) common.ShadowKind {
	if extent == CoverFull {
		return common.ShadowKindFull
	}

	return common.ShadowKindPartial
}

// shadowSeverity bundles a finding's severity and confidence — the pair
// severityFor/securitySeverity compute together from the KTD-6 matrix.
// Returning this as a single value (rather than two string results) avoids
// the gocritic unnamedResult / nonamedreturns tension that two same-typed
// named returns would create.
type shadowSeverity struct {
	severity   common.Severity
	confidence common.Confidence
}

// severityFor implements the KTD-6 severity matrix: severity and confidence
// are a pure function of impact class × reachability, with a distinct
// (lower-confidence) row for the R8 advisory path.
func severityFor(impactClass common.ImpactClass, reachability Reachability, advisory bool) shadowSeverity {
	wan := reachability == WANReachable

	switch impactClass {
	case common.ImpactClassSecurity:
		return securitySeverity(wan, advisory)
	case common.ImpactClassTroubleshooting:
		if wan {
			return shadowSeverity{severity: common.SeverityMedium, confidence: common.ConfidenceHigh}
		}

		return shadowSeverity{severity: common.SeverityLow, confidence: common.ConfidenceHigh}
	default: // common.ImpactClassHygiene
		return shadowSeverity{severity: common.SeverityLow, confidence: common.ConfidenceHigh}
	}
}

// securitySeverity implements the KTD-6 matrix's two Security rows: the
// confirmed row (critical on WAN, high on LAN/local) and the R8 advisory row
// (high on WAN, medium on LAN/local — both low confidence).
func securitySeverity(wan, advisory bool) shadowSeverity {
	if advisory {
		if wan {
			return shadowSeverity{severity: common.SeverityHigh, confidence: common.ConfidenceLow}
		}

		return shadowSeverity{severity: common.SeverityMedium, confidence: common.ConfidenceLow}
	}

	if wan {
		return shadowSeverity{severity: common.SeverityCritical, confidence: common.ConfidenceHigh}
	}

	return shadowSeverity{severity: common.SeverityHigh, confidence: common.ConfidenceHigh}
}

// eclipsedPort returns the best-effort eclipsed port subset for a partial
// shadow (R7), taken from the shadowed (loser) rule's destination port.
// Full shadows leave Port empty — the whole rule is shadowed, not a subset.
func eclipsedPort(pair PrecedencePair, kind common.ShadowKind) string {
	if kind != common.ShadowKindPartial {
		return ""
	}

	return pair.Loser.Rule.Destination.Port
}

// buildShadowDescription renders a human-readable summary of pair. advisory
// prefixes the description with the explicit "(unconfirmed — unresolved
// alias)" marker required by R8 so severity-sorted output distinguishes
// advisory findings from confirmed same-severity findings.
func buildShadowDescription(pair PrecedencePair, kind common.ShadowKind, advisory bool) string {
	extentWord := "fully"
	if kind == common.ShadowKindPartial {
		extentWord = "partially"
	}

	desc := fmt.Sprintf(
		"Rule %d (%s) on interface %s (%s) is %s shadowed by rule %d (%s); the %s rule never takes effect for the overlapping traffic under pf evaluation order.",
		pair.Loser.Index+1,
		pair.Loser.Rule.Type,
		pair.Interface,
		pair.Direction,
		extentWord,
		pair.Winner.Index+1,
		pair.Winner.Rule.Type,
		pair.Loser.Rule.Type,
	)

	if advisory {
		return fmt.Sprintf(
			"(unconfirmed — unresolved alias) %s This overlap involves a named object (alias) that could not be fully resolved, so the shadow could not be confirmed with certainty.",
			desc,
		)
	}

	return desc
}

// recommendationFor suggests a corrective action for impactClass.
func recommendationFor(impactClass common.ImpactClass, advisory bool) string {
	switch impactClass {
	case common.ImpactClassSecurity:
		if advisory {
			return "Resolve the alias reference and re-run analysis to confirm whether this deny rule is bypassed; reorder or narrow the covering pass rule if confirmed."
		}

		return "Reorder rules so the deny rule takes precedence, or narrow the covering pass rule to exclude this traffic."
	case common.ImpactClassTroubleshooting:
		return "Reorder rules so the intended pass rule takes precedence, or remove the shadowing deny rule if it is no longer needed."
	default: // common.ImpactClassHygiene
		return "Remove the redundant rule to simplify the configuration."
	}
}

// isTerminalDefaultDeny implements the R9 non-finding guard: a terminal
// block-all OR reject-all rule (last rule in its pf evaluation group,
// matching any source and any destination) sitting below specific allows is
// the correct default-deny pattern and is never reported as a shadow,
// regardless of coverage extent. This mirrors the i < len(rules)-1 exemption
// DetectDeadRules already applies to the same pattern, but — unlike
// DetectDeadRules, which is pinned to legacy Block-only byte-for-byte output
// — also recognizes RuleTypeReject: a terminal `reject any->any` below
// specific passes is exactly as legitimate a default-deny pattern as
// `block any->any`, and without this a mainstream reject-based default-deny
// configuration would produce a false-positive Security shadow.
func isTerminalDefaultDeny(pair PrecedencePair, rules []common.FirewallRule) bool {
	if !isTerminalDenyRule(pair.Loser.Rule) {
		return false
	}

	ordered := orderedGroupRules(rules, pair.Interface, pair.Direction)
	if len(ordered) == 0 {
		return false
	}

	return ordered[len(ordered)-1].Index == pair.Loser.Index
}

// detectAliasBlockedSecurityAdvisories scans every pf evaluation group for
// candidate pairs whose coverage could not be resolved because of an
// unresolvable named-object reference (aliasBlocked) and which — had the
// alias resolved — might have been a Security-class shadow (a pass rule
// possibly defeating a block/reject rule). ResolvePrecedence (U5) only
// returns pairs whose coverage() call resolved to CoverFull or CoverPartial,
// so a pair whose coverage folded back to CoverNone via U4's alias-blocked
// exact-singleton fallback is invisible to it — this scan is the only place
// such a pair surfaces, implementing R8's advisory carve-out (the same
// over-report bias GOTCHAS §8.4 documents for NAT-to-WAN correlation).
//
// Pairs whose coverage() call did resolve to CoverFull or CoverPartial with
// AliasBlocked=true are NOT re-derived here — ResolvePrecedence already
// returns those, and buildShadowFinding routes them through the same
// advisory branch via pair.AliasBlocked.
func detectAliasBlockedSecurityAdvisories(
	rules []common.FirewallRule,
	deviceIfaces []common.Interface,
	no common.NamedObjects,
) []PrecedencePair {
	groups := buildPrecedenceGroups(rules, deviceIfaces)

	var pairs []PrecedencePair

	for _, key := range sortedGroupKeys(groups) {
		ordered := groups[key]

		for i := range ordered {
			for j := i + 1; j < len(ordered); j++ {
				if pair, ok := resolveAliasBlockedAdvisoryPair(key, ordered[i], ordered[j], no); ok {
					pairs = append(pairs, pair)
				}
			}
		}
	}

	return pairs
}

// resolveAliasBlockedAdvisoryPair mirrors resolvePair's winner/loser
// derivation (precedence.go, derivePairWinnerLoser) for one candidate
// (earlier, later) pair, but — unlike resolvePair — surfaces the pair even
// when coverage() returns CoverNone, provided the CoverNone came from an
// unresolvable alias (aliasBlocked) and the resulting winner/loser action
// relationship would be Security. The pair's Extent is set to CoverFull: the
// true extent is unknown (that is precisely what "unresolved" means), and
// R8's over-report bias for security correlation prefers the conservative
// (full) framing over silently under-reporting a partial one.
func resolveAliasBlockedAdvisoryPair(
	key precedenceGroupKey,
	earlier, later IndexedRule,
	no common.NamedObjects,
) (PrecedencePair, bool) {
	wl, cov, aliasBlocked := derivePairWinnerLoser(earlier, later, no)

	if !aliasBlocked || cov != CoverNone {
		return PrecedencePair{}, false
	}

	if impactClassFor(wl.winner.Rule.Type, wl.loser.Rule.Type) != common.ImpactClassSecurity {
		return PrecedencePair{}, false
	}

	return PrecedencePair{
		Interface:    key.iface,
		Direction:    key.dir,
		Winner:       wl.winner,
		Loser:        wl.loser,
		Extent:       CoverFull,
		AliasBlocked: true,
	}, true
}

// sortShadowFindings orders findings deterministically (GOTCHAS §3.1):
// interface name, then direction, then the shadowed rule's position, then
// the covering rule's position.
func sortShadowFindings(findings []common.ShadowedRuleFinding) {
	slices.SortFunc(findings, func(a, b common.ShadowedRuleFinding) int {
		if c := strings.Compare(a.Interface, b.Interface); c != 0 {
			return c
		}

		if c := strings.Compare(string(a.Direction), string(b.Direction)); c != 0 {
			return c
		}

		if a.RuleIndex != b.RuleIndex {
			return a.RuleIndex - b.RuleIndex
		}

		return a.ShadowedByIndex - b.ShadowedByIndex
	})
}
