package analysis

import (
	"maps"
	"slices"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// bucketDirections enumerates the two canonical direction buckets rules are
// grouped into. A rule with Direction == DirectionAny joins both buckets; a
// rule with DirectionIn joins only the "in" bucket; DirectionOut joins only
// the "out" bucket. Iteration order here also fixes the deterministic
// bucket ordering within a given interface (in before out).
var bucketDirections = [2]common.FirewallDirection{common.DirectionIn, common.DirectionOut}

// minGroupSizeForOverlap is the fewest rules a pf evaluation group can hold
// and still have a candidate pair to resolve.
const minGroupSizeForOverlap = 2

// PrecedencePair describes one resolved overlapping pair of firewall rules
// within a single (interface, direction) pf evaluation group: which rule
// wins the shared traffic, which rule is shadowed on it, and how much of the
// loser's match set the winner covers.
//
// Quick and non-quick are mirror images (ADR-0005, KTD-5). Under quick
// (first-match) semantics the earlier-positioned rule in the group wins
// outright when it covers the later rule, so the later rule is the loser.
// Under non-quick (last-match) semantics the later-positioned rule wins the
// overlap, so the earlier rule is the loser. Winner and Loser therefore do
// not correlate with rule-list position in a fixed direction — callers must
// not assume Loser.Index is greater than Winner.Index.
type PrecedencePair struct {
	// Interface is the interface name the evaluation group was built for.
	Interface string
	// Direction is the direction bucket the group was evaluated under
	// (DirectionIn or DirectionOut; a DirectionAny rule joins both buckets
	// and so may appear in a PrecedencePair under either value).
	Direction common.FirewallDirection
	// Winner is the rule that wins the shared traffic under pf evaluation
	// semantics.
	Winner IndexedRule
	// Loser is the rule that is shadowed on the overlap — the rule a shadow
	// finding should be reported against.
	Loser IndexedRule
	// Extent is how much of Loser's match set Winner covers: CoverFull when
	// Loser is shadowed in its entirety, CoverPartial when only the
	// overlapping subset is shadowed. Never CoverNone or CoverIndeterminate;
	// pairs with those coverage results produce no PrecedencePair.
	Extent Coverage
	// AliasBlocked mirrors the coverage() aliasBlocked signal computed for
	// this pair, so consumers needing the R8 advisory path do not have to
	// re-run coverage() themselves.
	AliasBlocked bool
}

// ResolvePrecedence groups cfg's firewall rules into pf evaluation-order
// groups — by (interface, direction), with unscoped floating rules
// (Floating && len(Interfaces)==0) joining every interface group ahead of
// interface-bound rules — and resolves every overlapping pair within each
// group into its effective PrecedencePair per pf quick (first-match) /
// non-quick (last-match) semantics (ADR-0005, KTD-5). Overlap candidacy is
// decided by the U4 coverage predicate; pairs whose coverage is CoverNone or
// CoverIndeterminate produce no result.
//
// ResolvePrecedence is a pure function of cfg: no shared state, and
// deterministic output order (sorted interface name, then direction bucket,
// then group position). Returns nil for a nil cfg or fewer than two
// firewall rules.
func ResolvePrecedence(cfg *common.CommonDevice) []PrecedencePair {
	if cfg == nil || len(cfg.FirewallRules) < 2 {
		return nil
	}

	groups := buildPrecedenceGroups(cfg.FirewallRules)

	var pairs []PrecedencePair

	for _, key := range sortedGroupKeys(groups) {
		pairs = append(pairs, resolveGroup(key, groups[key], cfg.NamedObjects)...)
	}

	return pairs
}

// precedenceGroupKey identifies one (interface, direction-bucket) pf
// evaluation group.
type precedenceGroupKey struct {
	iface string
	dir   common.FirewallDirection
}

// buildPrecedenceGroups partitions rules into their pf evaluation-order
// groups: for every interface any rule is bound to, and for each direction
// bucket a rule is compatible with, unscoped floating rules are placed
// ahead of interface-bound rules, each subset preserving the rules'
// original relative list order. Groups with fewer than two rules are
// dropped — there is nothing to resolve a pair from.
func buildPrecedenceGroups(rules []common.FirewallRule) map[precedenceGroupKey][]IndexedRule {
	ifaceNames := make(map[string]struct{})

	for _, r := range rules {
		for _, iface := range r.Interfaces {
			ifaceNames[iface] = struct{}{}
		}
	}

	groups := make(map[precedenceGroupKey][]IndexedRule, len(ifaceNames)*len(bucketDirections))

	for iface := range ifaceNames {
		for _, bucket := range bucketDirections {
			ordered := orderedGroupRules(rules, iface, bucket)
			if len(ordered) >= minGroupSizeForOverlap {
				groups[precedenceGroupKey{iface: iface, dir: bucket}] = ordered
			}
		}
	}

	return groups
}

// orderedGroupRules builds the pf evaluation order for one (iface, bucket)
// group: every unscoped floating rule compatible with bucket, in original
// list order, followed by every rule bound to iface compatible with bucket,
// in original list order.
func orderedGroupRules(rules []common.FirewallRule, iface string, bucket common.FirewallDirection) []IndexedRule {
	var ordered []IndexedRule

	for i, r := range rules {
		if isUnscopedFloating(r) && ruleInBucket(r.Direction, bucket) {
			ordered = append(ordered, IndexedRule{Index: i, Rule: r})
		}
	}

	for i, r := range rules {
		if !isUnscopedFloating(r) && slices.Contains(r.Interfaces, iface) && ruleInBucket(r.Direction, bucket) {
			ordered = append(ordered, IndexedRule{Index: i, Rule: r})
		}
	}

	return ordered
}

// isUnscopedFloating reports whether r is a floating rule with no specific
// interface binding — the class that joins every interface group ahead of
// interface-bound rules.
func isUnscopedFloating(r common.FirewallRule) bool {
	return r.Floating && len(r.Interfaces) == 0
}

// ruleInBucket reports whether a rule with direction dir participates in
// the given direction bucket: an exact match, or dir == DirectionAny, which
// participates in both buckets. An empty/unspecified direction is treated as
// inbound — OPNsense/pfSense interface-tab rules omit the <direction> element
// and pf evaluates them as `in`, so the common real-world case (no explicit
// direction) must join the "in" bucket rather than no bucket at all.
func ruleInBucket(dir, bucket common.FirewallDirection) bool {
	return effectiveDirection(dir) == bucket || dir == common.DirectionAny
}

// effectiveDirection maps an unspecified direction to the pf default (inbound)
// for grouping purposes only. It does not mutate the model — the CommonDevice
// rule keeps its original (possibly empty) Direction.
func effectiveDirection(dir common.FirewallDirection) common.FirewallDirection {
	if dir == "" {
		return common.DirectionIn
	}

	return dir
}

// sortedGroupKeys returns groups' keys in deterministic order: interface
// name ascending, then direction bucket in bucketDirections order (in
// before out).
func sortedGroupKeys(groups map[precedenceGroupKey][]IndexedRule) []precedenceGroupKey {
	ifaceSet := make(map[string]struct{}, len(groups))
	for k := range groups {
		ifaceSet[k.iface] = struct{}{}
	}

	keys := make([]precedenceGroupKey, 0, len(groups))

	for _, iface := range slices.Sorted(maps.Keys(ifaceSet)) {
		for _, bucket := range bucketDirections {
			key := precedenceGroupKey{iface: iface, dir: bucket}
			if _, ok := groups[key]; ok {
				keys = append(keys, key)
			}
		}
	}

	return keys
}

// resolveGroup resolves every candidate pair within one ordered rule group
// into its effective PrecedencePair, per pf quick/non-quick evaluation
// semantics (KTD-5). Pairs are considered in group order (i before j);
// pairs whose coverage is CoverNone or CoverIndeterminate are skipped.
func resolveGroup(key precedenceGroupKey, ordered []IndexedRule, no common.NamedObjects) []PrecedencePair {
	var pairs []PrecedencePair

	for i := range ordered {
		for j := i + 1; j < len(ordered); j++ {
			if pair, ok := resolvePair(key, ordered[i], ordered[j], no); ok {
				pairs = append(pairs, pair)
			}
		}
	}

	return pairs
}

// resolvePair resolves one candidate pair — earlier and later by group
// position — into its effective PrecedencePair, or reports ok=false when
// the pair's coverage is CoverNone or CoverIndeterminate.
//
// The decision is keyed solely off earlier's own Quick flag (ADR-0005):
// quick earlier rule ⇒ first-match, earlier wins outright when it covers
// later, so later is the loser — the coverage question is "does earlier
// cover later". Non-quick earlier rule ⇒ last-match, whatever later covers
// of earlier wins the overlap, so earlier is the loser — the coverage
// question flips to "does later cover earlier". later's own Quick flag
// plays no part in this decision: a non-quick earlier rule never stops
// evaluation, so any later matching rule — quick or not — supersedes it for
// the overlapping traffic.
func resolvePair(key precedenceGroupKey, earlier, later IndexedRule, no common.NamedObjects) (PrecedencePair, bool) {
	var (
		cov           Coverage
		aliasBlocked  bool
		winner, loser IndexedRule
	)

	if earlier.Rule.Quick {
		cov, aliasBlocked = coverage(earlier.Rule, later.Rule, no)
		winner, loser = earlier, later
	} else {
		cov, aliasBlocked = coverage(later.Rule, earlier.Rule, no)
		winner, loser = later, earlier
	}

	if cov != CoverFull && cov != CoverPartial {
		return PrecedencePair{}, false
	}

	return PrecedencePair{
		Interface:    key.iface,
		Direction:    key.dir,
		Winner:       winner,
		Loser:        loser,
		Extent:       cov,
		AliasBlocked: aliasBlocked,
	}, true
}
