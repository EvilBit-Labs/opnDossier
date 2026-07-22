package analysis

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// maxResolvedMembers bounds how many resolved alias members the containment
// predicate will expand for a single endpoint. Above this, the endpoint is
// treated as opaque (aliasBlocked) so the O(n*m) address/port containment
// cross product cannot be driven into a DoS by an attacker-supplied config
// that defines pathologically large aliases. Set far above any realistic
// firewall alias.
const maxResolvedMembers = 4096

// Coverage classifies how completely an earlier firewall rule's match set
// covers a later rule's match set, on a single dimension or for a whole
// rule pair. See coverage for the combining rules across dimensions.
type Coverage int

// Recognized Coverage values.
const (
	// CoverNone indicates the earlier rule does not overlap the later rule
	// at all on this dimension (or, once combined, on the whole rule).
	CoverNone Coverage = iota
	// CoverPartial indicates the earlier rule overlaps some, but not all,
	// of the later rule's match set.
	CoverPartial
	// CoverFull indicates the earlier rule's match set fully contains the
	// later rule's match set.
	CoverFull
	// CoverIndeterminate indicates negation makes the overlap relationship
	// impossible to determine with confidence; callers must not report a
	// finding for this result (R10).
	CoverIndeterminate
)

// String returns a human-readable name for c, used in test failure output
// and any future debug logging.
func (c Coverage) String() string {
	switch c {
	case CoverNone:
		return "CoverNone"
	case CoverPartial:
		return "CoverPartial"
	case CoverFull:
		return "CoverFull"
	case CoverIndeterminate:
		return "CoverIndeterminate"
	default:
		return "CoverUnknown"
	}
}

// coverage reports how completely earlier's match set covers later's match
// set, and whether an unresolvable or dynamic named-object reference
// prevented a full member-set comparison on any dimension (aliasBlocked).
//
// aliasBlocked is a distinct signal from CoverNone: a genuinely
// non-overlapping pair and a pair whose overlap could not be determined
// because an alias was opaque both produce CoverNone on their own, but only
// the latter sets aliasBlocked. Callers that want to advise on a possible
// Security-class shadow that an unresolvable alias masked (R8) must inspect
// aliasBlocked rather than inferring it from CoverNone alone.
//
// Dimensions evaluated: IP family (gate, R11), source address, source port,
// destination address, destination port, and layer-4 protocol. Full
// requires every dimension fully covered; Partial requires at least one
// dimension strictly narrower with no dimension at CoverNone; any dimension
// at CoverNone makes the whole pair CoverNone. Negation (R10) downgrades an
// otherwise-Full or -Partial result to CoverIndeterminate: any apparent
// containment computed against a negated endpoint's literal value is
// untrustworthy (a negated "10.0.0.0/8" matches everything OUTSIDE that
// range, not inside it), so even an exact-literal match that resolves to
// CoverFull must not be reported as a confirmed shadow.
func coverage(earlier, later common.FirewallRule, no common.NamedObjects) (Coverage, bool) {
	if !familiesCompatible(earlier.IPProtocol, later.IPProtocol) {
		return CoverNone, false
	}

	srcAddrCov, srcAddrBlocked := addressCoverage(earlier.Source, later.Source, no)
	dstAddrCov, dstAddrBlocked := addressCoverage(earlier.Destination, later.Destination, no)
	srcPortCov, srcPortBlocked := portCoverage(earlier.Source, later.Source, no)
	dstPortCov, dstPortBlocked := portCoverage(earlier.Destination, later.Destination, no)
	protoCov := protocolCoverage(earlier.Protocol, later.Protocol)

	aliasBlocked := srcAddrBlocked || dstAddrBlocked || srcPortBlocked || dstPortBlocked

	raw := combineDimensions(srcAddrCov, dstAddrCov, srcPortCov, dstPortCov, protoCov)

	negated := earlier.Source.Negated || earlier.Destination.Negated ||
		later.Source.Negated || later.Destination.Negated
	if negated && (raw == CoverPartial || raw == CoverFull) {
		return CoverIndeterminate, aliasBlocked
	}

	return raw, aliasBlocked
}

// combineDimensions folds per-dimension Coverage results into a single
// whole-rule Coverage: any CoverNone dimension makes the whole rule
// CoverNone; otherwise any CoverPartial dimension makes it CoverPartial;
// otherwise (every dimension CoverFull) the whole rule is CoverFull.
func combineDimensions(dims ...Coverage) Coverage {
	hasPartial := false

	for _, d := range dims {
		if d == CoverNone {
			return CoverNone
		}

		if d == CoverPartial {
			hasPartial = true
		}
	}

	if hasPartial {
		return CoverPartial
	}

	return CoverFull
}

// familiesCompatible implements the R11 family gate: an empty/unset
// IPProtocol is a wildcard matching both address families (the common case
// for untyped rules), and inet46 (pfSense dual-stack) covers both families
// too. Only two explicit, differing families (inet vs inet6) are
// incompatible.
func familiesCompatible(a, b common.IPProtocol) bool {
	if a == "" || b == "" {
		return true
	}

	if a == common.IPProtocolInet46 || b == common.IPProtocolInet46 {
		return true
	}

	return a == b
}

// protocolCoverage classifies containment of the layer-4 protocol
// dimension. any/empty covers every specific protocol; matching specific
// protocols are Full; mismatched specific protocols are CoverNone; a
// specific earlier protocol against an any/empty later protocol is
// CoverPartial (earlier only covers the later rule's traffic for that one
// protocol, not the others the later rule also matches).
func protocolCoverage(earlierProto, laterProto string) Coverage {
	ep := normalizeProtocol(earlierProto)
	lp := normalizeProtocol(laterProto)

	if ep == "" {
		return CoverFull
	}

	if lp == "" {
		return CoverPartial
	}

	if strings.EqualFold(ep, lp) {
		return CoverFull
	}

	return CoverNone
}

// normalizeProtocol maps the any/empty wildcard spellings to "" so callers
// only need to check for emptiness.
func normalizeProtocol(p string) string {
	if strings.EqualFold(p, constants.NetworkAny) {
		return ""
	}

	return p
}

// aggregateCoverage classifies containment of a target set within a
// covering set: relate compares one covering element against one target
// element. The result is CoverFull when every target element is fully
// covered by some covering element, CoverPartial when at least one target
// element overlaps (fully or partially) some covering element but not every
// target element is fully covered, and CoverNone when nothing overlaps.
func aggregateCoverage[T any](covering, target []T, relate func(covering, target T) Coverage) Coverage {
	allFull := true
	anyOverlap := false

	for _, t := range target {
		best := CoverNone

		for _, c := range covering {
			best = max(best, relate(c, t))
			if best == CoverFull {
				break
			}
		}

		if best != CoverFull {
			allFull = false
		}

		if best != CoverNone {
			anyOverlap = true
		}
	}

	switch {
	case allFull:
		return CoverFull
	case anyOverlap:
		return CoverPartial
	default:
		return CoverNone
	}
}

// addressCoverage classifies containment of one endpoint pair's address
// dimension, resolving named-object references to their member sets first.
func addressCoverage(earlier, later common.RuleEndpoint, no common.NamedObjects) (Coverage, bool) {
	earlierVals, earlierBlocked := resolveAddressValues(earlier, no)
	laterVals, laterBlocked := resolveAddressValues(later, no)

	if earlierBlocked || laterBlocked {
		return exactSingletonCoverage(earlierVals, laterVals), true
	}

	if isAnyAddressSet(earlierVals) {
		return CoverFull, false
	}

	return aggregateCoverage(earlierVals, laterVals, addressRelation), false
}

// resolveAddressValues expands an endpoint's address into its full set of
// concrete member values (the first return). A literal (non-alias) address
// resolves to itself. An alias endpoint resolves via NamedObjects.Resolve;
// when resolution fails (unresolvable name, dynamic/opaque type, or a nil
// registry), the endpoint falls back to its own literal string value and
// the second return is true (R8: unresolvable aliases match only on exact
// equality, never expanded).
func resolveAddressValues(ep common.RuleEndpoint, no common.NamedObjects) ([]string, bool) {
	return resolveEndpointValues(ep.AddressRef, ep.Address, no)
}

// resolveEndpointValues expands ref/literal into their full set of concrete
// member values (the first return), the shared logic behind
// resolveAddressValues and resolvePortValues. A literal (nil ref) resolves
// to itself. A named-object reference resolves via NamedObjects.Resolve;
// when resolution fails (unresolvable name, dynamic/opaque type, or a nil
// registry), it falls back to the literal value and the second return is
// true (R8: unresolvable aliases match only on exact equality, never
// expanded).
func resolveEndpointValues(ref *common.ObjectRef, literal string, no common.NamedObjects) ([]string, bool) {
	if ref == nil {
		return []string{literal}, false
	}

	members, resolved := no.Resolve(ref.Name)
	// An alias that resolves to an implausibly large member set is treated as
	// opaque (aliasBlocked) rather than expanded: the O(n*m) containment cross
	// product below would otherwise be a DoS vector on an attacker-supplied
	// config that defines two huge aliases. The cap is far above any real
	// alias and biases safe — an unresolved Security overlap still surfaces as
	// the R8 advisory rather than being silently dropped.
	if resolved && len(members) > 0 && len(members) <= maxResolvedMembers {
		return members, false
	}

	return []string{literal}, true
}

// isAnyAddressSet reports whether vals represents the "any" address
// wildcard: a single empty or "any" (case-insensitive) value.
func isAnyAddressSet(vals []string) bool {
	return len(vals) == 1 && (vals[0] == "" || strings.EqualFold(vals[0], constants.NetworkAny))
}

// addressRelation classifies the relationship between one covering address
// value and one target address value: CoverFull when covering fully
// contains target, CoverPartial when they merely intersect (covering is a
// proper subset of target's range), CoverNone otherwise. any/empty covering
// matches everything. Values that are not literal IP addresses or CIDRs
// (e.g. hostnames) fall back to exact string equality.
func addressRelation(covering, target string) Coverage {
	if covering == "" || strings.EqualFold(covering, constants.NetworkAny) {
		return CoverFull
	}

	if covering == target {
		return CoverFull
	}

	cp, cErr := parsePrefixOrAddr(covering)
	tp, tErr := parsePrefixOrAddr(target)

	if cErr != nil || tErr != nil {
		return CoverNone
	}

	if cp.Addr().Is4() != tp.Addr().Is4() {
		return CoverNone
	}

	if cp.Bits() <= tp.Bits() && cp.Contains(tp.Addr()) {
		return CoverFull
	}

	if tp.Contains(cp.Addr()) {
		return CoverPartial
	}

	return CoverNone
}

// parsePrefixOrAddr parses s as a CIDR prefix, or — if s has no "/" — as a
// single host address represented as a maximally-specific prefix (a /32 for
// IPv4, a /128 for IPv6).
func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}

	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}

	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// portRange is an inclusive, normalized port interval ([lo, hi], both
// 0-65535, lo <= hi). A single port is represented as lo == hi.
type portRange struct {
	lo, hi int
}

// portCoverage classifies containment of one endpoint pair's port
// dimension, resolving named-object references to their member sets first.
func portCoverage(earlier, later common.RuleEndpoint, no common.NamedObjects) (Coverage, bool) {
	earlierVals, earlierBlocked := resolvePortValues(earlier, no)
	laterVals, laterBlocked := resolvePortValues(later, no)

	if earlierBlocked || laterBlocked {
		return exactSingletonCoverage(earlierVals, laterVals), true
	}

	earlierIntervals, earlierAny, earlierOK := parsePortMembers(earlierVals)
	laterIntervals, laterAny, laterOK := parsePortMembers(laterVals)

	if !earlierOK || !laterOK {
		// Unparseable port specs (neither a recognized number, range, nor
		// list) fall back to exact-string equality rather than failing
		// closed on the whole predicate.
		return exactSingletonCoverage(earlierVals, laterVals), false
	}

	if earlierAny {
		return CoverFull, false
	}

	if laterAny {
		return CoverPartial, false
	}

	merged := mergeIntervals(earlierIntervals)

	return aggregateCoverage(merged, laterIntervals, portRangeRelation), false
}

// resolvePortValues expands an endpoint's port spec into its full set of
// concrete member values, mirroring resolveAddressValues for the Port/PortRef
// pair.
func resolvePortValues(ep common.RuleEndpoint, no common.NamedObjects) ([]string, bool) {
	return resolveEndpointValues(ep.PortRef, ep.Port, no)
}

// exactSingletonCoverage compares two single-value sets for exact string
// equality, the fallback comparison used whenever alias resolution failed or
// a value could not be parsed into a richer representation. Anything other
// than two singleton sets with identical values is CoverNone: a resolved
// multi-member set on one side compared against an unresolved singleton on
// the other has no reliable containment relationship to claim, so this
// under-reports rather than guessing (R8).
func exactSingletonCoverage(earlierVals, laterVals []string) Coverage {
	if len(earlierVals) == 1 && len(laterVals) == 1 && earlierVals[0] == laterVals[0] {
		return CoverFull
	}

	return CoverNone
}

// parsePortMembers parses every member value (each a single port, a
// "lo-hi" range, or a comma-separated list of either) into a merged set of
// normalized intervals (the first return). The second return is true if any
// member is the any/empty wildcard, in which case the intervals are not
// meaningful. The third return is false if any member could not be parsed
// at all.
func parsePortMembers(vals []string) ([]portRange, bool, bool) {
	var all []portRange

	for _, v := range vals {
		sub, subAny, subOK := parsePortSpec(v)
		if !subOK {
			return nil, false, false
		}

		if subAny {
			return nil, true, true
		}

		all = append(all, sub...)
	}

	return mergeIntervals(all), false, true
}

// parsePortSpec parses a single port specification: "" or "any" (the
// wildcard), a single port number, a "lo-hi" range, or a comma-separated
// list of the above.
func parsePortSpec(s string) ([]portRange, bool, bool) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" || strings.EqualFold(trimmed, constants.NetworkAny) {
		return nil, true, true
	}

	var ranges []portRange

	for part := range strings.SplitSeq(trimmed, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		r, ok := parsePortPart(part)
		if !ok {
			return nil, false, false
		}

		ranges = append(ranges, r)
	}

	if len(ranges) == 0 {
		return nil, false, false
	}

	return ranges, false, true
}

// parsePortPart parses one comma-list element: either "N" or "lo-hi".
func parsePortPart(part string) (portRange, bool) {
	lo, hi, isRange := strings.Cut(part, "-")
	if !isRange {
		n, err := strconv.Atoi(part)
		if err != nil {
			return portRange{}, false
		}

		return portRange{lo: n, hi: n}, true
	}

	loN, errLo := strconv.Atoi(strings.TrimSpace(lo))
	hiN, errHi := strconv.Atoi(strings.TrimSpace(hi))

	if errLo != nil || errHi != nil || loN > hiN {
		return portRange{}, false
	}

	return portRange{lo: loN, hi: hiN}, true
}

// mergeIntervals sorts ranges by lo and merges overlapping or touching
// (adjacent, no gap) intervals into their minimal covering set.
func mergeIntervals(ranges []portRange) []portRange {
	if len(ranges) == 0 {
		return nil
	}

	sorted := make([]portRange, len(ranges))
	copy(sorted, ranges)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].lo < sorted[j].lo })

	merged := []portRange{sorted[0]}

	for _, r := range sorted[1:] {
		last := &merged[len(merged)-1]
		if r.lo <= last.hi+1 {
			if r.hi > last.hi {
				last.hi = r.hi
			}

			continue
		}

		merged = append(merged, r)
	}

	return merged
}

// portRangeRelation classifies the relationship between one covering
// interval and one target interval: CoverFull when covering fully contains
// target, CoverPartial when they merely overlap, CoverNone otherwise.
// covering is assumed to come from an already-merged set, so a target
// interval is never split across two separate covering intervals.
func portRangeRelation(covering, target portRange) Coverage {
	if covering.lo <= target.lo && target.hi <= covering.hi {
		return CoverFull
	}

	if covering.lo <= target.hi && target.lo <= covering.hi {
		return CoverPartial
	}

	return CoverNone
}
