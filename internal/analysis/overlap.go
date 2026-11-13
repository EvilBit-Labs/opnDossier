package analysis

import (
	"net/netip"
	"sort"
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
// set, and whether an unresolvable or dynamic named-object reference, or a port
// value the analysis cannot read, prevented a full member-set comparison on
// any dimension (aliasBlocked).
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
func coverage(earlier, later common.FirewallRule, no common.NamedObjects) (Coverage, blockCause) {
	if !familiesCompatible(earlier.IPProtocol, later.IPProtocol) {
		return CoverNone, 0
	}

	srcAddrCov, srcAddrBlocked := addressCoverage(earlier.Source, later.Source, no)
	dstAddrCov, dstAddrBlocked := addressCoverage(earlier.Destination, later.Destination, no)
	srcPortCov, srcPortCause := portCoverage(earlier.Source, later.Source, no)
	dstPortCov, dstPortCause := portCoverage(earlier.Destination, later.Destination, no)
	protoCov := protocolCoverage(earlier.Protocol, later.Protocol)

	// proven says a CoverNone in that dimension shows the rules cannot
	// overlap. Ports read in full and single protocols are compared exactly;
	// protocolCoverage reads tcp/udp against tcp as CoverNone although the
	// two overlap, so a combined protocol proves nothing. An address
	// CoverNone is proof only when both sides are literal addresses or
	// networks: addressRelation also returns CoverNone for values it cannot
	// compare, such as an interface network like lan, (self), a hostname or
	// a negated endpoint.
	dims := []struct {
		cov    Coverage
		cause  blockCause
		proven bool
	}{
		{srcAddrCov, aliasCause(srcAddrBlocked), addressesComparable(earlier.Source, later.Source, no)},
		{dstAddrCov, aliasCause(dstAddrBlocked), addressesComparable(earlier.Destination, later.Destination, no)},
		{srcPortCov, srcPortCause, true},
		{dstPortCov, dstPortCause, true},
		{protoCov, 0, singleProtocol(earlier.Protocol) && singleProtocol(later.Protocol)},
	}

	var cause blockCause

	for _, d := range dims {
		if d.cov == CoverNone && d.cause == 0 && d.proven {
			return CoverNone, 0
		}

		cause |= d.cause
	}

	raw := combineDimensions(srcAddrCov, dstAddrCov, srcPortCov, dstPortCov, protoCov)

	negated := earlier.Source.Negated || earlier.Destination.Negated ||
		later.Source.Negated || later.Destination.Negated
	if negated && (raw == CoverPartial || raw == CoverFull) {
		return CoverIndeterminate, cause
	}

	return raw, cause
}

// addressesComparable reports whether every address both endpoints resolve
// to is a literal IP address or network and neither endpoint is negated, so
// that addressRelation's answer for the pair is exact.
func addressesComparable(a, b common.RuleEndpoint, no common.NamedObjects) bool {
	if a.Negated || b.Negated {
		return false
	}

	for _, ep := range []common.RuleEndpoint{a, b} {
		vals, blocked := resolveAddressValues(ep, no)
		if blocked {
			return false
		}

		for _, v := range vals {
			if _, err := ParsePrefixOrAddr(v); err != nil {
				return false
			}
		}
	}

	return true
}

// singleProtocol reports whether p names one protocol, not a combination
// such as tcp/udp.
func singleProtocol(p string) bool {
	return !strings.Contains(p, "/")
}

// aliasCause maps an address dimension's blocked flag to its cause.
func aliasCause(blocked bool) blockCause {
	if blocked {
		return causeAlias
	}

	return 0
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
// for untyped rules), and inet46 (dual-stack) covers both families
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

	cp, cErr := ParsePrefixOrAddr(covering)
	tp, tErr := ParsePrefixOrAddr(target)

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

// ParsePrefixOrAddr parses s as a CIDR prefix, or — if s has no "/" — as a
// single host address represented as a maximally-specific prefix (a /32 for
// IPv4, a /128 for IPv6).
func ParsePrefixOrAddr(s string) (netip.Prefix, error) {
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
// dimension, resolving port aliases to their member sets first (resolvePorts).
// The second return says why the comparison rests on a set known only in
// part, and is zero when both sets are known in full.
//
// An earlier wildcard covers anything. Otherwise, when either set is known
// only in part, the parts that could be read still prove an overlap they
// share, but never that the later set is covered in full, and no overlap
// among them proves nothing: the result is then CoverNone with the cause set,
// which callers read as unknown rather than disjoint (R8). Two endpoints that
// name the same alias or the same literal still match each other in full.
func portCoverage(earlier, later common.RuleEndpoint, no common.NamedObjects) (Coverage, blockCause) {
	earlierVals := resolvePorts(earlier, no)
	laterVals := resolvePorts(later, no)

	// A set read in full that holds no port matches no traffic: a disabled
	// alias loads as { 0 <> 65535 } (filter.inc L607-L611), and the ruleset
	// skips a rule whose port alias has no content (Rule.php). Such a rule
	// neither covers another nor is covered by one, any-port rules included.
	if earlierVals.matchesNothing() || laterVals.matchesNothing() {
		return CoverNone, 0
	}

	if earlierVals.every {
		return CoverFull, 0
	}

	cause := earlierVals.cause | laterVals.cause
	if cause != 0 {
		if sameEndpointPort(earlier, later) {
			return CoverFull, cause & causeAlias
		}

		cov := partialPortCoverage(earlierVals, laterVals)
		if cov == CoverFull && !laterVals.complete() {
			cov = CoverPartial
		}

		return cov, cause
	}

	if laterVals.every {
		return CoverPartial, 0
	}

	return aggregateCoverage(earlierVals.ranges, laterVals.ranges, portRangeRelation), 0
}

// partialPortCoverage compares what could be read of two port sets.
func partialPortCoverage(earlier, later portValues) Coverage {
	if len(earlier.ranges) == 0 {
		return CoverNone
	}

	if later.every {
		return CoverPartial
	}

	return aggregateCoverage(earlier.ranges, later.ranges, portRangeRelation)
}

// sameEndpointPort reports whether two endpoints name the same port alias, or
// hold the same literal port with no alias.
func sameEndpointPort(a, b common.RuleEndpoint) bool {
	if a.PortRef != nil || b.PortRef != nil {
		return a.PortRef != nil && b.PortRef != nil && a.PortRef.Name == b.PortRef.Name
	}

	return a.Port == b.Port
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

// parsePortSpec parses a single port specification: "" or "any" (the
// wildcard), a single port number or service name, a "lo-hi" or "lo:hi"
// range, or a comma-separated list of the above. vocab says which service
// names it may use.
func parsePortSpec(s string, vocab portVocab) ([]portRange, bool, bool) {
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

		r, ok := parsePortPart(part, vocab)
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

// parsePortPart parses one comma-list element: a port number or service name,
// or a range of two. A port alias member can write a range only as "lo:hi":
// the alias model validates it with Util::isPort, which splits on ":", and the
// ruleset loads a member only when is_port or is_portrange accepts it, and
// is_portrange splits on ":" too (filter.lib.inc filter_core_get_port_alias,
// util.inc). A rule port writes "lo-hi", and the ruleset turns every dash into
// a colon before it reads the port (FilterRuleContainer/Rule.php), so a range
// of two names such as http-https is a range there too. A service name may
// itself hold dashes, so a whole name is tried first, and then every dash in
// turn as the separator. Either bound may be a service name vocab accepts.
func parsePortPart(part string, vocab portVocab) (portRange, bool) {
	if n, ok := parsePortNumber(part, vocab); ok {
		return portRange{lo: n, hi: n}, true
	}

	if lo, hi, isRange := strings.Cut(part, ":"); isRange {
		return portBounds(lo, hi, vocab)
	}

	for i := range len(part) {
		if part[i] != '-' {
			continue
		}

		if r, ok := portBounds(part[:i], part[i+1:], vocab); ok {
			return r, true
		}
	}

	return portRange{}, false
}

// portBounds parses the two bounds of a range, which must be in order.
func portBounds(lo, hi string, vocab portVocab) (portRange, bool) {
	loN, okLo := parsePortNumber(lo, vocab)
	hiN, okHi := parsePortNumber(hi, vocab)

	if !okLo || !okHi || loN > hiN {
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
