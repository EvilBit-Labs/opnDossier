package analysis

import (
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// Wildcard CIDR literals. A rule written with either of these matches every
// host in its family, exactly as "any" does, and operators and automation both
// write them this way.
const (
	wildcardCIDRv4 = "0.0.0.0/0"
	wildcardCIDRv6 = "::/0"
)

// IsAnyAddress reports whether an endpoint address matches every host.
//
// Four spellings mean the same thing in a pf ruleset, and all four reach the
// common model:
//
//   - "any", which the converters normalize <any/> and <network>any</network> to
//   - any casing of it, since the vendor XML is not case-normalized
//   - the empty string, produced by an omitted or empty <source>/<destination>
//     element; a rule with no source matches every source
//   - the wildcard CIDRs 0.0.0.0/0 and ::/0
//
// Comparing against the "any" literal alone classifies the other three as a
// specific host, so a pass rule matching all traffic reads as scoped and the
// checks that exist to catch exactly that rule report compliant.
//
// This tests an address spelling only. Callers holding a common.RuleEndpoint
// want IsAnyEndpoint, which also accounts for an inverted match. It is deliberately not used by the overlap engine in
// overlap.go, which does real CIDR containment: there, treating 0.0.0.0/0 as an
// unconditional wildcard would make it cover IPv6 targets it cannot match.
func IsAnyAddress(addr string) bool {
	trimmed := strings.TrimSpace(addr)

	return trimmed == "" ||
		strings.EqualFold(trimmed, constants.NetworkAny) ||
		trimmed == wildcardCIDRv4 ||
		trimmed == wildcardCIDRv6
}

// IsAnyEndpoint reports whether an endpoint matches every host.
//
// This is the endpoint-level predicate, and it is the one audit checks want.
// IsAnyAddress answers only whether an address string is a wildcard spelling;
// an endpoint additionally carries Negated, and a negated endpoint matches the
// complement of what its address names. A negated wildcard therefore matches
// nothing at all, so classifying it by address alone turns a rule that passes
// no traffic into a highest-severity wide-open finding.
//
// Negated inverts the address only. The vendor schema carries <not> beside the
// address fields and pfSense presents it as an invert-match toggle on the
// address, so port and protocol predicates are unaffected by it.
//
// overlap.go and rules.go already account for Negated; routing the checks
// through this keeps the audit path consistent with them rather than letting
// the two disagree about what a rule means.
//
// A negated address list is the exception. OPNsense negates each entry of a
// list on its own and matches each result, so the list matches every address
// outside the entries' overlap, which is every address when they do not
// overlap (GOTCHAS 3.8). It counts as any here, where reading it too broadly
// is the safe error; the overlap engine reads Negated and does not rely on it.
func IsAnyEndpoint(ep common.RuleEndpoint) bool {
	if ep.Negated {
		return strings.Contains(ep.Address, ",")
	}

	return IsAnyAddress(ep.Address)
}

// IsAnyPort reports whether an endpoint port specification matches every port.
// An empty port is the common shape; "any" appears in hand-written and
// API-created rules.
func IsAnyPort(port string) bool {
	trimmed := strings.TrimSpace(port)

	return trimmed == "" || strings.EqualFold(trimmed, constants.NetworkAny)
}

// IsAnyProtocol reports whether a rule's protocol field matches every layer-4
// protocol. An empty protocol is the common shape; "any" appears in
// hand-written and API-created rules.
func IsAnyProtocol(proto string) bool {
	trimmed := strings.TrimSpace(proto)

	return trimmed == "" || strings.EqualFold(trimmed, constants.NetworkAny)
}

// IsWideOpenPassRule reports whether rule is an enabled pass rule whose source,
// destination, port and protocol all match everything. Such a rule passes all
// traffic on the interfaces it applies to.
func IsWideOpenPassRule(rule common.FirewallRule) bool {
	if rule.Disabled || rule.Type != common.RuleTypePass {
		return false
	}

	return IsAnyEndpoint(rule.Source) &&
		IsAnyEndpoint(rule.Destination) &&
		IsAnyPort(rule.Destination.Port) &&
		IsAnyProtocol(rule.Protocol)
}
