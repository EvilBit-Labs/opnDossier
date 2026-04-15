package analysis

import (
	"hash/fnv"
	"slices"
	"strconv"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// RulesEquivalent checks if two firewall rules are functionally equivalent.
// Interface order is normalized before comparison so that ["wan","lan"] and
// ["lan","wan"] are treated as equivalent. Metadata fields (Description, etc.)
// are intentionally excluded from comparison. A disabled rule is not equivalent
// to an enabled rule.
func RulesEquivalent(a, b common.FirewallRule) bool {
	if a.Disabled != b.Disabled {
		return false
	}

	ifaces1 := slices.Clone(a.Interfaces)
	ifaces2 := slices.Clone(b.Interfaces)
	slices.Sort(ifaces1)
	slices.Sort(ifaces2)

	if a.Type != b.Type ||
		a.IPProtocol != b.IPProtocol ||
		!slices.Equal(ifaces1, ifaces2) {
		return false
	}

	if a.StateType != b.StateType ||
		a.Direction != b.Direction ||
		a.Protocol != b.Protocol ||
		a.Quick != b.Quick {
		return false
	}

	if a.Source.Address != b.Source.Address ||
		a.Source.Port != b.Source.Port ||
		a.Source.Negated != b.Source.Negated {
		return false
	}

	return a.Destination.Address == b.Destination.Address &&
		a.Destination.Port == b.Destination.Port &&
		a.Destination.Negated == b.Destination.Negated
}

// hashRule computes an FNV-64a hash over the same fields that RulesEquivalent
// compares. Rules for which RulesEquivalent returns true must produce the same
// hash; the converse need not hold (collisions are tolerated and resolved by
// callers via a RulesEquivalent fallback). Interface order is normalized so
// ["wan","lan"] and ["lan","wan"] hash identically.
//
// MAINTENANCE INVARIANT: if RulesEquivalent is extended with a new field,
// hashRule MUST hash that field — otherwise duplicate detection silently
// misses the new field and produces false negatives.
func hashRule(r common.FirewallRule) uint64 {
	h := fnv.New64a()

	writeField := func(s string) {
		_, _ = h.Write([]byte(s))
		_, _ = h.Write([]byte{0})
	}

	writeField(strconv.FormatBool(r.Disabled))
	writeField(string(r.Type))
	writeField(string(r.IPProtocol))

	ifaces := slices.Clone(r.Interfaces)
	slices.Sort(ifaces)
	for _, iface := range ifaces {
		writeField(iface)
	}
	writeField("")

	writeField(r.StateType)
	writeField(string(r.Direction))
	writeField(r.Protocol)
	writeField(strconv.FormatBool(r.Quick))

	writeField(r.Source.Address)
	writeField(r.Source.Port)
	writeField(strconv.FormatBool(r.Source.Negated))

	writeField(r.Destination.Address)
	writeField(r.Destination.Port)
	writeField(strconv.FormatBool(r.Destination.Negated))

	return h.Sum64()
}
