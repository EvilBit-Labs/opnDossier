package analysis

import (
	"slices"

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
