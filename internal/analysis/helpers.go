package analysis

import common "github.com/EvilBit-Labs/opnDossier/pkg/model"

// FindInterface returns the interface with the given name, or nil if not found.
func FindInterface(interfaces []common.Interface, name string) *common.Interface {
	for i := range interfaces {
		if interfaces[i].Name == name {
			return &interfaces[i]
		}
	}
	return nil
}

// FindDHCPScope returns the DHCP scope for the given interface, preferring an
// enabled one, or nil if not found.
func FindDHCPScope(scopes []common.DHCPScope, ifaceName string) *common.DHCPScope {
	// More than one server can hold a scope for the interface, such as a
	// disabled ISC scope left beside the dnsmasq one that serves it. The
	// enabled scope is the one that describes the interface.
	var first *common.DHCPScope
	for i := range scopes {
		if scopes[i].Interface != ifaceName {
			continue
		}
		if scopes[i].Enabled {
			return &scopes[i]
		}
		if first == nil {
			first = &scopes[i]
		}
	}
	return first
}

// IndexedRule pairs a firewall rule with its original index in the flat rule list.
type IndexedRule struct {
	// Index is the position of the rule in the original flat rule list.
	Index int
	// Rule is the firewall rule at this position.
	Rule common.FirewallRule
}
