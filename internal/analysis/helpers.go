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

// FindDHCPScope returns the DHCP scope for the given interface, or nil if not found.
func FindDHCPScope(scopes []common.DHCPScope, ifaceName string) *common.DHCPScope {
	for i := range scopes {
		if scopes[i].Interface == ifaceName {
			return &scopes[i]
		}
	}
	return nil
}

// IndexedRule pairs a firewall rule with its original index in the flat rule list.
type IndexedRule struct {
	// Index is the position of the rule in the original flat rule list.
	Index int
	// Rule is the firewall rule at this position.
	Rule common.FirewallRule
}
