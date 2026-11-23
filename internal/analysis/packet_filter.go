package analysis

import (
	"slices"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// PacketFilterDisabledComponent is the Component of the finding raised when
// "Disable all packet filtering" is set. Compliance plugins give their own
// findings for the same setting a different component, so the de-duplication
// against plugin findings never hides this one.
const PacketFilterDisabledComponent = "system.disablefilter"

// packetFilterDisabledFinding describes a firewall with pf turned off. Both
// vendors run pfctl -d and return before any ruleset loads, so the rules, the
// block options and NAT in the config describe nothing the firewall does.
func packetFilterDisabledFinding() common.SecurityFinding {
	return common.SecurityFinding{
		Component: PacketFilterDisabledComponent,
		Issue:     "Packet Filtering Disabled",
		Severity:  common.SeverityCritical,
		Description: "All packet filtering is disabled, so the firewall loads no rule and performs no NAT: " +
			"every service it runs is reachable from every interface, the WAN included, and the firewall " +
			"rules, block options and port forwards in this configuration are not enforced",
		Recommendation: "Re-enable packet filtering by clearing \"Disable all packet filtering\" " +
			"(OPNsense: Firewall > Settings > Advanced; pfSense: System > Advanced > Firewall & NAT)",
	}
}

// packetFilterFeatures are the SecurityFeatures entries that pf enforces. With
// packet filtering disabled the interface options still read as set, but
// nothing blocks those networks.
var packetFilterFeatures = []string{"Block Private Networks", "Block Bogon Networks"}

// dropPacketFilterFeatures removes the features pf enforces when packet
// filtering is disabled, so neither the feature list nor the security score
// credits a block the firewall does not apply. "NAT Reflection Disabled" stays:
// with NAT off there is no reflection either.
func dropPacketFilterFeatures(stats *common.Statistics, cfg *common.CommonDevice) {
	if !cfg.System.PacketFilterDisabled {
		return
	}

	stats.SecurityFeatures = slices.DeleteFunc(stats.SecurityFeatures, func(feature string) bool {
		return slices.Contains(packetFilterFeatures, feature)
	})
}
