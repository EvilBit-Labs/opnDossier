package analysis

import common "github.com/EvilBit-Labs/opnDossier/pkg/model"

// interfaceTypeGroup is the <type> OPNsense gives the entry it registers under
// <interfaces> for an interface group.
const interfaceTypeGroup = "group"

// IsNetworkZone reports whether iface is an enabled interface that carries a
// network of its own, and so can stand for a security zone.
//
// OPNsense writes pseudo-interfaces into <interfaces> on every save
// (plugins_interfaces in plugins.inc): lo0 always (loopback.inc), one entry
// per interface group (pf.inc), the OpenVPN and WireGuard groups while those
// services are enabled, and enc0 while IPsec is. Each is enabled and marked
// virtual, and OPNsense itself leaves virtual entries out wherever it wants
// the real interfaces (legacy_config_get_interfaces(['virtual' => false]) in
// interfaces.inc and console.inc). Counted as zones, lo0 alone made a
// firewall with only a WAN look segmented. A group entry is also left out by
// its type, in case one was written without the virtual flag: it stands for
// its members, which are counted on their own.
func IsNetworkZone(iface common.Interface) bool {
	return iface.Enabled && !iface.Virtual && iface.Type != interfaceTypeGroup
}

// CountNetworkZones returns how many of cfg's interfaces are network zones
// (see IsNetworkZone).
func CountNetworkZones(cfg *common.CommonDevice) int {
	if cfg == nil {
		return 0
	}

	var n int

	for _, iface := range cfg.Interfaces {
		if IsNetworkZone(iface) {
			n++
		}
	}

	return n
}
