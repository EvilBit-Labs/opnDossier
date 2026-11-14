package audit

import (
	"net/netip"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// snmpReachability is serviceReachability for the SNMP agent, which the
// os-net-snmp plugin can bind to chosen addresses. An agent whose every listen
// address is a loopback address answers no other host, so it is Local whatever
// the firewall rules pass. Any other listen address, and an empty list, which
// binds every IPv4 address, is judged by the rules as the other services are.
func snmpReachability(device *common.CommonDevice) analysis.Reachability {
	if listensOnLoopbackOnly(device.SNMP.ListenAddresses) {
		return analysis.Local
	}

	return serviceReachability(device, portSNMP)
}

// listensOnLoopbackOnly reports whether addresses is non-empty and every entry
// is a loopback address, or a network inside the loopback range. An entry that
// does not parse counts as reachable, so it never hides an exposure.
func listensOnLoopbackOnly(addresses []string) bool {
	if len(addresses) == 0 {
		return false
	}

	for _, entry := range addresses {
		if !isLoopbackEntry(entry) {
			return false
		}
	}

	return true
}

func isLoopbackEntry(entry string) bool {
	if addr, err := netip.ParseAddr(entry); err == nil {
		return addr.Unmap().IsLoopback()
	}

	prefix, err := netip.ParsePrefix(entry)
	if err != nil {
		return false
	}

	network := prefix.Masked().Addr().Unmap()
	if network.Is4() {
		return network.IsLoopback() && prefix.Bits() >= 8
	}

	return network.IsLoopback() && prefix.Bits() == 128
}
