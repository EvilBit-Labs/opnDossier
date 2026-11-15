package audit

import (
	"net/netip"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// serviceNameSNMP is the exposedService name of the SNMP agent.
const serviceNameSNMP = "snmp"

// applySNMPListen marks the SNMP agent in services as Local when the
// os-net-snmp plugin binds it only to loopback. Such an agent answers no other
// host, so it is Local whatever reachability services already gives it, and
// serviceExposures calls this last. A list holding any other address, or an
// empty list, leaves the agent as it is, judged as the other services are: an
// os-net-snmp agent with no listen address binds every IPv4 address and the
// IPv6 loopback, and for an <snmpd> agent no bind address is read.
func applySNMPListen(device *common.CommonDevice, services []exposedService) {
	if !listensOnLoopbackOnly(device.SNMP.ListenAddresses) {
		return
	}

	for i := range services {
		if services[i].name == serviceNameSNMP {
			services[i].reachability = analysis.Local
		}
	}
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
