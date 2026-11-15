package audit

import (
	"net/netip"
	"slices"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// serviceNameSNMP is the exposedService name of the SNMP agent.
const serviceNameSNMP = "snmp"

// loopbackAddresses are what a port forward's target is checked against, so
// that a network or range spanning loopback counts as well as one inside it.
var loopbackAddresses = []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()}

// applySNMPListen marks the SNMP agent in services as Local when the
// os-net-snmp plugin binds it only to loopback and no port forward redirects
// traffic to loopback. Such an agent answers no other host, so it is Local
// whatever reachability services already gives it, and serviceExposures calls
// this last. pf rewrites a forward's destination before the packet is
// delivered, so a forward to loopback reaches an agent bound there, and the
// agent then keeps the reachability services gives it (forwardsToLoopback). A
// list holding any other address, or an empty list, leaves the agent as it is
// too, judged as the other services are: an os-net-snmp agent with no listen
// address binds every IPv4 address and the IPv6 loopback, and for an <snmpd>
// agent no bind address is read.
func applySNMPListen(device *common.CommonDevice, services []exposedService) {
	if !listensOnLoopbackOnly(device.SNMP.ListenAddresses) || forwardsToLoopback(device) {
		return
	}

	for i := range services {
		if services[i].name == serviceNameSNMP {
			services[i].reachability = analysis.Local
		}
	}
}

// forwardsToLoopback reports whether an enabled port forward that redirects
// traffic has a target holding a loopback address (targetHoldsLoopback). The
// forward's interface, protocol and ports are not read, so a forward to
// loopback for another service, such as a transparent proxy, also leaves the
// SNMP agent as applySNMPListen found it. Nor is it read whether pf runs: with
// <system><disablefilter> set, pf is off and no forward redirects anything.
// Both can over-report, the safe direction.
func forwardsToLoopback(device *common.CommonDevice) bool {
	return slices.ContainsFunc(device.NAT.InboundRules, func(nat common.InboundNATRule) bool {
		return !nat.Disabled && !nat.NoRDR && targetHoldsLoopback(nat.InternalIP, device.NamedObjects)
	})
}

// targetHoldsLoopback reports whether a port forward's target is, or spans, a
// loopback address. OPNsense accepts an alias as the target, and pf then
// redirects to the addresses it holds, so a target an alias defines counts when
// a member of the alias, or of an alias it names, holds one
// (aliasHoldsFirewallAddress, which also counts a member naming a table the
// config does not store). A name no alias defines counts too when it has the
// shape of an alias name, since it can name such a table itself. A hostname
// with a domain tells nothing and does not count.
func targetHoldsLoopback(target string, objects common.NamedObjects) bool {
	if _, defined := objects[target]; defined {
		return aliasHoldsFirewallAddress(objects, target, loopbackAddresses)
	}

	return holdsFirewallAddress(target, loopbackAddresses) || aliasNamePattern.MatchString(target)
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
