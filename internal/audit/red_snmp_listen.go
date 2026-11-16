package audit

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// serviceNameSNMP is the exposedService name of the SNMP agent.
const serviceNameSNMP = "snmp"

// loopbackAddresses are what a port forward's target is checked against, so
// that a network or range spanning loopback counts as well as one inside it.
var loopbackAddresses = []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()}

// applySNMPListen marks the SNMP agent in services as Local when the
// os-net-snmp plugin binds it only to loopback and no port forward can
// redirect its traffic to loopback. Such an agent answers no other host, so it
// is Local whatever reachability services already gives it, and
// serviceExposures calls this last. pf rewrites a forward's destination before
// the packet is delivered, so a forward of UDP port 161 to loopback reaches an
// agent bound there, and the agent then keeps the reachability services gives
// it (forwardsToLoopback). A list holding any other address, or an empty list,
// leaves the agent as it is too, judged as the other services are: an
// os-net-snmp agent with no listen address binds every IPv4 address and the
// IPv6 loopback, and for an <snmpd> agent no bind address is read.
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
// traffic can redirect UDP to port 161 (forwardCanReachSNMPPort) and has a
// target holding a loopback address (targetHoldsLoopback). A forward to
// loopback that cannot, such as a DNS redirect to port 53 or a transparent
// proxy's TCP forward, leaves the agent Local. The forward's interface is not
// read, nor whether pf runs (with <system><disablefilter> set, pf is off and no
// forward redirects anything), nor whether the target's address family is one
// the agent listens on, so a forward to ::1 counts for an agent bound only to
// 127.0.0.1. Each can over-report, the safe direction.
func forwardsToLoopback(device *common.CommonDevice) bool {
	return slices.ContainsFunc(device.NAT.InboundRules, func(nat common.InboundNATRule) bool {
		return !nat.Disabled && !nat.NoRDR && forwardCanReachSNMPPort(nat) &&
			targetHoldsLoopback(nat.InternalIP, device)
	})
}

// forwardCanReachSNMPPort reports whether a port forward can redirect UDP to
// port 161, where the os-net-snmp template binds each agent address. OPNsense
// reads a forward's ports only for tcp, udp and tcp/udp, so a forward with no
// protocol or any, which matches every protocol, redirects every port and keeps
// it, and one for another named protocol, tcp among them, redirects no UDP.
// Without a local port pf keeps the destination port, which must then permit
// 161. With one, pf rewrites each port the forward matches to the local port
// when the destination port is a single number or any port, so the local port
// decides; another destination port, such as a range, is read as reaching the
// agent. A port alias, or another port analysis.RulePortPermits cannot read,
// is read as permitting 161.
func forwardCanReachSNMPPort(nat common.InboundNATRule) bool {
	if analysis.IsAnyProtocol(nat.Protocol) {
		return true
	}

	if proto := strings.ToLower(strings.TrimSpace(nat.Protocol)); proto != "udp" && proto != "tcp/udp" {
		return false
	}

	if nat.LocalPort == "" {
		return analysis.RulePortPermits(nat.Destination.Port, portSNMP)
	}

	destination := strings.TrimSpace(nat.Destination.Port)
	if _, err := strconv.Atoi(destination); err != nil && !analysis.IsAnyPort(destination) {
		return true
	}

	return analysis.RulePortPermits(nat.LocalPort, portSNMP)
}

// targetHoldsLoopback reports whether a port forward's target is, or spans, a
// loopback address. The target (self), This Firewall on the forward page,
// counts: pf reads it as every address of every interface, lo0's among them.
// OPNsense accepts an alias as the target, and pf then
// redirects to the addresses it holds, so a target an alias defines counts when
// a member of the alias, or of an alias it names, holds one
// (aliasHoldsFirewallAddress, which also counts a member naming a table the
// config does not store). OPNsense also accepts an interface: its key for the
// interface's network, and for wan, lan and optN the key and "ip" for its
// address. A target that is an interface's key, or its key and "ip", counts
// only when that interface's own address is a loopback address, as on lo0, so
// a forward to lanip or to the lan net leaves the agent Local. A name no alias
// or interface defines counts when it has the shape of an alias name, since it
// can name a table the config does not store. A hostname with a domain tells
// nothing and does not count.
func targetHoldsLoopback(target string, device *common.CommonDevice) bool {
	if target == "(self)" {
		return true
	}

	if _, defined := device.NamedObjects[target]; defined {
		return aliasHoldsFirewallAddress(device.NamedObjects, target, loopbackAddresses)
	}

	for _, iface := range device.Interfaces {
		if target == iface.Name || target == iface.Name+"ip" {
			return isLoopbackEntry(iface.IPAddress) || isLoopbackEntry(iface.IPv6Address)
		}
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
