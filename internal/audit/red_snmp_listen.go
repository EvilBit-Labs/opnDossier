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

// The OPNsense alias types for a URL table and a URL table in JSON format. The
// model has no constant for either, and the converter keeps the vendor type.
const (
	aliasTypeURLTable common.NamedObjectType = "urltable"
	// aliasTypeInternal is a table OPNsense itself fills, such as bogons.
	aliasTypeInternal common.NamedObjectType = "internal"
	aliasTypeURLJSON  common.NamedObjectType = "urljson"
)

// runtimeAliasTypes are the OPNsense alias types whose addresses the firewall
// fetches, or is given by another process, at runtime: a URL alias, a URL
// table, a URL table in JSON format, and an external alias.
var runtimeAliasTypes = []common.NamedObjectType{
	common.NamedObjectTypeURL, aliasTypeURLTable, aliasTypeURLJSON, common.NamedObjectTypeExternal,
}

// applySNMPListen marks the SNMP agent in services as Local when the
// os-net-snmp plugin binds it only to loopback and no port forward can
// redirect its traffic to loopback. Such an agent answers no other host, so it
// is Local whatever reachability services already gives it, and
// serviceExposures calls this last. pf rewrites a forward's destination before
// the packet is delivered, so a forward of UDP port 161 to loopback can reach
// an agent bound there, and the agent then keeps the reachability services
// gives it (forwardsToLoopback). A list holding any other address, or an empty list,
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
// target that is, spans or may hold a loopback address, such as a URL table
// (targetHoldsLoopback). A forward to loopback that cannot, such as a DNS
// redirect to port 53 or a transparent proxy's TCP forward, leaves the agent
// Local. The forward's interface is not read, nor whether pf runs (with
// <system><disablefilter> set, pf is off and no forward redirects anything),
// nor whether the target's address family is one the agent listens on, so a
// forward to ::1 counts for an agent bound only to 127.0.0.1. Each can
// over-report, the safe direction.
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

// targetHoldsLoopback reports whether a port forward's target is, spans or may
// hold a loopback address. It reads the target as ForwardRule.php does from
// OPNsense 26.1.2. The target (self), This Firewall on the forward page,
// counts: pf reads it as every address of every interface, lo0's among them.
// OPNsense accepts an alias other than a port alias as the target, and pf then
// redirects to the addresses it holds, so a target such an alias defines
// counts when a member of the alias, or of an alias it names, holds one
// (aliasHoldsFirewallAddress, which also counts a member naming a table the
// config does not store; a disabled alias loads empty and holds none), or when the alias, or an alias it names, gets its
// addresses at runtime, as a URL table does, and as a host alias does for a
// hostname it holds (aliasNamesRuntimeTable).
// aliasHoldsFirewallAddress alone reads such an alias as holding no address,
// which forwardsToAlias relies on. OPNsense also accepts an interface: its key
// for the interface's network, and for wan, lan and optN the key and "ip" for
// its address. A target that is an interface's key, or its key and "ip", counts
// only when that interface's own address is a loopback address, as on lo0, so a
// forward to lanip or to the lan net leaves the agent Local. OPNsense maps the
// interfaces first and then every alias but a port alias (loadAliasMap in
// Rule.php), so an alias named like an interface is read in its place. A port
// alias holds ports and no address, and is not read: one named like an
// interface leaves that interface's reading in place, and one named like no
// interface does not count, since OPNsense disables a forward to a name the map
// does not hold, if it is no address or network, as an invalid target. The key
// and "ip" is matched for every interface, so lo0ip counts beside a lo0 that
// holds loopback, although OPNsense maps that form only for wan, lan and optN
// and disables a forward to any other such name no alias defines as an invalid
// target: the wider match can only over-report. A name no alias or interface
// defines counts when it has the shape of an alias name, since it can name a
// table the config does not store. A target that is a hostname with a domain
// does not count, since OPNsense disables a forward to it as an invalid
// target. Through 26.1.1 ForwardRule.php maps a target only when an
// alias of that name exists, of any type, and disables a forward to any other
// name that is no address or network as an invalid target, (self) and
// interface names among them, so on those releases the readings of (self) and
// of an interface can only over-report.
func targetHoldsLoopback(target string, device *common.CommonDevice) bool {
	if target == "(self)" {
		return true
	}

	object, defined := device.NamedObjects[target]
	if defined && object.Type != common.NamedObjectTypePort {
		return aliasHoldsFirewallAddress(loadedAliases(device.NamedObjects), target, loopbackAddresses) ||
			aliasNamesRuntimeTable(device.NamedObjects, target)
	}

	for _, iface := range device.Interfaces {
		if target == iface.Name || target == iface.Name+"ip" {
			return isLoopbackEntry(iface.IPAddress) || isLoopbackEntry(iface.IPv6Address)
		}
	}

	if defined {
		return false
	}

	return holdsFirewallAddress(target, loopbackAddresses) || aliasNamePattern.MatchString(target)
}

// loadsEmpty reports whether OPNsense loads the alias with no members, so
// that it holds no address and names no alias: it is disabled. The alias
// loader skips an external and an internal alias, whose tables stay as they
// are when disabled.
func loadsEmpty(object common.NamedObject) bool {
	return object.Disabled &&
		object.Type != common.NamedObjectTypeExternal && object.Type != aliasTypeInternal
}

// loadedAliases returns the aliases with the members of every alias that
// loads empty left out, for a walk that reads members, such as
// aliasHoldsFirewallAddress. The aliases given are not changed.
func loadedAliases(objects common.NamedObjects) common.NamedObjects {
	loaded := make(common.NamedObjects, len(objects))
	for name, object := range objects {
		if loadsEmpty(object) {
			object.Members = nil
		}
		loaded[name] = object
	}

	return loaded
}

// aliasNamesRuntimeTable reports whether the alias name, or an alias it names
// at any depth, gets its addresses at runtime: it is of a type in
// runtimeAliasTypes, or it is a host alias holding a member that names no
// alias and that OPNsense resolves through DNS when it loads the alias, such
// as a hostname (resolvedThroughDNS). OPNsense loads every address a fetched
// list or a DNS answer holds, loopback addresses included, so such an alias may
// hold one. A host, network or network group alias can name an alias of any
// type. The walk follows each member that names an alias, as
// aliasHoldsFirewallAddress does, and seen ends a nesting loop.
func aliasNamesRuntimeTable(objects common.NamedObjects, name string) bool {
	seen := map[string]bool{name: true}
	pending := []string{name}

	for len(pending) > 0 {
		last := len(pending) - 1
		object := objects[pending[last]]
		pending = pending[:last]

		if loadsEmpty(object) {
			continue
		}

		if slices.Contains(runtimeAliasTypes, object.Type) {
			return true
		}

		for _, member := range object.Members {
			_, defined := objects[member]

			switch {
			case !defined && object.Type == common.NamedObjectTypeHost && resolvedThroughDNS(member):
				return true
			case defined && !seen[member]:
				seen[member] = true
				pending = append(pending, member)
			}
		}
	}

	return false
}

// resolvedThroughDNS reports whether member, an entry of an OPNsense host alias
// that names no alias, is one the alias loader resolves through DNS: an entry
// that is no address and no first-last range of addresses (iter_addresses in
// OPNsense's alias/base.py), such as a hostname with or without a domain. An
// entry with "/" is read as a network or a wildcard network, or dropped, and
// the alias page accepts "!" only before an address, so neither is resolved.
func resolvedThroughDNS(member string) bool {
	if member == "" || strings.ContainsAny(member, "/!") {
		return false
	}

	from, to, isRange := strings.Cut(member, "-")
	_, errFrom := netip.ParseAddr(from)
	_, errTo := netip.ParseAddr(to)

	return errFrom != nil || (isRange && errTo != nil)
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
