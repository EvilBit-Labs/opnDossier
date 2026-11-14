package analysis

import (
	"slices"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// Reachability describes where a firewall rule, interface, or NAT rule can be
// reached from: the public internet (WAN), only from local/internal networks
// (LAN), or nowhere on any network (Local — e.g. a disabled interface, or a
// NAT rule with no matching enabled pass rule).
type Reachability string

const (
	// WANReachable indicates the element is reachable from the WAN (internet).
	WANReachable Reachability = "wan"
	// LANOnly indicates the element is reachable only from LAN/internal networks.
	LANOnly Reachability = "lan"
	// Local indicates the element is not reachable from any network — for
	// example a disabled interface, or a NAT rule with no matching enabled
	// pass rule.
	Local Reachability = "local"
)

// String returns the string representation of the reachability tag.
func (r Reachability) String() string {
	return string(r)
}

// dynamicIPv4Types are the <ipaddr> values that obtain an address and a router
// from upstream. OPNsense writes them from interfaces.php (dhcp, l2tp, ppp,
// pppoe, pptp), and pfSense's interface_has_gateway treats the same five as an
// interface with a gateway.
var dynamicIPv4Types = []string{"dhcp", "l2tp", "ppp", "pppoe", "pptp"}

// dynamicIPv6Types are the <ipaddrv6> values for which both vendors create an
// upstream gateway on the interface (OPNsense Gateways::getGateways,
// pfSense interface_has_gatewayv6). track6 is deliberately absent: it is how a
// LAN takes a prefix delegated from the uplink.
var dynamicIPv6Types = []string{"6rd", "6to4", "dhcp6", "slaac"}

// IsWANInterface reports whether the interface or interface group named name
// faces the WAN on device.
//
// An interface group applies a rule on every member (OPNsense ifgroup_setup
// attaches each member to the pf group), so a group faces the WAN when any
// member does. Group membership comes from device.InterfaceGroups; a name that
// no group lists is classified as an interface.
//
// An interface faces the WAN when it is an uplink. The interface key alone is
// not enough: the first uplink is "wan", but every further one keeps the optN
// key the assignments page gave it. Besides a "wan" key prefix, which is
// opnDossier's own convention rather than a vendor test, two signals come from
// the vendors' own test for an interface with an upstream gateway
// (OPNsense filter.lib.inc reply-to and force-gw, Gateways::getInterfaceGateway;
// pfSense interface_has_gateway):
//   - dynamic addressing, which learns a router from upstream (dynamicIPv4Types,
//     dynamicIPv6Types);
//   - a gateway selected on the interface (<gateway> or <gatewayv6> other than
//     "none"), which the interface page describes as typically disabled on
//     LAN-type interfaces. On OPNsense it counts only when it names a gateway
//     on that interface, as getInterfaceGateway requires, or a name the config
//     does not define, such as a dynamic gateway, so a dangling name still
//     over-reports. On pfSense any name counts (selectsGateway).
//
// A third signal is opnDossier's own, not either vendor's: an enabled gateway
// on the interface whose per-gateway default flag is set, since the interface
// then carries the default route. pfSense from 2.4.5 keeps its default in
// <gateways><defaultgw4>/<defaultgw6> instead, which this does not read, so on
// pfSense the signal rarely fires.
//
// A static gateway on a LAN that is not the default, as used for a route to
// another internal network, does not count: neither vendor treats it as an
// upstream unless the interface selects it. Tunnel interfaces (OpenVPN client,
// IPsec, GIF, GRE) are not classified as WAN by their device name alone.
//
// A nil device has no interfaces, groups or gateways, so only the "wan" key
// prefix applies.
func IsWANInterface(device *common.CommonDevice, name string) bool {
	if members, ok := interfaceGroupMembers(device, name); ok {
		return slices.ContainsFunc(members, func(member string) bool {
			return isUplinkName(device, member)
		})
	}

	return isUplinkName(device, name)
}

// interfaceGroupMembers returns the members device.InterfaceGroups lists for
// the group named name, and false when no group has that name.
func interfaceGroupMembers(device *common.CommonDevice, name string) ([]string, bool) {
	if device == nil {
		return nil, false
	}

	for _, group := range device.InterfaceGroups {
		if group.Name == name {
			return group.Members, true
		}
	}

	return nil, false
}

// isUplinkName classifies the interface keyed name. A name the device does not
// define is still classified by its key and by the gateways that name it, so a
// rule bound to an interface missing from the interface list keeps working.
func isUplinkName(device *common.CommonDevice, name string) bool {
	if hasWANKey(name) || hasDefaultGateway(device, name) {
		return true
	}

	if device == nil {
		return false
	}

	for _, iface := range device.Interfaces {
		if iface.Name == name {
			return hasUpstreamAddressing(device, iface)
		}
	}

	return false
}

// isUplinkInterface classifies iface from its own settings and the gateways
// that name it. It does not expand interface groups, and the entry OPNsense
// writes for each group under <interfaces> (pf.inc pf_interfaces: virtual, type
// group) is never an uplink of its own, whatever its name: OPNsense gives no
// virtual interface a gateway (Gateways.php getDefinedInterfaces).
func isUplinkInterface(device *common.CommonDevice, iface common.Interface) bool {
	if iface.Virtual || isGroupEntry(iface) {
		return false
	}

	return hasWANKey(iface.Name) || hasUpstreamAddressing(device, iface) || hasDefaultGateway(device, iface.Name)
}

// isGroupEntry reports whether iface is the entry OPNsense writes under
// <interfaces> for an interface group.
func isGroupEntry(iface common.Interface) bool {
	return strings.EqualFold(strings.TrimSpace(iface.Type), "group")
}

// hasWANKey reports whether name is a "wan"-prefixed interface key, matched
// case-insensitively (e.g. "wan", "WAN", "wan2").
func hasWANKey(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "wan")
}

// hasUpstreamAddressing reports whether iface learns its addressing from
// upstream or selects an upstream gateway.
func hasUpstreamAddressing(device *common.CommonDevice, iface common.Interface) bool {
	if slices.Contains(dynamicIPv4Types, strings.ToLower(strings.TrimSpace(iface.IPAddress))) ||
		slices.Contains(dynamicIPv6Types, strings.ToLower(strings.TrimSpace(iface.IPv6Address))) {
		return true
	}

	return selectsGateway(device, iface.Name, iface.Gateway) || selectsGateway(device, iface.Name, iface.GatewayV6)
}

// selectsGateway reports whether an interface <gateway> or <gatewayv6> value
// selects an upstream gateway for the interface keyed name. interfaces.php
// stores nothing for "Disabled", but a hand-edited or older config can carry
// the option's value "none".
//
// The vendors resolve the name differently. On OPNsense a name the config
// defines only on other interfaces is a stale selection the firewall ignores
// (Gateways::getInterfaceGateway matches only a gateway on the interface), so
// it does not count; a name the config does not define at all still does.
// pfSense resolves the name with no interface check (interface_has_gateway
// tests only that the element is set, and get_interface_gateway looks the
// name up among every gateway), so any name counts there. A device of no
// known type takes the pfSense reading, which over-reports.
func selectsGateway(device *common.CommonDevice, name, value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "none") {
		return false
	}

	if device == nil || device.DeviceType != common.DeviceTypeOPNsense {
		return true
	}

	defined := false

	for _, gw := range device.Routing.Gateways {
		if gw.Name != value {
			continue
		}

		if gw.Interface == name {
			return true
		}

		defined = true
	}

	return !defined
}

// hasDefaultGateway reports whether an enabled gateway on the interface keyed
// name has its per-gateway default flag set. The OPNsense converter reduces the
// flag to "1" or empty; pfSense passes the stored text through, so "0" is read
// as unset too.
func hasDefaultGateway(device *common.CommonDevice, name string) bool {
	if device == nil {
		return false
	}

	return slices.ContainsFunc(device.Routing.Gateways, func(gw common.Gateway) bool {
		flag := strings.TrimSpace(gw.DefaultGW)

		return !gw.Disabled && gw.Interface == name && flag != "" && flag != "0"
	})
}

// isLoopbackInterfaceName reports whether name looks like a loopback
// interface (e.g. "lo0"). Loopback interfaces are never reachable from a
// network and are classified as Local.
func isLoopbackInterfaceName(name string) bool {
	lower := strings.ToLower(name)
	return lower == "lo" || strings.HasPrefix(lower, "lo0")
}

// InterfaceReachability classifies a single interface of device as
// WAN-reachable, LAN-only, or local, based on its administrative state and the
// uplink signals IsWANInterface describes.
func InterfaceReachability(iface common.Interface, device *common.CommonDevice) Reachability {
	if !iface.Enabled || isLoopbackInterfaceName(iface.Name) {
		return Local
	}

	if isUplinkInterface(device, iface) {
		return WANReachable
	}

	return LANOnly
}

// RuleReachability classifies a firewall rule's reachability using its bound
// interfaces and the interfaces, interface groups and gateways of device.
//
// A rule counts as WAN-reachable when it applies to any WAN interface. This
// includes:
//   - Interface-scoped floating rules, which — like ordinary rules — are
//     scoped to exactly the interfaces in rule.Interfaces; the Floating flag
//     does not by itself widen a rule's reach beyond its interface list.
//   - Unscoped floating rules (Floating == true with an empty rule.Interfaces),
//     which apply to every interface and are therefore WAN-reachable whenever
//     any live WAN interface exists on the device.
//   - Rules on an interface group with a WAN member (IsWANInterface).
//   - IPv6-only WAN interfaces: the classification does not branch on
//     rule.IPProtocol, so a misconfigured or unassigned address must not mask
//     a real exposure.
//
// Enabled-state handling is deliberately asymmetric between the two binding
// styles. The unscoped-floating path resolves against the actual interface
// list via InterfaceReachability, which treats a disabled interface as Local —
// a device-wide rule cannot reach a WAN that is administratively down, and
// nothing in rule.Interfaces tells us which interfaces exist. The
// interface-scoped path, by contrast, trusts the operator's explicit binding:
// a rule bound to an uplink is classified as governing WAN traffic by intent,
// independent of the interface's current admin state (a disabled interface
// merely makes the rule inert, which is a separate concern from where the rule
// is scoped). It also keeps classification working for rules that reference
// an interface name not present in device.Interfaces.
func RuleReachability(rule common.FirewallRule, device *common.CommonDevice) Reachability {
	// An unscoped floating rule (no interface list) applies device-wide, so it
	// is WAN-reachable whenever any live WAN interface exists. A floating rule
	// WITH an explicit interface list is scoped to exactly those interfaces —
	// the same as a non-floating rule — so it falls through to the name check
	// below. Treating every floating rule as device-wide would false-positive a
	// LAN-scoped floating rule (e.g. an anti-lockout rule) as WAN-reachable.
	if rule.Floating && len(rule.Interfaces) == 0 {
		if device != nil && slices.ContainsFunc(device.Interfaces, func(iface common.Interface) bool {
			return InterfaceReachability(iface, device) == WANReachable
		}) {
			return WANReachable
		}

		return LANOnly
	}

	if slices.ContainsFunc(rule.Interfaces, func(name string) bool {
		return IsWANInterface(device, name)
	}) {
		return WANReachable
	}

	return LANOnly
}

// InboundNATRuleReachability reports whether an inbound (port-forward) NAT
// rule of device is WAN-reachable.
//
// A NAT rule is WAN-reachable only when it is enabled, applies to a WAN
// interface or an interface group with a WAN member, AND at least one enabled
// pass rule in device.FirewallRules also applies to one. NAT presence alone,
// with no matching enabled pass rule, is never WAN-reachable: OPNsense and
// pfSense both require an explicit pass rule (or an auto-added "filter rule
// association") to actually allow the forwarded traffic through the firewall;
// a port-forward with no corresponding pass rule is inert.
func InboundNATRuleReachability(nat common.InboundNATRule, device *common.CommonDevice) Reachability {
	if nat.Disabled {
		return Local
	}

	if !slices.ContainsFunc(nat.Interfaces, func(name string) bool {
		return IsWANInterface(device, name)
	}) {
		return LANOnly
	}

	if device == nil {
		return LANOnly
	}

	for _, rule := range device.FirewallRules {
		if rule.Disabled || rule.Type != common.RuleTypePass {
			continue
		}

		if RuleReachability(rule, device) == WANReachable {
			return WANReachable
		}
	}

	return LANOnly
}
