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

// IsWANInterface reports whether the interface or interface group named name
// faces the WAN on device.
//
// An interface group applies a rule on every member (OPNsense ifgroup_setup
// attaches each member to the pf group), so a group faces the WAN when any
// member does. Group membership comes from device.InterfaceGroups; a name that
// no group lists is classified as an interface.
//
// An interface faces the WAN when its key starts with "wan".
//
// A nil device has no groups, so only the "wan" key prefix applies.
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

// isUplinkName classifies the interface keyed name.
func isUplinkName(_ *common.CommonDevice, name string) bool {
	return hasWANKey(name)
}

// isUplinkInterface classifies iface. It does not expand interface groups:
// an entry OPNsense writes for a group under <interfaces> is not an interface
// of its own.
func isUplinkInterface(_ *common.CommonDevice, iface common.Interface) bool {
	return hasWANKey(iface.Name)
}

// hasWANKey reports whether name is a "wan"-prefixed interface key, matched
// case-insensitively (e.g. "wan", "WAN", "wan2").
func hasWANKey(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "wan")
}

// isLoopbackInterfaceName reports whether name looks like a loopback
// interface (e.g. "lo0"). Loopback interfaces are never reachable from a
// network and are classified as Local.
func isLoopbackInterfaceName(name string) bool {
	lower := strings.ToLower(name)
	return lower == "lo" || strings.HasPrefix(lower, "lo0")
}

// InterfaceReachability classifies a single interface of device as
// WAN-reachable, LAN-only, or local, based on its administrative state and
// name.
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
// interfaces and the interface groups of device.
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
// pass rule in device.FirewallRules also applies to one. NAT presence alone —
// with no matching enabled pass rule — is never WAN-reachable: OPNsense and
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
