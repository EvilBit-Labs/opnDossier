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

// IsWANInterfaceName reports whether name is a WAN-style interface name,
// using case-insensitive "wan" prefix matching (e.g. "wan", "WAN", "wan2").
//
// This is the single canonical WAN-interface-name predicate in the codebase.
// internal/plugins/sans, internal/plugins/firewall, and the rest of
// internal/analysis all route through this function instead of
// reimplementing the check — see GOTCHAS.md and the reachability
// consolidation history for why the two previously-divergent exact-match
// sites in this package were bugs, not just duplication.
//
// Known limitation: detection is name-prefix-only. A secondary internet uplink
// left with its default logical name (e.g. "opt1") rather than renamed to a
// "wan"-prefixed name is classified LAN-only, so a service exposed on it can be
// under-reported. Closing this requires consulting gateway/default-route
// signals (common.Gateway.Interface) and is tracked as follow-up work, not
// addressed by this consolidation.
func IsWANInterfaceName(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "wan")
}

// isLoopbackInterfaceName reports whether name looks like a loopback
// interface (e.g. "lo0"). Loopback interfaces are never reachable from a
// network and are classified as Local.
func isLoopbackInterfaceName(name string) bool {
	lower := strings.ToLower(name)
	return lower == "lo" || strings.HasPrefix(lower, "lo0")
}

// InterfaceReachability classifies a single interface as WAN-reachable,
// LAN-only, or local, based on its administrative state and name.
func InterfaceReachability(iface common.Interface) Reachability {
	if !iface.Enabled || isLoopbackInterfaceName(iface.Name) {
		return Local
	}

	if IsWANInterfaceName(iface.Name) {
		return WANReachable
	}

	return LANOnly
}

// RuleReachability classifies a firewall rule's reachability using its bound
// interfaces and IP protocol.
//
// A rule counts as WAN-reachable when it applies to any WAN interface. This
// includes:
//   - Interface-scoped floating rules, which — like ordinary rules — are
//     scoped to exactly the interfaces in rule.Interfaces; the Floating flag
//     does not by itself widen a rule's reach beyond its interface list.
//   - Unscoped floating rules (Floating == true with an empty rule.Interfaces),
//     which apply to every interface and are therefore WAN-reachable whenever
//     any live WAN interface exists on the device.
//   - IPv6-only WAN interfaces (rule.IPProtocol == IPProtocolInet6 bound to a
//     WAN-named interface) — the WAN-name match alone is sufficient; the
//     interface's IPv6Address is not required to be non-empty because a
//     misconfigured/unassigned address must not mask a real exposure.
//
// Enabled-state handling is deliberately asymmetric between the two binding
// styles. The unscoped-floating path resolves against the actual interface
// list via InterfaceReachability, which treats a disabled interface as Local —
// a device-wide rule cannot reach a WAN that is administratively down, and
// nothing in rule.Interfaces tells us which interfaces exist. The
// interface-scoped path, by contrast, trusts the operator's explicit binding:
// a rule bound by name to "wan" is classified as governing WAN traffic by
// intent, independent of the interface's current admin state (a disabled
// interface merely makes the rule inert, which is a separate concern from
// where the rule is scoped). It also keeps classification working for rules
// that reference an interface name not present in the passed-in ifaces slice.
func RuleReachability(rule common.FirewallRule, ifaces []common.Interface) Reachability {
	// An unscoped floating rule (no interface list) applies device-wide, so it
	// is WAN-reachable whenever any live WAN interface exists. A floating rule
	// WITH an explicit interface list is scoped to exactly those interfaces —
	// the same as a non-floating rule — so it falls through to the name check
	// below. Treating every floating rule as device-wide would false-positive a
	// LAN-scoped floating rule (e.g. an anti-lockout rule) as WAN-reachable.
	if rule.Floating && len(rule.Interfaces) == 0 {
		if slices.ContainsFunc(ifaces, func(iface common.Interface) bool {
			return InterfaceReachability(iface) == WANReachable
		}) {
			return WANReachable
		}

		return LANOnly
	}

	if slices.ContainsFunc(rule.Interfaces, IsWANInterfaceName) {
		return WANReachable
	}

	return LANOnly
}

// InboundNATRuleReachability reports whether an inbound (port-forward) NAT
// rule is WAN-reachable.
//
// A NAT rule is WAN-reachable only when it is enabled, applies to a WAN
// interface, AND at least one enabled pass rule also applies to a WAN
// interface. NAT presence alone — with no matching enabled pass rule — is
// never WAN-reachable: OPNsense and pfSense both require an explicit pass
// rule (or an auto-added "filter rule association") to actually allow the
// forwarded traffic through the firewall; a port-forward with no
// corresponding pass rule is inert.
func InboundNATRuleReachability(
	nat common.InboundNATRule,
	ifaces []common.Interface,
	passRules []common.FirewallRule,
) Reachability {
	if nat.Disabled {
		return Local
	}

	if !slices.ContainsFunc(nat.Interfaces, IsWANInterfaceName) {
		return LANOnly
	}

	for _, rule := range passRules {
		if rule.Disabled || rule.Type != common.RuleTypePass {
			continue
		}

		if RuleReachability(rule, ifaces) == WANReachable {
			return WANReachable
		}
	}

	return LANOnly
}
