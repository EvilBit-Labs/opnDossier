// Package firewall provides a compliance plugin for firewall-specific security checks.
package firewall

import (
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// disabledRuleThreshold is the maximum number of disabled rules before a
// cleanup finding is raised. Exceeding this threshold suggests stale rules
// that should be reviewed and removed.
//

const disabledRuleThreshold = 10

// isWANInterface reports whether the given interface name represents a WAN
// interface. The check is case-insensitive and matches "wan" as well as
// prefixed variants like "wan2".
func isWANInterface(name string) bool {
	lower := strings.ToLower(name)

	return lower == "wan" || strings.HasPrefix(lower, "wan")
}

// checkNoAnyAnyPassRules checks that no firewall pass rules exist with source,
// destination, port, and protocol all set to "any". Such rules effectively
// disable the firewall for matching traffic.
func (fp *Plugin) checkNoAnyAnyPassRules(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: true, Known: true}
	}

	for _, rule := range device.FirewallRules {
		if rule.Disabled {
			continue
		}

		if rule.Type != common.RuleTypePass {
			continue
		}

		srcAny := rule.Source.Address == constants.NetworkAny
		dstAny := rule.Destination.Address == constants.NetworkAny
		portAny := rule.Destination.Port == "" || rule.Destination.Port == constants.NetworkAny
		protoAny := rule.Protocol == "" || strings.EqualFold(rule.Protocol, constants.NetworkAny)

		if srcAny && dstAny && portAny && protoAny {
			return checkResult{Result: false, Known: true}
		}
	}

	return checkResult{Result: true, Known: true}
}

// checkNoAnySourceOnWANInbound checks that no WAN pass rules have a source
// address of "any". Allowing any source on WAN exposes the network to the
// entire internet.
func (fp *Plugin) checkNoAnySourceOnWANInbound(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: true, Known: true}
	}

	for _, rule := range device.FirewallRules {
		if rule.Disabled || rule.Type != common.RuleTypePass {
			continue
		}

		for _, iface := range rule.Interfaces {
			if isWANInterface(iface) && rule.Source.Address == constants.NetworkAny {
				return checkResult{Result: false, Known: true}
			}
		}
	}

	return checkResult{Result: true, Known: true}
}

// checkSpecificPortRules checks that pass rules specify explicit destination
// ports rather than allowing all ports. Rules with empty or "any" destination
// ports are overly permissive.
func (fp *Plugin) checkSpecificPortRules(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: true, Known: true}
	}

	for _, rule := range device.FirewallRules {
		if rule.Disabled || rule.Type != common.RuleTypePass {
			continue
		}

		// ICMP and similar protocols do not use ports.
		proto := strings.ToLower(rule.Protocol)
		if proto == "icmp" || proto == "icmp6" {
			continue
		}

		portEmpty := rule.Destination.Port == "" || rule.Destination.Port == constants.NetworkAny
		if portEmpty && (proto == "tcp" || proto == "udp" || proto == "tcp/udp" || proto == "") {
			return checkResult{Result: false, Known: true}
		}
	}

	return checkResult{Result: true, Known: true}
}

// checkRuleDocumentation checks that all enabled firewall rules have a
// non-empty description for auditability and change tracking.
func (fp *Plugin) checkRuleDocumentation(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: true, Known: true}
	}

	for _, rule := range device.FirewallRules {
		if rule.Disabled {
			continue
		}

		if strings.TrimSpace(rule.Description) == "" {
			return checkResult{Result: false, Known: true}
		}
	}

	return checkResult{Result: true, Known: true}
}

// checkDisabledRuleCleanup checks whether the number of disabled firewall
// rules exceeds the cleanup threshold. A large number of disabled rules
// indicates stale configuration that should be reviewed.
func (fp *Plugin) checkDisabledRuleCleanup(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: true, Known: true}
	}

	disabledCount := 0
	for _, rule := range device.FirewallRules {
		if rule.Disabled {
			disabledCount++
		}
	}

	return checkResult{Result: disabledCount <= disabledRuleThreshold, Known: true}
}

// checkProtocolSpecification checks that pass rules specify an explicit
// protocol rather than matching all protocols. Rules without protocol
// restriction are overly broad.
func (fp *Plugin) checkProtocolSpecification(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: true, Known: true}
	}

	for _, rule := range device.FirewallRules {
		if rule.Disabled || rule.Type != common.RuleTypePass {
			continue
		}

		if rule.Protocol == "" || strings.EqualFold(rule.Protocol, constants.NetworkAny) {
			return checkResult{Result: false, Known: true}
		}
	}

	return checkResult{Result: true, Known: true}
}

// checkPassRuleLogging checks that pass rules have logging enabled. Logging
// on pass rules provides visibility into allowed traffic for forensic analysis.
func (fp *Plugin) checkPassRuleLogging(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: true, Known: true}
	}

	for _, rule := range device.FirewallRules {
		if rule.Disabled || rule.Type != common.RuleTypePass {
			continue
		}

		if !rule.Log {
			return checkResult{Result: false, Known: true}
		}
	}

	return checkResult{Result: true, Known: true}
}

// checkPrivateAddressFilteringOnWAN checks that WAN interfaces have
// BlockPrivate enabled to prevent RFC 1918 private addresses from being
// accepted on the public-facing interface.
func (fp *Plugin) checkPrivateAddressFilteringOnWAN(device *common.CommonDevice) checkResult {
	if device == nil {
		return unknown
	}

	foundWAN := false
	for _, iface := range device.Interfaces {
		if isWANInterface(iface.Name) {
			foundWAN = true
			if !iface.BlockPrivate {
				return checkResult{Result: false, Known: true}
			}
		}
	}

	if !foundWAN {
		return unknown
	}

	return checkResult{Result: true, Known: true}
}

// checkBogonFilteringOnWAN checks that WAN interfaces have BlockBogons
// enabled to prevent unassigned and reserved IP ranges from being accepted.
func (fp *Plugin) checkBogonFilteringOnWAN(device *common.CommonDevice) checkResult {
	if device == nil {
		return unknown
	}

	foundWAN := false
	for _, iface := range device.Interfaces {
		if isWANInterface(iface.Name) {
			foundWAN = true
			if !iface.BlockBogons {
				return checkResult{Result: false, Known: true}
			}
		}
	}

	if !foundWAN {
		return unknown
	}

	return checkResult{Result: true, Known: true}
}

// checkUnusedInterfaceDisablement checks that all configured interfaces are
// explicitly enabled. Interfaces that exist in the configuration but are not
// enabled may represent unused attack surface.
func (fp *Plugin) checkUnusedInterfaceDisablement(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: true, Known: true}
	}

	for _, iface := range device.Interfaces {
		if !iface.Enabled {
			return checkResult{Result: false, Known: true}
		}
	}

	return checkResult{Result: true, Known: true}
}

// checkVLANSegmentation checks whether VLANs are configured for network
// segmentation. The presence of at least one VLAN indicates the network
// is segmented beyond a flat topology.
func (fp *Plugin) checkVLANSegmentation(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	return checkResult{Result: len(device.VLANs) > 0, Known: true}
}

// sourceRouteSysctl is the sysctl tunable that controls IP source routing acceptance.
const sourceRouteSysctl = "net.inet.ip.sourceroute"

// checkSourceRouteRejection checks that IP source routing is disabled via
// the net.inet.ip.sourceroute sysctl. Source routing allows an attacker to
// specify the route packets take through the network.
func (fp *Plugin) checkSourceRouteRejection(device *common.CommonDevice) checkResult {
	if device == nil {
		return unknown
	}

	for _, item := range device.Sysctl {
		if item.Tunable == sourceRouteSysctl {
			return checkResult{Result: item.Value == "0", Known: true}
		}
	}

	// Tunable not present in config; cannot determine state.
	return unknown
}

// syncookiesSysctl is the sysctl tunable that controls TCP SYN cookie protection.
const syncookiesSysctl = "net.inet.tcp.syncookies"

// checkSYNFloodProtection checks that TCP SYN cookies are enabled via the
// net.inet.tcp.syncookies sysctl to mitigate SYN flood denial-of-service attacks.
func (fp *Plugin) checkSYNFloodProtection(device *common.CommonDevice) checkResult {
	if device == nil {
		return unknown
	}

	for _, item := range device.Sysctl {
		if item.Tunable == syncookiesSysctl {
			return checkResult{Result: item.Value == "1", Known: true}
		}
	}

	// Tunable not present in config; cannot determine state.
	return unknown
}

// FIREWALL-035 (checkConnectionStateLimits) was a no-op returning unknown —
// the CommonDevice model has no global max-states setting. Removed with the
// EvaluatedControlIDs cleanup; control remains in controls.go so the report
// labels it UNCONFIRMED.
