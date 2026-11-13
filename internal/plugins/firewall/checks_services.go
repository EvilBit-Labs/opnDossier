// Package firewall provides a compliance plugin for firewall-specific security checks.
package firewall

import (
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// checkDocumentedPortForwards checks that all inbound NAT (port-forward)
// rules have a non-empty description for audit trail and change management.
func (fp *Plugin) checkDocumentedPortForwards(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: true, Known: true}
	}

	for _, rule := range device.NAT.InboundRules {
		if rule.Disabled {
			continue
		}

		if strings.TrimSpace(rule.Description) == "" {
			return checkResult{Result: false, Known: true}
		}
	}

	return checkResult{Result: true, Known: true}
}

// checkOutboundNATControl checks that outbound NAT is configured in hybrid
// or advanced mode rather than the fully automatic mode. Automatic mode
// creates implicit rules without administrator review.
func (fp *Plugin) checkOutboundNATControl(device *common.CommonDevice) checkResult {
	if device == nil {
		return unknown
	}

	mode := device.NAT.OutboundMode
	if mode == "" {
		return unknown
	}

	controlled := mode == common.OutboundHybrid || mode == common.OutboundAdvanced

	return checkResult{Result: controlled, Known: true}
}

// checkNATReflectionDisabled checks that NAT reflection (hairpin NAT) is
// disabled. NAT reflection allows internal hosts to access services via the
// external IP, which can complicate firewall rule auditing.
func (fp *Plugin) checkNATReflectionDisabled(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: true, Known: true}
	}

	return checkResult{Result: device.NAT.ReflectionDisabled, Known: true}
}

// FIREWALL-057 (checkUPnPDisabled) was a no-op returning unknown — the
// CommonDevice model does not expose UPnP configuration. Removed with the
// EvaluatedControlIDs cleanup; control remains in controls.go so the report
// labels it UNCONFIRMED.

// checkDNSSECValidation checks that DNSSEC validation is enabled on the DNS
// resolver. DNSSEC prevents DNS spoofing by cryptographically verifying
// responses.
//
// The resolver is Unbound when it is enabled. Otherwise it is dnsmasq when
// dnsmasq answers DNS on port 53: an empty port means 53, and any other port,
// 0 among them, leaves clients of the firewall without it (Dnsmasq.php sets
// the effective port to 53 only when <port> is empty).
func (fp *Plugin) checkDNSSECValidation(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	if device.DNS.Unbound.Enabled {
		return checkResult{Result: device.DNS.Unbound.DNSSEC, Known: true}
	}

	dnsmasq := device.DNS.DNSMasq
	if dnsmasq.Enabled && (dnsmasq.Port == "" || dnsmasq.Port == "53") {
		return checkResult{Result: dnsmasq.DNSSEC, Known: true}
	}

	// No resolver answers on the standard port; DNSSEC cannot be validated.
	return checkResult{Result: false, Known: true}
}

// FIREWALL-059 (checkDNSResolverAccessRestriction) and FIREWALL-060
// (checkConfigurationRevisionTracking) were no-op helpers returning unknown.
// Removed with the EvaluatedControlIDs cleanup; controls remain in controls.go
// so the report labels them UNCONFIRMED.
//
// The two are not equally blocked:
//   - FIREWALL-060 is not blocked at all. Revision metadata is plumbed
//     end-to-end on both vendors and is readable today at device.Revision
//     (pkg/model/revision.go). Only the check function is missing.
//   - FIREWALL-059 is partially blocked. Both vendor schemas parse the Unbound
//     interface binding (opnsense UnboundPlusGeneral.ActiveInterface,
//     pfsense UnboundConfig.ActiveInterface), but common.UnboundConfig has no
//     corresponding field and neither converter carries it across.

// checkHAConfiguration checks whether a high-availability configuration is
// in place when pfsync peer IP is configured.
func (fp *Plugin) checkHAConfiguration(device *common.CommonDevice) checkResult {
	if device == nil {
		return unknown
	}

	// If no HA is configured at all, this is not evaluable (not all environments need HA).
	ha := device.HighAvailability
	if ha.PfsyncInterface == "" && ha.PfsyncPeerIP == "" && ha.SynchronizeToIP == "" {
		return unknown
	}

	// HA is partially configured; check that pfsync peer is defined.
	return checkResult{Result: ha.PfsyncPeerIP != "", Known: true}
}
