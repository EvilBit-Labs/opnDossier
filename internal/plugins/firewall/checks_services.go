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

// checkUPnPDisabled checks whether UPnP/NAT-PMP is disabled. The CommonDevice
// model does not expose UPnP configuration, so this cannot be evaluated.
func (fp *Plugin) checkUPnPDisabled(_ *common.CommonDevice) checkResult {
	return unknown
}

// checkDNSSECValidation checks that DNSSEC validation is enabled on the
// Unbound DNS resolver. DNSSEC prevents DNS spoofing by cryptographically
// verifying responses.
func (fp *Plugin) checkDNSSECValidation(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	if !device.DNS.Unbound.Enabled {
		// Unbound not enabled; DNSSEC cannot be validated.
		return checkResult{Result: false, Known: true}
	}

	return checkResult{Result: device.DNS.Unbound.DNSSEC, Known: true}
}

// checkDNSResolverAccessRestriction checks whether the DNS resolver access is
// restricted to specific interfaces. The CommonDevice model does not expose
// Unbound interface binding, so this cannot be evaluated.
func (fp *Plugin) checkDNSResolverAccessRestriction(_ *common.CommonDevice) checkResult {
	return unknown
}

// checkConfigurationRevisionTracking checks whether configuration revision
// tracking is configured. The CommonDevice model does not expose revision
// tracking settings in a way that enables this check.
func (fp *Plugin) checkConfigurationRevisionTracking(_ *common.CommonDevice) checkResult {
	return unknown
}

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
