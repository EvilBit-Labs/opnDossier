// Package firewall provides a compliance plugin for firewall-specific security checks.
package firewall

import (
	"slices"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// weakVPNAlgorithms contains encryption algorithms considered insecure for
// IPsec VPN tunnels.
var weakVPNAlgorithms = []string{"des", "3des", "blowfish", "cast128", "null"}

// weakHashAlgorithms contains hash algorithms considered insecure for
// IPsec VPN integrity verification.
var weakHashAlgorithms = []string{"md5", "sha1"}

// defaultSNMPCommunities contains SNMP community strings that ship as
// factory defaults and should never be used in production.
var defaultSNMPCommunities = []string{"public", "private"}

// minimumNTPServers is the minimum number of NTP servers recommended for
// reliable time synchronization (allows detection of a single faulty source).
//

const minimumNTPServers = 2

// checkValidWebGUICertificate checks that the web GUI has a TLS certificate
// reference configured. An empty SSLCertRef means the system is using a
// self-signed or missing certificate.
func (fp *Plugin) checkValidWebGUICertificate(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	return checkResult{Result: device.System.WebGUI.SSLCertRef != "", Known: true}
}

// checkCertificateExpiration checks whether certificates are at risk of
// expiration. The CommonDevice model does not expose certificate expiry dates,
// so this cannot be evaluated.
func (fp *Plugin) checkCertificateExpiration(_ *common.CommonDevice) checkResult {
	return unknown
}

// checkStrongKeyLengths checks whether certificates use strong key lengths.
// The CommonDevice model does not expose certificate key lengths, so this
// cannot be evaluated.
func (fp *Plugin) checkStrongKeyLengths(_ *common.CommonDevice) checkResult {
	return unknown
}

// checkRemoteSyslog checks that remote syslog forwarding is configured and
// a remote server address is defined. Centralized logging is essential for
// forensic analysis and compliance.
func (fp *Plugin) checkRemoteSyslog(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	return checkResult{
		Result: device.Syslog.Enabled && device.Syslog.RemoteServer != "",
		Known:  true,
	}
}

// checkAuthenticationEventLogging checks that authentication event logging
// is forwarded to the remote syslog server.
func (fp *Plugin) checkAuthenticationEventLogging(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	if !device.Syslog.Enabled {
		return checkResult{Result: false, Known: true}
	}

	return checkResult{Result: device.Syslog.AuthLogging, Known: true}
}

// checkFirewallFilterLogging checks that firewall filter event logging is
// forwarded to the remote syslog server.
func (fp *Plugin) checkFirewallFilterLogging(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	if !device.Syslog.Enabled {
		return checkResult{Result: false, Known: true}
	}

	return checkResult{Result: device.Syslog.FilterLogging, Known: true}
}

// checkLogRetention checks that log retention is configured with a log file
// size and rotation count. The presence of these settings indicates the
// administrator has considered log management.
func (fp *Plugin) checkLogRetention(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	hasSize := device.Syslog.LogFileSize != ""
	hasRotation := device.Syslog.RotateCount != ""

	return checkResult{Result: hasSize || hasRotation, Known: true}
}

// checkNTPConfiguration checks that at least two NTP servers are configured
// for reliable time synchronization. With only one server, a faulty source
// cannot be detected.
func (fp *Plugin) checkNTPConfiguration(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	return checkResult{
		Result: len(device.System.TimeServers) >= minimumNTPServers,
		Known:  true,
	}
}

// checkTimezoneConfiguration checks that a timezone is explicitly configured.
// An empty timezone may cause log timestamps to be ambiguous.
func (fp *Plugin) checkTimezoneConfiguration(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	return checkResult{Result: device.System.Timezone != "", Known: true}
}

// checkSNMPDisabledIfUnused checks that SNMP is disabled when not needed.
// An empty ROCommunity string indicates SNMP is not configured (good).
// Any non-empty value means SNMP is in use and may increase attack surface.
func (fp *Plugin) checkSNMPDisabledIfUnused(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: true, Known: true}
	}

	return checkResult{Result: device.SNMP.ROCommunity == "", Known: true}
}

// checkNoDefaultCommunityStrings checks that SNMP community strings are not
// set to well-known defaults ("public", "private"). These are the first
// values attackers try and provide no real access control.
func (fp *Plugin) checkNoDefaultCommunityStrings(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: true, Known: true}
	}

	community := device.SNMP.ROCommunity
	if community == "" {
		// SNMP not configured; no default community string risk.
		return checkResult{Result: true, Known: true}
	}

	isDefault := slices.ContainsFunc(defaultSNMPCommunities, func(s string) bool {
		return strings.EqualFold(community, s)
	})

	return checkResult{Result: !isDefault, Known: true}
}

// checkStrongVPNEncryption checks that IPsec Phase 2 tunnels use strong
// encryption algorithms (AES-GCM variants) and do not use weak algorithms
// (DES, 3DES, Blowfish, CAST128, null).
func (fp *Plugin) checkStrongVPNEncryption(device *common.CommonDevice) checkResult {
	if device == nil {
		return unknown
	}

	if !device.VPN.IPsec.Enabled || len(device.VPN.IPsec.Phase2Tunnels) == 0 {
		return unknown
	}

	for _, p2 := range device.VPN.IPsec.Phase2Tunnels {
		if p2.Disabled {
			continue
		}

		for _, algo := range p2.EncryptionAlgorithms {
			algoLower := strings.ToLower(algo)
			if slices.ContainsFunc(weakVPNAlgorithms, func(weak string) bool {
				return strings.Contains(algoLower, weak)
			}) {
				return checkResult{Result: false, Known: true}
			}
		}
	}

	return checkResult{Result: true, Known: true}
}

// checkStrongVPNIntegrity checks that IPsec Phase 2 tunnels use strong hash
// algorithms for integrity verification and do not use weak algorithms
// (MD5, SHA-1).
func (fp *Plugin) checkStrongVPNIntegrity(device *common.CommonDevice) checkResult {
	if device == nil {
		return unknown
	}

	if !device.VPN.IPsec.Enabled || len(device.VPN.IPsec.Phase2Tunnels) == 0 {
		return unknown
	}

	for _, p2 := range device.VPN.IPsec.Phase2Tunnels {
		if p2.Disabled {
			continue
		}

		for _, hash := range p2.HashAlgorithms {
			hashLower := strings.ToLower(hash)
			if slices.ContainsFunc(weakHashAlgorithms, func(weak string) bool {
				return strings.EqualFold(hashLower, weak)
			}) {
				return checkResult{Result: false, Known: true}
			}
		}
	}

	return checkResult{Result: true, Known: true}
}

// checkPerfectForwardSecrecy checks that IPsec Phase 2 tunnels have PFS
// (Perfect Forward Secrecy) enabled with a configured DH group.
func (fp *Plugin) checkPerfectForwardSecrecy(device *common.CommonDevice) checkResult {
	if device == nil {
		return unknown
	}

	if !device.VPN.IPsec.Enabled || len(device.VPN.IPsec.Phase2Tunnels) == 0 {
		return unknown
	}

	for _, p2 := range device.VPN.IPsec.Phase2Tunnels {
		if p2.Disabled {
			continue
		}

		if p2.PFSGroup == "" || strings.EqualFold(p2.PFSGroup, "off") {
			return checkResult{Result: false, Known: true}
		}
	}

	return checkResult{Result: true, Known: true}
}

// checkVPNKeyLifetime checks that IPsec Phase 2 tunnels have a configured
// lifetime. Unlimited lifetimes weaken security by allowing compromised keys
// to remain in use indefinitely.
func (fp *Plugin) checkVPNKeyLifetime(device *common.CommonDevice) checkResult {
	if device == nil {
		return unknown
	}

	if !device.VPN.IPsec.Enabled || len(device.VPN.IPsec.Phase2Tunnels) == 0 {
		return unknown
	}

	for _, p2 := range device.VPN.IPsec.Phase2Tunnels {
		if p2.Disabled {
			continue
		}

		if p2.Lifetime == "" {
			return checkResult{Result: false, Known: true}
		}
	}

	return checkResult{Result: true, Known: true}
}

// checkNoIKEv1AggressiveMode checks that no IPsec Phase 1 tunnels use
// IKEv1 aggressive mode, which exposes the pre-shared key hash to
// offline brute-force attacks.
func (fp *Plugin) checkNoIKEv1AggressiveMode(device *common.CommonDevice) checkResult {
	if device == nil {
		return unknown
	}

	if !device.VPN.IPsec.Enabled || len(device.VPN.IPsec.Phase1Tunnels) == 0 {
		return unknown
	}

	for _, p1 := range device.VPN.IPsec.Phase1Tunnels {
		if p1.Disabled {
			continue
		}

		if strings.EqualFold(p1.IKEType, "ikev1") && strings.EqualFold(p1.Mode, "aggressive") {
			return checkResult{Result: false, Known: true}
		}
	}

	return checkResult{Result: true, Known: true}
}

// checkIKEv2Preferred checks that IPsec Phase 1 tunnels prefer IKEv2 over
// IKEv1. IKEv2 provides improved security, reduced complexity, and built-in
// NAT traversal.
func (fp *Plugin) checkIKEv2Preferred(device *common.CommonDevice) checkResult {
	if device == nil {
		return unknown
	}

	if !device.VPN.IPsec.Enabled || len(device.VPN.IPsec.Phase1Tunnels) == 0 {
		return unknown
	}

	for _, p1 := range device.VPN.IPsec.Phase1Tunnels {
		if p1.Disabled {
			continue
		}

		if strings.EqualFold(p1.IKEType, "ikev1") {
			return checkResult{Result: false, Known: true}
		}
	}

	return checkResult{Result: true, Known: true}
}

// checkDeadPeerDetection checks that IPsec Phase 1 tunnels have Dead Peer
// Detection configured. DPD detects unresponsive peers and triggers
// renegotiation to maintain tunnel availability.
func (fp *Plugin) checkDeadPeerDetection(device *common.CommonDevice) checkResult {
	if device == nil {
		return unknown
	}

	if !device.VPN.IPsec.Enabled || len(device.VPN.IPsec.Phase1Tunnels) == 0 {
		return unknown
	}

	for _, p1 := range device.VPN.IPsec.Phase1Tunnels {
		if p1.Disabled {
			continue
		}

		if p1.DPDDelay == "" || p1.DPDDelay == "0" {
			return checkResult{Result: false, Known: true}
		}
	}

	return checkResult{Result: true, Known: true}
}
