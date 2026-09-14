package converter

import (
	"slices"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// computeSecurityAssessment populates a SecurityAssessment from the already-computed statistics.
func computeSecurityAssessment(stats *common.Statistics) *common.SecurityAssessment {
	return &common.SecurityAssessment{
		OverallScore:     stats.Summary.SecurityScore,
		SecurityFeatures: stats.SecurityFeatures,
	}
}

// computePerformanceMetrics populates PerformanceMetrics from the already-computed statistics.
func computePerformanceMetrics(stats *common.Statistics) *common.PerformanceMetrics {
	return &common.PerformanceMetrics{
		ConfigComplexity: stats.Summary.ConfigComplexity,
	}
}

// redactedValue is the placeholder for sensitive fields in exported output.
const redactedValue = "[REDACTED]"

// enrich populates the read-only enrichment fields on dst in place when nil.
// Callers must invoke enrich before any redaction so analysis.ComputeStatistics
// and analysis.ComputeAnalysis observe unredacted input. Callers must also
// guarantee dst is non-nil; nil-checking is the public-API caller's
// responsibility.
//
// SecurityAssessment and PerformanceMetrics are derived from Statistics. When
// Statistics is (re)computed, both derived fields are also (re)computed so a
// partial cache invalidation — caller clears only Statistics to refresh after
// a config change — does not leave stale derived metrics tied to a Statistics
// that no longer exists.
func enrich(dst *common.CommonDevice) {
	if dst.DeviceType == "" {
		dst.DeviceType = common.DeviceTypeOPNsense
	}
	if dst.Statistics == nil {
		dst.Statistics = analysis.ComputeStatistics(dst)
		// Refresh derived fields together with Statistics. Existing values are
		// intentionally overwritten — they were derived from a Statistics that
		// has just been discarded.
		dst.SecurityAssessment = computeSecurityAssessment(dst.Statistics)
		dst.PerformanceMetrics = computePerformanceMetrics(dst.Statistics)
	} else {
		// Statistics preserved; populate derived fields when absent so callers
		// who pre-populate Statistics alone still get a complete enrichment.
		if dst.SecurityAssessment == nil {
			dst.SecurityAssessment = computeSecurityAssessment(dst.Statistics)
		}
		if dst.PerformanceMetrics == nil {
			dst.PerformanceMetrics = computePerformanceMetrics(dst.Statistics)
		}
	}
	if dst.Analysis == nil {
		dst.Analysis = analysis.ComputeAnalysis(dst)
	}
}

// prepareForExport returns a shallow copy of the device with default DeviceType,
// Statistics, Analysis, SecurityAssessment, and PerformanceMetrics populated when absent.
// When redact is true, sensitive fields (passwords, private keys, API secrets, SNMP
// community strings, WireGuard PSKs, DHCPv6 authentication secrets) are replaced with
// [REDACTED]. When redact is false, sensitive fields are passed through as-is.
//
// prepareForExport does not mutate data. Callers that prepare the same device for
// multiple format exports should call enrich first to memoize the
// expensive Statistics and Analysis computations across calls.
//
// NOTE: analysis.ComputeStatistics and analysis.ComputeAnalysis intentionally receive
// the original unredacted data so that presence checks (e.g., "is SNMP configured?")
// see real values.
func prepareForExport(data *common.CommonDevice, redact bool) *common.CommonDevice {
	cp := *data

	// enrich must run before redaction so analysis.ComputeStatistics and
	// analysis.ComputeAnalysis observe unredacted input — see enrich godoc.
	enrich(&cp)

	if redact {
		redactSensitiveFields(&cp)
		cp.Statistics = redactStatisticsServiceDetails(cp.Statistics)
	}

	// ComplianceResults is populated externally by the audit handler;
	// pass through as-is when present.

	return &cp
}

// redactSensitiveFields replaces sensitive field values with a redaction marker.
// This must be called on the shallow copy, not the original, to avoid mutating
// the caller's data. Slice fields that contain sensitive data are deep-copied
// before redaction.
//
// SECURITY NOTE: The following sensitive field mappings are vetted:
//   - OpenVPN TLS keys (schema.OpenVPNServer.TLS, schema.OpenVPNSystem.StaticKeys)
//     — excluded by the converter's field mapping and never appear in CommonDevice.
//   - IPsec pre-shared keys — schema.IPsec.PreSharedKeys IS mapped to
//     common.IPsecConfig.PreSharedKeys. In the current OPNsense MVC model this
//     field stores UUID references to the Ipsec/KeyPairs/PreSharedKey MVC model
//     (not raw key material), so no credential leaks today. If a future schema
//     revision ever starts storing raw keys in this field, redaction logic
//     must be added below.
//   - pfSense IPsecPhase1.PreSharedKey is a scalar raw key but is intentionally
//     not mapped into common.IPsecPhase1Tunnel — see
//     pkg/parser/pfsense/converter_services.go convertIPsecPhase1Tunnels and
//     the TestConverter_IPsecPhase1_PreSharedKeyExclusion regression test.
//   - WireGuard private keys (only public keys are mapped; PSKs are mapped but redacted below)
//
// If new secret fields are added to common.*, they MUST be added here.
func redactSensitiveFields(cp *common.CommonDevice) {
	if cp.HighAvailability.Password != "" {
		cp.HighAvailability.Password = redactedValue
	}
	redactCertPrivateKeys(cp)
	redactCAPrivateKeys(cp)
	redactUserAPIKeySecrets(cp)
	if cp.SNMP.ROCommunity != "" {
		cp.SNMP.ROCommunity = redactedValue
	}
	redactWireGuardPSKs(cp)
	redactDHCPv6Secrets(cp)
	redactInterfaceDHCPv6Secrets(cp)
}

func redactCertPrivateKeys(cp *common.CommonDevice) {
	if len(cp.Certificates) == 0 {
		return
	}
	cp.Certificates = slices.Clone(cp.Certificates)
	for i := range cp.Certificates {
		if cp.Certificates[i].PrivateKey != "" {
			cp.Certificates[i].PrivateKey = redactedValue
		}
	}
}

func redactCAPrivateKeys(cp *common.CommonDevice) {
	if len(cp.CAs) == 0 {
		return
	}
	cp.CAs = slices.Clone(cp.CAs)
	for i := range cp.CAs {
		if cp.CAs[i].PrivateKey != "" {
			cp.CAs[i].PrivateKey = redactedValue
		}
	}
}

func redactUserAPIKeySecrets(cp *common.CommonDevice) {
	if len(cp.Users) == 0 {
		return
	}
	cp.Users = slices.Clone(cp.Users)
	for i := range cp.Users {
		if len(cp.Users[i].APIKeys) == 0 {
			continue
		}
		cp.Users[i].APIKeys = slices.Clone(cp.Users[i].APIKeys)
		for j := range cp.Users[i].APIKeys {
			if cp.Users[i].APIKeys[j].Secret != "" {
				cp.Users[i].APIKeys[j].Secret = redactedValue
			}
		}
	}
}

func redactWireGuardPSKs(cp *common.CommonDevice) {
	if len(cp.VPN.WireGuard.Clients) == 0 {
		return
	}
	cp.VPN.WireGuard.Clients = slices.Clone(cp.VPN.WireGuard.Clients)
	for i := range cp.VPN.WireGuard.Clients {
		if cp.VPN.WireGuard.Clients[i].PSK != "" {
			cp.VPN.WireGuard.Clients[i].PSK = redactedValue
		}
	}
}

func redactDHCPv6Secrets(cp *common.CommonDevice) {
	if len(cp.DHCP) == 0 {
		return
	}
	cp.DHCP = slices.Clone(cp.DHCP)
	for i := range cp.DHCP {
		adv := cp.DHCP[i].AdvancedV6
		if adv == nil || adv.AdvDHCP6KeyInfoStatementSecret == "" {
			continue
		}
		v6Copy := *adv
		v6Copy.AdvDHCP6KeyInfoStatementSecret = redactedValue
		cp.DHCP[i].AdvancedV6 = &v6Copy
	}
}

// redactInterfaceDHCPv6Secrets redacts the DHCPv6 authentication secret carried by
// each interface's advanced DHCPv6 *client* settings. This is a separate storage
// location from the DHCP server scopes redactDHCPv6Secrets covers: real config.xml
// files put the adv_dhcp6_* elements under <interfaces>, not under <dhcpd>.
func redactInterfaceDHCPv6Secrets(cp *common.CommonDevice) {
	if len(cp.Interfaces) == 0 {
		return
	}
	cp.Interfaces = slices.Clone(cp.Interfaces)
	for i := range cp.Interfaces {
		adv := cp.Interfaces[i].DHCPAdvancedV6
		if adv == nil || adv.AdvDHCP6KeyInfoStatementSecret == "" {
			continue
		}
		v6Copy := *adv
		v6Copy.AdvDHCP6KeyInfoStatementSecret = redactedValue
		cp.Interfaces[i].DHCPAdvancedV6 = &v6Copy
	}
}

// redactStatisticsServiceDetails returns a Statistics whose sensitive
// ServiceDetails values are replaced with the redaction marker. It delegates to
// analysis.RedactServiceDetails (the shared redaction primitive) and preserves a
// non-mutating contract: when nothing is redacted the input pointer is returned
// unchanged, so enrich can
// memoize a single Statistics across mixed redact=true and redact=false callers
// without leaking redacted values into the caller's data. Only when redaction
// occurs is the Statistics struct cloned around the already-cloned slice.
func redactStatisticsServiceDetails(stats *common.Statistics) *common.Statistics {
	if stats == nil {
		return nil
	}

	redacted, changed := analysis.RedactServiceDetails(stats.ServiceDetails)
	if !changed {
		return stats
	}

	out := *stats
	out.ServiceDetails = redacted
	return &out
}
