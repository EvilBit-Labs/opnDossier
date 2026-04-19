package converter

import (
	"maps"
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

// prepareForExport returns a shallow copy of the device with default DeviceType,
// Statistics, Analysis, SecurityAssessment, and PerformanceMetrics populated when absent.
// When redact is true, sensitive fields (passwords, private keys, API secrets, SNMP
// community strings, WireGuard PSKs, DHCPv6 authentication secrets) are replaced with
// [REDACTED]. When redact is false, sensitive fields are passed through as-is.
//
// NOTE: analysis.ComputeStatistics and analysis.ComputeAnalysis intentionally receive
// the original unredacted data so that presence checks (e.g., "is SNMP configured?")
// see real values.
func prepareForExport(data *common.CommonDevice, redact bool) *common.CommonDevice {
	cp := *data

	if cp.DeviceType == "" {
		cp.DeviceType = common.DeviceTypeOPNsense
	}

	if redact {
		redactSensitiveFields(&cp)
	}

	if cp.Statistics == nil {
		cp.Statistics = analysis.ComputeStatistics(data)
	}

	if redact {
		redactStatisticsServiceDetails(cp.Statistics)
	}

	if cp.Analysis == nil {
		cp.Analysis = analysis.ComputeAnalysis(data)
	}

	if cp.SecurityAssessment == nil {
		cp.SecurityAssessment = computeSecurityAssessment(cp.Statistics)
	}

	if cp.PerformanceMetrics == nil {
		cp.PerformanceMetrics = computePerformanceMetrics(cp.Statistics)
	}

	// ComplianceChecks is populated externally by the audit handler;
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
	// HA password
	if cp.HighAvailability.Password != "" {
		cp.HighAvailability.Password = redactedValue
	}

	// Certificate private keys
	if len(cp.Certificates) > 0 {
		cp.Certificates = slices.Clone(cp.Certificates)
		for i := range cp.Certificates {
			if cp.Certificates[i].PrivateKey != "" {
				cp.Certificates[i].PrivateKey = redactedValue
			}
		}
	}

	// CA private keys (present for locally-created CAs)
	if len(cp.CAs) > 0 {
		cp.CAs = slices.Clone(cp.CAs)
		for i := range cp.CAs {
			if cp.CAs[i].PrivateKey != "" {
				cp.CAs[i].PrivateKey = redactedValue
			}
		}
	}

	// API key secrets
	if len(cp.Users) > 0 {
		cp.Users = slices.Clone(cp.Users)
		for i := range cp.Users {
			if len(cp.Users[i].APIKeys) > 0 {
				cp.Users[i].APIKeys = slices.Clone(cp.Users[i].APIKeys)
				for j := range cp.Users[i].APIKeys {
					if cp.Users[i].APIKeys[j].Secret != "" {
						cp.Users[i].APIKeys[j].Secret = redactedValue
					}
				}
			}
		}
	}

	// SNMP community string
	if cp.SNMP.ROCommunity != "" {
		cp.SNMP.ROCommunity = redactedValue
	}

	// WireGuard pre-shared keys
	if len(cp.VPN.WireGuard.Clients) > 0 {
		cp.VPN.WireGuard.Clients = slices.Clone(cp.VPN.WireGuard.Clients)
		for i := range cp.VPN.WireGuard.Clients {
			if cp.VPN.WireGuard.Clients[i].PSK != "" {
				cp.VPN.WireGuard.Clients[i].PSK = redactedValue
			}
		}
	}

	// DHCPv6 authentication secrets
	if len(cp.DHCP) > 0 {
		cp.DHCP = slices.Clone(cp.DHCP)
		for i := range cp.DHCP {
			if cp.DHCP[i].AdvancedV6 != nil && cp.DHCP[i].AdvancedV6.AdvDHCP6KeyInfoStatementSecret != "" {
				v6Copy := *cp.DHCP[i].AdvancedV6
				v6Copy.AdvDHCP6KeyInfoStatementSecret = redactedValue
				cp.DHCP[i].AdvancedV6 = &v6Copy
			}
		}
	}
}

// redactStatisticsServiceDetails replaces sensitive values in Statistics.ServiceDetails
// with the redaction marker. This is needed because analysis.ComputeStatistics intentionally
// receives the original unredacted data for accurate presence detection, but the
// resulting ServiceDetails may contain sensitive values (e.g., SNMP community strings).
func redactStatisticsServiceDetails(stats *common.Statistics) {
	if stats == nil {
		return
	}

	for i := range stats.ServiceDetails {
		if stats.ServiceDetails[i].Name == analysis.ServiceNameSNMP && stats.ServiceDetails[i].Details != nil {
			if _, ok := stats.ServiceDetails[i].Details["community"]; ok {
				// Deep-copy the map to avoid mutating shared state.
				stats.ServiceDetails[i].Details = maps.Clone(stats.ServiceDetails[i].Details)
				stats.ServiceDetails[i].Details["community"] = redactedValue
			}
		}
	}
}
