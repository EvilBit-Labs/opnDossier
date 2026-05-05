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

// snmpSensitiveDetailKeys lists the keys in Statistics.ServiceDetails[].Details
// (for the SNMP service entry) whose values must be redacted on export.
// Adding a new sensitive key — for example, an SNMPv3 authentication password
// surfaced by a future analysis writer — is a one-line append here, not a
// rewrite of the redaction loop in redactStatisticsServiceDetails.
//
//nolint:gochecknoglobals // immutable allowlist; mutation would be a security regression
var snmpSensitiveDetailKeys = []string{"community"}

// EnrichForExport populates the read-only enrichment fields on data in place
// when they are nil: DeviceType (defaulting to OPNsense), Statistics, Analysis,
// SecurityAssessment, and PerformanceMetrics. ComplianceResults is left alone —
// it is populated externally by the audit handler.
//
// EnrichForExport is the explicit memoization entry point for callers preparing
// the same device for multiple format exports (e.g. JSON + YAML + Markdown).
// analysis.ComputeStatistics and analysis.ComputeAnalysis are linear-or-worse
// in the number of interfaces, rules, and services and dominate per-format
// export time; calling EnrichForExport once before the format loop avoids
// recomputing them per format. Subsequent prepareForExport calls reuse the
// populated fields and skip the heavy work.
//
// SECURITY: EnrichForExport does not redact sensitive fields. The resulting
// *CommonDevice carries plaintext secrets — most notably the SNMP community
// string in Statistics.ServiceDetails — because analysis.ComputeStatistics
// observes unredacted input by design (presence checks must see real values).
// Callers MUST NOT marshal or log the device directly after EnrichForExport.
// Always pass the device through prepareForExport (or a downstream Generator
// that calls prepareForExport) so the redact branch can produce a clone with
// the sensitive fields stripped.
//
// Redaction is per-export and is applied by prepareForExport on its shallow
// copy. The Statistics pointer produced here is reused by every subsequent
// prepareForExport call — the redact-path clones the Statistics struct before
// mutating ServiceDetails so a pre-enriched device is safe to share across
// redact=true and redact=false callers.
//
// CACHE INVALIDATION: EnrichForExport memoizes Statistics and Analysis as a
// snapshot of the device at call time. If the caller mutates a field that
// feeds those computations (e.g., device.SNMP.ROCommunity, FirewallRules,
// Interfaces) after calling EnrichForExport, the cached values go stale and
// subsequent exports will reflect the pre-mutation state. Re-call
// EnrichForExport (after first clearing the affected enrichment field) when
// the underlying configuration changes between exports.
//
// EnrichForExport is not safe for concurrent use on the same *CommonDevice.
// Callers preparing one device for parallel format exports must call
// EnrichForExport once before fanning out.
//
// EnrichForExport on a nil *CommonDevice is a documented no-op. Note that
// the downstream prepareForExport will still panic on nil; callers must guard
// nil at their own boundary (the JSONConverter / YAMLConverter wrappers and
// HybridGenerator.Generate already do).
//
// NOTE: analysis.ComputeStatistics and analysis.ComputeAnalysis intentionally
// receive the unredacted data so that presence checks (e.g., "is SNMP
// configured?") see real values.
func EnrichForExport(data *common.CommonDevice) {
	if data == nil {
		return
	}
	enrich(data)
}

// enrich populates the read-only enrichment fields on dst in place when nil.
// Callers must invoke enrich before any redaction so analysis.ComputeStatistics
// and analysis.ComputeAnalysis observe unredacted input. Callers must also
// guarantee dst is non-nil; nil-checking is the public-API caller's
// responsibility.
func enrich(dst *common.CommonDevice) {
	if dst.DeviceType == "" {
		dst.DeviceType = common.DeviceTypeOPNsense
	}
	if dst.Statistics == nil {
		dst.Statistics = analysis.ComputeStatistics(dst)
	}
	if dst.Analysis == nil {
		dst.Analysis = analysis.ComputeAnalysis(dst)
	}
	if dst.SecurityAssessment == nil {
		dst.SecurityAssessment = computeSecurityAssessment(dst.Statistics)
	}
	if dst.PerformanceMetrics == nil {
		dst.PerformanceMetrics = computePerformanceMetrics(dst.Statistics)
	}
}

// prepareForExport returns a shallow copy of the device with default DeviceType,
// Statistics, Analysis, SecurityAssessment, and PerformanceMetrics populated when absent.
// When redact is true, sensitive fields (passwords, private keys, API secrets, SNMP
// community strings, WireGuard PSKs, DHCPv6 authentication secrets) are replaced with
// [REDACTED]. When redact is false, sensitive fields are passed through as-is.
//
// prepareForExport does not mutate data. Callers that prepare the same device for
// multiple format exports should call EnrichForExport first to memoize the
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

// redactStatisticsServiceDetails returns a Statistics whose sensitive
// ServiceDetails values are replaced with the redaction marker. The input is
// not mutated: when redaction is required the function clones the Statistics
// struct, the ServiceDetails slice, and the affected per-element Details map.
// When no SNMP entry carries any sensitive key, the input pointer is returned
// unchanged. This non-mutating contract lets EnrichForExport memoize a single
// Statistics across mixed redact=true and redact=false callers without leaking
// redacted values into the caller's data.
//
// Every matching SNMP entry is redacted (not just the first), and every key
// in snmpSensitiveDetailKeys is redacted on each match.
// analysis.ComputeStatistics emits a single SNMP entry with a single sensitive
// key today, but a future schema change — SNMPv3 with both community and auth
// password, separate read/write communities, multi-instance agents — could
// surface multiple. Leaving any of them in cleartext would be a security
// regression.
func redactStatisticsServiceDetails(stats *common.Statistics) *common.Statistics {
	if stats == nil {
		return nil
	}

	var matches []int
	for i := range stats.ServiceDetails {
		if stats.ServiceDetails[i].Name != analysis.ServiceNameSNMP {
			continue
		}
		if stats.ServiceDetails[i].Details == nil {
			continue
		}
		if hasSensitiveSNMPKey(stats.ServiceDetails[i].Details) {
			matches = append(matches, i)
		}
	}
	if len(matches) == 0 {
		return stats
	}

	out := *stats
	out.ServiceDetails = slices.Clone(stats.ServiceDetails)
	for _, idx := range matches {
		out.ServiceDetails[idx].Details = maps.Clone(stats.ServiceDetails[idx].Details)
		for _, key := range snmpSensitiveDetailKeys {
			// Match the value-aware guard used by every other redactor in this
			// file (cert/CA private keys, API key secrets, WireGuard PSKs,
			// DHCPv6 secrets, HA password, SNMP ROCommunity): only replace when
			// the value is actually present and non-empty. Stops empty-string
			// placeholders from being flipped to "[REDACTED]", which would shift
			// the semantic meaning a downstream consumer reads from the field.
			if v, ok := out.ServiceDetails[idx].Details[key]; ok && v != "" {
				out.ServiceDetails[idx].Details[key] = redactedValue
			}
		}
	}

	return &out
}

func hasSensitiveSNMPKey(details map[string]string) bool {
	for _, key := range snmpSensitiveDetailKeys {
		if v, ok := details[key]; ok && v != "" {
			return true
		}
	}
	return false
}
