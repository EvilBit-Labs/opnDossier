package analysis

import (
	"maps"
	"slices"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// serviceDetailRedactedValue is the placeholder written over sensitive
// ServiceDetails values. It MUST remain "[REDACTED]" to preserve byte-identical
// rendered output across the processor statistics path and the converter export
// path — both delegate to RedactServiceDetails, so this constant is the single
// source of truth for the ServiceDetails redaction marker. (The converter's
// separate redactedValue const governs unrelated field redactions — certs, API
// keys, WireGuard PSKs — and is not shared with this path.)
const serviceDetailRedactedValue = "[REDACTED]"

// snmpSensitiveDetailKeys lists the keys in ServiceStatistics.Details (for the
// SNMP service entry) whose values must be redacted on export. Adding a new
// sensitive key — for example, an SNMPv3 authentication password surfaced once
// the OPNsense net-snmp plugin namespace is parsed — is a one-line append here,
// shared by every caller of RedactServiceDetails.
//
// When adding a key here, also verify the sanitizer's password/private_key
// FieldPatterns in internal/sanitizer/rules.go cover the corresponding raw XML
// element, so the raw-XML path stays in sync with this analysis path
// (GOTCHAS §11.2).
//
//nolint:gochecknoglobals // immutable allowlist; mutation would be a security regression
var snmpSensitiveDetailKeys = []string{"community"}

// RedactServiceDetails returns a copy of details whose sensitive SNMP detail
// values are replaced with the redaction marker, plus a flag indicating whether
// any redaction was applied.
//
// The input is never mutated. When at least one SNMP entry carries a non-empty
// sensitive key the slice is cloned and only the affected per-element Details
// maps are cloned (clone-on-write); the second return is true. When nothing
// matches, the input slice is returned unchanged and the second return is false,
// letting non-mutating callers (e.g. the converter's memoized Statistics) skip
// allocating a new container.
//
// Every matching SNMP entry is redacted — not just the first — and every key in
// snmpSensitiveDetailKeys is redacted on each match. analysis.ComputeStatistics
// emits a single SNMP entry with a single sensitive key today, but a future
// schema change could surface multiple; leaving any in cleartext would be a
// security regression.
func RedactServiceDetails(details []common.ServiceStatistics) ([]common.ServiceStatistics, bool) {
	var matches []int
	for i := range details {
		if details[i].Name != ServiceNameSNMP {
			continue
		}
		if details[i].Details == nil {
			continue
		}
		if hasSensitiveSNMPKey(details[i].Details) {
			matches = append(matches, i)
		}
	}
	if len(matches) == 0 {
		return details, false
	}

	out := slices.Clone(details)
	for _, idx := range matches {
		out[idx].Details = maps.Clone(details[idx].Details)
		for _, key := range snmpSensitiveDetailKeys {
			// Value-aware guard: only replace when the value is present and
			// non-empty, so empty-string placeholders are not flipped to
			// "[REDACTED]" (which would shift the semantic meaning a downstream
			// consumer reads from the field).
			if v, ok := out[idx].Details[key]; ok && v != "" {
				out[idx].Details[key] = serviceDetailRedactedValue
			}
		}
	}

	return out, true
}

// hasSensitiveSNMPKey reports whether details carries any snmpSensitiveDetailKeys
// entry with a non-empty value.
func hasSensitiveSNMPKey(details map[string]string) bool {
	for _, key := range snmpSensitiveDetailKeys {
		if v, ok := details[key]; ok && v != "" {
			return true
		}
	}
	return false
}
