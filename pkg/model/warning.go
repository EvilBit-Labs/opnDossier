package model

import "slices"

// Severity represents the severity level of a conversion warning. Severity is
// a triage signal, not a compliance verdict: consumers use it to decide
// presentation order and filtering, but a warning at any severity still
// indicates that something in the source configuration did not round-trip
// perfectly into the [CommonDevice] model.
//
// Severity values are case-sensitive typed strings. Use [IsValidSeverity] to
// check whether a given value is recognized.
type Severity string

// Severity level constants for conversion warnings.
//
// Converters should pick the level that best matches the consumer-visible
// impact of the issue:
//
//   - [SeverityCritical]: data loss or corruption that would cause downstream
//     analysis to be wrong. Reserved for cases that should fail loudly. No
//     converter currently emits this level — it is reserved for future
//     invariant-breaking conditions discovered during conversion.
//   - [SeverityHigh]: significant information missing or silently altered
//     (e.g., a firewall rule with an empty type, or an inbound NAT rule
//     missing its internal IP). Converters reserve this for conditions that
//     render the converted config functionally incorrect.
//   - [SeverityMedium]: partially preserved data, orphaned cross-references,
//     or missing but recoverable context (e.g., a rule missing its source
//     address, an orphan reservation pointing at no subnet).
//   - [SeverityLow]: best-effort gaps that do not impair analysis but are
//     worth surfacing (e.g., an unrecognized enum value that passes through
//     as a raw string).
//   - [SeverityInfo]: normal, expected observations (e.g., a Kea subnet
//     declared multiple pools and only the first is represented in the
//     unified DHCPScope). Not an error.
const (
	// SeverityCritical indicates data loss or corruption in the converted output.
	SeverityCritical Severity = "critical"
	// SeverityHigh indicates a material gap or silently altered behavior.
	SeverityHigh Severity = "high"
	// SeverityMedium indicates partial data preservation (e.g., truncated collections).
	SeverityMedium Severity = "medium"
	// SeverityLow indicates a cosmetic or best-effort conversion gap.
	SeverityLow Severity = "low"
	// SeverityInfo indicates an informational observation about the conversion.
	SeverityInfo Severity = "info"
)

// validSeverities is the package-level authoritative list of valid severity values.
var validSeverities = []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}

// ValidSeverities returns a fresh copy of all valid severity values.
// Returns a new slice each call to prevent callers from mutating shared state.
func ValidSeverities() []Severity {
	return append([]Severity{}, validSeverities...)
}

// String returns the string representation of the severity.
func (s Severity) String() string {
	return string(s)
}

// IsValidSeverity reports whether s is one of the recognized [Severity] values.
// Comparison is case-sensitive: "critical" is valid; "CRITICAL" is not.
//
// Implementation: delegates to [slices.Contains] against the package-level
// validSeverities slice so that both [ValidSeverities] and IsValidSeverity
// share a single source of truth. Adding a new [Severity] constant requires
// appending to validSeverities exactly once.
func IsValidSeverity(s Severity) bool {
	return slices.Contains(validSeverities, s)
}

// ConversionWarning represents a non-fatal issue encountered while converting
// a platform-specific configuration (OPNsense, pfSense) into the
// platform-agnostic [CommonDevice] model. Warnings never prevent conversion
// from completing; they signal data-quality issues (unrecognized enum values,
// truncated collections, orphan references, missing optional fields) that
// consumers may want to surface in reports, logs, or UI.
//
// Consumers receive warnings as a slice alongside the converted device:
//
//	device, warnings, err := opnsense.ConvertDocument(doc)
//	if err != nil {
//	    return err
//	}
//	for _, w := range warnings {
//	    log.Printf("[%s] %s: %s (value=%q)", w.Severity, w.Field, w.Message, w.Value)
//	}
//
// The order of warnings reflects the order in which the converter encountered
// them and is stable across runs for a given input, but is otherwise
// unspecified. Consumers should not rely on warnings being grouped by field
// or severity.
type ConversionWarning struct {
	// Field is the dot-path of the problematic field (e.g., "FirewallRules[0].Type").
	Field string
	// Value provides context to identify the affected config element (e.g., rule UUID,
	// gateway name, or certificate description). When the warning is about a missing or
	// empty field, this contains a sibling identifier rather than the empty field itself.
	// A few warnings instead store the raw input that triggered them (for example, the
	// multi-pool Kea warning stores the full newline-separated pool string), so
	// consumers should not assume Value is always a short identifier.
	Value string
	// Message is a human-readable description of the issue.
	Message string
	// Severity indicates the importance of the warning. See the Severity
	// constants for guidance on when to use each level.
	Severity Severity
}
