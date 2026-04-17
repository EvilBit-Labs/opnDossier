package model

// Severity represents the severity level of a conversion warning.
type Severity string

// Severity level constants for conversion warnings.
const (
	// SeverityCritical indicates a critical severity warning.
	SeverityCritical Severity = "critical"
	// SeverityHigh indicates a high severity warning.
	SeverityHigh Severity = "high"
	// SeverityMedium indicates a medium severity warning.
	SeverityMedium Severity = "medium"
	// SeverityLow indicates a low severity warning.
	SeverityLow Severity = "low"
	// SeverityInfo indicates an informational warning.
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

// IsValidSeverity checks whether the given severity is a recognized value.
// Uses a switch statement to avoid allocating a slice on every call.
func IsValidSeverity(s Severity) bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	default:
		return false
	}
}

// ConversionWarning represents a non-fatal issue encountered during conversion
// from a platform-specific schema to the platform-agnostic CommonDevice model.
// Warnings do not prevent conversion from completing; they signal data-quality
// issues (e.g., unrecognized enum values, missing optional fields, truncated
// collections) that consumers may want to surface in reports or logs.
type ConversionWarning struct {
	// Field is the dot-path of the problematic field (e.g., "FirewallRules[0].Type").
	Field string
	// Value provides context to identify the affected config element (e.g., rule UUID,
	// gateway name, or certificate description). When the warning is about a missing or
	// empty field, this contains a sibling identifier rather than the empty field itself.
	Value string
	// Message is a human-readable description of the issue.
	Message string
	// Severity indicates the importance of the warning.
	Severity Severity
}
