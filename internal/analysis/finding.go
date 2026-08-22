// Package analysis provides canonical types for security analysis findings and
// shared analysis functions (detection, statistics, rule comparison) used across
// the audit, compliance, and converter packages.
package analysis

import "slices"

// Severity represents the severity levels for findings.
type Severity string

// Severity level constants define the standard severity tiers for security findings.
const (
	// SeverityCritical indicates a critical severity finding.
	SeverityCritical Severity = "critical"
	// SeverityHigh indicates a high severity finding.
	SeverityHigh Severity = "high"
	// SeverityMedium indicates a medium severity finding.
	SeverityMedium Severity = "medium"
	// SeverityLow indicates a low severity finding.
	SeverityLow Severity = "low"
	// SeverityInfo indicates an informational finding.
	SeverityInfo Severity = "info"
)

// ValidSeverities returns a fresh copy of all valid severity values.
// Returns a new slice each call to prevent callers from mutating shared state.
func ValidSeverities() []Severity {
	return []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}
}

// String returns the string representation of the severity.
func (s Severity) String() string {
	return string(s)
}

// IsValidSeverity checks whether the given severity is a recognized value.
func IsValidSeverity(s Severity) bool {
	return slices.Contains(ValidSeverities(), s)
}

// Finding represents a canonical analysis finding that unifies the common
// fields across audit and compliance findings.
//
// JSON tag note: Recommendation, Component, and Reference intentionally lack
// omitempty to match compliance.Finding conventions, so downstream JSON
// consumers must tolerate empty-string values for those three keys.
type Finding struct {
	// Type categorizes the finding (e.g., "security", "performance", "compliance").
	Type string `json:"type"`
	// Severity indicates the severity level of the finding.
	Severity string `json:"severity,omitempty"`
	// Title is a brief description of the finding.
	Title string `json:"title"`
	// Description provides detailed information about the finding.
	Description string `json:"description"`
	// Recommendation suggests how to address the finding.
	Recommendation string `json:"recommendation"`
	// Component identifies the configuration component involved.
	Component string `json:"component"`
	// Reference provides additional information or documentation links.
	Reference string `json:"reference"`

	// Generic references and metadata
	// References contains related standard or control identifiers.
	References []string `json:"references,omitempty"`
	// Tags contains classification labels for the finding.
	Tags []string `json:"tags,omitempty"`
	// Metadata contains arbitrary key-value pairs for additional context.
	Metadata map[string]string `json:"metadata,omitempty"`
}
