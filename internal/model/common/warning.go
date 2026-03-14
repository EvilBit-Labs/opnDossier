package common

import "github.com/EvilBit-Labs/opnDossier/internal/analysis"

// ConversionWarning represents a non-fatal issue encountered during conversion
// from a platform-specific schema to the platform-agnostic CommonDevice model.
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
	Severity analysis.Severity
}
