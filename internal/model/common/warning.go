package common

import "github.com/EvilBit-Labs/opnDossier/internal/analysis"

// ConversionWarning represents a non-fatal issue encountered during conversion
// from a platform-specific schema to the platform-agnostic CommonDevice model.
type ConversionWarning struct {
	// Field is the dot-path of the problematic field (e.g., "FirewallRules[0].Type").
	Field string
	// Value is the problematic value encountered.
	Value string
	// Message is a human-readable description of the issue.
	Message string
	// Severity indicates the importance of the warning.
	Severity analysis.Severity
}
