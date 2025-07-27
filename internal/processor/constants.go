package processor

// Re-export constants from the constants package for backward compatibility.
// This allows existing code to continue working while avoiding import cycles.
const (
	// Network constants.
	NetworkAny = "any"

	// Protocol constants.
	ProtocolHTTPS = "https"

	// Rule type constants.
	RuleTypePass = "pass"

	// Finding types.
	FindingTypeSecurity = "security"

	// Theme constants.
	ThemeLight = "light"
	ThemeDark  = "dark"

	// Status display constants.
	StatusNotEnabled = "❌"
	StatusEnabled    = "✅"

	// Configuration availability.
	NoConfigAvailable = "*No configuration available*"
)
