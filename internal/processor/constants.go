package processor

// Compatibility constants mirroring values from the internal/constants package.
// These are duplicated here to avoid import cycles while preserving existing APIs.
const (
	// NetworkAny represents the "any" network in firewall rules.
	NetworkAny = "any"

	// ProtocolHTTPS represents the HTTPS protocol identifier.
	ProtocolHTTPS = "https"

	// RuleTypePass represents a firewall pass rule.
	RuleTypePass = "pass"

	// FindingTypeSecurity identifies security-related audit findings.
	FindingTypeSecurity = "security"

	// ThemeLight specifies the light color theme for terminal output.
	ThemeLight = "light"
	// ThemeDark specifies the dark color theme for terminal output.
	ThemeDark = "dark"

	// StatusNotEnabled is the display string for disabled features.
	StatusNotEnabled = "❌"
	// StatusEnabled is the display string for enabled features.
	StatusEnabled = "✅"

	// NoConfigAvailable is the placeholder text when configuration data is missing.
	NoConfigAvailable = "*No configuration available*"
)
