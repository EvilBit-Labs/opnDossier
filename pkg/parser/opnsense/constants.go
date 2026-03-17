package opnsense

// OPNsense XML value-based boolean constants.
// Value-based booleans use "1" for enabled/true (e.g., <enable>1</enable>).
// Presence-based booleans use BoolFlag instead (e.g., <disabled/>).
const (
	// xmlBoolTrue is the OPNsense XML value for enabled/true in value-based boolean fields.
	xmlBoolTrue = "1"

	// xmlBoolYes is the OPNsense XML value for affirmative options (e.g., floating="yes").
	xmlBoolYes = "yes"

	// packageTypePlugin identifies firmware plugin packages parsed from config.xml.
	packageTypePlugin = "plugin"
)
