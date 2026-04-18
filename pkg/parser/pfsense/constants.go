package pfsense

// pfSense XML boolean constants.
//
// Value-based booleans are parsed via [shared.IsValueTrue] (accepts "1",
// "on", "yes", "true", "enabled"). Presence-based booleans use
// [opnsense.BoolFlag] instead (e.g., <disabled/>).
const (
	// xmlBoolYes is the pfSense XML value for affirmative options
	// encoded as an attribute (e.g., floating="yes"). Attribute
	// comparisons do not flow through FlexBool/BoolFlag since attributes
	// are decoded directly into string fields — use this constant for
	// direct equality checks.
	xmlBoolYes = "yes"
)
