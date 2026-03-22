// Package pfsense provides a pfSense-specific parser and converter that
// transforms pfsense.Document into the platform-agnostic CommonDevice.
package pfsense

// pfSense XML value-based boolean constants.
// Value-based booleans use "1" for enabled/true (e.g., <enable>1</enable>).
// Presence-based booleans use BoolFlag instead (e.g., <disabled/>).
const (
	// xmlBoolTrue is the pfSense XML value for enabled/true in value-based boolean fields.
	xmlBoolTrue = "1"

	// xmlBoolYes is the pfSense XML value for affirmative options (e.g., floating="yes").
	xmlBoolYes = "yes"
)
