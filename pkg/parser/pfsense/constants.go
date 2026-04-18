package pfsense

import "strings"

// pfSense XML boolean constants.
// Value-based booleans use isPfSenseValueTrue() which accepts "1", "on", "yes".
// Presence-based booleans use BoolFlag instead (e.g., <disabled/>).
const (
	// xmlBoolYes is the pfSense XML value for affirmative options (e.g., floating="yes").
	xmlBoolYes = "yes"
)

// isPfSenseValueTrue reports whether s is a truthy value in pfSense XML.
// pfSense uses several encodings for value-based booleans: "1", "on", and "yes".
// This helper handles all three case-insensitively. For presence-based booleans
// (e.g., <disabled/>, <log/>), use opnsense.BoolFlag instead.
func isPfSenseValueTrue(s string) bool {
	switch strings.ToLower(s) {
	case "1", "on", "yes":
		return true
	default:
		return false
	}
}
