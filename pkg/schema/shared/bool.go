// Package shared provides schema-layer primitives reused across device-specific
// schemas (OPNsense, pfSense). The types and helpers here handle the common
// problem of XML-encoded configuration data whose textual encoding varies
// between sources even though the underlying semantics are identical.
package shared

import "strings"

// IsValueTrue reports whether s is a truthy XML value in the liberal
// vocabulary shared by OPNsense and pfSense.
//
// Recognised truthy values are "1", "on", "yes", "true", "enable", and
// "enabled". Matching is case-insensitive and leading/trailing whitespace
// is trimmed before comparison.
//
// Unknown values (e.g., "banana") return false — callers that need to
// distinguish unknown from falsy should also check [IsValueFalse].
func IsValueTrue(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "on", "yes", "true", "enable", "enabled":
		return true
	default:
		return false
	}
}

// IsValueFalse reports whether s is an explicitly falsy XML value in the
// liberal vocabulary.
//
// Recognised falsy values are "0", "off", "no", "false", "disable",
// "disabled", and the empty string (after trimming whitespace). Matching
// is case-insensitive.
//
// [IsValueTrue] and IsValueFalse are complementary but not exhaustive:
// unknown values return false from both so callers can decide how to
// handle them.
func IsValueFalse(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "0", "off", "no", "false", "disable", "disabled", "":
		return true
	default:
		return false
	}
}
