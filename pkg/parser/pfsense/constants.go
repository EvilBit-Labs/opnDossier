package pfsense

// pfSense XML boolean constants.
//
// Value-based booleans are parsed via [shared.IsValueTrue] (accepts "1",
// "on", "yes", "true", "enable", "enabled" case-insensitively).
// Presence-based booleans use [opnsense.BoolFlag] instead (e.g., <disabled/>).
const (
	// xmlBoolYes is the pfSense XML value for affirmative options
	// encoded as an attribute (e.g., floating="yes"). Attribute
	// comparisons do not flow through FlexBool/BoolFlag since attributes
	// are decoded directly into string fields — use this constant for
	// direct equality checks.
	xmlBoolYes = "yes"
)

// ruleTypeMatch is the filter rule type that neither passes nor blocks.
// common.FirewallRuleType has no value for it.
const ruleTypeMatch = "match"

// stateTypeKeep is the state type filter.inc compiles a pass rule with when the
// rule leaves <statetype> out.
const stateTypeKeep = "keep state"
