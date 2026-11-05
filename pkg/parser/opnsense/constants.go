package opnsense

// OPNsense XML value-based boolean constants.
// Value-based booleans use "1" for enabled/true (e.g., <enable>1</enable>).
// Presence-based booleans use BoolFlag instead. A filter rule's <disabled> is not
// one: it is a *string tested with modelFlagSet (GOTCHAS 15.0).
const (
	// xmlBoolTrue is the OPNsense XML value for enabled/true in value-based boolean fields.
	xmlBoolTrue = "1"

	// packageTypePlugin identifies firmware plugin packages parsed from config.xml.
	packageTypePlugin = "plugin"

	// interfaceTypeGroup is the <type> of an interface group's entry under
	// <interfaces>.
	interfaceTypeGroup = "group"
)
