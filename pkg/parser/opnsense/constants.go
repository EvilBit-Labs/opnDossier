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

	// gatewayDynamic is the legacy <gateway> value for a gateway whose
	// address comes from the interface (DHCP, PPPoE and similar).
	gatewayDynamic = "dynamic"

	// gatewayDefaultWeight is the weight the firewall gives a gateway that
	// leaves <weight> out or empty.
	gatewayDefaultWeight = "1"

	// gatewayDefaultInterface is the interface the gateway model gives an item
	// that leaves <interface> out (Routing/Gateways.xml).
	gatewayDefaultInterface = "wan"
)
