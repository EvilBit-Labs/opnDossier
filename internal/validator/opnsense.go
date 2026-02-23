// Package validator provides comprehensive validation functionality for OPNsense configuration files.
// It validates system settings, network interfaces, DHCP server configuration, firewall rules,
// NAT rules, user and group settings, and sysctl tunables to ensure configuration integrity
// and prevent deployment of invalid configurations.
package validator

import (
	"fmt"
	"maps"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

// ValidationError represents a configuration validation error.
type ValidationError struct {
	Field   string
	Message string
}

// Error returns a formatted string describing the validation error, including the field name and message.
func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s", e.Field, e.Message)
}

// ValidateOpnSenseDocument validates an entire OPNsense configuration document and returns all detected validation errors.
// It checks system settings, network interfaces, DHCP server, firewall rules, NAT rules, users and groups, and sysctl tunables for correctness and consistency.
func ValidateOpnSenseDocument(o *schema.OpnSenseDocument) []ValidationError {
	if o == nil {
		return []ValidationError{{
			Field:   "document",
			Message: "OPNsense document is nil",
		}}
	}

	var errors []ValidationError

	// Validate system configuration
	errors = append(errors, validateSystem(&o.System)...)

	// Validate interfaces
	errors = append(errors, validateInterfaces(&o.Interfaces)...)

	// Validate DHCP configuration
	errors = append(errors, validateDhcpd(&o.Dhcpd, &o.Interfaces)...)

	// Validate filter rules
	errors = append(errors, validateFilter(&o.Filter, &o.Interfaces)...)

	// Validate NAT configuration
	errors = append(errors, validateNat(&o.Nat)...)

	// Validate system users and groups
	errors = append(errors, validateUsersAndGroups(&o.System)...)

	// Validate sysctl items
	errors = append(errors, validateSysctl(o.Sysctl)...)

	return errors
}

// validateSystem checks the system-level configuration fields for required values and valid formats.
// It returns a slice of ValidationError for any invalid or missing system configuration fields, including hostname, domain, timezone, optimization, web GUI protocol, power management modes, and bogons interval.
func validateSystem(system *schema.System) []ValidationError {
	var errors []ValidationError

	// Hostname is required and must be valid
	if system.Hostname == "" {
		errors = append(errors, ValidationError{
			Field:   "system.hostname",
			Message: "hostname is required",
		})
	} else if !isValidHostname(system.Hostname) {
		errors = append(errors, ValidationError{
			Field:   "system.hostname",
			Message: fmt.Sprintf("hostname '%s' contains invalid characters", system.Hostname),
		})
	}

	// Domain is required
	if system.Domain == "" {
		errors = append(errors, ValidationError{
			Field:   "system.domain",
			Message: "domain is required",
		})
	}

	// Validate timezone format
	if system.Timezone != "" && !isValidTimezone(system.Timezone) {
		errors = append(errors, ValidationError{
			Field:   "system.timezone",
			Message: "invalid timezone format: " + system.Timezone,
		})
	}

	// Validate optimization setting
	if system.Optimization != "" {
		if _, ok := constants.ValidOptimizationModes[system.Optimization]; !ok {
			errors = append(errors, ValidationError{
				Field: "system.optimization",
				Message: fmt.Sprintf(
					"optimization '%s' must be one of: %v",
					system.Optimization,
					slices.Sorted(maps.Keys(constants.ValidOptimizationModes)),
				),
			})
		}
	}

	// Validate webgui protocol
	validProtocols := []string{"http", "https"}
	if system.WebGUI.Protocol != "" && !contains(validProtocols, system.WebGUI.Protocol) {
		errors = append(errors, ValidationError{
			Field:   "system.webgui.protocol",
			Message: fmt.Sprintf("protocol '%s' must be one of: %v", system.WebGUI.Protocol, validProtocols),
		})
	}

	// Validate power management modes
	validPowerdList := slices.Sorted(maps.Keys(constants.ValidPowerdModes))

	if system.PowerdACMode != "" {
		if _, ok := constants.ValidPowerdModes[system.PowerdACMode]; !ok {
			errors = append(errors, ValidationError{
				Field:   "system.powerd_ac_mode",
				Message: fmt.Sprintf("power mode '%s' must be one of: %v", system.PowerdACMode, validPowerdList),
			})
		}
	}

	if system.PowerdBatteryMode != "" {
		if _, ok := constants.ValidPowerdModes[system.PowerdBatteryMode]; !ok {
			errors = append(errors, ValidationError{
				Field:   "system.powerd_battery_mode",
				Message: fmt.Sprintf("power mode '%s' must be one of: %v", system.PowerdBatteryMode, validPowerdList),
			})
		}
	}

	if system.PowerdNormalMode != "" {
		if _, ok := constants.ValidPowerdModes[system.PowerdNormalMode]; !ok {
			errors = append(errors, ValidationError{
				Field:   "system.powerd_normal_mode",
				Message: fmt.Sprintf("power mode '%s' must be one of: %v", system.PowerdNormalMode, validPowerdList),
			})
		}
	}

	// Validate bogons interval
	validBogonsIntervals := []string{"monthly", "weekly", "daily", "never"}
	if system.Bogons.Interval != "" && !contains(validBogonsIntervals, system.Bogons.Interval) {
		errors = append(errors, ValidationError{
			Field: "system.bogons.interval",
			Message: fmt.Sprintf(
				"bogons interval '%s' must be one of: %v",
				system.Bogons.Interval,
				validBogonsIntervals,
			),
		})
	}

	return errors
}

// validateInterfaces validates all configured network interfaces and returns any validation errors found.
func validateInterfaces(interfaces *schema.Interfaces) []ValidationError {
	var errors []ValidationError

	if interfaces == nil || interfaces.Items == nil {
		return errors
	}

	// Validate each configured interface
	for name, iface := range interfaces.Items {
		ifaceCopy := iface // Create a copy to get a pointer
		errors = append(errors, validateInterface(&ifaceCopy, name, interfaces)...)
	}

	return errors
}

// validateInterface checks a single network interface configuration for valid IP address types and formats, subnet masks, MTU range, and required fields for track6 IPv6 addressing.
// It returns a slice of ValidationError for any invalid or missing configuration fields.
func validateInterface(iface *schema.Interface, name string, interfaces *schema.Interfaces) []ValidationError {
	var errors []ValidationError

	if iface == nil {
		return errors
	}

	validInterfaceNames := collectInterfaceNames(interfaces)

	errors = append(errors, validateIPAddress(iface, name)...)                   // IP Address Validation
	errors = append(errors, validateIPv6Address(iface, name)...)                 // IPv6 Address Validation
	errors = append(errors, validateSubnet(iface, name)...)                      // Subnet Mask Validation
	errors = append(errors, validateMTU(iface, name)...)                         // MTU Validation
	errors = append(errors, validateTrack6(iface, validInterfaceNames, name)...) // Track6 Specific Validation

	return errors
}

// validateIPAddress validates the IP address of an interface.
func validateIPAddress(iface *schema.Interface, name string) []ValidationError {
	var errors []ValidationError
	if iface.IPAddr != "" {
		validIPTypes := []string{"dhcp", "dhcp6", "track6", "none"}
		if !contains(validIPTypes, iface.IPAddr) && !isValidIP(iface.IPAddr) {
			errors = append(errors, ValidationError{
				Field: fmt.Sprintf("interfaces.%s.ipaddr", name),
				Message: fmt.Sprintf(
					"IP address '%s' must be a valid IP address or one of: %v",
					iface.IPAddr,
					validIPTypes,
				),
			})
		}
	}
	return errors
}

// validateIPv6Address validates the IPv6 address of an interface.
func validateIPv6Address(iface *schema.Interface, name string) []ValidationError {
	var errors []ValidationError
	if iface.IPAddrv6 != "" {
		validIPv6Types := []string{"dhcp6", "slaac", "track6", "none"}
		if !contains(validIPv6Types, iface.IPAddrv6) && !isValidIPv6(iface.IPAddrv6) {
			errors = append(errors, ValidationError{
				Field: fmt.Sprintf("interfaces.%s.ipaddrv6", name),
				Message: fmt.Sprintf(
					"IPv6 address '%s' must be a valid IPv6 address or one of: %v",
					iface.IPAddrv6,
					validIPv6Types,
				),
			})
		}
	}
	return errors
}

// validateSubnet validates the subnet mask of an interface.
func validateSubnet(iface *schema.Interface, name string) []ValidationError {
	var errors []ValidationError
	if iface.Subnet != "" {
		if subnet, err := strconv.Atoi(iface.Subnet); err != nil || subnet < 0 || subnet > 32 {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("interfaces.%s.subnet", name),
				Message: fmt.Sprintf("subnet mask '%s' must be a valid subnet mask (0-32)", iface.Subnet),
			})
		}
	}
	if iface.Subnetv6 != "" {
		if subnet, err := strconv.Atoi(iface.Subnetv6); err != nil || subnet < 0 || subnet > 128 {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("interfaces.%s.subnetv6", name),
				Message: fmt.Sprintf("IPv6 subnet mask '%s' must be a valid IPv6 subnet mask (0-128)", iface.Subnetv6),
			})
		}
	}
	return errors
}

// validateMTU validates the MTU of an interface.
func validateMTU(iface *schema.Interface, name string) []ValidationError {
	var errors []ValidationError
	if iface.MTU != "" {
		if mtu, err := strconv.Atoi(iface.MTU); err != nil || mtu < constants.MinMTU || mtu > constants.MaxMTU {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("interfaces.%s.mtu", name),
				Message: fmt.Sprintf("MTU '%s' must be a valid MTU (68-9000)", iface.MTU),
			})
		}
	}
	return errors
}

// validateTrack6 performs cross-field validation for track6 configurations.
func validateTrack6(iface *schema.Interface, validInterfaceNames map[string]struct{}, name string) []ValidationError {
	var errors []ValidationError
	if iface.IPAddrv6 == "track6" {
		if iface.Track6Interface == "" {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("interfaces.%s.track6-interface", name),
				Message: "track6-interface is required when using track6 IPv6 addressing",
			})
		} else {
			// Validate that the referenced interface exists
			if _, exists := validInterfaceNames[iface.Track6Interface]; !exists {
				// Create a sorted slice of interface names for error message
				interfaceList := make([]string, 0, len(validInterfaceNames))
				for interfaceName := range validInterfaceNames {
					interfaceList = append(interfaceList, interfaceName)
				}

				errors = append(errors, ValidationError{
					Field: fmt.Sprintf("interfaces.%s.track6-interface", name),
					Message: fmt.Sprintf(
						"track6-interface '%s' must reference a configured interface: %v",
						iface.Track6Interface,
						interfaceList,
					),
				})
			}
		}

		if iface.Track6PrefixID == "" {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("interfaces.%s.track6-prefix-id", name),
				Message: "track6-prefix-id is required when using track6 IPv6 addressing",
			})
		}
	}
	return errors
}

// It iterates over the interface map and validates each DHCP block that exists in the dhcpd section.
// Returns a slice of ValidationError for any invalid or inconsistent DHCP configuration fields.
func validateDhcpd(dhcpd *schema.Dhcpd, interfaces *schema.Interfaces) []ValidationError {
	var errors []ValidationError

	if dhcpd == nil || dhcpd.Items == nil {
		return errors
	}

	// Get valid interface names for cross-validation
	ifaceSet := collectInterfaceNames(interfaces)

	// Validate each DHCP interface configuration
	for name, cfg := range dhcpd.Items {
		errors = append(errors, validateDhcpdInterface(name, cfg, ifaceSet)...)
	}

	return errors
}

// validateDhcpdInterface checks a DHCP interface configuration for validity, ensuring the referenced interface exists and that any specified DHCP range addresses are valid IPs with the 'from' address less than the 'to' address.
//
// Returns a slice of ValidationError for any detected issues.
func validateDhcpdInterface(name string, cfg schema.DhcpdInterface, ifaceSet map[string]struct{}) []ValidationError {
	var errors []ValidationError

	// Validate that the interface exists in the configuration
	if _, exists := ifaceSet[name]; !exists {
		// Create a sorted slice of interface names for error message
		interfaceList := make([]string, 0, len(ifaceSet))
		for interfaceName := range ifaceSet {
			interfaceList = append(interfaceList, interfaceName)
		}

		errors = append(errors, ValidationError{
			Field:   "dhcpd." + name,
			Message: fmt.Sprintf("DHCP interface '%s' must reference a configured interface: %v", name, interfaceList),
		})
	}

	// Validate DHCP range if either from or to is set
	if cfg.Range.From != "" || cfg.Range.To != "" {
		if cfg.Range.From != "" && !isValidIP(cfg.Range.From) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("dhcpd.%s.range.from", name),
				Message: fmt.Sprintf("DHCP range 'from' address '%s' must be a valid IP address", cfg.Range.From),
			})
		}

		if cfg.Range.To != "" && !isValidIP(cfg.Range.To) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("dhcpd.%s.range.to", name),
				Message: fmt.Sprintf("DHCP range 'to' address '%s' must be a valid IP address", cfg.Range.To),
			})
		}

		// Cross-validation: from address should be less than to address
		if isValidIP(cfg.Range.From) && isValidIP(cfg.Range.To) {
			fromIP := net.ParseIP(cfg.Range.From).To4()

			toIP := net.ParseIP(cfg.Range.To).To4()
			if fromIP != nil && toIP != nil {
				// Compare byte by byte
				for i := range 4 {
					if fromIP[i] > toIP[i] {
						errors = append(errors, ValidationError{
							Field: fmt.Sprintf("dhcpd.%s.range", name),
							Message: fmt.Sprintf(
								"DHCP range 'from' address (%s) must be less than 'to' address (%s)",
								cfg.Range.From,
								cfg.Range.To,
							),
						})

						break
					} else if fromIP[i] < toIP[i] {
						break
					}
				}
			}
		}
	}

	return errors
}

// collectInterfaceNames returns every key from the interfaces map as a set.
func collectInterfaceNames(ifaces *schema.Interfaces) map[string]struct{} {
	interfaceNames := make(map[string]struct{})

	if ifaces != nil && ifaces.Items != nil {
		for name := range ifaces.Items {
			interfaceNames[name] = struct{}{}
		}
	}

	return interfaceNames
}

// validateFilter checks each firewall filter rule for valid type, IP protocol, interface, and source network values.
// stripIPSuffix removes the trailing "ip" suffix from a network string, if present.
func stripIPSuffix(network string) string {
	result, _ := strings.CutSuffix(network, "ip")
	return result
}

// isReservedNetwork returns true if the provided network string is a reserved keyword such as "any", "lan", "wan", "localhost", "loopback", or "(self)".
func isReservedNetwork(network string) bool {
	reserved := []string{"any", "lan", "wan", "localhost", "loopback", "(self)"}
	return slices.Contains(reserved, network)
}

// validateFilter checks each firewall filter rule for valid types, protocols, interface references, and network specifications.
// It returns a list of validation errors for any rule fields that are invalid or reference non-existent interfaces.
func validateFilter(filter *schema.Filter, interfaces *schema.Interfaces) []ValidationError {
	var errors []ValidationError

	// Collect valid interface names from the configuration
	validInterfaceNames := collectInterfaceNames(interfaces)

	for i, rule := range filter.Rule {
		// Validate rule type
		validTypes := []string{"pass", "block", "reject"}
		if rule.Type != "" && !contains(validTypes, rule.Type) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("filter.rule[%d].type", i),
				Message: fmt.Sprintf("rule type '%s' must be one of: %v", rule.Type, validTypes),
			})
		}

		// Validate IP protocol
		validIPProtocols := []string{"inet", "inet6"}
		if rule.IPProtocol != "" && !contains(validIPProtocols, rule.IPProtocol) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("filter.rule[%d].ipprotocol", i),
				Message: fmt.Sprintf("IP protocol '%s' must be one of: %v", rule.IPProtocol, validIPProtocols),
			})
		}

		// Validate interface against configured interfaces
		if !rule.Interface.IsEmpty() {
			for _, iface := range rule.Interface {
				if _, exists := validInterfaceNames[iface]; !exists {
					// Create a sorted slice of interface names for error message
					interfaceList := make([]string, 0, len(validInterfaceNames))
					for name := range validInterfaceNames {
						interfaceList = append(interfaceList, name)
					}

					errors = append(errors, ValidationError{
						Field: fmt.Sprintf("filter.rule[%d].interface", i),
						Message: fmt.Sprintf(
							"interface '%s' must be one of the configured interfaces: %v",
							iface,
							interfaceList,
						),
					})
				}
			}
		}

		// Validate source network
		network := stripIPSuffix(rule.Source.Network)
		if rule.Source.Network != "" && !isReservedNetwork(network) && !isValidCIDR(rule.Source.Network) {
			if _, exists := validInterfaceNames[network]; !exists {
				errors = append(errors, ValidationError{
					Field: fmt.Sprintf("filter.rule[%d].source.network", i),
					Message: fmt.Sprintf(
						"source network '%s' must be a valid CIDR, reserved word, or an interface key followed by 'ip'",
						rule.Source.Network,
					),
				})
			}
		}

		// Validate source address (IP/CIDR or alias)
		if rule.Source.Address != "" && !isValidCIDR(rule.Source.Address) && net.ParseIP(rule.Source.Address) == nil {
			// Not a valid IP or CIDR — could be an alias, which is acceptable.
			// Only flag if it looks like a malformed IP/CIDR attempt:
			// "/" = CIDR notation, ":" = IPv6, or digits-and-dots only (failed IPv4)
			if looksLikeMalformedIP(rule.Source.Address) {
				errors = append(errors, ValidationError{
					Field: fmt.Sprintf("filter.rule[%d].source.address", i),
					Message: fmt.Sprintf(
						"source address '%s' appears to be a malformed IP/CIDR",
						rule.Source.Address,
					),
				})
			}
		}

		// Validate destination network
		destNetwork := stripIPSuffix(rule.Destination.Network)
		if rule.Destination.Network != "" && !isReservedNetwork(destNetwork) && !isValidCIDR(rule.Destination.Network) {
			if _, exists := validInterfaceNames[destNetwork]; !exists {
				errors = append(errors, ValidationError{
					Field: fmt.Sprintf("filter.rule[%d].destination.network", i),
					Message: fmt.Sprintf(
						"destination network '%s' must be a valid CIDR, reserved word, or an interface key followed by 'ip'",
						rule.Destination.Network,
					),
				})
			}
		}

		// Validate destination address (IP/CIDR or alias)
		if rule.Destination.Address != "" && !isValidCIDR(rule.Destination.Address) &&
			net.ParseIP(rule.Destination.Address) == nil {
			if looksLikeMalformedIP(rule.Destination.Address) {
				errors = append(errors, ValidationError{
					Field: fmt.Sprintf("filter.rule[%d].destination.address", i),
					Message: fmt.Sprintf(
						"destination address '%s' appears to be a malformed IP/CIDR",
						rule.Destination.Address,
					),
				})
			}
		}

		// Validate source port
		if rule.Source.Port != "" && !isValidPortOrRange(rule.Source.Port) {
			errors = append(errors, ValidationError{
				Field: fmt.Sprintf("filter.rule[%d].source.port", i),
				Message: fmt.Sprintf(
					"source port '%s' is not a valid port (1-65535) or range (low-high)",
					rule.Source.Port,
				),
			})
		}

		// Validate destination port
		if rule.Destination.Port != "" && !isValidPortOrRange(rule.Destination.Port) {
			errors = append(errors, ValidationError{
				Field: fmt.Sprintf("filter.rule[%d].destination.port", i),
				Message: fmt.Sprintf(
					"destination port '%s' is not a valid port (1-65535) or range (low-high)",
					rule.Destination.Port,
				),
			})
		}

		// Validate Source mutual exclusivity (Any, Network, Address)
		sourceFieldCount := 0
		if rule.Source.IsAny() {
			sourceFieldCount++
		}
		if rule.Source.Network != "" {
			sourceFieldCount++
		}
		if rule.Source.Address != "" {
			sourceFieldCount++
		}
		if sourceFieldCount > 1 {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("filter.rule[%d].source", i),
				Message: "source can only specify one of: any, network, or address",
			})
		}

		// Validate Destination mutual exclusivity (Any, Network, Address)
		destFieldCount := 0
		if rule.Destination.IsAny() {
			destFieldCount++
		}
		if rule.Destination.Network != "" {
			destFieldCount++
		}
		if rule.Destination.Address != "" {
			destFieldCount++
		}
		if destFieldCount > 1 {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("filter.rule[%d].destination", i),
				Message: "destination can only specify one of: any, network, or address",
			})
		}

		// Validate floating rule constraints
		if rule.Floating == "yes" && rule.Direction == "" {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("filter.rule[%d].direction", i),
				Message: "direction is required for floating rules",
			})
		}
		validDirections := []string{"in", "out", "any"}
		if rule.Direction != "" && !contains(validDirections, rule.Direction) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("filter.rule[%d].direction", i),
				Message: fmt.Sprintf("direction '%s' must be one of: %v", rule.Direction, validDirections),
			})
		}

		// Validate state type
		validStateTypes := []string{"keep state", "sloppy state", "synproxy state", "none"}
		if rule.StateType != "" && !contains(validStateTypes, rule.StateType) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("filter.rule[%d].statetype", i),
				Message: fmt.Sprintf("state type '%s' must be one of: %v", rule.StateType, validStateTypes),
			})
		}

		// Validate max-src-conn-rate format (e.g., "15/5")
		if rule.MaxSrcConnRate != "" && !isValidConnRateFormat(rule.MaxSrcConnRate) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("filter.rule[%d].max-src-conn-rate", i),
				Message: "max-src-conn-rate must be in format 'connections/seconds' (e.g., '15/5')",
			})
		}
	}

	return errors
}

// validateNat checks NAT configuration including outbound mode and inbound rule fields.
// It returns a slice of ValidationError for any invalid values detected.
func validateNat(nat *schema.Nat) []ValidationError {
	var errors []ValidationError

	// Validate outbound NAT mode
	validModes := []string{"automatic", "hybrid", "advanced", "disabled"}
	if nat.Outbound.Mode != "" && !contains(validModes, nat.Outbound.Mode) {
		errors = append(errors, ValidationError{
			Field:   "nat.outbound.mode",
			Message: fmt.Sprintf("NAT outbound mode '%s' must be one of: %v", nat.Outbound.Mode, validModes),
		})
	}

	// Validate inbound NAT rules
	validReflectionModes := []string{"enable", "disable", "purenat"}
	for i, rule := range nat.Inbound {
		if rule.NATReflection != "" && !contains(validReflectionModes, rule.NATReflection) {
			errors = append(errors, ValidationError{
				Field: fmt.Sprintf("nat.inbound[%d].natreflection", i),
				Message: fmt.Sprintf(
					"NAT reflection mode '%s' must be one of: %v",
					rule.NATReflection,
					validReflectionModes,
				),
			})
		}
	}

	return errors
}

// validateUsersAndGroups checks system users and groups for required fields, uniqueness, valid IDs, valid scopes, and correct group references.
// It returns a slice of ValidationError for any invalid or inconsistent user or group entries.
func validateUsersAndGroups(system *schema.System) []ValidationError {
	var errors []ValidationError

	// Track group names and GIDs to ensure uniqueness
	groupNames := make(map[string]bool)
	groupGIDs := make(map[string]bool)

	errors = append(errors, validateGroups(system.Group, groupNames, groupGIDs)...)
	errors = append(errors, validateUsers(system.User, groupNames)...)

	return errors
}

// validateGroups validates all groups and tracks names and GIDs for uniqueness.
func validateGroups(groups []schema.Group, groupNames, groupGIDs map[string]bool) []ValidationError {
	var errors []ValidationError

	for i, group := range groups {
		errors = append(errors, validateGroupName(group, i, groupNames)...)
		errors = append(errors, validateGroupGID(group, i, groupGIDs)...)
		errors = append(errors, validateGroupScope(group, i)...)
	}

	return errors
}

// validateGroupName validates group name requirements and uniqueness.
func validateGroupName(group schema.Group, index int, groupNames map[string]bool) []ValidationError {
	var errors []ValidationError

	switch {
	case group.Name == "":
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.group[%d].name", index),
			Message: "group name is required",
		})
	case groupNames[group.Name]:
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.group[%d].name", index),
			Message: fmt.Sprintf("group name '%s' must be unique", group.Name),
		})
	default:
		groupNames[group.Name] = true
	}

	return errors
}

// validateGroupGID validates group GID requirements and uniqueness.
func validateGroupGID(group schema.Group, index int, groupGIDs map[string]bool) []ValidationError {
	var errors []ValidationError

	if group.Gid == "" {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.group[%d].gid", index),
			Message: "group GID is required",
		})
		return errors
	}

	gid, err := strconv.Atoi(group.Gid)
	if err != nil || gid < 0 {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.group[%d].gid", index),
			Message: fmt.Sprintf("GID '%s' must be a positive integer", group.Gid),
		})
		return errors
	}

	if groupGIDs[group.Gid] {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.group[%d].gid", index),
			Message: fmt.Sprintf("group GID '%s' must be unique", group.Gid),
		})
		return errors
	}

	groupGIDs[group.Gid] = true
	return errors
}

// validateGroupScope validates group scope requirements.
func validateGroupScope(group schema.Group, index int) []ValidationError {
	var errors []ValidationError

	if group.Scope == "" {
		return errors
	}

	validScopes := []string{"system", "local"}
	if !contains(validScopes, group.Scope) {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.group[%d].scope", index),
			Message: fmt.Sprintf("group scope '%s' must be one of: %v", group.Scope, validScopes),
		})
	}

	return errors
}

// validateUsers validates all users.
func validateUsers(users []schema.User, groupNames map[string]bool) []ValidationError {
	var errors []ValidationError
	userNames := make(map[string]bool)
	userUIDs := make(map[string]bool)

	for i, user := range users {
		errors = append(errors, validateUserName(user, i, userNames)...)
		errors = append(errors, validateUserUID(user, i, userUIDs)...)
		errors = append(errors, validateUserGroupMembership(user, i, groupNames)...)
		errors = append(errors, validateUserScope(user, i)...)
	}

	return errors
}

// validateUserName validates user name requirements and uniqueness.
func validateUserName(user schema.User, index int, userNames map[string]bool) []ValidationError {
	var errors []ValidationError

	switch {
	case user.Name == "":
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.user[%d].name", index),
			Message: "user name is required",
		})
	case userNames[user.Name]:
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.user[%d].name", index),
			Message: fmt.Sprintf("user name '%s' must be unique", user.Name),
		})
	default:
		userNames[user.Name] = true
	}

	return errors
}

// validateUserUID validates user UID requirements and uniqueness.
func validateUserUID(user schema.User, index int, userUIDs map[string]bool) []ValidationError {
	var errors []ValidationError

	if user.UID == "" {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.user[%d].uid", index),
			Message: "user UID is required",
		})
		return errors
	}

	uid, err := strconv.Atoi(user.UID)
	if err != nil || uid < 0 {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.user[%d].uid", index),
			Message: fmt.Sprintf("UID '%s' must be a positive integer", user.UID),
		})
		return errors
	}

	if userUIDs[user.UID] {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.user[%d].uid", index),
			Message: fmt.Sprintf("user UID '%s' must be unique", user.UID),
		})
		return errors
	}

	userUIDs[user.UID] = true
	return errors
}

// validateUserGroupMembership validates user group membership.
func validateUserGroupMembership(user schema.User, index int, groupNames map[string]bool) []ValidationError {
	var errors []ValidationError

	if user.Groupname != "" && !groupNames[user.Groupname] {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.user[%d].groupname", index),
			Message: fmt.Sprintf("referenced group '%s' does not exist", user.Groupname),
		})
	}

	return errors
}

// validateUserScope validates user scope requirements.
func validateUserScope(user schema.User, index int) []ValidationError {
	var errors []ValidationError

	if user.Scope == "" {
		return errors
	}

	validScopes := []string{"system", "local"}
	if !contains(validScopes, user.Scope) {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.user[%d].scope", index),
			Message: fmt.Sprintf("user scope '%s' must be one of: %v", user.Scope, validScopes),
		})
	}

	return errors
}

// validateSysctl checks sysctl tunable items for required fields, uniqueness, valid naming format, and presence of values.
// It returns a slice of ValidationError for any missing, duplicate, or improperly formatted tunable names, or missing values.
func validateSysctl(items []schema.SysctlItem) []ValidationError {
	var errors []ValidationError

	tunables := make(map[string]bool)

	for i, item := range items {
		// Tunable is required and must be unique
		switch {
		case item.Tunable == "":
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("sysctl[%d].tunable", i),
				Message: "tunable name is required",
			})
		case tunables[item.Tunable]:
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("sysctl[%d].tunable", i),
				Message: fmt.Sprintf("tunable name '%s' must be unique", item.Tunable),
			})
		default:
			tunables[item.Tunable] = true
		}

		// Validate tunable name format (basic validation)
		if item.Tunable != "" && !isValidSysctlName(item.Tunable) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("sysctl[%d].tunable", i),
				Message: fmt.Sprintf("tunable name '%s' has invalid format", item.Tunable),
			})
		}

		// Value is required
		if item.Value == "" {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("sysctl[%d].value", i),
				Message: "tunable value is required",
			})
		}
	}

	return errors
}

// Helper functions for validation

// contains reports whether a slice of strings contains a specified string.
func contains(slice []string, item string) bool {
	return slices.Contains(slice, item)
}

// hostnamePattern matches valid hostnames: starts and ends with alphanumeric, allows hyphens in between.
var hostnamePattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)

// isValidHostname returns true if the given string is a valid hostname according to length and character rules.
func isValidHostname(hostname string) bool {
	if hostname == "" || len(hostname) > constants.MaxHostnameLength {
		return false
	}

	return hostnamePattern.MatchString(hostname)
}

// timezonePatterns matches common timezone formats: Region/City, Etc/UTC, UTC, GMT+/-offset.
var timezonePatterns = []*regexp.Regexp{
	regexp.MustCompile(`^(America|Europe|Asia|Africa|Australia|Antarctica)/[A-Za-z_]+$`),
	regexp.MustCompile(`^Etc/(UTC|GMT[+-]?\d*)$`),
	regexp.MustCompile(`^UTC$`),
	regexp.MustCompile(`^GMT[+-]?\d*$`),
}

// isValidTimezone returns true if the given timezone string matches common timezone patterns such as "Region/City", "Etc/UTC", "UTC", or "GMT" with optional offset.
func isValidTimezone(timezone string) bool {
	for _, pattern := range timezonePatterns {
		if pattern.MatchString(timezone) {
			return true
		}
	}

	return false
}

// isValidIP returns true if the input string is a valid IPv4 address.
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil && net.ParseIP(ip).To4() != nil
}

// isValidIPv6 returns true if the input string is a valid IPv6 address.
func isValidIPv6(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.To4() == nil
}

// looksLikeMalformedIP returns true if the string appears to be a failed IP/CIDR
// attempt rather than a legitimate alias name. Checks for CIDR slash, IPv6 colons,
// or strings composed entirely of digits and dots (failed IPv4 parse).
var digitsAndDotsPattern = regexp.MustCompile(`^[\d.]+$`)

func looksLikeMalformedIP(s string) bool {
	return strings.Contains(s, "/") || strings.Contains(s, ":") || digitsAndDotsPattern.MatchString(s)
}

// isValidCIDR returns true if the input string is a valid CIDR notation, otherwise false.
func isValidCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// connRatePattern matches the "connections/seconds" format (e.g., "15/5").
var connRatePattern = regexp.MustCompile(`^\d+/\d+$`)

// isValidConnRateFormat returns true if the string matches the "connections/seconds" format (e.g., "15/5")
// with both values being positive integers.
func isValidConnRateFormat(rate string) bool {
	if !connRatePattern.MatchString(rate) {
		return false
	}

	//nolint:mnd // splitting "connections/seconds" into exactly 2 parts
	parts := strings.SplitN(rate, "/", 2)
	connections, err1 := strconv.Atoi(parts[0])
	seconds, err2 := strconv.Atoi(parts[1])

	return err1 == nil && err2 == nil && connections > 0 && seconds > 0
}

// portRangePattern matches a numeric port or numeric port range (e.g., "80", "1024-65535").
var portRangePattern = regexp.MustCompile(`^\d+(-\d+)?$`)

// numericPrefixPattern detects values that start with digits followed by a hyphen,
// indicating a malformed range attempt (e.g., "80-abc").
var numericPrefixPattern = regexp.MustCompile(`^\d+-`)

// maxPort is the maximum valid TCP/UDP port number.
const maxPort = constants.MaxPort

// portRangeParts is the maximum number of parts when splitting a port range on hyphen.
const portRangeParts = 2

// isValidPortOrRange validates a port specification.
// It permits empty values and alias-like strings (e.g., "http", "MyAlias").
// When the value matches a numeric or numeric range pattern, it ensures ports
// are 1–65535 and that range low <= high. Malformed values like "80-abc" are rejected.
func isValidPortOrRange(port string) bool {
	if port == "" {
		return true
	}

	if portRangePattern.MatchString(port) {
		return validateNumericPort(port)
	}

	// Detect malformed range attempts (starts with digits + hyphen but non-numeric tail)
	if numericPrefixPattern.MatchString(port) {
		return false
	}

	// Not numeric — treat as alias name (valid)
	return true
}

// validateNumericPort validates a purely numeric port or port range string.
func validateNumericPort(port string) bool {
	parts := strings.SplitN(port, "-", portRangeParts)

	low, err := strconv.Atoi(parts[0])
	if err != nil || low < 1 || low > maxPort {
		return false
	}

	if len(parts) == 1 {
		return true
	}

	high, err := strconv.Atoi(parts[1])
	if err != nil || high < 1 || high > maxPort {
		return false
	}

	return low <= high
}

// sysctlNamePattern matches valid sysctl tunable names: starts with letter, allows letters, digits, underscores, dots.
var sysctlNamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.]*$`)

// isValidSysctlName returns true if the provided string is a valid sysctl tunable name, requiring it to start with a letter, contain only letters, digits, underscores, or dots, and include at least one dot.
func isValidSysctlName(name string) bool {
	return sysctlNamePattern.MatchString(name) && strings.Contains(name, ".")
}
