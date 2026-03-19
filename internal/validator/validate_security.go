package validator

import (
	"fmt"
	"net"
	"slices"
	"strings"

	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

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
