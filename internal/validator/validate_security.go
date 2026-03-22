package validator

import (
	"fmt"
	"maps"
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

// sortedInterfaceNames returns a deterministic, sorted list of interface names from the set.
func sortedInterfaceNames(names map[string]struct{}) []string {
	return slices.Sorted(maps.Keys(names))
}

// validateNetworkField validates a network field value (source or destination) against reserved
// keywords, CIDR notation, and configured interface references. Reserved keywords are matched
// against the original value (exact match); the "ip" suffix is only stripped for interface lookups.
// The direction parameter (e.g., "source", "destination") is used in error messages.
func validateNetworkField(
	network string,
	fieldPath string,
	direction string,
	validInterfaceNames map[string]struct{},
) []ValidationError {
	if network == "" {
		return nil
	}

	// Check reserved keywords against the original value (exact match)
	if isReservedNetwork(network) {
		return nil
	}

	// Check if it's a valid CIDR
	if isValidCIDR(network) {
		return nil
	}

	// Strip "ip" suffix and check as interface reference (e.g., "lanip" -> "lan")
	stripped := stripIPSuffix(network)
	if _, exists := validInterfaceNames[stripped]; exists {
		return nil
	}

	return []ValidationError{{
		Field: fieldPath,
		Message: fmt.Sprintf(
			"%s network '%s' must be a valid CIDR, reserved word, or an interface key followed by 'ip'",
			direction,
			network,
		),
	}}
}

// validateAddressField validates an address field value (source or destination) for malformed IPs.
func validateAddressField(address, fieldPath string) []ValidationError {
	if address == "" || isValidCIDR(address) || net.ParseIP(address) != nil {
		return nil
	}

	// Not a valid IP or CIDR — could be an alias, which is acceptable.
	// Only flag if it looks like a malformed IP/CIDR attempt.
	if looksLikeMalformedIP(address) {
		return []ValidationError{{
			Field:   fieldPath,
			Message: fmt.Sprintf("address '%s' appears to be a malformed IP/CIDR", address),
		}}
	}

	return nil
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
					errors = append(errors, ValidationError{
						Field: fmt.Sprintf("filter.rule[%d].interface", i),
						Message: fmt.Sprintf(
							"interface '%s' must be one of the configured interfaces: %v",
							iface,
							sortedInterfaceNames(validInterfaceNames),
						),
					})
				}
			}
		}

		// Validate source/destination networks and addresses
		errors = append(errors, validateNetworkField(
			rule.Source.Network, fmt.Sprintf("filter.rule[%d].source.network", i), "source", validInterfaceNames,
		)...)
		errors = append(errors, validateAddressField(
			rule.Source.Address, fmt.Sprintf("filter.rule[%d].source.address", i),
		)...)
		errors = append(errors, validateNetworkField(
			rule.Destination.Network,
			fmt.Sprintf("filter.rule[%d].destination.network", i),
			"destination",
			validInterfaceNames,
		)...)
		errors = append(errors, validateAddressField(
			rule.Destination.Address, fmt.Sprintf("filter.rule[%d].destination.address", i),
		)...)

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
		if rule.Floating == floatingYes && rule.Direction == "" {
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
