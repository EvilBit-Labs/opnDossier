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

// validOPNRuleTypes / IPProtocols / Directions / StateTypes are hoisted to
// package scope so each helper does not reallocate them per rule.
var (
	validOPNRuleTypes      = []string{"pass", "block", "reject"}
	validOPNIPProtocols    = []string{"inet", "inet6"}
	validOPNDirections     = []string{"in", "out", "any"}
	validOPNRuleStateTypes = []string{"keep state", "sloppy state", "synproxy state", "none"}
)

// validateFilter checks each firewall filter rule for valid types, protocols, interface references, and network specifications.
// It returns a list of validation errors for any rule fields that are invalid or reference non-existent interfaces.
func validateFilter(filter *schema.Filter, interfaces *schema.Interfaces) []ValidationError {
	var errors []ValidationError
	validInterfaceNames := collectInterfaceNames(interfaces)
	for i, rule := range filter.Rule {
		errors = append(errors, validateOPNFilterRule(i, rule, validInterfaceNames)...)
	}
	return errors
}

// validateOPNFilterRule checks a single OPNsense filter rule by delegating
// to concern-specific helpers. Splitting keeps validateFilter cognitively flat.
func validateOPNFilterRule(
	i int,
	rule schema.Rule,
	validInterfaceNames map[string]struct{},
) []ValidationError {
	var errors []ValidationError
	prefix := fmt.Sprintf("filter.rule[%d]", i)
	errors = append(errors, validateOPNRuleTypeAndProtocol(prefix, rule)...)
	errors = append(errors, validateOPNRuleInterface(prefix, rule, validInterfaceNames)...)
	errors = append(errors, validateOPNRuleEndpoints(prefix, rule, validInterfaceNames)...)
	errors = append(errors, validateOPNRuleAnyExclusivity(prefix, rule)...)
	errors = append(errors, validateOPNRuleDirection(prefix, rule)...)
	errors = append(errors, validateOPNRuleStateAndRate(prefix, rule)...)
	return errors
}

func validateOPNRuleTypeAndProtocol(prefix string, rule schema.Rule) []ValidationError {
	var errors []ValidationError
	if rule.Type != "" && !contains(validOPNRuleTypes, rule.Type) {
		errors = append(errors, ValidationError{
			Field:   prefix + ".type",
			Message: fmt.Sprintf("rule type '%s' must be one of: %v", rule.Type, validOPNRuleTypes),
		})
	}
	if rule.IPProtocol != "" && !contains(validOPNIPProtocols, rule.IPProtocol) {
		errors = append(errors, ValidationError{
			Field:   prefix + ".ipprotocol",
			Message: fmt.Sprintf("IP protocol '%s' must be one of: %v", rule.IPProtocol, validOPNIPProtocols),
		})
	}
	return errors
}

func validateOPNRuleInterface(
	prefix string,
	rule schema.Rule,
	validInterfaceNames map[string]struct{},
) []ValidationError {
	if rule.Interface.IsEmpty() {
		return nil
	}
	var errors []ValidationError
	for _, iface := range rule.Interface {
		if _, exists := validInterfaceNames[iface]; exists {
			continue
		}
		errors = append(errors, ValidationError{
			Field: prefix + ".interface",
			Message: fmt.Sprintf(
				"interface '%s' must be one of the configured interfaces: %v",
				iface,
				sortedInterfaceNames(validInterfaceNames),
			),
		})
	}
	return errors
}

// validateOPNRuleEndpoints mirrors validatePfSenseRuleEndpoints in pfsense.go
// by design — the two devices share the same endpoint schema. The dupl linter
// flags this pair bidirectionally, so both sides carry the suppression per
// GOTCHAS §9.1.
//
//nolint:dupl // structurally identical to validatePfSenseRuleEndpoints by design
func validateOPNRuleEndpoints(
	prefix string,
	rule schema.Rule,
	validInterfaceNames map[string]struct{},
) []ValidationError {
	var errors []ValidationError
	errors = append(errors, validateNetworkField(
		rule.Source.Network, prefix+".source.network", "source", validInterfaceNames,
	)...)
	errors = append(errors, validateAddressField(
		rule.Source.Address, prefix+".source.address",
	)...)
	errors = append(errors, validateNetworkField(
		rule.Destination.Network, prefix+".destination.network", "destination", validInterfaceNames,
	)...)
	errors = append(errors, validateAddressField(
		rule.Destination.Address, prefix+".destination.address",
	)...)
	if rule.Source.Port != "" && !isValidPortOrRange(rule.Source.Port) {
		errors = append(errors, ValidationError{
			Field: prefix + ".source.port",
			Message: fmt.Sprintf(
				"source port '%s' is not a valid port (1-65535) or range (low-high)",
				rule.Source.Port,
			),
		})
	}
	if rule.Destination.Port != "" && !isValidPortOrRange(rule.Destination.Port) {
		errors = append(errors, ValidationError{
			Field: prefix + ".destination.port",
			Message: fmt.Sprintf(
				"destination port '%s' is not a valid port (1-65535) or range (low-high)",
				rule.Destination.Port,
			),
		})
	}
	return errors
}

// validateOPNRuleAnyExclusivity enforces that each endpoint specifies exactly
// one of {any, network, address} — OPNsense treats combinations as ambiguous.
func validateOPNRuleAnyExclusivity(prefix string, rule schema.Rule) []ValidationError {
	var errors []ValidationError
	if countOPNEndpointFields(rule.Source.IsAny(), rule.Source.Network, rule.Source.Address) > 1 {
		errors = append(errors, ValidationError{
			Field:   prefix + ".source",
			Message: "source can only specify one of: any, network, or address",
		})
	}
	if countOPNEndpointFields(rule.Destination.IsAny(), rule.Destination.Network, rule.Destination.Address) > 1 {
		errors = append(errors, ValidationError{
			Field:   prefix + ".destination",
			Message: "destination can only specify one of: any, network, or address",
		})
	}
	return errors
}

func countOPNEndpointFields(isAny bool, network, address string) int {
	count := 0
	if isAny {
		count++
	}
	if network != "" {
		count++
	}
	if address != "" {
		count++
	}
	return count
}

func validateOPNRuleDirection(prefix string, rule schema.Rule) []ValidationError {
	var errors []ValidationError
	if rule.Floating == floatingYes && rule.Direction == "" {
		errors = append(errors, ValidationError{
			Field:   prefix + ".direction",
			Message: "direction is required for floating rules",
		})
	}
	if rule.Direction != "" && !contains(validOPNDirections, rule.Direction) {
		errors = append(errors, ValidationError{
			Field:   prefix + ".direction",
			Message: fmt.Sprintf("direction '%s' must be one of: %v", rule.Direction, validOPNDirections),
		})
	}
	return errors
}

func validateOPNRuleStateAndRate(prefix string, rule schema.Rule) []ValidationError {
	var errors []ValidationError
	if rule.StateType != "" && !contains(validOPNRuleStateTypes, rule.StateType) {
		errors = append(errors, ValidationError{
			Field:   prefix + ".statetype",
			Message: fmt.Sprintf("state type '%s' must be one of: %v", rule.StateType, validOPNRuleStateTypes),
		})
	}
	if rule.MaxSrcConnRate != "" && !isValidConnRateFormat(rule.MaxSrcConnRate) {
		errors = append(errors, ValidationError{
			Field:   prefix + ".max-src-conn-rate",
			Message: "max-src-conn-rate must be in format 'connections/seconds' (e.g., '15/5')",
		})
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
