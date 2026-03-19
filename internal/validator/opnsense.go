// Package validator provides comprehensive validation functionality for OPNsense configuration files.
// It validates system settings, network interfaces, DHCP server configuration, firewall rules,
// NAT rules, user and group settings, and sysctl tunables to ensure configuration integrity
// and prevent deployment of invalid configurations.
package validator

import (
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"

	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
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

// Helper functions for validation

// contains reports whether a slice of strings contains a specified string.
func contains(slice []string, item string) bool {
	return slices.Contains(slice, item)
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

// looksLikeMalformedIP reports whether s appears to be a failed IP address parse
// attempt rather than a legitimate alias name.
func looksLikeMalformedIP(s string) bool {
	return strings.Contains(s, "/") || strings.Contains(s, ":") || digitsAndDotsPattern.MatchString(s)
}

// isValidCIDR returns true if the input string is a valid CIDR notation, otherwise false.
func isValidCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}
