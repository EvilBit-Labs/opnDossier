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
	"strconv"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
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

// Helper functions for validation

// contains reports whether a slice of strings contains a specified string.
func contains(slice []string, item string) bool {
	return slices.Contains(slice, item)
}

// isValidIP returns true if the input string is a valid IPv4 address.
func isValidIP(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() != nil
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

// sysctlNamePattern matches valid sysctl tunable names: starts with a letter, segments of
// letters/digits/underscores separated by dots, with at least one dot required.
var sysctlNamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z0-9_]+)+$`)

// isValidSysctlName returns true if the provided string is a valid sysctl tunable name, requiring it to start with a letter, contain only letters, digits, underscores, or dots, and include at least one dot.
func isValidSysctlName(name string) bool {
	return sysctlNamePattern.MatchString(name)
}

// connRatePattern matches the "connections/seconds" format (e.g., "15/5").
var connRatePattern = regexp.MustCompile(`^\d+/\d+$`)

// isValidConnRateFormat returns true if the string matches the "connections/seconds" format
// (e.g., "15/5") with both values being positive integers.
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

// floatingYes is the XML value indicating a floating firewall rule.
const floatingYes = "yes"

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
