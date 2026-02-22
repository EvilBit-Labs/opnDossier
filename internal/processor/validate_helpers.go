package processor

import (
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
)

// Compiled regular expressions used by the validation helper functions.
var (
	hostnamePattern     = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)
	timezonePatternIANA = regexp.MustCompile(`^[A-Za-z]+(?:/[A-Za-z0-9_+\-]+)+$`)
	timezonePatternEtc  = regexp.MustCompile(`^Etc/GMT[+-]\d+$`)
	timezonePatternUTC  = regexp.MustCompile(`^UTC$`)
	timezonePatternGMT  = regexp.MustCompile(`^GMT$`)
	portRangePattern    = regexp.MustCompile(`^\d+(-\d+)?$`)
	portAliasPattern    = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`)
	connRatePattern     = regexp.MustCompile(`^\d+/\d+$`)
	sysctlNamePattern   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.]*$`)
	numericLikePattern  = regexp.MustCompile(`^[\d.]+$`)
)

// connRatePartsCount is the expected number of parts when splitting a connection rate string.
const connRatePartsCount = 2

// isValidHostname checks that hostname is non-empty, within RFC 1035 length limits,
// and that each dot-separated label matches the hostname pattern.
func isValidHostname(hostname string) bool {
	if hostname == "" || len(hostname) > constants.MaxHostnameLength {
		return false
	}

	for part := range strings.SplitSeq(hostname, ".") {
		if part == "" || !hostnamePattern.MatchString(part) {
			return false
		}
	}

	return true
}

// isValidTimezone checks that timezone matches IANA (e.g., "America/New_York"),
// Etc/GMT offset, "UTC", or "GMT" format.
func isValidTimezone(timezone string) bool {
	if timezone == "" {
		return false
	}

	return timezonePatternIANA.MatchString(timezone) ||
		timezonePatternEtc.MatchString(timezone) ||
		timezonePatternUTC.MatchString(timezone) ||
		timezonePatternGMT.MatchString(timezone)
}

// isValidIP reports whether ip is a valid IPv4 address.
func isValidIP(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() != nil
}

// isValidIPv6 reports whether ip is a valid IPv6 address (not IPv4-mapped).
func isValidIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil
}

// isValidCIDR reports whether cidr is a valid CIDR notation (e.g., "192.168.1.0/24").
func isValidCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// portRangeParts is the maximum number of parts when splitting a port range on hyphen.
const portRangeParts = 2

// isValidPortOrRange reports whether port is empty (allowed), a valid single port
// number, a valid port range ("low-high"), or a recognized service name alias.
func isValidPortOrRange(port string) bool {
	if port == "" {
		return true
	}

	if !portRangePattern.MatchString(port) {
		// Non-numeric values are treated as service name aliases (e.g., "http", "ssh").
		// Validate they contain only alphanumeric chars and hyphens.
		return portAliasPattern.MatchString(port)
	}

	parts := strings.SplitN(port, "-", portRangeParts)
	if len(parts) == 1 {
		p, err := strconv.Atoi(parts[0])
		if err != nil {
			return false
		}

		return p >= constants.MinPort && p <= constants.MaxPort
	}

	low, errLow := strconv.Atoi(parts[0])
	high, errHigh := strconv.Atoi(parts[1])
	if errLow != nil || errHigh != nil {
		return false
	}

	return low >= constants.MinPort && high <= constants.MaxPort && low <= high
}

// isValidConnRateFormat reports whether rate follows the "count/seconds" format
// with both values being positive integers.
func isValidConnRateFormat(rate string) bool {
	if !connRatePattern.MatchString(rate) {
		return false
	}

	parts := strings.Split(rate, "/")
	if len(parts) != connRatePartsCount {
		return false
	}

	count, errCount := strconv.Atoi(parts[0])
	seconds, errSeconds := strconv.Atoi(parts[1])
	if errCount != nil || errSeconds != nil {
		return false
	}

	return count > 0 && seconds > 0
}

// isValidSysctlName reports whether name is a valid sysctl identifier
// (starts with a letter, contains alphanumerics/dots, and has at least one dot).
func isValidSysctlName(name string) bool {
	if !sysctlNamePattern.MatchString(name) {
		return false
	}

	return strings.Contains(name, ".")
}

// looksLikeMalformedIP reports whether value looks like it was intended to be an
// IP address or CIDR (contains "/" or ":" or is purely numeric/dots).
func looksLikeMalformedIP(value string) bool {
	return strings.Contains(value, "/") || strings.Contains(value, ":") || numericLikePattern.MatchString(value)
}
