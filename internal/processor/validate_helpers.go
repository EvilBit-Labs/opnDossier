package processor

import (
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
)

var (
	hostnamePattern     = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)
	timezonePatternIANA = regexp.MustCompile(`^[A-Za-z]+(?:/[A-Za-z0-9_+\-]+)+$`)
	timezonePatternEtc  = regexp.MustCompile(`^Etc/GMT[+-]\d+$`)
	timezonePatternUTC  = regexp.MustCompile(`^UTC$`)
	timezonePatternGMT  = regexp.MustCompile(`^GMT$`)
	portRangePattern    = regexp.MustCompile(`^\d+(?::\d+)?$`)
	portAliasPattern    = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`)
	connRatePattern     = regexp.MustCompile(`^\d+/\d+$`)
	sysctlNamePattern   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.]*$`)
	numericLikePattern  = regexp.MustCompile(`^[\d.]+$`)
)

const connRatePartsCount = 2

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

func isValidTimezone(timezone string) bool {
	if timezone == "" {
		return false
	}

	return timezonePatternIANA.MatchString(timezone) ||
		timezonePatternEtc.MatchString(timezone) ||
		timezonePatternUTC.MatchString(timezone) ||
		timezonePatternGMT.MatchString(timezone)
}

func isValidIP(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() != nil
}

func isValidIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil
}

func isValidCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

func isValidPortOrRange(port string) bool {
	if port == "" {
		return true
	}

	if !portRangePattern.MatchString(port) {
		// Non-numeric values are treated as service name aliases (e.g., "http", "ssh").
		// Validate they contain only alphanumeric chars and hyphens.
		return portAliasPattern.MatchString(port)
	}

	parts := strings.Split(port, ":")
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

func isValidSysctlName(name string) bool {
	if !sysctlNamePattern.MatchString(name) {
		return false
	}

	return strings.Contains(name, ".")
}

func looksLikeMalformedIP(value string) bool {
	return strings.Contains(value, "/") || strings.Contains(value, ":") || numericLikePattern.MatchString(value)
}
