// Package sanitizer provides functionality to redact sensitive information
// from OPNsense configuration files.
package sanitizer

import (
	"net"
	"regexp"
	"strings"
)

// Pattern detection constants.
const (
	// minBase64Length is the minimum length for a string to be considered base64-encoded.
	minBase64Length = 40
	// ipv6Length is the byte length of an IPv6 address.
	ipv6Length = 16
	// ipv6UniqueLocalMask is the mask for identifying IPv6 unique local addresses (fc00::/7).
	ipv6UniqueLocalMask = 0xfe
	// ipv6UniqueLocalPrefix is the prefix for IPv6 unique local addresses.
	ipv6UniqueLocalPrefix = 0xfc
)

// Compiled regex patterns for detecting sensitive data.
var (
	// IPv4 address pattern (matches 0.0.0.0 to 255.255.255.255).
	ipv4Pattern = regexp.MustCompile(
		`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`,
	)

	// IPv6 address pattern (simplified, matches common formats).
	ipv6Pattern = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|` +
		`\b(?:[0-9a-f]{1,4}:){1,7}:\b|` +
		`\b(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}\b|` +
		`\b::(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4}\b`)

	// MAC address pattern (XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX).
	macPattern = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b`)

	// Email address pattern.
	emailPattern = regexp.MustCompile(`\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`)

	// Hostname pattern (simple FQDN detection).
	hostnamePattern = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`)

	// Base64-encoded data pattern (for certificates/keys).
	base64Pattern = regexp.MustCompile(`^[A-Za-z0-9+/]{40,}={0,2}$`)

	// PEM certificate/key pattern.
	//nolint:gocritic // PEM format uses literal dashes, not a simplification
	pemPattern = regexp.MustCompile(`-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----`)
)

// RFC 1918 private IP ranges.
//
//nolint:mnd // RFC-defined IP address octets
var privateIPRanges = []net.IPNet{
	{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
	{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)},
	{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(16, 32)},
}

// Loopback and link-local ranges.
//
//nolint:mnd // RFC-defined IP address octets
var (
	loopbackRange  = net.IPNet{IP: net.IPv4(127, 0, 0, 0), Mask: net.CIDRMask(8, 32)}
	linkLocalRange = net.IPNet{IP: net.IPv4(169, 254, 0, 0), Mask: net.CIDRMask(16, 32)}
)

// IsIPv4 checks if the string is a valid IPv4 address.
func IsIPv4(s string) bool {
	return ipv4Pattern.MatchString(s)
}

// IsIPv6 reports whether s is a textual IPv6 address in common formats.
//
// The check accepts typical IPv6 representations such as full and compressed
// forms and mixed IPv4/IPv6 notations; it does not attempt network-level
// reachability checks. Returns true if s matches an IPv6 textual form, false otherwise.
func IsIPv6(s string) bool {
	return ipv6Pattern.MatchString(s)
}

// IsIP reports whether s is a valid IPv4 or IPv6 address.
// It returns true if s can be parsed as an IP address, false otherwise.
func IsIP(s string) bool {
	return net.ParseIP(s) != nil
}

// IsPrivateIP reports whether the provided string is an IPv4 or IPv6 private address.
// It returns `true` if the string parses as an IPv4 address within RFC1918 ranges or as an IPv6 unique local address (fc00::/7), and `false` otherwise.
func IsPrivateIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}

	// Check IPv4 private ranges
	ip4 := ip.To4()
	if ip4 != nil {
		for _, r := range privateIPRanges {
			if r.Contains(ip4) {
				return true
			}
		}
		return false
	}

	// Check IPv6 private (unique local addresses fc00::/7)
	if len(ip) == ipv6Length && (ip[0]&ipv6UniqueLocalMask) == ipv6UniqueLocalPrefix {
		return true
	}

	return false
}

// IsPublicIP reports whether s is a publicly routable IP address.
//
// For unparsable input it returns false. For IPv4 addresses it returns false
// for RFC1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), for
// loopback (127.0.0.0/8) and for link-local (169.254.0.0/16). For IPv6 it
// returns false for link-local addresses, for unique local addresses (fc00::/7)
// and for loopback.
func IsPublicIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}

	ip4 := ip.To4()
	if ip4 != nil {
		// Not private, not loopback, not link-local
		if loopbackRange.Contains(ip4) || linkLocalRange.Contains(ip4) {
			return false
		}
		for _, r := range privateIPRanges {
			if r.Contains(ip4) {
				return false
			}
		}
		return true
	}

	// IPv6: not link-local (fe80::/10) and not unique local (fc00::/7)
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if len(ip) == ipv6Length && (ip[0]&ipv6UniqueLocalMask) == ipv6UniqueLocalPrefix {
		return false
	}

	return !ip.IsLoopback()
}

// IsMAC reports whether s is a MAC address in common colon- or hyphen-separated notation.
// It matches six groups of two hexadecimal digits separated by `:` or `-` (for example
// "01:23:45:67:89:ab" or "01-23-45-67-89-ab").
func IsMAC(s string) bool {
	return macPattern.MatchString(s)
}

// IsEmail reports whether s is a syntactically valid email address according to the package's email pattern.
// It checks only the string format and does not verify DNS records, domain ownership, or mailbox deliverability.
func IsEmail(s string) bool {
	return emailPattern.MatchString(s)
}

// IsHostname reports whether s looks like a hostname or fully-qualified domain name.
// It requires at least one dot, rejects plain IP addresses, and validates the string
// against the package hostname pattern.
func IsHostname(s string) bool {
	// Must contain at least one dot and not be an IP
	if !strings.Contains(s, ".") {
		return false
	}
	if IsIP(s) {
		return false
	}
	return hostnamePattern.MatchString(s)
}

// IsDomain reports whether s is a domain name suitable as a hostname.
// It requires at least one dot, must not be an IP address, and must match the package's hostname pattern.
func IsDomain(s string) bool {
	return IsHostname(s)
}

// IsBase64 reports whether s appears to be base64-encoded data.
// It trims surrounding whitespace, requires s to be at least the package's
// minimum base64 length, and then checks against the compiled base64 pattern.
// Returns true if s matches those criteria, false otherwise.
func IsBase64(s string) bool {
	// Trim whitespace and check
	trimmed := strings.TrimSpace(s)
	if len(trimmed) < minBase64Length {
		return false
	}
	return base64Pattern.MatchString(trimmed)
}

// IsPEM reports whether s contains one or more PEM-formatted blocks delimited by
// "-----BEGIN ...-----" and "-----END ...-----" markers with content between them.
// It only detects the PEM markers and enclosed data and does not validate the decoded contents.
func IsPEM(s string) bool {
	return pemPattern.MatchString(s)
}

// IsCertificate reports whether s appears to contain an X.509 certificate.
//
// If s is PEM-formatted, it must include the literal "CERTIFICATE" in the
// PEM markers to be considered a certificate. Otherwise the function treats
// s as base64 and returns true if it matches base64 characteristics.
//
// Returns `true` if s appears to be a certificate in PEM or base64 form, `false` otherwise.
func IsCertificate(s string) bool {
	if IsPEM(s) {
		return strings.Contains(s, "CERTIFICATE")
	}
	return IsBase64(s)
}

// IsPrivateKey reports whether s appears to be a private key in PEM format.
// It returns true when s matches PEM structure and contains the "PRIVATE KEY" label,
// and false otherwise.
func IsPrivateKey(s string) bool {
	if IsPEM(s) {
		return strings.Contains(s, "PRIVATE KEY")
	}
	return false
}

// LooksLikePassword reports whether fieldName likely contains a password or secret.
// It performs a case-insensitive substring check for common password/key-related keywords
// such as "password", "passwd", "pass", "secret", "key", "token", "credential", "auth",
// "prv", and "private". It returns true if any keyword is present in fieldName, false otherwise.
func LooksLikePassword(fieldName string) bool {
	lower := strings.ToLower(fieldName)
	passwordKeywords := []string{
		"password", "passwd", "pass", "secret", "key", "token",
		"credential", "auth", "prv", "private",
	}
	for _, kw := range passwordKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// LooksLikeAPIKey reports whether fieldName likely refers to an API key.
// It performs a case-insensitive substring check and returns true if fieldName
// contains any of the common API key indicators such as "apikey", "api_key",
// "api-key", "accesskey", or "secretkey".
func LooksLikeAPIKey(fieldName string) bool {
	lower := strings.ToLower(fieldName)
	apiKeywords := []string{"apikey", "api_key", "api-key", "accesskey", "secretkey"}
	for _, kw := range apiKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// LooksLikePSK reports whether a field name suggests it contains a pre-shared key.
// It performs a case-insensitive substring check for common PSK-related tokens: "psk", "preshared", "pre-shared", and "ipsecpsk".
func LooksLikePSK(fieldName string) bool {
	lower := strings.ToLower(fieldName)
	pskKeywords := []string{"psk", "preshared", "pre-shared", "ipsecpsk"}
	for _, kw := range pskKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// LooksLikeSNMPCommunity reports whether fieldName likely refers to an SNMP community string.
// It returns true if the lower-cased field name contains "community" or "rocommunity".
func LooksLikeSNMPCommunity(fieldName string) bool {
	lower := strings.ToLower(fieldName)
	return strings.Contains(lower, "community") || strings.Contains(lower, "rocommunity")
}

// ExtractIPv4Addresses extracts all IPv4 addresses from s.
// It returns a slice of IPv4 address strings in dotted-decimal form, in the order they appear; duplicates are preserved and an empty slice is returned if none are found.
func ExtractIPv4Addresses(s string) []string {
	return ipv4Pattern.FindAllString(s, -1)
}

// ExtractEmails extracts all substrings that match email addresses in s, in the order they appear.
// It preserves duplicates and returns an empty slice if none are found.
func ExtractEmails(s string) []string {
	return emailPattern.FindAllString(s, -1)
}
