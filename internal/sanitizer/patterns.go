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

// IsIPv6 checks if the string is a valid IPv6 address.
func IsIPv6(s string) bool {
	return ipv6Pattern.MatchString(s)
}

// IsIP checks if the string is a valid IP address (v4 or v6).
func IsIP(s string) bool {
	return net.ParseIP(s) != nil
}

// IsPrivateIP checks if the IP address is in a private range (RFC 1918).
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

// IsPublicIP checks if the IP address is publicly routable.
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

// IsMAC checks if the string is a valid MAC address.
func IsMAC(s string) bool {
	return macPattern.MatchString(s)
}

// IsEmail checks if the string is a valid email address.
func IsEmail(s string) bool {
	return emailPattern.MatchString(s)
}

// IsHostname checks if the string looks like a hostname/FQDN.
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

// IsDomain checks if the string is a domain name (similar to hostname but more strict).
func IsDomain(s string) bool {
	return IsHostname(s)
}

// IsBase64 checks if the string appears to be base64-encoded data.
func IsBase64(s string) bool {
	// Trim whitespace and check
	trimmed := strings.TrimSpace(s)
	if len(trimmed) < minBase64Length {
		return false
	}
	return base64Pattern.MatchString(trimmed)
}

// IsPEM checks if the string contains PEM-encoded data.
func IsPEM(s string) bool {
	return pemPattern.MatchString(s)
}

// IsCertificate checks if the string looks like a certificate.
func IsCertificate(s string) bool {
	if IsPEM(s) {
		return strings.Contains(s, "CERTIFICATE")
	}
	return IsBase64(s)
}

// IsPrivateKey checks if the string looks like a private key.
func IsPrivateKey(s string) bool {
	if IsPEM(s) {
		return strings.Contains(s, "PRIVATE KEY")
	}
	return false
}

// LooksLikePassword checks if the field name suggests it contains a password.
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

// LooksLikeAPIKey checks if the field name suggests it contains an API key.
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

// LooksLikePSK checks if the field name suggests it contains a pre-shared key.
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

// LooksLikeSNMPCommunity checks if the field name suggests SNMP community string.
func LooksLikeSNMPCommunity(fieldName string) bool {
	lower := strings.ToLower(fieldName)
	return strings.Contains(lower, "community") || strings.Contains(lower, "rocommunity")
}

// ExtractIPv4Addresses extracts all IPv4 addresses from a string.
func ExtractIPv4Addresses(s string) []string {
	return ipv4Pattern.FindAllString(s, -1)
}

// ExtractEmails extracts all email addresses from a string.
func ExtractEmails(s string) []string {
	return emailPattern.FindAllString(s, -1)
}
