// Package analyzers provides semantic analysis utilities for diff comparisons.
package analyzers

import (
	"cmp"
	"net"
	"strconv"
	"strings"
)

// rangeParts is the expected number of parts when splitting a range string.
const rangeParts = 2

// Normalizer normalizes configuration values to reduce false-positive diffs.
// It returns normalized copies and never mutates the originals.
type Normalizer struct{}

// NewNormalizer creates a new Normalizer.
func NewNormalizer() *Normalizer {
	return &Normalizer{}
}

// NormalizeIP returns the canonical form of an IP address or CIDR: IPv6 is
// shortened ("2001:0db8::1" becomes "2001:db8::1") and a CIDR prefix length
// loses leading zeros ("/024" becomes "/24"). Anything the standard library
// rejects is returned unchanged. That includes an IPv4 address with a
// zero-padded octet such as "172.016.000.001": inet_aton-family parsers read
// a leading zero as octal and the validator rejects the form, so it is never
// treated as formatting.
func (n *Normalizer) NormalizeIP(s string) string {
	if s == "" {
		return s
	}

	if strings.Contains(s, "/") {
		ip, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return s
		}
		ones, _ := ipNet.Mask.Size()
		return ip.String() + "/" + strconv.Itoa(ones)
	}

	ip := net.ParseIP(s)
	if ip == nil {
		return s
	}
	return ip.String()
}

// NormalizeWhitespace collapses consecutive whitespace into single spaces
// and trims leading/trailing whitespace.
func (n *Normalizer) NormalizeWhitespace(s string) string {
	fields := strings.Fields(s)
	return strings.Join(fields, " ")
}

// NormalizePort normalizes a port or port range string.
// "80" stays "80", "0080" becomes "80", "80-443" stays "80-443".
// Returns the input unchanged if it does not look like a port or port range
// (i.e., contains non-digit characters other than a single separator).
func (n *Normalizer) NormalizePort(s string) string {
	if s == "" {
		return s
	}

	// Single-pass separator detection for range formats
	if idx := strings.IndexAny(s, "-:"); idx >= 0 {
		sep := string(s[idx])
		parts := strings.SplitN(s, sep, rangeParts)
		if len(parts) == rangeParts && isDigitsOnly(parts[0]) && isDigitsOnly(parts[1]) {
			start := n.normalizePortNumber(parts[0])
			end := n.normalizePortNumber(parts[1])
			return start + sep + end
		}
		return s // Not a port range
	}

	if !isDigitsOnly(s) {
		return s // Not a port number
	}

	return n.normalizePortNumber(s)
}

// isDigitsOnly returns true if the trimmed string consists only of digits.
func isDigitsOnly(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// normalizePortNumber strips leading zeros from a port number string.
func (n *Normalizer) normalizePortNumber(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}

	// Strip leading zeros, preserving "0" when the result would be empty
	// (e.g., "0" or "000" → "0").
	return cmp.Or(strings.TrimLeft(s, "0"), "0")
}
