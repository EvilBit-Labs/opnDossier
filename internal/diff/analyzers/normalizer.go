// Package analyzers provides semantic analysis utilities for diff comparisons.
package analyzers

import (
	"net"
	"strconv"
	"strings"
)

// ipv4OctetCount is the number of octets in an IPv4 address.
const ipv4OctetCount = 4

// rangeParts is the expected number of parts when splitting a range string.
const rangeParts = 2

// Normalizer normalizes configuration values to reduce false-positive diffs.
// It returns normalized copies and never mutates the originals.
type Normalizer struct{}

// NewNormalizer creates a new Normalizer.
func NewNormalizer() *Normalizer {
	return &Normalizer{}
}

// NormalizeIP normalizes an IP address string by stripping leading zeros from each octet.
// For example, "192.168.001.001" becomes "192.168.1.1".
// CIDR notation is also supported: "010.000.000.000/8" becomes "10.0.0.0/8".
// Returns the original string unchanged if it's not a valid IPv4/IPv6 address.
func (n *Normalizer) NormalizeIP(s string) string {
	if s == "" {
		return s
	}

	// Split off CIDR prefix length if present
	addr, prefix, hasCIDR := strings.Cut(s, "/")

	// Try IPv4 normalization (strip leading zeros then parse)
	if strings.Contains(addr, ".") {
		normalized := n.normalizeIPv4Octets(addr)
		ip := net.ParseIP(normalized)
		if ip == nil {
			return s
		}
		result := ip.String()
		if hasCIDR {
			result += "/" + prefix
		}
		return result
	}

	// IPv6: use stdlib directly
	if hasCIDR {
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

// normalizeIPv4Octets strips leading zeros from each octet of an IPv4 address string.
func (n *Normalizer) normalizeIPv4Octets(s string) string {
	octets := strings.Split(s, ".")
	if len(octets) != ipv4OctetCount {
		return s
	}
	for i, octet := range octets {
		trimmed := strings.TrimLeft(octet, "0")
		if trimmed == "" {
			trimmed = "0"
		}
		octets[i] = trimmed
	}
	return strings.Join(octets, ".")
}

// NormalizeWhitespace collapses consecutive whitespace into single spaces
// and trims leading/trailing whitespace.
func (n *Normalizer) NormalizeWhitespace(s string) string {
	fields := strings.Fields(s)
	return strings.Join(fields, " ")
}

// NormalizePort normalizes a port or port range string.
// "80" stays "80", "0080" becomes "80", "80-443" stays "80-443".
func (n *Normalizer) NormalizePort(s string) string {
	if s == "" {
		return s
	}

	// Handle port ranges
	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", rangeParts)
		if len(parts) == rangeParts {
			start := n.normalizePortNumber(parts[0])
			end := n.normalizePortNumber(parts[1])
			return start + "-" + end
		}
	}

	// Handle colon-separated ranges (OPNsense uses this format too)
	if strings.Contains(s, ":") {
		parts := strings.SplitN(s, ":", rangeParts)
		if len(parts) == rangeParts {
			start := n.normalizePortNumber(parts[0])
			end := n.normalizePortNumber(parts[1])
			return start + ":" + end
		}
	}

	return n.normalizePortNumber(s)
}

// NormalizeProtocol normalizes a protocol name to lowercase.
func (n *Normalizer) NormalizeProtocol(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// NormalizePath normalizes a file or configuration path by removing trailing slashes
// and collapsing consecutive slashes.
func (n *Normalizer) NormalizePath(s string) string {
	// Remove trailing slashes
	s = strings.TrimRight(s, "/")
	// Collapse consecutive slashes
	for strings.Contains(s, "//") {
		s = strings.ReplaceAll(s, "//", "/")
	}
	return s
}

// normalizePortNumber strips leading zeros from a port number string.
func (n *Normalizer) normalizePortNumber(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}

	// Strip leading zeros
	result := strings.TrimLeft(s, "0")
	if result == "" {
		return "0"
	}
	return result
}
