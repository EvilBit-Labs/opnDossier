// Package analyzers provides semantic analysis utilities for diff comparisons.
package analyzers

import (
	"net"
	"strconv"
	"strings"
)

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
