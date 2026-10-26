package analyzers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizer_NormalizeIP(t *testing.T) {
	t.Parallel()
	n := NewNormalizer()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"standard IPv4", "192.168.1.1", "192.168.1.1"},
		// A zero-padded octet is read as octal by inet_aton-family parsers,
		// so it is never formatting; the value is returned as written.
		{"leading zeros stay unchanged", "192.168.001.001", "192.168.001.001"},
		{"all zeros stay unchanged", "000.000.000.000", "000.000.000.000"},
		{"octal-looking stays unchanged", "172.016.000.001", "172.016.000.001"},
		{"CIDR notation", "192.168.1.0/24", "192.168.1.0/24"},
		{"CIDR with leading zeros stays unchanged", "010.000.000.000/8", "010.000.000.000/8"},
		{"CIDR prefix leading zero", "192.168.1.0/024", "192.168.1.0/24"},
		{"IPv6 loopback", "::1", "::1"},
		{"full IPv6", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
		{"IPv6 CIDR", "2001:db8::/32", "2001:db8::/32"},
		{"invalid CIDR prefix", "192.168.1.1/33", "192.168.1.1/33"},
		{"invalid stays unchanged", "not-an-ip", "not-an-ip"},
		{"empty stays empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, n.NormalizeIP(tt.input))
		})
	}
}

func TestNormalizer_NormalizeWhitespace(t *testing.T) {
	n := NewNormalizer()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no change needed", "hello world", "hello world"},
		{"multiple spaces", "hello   world", "hello world"},
		{"leading trailing", "  hello  ", "hello"},
		{"tabs and newlines", "hello\t\nworld", "hello world"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, n.NormalizeWhitespace(tt.input))
		})
	}
}

func TestNormalizer_NormalizePort(t *testing.T) {
	n := NewNormalizer()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"standard port", "80", "80"},
		{"leading zeros", "0080", "80"},
		{"port range dash", "80-443", "80-443"},
		{"port range colon", "80:443", "80:443"},
		{"leading zeros in range", "0080-0443", "80-443"},
		{"zero", "0", "0"},
		{"empty", "", ""},
		{"non-port text unchanged", "Label: Value", "Label: Value"},
		{"text with dash unchanged", "some-text", "some-text"},
		{"description unchanged", "Allow SSH access", "Allow SSH access"},
		{"mixed digits text unchanged", "rule 001", "rule 001"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, n.NormalizePort(tt.input))
		})
	}
}
